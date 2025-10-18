# tinysocs/agent/adapters/opensearch_client.py
from __future__ import annotations

import os, ssl, time
import typing as t
from urllib.parse import urlparse

from opensearchpy import OpenSearch
from opensearchpy.connection import RequestsHttpConnection

from requests.exceptions import ConnectionError as ReqConnError, ReadTimeout as ReqReadTimeout
from urllib3.exceptions import ProtocolError
from opensearchpy.exceptions import ConnectionError as OSConnError, ConnectionTimeout as OSTimeout


def _truthy(v: str | None) -> bool:
    return str(v or "").strip().lower() in ("1", "true", "yes", "y", "on")


class OpenSearchClient:
    """
    Windows/self-signed-friendly OpenSearch adapter:
      • Requests-backed connection
      • TLS 1.2
      • No keep-alive (Connection: close)
      • Small pool (1 per node)
      • Single retry on transient socket reset/timeouts
    """

    def __init__(self):
        # Prefer SIEM_* envs; fall back to legacy OPENSEARCH_* if present
        url = (
            os.getenv("SIEM_URL")
            or os.getenv("OPENSEARCH_URL")
            or "https://localhost:9201"
        )
        user = os.getenv("SIEM_USER") or os.getenv("OPENSEARCH_USER") or "admin"
        pwd  = os.getenv("SIEM_PASS") or os.getenv("OPENSEARCH_PASS") or "ChangeMe123!"
        verify = _truthy(os.getenv("SIEM_SSL_VERIFY", os.getenv("OPENSEARCH_VERIFY_SSL", "false")))
        timeout = float(os.getenv("SIEM_TIMEOUT_SECONDS", "20"))

        self._cfg = dict(url=url, user=user, pwd=pwd, verify=verify, timeout=timeout)
        self._mk_client()

        # Prove connectivity early
        info = self.os.info()
        ver  = info.get("version", {})
        p = urlparse(url)
        base = f"{p.scheme}://{p.hostname or 'localhost'}:{p.port or (443 if (p.scheme or 'https')=='https' else 80)}"
        dist = ver.get("distribution") or "elasticsearch"
        num  = ver.get("number")
        print(f"[siem] connected -> {dist} @ {base} (version={num})", flush=True)

    # ---------- internals ----------

    def _mk_client(self):
        url     = self._cfg["url"]
        user    = self._cfg["user"]
        pwd     = self._cfg["pwd"]
        verify  = self._cfg["verify"]
        timeout = self._cfg["timeout"]

        p = urlparse(url)
        host_cfg = {
            "host": p.hostname or "localhost",
            "port": p.port or (443 if (p.scheme or "https") == "https" else 80),
            "scheme": p.scheme or "https",
        }

        self.os = OpenSearch(
            hosts=[host_cfg],
            http_auth=(user, pwd),
            use_ssl=(p.scheme == "https"),
            verify_certs=verify,
            ssl_assert_hostname=verify,
            ssl_show_warn=False,
            ssl_version=ssl.PROTOCOL_TLSv1_2,
            connection_class=RequestsHttpConnection,
            headers={"connection": "close", "user-agent": "tinysocs/0.1"},
            http_compress=False,
            timeout=timeout,
            max_retries=0,
            retry_on_timeout=False,
            connections_per_node=1,
        )

    def _with_retry(self, fn, *args, **kwargs):
        for attempt in (1, 2):
            try:
                return fn(*args, **kwargs)
            except (ReqConnError, ReqReadTimeout, ProtocolError, OSConnError, OSTimeout):
                if attempt == 2:
                    raise
                print("[opensearch] transient connection error; recreating client and retrying once…", flush=True)
                time.sleep(0.5)
                self._mk_client()

    # ---------- API ----------

    def search_kql(
        self,
        index: str,
        kql: str,
        size: int = 100,
        *,
        track_total_hits: bool | int = False,
        source: bool = True,
    ) -> t.Union[t.List[dict], dict, int]:
        """
        Route KQL-ish text via query_string.

        When size == 0: returns {"total": <int>} (count-only).
        Otherwise: returns a list of docs (each doc is the _source dict).
        """
        body = {
            "query": {"query_string": {"query": kql}},
            "size": int(size),
            "track_total_hits": bool(track_total_hits),
            "_source": bool(source),
        }
        # sort only when fetching docs
        if size and size > 0:
            body["sort"] = [{"@timestamp": {"order": "desc"}}]

        resp = self._with_retry(self.os.search, index=index, body=body)
        if not size or size == 0:
            total = resp.get("hits", {}).get("total", 0)
            if isinstance(total, dict):
                total = total.get("value", 0)
            return {"total": int(total)}

        hits = resp.get("hits", {}).get("hits", [])
        # return _source dicts for compactness
        return [h.get("_source", {}) for h in hits]

    def aggregate(self, index: str, dsl: dict) -> dict:
        resp = self._with_retry(self.os.search, index=index, body=dsl)
        return resp.get("aggregations", {}) or {}


# Back-compat alias so older code importing OSClient keeps working
OSClient = OpenSearchClient