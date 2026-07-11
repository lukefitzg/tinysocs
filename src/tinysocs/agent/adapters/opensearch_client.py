# tinysocs/agent/adapters/opensearch_client.py
from __future__ import annotations

import os
import ssl
import time
from urllib.parse import urlparse

from opensearchpy import OpenSearch
from opensearchpy.connection import Urllib3HttpConnection
from opensearchpy.exceptions import ConnectionError as OSConnError
from opensearchpy.exceptions import ConnectionTimeout as OSTimeout
from requests.exceptions import ConnectionError as ReqConnError
from requests.exceptions import ReadTimeout as ReqReadTimeout
from urllib3.exceptions import ProtocolError

from tinysocs.tls import resolve_ca_cert


def _truthy(v: str | None) -> bool:
    return str(v or "").strip().lower() in ("1", "true", "yes", "y", "on")


# Minimal fields we actually need for detections/summaries
DEFAULT_SOURCE_FIELDS: list[str] = [
    "@timestamp",
    "event.code", "event.action", "log.level",
    "host.name", "host.hostname",
    "user.name",
    "process.name", "process.executable", "process.command_line", "process.pid",
    "source.ip", "destination.ip",
    "winlog.event_id",
    "message",
    "powershell.command.value",
]


class OpenSearchClient:
    """
    Windows/self-signed-friendly OpenSearch adapter:
      - Requests-backed connection
      - TLS 1.2
      - No keep-alive (Connection: close)
      - Small pool (1 per node)
      - Single retry on transient socket reset/timeouts

    Connectivity is not required at import time. We build a client and
    attempt a lightweight probe, but swallow failures and defer hard errors
    until the first real query/aggregation.
    """

    def __init__(self):
        # Prefer SIEM_* envs; fall back to legacy OPENSEARCH_* if present
        url = (
            os.getenv("SIEM_URL")
            or os.getenv("OPENSEARCH_URL")
            or "https://localhost:9201"
        )
        user = os.getenv("SIEM_USER") or os.getenv("OPENSEARCH_USER") or "admin"
        pwd  = os.getenv("SIEM_PASS") or os.getenv("OPENSEARCH_PASS") or ""
        tls_result = resolve_ca_cert()
        timeout = float(os.getenv("SIEM_TIMEOUT_SECONDS", "20"))

        self._cfg = dict(url=url, user=user, pwd=pwd, tls_result=tls_result, timeout=timeout)
        self._mk_client()

        # Best-effort connectivity probe (non-fatal).
        try:
            info = self.os.info()
            ver  = info.get("version", {})
            p = urlparse(url)
            base = f"{p.scheme}://{p.hostname or 'localhost'}:{p.port or (443 if (p.scheme or 'https')=='https' else 80)}"
            dist = ver.get("distribution") or "elasticsearch"
            num  = ver.get("number")
            print(f"[siem] connected -> {dist} @ {base} (version={num})", flush=True)
        except Exception as e:
            # Defer failure until first real call
            print(f"[opensearch] WARN: connection check failed at init: {type(e).__name__}: {e}", flush=True)

    # ---------- internals ----------

    def _mk_client(self):
        url        = self._cfg["url"]
        user       = self._cfg["user"]
        pwd        = self._cfg["pwd"]
        tls_result = self._cfg["tls_result"]
        timeout    = self._cfg["timeout"]

        # resolve_ca_cert() returns str (PEM path), True (system bundle), or False (skip)
        if isinstance(tls_result, str):
            verify_certs = True
            ca_certs = tls_result
        elif tls_result is True:
            verify_certs = True
            ca_certs = None
        else:
            verify_certs = False
            ca_certs = None

        p = urlparse(url)
        host_cfg = {
            "host": p.hostname or "localhost",
            "port": p.port or (443 if (p.scheme or "https") == "https" else 80),
            "scheme": p.scheme or "https",
        }

        # opensearch-py's RequestsHttpConnection internally calls
        # certifi.where() even with verify_certs=False, and the certifi
        # bundle may be corrupt in PyInstaller builds.  Use
        # Urllib3HttpConnection instead -- it accepts ssl_context directly
        # and bypasses certifi entirely.
        import warnings
        warnings.filterwarnings("ignore", message=".*ssl_context.*SSL related kwargs.*")
        try:
            import urllib3 as _u3
            _u3.disable_warnings(_u3.exceptions.InsecureRequestWarning)
        except Exception:
            pass

        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        if not verify_certs:
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE
        elif ca_certs:
            ssl_ctx.load_verify_locations(ca_certs)
        # else: uses system trust store (default)

        self.os = OpenSearch(
            hosts=[host_cfg],
            http_auth=(user, pwd),
            use_ssl=(p.scheme == "https"),
            verify_certs=verify_certs,
            ssl_assert_hostname=verify_certs,
            ssl_show_warn=False,
            ssl_context=ssl_ctx,
            connection_class=Urllib3HttpConnection,
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
                print("[opensearch] transient connection error; recreating client and retrying once...", flush=True)
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
    ) -> list[dict] | dict | int:
        """
        Route KQL-ish text via query_string.

        When size == 0: returns {"total": <int>} (count-only) with filter_path.
        Otherwise: returns a list of docs (each doc is the _source dict), trimmed and capped.
        """
        # Hard cap result size (configurable via DETECTION_MAX_HITS)
        max_hits = int(os.getenv("DETECTION_MAX_HITS", "500"))
        if size is None:
            size = 200
        size = int(size)
        if size > 0:
            size = min(size, max_hits)

        if not size or size == 0:
            # COUNT-ONLY path: small & cheap
            body = {
                "query": {"query_string": {"query": kql, "default_operator": "AND"}},
                "size": 0,
                "track_total_hits": True,
                "_source": False,
                "stored_fields": "_none_",
                "timeout": "10s",
            }
            params = {"filter_path": "hits.total.value,hits.total"}
            resp = self._with_retry(self.os.search, index=index, body=body, params=params)
            total = (resp.get("hits", {}).get("total", 0) if isinstance(resp, dict) else 0)
            if isinstance(total, dict):
                total = total.get("value", 0)
            return {"total": int(total)}

        # DOC FETCH path: keep it lean
        body = {
            "query": {"query_string": {"query": kql, "default_operator": "AND"}},
            "size": size,
            "track_total_hits": False,                 # cheaper; we don't need exact totals here
            "_source": (DEFAULT_SOURCE_FIELDS if source else False),
            "sort": [{"@timestamp": {"order": "desc"}}],
            "terminate_after": 5000,                   # safety valve
            "timeout": "10s",
        }
        params = {"filter_path": "hits.hits._source"}  # strip metadata bloat

        resp = self._with_retry(self.os.search, index=index, body=body, params=params)
        hits = (((resp or {}).get("hits") or {}).get("hits") or [])
        # return _source dicts for compactness
        return [h.get("_source", {}) for h in hits]

    def aggregate(self, index: str, dsl: dict) -> dict:
        # Make sure we don't accidentally return hits for agg calls
        if "size" not in dsl:
            dsl["size"] = 0
        # avoid fetching _source when not needed
        dsl.setdefault("_source", False)
        dsl.setdefault("stored_fields", "_none_")

        params = {"filter_path": "aggregations"}
        resp = self._with_retry(self.os.search, index=index, body=dsl, params=params)
        return resp.get("aggregations", {}) or {}


# Back-compat alias so older code importing OSClient keeps working
OSClient = OpenSearchClient
