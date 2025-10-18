# tinysocs/agent/adapters/elastic_client.py
from __future__ import annotations

import os
import typing as t

import httpx

# ---- Env helpers (supports both new SIEM_* and legacy ELASTIC_* names) ----
def _env_bool(name: str, default: bool = False) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return str(v).strip().lower() in ("1", "true", "yes", "on")

def _env_first(*names: str, default: str | None = None) -> str | None:
    for n in names:
        v = os.getenv(n)
        if v:
            return v
    return default

# Connection settings (prefer SIEM_*; fall back to ELASTIC_*)
BASE_URL      = _env_first("SIEM_URL", "ELASTIC_URL", default="http://localhost:9200")
USER          = _env_first("SIEM_USER", "ELASTIC_USER", default="")
PASS          = _env_first("SIEM_PASS", "ELASTIC_PASS", default="")
VERIFY_SSL    = _env_bool("SIEM_SSL_VERIFY", default=_env_bool("ELASTIC_VERIFY_SSL", default=False))
DEFAULT_INDEX = _env_first("SIEM_DEFAULT_INDEX", "DEFAULT_INDEX", default="winlogbeat-*")
TIMEOUT_S     = int(_env_first("SIEM_TIMEOUT_SECONDS", "ELASTIC_TIMEOUT_SECONDS", default="10") or "10")

def _auth_tuple() -> t.Optional[tuple[str, str]]:
    if USER and PASS:
        return (USER, PASS)
    return None

# ----------------------------------------------------------------------------

class ElasticClient:
    """
    Minimal REST adapter for Elasticsearch/OpenSearch that matches the surface
    used elsewhere in TinySOCS.

    Methods:
      - search_kql(index, kql, size=100, *, track_total_hits=False, source=True)
      - aggregate(index, dsl) -> dict
      - index_doc(index, doc) -> dict
    """

    def __init__(
        self,
        base_url: str | None = None,
        default_index: str | None = None,
        auth: tuple[str, str] | None = None,
        timeout: int = TIMEOUT_S,
        verify: bool | None = None,
    ):
        self.base_url = (base_url or BASE_URL).rstrip("/")
        self.default_index = default_index or DEFAULT_INDEX
        self.auth = auth if auth is not None else _auth_tuple()
        self.timeout = timeout
        self.verify = VERIFY_SSL if verify is None else verify

        # HTTP client: disable keep-alive, set explicit timeouts, honor TLS verify
        self.http = httpx.Client(
            verify=self.verify,
            timeout=httpx.Timeout(timeout, connect=5.0, read=timeout, write=timeout),
            limits=httpx.Limits(max_keepalive_connections=0, max_connections=10),
            headers={"Connection": "close"},
            auth=self.auth,
        )

    def _index(self, index: str | None) -> str:
        return index or self.default_index

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
        Route simplified “KQL-like” text through query_string.
        For our rules (field:value AND field2:value) it works on ES & OS.

        When size == 0: returns {"total": <int>} (count-only).
        Otherwise: returns a list of _source dicts.
        """
        body: dict = {
            "query": {"query_string": {"query": kql}},
            "size": int(size),
            "track_total_hits": bool(track_total_hits),
            "_source": bool(source),
        }
        if size and size > 0:
            body["sort"] = [{"@timestamp": {"order": "desc"}}]

        url = f"{self.base_url}/{self._index(index)}/_search"
        r = self.http.post(url, json=body)
        r.raise_for_status()
        j = r.json()

        if not size or size == 0:
            total = j.get("hits", {}).get("total", 0)
            if isinstance(total, dict):
                total = total.get("value", 0)
            return {"total": int(total)}

        hits = j.get("hits", {}).get("hits", [])
        return [h.get("_source", {}) for h in hits]

    def aggregate(self, index: str, dsl: dict) -> dict:
        """
        Accept a full ES/OS DSL with aggs; return the 'aggregations' node (or {}).
        """
        url = f"{self.base_url}/{self._index(index)}/_search"
        r = self.http.post(url, json=dsl)
        r.raise_for_status()
        return r.json().get("aggregations", {}) or {}

    def index_doc(self, index: str, doc: dict) -> dict:
        """
        Index a single document into the target index.
        """
        url = f"{self.base_url}/{self._index(index)}/_doc"
        r = self.http.post(url, json=doc)
        r.raise_for_status()
        return r.json()