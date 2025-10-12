# adapters/elastic_client.py
import os
import typing as t
import httpx

ELASTIC_URL   = os.getenv("ELASTIC_URL", "http://localhost:9200")
ELASTIC_USER  = os.getenv("ELASTIC_USER", "")           # optional
ELASTIC_PASS  = os.getenv("ELASTIC_PASS", "")           # optional
DEFAULT_INDEX = os.getenv("DEFAULT_INDEX", "winlogbeat-*")
VERIFY_SSL    = os.getenv("ELASTIC_VERIFY_SSL", "false").lower() == "true"
TIMEOUT_S     = int(os.getenv("SIEM_TIMEOUT_SECONDS", "10"))

def _auth() -> t.Optional[tuple[str, str]]:
    if ELASTIC_USER and ELASTIC_PASS:
        return (ELASTIC_USER, ELASTIC_PASS)
    return None

class ElasticClient:
    """
    Minimal REST adapter for Elasticsearch 8.x that matches our OpenSearch adapter surface.
    Methods:
      - search_kql(index, kql, size=100) -> List[dict]
      - aggregate(index, dsl) -> dict
    """
    def __init__(
        self,
        base_url: str | None = None,
        default_index: str | None = None,
        auth: tuple[str, str] | None = None,
        timeout: int = TIMEOUT_S,
    ):
        self.base_url = (base_url or ELASTIC_URL).rstrip("/")
        self.default_index = default_index or DEFAULT_INDEX
        self.auth = auth if auth is not None else _auth()
        self.timeout = timeout

        # One client per instance; HTTP/1.1 keep-alive is fine here
        self.http = httpx.Client(
            timeout=self.timeout,
            verify=VERIFY_SSL,
            auth=self.auth,
        )

    def _index(self, index: str | None) -> str:
        return index or self.default_index

    def search_kql(self, index: str, kql: str, size: int = 100) -> t.List[dict]:
        """
        We route simplified “KQL-like” text through query_string.
        For our rules (field:value AND field2:value), this works on ES & OS.
        """
        body = {
            "query": {"query_string": {"query": kql}},
            "size": size,
            "_source": True,
            "sort": [{"@timestamp": {"order": "desc"}}],
        }
        url = f"{self.base_url}/{self._index(index)}/_search"
        r = self.http.post(url, json=body)
        r.raise_for_status()
        hits = r.json().get("hits", {}).get("hits", [])
        return [h.get("_source", {}) for h in hits]

    def aggregate(self, index: str, dsl: dict) -> dict:
        """
        Accept a full ES DSL with aggs; we return just the aggregations node.
        """
        url = f"{self.base_url}/{self._index(index)}/_search"
        r = self.http.post(url, json=dsl)
        r.raise_for_status()
        return r.json().get("aggregations", {}) or {}
