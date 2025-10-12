# adapters/opensearch_client.py
import os
import typing as t

try:
    from opensearchpy import OpenSearch
except ImportError:  # guard if someone forgets to install it
    OpenSearch = None

# Optional normalizer to keep our docs flatish across backends.
def _flatten_doc(d: dict, parent: str = "", out: dict | None = None) -> dict:
    if out is None:
        out = {}
    for k, v in (d or {}).items():
        key = f"{parent}.{k}" if parent else k
        if isinstance(v, dict):
            _flatten_doc(v, key, out)
        else:
            out[key] = v
    return out

OS_URL   = os.getenv("OPENSEARCH_URL", "http://localhost:9201")
OS_USER  = os.getenv("OPENSEARCH_USER", "admin")
OS_PASS  = os.getenv("OPENSEARCH_PASS", "admin")
VERIFY   = os.getenv("OPENSEARCH_VERIFY_SSL", "false").lower() == "true"
TIMEOUT  = int(os.getenv("SIEM_TIMEOUT_SECONDS", "10"))

class OpenSearchClient:
    """Adapter mirroring ElasticClient: search_kql() and aggregate()."""
    def __init__(self):
        if OpenSearch is None:
            raise RuntimeError("opensearch-py not installed. pip install opensearch-py")
        self.os = OpenSearch(
            hosts=[OS_URL],
            http_auth=(OS_USER, OS_PASS) if OS_USER else None,
            use_ssl=OS_URL.startswith("https"),
            verify_certs=VERIFY,
            ssl_assert_hostname=False,
            ssl_show_warn=False,
            timeout=TIMEOUT,
        )

    def search_kql(self, index: str, kql: str, size: int = 100) -> t.List[dict]:
        """
        We route 'KQL-like' expressions via query_string. For our simple rules
        (field:value AND field2:value), this is good enough across ES/OS.
        """
        body = {
            "query": {"query_string": {"query": kql}},
            "size": size,
            "_source": True,
            "sort": [{"@timestamp": {"order": "desc"}}],
        }
        resp = self.os.search(index=index, body=body)
        hits = [h.get("_source", {}) for h in resp.get("hits", {}).get("hits", [])]
        # shape to match our engine’s expectations
        return hits

    def aggregate(self, index: str, dsl: dict) -> dict:
        resp = self.os.search(index=index, body=dsl)
        return resp.get("aggregations", {}) or {}
