# agent/adapters/select.py
import os
from .elastic_client import ElasticClient

def make_client():
    backend = os.getenv("SIEM_BACKEND", "elastic").lower()
    if backend in ("opensearch", "os", "open"):
        from .opensearch_client import OpenSearchClient
        return OpenSearchClient()
    return ElasticClient()