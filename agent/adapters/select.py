# tinysocs/agent/adapters/select.py
"""
Adapter selector for TinySocs — Golden config (OpenSearch-only).

We hard-select the OpenSearch client to avoid accidental drift or
undeclared dependencies. If Elasticsearch support returns in future,
reintroduce it behind a clear feature flag with CI coverage.
"""
from tinysocs.agent.adapters.opensearch_client import OpenSearchClient


def make_client() -> OpenSearchClient:
    return OpenSearchClient()
