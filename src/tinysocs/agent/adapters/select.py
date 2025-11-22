# tinysocs/agent/adapters/select.py
"""
Adapter selector for TinySocs â€” Golden config (OpenSearch-only).

We hard-select the OpenSearch client to avoid accidental drift or
undeclared dependencies. If Elasticsearch support returns in future,
reintroduce it behind a clear feature flag with CI coverage.
"""
# Prefer intra-package relative; fall back to flat or shimmed absolute if needed.
try:
    from .opensearch_client import OpenSearchClient  # namespace/regular package relative
except Exception:
    try:
        from tinysocs.agent.adapters.opensearch_client import OpenSearchClient  # flat tree
    except Exception:
        from tinysocs.agent.adapters.opensearch_client import OpenSearchClient  # shimmed

def make_client() -> OpenSearchClient:
    return OpenSearchClient()
