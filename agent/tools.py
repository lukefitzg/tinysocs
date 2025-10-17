# agent/tools.py
from typing import Dict, Any
from tinysocs.agent.adapters.select import make_client
from netutil import is_loopback
import os

# --- Optional: import backend-specific exceptions (fallback to base Exception) ---
try:
    from opensearchpy.exceptions import (
        NotFoundError as OSNotFoundError,
        ConnectionTimeout as OSConnectionTimeout,
        ConnectionError as OSConnectionError,
    )
except Exception:  # opensearch-py may not be installed
    OSNotFoundError = OSConnectionTimeout = OSConnectionError = Exception

try:
    # Elasticsearch 8.x
    from elasticsearch import NotFoundError as ESNotFoundError  # type: ignore
except Exception:
    ESNotFoundError = Exception

_client = None


def _client_or_make():
    global _client
    if _client is None:
        _client = make_client()
    return _client


def _backend_name() -> str:
    return (os.getenv("SIEM_BACKEND") or "").lower() or "unknown"


def search_kql(index: str, kql: str, size: int = 100) -> Dict[str, Any]:
    """
    Run a simple KQL-like query. Never raises — returns a structured error on failure.
    """
    c = _client_or_make()
    try:
        docs = c.search_kql(index=index, kql=kql, size=size)
        return {
            "ok": True,
            "hits": (docs or [])[:size],
            "count": len(docs or []),
            "index": index,
            "backend": _backend_name(),
        }
    except (OSNotFoundError, ESNotFoundError) as e:
        return {
            "ok": False,
            "error": "index_not_found",
            "index": index,
            "message": str(e),
            "backend": _backend_name(),
            "retry_hint": "Use an existing index pattern (e.g., winlogbeat-*)",
        }
    except (OSConnectionTimeout, OSConnectionError) as e:
        return {
            "ok": False,
            "error": "connection_error",
            "index": index,
            "message": str(e),
            "backend": _backend_name(),
            "retry_hint": "Check container health and SIEM_URL/credentials",
        }
    except Exception as e:
        return {
            "ok": False,
            "error": type(e).__name__,
            "index": index,
            "message": str(e),
            "backend": _backend_name(),
        }


def aggregate(index: str, dsl: Dict[str, Any]) -> Dict[str, Any]:
    """
    Run a raw DSL aggregation. Never raises — returns structured error on failure.
    """
    c = _client_or_make()
    try:
        res = c.aggregate(index=index, dsl=dsl) or {}
        return {
            "ok": True,
            "result": res,            # keep original shape
            "aggregations": res,      # convenience alias many LLMs expect
            "index": index,
            "backend": _backend_name(),
        }
    except (OSNotFoundError, ESNotFoundError) as e:
        return {
            "ok": False,
            "error": "index_not_found",
            "index": index,
            "message": str(e),
            "backend": _backend_name(),
            "retry_hint": "Use an existing index pattern (e.g., winlogbeat-*)",
        }
    except (OSConnectionTimeout, OSConnectionError) as e:
        return {
            "ok": False,
            "error": "connection_error",
            "index": index,
            "message": str(e),
            "backend": _backend_name(),
            "retry_hint": "Check container health and SIEM_URL/credentials",
        }
    except Exception as e:
        return {
            "ok": False,
            "error": type(e).__name__,
            "index": index,
            "message": str(e),
            "backend": _backend_name(),
        }


def propose_rule(rule_id: str, query: str, schedule: str = "15m") -> Dict[str, Any]:
    return {
        "ok": True,
        "proposal": {
            "id": rule_id,
            "query": query,
            "schedule": schedule,
            "note": "Design-only; not installed",
        },
    }


def stage_action(action: str, params: Dict[str, Any]) -> Dict[str, Any]:
    # Guard rails: never block loopback
    if action == "block_ip":
        ip = (params or {}).get("ip")
        if ip and is_loopback(ip):
            return {
                "ok": False,
                "reason": "Refusing to block loopback address",
                "params": params,
            }
    # Dry-run acknowledgment; actual queuing happens in main via actions_queue
    return {"ok": True, "staged": True, "action": action, "params": params}
