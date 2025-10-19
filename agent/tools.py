# agent/tools.py
from __future__ import annotations

from typing import Dict, Any
import os
import sys
from pathlib import Path

# --- Make this file work whether imported as `agent.*` or `tinysocs.agent.*`
HERE = Path(__file__).resolve()
REPO_ROOT = HERE.parents[1]  # .../tinysocs
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# Adapter + net util with robust fallbacks
try:
    # when installed/used as a package
    from tinysocs.agent.adapters.select import make_client  # type: ignore
except ModuleNotFoundError:
    # when running from source (python -m agent.main)
    from agent.adapters.select import make_client  # type: ignore

try:
    from tinysocs.netutil import is_loopback  # type: ignore
except ModuleNotFoundError:
    from netutil import is_loopback  # type: ignore

# --- Optional: import backend-specific exceptions (fallback to base Exception) ---
try:
    from opensearchpy.exceptions import (  # type: ignore
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


def search_kql(
    index: str,
    kql: str,
    size: int = 100,
    # tolerate extra kwargs some callers pass; adapters may ignore
    track_total_hits: bool | int | None = None,
    source: bool | None = None,
) -> Dict[str, Any]:
    """
    Run a simple KQL-like query. Never raises — returns a structured error on failure.
    Accepts optional pass-through args (track_total_hits/source) for adapter parity.
    """
    c = _client_or_make()
    try:
        # Prefer the newer signature if adapter supports it; fall back gracefully.
        try:
            docs = c.search_kql(
                index=index,
                kql=kql,
                size=size,
                track_total_hits=track_total_hits,
                source=source if source is not None else True,
            )
        except TypeError:
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