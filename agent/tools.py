# agent/tools.py
from typing import Dict, Any
from adapters.select import make_client
from netutil import is_loopback

_client = None
def _client_or_make():
    global _client
    if _client is None:
        _client = make_client()
    return _client

def search_kql(index: str, kql: str, size: int = 100) -> Dict[str, Any]:
    c = _client_or_make()
    docs = c.search_kql(index=index, kql=kql, size=size)
    return {"ok": True, "hits": docs[:size], "count": len(docs)}

def aggregate(index: str, dsl: Dict[str, Any]) -> Dict[str, Any]:
    c = _client_or_make()
    res = c.aggregate(index=index, dsl=dsl)
    return {"ok": True, "result": res}

def propose_rule(rule_id: str, query: str, schedule: str = "15m") -> Dict[str, Any]:
    return {
        "ok": True,
        "proposal": {
            "id": rule_id, "query": query, "schedule": schedule,
            "note": "Design-only; not installed"
        }
    }

def stage_action(action: str, params: Dict[str, Any]) -> Dict[str, Any]:
    # Guard rails: never block loopback
    if action == "block_ip":
        ip = (params or {}).get("ip")
        if ip and is_loopback(ip):
            return {"ok": False, "reason": "Refusing to block loopback address", "params": params}
    # Dry-run acknowledgment; actual queuing happens in main via actions_queue
    return {"ok": True, "staged": True, "action": action, "params": params}
