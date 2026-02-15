# tinysocs/api/bot_actions.py
from __future__ import annotations

import hashlib
import hmac
import os
from typing import Any, Dict, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from tinysocs.agent.actions_queue import stage_actions

router = APIRouter(prefix="/bot", tags=["bot"])

# Keep the action surface tiny & safe
ALLOWED_ACTIONS: set[str] = {
    "ack_incident", "open_ticket", "disable_user", "isolate_host", "block_ip"
}

# --- HMAC verification (accept ts OR ts|nonce OR ts.nonce; raw or 'sha256=' prefix) ---
def _consteq(a: str, b: str) -> bool:
    try:  # constant-time compare
        return hmac.compare_digest(a, b)
    except Exception:
        return a == b

def _normalize_sig(sig: str) -> str:
    sig = sig.strip()
    if sig.lower().startswith("sha256="):
        sig = sig.split("=", 1)[1]
    return sig

def _calc_mac(secret: str, msg: str) -> str:
    return hmac.new(secret.encode("utf-8"), msg.encode("utf-8"), hashlib.sha256).hexdigest()

def verify_hmac(request: Request) -> None:
    secret = os.getenv("BOT_SHARED_SECRET", "")
    if not secret:
        raise HTTPException(status_code=503, detail="BOT_SHARED_SECRET not set")

    ts = request.headers.get("X-TinySOCS-Timestamp")
    if not ts:
        raise HTTPException(status_code=401, detail="missing timestamp")

    nonce = request.headers.get("X-TinySOCS-Nonce", "")
    provided = request.headers.get("X-TinySOCS-Signature") or ""
    provided = _normalize_sig(provided)

    # Accept any of the three message shapes
    candidates = [ts]
    if nonce:
        candidates.append(f"{ts}|{nonce}")
        candidates.append(f"{ts}.{nonce}")

    for msg in candidates:
        if _consteq(_calc_mac(secret, msg), provided):
            return

    raise HTTPException(status_code=401, detail="bad signature")


def write_action(
    action: str,
    params: Dict[str, Any],
    actor: str = "system",
    dry_run: bool = True,
) -> Dict[str, Any]:
    """Write an action to both the legacy JSONL queue and the new executor."""
    import time
    import uuid

    action_id = str(uuid.uuid4())[:12]
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    entry = {
        "action_id": action_id,
        "timestamp": ts,
        "action": action,
        "params": params,
        "who": actor,
        "dry_run": dry_run,
        "status": "staged",
    }

    # Write to legacy JSONL queue
    stage_actions([entry])

    # Also stage in executor for approval workflow (Phase 12)
    try:
        from tinysocs.actions.executor import stage_action
        stage_action(action=action, params=params, who=actor, dry_run=dry_run)
    except ImportError:
        pass

    return entry


# --- Models ---
class ExecBody(BaseModel):
    action: Literal["ack_incident","open_ticket","disable_user","isolate_host","block_ip"]
    params: Dict[str, Any] = Field(default_factory=dict)
    # optional human context
    tldr: Optional[str] = None
    incident_id: Optional[str] = None
    dry_run: bool = True

@router.post("/exec")
async def bot_exec(body: ExecBody, _: None = Depends(verify_hmac)):
    if body.action not in ALLOWED_ACTIONS:
        raise HTTPException(status_code=400, detail="action not allowed")

    # guardrails examples (cheap loopback checks)
    if body.action == "block_ip":
        ip = (body.params or {}).get("ip") or ""
        if ip.startswith("127.") or ip in ("::1","localhost"):
            raise HTTPException(status_code=400, detail="refusing to block loopback")

    # enrich minimal context into params for the operator runner
    params = dict(body.params or {})
    if body.tldr:        params["tldr"] = body.tldr
    if body.incident_id: params["incident_id"] = body.incident_id

    entry = write_action(action=body.action, params=params, actor="chat-bot", dry_run=body.dry_run)
    return {"queued": True, "action_id": entry["action_id"], "dry_run": entry["dry_run"]}
