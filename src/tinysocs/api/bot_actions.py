# tinysocs/api/bot_actions.py
from __future__ import annotations

import os
from typing import Any, Dict, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from tinysocs.agent.actions_queue import stage_actions
from tinysocs.api.auth import make_verify_hmac

router = APIRouter(prefix="/bot", tags=["bot"])

# Keep the action surface tiny & safe
ALLOWED_ACTIONS: set[str] = {
    "ack_incident", "open_ticket", "disable_user", "isolate_host", "block_ip"
}

# --- HMAC verification (centralized, with timestamp + replay protection) ---
_bot_secret = os.getenv("BOT_SHARED_SECRET", "")
if not _bot_secret:
    import sys as _sys
    print("[bot_actions] FATAL: BOT_SHARED_SECRET must be set.", file=_sys.stderr, flush=True)
    _sys.exit(1)

verify_hmac = make_verify_hmac(_bot_secret)


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
