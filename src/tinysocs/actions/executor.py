# tinysocs/actions/executor.py
"""
Action Execution Engine

Reads approved actions from the queue, validates, dispatches to handlers,
and maintains an audit trail. Actions default to dry_run=True and require
explicit operator approval via the /bot/approve API before execution.

States: staged -> approved -> executing -> completed | failed
"""

from __future__ import annotations

import json
import os
import time
import traceback
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

# ---------------------------------------------------------------------------
# Audit log path
# ---------------------------------------------------------------------------
_AUDIT_DIR = Path(os.getenv(
    "TINYSOCS_AUDIT_DIR",
    os.path.join(os.getenv("ProgramData", "/var/lib/tinysocs"), "TinySocs", "audit"),
))
AUDIT_LOG_PATH = _AUDIT_DIR / "actions_audit.jsonl"

# ---------------------------------------------------------------------------
# In-memory action store (backed by JSONL queue file)
# ---------------------------------------------------------------------------
_actions: Dict[str, Dict[str, Any]] = {}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _write_audit(entry: Dict[str, Any]) -> None:
    """Append an audit record to the JSONL audit log."""
    AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")


# ---------------------------------------------------------------------------
# Handler registry
# ---------------------------------------------------------------------------
_handlers: Dict[str, Callable[[Dict[str, Any], bool], Dict[str, Any]]] = {}


def register_handler(action_name: str, handler: Callable[[Dict[str, Any], bool], Dict[str, Any]]) -> None:
    """Register an action handler function.

    Handler signature: handler(params: dict, dry_run: bool) -> dict
    Must return {"success": bool, "detail": str, ...}
    """
    _handlers[action_name] = handler


# ---------------------------------------------------------------------------
# Core operations
# ---------------------------------------------------------------------------
def stage_action(
    action: str,
    params: Dict[str, Any],
    who: Optional[str] = None,
    dry_run: bool = True,
) -> Dict[str, Any]:
    """Stage an action for operator review.

    Returns the full action record including its generated action_id.
    """
    action_id = str(uuid.uuid4())[:12]
    record = {
        "action_id": action_id,
        "action": action,
        "params": params,
        "who": who or "system",
        "dry_run": dry_run,
        "status": "staged",
        "staged_at": _now(),
        "approved_at": None,
        "approved_by": None,
        "completed_at": None,
        "result": None,
    }
    _actions[action_id] = record

    _write_audit({
        "event": "action_staged",
        "action_id": action_id,
        "action": action,
        "params": params,
        "who": who,
        "dry_run": dry_run,
        "timestamp": _now(),
    })

    return record


def approve_action(action_id: str, approved_by: str = "operator") -> Dict[str, Any]:
    """Move an action from staged to approved, then execute it.

    Returns the updated action record after execution attempt.
    """
    record = _actions.get(action_id)
    if not record:
        raise ValueError(f"Action {action_id} not found")

    if record["status"] != "staged":
        raise ValueError(f"Action {action_id} is '{record['status']}', not 'staged'")

    record["status"] = "approved"
    record["approved_at"] = _now()
    record["approved_by"] = approved_by

    _write_audit({
        "event": "action_approved",
        "action_id": action_id,
        "approved_by": approved_by,
        "timestamp": _now(),
    })

    # Execute immediately after approval
    return execute_action(action_id)


def execute_action(action_id: str) -> Dict[str, Any]:
    """Execute an approved action via its registered handler."""
    record = _actions.get(action_id)
    if not record:
        raise ValueError(f"Action {action_id} not found")

    if record["status"] not in ("approved",):
        raise ValueError(f"Action {action_id} is '{record['status']}', expected 'approved'")

    handler = _handlers.get(record["action"])
    if not handler:
        record["status"] = "failed"
        record["completed_at"] = _now()
        record["result"] = {"success": False, "detail": f"No handler for action '{record['action']}'"}
        _write_audit({
            "event": "action_failed",
            "action_id": action_id,
            "reason": "no_handler",
            "timestamp": _now(),
        })
        return record

    record["status"] = "executing"
    _write_audit({
        "event": "action_executing",
        "action_id": action_id,
        "dry_run": record["dry_run"],
        "timestamp": _now(),
    })

    try:
        result = handler(record["params"], record["dry_run"])
        record["result"] = result
        record["status"] = "completed" if result.get("success") else "failed"
    except Exception as exc:
        record["result"] = {
            "success": False,
            "detail": f"{type(exc).__name__}: {exc}",
            "traceback": traceback.format_exc(),
        }
        record["status"] = "failed"

    record["completed_at"] = _now()

    _write_audit({
        "event": f"action_{record['status']}",
        "action_id": action_id,
        "action": record["action"],
        "params": record["params"],
        "dry_run": record["dry_run"],
        "result": record["result"],
        "who": record["who"],
        "approved_by": record.get("approved_by"),
        "timestamp": _now(),
    })

    return record


def get_action(action_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve a single action by ID."""
    return _actions.get(action_id)


def list_actions(
    status: Optional[str] = None,
    action: Optional[str] = None,
    limit: int = 50,
) -> List[Dict[str, Any]]:
    """List actions, optionally filtered by status or action type. Newest first."""
    items = list(_actions.values())

    if status:
        items = [a for a in items if a["status"] == status]
    if action:
        items = [a for a in items if a["action"] == action]

    # Sort by staged_at descending
    items.sort(key=lambda a: a.get("staged_at", ""), reverse=True)
    return items[:limit]


# ---------------------------------------------------------------------------
# Bootstrap: register built-in handlers
# ---------------------------------------------------------------------------
def _register_builtin_handlers() -> None:
    """Auto-register the built-in action handlers."""
    try:
        from tinysocs.actions.handlers.block_ip import handle_block_ip
        register_handler("block_ip", handle_block_ip)
    except ImportError:
        pass

    try:
        from tinysocs.actions.handlers.disable_user import handle_disable_user
        register_handler("disable_user", handle_disable_user)
    except ImportError:
        pass

    try:
        from tinysocs.actions.handlers.isolate_host import handle_isolate_host
        register_handler("isolate_host", handle_isolate_host)
    except ImportError:
        pass


_register_builtin_handlers()
