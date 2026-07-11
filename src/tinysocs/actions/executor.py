# tinysocs/actions/executor.py
"""
Guided Response Engine

Manages operator-facing response recommendations. TinySocs detects and advises
but never executes invasive actions on hosts or networks. The operator reviews
recommendations, acknowledges or dismisses them, and manually carries out any
remediation steps using the provided runbook guidance.

States: staged -> acknowledged  (operator will handle it)
        staged -> dismissed     (false positive / not applicable)
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Audit log path
# ---------------------------------------------------------------------------
_AUDIT_DIR = Path(os.getenv(
    "TINYSOCS_AUDIT_DIR",
    os.path.join(os.getenv("ProgramData", "/var/lib/tinysocs"), "TinySocs", "audit"),
))
AUDIT_LOG_PATH = _AUDIT_DIR / "actions_audit.jsonl"

# ---------------------------------------------------------------------------
# In-memory action store
# ---------------------------------------------------------------------------
_actions: dict[str, dict[str, Any]] = {}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _write_audit(entry: dict[str, Any]) -> None:
    """Append an audit record to the JSONL audit log."""
    AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")


# ---------------------------------------------------------------------------
# Runbook templates — step-by-step guidance for each recommendation type
# ---------------------------------------------------------------------------
_RUNBOOKS: dict[str, list[str]] = {
    "block_ip": [
        "Verify the IP {ip} is genuinely malicious (check threat intel, VirusTotal, AbuseIPDB)",
        "Open Windows Firewall (wf.msc) or your network firewall admin console",
        "Create an inbound deny rule for {ip}",
        "Create an outbound deny rule for {ip}",
        "Monitor for continued connection attempts from {ip} in Event Explorer",
        "Document the block in your incident log with the reason: {reason}",
    ],
    "isolate_host": [
        "Confirm the host {host} is compromised (review alert details and matched events)",
        "Notify the user of {host} that their machine is under investigation",
        "Disconnect {host} from the network (unplug cable or disable Wi-Fi adapter)",
        "If remote: use Windows Firewall to block all outbound except SIEM — run:",
        '  netsh advfirewall firewall add rule name="TinySocs-Isolate-AllowSIEM" dir=out action=allow remoteip=<SIEM_IP>',
        '  netsh advfirewall firewall add rule name="TinySocs-Isolate-DenyAll" dir=out action=block remoteip=any',
        "Begin forensic triage on {host} (collect logs, memory dump, check persistence)",
        "Document isolation in your incident log: {reason}",
    ],
    "disable_user": [
        "Verify the user account '{user}' is genuinely compromised",
        "Check if '{user}' is a service account — disabling it may cause outages",
        "Disable the account: net user {user} /active:no",
        "Force logoff any active sessions for '{user}'",
        "Reset the password for '{user}' before re-enabling",
        "Review recent activity for '{user}' in Event Explorer (winlog.event_id:4624 AND winlog.TargetUserName:{user})",
        "Document the action in your incident log: {reason}",
    ],
    "open_ticket": [
        "Create a ticket in your ITSM/ticketing system",
        "Include the alert details: {reason}",
        "Assign to the appropriate team for investigation",
        "Link this TinySocs alert ID for reference",
    ],
}

_DEFAULT_RUNBOOK = [
    "Review the alert details and matched events in the dashboard",
    "Assess the severity and determine if this requires immediate action",
    "Follow your organisation's incident response playbook",
    "Document your findings and actions taken",
]


def _build_runbook(action: str, params: dict[str, Any]) -> list[str]:
    """Generate runbook steps for a given action type, interpolating parameters."""
    template = _RUNBOOKS.get(action, _DEFAULT_RUNBOOK)
    steps = []
    for step in template:
        try:
            steps.append(step.format(**params))
        except (KeyError, IndexError):
            steps.append(step)
    return steps


# ---------------------------------------------------------------------------
# Core operations
# ---------------------------------------------------------------------------
def stage_action(
    action: str,
    params: dict[str, Any],
    who: str | None = None,
    dry_run: bool = True,
) -> dict[str, Any]:
    """Stage a guided response recommendation for operator review.

    Returns the full record including its generated action_id and runbook steps.
    """
    action_id = str(uuid.uuid4())[:12]
    runbook = _build_runbook(action, params)
    record = {
        "action_id": action_id,
        "action": action,
        "params": params,
        "who": who or "system",
        "status": "staged",
        "runbook": runbook,
        "staged_at": _now(),
        "resolved_at": None,
        "resolved_by": None,
        "resolution": None,
    }
    _actions[action_id] = record

    _write_audit({
        "event": "response_staged",
        "action_id": action_id,
        "action": action,
        "params": params,
        "who": who,
        "runbook_steps": len(runbook),
        "timestamp": _now(),
    })

    return record


def approve_action(action_id: str, approved_by: str = "operator") -> dict[str, Any]:
    """Acknowledge a staged recommendation — operator will handle it manually.

    This does NOT execute anything. It records the operator's acknowledgement
    and provides the runbook steps for manual remediation.
    """
    record = _actions.get(action_id)
    if not record:
        raise ValueError(f"Action {action_id} not found")

    if record["status"] != "staged":
        raise ValueError(f"Action {action_id} is '{record['status']}', not 'staged'")

    record["status"] = "acknowledged"
    record["resolved_at"] = _now()
    record["resolved_by"] = approved_by
    record["resolution"] = "Operator acknowledged — manual remediation in progress"

    _write_audit({
        "event": "response_acknowledged",
        "action_id": action_id,
        "resolved_by": approved_by,
        "timestamp": _now(),
    })

    return record


def reject_action(action_id: str, rejected_by: str = "operator", reason: str = "") -> dict[str, Any]:
    """Dismiss a staged recommendation — false positive or not applicable.

    Returns the updated record.
    """
    record = _actions.get(action_id)
    if not record:
        raise ValueError(f"Action {action_id} not found")

    if record["status"] != "staged":
        raise ValueError(f"Action {action_id} is '{record['status']}', not 'staged'")

    record["status"] = "dismissed"
    record["resolved_at"] = _now()
    record["resolved_by"] = rejected_by
    record["resolution"] = f"Dismissed by {rejected_by}" + (f": {reason}" if reason else "")

    _write_audit({
        "event": "response_dismissed",
        "action_id": action_id,
        "resolved_by": rejected_by,
        "reason": reason,
        "timestamp": _now(),
    })

    return record


def get_action(action_id: str) -> dict[str, Any] | None:
    """Retrieve a single recommendation by ID."""
    return _actions.get(action_id)


def list_actions(
    status: str | None = None,
    action: str | None = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """List recommendations, optionally filtered by status or type. Newest first."""
    items = list(_actions.values())

    if status:
        items = [a for a in items if a["status"] == status]
    if action:
        items = [a for a in items if a["action"] == action]

    # Sort by staged_at descending
    items.sort(key=lambda a: a.get("staged_at", ""), reverse=True)
    return items[:limit]
