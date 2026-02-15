# tinysocs/actions/handlers/disable_user.py
"""
Handler: disable_user

Disables a Windows local account using `net user /active:no`.
Falls back to PowerShell `Disable-LocalUser` if available.

Params:
    user (str): The username to disable.

Dry-run: Logs what would happen without disabling the account.
"""

from __future__ import annotations

import subprocess
from typing import Any, Dict


# Protected accounts that must never be disabled
_PROTECTED_USERS = frozenset({
    "administrator", "system", "local service", "network service",
    "defaultaccount", "wdagutilityaccount",
})


def handle_disable_user(params: Dict[str, Any], dry_run: bool) -> Dict[str, Any]:
    user = str(params.get("user", "")).strip()
    if not user:
        return {"success": False, "detail": "Missing 'user' parameter"}

    if user.lower() in _PROTECTED_USERS:
        return {"success": False, "detail": f"Refusing to disable protected account: {user}"}

    if dry_run:
        return {
            "success": True,
            "detail": f"DRY RUN: Would disable user account '{user}'",
            "dry_run": True,
            "commands": [f"net user {user} /active:no"],
        }

    # Try net user first (works on all Windows)
    cmd = ["net", "user", user, "/active:no"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if proc.returncode == 0:
            return {
                "success": True,
                "detail": f"Disabled user '{user}' via net user",
                "stdout": proc.stdout.strip(),
            }
    except Exception:
        pass

    # Fallback: PowerShell Disable-LocalUser
    ps_cmd = ["powershell", "-NoProfile", "-Command", f"Disable-LocalUser -Name '{user}'"]
    try:
        proc = subprocess.run(ps_cmd, capture_output=True, text=True, timeout=30)
        if proc.returncode == 0:
            return {
                "success": True,
                "detail": f"Disabled user '{user}' via Disable-LocalUser",
                "stdout": proc.stdout.strip(),
            }
        return {
            "success": False,
            "detail": f"Failed to disable user '{user}'",
            "returncode": proc.returncode,
            "stderr": proc.stderr.strip(),
        }
    except Exception as exc:
        return {
            "success": False,
            "detail": f"Exception disabling user '{user}': {type(exc).__name__}: {exc}",
        }
