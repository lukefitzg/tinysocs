# tinysocs/actions/handlers/isolate_host.py
"""
Handler: isolate_host

Creates an outbound deny-all Windows Firewall rule with an exception
for the SIEM endpoint (so the agent can still report).

Params:
    host (str): The hostname being isolated (for labeling/audit).
    siem_ip (str, optional): SIEM IP to exempt. Defaults to 127.0.0.1.

Dry-run: Logs what would happen without creating firewall rules.
"""

from __future__ import annotations

import os
import subprocess
from typing import Any, Dict


def handle_isolate_host(params: Dict[str, Any], dry_run: bool) -> Dict[str, Any]:
    host = str(params.get("host", "")).strip()
    if not host:
        return {"success": False, "detail": "Missing 'host' parameter"}

    siem_ip = str(params.get("siem_ip", "")).strip()
    if not siem_ip:
        # Derive from SIEM_URL or default
        siem_url = os.getenv("SIEM_URL", "https://127.0.0.1:9201")
        # Extract IP/host from URL
        try:
            from urllib.parse import urlparse
            parsed = urlparse(siem_url)
            siem_ip = parsed.hostname or "127.0.0.1"
        except Exception:
            siem_ip = "127.0.0.1"

    rule_deny = "TinySocs-Isolate-DenyAll-Out"
    rule_allow = "TinySocs-Isolate-AllowSIEM-Out"

    if dry_run:
        return {
            "success": True,
            "detail": f"DRY RUN: Would isolate host '{host}' — deny all outbound except SIEM ({siem_ip})",
            "dry_run": True,
            "commands": [
                f"netsh advfirewall firewall add rule name=\"{rule_allow}\" dir=out action=allow remoteip={siem_ip}",
                f"netsh advfirewall firewall add rule name=\"{rule_deny}\" dir=out action=block remoteip=any",
            ],
        }

    results = []

    # Step 1: Allow SIEM traffic (must be added first — rules are evaluated in order)
    cmd_allow = [
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={rule_allow}",
        "dir=out", "action=allow",
        f"remoteip={siem_ip}",
    ]
    try:
        proc = subprocess.run(cmd_allow, capture_output=True, text=True, timeout=30)
        results.append({
            "rule": rule_allow,
            "returncode": proc.returncode,
            "stdout": proc.stdout.strip(),
            "stderr": proc.stderr.strip(),
        })
    except Exception as exc:
        results.append({"rule": rule_allow, "error": str(exc)})

    # Step 2: Block all other outbound
    cmd_deny = [
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={rule_deny}",
        "dir=out", "action=block",
        "remoteip=any",
    ]
    try:
        proc = subprocess.run(cmd_deny, capture_output=True, text=True, timeout=30)
        results.append({
            "rule": rule_deny,
            "returncode": proc.returncode,
            "stdout": proc.stdout.strip(),
            "stderr": proc.stderr.strip(),
        })
    except Exception as exc:
        results.append({"rule": rule_deny, "error": str(exc)})

    all_ok = all(r.get("returncode") == 0 for r in results)
    return {
        "success": all_ok,
        "detail": f"Host isolation {'applied' if all_ok else 'partially failed'} for '{host}' (SIEM exempt: {siem_ip})",
        "results": results,
    }
