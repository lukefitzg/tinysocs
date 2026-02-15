# tinysocs/actions/handlers/block_ip.py
"""
Handler: block_ip

Adds a Windows Firewall inbound+outbound deny rule for a given IP address
using `netsh advfirewall firewall`.

Params:
    ip (str): The IP address to block.

Dry-run: Logs what would happen without creating any firewall rule.
"""

from __future__ import annotations

import ipaddress
import subprocess
from typing import Any, Dict


def handle_block_ip(params: Dict[str, Any], dry_run: bool) -> Dict[str, Any]:
    ip = str(params.get("ip", "")).strip()
    if not ip:
        return {"success": False, "detail": "Missing 'ip' parameter"}

    # Validate IP format
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return {"success": False, "detail": f"Invalid IP address: {ip}"}

    if ip_obj.is_loopback:
        return {"success": False, "detail": "Refusing to block loopback address"}

    if ip_obj.is_private:
        # Warn but allow — operator may want to block internal lateral movement
        pass

    rule_name_in = f"TinySocs-Block-{ip}-In"
    rule_name_out = f"TinySocs-Block-{ip}-Out"

    if dry_run:
        return {
            "success": True,
            "detail": f"DRY RUN: Would create firewall rules '{rule_name_in}' and '{rule_name_out}' blocking {ip}",
            "dry_run": True,
            "commands": [
                f"netsh advfirewall firewall add rule name=\"{rule_name_in}\" dir=in action=block remoteip={ip}",
                f"netsh advfirewall firewall add rule name=\"{rule_name_out}\" dir=out action=block remoteip={ip}",
            ],
        }

    results = []
    for rule_name, direction in [(rule_name_in, "in"), (rule_name_out, "out")]:
        cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}",
            f"dir={direction}",
            "action=block",
            f"remoteip={ip}",
        ]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            results.append({
                "rule": rule_name,
                "returncode": proc.returncode,
                "stdout": proc.stdout.strip(),
                "stderr": proc.stderr.strip(),
            })
        except Exception as exc:
            results.append({
                "rule": rule_name,
                "error": f"{type(exc).__name__}: {exc}",
            })

    all_ok = all(r.get("returncode") == 0 for r in results)
    return {
        "success": all_ok,
        "detail": f"Firewall rules for {ip}: {'all created' if all_ok else 'some failed'}",
        "results": results,
    }
