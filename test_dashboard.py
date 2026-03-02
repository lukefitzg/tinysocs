#!/usr/bin/env python3
"""
Minimal test server for the dashboard HTML.
Mocks just enough API to test login + widget JS execution.

Usage:  python test_dashboard.py
Then open: http://localhost:8090/dashboard/
Password:  test
"""
import json
import re
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path

# Extract the HTML from dashboard.py by executing the assignment
_src = Path(__file__).with_name("src") / "tinysocs" / "api" / "dashboard.py"
_raw = _src.read_text(encoding="utf-8")
_start = _raw.index('_DASHBOARD_HTML = """\\')
_end = _raw.index('"""', _start + len('_DASHBOARD_HTML = """\\') + 1) + 3
_ns: dict = {}
exec(_raw[_start:_end], _ns)
DASHBOARD_HTML = _ns["_DASHBOARD_HTML"]

# Fake session token
FAKE_TOKEN = "test-session-token-12345"
PASSWORD = "test"


def _mitre_coverage_data():
    """Return MITRE coverage from real rules if importable, else a realistic mock."""
    import sys
    src_dir = str(Path(__file__).with_name("src"))
    if src_dir not in sys.path:
        sys.path.insert(0, src_dir)
    try:
        from tinysocs.reporting.mitre_coverage import (
            load_all_rules, extract_mitre_annotations, calculate_coverage,
        )
        rules = load_all_rules()
        annotations = extract_mitre_annotations(rules)
        coverage = calculate_coverage(annotations)
        return {"ok": True, **coverage}
    except Exception:
        # Fallback: realistic mock so the widget renders
        return {
            "ok": True,
            "total_techniques": 17,
            "total_tactics": 8,
            "techniques": {
                "T1110.001": {"technique_id": "T1110.001", "technique_name": "Brute Force: Password Guessing", "tactic": "credential-access", "rules": ["TS-001", "TS-002"]},
                "T1003.001": {"technique_id": "T1003.001", "technique_name": "LSASS Memory", "tactic": "credential-access", "rules": ["TS-060"]},
                "T1059.001": {"technique_id": "T1059.001", "technique_name": "PowerShell", "tactic": "execution", "rules": ["TS-030"]},
                "T1053.005": {"technique_id": "T1053.005", "technique_name": "Scheduled Task", "tactic": "persistence", "rules": ["TS-020"]},
                "T1547.001": {"technique_id": "T1547.001", "technique_name": "Registry Run Keys", "tactic": "persistence", "rules": ["TS-091", "TS-092"]},
                "T1070.001": {"technique_id": "T1070.001", "technique_name": "Clear Event Logs", "tactic": "defense-evasion", "rules": ["TS-080"]},
                "T1562.001": {"technique_id": "T1562.001", "technique_name": "Disable Defender", "tactic": "defense-evasion", "rules": ["TS-081"]},
                "T1021.002": {"technique_id": "T1021.002", "technique_name": "SMB/Admin Shares", "tactic": "lateral-movement", "rules": ["TS-070"]},
            },
            "tactic_summary": [
                {"tactic": "reconnaissance", "label": "Reconnaissance", "techniques_covered": 0, "technique_ids": []},
                {"tactic": "resource-development", "label": "Resource Development", "techniques_covered": 0, "technique_ids": []},
                {"tactic": "initial-access", "label": "Initial Access", "techniques_covered": 0, "technique_ids": []},
                {"tactic": "execution", "label": "Execution", "techniques_covered": 1, "technique_ids": ["T1059.001"]},
                {"tactic": "persistence", "label": "Persistence", "techniques_covered": 2, "technique_ids": ["T1053.005", "T1547.001"]},
                {"tactic": "privilege-escalation", "label": "Privilege Escalation", "techniques_covered": 0, "technique_ids": []},
                {"tactic": "defense-evasion", "label": "Defense Evasion", "techniques_covered": 2, "technique_ids": ["T1070.001", "T1562.001"]},
                {"tactic": "credential-access", "label": "Credential Access", "techniques_covered": 2, "technique_ids": ["T1110.001", "T1003.001"]},
                {"tactic": "discovery", "label": "Discovery", "techniques_covered": 0, "technique_ids": []},
                {"tactic": "lateral-movement", "label": "Lateral Movement", "techniques_covered": 1, "technique_ids": ["T1021.002"]},
                {"tactic": "collection", "label": "Collection", "techniques_covered": 0, "technique_ids": []},
                {"tactic": "command-and-control", "label": "Command and Control", "techniques_covered": 0, "technique_ids": []},
                {"tactic": "exfiltration", "label": "Exfiltration", "techniques_covered": 0, "technique_ids": []},
                {"tactic": "impact", "label": "Impact", "techniques_covered": 0, "technique_ids": []},
            ],
        }


class Handler(BaseHTTPRequestHandler):
    def _json(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _html(self, code, text):
        body = text.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length) if length else b""

    # ---- Routes ----
    def do_GET(self):
        path = self.path.split("?")[0].rstrip("/")

        # Dashboard page
        if path in ("/dashboard", ""):
            self._html(200, DASHBOARD_HTML)
            return

        # Auth check — always say yes
        if path == "/dashboard/api/auth/check":
            self._json(200, {"ok": True, "authenticated": True})
            return

        # Summary widget
        if path == "/dashboard/api/alerts/summary":
            self._json(200, {
                "total": 42, "critical": 3, "high": 7, "medium": 15, "low": 17,
                "by_category": {"Sysmon": 20, "Security": 12, "System": 10},
            })
            return

        # Timeline widget
        if path == "/dashboard/api/alerts/timeline":
            self._json(200, {"buckets": []})
            return

        # Detections widget
        if path == "/dashboard/api/detections/fired":
            self._json(200, {"detections": [], "total": 0})
            return

        # Fleet / agents
        if path == "/dashboard/api/fleet/agents":
            self._json(200, {"agents": [], "total": 0})
            return

        # Fleet health
        if path == "/dashboard/api/fleet/health":
            self._json(200, {"hosts": [
                {
                    "hostname": "TINYBOX-01",
                    "event_count": 1284,
                    "last_seen": "2026-02-25T09:00:00Z",
                    "first_seen": "2026-02-25T01:00:00Z",
                    "alert_count": 3,
                    "alert_severities": {"high": 1, "medium": 2},
                    "active_detections": ["auth_failed_burst", "fim_critical_file_modified"],
                    "top_channels": [
                        {"channel": "Security", "count": 820},
                        {"channel": "Microsoft-Windows-Sysmon/Operational", "count": 380},
                        {"channel": "TinySocs-FIM", "count": 84},
                    ],
                    "top_event_ids": [{"event_id": "4625", "count": 312}, {"event_id": "1", "count": 245}],
                    "agent_version": "0.8.0",
                    "uptime": "3d 14h",
                    "events_shipped": 12840,
                    "queue_files": 0,
                    "last_ship_time": "2026-02-25T08:59:50Z",
                    "heartbeat_ts": "2026-02-25T09:00:00Z",
                },
                {
                    "hostname": "TINYBOX-02",
                    "event_count": 763,
                    "last_seen": "2026-02-25T08:55:00Z",
                    "first_seen": "2026-02-25T02:00:00Z",
                    "alert_count": 1,
                    "alert_severities": {"medium": 1},
                    "active_detections": ["powershell_scriptblock"],
                    "top_channels": [
                        {"channel": "Security", "count": 520},
                        {"channel": "Microsoft-Windows-Sysmon/Operational", "count": 203},
                        {"channel": "System", "count": 40},
                    ],
                    "top_event_ids": [{"event_id": "4624", "count": 180}, {"event_id": "1", "count": 150}],
                    "agent_version": "0.8.0",
                    "uptime": "1d 6h",
                    "events_shipped": 7630,
                    "queue_files": 0,
                    "last_ship_time": "2026-02-25T08:54:30Z",
                    "heartbeat_ts": "2026-02-25T08:55:00Z",
                },
            ]})
            return

        # Host timeline (fleet-wide event flow)
        if path == "/dashboard/api/host/timeline":
            import datetime
            base = datetime.datetime(2026, 2, 25, 0, 0, 0)
            buckets = []
            for i in range(24):
                t = base + datetime.timedelta(hours=i)
                buckets.append({
                    "time": t.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "count": 40 + (i * 7 % 30),
                    "channels": {
                        "Security": 20 + (i * 3 % 15),
                        "Microsoft-Windows-Sysmon/Operational": 15 + (i * 5 % 12),
                        "TinySocs-FIM": 5 + (i % 4),
                    },
                })
            self._json(200, {
                "hostname": "", "hours": 24, "interval": "1h",
                "buckets": buckets,
                "channels": ["Security", "Microsoft-Windows-Sysmon/Operational", "TinySocs-FIM"],
            })
            return

        # Version status
        if path == "/dashboard/api/version/status":
            self._json(200, {
                "ok": True, "has_outdated": False,
                "manifest": {"current_version": "0.8.0"},
                "fleet_versions": [
                    {"hostname": "TINYBOX-01", "agent_version": "0.8.0", "status": "current"},
                    {"hostname": "TINYBOX-02", "agent_version": "0.8.0", "status": "current"},
                ],
                "summary": {"current": 2, "outdated_minor": 0, "outdated_major": 0},
            })
            return

        # Threat intel status
        if path == "/dashboard/api/threat-intel/status":
            self._json(200, {
                "ok": True,
                "providers": [
                    {"name": "AbuseIPDB", "configured": True, "available": True, "quota_remaining": 847},
                    {"name": "AlienVault OTX", "configured": True, "available": True, "quota_remaining": 99900},
                    {"name": "GreyNoise Community", "configured": False, "available": False, "quota_remaining": 0},
                ],
                "cache": {"total_entries": 42, "valid_entries": 38, "expired_entries": 4},
            })
            return

        # Rules
        if path == "/dashboard/api/rules":
            self._json(200, {"rules": [], "total": 0})
            return

        # Compliance frameworks
        if path == "/dashboard/api/compliance/frameworks":
            self._json(200, {"frameworks": []})
            return

        # MITRE coverage — use real rule data if available, else realistic mock
        if path == "/dashboard/api/mitre/coverage":
            self._json(200, _mitre_coverage_data())
            return

        # LLM status
        if path == "/dashboard/api/llm/status":
            self._json(200, {"available": False, "model": "none"})
            return

        # Events
        if path == "/dashboard/api/events":
            self._json(200, {"events": [], "total": 0})
            return

        # Threat intel
        if path == "/dashboard/api/threat-intel/feeds":
            self._json(200, {"feeds": []})
            return

        # FIM
        if path == "/dashboard/api/fim/events":
            self._json(200, {"events": [], "total": 0})
            return

        # Version
        if path == "/dashboard/api/version":
            self._json(200, {"version": "test-dev", "components": {}})
            return

        # Alerts retention
        if path == "/dashboard/api/alerts/retention":
            self._json(200, {"policy": "30d"})
            return

        # Chat history
        if path == "/dashboard/api/chat/history":
            self._json(200, {"messages": []})
            return

        # Catch-all: return empty JSON
        if "/api/" in path:
            print(f"  [MOCK 200] GET {path}")
            self._json(200, {})
            return

        self.send_error(404, f"Not found: {path}")

    def do_POST(self):
        path = self.path.split("?")[0].rstrip("/")
        body_raw = self._read_body()

        # Login
        if path == "/dashboard/api/auth/login":
            try:
                data = json.loads(body_raw) if body_raw else {}
            except json.JSONDecodeError:
                data = {}
            pw = data.get("password", "")
            if pw == PASSWORD:
                self._json(200, {"ok": True, "token": FAKE_TOKEN})
            else:
                self._json(401, {"error": "Invalid password"})
            return

        # Catch-all POST
        if "/api/" in path:
            print(f"  [MOCK 200] POST {path}")
            self._json(200, {"ok": True})
            return

        self.send_error(404, f"Not found: {path}")

    def log_message(self, fmt, *args):
        print(f"  {args[0]}")


def main():
    port = 9999
    server = HTTPServer(("0.0.0.0", port), Handler)
    print(f"Dashboard test server running on http://localhost:{port}/dashboard/")
    print(f"Password: {PASSWORD}")
    print("Press Ctrl+C to stop.\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
        server.server_close()


if __name__ == "__main__":
    main()
