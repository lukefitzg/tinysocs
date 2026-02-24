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

# Extract the HTML from dashboard.py
_src = Path(__file__).with_name("src") / "tinysocs" / "api" / "dashboard.py"
_raw = _src.read_text(encoding="utf-8")
_m = re.search(r'_DASHBOARD_HTML\s*=\s*"""\\\n(.*?)"""', _raw, re.DOTALL)
if not _m:
    raise RuntimeError("Could not extract _DASHBOARD_HTML from dashboard.py")
DASHBOARD_HTML = _m.group(1)

# Fake session token
FAKE_TOKEN = "test-session-token-12345"
PASSWORD = "test"


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

        # Rules
        if path == "/dashboard/api/rules":
            self._json(200, {"rules": [], "total": 0})
            return

        # Compliance frameworks
        if path == "/dashboard/api/compliance/frameworks":
            self._json(200, {"frameworks": []})
            return

        # MITRE coverage
        if path == "/dashboard/api/mitre/coverage":
            self._json(200, {"techniques": [], "coverage_pct": 0})
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
