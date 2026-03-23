"""
test_notifications_e2e.py — End-to-end notification verification tests.

Phase 13 (M2): Tests the full alert → notification delivery pipeline
for both webhook and email, using local test servers.
"""

import json
import os
import socket
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from email.parser import BytesParser
from unittest.mock import patch

import pytest


# ── Helpers ──────────────────────────────────────────────────────────

def _free_port() -> int:
    """Find a free TCP port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class WebhookCapture(BaseHTTPRequestHandler):
    """Simple HTTP handler that captures POST payloads."""

    received: list = []

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        WebhookCapture.received.append({
            "path": self.path,
            "body": body,
            "content_type": self.headers.get("Content-Type", ""),
        })
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"ok": true}')

    def log_message(self, *args, **kwargs):
        pass  # Suppress access logs during tests


class SlowWebhookHandler(BaseHTTPRequestHandler):
    """Handler that never responds (for timeout tests)."""

    def do_POST(self):
        time.sleep(30)  # hang — test should timeout before this

    def log_message(self, *args, **kwargs):
        pass


class SMTPCapture:
    """Minimal SMTP server that captures messages using asyncio aiosmtpd."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0):
        self.host = host
        self.port = port or _free_port()
        self.messages: list = []
        self._server = None
        self._thread = None

    def start(self):
        """Start the SMTP server in a background thread."""
        try:
            from aiosmtpd.controller import Controller
            from aiosmtpd.handlers import Message as MessageHandler

            class _Handler(MessageHandler):
                def __init__(self, mailbox):
                    super().__init__()
                    self._mailbox = mailbox

                def handle_message(self, msg):
                    self._mailbox.append(msg)

            handler = _Handler(self.messages)
            self._server = Controller(handler, hostname=self.host, port=self.port)
            self._server.start()
        except ImportError:
            pytest.skip("aiosmtpd not installed — skipping email E2E tests")

    def stop(self):
        if self._server:
            self._server.stop()


# ── Fixtures ──────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def dashboard_client():
    """Create a TestClient for the dashboard with SIEM_PASS set."""
    # Set SIEM_PASS so auth works
    os.environ["SIEM_PASS"] = "test-password-e2e"
    # Avoid importing before env is set
    from starlette.testclient import TestClient
    from tinysocs.api.dashboard import dashboard_app
    with TestClient(dashboard_app) as client:
        yield client


@pytest.fixture(scope="module")
def auth_headers(dashboard_client):
    """Login and return Bearer auth headers for settings API calls."""
    resp = dashboard_client.post("/api/auth/login", json={"password": "test-password-e2e"})
    token = resp.json()["token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def webhook_server():
    """Start a local webhook capture server."""
    WebhookCapture.received.clear()
    port = _free_port()
    server = HTTPServer(("127.0.0.1", port), WebhookCapture)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}/webhook", WebhookCapture.received
    server.shutdown()


@pytest.fixture
def slow_webhook_server():
    """Start a webhook server that never responds (timeout test)."""
    port = _free_port()
    server = HTTPServer(("127.0.0.1", port), SlowWebhookHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}/slow"
    server.shutdown()


@pytest.fixture
def smtp_server():
    """Start a local SMTP capture server."""
    srv = SMTPCapture("127.0.0.1", _free_port())
    srv.start()
    yield srv
    srv.stop()


# ── Webhook delivery tests ───────────────────────────────────────────

class TestWebhookE2E:

    def test_webhook_delivery_success(self, dashboard_client, auth_headers, webhook_server):
        """Test that the test-webhook endpoint delivers a payload to a local server."""
        url, received = webhook_server
        resp = dashboard_client.post("/api/settings/test-webhook", json={
            "webhook_url": url,
        }, headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert "successful" in data["message"].lower()

        # Verify the webhook server received the payload
        assert len(received) == 1
        payload = json.loads(received[0]["body"])
        assert "[TinySocs]" in payload["text"]
        assert "test notification" in payload["text"].lower()

    def test_webhook_delivery_invalid_url(self, dashboard_client, auth_headers):
        """Test that connection refused is handled gracefully."""
        # Use a port that's almost certainly not listening
        resp = dashboard_client.post("/api/settings/test-webhook", json={
            "webhook_url": "http://127.0.0.1:1/dead",
        }, headers=auth_headers)
        assert resp.status_code == 502
        data = resp.json()
        assert "error" in data

    def test_webhook_no_url_configured(self, dashboard_client, auth_headers):
        """Test that missing webhook URL returns 400."""
        # Ensure no WEBHOOK_URL in env either
        with patch.dict(os.environ, {"WEBHOOK_URL": ""}, clear=False):
            resp = dashboard_client.post("/api/settings/test-webhook", json={
                "webhook_url": "",
            }, headers=auth_headers)
            assert resp.status_code == 400
            assert "webhook" in resp.json()["error"].lower()

    def test_webhook_auth_required(self, dashboard_client, webhook_server):
        """Test that test-webhook requires valid session token."""
        url, _ = webhook_server
        resp = dashboard_client.post("/api/settings/test-webhook", json={
            "webhook_url": url,
        })
        assert resp.status_code == 401

    def test_webhook_payload_format(self, dashboard_client, auth_headers, webhook_server):
        """Verify the webhook payload is Slack-compatible JSON."""
        url, received = webhook_server
        dashboard_client.post("/api/settings/test-webhook", json={
            "webhook_url": url,
        }, headers=auth_headers)
        assert len(received) >= 1
        payload = json.loads(received[-1]["body"])
        # Slack-compatible format: must have "text" key
        assert "text" in payload
        assert isinstance(payload["text"], str)
        assert received[-1]["content_type"] == "application/json"


# ── Email delivery tests ─────────────────────────────────────────────

class TestEmailE2E:

    def test_email_delivery_success(self, dashboard_client, auth_headers, smtp_server):
        """Test that the test-email endpoint sends to a local SMTP server."""
        resp = dashboard_client.post("/api/settings/test-email", json={
            "smtp_host": smtp_server.host,
            "smtp_port": smtp_server.port,
            "email_from": "tinysocs@test.local",
            "email_to": "operator@test.local",
        }, headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert "operator@test.local" in data["message"]

        # Verify SMTP server received the email
        time.sleep(0.5)  # Give async SMTP a moment
        assert len(smtp_server.messages) >= 1
        msg = smtp_server.messages[-1]
        # Subject may be MIME-encoded (UTF-8 em dash), so decode it
        from email.header import decode_header
        raw_subject = msg["Subject"]
        decoded_parts = decode_header(raw_subject)
        subject = "".join(
            part.decode(enc or "utf-8") if isinstance(part, bytes) else part
            for part, enc in decoded_parts
        )
        assert "[TinySocs]" in subject
        assert "Configuration Verified" in subject

    def test_email_connection_refused(self, dashboard_client, auth_headers):
        """Test that SMTP connection refused is handled gracefully."""
        resp = dashboard_client.post("/api/settings/test-email", json={
            "smtp_host": "127.0.0.1",
            "smtp_port": 1,  # almost certainly refused
            "email_from": "tinysocs@test.local",
            "email_to": "operator@test.local",
        }, headers=auth_headers)
        assert resp.status_code == 502
        assert "error" in resp.json()

    def test_email_missing_config(self, dashboard_client, auth_headers):
        """Test that missing SMTP host returns 400."""
        resp = dashboard_client.post("/api/settings/test-email", json={
            "smtp_host": "",
            "smtp_port": 587,
            "email_from": "",
            "email_to": "",
        }, headers=auth_headers)
        assert resp.status_code == 400
        assert "not configured" in resp.json()["error"].lower()

    def test_email_auth_required(self, dashboard_client):
        """Test that test-email requires valid session token."""
        resp = dashboard_client.post("/api/settings/test-email", json={
            "smtp_host": "127.0.0.1",
            "smtp_port": 587,
            "email_from": "a@b.c",
            "email_to": "d@e.f",
        })
        assert resp.status_code == 401


# ── Password API tests (M0 regression coverage) ──────────────────────

class TestPasswordAPI:
    """Exercise M0 password endpoints to prevent regression."""

    def test_password_status(self, dashboard_client):
        resp = dashboard_client.get("/api/settings/password-status")
        assert resp.status_code == 200
        assert resp.json()["configured"] is True

    def test_settings_requires_auth(self, dashboard_client):
        resp = dashboard_client.get("/api/settings")
        assert resp.status_code == 401

    def test_settings_correct_password(self, dashboard_client, auth_headers):
        resp = dashboard_client.get("/api/settings", headers=auth_headers)
        assert resp.status_code == 200
        assert "settings" in resp.json()

    def test_change_password_wrong_current(self, dashboard_client, auth_headers):
        resp = dashboard_client.post("/api/settings/change-password", json={
            "old_password": "wrong",
            "new_password": "new-secure-pw",
        }, headers=auth_headers)
        assert resp.status_code == 401

    def test_change_password_too_short(self, dashboard_client, auth_headers):
        resp = dashboard_client.post("/api/settings/change-password", json={
            "old_password": "test-password-e2e",
            "new_password": "short",
        }, headers=auth_headers)
        assert resp.status_code == 400

    def test_setup_password_already_set(self, dashboard_client):
        """setup-password should fail if password already exists."""
        resp = dashboard_client.post("/api/settings/setup-password", json={
            "new_password": "some-new-password",
        })
        assert resp.status_code == 400
        assert "already configured" in resp.json()["error"].lower()
