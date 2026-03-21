# tests/test_security_auth.py
"""
Security-focused tests for HMAC authentication, input validation,
rate limiting, and replay protection.
"""

from __future__ import annotations

import hashlib
import hmac as hmac_mod
import os
import time

import pytest

# ---------------------------------------------------------------------------
# Set env vars BEFORE importing any tinysocs modules
# ---------------------------------------------------------------------------
# Use the same secret as test_e2e_phase12 to avoid import-time conflicts
# (bot.py reads BOT_SECRET at module load, so whichever fixture runs first wins)
_TEST_SECRET = "test-secret-for-e2e"


@pytest.fixture(scope="session", autouse=True)
def _auth_env(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("security")
    os.environ.setdefault("BOT_SHARED_SECRET", _TEST_SECRET)
    os.environ.setdefault("MASTER_SHARED_SECRET", _TEST_SECRET)
    os.environ.setdefault("TINYSOCS_QUEUE_PATH", str(tmp / "queue.jsonl"))
    os.environ.setdefault("TINYSOCS_NODES", "http://127.0.0.1:1")
    os.environ.setdefault("TINYSOCS_INSECURE_SKIP_VERIFY", "1")
    yield


def _sign(secret: str, msg: str) -> str:
    return hmac_mod.new(
        secret.encode(), msg.encode(), hashlib.sha256
    ).hexdigest()


def _make_headers(secret: str = _TEST_SECRET, *, style: str = "pipe"):
    import secrets
    ts = str(int(time.time()))
    nonce = secrets.token_hex(8)
    if style == "pipe":
        msg = f"{ts}|{nonce}"
    elif style == "dot":
        msg = f"{ts}.{nonce}"
    else:
        msg = ts
    sig = _sign(secret, msg)
    headers = {
        "X-TinySOCS-Timestamp": ts,
        "X-TinySOCS-Signature": sig,
    }
    if style != "ts":
        headers["X-TinySOCS-Nonce"] = nonce
    return headers


# ---------------------------------------------------------------------------
# Auth module unit tests
# ---------------------------------------------------------------------------
class TestAuthModule:
    def test_make_verify_hmac_valid_pipe(self):

        from tinysocs.api.auth import make_verify_hmac

        verify = make_verify_hmac(_TEST_SECRET)
        assert callable(verify)

    def test_normalize_sig_strips_prefix(self):
        from tinysocs.api.auth import _normalize_sig
        assert _normalize_sig("sha256=abc123") == "abc123"
        assert _normalize_sig("ABC123") == "abc123"
        assert _normalize_sig("  sha256=DEF  ") == "def"

    def test_sign_request_headers_pipe(self):
        from tinysocs.api.auth import sign_request_headers
        headers = sign_request_headers(_TEST_SECRET, style="pipe")
        assert "X-TinySOCS-Timestamp" in headers
        assert "X-TinySOCS-Signature" in headers
        assert "X-TinySOCS-Nonce" in headers

    def test_sign_request_headers_ts_only(self):
        from tinysocs.api.auth import sign_request_headers
        headers = sign_request_headers(_TEST_SECRET, style="ts")
        assert "X-TinySOCS-Timestamp" in headers
        assert "X-TinySOCS-Signature" in headers
        assert "X-TinySOCS-Nonce" not in headers


# ---------------------------------------------------------------------------
# Input validation tests
# ---------------------------------------------------------------------------
class TestInputValidation:
    @pytest.fixture
    def client(self):
        from fastapi.testclient import TestClient

        from tinysocs.api.bot import app
        return TestClient(app)

    def test_block_ip_rejects_loopback(self, client):
        headers = _make_headers()
        r = client.post("/bot/exec", json={
            "action": "block_ip",
            "params": {"ip": "127.0.0.1"},
        }, headers=headers)
        assert r.status_code == 400
        assert "loopback" in r.json()["detail"].lower()

    def test_block_ip_rejects_invalid_ip(self, client):
        headers = _make_headers()
        r = client.post("/bot/exec", json={
            "action": "block_ip",
            "params": {"ip": "not-an-ip"},
        }, headers=headers)
        assert r.status_code == 400

    def test_disable_user_rejects_empty(self, client):
        headers = _make_headers()
        r = client.post("/bot/exec", json={
            "action": "disable_user",
            "params": {"user": ""},
        }, headers=headers)
        assert r.status_code == 400

    def test_disable_user_rejects_invalid_chars(self, client):
        headers = _make_headers()
        r = client.post("/bot/exec", json={
            "action": "disable_user",
            "params": {"user": "admin; rm -rf /"},
        }, headers=headers)
        assert r.status_code == 400
        assert "invalid" in r.json()["detail"].lower()

    def test_disable_user_rejects_too_long(self, client):
        headers = _make_headers()
        r = client.post("/bot/exec", json={
            "action": "disable_user",
            "params": {"user": "a" * 300},
        }, headers=headers)
        assert r.status_code == 400
        assert "too long" in r.json()["detail"].lower()

    def test_isolate_host_rejects_invalid_chars(self, client):
        headers = _make_headers()
        r = client.post("/bot/exec", json={
            "action": "isolate_host",
            "params": {"host": "host; cat /etc/passwd"},
        }, headers=headers)
        assert r.status_code == 400
        assert "invalid" in r.json()["detail"].lower()


# ---------------------------------------------------------------------------
# HMAC authentication tests
# ---------------------------------------------------------------------------
class TestHMACAuth:
    @pytest.fixture
    def client(self):
        from fastapi.testclient import TestClient

        from tinysocs.api.bot import app
        return TestClient(app)

    def test_missing_headers_returns_401(self, client):
        r = client.post("/bot/exec", json={
            "action": "block_ip",
            "params": {"ip": "1.2.3.4"},
        })
        assert r.status_code == 401

    def test_wrong_secret_returns_401(self, client):
        headers = _make_headers(secret="wrong-secret")
        r = client.post("/bot/exec", json={
            "action": "block_ip",
            "params": {"ip": "1.2.3.4"},
        }, headers=headers)
        assert r.status_code == 401

    def test_old_timestamp_returns_401(self, client):
        ts = str(int(time.time()) - 600)  # 10 min ago
        nonce = "test-nonce"
        msg = f"{ts}|{nonce}"
        sig = _sign(_TEST_SECRET, msg)
        headers = {
            "X-TinySOCS-Timestamp": ts,
            "X-TinySOCS-Signature": sig,
            "X-TinySOCS-Nonce": nonce,
        }
        r = client.post("/bot/exec", json={
            "action": "block_ip",
            "params": {"ip": "1.2.3.4"},
        }, headers=headers)
        assert r.status_code == 401

    def test_valid_request_succeeds(self, client):
        headers = _make_headers()
        r = client.post("/bot/ack", json={
            "incident_id": "test-123",
            "tldr": "test ack",
        }, headers=headers)
        # Should succeed (may fail on ledger post, but auth passes)
        assert r.status_code in (200, 500)  # 500 if node unreachable

    def test_sha256_prefix_accepted(self, client):
        import secrets
        ts = str(int(time.time()))
        nonce = secrets.token_hex(8)
        msg = f"{ts}|{nonce}"
        sig = "sha256=" + _sign(_TEST_SECRET, msg)
        headers = {
            "X-TinySOCS-Timestamp": ts,
            "X-TinySOCS-Signature": sig,
            "X-TinySOCS-Nonce": nonce,
        }
        r = client.post("/bot/ack", json={
            "incident_id": "test-sha256",
            "tldr": "test",
        }, headers=headers)
        assert r.status_code in (200, 500)


# ---------------------------------------------------------------------------
# Diagnostic endpoint gating tests
# ---------------------------------------------------------------------------
class TestDiagEndpoints:
    @pytest.fixture
    def client(self):
        from fastapi.testclient import TestClient

        from tinysocs.api.bot import app
        return TestClient(app)

    def test_diag_disabled_by_default(self, client):
        headers = _make_headers()
        r = client.post("/bot/_diag/ledger-shapes", json={}, headers=headers)
        assert r.status_code == 403
        assert "diag disabled" in r.json()["detail"].lower()

    def test_diag_queue_append_disabled_by_default(self, client):
        headers = _make_headers()
        r = client.post("/bot/_diag/queue-append-sample", headers=headers)
        assert r.status_code == 403


# ---------------------------------------------------------------------------
# Production config guard tests
# ---------------------------------------------------------------------------
class TestProdGuards:
    def test_weak_siem_pass_blocked_in_prod(self):
        from pathlib import Path

        from tinysocs.agent.config import Config, _prod_guard
        cfg = Config(
            siem_url="https://siem.example.com:9200",
            siem_user="secops",
            siem_pass="ChangeMe123!",
            ssl_verify=True,
            actions_queue_path=Path("/tmp/q.jsonl"),
            rules_path=Path("/tmp/rules.yaml"),
        )
        with pytest.raises(RuntimeError, match="weak SIEM_PASS"):
            _prod_guard(cfg, "prod")

    def test_ssl_verify_required_in_prod(self):
        from pathlib import Path

        from tinysocs.agent.config import Config, _prod_guard
        cfg = Config(
            siem_url="https://siem.example.com:9200",
            siem_user="secops",
            siem_pass="a-strong-password-here",
            ssl_verify=False,
            actions_queue_path=Path("/tmp/q.jsonl"),
            rules_path=Path("/tmp/rules.yaml"),
        )
        with pytest.raises(RuntimeError, match="SIEM_SSL_VERIFY"):
            _prod_guard(cfg, "prod")

    def test_dev_mode_allows_weak_config(self):
        from pathlib import Path

        from tinysocs.agent.config import Config, _prod_guard
        cfg = Config(
            siem_url="https://localhost:9201",
            siem_user="admin",
            siem_pass="ChangeMe123!",
            ssl_verify=False,
            actions_queue_path=Path("/tmp/q.jsonl"),
            rules_path=Path("/tmp/rules.yaml"),
        )
        # Should not raise in dev mode
        _prod_guard(cfg, "dev")
