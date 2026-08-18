"""Dashboard auth enforcement tests.

Covers the deny-by-default session middleware (every route requires a Bearer
session except the explicit public allowlist) and the first-boot setup-token
gate on /api/settings/setup-password.

The dashboard module is a process-wide singleton that other test modules also
import (test_demo_mode.py flips TINYSOCS_DEMO_MODE at import time), so these
tests monkeypatch module attributes (_DEMO_MODE, _setup_token) rather than
relying on import order or environment variables read at import.
"""

from __future__ import annotations

import importlib

import pytest
from fastapi.testclient import TestClient

TEST_PW = "auth-test-password-1"


@pytest.fixture()
def dash(monkeypatch):
    mod = importlib.import_module("tinysocs.api.dashboard")
    monkeypatch.setattr(mod, "_DEMO_MODE", False)
    monkeypatch.setattr(mod, "_setup_token", None)
    monkeypatch.setenv("SIEM_PASS", TEST_PW)
    return mod


@pytest.fixture()
def client(dash):
    with TestClient(dash.dashboard_app) as c:
        yield c


def _login(client) -> dict[str, str]:
    resp = client.post("/api/auth/login", json={"password": TEST_PW})
    assert resp.status_code == 200, resp.text
    return {"Authorization": f"Bearer {resp.json()['token']}"}


class TestMiddlewareDeniesByDefault:
    def test_mutating_routes_unauthenticated_401(self, client):
        for method, path in [
            ("POST", "/api/alerts/purge"),
            ("POST", "/api/storage/purge"),
            ("POST", "/api/rules"),
            ("POST", "/api/rules/upload"),
            ("PUT", "/api/rules/some-rule"),
            ("DELETE", "/api/rules/some-rule"),
            ("POST", "/api/rules/some-rule/toggle"),
            ("POST", "/api/actions/a1/approve"),
            ("POST", "/api/actions/a1/reject"),
            ("POST", "/api/nodes/add"),
            ("POST", "/api/nodes/approve"),
            ("POST", "/api/chat"),
        ]:
            resp = client.request(method, path, json={})
            assert resp.status_code == 401, f"{method} {path} -> {resp.status_code}"
            assert resp.json() == {"error": "Not authenticated"}

    def test_read_routes_unauthenticated_401(self, client):
        for path in ["/api/rules", "/api/settings/llm-mode", "/api/events/recent", "/api/diag"]:
            resp = client.get(path)
            assert resp.status_code == 401, f"GET {path} -> {resp.status_code}"

    def test_garbage_token_401(self, client):
        resp = client.get("/api/settings/llm-mode", headers={"Authorization": "Bearer nonsense"})
        assert resp.status_code == 401

    def test_valid_session_passes_middleware(self, client):
        headers = _login(client)
        assert client.get("/api/auth/check", headers=headers).status_code == 200
        # Not asserting 200 (handler may need OpenSearch); asserting auth passed.
        assert client.get("/api/settings/llm-mode", headers=headers).status_code != 401

    def test_demo_mode_bypasses_auth(self, dash, client, monkeypatch):
        monkeypatch.setattr(dash, "_DEMO_MODE", True)
        assert client.get("/api/settings/llm-mode").status_code != 401


class TestPublicAllowlist:
    def test_spa_shell_public(self, client):
        resp = client.get("/")
        assert resp.status_code == 200
        assert "text/html" in resp.headers.get("content-type", "")

    def test_password_status_public(self, client):
        resp = client.get("/api/settings/password-status")
        assert resp.status_code == 200
        assert resp.json()["configured"] is True

    def test_login_reachable_and_rejects_bad_password(self, dash, client, monkeypatch):
        # Reset the login rate limiter so parallel test runs don't trip it.
        monkeypatch.setattr(dash, "_login_attempts", {})
        resp = client.post("/api/auth/login", json={"password": "wrong-password"})
        assert resp.status_code == 401
        assert resp.json() == {"error": "Invalid password"}

    def test_auth_check_public_but_self_rejecting(self, client):
        resp = client.get("/api/auth/check")
        assert resp.status_code == 401
        assert resp.json()["authenticated"] is False

    def test_nodes_register_bypasses_session_auth(self, dash, client, tmp_path, monkeypatch):
        # HMAC-authenticated machine endpoint: the middleware must let it through
        # to its own auth (which rejects for missing HMAC headers, not 'Not
        # authenticated' from the middleware).
        monkeypatch.setattr(dash, "_PENDING_FILE", tmp_path / "pending_sites.json")
        resp = client.post("/api/nodes/register", json={"node_id": "n1", "url": "https://x"})
        assert resp.json() != {"error": "Not authenticated"}


class TestSetupTokenGate:
    @pytest.fixture()
    def unconfigured(self, dash, monkeypatch, tmp_path):
        monkeypatch.delenv("SIEM_PASS", raising=False)
        # Keep the handler from finding a real assistant.env on the host.
        monkeypatch.setattr(dash, "_find_assistant_env", lambda: None)
        monkeypatch.setattr(dash, "_find_assistant_env_for_auth", lambda: None)
        return dash

    def test_password_status_mints_token(self, unconfigured, client, capsys):
        resp = client.get("/api/settings/password-status")
        assert resp.status_code == 200
        assert resp.json() == {"configured": False, "setup_token_required": True}
        assert unconfigured._setup_token is not None
        assert unconfigured._setup_token in capsys.readouterr().out

    def test_setup_without_token_403(self, unconfigured, client):
        resp = client.post("/api/settings/setup-password", json={"new_password": "longenough1"})
        assert resp.status_code == 403

    def test_setup_with_wrong_token_403(self, unconfigured, client):
        client.get("/api/settings/password-status")  # mint
        resp = client.post(
            "/api/settings/setup-password",
            json={"new_password": "longenough1", "setup_token": "not-the-token"},
        )
        assert resp.status_code == 403

    def test_setup_with_token_succeeds(self, unconfigured, client, monkeypatch):
        client.get("/api/settings/password-status")  # mint
        resp = client.post(
            "/api/settings/setup-password",
            json={"new_password": "longenough1", "setup_token": unconfigured._setup_token},
        )
        assert resp.status_code == 200, resp.text
        # Password is live; login works with it.
        monkeypatch.setattr(unconfigured, "_login_attempts", {})
        login = client.post("/api/auth/login", json={"password": "longenough1"})
        assert login.status_code == 200

    def test_setup_blocked_when_configured(self, dash, client):
        resp = client.post(
            "/api/settings/setup-password",
            json={"new_password": "longenough1", "setup_token": "anything"},
        )
        assert resp.status_code == 400
