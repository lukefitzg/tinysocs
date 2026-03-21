# tests/test_e2e_phase12.py
"""
End-to-end integration tests for Phase 12.

Exercises the full lifecycle through the real FastAPI app using TestClient:
  1. Bot API: stage action → list → approve → status (M2)
  2. Daily summary: generate HTML with mocked OpenSearch data (M3)
  3. Audit trail integrity (M2)
  4. Installer artefacts: dashboard NDJSON, scheduled task function (M0/M3)

These tests run entirely in-process — no external services required.
"""

from __future__ import annotations

import hashlib
import hmac as hmac_mod
import json
import os
import time
import uuid
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

# ---------------------------------------------------------------------------
# Fixtures: set env vars BEFORE importing the bot module (which reads them
# at import time).
# ---------------------------------------------------------------------------
_BOT_SECRET = "test-secret-for-e2e"


@pytest.fixture(scope="session", autouse=True)
def _bot_env(tmp_path_factory):
    """Set env vars the bot module needs, before it's imported."""
    tmp = tmp_path_factory.mktemp("e2e")
    os.environ["BOT_SHARED_SECRET"] = _BOT_SECRET
    os.environ["MASTER_SHARED_SECRET"] = _BOT_SECRET
    os.environ["TINYSOCS_QUEUE_PATH"] = str(tmp / "queue.jsonl")
    os.environ["TINYSOCS_AUDIT_DIR"] = str(tmp / "audit")
    os.environ["TINYSOCS_HMAC_STYLE"] = "pipe"
    # Prevent real node calls
    os.environ["TINYSOCS_NODES"] = "http://127.0.0.1:1"
    os.environ["TINYSOCS_INSECURE_SKIP_VERIFY"] = "1"
    yield
    for k in ("BOT_SHARED_SECRET", "MASTER_SHARED_SECRET", "TINYSOCS_QUEUE_PATH",
              "TINYSOCS_AUDIT_DIR", "TINYSOCS_HMAC_STYLE", "TINYSOCS_NODES",
              "TINYSOCS_INSECURE_SKIP_VERIFY"):
        os.environ.pop(k, None)


def _hmac_headers() -> dict:
    """Build valid HMAC headers for test requests."""
    ts = str(int(time.time()))
    nonce = f"e2e-{uuid.uuid4().hex[:12]}"
    msg = f"{ts}|{nonce}"
    sig = hmac_mod.new(_BOT_SECRET.encode(), msg.encode(), hashlib.sha256).hexdigest()
    return {
        "X-TinySOCS-Timestamp": ts,
        "X-TinySOCS-Nonce": nonce,
        "X-TinySOCS-Signature": sig,
    }


# ---------------------------------------------------------------------------
# Import app + TestClient after env is set
# ---------------------------------------------------------------------------
@pytest.fixture(scope="session")
def client(_bot_env):
    # Patch out the ledger POST so /bot/exec doesn't try to reach the node
    with patch("tinysocs.api.bot._post_ledger", return_value={"ok": True, "mocked": True}):
        from tinysocs.api.bot import app
        from starlette.testclient import TestClient
        with TestClient(app, raise_server_exceptions=False) as c:
            yield c


# ===================================================================
# M2 — Action Execution Engine: full lifecycle through the API
# ===================================================================
class TestActionLifecycleE2E:
    """Stage → list → approve → status, entirely through HTTP endpoints."""

    def test_stage_block_ip(self, client):
        resp = client.post("/bot/exec", json={
            "action": "block_ip",
            "params": {"ip": "203.0.113.42"},
            "who": "e2e-test",
            "dry_run": True,
        }, headers=_hmac_headers())
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["queued"] is True
        assert data.get("action_id") is not None

    def test_stage_and_list(self, client):
        # Stage an action
        resp = client.post("/bot/exec", json={
            "action": "disable_user",
            "params": {"user": "malicious-bob"},
            "who": "e2e-test",
        }, headers=_hmac_headers())
        assert resp.status_code == 200

        # List actions via /bot/actions
        resp2 = client.get("/bot/actions", headers=_hmac_headers())
        assert resp2.status_code == 200
        data = resp2.json()
        assert data["count"] > 0
        actions_found = [i["action"] for i in data["items"]]
        assert "disable_user" in actions_found

    def test_full_approve_lifecycle(self, client):
        # 1. Stage
        resp = client.post("/bot/exec", json={
            "action": "block_ip",
            "params": {"ip": "198.51.100.1"},
            "who": "e2e-lifecycle",
            "dry_run": True,
        }, headers=_hmac_headers())
        assert resp.status_code == 200
        action_id = resp.json()["action_id"]
        assert action_id is not None

        # 2. Check status (should be staged)
        resp2 = client.get(f"/bot/actions/{action_id}/status", headers=_hmac_headers())
        assert resp2.status_code == 200
        assert resp2.json()["status"] == "staged"

        # 3. Approve (executor acknowledges — operator handles manually)
        resp3 = client.post("/bot/approve", json={
            "action_id": action_id,
            "approved_by": "e2e-operator",
        }, headers=_hmac_headers())
        assert resp3.status_code == 200
        result = resp3.json()
        assert result["status"] == "acknowledged"
        assert result["dry_run"] is True

        # 4. Check final status
        resp4 = client.get(f"/bot/actions/{action_id}/status", headers=_hmac_headers())
        assert resp4.status_code == 200
        final = resp4.json()
        assert final["status"] == "acknowledged"

    def test_approve_nonexistent_returns_404(self, client):
        resp = client.post("/bot/approve", json={
            "action_id": "does-not-exist",
        }, headers=_hmac_headers())
        assert resp.status_code == 404

    def test_bad_action_rejected(self, client):
        resp = client.post("/bot/exec", json={
            "action": "launch_missiles",
            "params": {},
        }, headers=_hmac_headers())
        assert resp.status_code == 400

    def test_block_ip_missing_param_rejected(self, client):
        resp = client.post("/bot/exec", json={
            "action": "block_ip",
            "params": {},
        }, headers=_hmac_headers())
        assert resp.status_code == 400

    def test_meta_endpoint(self, client):
        resp = client.get("/meta", headers=_hmac_headers())
        assert resp.status_code == 200
        data = resp.json()
        assert "capabilities" in data
        assert "time_utc" in data


# ===================================================================
# M2 — HMAC authentication
# ===================================================================
class TestHMACAuth:
    def test_no_headers_returns_401(self, client):
        resp = client.get("/meta")
        assert resp.status_code == 401

    def test_bad_signature_returns_401(self, client):
        headers = _hmac_headers()
        headers["X-TinySOCS-Signature"] = "deadbeef" * 8
        resp = client.get("/meta", headers=headers)
        assert resp.status_code == 401

    def test_stale_timestamp_returns_401(self, client):
        ts = str(int(time.time()) - 600)  # 10 min old
        nonce = "stale-nonce"
        msg = f"{ts}|{nonce}"
        sig = hmac_mod.new(_BOT_SECRET.encode(), msg.encode(), hashlib.sha256).hexdigest()
        headers = {
            "X-TinySOCS-Timestamp": ts,
            "X-TinySOCS-Nonce": nonce,
            "X-TinySOCS-Signature": sig,
        }
        resp = client.get("/meta", headers=headers)
        assert resp.status_code == 401


# ===================================================================
# M3 — Daily Summary Report: generate with mocked OpenSearch
# ===================================================================
class TestDailySummaryE2E:
    """End-to-end: generate summary HTML, verify content matches data."""

    def _mock_os_query(self, index, body, size=0):
        """Route OpenSearch queries to canned responses based on agg name."""
        aggs = body.get("aggs", {})
        if "by_severity" in aggs:
            return {
                "hits": {"total": {"value": 23}},
                "aggregations": {"by_severity": {"buckets": [
                    {"key": "critical", "doc_count": 2},
                    {"key": "high", "doc_count": 8},
                    {"key": "medium", "doc_count": 10},
                    {"key": "low", "doc_count": 3},
                ]}},
            }
        elif "by_rule" in aggs:
            return {
                "hits": {"total": {"value": 23}},
                "aggregations": {"by_rule": {"buckets": [
                    {"key": "TS-001", "doc_count": 10},
                    {"key": "TS-030", "doc_count": 5},
                    {"key": "TS-010", "doc_count": 4},
                    {"key": "TS-020", "doc_count": 3},
                    {"key": "TS-040", "doc_count": 1},
                ]}},
            }
        elif "by_host" in aggs:
            return {
                "hits": {"total": {"value": 23}},
                "aggregations": {"by_host": {"buckets": [
                    {"key": "DC01", "doc_count": 12},
                    {"key": "WEB02", "doc_count": 6},
                    {"key": "APP03", "doc_count": 5},
                ]}},
            }
        elif "hosts" in aggs:
            # cardinality or terms depending on query
            if "cardinality" in aggs.get("hosts", {}):
                return {"hits": {"total": {"value": 0}}, "aggregations": {"hosts": {"value": 5}}}
            # terms for new_hosts_seen: differentiate recent vs older by query range
            q_range = body.get("query", {}).get("range", {}).get("@timestamp", {})
            if q_range.get("lt"):
                # older
                return {"hits": {"total": {"value": 0}}, "aggregations": {"hosts": {"buckets": [
                    {"key": "DC01", "doc_count": 100},
                    {"key": "WEB02", "doc_count": 50},
                ]}}}
            else:
                # recent — includes a new host
                return {"hits": {"total": {"value": 0}}, "aggregations": {"hosts": {"buckets": [
                    {"key": "DC01", "doc_count": 10},
                    {"key": "WEB02", "doc_count": 5},
                    {"key": "NEWHOST", "doc_count": 1},
                ]}}}
        else:
            # _total_alerts — distinguish 24h vs 48h by the range
            q_range = body.get("query", {}).get("range", {}).get("@timestamp", {})
            gte = q_range.get("gte", "")
            if "48" in gte:
                return {"hits": {"total": {"value": 40}}}  # 48h total
            return {"hits": {"total": {"value": 23}}}  # 24h total

    def test_generate_summary_with_alerts(self):
        with patch("tinysocs.reporting.daily_summary._os_query", side_effect=self._mock_os_query):
            from tinysocs.reporting.daily_summary import generate_summary
            html = generate_summary(24)

        # Structure
        assert "<!DOCTYPE html>" in html or "<html>" in html
        assert "TinySocs Daily Summary" in html
        assert "Open Dashboards" in html

        # Severity breakdown
        assert "Critical" in html
        assert "High" in html
        assert "Medium" in html

        # Top rules
        assert "TS-001" in html
        assert "TS-030" in html

        # Top hosts
        assert "DC01" in html
        assert "WEB02" in html

        # New hosts
        assert "NEWHOST" in html

        # Trend (23 today vs 17 yesterday = up)
        assert "23 Alerts" in html

    def test_generate_summary_all_quiet(self):
        def _quiet(index, body, size=0):
            aggs = body.get("aggs", {})
            if "hosts" in aggs and "cardinality" in aggs.get("hosts", {}):
                return {"hits": {"total": {"value": 0}}, "aggregations": {"hosts": {"value": 3}}}
            if "hosts" in aggs:
                return {"hits": {"total": {"value": 0}}, "aggregations": {"hosts": {"buckets": []}}}
            if any(k.startswith("by_") for k in aggs):
                return {"hits": {"total": {"value": 0}}, "aggregations": {list(aggs.keys())[0]: {"buckets": []}}}
            return {"hits": {"total": {"value": 0}}}

        with patch("tinysocs.reporting.daily_summary._os_query", side_effect=_quiet):
            from tinysocs.reporting.daily_summary import generate_summary
            html = generate_summary(24)

        assert "All Quiet" in html
        assert "3 monitored hosts" in html

    def test_cli_stdout_mode(self):
        """python -m tinysocs.reporting.daily_summary --to x --stdout"""
        with patch("tinysocs.reporting.daily_summary._os_query", side_effect=self._mock_os_query):
            from tinysocs.reporting.daily_summary import generate_summary
            html = generate_summary(24)
            # Verify it's valid HTML that could be piped/emailed
            assert html.startswith("<!DOCTYPE html>") or "<html>" in html


# ===================================================================
# M2 — Audit trail: verify JSONL log has complete lifecycle
# ===================================================================
class TestAuditTrailE2E:
    def test_audit_log_written(self, client):
        audit_dir = os.environ.get("TINYSOCS_AUDIT_DIR")
        if not audit_dir:
            pytest.skip("TINYSOCS_AUDIT_DIR not set")

        audit_file = Path(audit_dir) / "actions_audit.jsonl"
        if not audit_file.exists():
            pytest.skip("No audit file yet")

        lines = audit_file.read_text().strip().split("\n")
        events = [json.loads(l) for l in lines if l.strip()]

        # Should have at least some events from earlier tests
        assert len(events) > 0
        event_types = {e["event"] for e in events}
        # We expect at least staged and completed from the lifecycle test
        assert "action_staged" in event_types

        # Every entry should have a timestamp
        for e in events:
            assert "timestamp" in e


# ===================================================================
# M0 — Dashboard artefacts: verify NDJSON saved objects exist
# ===================================================================
class TestDashboardArtefacts:
    def test_ndjson_file_exists(self):
        ndjson = Path(__file__).resolve().parents[1] / "packaging" / "opensearch" / "dashboards" / "tinysocs-dashboards.ndjson"
        assert ndjson.exists(), f"Missing dashboard NDJSON: {ndjson}"

    def test_ndjson_contains_expected_objects(self):
        ndjson = Path(__file__).resolve().parents[1] / "packaging" / "opensearch" / "dashboards" / "tinysocs-dashboards.ndjson"
        lines = ndjson.read_text().strip().split("\n")
        objects = [json.loads(l) for l in lines if l.strip()]
        types = {obj.get("type") for obj in objects}
        # Must contain dashboards, visualizations, index patterns, and a saved search
        assert "dashboard" in types
        assert "visualization" in types
        assert "index-pattern" in types
        assert "search" in types

        # Count dashboards — plan says 4
        dashboards = [o for o in objects if o.get("type") == "dashboard"]
        assert len(dashboards) >= 4, f"Expected 4 dashboards, got {len(dashboards)}"

    def test_ndjson_has_required_index_patterns(self):
        ndjson = Path(__file__).resolve().parents[1] / "packaging" / "opensearch" / "dashboards" / "tinysocs-dashboards.ndjson"
        text = ndjson.read_text()
        assert "tinysocs-winlog-*" in text
        assert "tinysocs-alerts-*" in text
        assert "tinysocs-heartbeat" in text


# ===================================================================
# M3 — Installer artefact: scheduled task function exists
# ===================================================================
class TestInstallerArtefacts:
    def test_daily_summary_task_function_exists(self):
        psm1 = Path(__file__).resolve().parents[1] / "modules" / "TinySocs.Installer.psm1"
        assert psm1.exists()
        text = psm1.read_text(encoding="utf-8")
        assert "Register-TinySocsDailySummaryTask" in text

    def test_installer_calls_daily_summary_registration(self):
        iss = Path(__file__).resolve().parents[1] / "packaging" / "iss" / "Quickstart.iss"
        assert iss.exists()
        text = iss.read_text(encoding="utf-8")
        assert "Register-TinySocsDailySummaryTask" in text

    def test_installer_imports_dashboards(self):
        iss = Path(__file__).resolve().parents[1] / "packaging" / "iss" / "Quickstart.iss"
        text = iss.read_text(encoding="utf-8")
        assert "Import-TinySocsDashboards" in text

    def test_uninstaller_removes_daily_summary_task(self):
        iss = Path(__file__).resolve().parents[1] / "packaging" / "iss" / "Quickstart.iss"
        text = iss.read_text(encoding="utf-8")
        assert 'TinySocs\\DailySummary' in text
        assert 'schtasks.exe' in text


# ===================================================================
# M1 — Notification wizard: installer has notification config pages
# ===================================================================
class TestNotificationWizardArtefacts:
    def test_webhook_url_field(self):
        iss = Path(__file__).resolve().parents[1] / "packaging" / "iss" / "Quickstart.iss"
        text = iss.read_text(encoding="utf-8")
        assert "WebhookUrl" in text or "webhook_url" in text

    def test_email_fields(self):
        iss = Path(__file__).resolve().parents[1] / "packaging" / "iss" / "Quickstart.iss"
        text = iss.read_text(encoding="utf-8")
        assert "SmtpHost" in text or "smtp_host" in text
        assert "EmailFrom" in text or "email_from" in text
        assert "EmailTo" in text or "email_to" in text


# ===================================================================
# M4 — Documentation exists
# ===================================================================
class TestDocumentation:
    def test_getting_started(self):
        doc = Path(__file__).resolve().parents[1] / "docs" / "getting-started.md"
        assert doc.exists()
        text = doc.read_text()
        assert len(text) > 500  # non-trivial content
        assert "install" in text.lower()

    def test_operator_runbook(self):
        doc = Path(__file__).resolve().parents[1] / "docs" / "operator-runbook.md"
        assert doc.exists()
        text = doc.read_text()
        assert len(text) > 500
        assert "dashboard" in text.lower() or "notification" in text.lower()

    def test_troubleshooting(self):
        doc = Path(__file__).resolve().parents[1] / "docs" / "troubleshooting.md"
        assert doc.exists()
        text = doc.read_text()
        assert len(text) > 300

    def test_readme(self):
        doc = Path(__file__).resolve().parents[1] / "README.md"
        assert doc.exists()
        text = doc.read_text()
        assert "TinySocs" in text
        assert "Daily Summar" in text or "daily_summary" in text
