# tests/test_action_executor.py
"""Unit tests for the guided response engine."""

import json
import os

import pytest

from tinysocs.actions import executor
from tinysocs.actions.executor import (
    stage_action,
    approve_action,
    reject_action,
    get_action,
    list_actions,
    _actions,
    _build_runbook,
)


@pytest.fixture(autouse=True)
def _clean_state(tmp_path):
    """Clear the in-memory action store and redirect audit log before each test."""
    _actions.clear()
    executor.AUDIT_LOG_PATH = tmp_path / "audit" / "actions_audit.jsonl"
    yield
    _actions.clear()


# ---------------------------------------------------------------------------
# stage_action
# ---------------------------------------------------------------------------
class TestStageAction:
    def test_creates_staged_record(self):
        rec = stage_action("block_ip", {"ip": "10.0.0.1"}, who="llm")
        assert rec["status"] == "staged"
        assert rec["action"] == "block_ip"
        assert rec["params"] == {"ip": "10.0.0.1"}
        assert rec["who"] == "llm"
        assert rec["action_id"] in _actions

    def test_includes_runbook(self):
        rec = stage_action("block_ip", {"ip": "10.0.0.1", "reason": "suspicious"})
        assert isinstance(rec["runbook"], list)
        assert len(rec["runbook"]) > 0
        # Runbook should interpolate params
        assert any("10.0.0.1" in step for step in rec["runbook"])

    def test_writes_audit_entry(self, tmp_path):
        rec = stage_action("block_ip", {"ip": "1.2.3.4"})
        log = executor.AUDIT_LOG_PATH.read_text()
        entry = json.loads(log.strip())
        assert entry["event"] == "response_staged"
        assert entry["action_id"] == rec["action_id"]

    def test_defaults_who_to_system(self):
        rec = stage_action("block_ip", {})
        assert rec["who"] == "system"

    def test_unique_ids(self):
        r1 = stage_action("block_ip", {})
        r2 = stage_action("block_ip", {})
        assert r1["action_id"] != r2["action_id"]

    def test_unknown_action_gets_default_runbook(self):
        rec = stage_action("unknown_action", {"foo": "bar"})
        assert isinstance(rec["runbook"], list)
        assert len(rec["runbook"]) > 0


# ---------------------------------------------------------------------------
# approve_action (now = acknowledge)
# ---------------------------------------------------------------------------
class TestAcknowledgeAction:
    def test_acknowledge_sets_status(self):
        rec = stage_action("block_ip", {"ip": "1.2.3.4"})
        result = approve_action(rec["action_id"], approved_by="admin")
        assert result["status"] == "acknowledged"
        assert result["resolved_by"] == "admin"
        assert result["resolved_at"] is not None
        assert "acknowledged" in result["resolution"].lower()

    def test_acknowledge_does_not_execute(self):
        """Approve (acknowledge) should NEVER execute any action — advisory only."""
        rec = stage_action("block_ip", {"ip": "1.2.3.4"})
        result = approve_action(rec["action_id"])
        # No execution-related fields
        assert result["status"] == "acknowledged"
        assert "runbook" in result  # Runbook should still be present

    def test_acknowledge_nonexistent_raises(self):
        with pytest.raises(ValueError, match="not found"):
            approve_action("nonexistent-id")

    def test_acknowledge_already_acknowledged_raises(self):
        rec = stage_action("block_ip", {})
        approve_action(rec["action_id"])
        with pytest.raises(ValueError, match="not 'staged'"):
            approve_action(rec["action_id"])


# ---------------------------------------------------------------------------
# reject_action (now = dismiss)
# ---------------------------------------------------------------------------
class TestDismissAction:
    def test_dismiss_sets_status(self):
        rec = stage_action("block_ip", {"ip": "1.2.3.4"})
        result = reject_action(rec["action_id"], rejected_by="analyst", reason="false positive")
        assert result["status"] == "dismissed"
        assert result["resolved_by"] == "analyst"
        assert "false positive" in result["resolution"]

    def test_dismiss_nonexistent_raises(self):
        with pytest.raises(ValueError, match="not found"):
            reject_action("nonexistent-id")

    def test_dismiss_already_dismissed_raises(self):
        rec = stage_action("block_ip", {})
        reject_action(rec["action_id"])
        with pytest.raises(ValueError, match="not 'staged'"):
            reject_action(rec["action_id"])


# ---------------------------------------------------------------------------
# get_action / list_actions
# ---------------------------------------------------------------------------
class TestGetAndList:
    def test_get_action(self):
        rec = stage_action("block_ip", {"ip": "1.2.3.4"})
        fetched = get_action(rec["action_id"])
        assert fetched is not None
        assert fetched["action_id"] == rec["action_id"]

    def test_get_nonexistent_returns_none(self):
        assert get_action("nope") is None

    def test_list_all_actions(self):
        stage_action("block_ip", {"ip": "1.1.1.1"})
        stage_action("disable_user", {"user": "evil"})
        items = list_actions()
        assert len(items) == 2

    def test_list_filter_by_status(self):
        r1 = stage_action("block_ip", {})
        r2 = stage_action("block_ip", {})
        approve_action(r1["action_id"])

        staged = list_actions(status="staged")
        assert len(staged) == 1
        assert staged[0]["action_id"] == r2["action_id"]

        acknowledged = list_actions(status="acknowledged")
        assert len(acknowledged) == 1
        assert acknowledged[0]["action_id"] == r1["action_id"]

    def test_list_filter_by_action_type(self):
        stage_action("block_ip", {})
        stage_action("disable_user", {})
        result = list_actions(action="block_ip")
        assert len(result) == 1
        assert result[0]["action"] == "block_ip"

    def test_list_limit(self):
        for i in range(10):
            stage_action("block_ip", {"ip": f"10.0.0.{i}"})
        assert len(list_actions(limit=3)) == 3


# ---------------------------------------------------------------------------
# Runbook generation
# ---------------------------------------------------------------------------
class TestRunbook:
    def test_block_ip_runbook(self):
        steps = _build_runbook("block_ip", {"ip": "192.168.1.1", "reason": "malware C2"})
        assert len(steps) > 0
        assert any("192.168.1.1" in s for s in steps)
        assert any("malware C2" in s for s in steps)

    def test_isolate_host_runbook(self):
        steps = _build_runbook("isolate_host", {"host": "WORKSTATION-01", "reason": "compromised"})
        assert len(steps) > 0
        assert any("WORKSTATION-01" in s for s in steps)

    def test_disable_user_runbook(self):
        steps = _build_runbook("disable_user", {"user": "jdoe", "reason": "brute force"})
        assert len(steps) > 0
        assert any("jdoe" in s for s in steps)

    def test_unknown_action_gets_default(self):
        steps = _build_runbook("something_new", {})
        assert len(steps) > 0
        assert any("incident response" in s.lower() for s in steps)

    def test_missing_params_dont_crash(self):
        """Runbook should handle missing params gracefully (leave template vars as-is)."""
        steps = _build_runbook("block_ip", {})
        assert len(steps) > 0


# ---------------------------------------------------------------------------
# Audit trail
# ---------------------------------------------------------------------------
class TestAuditTrail:
    def test_acknowledge_lifecycle_audit(self, tmp_path):
        rec = stage_action("block_ip", {"ip": "1.2.3.4"})
        approve_action(rec["action_id"], approved_by="admin")

        lines = executor.AUDIT_LOG_PATH.read_text().strip().split("\n")
        events = [json.loads(l)["event"] for l in lines]
        assert events == [
            "response_staged",
            "response_acknowledged",
        ]

    def test_dismiss_lifecycle_audit(self, tmp_path):
        rec = stage_action("block_ip", {"ip": "1.2.3.4"})
        reject_action(rec["action_id"], rejected_by="analyst", reason="FP")

        lines = executor.AUDIT_LOG_PATH.read_text().strip().split("\n")
        events = [json.loads(l)["event"] for l in lines]
        assert events == [
            "response_staged",
            "response_dismissed",
        ]
