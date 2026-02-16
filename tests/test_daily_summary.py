# tests/test_daily_summary.py
"""Unit tests for the daily summary report generator (Phase 12 / M3)."""

import os
from unittest.mock import patch, MagicMock

import pytest

from tinysocs.reporting.daily_summary import (
    _alerts_by_severity,
    _top_rules,
    _top_hosts,
    _total_alerts,
    _alert_trend,
    _new_hosts_seen,
    _host_count,
    _severity_color,
    generate_summary,
    send_email,
)


# ---------------------------------------------------------------------------
# Helpers: mock OpenSearch responses
# ---------------------------------------------------------------------------
def _os_agg_response(agg_name, buckets, total=0):
    """Build a minimal OpenSearch aggregation response."""
    return {
        "hits": {"total": {"value": total, "relation": "eq"}, "hits": []},
        "aggregations": {agg_name: {"buckets": buckets}},
    }


def _os_cardinality_response(agg_name, value):
    return {
        "hits": {"total": {"value": 0}, "hits": []},
        "aggregations": {agg_name: {"value": value}},
    }


# ---------------------------------------------------------------------------
# _alerts_by_severity
# ---------------------------------------------------------------------------
class TestAlertsBySeverity:
    @patch("tinysocs.reporting.daily_summary._os_query")
    def test_returns_severity_dict(self, mock_q):
        mock_q.return_value = _os_agg_response("by_severity", [
            {"key": "high", "doc_count": 5},
            {"key": "medium", "doc_count": 3},
        ])
        result = _alerts_by_severity(24)
        assert result == {"high": 5, "medium": 3}
        mock_q.assert_called_once()

    @patch("tinysocs.reporting.daily_summary._os_query")
    def test_returns_empty_on_error(self, mock_q):
        mock_q.side_effect = ConnectionError("offline")
        assert _alerts_by_severity(24) == {}


# ---------------------------------------------------------------------------
# _top_rules
# ---------------------------------------------------------------------------
class TestTopRules:
    @patch("tinysocs.reporting.daily_summary._os_query")
    def test_returns_tuples(self, mock_q):
        mock_q.return_value = _os_agg_response("by_rule", [
            {"key": "TS-001", "doc_count": 12},
            {"key": "TS-030", "doc_count": 4},
        ])
        result = _top_rules(24, top_n=5)
        assert result == [("TS-001", 12), ("TS-030", 4)]

    @patch("tinysocs.reporting.daily_summary._os_query")
    def test_empty_on_error(self, mock_q):
        mock_q.side_effect = Exception("fail")
        assert _top_rules(24) == []


# ---------------------------------------------------------------------------
# _top_hosts
# ---------------------------------------------------------------------------
class TestTopHosts:
    @patch("tinysocs.reporting.daily_summary._os_query")
    def test_returns_tuples(self, mock_q):
        mock_q.return_value = _os_agg_response("by_host", [
            {"key": "DC01", "doc_count": 8},
            {"key": "WEB02", "doc_count": 2},
        ])
        assert _top_hosts(24) == [("DC01", 8), ("WEB02", 2)]


# ---------------------------------------------------------------------------
# _total_alerts
# ---------------------------------------------------------------------------
class TestTotalAlerts:
    @patch("tinysocs.reporting.daily_summary._os_query")
    def test_returns_count(self, mock_q):
        mock_q.return_value = {"hits": {"total": {"value": 42, "relation": "eq"}}}
        assert _total_alerts(24) == 42

    @patch("tinysocs.reporting.daily_summary._os_query")
    def test_handles_legacy_total_format(self, mock_q):
        mock_q.return_value = {"hits": {"total": 7}}
        assert _total_alerts(24) == 7

    @patch("tinysocs.reporting.daily_summary._os_query")
    def test_zero_on_error(self, mock_q):
        mock_q.side_effect = RuntimeError("boom")
        assert _total_alerts(24) == 0


# ---------------------------------------------------------------------------
# _alert_trend
# ---------------------------------------------------------------------------
class TestAlertTrend:
    @patch("tinysocs.reporting.daily_summary._total_alerts")
    def test_trend_up(self, mock_total):
        mock_total.side_effect = [10, 15]  # 24h=10, 48h=15 → yesterday=5
        today, yesterday, arrow = _alert_trend()
        assert today == 10
        assert yesterday == 5
        assert arrow == "up"

    @patch("tinysocs.reporting.daily_summary._total_alerts")
    def test_trend_down(self, mock_total):
        mock_total.side_effect = [3, 20]  # 24h=3, 48h=20 → yesterday=17
        today, yesterday, arrow = _alert_trend()
        assert today == 3
        assert yesterday == 17
        assert arrow == "down"

    @patch("tinysocs.reporting.daily_summary._total_alerts")
    def test_trend_flat(self, mock_total):
        mock_total.side_effect = [5, 10]  # 24h=5, 48h=10 → yesterday=5
        today, yesterday, arrow = _alert_trend()
        assert arrow == "flat"

    @patch("tinysocs.reporting.daily_summary._total_alerts")
    def test_negative_yesterday_clamped(self, mock_total):
        # Edge case: 48h total less than 24h (e.g. data deleted)
        mock_total.side_effect = [10, 5]  # yesterday = 5 - 10 = -5 → clamped to 0
        today, yesterday, arrow = _alert_trend()
        assert yesterday == 0


# ---------------------------------------------------------------------------
# _new_hosts_seen
# ---------------------------------------------------------------------------
class TestNewHostsSeen:
    @patch("tinysocs.reporting.daily_summary._os_query")
    def test_detects_new_hosts(self, mock_q):
        # First call: recent hosts; second call: older hosts
        mock_q.side_effect = [
            _os_agg_response("hosts", [
                {"key": "DC01", "doc_count": 5},
                {"key": "NEW-HOST", "doc_count": 1},
            ]),
            _os_agg_response("hosts", [
                {"key": "DC01", "doc_count": 50},
            ]),
        ]
        assert _new_hosts_seen(24) == ["NEW-HOST"]

    @patch("tinysocs.reporting.daily_summary._os_query")
    def test_no_new_hosts(self, mock_q):
        mock_q.side_effect = [
            _os_agg_response("hosts", [{"key": "DC01", "doc_count": 5}]),
            _os_agg_response("hosts", [{"key": "DC01", "doc_count": 50}]),
        ]
        assert _new_hosts_seen(24) == []

    @patch("tinysocs.reporting.daily_summary._os_query")
    def test_empty_on_error(self, mock_q):
        mock_q.side_effect = Exception("fail")
        assert _new_hosts_seen(24) == []


# ---------------------------------------------------------------------------
# _host_count
# ---------------------------------------------------------------------------
class TestHostCount:
    @patch("tinysocs.reporting.daily_summary._os_query")
    def test_returns_cardinality(self, mock_q):
        mock_q.return_value = _os_cardinality_response("hosts", 7)
        assert _host_count() == 7


# ---------------------------------------------------------------------------
# _severity_color
# ---------------------------------------------------------------------------
def test_severity_color_known():
    assert _severity_color("critical") == "#e74c3c"
    assert _severity_color("high") == "#e67e22"
    assert _severity_color("medium") == "#f39c12"
    assert _severity_color("low") == "#3498db"
    assert _severity_color("info") == "#95a5a6"

def test_severity_color_unknown():
    assert _severity_color("unknown") == "#95a5a6"

def test_severity_color_case_insensitive():
    assert _severity_color("HIGH") == "#e67e22"
    assert _severity_color("Critical") == "#e74c3c"


# ---------------------------------------------------------------------------
# generate_summary — integration-level with mocked queries
# ---------------------------------------------------------------------------
class TestGenerateSummary:
    @patch("tinysocs.reporting.daily_summary._host_count", return_value=3)
    @patch("tinysocs.reporting.daily_summary._new_hosts_seen", return_value=[])
    @patch("tinysocs.reporting.daily_summary._alert_trend", return_value=(0, 0, "flat"))
    @patch("tinysocs.reporting.daily_summary._top_hosts", return_value=[])
    @patch("tinysocs.reporting.daily_summary._top_rules", return_value=[])
    @patch("tinysocs.reporting.daily_summary._alerts_by_severity", return_value={})
    def test_no_alerts_shows_all_quiet(self, *mocks):
        html = generate_summary(24)
        assert "All Quiet" in html
        assert "3 monitored hosts" in html
        assert "TinySocs Daily Summary" in html

    @patch("tinysocs.reporting.daily_summary._host_count", return_value=5)
    @patch("tinysocs.reporting.daily_summary._new_hosts_seen", return_value=["NEW01"])
    @patch("tinysocs.reporting.daily_summary._alert_trend", return_value=(15, 10, "up"))
    @patch("tinysocs.reporting.daily_summary._top_hosts", return_value=[("DC01", 8), ("WEB02", 7)])
    @patch("tinysocs.reporting.daily_summary._top_rules", return_value=[("TS-001", 10), ("TS-030", 5)])
    @patch("tinysocs.reporting.daily_summary._alerts_by_severity", return_value={"high": 10, "medium": 5})
    def test_with_alerts_shows_breakdown(self, *mocks):
        html = generate_summary(24)
        assert "15 Alerts" in html
        assert "All Quiet" not in html
        assert "High" in html
        assert "TS-001" in html
        assert "DC01" in html
        assert "NEW01" in html

    @patch("tinysocs.reporting.daily_summary._host_count", return_value=0)
    @patch("tinysocs.reporting.daily_summary._new_hosts_seen", return_value=[])
    @patch("tinysocs.reporting.daily_summary._alert_trend", return_value=(0, 0, "flat"))
    @patch("tinysocs.reporting.daily_summary._top_hosts", return_value=[])
    @patch("tinysocs.reporting.daily_summary._top_rules", return_value=[])
    @patch("tinysocs.reporting.daily_summary._alerts_by_severity", return_value={})
    def test_html_has_template_structure(self, *mocks):
        html = generate_summary(24)
        assert "<!DOCTYPE html>" in html or "<html>" in html
        assert "Open Dashboards" in html


# ---------------------------------------------------------------------------
# send_email
# ---------------------------------------------------------------------------
class TestSendEmail:
    def test_no_smtp_host_prints_to_stdout(self, capsys):
        os.environ.pop("TINYSOCS_SMTP_HOST", None)
        result = send_email("<html>test</html>", to="admin@test.com")
        assert result is False
        captured = capsys.readouterr()
        assert "No SMTP host configured" in captured.out

    @patch("tinysocs.reporting.daily_summary.smtplib.SMTP")
    def test_sends_email_with_smtp(self, mock_smtp_cls):
        mock_server = MagicMock()
        mock_smtp_cls.return_value.__enter__ = MagicMock(return_value=mock_server)
        mock_smtp_cls.return_value.__exit__ = MagicMock(return_value=False)

        result = send_email(
            "<html>test</html>",
            to="admin@test.com",
            smtp_host="mail.test.com",
            smtp_port=587,
            from_addr="tinysocs@test.com",
        )
        assert result is True
        mock_smtp_cls.assert_called_once_with("mail.test.com", 587, timeout=30)

    @patch("tinysocs.reporting.daily_summary.smtplib.SMTP")
    def test_returns_false_on_smtp_error(self, mock_smtp_cls):
        mock_smtp_cls.side_effect = ConnectionRefusedError("no server")
        result = send_email(
            "<html>test</html>",
            to="admin@test.com",
            smtp_host="bad.host",
        )
        assert result is False
