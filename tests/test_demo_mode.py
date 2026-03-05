"""
Phase 17 M5: Demo mode response shape tests.

Validates that all demo data generator functions return dicts/lists
matching the exact shape expected by the dashboard JavaScript frontend.
"""

import os
import sys
from datetime import datetime, timezone

import pytest

# Enable demo mode before importing dashboard
os.environ["TINYSOCS_DEMO_MODE"] = "1"

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from tinysocs.api.dashboard import (  # noqa: E402
    _DEMO_MODE,
    _demo_alerts_summary,
    _demo_alerts_timeline,
    _demo_compliance_report,
    _demo_detections_fired,
    _demo_events_recent,
    _demo_fleet_health,
    _demo_host_timeline,
    _demo_nodes,
    _demo_threat_intel_status,
    _demo_version_status,
)


class TestDemoModeEnabled:
    """Verify demo mode flag is active."""

    def test_demo_mode_flag(self):
        assert _DEMO_MODE is True


class TestDemoAlertsSummary:
    """Verify _demo_alerts_summary returns the expected shape."""

    def test_shape(self):
        d = _demo_alerts_summary(24)
        assert isinstance(d, dict)
        assert "total" in d
        assert "severity" in d
        assert "top_rules" in d
        assert "top_hosts" in d

    def test_total_is_positive(self):
        d = _demo_alerts_summary(24)
        assert d["total"] > 0

    def test_severity_keys(self):
        d = _demo_alerts_summary(24)
        sev = d["severity"]
        for key in ("critical", "high", "medium", "low"):
            assert key in sev
            assert isinstance(sev[key], int)
            assert sev[key] >= 0

    def test_severity_sums_to_total(self):
        d = _demo_alerts_summary(24)
        total = sum(d["severity"].values())
        assert total == d["total"]

    def test_top_rules_structure(self):
        d = _demo_alerts_summary(24)
        assert isinstance(d["top_rules"], list)
        assert len(d["top_rules"]) > 0
        for rule in d["top_rules"]:
            assert "rule" in rule
            assert "count" in rule

    def test_top_hosts_structure(self):
        d = _demo_alerts_summary(24)
        assert isinstance(d["top_hosts"], list)
        assert len(d["top_hosts"]) > 0
        for host in d["top_hosts"]:
            assert "host" in host
            assert "count" in host


class TestDemoAlertsTimeline:
    """Verify _demo_alerts_timeline returns bucketed time-series data."""

    def test_shape(self):
        d = _demo_alerts_timeline(24)
        assert isinstance(d, dict)
        assert "buckets" in d

    def test_buckets_count(self):
        d = _demo_alerts_timeline(24)
        buckets = d["buckets"]
        assert isinstance(buckets, list)
        assert len(buckets) == 24

    def test_bucket_shape(self):
        d = _demo_alerts_timeline(24)
        for b in d["buckets"]:
            assert "time" in b
            assert "count" in b
            assert "severity" in b
            assert isinstance(b["severity"], dict)


class TestDemoDetectionsFired:
    """Verify _demo_detections_fired returns alert objects."""

    def test_shape(self):
        d = _demo_detections_fired(24, 50)
        assert isinstance(d, dict)
        assert "detections" in d
        assert "total" in d

    def test_alert_count(self):
        d = _demo_detections_fired(24, 50)
        alerts = d["detections"]
        assert isinstance(alerts, list)
        assert len(alerts) == 7  # 7 demo alerts

    def test_alert_fields(self):
        d = _demo_detections_fired(24, 50)
        for alert in d["detections"]:
            assert "rule_id" in alert
            assert "rule_name" in alert
            assert "severity" in alert
            assert "host" in alert
            assert "first_seen" in alert or "timestamp" in alert


class TestDemoFleetHealth:
    """Verify _demo_fleet_health returns host health data."""

    def test_shape(self):
        d = _demo_fleet_health()
        assert isinstance(d, dict)
        assert "hosts" in d

    def test_host_count(self):
        d = _demo_fleet_health()
        hosts = d["hosts"]
        assert isinstance(hosts, list)
        assert len(hosts) == 3  # 3 demo hosts

    def test_host_fields(self):
        d = _demo_fleet_health()
        required_fields = [
            "hostname", "event_count", "last_seen", "alert_count",
            "alert_severities", "top_channels", "agent_version",
        ]
        for host in d["hosts"]:
            for field in required_fields:
                assert field in host, f"Missing field '{field}' in host {host.get('hostname')}"

    def test_host_names(self):
        d = _demo_fleet_health()
        names = {h["hostname"] for h in d["hosts"]}
        assert "RECEPTION-PC" in names
        assert "FILESERVER-01" in names
        assert "DC-01" in names


class TestDemoHostTimeline:
    """Verify _demo_host_timeline returns per-host timeline data."""

    def test_shape(self):
        d = _demo_host_timeline("RECEPTION-PC", 24)
        assert isinstance(d, dict)
        assert "buckets" in d

    def test_buckets_have_channels(self):
        d = _demo_host_timeline("RECEPTION-PC", 24)
        for b in d["buckets"]:
            assert "time" in b
            assert "channels" in b
            assert isinstance(b["channels"], dict)

    def test_unknown_host_returns_empty_buckets(self):
        d = _demo_host_timeline("NONEXISTENT-HOST", 24)
        assert "buckets" in d
        assert isinstance(d["buckets"], list)


class TestDemoEventsRecent:
    """Verify _demo_events_recent returns event objects."""

    def test_shape(self):
        d = _demo_events_recent(20)
        assert isinstance(d, dict)
        assert "events" in d

    def test_event_count(self):
        d = _demo_events_recent(20)
        assert len(d["events"]) <= 20
        assert len(d["events"]) > 0

    def test_event_fields(self):
        d = _demo_events_recent(20)
        for evt in d["events"]:
            assert "timestamp" in evt
            assert "host" in evt
            assert "channel" in evt
            assert "event_id" in evt


class TestDemoVersionStatus:
    """Verify _demo_version_status returns version info."""

    def test_shape(self):
        d = _demo_version_status()
        assert isinstance(d, dict)
        assert "fleet_versions" in d
        assert "has_outdated" in d

    def test_host_count(self):
        d = _demo_version_status()
        assert len(d["fleet_versions"]) == 3

    def test_version_drift(self):
        """At least one host should be outdated in demo data."""
        d = _demo_version_status()
        assert d["has_outdated"] is True
        statuses = {h.get("status") for h in d["fleet_versions"]}
        assert "outdated-minor" in statuses


class TestDemoComplianceReport:
    """Verify _demo_compliance_report returns compliance data."""

    def test_nist_shape(self):
        d = _demo_compliance_report("nist_csf", 24)
        assert isinstance(d, dict)
        assert "framework" in d
        assert "controls" in d

    def test_hipaa_shape(self):
        d = _demo_compliance_report("hipaa", 24)
        assert isinstance(d, dict)
        assert "framework" in d

    def test_pci_shape(self):
        d = _demo_compliance_report("pci_dss", 24)
        assert isinstance(d, dict)
        assert "framework" in d

    def test_controls_structure(self):
        d = _demo_compliance_report("nist_csf", 24)
        controls = d["controls"]
        assert isinstance(controls, list)
        assert len(controls) > 0
        for ctrl in controls:
            assert "id" in ctrl
            assert "status" in ctrl
            assert ctrl["status"] in ("pass", "partial", "fail")


class TestDemoThreatIntelStatus:
    """Verify _demo_threat_intel_status returns provider info."""

    def test_shape(self):
        d = _demo_threat_intel_status()
        assert isinstance(d, dict)
        assert "providers" in d

    def test_provider_count(self):
        d = _demo_threat_intel_status()
        providers = d["providers"]
        assert isinstance(providers, list)
        assert len(providers) == 3  # AbuseIPDB, OTX, GreyNoise

    def test_provider_fields(self):
        d = _demo_threat_intel_status()
        for p in d["providers"]:
            assert "name" in p
            assert "configured" in p


class TestDemoNodes:
    """Verify _demo_nodes returns multi-site data."""

    def test_shape(self):
        d = _demo_nodes()
        assert isinstance(d, dict)
        assert "nodes" in d

    def test_node_count(self):
        d = _demo_nodes()
        assert len(d["nodes"]) == 3

    def test_node_fields(self):
        d = _demo_nodes()
        required = [
            "url", "node_id", "version", "status",
            "ledger_sequence", "last_anchor_at", "reachable",
        ]
        for node in d["nodes"]:
            for field in required:
                assert field in node, f"Missing field '{field}' in node {node.get('node_id')}"

    def test_node_statuses(self):
        d = _demo_nodes()
        statuses = {n["status"] for n in d["nodes"]}
        # At least one healthy and one warning
        assert "healthy" in statuses
        assert "warning" in statuses

    def test_node_ids(self):
        d = _demo_nodes()
        ids = {n["node_id"] for n in d["nodes"]}
        assert "acme-law" in ids
        assert "mainst-dental" in ids
        assert "harbor-ins" in ids


class TestDemoTimestampsRelative:
    """Verify all demo timestamps are recent (not hardcoded stale dates)."""

    def _parse_iso(self, ts):
        """Parse ISO timestamp, handling Z suffix."""
        if ts.endswith("Z"):
            ts = ts[:-1] + "+00:00"
        return datetime.fromisoformat(ts)

    def test_alerts_timeline_timestamps_recent(self):
        d = _demo_alerts_timeline(24)
        now = datetime.now(timezone.utc)
        for b in d["buckets"]:
            ts = self._parse_iso(b["time"])
            delta = abs((now - ts).total_seconds())
            assert delta < 90000, f"Timestamp {b['time']} is too far from now ({delta}s)"

    def test_fleet_health_timestamps_recent(self):
        d = _demo_fleet_health()
        now = datetime.now(timezone.utc)
        for host in d["hosts"]:
            ts = self._parse_iso(host["last_seen"])
            delta = abs((now - ts).total_seconds())
            assert delta < 7200, f"last_seen {host['last_seen']} too old ({delta}s)"

    def test_nodes_anchor_timestamps_recent(self):
        d = _demo_nodes()
        now = datetime.now(timezone.utc)
        for node in d["nodes"]:
            if node["last_anchor_at"]:
                ts = self._parse_iso(node["last_anchor_at"])
                delta = abs((now - ts).total_seconds())
                assert delta < 90000, f"Anchor ts {node['last_anchor_at']} too old ({delta}s)"

    def test_detections_timestamps_recent(self):
        d = _demo_detections_fired(24, 50)
        now = datetime.now(timezone.utc)
        for alert in d["detections"]:
            ts_str = alert.get("first_seen") or alert.get("timestamp")
            assert ts_str, f"Alert {alert.get('rule_id')} has no timestamp"
            ts = self._parse_iso(ts_str)
            delta = abs((now - ts).total_seconds())
            assert delta < 90000, f"Alert ts {ts_str} too old ({delta}s)"
