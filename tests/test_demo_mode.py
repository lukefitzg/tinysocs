"""
Phase 17 M5 + Phase 18 M5: Demo mode response shape tests.

Validates that all demo data generator functions return dicts/lists
matching the exact shape expected by the dashboard JavaScript frontend.

Phase 18 additions:
  - Per-site demo data generators (_demo_site_*)
  - Demo proxy handler (_demo_site_proxy)
  - Site data consistency checks
"""

import os
import sys
from datetime import datetime, timezone

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
    # Phase 18 M4: per-site demo data generators
    _demo_site_alerts_summary,
    _demo_site_alerts_timeline,
    _demo_site_detections_fired,
    _demo_site_events_recent,
    _demo_site_fleet_health,
    _demo_site_host_timeline,
    _demo_site_proxy,
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
            # Demo data uses the SAME status vocabulary as the real generator
            # (active/deployed/not_mapped) so it exercises the real render path.
            assert ctrl["status"] in ("active", "deployed", "not_mapped")


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
        assert "head-office" in ids
        assert "branch-north" in ids
        assert "warehouse" in ids


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


# =========================================================================
# Phase 18 M4+M5: Per-site demo data generators
# =========================================================================

_SITE_IDS = ["head-office", "branch-north", "warehouse"]


class TestDemoSiteAlertsSummary:
    """Per-site alert summary shape tests."""

    def test_all_sites_return_valid_shape(self):
        for site in _SITE_IDS:
            d = _demo_site_alerts_summary(site)
            assert "total" in d
            assert "severity" in d
            assert "top_rules" in d
            assert "top_hosts" in d
            assert d.get("error") is None

    def test_acme_alert_counts(self):
        d = _demo_site_alerts_summary("head-office")
        assert d["total"] == 14
        assert d["severity"]["critical"] == 2

    def test_dental_no_critical(self):
        d = _demo_site_alerts_summary("branch-north")
        assert d["total"] == 3
        # No critical key or critical == 0
        assert d["severity"].get("critical", 0) == 0

    def test_harbor_most_alerts(self):
        d = _demo_site_alerts_summary("warehouse")
        assert d["total"] == 31
        assert d["severity"]["critical"] == 3

    def test_unknown_site_returns_error(self):
        d = _demo_site_alerts_summary("nonexistent")
        assert "error" in d


class TestDemoSiteAlertsTimeline:
    """Per-site alert timeline shape tests."""

    def test_all_sites_return_buckets(self):
        for site in _SITE_IDS:
            d = _demo_site_alerts_timeline(site)
            assert "buckets" in d
            assert len(d["buckets"]) == 24

    def test_bucket_shape(self):
        d = _demo_site_alerts_timeline("head-office")
        for b in d["buckets"]:
            assert "time" in b
            assert "count" in b
            assert "severity" in b


class TestDemoSiteFleetHealth:
    """Per-site fleet health shape tests."""

    def test_acme_has_two_hosts(self):
        d = _demo_site_fleet_health("head-office")
        assert len(d["hosts"]) == 2
        names = {h["hostname"] for h in d["hosts"]}
        assert "RECEPTION-PC" in names
        assert "EXEC-LAPTOP" in names

    def test_dental_has_two_hosts(self):
        d = _demo_site_fleet_health("branch-north")
        assert len(d["hosts"]) == 2
        names = {h["hostname"] for h in d["hosts"]}
        assert "BRANCH-PC-01" in names
        assert "BRANCH-PC-02" in names

    def test_harbor_has_three_hosts(self):
        d = _demo_site_fleet_health("warehouse")
        assert len(d["hosts"]) == 3
        names = {h["hostname"] for h in d["hosts"]}
        assert "SHIPPING-PC" in names
        assert "INVENTORY-SERVER" in names
        assert "LOGISTICS-DB" in names

    def test_host_fields_present(self):
        for site in _SITE_IDS:
            d = _demo_site_fleet_health(site)
            for host in d["hosts"]:
                for field in ("hostname", "event_count", "last_seen",
                              "alert_count", "alert_severities", "top_channels"):
                    assert field in host, f"Missing {field} in {site} host {host.get('hostname')}"

    def test_no_host_overlap_between_sites(self):
        """Each site should have distinct hosts."""
        all_hosts = []
        for site in _SITE_IDS:
            d = _demo_site_fleet_health(site)
            all_hosts.extend(h["hostname"] for h in d["hosts"])
        assert len(all_hosts) == len(set(all_hosts)), "Hosts overlap between sites"


class TestDemoSiteDetectionsFired:
    """Per-site fired detections shape tests."""

    def test_all_sites_return_detections(self):
        for site in _SITE_IDS:
            d = _demo_site_detections_fired(site)
            assert "detections" in d
            assert "total" in d
            assert isinstance(d["detections"], list)

    def test_detection_fields(self):
        d = _demo_site_detections_fired("warehouse")
        for det in d["detections"]:
            for field in ("rule_id", "rule_name", "severity", "host", "timestamp"):
                assert field in det, f"Missing {field} in detection"


class TestDemoSiteEventsRecent:
    """Per-site recent events shape tests."""

    def test_all_sites_return_events(self):
        for site in _SITE_IDS:
            d = _demo_site_events_recent(site, 10)
            assert "events" in d
            assert len(d["events"]) > 0

    def test_event_fields(self):
        d = _demo_site_events_recent("head-office", 5)
        for evt in d["events"]:
            for field in ("timestamp", "host", "channel", "event_id"):
                assert field in evt

    def test_events_sorted_by_timestamp_desc(self):
        d = _demo_site_events_recent("warehouse", 20)
        ts = [e["timestamp"] for e in d["events"]]
        assert ts == sorted(ts, reverse=True)


class TestDemoSiteHostTimeline:
    """Per-site host timeline shape tests."""

    def test_all_sites_return_buckets(self):
        for site in _SITE_IDS:
            d = _demo_site_host_timeline(site)
            assert "buckets" in d
            assert len(d["buckets"]) == 24

    def test_buckets_have_channels(self):
        d = _demo_site_host_timeline("warehouse")
        for b in d["buckets"]:
            assert "time" in b
            assert "channels" in b
            assert isinstance(b["channels"], dict)


class TestDemoSiteProxy:
    """Test the demo site proxy dispatcher."""

    def test_known_site_alerts_summary(self):
        d = _demo_site_proxy("head-office", "alerts/summary", {})
        assert d["total"] == 14
        assert d.get("error") is None

    def test_known_site_fleet_health(self):
        d = _demo_site_proxy("warehouse", "fleet/health", {})
        assert len(d["hosts"]) == 3

    def test_known_site_detections_fired(self):
        d = _demo_site_proxy("branch-north", "detections/fired", {})
        assert "detections" in d

    def test_known_site_events_recent(self):
        d = _demo_site_proxy("head-office", "events/recent", {"limit": "5"})
        assert "events" in d

    def test_known_site_host_timeline(self):
        d = _demo_site_proxy("warehouse", "host/timeline",
                             {"hostname": "INVENTORY-SERVER", "hours": "12"})
        assert "buckets" in d

    def test_unknown_site_returns_404(self):
        from fastapi.responses import JSONResponse
        result = _demo_site_proxy("nonexistent", "alerts/summary", {})
        assert isinstance(result, JSONResponse)
        assert result.status_code == 404

    def test_unknown_endpoint_returns_404(self):
        from fastapi.responses import JSONResponse
        result = _demo_site_proxy("head-office", "unknown/path", {})
        assert isinstance(result, JSONResponse)
        assert result.status_code == 404


class TestDemoSiteDataConsistency:
    """Verify consistency between site cards and drill-through data."""

    def test_card_alert_count_matches_drillthrough(self):
        """Site card alerts_24h should equal drill-through alerts/summary total."""
        nodes = _demo_nodes()
        for node in nodes["nodes"]:
            nid = node["node_id"]
            summary = _demo_site_alerts_summary(nid)
            assert node["alerts_24h"] == summary["total"], (
                f"{nid}: card shows {node['alerts_24h']} but "
                f"drill-through shows {summary['total']}"
            )

    def test_card_host_count_matches_drillthrough(self):
        """Site card host_count should equal drill-through fleet/health host count."""
        nodes = _demo_nodes()
        for node in nodes["nodes"]:
            nid = node["node_id"]
            fleet = _demo_site_fleet_health(nid)
            assert node["host_count"] == len(fleet["hosts"]), (
                f"{nid}: card shows {node['host_count']} hosts but "
                f"drill-through shows {len(fleet['hosts'])}"
            )

    def test_aggregate_matches_sum(self):
        """Aggregate totals should equal sum of per-site summaries."""
        nodes = _demo_nodes()
        agg = nodes["aggregate"]
        total_from_sites = sum(
            _demo_site_alerts_summary(n["node_id"])["total"]
            for n in nodes["nodes"]
        )
        assert agg["total_alerts_24h"] == total_from_sites


class TestDemoSiteTimestampsRelative:
    """Verify per-site demo timestamps are recent."""

    def _parse_iso(self, ts):
        if ts.endswith("Z"):
            ts = ts[:-1] + "+00:00"
        return datetime.fromisoformat(ts)

    def test_site_fleet_timestamps_recent(self):
        now = datetime.now(timezone.utc)
        for site in _SITE_IDS:
            d = _demo_site_fleet_health(site)
            for host in d["hosts"]:
                ts = self._parse_iso(host["last_seen"])
                delta = abs((now - ts).total_seconds())
                assert delta < 7200, f"{site} host {host['hostname']} last_seen too old"

    def test_site_detections_timestamps_recent(self):
        now = datetime.now(timezone.utc)
        for site in _SITE_IDS:
            d = _demo_site_detections_fired(site)
            for det in d["detections"]:
                ts = self._parse_iso(det["timestamp"])
                delta = abs((now - ts).total_seconds())
                assert delta < 90000, f"{site} detection {det['rule_id']} timestamp too old"


# ---------------------------------------------------------------------------
# Phase 19 M5: Demo mode HTTPS URL tests
# ---------------------------------------------------------------------------

class TestDemoNodesHttps:
    """Phase 19: Verify demo nodes use https:// URLs."""

    def test_demo_node_urls_use_https(self):
        """All demo node URLs should use https:// prefix."""
        result = _demo_nodes()
        for node in result["nodes"]:
            url = node.get("url", "")
            assert url.startswith("https://"), \
                f"Demo node {node.get('node_id')} uses non-https URL: {url}"

    def test_demo_node_urls_include_port(self):
        """All demo node URLs should include port 8081."""
        result = _demo_nodes()
        for node in result["nodes"]:
            url = node.get("url", "")
            assert ":8081" in url, \
                f"Demo node {node.get('node_id')} missing port in URL: {url}"
