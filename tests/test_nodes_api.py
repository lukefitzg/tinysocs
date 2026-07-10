"""
Phase 17 M5 + Phase 18 M5: Node awareness API tests.

Validates the /api/nodes endpoint logic including:
  - Empty TINYSOCS_NODES config
  - Demo mode node response shape
  - Node URL parsing from environment variable
  - Phase 18 M1: operational data fields (alerts, hosts, events)
  - Phase 18 M1: aggregate summary across nodes
  - Phase 18 M3: node_id → URL cache for proxy
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import tinysocs.api.dashboard as dashboard_mod


class TestGetNodeUrls:
    """Test the _get_node_urls helper that parses TINYSOCS_NODES."""

    def _call(self):
        """Call _get_node_urls with fresh cache."""
        dashboard_mod._NODES_LIST = None  # Reset cache
        return dashboard_mod._get_node_urls()

    def test_empty_env(self, monkeypatch):
        monkeypatch.delenv("TINYSOCS_NODES", raising=False)
        assert self._call() == []

    def test_single_node(self, monkeypatch):
        monkeypatch.setenv("TINYSOCS_NODES", "http://node1:8081")
        assert self._call() == ["http://node1:8081"]

    def test_multiple_nodes(self, monkeypatch):
        monkeypatch.setenv("TINYSOCS_NODES", "http://node1:8081,http://node2:8082")
        urls = self._call()
        assert len(urls) == 2
        assert "http://node1:8081" in urls
        assert "http://node2:8082" in urls

    def test_whitespace_stripped(self, monkeypatch):
        monkeypatch.setenv("TINYSOCS_NODES", "  http://node1:8081 , http://node2:8082  ")
        urls = self._call()
        assert urls == ["http://node1:8081", "http://node2:8082"]

    def test_empty_string(self, monkeypatch):
        monkeypatch.setenv("TINYSOCS_NODES", "")
        assert self._call() == []

    def test_trailing_comma(self, monkeypatch):
        monkeypatch.setenv("TINYSOCS_NODES", "http://node1:8081,")
        urls = self._call()
        assert urls == ["http://node1:8081"]


class TestDemoNodesEndpoint:
    """Test demo mode nodes response (no network calls)."""

    def test_demo_nodes_returns_three_sites(self):
        os.environ["TINYSOCS_DEMO_MODE"] = "1"
        d = dashboard_mod._demo_nodes()
        assert len(d["nodes"]) == 3

    def test_demo_nodes_all_reachable(self):
        os.environ["TINYSOCS_DEMO_MODE"] = "1"
        d = dashboard_mod._demo_nodes()
        for node in d["nodes"]:
            assert node["reachable"] is True

    def test_demo_nodes_harbor_version_drift(self):
        """Harbor Insurance should show version 0.8.9 (outdated)."""
        os.environ["TINYSOCS_DEMO_MODE"] = "1"
        d = dashboard_mod._demo_nodes()
        harbor = [n for n in d["nodes"] if n["node_id"] == "warehouse"]
        assert len(harbor) == 1
        assert harbor[0]["version"] == "0.8.9"
        assert harbor[0]["status"] == "warning"

    def test_demo_nodes_acme_healthy(self):
        os.environ["TINYSOCS_DEMO_MODE"] = "1"
        d = dashboard_mod._demo_nodes()
        acme = [n for n in d["nodes"] if n["node_id"] == "head-office"]
        assert len(acme) == 1
        assert acme[0]["status"] == "healthy"
        assert acme[0]["version"] == "0.9.0"

    def test_demo_nodes_detection_counts(self):
        """Verify detection counts match plan: acme=2, dental=0, harbor=5."""
        os.environ["TINYSOCS_DEMO_MODE"] = "1"
        d = dashboard_mod._demo_nodes()
        by_id = {n["node_id"]: n for n in d["nodes"]}
        assert by_id["head-office"]["last_anchor_items"] == 2
        assert by_id["branch-north"]["last_anchor_items"] == 0
        assert by_id["warehouse"]["last_anchor_items"] == 5


class TestNodeResponseContract:
    """Verify the node response contract matches what the JS frontend expects."""

    def test_node_has_all_js_expected_fields(self):
        """The loadSites() JS function reads these fields from each node."""
        os.environ["TINYSOCS_DEMO_MODE"] = "1"
        d = dashboard_mod._demo_nodes()
        js_expected = [
            "url", "node_id", "version", "status",
            "ledger_sequence", "ledger_head",
            "last_anchor_at", "last_anchor_items",
            "reachable", "error",
        ]
        for node in d["nodes"]:
            for field in js_expected:
                assert field in node, (
                    f"Node {node.get('node_id')} missing field '{field}' "
                    f"expected by dashboard JS"
                )


# ---------------------------------------------------------------------------
# Phase 18 M1: Operational data fields
# ---------------------------------------------------------------------------

class TestPhase18OperationalFields:
    """Verify Phase 18 M1 enriched operational data in /api/nodes response."""

    def test_demo_nodes_have_operational_fields(self):
        """Each demo node should include alert/fleet operational data."""
        os.environ["TINYSOCS_DEMO_MODE"] = "1"
        d = dashboard_mod._demo_nodes()
        ops_fields = [
            "alerts_24h", "alerts_critical", "alerts_high",
            "top_rule", "host_count", "total_events_24h",
        ]
        for node in d["nodes"]:
            for field in ops_fields:
                assert field in node, (
                    f"Node {node.get('node_id')} missing Phase 18 field '{field}'"
                )

    def test_demo_acme_alert_data(self):
        """head-office: 14 alerts, 2 critical, 5 high."""
        os.environ["TINYSOCS_DEMO_MODE"] = "1"
        d = dashboard_mod._demo_nodes()
        acme = [n for n in d["nodes"] if n["node_id"] == "head-office"][0]
        assert acme["alerts_24h"] == 14
        assert acme["alerts_critical"] == 2
        assert acme["alerts_high"] == 5
        assert acme["top_rule"] == "brute_force_password"

    def test_demo_dental_alert_data(self):
        """branch-north: 3 alerts, 0 critical, 1 high."""
        os.environ["TINYSOCS_DEMO_MODE"] = "1"
        d = dashboard_mod._demo_nodes()
        dental = [n for n in d["nodes"] if n["node_id"] == "branch-north"][0]
        assert dental["alerts_24h"] == 3
        assert dental["alerts_critical"] == 0
        assert dental["alerts_high"] == 1

    def test_demo_harbor_alert_data(self):
        """warehouse: 31 alerts, 3 critical, 8 high, 3 hosts."""
        os.environ["TINYSOCS_DEMO_MODE"] = "1"
        d = dashboard_mod._demo_nodes()
        harbor = [n for n in d["nodes"] if n["node_id"] == "warehouse"][0]
        assert harbor["alerts_24h"] == 31
        assert harbor["alerts_critical"] == 3
        assert harbor["alerts_high"] == 8
        assert harbor["host_count"] == 3

    def test_demo_host_counts(self):
        """acme: 2, dental: 2, harbor: 3."""
        os.environ["TINYSOCS_DEMO_MODE"] = "1"
        d = dashboard_mod._demo_nodes()
        by_id = {n["node_id"]: n for n in d["nodes"]}
        assert by_id["head-office"]["host_count"] == 2
        assert by_id["branch-north"]["host_count"] == 2
        assert by_id["warehouse"]["host_count"] == 3


# ---------------------------------------------------------------------------
# Phase 18 M1: Aggregate summary
# ---------------------------------------------------------------------------

class TestPhase18Aggregate:
    """Verify Phase 18 M1 aggregate summary across all nodes."""

    def test_aggregate_present(self):
        os.environ["TINYSOCS_DEMO_MODE"] = "1"
        d = dashboard_mod._demo_nodes()
        assert "aggregate" in d
        assert d["aggregate"] is not None

    def test_aggregate_fields(self):
        os.environ["TINYSOCS_DEMO_MODE"] = "1"
        d = dashboard_mod._demo_nodes()
        agg = d["aggregate"]
        for field in ("total_alerts_24h", "total_critical", "total_high",
                      "total_hosts", "sites_healthy", "sites_warning",
                      "sites_unreachable"):
            assert field in agg, f"Aggregate missing field: {field}"

    def test_aggregate_totals_match_sum(self):
        """Aggregate totals should equal sum of per-node values."""
        os.environ["TINYSOCS_DEMO_MODE"] = "1"
        d = dashboard_mod._demo_nodes()
        nodes = d["nodes"]
        agg = d["aggregate"]
        assert agg["total_alerts_24h"] == sum(n["alerts_24h"] for n in nodes)
        assert agg["total_critical"] == sum(n["alerts_critical"] for n in nodes)
        assert agg["total_high"] == sum(n["alerts_high"] for n in nodes)
        assert agg["total_hosts"] == sum(n["host_count"] for n in nodes)

    def test_aggregate_site_statuses(self):
        os.environ["TINYSOCS_DEMO_MODE"] = "1"
        d = dashboard_mod._demo_nodes()
        agg = d["aggregate"]
        # 2 healthy (acme, dental) + 1 warning (harbor)
        assert agg["sites_healthy"] == 2
        assert agg["sites_warning"] == 1
        assert agg["sites_unreachable"] == 0
