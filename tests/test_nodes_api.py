"""
Phase 17 M5: Node awareness API tests.

Validates the /api/nodes endpoint logic including:
  - Empty TINYSOCS_NODES config
  - Demo mode node response shape
  - Node URL parsing from environment variable
"""

import os
import sys

import pytest

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
        """Harbor Insurance should show version 0.7.9 (outdated)."""
        os.environ["TINYSOCS_DEMO_MODE"] = "1"
        d = dashboard_mod._demo_nodes()
        harbor = [n for n in d["nodes"] if n["node_id"] == "harbor-ins"]
        assert len(harbor) == 1
        assert harbor[0]["version"] == "0.7.9"
        assert harbor[0]["status"] == "warning"

    def test_demo_nodes_acme_healthy(self):
        os.environ["TINYSOCS_DEMO_MODE"] = "1"
        d = dashboard_mod._demo_nodes()
        acme = [n for n in d["nodes"] if n["node_id"] == "acme-law"]
        assert len(acme) == 1
        assert acme[0]["status"] == "healthy"
        assert acme[0]["version"] == "0.8.0"

    def test_demo_nodes_detection_counts(self):
        """Verify detection counts match plan: acme=2, dental=0, harbor=5."""
        os.environ["TINYSOCS_DEMO_MODE"] = "1"
        d = dashboard_mod._demo_nodes()
        by_id = {n["node_id"]: n for n in d["nodes"]}
        assert by_id["acme-law"]["last_anchor_items"] == 2
        assert by_id["mainst-dental"]["last_anchor_items"] == 0
        assert by_id["harbor-ins"]["last_anchor_items"] == 5


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
