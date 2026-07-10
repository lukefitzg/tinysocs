"""
Phase 18 M5: Node endpoint response shape tests.

Validates that node.py's M0 + M2 endpoints return responses matching
the shapes expected by the dashboard JS frontend.  All tests mock
_os_search_raw() so no real OpenSearch is needed.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

# Suppress warnings from node startup
os.environ.setdefault("MASTER_SHARED_SECRET", "test-secret-for-unit-tests")

from fastapi.testclient import TestClient  # noqa: E402

import tinysocs.api.node as node_mod  # noqa: E402

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def client():
    return TestClient(node_mod.app)


@pytest.fixture(autouse=True)
def _mock_os_search(monkeypatch):
    """Mock _os_search_raw to return empty OpenSearch responses."""
    empty = {"hits": {"total": {"value": 0}, "hits": []}, "aggregations": {}}
    monkeypatch.setattr(node_mod, "_os_search_raw", lambda *a, **kw: empty)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_os_response(total=0, hits=None, aggs=None):
    """Build a synthetic OpenSearch response dict."""
    return {
        "hits": {
            "total": {"value": total},
            "hits": hits or [],
        },
        "aggregations": aggs or {},
    }


# ---------------------------------------------------------------------------
# M0: /alerts/summary
# ---------------------------------------------------------------------------

class TestAlertsSummary:
    """GET /alerts/summary response shape tests."""

    def test_empty_opensearch(self, client):
        resp = client.get("/alerts/summary")
        assert resp.status_code == 200
        d = resp.json()
        assert d["total"] == 0
        assert d["severity"] == {}
        assert d["top_rules"] == []
        assert d["top_hosts"] == []
        assert d.get("error") is None

    def test_shape_fields(self, client):
        resp = client.get("/alerts/summary")
        d = resp.json()
        for field in ("hours", "total", "severity", "top_rules", "top_hosts"):
            assert field in d, f"Missing field: {field}"

    def test_hours_parameter(self, client):
        resp = client.get("/alerts/summary?hours=48")
        d = resp.json()
        assert d["hours"] == 48

    def test_with_severity_data(self, client, monkeypatch):
        """Simulate OpenSearch returning severity aggregation buckets."""
        call_count = [0]

        def mock_search(index_pattern, body, size=0):
            call_count[0] += 1
            if call_count[0] == 1:
                # First call: severity agg
                return _make_os_response(total=10, aggs={
                    "by_severity": {
                        "buckets": [
                            {"key": "critical", "doc_count": 2},
                            {"key": "high", "doc_count": 3},
                            {"key": "medium", "doc_count": 5},
                        ]
                    }
                })
            elif call_count[0] == 2:
                # Second call: top rules agg
                return _make_os_response(total=10, aggs={
                    "by_rule": {
                        "buckets": [
                            {"key": "brute_force", "doc_count": 5},
                            {"key": "fim_change", "doc_count": 3},
                        ]
                    }
                })
            else:
                # Third call: top hosts agg
                return _make_os_response(total=10, aggs={
                    "by_host": {
                        "buckets": [
                            {"key": "RECEPTION-PC", "doc_count": 6},
                            {"key": "DC-01", "doc_count": 4},
                        ]
                    }
                })

        monkeypatch.setattr(node_mod, "_os_search_raw", mock_search)
        resp = client.get("/alerts/summary")
        d = resp.json()
        assert d["total"] == 10
        assert d["severity"]["critical"] == 2
        assert d["severity"]["high"] == 3
        assert len(d["top_rules"]) == 2
        assert d["top_rules"][0]["rule"] == "brute_force"
        assert len(d["top_hosts"]) == 2


# ---------------------------------------------------------------------------
# M0: /fleet/summary
# ---------------------------------------------------------------------------

class TestFleetSummary:
    """GET /fleet/summary response shape tests."""

    def test_empty_opensearch(self, client):
        resp = client.get("/fleet/summary")
        assert resp.status_code == 200
        d = resp.json()
        assert d["host_count"] == 0
        assert d["total_events_24h"] == 0
        assert d["hosts"] == []

    def test_shape_fields(self, client):
        resp = client.get("/fleet/summary")
        d = resp.json()
        for field in ("host_count", "total_events_24h", "hosts"):
            assert field in d, f"Missing field: {field}"

    def test_with_hosts(self, client, monkeypatch):
        def mock_search(index_pattern, body, size=0):
            return _make_os_response(total=1000, aggs={
                "by_host": {
                    "buckets": [
                        {
                            "key": "RECEPTION-PC",
                            "doc_count": 600,
                            "last_seen": {"value_as_string": "2026-03-07T10:00:00.000Z"},
                        },
                        {
                            "key": "DC-01",
                            "doc_count": 400,
                            "last_seen": {"value_as_string": "2026-03-07T09:50:00.000Z"},
                        },
                    ]
                }
            })

        monkeypatch.setattr(node_mod, "_os_search_raw", mock_search)
        resp = client.get("/fleet/summary")
        d = resp.json()
        assert d["host_count"] == 2
        assert d["total_events_24h"] == 1000
        assert len(d["hosts"]) == 2
        assert d["hosts"][0]["hostname"] == "RECEPTION-PC"
        assert d["hosts"][0]["events_24h"] == 600


# ---------------------------------------------------------------------------
# M2: /alerts/timeline
# ---------------------------------------------------------------------------

class TestAlertsTimeline:
    """GET /alerts/timeline response shape tests."""

    def test_empty_opensearch(self, client):
        resp = client.get("/alerts/timeline")
        assert resp.status_code == 200
        d = resp.json()
        assert "buckets" in d
        assert "hours" in d

    def test_hours_parameter(self, client):
        resp = client.get("/alerts/timeline?hours=12")
        d = resp.json()
        assert d["hours"] == 12

    def test_with_timeline_data(self, client, monkeypatch):
        def mock_search(index_pattern, body, size=0):
            return _make_os_response(total=5, aggs={
                "timeline": {
                    "buckets": [
                        {
                            "key_as_string": "2026-03-07T10:00:00.000Z",
                            "doc_count": 3,
                            "by_severity": {
                                "buckets": [
                                    {"key": "critical", "doc_count": 1},
                                    {"key": "high", "doc_count": 2},
                                ]
                            }
                        },
                        {
                            "key_as_string": "2026-03-07T11:00:00.000Z",
                            "doc_count": 2,
                            "by_severity": {
                                "buckets": [
                                    {"key": "medium", "doc_count": 2},
                                ]
                            }
                        },
                    ]
                }
            })

        monkeypatch.setattr(node_mod, "_os_search_raw", mock_search)
        resp = client.get("/alerts/timeline")
        d = resp.json()
        assert len(d["buckets"]) == 2
        assert d["buckets"][0]["count"] == 3
        assert d["buckets"][0]["severity"]["critical"] == 1


# ---------------------------------------------------------------------------
# M2: /detections/fired
# ---------------------------------------------------------------------------

class TestDetectionsFired:
    """GET /detections/fired response shape tests."""

    def test_empty_opensearch(self, client):
        resp = client.get("/detections/fired")
        assert resp.status_code == 200
        d = resp.json()
        assert "detections" in d
        assert d["detections"] == []

    def test_shape_fields(self, client):
        resp = client.get("/detections/fired")
        d = resp.json()
        for field in ("total", "detections"):
            assert field in d

    def test_with_detections(self, client, monkeypatch):
        def mock_search(index_pattern, body, size=0):
            return _make_os_response(total=1, hits=[
                {
                    "_source": {
                        "alert": {
                            "id": "test-alert-1",
                            "rule_id": "TS-001",
                            "rule_name": "brute_force",
                            "severity": "critical",
                            "description": "Brute force detected",
                            "event_count": 5,
                            "matched_events": 5,
                        },
                        "source": {"computer_name": "RECEPTION-PC"},
                        "timestamp": "2026-03-07T10:00:00.000Z",
                    }
                }
            ])

        monkeypatch.setattr(node_mod, "_os_search_raw", mock_search)
        resp = client.get("/detections/fired")
        d = resp.json()
        assert len(d["detections"]) == 1
        det = d["detections"][0]
        assert det["rule_id"] == "TS-001"
        assert det["severity"] == "critical"
        assert det["host"] == "RECEPTION-PC"


# ---------------------------------------------------------------------------
# M2: /fleet/health
# ---------------------------------------------------------------------------

class TestFleetHealth:
    """GET /fleet/health response shape tests."""

    def test_empty_opensearch(self, client):
        resp = client.get("/fleet/health")
        assert resp.status_code == 200
        d = resp.json()
        assert "hosts" in d
        assert d["hosts"] == []

    def test_with_hosts(self, client, monkeypatch):
        call_count = [0]

        def mock_search(index_pattern, body, size=0):
            call_count[0] += 1
            if "winlog" in index_pattern:
                return _make_os_response(total=1000, aggs={
                    "by_host": {
                        "buckets": [
                            {
                                "key": "RECEPTION-PC",
                                "doc_count": 600,
                                "event_count": {"value": 600},
                                "last_seen": {"value_as_string": "2026-03-07T10:00:00.000Z"},
                                "first_seen": {"value_as_string": "2026-03-06T00:00:00.000Z"},
                                "top_channels": {
                                    "buckets": [
                                        {"key": "Security", "doc_count": 400},
                                        {"key": "System", "doc_count": 200},
                                    ]
                                },
                                "top_event_ids": {
                                    "buckets": [
                                        {"key": "4624", "doc_count": 300},
                                    ]
                                },
                            },
                        ]
                    }
                })
            else:
                # alerts index
                return _make_os_response(total=5, aggs={
                    "by_host": {
                        "buckets": [
                            {
                                "key": "RECEPTION-PC",
                                "doc_count": 5,
                                "by_severity": {
                                    "buckets": [
                                        {"key": "critical", "doc_count": 2},
                                        {"key": "high", "doc_count": 3},
                                    ]
                                },
                            },
                        ]
                    }
                })

        monkeypatch.setattr(node_mod, "_os_search_raw", mock_search)
        resp = client.get("/fleet/health")
        d = resp.json()
        assert len(d["hosts"]) == 1
        host = d["hosts"][0]
        assert host["hostname"] == "RECEPTION-PC"
        assert host["event_count"] == 600
        assert host["alert_count"] == 5
        assert host["alert_severities"]["critical"] == 2


# ---------------------------------------------------------------------------
# M2: /events/recent
# ---------------------------------------------------------------------------

class TestEventsRecent:
    """GET /events/recent response shape tests."""

    def test_empty_opensearch(self, client):
        resp = client.get("/events/recent")
        assert resp.status_code == 200
        d = resp.json()
        assert "events" in d
        assert d["events"] == []

    def test_limit_parameter(self, client):
        resp = client.get("/events/recent?limit=10")
        assert resp.status_code == 200

    def test_with_events(self, client, monkeypatch):
        def mock_search(index_pattern, body, size=0):
            return _make_os_response(total=1, hits=[
                {
                    "_source": {
                        "@timestamp": "2026-03-07T10:00:00.000Z",
                        "winlog": {
                            "computer_name": "RECEPTION-PC",
                            "channel": "Security",
                            "event_id": "4624",
                        },
                        "message": "An account was successfully logged on.",
                    }
                }
            ])

        monkeypatch.setattr(node_mod, "_os_search_raw", mock_search)
        resp = client.get("/events/recent")
        d = resp.json()
        assert len(d["events"]) == 1
        evt = d["events"][0]
        assert evt["host"] == "RECEPTION-PC"
        assert evt["channel"] == "Security"


# ---------------------------------------------------------------------------
# M2: /host/timeline
# ---------------------------------------------------------------------------

class TestHostTimeline:
    """GET /host/timeline response shape tests."""

    def test_empty_opensearch(self, client):
        resp = client.get("/host/timeline")
        assert resp.status_code == 200
        d = resp.json()
        assert "buckets" in d

    def test_hostname_parameter(self, client):
        resp = client.get("/host/timeline?hostname=RECEPTION-PC")
        d = resp.json()
        assert d["hostname"] == "RECEPTION-PC"

    def test_with_timeline_data(self, client, monkeypatch):
        def mock_search(index_pattern, body, size=0):
            return _make_os_response(total=100, aggs={
                "over_time": {
                    "buckets": [
                        {
                            "key_as_string": "2026-03-07T10:00:00.000Z",
                            "doc_count": 50,
                            "by_channel": {
                                "buckets": [
                                    {"key": "Security", "doc_count": 30},
                                    {"key": "System", "doc_count": 20},
                                ]
                            }
                        },
                    ]
                }
            })

        monkeypatch.setattr(node_mod, "_os_search_raw", mock_search)
        resp = client.get("/host/timeline?hostname=RECEPTION-PC")
        d = resp.json()
        assert len(d["buckets"]) == 1
        assert d["buckets"][0]["Security"] == 30
        assert d["buckets"][0]["System"] == 20


# ---------------------------------------------------------------------------
# /meta endpoint includes new endpoints
# ---------------------------------------------------------------------------

class TestMetaEndpoints:
    """Verify /meta lists all Phase 18 endpoints."""

    def test_meta_includes_summary_endpoints(self, client):
        resp = client.get("/meta")
        assert resp.status_code == 200
        d = resp.json()
        endpoints = d.get("endpoints", [])
        for ep in ("/alerts/summary", "/fleet/summary",
                    "/alerts/timeline", "/detections/fired",
                    "/fleet/health", "/events/recent", "/host/timeline"):
            assert ep in endpoints, f"Missing endpoint {ep} in /meta"
