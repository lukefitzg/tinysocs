"""
test_version_check.py — Tests for version comparison, manifest loading,
and fleet version check aggregation (Phase 15 M5).
"""

import json
import pathlib
import tempfile

import pytest

from tinysocs.reporting.version_check import (
    _parse_semver,
    check_fleet_versions,
    compare_versions,
    load_version_manifest,
)

# ── Manifest path ────────────────────────────────────────────────────────
ROOT = pathlib.Path(__file__).resolve().parent.parent
MANIFEST_PATH = ROOT / "config" / "version-manifest.json"


# ── Version comparison tests ─────────────────────────────────────────────

class TestCompareVersions:
    """Test compare_versions() with various version combinations."""

    def test_equal_versions(self):
        assert compare_versions("0.8.0", "0.8.0") == "current"

    def test_equal_versions_two_part(self):
        assert compare_versions("0.8", "0.8.0") == "current"

    def test_agent_newer_than_manifest(self):
        """An agent running a newer version is treated as current."""
        assert compare_versions("0.9.0", "0.8.0") == "current"

    def test_minor_drift(self):
        assert compare_versions("0.7.1", "0.8.0") == "outdated-minor"

    def test_minor_drift_patch_only(self):
        assert compare_versions("0.8.0", "0.8.1") == "outdated-minor"

    def test_major_drift(self):
        assert compare_versions("0.8.0", "1.0.0") == "outdated-major"

    def test_major_drift_large_gap(self):
        assert compare_versions("1.2.3", "3.0.0") == "outdated-major"

    def test_unknown_empty_agent(self):
        assert compare_versions("", "0.8.0") == "unknown"

    def test_unknown_empty_manifest(self):
        assert compare_versions("0.8.0", "") == "unknown"

    def test_unknown_both_empty(self):
        assert compare_versions("", "") == "unknown"

    def test_unknown_garbage_input(self):
        assert compare_versions("not-a-version", "0.8.0") == "unknown"

    def test_v_prefix(self):
        """Versions with 'v' prefix should still parse."""
        assert compare_versions("v0.8.0", "0.8.0") == "current"

    def test_v_prefix_both(self):
        assert compare_versions("v0.7.0", "v0.8.0") == "outdated-minor"


# ── Semver parsing tests ────────────────────────────────────────────────

class TestParseSemver:
    """Test the internal _parse_semver helper."""

    def test_three_part(self):
        assert _parse_semver("1.2.3") == (1, 2, 3)

    def test_two_part(self):
        assert _parse_semver("1.2") == (1, 2, 0)

    def test_one_part(self):
        assert _parse_semver("5") == (5, 0, 0)

    def test_v_prefix(self):
        assert _parse_semver("v2.1.0") == (2, 1, 0)

    def test_empty(self):
        assert _parse_semver("") is None

    def test_none(self):
        assert _parse_semver(None) is None

    def test_garbage(self):
        assert _parse_semver("abc") is None


# ── Manifest loading tests ──────────────────────────────────────────────

class TestLoadManifest:
    """Test load_version_manifest() with real and synthetic manifests."""

    def test_repo_manifest_exists(self):
        """The config/version-manifest.json shipped with the repo must exist."""
        assert MANIFEST_PATH.is_file(), f"Manifest not found at {MANIFEST_PATH}"

    def test_repo_manifest_parses(self):
        manifest = load_version_manifest(MANIFEST_PATH)
        assert isinstance(manifest, dict)
        assert manifest != {}

    def test_repo_manifest_required_keys(self):
        manifest = load_version_manifest(MANIFEST_PATH)
        for key in ("current_version", "minimum_compatible", "components"):
            assert key in manifest, f"Manifest missing required key: {key}"

    def test_components_has_agent(self):
        manifest = load_version_manifest(MANIFEST_PATH)
        components = manifest.get("components", {})
        assert "agent" in components, "Manifest components must include 'agent'"

    def test_load_from_explicit_path(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump({"current_version": "1.0.0", "minimum_compatible": "0.9.0"}, f)
            f.flush()
            manifest = load_version_manifest(pathlib.Path(f.name))
        assert manifest["current_version"] == "1.0.0"

    def test_load_missing_path_returns_empty(self):
        manifest = load_version_manifest(pathlib.Path("/nonexistent/path/manifest.json"))
        assert manifest == {}

    def test_load_invalid_json_returns_empty(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            f.write("this is not json {{{")
            f.flush()
            manifest = load_version_manifest(pathlib.Path(f.name))
        assert manifest == {}


# ── Fleet version check tests ───────────────────────────────────────────

class TestCheckFleetVersions:
    """Test check_fleet_versions() aggregation logic."""

    @pytest.fixture()
    def manifest(self):
        return {
            "current_version": "0.8.0",
            "minimum_compatible": "0.7.0",
            "components": {"agent": "0.8.0"},
        }

    def test_all_current(self, manifest):
        fleet = [
            {"hostname": "host-a", "agent_version": "0.8.0"},
            {"hostname": "host-b", "agent_version": "0.8.0"},
        ]
        results = check_fleet_versions(fleet, manifest)
        assert len(results) == 2
        assert all(r["status"] == "current" for r in results)

    def test_mixed_versions(self, manifest):
        fleet = [
            {"hostname": "host-a", "agent_version": "0.8.0"},
            {"hostname": "host-b", "agent_version": "0.7.1"},
            {"hostname": "host-c", "agent_version": "0.5.0"},
        ]
        results = check_fleet_versions(fleet, manifest)
        statuses = {r["hostname"]: r["status"] for r in results}
        assert statuses["host-a"] == "current"
        assert statuses["host-b"] == "outdated-minor"
        # 0.5.0 is below minimum_compatible 0.7.0 so should be major
        assert statuses["host-c"] == "outdated-major"

    def test_unknown_agent_version(self, manifest):
        fleet = [{"hostname": "host-x", "agent_version": ""}]
        results = check_fleet_versions(fleet, manifest)
        assert results[0]["status"] == "unknown"

    def test_empty_fleet(self, manifest):
        results = check_fleet_versions([], manifest)
        assert results == []

    def test_agent_newer_than_manifest(self, manifest):
        fleet = [{"hostname": "host-new", "agent_version": "0.9.0"}]
        results = check_fleet_versions(fleet, manifest)
        assert results[0]["status"] == "current"

    def test_result_fields_present(self, manifest):
        fleet = [{"hostname": "host-a", "agent_version": "0.7.5"}]
        results = check_fleet_versions(fleet, manifest)
        result = results[0]
        assert "hostname" in result
        assert "agent_version" in result
        assert "manifest_version" in result
        assert "minimum_compatible" in result
        assert "status" in result

    def test_below_minimum_compatible_is_major(self, manifest):
        """Versions below minimum_compatible should be flagged as outdated-major."""
        fleet = [{"hostname": "host-old", "agent_version": "0.6.9"}]
        results = check_fleet_versions(fleet, manifest)
        assert results[0]["status"] == "outdated-major"
