# tinysocs/reporting/version_check.py
"""
Agent Version Awareness & Update Notifications (Phase 15 — M5)

Provides version comparison logic, manifest loading, fleet version
drift checking, and a CLI entry point for printing version status.

Usage:
    python -m tinysocs.reporting.version_check
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Manifest loading
# ---------------------------------------------------------------------------

_MANIFEST_FILENAME = "version-manifest.json"


def _manifest_search_paths() -> List[Path]:
    """Return platform-appropriate paths to search for version-manifest.json."""
    paths: List[Path] = []
    # Windows paths
    prog_data = os.getenv("ProgramData", r"C:\ProgramData")
    paths.append(Path(prog_data) / "TinySocs" / _MANIFEST_FILENAME)
    # Linux / macOS paths
    paths.append(Path("/var/lib/tinysocs") / _MANIFEST_FILENAME)
    # Repo-local fallback (config/ next to pyproject.toml)
    repo_config = Path(__file__).resolve().parent.parent.parent.parent / "config" / _MANIFEST_FILENAME
    paths.append(repo_config)
    return paths


def load_version_manifest(path: Optional[Path] = None) -> Dict[str, Any]:
    """Read version-manifest.json from *path* or from standard search paths.

    Returns the parsed dict, or an empty dict if no manifest is found.
    """
    if path is not None:
        candidates = [path]
    else:
        candidates = _manifest_search_paths()

    for p in candidates:
        if p.is_file():
            try:
                text = p.read_text(encoding="utf-8")
                data = json.loads(text)
                if isinstance(data, dict):
                    data["_source_path"] = str(p)
                    return data
            except (json.JSONDecodeError, OSError):
                continue
    return {}


# ---------------------------------------------------------------------------
# Version comparison
# ---------------------------------------------------------------------------

def _parse_semver(version_str: str) -> Optional[Tuple[int, int, int]]:
    """Parse a semver-like string (e.g. '0.8.0') into (major, minor, patch).

    Returns None if the string cannot be parsed.
    """
    if not version_str or not isinstance(version_str, str):
        return None
    parts = version_str.strip().lstrip("v").split(".")
    try:
        major = int(parts[0])
        minor = int(parts[1]) if len(parts) > 1 else 0
        patch = int(parts[2]) if len(parts) > 2 else 0
        return (major, minor, patch)
    except (ValueError, IndexError):
        return None


def compare_versions(agent_version: str, manifest_version: str) -> str:
    """Compare an agent's reported version against the manifest version.

    Returns one of:
        "current"          — versions match
        "outdated-minor"   — same major, agent minor/patch is behind
        "outdated-major"   — agent major version is behind
        "unknown"          — one or both versions could not be parsed
    """
    av = _parse_semver(agent_version)
    mv = _parse_semver(manifest_version)
    if av is None or mv is None:
        return "unknown"
    if av == mv:
        return "current"
    if av[0] < mv[0]:
        return "outdated-major"
    if av < mv:
        return "outdated-minor"
    # Agent version is *newer* than manifest — treat as current
    return "current"


# ---------------------------------------------------------------------------
# Fleet-level version checking
# ---------------------------------------------------------------------------

def check_fleet_versions(
    fleet_health_data: List[Dict[str, Any]],
    manifest: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """Compare each host's agent version from fleet health data against the manifest.

    *fleet_health_data* is a list of host dicts (from /api/fleet/health).
    *manifest* is the parsed version-manifest.json dict.

    Returns a list of result dicts, one per host:
        {
            "hostname": str,
            "agent_version": str,
            "manifest_version": str,
            "status": "current" | "outdated-minor" | "outdated-major" | "unknown",
        }
    """
    manifest_version = manifest.get("current_version", "")
    min_compatible = manifest.get("minimum_compatible", "")
    results: List[Dict[str, Any]] = []

    for host in fleet_health_data:
        hostname = host.get("hostname", "")
        agent_ver = host.get("agent_version", "")
        status = compare_versions(agent_ver, manifest_version)

        # Upgrade to outdated-major if below minimum_compatible
        if status == "outdated-minor" and min_compatible:
            av = _parse_semver(agent_ver)
            mc = _parse_semver(min_compatible)
            if av is not None and mc is not None and av < mc:
                status = "outdated-major"

        results.append({
            "hostname": hostname,
            "agent_version": agent_ver,
            "manifest_version": manifest_version,
            "minimum_compatible": min_compatible,
            "status": status,
        })

    return results


# ---------------------------------------------------------------------------
# pyproject.toml version reader
# ---------------------------------------------------------------------------

def _read_pyproject_version() -> str:
    """Extract version from pyproject.toml (best effort)."""
    pyproject = Path(__file__).resolve().parent.parent.parent.parent / "pyproject.toml"
    if not pyproject.is_file():
        return ""
    try:
        for line in pyproject.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if stripped.startswith("version") and "=" in stripped:
                val = stripped.split("=", 1)[1].strip().strip('"').strip("'")
                return val
    except OSError:
        pass
    return ""


# ---------------------------------------------------------------------------
# CLI summary
# ---------------------------------------------------------------------------

def version_status_summary() -> None:
    """Print version information from manifest and pyproject.toml."""
    manifest = load_version_manifest()
    pyproject_ver = _read_pyproject_version()

    print("=== TinySocs Version Status ===")
    print()

    if pyproject_ver:
        print(f"  Installed package version : {pyproject_ver}")
    else:
        print("  Installed package version : (could not read pyproject.toml)")

    if not manifest:
        print("  Version manifest          : NOT FOUND")
        print()
        print("  Searched paths:")
        for p in _manifest_search_paths():
            print(f"    - {p}")
        return

    print(f"  Manifest source           : {manifest.get('_source_path', 'unknown')}")
    print(f"  Current version           : {manifest.get('current_version', 'N/A')}")
    print(f"  Minimum compatible        : {manifest.get('minimum_compatible', 'N/A')}")
    print(f"  Installed at              : {manifest.get('installed_at', 'N/A') or '(not recorded)'}")
    print(f"  Changelog URL             : {manifest.get('changelog_url', 'N/A')}")
    print()

    components = manifest.get("components", {})
    if components:
        print("  Components:")
        for comp, ver in components.items():
            print(f"    {comp:20s} {ver}")
    print()

    # Compare pyproject vs manifest
    if pyproject_ver and manifest.get("current_version"):
        status = compare_versions(pyproject_ver, manifest["current_version"])
        if status == "current":
            print("  Package version matches manifest. All up to date.")
        elif status in ("outdated-minor", "outdated-major"):
            print(f"  WARNING: Package version ({pyproject_ver}) is behind "
                  f"manifest ({manifest['current_version']}). Consider upgrading.")
        else:
            print("  Could not compare package version with manifest.")


# ---------------------------------------------------------------------------
# Module entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    version_status_summary()
