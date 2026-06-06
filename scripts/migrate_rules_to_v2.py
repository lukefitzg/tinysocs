#!/usr/bin/env python3
"""One-shot migration: v1 C# agent rules -> v2 signed-pack format.

Reads packaging/detection/rules.yml (the 39 rules that actually fire in the
C# engine, plus 2 disabled lab variants) and emits v2 packs:

    packs/base/<version>/pack.yml    # production rules, runs_on: agent
    packs/demo/<version>/pack.yml    # *-lab rules, never shipped to customers

The mapping is mechanical and lossless (see docs/design/rule-format-v2.md
-> "Migration mapping"): every v1 field maps deterministically to a v2 path,
including the `field_match` pre-filter used by 8 live rules. No per-rule human
judgement. Re-running overwrites the same version directory (idempotent).

The emitted pack has NO signature block yet -- sign it with
scripts/pack_sign.py, which injects metadata.signature.

This migrates only the C# agent rules. The 50-rule Python catalogue
(src/tinysocs/agent/detections/rules.yaml, runs_on: backend) is a separate
mechanical pass, deferred until the backend runner activates (v2.1).

Usage:
    python3 scripts/migrate_rules_to_v2.py
    python3 scripts/migrate_rules_to_v2.py --dry-run
    python3 scripts/migrate_rules_to_v2.py --version 2026.23
    python3 scripts/migrate_rules_to_v2.py \
        --input packaging/detection/rules.yml --out-dir packs
"""

from __future__ import annotations

import argparse
import datetime as dt
import sys
from pathlib import Path

import yaml

_REPO_ROOT = Path(__file__).resolve().parent.parent

# v1 lab rules go to the demo pack; everything else is base.
_DEMO_RULE_IDS = {"TS-001-lab", "TS-030-lab"}

# Tactic -> nothing special; carried through verbatim. Listed here only as the
# canonical set we expect, so an unrecognised tactic is a loud warning not a
# silent passthrough.
_KNOWN_TACTICS = {
    "initial-access", "execution", "persistence", "privilege-escalation",
    "defense-evasion", "credential-access", "discovery", "lateral-movement",
    "collection", "command-and-control", "exfiltration", "impact",
}


def _pack_version_now() -> str:
    """year.weeknum (ISO week), matching the validation pipeline's labelling."""
    iso = dt.date.today().isocalendar()
    return f"{iso.year}.{iso.week:02d}"


def derive_allowlist_scopes(group_by: str, channel: str, has_field_match: bool) -> list[str]:
    """Mechanical per-family scope derivation (rule-format-v2.md).

    Scope vocabulary a rule honours is a function of what it groups by and its
    event source -- not a per-rule judgement call.
    """
    gb = (group_by or "").lower()
    scopes: list[str] = []

    if channel == "TinySocs-FIM":
        # FIM keys on FilePath; allow excluding a path or a whole host.
        scopes = ["process_path", "process_pattern", "host"]
    elif "targetusername" in gb or "subjectusername" in gb:
        scopes = ["user", "user_pattern", "host"]
    elif "ipaddress" in gb:
        scopes = ["source_ip", "source_ip_cidr"]
    elif "newprocessname" in gb or "image" in gb or "sourceimage" in gb:
        scopes = ["process_path", "process_pattern", "user"]
    elif "computer_name" in gb or "computername" in gb:
        scopes = ["host", "host_pattern"]
    elif "queryname" in gb:
        scopes = ["host", "event_data.QueryName"]
    elif "servicename" in gb:
        scopes = ["host", "event_data.ServiceName"]
    else:
        # Heartbeat/version-drift and anything unkeyed: host-level only.
        scopes = ["host"]

    # Rules that pre-filter on a process/command field can be tuned by excluding
    # a specific binary path even when they group by something else.
    if has_field_match and "process_path" not in scopes:
        scopes.append("process_path")

    return scopes


def derive_tuning(threshold: int) -> dict | None:
    """Threshold knob only where operator tuning is meaningful.

    Single-event rules (threshold == 1) fire on presence; there is no count to
    tune, so they get no knob. Count/burst rules get a range-validated knob
    centred on the shipped default.
    """
    if threshold is None or threshold <= 1:
        return None
    return {
        "threshold": {
            "envvar": None,  # set per-deployment; null = use default
            "min": max(1, threshold // 4),
            "max": threshold * 5,
            "default": threshold,
        }
    }


def migrate_rule(v1: dict) -> dict:
    rule_id = v1["id"]
    cond = v1.get("condition", {}) or {}
    channel = cond.get("channel")
    group_by = cond.get("group_by")
    threshold = cond.get("threshold")

    tactic = (v1.get("mitre", {}) or {}).get("tactic")
    if tactic and tactic not in _KNOWN_TACTICS:
        print(f"  warning: {rule_id} has unrecognised tactic {tactic!r}", file=sys.stderr)

    pack = "demo" if rule_id in _DEMO_RULE_IDS else "base"

    detection: dict = {
        "type": "threshold_by_key",
        "event_id": cond.get("event_id"),
        "channel": channel,
        "group_by": group_by,
        "threshold": threshold,
        "window_minutes": cond.get("window_minutes", 5),
    }
    if "cooldown_minutes" in cond:
        detection["cooldown_minutes"] = cond["cooldown_minutes"]

    # field_match carried through verbatim; make the implicit v1 substring
    # semantics explicit as match: contains.
    if "field_match" in cond and cond["field_match"]:
        fm = cond["field_match"]
        detection["field_match"] = {
            "field": fm["field"],
            "match": fm.get("match", "contains"),
            "values": list(fm["values"]),
        }

    has_field_match = "field_match" in detection

    v2: dict = {
        "id": rule_id,
        "name": v1.get("name"),
        "description": v1.get("description"),
        "severity": v1.get("severity"),
        "enabled": v1.get("enabled", True),
        "runs_on": "agent",
        "pack": pack,
        "mitre": v1.get("mitre"),
        "docs": f"tinydocs/{rule_id}.md",
        "detection": detection,
        "allowlist_scopes": derive_allowlist_scopes(group_by, channel, has_field_match),
        "baseline": {
            "enabled": False,
            "learning_days": 7,
            "keyed_by": ["host"],
            "action_below_baseline": "suppress",
        },
        "actions": list(v1.get("actions", [])),
    }

    tuning = derive_tuning(threshold)
    if tuning:
        v2["tuning"] = tuning

    return v2


def build_pack(pack_id: str, version: str, rules: list[dict], generated_at: str) -> dict:
    tier = "free" if pack_id == "base" else "demo" if pack_id == "demo" else "pro"
    return {
        "schema_version": 2,
        "metadata": {
            "pack_id": pack_id,
            "pack_version": version,
            "tier": tier,
            "generated_at": generated_at,
            "validation": {
                # Filled by the validation pipeline at release time; null here so
                # the pack is honest about not having been validated yet.
                "atomic_red_team_run": None,
                "passing": None,
                "failing": None,
                "pending": None,
            },
            # No signature block: scripts/pack_sign.py injects it.
        },
        "rules": rules,
    }


def migrate(input_path: Path, version: str) -> dict[str, dict]:
    doc = yaml.safe_load(input_path.read_text(encoding="utf-8"))
    v1_rules = doc.get("rules", [])
    generated_at = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    by_pack: dict[str, list[dict]] = {"base": [], "demo": []}
    for v1 in v1_rules:
        v2 = migrate_rule(v1)
        by_pack[v2["pack"]].append(v2)

    packs: dict[str, dict] = {}
    for pack_id, rules in by_pack.items():
        if rules:
            packs[pack_id] = build_pack(pack_id, version, rules, generated_at)
    return packs


def write_pack(pack: dict, out_dir: Path) -> Path:
    meta = pack["metadata"]
    dest_dir = out_dir / meta["pack_id"] / meta["pack_version"]
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / "pack.yml"
    # Underscored keys, block style, stable key order (sort_keys=False keeps our
    # authored ordering; the *signature* canonicalises to sorted JSON separately).
    dest.write_text(
        yaml.safe_dump(pack, sort_keys=False, default_flow_style=False, allow_unicode=True),
        encoding="utf-8",
    )
    return dest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                      formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--input", default=str(_REPO_ROOT / "packaging" / "detection" / "rules.yml"))
    parser.add_argument("--out-dir", default=str(_REPO_ROOT / "packs"))
    parser.add_argument("--version", default=None, help="pack_version (year.weeknum); default = current ISO week")
    parser.add_argument("--dry-run", action="store_true", help="print summary, write nothing")
    args = parser.parse_args()

    version = args.version or _pack_version_now()
    input_path = Path(args.input)
    out_dir = Path(args.out_dir)

    packs = migrate(input_path, version)

    for pack_id, pack in packs.items():
        n = len(pack["rules"])
        n_fm = sum(1 for r in pack["rules"] if "field_match" in r["detection"])
        n_tuning = sum(1 for r in pack["rules"] if "tuning" in r)
        print(f"{pack_id} {version}: {n} rules ({n_fm} with field_match, {n_tuning} tunable)")
        if not args.dry_run:
            dest = write_pack(pack, out_dir)
            print(f"  -> {dest.relative_to(_REPO_ROOT)}")

    if args.dry_run:
        print("dry-run: nothing written")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
