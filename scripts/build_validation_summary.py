#!/usr/bin/env python3
"""Build the dashboard summary JSON from the per-week validation results.

Reads every results/<iso-week>.json (the v2 per-run files written by the
migration / normaliser), plus the detection pack for rule metadata, and emits
a single consolidated site/validation/data/summary.json that the static
dashboard fetches on load. No backend at view time — everything is precomputed
here and deployed as a flat file (see docs/design/continuous-validation.md).

The summary contains:
  - latest:   headline block for the most recent run (counts, platform, commit)
  - weeks:    the ISO weeks present (chronological), trimmed to --weeks
  - rules:    per-rule metadata + last-N-week history (for the sortable table
              and the coloured-dot sparkline)
  - coverage: rules with / without an Atomic Red Team test

This is the only pipeline component besides validation_lib that consumes the
rule pack, and it reads it via validation_lib.load_rules — so when v2 rule
format lands, the schema-invariance budget is paid in that one module.

Usage:
    python3 scripts/build_validation_summary.py
    python3 scripts/build_validation_summary.py \
        --results-dir results \
        --rules packaging/detection/rules.yml \
        --output site/validation/data/summary.json \
        --weeks 12
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from pathlib import Path

# Allow running as a script from anywhere in the repo.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import validation_lib as vl  # noqa: E402

_REPO_ROOT = Path(__file__).resolve().parent.parent

# This summary file's own schema version (independent of the result schema).
SUMMARY_SCHEMA_VERSION = 1


def _load_runs(results_dir: Path) -> list[dict]:
    """Load every per-week result file (latest.json excluded — it's a copy)."""
    runs = []
    for path in sorted(results_dir.glob("*.json")):
        if path.name == "latest.json":
            continue
        try:
            runs.append(json.loads(path.read_text(encoding="utf-8")))
        except json.JSONDecodeError as exc:
            print(f"WARNING: skipping unparseable {path}: {exc}", file=sys.stderr)
    # Chronological by ISO week (zero-padded, so lexical == chronological).
    runs.sort(key=lambda r: r.get("iso_week", ""))
    return runs


def build(results_dir: Path, rules_path: Path, weeks: int) -> dict:
    runs = _load_runs(results_dir)
    if not runs:
        raise ValueError(f"no result files found in {results_dir}")

    kept = runs[-weeks:]
    kept_weeks = [r["iso_week"] for r in kept]
    latest = runs[-1]

    rules = vl.load_rules(rules_path)

    # has_test is "covered by the latest run" so the coverage headline matches
    # the latest run's summary.rules_with_atomic_test exactly.
    latest_covered = vl.covered_rule_ids(latest.get("results", []))

    # Index each kept run's results by iso_week for history lookups.
    results_by_week = {r["iso_week"]: r.get("results", []) for r in kept}

    rule_entries = []
    for rule in rules:
        rid = rule["id"]
        history = []
        for wk in kept_weeks:
            verdict = vl.rule_category_for_week(rid, results_by_week[wk])
            history.append(
                {
                    "iso_week": wk,
                    "category": verdict["category"] if verdict else None,
                    "reason": verdict["reason"] if verdict else "",
                }
            )
        latest_entry = history[-1] if history else None
        rule_entries.append(
            {
                "id": rid,
                "name": rule["name"],
                "severity": rule["severity"],
                "mitre": rule["mitre"],
                "has_test": rid in latest_covered,
                "latest_category": latest_entry["category"] if latest_entry else None,
                "latest_reason": latest_entry["reason"] if latest_entry else "",
                "history": history,
            }
        )

    pack_ids = [r["id"] for r in rules]
    rules_without_test = [rid for rid in pack_ids if rid not in latest_covered]

    return {
        "summary_schema_version": SUMMARY_SCHEMA_VERSION,
        "built_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "latest": {
            "run_id": latest.get("run_id"),
            "iso_week": latest.get("iso_week"),
            "generated_at": latest.get("generated_at"),
            "git_commit": latest.get("git_commit"),
            "migrated": latest.get("migrated", False),
            "platform": latest.get("platform", {}),
            "summary": latest.get("summary", {}),
        },
        "weeks": kept_weeks,
        "rules": rule_entries,
        "coverage": {
            "rules_in_pack": len(pack_ids),
            "rules_with_test": len(latest_covered & set(pack_ids)),
            "rules_without_test": rules_without_test,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--results-dir",
        default=str(_REPO_ROOT / "results"),
        help="Directory of per-week result files",
    )
    parser.add_argument(
        "--rules",
        default=str(_REPO_ROOT / "packaging" / "detection" / "rules.yml"),
        help="Path to the detection pack YAML (for rule metadata)",
    )
    parser.add_argument(
        "--output",
        default=str(_REPO_ROOT / "site" / "validation" / "data" / "summary.json"),
        help="Where to write the consolidated summary JSON",
    )
    parser.add_argument(
        "--weeks",
        type=int,
        default=12,
        help="How many recent weeks of history to include (default 12)",
    )
    args = parser.parse_args()

    results_dir = Path(args.results_dir)
    rules_path = Path(args.rules)
    output_path = Path(args.output)

    if not results_dir.exists():
        print(f"ERROR: results dir not found: {results_dir}", file=sys.stderr)
        return 1
    if not rules_path.exists():
        print(f"ERROR: rules pack not found: {rules_path}", file=sys.stderr)
        return 1

    try:
        summary = build(results_dir, rules_path, args.weeks)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

    cov = summary["coverage"]
    s = summary["latest"]["summary"]
    print(f"[*] Wrote {output_path}")
    print(
        f"[*] latest {summary['latest']['iso_week']}: "
        f"{s.get('atomic_tests_detected', 0)} detected, "
        f"{s.get('atomic_tests_missed', 0)} missed "
        f"({cov['rules_with_test']}/{cov['rules_in_pack']} rules covered, "
        f"{len(summary['weeks'])} weeks of history)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
