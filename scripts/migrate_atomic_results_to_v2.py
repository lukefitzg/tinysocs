#!/usr/bin/env python3
"""One-shot migration: legacy atomic-results.json -> v2 per-week result file.

The legacy harness wrote a single tests/atomic-results.json (implicit v1
schema). The continuous validation pipeline expects per-week files under
results/ in the v2 schema (see docs/design/continuous-validation.md).

This script reads the legacy file, derives the ISO week from its
generated_at timestamp, normalises each result (adding a `category`),
computes the v2 summary block (with coverage stats from the detection
pack), and writes results/<YYYY-Www>.json. It also refreshes
results/latest.json to point at the newest file.

Run once to seed the historical snapshot so the dashboard has data on
day one. Idempotent: re-running overwrites the same week's file.

Usage:
    python3 scripts/migrate_atomic_results_to_v2.py
    python3 scripts/migrate_atomic_results_to_v2.py --dry-run
    python3 scripts/migrate_atomic_results_to_v2.py \
        --input tests/atomic-results.json \
        --rules packaging/detection/rules.yml \
        --results-dir results
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Allow running as a script from anywhere in the repo.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import validation_lib as vl  # noqa: E402

_REPO_ROOT = Path(__file__).resolve().parent.parent


def migrate(input_path: Path, rules_path: Path) -> dict:
    legacy = json.loads(input_path.read_text(encoding="utf-8"))

    generated_at = legacy.get("generated_at")
    if not generated_at:
        raise ValueError(f"{input_path} has no generated_at timestamp")
    dt = vl.parse_timestamp(generated_at)
    iso_week = vl.iso_week_label(dt)

    # Legacy file has no per-test timing; normalize_result carries the absent
    # started_at/duration_seconds through as null rather than fabricating them.
    results = [vl.normalize_result(r) for r in legacy.get("results", [])]
    rule_ids = vl.load_rule_ids(rules_path)
    summary = vl.build_summary(results, rule_ids)

    return {
        "schema_version": vl.RESULT_SCHEMA_VERSION,
        "run_id": f"{iso_week}-migrated",
        "generated_at": generated_at,
        "iso_week": iso_week,
        "git_commit": None,  # unknown for the backfilled historical run
        "migrated": True,  # honest flag: this record was backfilled, not freshly run
        "platform": {
            # Best-effort from what the legacy notes imply; unknown fields null.
            "os": None,
            "tinysocs_version": "0.9.0",
            "sysmon_version": None,
            "opensearch_version": None,
        },
        "summary": summary,
        "results": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input",
        default=str(_REPO_ROOT / "tests" / "atomic-results.json"),
        help="Path to the legacy atomic-results.json",
    )
    parser.add_argument(
        "--rules",
        default=str(_REPO_ROOT / "packaging" / "detection" / "rules.yml"),
        help="Path to the detection pack YAML (for coverage stats)",
    )
    parser.add_argument(
        "--results-dir",
        default=str(_REPO_ROOT / "results"),
        help="Directory to write per-week result files into",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the migrated JSON to stdout without writing files",
    )
    args = parser.parse_args()

    input_path = Path(args.input)
    rules_path = Path(args.rules)
    results_dir = Path(args.results_dir)

    if not input_path.exists():
        print(f"ERROR: input not found: {input_path}", file=sys.stderr)
        return 1
    if not rules_path.exists():
        print(f"ERROR: rules pack not found: {rules_path}", file=sys.stderr)
        return 1

    migrated = migrate(input_path, rules_path)
    out_text = json.dumps(migrated, indent=2) + "\n"

    if args.dry_run:
        print(out_text)
        s = migrated["summary"]
        print(
            f"[dry-run] would write {migrated['iso_week']}.json: "
            f"{s['atomic_tests_detected']} detected, "
            f"{s['atomic_tests_skipped']} skipped, "
            f"{s['atomic_tests_missed']} missed, "
            f"{s['atomic_tests_error']} error "
            f"({s['rules_with_atomic_test']}/{s['rules_in_pack']} rules covered)",
            file=sys.stderr,
        )
        return 0

    results_dir.mkdir(parents=True, exist_ok=True)
    out_file = results_dir / f"{migrated['iso_week']}.json"
    out_file.write_text(out_text, encoding="utf-8")
    (results_dir / "latest.json").write_text(out_text, encoding="utf-8")

    s = migrated["summary"]
    print(f"[*] Wrote {out_file}")
    print(f"[*] Wrote {results_dir / 'latest.json'}")
    print(
        f"[*] {migrated['iso_week']}: {s['atomic_tests_detected']} detected, "
        f"{s['atomic_tests_skipped']} skipped, {s['atomic_tests_missed']} missed, "
        f"{s['atomic_tests_error']} error "
        f"({s['rules_with_atomic_test']}/{s['rules_in_pack']} rules covered, "
        f"technique pass rate {s['technique_pass_rate']:.0%})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
