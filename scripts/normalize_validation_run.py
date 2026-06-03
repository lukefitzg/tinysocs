#!/usr/bin/env python3
"""Normalise a raw harness run into a v2 per-week validation result.

The PowerShell harness (tests/Test-AtomicDetection.ps1) writes a *raw* run
file: run metadata (generated_at, git_commit, platform) plus per-test
status/reason/timing. It deliberately does NOT compute the dashboard
`category` or the `summary` block — that logic lives in validation_lib so the
categorisation rules never drift between PowerShell and Python.

This script reads that raw file, derives the ISO week from generated_at,
adds a `category` to each result, computes the v2 summary (with coverage
stats from the detection pack), and writes results/<YYYY-Www>.json plus a
refreshed results/latest.json.

It is the per-run sibling of migrate_atomic_results_to_v2.py (which is a
one-shot backfill of the legacy v1 file). Both share the per-test and summary
shaping from validation_lib.

Usage:
    python3 scripts/normalize_validation_run.py tests/atomic-results.json
    python3 scripts/normalize_validation_run.py tests/atomic-results.json --dry-run
    python3 scripts/normalize_validation_run.py raw.json \
        --rules packaging/detection/rules.yml \
        --results-dir results \
        --run-seq 002
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

# Categories that mean "no real test executed", used to reject dry runs.
_NON_RESULT_CATEGORIES = {vl.CATEGORY_DRY}


def normalize(raw_path: Path, rules_path: Path, run_seq: str) -> dict:
    raw = json.loads(raw_path.read_text(encoding="utf-8"))

    generated_at = raw.get("generated_at")
    if not generated_at:
        raise ValueError(f"{raw_path} has no generated_at timestamp")
    dt = vl.parse_timestamp(generated_at)
    iso_week = vl.iso_week_label(dt)

    results = [vl.normalize_result(r) for r in raw.get("results", [])]

    # Guard against accidentally publishing a dry-run listing as a real result.
    real = [r for r in results if r["category"] not in _NON_RESULT_CATEGORIES]
    if results and not real:
        raise ValueError(
            f"{raw_path} contains only dry-run results; refusing to write a "
            f"validation result. Re-run the harness without -DryRun."
        )

    rule_ids = vl.load_rule_ids(rules_path)
    summary = vl.build_summary(results, rule_ids)

    platform = raw.get("platform") or {}

    return {
        "schema_version": vl.RESULT_SCHEMA_VERSION,
        "run_id": f"{iso_week}-{run_seq}",
        "generated_at": generated_at,
        "iso_week": iso_week,
        "git_commit": raw.get("git_commit"),
        "platform": {
            "os": platform.get("os"),
            "tinysocs_version": platform.get("tinysocs_version"),
            "sysmon_version": platform.get("sysmon_version"),
            "opensearch_version": platform.get("opensearch_version"),
        },
        "summary": summary,
        "results": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "raw",
        nargs="?",
        default=str(_REPO_ROOT / "tests" / "atomic-results.json"),
        help="Path to the raw harness run JSON",
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
        "--run-seq",
        default="001",
        help="Run sequence within the week, for the run_id (default 001)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the normalised JSON to stdout without writing files",
    )
    args = parser.parse_args()

    raw_path = Path(args.raw)
    rules_path = Path(args.rules)
    results_dir = Path(args.results_dir)

    if not raw_path.exists():
        print(f"ERROR: raw run file not found: {raw_path}", file=sys.stderr)
        return 1
    if not rules_path.exists():
        print(f"ERROR: rules pack not found: {rules_path}", file=sys.stderr)
        return 1

    try:
        record = normalize(raw_path, rules_path, args.run_seq)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    out_text = json.dumps(record, indent=2) + "\n"
    s = record["summary"]

    if args.dry_run:
        print(out_text)
        print(
            f"[dry-run] would write {record['iso_week']}.json: "
            f"{s['atomic_tests_detected']} detected, "
            f"{s['atomic_tests_skipped']} skipped, "
            f"{s['atomic_tests_missed']} missed, "
            f"{s['atomic_tests_error']} error "
            f"({s['rules_with_atomic_test']}/{s['rules_in_pack']} rules covered)",
            file=sys.stderr,
        )
        return 0

    results_dir.mkdir(parents=True, exist_ok=True)
    out_file = results_dir / f"{record['iso_week']}.json"
    out_file.write_text(out_text, encoding="utf-8")
    (results_dir / "latest.json").write_text(out_text, encoding="utf-8")

    print(f"[*] Wrote {out_file}")
    print(f"[*] Wrote {results_dir / 'latest.json'}")
    miss = s["atomic_tests_missed"]
    flag = "  <-- MISS: investigate" if miss else ""
    print(
        f"[*] {record['run_id']}: {s['atomic_tests_detected']} detected, "
        f"{s['atomic_tests_skipped']} skipped, {miss} missed{flag}, "
        f"{s['atomic_tests_error']} error "
        f"({s['rules_with_atomic_test']}/{s['rules_in_pack']} rules covered, "
        f"technique pass rate {s['technique_pass_rate']:.0%})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
