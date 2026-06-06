"""Shared logic for the TinySOCs continuous validation pipeline.

Single source of truth for:
  - categorising a raw harness status+reason into a dashboard colour bucket
  - rolling a list of per-test results into a summary block
  - loading rule IDs from the detection pack (for coverage stats)
  - ISO-week helpers

Both the one-shot migration (migrate_atomic_results_to_v2.py) and the
per-run normaliser (normalize_validation_run.py) import from here so the
categorisation rules never drift between code paths.

See docs/design/continuous-validation.md for the schema and the category
definitions this module implements.
"""

from __future__ import annotations

import datetime as _dt
import re
from pathlib import Path
from typing import Iterable

import yaml

# Result-file schema version this library emits.
RESULT_SCHEMA_VERSION = 2

# --------------------------------------------------------------------------
# Category mapping (status + reason -> dashboard colour bucket)
# --------------------------------------------------------------------------
# Categories, in rough "severity" order for the dashboard:
#   PASS          - green   - the pack caught what it should have
#   SKIP_PLATFORM - grey    - test cannot run on this venue (needs DC, FIM, Sysmon...)
#   SKIP_PREREQ   - grey    - environmental prerequisite unmet (Tamper Protection, admin)
#   MISS          - red     - rule should have fired and did not (the only alarming one)
#   ERROR         - grey    - harness issue (network, ART install, query) - not a rule defect
#   DRY           - n/a     - dry-run listing; excluded from summary maths
CATEGORY_PASS = "PASS"
CATEGORY_SKIP_PLATFORM = "SKIP_PLATFORM"
CATEGORY_SKIP_PREREQ = "SKIP_PREREQ"
CATEGORY_MISS = "MISS"
CATEGORY_ERROR = "ERROR"
CATEGORY_DRY = "DRY"

# Reasons that mean "the test environment can't exercise this", not "the rule failed".
# Matched case-insensitively as substrings/patterns against the harness `reason`.
_PLATFORM_SKIP_PATTERNS = [
    r"domain controller",
    r"\bnot a dc\b",
    r"\bfim\b",
    r"fim event channel",
    r"fim module",
    r"sysmon",
]
_PREREQ_SKIP_PATTERNS = [
    r"tamper protection",
    r"requires admin",
    r"\badmin\b",
    r"elevation",
]

_PLATFORM_SKIP_RE = re.compile("|".join(_PLATFORM_SKIP_PATTERNS), re.IGNORECASE)
_PREREQ_SKIP_RE = re.compile("|".join(_PREREQ_SKIP_PATTERNS), re.IGNORECASE)


def categorize(status: str, reason: str | None) -> str:
    """Map a raw harness (status, reason) pair to a dashboard category.

    `status` is the harness value: DETECTED | MISSED | SKIP | ERROR | DRY_RUN.
    `reason` is the free-text explanation (may be empty).
    """
    status = (status or "").strip().upper()
    reason = reason or ""

    if status == "DETECTED":
        return CATEGORY_PASS
    if status == "MISSED":
        return CATEGORY_MISS
    if status == "ERROR":
        return CATEGORY_ERROR
    if status in ("DRY_RUN", "DRY"):
        return CATEGORY_DRY
    if status == "SKIP":
        # Platform constraints take precedence over prereq if both somehow match.
        if _PLATFORM_SKIP_RE.search(reason):
            return CATEGORY_SKIP_PLATFORM
        if _PREREQ_SKIP_RE.search(reason):
            return CATEGORY_SKIP_PREREQ
        # Unclassified skip: treat as platform skip (benign) but it should be
        # rare; an unexpected skip reason is worth eyeballing in review.
        return CATEGORY_SKIP_PLATFORM
    # Unknown status: surface as ERROR so it can't silently inflate pass rate.
    return CATEGORY_ERROR


# --------------------------------------------------------------------------
# Per-test normalisation (raw harness result -> v2 per-test shape)
# --------------------------------------------------------------------------
def normalize_result(raw: dict) -> dict:
    """Convert a raw harness per-test result into the v2 per-test shape.

    Adds the derived `category` and carries through timing if the harness
    captured it (legacy v1 files have none, so those come through as null).
    Used by both the one-shot migration and the per-run normaliser so the
    shape is defined in exactly one place.
    """
    status = raw.get("status", "")
    reason = raw.get("reason", "") or ""
    return {
        "technique_id": raw.get("technique_id", ""),
        "technique_name": raw.get("technique_name", ""),
        "expected_rules": [r for r in (raw.get("expected_rules") or []) if r],
        "detected_rules": [r for r in (raw.get("detected_rules") or []) if r],
        "status": status,
        "category": categorize(status, reason),
        "reason": reason,
        "started_at": raw.get("started_at"),
        "duration_seconds": raw.get("duration_seconds"),
    }


# --------------------------------------------------------------------------
# Rule-pack loading (for coverage stats)
# --------------------------------------------------------------------------
def load_rules(rules_yml: Path) -> list[dict]:
    """Return rule metadata from a detection pack YAML.

    Each entry: {id, name, severity, enabled, mitre:{technique_id,
    technique_name, tactic}}. Works against the v1 C# pack
    (packaging/detection/rules.yml). Schema-invariant against v2: v2 keeps the
    top-level `rules:` list and per-rule `id`/`name`/`mitre`, so this keeps
    working after migration. This is the one place that reads the pack format,
    so it's the one place v2 might touch.
    """
    with rules_yml.open(encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    rules = data.get("rules", []) if isinstance(data, dict) else (data or [])
    out: list[dict] = []
    for r in rules:
        if not isinstance(r, dict) or not r.get("id"):
            continue
        mitre = r.get("mitre") or {}
        out.append(
            {
                "id": r["id"],
                "name": r.get("name", ""),
                "severity": r.get("severity"),
                "enabled": r.get("enabled", True),
                "mitre": {
                    "technique_id": mitre.get("technique_id"),
                    "technique_name": mitre.get("technique_name"),
                    "tactic": mitre.get("tactic"),
                },
            }
        )
    return out


def load_rule_ids(rules_yml: Path) -> list[str]:
    """Return just the list of rule IDs defined in a detection pack YAML."""
    return [r["id"] for r in load_rules(rules_yml)]


def covered_rule_ids(results: Iterable[dict]) -> set[str]:
    """Set of rule IDs that appear in any test's expected_rules."""
    covered: set[str] = set()
    for r in results:
        for rid in r.get("expected_rules", []) or []:
            if rid:
                covered.add(rid)
    return covered


# --------------------------------------------------------------------------
# Summary roll-up
# --------------------------------------------------------------------------
def build_summary(results: list[dict], rule_ids: list[str]) -> dict:
    """Roll a list of per-test result dicts into the summary block.

    Each result dict must have at least `status`, `reason`, `expected_rules`.
    `category` is computed here if not already present.
    `rule_ids` is the full set of rule IDs in the pack (for coverage stats).
    """
    cats = {
        CATEGORY_PASS: 0,
        CATEGORY_SKIP_PLATFORM: 0,
        CATEGORY_SKIP_PREREQ: 0,
        CATEGORY_MISS: 0,
        CATEGORY_ERROR: 0,
        CATEGORY_DRY: 0,
    }
    for r in results:
        cat = r.get("category") or categorize(r.get("status"), r.get("reason"))
        cats[cat] = cats.get(cat, 0) + 1

    pack = set(rule_ids)
    covered = covered_rule_ids(results) & pack  # only count rules that exist in the pack

    # "executed" = tests that actually ran to a pass/miss verdict.
    executed = cats[CATEGORY_PASS] + cats[CATEGORY_MISS]
    technique_pass_rate = round(cats[CATEGORY_PASS] / executed, 4) if executed else 0.0

    # Rule pass rate: of the rules that have a test AND whose test executed,
    # how many were detected. We approximate at the technique granularity that
    # the harness operates on; a rule is "passing" if any test covering it passed.
    passing_rules = _passing_rule_ids(results) & pack
    rules_with_test = covered
    rule_pass_rate = (
        round(len(passing_rules) / len(rules_with_test), 4) if rules_with_test else 0.0
    )

    return {
        "rules_in_pack": len(pack),
        "rules_with_atomic_test": len(rules_with_test),
        "atomic_tests_total": len(results),
        "atomic_tests_detected": cats[CATEGORY_PASS],
        "atomic_tests_skipped": cats[CATEGORY_SKIP_PLATFORM] + cats[CATEGORY_SKIP_PREREQ],
        "atomic_tests_missed": cats[CATEGORY_MISS],
        "atomic_tests_error": cats[CATEGORY_ERROR],
        "technique_pass_rate": technique_pass_rate,
        "rule_pass_rate": rule_pass_rate,
    }


# Precedence for collapsing several covering tests into one per-rule verdict.
# A rule shows its *best available evidence*: if any covering technique test
# passed, the rule is demonstrably working (PASS) even if other tests skipped.
# This is technique-granularity (see the rule_pass_rate note above) — a rule is
# PASS for the week if any test that covers it passed, not "every expected rule
# fired in every test". Keeps the per-rule table consistent with the headline.
_RULE_WEEK_PRECEDENCE = [
    CATEGORY_PASS,
    CATEGORY_MISS,
    CATEGORY_ERROR,
    CATEGORY_SKIP_PREREQ,
    CATEGORY_SKIP_PLATFORM,
]


def rule_category_for_week(rule_id: str, results: list[dict]) -> dict | None:
    """Collapse a rule's covering tests in one week to a single verdict.

    Returns {category, reason} or None if no test in this run covers the rule.
    A test "covers" a rule if the rule is in its expected_rules.
    """
    covering = [r for r in results if rule_id in (r.get("expected_rules") or [])]
    if not covering:
        return None
    by_cat: dict[str, dict] = {}
    for r in covering:
        cat = r.get("category") or categorize(r.get("status"), r.get("reason"))
        by_cat.setdefault(cat, r)
    for cat in _RULE_WEEK_PRECEDENCE:
        if cat in by_cat:
            return {"category": cat, "reason": by_cat[cat].get("reason", "") or ""}
    # Unknown category fell outside the precedence list; surface the first.
    first = covering[0]
    cat = first.get("category") or categorize(first.get("status"), first.get("reason"))
    return {"category": cat, "reason": first.get("reason", "") or ""}


def _passing_rule_ids(results: list[dict]) -> set[str]:
    """Rule IDs that were actually detected in at least one passing test."""
    passing: set[str] = set()
    for r in results:
        cat = r.get("category") or categorize(r.get("status"), r.get("reason"))
        if cat == CATEGORY_PASS:
            for rid in r.get("detected_rules", []) or []:
                if rid:
                    passing.add(rid)
    return passing


# --------------------------------------------------------------------------
# ISO-week helpers
# --------------------------------------------------------------------------
def iso_week_label(dt: _dt.datetime | _dt.date) -> str:
    """Return an ISO week label like '2026-W09' for a date/datetime."""
    cal = dt.isocalendar()
    return f"{cal[0]}-W{cal[1]:02d}"


def parse_timestamp(value: str) -> _dt.datetime:
    """Parse an ISO-8601 timestamp (tolerating a trailing 'Z')."""
    return _dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
