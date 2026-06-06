#!/usr/bin/env python3
"""Generate TinyDocs stubs from a v2 pack.

Each v2 rule pins a `docs: tinydocs/<id>.md` path (rule-format-v2.md). This
script reads a pack and, for every rule (or a priority subset), emits a stub
under tinydocs/ pre-filled with front-matter and section headers derived from
the rule's own metadata -- including the allowlist scopes it honours and any
tuning knob, so the author starts from facts instead of a blank page.

It NEVER overwrites an existing doc (hand-written content is safe). This makes
it a content-cadence tool too: add a rule, run this, fill in the stub.

Usage:
    python3 scripts/scaffold_tinydocs.py                       # priority 20, stubs only
    python3 scripts/scaffold_tinydocs.py --all                 # every rule in the pack
    python3 scripts/scaffold_tinydocs.py --pack packs/base/2026.23/pack.yml --out tinydocs
"""

from __future__ import annotations

import argparse
from pathlib import Path

import yaml

_REPO_ROOT = Path(__file__).resolve().parent.parent

# Top ~20 most customer-visible rules: high/critical severity + the techniques
# that show up in demos, validation, and real intrusions. The rest are still
# documented eventually (--all), but these lead.
PRIORITY = [
    "TS-061", "TS-062", "TS-060", "TS-001", "TS-002", "TS-071", "TS-070",
    "TS-080", "TS-081", "TS-082", "TS-090", "TS-010", "TS-020", "TS-100",
    "TS-113", "TS-114", "TS-133", "TS-135", "TS-132", "TS-130",
]


def stub(rule: dict) -> str:
    rid = rule["id"]
    mitre = rule.get("mitre") or {}
    det = rule.get("detection") or {}
    scopes = rule.get("allowlist_scopes") or []
    tuning = rule.get("tuning") or {}

    scope_lines = "\n".join(f"- `{s}`" for s in scopes) or "- (none declared)"
    if tuning:
        knobs = ", ".join(f"`{k}`" for k in tuning)
        tuning_text = f"This rule exposes tuning knob(s): {knobs}. Document the trade-off of raising/lowering."
    else:
        tuning_text = "None — single-event trigger; there is no count to tune."

    fm = mitre.get("technique_id", "")
    fmn = mitre.get("technique_name", "")

    return f"""---
rule_id: {rid}
name: {rule.get('name', '')}
severity: {rule.get('severity', '')}
mitre: {fm} ({fmn})
tactic: {mitre.get('tactic', '')}
pack: {rule.get('pack', '')}
runs_on: {rule.get('runs_on', '')}
status: draft
---

# {rid} — {rule.get('name', '').replace('_', ' ').title()}

> {rule.get('description', '')}

## What it detects

Event ID `{det.get('event_id')}` on channel `{det.get('channel')}`, grouped by
`{det.get('group_by')}`, firing at threshold `{det.get('threshold')}` within a
`{det.get('window_minutes')}`-minute window.
{_field_match_note(det)}

_TODO: explain in plain English._

## Why it matters

_TODO: the attacker behaviour behind the signal; the "should I care at 2am" answer._

## What a true positive looks like

_TODO: concrete example of a real detection._

## Common false positives

_TODO: benign activity that also trips this, and how to allowlist it._

This rule honours these allowlist scopes (tune without editing the rule):

{scope_lines}

## Tuning knobs

{tuning_text}

## References

- MITRE ATT&CK: https://attack.mitre.org/techniques/{(fm or '').replace('.', '/')}/
- Atomic Red Team: _TODO link `tests/atomic-tests.yaml` entry_
"""


def _field_match_note(det: dict) -> str:
    fm = det.get("field_match")
    if not fm:
        return ""
    vals = ", ".join(f"`{v}`" for v in fm.get("values", [])[:6])
    more = "…" if len(fm.get("values", [])) > 6 else ""
    return (f"\nOnly counts events whose `{fm.get('field')}` "
            f"{fm.get('match', 'contains')} one of: {vals}{more}.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                      formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--pack", default=str(_REPO_ROOT / "packs" / "base" / "2026.23" / "pack.yml"))
    parser.add_argument("--out", default=str(_REPO_ROOT / "tinydocs"))
    parser.add_argument("--all", action="store_true", help="scaffold every rule, not just the priority 20")
    args = parser.parse_args()

    pack = yaml.safe_load(Path(args.pack).read_text(encoding="utf-8"))
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    rules = {r["id"]: r for r in pack.get("rules", [])}
    targets = list(rules) if args.all else [r for r in PRIORITY if r in rules]

    created, skipped = 0, 0
    for rid in targets:
        dest = out / f"{rid}.md"
        if dest.exists():
            skipped += 1
            continue
        dest.write_text(stub(rules[rid]), encoding="utf-8")
        created += 1

    print(f"scaffolded {created} stub(s), skipped {skipped} existing, into {out.relative_to(_REPO_ROOT)}/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
