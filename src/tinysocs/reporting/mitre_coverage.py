"""
MITRE ATT&CK coverage calculator and Navigator layer generator.

Reads MITRE annotations from all rule files, calculates coverage metrics,
and generates ATT&CK Navigator JSON layers.

CLI usage:
    python -m tinysocs.reporting.mitre_coverage
    python -m tinysocs.reporting.mitre_coverage --output navigator-layer.json
    python -m tinysocs.reporting.mitre_coverage --output-md docs/detection-coverage.md
"""

from __future__ import annotations

import json
import logging
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import yaml

logger = logging.getLogger(__name__)

# Standard paths for rule files
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent
_CSHARP_RULES = _PROJECT_ROOT / "packaging" / "detection" / "rules.yml"
_PYTHON_RULES = _PROJECT_ROOT / "src" / "tinysocs" / "agent" / "detections" / "rules.yaml"

# ATT&CK tactics in standard order
TACTIC_ORDER = [
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]

TACTIC_LABELS = {
    "reconnaissance": "Reconnaissance",
    "resource-development": "Resource Development",
    "initial-access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege-escalation": "Privilege Escalation",
    "defense-evasion": "Defense Evasion",
    "credential-access": "Credential Access",
    "discovery": "Discovery",
    "lateral-movement": "Lateral Movement",
    "collection": "Collection",
    "command-and-control": "Command and Control",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
}


# ---------------------------------------------------------------------------
# Rule loading
# ---------------------------------------------------------------------------

def load_all_rules() -> List[Dict[str, Any]]:
    """Load all rules from both C# and Python rule files."""
    rules = []
    if _CSHARP_RULES.exists():
        with open(_CSHARP_RULES) as f:
            data = yaml.safe_load(f)
            for r in data.get("rules", []):
                r["_source"] = "csharp"
                rules.append(r)
    if _PYTHON_RULES.exists():
        with open(_PYTHON_RULES) as f:
            for r in yaml.safe_load(f) or []:
                r["_source"] = "python"
                rules.append(r)
    return rules


def extract_mitre_annotations(rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Extract MITRE annotations from rules, returning annotated entries."""
    annotations = []
    for rule in rules:
        mitre = rule.get("mitre")
        if mitre:
            annotations.append({
                "rule_id": rule.get("id", ""),
                "rule_name": rule.get("name", ""),
                "description": rule.get("description", ""),
                "severity": rule.get("severity", ""),
                "technique_id": mitre.get("technique_id", ""),
                "technique_name": mitre.get("technique_name", ""),
                "tactic": mitre.get("tactic", ""),
                "source": rule.get("_source", ""),
            })
    return annotations


# ---------------------------------------------------------------------------
# Coverage calculation
# ---------------------------------------------------------------------------

def calculate_coverage(annotations: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Calculate MITRE ATT&CK coverage metrics."""
    techniques: Dict[str, Dict[str, Any]] = {}
    tactics: Dict[str, Set[str]] = defaultdict(set)
    rules_without_mitre: List[str] = []

    for ann in annotations:
        tid = ann["technique_id"]
        tactic = ann["tactic"]
        if not tid:
            continue
        if tid not in techniques:
            techniques[tid] = {
                "technique_id": tid,
                "technique_name": ann["technique_name"],
                "tactic": tactic,
                "rules": [],
            }
        techniques[tid]["rules"].append(ann["rule_id"])
        tactics[tactic].add(tid)

    # Summary by tactic
    tactic_summary = []
    for tactic in TACTIC_ORDER:
        tech_ids = tactics.get(tactic, set())
        tactic_summary.append({
            "tactic": tactic,
            "label": TACTIC_LABELS.get(tactic, tactic),
            "techniques_covered": len(tech_ids),
            "technique_ids": sorted(tech_ids),
        })

    return {
        "total_techniques": len(techniques),
        "total_tactics": len([t for t in tactics if tactics[t]]),
        "techniques": techniques,
        "tactic_summary": tactic_summary,
        "rules_without_mitre": rules_without_mitre,
    }


# ---------------------------------------------------------------------------
# ATT&CK Navigator layer generation
# ---------------------------------------------------------------------------

def generate_navigator_layer(
    coverage: Dict[str, Any],
    atomic_results: Optional[Dict[str, Any]] = None,
    layer_name: str = "TinySocs Detection Coverage",
    layer_description: str = "Auto-generated from TinySocs detection rule MITRE annotations",
) -> Dict[str, Any]:
    """
    Generate ATT&CK Navigator v4.x JSON layer.

    Colour coding:
      - Dark green (#27ae60): detected in Atomic test
      - Light green (#82e0aa): rule exists but untested
      - Grey (#bdc3c7): no coverage
    """
    techniques_layer = []
    tested_techniques: Set[str] = set()

    if atomic_results:
        for result in atomic_results.get("results", []):
            if result.get("status") == "DETECTED":
                tested_techniques.add(result.get("technique_id", ""))

    for tid, tech_info in coverage["techniques"].items():
        is_tested = tid in tested_techniques
        color = "#27ae60" if is_tested else "#82e0aa"
        comment = f"Rules: {', '.join(tech_info['rules'])}"
        if is_tested:
            comment += " [TESTED]"

        # ATT&CK Navigator technique entry
        entry: Dict[str, Any] = {
            "techniqueID": tid,
            "color": color,
            "comment": comment,
            "enabled": True,
            "metadata": [
                {"name": "rules", "value": ", ".join(tech_info["rules"])},
            ],
            "showSubtechniques": False,
        }

        # Map tactic to Navigator tactic shortname
        tactic = tech_info.get("tactic", "")
        if tactic:
            entry["tactic"] = tactic

        techniques_layer.append(entry)

    layer = {
        "name": layer_name,
        "versions": {
            "attack": "14",
            "navigator": "4.9.1",
            "layer": "4.5",
        },
        "domain": "enterprise-attack",
        "description": layer_description,
        "filters": {
            "platforms": ["Windows"],
        },
        "sorting": 0,
        "layout": {
            "layout": "side",
            "aggregateFunction": "average",
            "showID": True,
            "showName": True,
            "showAggregateScores": False,
            "countUnscored": False,
        },
        "hideDisabled": False,
        "techniques": techniques_layer,
        "gradient": {
            "colors": ["#bdc3c7", "#82e0aa", "#27ae60"],
            "minValue": 0,
            "maxValue": 100,
        },
        "legendItems": [
            {"label": "Detected (Atomic tested)", "color": "#27ae60"},
            {"label": "Rule exists (untested)", "color": "#82e0aa"},
            {"label": "No coverage", "color": "#bdc3c7"},
        ],
        "metadata": [],
        "links": [],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#1a1d27",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
    }

    return layer


# ---------------------------------------------------------------------------
# Markdown report generation
# ---------------------------------------------------------------------------

def generate_coverage_markdown(coverage: Dict[str, Any]) -> str:
    """Generate detection-coverage.md content from coverage data."""
    lines = [
        "# TinySocs Detection Coverage — MITRE ATT&CK Mapping",
        "",
        f"**Total techniques covered:** {coverage['total_techniques']}  ",
        f"**Tactics with coverage:** {coverage['total_tactics']}/{len(TACTIC_ORDER)}",
        "",
        "*Auto-generated by `python -m tinysocs.reporting.mitre_coverage`*",
        "",
    ]

    # Tactic summary table
    lines.append("## Coverage by Tactic")
    lines.append("")
    lines.append("| Tactic | Techniques Covered |")
    lines.append("|--------|-------------------|")
    for ts in coverage["tactic_summary"]:
        count = ts["techniques_covered"]
        bar = "+" * min(count, 20) if count > 0 else "-"
        lines.append(f"| {ts['label']} | {count} {bar} |")
    lines.append("")

    # Detailed per-technique table
    lines.append("## Technique Details")
    lines.append("")
    lines.append("| Technique ID | Technique Name | Tactic | TinySocs Rules |")
    lines.append("|-------------|---------------|--------|----------------|")
    for tid in sorted(coverage["techniques"].keys()):
        tech = coverage["techniques"][tid]
        rules = ", ".join(tech["rules"])
        tactic_label = TACTIC_LABELS.get(tech["tactic"], tech["tactic"])
        lines.append(f"| {tid} | {tech['technique_name']} | {tactic_label} | {rules} |")
    lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def _cli():
    import argparse

    parser = argparse.ArgumentParser(description="TinySocs MITRE ATT&CK Coverage")
    parser.add_argument("--output", help="Output ATT&CK Navigator layer JSON file")
    parser.add_argument("--output-md", help="Output detection-coverage.md file")
    parser.add_argument("--atomic-results", help="Path to atomic-results.json for test colouring")
    parser.add_argument("--json", action="store_true", help="Output coverage as JSON")
    args = parser.parse_args()

    rules = load_all_rules()
    annotations = extract_mitre_annotations(rules)
    coverage = calculate_coverage(annotations)

    # Check for rules without MITRE annotations
    annotated_ids = {a["rule_id"] for a in annotations}
    missing = [r.get("id", "?") for r in rules if r.get("id") and r["id"] not in annotated_ids]

    if not args.json and not args.output and not args.output_md:
        # Print summary to stdout
        print(f"TinySocs MITRE ATT&CK Coverage")
        print(f"{'=' * 40}")
        print(f"Total rules: {len(rules)}")
        print(f"Rules with MITRE annotations: {len(annotations)}")
        print(f"Unique techniques covered: {coverage['total_techniques']}")
        print(f"Tactics with coverage: {coverage['total_tactics']}/{len(TACTIC_ORDER)}")
        print()

        for ts in coverage["tactic_summary"]:
            if ts["techniques_covered"] > 0:
                ids = ", ".join(ts["technique_ids"])
                print(f"  {ts['label']}: {ts['techniques_covered']} techniques ({ids})")

        if missing:
            print(f"\nRules missing MITRE annotations: {', '.join(missing)}")

    if args.json:
        print(json.dumps(coverage, indent=2, default=list))

    # Load atomic results if provided
    atomic_results = None
    if args.atomic_results:
        with open(args.atomic_results) as f:
            atomic_results = json.load(f)

    if args.output:
        layer = generate_navigator_layer(coverage, atomic_results)
        with open(args.output, "w") as f:
            json.dump(layer, f, indent=2)
        print(f"Navigator layer written to {args.output}")

    if args.output_md:
        md = generate_coverage_markdown(coverage)
        with open(args.output_md, "w") as f:
            f.write(md)
        print(f"Detection coverage markdown written to {args.output_md}")


if __name__ == "__main__":
    _cli()
