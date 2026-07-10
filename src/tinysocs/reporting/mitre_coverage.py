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
import os
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

# Standard paths for rule files (development layout)
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent
_CSHARP_RULES = _PROJECT_ROOT / "packaging" / "detection" / "rules.yml"
_PYTHON_RULES = _PROJECT_ROOT / "src" / "tinysocs" / "agent" / "detections" / "rules.yaml"


def _find_csharp_rules() -> Path | None:
    """Locate C# rules file across dev and installed layouts."""
    candidates = [
        _CSHARP_RULES,
        Path(os.environ.get("ProgramData", r"C:\ProgramData"))
        / "TinySocs" / "Collector" / "rules" / "rules.yml",
    ]
    # PyInstaller frozen bundle
    if getattr(sys, "_MEIPASS", None):
        candidates.append(Path(sys._MEIPASS) / "tinysocs" / "detection" / "rules.yml")  # type: ignore[attr-defined]
    for c in candidates:
        if c.exists():
            return c
    return None


def _find_python_rules() -> Path | None:
    """Locate Python rules file across dev and installed layouts."""
    candidates = [
        _PYTHON_RULES,
        # Relative to this module — works inside PyInstaller bundles
        Path(__file__).resolve().parent.parent / "agent" / "detections" / "rules.yaml",
    ]
    # PyInstaller frozen bundle
    if getattr(sys, "_MEIPASS", None):
        candidates.append(Path(sys._MEIPASS) / "tinysocs" / "agent" / "detections" / "rules.yaml")  # type: ignore[attr-defined]
    for c in candidates:
        if c.exists():
            return c
    return None

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

def load_all_rules() -> list[dict[str, Any]]:
    """Load all rules from both C# and Python rule files."""
    rules = []
    csharp_path = _find_csharp_rules()
    if csharp_path:
        logger.info("Loading C# rules from %s", csharp_path)
        try:
            with open(csharp_path) as f:
                data = yaml.safe_load(f)
                for r in (data.get("rules", []) if isinstance(data, dict) else data or []):
                    if isinstance(r, dict):
                        r["_source"] = "csharp"
                        rules.append(r)
        except Exception as exc:
            logger.error("Failed to load C# rules from %s: %s", csharp_path, exc)
    else:
        logger.warning("No C# rules file found (checked: %s, ProgramData, _MEIPASS=%s)",
                        _CSHARP_RULES, getattr(sys, "_MEIPASS", None))
    python_path = _find_python_rules()
    if python_path:
        logger.info("Loading Python rules from %s", python_path)
        try:
            with open(python_path) as f:
                for r in yaml.safe_load(f) or []:
                    if isinstance(r, dict):
                        r["_source"] = "python"
                        rules.append(r)
        except Exception as exc:
            logger.error("Failed to load Python rules from %s: %s", python_path, exc)
    else:
        logger.warning("No Python rules file found")
    logger.info("Loaded %d total rules", len(rules))
    return rules


def extract_mitre_annotations(rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
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

def calculate_coverage(annotations: list[dict[str, Any]]) -> dict[str, Any]:
    """Calculate MITRE ATT&CK coverage metrics."""
    techniques: dict[str, dict[str, Any]] = {}
    tactics: dict[str, set[str]] = defaultdict(set)
    rules_without_mitre: list[str] = []

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
    coverage: dict[str, Any],
    atomic_results: dict[str, Any] | None = None,
    layer_name: str = "TinySocs Detection Coverage",
    layer_description: str = "Auto-generated from TinySocs detection rule MITRE annotations",
) -> dict[str, Any]:
    """
    Generate ATT&CK Navigator v4.x JSON layer.

    Colour coding:
      - Dark green (#27ae60): detected in Atomic test
      - Light green (#82e0aa): rule exists but untested
      - Grey (#bdc3c7): no coverage
    """
    techniques_layer = []
    tested_techniques: set[str] = set()

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
        entry: dict[str, Any] = {
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

def generate_coverage_markdown(coverage: dict[str, Any]) -> str:
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
        print("TinySocs MITRE ATT&CK Coverage")
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
