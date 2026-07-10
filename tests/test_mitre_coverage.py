"""Tests for MITRE ATT&CK coverage calculator and Navigator layer generator."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from tinysocs.reporting.mitre_coverage import (
    TACTIC_LABELS,
    TACTIC_ORDER,
    _find_csharp_rules,
    _find_python_rules,
    calculate_coverage,
    extract_mitre_annotations,
    generate_coverage_markdown,
    generate_navigator_layer,
    load_all_rules,
)

_PROJECT_ROOT = Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------------------
# Rule loading & MITRE annotation tests
# ---------------------------------------------------------------------------

class TestRuleLoading:
    def test_load_all_rules(self):
        rules = load_all_rules()
        assert len(rules) > 0, "Expected at least some rules to be loaded"

    def test_csharp_rules_have_mitre(self):
        """All production C# rules (TS-xxx) should have mitre annotations."""
        csharp_path = _PROJECT_ROOT / "packaging" / "detection" / "rules.yml"
        if not csharp_path.exists():
            pytest.skip("C# rules file not found")
        with open(csharp_path) as f:
            data = yaml.safe_load(f)
        prod_rules = [r for r in data.get("rules", []) if r.get("id", "").startswith("TS-")]
        missing = [r["id"] for r in prod_rules if not r.get("mitre")]
        assert not missing, f"C# rules missing mitre annotations: {missing}"

    def test_python_rules_have_mitre(self):
        """All Python rules should have mitre annotations."""
        python_path = _PROJECT_ROOT / "src" / "tinysocs" / "agent" / "detections" / "rules.yaml"
        if not python_path.exists():
            pytest.skip("Python rules file not found")
        with open(python_path) as f:
            rules = yaml.safe_load(f) or []
        missing = [r.get("id", "?") for r in rules if not r.get("mitre")]
        assert not missing, f"Python rules missing mitre annotations: {missing}"

    def test_mitre_annotations_valid(self):
        """Every mitre annotation should have technique_id, technique_name, tactic."""
        rules = load_all_rules()
        for rule in rules:
            mitre = rule.get("mitre")
            if mitre:
                rule_id = rule.get("id", "?")
                assert mitre.get("technique_id"), f"Rule {rule_id} missing technique_id"
                assert mitre.get("technique_name"), f"Rule {rule_id} missing technique_name"
                assert mitre.get("tactic"), f"Rule {rule_id} missing tactic"
                assert mitre["tactic"] in TACTIC_ORDER, \
                    f"Rule {rule_id} has invalid tactic: {mitre['tactic']}"

    def test_technique_id_format(self):
        """Technique IDs should match ATT&CK format (T####[.###])."""
        import re
        rules = load_all_rules()
        pattern = re.compile(r"^T\d{4}(\.\d{3})?$")
        for rule in rules:
            mitre = rule.get("mitre")
            if mitre and mitre.get("technique_id"):
                tid = mitre["technique_id"]
                assert pattern.match(tid), \
                    f"Rule {rule.get('id', '?')}: invalid technique_id format: {tid}"

    def test_find_csharp_rules_dev_path(self):
        """_find_csharp_rules should find rules in development layout."""
        path = _find_csharp_rules()
        assert path is not None, "C# rules file should be found in dev layout"
        assert path.name == "rules.yml"

    def test_find_python_rules_dev_path(self):
        """_find_python_rules should find rules in development layout."""
        path = _find_python_rules()
        assert path is not None, "Python rules file should be found in dev layout"
        assert path.name == "rules.yaml"


# ---------------------------------------------------------------------------
# Coverage calculation tests
# ---------------------------------------------------------------------------

class TestCoverageCalculation:
    def _sample_annotations(self):
        return [
            {"rule_id": "R1", "rule_name": "test1", "description": "", "severity": "high",
             "technique_id": "T1110.001", "technique_name": "Brute Force", "tactic": "credential-access", "source": "test"},
            {"rule_id": "R2", "rule_name": "test2", "description": "", "severity": "medium",
             "technique_id": "T1059.001", "technique_name": "PowerShell", "tactic": "execution", "source": "test"},
            {"rule_id": "R3", "rule_name": "test3", "description": "", "severity": "medium",
             "technique_id": "T1059.001", "technique_name": "PowerShell", "tactic": "execution", "source": "test"},
        ]

    def test_coverage_counts(self):
        coverage = calculate_coverage(self._sample_annotations())
        assert coverage["total_techniques"] == 2
        assert coverage["total_tactics"] == 2

    def test_technique_rules_list(self):
        coverage = calculate_coverage(self._sample_annotations())
        ps = coverage["techniques"]["T1059.001"]
        assert "R2" in ps["rules"]
        assert "R3" in ps["rules"]

    def test_tactic_summary(self):
        coverage = calculate_coverage(self._sample_annotations())
        exec_tactic = next(t for t in coverage["tactic_summary"] if t["tactic"] == "execution")
        assert exec_tactic["techniques_covered"] == 1
        assert "T1059.001" in exec_tactic["technique_ids"]

    def test_empty_annotations(self):
        coverage = calculate_coverage([])
        assert coverage["total_techniques"] == 0
        assert coverage["total_tactics"] == 0

    def test_actual_rules_coverage(self):
        """Integration: actual rules should cover at least 8 tactics."""
        rules = load_all_rules()
        annotations = extract_mitre_annotations(rules)
        coverage = calculate_coverage(annotations)
        assert coverage["total_techniques"] >= 10, \
            f"Expected >=10 techniques, got {coverage['total_techniques']}"
        assert coverage["total_tactics"] >= 6, \
            f"Expected >=6 tactics, got {coverage['total_tactics']}"


# ---------------------------------------------------------------------------
# Navigator layer generation tests
# ---------------------------------------------------------------------------

class TestNavigatorLayer:
    def test_layer_structure(self):
        coverage = calculate_coverage([
            {"rule_id": "R1", "rule_name": "t", "description": "", "severity": "h",
             "technique_id": "T1110.001", "technique_name": "Brute Force",
             "tactic": "credential-access", "source": "test"},
        ])
        layer = generate_navigator_layer(coverage)
        assert layer["name"] == "TinySocs Detection Coverage"
        assert layer["domain"] == "enterprise-attack"
        assert layer["versions"]["attack"] == "14"
        assert len(layer["techniques"]) == 1
        assert layer["techniques"][0]["techniqueID"] == "T1110.001"
        assert layer["techniques"][0]["color"] == "#82e0aa"  # untested

    def test_tested_technique_color(self):
        coverage = calculate_coverage([
            {"rule_id": "R1", "rule_name": "t", "description": "", "severity": "h",
             "technique_id": "T1110.001", "technique_name": "Brute Force",
             "tactic": "credential-access", "source": "test"},
        ])
        atomic = {"results": [{"technique_id": "T1110.001", "status": "DETECTED"}]}
        layer = generate_navigator_layer(coverage, atomic_results=atomic)
        assert layer["techniques"][0]["color"] == "#27ae60"  # tested
        assert "[TESTED]" in layer["techniques"][0]["comment"]

    def test_layer_is_valid_json(self):
        """Full layer from actual rules should be serializable JSON."""
        rules = load_all_rules()
        annotations = extract_mitre_annotations(rules)
        coverage = calculate_coverage(annotations)
        layer = generate_navigator_layer(coverage)
        json_str = json.dumps(layer, indent=2)
        parsed = json.loads(json_str)
        assert parsed["domain"] == "enterprise-attack"
        assert len(parsed["techniques"]) > 0

    def test_legend_items(self):
        coverage = calculate_coverage([])
        layer = generate_navigator_layer(coverage)
        labels = [li["label"] for li in layer["legendItems"]]
        assert "Detected (Atomic tested)" in labels
        assert "Rule exists (untested)" in labels
        assert "No coverage" in labels


# ---------------------------------------------------------------------------
# Markdown report generation tests
# ---------------------------------------------------------------------------

class TestMarkdownReport:
    def test_markdown_has_header(self):
        coverage = calculate_coverage([
            {"rule_id": "R1", "rule_name": "t", "description": "", "severity": "h",
             "technique_id": "T1110.001", "technique_name": "Brute Force",
             "tactic": "credential-access", "source": "test"},
        ])
        md = generate_coverage_markdown(coverage)
        assert "# TinySocs Detection Coverage" in md
        assert "T1110.001" in md
        assert "Brute Force" in md

    def test_tactic_summary_table(self):
        coverage = calculate_coverage([
            {"rule_id": "R1", "rule_name": "t", "description": "", "severity": "h",
             "technique_id": "T1110.001", "technique_name": "Brute Force",
             "tactic": "credential-access", "source": "test"},
        ])
        md = generate_coverage_markdown(coverage)
        assert "Coverage by Tactic" in md
        assert "Credential Access" in md

    def test_empty_coverage(self):
        coverage = calculate_coverage([])
        md = generate_coverage_markdown(coverage)
        assert "Total techniques covered:** 0" in md


# ---------------------------------------------------------------------------
# Tactic constants tests
# ---------------------------------------------------------------------------

class TestTacticConstants:
    def test_tactic_order_length(self):
        assert len(TACTIC_ORDER) == 14

    def test_tactic_labels_match_order(self):
        for tactic in TACTIC_ORDER:
            assert tactic in TACTIC_LABELS, f"Missing label for tactic: {tactic}"
