"""Tests for FIM detection rules (Python-side)."""

from __future__ import annotations

from pathlib import Path

import yaml

RULES_FILE = Path(__file__).resolve().parent.parent / "src" / "tinysocs" / "agent" / "detections" / "rules.yaml"
CSHARP_RULES = Path(__file__).resolve().parent.parent / "packaging" / "detection" / "rules.yml"

FIM_RULE_IDS_PYTHON = [
    "fim_critical_file_modified",
    "fim_mass_modification",
    "fim_config_tampered",
    "fim_sensitive_file_deleted",
    "fim_executable_replaced",
    "fim_permission_change",
]

FIM_RULE_IDS_CSHARP = [
    "TS-110",
    "TS-111",
    "TS-112",
    "TS-113",
    "TS-114",
    "TS-115",
]


def _load_python_rules():
    with open(RULES_FILE) as f:
        return yaml.safe_load(f)


def _load_csharp_rules():
    with open(CSHARP_RULES) as f:
        data = yaml.safe_load(f)
    return data.get("rules", [])


class TestPythonFimRules:
    def test_fim_rules_exist(self):
        rules = _load_python_rules()
        rule_ids = {r["id"] for r in rules}
        for expected in FIM_RULE_IDS_PYTHON:
            assert expected in rule_ids, f"Missing Python FIM rule: {expected}"

    def test_fim_rules_have_required_fields(self):
        rules = _load_python_rules()
        fim_rules = [r for r in rules if r["id"] in FIM_RULE_IDS_PYTHON]
        for rule in fim_rules:
            assert "description" in rule, f"Rule {rule['id']} missing description"
            assert "kql" in rule, f"Rule {rule['id']} missing kql"
            assert "severity" in rule, f"Rule {rule['id']} missing severity"
            assert "category" in rule, f"Rule {rule['id']} missing category"
            assert rule["category"] == "fim", f"Rule {rule['id']} category should be 'fim'"

    def test_fim_rules_target_correct_channel(self):
        rules = _load_python_rules()
        fim_rules = [r for r in rules if r["id"] in FIM_RULE_IDS_PYTHON]
        for rule in fim_rules:
            assert "TinySocs-FIM" in rule["kql"], \
                f"Rule {rule['id']} should target TinySocs-FIM channel"


class TestCsharpFimRules:
    def test_fim_rules_exist(self):
        rules = _load_csharp_rules()
        rule_ids = {r["id"] for r in rules}
        for expected in FIM_RULE_IDS_CSHARP:
            assert expected in rule_ids, f"Missing C# FIM rule: {expected}"

    def test_fim_rules_have_required_fields(self):
        rules = _load_csharp_rules()
        fim_rules = [r for r in rules if r["id"] in FIM_RULE_IDS_CSHARP]
        for rule in fim_rules:
            assert "description" in rule, f"Rule {rule['id']} missing description"
            assert "severity" in rule, f"Rule {rule['id']} missing severity"
            assert "condition" in rule, f"Rule {rule['id']} missing condition"
            assert rule["condition"]["channel"] == "TinySocs-FIM", \
                f"Rule {rule['id']} should target TinySocs-FIM channel"

    def test_fim_event_ids_correct(self):
        rules = _load_csharp_rules()
        fim_rules = {r["id"]: r for r in rules if r["id"] in FIM_RULE_IDS_CSHARP}
        # TS-110, TS-111, TS-112 should match event_id 1002 (modified)
        for rid in ["TS-110", "TS-111", "TS-112"]:
            assert fim_rules[rid]["condition"]["event_id"] == 1002
        # TS-113 should match event_id 1002 (mass modification)
        assert fim_rules["TS-113"]["condition"]["event_id"] == 1002
        # TS-114 should match event_id 1003 (deleted)
        assert fim_rules["TS-114"]["condition"]["event_id"] == 1003
        # TS-115 should match event_id 1004 (renamed/permission)
        assert fim_rules["TS-115"]["condition"]["event_id"] == 1004
