"""
test_detection_rules.py — Validate detection rule syntax, required fields,
and action coverage across both rule packs.

Phase 13 (M3): Detection Coverage Expansion validation.
"""

import pathlib
import pytest
import yaml

# ── File locations ────────────────────────────────────────────────────
ROOT = pathlib.Path(__file__).resolve().parent.parent
PYTHON_RULES = ROOT / "src" / "tinysocs" / "agent" / "detections" / "rules.yaml"
CSHARP_RULES = ROOT / "packaging" / "detection" / "rules.yml"
ACTIONS_FILE = ROOT / "src" / "tinysocs" / "agent" / "actions.yaml"


def _load_yaml(path: pathlib.Path):
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


# ── Python / dashboard KQL rules ─────────────────────────────────────

class TestPythonRules:
    """Validate the KQL-based rules used by the Python dashboard."""

    @pytest.fixture(scope="class")
    def rules(self):
        data = _load_yaml(PYTHON_RULES)
        assert isinstance(data, list), "rules.yaml must be a list of rule objects"
        return data

    def test_file_exists(self):
        assert PYTHON_RULES.is_file(), f"{PYTHON_RULES} not found"

    def test_rules_parse(self, rules):
        assert len(rules) > 0, "No rules found"

    def test_required_fields(self, rules):
        required = {"id", "description", "index", "time_field", "kql",
                     "group_by", "threshold", "severity", "category"}
        for rule in rules:
            rule_id = rule.get("id", "<unknown>")
            missing = required - set(rule.keys())
            assert not missing, f"Rule '{rule_id}' missing fields: {missing}"

    def test_unique_ids(self, rules):
        ids = [r["id"] for r in rules]
        dupes = [i for i in ids if ids.count(i) > 1]
        assert not dupes, f"Duplicate rule IDs: {set(dupes)}"

    def test_severity_values(self, rules):
        valid = {"low", "medium", "high", "critical"}
        for rule in rules:
            assert rule["severity"] in valid, (
                f"Rule '{rule['id']}' has invalid severity '{rule['severity']}'"
            )

    def test_threshold_positive(self, rules):
        for rule in rules:
            assert isinstance(rule["threshold"], int) and rule["threshold"] > 0, (
                f"Rule '{rule['id']}' threshold must be a positive integer"
            )

    def test_group_by_is_list(self, rules):
        for rule in rules:
            assert isinstance(rule["group_by"], list), (
                f"Rule '{rule['id']}' group_by must be a list"
            )

    def test_kql_not_empty(self, rules):
        for rule in rules:
            kql = rule.get("kql", "").strip()
            assert len(kql) > 0, f"Rule '{rule['id']}' has empty KQL"

    def test_minimum_rule_count(self, rules):
        """Phase 13 target: ~40 total rules (production + lab)."""
        prod_rules = [r for r in rules if not r["id"].endswith("_lab")]
        assert len(prod_rules) >= 34, (
            f"Expected >=34 production rules, found {len(prod_rules)}"
        )

    def test_category_coverage(self, rules):
        """Ensure rules span at least 8 categories (Phase 13 target)."""
        categories = {r["category"] for r in rules if not r["id"].endswith("_lab")}
        assert len(categories) >= 8, (
            f"Expected >=8 categories, found {len(categories)}: {categories}"
        )


# ── C# agent threshold_by_key rules ──────────────────────────────────

class TestCSharpRules:
    """Validate the C# agent rules used by DetectionEngine."""

    @pytest.fixture(scope="class")
    def rules(self):
        data = _load_yaml(CSHARP_RULES)
        assert isinstance(data, dict) and "rules" in data
        return data["rules"]

    def test_file_exists(self):
        assert CSHARP_RULES.is_file(), f"{CSHARP_RULES} not found"

    def test_rules_parse(self, rules):
        assert len(rules) > 0, "No rules found"

    def test_required_fields(self, rules):
        required_top = {"id", "name", "description", "severity", "enabled",
                        "type", "condition", "actions"}
        required_cond = {"event_id", "group_by", "threshold"}
        for rule in rules:
            rule_id = rule.get("id", "<unknown>")
            missing_top = required_top - set(rule.keys())
            assert not missing_top, f"Rule '{rule_id}' missing top-level: {missing_top}"
            cond = rule.get("condition", {})
            missing_cond = required_cond - set(cond.keys())
            assert not missing_cond, f"Rule '{rule_id}' missing condition: {missing_cond}"

    def test_unique_ids(self, rules):
        ids = [r["id"] for r in rules]
        dupes = [i for i in ids if ids.count(i) > 1]
        assert not dupes, f"Duplicate rule IDs: {set(dupes)}"

    def test_severity_values(self, rules):
        valid = {"low", "medium", "high", "critical"}
        for rule in rules:
            assert rule["severity"] in valid, (
                f"Rule '{rule['id']}' has invalid severity '{rule['severity']}'"
            )

    def test_minimum_rule_count(self, rules):
        """Phase 13 target: expand C# rules significantly."""
        prod_rules = [r for r in rules if "-lab" not in r["id"]]
        assert len(prod_rules) >= 22, (
            f"Expected >=22 production C# rules, found {len(prod_rules)}"
        )

    def test_cooldown_minutes_valid(self, rules):
        """cooldown_minutes must be a non-negative integer when present."""
        for rule in rules:
            cond = rule.get("condition", {})
            cd = cond.get("cooldown_minutes")
            if cd is not None:
                assert isinstance(cd, int) and cd >= 0, (
                    f"Rule '{rule['id']}' cooldown_minutes must be a non-negative integer, got {cd!r}"
                )

    def test_lab_rules_disabled(self, rules):
        """Lab rules must be disabled by default to avoid alert noise in production."""
        lab_rules = [r for r in rules if "-lab" in r["id"]]
        for rule in lab_rules:
            assert rule.get("enabled") is False, (
                f"Lab rule '{rule['id']}' must have enabled: false"
            )


# ── Action coverage ───────────────────────────────────────────────────

class TestActionCoverage:
    """Ensure every production KQL rule has a corresponding actions.yaml entry."""

    @pytest.fixture(scope="class")
    def rule_ids(self):
        data = _load_yaml(PYTHON_RULES)
        return {r["id"] for r in data if not r["id"].endswith("_lab")}

    @pytest.fixture(scope="class")
    def action_ids(self):
        data = _load_yaml(ACTIONS_FILE)
        return set(data.keys())

    def test_actions_file_exists(self):
        assert ACTIONS_FILE.is_file(), f"{ACTIONS_FILE} not found"

    def test_every_rule_has_actions(self, rule_ids, action_ids):
        # Some rules intentionally share actions or have generic coverage.
        # But all new Phase 13 rules should be covered. Check production rules
        # excluding vpn/firewall/m365/cloud rules (different index, may not need
        # operator remediation snippets on the same host).
        winlog_rules = {r for r in rule_ids
                        if not r.startswith(("vpn_", "firewall_", "m365_"))}
        missing = winlog_rules - action_ids
        assert not missing, (
            f"Rules missing action snippets: {missing}"
        )

    def test_actions_have_content(self):
        data = _load_yaml(ACTIONS_FILE)
        for rule_id, actions in data.items():
            assert isinstance(actions, list), f"'{rule_id}' actions must be a list"
            assert len(actions) > 0, f"'{rule_id}' has no action entries"
            for action in actions:
                assert "label" in action, f"'{rule_id}' action missing 'label'"
                assert "cmd" in action, f"'{rule_id}' action missing 'cmd'"
