# tests/test_compliance_reports.py
"""Unit tests for compliance report generator (Phase 14 / M4)."""

from unittest.mock import patch

import pytest

from tinysocs.reporting.compliance_report import (
    generate_compliance_report,
    list_frameworks,
    load_framework,
    render_html,
)


# ---------------------------------------------------------------------------
# Framework loading
# ---------------------------------------------------------------------------
class TestLoadFramework:
    def test_loads_nist_csf(self):
        fw = load_framework("nist_csf")
        assert fw["name"] == "NIST Cybersecurity Framework 2.0"
        assert "controls" in fw
        assert len(fw["controls"]) > 0

    def test_loads_hipaa(self):
        fw = load_framework("hipaa")
        assert "HIPAA" in fw["name"]
        assert "controls" in fw

    def test_loads_pci_dss(self):
        fw = load_framework("pci_dss")
        assert "PCI" in fw["name"]
        assert "controls" in fw

    def test_missing_framework_raises(self):
        with pytest.raises(FileNotFoundError, match="Framework not found"):
            load_framework("nonexistent_framework_xyz")


class TestListFrameworks:
    def test_lists_available_frameworks(self):
        names = list_frameworks()
        assert "nist_csf" in names
        assert "hipaa" in names
        assert "pci_dss" in names

    def test_returns_sorted(self):
        names = list_frameworks()
        assert names == sorted(names)


# ---------------------------------------------------------------------------
# Framework YAML validity
# ---------------------------------------------------------------------------
class TestFrameworkYamlValidity:
    @pytest.fixture(params=["nist_csf", "hipaa", "pci_dss"])
    def framework(self, request):
        return load_framework(request.param)

    def test_has_required_fields(self, framework):
        assert "name" in framework
        assert "controls" in framework
        assert isinstance(framework["controls"], list)

    def test_controls_have_required_keys(self, framework):
        for control in framework["controls"]:
            assert "id" in control, f"Control missing 'id': {control}"
            assert "name" in control, f"Control missing 'name': {control}"
            assert "rules" in control, f"Control {control['id']} missing 'rules'"
            assert isinstance(control["rules"], list), f"Control {control['id']} 'rules' is not a list"

    def test_rule_ids_are_strings(self, framework):
        for control in framework["controls"]:
            for rule_id in control["rules"]:
                assert isinstance(rule_id, str), f"Rule ID {rule_id} in control {control['id']} is not a string"


# ---------------------------------------------------------------------------
# Report generation (mocked OpenSearch)
# ---------------------------------------------------------------------------
def _mock_rule_counts():
    """Return a fake rule fire count dict."""
    return {
        "auth_failed_burst": 15,
        "TS-001": 8,
        "lsass_access": 3,
        "TS-060": 2,
        "event_log_cleared": 1,
    }


class TestGenerateComplianceReport:
    @patch("tinysocs.reporting.compliance_report._rule_fire_counts")
    def test_report_structure(self, mock_counts):
        mock_counts.return_value = _mock_rule_counts()
        report = generate_compliance_report("nist_csf", hours=168)

        assert "framework" in report
        assert "controls" in report
        assert "summary" in report
        assert "generated_at" in report
        assert report["period_hours"] == 168
        assert report["framework"]["name"] == "NIST Cybersecurity Framework 2.0"

    @patch("tinysocs.reporting.compliance_report._rule_fire_counts")
    def test_summary_counts(self, mock_counts):
        mock_counts.return_value = _mock_rule_counts()
        report = generate_compliance_report("nist_csf", hours=720)
        s = report["summary"]

        assert s["total_controls"] > 0
        assert s["covered"] >= 0
        assert s["not_mapped"] >= 0
        assert s["covered"] + s["not_mapped"] == s["total_controls"]
        assert 0 <= s["coverage_pct"] <= 100

    @patch("tinysocs.reporting.compliance_report._rule_fire_counts")
    def test_control_statuses(self, mock_counts):
        mock_counts.return_value = _mock_rule_counts()
        report = generate_compliance_report("nist_csf", hours=720)

        for c in report["controls"]:
            assert c["status"] in ("active", "deployed", "not_mapped")
            assert "id" in c
            assert "name" in c
            assert isinstance(c["mapped_rules"], list)
            assert isinstance(c["fired_rules"], list)
            assert isinstance(c["fire_count"], int)

    @patch("tinysocs.reporting.compliance_report._rule_fire_counts")
    def test_active_status_when_rules_fired(self, mock_counts):
        mock_counts.return_value = {"auth_failed_burst": 5, "TS-001": 3}
        report = generate_compliance_report("nist_csf", hours=24)

        # PR.AC-07 maps auth_failed_burst — should be active
        pr_ac07 = next(c for c in report["controls"] if c["id"] == "PR.AC-07")
        assert pr_ac07["status"] == "active"
        assert pr_ac07["fire_count"] > 0
        assert len(pr_ac07["fired_rules"]) > 0

    @patch("tinysocs.reporting.compliance_report._rule_fire_counts")
    def test_deployed_status_when_no_fires(self, mock_counts):
        mock_counts.return_value = {}  # no rules fired
        report = generate_compliance_report("nist_csf", hours=24)

        # PR.AC-07 has mapped rules but none fired — should be deployed
        pr_ac07 = next(c for c in report["controls"] if c["id"] == "PR.AC-07")
        assert pr_ac07["status"] == "deployed"
        assert pr_ac07["fire_count"] == 0

    @patch("tinysocs.reporting.compliance_report._rule_fire_counts")
    def test_not_mapped_status(self, mock_counts):
        mock_counts.return_value = {}
        report = generate_compliance_report("nist_csf", hours=24)

        # ID.AM-01 has no mapped rules — should be not_mapped
        id_am01 = next(c for c in report["controls"] if c["id"] == "ID.AM-01")
        assert id_am01["status"] == "not_mapped"

    @patch("tinysocs.reporting.compliance_report._rule_fire_counts")
    def test_hipaa_report(self, mock_counts):
        mock_counts.return_value = _mock_rule_counts()
        report = generate_compliance_report("hipaa", hours=720)
        assert "HIPAA" in report["framework"]["name"]
        assert report["summary"]["total_controls"] > 0

    @patch("tinysocs.reporting.compliance_report._rule_fire_counts")
    def test_pci_dss_report(self, mock_counts):
        mock_counts.return_value = _mock_rule_counts()
        report = generate_compliance_report("pci_dss", hours=720)
        assert "PCI" in report["framework"]["name"]
        assert report["summary"]["total_controls"] > 0


# ---------------------------------------------------------------------------
# HTML rendering
# ---------------------------------------------------------------------------
class TestRenderHtml:
    @patch("tinysocs.reporting.compliance_report._rule_fire_counts")
    def test_html_output_structure(self, mock_counts):
        mock_counts.return_value = _mock_rule_counts()
        report = generate_compliance_report("nist_csf", hours=720)
        html = render_html(report)

        assert "<!DOCTYPE html>" in html
        assert "NIST Cybersecurity Framework 2.0" in html
        assert "Coverage" in html
        assert "</table>" in html

    @patch("tinysocs.reporting.compliance_report._rule_fire_counts")
    def test_html_contains_control_ids(self, mock_counts):
        mock_counts.return_value = {}
        report = generate_compliance_report("nist_csf", hours=24)
        html = render_html(report)

        # Spot-check a few control IDs appear in the output
        assert "DE.CM-01" in html
        assert "PR.AC-01" in html

    @patch("tinysocs.reporting.compliance_report._rule_fire_counts")
    def test_html_contains_status_classes(self, mock_counts):
        mock_counts.return_value = _mock_rule_counts()
        report = generate_compliance_report("nist_csf", hours=720)
        html = render_html(report)

        assert "status-pass" in html or "status-warn" in html or "status-na" in html

    @patch("tinysocs.reporting.compliance_report._rule_fire_counts")
    def test_renders_all_frameworks(self, mock_counts):
        mock_counts.return_value = {}
        for fw_name in list_frameworks():
            report = generate_compliance_report(fw_name, hours=24)
            html = render_html(report)
            assert "<!DOCTYPE html>" in html
            assert report["framework"]["name"] in html
