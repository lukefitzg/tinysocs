"""
Compliance Report Generator — Phase 14 M4

Maps TinySocs detection rules to compliance framework controls (NIST CSF, HIPAA, PCI DSS).
Queries OpenSearch for rule fire counts and generates a per-control status report.

Usage:
    python -m tinysocs.reporting.compliance_report --framework nist_csf --hours 720
    python -m tinysocs.reporting.compliance_report --framework hipaa --hours 168 --output report.html
"""
from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

# Reuse OpenSearch client infrastructure from daily_summary
from tinysocs.reporting.daily_summary import (
    _load_assistant_env,
    _os_query,
)

_load_assistant_env()

# ---------------------------------------------------------------------------
# Framework loading
# ---------------------------------------------------------------------------
def _resolve_frameworks_dir() -> Path:
    """Locate the frameworks directory, with PyInstaller bundle fallback."""
    d = Path(__file__).parent / "frameworks"
    if d.is_dir():
        return d
    # PyInstaller _MEIPASS fallback
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        d2 = Path(meipass) / "tinysocs" / "reporting" / "frameworks"
        if d2.is_dir():
            return d2
    return d  # return original even if missing; callers handle gracefully


FRAMEWORKS_DIR = _resolve_frameworks_dir()


def load_framework(name: str) -> Dict[str, Any]:
    """Load a compliance framework YAML file."""
    path = FRAMEWORKS_DIR / f"{name}.yaml"
    if not path.is_file():
        raise FileNotFoundError(f"Framework not found: {path}")
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def list_frameworks() -> List[str]:
    """List available framework names."""
    if not FRAMEWORKS_DIR.is_dir():
        return []
    return sorted(p.stem for p in FRAMEWORKS_DIR.glob("*.yaml"))


# ---------------------------------------------------------------------------
# Data collection
# ---------------------------------------------------------------------------
def _rule_fire_counts(hours: int) -> Dict[str, int]:
    """Count how many times each rule fired in the last N hours."""
    body = {
        "size": 0,
        "query": {"range": {"timestamp": {"gte": f"now-{hours}h", "lte": "now"}}},
        "aggs": {
            "by_rule": {
                "terms": {"field": "alert.rule_id", "size": 500}
            }
        },
    }
    try:
        resp = _os_query("tinysocs-alerts-*", body)
        buckets = resp.get("aggregations", {}).get("by_rule", {}).get("buckets", [])
        return {b["key"]: b["doc_count"] for b in buckets}
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------
def generate_compliance_report(
    framework_name: str,
    hours: int = 720,  # default 30 days
) -> Dict[str, Any]:
    """Generate a compliance report for the given framework.

    Returns a dict with:
      - framework: name and metadata
      - controls: list of controls with status
      - summary: total/covered/not_mapped counts and coverage_pct
    """
    fw = load_framework(framework_name)
    rule_counts = _rule_fire_counts(hours)

    controls: List[Dict[str, Any]] = []
    total = 0
    covered = 0
    not_mapped = 0

    for control in fw.get("controls", []):
        control_id = control["id"]
        control_name = control["name"]
        mapped_rules = control.get("rules", [])

        if not mapped_rules:
            status = "not_mapped"
            not_mapped += 1
        else:
            fired_rules = [r for r in mapped_rules if r in rule_counts]
            if fired_rules:
                status = "active"  # Detection is working and firing
            else:
                status = "deployed"  # Rule exists but hasn't fired (still covered)
            covered += 1

        total += 1
        controls.append({
            "id": control_id,
            "name": control_name,
            "description": control.get("description", ""),
            "status": status,
            "mapped_rules": mapped_rules,
            "fired_rules": [r for r in mapped_rules if r in rule_counts],
            "fire_count": sum(rule_counts.get(r, 0) for r in mapped_rules),
            "required": control.get("required", True),
        })

    return {
        "framework": {
            "name": fw.get("name", framework_name),
            "version": fw.get("version", ""),
            "description": fw.get("description", ""),
        },
        "period_hours": hours,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "controls": controls,
        "summary": {
            "total_controls": total,
            "covered": covered,
            "not_mapped": not_mapped,
            "coverage_pct": round(covered / max(total, 1) * 100, 1),
        },
    }


# ---------------------------------------------------------------------------
# HTML rendering
# ---------------------------------------------------------------------------
def render_html(report: Dict[str, Any]) -> str:
    """Render the compliance report as HTML."""
    template_path = Path(__file__).parent / "templates" / "compliance_report.html"
    if template_path.is_file():
        template = template_path.read_text(encoding="utf-8")
    else:
        template = _FALLBACK_TEMPLATE

    # Build controls table rows
    rows = []
    for c in report["controls"]:
        status_class = {
            "active": "status-pass",
            "deployed": "status-warn",
            "not_mapped": "status-na",
        }.get(c["status"], "status-na")

        status_label = {
            "active": "Active",
            "deployed": "Deployed",
            "not_mapped": "Not Mapped",
        }.get(c["status"], c["status"])

        rules_str = ", ".join(c["mapped_rules"]) if c["mapped_rules"] else "&mdash;"
        rows.append(
            f'<tr><td>{c["id"]}</td><td>{c["name"]}</td>'
            f'<td><span class="{status_class}">{status_label}</span></td>'
            f'<td>{rules_str}</td><td>{c["fire_count"]}</td></tr>'
        )

    s = report["summary"]
    html = template
    html = html.replace("{{framework_name}}", report["framework"]["name"])
    html = html.replace("{{framework_version}}", report["framework"].get("version", ""))
    html = html.replace("{{generated_at}}", report["generated_at"][:19].replace("T", " "))
    html = html.replace("{{period_hours}}", str(report["period_hours"]))
    html = html.replace("{{total}}", str(s["total_controls"]))
    html = html.replace("{{covered}}", str(s["covered"]))
    html = html.replace("{{not_mapped}}", str(s["not_mapped"]))
    html = html.replace("{{coverage_pct}}", str(s["coverage_pct"]))
    html = html.replace("{{controls_rows}}", "\n".join(rows))
    return html


_FALLBACK_TEMPLATE = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>TinySocs Compliance Report — {{framework_name}}</title>
<style>
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;margin:0;padding:20px;background:#f5f6fa;color:#2d3436}
.container{max-width:960px;margin:0 auto;background:#fff;padding:32px;border-radius:10px;box-shadow:0 2px 8px rgba(0,0,0,.08)}
h1{font-size:22px;margin:0 0 4px} .subtitle{color:#636e72;font-size:13px;margin-bottom:24px}
table{width:100%;border-collapse:collapse;margin-top:16px;font-size:13px}
th,td{padding:10px 12px;border-bottom:1px solid #eee;text-align:left}
th{background:#f8f9fa;font-weight:600;color:#636e72;font-size:11px;text-transform:uppercase;letter-spacing:.5px}
tr:hover{background:#f8f9fa}
.status-pass{color:#00b894;font-weight:600}
.status-warn{color:#fdcb6e;font-weight:600}
.status-na{color:#b2bec3}
.summary{display:flex;gap:16px;margin:20px 0}
.summary div{background:#f8f9fa;padding:16px 20px;border-radius:8px;flex:1;text-align:center}
.summary .value{font-size:28px;font-weight:700;color:#2d3436}
.summary .label{font-size:11px;color:#636e72;margin-top:4px;text-transform:uppercase;letter-spacing:.5px}
.footer{margin-top:24px;padding-top:16px;border-top:1px solid #eee;color:#b2bec3;font-size:11px;text-align:center}
</style></head><body>
<div class="container">
<h1>{{framework_name}} Compliance Report</h1>
<div class="subtitle">Version {{framework_version}} &middot; Generated {{generated_at}} UTC &middot; Period: last {{period_hours}} hours</div>
<div class="summary">
<div><div class="value">{{coverage_pct}}%</div><div class="label">Coverage</div></div>
<div><div class="value">{{covered}}</div><div class="label">Covered</div></div>
<div><div class="value">{{not_mapped}}</div><div class="label">Not Mapped</div></div>
<div><div class="value">{{total}}</div><div class="label">Total Controls</div></div>
</div>
<table><tr><th>Control ID</th><th>Control Name</th><th>Status</th><th>Detection Rules</th><th>Events</th></tr>
{{controls_rows}}
</table>
<div class="footer">Generated by TinySocs &middot; tinysocs.local</div>
</div></body></html>"""


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main() -> None:
    available = list_frameworks()
    parser = argparse.ArgumentParser(description="TinySocs Compliance Report Generator")
    parser.add_argument(
        "--framework", required=True,
        help=f"Framework name: {', '.join(available) if available else 'nist_csf, hipaa, pci_dss'}",
    )
    parser.add_argument("--hours", type=int, default=720, help="Lookback window in hours (default: 720 = 30 days)")
    parser.add_argument("--output", default=None, help="Output HTML file path (default: stdout)")
    args = parser.parse_args()

    report = generate_compliance_report(args.framework, args.hours)
    html = render_html(report)

    if args.output:
        Path(args.output).write_text(html, encoding="utf-8")
        s = report["summary"]
        print(f"Report written to {args.output}")
        print(f"  Framework: {report['framework']['name']}")
        print(f"  Coverage: {s['coverage_pct']}% ({s['covered']}/{s['total_controls']} controls)")
    else:
        print(html)


if __name__ == "__main__":
    main()
