# tinysocs/reporting/daily_summary.py
"""
Daily Summary Report Generator

Queries OpenSearch for last 24h of alerts and generates an HTML email digest.

Usage:
    python -m tinysocs.reporting.daily_summary --to admin@company.com

Or programmatically:
    from tinysocs.reporting.daily_summary import generate_summary, send_email
    html = generate_summary()
    send_email(html, to="admin@company.com")
"""

from __future__ import annotations

import argparse
import json
import os
import smtplib
import ssl
import sys
from datetime import datetime, timezone, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Env bootstrap: load assistant.env if SIEM creds missing
# ---------------------------------------------------------------------------
def _load_assistant_env() -> None:
    if os.getenv("SIEM_PASS"):
        return
    candidates = [
        Path(os.getenv("ProgramData", "C:\\ProgramData")) / "TinySocs" / "Assistant" / "assistant.env",
        Path(os.getenv("ProgramFiles", "C:\\Program Files")) / "TinySocs" / "Assistant" / "assistant.env",
    ]
    for p in candidates:
        if p.is_file():
            try:
                for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    k, _, v = line.partition("=")
                    k, v = k.strip(), v.strip().strip('"').strip("'")
                    if k and k not in os.environ:
                        os.environ[k] = v
            except Exception:
                pass
            break

_load_assistant_env()


# ---------------------------------------------------------------------------
# TLS CA cert resolution (matches dashboard.py logic)
# ---------------------------------------------------------------------------
_ca_pem_cache: Optional[str] = None


def _ensure_pem(cert_path: Path) -> str:
    """Return a PEM file path for the given cert. Converts DER->PEM if needed."""
    raw = cert_path.read_bytes()
    if raw[:27] == b"-----BEGIN CERTIFICATE-----":
        return str(cert_path)

    # DER-encoded: convert to PEM
    import base64, tempfile
    b64 = base64.encodebytes(raw).decode("ascii")
    pem = f"-----BEGIN CERTIFICATE-----\n{b64}-----END CERTIFICATE-----\n"
    pem_path = cert_path.parent / "ca-converted.pem"
    try:
        pem_path.write_text(pem, encoding="ascii")
        return str(pem_path)
    except Exception:
        fd, tmp = tempfile.mkstemp(suffix=".pem", prefix="tinysocs-ca-")
        os.write(fd, pem.encode("ascii"))
        os.close(fd)
        return tmp


def _resolve_ca_cert() -> Any:
    """Find the TinyBox CA certificate for OpenSearch TLS verification.

    Returns a path to a PEM file (str), True for system bundle, or False to skip.
    Converts DER-encoded certs to PEM automatically.
    """
    global _ca_pem_cache
    if _ca_pem_cache is not None:
        return _ca_pem_cache

    # 1. Explicit env override
    explicit = os.getenv("SIEM_CA_CERT", "")
    if explicit and Path(explicit).is_file():
        _ca_pem_cache = _ensure_pem(Path(explicit))
        return _ca_pem_cache

    verify_str = os.getenv("SIEM_SSL_VERIFY", "").lower()
    if verify_str in ("true", "1", "yes"):
        _ca_pem_cache = True  # type: ignore[assignment]
        return True

    # 2. Auto-discover TinyBox CA cert
    pd = os.getenv("ProgramData", "C:\\ProgramData")
    candidates = [
        Path(pd) / "TinySocs" / "OpenSearch" / "config" / "root-ca.pem",
        Path(pd) / "TinySocs" / "OpenSearch" / "config" / "certs" / "ca.pem",
        Path(pd) / "TinySocs" / "OpenSearch" / "config" / "certs" / "ca.cer",
    ]
    for cert_path in candidates:
        if not cert_path.is_file():
            continue
        _ca_pem_cache = _ensure_pem(cert_path)
        return _ca_pem_cache

    # 3. No cert found - disable verification with a warning
    _ca_pem_cache = False  # type: ignore[assignment]
    return False


# ---------------------------------------------------------------------------
# OpenSearch client (reuse existing adapter if available, else direct HTTP)
# ---------------------------------------------------------------------------
def _os_query(index: str, body: Dict[str, Any], size: int = 0) -> Dict[str, Any]:
    """Execute an OpenSearch query via requests (direct HTTP)."""
    import requests

    url = os.getenv("SIEM_URL", "https://localhost:9201")
    user = os.getenv("SIEM_USER", "admin")
    passwd = os.getenv("SIEM_PASS", "admin")
    verify = _resolve_ca_cert()

    body["size"] = size
    resp = requests.post(
        f"{url.rstrip('/')}/{index}/_search",
        json=body,
        auth=(user, passwd),
        verify=verify,
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()


# ---------------------------------------------------------------------------
# Data queries
# ---------------------------------------------------------------------------
def _alerts_by_severity(hours: int = 24) -> Dict[str, int]:
    """Count alerts by severity for the last N hours."""
    body = {
        "query": {"range": {"@timestamp": {"gte": f"now-{hours}h", "lte": "now"}}},
        "aggs": {
            "by_severity": {
                "terms": {"field": "severity.keyword", "size": 10}
            }
        },
    }
    try:
        resp = _os_query("tinysocs-alerts-*", body)
        buckets = resp.get("aggregations", {}).get("by_severity", {}).get("buckets", [])
        return {b["key"]: b["doc_count"] for b in buckets}
    except Exception:
        return {}


def _top_rules(hours: int = 24, top_n: int = 5) -> List[Tuple[str, int]]:
    """Top N rules that fired in the last N hours."""
    body = {
        "query": {"range": {"@timestamp": {"gte": f"now-{hours}h", "lte": "now"}}},
        "aggs": {
            "by_rule": {
                "terms": {"field": "rule_id.keyword", "size": top_n, "order": {"_count": "desc"}}
            }
        },
    }
    try:
        resp = _os_query("tinysocs-alerts-*", body)
        buckets = resp.get("aggregations", {}).get("by_rule", {}).get("buckets", [])
        return [(b["key"], b["doc_count"]) for b in buckets]
    except Exception:
        return []


def _top_hosts(hours: int = 24, top_n: int = 5) -> List[Tuple[str, int]]:
    """Top N hosts with alerts in the last N hours."""
    body = {
        "query": {"range": {"@timestamp": {"gte": f"now-{hours}h", "lte": "now"}}},
        "aggs": {
            "by_host": {
                "terms": {"field": "host.name.keyword", "size": top_n, "order": {"_count": "desc"}}
            }
        },
    }
    try:
        resp = _os_query("tinysocs-alerts-*", body)
        buckets = resp.get("aggregations", {}).get("by_host", {}).get("buckets", [])
        return [(b["key"], b["doc_count"]) for b in buckets]
    except Exception:
        return []


def _total_alerts(hours: int = 24) -> int:
    """Total alert count for the last N hours."""
    body = {
        "query": {"range": {"@timestamp": {"gte": f"now-{hours}h", "lte": "now"}}},
    }
    try:
        resp = _os_query("tinysocs-alerts-*", body)
        total = resp.get("hits", {}).get("total", {})
        if isinstance(total, dict):
            return total.get("value", 0)
        return int(total)
    except Exception:
        return 0


def _alert_trend() -> Tuple[int, int, str]:
    """Compare today's alerts vs yesterday. Returns (today, yesterday, arrow)."""
    today = _total_alerts(24)
    yesterday = _total_alerts(48) - today  # 48h total minus today's
    if yesterday < 0:
        yesterday = 0
    if today > yesterday:
        arrow = "up"
    elif today < yesterday:
        arrow = "down"
    else:
        arrow = "flat"
    return today, yesterday, arrow


def _new_hosts_seen(hours: int = 24) -> List[str]:
    """Hosts that appeared for the first time in the last N hours."""
    # First: get all hosts seen in the window
    body_recent = {
        "query": {"range": {"@timestamp": {"gte": f"now-{hours}h", "lte": "now"}}},
        "aggs": {
            "hosts": {"terms": {"field": "agent.hostname.keyword", "size": 100}}
        },
    }
    # Second: hosts seen before the window
    body_older = {
        "query": {"range": {"@timestamp": {"lt": f"now-{hours}h"}}},
        "aggs": {
            "hosts": {"terms": {"field": "agent.hostname.keyword", "size": 500}}
        },
    }
    try:
        recent = _os_query("tinysocs-winlog-*", body_recent)
        older = _os_query("tinysocs-winlog-*", body_older)
        recent_hosts = {b["key"] for b in recent.get("aggregations", {}).get("hosts", {}).get("buckets", [])}
        older_hosts = {b["key"] for b in older.get("aggregations", {}).get("hosts", {}).get("buckets", [])}
        return sorted(recent_hosts - older_hosts)
    except Exception:
        return []


def _host_count() -> int:
    """Total distinct hosts seen."""
    body = {
        "aggs": {"hosts": {"cardinality": {"field": "agent.hostname.keyword"}}},
        "query": {"match_all": {}},
    }
    try:
        resp = _os_query("tinysocs-winlog-*", body)
        return resp.get("aggregations", {}).get("hosts", {}).get("value", 0)
    except Exception:
        return 0


# ---------------------------------------------------------------------------
# HTML generation
# ---------------------------------------------------------------------------
def _load_template() -> str:
    """Load the HTML email template."""
    template_path = Path(__file__).parent / "templates" / "daily_summary.html"
    if template_path.exists():
        return template_path.read_text(encoding="utf-8")
    # Fallback inline template
    return _FALLBACK_TEMPLATE


_FALLBACK_TEMPLATE = """\
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>TinySocs Daily Summary</title>
</head>
<body style="margin:0;padding:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f4f4f4;">
<table width="100%" cellpadding="0" cellspacing="0" style="max-width:600px;margin:20px auto;background:#ffffff;border-radius:8px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.1);">
<tr><td style="background:#1a1a2e;color:#ffffff;padding:24px 32px;">
<h1 style="margin:0;font-size:22px;">TinySocs Daily Summary</h1>
<p style="margin:4px 0 0;font-size:13px;color:#a0a0c0;">{{date}} &middot; {{period}}</p>
</td></tr>
<tr><td style="padding:24px 32px;">
{{content}}
</td></tr>
<tr><td style="padding:16px 32px;background:#f8f8fa;font-size:12px;color:#888;">
Generated by TinySocs &middot; <a href="https://localhost:5602" style="color:#4a69bd;">Open Dashboards</a>
</td></tr>
</table>
</body>
</html>
"""


def _severity_color(sev: str) -> str:
    return {
        "critical": "#e74c3c",
        "high": "#e67e22",
        "medium": "#f39c12",
        "low": "#3498db",
        "info": "#95a5a6",
    }.get(sev.lower(), "#95a5a6")


def generate_summary(hours: int = 24) -> str:
    """Generate the daily summary HTML."""
    now = datetime.now(timezone.utc)
    period = f"Last {hours} hours"
    date_str = now.strftime("%A, %B %d, %Y")

    severity = _alerts_by_severity(hours)
    total = sum(severity.values())
    top_rules = _top_rules(hours)
    top_hosts = _top_hosts(hours)
    today_count, yesterday_count, trend = _alert_trend()
    new_hosts = _new_hosts_seen(hours)
    host_total = _host_count()

    parts: List[str] = []

    # Summary header
    if total == 0:
        parts.append('<div style="text-align:center;padding:20px 0;">')
        parts.append('<p style="font-size:48px;margin:0;">&#x2705;</p>')
        parts.append('<h2 style="color:#27ae60;margin:8px 0;">All Quiet</h2>')
        parts.append(f'<p style="color:#666;">No alerts in the last {hours} hours across {host_total} monitored hosts.</p>')
        parts.append('</div>')
    else:
        # Trend indicator
        trend_icon = {"up": "&#x1F4C8;", "down": "&#x1F4C9;", "flat": "&#x2796;"}.get(trend, "")
        trend_text = {"up": "up", "down": "down", "flat": "unchanged"}.get(trend, "")
        parts.append(f'<h2 style="margin:0 0 8px;font-size:18px;">{total} Alerts {trend_icon}</h2>')
        parts.append(f'<p style="color:#666;margin:0 0 16px;font-size:13px;">{trend_text} from yesterday ({yesterday_count})</p>')

        # Severity breakdown
        parts.append('<table width="100%" cellpadding="6" cellspacing="0" style="margin-bottom:16px;border:1px solid #eee;border-radius:4px;">')
        parts.append('<tr style="background:#f8f8fa;"><th align="left" style="font-size:13px;color:#666;">Severity</th><th align="right" style="font-size:13px;color:#666;">Count</th></tr>')
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = severity.get(sev, 0)
            if count > 0:
                color = _severity_color(sev)
                parts.append(f'<tr><td><span style="display:inline-block;width:10px;height:10px;background:{color};border-radius:50%;margin-right:6px;"></span>{sev.title()}</td><td align="right"><strong>{count}</strong></td></tr>')
        parts.append('</table>')

        # Top rules
        if top_rules:
            parts.append('<h3 style="font-size:15px;margin:16px 0 8px;">Top Rules</h3>')
            parts.append('<table width="100%" cellpadding="6" cellspacing="0" style="border:1px solid #eee;border-radius:4px;">')
            for rule, count in top_rules:
                parts.append(f'<tr><td style="font-family:monospace;font-size:13px;">{rule}</td><td align="right"><strong>{count}</strong></td></tr>')
            parts.append('</table>')

        # Top hosts
        if top_hosts:
            parts.append('<h3 style="font-size:15px;margin:16px 0 8px;">Top Hosts</h3>')
            parts.append('<table width="100%" cellpadding="6" cellspacing="0" style="border:1px solid #eee;border-radius:4px;">')
            for host, count in top_hosts:
                parts.append(f'<tr><td style="font-size:13px;">{host}</td><td align="right"><strong>{count}</strong></td></tr>')
            parts.append('</table>')

    # New hosts
    if new_hosts:
        parts.append(f'<h3 style="font-size:15px;margin:16px 0 8px;">New Hosts ({len(new_hosts)})</h3>')
        parts.append('<p style="font-size:13px;color:#666;">' + ', '.join(new_hosts) + '</p>')

    content = '\n'.join(parts)
    template = _load_template()
    html = template.replace("{{date}}", date_str).replace("{{period}}", period).replace("{{content}}", content)
    return html


# ---------------------------------------------------------------------------
# Email sending
# ---------------------------------------------------------------------------
def send_email(
    html: str,
    to: str,
    subject: Optional[str] = None,
    smtp_host: Optional[str] = None,
    smtp_port: Optional[int] = None,
    from_addr: Optional[str] = None,
) -> bool:
    """Send the summary email via SMTP."""
    smtp_host = smtp_host or os.getenv("TINYSOCS_SMTP_HOST", "")
    smtp_port = smtp_port or int(os.getenv("TINYSOCS_SMTP_PORT", "587"))
    from_addr = from_addr or os.getenv("TINYSOCS_EMAIL_FROM", "tinysocs@localhost")

    if not smtp_host:
        print("[daily_summary] No SMTP host configured; writing to stdout instead.")
        print(html)
        return False

    now = datetime.now(timezone.utc)
    if not subject:
        subject = f"[TinySocs] Daily Summary — {now.strftime('%Y-%m-%d')}"

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = to
    msg.attach(MIMEText(html, "html"))

    try:
        ctx = ssl.create_default_context()
        with smtplib.SMTP(smtp_host, smtp_port, timeout=30) as server:
            server.ehlo()
            server.starttls(context=ctx)
            server.ehlo()
            # If SMTP user/pass are set, authenticate
            smtp_user = os.getenv("TINYSOCS_SMTP_USER")
            smtp_pass = os.getenv("TINYSOCS_SMTP_PASS")
            if smtp_user and smtp_pass:
                server.login(smtp_user, smtp_pass)
            server.sendmail(from_addr, [to], msg.as_string())
        print(f"[daily_summary] Email sent to {to}")
        return True
    except Exception as exc:
        print(f"[daily_summary] Failed to send email: {exc}")
        return False


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(description="TinySocs Daily Summary Report")
    parser.add_argument("--to", required=True, help="Recipient email address")
    parser.add_argument("--hours", type=int, default=24, help="Lookback window in hours (default: 24)")
    parser.add_argument("--subject", default=None, help="Custom email subject")
    parser.add_argument("--smtp-host", default=None, help="SMTP server host")
    parser.add_argument("--smtp-port", type=int, default=None, help="SMTP server port")
    parser.add_argument("--from", dest="from_addr", default=None, help="From email address")
    parser.add_argument("--stdout", action="store_true", help="Print HTML to stdout instead of emailing")
    args = parser.parse_args()

    html = generate_summary(hours=args.hours)

    if args.stdout:
        print(html)
        return

    send_email(
        html=html,
        to=args.to,
        subject=args.subject,
        smtp_host=args.smtp_host,
        smtp_port=args.smtp_port,
        from_addr=args.from_addr,
    )


if __name__ == "__main__":
    main()
