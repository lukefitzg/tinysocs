# TinySocs Pilot Deployment Guide

This guide walks through deploying TinySocs for a pilot evaluation. By the end you will have a working SIEM with endpoint detection, an AI assistant, and compliance reporting.

## Prerequisites

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| OS | Windows 10 / Server 2019 | Windows 11 / Server 2022 |
| RAM | 8 GB | 16 GB |
| Disk | 20 GB free | 50 GB free |
| CPU | 2 cores | 4 cores |
| .NET | 8.0 Runtime | Included in installer |
| Network | Localhost only | LAN for multi-endpoint |
| LLM API Key | One of: Anthropic, OpenAI, or Ollama | Anthropic (Claude) |

## 15-Minute Install

1. **Download** `TinySocs-Setup.exe` from the releases page.
2. **Run as Administrator** and select the **TinyBox** role (all-in-one).
3. **Secrets page**: Enter your LLM API key and choose a dashboard password.
4. **Notifications page** (optional): Configure a Slack/Teams webhook URL for alerts.
5. **Dashboard Access page**: Choose "Localhost only" (recommended) or "Network accessible" (generates TLS certs).
6. **Sysmon page**: Leave "Install Sysmon" checked for enhanced detection (recommended).
7. Click **Install** and wait for completion (~3 minutes).

### Verify Installation

Open an elevated PowerShell and run:

```powershell
Import-Module "C:\Program Files\TinySocs\modules\TinySocs.Installer.psm1"
Test-TinySocsHealth
```

Expect **16/16 PASS**. Key checks: OpenSearch running, Agent connected, Dashboard accessible, Sysmon active.

### Access the Dashboard

Open a browser to:
- **Localhost**: `http://localhost:8090`
- **Network mode**: `https://<machine-ip>:8090` (accept the self-signed certificate warning)

Log in with the dashboard password you set during install.

## First 24 Hours

After installation, TinySocs immediately begins collecting Windows events and running detection rules.

**What to expect:**
- Windows Security events (logon, process creation, privilege use) appear within minutes
- Sysmon events (process creation with command lines, network connections, file changes) appear if Sysmon was installed
- Detection rules start evaluating events on each agent cycle (default: 60 seconds)
- The AI assistant is ready to answer questions about your security posture

**Things to check:**
- Dashboard shows event counts increasing in the Alert Timeline
- Fleet Health shows your endpoint(s) as connected
- Try asking the assistant: "What events have been collected in the last hour?"

## Week 1 Checklist

- [ ] Verify all endpoints are reporting (Fleet Health card)
- [ ] Review any fired detections and triage them
- [ ] Test the AI assistant with sample questions
- [ ] Configure email notifications if not done during install
- [ ] Generate a compliance report: Dashboard > Compliance Coverage section
- [ ] Run the daily summary manually: `python -m tinysocs.reporting.daily_summary`
- [ ] Familiarise yourself with the Event Explorer for ad-hoc queries
- [ ] Review the [Operator Runbook](operator-runbook.md) for ongoing operations

## Adding More Endpoints

To monitor additional machines, deploy the TinySocs Agent:

1. Copy the agent installer or use the same `TinySocs-Setup.exe` with the **Agent** role
2. Configure `agent-config.yml` to point to the TinyBox machine's OpenSearch URL
3. Verify with `Test-TinySocsHealth` on the new endpoint

## Compliance Reporting

TinySocs maps its detection rules to three compliance frameworks:

- **NIST CSF 2.0** — 17 controls mapped
- **HIPAA Security Rule** — 11 controls mapped
- **PCI DSS v4.0** — 12 controls mapped

Generate a report from the Dashboard (Compliance Coverage card) or CLI:

```powershell
python -m tinysocs.reporting.compliance_report --framework nist_csf --hours 720 --output report.html
```

## Feedback

We value your feedback during the pilot. Key areas to evaluate:

1. **Detection accuracy** — Are rules firing on real threats? Any false positives?
2. **AI assistant quality** — Are recommendations helpful and actionable?
3. **Dashboard usability** — Is the interface intuitive?
4. **Performance impact** — Any noticeable CPU/memory impact on endpoints?
5. **Installation experience** — Was setup smooth?

## Uninstall

If you need to remove TinySocs:

1. Open **Add/Remove Programs** > TinySocs > Uninstall
2. Choose whether to keep data (`C:\ProgramData\TinySocs`) or remove everything
3. Sysmon is automatically removed during full uninstall

For manual removal, see the [Troubleshooting Guide](troubleshooting.md).
