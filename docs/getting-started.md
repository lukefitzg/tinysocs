# Getting Started with TinySocs

This guide walks you through installing TinySocs and verifying a working system in under 15 minutes.

## Prerequisites

- **Windows Server 2016+** or **Windows 10/11 Pro** (64-bit)
- **8 GB RAM minimum** (16 GB recommended for TinyBox all-in-one mode)
- **PowerShell 5.1+** (PowerShell 7 recommended)
- **Administrator access**
- **.NET 8.0 Runtime** (bundled with agent)
- **20 GB free disk space** (50 GB recommended)

## Step 1: Run the Installer

1. Download `TinySocs-Setup.exe` from the releases page
2. Right-click and **Run as Administrator**
3. Select the **Hub** role — the default; all-in-one: agent + SIEM + dashboards. (The **Site** role is only for multi-node federation, which is experimental — skip it on a first install.)
4. Enter a shared secret (or let the installer generate one)
5. Set the **SIEM + Dashboard password** (or leave blank to auto-generate). This single password protects both the OpenSearch datastore and the TinySocs dashboard.
6. Configure notifications (optional):
   - **Webhook URL**: Paste a Slack/Teams webhook URL to get alert notifications
   - **Email**: Enter SMTP settings if you want email alerts
7. **Dashboard Access**: Choose "Localhost only" (default, HTTP) or "Network accessible" (auto-generates TLS certificates for HTTPS)
8. **Enhanced Detection**: Leave "Install Sysmon" checked for detailed endpoint telemetry (recommended)
9. Click **Install** and wait for the post-install steps to complete (~3 minutes)

## Step 2: Verify Health

Open an **elevated PowerShell** prompt and run:

```powershell
Import-Module "$env:ProgramFiles\TinySocs\modules\TinySocs.Installer.psm1"
Test-TinySocsHealth
```

Every check should report PASS, INFO, or WARN — **FAIL means something is actually broken** (see the [Troubleshooting Guide](troubleshooting.md)). On a minimal install some INFO/WARN results are structural and expected: the webhook and SMTP checks are skipped unless notifications are configured, the Sysmon check reports INFO if you declined Sysmon, and the TLS check only validates certificates in network mode. A localhost-only install with no notifications will not show a perfect scoreboard, and that's fine.

> **New in Phase 14**: Health checks now include Sysmon service status (#15) and Dashboard TLS configuration (#16).

## Step 3: Open Dashboards

Open a browser and navigate to the TinySocs operator dashboard:

- **Localhost mode**: `http://localhost:8090`
- **Network mode**: `https://<machine-ip>:8090` (accept the self-signed certificate warning)

Log in with the dashboard password you set during install.

The dashboard includes:
- **Alert Summary** — Severity breakdown and timeline
- **Fired Detections** — Detection alerts with threat intelligence enrichment
- **Fleet Health** — Agent heartbeat status, event throughput, and version drift alerts
- **Event Explorer** — Browse raw Windows events with KQL queries
- **Alert Rules** — Manage detection rules, create custom rules
- **Compliance Coverage** — NIST CSF, HIPAA, PCI DSS compliance reports
- **MITRE ATT&CK Coverage** — Tactic heatmap with Navigator layer export
- **AI Assistant** — Ask questions about your security posture in plain English

All dashboard cards are collapsible — click the chevron or heading to collapse/expand. State persists across sessions.

> **New in Phase 15**: Threat intelligence enrichment (AbuseIPDB, OTX, GreyNoise), File Integrity Monitoring, MITRE ATT&CK coverage widget, agent version awareness, and 19 Atomic Red Team test mappings.

You can also access OpenSearch Dashboards directly at `https://localhost:5602`.

## Step 4: Trigger a Test Alert

The easiest way is the built-in smoke test, which generates test events, waits for the
detection cycle, and confirms an alert landed:

```powershell
Import-Module "$env:ProgramFiles\TinySocs\modules\TinySocs.Installer.psm1"
Invoke-TinySocsSmokeTest
```

To trigger it manually instead, generate failed login attempts for a fake user. The
brute-force rule (TS-001) fires at **15 failed logons for the same user within 5 minutes**,
so run at least 20:

```powershell
# This creates failed logon events (Event ID 4625) for a user that doesn't exist
$cred = New-Object PSCredential("tinysocs_testuser", (ConvertTo-SecureString "wrong" -AsPlainText -Force))
1..20 | ForEach-Object {
    try { Start-Process cmd.exe -ArgumentList "/c exit" -Credential $cred -WindowStyle Hidden -ErrorAction Stop } catch {}
}

# Wait for the detection cycle
Start-Sleep -Seconds 30
```

## Step 5: See the Alert in the Dashboard

Open the TinySocs dashboard (`http://localhost:8090` — it redirects to `/dashboard`), go to
the **Detections** tab, and you should see a high-severity alert: **brute_force_logon
(TS-001)** for user `tinysocs_testuser`. It can take up to a minute after the events are
generated.

If you configured a webhook, the same alert appears in your Slack/Teams channel; if you
configured email, check the inbox.

This is a real alert from the real detection pipeline — acknowledge or dismiss it from the
Detections tab once you've seen it, the same way you would triage a live one.

If nothing appears after two minutes, check the agent service is running
(`Get-Service TinySocsAgent`) and see [Troubleshooting](troubleshooting.md).

## Step 6: Review the LLM Assistant (Optional)

If you installed with an API key (Anthropic or OpenAI), the assistant service analyzes alerts automatically:

```powershell
# Check assistant status
Get-Service TinySocsAssistant

# View staged actions
curl http://localhost:8090/bot/actions
```

## Step 7: Generate a Daily Summary (Optional)

This step needs a Python dev environment (`pip install -e .` from a repo checkout) —
the Windows installer does not create one. Skip it unless you're running from source.

```powershell
python -m tinysocs.reporting.daily_summary --to admin@localhost --stdout
```

## Next Steps

- Read the [Operator Runbook](operator-runbook.md) for day-to-day operations
- Check [Troubleshooting](troubleshooting.md) if anything went wrong
- Review the [Detection Coverage Matrix](detection-coverage.md) for rule details and MITRE ATT&CK mapping
- Generate a Compliance Report (NIST CSF, HIPAA, or PCI DSS) from the dashboard's Compliance tab
- Review and customize detection rules in `C:\ProgramData\TinySocs\Collector\rules\rules.yml` — they're yours to edit
- Review the JSON schemas in the `schema/` directory for event and alert document formats
- See the [FAQ](faq.md) for common questions and [KNOWN-LIMITATIONS.md](../KNOWN-LIMITATIONS.md) for the honest rough-edges list
