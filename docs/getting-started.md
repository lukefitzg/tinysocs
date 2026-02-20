# Getting Started with TinySocs

This guide walks you through installing TinySocs and verifying a working system in under 15 minutes.

## Prerequisites

- **Windows Server 2016+** or **Windows 10/11 Pro** (64-bit)
- **4 GB RAM minimum** (8 GB recommended for TinyBox all-in-one mode)
- **PowerShell 5.1+** (PowerShell 7 recommended)
- **Administrator access**
- **.NET 8.0 Runtime** (bundled with agent)

## Step 1: Run the Installer

1. Download `TinySocs-Setup.exe` from the releases page
2. Right-click and **Run as Administrator**
3. Select the **TinyBox** role (all-in-one: agent + SIEM + dashboards)
4. Enter a shared secret (or let the installer generate one)
5. Set the **SIEM + Dashboard password** (or leave blank to auto-generate). This single password protects both the OpenSearch datastore and the TinySocs dashboard.
6. Configure notifications (optional):
   - **Webhook URL**: Paste a Slack/Teams webhook URL to get alert notifications
   - **Email**: Enter SMTP settings if you want email alerts
7. Click **Install** and wait for the post-install steps to complete (~2-3 minutes)

## Step 2: Verify Health

Open an **elevated PowerShell** prompt and run:

```powershell
Import-Module "$env:ProgramFiles\TinySocs\modules\TinySocs.Installer.psm1"
Test-TinySocsHealth
```

You should see **14/14 PASS**. If any checks fail, see the [Troubleshooting Guide](troubleshooting.md).

> **New in v0.8.0 (Phase 13)**: Health checks now include webhook delivery (#13) and email SMTP connectivity (#14).

## Step 3: Open Dashboards

Open a browser and navigate to:

```
https://localhost:5602
```

Log in with the SIEM credentials you configured during install (default user: `admin`).

You should see 4 pre-built dashboards:
- **Alert Timeline** — Bar chart of alerts over time by severity
- **Detection Rules** — Table of active rules with fire counts
- **Fleet Health** — Agent heartbeat status and event throughput
- **Event Explorer** — Browse raw Windows events

## Step 4: Trigger a Test Alert

Generate some failed login attempts to trigger the brute-force detection rule:

```powershell
# This creates failed logon events (Event ID 4625)
1..6 | ForEach-Object {
    $cred = New-Object PSCredential("fakeuser", (ConvertTo-SecureString "wrong" -AsPlainText -Force))
    try { Start-Process cmd.exe -Credential $cred -ErrorAction SilentlyContinue } catch {}
}

# Wait for the detection cycle
Start-Sleep -Seconds 30
```

## Step 5: Verify Alert Delivery

Check that alerts appeared:

```powershell
# Check alert log
Get-Content "C:\ProgramData\TinySocs\Collector\logs\alerts.log" -Tail 10

# Check the Alert Timeline dashboard in the browser
Start-Process "https://localhost:5602"
```

If you configured a webhook, you should see a notification in your Slack/Teams channel.

## Step 6: Review the LLM Assistant (Optional)

If you installed with an API key (Anthropic or OpenAI), the assistant service analyzes alerts automatically:

```powershell
# Check assistant status
Get-Service TinySocsAssistant

# View staged actions
curl http://localhost:8090/bot/actions
```

## Step 7: Generate a Daily Summary (Optional)

```powershell
python -m tinysocs.reporting.daily_summary --to admin@localhost --stdout
```

### Post-Install Smoke Test (Optional)

Run a full end-to-end smoke test that verifies the detection pipeline is working:

```powershell
Import-Module "$env:ProgramFiles\TinySocs\modules\TinySocs.Installer.psm1"
Invoke-TinySocsSmokeTest
```

This generates test events, waits for the detection engine to process them, and checks that alerts appear in the `tinysocs-alerts-*` index.

## Next Steps

- Read the [Operator Runbook](operator-runbook.md) for day-to-day operations
- Check [Troubleshooting](troubleshooting.md) if anything went wrong
- Review the [Detection Coverage Matrix](detection-coverage.md) for rule details and MITRE ATT&CK mapping
- Review and customize detection rules in `C:\ProgramData\TinySocs\Collector\rules\rules.yml`
- Review the JSON schemas in the `schema/` directory for event and alert document formats
