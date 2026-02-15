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
5. Configure notifications (optional):
   - **Webhook URL**: Paste a Slack/Teams webhook URL to get alert notifications
   - **Email**: Enter SMTP settings if you want email alerts
6. Click **Install** and wait for the post-install steps to complete (~2-3 minutes)

## Step 2: Verify Health

Open an **elevated PowerShell** prompt and run:

```powershell
Import-Module "$env:ProgramFiles\TinySocs\modules\TinySocs.Installer.psm1"
Test-TinySocsHealth
```

You should see **12/12 PASS**. If any checks fail, see the [Troubleshooting Guide](troubleshooting.md).

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

## Next Steps

- Read the [Operator Runbook](operator-runbook.md) for day-to-day operations
- Check [Troubleshooting](troubleshooting.md) if anything went wrong
- Review and customize detection rules in `C:\ProgramData\TinySocs\Collector\rules\rules.yml`
