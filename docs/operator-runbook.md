# TinySocs Operator Runbook

Day-to-day operations reference for TinySocs operators.

## Health Checks

### Quick Health Check

```powershell
Import-Module "$env:ProgramFiles\TinySocs\modules\TinySocs.Installer.psm1"
Test-TinySocsHealth
```

Expected: **14/14 PASS**. Any FAIL or WARN items need investigation.

> Checks 13 and 14 (webhook delivery, SMTP EHLO) are only exercised if notifications are configured.

### Service Status

```powershell
Get-Service TinySocs* | Format-Table Name, Status, StartType
```

Key services:
- **TinySocsAgent** — Windows event collector
- **TinySocsOpenSearch** — Local SIEM datastore
- **TinySocsAssistant** — LLM analysis service (optional)

### OpenSearch Cluster Health

```powershell
curl.exe -k -u admin:PASSWORD https://localhost:9201/_cluster/health?pretty
```

## Notifications

### Configure Webhook

Edit `C:\ProgramData\TinySocs\Collector\agent-config.yml`:

```yaml
detection:
  notification:
    webhook_url: "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
```

Restart the agent after changes:

```powershell
Restart-Service TinySocsAgent
```

### Configure Email Alerts

In the same config file:

```yaml
detection:
  notification:
    email:
      smtp_host: "smtp.company.com"
      smtp_port: 587
      from: "tinysocs@company.com"
      to: "secops@company.com"
```

### Test Webhook

From the TinySocs dashboard Settings page, use the **Test Webhook** button.

Or via PowerShell:

```powershell
# Quick test with curl
curl.exe -X POST "https://hooks.slack.com/services/YOUR/WEBHOOK/URL" `
  -H "Content-Type: application/json" `
  -d '{"text":"[TinySocs] Test notification"}'
```

### Notification Retry Queue

Failed webhook and email notifications are automatically queued for retry in:

```
C:\ProgramData\TinySocs\Collector\notification_queue.jsonl
```

The retry queue uses exponential backoff (default: 3 attempts, 30s base backoff). Entries older than 1 hour are discarded. Configure in `agent-config.yml`:

```yaml
detection:
  notification:
    retry:
      max_attempts: 3
      backoff_seconds: 30
      max_age_seconds: 3600
```

## Dashboards

Access at `https://localhost:5602`.

### Available Dashboards

| Dashboard | Purpose |
|-----------|---------|
| Alert Timeline | Alerts over time by severity, filterable by rule/host |
| Detection Rules | Active rules with fire counts (24h/7d) |
| Fleet Health | Agent heartbeat status and event throughput |
| Event Explorer | Browse raw tinysocs-winlog-* events |

### Re-import Dashboards

If dashboards are missing after an upgrade:

```powershell
Import-Module "$env:ProgramFiles\TinySocs\modules\TinySocs.Installer.psm1"
Import-TinySocsDashboards `
  -DashboardsUrl "https://localhost:5602" `
  -NdjsonPath "$env:ProgramFiles\TinySocs\OpenSearch\dashboards\tinysocs-dashboards.ndjson" `
  -SiemUser admin `
  -SiemPass YOUR_PASSWORD
```

## Detection Rules

### View Active Rules

Rules are in `C:\ProgramData\TinySocs\Collector\rules\rules.yml`.

```powershell
Get-Content "C:\ProgramData\TinySocs\Collector\rules\rules.yml"
```

### Add a Custom Rule

Add to `rules.yml`:

```yaml
- id: my_custom_rule
  description: "Custom detection for suspicious activity"
  index: "tinysocs-winlog-*"
  time_field: "@timestamp"
  kql: "winlog.event_id:4688 AND process.name:powershell.exe"
  threshold: 10
  group_by: ["host.name"]
  severity: medium
  category: execution
```

Rules reload automatically (default: every 60 seconds).

## Action Management

### View Staged Actions

Actions recommended by the LLM assistant are staged for review:

```powershell
# Via API (requires HMAC auth)
curl http://localhost:8090/bot/actions

# Check the actions queue file
Get-Content "C:\ProgramData\TinySocs\queue\actions_queue.jsonl" -Tail 20
```

### Approve an Action

```powershell
# Approve a staged action for execution
curl -X POST http://localhost:8090/bot/approve `
  -H "Content-Type: application/json" `
  -d '{"action_id":"abc123","approved_by":"operator"}'
```

### Action Types

| Action | Effect | Reversible? |
|--------|--------|-------------|
| `block_ip` | Creates Windows Firewall deny rules for the IP | Yes (delete rules) |
| `disable_user` | Disables Windows local account | Yes (`net user X /active:yes`) |
| `isolate_host` | Blocks all outbound except SIEM | Yes (delete rules) |

### Audit Trail

All actions are logged to:

```
C:\ProgramData\TinySocs\audit\actions_audit.jsonl
```

Each entry includes timestamp, who approved, what was done, and the result.

## Daily Summary Reports

### On-Demand Report

```powershell
python -m tinysocs.reporting.daily_summary --to admin@company.com
```

Or print to stdout:

```powershell
python -m tinysocs.reporting.daily_summary --to admin@company.com --stdout
```

### Scheduled Reports

Register a daily task (runs at 07:00):

```powershell
Import-Module "$env:ProgramFiles\TinySocs\modules\TinySocs.Installer.psm1"
Register-TinySocsDailySummaryTask -To "secops@company.com"
```

Verify the task:

```powershell
Get-ScheduledTask -TaskName "TinySocs\DailySummary"
```

## LLM API Keys

### Set Anthropic Key

Edit `C:\ProgramData\TinySocs\Assistant\assistant.env`:

```
LLM_MODE=claude
ANTHROPIC_API_KEY=sk-ant-...
```

### Set OpenAI Key

```
LLM_MODE=openai
OPENAI_API_KEY=sk-...
```

### Use Local Ollama

```
LLM_MODE=ollama
OLLAMA_URL=http://localhost:11434
OLLAMA_MODEL=llama3
```

Restart the assistant service after changes:

```powershell
Restart-Service TinySocsAssistant
```

## Log Locations

| Log | Path |
|-----|------|
| Agent output | `C:\ProgramData\TinySocs\Collector\logs\TinySocsAgent.out.log` |
| Agent errors | `C:\ProgramData\TinySocs\Collector\logs\TinySocsAgent.err.log` |
| Alert log | `C:\ProgramData\TinySocs\Collector\logs\alerts.log` |
| Assistant log | `C:\ProgramData\TinySocs\Assistant\logs\` |
| OpenSearch logs | `C:\ProgramData\TinySocs\OpenSearch\logs\` |
| Notification retry | `C:\ProgramData\TinySocs\Collector\notification_queue.jsonl` |
| Installer log | `C:\ProgramData\TinySocs\logs\postinstall-powershell*.log` |
| Uninstall log | `%TEMP%\tinysocs-uninstall.log` |
| Action audit | `C:\ProgramData\TinySocs\audit\actions_audit.jsonl` |

## Upgrading

### In-Place Upgrade

Run the new `TinySocs-Setup.exe` over the existing installation. The installer will:

1. **Detect** the existing version and log it
2. **Back up** `agent-config.yml`, `assistant.env`, and `rules.yml` to `.pre-upgrade.bak` files
3. **Stop** non-OpenSearch services before file replacement
4. **Deploy** new binaries and modules (configs use `onlyifdoesntexist` to preserve edits)
5. **Verify** config backups — if the installer accidentally overwrote a config, the backup is restored
6. **Restart** services and run the full post-install chain

After upgrade, verify:

```powershell
Import-Module "$env:ProgramFiles\TinySocs\modules\TinySocs.Installer.psm1"
Test-TinySocsHealth
```

### Smoke Test After Upgrade

```powershell
Invoke-TinySocsSmokeTest
```

This generates test events and verifies alerts appear in the index.

## Data Retention

Default ISM policies:
- **winlog-retention**: 30 days
- **alerts-retention**: 90 days

To adjust, modify the ISM policies in OpenSearch Dashboards under **Index Management > Policies**.
