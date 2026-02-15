# TinySocs Troubleshooting Guide

Common issues encountered during installation and operation, with fixes.

## Installation Issues

### 1. OpenSearch fails to start (service stuck in "Starting")

**Symptom**: `TinySocsOpenSearch` service never reaches Running state.

**Causes & Fixes**:
- **Java heap too large**: Reduce `OPENSEARCH_JAVA_OPTS` in the service environment. Default is `-Xms2g -Xmx2g`; try `-Xms1g -Xmx1g` on machines with <8 GB RAM.
- **Port conflict**: Check if port 9201 is already in use: `netstat -ano | findstr :9201`
- **Disk full**: OpenSearch needs free disk space. Check `C:\ProgramData\TinySocs\OpenSearch\data`.

```powershell
# Check service status and recent events
Get-Service TinySocsOpenSearch
Get-WinEvent -LogName System -MaxEvents 20 | Where-Object { $_.Message -match 'OpenSearch' }
```

### 2. "Security not initialized" (503 errors)

**Symptom**: OpenSearch responds with 503 and "OpenSearch Security not initialized".

**Fix**: Run the security initialization manually:

```powershell
Import-Module "$env:ProgramFiles\TinySocs\modules\TinySocs.Installer.psm1"
Initialize-TinySocsOpenSearchSecurity -SiemUrl https://127.0.0.1:9201 -AdminUser admin -AdminPass YOUR_PASSWORD -SkipTlsVerify
```

### 3. TLS certificate errors / "admin-keystore.p12 not found"

**Symptom**: Installer fails at TB-10 with certificate errors.

**Fix**: Repair the keystore:

```powershell
Import-Module "$env:ProgramFiles\TinySocs\modules\TinySocs.Installer.psm1"
Repair-TinySocsOpenSearchTlsKeystore `
  -OpenSearchRoot "$env:ProgramFiles\TinySocs\OpenSearch" `
  -ProgramDataConf "$env:ProgramData\TinySocs\OpenSearch\config" `
  -CertsDir "$env:ProgramData\TinySocs\OpenSearch\config\certs"
```

### 4. Installer hangs at "Waiting for OpenSearch"

**Symptom**: Post-install takes >5 minutes at the persistence/readiness gate step.

**Cause**: OpenSearch is slow to start, or the port binding failed.

**Fix**: Check the log at `C:\ProgramData\TinySocs\logs\postinstall-powershell*.log` for the exact error. Common causes:
- Another OpenSearch process on the same port
- Antivirus blocking Java
- Insufficient memory

### 5. Authentication failure (401) after install

**Symptom**: All API calls return 401 Unauthorized.

**Fix**: The installer probes multiple credential combinations. Check which credentials actually work:

```powershell
# Test with curl
curl.exe -k -u admin:YOUR_PASSWORD https://localhost:9201/_plugins/_security/authinfo
```

If the default password changed, update credentials:

```powershell
Import-Module "$env:ProgramFiles\TinySocs\modules\TinySocs.Installer.psm1"
Set-TinySocsSiemCredential -SiemUrl https://localhost:9201 -SiemUser admin -SiemPass CORRECT_PASSWORD
```

## Runtime Issues

### 6. No alerts appearing

**Symptom**: Detection engine runs but no alerts in the dashboard.

**Checklist**:
1. Verify the agent is running: `Get-Service TinySocsAgent`
2. Check events are being indexed: `curl.exe -k -u admin:PASSWORD "https://localhost:9201/tinysocs-winlog-*/_count"`
3. Verify rules file exists: `Test-Path "C:\ProgramData\TinySocs\Collector\rules\rules.yml"`
4. Check agent logs: `Get-Content "C:\ProgramData\TinySocs\Collector\logs\TinySocsAgent.out.log" -Tail 50`

### 7. Webhook notifications not firing

**Symptom**: Alerts are created but no webhook POST is sent.

**Checklist**:
1. Verify `webhook_url` is set in `agent-config.yml`
2. Test the URL manually with curl
3. Check firewall rules allow outbound HTTPS
4. Check agent logs for webhook errors

### 8. Assistant service won't start

**Symptom**: `TinySocsAssistant` service fails to start.

**Causes**:
- Missing API key in `assistant.env`
- Python dependencies not found (PyInstaller bundle issue)
- Port 8081 or 8090 already in use

**Fix**:

```powershell
# Check the service log
Get-Content "C:\ProgramData\TinySocs\Assistant\logs\*" -Tail 50

# Verify the assistant.env has required keys
Get-Content "C:\ProgramData\TinySocs\Assistant\assistant.env"

# Check port availability
netstat -ano | findstr ":8081 :8090"
```

### 9. Dashboard import fails

**Symptom**: Dashboards don't appear in OpenSearch Dashboards.

**Fix**: Re-import manually:

```powershell
Import-Module "$env:ProgramFiles\TinySocs\modules\TinySocs.Installer.psm1"
Import-TinySocsDashboards `
  -DashboardsUrl "https://localhost:5602" `
  -NdjsonPath "$env:ProgramFiles\TinySocs\OpenSearch\dashboards\tinysocs-dashboards.ndjson" `
  -SiemUser admin `
  -SiemPass YOUR_PASSWORD
```

If OpenSearch Dashboards is still initializing, wait a minute and retry.

### 10. Daily summary email not sending

**Symptom**: Scheduled task runs but no email arrives.

**Checklist**:
1. Verify SMTP settings: `Get-ScheduledTask -TaskName "TinySocs\DailySummary" | Get-ScheduledTaskInfo`
2. Test manually: `python -m tinysocs.reporting.daily_summary --to your@email.com --stdout`
3. Check environment variables are set (TINYSOCS_SMTP_HOST, SIEM_URL, etc.)
4. Test SMTP connectivity: `Test-NetConnection smtp.company.com -Port 587`

## Performance Issues

### OpenSearch using too much memory

Reduce the heap size in the service environment:

```powershell
$svcKey = "HKLM:\SYSTEM\CurrentControlSet\Services\TinySocsOpenSearch"
# View current environment
(Get-ItemProperty -Path $svcKey -Name Environment).Environment
```

### Agent consuming high CPU

Check if the detection rules are too broad:
1. Review `rules.yml` for rules without `threshold` (these scan all matching events)
2. Increase `reload_interval_seconds` in `agent-config.yml`
3. Reduce event channel verbosity (e.g., set Application to `warning` instead of `information`)

## Getting Help

If none of the above resolves your issue:

1. Check all logs listed in the [Operator Runbook](operator-runbook.md#log-locations)
2. Run `Test-TinySocsHealth` and note which checks fail
3. Open an issue at the project repository with:
   - Health check output
   - Relevant log excerpts
   - Windows version and PowerShell version (`$PSVersionTable`)
