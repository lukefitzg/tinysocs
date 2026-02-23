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

### 11. Dashboard login fails ("Password not set")

**Symptom**: The TinySocs dashboard (`http://localhost:8090/dashboard/`) shows a "Set up password" prompt instead of the login form.

**Cause**: `SIEM_PASS` environment variable is not set or is empty.

**Fix**: Check `assistant.env` has a SIEM_PASS value:

```powershell
Select-String "SIEM_PASS" "C:\ProgramData\TinySocs\Assistant\assistant.env"
```

If it's empty, set it to the same password used for OpenSearch:

```powershell
# Find the working password from CredMan
Import-Module "$env:ProgramFiles\TinySocs\modules\TinySocs.Installer.psm1"
$creds = Get-TSSiemCredsCanonical
$creds.Pass  # This is the current working password
```

### 12. Webhook notifications stuck in retry queue

**Symptom**: Webhook messages appear in `notification_queue.jsonl` but are never delivered.

**Cause**: The webhook URL is unreachable or returning non-2xx status codes.

**Fix**:
1. Test the URL manually: `curl.exe -X POST "YOUR_URL" -H "Content-Type: application/json" -d '{"text":"test"}'`
2. Check firewall/proxy allows outbound HTTPS to the webhook host
3. Clear the retry queue if entries are stale: `Remove-Item "C:\ProgramData\TinySocs\Collector\notification_queue.jsonl"`

### 13. Upgrade clobbered my config

**Symptom**: After an upgrade, `agent-config.yml` or `assistant.env` was reset to defaults.

**Fix**: The installer creates `.pre-upgrade.bak` backups before deployment. Restore them:

```powershell
$pd = "C:\ProgramData\TinySocs"
Copy-Item "$pd\Collector\agent-config.yml.pre-upgrade.bak" "$pd\Collector\agent-config.yml" -Force
Copy-Item "$pd\Assistant\assistant.env.pre-upgrade.bak" "$pd\Assistant\assistant.env" -Force
Restart-Service TinySocsAgent, TinySocsAssistant
```

### 14. Dashboard certificate errors (HTTPS mode)

**Symptom**: Browser shows "connection refused" or "certificate invalid" when accessing `https://<ip>:8090`.

**Checklist**:
1. Verify cert files exist: `Test-Path "C:\ProgramData\TinySocs\Assistant\certs\dashboard-cert.pem"`
2. Check `assistant.env` has `DASHBOARD_TLS_CERT` and `DASHBOARD_TLS_KEY` set
3. Verify `DASHBOARD_BIND=0.0.0.0` for network access

**Fix**: Regenerate certificates:

```powershell
Import-Module "$env:ProgramFiles\TinySocs\modules\TinySocs.Installer.psm1"
New-TinySocsDashboardCert
```

### 15. Sysmon conflicts with existing installation

**Symptom**: Sysmon install fails or events are not captured.

**Checklist**:
1. Check if another Sysmon version is already installed: `Get-Service Sysmon64`
2. Check for conflicting Sysmon configs: `Sysmon64.exe -c`

**Fix**: Update the existing Sysmon with TinySocs config:

```powershell
Import-Module "$env:ProgramFiles\TinySocs\modules\TinySocs.Installer.psm1"
Install-TinySocsSysmon  # Updates config on existing Sysmon installs
```

### 16. Rate limiting lockout on dashboard

**Symptom**: Dashboard login returns HTTP 429 "Too many login attempts".

**Cause**: 5+ failed login attempts within 60 seconds from the same IP.

**Fix**: Wait 60 seconds for the rate limit window to expire, then try again with the correct password. The rate limit is in-memory and resets when the assistant service restarts.

### 17. Compliance report shows empty data

**Symptom**: Compliance report shows 0% coverage and no rule fire counts.

**Checklist**:
1. Verify OpenSearch is running and accessible
2. Check that alerts exist: `curl.exe -k -u admin:PASSWORD "https://localhost:9201/tinysocs-alerts-*/_count"`
3. Try a shorter time window or ensure the lookback period covers when alerts occurred

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

## Phase 15 Issues

### Threat intelligence enrichment shows "unconfigured"

**Symptom**: Threat badges don't appear on alerts; Settings shows all providers as unconfigured.

**Fix**: Add API keys in the dashboard Settings > Threat Intelligence section, or directly in `assistant.env`:

```
ABUSEIPDB_API_KEY=your_key_here
OTX_API_KEY=your_key_here
GREYNOISE_API_KEY=your_key_here
```

Restart the assistant service after editing `assistant.env`.

### FIM not generating alerts

**Symptom**: File Integrity Monitoring rules (TS-110 through TS-115) never fire.

**Fix**:
1. Verify FIM input is enabled in `agent-config.yml`:
   ```yaml
   inputs:
     - type: fim
       fim:
         paths:
           - C:\Windows\System32\drivers\etc\hosts
           - C:\Windows\System32\config\SAM
   ```
2. Check `C:\ProgramData\TinySocs\Agent\fim-baseline.json` exists (created on first run)
3. Restart the agent: `Restart-Service TinySocsAgent`

### MITRE coverage widget shows 0 techniques

**Symptom**: MITRE ATT&CK Coverage card shows 0 techniques and 0 tactics.

**Fix**: This means rules files could not be loaded. Check:
1. `packaging/detection/rules.yml` exists and has `mitre:` annotations
2. `src/tinysocs/agent/detections/rules.yaml` exists with `mitre:` fields
3. Run `python -m tinysocs.reporting.mitre_coverage` to verify locally

### Agent version drift banner keeps appearing

**Symptom**: Orange "Agent version drift detected" banner persists despite agents being current.

**Fix**: Update `config/version-manifest.json` with the correct `current_version` and `minimum_compatible` values matching your deployed agent versions.

## Getting Help

If none of the above resolves your issue:

1. Check all logs listed in the [Operator Runbook](operator-runbook.md#log-locations)
2. Run `Test-TinySocsHealth` and note which checks fail
3. Open an issue at the project repository with:
   - Health check output
   - Relevant log excerpts
   - Windows version and PowerShell version (`$PSVersionTable`)
