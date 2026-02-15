<#
.SYNOPSIS
  End-to-end smoke test: generate events, trigger detections, verify dashboard.

.DESCRIPTION
  1. Diagnoses SIEM connectivity (OpenSearch + assistant.env)
  2. Generates real Windows events to trigger detection rules:
       - TS-001  brute_force_logon         (5 failed logons)
       - TS-001-lab                         (2 failed logons)
       - TS-010  local_account_created      (net user create/delete)
       - TS-020  scheduled_task_created     (schtasks create/delete)
       - TS-030-lab  powershell_scriptblock (3 ScriptBlock events)
  3. Waits for the agent pipeline to ingest and detect
  4. Queries the dashboard APIs to verify data appears

  Run from an elevated PowerShell session on the TinySocs VM.

.EXAMPLE
  .\Test-DashboardSmoke.ps1
  .\Test-DashboardSmoke.ps1 -WaitSeconds 60
#>
[CmdletBinding()]
param(
  [int]$WaitSeconds = 45,
  [string]$SiemUrl  = "https://localhost:9201",
  [string]$BotUrl   = "http://localhost:8090"
)

$ErrorActionPreference = "Continue"
Set-StrictMode -Version Latest

# ── TLS bypass for self-signed certs ──
Add-Type @"
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
public class SSLBypass {
    public static void Ignore() {
        ServicePointManager.ServerCertificateValidationCallback =
            delegate { return true; };
    }
}
"@
[SSLBypass]::Ignore()
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

# ── Resolve SIEM credentials ──
$SiemUser = "admin"
$SiemPass = ""

# Try Windows Credential Manager first (what the agent uses)
try {
  $modPath = "C:\Program Files\TinySocs\modules\TinySocs.Installer.psm1"
  if (Test-Path $modPath) {
    Import-Module $modPath -Force -ErrorAction SilentlyContinue
    if (Get-Command Get-TSSiemCredsCanonical -ErrorAction SilentlyContinue) {
      $creds = Get-TSSiemCredsCanonical
      if ($creds) { $SiemUser = $creds.User; $SiemPass = $creds.Pass }
    }
  }
} catch { }

# Fallback: try assistant.env file
if ([string]::IsNullOrWhiteSpace($SiemPass)) {
  $envFile = "C:\ProgramData\TinySocs\Assistant\assistant.env"
  if (Test-Path $envFile) {
    Get-Content $envFile | ForEach-Object {
      if ($_ -match '^SIEM_PASS=(.+)$') { $SiemPass = $Matches[1] }
      if ($_ -match '^SIEM_USER=(.+)$') { $SiemUser = $Matches[1] }
    }
  }
}

# Build auth header + test it; fall back to admin/admin if needed
function _BuildAuth([string]$u, [string]$p) {
  $b64 = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("${u}:${p}"))
  return @{ Authorization = "Basic $b64" }
}

function _TestAuth([string]$u, [string]$p) {
  try {
    $h = _BuildAuth $u $p
    Invoke-RestMethod -Uri "$SiemUrl/_cluster/health" -Headers $h -TimeoutSec 5 -ErrorAction Stop | Out-Null
    return $true
  } catch { return $false }
}

$authHeader = _BuildAuth $SiemUser $SiemPass
$authOk = _TestAuth $SiemUser $SiemPass

if (-not $authOk -and $SiemPass -ne "admin") {
  Write-Host "  [WARN] CredMan/env password failed; trying admin/admin (OpenSearch default)..." -ForegroundColor Yellow
  if (_TestAuth "admin" "admin") {
    $SiemUser = "admin"
    $SiemPass = "admin"
    $authHeader = _BuildAuth $SiemUser $SiemPass
    $authOk = $true
    Write-Host "  [OK] admin/admin works - OpenSearch used default bootstrap password" -ForegroundColor Green

    # Fix assistant.env so the dashboard also works
    $envFile = "C:\ProgramData\TinySocs\Assistant\assistant.env"
    if (Test-Path $envFile) {
      $envContent = Get-Content $envFile -Raw
      $envContent = $envContent -replace '(?m)^SIEM_PASS=.*$', "SIEM_PASS=$SiemPass"
      $envContent = $envContent -replace '(?m)^SIEM_USER=.*$', "SIEM_USER=$SiemUser"
      Set-Content -Path $envFile -Value $envContent -Force
      Write-Host "  [OK] Patched assistant.env with working credentials" -ForegroundColor Green
      Restart-Service TinySocsAssistant -ErrorAction SilentlyContinue
      Start-Sleep -Seconds 5
      Write-Host "  [OK] Restarted TinySocsAssistant" -ForegroundColor Green
    }
  }
}

if (-not $authOk) {
  Write-Host "  [FAIL] Cannot authenticate to OpenSearch with any known password!" -ForegroundColor Red
}

# Always ensure assistant.env matches the working credentials (dashboard uses this file)
if ($authOk) {
  $envFile = "C:\ProgramData\TinySocs\Assistant\assistant.env"
  if (Test-Path $envFile) {
    $envContent = Get-Content $envFile -Raw
    $needsPatch = $false
    if ($envContent -match '(?m)^SIEM_PASS=(.*)$') {
      $currentPass = $Matches[1].Trim()
      if ($currentPass -ne $SiemPass) { $needsPatch = $true }
    } else { $needsPatch = $true }

    if ($needsPatch) {
      Write-Host "  [WARN] assistant.env SIEM_PASS does not match working credentials - patching..." -ForegroundColor Yellow
      $envContent = $envContent -replace '(?m)^SIEM_PASS=.*$', "SIEM_PASS=$SiemPass"
      $envContent = $envContent -replace '(?m)^SIEM_USER=.*$', "SIEM_USER=$SiemUser"
      Set-Content -Path $envFile -Value $envContent -Force -NoNewline
      Write-Host "  [OK] Patched assistant.env with working SIEM credentials" -ForegroundColor Green
      Restart-Service TinySocsAssistant -ErrorAction SilentlyContinue
      Start-Sleep -Seconds 5
      Write-Host "  [OK] Restarted TinySocsAssistant to pick up new credentials" -ForegroundColor Green
    }
  }
}

# ── Helpers ──
function Write-Step($msg) {
  Write-Host "`n$msg" -ForegroundColor Cyan
}

function Write-OK($msg) {
  Write-Host "  [OK] $msg" -ForegroundColor Green
}

function Write-Fail($msg) {
  Write-Host "  [FAIL] $msg" -ForegroundColor Red
}

function Write-Info($msg) {
  Write-Host "  [INFO] $msg" -ForegroundColor Gray
}

function Invoke-SiemQuery {
  param([string]$Index, [hashtable]$Body, [int]$Size = 0)
  $Body["size"] = $Size
  $json = $Body | ConvertTo-Json -Depth 10
  try {
    $resp = Invoke-RestMethod -Uri "$SiemUrl/$Index/_search" `
      -Headers $authHeader -Method POST -ContentType "application/json" `
      -Body $json -TimeoutSec 10 -ErrorAction Stop
    # Invoke-RestMethod may return a string on some PS versions
    if ($resp -is [string]) { $resp = $resp | ConvertFrom-Json }
    return $resp
  } catch {
    Write-Fail "Query $Index failed: $($_.Exception.Message)"
    return $null
  }
}

function Get-EventCount {
  param([string]$Index = "tinysocs-winlog-*", [int]$MinutesAgo = 5)
  $body = @{ query = @{ range = @{ "@timestamp" = @{ gte = "now-${MinutesAgo}m" } } } }
  $r = Invoke-SiemQuery -Index $Index -Body $body
  if ($r) { return [int]($r.hits.total.value) }
  return -1
}

function Get-AlertCount {
  param([string]$RuleId = "", [int]$MinutesAgo = 10)
  $must = @( @{ range = @{ "@timestamp" = @{ gte = "now-${MinutesAgo}m" } } } )
  if ($RuleId) {
    $must += @{ term = @{ "alert.rule_id" = $RuleId } }
  }
  $body = @{ query = @{ bool = @{ must = $must } } }
  $r = Invoke-SiemQuery -Index "tinysocs-alerts-*" -Body $body
  if ($r) { return [int]($r.hits.total.value) }
  return -1
}

# ═══════════════════════════════════════════════════════════════
Write-Host "`n========================================" -ForegroundColor Yellow
Write-Host " TinySocs Dashboard Smoke Test" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Yellow

# ── Phase 1: Diagnose connectivity ──
Write-Step "Phase 1: Connectivity diagnostics"

# 1a. Check services
$services = @("TinySocsAgent", "TinySocsAssistant", "TinySocsOpenSearch")
foreach ($svc in $services) {
  $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
  if ($s -and $s.Status -eq "Running") { Write-OK "$svc is running" }
  else { Write-Fail "$svc is NOT running (status: $($s.Status))" }
}

# 1b. Check OpenSearch health
Write-Info "Testing OpenSearch at $SiemUrl..."
try {
  $health = Invoke-RestMethod -Uri "$SiemUrl/_cluster/health" `
    -Headers $authHeader -TimeoutSec 10 -ErrorAction Stop
  if ($health -is [string]) { $health = $health | ConvertFrom-Json }
  Write-OK "OpenSearch cluster: $($health.status) ($($health.number_of_nodes) node(s))"
} catch {
  Write-Fail "Cannot reach OpenSearch: $($_.Exception.Message)"
  if ($_.Exception.Message -match "401|403") {
    Write-Fail "Authentication failed! SIEM_PASS may be wrong."
    Write-Info "User: $SiemUser | Pass: $($SiemPass.Substring(0, [Math]::Min(3, $SiemPass.Length)))..."
  }
}

# 1c. Check assistant.env has SIEM_PASS
$envFile = "C:\ProgramData\TinySocs\Assistant\assistant.env"
if (Test-Path $envFile) {
  $envContent = Get-Content $envFile -Raw
  if ($envContent -match "SIEM_PASS=\S+") {
    Write-OK "assistant.env has SIEM_PASS populated"
  } else {
    Write-Fail "assistant.env has empty SIEM_PASS - dashboard will show 'SIEM not connected'!"
    Write-Info "Attempting to fix: copying SIEM_PASS from Credential Manager to assistant.env..."

    if (-not [string]::IsNullOrWhiteSpace($SiemPass)) {
      # Patch assistant.env with the SIEM password from credman
      $envContent = $envContent -replace 'SIEM_PASS=.*', "SIEM_PASS=$SiemPass"
      $envContent | Set-Content -Path $envFile -Force -NoNewline
      Write-OK "Patched assistant.env with SIEM_PASS from Credential Manager"

      # Restart assistant to pick up new env
      Write-Info "Restarting TinySocsAssistant to pick up new credentials..."
      Restart-Service TinySocsAssistant -ErrorAction SilentlyContinue
      Start-Sleep -Seconds 5
      Write-OK "TinySocsAssistant restarted"
    } else {
      Write-Fail "No SIEM password found in Credential Manager either!"
    }
  }
} else {
  Write-Fail "assistant.env not found at $envFile"
}

# 1d. Check dashboard responds
Write-Info "Testing dashboard at $BotUrl/dashboard/..."
try {
  $dashResp = Invoke-WebRequest -Uri "$BotUrl/dashboard/" -TimeoutSec 10 -UseBasicParsing -ErrorAction Stop
  if ($dashResp.StatusCode -eq 200) { Write-OK "Dashboard responds (HTTP 200)" }
  else { Write-Fail "Dashboard returned HTTP $($dashResp.StatusCode)" }
} catch {
  Write-Fail "Dashboard not reachable: $($_.Exception.Message)"
}

# 1e. Check dashboard API
try {
  $apiResp = Invoke-RestMethod -Uri "$BotUrl/dashboard/api/fleet/health" -TimeoutSec 10 -ErrorAction Stop
  if ($apiResp -is [string]) { $apiResp = $apiResp | ConvertFrom-Json }
  if ($apiResp.error) {
    Write-Fail "Dashboard API error: $($apiResp.error)"
  } else {
    Write-OK "Dashboard API working (fleet/health returned $($apiResp.hosts.Count) hosts)"
  }
} catch {
  Write-Fail "Dashboard API failed: $($_.Exception.Message)"
}

# 1f. Check detection engine prerequisites
$rulesFile = "C:\ProgramData\TinySocs\Collector\rules\rules.yml"
if (Test-Path $rulesFile) {
  Write-OK "Detection rules file exists: $rulesFile"
} else {
  Write-Fail "Detection rules file MISSING: $rulesFile"
  Write-Info "The C# detection engine needs this file to evaluate alerts."
  Write-Info "Copy from: packaging/detection/rules.yml"
}

# Check agent log for detection engine activity
$agentLog = "C:\ProgramData\TinySocs\Collector\logs\agent.log"
if (Test-Path $agentLog) {
  $logTail = Get-Content $agentLog -Tail 50
  $detLines = @($logTail | Where-Object { $_ -match "[Dd]etect|[Rr]ule|[Aa]lert" })
  if ($detLines.Count -gt 0) {
    Write-OK "Agent log has detection activity ($($detLines.Count) lines)"
    $detLines | Select-Object -Last 3 | ForEach-Object { Write-Info "  $_" }
  } else {
    Write-Info "No detection-related messages in agent log tail"
  }
} else {
  Write-Info "Agent log not found at $agentLog"
}

# 1g. Show existing data
$existingEvents = Get-EventCount -MinutesAgo 60
$existingAlerts = Get-AlertCount -MinutesAgo 60
Write-Info "Existing data (last 60m): $existingEvents events, $existingAlerts alerts"

# ═══════════════════════════════════════════════════════════════
Write-Step "Phase 2: Generating test events"

# Capture baseline
$baselineEvents = Get-EventCount -MinutesAgo 5
$baselineAlerts = Get-AlertCount -MinutesAgo 10
Write-Info "Baseline: $baselineEvents events, $baselineAlerts alerts"

# ── 2a. Failed logons (triggers TS-001 brute_force_logon, threshold=5) ──
Write-Step "  2a. Generating 7 failed logon attempts (triggers TS-001, TS-001-lab)"
for ($i = 1; $i -le 7; $i++) {
  & net use "\\localhost\C$" /user:fakeuser_dashtest wrongpass 2>$null | Out-Null
  Write-Host "    Failed logon $i/7" -ForegroundColor DarkGray
  Start-Sleep -Milliseconds 300
}
Write-OK "7 failed logon events generated (Event ID 4625)"

# ── 2b. Account creation (triggers TS-010 local_account_created) ──
Write-Step "  2b. Creating and deleting test user account (triggers TS-010)"
try {
  # Create a temporary local user — generates Event ID 4720
  & net user tinysocs_test_user "T3st!Pass#99" /add 2>$null | Out-Null
  Write-OK "Test user 'tinysocs_test_user' created (Event ID 4720)"
  Start-Sleep -Seconds 1
  # Clean up immediately
  & net user tinysocs_test_user /delete 2>$null | Out-Null
  Write-OK "Test user deleted (Event ID 4726)"
} catch {
  Write-Fail "Account creation failed: $($_.Exception.Message)"
  Write-Info "This test requires an elevated (Administrator) PowerShell session"
}

# ── 2c. Scheduled task creation (triggers TS-020 scheduled_task_created) ──
Write-Step "  2c. Creating and deleting test scheduled task (triggers TS-020)"
try {
  $taskName = "TinySocs_SmokeTest_$(Get-Date -Format 'HHmmss')"
  & schtasks /create /tn $taskName /tr "cmd.exe /c echo smoketest" `
    /sc once /st 23:59 /f 2>$null | Out-Null
  Write-OK "Scheduled task '$taskName' created (Event ID 4698)"
  Start-Sleep -Seconds 1
  & schtasks /delete /tn $taskName /f 2>$null | Out-Null
  Write-OK "Scheduled task deleted"
} catch {
  Write-Fail "Scheduled task creation failed: $($_.Exception.Message)"
}

# ── 2d. PowerShell ScriptBlock logging (triggers TS-030-lab) ──
Write-Step "  2d. Generating PowerShell ScriptBlock events (triggers TS-030-lab)"
# Running multiple script blocks produces Event ID 4104 in PowerShell/Operational
for ($i = 1; $i -le 5; $i++) {
  $sb = [ScriptBlock]::Create("Write-Output 'TinySocs-SmokeTest-ScriptBlock-$i'")
  & $sb | Out-Null
  Write-Host "    ScriptBlock event $i/5" -ForegroundColor DarkGray
}
# Also invoke via powershell.exe to ensure ScriptBlock logging triggers
& powershell.exe -NoProfile -Command "Write-Output 'TinySocs-SmokeTest-PS1'" 2>$null | Out-Null
& powershell.exe -NoProfile -Command "Write-Output 'TinySocs-SmokeTest-PS2'" 2>$null | Out-Null
& powershell.exe -NoProfile -Command "Write-Output 'TinySocs-SmokeTest-PS3'" 2>$null | Out-Null
Write-OK "PowerShell ScriptBlock events generated (Event ID 4104)"

# ── 2e. General activity for fleet health ──
Write-Step "  2e. Generating general Windows events for fleet health panel"
# Application log event
& eventcreate /ID 999 /L Application /T INFORMATION /SO TinySocsTest /D "Dashboard smoke test event" 2>$null | Out-Null
Write-OK "Application log event created (Event ID 999)"

# ═══════════════════════════════════════════════════════════════
Write-Step "Phase 3: Waiting for agent pipeline (${WaitSeconds}s)"
Write-Info "The agent collects events → queues → ships to OpenSearch → runs detections"
Write-Info "This typically takes 15-45 seconds depending on flush intervals."

$segments = [math]::Ceiling($WaitSeconds / 5)
for ($i = 1; $i -le $segments; $i++) {
  $elapsed = $i * 5
  $pct = [math]::Min(100, [math]::Round(($elapsed / $WaitSeconds) * 100))
  Write-Host "`r  Waiting... $elapsed/${WaitSeconds}s [$('=' * ($pct / 5))$(' ' * (20 - $pct / 5))] $pct%" -NoNewline -ForegroundColor Gray
  Start-Sleep -Seconds 5
}
Write-Host "`r  Done waiting!                                              " -ForegroundColor Gray

# ═══════════════════════════════════════════════════════════════
Write-Step "Phase 4: Verifying data in OpenSearch"

# 4a. Check events were ingested
$newEvents = Get-EventCount -MinutesAgo 5
Write-Info "Events (last 5m): $newEvents (was $baselineEvents)"
if ($newEvents -gt $baselineEvents) {
  Write-OK "New events ingested! ($($newEvents - $baselineEvents) new)"
} else {
  Write-Fail "No new events detected. Agent may not be shipping."
  # Check if agent is collecting
  $agentLog = "C:\ProgramData\TinySocs\Collector\logs\agent.log"
  if (Test-Path $agentLog) {
    Write-Info "Last 5 lines of agent log:"
    Get-Content $agentLog -Tail 5 | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
  }
}

# 4b. Check alerts fired
$newAlerts = Get-AlertCount -MinutesAgo 10
Write-Info "Alerts (last 10m): $newAlerts (was $baselineAlerts)"
if ($newAlerts -gt $baselineAlerts) {
  Write-OK "Detection rules fired! ($($newAlerts - $baselineAlerts) new alerts)"
} else {
  Write-Info "No new alerts yet. The detection engine may need more time."
  Write-Info "Rules use sliding windows - if the agent just started, it may not have enough events."
}

# 4c. Check specific rules
Write-Step "  Rule-level check:"
$ruleChecks = @(
  @{ Id = "TS-001";     Name = "brute_force_logon";       Expected = "5+ failed logons" },
  @{ Id = "TS-001-lab"; Name = "brute_force_logon_lab";   Expected = "2+ failed logons" },
  @{ Id = "TS-010";     Name = "local_account_created";   Expected = "account created" },
  @{ Id = "TS-020";     Name = "scheduled_task_created";  Expected = "schtask created" }
)
foreach ($rule in $ruleChecks) {
  $count = Get-AlertCount -RuleId $rule.Id -MinutesAgo 10
  if ($count -gt 0) {
    Write-OK "$($rule.Id) ($($rule.Name)): $count alert(s)"
  } else {
    Write-Info "$($rule.Id) ($($rule.Name)): 0 alerts (trigger: $($rule.Expected))"
  }
}

# ═══════════════════════════════════════════════════════════════
Write-Step "Phase 5: Verifying dashboard API responses"

# 5a. Alert summary
try {
  $summary = Invoke-RestMethod -Uri "$BotUrl/dashboard/api/alerts/summary?hours=1" -TimeoutSec 10
  if ($summary -is [string]) { $summary = $summary | ConvertFrom-Json }
  if ($summary.error) {
    Write-Fail "Alert summary: $($summary.error)"
  } else {
    Write-OK "Alert summary: $($summary.total) total alerts"
    if ($summary.top_rules) {
      foreach ($r in $summary.top_rules) {
        Write-Info "  Rule $($r.rule): $($r.count) fires"
      }
    }
    if ($summary.severity) {
      $sevStr = ($summary.severity.PSObject.Properties | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join ", "
      Write-Info "  Severity breakdown: $sevStr"
    }
  }
} catch {
  Write-Fail "Dashboard API /alerts/summary failed: $($_.Exception.Message)"
}

# 5b. Fleet health
try {
  $fleet = Invoke-RestMethod -Uri "$BotUrl/dashboard/api/fleet/health" -TimeoutSec 10
  if ($fleet -is [string]) { $fleet = $fleet | ConvertFrom-Json }
  if ($fleet.error) {
    Write-Fail "Fleet health: $($fleet.error)"
  } else {
    Write-OK "Fleet health: $($fleet.hosts.Count) host(s) reporting"
    foreach ($h in $fleet.hosts) {
      Write-Info "  $($h.hostname): $($h.event_count) events, last seen $($h.last_seen)"
    }
  }
} catch {
  Write-Fail "Dashboard API /fleet/health failed: $($_.Exception.Message)"
}

# 5c. Recent events
try {
  $events = Invoke-RestMethod -Uri "$BotUrl/dashboard/api/events/recent?limit=5" -TimeoutSec 10
  if ($events -is [string]) { $events = $events | ConvertFrom-Json }
  if ($events.error) {
    Write-Fail "Events API: $($events.error)"
  } else {
    Write-OK "Events API: $($events.total) recent events"
    foreach ($e in $events.events) {
      $ts = if ($e.timestamp) { $e.timestamp.Substring(11, 8) } else { "?" }
      Write-Info "  [$ts] $($e.channel) / $($e.event_id) on $($e.host)"
    }
  }
} catch {
  Write-Fail "Dashboard API /events/recent failed: $($_.Exception.Message)"
}

# 5d. Alert timeline
try {
  $tl = Invoke-RestMethod -Uri "$BotUrl/dashboard/api/alerts/timeline?hours=1" -TimeoutSec 10
  if ($tl -is [string]) { $tl = $tl | ConvertFrom-Json }
  if ($tl.error) {
    Write-Fail "Timeline: $($tl.error)"
  } else {
    $nonZero = @($tl.buckets | Where-Object { $_.count -gt 0 })
    Write-OK "Alert timeline: $($tl.buckets.Count) buckets, $($nonZero.Count) with data"
  }
} catch {
  Write-Fail "Dashboard API /alerts/timeline failed: $($_.Exception.Message)"
}

# ═══════════════════════════════════════════════════════════════
Write-Step "Phase 6: Summary"
Write-Host ""
Write-Host "  Events ingested:  $newEvents (was $baselineEvents)" -ForegroundColor White
Write-Host "  Alerts generated: $newAlerts (was $baselineAlerts)" -ForegroundColor White
Write-Host ""
if ($newEvents -gt $baselineEvents -and $newAlerts -gt $baselineAlerts) {
  Write-Host "  FULL PIPELINE WORKING!" -ForegroundColor Green
  Write-Host "  Events -> Agent -> OpenSearch -> Detection -> Alerts -> Dashboard" -ForegroundColor Green
} elseif ($newEvents -gt $baselineEvents) {
  Write-Host "  PARTIAL: Events ingested but no alerts yet." -ForegroundColor Yellow
  Write-Host "  The detection engine may need another cycle." -ForegroundColor Yellow
  Write-Host "  Re-run this script or wait 60s and check the dashboard." -ForegroundColor Yellow
} else {
  Write-Host "  ISSUE: No new events ingested." -ForegroundColor Red
  Write-Host "  Check the agent service and log:" -ForegroundColor Red
  Write-Host "    Get-Service TinySocsAgent" -ForegroundColor Gray
  Write-Host "    Get-Content 'C:\ProgramData\TinySocs\Collector\logs\agent.log' -Tail 20" -ForegroundColor Gray
}

Write-Host ""
Write-Host "  Dashboard: $BotUrl/dashboard/" -ForegroundColor Cyan
Write-Host "  (Refresh the browser to see updated data)" -ForegroundColor Gray
Write-Host ""
