<#
.SYNOPSIS
  End-to-end verification for Phase 12: Operator Experience & Visibility.

.DESCRIPTION
  Runs on a fully installed TinySocs Windows host. Verifies:
    M0  Custom operator dashboard at localhost:8090/dashboard/ (API endpoints)
    M1  Notification config persisted in agent-config.yml
    M2  Action engine: stage -> approve -> status via Bot API
    M3  Daily summary: CLI generates HTML, scheduled task (if email configured)
    M4  Documentation files present

.EXAMPLE
  .\Test-Phase12.ps1
  .\Test-Phase12.ps1 -SiemUrl https://localhost:9201 -BotUrl http://localhost:8090
#>
[CmdletBinding()]
param(
  [string]$SiemUrl = "https://localhost:9201",
  [string]$BotUrl  = "http://localhost:8090",
  [string]$InstallDir = "$env:ProgramFiles\TinySocs"
)

$ErrorActionPreference = "Continue"
Set-StrictMode -Version Latest

# ── Helpers ──
$pass = 0; $fail = 0; $warn = 0
function Report([string]$label, [bool]$ok, [string]$detail = "") {
  if ($ok) {
    Write-Host "  [PASS] $label" -ForegroundColor Green
    $script:pass++
  } else {
    Write-Host "  [FAIL] $label  $detail" -ForegroundColor Red
    $script:fail++
  }
}
function Warn([string]$label, [string]$detail = "") {
  Write-Host "  [WARN] $label  $detail" -ForegroundColor Yellow
  $script:warn++
}

# ── TLS bypass ──
try {
  Add-Type @"
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
public class SSLBypass { public static void Ignore() { ServicePointManager.ServerCertificateValidationCallback = delegate { return true; }; } }
"@
} catch { <# Already loaded #> }
[SSLBypass]::Ignore()
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

# ── Locate assistant.env (ProgramData takes priority, then InstallDir) ──
$AssistantEnv = $null
$envCandidates = @(
  (Join-Path $env:ProgramData "TinySocs\Assistant\assistant.env"),
  (Join-Path $InstallDir "Assistant\assistant.env")
)
foreach ($c in $envCandidates) {
  if (Test-Path $c) { $AssistantEnv = $c; break }
}

# ── Parse assistant.env into a hashtable ──
$EnvVars = @{}
if ($AssistantEnv) {
  Get-Content $AssistantEnv | ForEach-Object {
    if ($_ -match '^\s*([A-Z_]+)\s*=\s*(.*)$') {
      $EnvVars[$Matches[1]] = $Matches[2].Trim('"', "'")
    }
  }
}

# ── Resolve SIEM creds ──
$SiemUser = "admin"
$SiemPass = ""
$modPath = Join-Path $InstallDir "modules\TinySocs.Installer.psm1"
if (Test-Path $modPath) {
  Import-Module $modPath -Force -ErrorAction SilentlyContinue
  if (Get-Command Get-TSSiemCredsCanonical -ErrorAction SilentlyContinue) {
    $creds = Get-TSSiemCredsCanonical
    if ($creds) { $SiemUser = $creds.User; $SiemPass = $creds.Pass }
  }
}
if (-not $SiemPass -and $EnvVars['SIEM_PASS']) {
  $SiemPass = $EnvVars['SIEM_PASS']
}
$authHeader = @{ Authorization = "Basic " + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${SiemUser}:${SiemPass}")) }

# ── Resolve BOT_SHARED_SECRET for HMAC ──
$BotSecret = $env:BOT_SHARED_SECRET
if (-not $BotSecret -and $EnvVars['BOT_SHARED_SECRET']) {
  $BotSecret = $EnvVars['BOT_SHARED_SECRET']
}

function Get-BotHeaders {
  $ts = [int](Get-Date -UFormat %s)
  $nonce = "ps-e2e-$(Get-Random)-$(Get-Random)"
  $msg = "$ts|$nonce"
  $hmac = New-Object System.Security.Cryptography.HMACSHA256
  $hmac.Key = [Text.Encoding]::UTF8.GetBytes($script:BotSecret)
  $sig = -join ($hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($msg)) | ForEach-Object { $_.ToString("x2") })
  return @{
    "X-TinySOCS-Timestamp" = "$ts"
    "X-TinySOCS-Nonce"     = $nonce
    "X-TinySOCS-Signature" = $sig
    "Content-Type"         = "application/json"
  }
}

Write-Host "`n===== Phase 12 End-to-End Verification =====`n" -ForegroundColor Cyan

# ─────────────────────────────────────────────────────────────────
# M0: Operator Dashboard (custom built-in dashboard at :8090)
# ─────────────────────────────────────────────────────────────────
Write-Host "── M0: Operator Dashboard ──" -ForegroundColor White

# Dashboard HTML page
try {
  $resp = Invoke-WebRequest "$BotUrl/dashboard/" -UseBasicParsing -TimeoutSec 10
  Report "Dashboard UI reachable ($BotUrl/dashboard/)" ($resp.StatusCode -eq 200)
  $html = $resp.Content
  Report "Dashboard has Alert Summary panel" ($html -match "ALERT SUMMARY|alert-summary|Alert Summary")
  Report "Dashboard has Alert Timeline panel" ($html -match "ALERT TIMELINE|alert-timeline|Alert Timeline")
  Report "Dashboard has Fleet Health panel" ($html -match "FLEET HEALTH|fleet-health|Fleet Health")
  Report "Dashboard has Event Explorer panel" ($html -match "EVENT EXPLORER|event-explorer|Event Explorer")
} catch {
  Report "Dashboard UI reachable" $false $_.Exception.Message
}

# Dashboard API endpoints
foreach ($ep in @(
  @{ Path = "/dashboard/api/alerts/summary"; Name = "Alerts Summary API" },
  @{ Path = "/dashboard/api/alerts/timeline"; Name = "Alerts Timeline API" },
  @{ Path = "/dashboard/api/fleet/health";   Name = "Fleet Health API" },
  @{ Path = "/dashboard/api/events/recent";  Name = "Recent Events API" },
  @{ Path = "/dashboard/api/actions";        Name = "Actions API" }
)) {
  try {
    $resp = Invoke-WebRequest "$BotUrl$($ep.Path)" -UseBasicParsing -TimeoutSec 10
    Report "$($ep.Name) responds" ($resp.StatusCode -eq 200)
  } catch {
    Report "$($ep.Name) responds" $false $_.Exception.Message
  }
}

# Dashboard NDJSON artefact exists in packaging
$ndjson = Join-Path (Split-Path $PSScriptRoot -Parent) "packaging\opensearch\dashboards\tinysocs-dashboards.ndjson"
if (Test-Path $ndjson) {
  $ndjsonSize = (Get-Item $ndjson).Length
  Report "Dashboard NDJSON artefact present" ($ndjsonSize -gt 1000) "$ndjsonSize bytes"
} else {
  Report "Dashboard NDJSON artefact present" $false "Not found at $ndjson"
}

# ─────────────────────────────────────────────────────────────────
# M1: Notification Config
# ─────────────────────────────────────────────────────────────────
Write-Host "`n── M1: Notification Configuration ──" -ForegroundColor White

$configPath = Join-Path $env:ProgramData "TinySocs\Collector\agent-config.yml"
if (-not (Test-Path $configPath)) {
  $configPath = Join-Path $env:ProgramData "TinySocs\Collector\agent\config.yml"
}

if (Test-Path $configPath) {
  $configText = Get-Content $configPath -Raw
  $hasWebhook = $configText -match "webhook_url"
  $hasSmtp    = $configText -match "smtp_host"
  if ($hasWebhook -or $hasSmtp) {
    Report "Notification config in agent-config.yml" $true "webhook=$hasWebhook, smtp=$hasSmtp"
  } else {
    Warn "Notification config in agent-config.yml" "No webhook or SMTP configured (ok if skipped during install)"
  }
} else {
  Warn "agent-config.yml exists" "Not found at expected paths"
}

# ─────────────────────────────────────────────────────────────────
# M2: Action Execution Engine
# ─────────────────────────────────────────────────────────────────
Write-Host "`n── M2: Action Execution Engine ──" -ForegroundColor White

if (-not $BotSecret) {
  Warn "Bot API HMAC" "BOT_SHARED_SECRET not found; skipping M2 API tests"
} else {
  Write-Host "  Using BOT_SHARED_SECRET from $(if ($env:BOT_SHARED_SECRET) {'env var'} else {'assistant.env'})" -ForegroundColor DarkGray

  # Stage an action
  try {
    $headers = Get-BotHeaders
    $body = '{"action":"block_ip","params":{"ip":"198.51.100.99"},"who":"phase12-test","dry_run":true}'
    $resp = Invoke-RestMethod "$BotUrl/bot/exec" -Method POST -Headers $headers -Body $body
    $actionId = $resp.action_id
    Report "Stage block_ip action" ($null -ne $actionId) "action_id=$actionId"

    # List actions
    $headers = Get-BotHeaders
    $resp2 = Invoke-RestMethod "$BotUrl/bot/actions" -Method GET -Headers $headers
    Report "List staged actions" ($resp2.count -gt 0) "count=$($resp2.count)"

    # Check status
    $headers = Get-BotHeaders
    $resp3 = Invoke-RestMethod "$BotUrl/bot/actions/$actionId/status" -Method GET -Headers $headers
    Report "Action status (staged)" ($resp3.status -eq "staged")

    # Approve
    $headers = Get-BotHeaders
    $approveBody = "{`"action_id`":`"$actionId`",`"approved_by`":`"e2e-test`"}"
    $resp4 = Invoke-RestMethod "$BotUrl/bot/approve" -Method POST -Headers $headers -Body $approveBody
    Report "Approve action (dry_run)" ($resp4.status -eq "completed" -and $resp4.dry_run -eq $true)
    Report "Dry run detail" ($resp4.result.detail -match "DRY RUN")

    # Final status
    $headers = Get-BotHeaders
    $resp5 = Invoke-RestMethod "$BotUrl/bot/actions/$actionId/status" -Method GET -Headers $headers
    Report "Final status (completed)" ($resp5.status -eq "completed")
    Report "Audit fields present" ($null -ne $resp5.approved_at -and $null -ne $resp5.completed_at)
  } catch {
    Report "Bot API action lifecycle" $false $_.Exception.Message
  }

  # Audit trail file
  $auditFile = Join-Path $env:ProgramData "TinySocs\audit\actions_audit.jsonl"
  if (Test-Path $auditFile) {
    $lines = Get-Content $auditFile
    Report "Audit trail file exists" $true "$($lines.Count) entries"
  } else {
    Warn "Audit trail file" "Not at $auditFile (may use different path)"
  }
}

# ─────────────────────────────────────────────────────────────────
# M3: Daily Summary Report
# ─────────────────────────────────────────────────────────────────
Write-Host "`n── M3: Daily Summary Report ──" -ForegroundColor White

# Check scheduled task
$task = Get-ScheduledTask -TaskName "TinySocs\DailySummary" -ErrorAction SilentlyContinue
if ($null -ne $task) {
  Report "Daily summary scheduled task registered" $true
  $trigger = $task.Triggers | Select-Object -First 1
  Report "Task trigger daily at 07:00" ($trigger.StartBoundary -match "07:00")
} else {
  # Task won't exist if email was not configured during install - correct behavior
  $hasEmail = $EnvVars['TINYSOCS_SMTP_HOST'] -or ($configPath -and (Test-Path $configPath) -and ((Get-Content $configPath -Raw) -match "email_to"))
  if ($hasEmail) {
    Report "Daily summary scheduled task registered" $false "Email configured but task missing"
  } else {
    Warn "Daily summary scheduled task" "Not registered (email was not configured during install - expected)"
  }
}

# CLI test: generate to stdout
try {
  $pythonCandidates = @(
    (Join-Path $InstallDir "Assistant\python.exe"),
    (Join-Path $InstallDir ".venv\Scripts\python.exe"),
    "python.exe"
  )
  $py = $null
  foreach ($c in $pythonCandidates) {
    if (Get-Command $c -ErrorAction SilentlyContinue) { $py = $c; break }
  }
  if ($py) {
    $html = & $py -m tinysocs.reporting.daily_summary --to test@localhost --stdout 2>&1
    $htmlStr = $html -join "`n"
    Report "CLI daily summary generates HTML" ($htmlStr -match "TinySocs Daily Summary")
    $isAllQuiet = $htmlStr -match "All Quiet"
    $hasAlerts  = $htmlStr -match "\d+ Alerts"
    Report "CLI output has content" ($isAllQuiet -or $hasAlerts) $(if ($isAllQuiet) {"All Quiet"} else {"Has alerts"})
  } else {
    Warn "Python not found" "Cannot test daily summary CLI"
  }
} catch {
  Report "CLI daily summary" $false $_.Exception.Message
}

# Module function exists
if (Get-Command Register-TinySocsDailySummaryTask -ErrorAction SilentlyContinue) {
  Report "Register-TinySocsDailySummaryTask function available" $true
} else {
  Report "Register-TinySocsDailySummaryTask function available" $false
}

# ─────────────────────────────────────────────────────────────────
# M4: Documentation
# ─────────────────────────────────────────────────────────────────
Write-Host "`n── M4: Documentation ──" -ForegroundColor White

$repoRoot = Split-Path $PSScriptRoot -Parent
foreach ($doc in @("docs\getting-started.md", "docs\operator-runbook.md", "docs\troubleshooting.md", "README.md")) {
  $p = Join-Path $repoRoot $doc
  $exists = Test-Path $p
  $size = if ($exists) { (Get-Item $p).Length } else { 0 }
  Report "$doc" ($exists -and $size -gt 200) "$('{0:N0}' -f $size) bytes"
}

# ─────────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────────
Write-Host "`n===== Results =====" -ForegroundColor Cyan
Write-Host "  PASS: $pass" -ForegroundColor Green
Write-Host "  FAIL: $fail" -ForegroundColor $(if ($fail -gt 0) {"Red"} else {"Green"})
Write-Host "  WARN: $warn" -ForegroundColor $(if ($warn -gt 0) {"Yellow"} else {"Green"})
Write-Host ""

if ($fail -gt 0) {
  Write-Host "Phase 12 verification: FAILED ($fail failures)" -ForegroundColor Red
  exit 1
} else {
  Write-Host "Phase 12 verification: PASSED" -ForegroundColor Green
  exit 0
}
