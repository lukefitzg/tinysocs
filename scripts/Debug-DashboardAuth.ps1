<#
.SYNOPSIS
  Diagnose why the dashboard gets "SIEM authentication failed".
  Tests every credential source against OpenSearch directly.
#>
$ErrorActionPreference = "Continue"

Add-Type @"
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
public class SSLBypass2 {
    public static void Ignore() {
        ServicePointManager.ServerCertificateValidationCallback =
            delegate { return true; };
    }
}
"@
[SSLBypass2]::Ignore()
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

$SiemUrl = "https://localhost:9201"

function Test-Creds([string]$Label, [string]$User, [string]$Pass) {
  $masked = if ($Pass.Length -gt 4) { $Pass.Substring(0,4) + "..." } else { "****" }
  Write-Host "  Testing $Label (user=$User, pass=$masked) ... " -NoNewline
  try {
    $b64 = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("${User}:${Pass}"))
    $h = @{ Authorization = "Basic $b64" }
    $r = Invoke-RestMethod -Uri "$SiemUrl/_cluster/health" -Headers $h -TimeoutSec 5 -ErrorAction Stop
    Write-Host "OK (cluster=$($r.status))" -ForegroundColor Green
    return $true
  } catch {
    $code = ""
    if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
    Write-Host "FAILED ($code $($_.Exception.Message))" -ForegroundColor Red
    return $false
  }
}

Write-Host "`n=== Dashboard Auth Diagnostics ===" -ForegroundColor Cyan

# 1. CredMan
Write-Host "`n[1] Credential Manager:" -ForegroundColor Yellow
try {
  Import-Module "C:\Program Files\TinySocs\modules\TinySocs.Installer.psm1" -Force -ErrorAction SilentlyContinue 3>$null
  $creds = Get-TSSiemCredsCanonical
  if ($creds) {
    Write-Host "  Found: user=$($creds.User)" -ForegroundColor Gray
    Test-Creds "CredMan" $creds.User $creds.Pass | Out-Null
  } else {
    Write-Host "  No credentials in CredMan" -ForegroundColor Gray
  }
} catch {
  Write-Host "  Error reading CredMan: $($_.Exception.Message)" -ForegroundColor Red
}

# 2. assistant.env
Write-Host "`n[2] assistant.env:" -ForegroundColor Yellow
$envFile = "C:\ProgramData\TinySocs\Assistant\assistant.env"
if (Test-Path $envFile) {
  $envUser = ""; $envPass = ""; $envUrl = ""
  Get-Content $envFile | ForEach-Object {
    if ($_ -match '^SIEM_USER=(.*)$') { $envUser = $Matches[1].Trim() }
    if ($_ -match '^SIEM_PASS=(.*)$') { $envPass = $Matches[1].Trim() }
    if ($_ -match '^SIEM_URL=(.*)$')  { $envUrl  = $Matches[1].Trim() }
  }
  Write-Host "  SIEM_URL=$envUrl" -ForegroundColor Gray
  Write-Host "  SIEM_USER=$envUser" -ForegroundColor Gray
  Write-Host "  SIEM_PASS length=$($envPass.Length) chars" -ForegroundColor Gray
  if ($envPass.Length -gt 0) {
    Test-Creds "assistant.env" $envUser $envPass | Out-Null
  } else {
    Write-Host "  SIEM_PASS is EMPTY!" -ForegroundColor Red
  }
} else {
  Write-Host "  File not found: $envFile" -ForegroundColor Red
}

# 3. Default admin/admin
Write-Host "`n[3] Default admin/admin:" -ForegroundColor Yellow
Test-Creds "admin/admin" "admin" "admin" | Out-Null

# 4. Dashboard API test
Write-Host "`n[4] Dashboard API (what the browser sees):" -ForegroundColor Yellow
try {
  $r = Invoke-RestMethod -Uri "http://localhost:8090/dashboard/api/fleet/health" -TimeoutSec 10 -ErrorAction Stop
  if ($r -is [string]) { $r = $r | ConvertFrom-Json }
  if ($r.error) {
    Write-Host "  API returned error: $($r.error)" -ForegroundColor Red
  } else {
    Write-Host "  API working: $($r.hosts.Count) hosts" -ForegroundColor Green
  }
} catch {
  Write-Host "  API failed: $($_.Exception.Message)" -ForegroundColor Red
}

# 5. Check assistant service env
Write-Host "`n[5] TinySocsAssistant service status:" -ForegroundColor Yellow
$svc = Get-Service TinySocsAssistant -ErrorAction SilentlyContinue
if ($svc) {
  Write-Host "  Status: $($svc.Status)" -ForegroundColor Gray
  $pid = (Get-WmiObject Win32_Service -Filter "Name='TinySocsAssistant'" -ErrorAction SilentlyContinue).ProcessId
  if ($pid -and $pid -ne 0) {
    Write-Host "  PID: $pid" -ForegroundColor Gray
    # Check what env the process sees
    Write-Host "  Checking assistant process environment..." -ForegroundColor Gray
    try {
      $proc = Get-Process -Id $pid -ErrorAction SilentlyContinue
      if ($proc) { Write-Host "  Process: $($proc.ProcessName) (started $($proc.StartTime))" -ForegroundColor Gray }
    } catch { }
  } else {
    Write-Host "  PID: not running" -ForegroundColor Red
  }
}

# 6. Check service env file location
Write-Host "`n[6] Environment file the assistant loads:" -ForegroundColor Yellow
$svcKey = "HKLM:\SYSTEM\CurrentControlSet\Services\TinySocsAssistant"
if (Test-Path $svcKey) {
  $imgPath = (Get-ItemProperty $svcKey -Name ImagePath -ErrorAction SilentlyContinue).ImagePath
  Write-Host "  ImagePath: $imgPath" -ForegroundColor Gray
}
# Check if assistant loads .env from a different path
$assistantDir = "C:\Program Files\TinySocs\Assistant"
if (Test-Path $assistantDir) {
  $localEnv = Join-Path $assistantDir ".env"
  $localEnv2 = Join-Path $assistantDir "assistant.env"
  if (Test-Path $localEnv) { Write-Host "  Found: $localEnv" -ForegroundColor Yellow }
  if (Test-Path $localEnv2) { Write-Host "  Found: $localEnv2" -ForegroundColor Yellow }
}
$pdAssistant = "C:\ProgramData\TinySocs\Assistant"
if (Test-Path $pdAssistant) {
  Write-Host "  Contents of $pdAssistant :" -ForegroundColor Gray
  Get-ChildItem $pdAssistant | ForEach-Object { Write-Host "    $($_.Name) ($($_.Length) bytes)" -ForegroundColor Gray }
}

Write-Host "`n=== Done ===" -ForegroundColor Cyan
Write-Host ""
