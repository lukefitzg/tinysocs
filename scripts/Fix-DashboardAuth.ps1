<#
.SYNOPSIS
  Fixes the dashboard "SIEM authentication failed" error by syncing
  the NSSM service environment with the correct SIEM password.

.DESCRIPTION
  The TinySocsAssistant runs via NSSM, which bakes AppEnvironmentExtra
  into the registry at install time. Editing assistant.env alone does
  NOT update what NSSM passes to the process. This script:
    1. Finds the working OpenSearch password (CredMan, env, or admin/admin)
    2. Updates assistant.env
    3. Updates NSSM AppEnvironmentExtra in the registry
    4. Restarts the assistant service

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File Fix-DashboardAuth.ps1
#>
$ErrorActionPreference = "Continue"

Add-Type @"
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
public class TLS {
    public static void Trust() {
        ServicePointManager.ServerCertificateValidationCallback =
            delegate { return true; };
    }
}
"@
[TLS]::Trust()
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

$SiemUrl = "https://localhost:9201"
$nssm = "C:\Program Files\TinySocs\bin\nssm.exe"

function Test-Auth([string]$u, [string]$p) {
  try {
    $b64 = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("${u}:${p}"))
    Invoke-RestMethod -Uri "$SiemUrl/_cluster/health" `
      -Headers @{ Authorization = "Basic $b64" } -TimeoutSec 5 -ErrorAction Stop | Out-Null
    return $true
  } catch { return $false }
}

Write-Host "`n=== Fix Dashboard Auth ===" -ForegroundColor Cyan

# Step 1: Find working password
$workUser = ""; $workPass = ""

# Try CredMan
try {
  Import-Module "C:\Program Files\TinySocs\modules\TinySocs.Installer.psm1" -Force -ErrorAction SilentlyContinue 3>$null
  $creds = Get-TSSiemCredsCanonical
  if ($creds -and (Test-Auth $creds.User $creds.Pass)) {
    $workUser = $creds.User; $workPass = $creds.Pass
    Write-Host "  Working creds: CredMan ($workUser)" -ForegroundColor Green
  }
} catch { }

# Try admin/admin
if (-not $workPass) {
  if (Test-Auth "admin" "admin") {
    $workUser = "admin"; $workPass = "admin"
    Write-Host "  Working creds: admin/admin (default)" -ForegroundColor Green
  }
}

if (-not $workPass) {
  Write-Host "  [FAIL] No working credentials found!" -ForegroundColor Red
  exit 1
}

# Step 2: Update assistant.env
$envFile = "C:\ProgramData\TinySocs\Assistant\assistant.env"
if (Test-Path $envFile) {
  $content = Get-Content $envFile -Raw
  $content = $content -replace '(?m)^SIEM_USER=.*$', "SIEM_USER=$workUser"
  $content = $content -replace '(?m)^SIEM_PASS=.*$', "SIEM_PASS=$workPass"
  Set-Content -Path $envFile -Value $content -Force -NoNewline
  Write-Host "  Updated assistant.env" -ForegroundColor Green
} else {
  Write-Host "  [WARN] assistant.env not found at $envFile" -ForegroundColor Yellow
}

# Step 3: Update NSSM AppEnvironmentExtra from the updated assistant.env
if (Test-Path $nssm) {
  $envExtras = @()
  if (Test-Path $envFile) {
    foreach ($line in (Get-Content $envFile)) {
      $trimmed = $line.Trim()
      if ($trimmed -and -not $trimmed.StartsWith("#") -and $trimmed -match "^[A-Z_]+=") {
        $envExtras += $trimmed
      }
    }
  }

  if ($envExtras.Count -gt 0) {
    # NSSM AppEnvironmentExtra is a REG_MULTI_SZ - each line is a separate string
    # nssm set expects them as a single argument with newlines
    $svcName = "TinySocsAssistant"

    # Stop service first
    Write-Host "  Stopping $svcName..." -ForegroundColor Gray
    & $nssm stop $svcName 2>$null | Out-Null
    Start-Sleep -Seconds 2

    # Write each env var via nssm set (reset then append)
    # NSSM set AppEnvironmentExtra accepts multiple values separated by newlines
    $joined = $envExtras -join "`n"
    & $nssm set $svcName AppEnvironmentExtra $joined 2>$null | Out-Null
    Write-Host "  Updated NSSM AppEnvironmentExtra ($($envExtras.Count) vars)" -ForegroundColor Green

    # Start service
    & $nssm start $svcName 2>$null | Out-Null
    Write-Host "  Started $svcName" -ForegroundColor Green
    Start-Sleep -Seconds 5
  }
} else {
  # Fallback: just restart the service
  Restart-Service TinySocsAssistant -ErrorAction SilentlyContinue
  Start-Sleep -Seconds 5
}

# Step 4: Verify
Write-Host "`n  Verifying dashboard API..." -ForegroundColor Gray
try {
  $r = Invoke-RestMethod -Uri "http://localhost:8090/dashboard/api/fleet/health" -TimeoutSec 10
  if ($r -is [string]) { $r = $r | ConvertFrom-Json }
  if ($r.error) {
    Write-Host "  [FAIL] Dashboard API: $($r.error)" -ForegroundColor Red
    Write-Host "  The assistant may still be starting up. Wait 10s and try:" -ForegroundColor Yellow
    Write-Host '  Invoke-RestMethod "http://localhost:8090/dashboard/api/fleet/health"' -ForegroundColor Gray
  } else {
    Write-Host "  [OK] Dashboard API working! ($($r.hosts.Count) hosts)" -ForegroundColor Green
  }
} catch {
  Write-Host "  [FAIL] Dashboard API: $($_.Exception.Message)" -ForegroundColor Red
  Write-Host "  The assistant may still be starting up." -ForegroundColor Yellow
}

Write-Host "`n=== Done ===" -ForegroundColor Cyan
Write-Host ""
