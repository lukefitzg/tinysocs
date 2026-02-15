<#
.SYNOPSIS
  Show actual alert document structure and alerts.log content.
#>
$ErrorActionPreference = "Continue"

Add-Type @"
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
public class TLS4 {
    public static void Ignore() {
        ServicePointManager.ServerCertificateValidationCallback =
            delegate { return true; };
    }
}
"@
[TLS4]::Ignore()
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

$SiemUrl = "https://localhost:9201"
try {
  Import-Module "C:\Program Files\TinySocs\modules\TinySocs.Installer.psm1" -Force -ErrorAction SilentlyContinue 3>$null
  $creds = Get-TSSiemCredsCanonical; $User = $creds.User; $Pass = $creds.Pass
} catch { $User = "admin"; $Pass = "admin" }
$b64 = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("${User}:${Pass}"))
$auth = @{ Authorization = "Basic $b64" }

Write-Host "`n=== Alert Document Analysis ===" -ForegroundColor Cyan

# 1. Show raw alert documents
Write-Host "`n[1] Raw alert documents (newest 3):" -ForegroundColor Yellow
try {
  $body = @{
    size = 3
    sort = @(@{ "_id" = @{ order = "desc" } })
    query = @{ match_all = @{} }
  } | ConvertTo-Json -Depth 10
  $r = Invoke-RestMethod -Uri "$SiemUrl/tinysocs-alerts-*/_search" `
    -Headers $auth -Method POST -ContentType "application/json" `
    -Body $body -TimeoutSec 10 -ErrorAction Stop
  if ($r -is [string]) { $r = $r | ConvertFrom-Json }
  Write-Host "  Total hits: $($r.hits.total.value)" -ForegroundColor Green
  foreach ($hit in $r.hits.hits) {
    Write-Host "`n  --- Alert ID: $($hit._id) ---" -ForegroundColor Cyan
    $json = $hit._source | ConvertTo-Json -Depth 5
    $json -split "`n" | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
  }
} catch {
  Write-Host "  Failed: $($_.Exception.Message)" -ForegroundColor Red
}

# 2. Show index mapping
Write-Host "`n[2] Alert index mapping:" -ForegroundColor Yellow
try {
  $r = Invoke-RestMethod -Uri "$SiemUrl/tinysocs-alerts-2026.02.14/_mapping" `
    -Headers $auth -TimeoutSec 5 -ErrorAction Stop
  if ($r -is [string]) { $r = $r | ConvertFrom-Json }
  $json = $r | ConvertTo-Json -Depth 6
  $json -split "`n" | Select-Object -First 60 | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
} catch {
  Write-Host "  Failed: $($_.Exception.Message)" -ForegroundColor Red
}

# 3. Show alerts.log content
Write-Host "`n[3] alerts.log content:" -ForegroundColor Yellow
$alertsLog = "C:\ProgramData\TinySocs\Collector\logs\alerts.log"
if (Test-Path $alertsLog) {
  Get-Content $alertsLog -Tail 20 | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
} else {
  Write-Host "  Not found" -ForegroundColor Red
}

# 4. Show one raw winlog event (4625 via event.code)
Write-Host "`n[4] Raw winlog event (event.code:4625):" -ForegroundColor Yellow
try {
  $body = @{
    size = 1
    sort = @(@{ "@timestamp" = @{ order = "desc" } })
    query = @{ term = @{ "event.code" = 4625 } }
  } | ConvertTo-Json -Depth 10
  $r = Invoke-RestMethod -Uri "$SiemUrl/tinysocs-winlog-*/_search" `
    -Headers $auth -Method POST -ContentType "application/json" `
    -Body $body -TimeoutSec 10 -ErrorAction Stop
  if ($r -is [string]) { $r = $r | ConvertFrom-Json }
  if ($r.hits.hits.Count -gt 0) {
    $json = $r.hits.hits[0]._source | ConvertTo-Json -Depth 5
    $json -split "`n" | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
  } else {
    Write-Host "  No 4625 events found" -ForegroundColor Red
  }
} catch {
  Write-Host "  Failed: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n=== Done ===" -ForegroundColor Cyan
Write-Host ""
