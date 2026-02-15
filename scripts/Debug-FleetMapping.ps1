<#
.SYNOPSIS
  Check winlog index mapping for computer_name field type.
#>
$ErrorActionPreference = "Continue"
Add-Type @"
using System.Net;using System.Net.Security;using System.Security.Cryptography.X509Certificates;
public class TLS5{public static void Ignore(){ServicePointManager.ServerCertificateValidationCallback=delegate{return true;};}}
"@
[TLS5]::Ignore()
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
$SiemUrl = "https://localhost:9201"
try {
  Import-Module "C:\Program Files\TinySocs\modules\TinySocs.Installer.psm1" -Force -ErrorAction SilentlyContinue 3>$null
  $creds = Get-TSSiemCredsCanonical; $User = $creds.User; $Pass = $creds.Pass
} catch { $User = "admin"; $Pass = "admin" }
$b64 = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("${User}:${Pass}"))
$auth = @{ Authorization = "Basic $b64" }

Write-Host "`n=== Winlog Mapping for computer_name ===" -ForegroundColor Cyan

# Get mapping for winlog.computer_name
try {
  $r = Invoke-RestMethod -Uri "$SiemUrl/tinysocs-winlog-*/_mapping/field/winlog.computer_name" `
    -Headers $auth -TimeoutSec 5 -ErrorAction Stop
  $json = $r | ConvertTo-Json -Depth 10
  Write-Host $json -ForegroundColor Gray
} catch {
  Write-Host "  Failed: $($_.Exception.Message)" -ForegroundColor Red
}

# Try aggregating with different field variants
Write-Host "`n=== Testing aggregation variants ===" -ForegroundColor Cyan
$variants = @(
  "winlog.computer_name.keyword",
  "winlog.computer_name",
  "host.name.keyword",
  "host.name"
)
foreach ($field in $variants) {
  try {
    $body = @{
      size = 0
      query = @{ range = @{ "@timestamp" = @{ gte = "now-24h" } } }
      aggs = @{ hosts = @{ terms = @{ field = $field; size = 5 } } }
    } | ConvertTo-Json -Depth 10
    $r = Invoke-RestMethod -Uri "$SiemUrl/tinysocs-winlog-*/_search" `
      -Headers $auth -Method POST -ContentType "application/json" `
      -Body $body -TimeoutSec 5 -ErrorAction Stop
    if ($r -is [string]) { $r = $r | ConvertFrom-Json }
    $buckets = $r.aggregations.hosts.buckets
    if ($buckets.Count -gt 0) {
      Write-Host "  $field -> $($buckets.Count) host(s): $($buckets[0].key) ($($buckets[0].doc_count) docs)" -ForegroundColor Green
    } else {
      Write-Host "  $field -> 0 buckets" -ForegroundColor Yellow
    }
  } catch {
    $msg = $_.Exception.Message
    if ($msg.Length -gt 100) { $msg = $msg.Substring(0, 100) + "..." }
    Write-Host "  $field -> ERROR: $msg" -ForegroundColor Red
  }
}
Write-Host ""
