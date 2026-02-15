<#
.SYNOPSIS
  Diagnose why the C# detection engine produces 0 alerts.
#>
$ErrorActionPreference = "Continue"

Add-Type @"
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
public class TLS3 {
    public static void Ignore() {
        ServicePointManager.ServerCertificateValidationCallback =
            delegate { return true; };
    }
}
"@
[TLS3]::Ignore()
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

$SiemUrl = "https://localhost:9201"

# Get auth
try {
  Import-Module "C:\Program Files\TinySocs\modules\TinySocs.Installer.psm1" -Force -ErrorAction SilentlyContinue 3>$null
  $creds = Get-TSSiemCredsCanonical
  $User = $creds.User; $Pass = $creds.Pass
} catch { $User = "admin"; $Pass = "admin" }
$b64 = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("${User}:${Pass}"))
$auth = @{ Authorization = "Basic $b64" }

Write-Host "`n=== Detection Engine Diagnostics ===" -ForegroundColor Cyan

# 1. Check rules file
Write-Host "`n[1] Rules file:" -ForegroundColor Yellow
$rulesFile = "C:\ProgramData\TinySocs\Collector\rules\rules.yml"
if (Test-Path $rulesFile) {
  $content = Get-Content $rulesFile -Raw
  $ruleCount = ([regex]::Matches($content, '^\s*- id:', [System.Text.RegularExpressions.RegexOptions]::Multiline)).Count
  Write-Host "  EXISTS: $rulesFile ($ruleCount rules)" -ForegroundColor Green
} else {
  Write-Host "  MISSING: $rulesFile" -ForegroundColor Red
}

# 2. Find agent logs (check all possible locations)
Write-Host "`n[2] Agent logs:" -ForegroundColor Yellow
$logPaths = @(
  "C:\ProgramData\TinySocs\Collector\logs\agent.log",
  "C:\ProgramData\TinySocs\Collector\logs\alerts.log",
  "C:\ProgramData\TinySocs\Collector\agent.log",
  "C:\ProgramData\TinySocs\Agent\logs\agent.log",
  "C:\ProgramData\TinySocs\Agent\agent.log",
  "C:\Program Files\TinySocs\Agent\logs\agent.log",
  "C:\Program Files\TinySocs\Collector\logs\agent.log"
)
foreach ($p in $logPaths) {
  if (Test-Path $p) {
    $size = (Get-Item $p).Length
    Write-Host "  FOUND: $p ($size bytes)" -ForegroundColor Green
  }
}

# Also search more broadly
Write-Host "  Searching ProgramData for *.log files..." -ForegroundColor Gray
$allLogs = Get-ChildItem "C:\ProgramData\TinySocs" -Recurse -Filter "*.log" -ErrorAction SilentlyContinue
foreach ($log in $allLogs) {
  Write-Host "    $($log.FullName) ($($log.Length) bytes)" -ForegroundColor Gray
}

# NSSM stdout/stderr for the agent
Write-Host "  Searching for NSSM agent logs..." -ForegroundColor Gray
$agentLogs = Get-ChildItem "C:\ProgramData\TinySocs" -Recurse -Filter "TinySocsAgent*" -ErrorAction SilentlyContinue
foreach ($log in $agentLogs) {
  if ($log.Length -gt 0) {
    Write-Host "    $($log.FullName) ($($log.Length) bytes)" -ForegroundColor Green
    $tail = Get-Content $log.FullName -Tail 20 -ErrorAction SilentlyContinue
    if ($tail) {
      Write-Host "    Last 20 lines:" -ForegroundColor Gray
      $tail | ForEach-Object { Write-Host "      $_" -ForegroundColor DarkGray }
    }
  }
}

# 3. Check agent service config
Write-Host "`n[3] Agent service configuration:" -ForegroundColor Yellow
$svcKey = "HKLM:\SYSTEM\CurrentControlSet\Services\TinySocsAgent"
if (Test-Path $svcKey) {
  $imgPath = (Get-ItemProperty $svcKey -Name ImagePath -ErrorAction SilentlyContinue).ImagePath
  Write-Host "  ImagePath: $imgPath" -ForegroundColor Gray
  try {
    $envExtra = (Get-ItemProperty $svcKey -Name Environment -ErrorAction SilentlyContinue).Environment
    if ($envExtra) {
      Write-Host "  Environment vars:" -ForegroundColor Gray
      foreach ($e in $envExtra) { Write-Host "    $e" -ForegroundColor DarkGray }
    }
  } catch { }
}

# Check NSSM env
$nssm = "C:\Program Files\TinySocs\bin\nssm.exe"
if (Test-Path $nssm) {
  try {
    $appDir = & $nssm get TinySocsAgent AppDirectory 2>$null
    $appEnv = & $nssm get TinySocsAgent AppEnvironmentExtra 2>$null
    Write-Host "  NSSM AppDirectory: $appDir" -ForegroundColor Gray
    if ($appEnv) {
      Write-Host "  NSSM AppEnvironmentExtra:" -ForegroundColor Gray
      $appEnv -split "`n" | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
    }
  } catch { }
}

# 4. Agent config being used
Write-Host "`n[4] Agent config file:" -ForegroundColor Yellow
$configPaths = @(
  "C:\ProgramData\TinySocs\Collector\agent-config.yml",
  "C:\ProgramData\TinySocs\Agent\agent-config.yml",
  "C:\Program Files\TinySocs\Agent\agent-config.yml",
  "C:\Program Files\TinySocs\Collector\agent-config.yml"
)
foreach ($p in $configPaths) {
  if (Test-Path $p) {
    Write-Host "  FOUND: $p" -ForegroundColor Green
    # Check detection section
    $cfg = Get-Content $p -Raw
    if ($cfg -match "detection:") {
      $detSection = $cfg -replace '(?s).*?(detection:.*?)(?=\n\w|\z)', '$1'
      Write-Host "  Detection config:" -ForegroundColor Gray
      ($cfg -split "`n" | Select-String -Pattern "detection:|enabled:|rules_file:" | Select-Object -First 5) | ForEach-Object {
        Write-Host "    $($_.Line.Trim())" -ForegroundColor DarkGray
      }
    }
  }
}

# 5. Check actual events in OpenSearch (verify field structure)
Write-Host "`n[5] Event structure in OpenSearch (4625 events):" -ForegroundColor Yellow
try {
  $body = @{
    size = 2
    sort = @(@{ "@timestamp" = @{ order = "desc" } })
    query = @{
      bool = @{
        must = @(
          @{ term = @{ "winlog.event_id" = 4625 } }
        )
      }
    }
  } | ConvertTo-Json -Depth 10

  $r = Invoke-RestMethod -Uri "$SiemUrl/tinysocs-winlog-*/_search" `
    -Headers $auth -Method POST -ContentType "application/json" `
    -Body $body -TimeoutSec 10 -ErrorAction Stop
  if ($r -is [string]) { $r = $r | ConvertFrom-Json }

  $total = $r.hits.total.value
  Write-Host "  Total 4625 events: $total" -ForegroundColor $(if ($total -gt 0) { "Green" } else { "Red" })

  if ($r.hits.hits.Count -gt 0) {
    $src = $r.hits.hits[0]._source
    Write-Host "  Sample event fields:" -ForegroundColor Gray

    # Check event_id location
    $eid = $src | Select-Object -ExpandProperty "event" -ErrorAction SilentlyContinue
    if ($eid) { Write-Host "    event.code = $($eid.code)" -ForegroundColor DarkGray }

    $wl = $src | Select-Object -ExpandProperty "winlog" -ErrorAction SilentlyContinue
    if ($wl) {
      Write-Host "    winlog.event_id = $($wl.event_id)" -ForegroundColor DarkGray
      Write-Host "    winlog.channel = $($wl.channel)" -ForegroundColor DarkGray
      $ed = $wl | Select-Object -ExpandProperty "event_data" -ErrorAction SilentlyContinue
      if ($ed) {
        Write-Host "    winlog.event_data keys: $(($ed.PSObject.Properties.Name | Select-Object -First 10) -join ', ')" -ForegroundColor DarkGray
        $tun = $ed | Select-Object -ExpandProperty "TargetUserName" -ErrorAction SilentlyContinue
        Write-Host "    winlog.event_data.TargetUserName = $tun" -ForegroundColor $(if ($tun) { "Green" } else { "Red" })
      } else {
        Write-Host "    winlog.event_data: NOT PRESENT" -ForegroundColor Red
      }
    } else {
      Write-Host "    winlog: NOT PRESENT" -ForegroundColor Red
    }

    # Show raw source for inspection
    Write-Host "  Raw source (first event):" -ForegroundColor Gray
    $rawJson = $r.hits.hits[0]._source | ConvertTo-Json -Depth 5
    $rawJson -split "`n" | Select-Object -First 30 | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
  }
} catch {
  Write-Host "  Query failed: $($_.Exception.Message)" -ForegroundColor Red
}

# Also try event.code field
Write-Host "`n  Trying event.code:4625 query..." -ForegroundColor Gray
try {
  $body2 = @{
    size = 0
    query = @{ term = @{ "event.code" = 4625 } }
  } | ConvertTo-Json -Depth 10
  $r2 = Invoke-RestMethod -Uri "$SiemUrl/tinysocs-winlog-*/_search" `
    -Headers $auth -Method POST -ContentType "application/json" `
    -Body $body2 -TimeoutSec 10 -ErrorAction Stop
  if ($r2 -is [string]) { $r2 = $r2 | ConvertFrom-Json }
  Write-Host "  event.code:4625 hits: $($r2.hits.total.value)" -ForegroundColor Gray
} catch { }

# 6. Check tinysocs-alerts-* index
Write-Host "`n[6] Alerts index:" -ForegroundColor Yellow
try {
  $r = Invoke-RestMethod -Uri "$SiemUrl/tinysocs-alerts-*/_count" `
    -Headers $auth -TimeoutSec 5 -ErrorAction Stop
  if ($r -is [string]) { $r = $r | ConvertFrom-Json }
  Write-Host "  Total alert docs: $($r.count)" -ForegroundColor $(if ($r.count -gt 0) { "Green" } else { "Gray" })
} catch {
  Write-Host "  Alerts index query failed: $($_.Exception.Message)" -ForegroundColor Red
  Write-Host "  (Index may not exist yet - created on first alert)" -ForegroundColor Gray
}

# 7. Check all indices
Write-Host "`n[7] All TinySocs indices:" -ForegroundColor Yellow
try {
  $r = Invoke-RestMethod -Uri "$SiemUrl/_cat/indices/tinysocs*?h=index,docs.count,store.size&format=json" `
    -Headers $auth -TimeoutSec 5 -ErrorAction Stop
  if ($r -is [string]) { $r = $r | ConvertFrom-Json }
  foreach ($idx in $r) {
    Write-Host "  $($idx.index): $($idx.'docs.count') docs ($($idx.'store.size'))" -ForegroundColor Gray
  }
} catch {
  Write-Host "  Failed: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n=== Done ===" -ForegroundColor Cyan
Write-Host ""
