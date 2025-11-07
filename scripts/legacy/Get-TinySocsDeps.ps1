param(
  [string]$WinlogbeatUrl = "https://artifacts.elastic.co/downloads/beats/winlogbeat/winlogbeat-8.14.3-windows-x86_64.zip",
  [string]$WinlogbeatSha256 = "PUT_SHA256_HERE",
  [string]$SysmonUrl = "https://download.sysinternals.com/files/Sysmon.zip",
  [string]$SysmonSha256 = "PUT_SHA256_HERE"
)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path "$PSScriptRoot\..").Path
$deps = Join-Path $root "deps"
$wlbDir = Join-Path $root "winlogbeat-bin"
$sysmonDir = Join-Path $root "sysmon-bin"
New-Item -ItemType Directory -Force -Path $deps, $wlbDir, $sysmonDir | Out-Null

function Get-And-Verify($url, $outPath, $expectedSha256) {
  Invoke-WebRequest -Uri $url -OutFile $outPath -UseBasicParsing
  $hash = (Get-FileHash -Path $outPath -Algorithm SHA256).Hash.ToLower()
  if ($hash -ne $expectedSha256.ToLower()) {
    throw "SHA256 mismatch for $outPath. Expected $expectedSha256 got $hash"
  }
}

$wlbZip = Join-Path $deps "winlogbeat.zip"
$sysmonZip = Join-Path $deps "sysmon.zip"

Write-Host "[deps] Downloading Winlogbeat…" -ForegroundColor Cyan
Get-And-Verify $WinlogbeatUrl $wlbZip $WinlogbeatSha256

Write-Host "[deps] Downloading Sysmon…" -ForegroundColor Cyan
Get-And-Verify $SysmonUrl $sysmonZip $SysmonSha256

Write-Host "[deps] Extracting…" -ForegroundColor Cyan
Expand-Archive -Path $wlbZip -DestinationPath $deps -Force
Expand-Archive -Path $sysmonZip -DestinationPath $deps -Force

$wlbSrc = Get-ChildItem -Directory $deps | Where-Object { $_.Name -like "winlogbeat-*" } | Select-Object -First 1
Copy-Item -Recurse -Force "$($wlbSrc.FullName)\*" $wlbDir
Copy-Item -Recurse -Force (Join-Path $deps "Sysmon*") $sysmonDir

Write-Host "[deps] Done. Binaries at:"
Write-Host "  $wlbDir"
Write-Host "  $sysmonDir"
