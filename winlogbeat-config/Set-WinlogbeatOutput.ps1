param(
  [ValidateSet("elastic","opensearch")]
  [string]$Backend
)

$ErrorActionPreference = "Stop"

# Paths – change these if your repo layout differs
$RepoRoot   = "C:\tinysocs\tinysocs"
$CfgDir     = Join-Path $RepoRoot "winlogbeat-config"
$BinDir     = "C:\tinysocs\winlogbeat-bin"            # where winlogbeat.exe lives (from your fetch script)
$TargetCfg  = Join-Path $BinDir   "winlogbeat.yml"

if ($Backend -eq "elastic") {
  $SrcCfg = Join-Path $CfgDir "winlogbeat.elastic.yml"
} else {
  $SrcCfg = Join-Path $CfgDir "winlogbeat.opensearch.yml"
}

if (!(Test-Path $SrcCfg)) { throw "Config not found: $SrcCfg" }
if (!(Test-Path $BinDir)) { throw "Winlogbeat bin dir not found: $BinDir (run fetch_winlogbeat.ps1 first)" }

Write-Host "Switching Winlogbeat output to: $Backend"
Copy-Item -Path $SrcCfg -Destination $TargetCfg -Force
Write-Host "Copied: $SrcCfg -> $TargetCfg"

# Restart service if installed and we have rights
$svc = Get-Service -Name winlogbeat -ErrorAction SilentlyContinue
if ($svc) {
  try {
    if ($svc.Status -eq "Running") {
      Write-Host "Stopping service..."
      Stop-Service winlogbeat -Force
      $svc.WaitForStatus('Stopped','00:00:20')
    }
    Write-Host "Starting service..."
    Start-Service winlogbeat
    Write-Host "Service restarted."
  } catch {
    Write-Warning "Could not control 'winlogbeat' service (not elevated or blocked)."
    Write-Host "Run this in an **Administrator** PowerShell, or run Winlogbeat in console mode:"
    Write-Host "  cd `"$BinDir`" ; .\winlogbeat.exe -c winlogbeat.yml -e"
  }
} else {
  Write-Host "Service not installed. To run ad-hoc:"
  Write-Host "  cd `"$BinDir`" ; .\winlogbeat.exe -c winlogbeat.yml -e"
  Write-Host "To install the service (Admin PS):"
  Write-Host "  cd `"$BinDir`" ; .\install-service-winlogbeat.ps1 ; Start-Service winlogbeat"
}

