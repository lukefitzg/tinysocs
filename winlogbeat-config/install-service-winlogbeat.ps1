<#
Installs/refreshes the Winlogbeat Windows service.
- Self-elevates if not admin
- Stops/deletes existing service if present (ignore if missing)
- Points service to C:\tinysocs\winlogbeat-bin
#>

param(
  [switch]$ForceLegacyPath
)

$ErrorActionPreference = "Stop"

function Test-IsAdmin {
  $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
  $p  = New-Object System.Security.Principal.WindowsPrincipal($id)
  return $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Self-elevate if needed
if (-not (Test-IsAdmin)) {
  Write-Host "Re-launching elevated to install the service..."
  Start-Process powershell -Verb RunAs -ArgumentList @(
    "-NoProfile","-ExecutionPolicy","Bypass",
    "-File", $MyInvocation.MyCommand.Path
  )
  exit 0
}

# Paths (bin = this script's folder)
$WorkDir        = Split-Path -Parent $MyInvocation.MyCommand.Path
$ExePath        = Join-Path $WorkDir "winlogbeat.exe"
$CfgPath        = Join-Path $WorkDir "winlogbeat.yml"

if (-not (Test-Path $ExePath)) { throw "Missing $ExePath" }
if (-not (Test-Path $CfgPath)) { throw "Missing $CfgPath" }

# Data paths (new vs legacy)
$BasePath       = "$env:ProgramFiles\Winlogbeat-Data"
$LegacyDataPath = "$env:ProgramData\Winlogbeat"
if ($ForceLegacyPath) { $BasePath = $LegacyDataPath }
elseif (Test-Path $LegacyDataPath) {
  try {
    Write-Host "Migrating legacy data: $LegacyDataPath -> $BasePath"
    Move-Item $LegacyDataPath $BasePath -ErrorAction Stop
  } catch {
    Write-Warning "Could not move legacy data; continuing with legacy path"
    $BasePath = $LegacyDataPath
  }
}
$HomePath  = Join-Path $BasePath "Winlogbeat"
$LogsPath  = Join-Path $HomePath "logs"
New-Item -ItemType Directory -Force -Path $HomePath,$LogsPath | Out-Null

# Stop & delete if exists (ignore errors)
$svc = Get-Service -Name winlogbeat -ErrorAction SilentlyContinue
if ($svc) {
  Write-Host "Stopping existing service..."
  try {
    Stop-Service winlogbeat -Force -ErrorAction SilentlyContinue
    $svc.WaitForStatus('Stopped','00:00:10') | Out-Null
  } catch { }
  Start-Sleep -Seconds 1
  try { sc.exe delete winlogbeat | Out-Null } catch { }
}

# Build service command
$KeystorePath = Join-Path $WorkDir "data\Winlogbeat.keystore"
$FullCmd = "`"$ExePath`" " +
           "--environment=windows_service " +
           "-c `"$CfgPath`" " +
           "--path.home `"$WorkDir`" " +
           "--path.data `"$HomePath`" " +
           "--path.logs `"$LogsPath`" " +
           "-E keystore.path=`"$KeystorePath`" " +
           "-E logging.files.redirect_stderr=true"

Write-Host "Creating service..."
New-Service -Name winlogbeat `
  -DisplayName "Winlogbeat" `
  -BinaryPathName $FullCmd `
  -StartupType Automatic | Out-Null

# Delayed start (best for boot)
try { sc.exe config winlogbeat start= delayed-auto | Out-Null } catch {}

Write-Host "Starting service..."
Start-Service winlogbeat
(Get-Service winlogbeat).WaitForStatus('Running','00:00:10') | Out-Null

Write-Host "Winlogbeat service is Running."
Write-Host "Bin: $ExePath"
Write-Host "Cfg: $CfgPath"
Write-Host "Data: $HomePath"
