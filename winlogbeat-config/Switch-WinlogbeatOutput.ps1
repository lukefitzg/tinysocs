param(
  [Parameter(Mandatory=$true)]
  [ValidateSet('elastic','opensearch','opensearch-auth')]
  [string]$Target,

  # Where winlogbeat.exe + winlogbeat.yml live
  [string]$WinlogbeatBin = "C:\tinysocs\winlogbeat-bin",

  # Where the template configs live
  [string]$ConfigDir = (Split-Path -Parent $PSCommandPath),

  # Windows service name
  [string]$ServiceName = "winlogbeat"
)

# --- Self-elevate if needed ---
function Test-IsAdmin {
  $wi = [Security.Principal.WindowsIdentity]::GetCurrent()
  $wp = New-Object Security.Principal.WindowsPrincipal($wi)
  return $wp.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdmin)) {
  Write-Host "[INFO] Elevation required. Re-launching as Administrator…" -ForegroundColor Yellow
  $argsList = @(
    '-NoProfile','-ExecutionPolicy','Bypass',
    '-File',"`"$PSCommandPath`"",
    '-Target', $Target,
    '-WinlogbeatBin', "`"$WinlogbeatBin`"",
    '-ConfigDir', "`"$ConfigDir`"",
    '-ServiceName', $ServiceName
  )
  Start-Process -FilePath "powershell.exe" -Verb RunAs -ArgumentList $argsList | Out-Null
  exit 0
}

# --- Resolve files ---
$map = @{
  'elastic'        = 'winlogbeat.elastic.yml'
  'opensearch'     = 'winlogbeat.opensearch.yml'
  'opensearch-auth'= 'winlogbeat.opensearch-auth.yml'
}

$srcName = $map[$Target]
$CfgSrc  = Join-Path $ConfigDir $srcName
$CfgDst  = Join-Path $WinlogbeatBin 'winlogbeat.yml'
$ExePath = Join-Path $WinlogbeatBin 'winlogbeat.exe'

if (-not (Test-Path $ExePath)) {
  throw "winlogbeat.exe not found at: $ExePath"
}
if (-not (Test-Path $CfgSrc)) {
  throw "Config not found: $CfgSrc"
}

Write-Host "Switching Winlogbeat output to: $Target" -ForegroundColor Cyan
Copy-Item $CfgSrc $CfgDst -Force
Write-Host "Copied: $CfgSrc -> $CfgDst"

# --- Ensure service points at this binary/config ---
function Ensure-Service {
  param([string]$Name)

  $exists = Get-Service -Name $Name -ErrorAction SilentlyContinue
  if ($exists) {
    Write-Host "Stopping service..." -ForegroundColor DarkCyan
    try {
      Stop-Service $Name -Force -ErrorAction Stop
      (Get-Service $Name).WaitForStatus('Stopped','00:00:10')
    } catch { Write-Host "[WARN] Stop-Service: $($_.Exception.Message)" -ForegroundColor Yellow }
    Write-Host "Uninstalling service..." -ForegroundColor DarkCyan
    try { sc.exe delete $Name | Out-Null } catch {}
    Start-Sleep -Seconds 1
  }

  # Prefer your existing installer if present
  $Installer = Join-Path $WinlogbeatBin 'install-service-winlogbeat.ps1'
  if (Test-Path $Installer) {
    Write-Host "Installing service (script)..." -ForegroundColor DarkCyan
    & $Installer
    return
  }

  # Fallback: create service directly (same BinaryPathName your script uses)
  Write-Host "Installing service (direct)..." -ForegroundColor DarkCyan
  $DataRoot  = "$env:ProgramFiles\Winlogbeat-Data\Winlogbeat"
  $LogsRoot  = Join-Path $DataRoot 'logs'
  $Keystore  = Join-Path (Join-Path $WinlogbeatBin 'data') 'Winlogbeat.keystore'

  $bin = @(
    "`"$ExePath`"",
    "--environment=windows_service",
    "-c `"$CfgDst`"",
    "--path.home `"$WinlogbeatBin`"",
    "--path.data `"$DataRoot`"",
    "--path.logs `"$LogsRoot`"",
    "-E keystore.path=`"$Keystore`"",
    "-E logging.files.redirect_stderr=true"
  ) -join ' '

  New-Service -Name $Name -DisplayName 'winlogbeat' -BinaryPathName $bin -StartupType Automatic
  try { Start-Process -FilePath sc.exe -ArgumentList 'config', $Name, 'start=', 'delayed-auto' | Out-Null } catch {}
}

Ensure-Service -Name $ServiceName

Write-Host "Starting service..." -ForegroundColor DarkCyan
Start-Service $ServiceName
(Get-Service $ServiceName).WaitForStatus('Running','00:00:10')

Write-Host "Service status:" -ForegroundColor Green
Get-Service $ServiceName | Format-Table Name,Status,StartType -AutoSize
