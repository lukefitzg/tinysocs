param(
  [string]$RepoRoot = (Resolve-Path "$PSScriptRoot\..").Path,
  [int]$RotateEveryMinutes = 60,
  [string]$VerifyAt = "02:15"  # HH:mm 24h
)

$ErrorActionPreference = 'Stop'
Set-Location $RepoRoot

$rotate = Join-Path $RepoRoot "scripts\Rotate-Queues.ps1"
$verify = Join-Path $RepoRoot "scripts\Nightly-VerifyLedger.ps1"
if (-not (Test-Path $rotate)) { throw "Missing $rotate" }
if (-not (Test-Path $verify)) { throw "Missing $verify" }

function New-PSAction([string]$ScriptPath){
  $args = "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`""
  New-ScheduledTaskAction -Execute "powershell.exe" -Argument $args
}

function Test-IsAdmin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $pr = New-Object Security.Principal.WindowsPrincipal($id)
  return $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

$who = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$elevated = Test-IsAdmin

# Principal: highest only if admin
try {
  if ($elevated) {
    $principal = New-ScheduledTaskPrincipal -UserId $who -LogonType S4U -RunLevel Highest
  } else {
    $principal = New-ScheduledTaskPrincipal -UserId $who -LogonType Interactive -RunLevel Limited
  }
} catch {
  $principal = New-ScheduledTaskPrincipal -UserId $who -LogonType Interactive
}

# Task 1: Rotate-Queues every N minutes
$start = (Get-Date).AddMinutes(1)
$rotTrigger = New-ScheduledTaskTrigger -Once -At $start `
  -RepetitionInterval (New-TimeSpan -Minutes $RotateEveryMinutes) `
  -RepetitionDuration (New-TimeSpan -Days 3650)
$rotAction  = New-PSAction $rotate
$rotTask = New-ScheduledTask -Action $rotAction -Trigger $rotTrigger -Principal $principal `
  -Settings (New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -Compatibility Win8)
try { Unregister-ScheduledTask -TaskName "TinySocs-RotateQueues" -Confirm:$false -ErrorAction SilentlyContinue } catch {}

$rotOk = $true
try {
  Register-ScheduledTask -TaskName "TinySocs-RotateQueues" -InputObject $rotTask | Out-Null
} catch {
  $rotOk = $false
}

if (-not $rotOk) {
  Write-Warning "Register-ScheduledTask denied for RotateQueues; attempting schtasks.exe fallback."
  schtasks /Create /TN "TinySocs-RotateQueues" /SC MINUTE /MO $RotateEveryMinutes /F /TR `
    "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$rotate`""
}

Write-Host "Installed (or attempted) RotateQueues (every $RotateEveryMinutes min, starts $($start.ToString('HH:mm'))) "

# Task 2: Nightly verify
$hh,$mm = $VerifyAt.Split(':')
$verifyTime = (Get-Date).Date.AddHours([int]$hh).AddMinutes([int]$mm)
$verTrigger = New-ScheduledTaskTrigger -Daily -At $verifyTime
$verAction  = New-PSAction $verify
$verTask = New-ScheduledTask -Action $verAction -Trigger $verTrigger -Principal $principal `
  -Settings (New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -Compatibility Win8)
try { Unregister-ScheduledTask -TaskName "TinySocs-NightlyVerifyLedger" -Confirm:$false -ErrorAction SilentlyContinue } catch {}

$verOk = $true
try {
  Register-ScheduledTask -TaskName "TinySocs-NightlyVerifyLedger" -InputObject $verTask | Out-Null
} catch {
  $verOk = $false
}

if (-not $verOk) {
  Write-Warning "Register-ScheduledTask denied for NightlyVerify; attempting schtasks.exe fallback."
  schtasks /Create /TN "TinySocs-NightlyVerifyLedger" /SC DAILY /ST $VerifyAt /F /TR `
    "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$verify`""
}

Write-Host "Installed (or attempted) NightlyVerify (@ $VerifyAt)"