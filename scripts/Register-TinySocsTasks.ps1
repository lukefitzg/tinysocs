param(
  [switch]$ForUser  # default: for current user only
)
$repo = (Resolve-Path "$PSScriptRoot\..").Path
$ps   = (Get-Command powershell.exe).Source
$sc   = { param($f) "$ps -NoProfile -ExecutionPolicy Bypass -File `"$f`"" }

$trgUser = $env:USERNAME
$principal = if ($ForUser) { New-ScheduledTaskPrincipal -UserId $trgUser -LogonType Interactive } else { New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest }

# Master hourly
$act1 = New-ScheduledTaskAction -Execute $ps -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$repo\scripts\Run-Master.ps1`""
$trg1 = New-ScheduledTaskTrigger -Once -At (Get-Date).Date.AddMinutes(2) -RepetitionInterval (New-TimeSpan -Hours 1) -RepetitionDuration ([TimeSpan]::MaxValue)
Register-ScheduledTask -TaskName "TinySocs_Master_Hourly" -Action $act1 -Trigger $trg1 -Principal $principal -Force

# Verify daily (00:10)
$act2 = New-ScheduledTaskAction -Execute $ps -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$repo\scripts\Run-Verify.ps1`""
$trg2 = New-ScheduledTaskTrigger -Daily -At 00:10
Register-ScheduledTask -TaskName "TinySocs_LedgerVerify_Daily" -Action $act2 -Trigger $trg2 -Principal $principal -Force

# Retention daily (00:30)
$act3 = New-ScheduledTaskAction -Execute $ps -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$repo\scripts\Run-AnchorsRetention.ps1`""
$trg3 = New-ScheduledTaskTrigger -Daily -At 00:30
Register-ScheduledTask -TaskName "TinySocs_AnchorsRetention_Daily" -Action $act3 -Trigger $trg3 -Principal $principal -Force

Write-Host "Registered: TinySocs_Master_Hourly, TinySocs_LedgerVerify_Daily, TinySocs_AnchorsRetention_Daily"