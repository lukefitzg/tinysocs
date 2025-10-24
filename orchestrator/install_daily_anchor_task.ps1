<#
\orchestrator\install_daily_anchor_task.ps1
TinySocs — install two scheduled tasks:
  1) TinySOCS_Master_Daily: runs master once per day to post anchors + incident
  2) TinySOCS_Ledger_Health: runs check_ledger.py and writes a JSON log

Requires:
 - Python venv set up at C:\tinysocs\tinysocs\.venv
 - Environment variables below (edit as needed)
#>

param(
  [string]$RepoRoot = "C:\tinysocs\tinysocs",
  [string]$Nodes    = "http://localhost:8081",
  [string]$Rules    = "auth_failed_burst,ps_script_block",
  [string]$Window   = "15m",
  [string]$TimeDaily = "03:30" # 24h HH:mm
)

$python     = Join-Path $RepoRoot ".venv\Scripts\python.exe"
$masterPy   = Join-Path $RepoRoot "orchestrator\master.py"
$checkPy    = Join-Path $RepoRoot "orchestrator\check_ledger.py"
$logsDir    = Join-Path $RepoRoot "logs"
$null = New-Item -ItemType Directory -Path $logsDir -Force -ErrorAction SilentlyContinue

$envBlock = @"
set TINYSOCS_NODES=$Nodes
set MASTER_SHARED_SECRET=dev-secret-change-me
set PRIVACY_MODE=abstract
set TINYSOCS_INSECURE_SKIP_VERIFY=1
"@

# Task 1: daily master
$action1 = New-ScheduledTaskAction -Execute $python -Argument "`"$masterPy`" --rules $Rules --window $Window"
$trigger1 = New-ScheduledTaskTrigger -Daily -At ([datetime]::ParseExact($TimeDaily,'HH:mm',$null))
$task1 = New-ScheduledTask -Action $action1 -Trigger $trigger1 -Settings (New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -StartWhenAvailable)

# Task 2: ledger health (5 minutes after master)
$time2 = ([datetime]::ParseExact($TimeDaily,'HH:mm',$null)).AddMinutes(5).ToString('HH:mm')
$action2 = New-ScheduledTaskAction -Execute $python -Argument "`"$checkPy`""
$trigger2 = New-ScheduledTaskTrigger -Daily -At ([datetime]::ParseExact($time2,'HH:mm',$null))
$task2 = New-ScheduledTask -Action $action2 -Trigger $trigger2 -Settings (New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -StartWhenAvailable)

# Register with the environment block via wrapper cmd.exe
# (This bakes the env vars in so the tasks don't depend on your user session.)
$wrapper1 = Join-Path $RepoRoot "orchestrator\run_master_daily.cmd"
$wrapper2 = Join-Path $RepoRoot "orchestrator\run_ledger_health.cmd"
$envBlock | Set-Content -Path $wrapper1 -Encoding ASCII
Add-Content -Path $wrapper1 -Value "`"$python`" `"$masterPy`" --rules $Rules --window $Window >> `"$logsDir\master-daily.log`" 2>&1"
$envBlock | Set-Content -Path $wrapper2 -Encoding ASCII
Add-Content -Path $wrapper2 -Value "`"$python`" `"$checkPy`" > `"$logsDir\ledger-health.json`" 2>&1"

# Rewire actions to wrappers so env is applied
$action1 = New-ScheduledTaskAction -Execute $wrapper1
$task1 = New-ScheduledTask -Action $action1 -Trigger $trigger1 -Settings (New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -StartWhenAvailable)

$action2 = New-ScheduledTaskAction -Execute $wrapper2
$task2 = New-ScheduledTask -Action $action2 -Trigger $trigger2 -Settings (New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -StartWhenAvailable)

Register-ScheduledTask -TaskName "TinySOCS_Master_Daily" -InputObject $task1 -Force
Register-ScheduledTask -TaskName "TinySOCS_Ledger_Health" -InputObject $task2 -Force

Write-Host "[TinySocs] Installed tasks:"
Write-Host "  - TinySOCS_Master_Daily @ $TimeDaily"
Write-Host "  - TinySOCS_Ledger_Health @ $time2"
Write-Host "Logs:"
Write-Host "  - $logsDir\master-daily.log"
Write-Host "  - $logsDir\ledger-health.json"