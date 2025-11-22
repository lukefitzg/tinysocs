# modules\TinySocs.Installer.psm1
# Windows-first installer helpers for TinySocs

# ── ProgramData layout ──────────────────────────────────────────────────────────
function New-ProgramDataLayout {
  $root = "$env:ProgramData\TinySocs"
  "$root\logs","$root\queue","$root\ledger","$root\rules","$root\anchors\state","$root\config" |
    ForEach-Object { New-Item -ItemType Directory -Force -Path $_ | Out-Null }
}

function Install-TinySocs {
  New-ProgramDataLayout
  Write-Host "[TinySocs] ProgramData ensured."
}

# ── Service via NSSM ────────────────────────────────────────────────────────────
function Register-TinySocsServices {
  $n = "C:\Program Files\TinySocs\bin\nssm.exe"
  $e = "C:\Program Files\TinySocs\bin\TinySocsNode.exe"
  $w = "$env:ProgramData\TinySocs"

  if (!(Test-Path $n)) {
    Write-Warning "[TinySocs] nssm.exe missing; skipping service."
    return
  }

  # Install or update service config idempotently
  & $n install TinySocsNode $e | Out-Null
  & $n set TinySocsNode AppDirectory    $w                                   | Out-Null
  & $n set TinySocsNode Start           SERVICE_AUTO_START                   | Out-Null
  & $n set TinySocsNode AppStdout       "$w\logs\TinySocsNode.out.log"       | Out-Null
  & $n set TinySocsNode AppStderr       "$w\logs\TinySocsNode.err.log"       | Out-Null
  & $n set TinySocsNode AppNoConsole    1                                    | Out-Null
  & $n set TinySocsNode AppRestartDelay 2000                                 | Out-Null
  & $n set TinySocsNode AppEnvironmentExtra `
      'PORT=8081;SIEM_URL=https://localhost:9201;SIEM_SSL_VERIFY=false;PRIVACY_MODE=abstract' | Out-Null

  sc.exe failure TinySocsNode reset= 60 actions= restart/2000/restart/2000/""/0 | Out-Null
  & $n start TinySocsNode | Out-Null

  Write-Host "[TinySocs] Service installed and started."
}

# ── Scheduled task helpers (PowerShell API, not schtasks) ──────────────────────

function Ensure-TaskFolder {
  param([string]$FolderPath = "\TinySocs")
  $svc = New-Object -ComObject "Schedule.Service"
  $svc.Connect()
  $root = $svc.GetFolder("\")
  try { $null = $root.GetFolder($FolderPath) } catch {
    $null = $root.CreateFolder($FolderPath.TrimStart("\"))  # Create without leading slash
  }
}

function New-TinySocsTaskAction {
  param(
    [Parameter(Mandatory)][string]$ScriptPath,
    [string]$Args = ""
  )
  $ps  = "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe"
  $arg = "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`" $Args".Trim()
  New-ScheduledTaskAction -Execute $ps -Argument $arg
}

function New-TinySocsExeAction {
  param(
    [Parameter(Mandatory)][string]$ExePath,
    [string]$Args = ""
  )
  New-ScheduledTaskAction -Execute $ExePath -Argument $Args
}

function New-TinySocsRepeatTrigger {
  param([Parameter(Mandatory)][int]$EveryMinutes)
  $start = (Get-Date).AddMinutes(1)

  # IMPORTANT: Task Scheduler rejects MaxValue/“infinite”. Use a long but valid duration (10 years).
  $dur = New-TimeSpan -Days 3650

  New-ScheduledTaskTrigger -Once -At $start `
    -RepetitionInterval (New-TimeSpan -Minutes $EveryMinutes) `
    -RepetitionDuration $dur
}

function New-TinySocsDailyTrigger {
  param([Parameter(Mandatory)][string]$At) # "HH:mm"
  $time = [DateTime]::Today.Add([TimeSpan]::Parse($At))
  New-ScheduledTaskTrigger -Daily -At $time
}

function Register-TinySocsTasks {
  $taskPath  = "\TinySocs\"
  $modDir    = "C:\Program Files\TinySocs\modules"
  $binDir    = "C:\Program Files\TinySocs\bin"
  $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

  Ensure-TaskFolder -FolderPath "\TinySocs"

  # Derive heartbeat + retention from env (with sane defaults)
  $hb = 15
  if ($env:HEARTBEAT_MINUTES) {
    [int]::TryParse($env:HEARTBEAT_MINUTES, [ref]$hb) | Out-Null
  }

  $retention = 45
  if ($env:ANCHORS_RETENTION_DAYS) {
    [int]::TryParse($env:ANCHORS_RETENTION_DAYS, [ref]$retention) | Out-Null
  }

  function _RegisterIdempotent([string]$Name, $Action, $Trigger) {
    try {
      Unregister-ScheduledTask -TaskName $Name -TaskPath $taskPath -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
    } catch { }
    $def = New-ScheduledTask -Action $Action -Trigger $Trigger -Principal $principal
    Register-ScheduledTask -TaskName $Name -TaskPath $taskPath -InputObject $def -Force | Out-Null
  }

  # Heartbeat every $hb minutes
  $a1 = New-TinySocsTaskAction -ScriptPath "$modDir\Launch-Master.ps1" `
        -Args ("--window {0}m --deadline 30 --rules auth_failed_burst,ps_script_block" -f $hb)
  $t1 = New-TinySocsRepeatTrigger -EveryMinutes $hb
  _RegisterIdempotent "TinySocsMaster-Heartbeat" $a1 $t1

  # Verify anchors daily 03:10
  $a2 = New-TinySocsExeAction -ExePath "$binDir\TinySocsAnchors.exe" -Args "--ensure"
  $t2 = New-TinySocsDailyTrigger -At "03:10"
  _RegisterIdempotent "TinySocs-VerifyAnchors" $a2 $t2

  # Prune anchors daily 03:15 with retention from env
  $a3 = New-TinySocsExeAction -ExePath "$binDir\TinySocsAnchors.exe" -Args ("--prune --retention-days {0}" -f $retention)
  $t3 = New-TinySocsDailyTrigger -At "03:15"
  _RegisterIdempotent "TinySocs-PruneAnchors" $a3 $t3

  # Rotate queue hourly
  $a4 = New-TinySocsTaskAction -ScriptPath "$modDir\TinySocs.RotateQueue.ps1"
  $t4 = New-TinySocsRepeatTrigger -EveryMinutes 60
  _RegisterIdempotent "TinySocs-RotateQueue" $a4 $t4

  Write-Host "[TinySocs] Tasks created."
}

# ── Environment + pairing ──────────────────────────────────────────────────────
function Set-MachineEnv([hashtable]$Vars){
  foreach($k in $Vars.Keys){
    $v = [string]$Vars[$k]

    # Persisted at machine scope (for future sessions / services)
    [Environment]::SetEnvironmentVariable($k, $v, 'Machine')

    # Also update current process so anything we launch *now*
    # (TinySocsNode.exe, TinySocsMaster.exe, etc.) sees the new values.
    [Environment]::SetEnvironmentVariable($k, $v, 'Process')
  }
  $md='[DllImport("user32.dll")] public static extern IntPtr SendMessageTimeout(IntPtr h,int m,IntPtr w,string l,int f,int t,out IntPtr r);'
  $t=Add-Type -MemberDefinition $md -Name 'W' -Namespace 'U' -PassThru; $z=[intptr]::Zero
  [U.W]::SendMessageTimeout([intptr]0xffff,0x1A,[intptr]0,'Environment',2,5000,[ref]$z) | Out-Null
}

function Pair-TinySocs{
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][ValidateSet('Node','Master')]$Role,
    [Parameter(Mandatory)][string]$SharedSecret,
    [string]$NodePort='8081',
    [string]$SiemUrl='https://localhost:9201',
    [string]$Nodes,
    [int]$AnchorsRetentionDays=45,
    [int]$HeartbeatMinutes=15
  )
  Install-TinySocs

  if($Role -eq 'Node'){
    # Node now shares the same MASTER_SHARED_SECRET as the master.
    Set-MachineEnv @{
      MASTER_SHARED_SECRET = $SharedSecret
      PORT                 = $NodePort
      SIEM_URL             = $SiemUrl
      SIEM_SSL_VERIFY      = 'false'
      PRIVACY_MODE         = 'abstract'
    }

    # Ensure service exists, then update env + restart
    if (-not (Get-Service TinySocsNode -ErrorAction SilentlyContinue)) {
      Register-TinySocsServices
    }

    $n = "C:\Program Files\TinySocs\bin\nssm.exe"
    if (Test-Path $n) {
      # AppEnvironmentExtra carries only non-secret config
      & $n set TinySocsNode AppEnvironmentExtra `
        ("PORT={0};SIEM_URL={1};SIEM_SSL_VERIFY=false;PRIVACY_MODE=abstract" -f $NodePort,$SiemUrl) | Out-Null
      & $n restart TinySocsNode | Out-Null
    }

    Write-Host "[TinySocs] Node paired."
  } else {
    Set-MachineEnv @{
      MASTER_SHARED_SECRET   = $SharedSecret
      TINYSOCS_NODES         = $Nodes
      ALWAYS_ANCHOR          = '0'
      PRIVACY_MODE           = 'abstract'
      MASTER_DEADLINE_SEC    = '30'
      HEARTBEAT_MINUTES      = $HeartbeatMinutes
      ANCHORS_RETENTION_DAYS = $AnchorsRetentionDays
    }

    # Tasks now read their schedule/retention from env
    Register-TinySocsTasks

    Write-Host "[TinySocs] Master paired."
  }
}

function Rotate-TinySocsSecrets([Parameter(Mandatory)][string]$SharedSecret){
  # Single source of truth: MASTER_SHARED_SECRET
  Set-MachineEnv @{
    MASTER_SHARED_SECRET = $SharedSecret
  }

  $n = "C:\Program Files\TinySocs\bin\nssm.exe"
  if (Test-Path $n) {
    try { & $n restart TinySocsNode 2>$null | Out-Null } catch { }
  }

  Write-Host "[TinySocs] Secrets rotated."
}

# ── Uninstall (service, tasks, env, optional data) ─────────────────────────────
function Uninstall-TinySocs {
  [CmdletBinding()]
  param(
    [switch]$KeepData
  )

  $svcName = "TinySocsNode"
  $taskPath = "\TinySocs\"
  $binDir  = "C:\Program Files\TinySocs\bin"
  $appData = "$env:ProgramData\TinySocs"

  Write-Host "[TinySocs] Uninstall starting (KeepData=$KeepData)..."

  # Stop scheduled tasks
  try {
    Get-ScheduledTask -TaskPath $taskPath -ErrorAction SilentlyContinue |
      Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
  } catch { }

  # Stop service
  try {
    Stop-Service $svcName -ErrorAction SilentlyContinue
  } catch { }

  # Remove service via NSSM if we have it; otherwise direct SC delete
  $n = Join-Path $binDir "nssm.exe"
  if (Test-Path $n) {
    try { & $n remove $svcName confirm | Out-Null } catch { }
  } else {
    try { sc.exe delete $svcName | Out-Null } catch { }
  }

  # Kill any stray processes
  try {
    Get-Process TinySocsNode -ErrorAction SilentlyContinue |
      Stop-Process -Force -ErrorAction SilentlyContinue
  } catch { }

  # Clear machine env we know we set
  $vars = @(
    "PORT","NODE_PORT","SIEM_URL","SIEM_SSL_VERIFY",
    "PRIVACY_MODE","NODE_SECRET","MASTER_SHARED_SECRET",
    "TINYSOCS_NODES","HEARTBEAT_MINUTES","ANCHORS_RETENTION_DAYS",
    "ALWAYS_ANCHOR","MASTER_DEADLINE_SEC"
  )
  foreach ($v in $vars) {
    [Environment]::SetEnvironmentVariable($v, $null, 'Machine')
  }

  if (-not $KeepData) {
    try { Remove-Item -Recurse -Force $appData -ErrorAction SilentlyContinue } catch { }
  }

  Write-Host "[TinySocs] Uninstall complete."
}

Export-ModuleMember -Function Install-TinySocs,Register-TinySocsServices,Register-TinySocsTasks,Pair-TinySocs,Rotate-TinySocsSecrets,Uninstall-TinySocs