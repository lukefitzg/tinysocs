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


# ── Credential Manager helpers (TinySocs/Phase7) ──────────────────────────────
# We store secrets as Generic credentials so services and tasks can read them.
# Targets we use:
#   TinySocs/Node/Secret
#   TinySocs/Master/SharedSecret
#   TinySocs/SIEM/Creds
Add-Type -Namespace TinySocs.Security -Name CredNative -MemberDefinition @"
using System;
using System.Runtime.InteropServices;

public static class CredNative
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct CREDENTIAL
    {
        public uint Flags;
        public uint Type;
        public string TargetName;
        public string Comment;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
        public uint CredentialBlobSize;
        public IntPtr CredentialBlob;
        public uint Persist;
        public uint AttributeCount;
        public IntPtr Attributes;
        public string TargetAlias;
        public string UserName;
    }

    [DllImport("advapi32.dll", EntryPoint="CredWriteW", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool CredWrite(ref CREDENTIAL userCredential, uint flags);

    [DllImport("advapi32.dll", EntryPoint="CredReadW", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool CredRead(string target, uint type, uint reservedFlag, out IntPtr credentialPtr);

    [DllImport("advapi32.dll", EntryPoint="CredFree", SetLastError = false)]
    public static extern void CredFree(IntPtr cred);

    [DllImport("advapi32.dll", EntryPoint="CredDeleteW", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool CredDelete(string target, uint type, uint flags);
}
"@

function Set-TSCredential {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][string]$Secret
  )
  $bytes = [System.Text.Encoding]::Unicode.GetBytes($Secret)
  $cred = New-Object TinySocs.Security.CredNative+CREDENTIAL
  $cred.Flags = 0
  $cred.Type  = 1           # CRED_TYPE_GENERIC
  $cred.TargetName = $Name
  $cred.CredentialBlobSize = $bytes.Length
  $cred.Persist = 2         # CRED_PERSIST_LOCAL_MACHINE
  $cred.AttributeCount = 0
  $cred.UserName = "TinySocs"
  $cred.CredentialBlob = [Runtime.InteropServices.Marshal]::AllocHGlobal($bytes.Length)
  [Runtime.InteropServices.Marshal]::Copy($bytes, 0, $cred.CredentialBlob, $bytes.Length)
  try {
    if (-not [TinySocs.Security.CredNative]::CredWrite([ref]$cred, 0)) {
      $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
      throw "CredWrite failed for $Name (Win32 $err)"
    }
  }
  finally {
    if ($cred.CredentialBlob -ne [IntPtr]::Zero) {
      [Runtime.InteropServices.Marshal]::FreeHGlobal($cred.CredentialBlob)
    }
  }
}

function Get-TSCredential {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Name
  )
  $ptr = [IntPtr]::Zero
  try {
    $ok = [TinySocs.Security.CredNative]::CredRead($Name, 1, 0, [ref]$ptr) # CRED_TYPE_GENERIC
    if (-not $ok -or $ptr -eq [IntPtr]::Zero) { return $null }
    $raw = [Runtime.InteropServices.Marshal]::PtrToStructure($ptr, [Type][TinySocs.Security.CredNative+CREDENTIAL])
    if ($raw.CredentialBlobSize -le 0 -or $raw.CredentialBlob -eq [IntPtr]::Zero) { return $null }
    $bytes = New-Object byte[] $raw.CredentialBlobSize
    [Runtime.InteropServices.Marshal]::Copy($raw.CredentialBlob, $bytes, 0, $raw.CredentialBlobSize)
    return [System.Text.Encoding]::Unicode.GetString($bytes)
  }
  finally {
    if ($ptr -ne [IntPtr]::Zero) {
      [TinySocs.Security.CredNative]::CredFree($ptr)
    }
  }
}

function Remove-TSCredential {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Name
  )
  [TinySocs.Security.CredNative]::CredDelete($Name, 1, 0) | Out-Null
}

function Set-TinySocsSiemCredential {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$SiemUrl,
    [Parameter(Mandatory)][string]$SiemUser,
    [Parameter(Mandatory)][string]$SiemPass,
    [bool]$SiemSslVerify = $true
  )

  # Normalise URL a bit (no trailing slash noise)
  $normUrl = $SiemUrl.TrimEnd('/')

  $payload = @{
    url       = $normUrl
    user      = $SiemUser
    pass      = $SiemPass
    sslVerify = $SiemSslVerify
  } | ConvertTo-Json -Compress

  # Write to CredMan as authoritative store
  Set-TSCredential -Name 'TinySocs/SIEM/Creds' -Secret $payload

  # Mirror into machine/env for compatibility + non-CredMan paths
  $verifyString = if ($SiemSslVerify) { 'true' } else { 'false' }

  Set-MachineEnv @{
    SIEM_URL        = $normUrl
    SIEM_USER       = $SiemUser
    SIEM_PASS       = $SiemPass
    SIEM_SSL_VERIFY = $verifyString
  }

  Write-Host "[TinySocs] SIEM credentials stored in CredMan and env (url=$normUrl, sslVerify=$verifyString)."
}

# ── Service via NSSM ────────────────────────────────────────────────────────────
...
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

  Write-Host "[TinySocs] Node service registered."
}

function Register-TinySocsServices {
  Register-TinySocsNodeService
}

# ── Scheduled tasks (Master, Anchors, Queue rotation) ──────────────────────────
...
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

  function _RegisterIdempotent(
    [string]$TaskName,
    [scriptblock]$ActionFactory,
    [Microsoft.Win32.TaskScheduler.TaskTrigger]$Trigger
  ) {
    try {
      $existing = Get-ScheduledTask -TaskPath "\TinySocs\" -TaskName $TaskName -ErrorAction SilentlyContinue
      if ($existing) {
        Unregister-ScheduledTask -TaskName $TaskName -TaskPath "\TinySocs\" -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
      }
    } catch { }

    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
    $settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 60)

    $action = & $ActionFactory
    $task = New-ScheduledTask -Action $action -Trigger $Trigger -Principal $principal -Settings $settings
    Register-ScheduledTask -TaskName $TaskName -TaskPath "\TinySocs\" -InputObject $task -Force | Out-Null
  }

  # Heartbeat: TinySocsMaster every $hb minutes
  $masterScript = "C:\Program Files\TinySocs\modules\Launch-Master.ps1"
  $masterArgs   = "-window 15m -deadline 30 -rules 'auth_failed_burst,ps_script_block'"
  $masterTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes $hb) -RepetitionDuration ([TimeSpan]::MaxValue)
  _RegisterIdempotent -TaskName "TinySocsHeartbeat" -ActionFactory {
    New-TinySocsTaskAction -ScriptPath $masterScript -Args $masterArgs
  } -Trigger $masterTrigger

  # Anchors ensure + prune (daily)
  $anchorsScript = "C:\Program Files\TinySocs\modules\Launch-Anchors.ps1"
  $ensureTrigger  = New-ScheduledTaskTrigger -Daily -At 02:00
  _RegisterIdempotent -TaskName "TinySocsAnchorsEnsure" -ActionFactory {
    New-TinySocsTaskAction -ScriptPath $anchorsScript -Args "-Ensure"
  } -Trigger $ensureTrigger

  $pruneTrigger = New-ScheduledTaskTrigger -Daily -At 03:00
  _RegisterIdempotent -TaskName "TinySocsAnchorsPrune" -ActionFactory {
    New-TinySocsTaskAction -ScriptPath $anchorsScript -Args ("-Prune -RetentionDays {0}" -f $retention)
  } -Trigger $pruneTrigger

  # Queue rotation (hourly)
  $rotateScript = "C:\Program Files\TinySocs\modules\TinySocs.RotateQueue.ps1"
  $rotateTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5) -RepetitionInterval (New-TimeSpan -Hours 1) -RepetitionDuration ([TimeSpan]::MaxValue)
  _RegisterIdempotent -TaskName "TinySocsRotateQueue" -ActionFactory {
    New-TinySocsTaskAction -ScriptPath $rotateScript -Args ""
  } -Trigger $rotateTrigger

  Write-Host "[TinySocs] Scheduled tasks registered."
}

function Register-TinySocsTasks {
  New-TinySocsTasks
}

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

    # Node-ish knobs
    [string]$NodePort='8081',

    # SIEM connection (URL is shared by node+master; creds are usually master-only)
    [string]$SiemUrl='https://localhost:9201',
    [string]$SiemUser,
    [string]$SiemPass,
    [bool]  $SiemSslVerify = $false,

    # Master knobs
    [string]$Nodes,
    [int]$AnchorsRetentionDays=45,
    [int]$HeartbeatMinutes=15
  )
  Install-TinySocs

  if($Role -eq 'Node'){
    # Store shared secret in CredMan for the node
    Set-TSCredential -Name 'TinySocs/Node/Secret' -Secret $SharedSecret

    $verifyString = if ($SiemSslVerify) { 'true' } else { 'false' }

    # Node shares the same MASTER_SHARED_SECRET as the master and talks to SIEM directly
    Set-MachineEnv @{
      MASTER_SHARED_SECRET = $SharedSecret
      PORT                 = $NodePort
      SIEM_URL             = $SiemUrl.TrimEnd('/')
      SIEM_SSL_VERIFY      = $verifyString
      PRIVACY_MODE         = 'abstract'
    }

    # Ensure service exists, then restart to pick up env
    if (-not (Get-Service TinySocsNode -ErrorAction SilentlyContinue)) {
      Register-TinySocsServices
    }

    $n = "C:\Program Files\TinySocs\bin\nssm.exe"
    if (Test-Path $n) {
      try { & $n restart TinySocsNode 2>$null | Out-Null } catch { }
    }

    Write-Host "[TinySocs] Node paired: PORT=$NodePort SIEM_URL=$SiemUrl"
    return
  }

  if($Role -eq 'Master'){
    # Store shared secret for the master
    Set-TSCredential -Name 'TinySocs/Master/SharedSecret' -Secret $SharedSecret

    # Nodes list can live in env/config; not strictly secret
    if (-not $Nodes) {
      # Default to local node if none supplied
      $Nodes = "http://127.0.0.1:$NodePort"
    }

    # If SIEM creds are provided, write them via helper (CredMan + env)
    if ($SiemUser -and $SiemPass) {
      Set-TinySocsSiemCredential -SiemUrl $SiemUrl -SiemUser $SiemUser -SiemPass $SiemPass -SiemSslVerify:$SiemSslVerify
    } else {
      # Still at least set URL + verify flag in env
      $verifyString = if ($SiemSslVerify) { 'true' } else { 'false' }
      Set-MachineEnv @{
        SIEM_URL        = $SiemUrl.TrimEnd('/')
        SIEM_SSL_VERIFY = $verifyString
      }
    }

    Set-MachineEnv @{
      MASTER_SHARED_SECRET   = $SharedSecret
      TINYSOCS_NODES         = $Nodes
      HEARTBEAT_MINUTES      = $HeartbeatMinutes
      ANCHORS_RETENTION_DAYS = $AnchorsRetentionDays
    }

    # Tasks read schedule + retention from env
    Register-TinySocsTasks

    Write-Host "[TinySocs] Master paired: NODES=$Nodes SIEM_URL=$SiemUrl HEARTBEAT=$HeartbeatMinutes RETENTION=$AnchorsRetentionDays"
  }
}

function Rotate-TinySocsSecrets([Parameter(Mandatory)][string]$SharedSecret){
  # Single source of truth now lives in CredMan, env is just delivery.
  Set-TSCredential -Name 'TinySocs/Node/Secret'           -Secret $SharedSecret
  Set-TSCredential -Name 'TinySocs/Master/SharedSecret'   -Secret $SharedSecret

  Set-MachineEnv @{
    MASTER_SHARED_SECRET = $SharedSecret
  }

  $n = "C:\Program Files\TinySocs\bin\nssm.exe"
  if (Test-Path $n) {
    try { & $n restart TinySocsNode 2>$null | Out-Null } catch { }
  }

  Write-Host "[TinySocs] Secrets rotated (CredMan + env)."
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

  # Best-effort cleanup of stored credentials
  try {
    Remove-TSCredential -Name 'TinySocs/Node/Secret'
    Remove-TSCredential -Name 'TinySocs/Master/SharedSecret'
    Remove-TSCredential -Name 'TinySocs/SIEM/Creds'
  } catch { }

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