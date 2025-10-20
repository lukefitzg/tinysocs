<# model_toggles.ps1 -----------------------------------------------------------
LLM toggles + SIEM target toggles + backend helpers for TinySOCS.
Dot-source this file in your PowerShell session, e.g.:
  PS> Set-Location C:\tinysocs\tinysocs
  PS> . .\model_toggles.ps1
Nothing auto-runs when dot-sourced.

Phase 3: Logstash removed. Winlogbeat ships directly to OpenSearch.
-------------------------------------------------------------------------------#>

# ========================= LLM (model) toggles =========================
function Use-OpenAI {
  $env:LLM_MODE = "openai"
  Remove-Item Env:OFFLINE_LLM_URL, Env:OFFLINE_LLM_MODEL -ErrorAction SilentlyContinue
  Write-Host "[TinySOCS] Using OpenAI (cloud) mode."
}

function Use-Ollama {
  param(
    [string]$Url   = "http://localhost:11434",
    [string]$Model = "qwen2.5:0.5b-instruct"
  )
  $env:LLM_MODE          = "ollama"
  $env:OFFLINE_LLM_URL   = $Url
  $env:OFFLINE_LLM_MODEL = $Model
  Write-Host ("[TinySOCS] Using Ollama (local) mode -> {0} ({1})" -f $Url, $Model)
}

# ========================= Import .env variables =========================
function Import-DotEnv {
  param([string]$Path = ".env")
  if (!(Test-Path $Path)) { return }
  Get-Content $Path | ForEach-Object {
    $line = $_.Trim()
    if ($line -eq "" -or $line.StartsWith("#")) { return }

    $eq = $line.IndexOf("=")
    if ($eq -lt 1) { return }
    $name  = $line.Substring(0,$eq).Trim()
    $value = $line.Substring($eq+1).Trim()

    if ($value.StartsWith('"') -and $value.EndsWith('"')) { $value = $value.Substring(1, $value.Length-2) }
    elseif ($value.StartsWith("'") -and $value.EndsWith("'")) { $value = $value.Substring(1, $value.Length-2) }

    if (-not [string]::IsNullOrWhiteSpace($name)) {
      Set-Item -Path ("Env:{0}" -f $name) -Value $value
    }
  }
}

# ===================== SIEM target (what detections hit) =====================
function Use-ElasticSIEM {
  # Kept for legacy/testing, but not used in Phase 3 by default
  $env:SIEM_BACKEND = "elasticsearch"
  $env:SIEM_URL     = "http://localhost:9200"
  Remove-Item Env:SIEM_USER, Env:SIEM_PASS, Env:SIEM_SSL_VERIFY -ErrorAction SilentlyContinue
  Write-Host ("[TinySOCS] Detections will query Elasticsearch @ {0}" -f $env:SIEM_URL)
}

function Use-OpenSearchSIEM {
  param(
    [string]$Url  = "https://127.0.0.1:9201",
    [string]$User = "admin",
    [string]$Pass = $env:OPENSEARCH_INITIAL_ADMIN_PASSWORD
  )
  if (-not $Pass -or $Pass -eq "") { $Pass = "ChangeMe123!" } # dev default

  $env:SIEM_BACKEND   = "opensearch"
  $env:SIEM_URL       = $Url
  $env:SIEM_USER      = $User
  $env:SIEM_PASS      = $Pass
  $env:SIEM_SSL_VERIFY = "false"   # self-signed in dev

  if (-not $env:OPENSEARCH_INITIAL_ADMIN_PASSWORD) {
    $env:OPENSEARCH_INITIAL_ADMIN_PASSWORD = $Pass
  }

  Write-Host ("[TinySOCS] Detections will query OpenSearch @ {0} (ssl verify={1})" -f $Url, $env:SIEM_SSL_VERIFY)
}

# ===================== Docker readiness & helpers =====================
function Test-DockerReady {
  try { $null = docker version --format '{{.Server.Version}}' 2>$null; return $LASTEXITCODE -eq 0 }
  catch { return $false }
}

function Start-DockerDesktop {
  try { & "$env:ProgramFiles\Docker\Docker\Docker Desktop.exe" | Out-Null } catch {}
  $max = [DateTime]::UtcNow.AddMinutes(3)
  while (-not (Test-Path \\.\pipe\docker_engine) -and -not (Test-Path \\.\pipe\dockerDesktopLinuxEngine)) {
    if ([DateTime]::UtcNow -gt $max) { return $false }
    Start-Sleep 2
  }
  return $true
}

function Restart-DockerDesktop {
  Write-Host "[TinySOCS] Restarting Docker Desktop backend..." -ForegroundColor Yellow
  try { wsl --shutdown | Out-Null } catch {}
  try { Stop-Service com.docker.service -Force -ErrorAction SilentlyContinue } catch {}
  Start-Sleep 2
  try { Start-Service com.docker.service -ErrorAction SilentlyContinue } catch {}
  if (-not (Start-DockerDesktop)) {
    Write-Warning "[TinySOCS] Docker Desktop start timed out."
    return $false
  }
  return (Test-DockerReady)
}

function Ensure-DockerReady {
  if (Test-DockerReady) { return $true }
  Write-Warning "[TinySOCS] Docker engine not available. Attempting to start Docker Desktop..."
  if (-not (Start-DockerDesktop)) {
    Write-Warning "[TinySOCS] Initial start failed, trying full restart..."
    if (-not (Restart-DockerDesktop)) { return $false }
  }
  return (Test-DockerReady)
}

function Wait-ContainerHealthy {
  param(
    [Parameter(Mandatory=$true)][string]$Name,
    [int]$TimeoutSec = 180
  )
  $sw = [Diagnostics.Stopwatch]::StartNew()
  while ($sw.Elapsed.TotalSeconds -lt $TimeoutSec) {
    $status = (docker inspect --format '{{.State.Health.Status}}' $Name 2>$null)
    if ($status -eq 'healthy') { return $true }
    if (-not $status) { Start-Sleep 2; continue }
    Start-Sleep 2
  }
  return $false
}

function Invoke-ComposeSafe {
  param(
    [Parameter(Mandatory=$true)][string[]]$Args,
    [int]$Retries = 1
  )
  if (-not (Ensure-DockerReady)) { throw "[TinySOCS] Docker engine not available." }

  $out = & docker compose @Args 2>&1
  $txt = ($out | Out-String)
  $bad = ($LASTEXITCODE -ne 0) -or ($txt -match "dockerDesktopLinuxEngine") -or ($txt -match "500 Internal Server Error")

  if ($bad) {
    if ($Retries -gt 0) {
      Write-Warning "[TinySOCS] docker compose failed; restarting Docker and retrying once..."
      if (-not (Restart-DockerDesktop)) { throw "[TinySOCS] Docker restart failed." }
      return Invoke-ComposeSafe -Args $Args -Retries ($Retries - 1)
    }
    Write-Host $txt
    throw "[TinySOCS] docker compose failed"
  }
  return $out
}

# ===================== Backend stacks (no Logstash in Phase 3) =====================
function Start-OpenSearchStack {
  param([switch]$Dashboards)
  Write-Host "[TinySOCS] Starting OpenSearch (no Logstash)..." -ForegroundColor DarkCyan

  Invoke-ComposeSafe -Args @("up","-d","opensearch") | Out-Null
  if (-not (Wait-ContainerHealthy -Name 'ts-opensearch' -TimeoutSec 240)) { throw "ts-opensearch did not become healthy" }

  if ($Dashboards) { Invoke-ComposeSafe -Args @("up","-d","opensearch-dashboards") | Out-Null }
  else { Invoke-ComposeSafe -Args @("stop","opensearch-dashboards") | Out-Null }

  Write-Host "[TinySOCS] OpenSearch is healthy." -ForegroundColor Green
}

function Stop-OpenSearchStack {
  Write-Host "[TinySOCS] Stopping OpenSearch stack..." -ForegroundColor DarkCyan
  if (-not (Ensure-DockerReady)) { Write-Warning "[TinySOCS] Docker offline; skipping."; return }
  Invoke-ComposeSafe -Args @("stop","opensearch","opensearch-dashboards") | Out-Null
}

# Legacy Elastic helpers (kept for completeness; not used by default)
function Start-ElasticStack {
  param([switch]$Kibana)
  Write-Host "[TinySOCS] Starting Elasticsearch (no Logstash path here)..." -ForegroundColor DarkCyan
  Invoke-ComposeSafe -Args @("up","-d","elasticsearch") | Out-Null
  if ($Kibana) { Invoke-ComposeSafe -Args @("up","-d","kibana") | Out-Null }
  Write-Host "[TinySOCS] Elasticsearch request issued." -ForegroundColor Green
}

function Stop-ElasticStack {
  Write-Host "[TinySOCS] Stopping Elastic stack..." -ForegroundColor DarkCyan
  if (-not (Ensure-DockerReady)) { Write-Warning "[TinySOCS] Docker offline; skipping."; return }
  $null = Invoke-ComposeSafe -Args @("stop","-t","5","elasticsearch","kibana")
  $running = (docker ps --format "{{.Names}}" 2>$null) -join ','
  if ($running -match "ts-es" -or $running -match "ts-kibana") {
    Write-Warning "[TinySOCS] Force-killing lingering Elastic containers"
    $null = Invoke-ComposeSafe -Args @("kill","elasticsearch","kibana")
    $null = Invoke-ComposeSafe -Args @("rm","-f","elasticsearch","kibana")
  }
  Write-Host "[TinySOCS] Elastic stack stopped." -ForegroundColor Green
}

# ===================== Test noise generators (messages updated) =====================
function New-EncodedCommand {
  param([Parameter(Mandatory=$true)][string]$Command)
  $bytes = [Text.Encoding]::Unicode.GetBytes($Command)
  return [Convert]::ToBase64String($bytes)
}

function Invoke-Noise-PSScriptBlock {
  try {
    $cmd = 'Write-Host "TinySOCS ScriptBlock test"'
    $enc = New-EncodedCommand -Command "Invoke-Expression '$cmd'"
    Start-Process -FilePath powershell.exe -ArgumentList '-NoProfile','-EncodedCommand', $enc -WindowStyle Hidden -Wait
    Write-Host "[TinySOCS] Generated PowerShell ScriptBlock (4104)" -ForegroundColor Green
  } catch { Write-Warning ("[TinySOCS] PSScriptBlock generation failed: {0}" -f $_.Exception.Message) }
}

function Invoke-Noise-SuspiciousPS {
  try {
    $inner = 'Write-Host "TinySOCS suspicious PS flags"'
    $enc = New-EncodedCommand -Command $inner
    Start-Process -FilePath powershell.exe -ArgumentList '-NoProfile','-EncodedCommand', $enc -WindowStyle Hidden -Wait
    Write-Host "[TinySOCS] Generated suspicious PowerShell process (-NoProfile -EncodedCommand)" -ForegroundColor Green
  } catch { Write-Warning ("[TinySOCS] Suspicious PowerShell generation failed: {0}" -f $_.Exception.Message) }
}

function Invoke-Noise-LOLBins {
  try { Start-Process -FilePath mshta.exe -ArgumentList 'javascript:close()' -WindowStyle Hidden -Wait } catch { Write-Warning ("[TinySOCS] mshta.exe failed: {0}" -f $_.Exception.Message) }
  try { Start-Process -FilePath rundll32.exe -ArgumentList 'shell32.dll,Control_RunDLL' -WindowStyle Hidden -Wait } catch { Write-Warning ("[TinySOCS] rundll32.exe failed: {0}" -f $_.Exception.Message) }
  Write-Host "[TinySOCS] Generated LOLBIN executions (mshta, rundll32)" -ForegroundColor Green
}

function Invoke-Noise-SysmonBurst {
  param([int]$Count = 12)
  for ($i=0; $i -lt $Count; $i++) {
    try { Start-Process -FilePath cmd.exe -ArgumentList '/c','echo TinySOCS sysmon burst' -WindowStyle Hidden -Wait } catch { Write-Warning ("[TinySOCS] Sysmon burst iteration {0} failed: {1}" -f $i, $_.Exception.Message) }
  }
  Write-Host ("[TinySOCS] Generated Sysmon process-creation burst x{0}" -f $Count) -ForegroundColor Green
}

function Invoke-Noise-AuthFailed4625 {
  param(
    [string]$TargetHost,
    [string]$UserName,
    [int]$Attempts = 6
  )
  if (-not $TargetHost -or -not $UserName) {
    Write-Warning "[TinySOCS] Skipping 4625 noise (TargetHost/UserName not provided)."
    return
  }
  Write-Warning ("[TinySOCS] Generating 4625 failed logons to \\{0} as {1} (Attempts={2}). Ensure this won't lock out the account." -f $TargetHost,$UserName,$Attempts)
  for ($i=0; $i -lt $Attempts; $i++) {
    try {
      cmd.exe /c "net use \\$TargetHost\IPC$ /user:$UserName WrongPassword$i" | Out-Null
      Start-Sleep -Milliseconds 300
    } catch { Write-Warning ("[TinySOCS] 4625 attempt {0} failed to execute: {1}" -f $i, $_.Exception.Message) }
  }
  Write-Host ("[TinySOCS] Attempted {0} failed network logons (4625)." -f $Attempts) -ForegroundColor Green
}

function Invoke-TinySOCS-TestNoise {
  param(
    [switch]$All,
    [switch]$ScriptBlock,
    [switch]$SuspiciousPS,
    [switch]$LOLBins,
    [switch]$SysmonBurst,
    [int]$SysmonCount = 12,
    [switch]$IncludeAuthFailed,
    [string]$AuthTargetHost,
    [string]$AuthUserName,
    [int]$AuthAttempts = 6
  )

  if (-not ($All -or $ScriptBlock -or $SuspiciousPS -or $LOLBins -or $SysmonBurst -or $IncludeAuthFailed)) {
@"
[TinySOCS] Nothing selected. Examples:
  Invoke-TinySOCS-TestNoise -All
  Invoke-TinySOCS-TestNoise -ScriptBlock -SuspiciousPS -LOLBins
  Invoke-TinySOCS-TestNoise -SysmonBurst -SysmonCount 15
"@ | Write-Host
    return
  }

  if ($All) { $ScriptBlock=$true; $SuspiciousPS=$true; $LOLBins=$true; $SysmonBurst=$true }

  if ($ScriptBlock)  { Invoke-Noise-PSScriptBlock }
  if ($SuspiciousPS) { Invoke-Noise-SuspiciousPS }
  if ($LOLBins)      { Invoke-Noise-LOLBins }
  if ($SysmonBurst)  { Invoke-Noise-SysmonBurst -Count $SysmonCount }
  if ($IncludeAuthFailed) {
    Invoke-Noise-AuthFailed4625 -TargetHost $AuthTargetHost -UserName $AuthUserName -Attempts $AuthAttempts
  }

  Write-Host "[TinySOCS] Noise generation complete. Winlogbeat ships directly to OpenSearch." -ForegroundColor Cyan
}

# ===================== Agent prerequisites (unchanged core) =========
$Global:TinySOCS_WinlogbeatDir  = "C:\Program Files\Winlogbeat"
$Global:TinySOCS_WinlogbeatData = "C:\ProgramData\winlogbeat"

function Resolve-NormalPath([string]$p) {
  if (-not $p) { return "" }
  try { return ([IO.Path]::GetFullPath($p)).TrimEnd('\').ToLowerInvariant() }
  catch { return ($p.TrimEnd('\').ToLowerInvariant()) }
}

function Get-TinySOCSLogPath {
  $dir = "C:\tinysocs\tinysocs\logs"
  try { New-Item -ItemType Directory -Path $dir -Force | Out-Null } catch {}
  return (Join-Path $dir ("setup-{0}.log" -f (Get-Date).ToString("yyyyMMdd-HHmmss")))
}

function Test-IsAdmin {
  try {
    $wi = [Security.Principal.WindowsIdentity]::GetCurrent()
    $wp = New-Object Security.Principal.WindowsPrincipal($wi)
    return $wp.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  } catch { return $false }
}

function Ensure-AdminOrRelaunch {
  param(
    [Parameter(Mandatory=$true)][string]$PostCommand,
    [switch]$NoExit
  )
  if (Test-IsAdmin) { return $true }

  $logPath = Get-TinySOCSLogPath
  Write-Host "[TinySOCS] Elevation required; relaunching as Administrator..." -ForegroundColor Yellow
  Write-Host ("[TinySOCS] Transcript will be saved to: {0}" -f $logPath) -ForegroundColor Yellow

  $tmpDir  = "C:\tinysocs\tinysocs\logs"
  try { New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null } catch {}
  $tmpFile = Join-Path $tmpDir ("elev-{0}.ps1" -f (Get-Date).ToString("yyyyMMdd-HHmmss"))

  $content = @'
Start-Transcript -Path "__LOG__" -Append | Out-Null
try {
  Set-Location 'C:\tinysocs\tinysocs'
  . '.\model_toggles.ps1'
  $ErrorActionPreference = 'Continue'
  $ProgressPreference    = 'SilentlyContinue'
  $VerbosePreference     = 'SilentlyContinue'
  if ($PSStyle -and $PSStyle.PSObject.Properties['OutputRendering']) { $PSStyle.OutputRendering = 'Ansi' }
  Write-Host "[TinySOCS] Elevated session ready. Running: __CMD__" -ForegroundColor Cyan

  $global:TinySOCS_LogPath = "__LOG__"
  __CMD__
}
catch {
  Write-Error ("[TinySOCS] Unhandled error in elevated session: {0}" -f $_.Exception.Message)
  if ($_.ScriptStackTrace) { Write-Error $_.ScriptStackTrace }
}
finally {
  try { Stop-Transcript | Out-Null } catch {}
}
'@

  $content = $content.Replace("__LOG__", $logPath).Replace("__CMD__", $PostCommand)
  Set-Content -Path $tmpFile -Value $content -Encoding UTF8

  $args = @('-NoProfile','-ExecutionPolicy','Bypass','-File', $tmpFile)
  if ($NoExit) { $args = @('-NoExit') + $args }

  Start-Process -FilePath "powershell.exe" -Verb RunAs -ArgumentList $args -Wait
  Write-Host ("[TinySOCS] Elevated command finished. Log: {0}" -f $logPath) -ForegroundColor Yellow
  return $false
}

# -------- Helpers (unchanged) --------
function Get-ExePathFromServicePathName {
  param([Parameter(Mandatory=$true)][string]$PathName)
  $s = $PathName.Trim()
  if ($s.StartsWith('"')) {
    $second = $s.IndexOf('"',1)
    if ($second -gt 1) { return $s.Substring(1, $second-1) }
  }
  $sp = $s.IndexOf(' ')
  if ($sp -gt 0) { return $s.Substring(0,$sp) }
  return $s
}

function Stop-And-Delete-ServiceSafely {
  param(
    [Parameter(Mandatory=$true)][string]$Name,
    [int]$TimeoutSec = 20
  )
  try {
    $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq 'Running') {
      Write-Warning ("Waiting for service '{0}' to stop..." -f $Name)
      try { Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue } catch {}
      $deadline = (Get-Date).AddSeconds($TimeoutSec)
      while ($svc.Status -ne 'Stopped' -and (Get-Date) -lt $deadline) {
        Start-Sleep -Milliseconds 500
        try { $svc.Refresh() } catch {}
      }
    }
  } catch {}
  try { sc.exe delete $Name | Out-Null } catch {}
}

# -------- Winlogbeat singleton helpers (trimmed messages) --------
function Stop-OtherWinlogbeatInstances {
  param([string]$TargetDir = $Global:TinySOCS_WinlogbeatDir)

  $targetNorm = Resolve-NormalPath $TargetDir

  try {
    $procs = Get-CimInstance Win32_Process -Filter "Name='winlogbeat.exe'" -ErrorAction SilentlyContinue
    foreach ($p in ($procs | ForEach-Object { [pscustomobject]@{ Id=$_.ProcessId; Path=$_.ExecutablePath } })) {
      $pNorm = Resolve-NormalPath (Split-Path ($p.Path) -Parent)
      if ($pNorm -and $pNorm -ne $targetNorm) {
        Write-Warning ("[TinySOCS] Stopping foreign Winlogbeat process (PID {0}) @ {1}" -f $p.Id, $p.Path)
        try { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } catch { Write-Warning $_.Exception.Message }
      }
    }
  } catch { Write-Warning ("[TinySOCS] Process probe failed: {0}" -f $_.Exception.Message) }

  try {
    $svcs = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match '(?i)winlogbeat' -or ($_.PathName -match 'winlogbeat\.exe') }

    foreach ($svc in ($svcs | Sort-Object Name -Unique)) {
      if ($svc.Name -eq 'winlogbeat') { continue }
      $exePath = Get-ExePathFromServicePathName -PathName $svc.PathName
      $svcDir  = Resolve-NormalPath (Split-Path $exePath -Parent)
      if ($svcDir -and $svcDir -ne $targetNorm) {
        Write-Warning ("[TinySOCS] Removing foreign Winlogbeat service '{0}'" -f $svc.Name)
        Stop-And-Delete-ServiceSafely -Name $svc.Name -TimeoutSec 20
      }
    }
  } catch { Write-Warning ("[TinySOCS] Service probe failed: {0}" -f $_.Exception.Message) }

  try {
    $tasks = Get-ScheduledTask -TaskName *winlogbeat* -ErrorAction SilentlyContinue
    foreach ($t in $tasks) {
      Write-Warning ("[TinySOCS] Removing scheduled task '{0}' related to winlogbeat" -f $t.TaskName)
      try { Unregister-ScheduledTask -TaskName $t.TaskName -Confirm:$false } catch { Write-Warning $_.Exception.Message }
    }
  } catch {}
}

function Stop-WinlogbeatConsoleFromDir {
  param([string]$TargetDir = $Global:TinySOCS_WinlogbeatDir, [int]$WaitSec = 10)
  $targetNorm = Resolve-NormalPath $TargetDir
  try {
    $procs = Get-CimInstance Win32_Process -Filter "Name='winlogbeat.exe'" -ErrorAction SilentlyContinue
    $killed = @()
    foreach ($p in $procs) {
      $dir = Resolve-NormalPath (Split-Path $p.ExecutablePath -Parent)
      if ($dir -eq $targetNorm) {
        Write-Warning ("[TinySOCS] Killing lingering console winlogbeat (PID {0}) @ {1}" -f $p.ProcessId, $p.ExecutablePath)
        try { Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue } catch { Write-Warning $_.Exception.Message }
        $killed += $p.ProcessId
      }
    }
    if ($killed.Count -gt 0) {
      $deadline = (Get-Date).AddSeconds($WaitSec)
      do {
        Start-Sleep -Milliseconds 300
        $still = Get-Process -Id $killed -ErrorAction SilentlyContinue
      } while ($still -and (Get-Date) -lt $deadline)
      Start-Sleep -Milliseconds 500
    }
  } catch { Write-Warning ("[TinySOCS] Probe/kill console winlogbeat failed: {0}" -f $_.Exception.Message) }
}

function Remove-WinlogbeatStaleLock {
  param([string]$DataPath = $Global:TinySOCS_WinlogbeatData)
  try {
    $lock = Join-Path $DataPath 'winlogbeat.lock'
    if (-not (Test-Path $lock)) { return }

    # Try exclusive open; if it fails, the lock is genuinely in use.
    $fs = $null
    try {
      $fs = [System.IO.File]::Open($lock, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
    } catch {
      Write-Host "[TinySOCS] winlogbeat.lock appears to be in use; leaving it." -ForegroundColor DarkYellow
      return
    } finally {
      if ($fs) { $fs.Close() }
    }

    Write-Warning "[TinySOCS] Removing stale winlogbeat.lock"
    Remove-Item -Path $lock -Force -ErrorAction SilentlyContinue
  } catch {
    Write-Warning ("[TinySOCS] Failed to evaluate/remove winlogbeat.lock: {0}" -f $_.Exception.Message)
  }
}

function Install-Winlogbeat {
  param(
    [string]$Version    = "8.14.3",
    [string]$InstallDir = $Global:TinySOCS_WinlogbeatDir
  )

  if (Test-Path (Join-Path $InstallDir "winlogbeat.exe")) {
    Write-Host ("[TinySOCS] Winlogbeat already installed at {0}" -f $InstallDir) -ForegroundColor Green
    return
  }

  try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

  $arch = if ([Environment]::Is64BitOperatingSystem) { "windows-x86_64" } else { "windows-x86" }
  $zip  = "winlogbeat-$Version-$arch.zip"
  $url  = "https://artifacts.elastic.co/downloads/beats/winlogbeat/$zip"
  $tmp  = Join-Path $env:TEMP $zip

  Write-Host ("[TinySOCS] Downloading Winlogbeat {0} ({1})..." -f $Version, $arch) -ForegroundColor DarkCyan
  Invoke-WebRequest -Uri $url -OutFile $tmp -UseBasicParsing

  Write-Host ("[TinySOCS] Extracting to {0}..." -f $InstallDir) -ForegroundColor DarkCyan
  Expand-Archive -Path $tmp -DestinationPath $env:TEMP -Force
  New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
  Copy-Item -Path (Join-Path $env:TEMP "winlogbeat-$Version-$arch\*") -Destination $InstallDir -Recurse -Force

  # Ensure runtime dirs exist so the service can start cleanly
  New-Item -ItemType Directory -Path $Global:TinySOCS_WinlogbeatData -Force | Out-Null
  New-Item -ItemType Directory -Path (Join-Path $Global:TinySOCS_WinlogbeatData "logs") -Force | Out-Null
  New-Item -ItemType Directory -Path (Join-Path $InstallDir "data") -Force | Out-Null

  # Minimal config -> OpenSearch direct (Phase 3 default)
  $pass = if ($env:OPENSEARCH_INITIAL_ADMIN_PASSWORD) { $env:OPENSEARCH_INITIAL_ADMIN_PASSWORD } else { "ChangeMe123!" }
  $yml = @"
winlogbeat.event_logs:
  - name: Security
  - name: System
  - name: Application
  - name: Microsoft-Windows-Sysmon/Operational
  - name: Microsoft-Windows-PowerShell/Operational

output.elasticsearch:
  hosts: ["https://127.0.0.1:9201"]
  username: "admin"
  password: "$pass"
  ssl.verification_mode: none
  allow_older_versions: true

setup.ilm.enabled: false
"@
  $yml | Set-Content -Path (Join-Path $InstallDir "winlogbeat.yml") -Encoding UTF8
}

function Install-Or-Repair-WinlogbeatService {
  param([string]$InstallDir = $Global:TinySOCS_WinlogbeatDir)

  $targetNorm = Resolve-NormalPath $InstallDir
  $svcWmi = Get-CimInstance Win32_Service -Filter "Name='winlogbeat'" -ErrorAction SilentlyContinue

  if ($svcWmi) {
    $currExe = Get-ExePathFromServicePathName -PathName $svcWmi.PathName
    $currDir = Resolve-NormalPath (Split-Path $currExe -Parent)
    if ($currDir -ne $targetNorm) {
      Write-Warning ("[TinySOCS] 'winlogbeat' service points to '{0}' not '{1}' - replacing it." -f $currDir, $targetNorm)
      Stop-And-Delete-ServiceSafely -Name winlogbeat -TimeoutSec 20
      $svcWmi = $null
    } else {
      Write-Host "[TinySOCS] Existing 'winlogbeat' service already points to TinySOCS path; keeping it." -ForegroundColor Green
    }
  }

  $binPath = ('"{0}\winlogbeat.exe" --environment=windows_service -c "{0}\winlogbeat.yml" --path.home "{0}" --path.data "{1}" --path.logs "{1}\logs"' -f $InstallDir, $Global:TinySOCS_WinlogbeatData)

  if (-not $svcWmi) {
    sc.exe create winlogbeat binPath= $binPath start= auto | Out-Null
    sc.exe description winlogbeat "Winlogbeat (TinySOCS-managed)" | Out-Null
  } else {
    try { sc.exe config winlogbeat start= auto | Out-Null } catch {}
    try { sc.exe config winlogbeat binPath= $binPath | Out-Null } catch {}
  }

  New-Item -ItemType Directory -Path $Global:TinySOCS_WinlogbeatData -Force | Out-Null
  New-Item -ItemType Directory -Path (Join-Path $Global:TinySOCS_WinlogbeatData "logs") -Force | Out-Null
  New-Item -ItemType Directory -Path (Join-Path $InstallDir "data") -Force | Out-Null

  $exe = Join-Path $InstallDir "winlogbeat.exe"
  $yml = Join-Path $InstallDir "winlogbeat.yml"
  Write-Host "[TinySOCS] Validating winlogbeat config..." -ForegroundColor DarkCyan
  $stdOut = Join-Path $env:TEMP "wlb_test_out.txt"
  $stdErr = Join-Path $env:TEMP "wlb_test_err.txt"
  $argStr = ('test config -c "{0}"' -f $yml)
  $proc = Start-Process -FilePath $exe -WorkingDirectory $InstallDir `
           -ArgumentList $argStr -NoNewWindow -Wait -PassThru `
           -RedirectStandardOutput $stdOut -RedirectStandardError $stdErr
  if ($proc.ExitCode -ne 0) {
    Write-Error ("[TinySOCS] winlogbeat config validation failed (exit {0})." -f $proc.ExitCode)
    Get-Content $stdOut -ErrorAction SilentlyContinue | Select-Object -Last 40 | Write-Host
    Get-Content $stdErr -ErrorAction SilentlyContinue | Select-Object -Last 40 | Write-Host
    throw "winlogbeat test config failed"
  }
  Write-Host "[TinySOCS] Config OK." -ForegroundColor Green

  try { Set-Service winlogbeat -StartupType Automatic -ErrorAction SilentlyContinue } catch {}
  Start-WinlogbeatAndWaitHealthy -TimeoutSec 60 -InstallDir $InstallDir
}

function Invoke-WinlogbeatDiagnostic {
  param(
    [string]$InstallDir,
    [int]$Seconds = 12
  )
  try {
    $exe = Join-Path $InstallDir 'winlogbeat.exe'
    $yml = Join-Path $InstallDir 'winlogbeat.yml'
    $out = Join-Path $env:TEMP 'wlb_diag_out.txt'
    $err = Join-Path $env:TEMP 'wlb_diag_err.txt'
    $args = ('run -e -c "{0}" --path.home "{1}" --path.data "{2}" --path.logs "{2}\logs" -d "*"' -f $yml, $InstallDir, $Global:TinySOCS_WinlogbeatData)

    $p = Start-Process -FilePath $exe -WorkingDirectory $InstallDir `
          -ArgumentList $args -PassThru -RedirectStandardOutput $out -RedirectStandardError $err
    try { Wait-Process -Id $p.Id -Timeout $Seconds } catch {}
    if (-not $p.HasExited) { try { Stop-Process -Id $p.Id -Force } catch {} }

    Write-Host "[TinySOCS] Diagnostic (stdout tail):" -ForegroundColor Yellow
    Get-Content $out -ErrorAction SilentlyContinue | Select-Object -Last 60 | Write-Host
    Write-Host "[TinySOCS] Diagnostic (stderr tail):" -ForegroundColor Yellow
    Get-Content $err -ErrorAction SilentlyContinue | Select-Object -Last 60 | Write-Host
  } catch {
    Write-Warning ("[TinySOCS] Diagnostic run failed: {0}" -f $_.Exception.Message)
  }
}

function Start-WinlogbeatAndWaitHealthy {
  param(
    [int]$TimeoutSec = 60,
    [string]$InstallDir = $Global:TinySOCS_WinlogbeatDir,
    [int]$Attempts = 3
  )

  for ($try = 1; $try -le $Attempts; $try++) {
    if ($try -gt 1) {
      Write-Warning ("[TinySOCS] winlogbeat start retry {0}/{1} (clearing lock & ensuring no console instance)..." -f $try, $Attempts)
    }

    # Ensure no console instance from our dir; then clear lock if stale
    Stop-WinlogbeatConsoleFromDir -TargetDir $InstallDir
    Remove-WinlogbeatStaleLock -DataPath $Global:TinySOCS_WinlogbeatData

    # Stop service if stuck in 'Starting'/'Stopping'
    $svc = Get-Service -Name winlogbeat -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -in 'StartPending','StopPending') {
      try { Stop-Service winlogbeat -Force -ErrorAction SilentlyContinue } catch {}
      Start-Sleep -Milliseconds 800
    }

    # Start (or re-start) the service
    try { Start-Service winlogbeat -ErrorAction SilentlyContinue } catch {}

    # Wait for Running
    $deadline = (Get-Date).AddSeconds([Math]::Ceiling($TimeoutSec / $Attempts))
    do {
      Start-Sleep -Milliseconds 700
      try { $svc = Get-Service -Name winlogbeat -ErrorAction Stop } catch {}
      if ($svc -and $svc.Status -eq 'Running') { break }
    } while ((Get-Date) -lt $deadline)

    if ($svc -and $svc.Status -eq 'Running') {
      # (Optional) quick hint from logs
      $logDir = Join-Path $Global:TinySOCS_WinlogbeatData 'logs'
      if (Test-Path $logDir) {
        try {
          $last = Get-ChildItem $logDir -Filter 'winlogbeat*.log' | Sort-Object LastWriteTime -Desc | Select-Object -First 1
          if ($last) {
            $lines = Get-Content $last.FullName -Tail 200 -ErrorAction SilentlyContinue
            $hint = ($lines | Where-Object { $_ -match 'Connection .*established|Beat .* start' } | Select-Object -Last 1)
            if ($hint) { Write-Host ("[TinySOCS] Log hint: {0}" -f $hint) -ForegroundColor DarkGray }
          }
        } catch {}
      }
      return  # success
    }

    # If not running yet: try to stop before next attempt
    try { Stop-Service winlogbeat -Force -ErrorAction SilentlyContinue } catch {}
    Start-Sleep -Milliseconds 600
  }

  # Hard failure path: print details + run the timed diagnostic
  Write-Error ("[TinySOCS] winlogbeat failed to reach Running state after {0} attempt(s)." -f $Attempts)

  Write-Host "[TinySOCS] Service configuration:" -ForegroundColor Yellow
  sc.exe qc winlogbeat | Write-Host

  Write-Host "[TinySOCS] Recent Application/SCM events mentioning winlogbeat:" -ForegroundColor Yellow
  try {
    Get-WinEvent -MaxEvents 200 -FilterHashtable @{ LogName='Application' } |
      Where-Object { $_.ProviderName -in @('winlogbeat','Service Control Manager') -and $_.Message -match 'winlogbeat' } |
      Select-Object -First 15 |
      ForEach-Object { $_.TimeCreated.ToString('u') + ' - ' + $_.Message } | Write-Host
  } catch {}

  Write-Host "[TinySOCS] Running timed diagnostic (capturing ~15s of startup output)..." -ForegroundColor Yellow
  Invoke-WinlogbeatDiagnostic -InstallDir $InstallDir -Seconds 15
  throw "winlogbeat not healthy"
}

function Get-WinlogbeatStatus {
  $svc  = Get-Service -Name winlogbeat -ErrorAction SilentlyContinue
  $img  = $null
  try { $img = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\winlogbeat' -Name ImagePath -ErrorAction Stop).ImagePath } catch {}

  $exePath = $null
  if ($img) { $exePath = Get-ExePathFromServicePathName -PathName $img }
  $dir  = if ($exePath) { Split-Path $exePath -Parent } else { $null }
  $ver  = if ($exePath -and (Test-Path $exePath)) { (Get-Item $exePath).VersionInfo.FileVersion } else { $null }
  $logs = Join-Path $Global:TinySOCS_WinlogbeatData 'Logs'

  $svcState = $null
  $svcName  = $null
  if ($svc) { $svcState = $svc.Status; $svcName = $svc.Name }

  [pscustomobject]@{
    ServiceState      = $svcState
    ServiceName       = $svcName
    ServiceImagePath  = $img
    ExePath           = $exePath
    ExeDir            = $dir
    FileVersion       = $ver
    LogsPath          = $logs
  }
}

function Ensure-WinlogbeatSingleton {
  param(
    [string]$InstallDir = $Global:TinySOCS_WinlogbeatDir,
    [string]$Version    = "8.14.3"
  )

  try { Stop-OtherWinlogbeatInstances -TargetDir $InstallDir } catch { Write-Warning ("[TinySOCS] Stop-OtherWinlogbeatInstances error: {0}" -f $_.Exception.Message) }

  if (!(Test-Path (Join-Path $InstallDir "winlogbeat.exe"))) {
    Write-Host ("[TinySOCS] Installing Winlogbeat to {0} ..." -f $InstallDir) -ForegroundColor Yellow
    try { Install-Winlogbeat -Version $Version -InstallDir $InstallDir }
    catch { Write-Error ("[TinySOCS] Install-Winlogbeat failed: {0}" -f $_.Exception.Message); return }
  } else {
    Write-Host ("[TinySOCS] TinySOCS Winlogbeat already present at {0}" -f $InstallDir) -ForegroundColor Green
  }

  Install-Or-Repair-WinlogbeatService -InstallDir $InstallDir
  Get-WinlogbeatStatus | Format-List
}

function Ensure-TinySOCS-Agents {
  if (-not (Test-IsAdmin)) {
    if (-not (Ensure-AdminOrRelaunch -PostCommand 'Ensure-TinySOCS-Agents')) { return }
  }

  if (-not $global:TinySOCS_LogPath) {
    $global:TinySOCS_LogPath = Get-TinySOCSLogPath
    try { Start-Transcript -Path $global:TinySOCS_LogPath -Append | Out-Null } catch {}
  }
  Write-Host ("[TinySOCS] Logging to: {0}" -f $global:TinySOCS_LogPath) -ForegroundColor Yellow

  $sysmon = Get-Service -Name Sysmon64 -ErrorAction SilentlyContinue
  if ($sysmon) {
    Write-Host ("[TinySOCS] Sysmon present: {0} - {1}" -f $sysmon.Status, $sysmon.Name)
  } else {
    Write-Warning "[TinySOCS] Sysmon not detected. TinySOCS will still work, but richer detections come with Sysmon."
  }

  try {
    Ensure-WinlogbeatSingleton
  } catch {
    Write-Error ("[TinySOCS] Ensure-WinlogbeatSingleton fatal: {0}" -f $_.Exception.Message)
    throw
  }

  Write-Host "[TinySOCS] Agents ready. Generate test noise with: Invoke-TinySOCS-TestNoise -All" -ForegroundColor Cyan
  try { Stop-Transcript | Out-Null } catch {}
}

# ===================== Routes (logstash-free) =====================
function Show-TinySOCS-Targets {
  Write-Host ("LLM_MODE              = {0}" -f $env:LLM_MODE)
  Write-Host ("SIEM_BACKEND          = {0}" -f $env:SIEM_BACKEND)
  Write-Host ("SIEM_URL              = {0}" -f $env:SIEM_URL)
  if ($env:SIEM_USER)            { Write-Host ("SIEM_USER             = {0}" -f $env:SIEM_USER) }
  if ($env:SIEM_SSL_VERIFY)      { Write-Host ("SIEM_SSL_VERIFY       = {0}" -f $env:SIEM_SSL_VERIFY) }
  if ($env:SIEM_TIMEOUT_SECONDS) { Write-Host ("SIEM_TIMEOUT_SECONDS  = {0}" -f $env:SIEM_TIMEOUT_SECONDS) }
}

function Route-To-OpenSearch {
  param([switch]$Full)
  if (-not (Ensure-DockerReady)) { Write-Warning "[TinySOCS] Docker engine not available."; return }
  Use-OpenSearchSIEM
  Stop-ElasticStack
  Start-OpenSearchStack -Dashboards:$Full
  $env:SIEM_TIMEOUT_SECONDS = "60"
}

function Route-To-Elastic {
  param([switch]$Full)
  if (-not (Ensure-DockerReady)) { Write-Warning "[TinySOCS] Docker engine not available."; return }
  Use-ElasticSIEM
  Stop-OpenSearchStack
  Start-ElasticStack -Kibana:$Full
  Remove-Item Env:SIEM_TIMEOUT_SECONDS -ErrorAction SilentlyContinue
}

# ===================== Node/Master helpers =====================
function Start-TinySocsNodeApi { param([int]$Port=8081)
  if (-not $env:NODE_ID) { $env:NODE_ID="node-1" }
  if (-not $env:NODE_SECRET) { $env:NODE_SECRET="dev-secret-change-me" }
  $env:PORT="$Port"
  Write-Host "Starting Node API on port $Port (NODE_ID=$env:NODE_ID)..."
  Start-Process -FilePath "python" -ArgumentList "tinysocs\api\node.py" -NoNewWindow
}

function Start-TinySocsMaster {
  param([string]$Nodes="http://localhost:8081,http://localhost:8082",
        [string]$Rules="auth_failed_burst,ps_script_block",
        [string]$Window="15m",
        [string]$Host="")
  $env:TINYSOCS_NODES=$Nodes
  $env:MASTER_SHARED_SECRET=$env:NODE_SECRET
  $args=@("--rules",$Rules,"--window",$Window); if($Host){$args+=@("--host",$Host)}
  Write-Host "Running master against $Nodes..."
  python "tinysocs\orchestrator\master.py" @args
}

function New-TinySocsAuthHeaders {
  param([string]$Secret)
  $ts = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
  $hmac = New-Object System.Security.Cryptography.HMACSHA256
  $hmac.Key = [Text.Encoding]::UTF8.GetBytes($Secret)
  $sigBytes = $hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes([string]$ts))
  $sigHex = -join ($sigBytes | % { $_.ToString("x2") })
  @{ "X-TinySOCS-Timestamp" = [string]$ts; "X-TinySOCS-Signature" = "sha256=$sigHex" }
}

function Use-Role {
  param(
    [ValidateSet('solo','node','master')] [string]$Role,
    [string]$Backend = 'opensearch'
  )
  $env:ROLE = $Role
  if ($Backend -eq 'opensearch') {
    Route-To-OpenSearch
  } else {
    Route-To-Elastic
  }
  Ensure-TinySOCS-Agents
  Write-Host "ROLE set to $Role (backend: $Backend)"
}

function Start-TinySocs-Node {
  param(
    [int]$Port = 8081,
    [string]$NodeId = "node-$Port",
    [string]$Secret = "dev-secret-change-me"
  )
  Set-Location $PSScriptRoot
  Import-DotEnv

  $env:ROLE            = "node"
  $env:NODE_ID         = $NodeId
  $env:NODE_SECRET     = $Secret
  $env:PORT            = "$Port"

  if (-not $env:SIEM_BACKEND)    { $env:SIEM_BACKEND = "opensearch" }
  if (-not $env:SIEM_URL)        { $env:SIEM_URL     = "https://127.0.0.1:9201" }
  if (-not $env:SIEM_USER)       { $env:SIEM_USER    = "admin" }
  if (-not $env:SIEM_PASS)       { $env:SIEM_PASS    = "ChangeMe123!" }
  if (-not $env:SIEM_SSL_VERIFY) { $env:SIEM_SSL_VERIFY = "false" }

  Show-TinySOCS-Targets | Out-Null
  Write-Host "[node] starting $NodeId on :$Port"
  python .\api\node.py
}

function Start-TinySocs-MultiNode {
  param(
    [int]$Count = 2,
    [int]$StartPort = 8081,
    [string]$Secret = "dev-secret-change-me"
  )
  for ($i=0; $i -lt $Count; $i++) {
    $port = $StartPort + $i
    Start-Process -WindowStyle Minimized powershell -ArgumentList "-NoExit","-Command",
      "Set-Location `"$PSScriptRoot`"; . .\.venv\Scripts\Activate.ps1; ``
       . .\model_toggles.ps1; Import-DotEnv; ``
       `$env:NODE_SECRET='$Secret'; `$env:NODE_ID='node-$port'; `$env:PORT='$port'; ``
       python .\api\node.py"
    Start-Sleep -Milliseconds 500
  }
  Write-Host "[multinode] launched $Count nodes starting at $StartPort"
}

function Run-TinySocs-Master {
  param(
    [string]$Nodes = "http://localhost:8081,http://localhost:8082",
    [string]$Secret = "dev-secret-change-me",
    [string]$Rules  = "auth_failed_burst,ps_script_block",
    [string]$Window = "15m"
  )
  Set-Location $PSScriptRoot
  Import-DotEnv

  $env:ROLE = "master"
  $env:TINYSOCS_NODES       = $Nodes
  $env:MASTER_SHARED_SECRET = $Secret
  $env:REQUEST_TIMEOUT_SEC  = "20"

  if (-not $env:LLM_MODE)       { $env:LLM_MODE = "openai" }
  if (-not $env:OPENAI_API_KEY) { Write-Warning "OPENAI_API_KEY not set; summary may fallback" }

  if (-not $env:SIEM_BACKEND)    { $env:SIEM_BACKEND = "opensearch" }
  if (-not $env:SIEM_URL)        { $env:SIEM_URL     = "https://127.0.0.1:9201" }
  if (-not $env:SIEM_USER)       { $env:SIEM_USER    = "admin" }
  if (-not $env:SIEM_PASS)       { $env:SIEM_PASS    = "ChangeMe123!" }
  if (-not $env:SIEM_SSL_VERIFY) { $env:SIEM_SSL_VERIFY = "false" }

  Write-Host "[master] fan-out to $Nodes; rules=$Rules; window=$Window"
  python .\orchestrator\master.py --rules $Rules --window $Window
}

function Run-TinySocs-Solo {
  param([switch]$Noise)
  Set-Location $PSScriptRoot
  Use-Role -Role solo -Backend opensearch
  if ($Noise) { Invoke-TinySOCS-TestNoise -All }
  python -u -m agent.main
}

# ===================== Requirements + index helpers =====================
function Ensure-PythonRequirements {
  param([string]$RepoRoot = $PSScriptRoot)
  Push-Location $RepoRoot
  try {
    $req = Join-Path $RepoRoot 'requirements.txt'
    if (Test-Path $req) {
      Write-Host "[TinySOCS] Ensuring Python requirements..." -ForegroundColor DarkCyan
      python -m pip install --upgrade pip | Out-Null
      python -m pip install -r $req
    } else {
      Write-Host "[TinySOCS] requirements.txt not found; skipping pip install." -ForegroundColor DarkYellow
    }
  } finally { Pop-Location }
}

function Ensure-SIEM-Index {
  param(
    [string]$Index = "siem_index"
  )
  if (-not $env:SIEM_URL) { Write-Warning "[TinySOCS] SIEM_URL not set; skipping index check."; return }
  if (-not $env:SIEM_USER -or -not $env:SIEM_PASS) { Write-Warning "[TinySOCS] SIEM creds not set; skipping index check."; return }

  $auth = "$($env:SIEM_USER):$($env:SIEM_PASS)"
  $url  = "$($env:SIEM_URL.TrimEnd('/'))/$Index"
  $isHttps = $env:SIEM_URL -like "https*"
  $insecure = $isHttps -and (($env:SIEM_SSL_VERIFY -as [string]).ToLower() -eq "false")

  $curlArgs = @()
  if ($insecure) { $curlArgs += "-k" }
  $curlArgs += @("-s","-u", $auth, $url)

  $null = & curl.exe @curlArgs
  if ($LASTEXITCODE -ne 0) {
    Write-Host "[TinySOCS] Creating SIEM index '$Index'..." -ForegroundColor DarkCyan
    $curlArgs = @()
    if ($insecure) { $curlArgs += "-k" }
    $curlArgs += @("-s","-u", $auth, "-X","PUT", $url)
    $null = & curl.exe @curlArgs
  } else {
    Write-Host "[TinySOCS] SIEM index '$Index' present." -ForegroundColor Green
  }
}

# ===================== Winlogbeat template + mapping (default ON) =====================
function Get-OSCurlArgs {
  param(
    [Parameter(Mandatory=$true)][string]$Endpoint,
    [ValidateSet('GET','PUT','POST')][string]$Method = 'GET',
    [string]$DataFile,
    [switch]$Json
  )
  $auth = "$($env:SIEM_USER):$($env:SIEM_PASS)"
  $isHttps = $env:SIEM_URL -like "https*"
  $insecure = $isHttps -and (($env:SIEM_SSL_VERIFY -as [string]).ToLower() -eq "false")

  $args = @()
  if ($insecure) { $args += "-k" }
  $args += @("-s","-u", $auth, "-X", $Method, $Endpoint)
  if ($Json) { $args += @("-H","Content-Type: application/json") }
  if ($DataFile) { $args += @("--data-binary", "@$DataFile") }
  return ,$args
}

function Install-WB-HighPriorityTemplate {
  param([string]$RepoRoot = $PSScriptRoot)

  $base   = $env:SIEM_URL.TrimEnd('/')
  $name   = "winlogbeat-high-priority"
  $prio   = Join-Path $RepoRoot "integrations\winlogbeat\winlogbeat_template_priority500.json"
  $std    = Join-Path $RepoRoot "integrations\winlogbeat\winlogbeat_template.json"
  $altPrio= Join-Path $RepoRoot "winlogbeat_template_priority500.json"
  $altStd = Join-Path $RepoRoot "winlogbeat_template.json"

  $file = if (Test-Path $prio) { $prio }
          elseif (Test-Path $std) { $std }
          elseif (Test-Path $altPrio) { $altPrio }
          elseif (Test-Path $altStd) { $altStd }
          else { $null }

  if (-not $file) { Write-Warning "[TinySOCS] No winlogbeat template JSON found; skipping template install."; return }

  $endpoint = "$base/_index_template/$name"
  $args = Get-OSCurlArgs -Endpoint $endpoint -Method PUT -DataFile $file -Json
  $out = & curl.exe @args
  if ($LASTEXITCODE -eq 0) {
    Write-Host "[TinySOCS] Installed/updated index template '$name' from $(Split-Path $file -Leaf)." -ForegroundColor Green
  } else {
    Write-Warning "[TinySOCS] Failed installing index template '$name'."
    Write-Host $out
  }
}

function Patch-WB-KeywordFields {
  param([string]$RepoRoot = $PSScriptRoot)

  $kw     = Join-Path $RepoRoot "integrations\winlogbeat\winlogbeat_keyword_mapping.json"
  $altKw  = Join-Path $RepoRoot "winlogbeat_keyword_mapping.json"
  $file   = if (Test-Path $kw) { $kw } elseif (Test-Path $altKw) { $altKw } else { $null }
  if (-not $file) { Write-Warning "[TinySOCS] No winlogbeat keyword mapping JSON found; skipping mapping patch."; return }

  $base    = $env:SIEM_URL.TrimEnd('/')
  $endpoint= "$base/winlogbeat-*/_mapping"
  $args = Get-OSCurlArgs -Endpoint $endpoint -Method PUT -DataFile $file -Json
  $out = & curl.exe @args
  if ($LASTEXITCODE -eq 0) {
    Write-Host "[TinySOCS] Applied keyword multi-field patch to winlogbeat-* indices." -ForegroundColor Green
  } else {
    Write-Warning "[TinySOCS] Failed applying keyword mapping to winlogbeat-*."
    Write-Host $out
  }
}

function Ensure-WB-Setup {
  param([string]$RepoRoot = $PSScriptRoot)
  try { Install-WB-HighPriorityTemplate -RepoRoot $RepoRoot } catch {
    Write-Warning ("[TinySOCS] Winlogbeat template install failed: {0}" -f $_.Exception.Message)
  }
  try { Patch-WB-KeywordFields -RepoRoot $RepoRoot } catch {
    Write-Warning ("[TinySOCS] Winlogbeat mapping patch failed: {0}" -f $_.Exception.Message)
  }
}

# ===================== Core starter + four toggles =====================
function Start-TinySOCS {
  param(
    [ValidateSet('opensearch','elastic')] [string]$Backend = 'opensearch',
    [switch]$Full,                                # dashboards/kibana
    [ValidateSet('solo','node','master')] [string]$Role = 'solo',
    [switch]$LocalLLM,                             # use ollama instead of openai
    [int]$NodePort = 8081,                         # when Role=node
    [string]$Nodes = "http://localhost:8081,http://localhost:8082",  # when Role=master
    [string]$Rules = "auth_failed_burst,ps_script_block",
    [string]$Window = "15m",
    [switch]$NoWBSetup                              # opt-out of template/mapping setup
  )

  Set-Location $PSScriptRoot
  Import-DotEnv

  if ($LocalLLM) { Use-Ollama } else { Use-OpenAI }

  if ($Backend -eq 'opensearch') {
    Route-To-OpenSearch -Full:$Full
    if (-not $NoWBSetup) { Ensure-WB-Setup -RepoRoot $PSScriptRoot }
  } else {
    Route-To-Elastic -Full:$Full
  }

  Ensure-TinySOCS-Agents
  Ensure-PythonRequirements
  Ensure-SIEM-Index -Index "siem_index"

  switch ($Role) {
    'solo'   { Write-Host "[TinySOCS] Running SOLO agent loop..." -ForegroundColor Cyan; python -u -m agent.main }
    'node'   { Start-TinySocs-Node -Port $NodePort }
    'master' { Run-TinySocs-Master -Nodes $Nodes -Rules $Rules -Window $Window }
  }
}

function Start-TinySOCS-OpenSearchLean {
  param(
    [ValidateSet('solo','node','master')] [string]$Role = 'solo',
    [switch]$LocalLLM,
    [int]$NodePort = 8081,
    [string]$Nodes = "http://localhost:8081,http://localhost:8082",
    [string]$Rules = "auth_failed_burst,ps_script_block",
    [string]$Window = "15m",
    [switch]$NoWBSetup
  )
  Start-TinySOCS -Backend opensearch -Full:$false -Role $Role -LocalLLM:$LocalLLM -NodePort $NodePort -Nodes $Nodes -Rules $Rules -Window $Window -NoWBSetup:$NoWBSetup
}

function Start-TinySOCS-OpenSearchFull {
  param(
    [ValidateSet('solo','node','master')] [string]$Role = 'solo',
    [switch]$LocalLLM,
    [int]$NodePort = 8081,
    [string]$Nodes = "http://localhost:8081,http://localhost:8082",
    [string]$Rules = "auth_failed_burst,ps_script_block",
    [string]$Window = "15m",
    [switch]$NoWBSetup
  )
  Start-TinySOCS -Backend opensearch -Full:$true -Role $Role -LocalLLM:$LocalLLM -NodePort $NodePort -Nodes $Nodes -Rules $Rules -Window $Window -NoWBSetup:$NoWBSetup
}

function Start-TinySOCS-ElasticLean {
  param(
    [ValidateSet('solo','node','master')] [string]$Role = 'solo',
    [switch]$LocalLLM,
    [int]$NodePort = 8081,
    [string]$Nodes = "http://localhost:8081,http://localhost:8082",
    [string]$Rules = "auth_failed_burst,ps_script_block",
    [string]$Window = "15m"
  )
  Start-TinySOCS -Backend elastic -Full:$false -Role $Role -LocalLLM:$LocalLLM -NodePort $NodePort -Nodes $Nodes -Rules $Rules -Window $Window
}

function Start-TinySOCS-ElasticFull {
  param(
    [ValidateSet('solo','node','master')] [string]$Role = 'solo',
    [switch]$LocalLLM,
    [int]$NodePort = 8081,
    [string]$Nodes = "http://localhost:8081,http://localhost:8082",
    [string]$Rules = "auth_failed_burst,ps_script_block",
    [string]$Window = "15m"
  )
  Start-TinySOCS -Backend elastic -Full:$true -Role $Role -LocalLLM:$LocalLLM -NodePort $NodePort -Nodes $Nodes -Rules $Rules -Window $Window
}