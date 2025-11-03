[CmdletBinding()]
param(
  [switch]$SimulateSlowNode,
  [int]$DeadlineSec = 20,
  [string]$Rules = "auth_failed_burst,script_block_volume",
  [string]$Window = "15m"
)

$ErrorActionPreference = "Stop"

# Resolve repo root
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$repo = Resolve-Path (Join-Path $here "..") | ForEach-Object { $_.Path }
Push-Location $repo

# Baseline env (Windows-only demo)
$Env:PYTHONUNBUFFERED = "1"
if (-not $Env:MASTER_SHARED_SECRET) { $Env:MASTER_SHARED_SECRET = "dev-secret-change-me" }
if (-not $Env:TINYSOCS_HMAC_STYLE)  { $Env:TINYSOCS_HMAC_STYLE  = "pipe" }  # pipe|dot|ts
if (-not $Env:REQUEST_TIMEOUT_SEC)  { $Env:REQUEST_TIMEOUT_SEC  = "6" }
if (-not $Env:MASTER_DEADLINE_SEC)  { $Env:MASTER_DEADLINE_SEC  = "$DeadlineSec" }
if (-not $Env:SIEM_SSL_VERIFY)      { $Env:SIEM_SSL_VERIFY      = "false" }  # local self-signed

# Ports/paths
$node1Port = 8081
$node2Port = 8082
$botPort   = 8090

$ledgerRoot  = Join-Path $repo "ledger"
$node1Ledger = Join-Path $ledgerRoot "node-$node1Port"
$node2Ledger = Join-Path $ledgerRoot "node-$node2Port"

# Ensure repo-scoped dirs
New-Item -ItemType Directory -Force -Path $node1Ledger | Out-Null
New-Item -ItemType Directory -Force -Path $node2Ledger | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $repo "data") | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $repo "logs") | Out-Null

# ---- Queue path (robust) ---------------------------------------------------
$queueEnv = $Env:TINYSOCS_QUEUE_PATH
if ([string]::IsNullOrWhiteSpace($queueEnv)) { $queueEnv = ".\data\actions_queue.jsonl" }
if (-not [System.IO.Path]::IsPathRooted($queueEnv)) { $queuePath = Join-Path $repo $queueEnv } else { $queuePath = $queueEnv }
$queueParent = Split-Path -Parent $queuePath
if (-not (Test-Path -LiteralPath $queueParent)) { New-Item -ItemType Directory -Force -Path $queueParent | Out-Null }

# ---- Helpers ---------------------------------------------------------------

function New-TinySocsHeaders {
  param([string]$Secret)

  $ts = [int][double]::Parse((Get-Date -UFormat %s))
  $nonce = -join ((48..57 + 97..102) | Get-Random -Count 16 | ForEach-Object {[char]$_})

  $style = $Env:TINYSOCS_HMAC_STYLE
  if ([string]::IsNullOrEmpty($style)) { $style = "pipe" }
  $style = $style.ToLower()

  $msg = ""
  $includeNonce = $false
  if ($style -eq "dot") { $msg = "$ts.$nonce"; $includeNonce = $true }
  elseif ($style -eq "ts") { $msg = "$ts"; $includeNonce = $false }
  else { $msg = "$ts|$nonce"; $includeNonce = $true }

  $hmac = New-Object System.Security.Cryptography.HMACSHA256
  $hmac.Key = [Text.Encoding]::UTF8.GetBytes($Secret)
  $mac = $hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($msg))
  $hex = -join ($mac | ForEach-Object { $_.ToString("x2") })

  $sig = $hex
  $prefix = $Env:TINYSOCS_SIG_PREFIX
  if ($prefix -and ($prefix -match '^(1|true|yes|on|sha256)$')) { $sig = "sha256=$hex" }

  $h = @{
    "X-TinySOCS-Timestamp" = "$ts"
    "X-TinySOCS-Signature" = $sig
    "User-Agent" = "tinysocs/harness"
  }
  if ($includeNonce) { $h["X-TinySOCS-Nonce"] = $nonce }
  return $h
}

function Start-Proc {
  param(
    [string]$Name,
    [string]$Cmd,        # e.g. 'python -m tinysocs.api.node'
    [hashtable]$EnvOverride
  )
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = "powershell.exe"
  $psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -Command $Cmd"
  $psi.WorkingDirectory = $repo
  $psi.UseShellExecute = $false
  $psi.CreateNoWindow = $true
  foreach ($k in $EnvOverride.Keys) { $psi.Environment[$k] = [string]$EnvOverride[$k] }
  $p = [System.Diagnostics.Process]::Start($psi)
  Write-Host "Started $Name (PID=$($p.Id))"
  return $p
}

function Test-NodeReady {
  param([string]$BaseUrl)
  try {
    $headers = New-TinySocsHeaders -Secret $Env:MASTER_SHARED_SECRET
    try {
      $r = Invoke-RestMethod -Uri "$BaseUrl/meta" -Headers $headers -Method GET
      if ($r -and $r.node_id) { return $true }
    } catch {
      $probe = @{ window = "1m"; query = "*"; size = 0 } | ConvertTo-Json
      $r = Invoke-RestMethod -Uri "$BaseUrl/agg" -Headers $headers -Method POST -Body $probe -ContentType "application/json"
      if ($r) { return $true }
    }
  } catch { }
  return $false
}

function Wait-NodeReady {
  param([string]$BaseUrl,[int]$Retries=40)
  for ($i=0; $i -lt $Retries; $i++) {
    if (Test-NodeReady -BaseUrl $BaseUrl) { return }
    Start-Sleep -Milliseconds 250
  }
  Write-Warning "Node at $BaseUrl did not confirm readiness in time (continuing; master will retry)."
}

# ---- Start components ------------------------------------------------------

$procs = @()
try {
  # Node1
  $procs += Start-Proc -Name "node-$node1Port" -Cmd "python -m tinysocs.api.node" -EnvOverride @{
    "NODE_ID"              = "node-$node1Port"
    "NODE_PORT"            = "$node1Port"
    "PORT"                 = "$node1Port"
    "TINYSOCS_LEDGER_DIR"  = "$node1Ledger"
  }
  Wait-NodeReady -BaseUrl "http://127.0.0.1:$node1Port"

  # Bot (single)
  $procs += Start-Proc -Name "bot-$botPort" -Cmd "python -m tinysocs.api.bot" -EnvOverride @{
    "BOT_PORT"            = "$botPort"
    "TINYSOCS_QUEUE_PATH" = "$queuePath"
  }
  Start-Sleep -Milliseconds 600

  # Node2 (optionally 'slow')
  if ($SimulateSlowNode) {
    Write-Host "Simulating slow/failing node: delaying Node2 start..." -ForegroundColor Yellow
    Start-Sleep -Seconds 10
  }
  $simSleep = ""
  if ($SimulateSlowNode) { $simSleep = "5000" }

  $procs += Start-Proc -Name "node-$node2Port" -Cmd "python -m tinysocs.api.node" -EnvOverride @{
    "NODE_ID"                 = "node-$node2Port"
    "NODE_PORT"               = "$node2Port"
    "PORT"                    = "$node2Port"
    "TINYSOCS_LEDGER_DIR"     = "$node2Ledger"
    "TINYSOCS_SIMULATE_SLEEP_MS" = $simSleep
  }
  if (-not $SimulateSlowNode) {
    Wait-NodeReady -BaseUrl "http://127.0.0.1:$node2Port"
  } else {
    Write-Host "Skipping readiness wait for Node2 (slow mode)" -ForegroundColor DarkYellow
  }

  # Master one-shot
  $Env:TINYSOCS_NODES = "http://127.0.0.1:$node1Port,http://127.0.0.1:$node2Port"
  $Env:MASTER_DEADLINE_SEC = "$DeadlineSec"
  Write-Host ""
  Write-Host "Running Master once:" -ForegroundColor Cyan
  Write-Host "  Nodes:     $Env:TINYSOCS_NODES"
  Write-Host "  Rules:     $Rules"
  Write-Host "  Window:    $Window"
  Write-Host "  Deadline:  $DeadlineSec sec"
  Write-Host ""

  $masterArgs = @("--rules", $Rules, "--window", $Window, "--deadline", $DeadlineSec)
  python -m tinysocs.orchestrator.master @masterArgs
  $masterExit = $LASTEXITCODE

  # ---- Doctor (robust locator) --------------------------------------------
  $doctorPath = $null
  if ($Env:DOCTOR_PATH -and (Test-Path $Env:DOCTOR_PATH)) { $doctorPath = $Env:DOCTOR_PATH }
  else {
    $doctorCandidates = @(
      (Join-Path $repo "Doctor.ps1"),
      (Join-Path $repo "scripts\Doctor.ps1"),
      (Join-Path $here "Doctor.ps1")
    )
    foreach ($c in $doctorCandidates) { if (Test-Path $c) { $doctorPath = $c; break } }
  }

  if ($doctorPath) {
    Write-Host "`nRunning Doctor ($doctorPath)..." -ForegroundColor Cyan
    & $doctorPath | Out-Host
  } else {
    Write-Host "`nDoctor.ps1 not found; running anchors ensure..." -ForegroundColor DarkYellow
    python -m tinysocs.orchestrator.anchors --ensure | Out-Host
  }

  if ($masterExit -ne 0) { throw "Master returned non-zero exit code ($masterExit)" }

  Write-Host "`nMulti-node demo complete." -ForegroundColor Green
}
catch {
  Write-Error $_
  exit 1
}
finally {
  foreach ($p in $procs) {
    try { if ($p -and -not $p.HasExited) { $p.Kill() } } catch {}
  }
  Pop-Location
}