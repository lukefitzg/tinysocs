# scripts/Start-TinySocs-Quick.ps1
# TinySocs Quickstart
# Brings the box to "ready" (WB + shim + Node + Bot), runs master once, verifies anchors, then runs Doctor.

Import-Module "$PSScriptRoot\TinySocs.Utils.psm1" -Force

$ErrorActionPreference = 'Stop'
Set-Location (Resolve-Path "$PSScriptRoot\..")  # repo root

function Import-DotEnv {
  param([string]$Path)
  if (-not (Test-Path $Path)) { return }
  Get-Content $Path | ForEach-Object {
    $line = $_.Trim()
    if (-not $line -or $line.StartsWith('#') -or ($line -notmatch '=')) { return }
    $k, $v = $line -split '=', 2
    $k = $k.Trim(); $v = $v.Trim().Trim("'").Trim('"')
    if ($k -and -not (Test-Path "Env:$k")) {
      Set-Item -Path "Env:$k" -Value $v
    }
  }
}

function Get-PythonExe {
  param([string]$RepoRoot = (Resolve-Path ".").Path)
  $venvPy = Join-Path $RepoRoot ".venv\Scripts\python.exe"
  if (Test-Path $venvPy) { return $venvPy }
  return "python"
}

function New-TinySocsHmacHeaders {
  param(
    [Parameter(Mandatory)][string]$Secret,
    [string]$Style = $env:TINYSOCS_HMAC_STYLE,
    [string]$SigPrefix = $env:TINYSOCS_SIG_PREFIX
  )
  if (-not $Style) { $Style = 'pipe' }   # default
  $Style = $Style.ToLower()

  $ts    = [int][DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
  $nonce = [Guid]::NewGuid().ToString('N')

  switch ($Style) {
    'dot'  { $msg = "$ts.$nonce"; $includeNonce = $true }
    'pipe' { $msg = "$ts|$nonce"; $includeNonce = $true }
    default { # 'ts'
      $msg = "$ts"; $includeNonce = $false
    }
  }

  $h   = [System.Security.Cryptography.HMACSHA256]::new([Text.Encoding]::UTF8.GetBytes($Secret))
  try {
    $raw = -join ($h.ComputeHash([Text.Encoding]::UTF8.GetBytes($msg)) | ForEach-Object { $_.ToString('x2') })
  } finally {
    $h.Dispose()
  }

  $sig = if ($SigPrefix -and $SigPrefix.Trim()) { "sha256=$raw" } else { $raw }

  $hdr = @{
    'X-TinySOCS-Timestamp' = $ts
    'X-TinySOCS-Signature' = $sig
  }
  if ($includeNonce) { $hdr['X-TinySOCS-Nonce'] = $nonce }
  return $hdr
}

function Test-HttpReady {
  param(
    [Parameter(Mandatory)] [string] $Url,
    [hashtable] $Headers,
    [int] $TimeoutSec = 20
  )
  $t0 = Get-Date
  while ((Get-Date) -lt $t0.AddSeconds($TimeoutSec)) {
    try {
      if ($null -ne $Headers) {
        $r = Invoke-WebRequest -Uri $Url -Headers $Headers -UseBasicParsing -TimeoutSec 4 -ErrorAction Stop
      } else {
        $r = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 4 -ErrorAction Stop
      }
      if ($r.StatusCode -ge 200 -and $r.StatusCode -lt 500) { return $true }
    } catch { Start-Sleep -Milliseconds 500 }
  }
  return $false
}

function Start-TinySocs-Ready {
  param(
    [string] $RepoRoot = "$PSScriptRoot\..",
    [int]    $NodePort = 8081,
    [int]    $BotPort  = 8090
  )
  # 0) Load .env (repo/.env or tinysocs/.env)
  Import-DotEnv (Join-Path $RepoRoot ".env")
  Import-DotEnv (Join-Path $RepoRoot "tinysocs\.env")

  # 0.1) Honor BOT_PORT env if provided
  if ($env:BOT_PORT) { try { $BotPort = [int]$env:BOT_PORT } catch {} }

  # 1) Elevation (if you kept Ensure-AdminOrRelaunch, use it)
  if (Get-Command Ensure-AdminOrRelaunch -ErrorAction SilentlyContinue) {
    Ensure-AdminOrRelaunch
  }

  # 2) Python venv + deps (best-effort)
  $PyExe = Get-PythonExe -RepoRoot $RepoRoot
  if (-not $env:VIRTUAL_ENV -and (Test-Path "$RepoRoot\.venv\Scripts\Activate.ps1")) {
    & "$RepoRoot\.venv\Scripts\Activate.ps1"
  }
  if (Get-Command Ensure-PythonRequirements -ErrorAction SilentlyContinue) {
    Ensure-PythonRequirements
  }

  # 3) SIEM + Core defaults
  if (-not $env:SIEM_URL)               { Set-Item Env:SIEM_URL "https://127.0.0.1:9201" }
  if (-not $env:SIEM_USER)              { Set-Item Env:SIEM_USER "admin" }
  if (-not $env:SIEM_PASS)              { Set-Item Env:SIEM_PASS "ChangeMe123!" }
  if (-not $env:SIEM_SSL_VERIFY)        { Set-Item Env:SIEM_SSL_VERIFY "0" }
  if (-not $env:TINYSOCS_NODES)         { Set-Item Env:TINYSOCS_NODES "http://localhost:$NodePort" }
  if (-not $env:MASTER_SHARED_SECRET)   { Set-Item Env:MASTER_SHARED_SECRET "dev-secret-change-me" }
  if (-not $env:NODE_SECRET)            { Set-Item Env:NODE_SECRET $env:MASTER_SHARED_SECRET }
  if (-not $env:BOT_SHARED_SECRET)      { Set-Item Env:BOT_SHARED_SECRET "supersecret" }
  if (-not $env:ENSURE_ANCHORS)         { Set-Item Env:ENSURE_ANCHORS "1" }
  if (-not $env:TINYSOCS_INSECURE_SKIP_VERIFY) { Set-Item Env:TINYSOCS_INSECURE_SKIP_VERIFY "1" }
  if (-not $env:TINYSOCS_HMAC_STYLE)    { Set-Item Env:TINYSOCS_HMAC_STYLE "pipe" }
  if ($null -eq $env:TINYSOCS_SIG_PREFIX) { Set-Item Env:TINYSOCS_SIG_PREFIX "" }
  # Canonical queue path default if not set
  if (-not $env:TINYSOCS_QUEUE_PATH) { Set-Item Env:TINYSOCS_QUEUE_PATH (Join-Path $RepoRoot 'data\actions_queue.jsonl') }

  # 4) Winlogbeat + Shim (idempotent)
  if (Get-Command Ensure-WB-Setup -ErrorAction SilentlyContinue) { Ensure-WB-Setup }
  if (Get-Command Install-Or-Repair-WinlogbeatService -ErrorAction SilentlyContinue) { Install-Or-Repair-WinlogbeatService }
  if (Get-Command Sync-TinySocsWinlogbeatConfig -ErrorAction SilentlyContinue) { Sync-TinySocsWinlogbeatConfig }
  if (Get-Command Ensure-OSShim-And-PointWinlogbeat -ErrorAction SilentlyContinue) { Ensure-OSShim-And-PointWinlogbeat }
  if (Get-Command Start-WinlogbeatAndWaitHealthy -ErrorAction SilentlyContinue) { Start-WinlogbeatAndWaitHealthy }
  if (Get-Command Start-OSShim -ErrorAction SilentlyContinue) { Start-OSShim }

  # 5) Start Node (background)
  $nodeUp = $false
  try {
    $isListening = Get-NetTCPConnection -ErrorAction SilentlyContinue |
                   Where-Object { $_.LocalPort -eq $NodePort -and $_.State -eq 'Listen' }
    if (-not $isListening) {
      Start-Process -FilePath $PyExe -ArgumentList @("-m","tinysocs.api.node") -WorkingDirectory $RepoRoot -WindowStyle Minimized
    }

    # try ts-only first (widest compatibility), then env style if needed
    $hdrTsOnly = New-TinySocsHmacHeaders -Secret $env:MASTER_SHARED_SECRET -Style 'ts' -SigPrefix ''
    $nodeUp = Test-HttpReady -Url "http://localhost:$NodePort/evidence/head" -Headers $hdrTsOnly -TimeoutSec 20
    if (-not $nodeUp) {
      $hdrEnv = New-TinySocsHmacHeaders -Secret $env:MASTER_SHARED_SECRET -Style $env:TINYSOCS_HMAC_STYLE -SigPrefix $env:TINYSOCS_SIG_PREFIX
      $nodeUp = Test-HttpReady -Url "http://localhost:$NodePort/evidence/head" -Headers $hdrEnv -TimeoutSec 10
    }
  } catch {}

  # 6) Start Bot (background)
  $botUp = $false
  try {
    $botListening = Get-NetTCPConnection -ErrorAction SilentlyContinue |
                    Where-Object { $_.LocalPort -eq $BotPort -and $_.State -eq 'Listen' }
    if (-not $botListening) {
      Start-Process -FilePath $PyExe -ArgumentList @("-m","tinysocs.api.bot") -WorkingDirectory $RepoRoot -WindowStyle Minimized
    }
    # docs isn't auth-protected; simple probe without headers
    $botUp = Test-HttpReady -Url "http://localhost:$BotPort/docs" -TimeoutSec 15
  } catch {}

  # 7) Gather optional status (PowerShell 5.1-safe)
  $wbSvc = $null
  try { $wbSvc = Get-Service -Name winlogbeat -ErrorAction SilentlyContinue } catch {}
  $wbStatus = if ($null -ne $wbSvc) { $wbSvc.Status } else { $null }

  $shimPort = $null
  if (Get-Command Get-TinySOCSShimPort -ErrorAction SilentlyContinue) {
    try { $shimPort = Get-TinySOCSShimPort } catch { $shimPort = $null }
  }

  # 8) Return status object
  [pscustomobject]@{
    NodeUrl    = "http://localhost:$NodePort"
    BotUrl     = "http://localhost:$BotPort"
    NodeReady  = $nodeUp
    BotReady   = $botUp
    Winlogbeat = $wbStatus
    ShimPort   = $shimPort
  }
}

function Invoke-TinySocs-Scan {
  param(
    [string] $Rules    = "ps_script_block_lab",
    [string] $Window   = "10m",
    [double] $Deadline = 30,
    [switch] $AlwaysAnchor
  )
  $RepoRoot = (Resolve-Path ".").Path
  $PyExe = Get-PythonExe -RepoRoot $RepoRoot
  $args = @("-m","tinysocs.orchestrator.master","--rules",$Rules,"--window",$Window,"--deadline",$Deadline)
  if ($AlwaysAnchor) { $args += "--always-anchor" }
  & $PyExe $args
  & $PyExe -m tinysocs.orchestrator.check_ledger --verify
}

# ---- Quickstart flow ----
$RepoRoot = (Resolve-Path "$PSScriptRoot\..").Path
$ready = Start-TinySocs-Ready -RepoRoot $RepoRoot
$ready | Format-List

$rules = if ($env:TSQ_RULES) { $env:TSQ_RULES } else { "ps_script_block_lab" }
$ensure = ($env:ENSURE_ANCHORS -and $env:ENSURE_ANCHORS.ToString().ToLower() -in @('1','true','yes','on'))
Invoke-TinySocs-Scan -Rules $rules -Window "10m" -Deadline 30 -AlwaysAnchor:$ensure

Write-Host "`nTinySocs is up." -ForegroundColor Green
Write-Host "  Node: $($ready.NodeUrl)"
Write-Host "  Bot:  $($ready.BotUrl)"
Write-Host 'Stop with:  Get-Process python | ? {$_.MainWindowTitle -eq ''''} | Stop-Process'

function Invoke-TinySocs {
  param([Parameter(Mandatory)][string]$Path, [string]$Secret = $env:MASTER_SHARED_SECRET)
  $style = if ($env:TINYSOCS_HMAC_STYLE) { $env:TINYSOCS_HMAC_STYLE } else { 'pipe' }
  $hdr = New-TinySocsHmacHeaders -Secret $Secret -Style $style -SigPrefix $env:TINYSOCS_SIG_PREFIX
  Invoke-RestMethod -Uri ("http://localhost:8081/" + $Path.TrimStart('/')) -Headers $hdr
}

function Invoke-TinySocsBot {
  param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][hashtable]$Body)
  $style = if ($env:TINYSOCS_HMAC_STYLE) { $env:TINYSOCS_HMAC_STYLE } else { 'pipe' }
  $hdr = New-TinySocsHmacHeaders -Secret $env:BOT_SHARED_SECRET -Style $style -SigPrefix $env:TINYSOCS_SIG_PREFIX
  Invoke-RestMethod -Uri ("http://localhost:8090/" + $Path.TrimStart('/')) -Method Post `
    -Headers $hdr -ContentType application/json -Body ($Body | ConvertTo-Json -Compress)
}

# ---- Doctor (final gate) ----------------------------------------------------
try {
  # Doctor writes formatted lines to the pipeline before emitting the PSObject.
  # Select the *last* pipeline object, which is the structured summary we need.
  $doc = & "$PSScriptRoot\Doctor.ps1" -RepoRoot $RepoRoot | Select-Object -Last 1
} catch {
  Write-Error "Doctor.ps1 failed to execute: $($_.Exception.Message)"
  exit 2
}

# Core checks: if any are false → non-zero exit so CI/scripts can catch it
$critical = @('PythonReady','NodeReady','BotReady','BotAckQueued','SIEMReachable','AnchorsAliasOK','SecretsPresent')
$bad = @()
foreach ($k in $critical) {
  if (-not ($doc.PSObject.Properties.Name -contains $k)) { $bad += "$k(missing)"; continue }
  if (-not ($doc.$k)) { $bad += $k }
}

if ($bad.Count -gt 0) {
  Write-Error ("Doctor failed checks: " + ($bad -join ', '))
  exit 1
}

Write-Host "Doctor checks passed." -ForegroundColor Green