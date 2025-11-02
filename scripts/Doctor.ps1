# scripts/Doctor.ps1
# TinySocs Doctor — quick green/red diagnostics for a Windows host
# - Loads .env
# - Checks Python/venv + key deps
# - Pings Node (/evidence/head) with HMAC (ts-only first, then env style)
# - Pings Bot (/bot/ack) with a signed dry-run ack (fallback to MASTER_SHARED_SECRET)
# - Checks OpenSearch reachability + tinysocs_anchors alias presence
# Returns a PSObject summary and prints a short report.

param(
  [string] $RepoRoot = (Resolve-Path "$PSScriptRoot\..").Path,
  [int]    $DefaultNodePort = 8081,
  [int]    $DefaultBotPort  = 8090
)

$ErrorActionPreference = 'Stop'
Set-Location $RepoRoot

# Ensure TLS 1.2 for OpenSearch over HTTPS
try {
  [System.Net.ServicePointManager]::SecurityProtocol =
    [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12
} catch {}

function Import-DotEnv {
  param([string]$Path)
  if (-not (Test-Path $Path)) { return }
  Get-Content $Path | ForEach-Object {
    $line = $_.Trim()
    if (-not $line -or $line.StartsWith('#') -or ($line -notmatch '=')) { return }
    $k, $v = $line -split '=', 2
    $k = $k.Trim(); $v = $v.Trim().Trim("'").Trim('"')
    # Always set for this process (doctor runs in its own process)
    Set-Item "Env:$k" $v
  }
}

function Get-EnvOrDefault {
  param([Parameter(Mandatory)][string]$Name, [string]$Default = "")
  $v = [Environment]::GetEnvironmentVariable($Name, 'Process')
  if ([string]::IsNullOrWhiteSpace($v)) { $v = [Environment]::GetEnvironmentVariable($Name, 'User') }
  if ([string]::IsNullOrWhiteSpace($v)) { $v = [Environment]::GetEnvironmentVariable($Name, 'Machine') }
  if ([string]::IsNullOrWhiteSpace($v)) { return $Default } else { return $v }
}

function Get-PythonExe {
  param([string]$Root)
  $venvPy = Join-Path $Root ".venv\Scripts\python.exe"
  if (Test-Path $venvPy) { return $venvPy }
  return "python"
}

function Test-PythonDeps {
  param([string]$PyExe)
  $code = @"
import importlib, sys
mods = ['fastapi','uvicorn','requests','pydantic','opensearchpy']
missing = [m for m in mods if importlib.util.find_spec(m) is None]
print(';'.join(missing))
"@
  try {
    $out = & $PyExe -c $code 2>$null
    return ($out -split ';' | Where-Object { $_ -ne '' })
  } catch {
    return @('python-failed')
  }
}

function New-TinySocsHmacHeaders {
  param(
    [Parameter(Mandatory)][string]$Secret,
    [string]$Style = $env:TINYSOCS_HMAC_STYLE,
    [string]$SigPrefix = $env:TINYSOCS_SIG_PREFIX
  )
  if (-not $Style) { $Style = 'pipe' }
  $Style = $Style.ToLower()
  $ts    = [int][DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
  $nonce = [Guid]::NewGuid().ToString('N')

  switch ($Style) {
    'dot'  { $msg = "$ts.$nonce"; $includeNonce = $true }
    'pipe' { $msg = "$ts|$nonce"; $includeNonce = $true }
    default { $msg = "$ts"; $includeNonce = $false } # 'ts'
  }

  $h   = [System.Security.Cryptography.HMACSHA256]::new([Text.Encoding]::UTF8.GetBytes($Secret))
  try {
    $raw = -join ($h.ComputeHash([Text.Encoding]::UTF8.GetBytes($msg)) | ForEach-Object { $_.ToString('x2') })
  } finally { $h.Dispose() }
  $sig = if ($SigPrefix -and $SigPrefix.Trim()) { "sha256=$raw" } else { $raw }

  $hdr = @{
    'X-TinySOCS-Timestamp' = $ts
    'X-TinySOCS-Signature' = $sig
    'User-Agent'           = 'tinysocs/doctor'
  }
  if ($includeNonce) { $hdr['X-TinySOCS-Nonce'] = $nonce }
  return $hdr
}

function Test-HttpReady {
  param([string]$Url, [hashtable]$Headers, [int]$TimeoutSec = 20)
  $t0 = Get-Date
  while ((Get-Date) -lt $t0.AddSeconds($TimeoutSec)) {
    try {
      $r = if ($null -ne $Headers) {
        Invoke-WebRequest -Uri $Url -Headers $Headers -UseBasicParsing -TimeoutSec 4 -ErrorAction Stop
      } else {
        Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 4 -ErrorAction Stop
      }
      if ($r.StatusCode -ge 200 -and $r.StatusCode -lt 500) { return $true }
    } catch { Start-Sleep -Milliseconds 400 }
  }
  return $false
}

function Get-FirstNodeUrl {
  $nodes = ($env:TINYSOCS_NODES -split ',') | Where-Object { $_.Trim() } | Select-Object -First 1
  if (-not $nodes) { return "http://localhost:$DefaultNodePort" }
  return $nodes.Trim()
}

function Get-PortFromUrl {
  param([string]$Url, [int]$DefaultPort)
  try {
    $u = [System.Uri]::new($Url)
    if ($u.Port -gt 0) { return $u.Port } else { return $DefaultPort }
  } catch { return $DefaultPort }
}

function Invoke-NodeHead {
  param([string]$NodeUrl, [string]$Secret)
  $uri = ($NodeUrl.TrimEnd('/') + '/evidence/head')

  # Try ts-only first, then env style, with one short backoff retry
  $hdrTs = New-TinySocsHmacHeaders -Secret $Secret -Style 'ts' -SigPrefix ''
  try {
    return Invoke-RestMethod -Method Get -Uri $uri -Headers $hdrTs -TimeoutSec 10
  } catch {
    try {
      $hdrEnv = New-TinySocsHmacHeaders -Secret $Secret -Style $env:TINYSOCS_HMAC_STYLE -SigPrefix $env:TINYSOCS_SIG_PREFIX
      return Invoke-RestMethod -Method Get -Uri $uri -Headers $hdrEnv -TimeoutSec 10
    } catch {
      Start-Sleep -Milliseconds 600
      return Invoke-RestMethod -Method Get -Uri $uri -Headers $hdrTs -TimeoutSec 10
    }
  }
}

# --- OpenSearch helpers (preemptive Basic auth) -----------------------------
function New-BasicAuthHeaders {
  param([Parameter(Mandatory)][string]$User, [Parameter(Mandatory)][string]$Pass)
  $bytes = [System.Text.Encoding]::ASCII.GetBytes("$User`:$Pass")
  $b64   = [Convert]::ToBase64String($bytes)
  return @{ 'Authorization' = "Basic $b64"; 'Accept' = 'application/json' }
}

function Test-OpenSearch {
  param([string]$Url, [string]$User, [string]$Pass, [bool]$Verify)
  # Optional: disable TLS verify when SIEM_SSL_VERIFY=false (PowerShell 5.1-safe)
  $oldCb = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
  if (-not $Verify) {
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
  }
  try {
    $headers = New-BasicAuthHeaders -User $User -Pass $Pass

    $clusterOk = $false
    try {
      $healthUri = ($Url.TrimEnd('/') + '/_cluster/health')
      $h = Invoke-RestMethod -Method Get -Uri $healthUri -Headers $headers -TimeoutSec 8 -ErrorAction Stop
      $clusterOk = $true
    } catch { $clusterOk = $false }

    $aliasOk = $false
    try {
      $searchUri = ($Url.TrimEnd('/') + '/tinysocs_anchors/_search')
      $payload = '{"size":0}'
      $res = Invoke-RestMethod -Method Post -Uri $searchUri -Headers $headers -TimeoutSec 8 `
              -ContentType 'application/json' -Body $payload -ErrorAction Stop
      $aliasOk = $true
    } catch { $aliasOk = $false }

    # Consider SIEM reachable if either cluster health or alias search works
    return @{ Reachable = ($clusterOk -or $aliasOk); AnchorsAlias = $aliasOk }
  } finally {
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $oldCb
  }
}

function Invoke-BotAck {
  param([string]$BotUrl, [string]$Secret)
  $uri = ($BotUrl.TrimEnd('/') + '/bot/ack')
  $hdr = New-TinySocsHmacHeaders -Secret $Secret -Style $env:TINYSOCS_HMAC_STYLE -SigPrefix $env:TINYSOCS_SIG_PREFIX
  $body = @{ incident_id = "doctor-$(Get-Date -Format 'yyyyMMddHHmmssffff')"; tldr = "doctor ping" } | ConvertTo-Json -Compress
  return Invoke-RestMethod -Method Post -Uri $uri -Headers $hdr -ContentType 'application/json' -Body $body -TimeoutSec 12
}

function Test-BotAckSuccess {
  param($Obj)
  try {
    if ($null -eq $Obj) { return $false }
    if ($Obj.queued -eq $true) { return $true }
    if ($Obj.ok -eq $true)     { return $true }
    if ($Obj.enqueued -eq $true) { return $true }
    if ($Obj.status -and ($Obj.status -match 'ok|queued|accepted|success')) { return $true }
    if ($Obj.id -or $Obj.ack_id) { return $true }
    return $false
  } catch { return $false }
}

# ---- Run checks -------------------------------------------------------------

# Load envs (force into this process so we don't depend on parent proc inheritance)
Import-DotEnv (Join-Path $RepoRoot ".env")
Import-DotEnv (Join-Path $RepoRoot "tinysocs\.env")

# Python + deps
$PyExe = Get-PythonExe -Root $RepoRoot
$missing = Test-PythonDeps -PyExe $PyExe
$pyOk = ($missing.Count -eq 0)

# Node/Bot URLs
$nodeUrl = Get-FirstNodeUrl
$nodePort = Get-PortFromUrl -Url $nodeUrl -DefaultPort $DefaultNodePort
$botUrl = "http://localhost:$DefaultBotPort"

# Node head (ts-only then env style)
$nodeReady = $false
$nodeHead = $null
try {
  $nodeSecret = Get-EnvOrDefault -Name 'MASTER_SHARED_SECRET' -Default 'dev-secret-change-me'
  $nodeHead = Invoke-NodeHead -NodeUrl $nodeUrl -Secret $nodeSecret
  $nodeReady = $true
} catch { $nodeReady = $false }

# Bot docs probe (no auth) to see if service is up (longer timeout)
$botReady = $false
try {
  $botReady = Test-HttpReady -Url ($botUrl + "/docs") -Headers @{} -TimeoutSec 15
} catch { $botReady = $false }

# Bot ack (signed) with fallback to MASTER_SHARED_SECRET and broader success recognition
$botAckOk = $false
$botAckInfo = $null
if ($botReady) {
  $primarySecret   = Get-EnvOrDefault -Name 'BOT_SHARED_SECRET' -Default 'supersecret'
  $secondarySecret = Get-EnvOrDefault -Name 'MASTER_SHARED_SECRET' -Default 'dev-secret-change-me'
  $ackError = $null

  try {
    $botAckInfo = Invoke-BotAck -BotUrl $botUrl -Secret $primarySecret
    $botAckOk = Test-BotAckSuccess -Obj $botAckInfo
    if (-not $botAckOk) {
      throw "unexpected bot ack shape"
    }
  } catch {
    try {
      $botAckInfo = Invoke-BotAck -BotUrl $botUrl -Secret $secondarySecret
      $botAckOk = Test-BotAckSuccess -Obj $botAckInfo
      if (-not $botAckOk) { throw "unexpected bot ack shape (fallback)" }
    } catch {
      $ackError = $_.Exception.Message
      try {
        if ($_.Exception.Response) {
          $sr = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
          $respBody = $sr.ReadToEnd()
          if ($respBody) { $ackError = "$ackError | $respBody" }
        }
      } catch {}
      $botAckInfo = @{ error = $ackError }
      $botAckOk = $false
    }
  }
}

# SIEM reachability
$verifySiem = $true
if ($env:SIEM_SSL_VERIFY) {
  $v = $env:SIEM_SSL_VERIFY.ToLower()
  if ($v -in @('0','false','no','off')) { $verifySiem = $false }
}
$siemUrl  = Get-EnvOrDefault -Name 'SIEM_URL'  -Default 'https://127.0.0.1:9201'
$siemUser = Get-EnvOrDefault -Name 'SIEM_USER' -Default 'admin'
$siemPass = Get-EnvOrDefault -Name 'SIEM_PASS' -Default 'admin'

$siemRes = @{ Reachable = $false; AnchorsAlias = $false }
try {
  $siemRes = Test-OpenSearch -Url $siemUrl -User $siemUser -Pass $siemPass -Verify $verifySiem
} catch {
  $siemRes = @{ Reachable = $false; AnchorsAlias = $false }
}

# HMAC style summary (no secrets)
$hmacStyle = Get-EnvOrDefault -Name 'TINYSOCS_HMAC_STYLE' -Default 'pipe'
if ($hmacStyle) { $hmacStyle = $hmacStyle.ToLower() }
$rawSigPrefix = Get-EnvOrDefault -Name 'TINYSOCS_SIG_PREFIX' -Default ''
if ([string]::IsNullOrWhiteSpace($rawSigPrefix)) { $sigPrefix = 'no' } else { $sigPrefix = 'yes' }

# Secrets presence (treat null/empty/whitespace as missing)
$ms = Get-EnvOrDefault -Name 'MASTER_SHARED_SECRET' -Default ''
$bs = Get-EnvOrDefault -Name 'BOT_SHARED_SECRET' -Default ''
$secretsOk = -not ([string]::IsNullOrWhiteSpace($ms) -or [string]::IsNullOrWhiteSpace($bs))

# Queue file (if configured)
$queuePath = $env:TINYSOCS_QUEUE_PATH
if (-not $queuePath) { $queuePath = $env:ACTIONS_QUEUE_PATH }
if (-not $queuePath) { $queuePath = Join-Path $RepoRoot "data\actions_queue.jsonl" }
$queueExists = Test-Path $queuePath

$result = [pscustomobject]@{
  RepoRoot        = $RepoRoot
  PythonExe       = $PyExe
  PythonReady     = $pyOk
  MissingModules  = $missing -join ', '
  NodeUrl         = $nodeUrl
  NodePort        = $nodePort
  NodeReady       = $nodeReady
  NodeHeadSummary = if ($nodeHead) { "ok=$($nodeHead.ok) seq=$($nodeHead.sequence) cap=$($nodeHead.capability)" } else { $null }
  BotUrl          = $botUrl
  BotReady        = $botReady
  BotAckQueued    = $botAckOk
  BotAckLedger    = if ($botAckInfo -and $botAckInfo.ledger) { $botAckInfo.ledger } else { $null }
  SIEMUrl         = $siemUrl
  SIEMReachable   = $siemRes.Reachable
  AnchorsAliasOK  = $siemRes.AnchorsAlias
  HMACStyle       = $hmacStyle
  SigPrefix       = $sigPrefix
  SecretsPresent  = $secretsOk
  QueuePath       = $queuePath
  QueueExists     = $queueExists
}

# Pretty print summary
Write-Host "TinySocs Doctor summary:" -ForegroundColor Cyan
"{0,-18} {1}" -f "RepoRoot:",        $result.RepoRoot
"{0,-18} {1}" -f "PythonExe:",       $result.PythonExe
"{0,-18} {1}" -f "PythonReady:",     $result.PythonReady
if (-not $result.PythonReady) { "{0,-18} {1}" -f "MissingModules:", $result.MissingModules | Write-Host -ForegroundColor Yellow }
"{0,-18} {1}" -f "NodeUrl:",         $result.NodeUrl
"{0,-18} {1}" -f "NodeReady:",       $result.NodeReady
$nodeHeadLine = if ($result.NodeHeadSummary) { $result.NodeHeadSummary } else { '(n/a)' }
"{0,-18} {1}" -f "NodeHead:",        $nodeHeadLine
"{0,-18} {1}" -f "BotUrl:",          $result.BotUrl
"{0,-18} {1}" -f "BotReady:",        $result.BotReady
"{0,-18} {1}" -f "BotAckQueued:",    $result.BotAckQueued
"{0,-18} {1}" -f "SIEMUrl:",         $result.SIEMUrl
"{0,-18} {1}" -f "SIEMReachable:",   $result.SIEMReachable
"{0,-18} {1}" -f "AnchorsAliasOK:",  $result.AnchorsAliasOK
"{0,-18} {1}" -f "HMACStyle:",       $result.HMACStyle
"{0,-18} {1}" -f "SigPrefix:",       $result.SigPrefix
"{0,-18} {1}" -f "SecretsPresent:",  $result.SecretsPresent
"{0,-18} {1}" -f "QueuePath:",       $result.QueuePath
"{0,-18} {1}" -f "QueueExists:",     $result.QueueExists

# Return structured object for callers/pipelines
$result