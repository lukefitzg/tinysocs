param(
  [Parameter(Mandatory)]
  [ValidateSet('block_ip','disable_user','isolate_host','open_ticket')]
  [string]$Action,

  # Use ONE of these three. Priority: Params -> ParamsJson -> ParamsKv
  [object]$Params,                           # ex: @{ ip = '203.0.113.10' }  (only works with -Command)
  [string]$ParamsJson,                       # ex: '{"ip":"203.0.113.10"}'
  [string]$ParamsKv,                         # ex: 'ip=203.0.113.10;note=test'

  [string]$Who,
  [string]$BotUrl   = "http://localhost:8090",
  [string]$Secret   = $env:BOT_SHARED_SECRET,
  [string]$Style    = $env:TINYSOCS_HMAC_STYLE,
  [string]$SigPrefix = $env:TINYSOCS_SIG_PREFIX
)

$ErrorActionPreference = 'Stop'

function Import-DotEnv { param([string]$Path)
  if (-not (Test-Path $Path)) { return }
  Get-Content $Path | ForEach-Object {
    $l=$_.Trim(); if(-not $l -or $l.StartsWith('#') -or $l -notmatch '='){return}
    $k,$v=$l -split '=',2; Set-Item "Env:$($k.Trim())" ($v.Trim().Trim("'").Trim('"'))
  }
}
Import-DotEnv (Join-Path $PSScriptRoot "..\.env")
Import-DotEnv (Join-Path $PSScriptRoot "..\tinysocs\.env")

if ([string]::IsNullOrWhiteSpace($Secret)) { $Secret = "supersecret" }
if ([string]::IsNullOrWhiteSpace($Style))  { $Style  = "pipe" }

function Parse-Kv([string]$s){
  $h=@{}; if([string]::IsNullOrWhiteSpace($s)){return $h}
  foreach($pair in $s.Split(';')){
    if([string]::IsNullOrWhiteSpace($pair)){continue}
    $k,$v = $pair.Split('=',2)
    if($k){ $h[$k.Trim()] = $v.Trim() }
  }
  return $h
}

function LooksLikeIPv4([string]$s){
  return $s -match '^(25[0-5]|2[0-4]\d|1\d\d|\d?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|\d?\d)){3}$'
}

function New-TinySocsHmacHeaders {
  param([string]$Secret,[string]$Style='pipe',[string]$SigPrefix)
  $Style = $Style.ToLower()
  $ts=[int][DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
  $nonce=[Guid]::NewGuid().ToString('N')
  switch($Style){
    'dot' { $msg="$ts.$nonce"; $n=$true }
    'pipe'{ $msg="$ts|$nonce"; $n=$true }
    default{ $msg="$ts"; $n=$false }
  }
  $h=[System.Security.Cryptography.HMACSHA256]::new([Text.Encoding]::UTF8.GetBytes($Secret))
  try { $raw = -join ($h.ComputeHash([Text.Encoding]::UTF8.GetBytes($msg)) | ForEach-Object { $_.ToString('x2') }) } finally { $h.Dispose() }
  $sig = if ($SigPrefix -and $SigPrefix.Trim()) { "sha256=$raw" } else { $raw }
  $hdr=@{ 'X-TinySOCS-Timestamp'=$ts; 'X-TinySOCS-Signature'=$sig; 'User-Agent'='tinysocs/send-exec' }
  if($n){ $hdr['X-TinySOCS-Nonce']=$nonce }
  return $hdr
}

$headers = New-TinySocsHmacHeaders -Secret $Secret -Style $Style -SigPrefix $SigPrefix

# Build params (robust fallbacks)
$ParamsObj = @{}
if ($null -ne $Params) {
  if ($Params -is [hashtable] -or $Params -is [pscustomobject]) {
    $ParamsObj = $Params
  } elseif ($Params -is [string]) {
    try { $ParamsObj = ConvertFrom-Json $Params -Depth 50 } catch { $ParamsObj = Parse-Kv $Params }
  }
} elseif ($ParamsJson) {
  try {
    # If the JSON was shell-mangled (e.g. {"ip":203.0.113.10}), try to rescue by quoting dotted tokens
    try { $ParamsObj = ConvertFrom-Json $ParamsJson -Depth 50 }
    catch {
      $fixed = $ParamsJson -replace '(:\s*)(\d+\.\d+\.\d+\.\d+)(\s*[,}])','$1"$2"$3'
      $ParamsObj = ConvertFrom-Json $fixed -Depth 50
    }
  } catch {
    if (LooksLikeIPv4 $ParamsJson) { $ParamsObj = @{ ip = $ParamsJson } }
    else { throw "Could not parse -ParamsJson. Try -ParamsKv 'ip=203.0.113.10'." }
  }
} elseif ($ParamsKv) {
  $ParamsObj = Parse-Kv $ParamsKv
}

$body = @{ action = $Action; params = $ParamsObj }
if ($Who) { $body['who'] = $Who }

$uri = ($BotUrl.TrimEnd('/') + "/bot/exec")
$res = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -ContentType 'application/json' -Body ($body | ConvertTo-Json -Compress -Depth 8)
$res | ConvertTo-Json -Depth 8