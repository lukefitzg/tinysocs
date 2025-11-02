param(
  [string]$BotUrl   = "http://localhost:8090",
  [string]$IncidentId = ("test-" + (Get-Date -Format "yyyyMMddHHmmss")),
  [string]$Tldr     = "ack via helper",
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

if (-not $Secret -or [string]::IsNullOrWhiteSpace($Secret)) { $Secret = "supersecret" }
if (-not $Style  -or [string]::IsNullOrWhiteSpace($Style))  { $Style  = "pipe" }
# SigPrefix can be empty — that means “raw” signature

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
  $hdr=@{ 'X-TinySOCS-Timestamp'=$ts; 'X-TinySOCS-Signature'=$sig; 'User-Agent'='tinysocs/send-ack' }
  if($n){ $hdr['X-TinySOCS-Nonce']=$nonce }
  return $hdr
}

$headers = New-TinySocsHmacHeaders -Secret $Secret -Style $Style -SigPrefix $SigPrefix
$body = @{ incident_id=$IncidentId; tldr=$Tldr } | ConvertTo-Json -Compress

$uri = ($BotUrl.TrimEnd('/') + "/bot/ack")
$res = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -ContentType 'application/json' -Body $body
$res | ConvertTo-Json -Depth 6