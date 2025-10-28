# TinySOCS - Ledger Health + Retention
param(
  [int]$FileRetentionDays   = 14,
  [int]$AnchorRetentionDays = 30
)

$ErrorActionPreference = 'Stop'
Set-Location (Split-Path -Parent $MyInvocation.MyCommand.Path)

# --- TLS + self-signed defaults (esp. WinPS 5.1) ---
if ($PSVersionTable.PSVersion.Major -le 5) {
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
}
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

# --- Load .env if available (best-effort, simple KEY=VALUE parser) ---
try {
  $root = (Resolve-Path "$PSScriptRoot\..\..").Path
  $envFile = Join-Path $root ".env"
  if (Test-Path $envFile) {
    Get-Content $envFile | Where-Object { $_ -match '^\s*[^#\s]+' } | ForEach-Object {
      $k,$v = $_ -split '=',2
      if ($k -and $v) { [Environment]::SetEnvironmentVariable($k.Trim(), $v.Trim()) }
    }
  }
} catch {}

# --- On-disk ledger retention ---
if ($env:TINYSOCS_LEDGER_DIR) {
  try {
    Get-ChildItem "$env:TINYSOCS_LEDGER_DIR\*.jsonl" -ErrorAction SilentlyContinue |
      Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-$FileRetentionDays) } |
      Remove-Item -Force -ErrorAction SilentlyContinue
  } catch {}
}

# --- Verify heads vs anchors -> logs\ledger-health.json (one JSON object per line) ---
try {
  $logDir  = Join-Path $root 'logs'
  if (!(Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir | Out-Null }
  $logFile = Join-Path $logDir 'ledger-health.json'

  $env:PYTHONWARNINGS = 'ignore'  # hush urllib3 self-signed warnings
  $py = Join-Path $root ".venv\Scripts\python.exe"
  $verifyOut = & $py -m tinysocs.orchestrator.check_ledger --verify 2>$null

  $ts = (Get-Date).ToUniversalTime().ToString('s') + 'Z'
  if ($LASTEXITCODE -eq 0 -and $verifyOut) {
    $obj = @{ ts = $ts; results = (ConvertFrom-Json $verifyOut) }
    Add-Content -Path $logFile -Value ($obj | ConvertTo-Json -Compress)
  } else {
    $obj = @{ ts = $ts; ok = $false; reason = 'verify_failed' }
    Add-Content -Path $logFile -Value ($obj | ConvertTo-Json -Compress)
  }
} catch {
  try {
    $obj = @{ ts = ((Get-Date).ToUniversalTime().ToString('s') + 'Z'); ok = $false; reason = 'verify_exception'; error = "$_" }
    Add-Content -Path (Join-Path $root 'logs\ledger-health.json') -Value ($obj | ConvertTo-Json -Compress)
  } catch {}
}

# --- Anchor retention (requires 'anchored_at' mapped as date) ---
try {
  if ($env:SIEM_URL -and $env:SIEM_USER -and $env:SIEM_PASS) {
    $auth = "$($env:SIEM_USER):$($env:SIEM_PASS)"

    # Build temp JSON bodies as ASCII (no BOM) to avoid PS quoting issues
    $tmpCount  = Join-Path $env:TEMP "ts_count.json"
    $tmpDelete = Join-Path $env:TEMP "ts_delete.json"

    $jsonRange = '{"query":{"range":{"anchored_at":{"lt":"now-' + $AnchorRetentionDays + 'd/d"}}}}'
    Set-Content -Path $tmpCount  -Value $jsonRange -NoNewline -Encoding ascii
    Set-Content -Path $tmpDelete -Value $jsonRange -NoNewline -Encoding ascii

    # Optional preview count (discard output, but ensures API is reachable)
    & curl.exe -s -k -u $auth -H "Content-Type: application/json" -X POST `
      "$($env:SIEM_URL)/tinysocs_anchors/_count" --data-binary "@$tmpCount" | Out-Null

    # Actual delete
    & curl.exe -s -k -u $auth -H "Content-Type: application/json" -X POST `
      "$($env:SIEM_URL)/tinysocs_anchors/_delete_by_query?conflicts=proceed" --data-binary "@$tmpDelete" | Out-Null

    # Cleanup
    Remove-Item $tmpCount,$tmpDelete -ErrorAction SilentlyContinue
  }
} catch {
  # If mapping/alias/auth isn’t ready yet, skip quietly so the task never fails hard
}
