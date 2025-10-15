param(
  [Parameter(Mandatory=$true)]
  [ValidateSet('elastic','opensearch','opensearch-auth')]
  [string]$Backend,

  [switch]$WriteDotEnv,

  # Paths (override if your layout differs)
  [string]$RepoRoot = (Split-Path -Parent $PSCommandPath),
  [string]$WinlogbeatBin = "C:\tinysocs\winlogbeat-bin"
)

$SwitchScript = Join-Path $RepoRoot 'winlogbeat-config\Switch-WinlogbeatOutput.ps1'
if (-not (Test-Path $SwitchScript)) {
  throw "Switcher not found: $SwitchScript"
}

# --- Set env vars for the current shell (TinySocs agent) ---
switch ($Backend) {
  'elastic' {
    $env:SIEM_BACKEND = 'elastic'
    $env:SIEM_URL     = 'http://localhost:9200'
    $env:SIEM_USER    = ''
    $env:SIEM_PASS    = ''
  }
  'opensearch' {
    # HTTP (dev) – NOT recommended for production
    $env:SIEM_BACKEND = 'opensearch'
    $env:SIEM_URL     = 'http://localhost:9201'
    $env:SIEM_USER    = 'admin'
    $env:SIEM_PASS    = 'ChangeMe123!'
  }
  'opensearch-auth' {
    # HTTPS + auth (recommended for your setup)
    $env:SIEM_BACKEND = 'opensearch'
    $env:SIEM_URL     = 'https://localhost:9201'
    $env:SIEM_USER    = 'admin'
    $env:SIEM_PASS    = 'ChangeMe123!'
    $env:OPENSEARCH_TLS_INSECURE = '1'   # if you use self-signed certs (TinySocs can honor this)
  }
}

Write-Host "[SIEM] $($env:SIEM_BACKEND) @ $($env:SIEM_URL)" -ForegroundColor Cyan

# --- Optionally write .env in repo root so VS Code / your app loads it on start ---
if ($WriteDotEnv) {
  $dotEnvPath = Join-Path $RepoRoot '.env'
  $lines = @(
    "SIEM_BACKEND=$($env:SIEM_BACKEND)"
    "SIEM_URL=$($env:SIEM_URL)"
    "SIEM_USER=$($env:SIEM_USER)"
    "SIEM_PASS=$($env:SIEM_PASS)"
    ""
    "# LLM defaults"
    "LLM_MODE=openai"
    "OPENAI_MODEL=gpt-4o-mini"
    "OPENAI_API_KEY=" # leave blank locally; never commit secrets
  )
  Set-Content -Path $dotEnvPath -Value ($lines -join [Environment]::NewLine) -Encoding UTF8
  Write-Host "Updated $dotEnvPath" -ForegroundColor Green
}

# --- Flip Winlogbeat output (this script self-elevates and handles service) ---
& $SwitchScript -Target $Backend -WinlogbeatBin $WinlogbeatBin -ConfigDir (Join-Path $RepoRoot 'winlogbeat-config')

Write-Host "`nDone. TinySocs + Winlogbeat are now pointed at '$Backend'." -ForegroundColor Green
