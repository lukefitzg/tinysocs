
  [CmdletBinding()]
  param(
    [string]$OpenSearchPort = "9201"
  )

  $scriptsDir = Join-Path (Join-Path $env:ProgramData "TinySocs") "scripts"
  $logsDir    = Join-Path (Join-Path $env:ProgramData "TinySocs") "logs"

  New-Item -ItemType Directory -Force -Path $scriptsDir | Out-Null
  New-Item -ItemType Directory -Force -Path $logsDir    | Out-Null

  $scriptPath = Join-Path $scriptsDir "installer-set-siem-creds-system.ps1"
  $outJson    = Join-Path $logsDir "siem-creds-system.json"

  $modulePath = Join-Path (Join-Path $env:ProgramFiles "TinySocs") "modules\TinySocs.Installer.psm1"

  $payload = @"
`$ErrorActionPreference = 'Stop'

Import-Module `"$modulePath`" -Force -DisableNameChecking -WarningAction SilentlyContinue

`$siem = Get-TSSiemCredsCanonical -OpenSearchPort `"$OpenSearchPort`"

# Force canonical localhost (avoid regressions from older 127.0.0.1 defaults)
if (`$siem.url -match '^https://127\.0\.0\.1(:\d+)?') {
  `$siem.url = `$siem.url -replace '^https://127\.0\.0\.1', 'https://localhost'
}

Set-TSCredential -Name 'TinySocs/SIEM/Creds' -Secret (`$siem | ConvertTo-Json -Compress)

(Get-TSCredential -Name 'TinySocs/SIEM/Creds') | Out-File -Encoding utf8 `"$outJson`"
"@

  Set-Content -LiteralPath $scriptPath -Value $payload -Encoding UTF8 -Force

  Invoke-TSAsSystemOnce -Name "InstallerSetSiemCredsSystem" -ScriptPath $scriptPath -TimeoutSeconds 90

  if (-not (Test-Path -LiteralPath $outJson)) {
    throw "Ensure-TSSiemCredsSystemCanonical: expected proof file not found: $outJson"
  }

  return $outJson

