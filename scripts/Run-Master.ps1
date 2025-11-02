# Loads .env then runs master once (used by Scheduled Task)
$ErrorActionPreference='Stop'
$RepoRoot = (Resolve-Path "$PSScriptRoot\..").Path
Set-Location $RepoRoot
. "$PSScriptRoot\_dotenv.ps1"
Import-DotEnv "$RepoRoot\.env"

$py = Join-Path $RepoRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $py)) { py -3 -m venv .venv; & (Join-Path $RepoRoot ".venv\Scripts\pip.exe") install -r requirements.txt }

$rules  = $env:TINYSOCS_CRON_RULES;  if (-not $rules)  { $rules  = "ps_script_block,auth_failed_burst" }
$window = $env:TINYSOCS_CRON_WINDOW; if (-not $window) { $window = "15m" }
& $py -m tinysocs.orchestrator.master --rules $rules --window $window --deadline ($env:MASTER_DEADLINE_SEC ?? "120")

scripts\Run-Verify.ps1

$ErrorActionPreference='Stop'
$RepoRoot = (Resolve-Path "$PSScriptRoot\..").Path
Set-Location $RepoRoot
. "$PSScriptRoot\_dotenv.ps1"
Import-DotEnv "$RepoRoot\.env"

$py = Join-Path $RepoRoot ".venv\Scripts\python.exe"
& $py -m tinysocs.orchestrator.check_ledger --verify