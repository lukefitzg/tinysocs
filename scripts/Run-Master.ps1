# Loads .env then runs master once (used by Scheduled Task)
$ErrorActionPreference = 'Stop'

# Resolve repo root and load .env
$RepoRoot = (Resolve-Path "$PSScriptRoot\..").Path
Set-Location $RepoRoot
. "$PSScriptRoot\_dotenv.ps1"
Import-DotEnv "$RepoRoot\.env"

# Ensure venv exists; bootstrap if missing
$VenvPy  = Join-Path $RepoRoot ".venv\Scripts\python.exe"
$VenvPip = Join-Path $RepoRoot ".venv\Scripts\pip.exe"
if (-not (Test-Path $VenvPy)) {
  Write-Host "[TinySocs] Creating venv and installing package (editable)..." -ForegroundColor Cyan
  py -3 -m venv .venv
  & $VenvPip install --upgrade pip
  # Prefer editable install from pyproject; fallback to requirements if present
  if (Test-Path (Join-Path $RepoRoot "pyproject.toml")) {
    & $VenvPip install -e ".[dev]"
  } elseif (Test-Path (Join-Path $RepoRoot "requirements.txt")) {
    & $VenvPip install -r (Join-Path $RepoRoot "requirements.txt")
  }
}

# Resolve CLI exe (preferred) or python -m (fallback)
$CliExe = Join-Path $RepoRoot ".venv\Scripts\tinysocs-master.exe"

# Cron knobs (env with sane defaults)
$rules    = $env:TINYSOCS_CRON_RULES;   if (-not $rules)    { $rules    = "ps_script_block,auth_failed_burst" }
$window   = $env:TINYSOCS_CRON_WINDOW;  if (-not $window)   { $window   = "15m" }
$deadline = $env:MASTER_DEADLINE_SEC;   if (-not $deadline) { $deadline = "120" }

# Execute
if (Test-Path $CliExe) {
  & $CliExe --rules $rules --window $window --deadline $deadline
} else {
  & $VenvPy -m tinysocs.orchestrator.master --rules $rules --window $window --deadline $deadline
}
