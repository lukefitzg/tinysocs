# TinySocs-Ensure.ps1 — bootstrap venv + entry points, no PATH assumptions
param(
  [Parameter(Mandatory=$true)][ValidateSet('master','node','agent')]
  [string]$Component
)

$ErrorActionPreference = "Stop"

# Resolve repo root from this script’s location
$ScriptDir = Split-Path -Parent $PSCommandPath
$RepoRoot  = Split-Path -Parent $ScriptDir          # ..\tinysocs
if (-not (Test-Path (Join-Path $RepoRoot "pyproject.toml"))) {
  throw "Could not locate repo root next to scripts\. Expected pyproject.toml in $RepoRoot"
}

# Ensure Python exists
$py = (Get-Command python -ErrorAction SilentlyContinue)
if (-not $py) { throw "Python not found on PATH. Please install Python 3.10+." }

# Ensure venv exists
$VenvDir = Join-Path $RepoRoot ".venv"
$Activate = Join-Path $VenvDir "Scripts\Activate.ps1"
$ExeDir   = Join-Path $VenvDir "Scripts"

if (-not (Test-Path $VenvDir)) {
  Write-Host "[TinySocs] Creating venv at $VenvDir"
  & python -m venv $VenvDir
}

# Ensure tinysocs is installed (editable)
$tinysocsMarker = Join-Path $VenvDir "Lib\site-packages\tinysocs.egg-link"
$NeedsInstall = -not (Test-Path $tinysocsMarker)
if ($NeedsInstall) {
  Write-Host "[TinySocs] Installing package in editable mode (.[dev])"
  & $ExeDir\python.exe -m pip install --upgrade pip | Out-Null
  & $ExeDir\pip.exe install -e "$RepoRoot.[dev]"
}

# Put venv Scripts on PATH for this process so console scripts resolve
$env:Path = "$ExeDir;$env:Path"

# Prefer console EXE; fall back to python -m
switch ($Component) {
  'master' {
    $exe = Join-Path $ExeDir "tinysocs-master.exe"
    if (Test-Path $exe) { & $exe @Args; break }
    & $ExeDir\python.exe -m tinysocs.orchestrator.master @Args
  }
  'node' {
    $exe = Join-Path $ExeDir "tinysocs-node.exe"
    if (Test-Path $exe) { & $exe @Args; break }
    & $ExeDir\python.exe -m tinysocs.node @Args
  }
  'agent' {
    $exe = Join-Path $ExeDir "tinysocs-agent.exe"
    if (Test-Path $exe) { & $exe @Args; break }
    & $ExeDir\python.exe -m tinysocs.agent.main @Args
  }
}
