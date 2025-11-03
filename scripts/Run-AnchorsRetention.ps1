# TinySocs — prune old anchor docs via unified anchors.py
param(
  [switch]$DryRun
)

$ErrorActionPreference = 'Stop'
Set-Location (Resolve-Path "$PSScriptRoot\..")  # repo root

function Get-PythonExe {
  param([string]$RepoRoot = (Resolve-Path ".").Path)
  $venvPy = Join-Path $RepoRoot ".venv\Scripts\python.exe"
  if (Test-Path $venvPy) { return $venvPy }
  return "python"
}

$RepoRoot = (Resolve-Path "$PSScriptRoot\..").Path
$py = Get-PythonExe -RepoRoot $RepoRoot

# Default to 30 if not set
$days = $env:ANCHORS_RETENTION_DAYS
if (-not $days -or -not ($days -as [int])) { $days = 30 }

# Unified CLI: --prune --retention-days [--dry-run]
$argv = @("-m","tinysocs.orchestrator.anchors","--prune","--retention-days",$days.ToString())
if ($DryRun) { $argv += "--dry-run" }

& $py $argv