$ErrorActionPreference='Stop'
$RepoRoot = (Resolve-Path "$PSScriptRoot\..").Path
Set-Location $RepoRoot
. "$PSScriptRoot\_dotenv.ps1"
Import-DotEnv "$RepoRoot\.env"

$py = Join-Path $RepoRoot ".venv\Scripts\python.exe"
$days = $env:ANCHORS_RETENTION_DAYS; if (-not $days) { $days = 30 }
& $py -m tinysocs.orchestrator.anchors_retention --days $days