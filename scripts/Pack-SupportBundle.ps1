param(
  [string]$RepoRoot = (Resolve-Path "$PSScriptRoot\..").Path,
  [string]$OutDir = (Join-Path $PSScriptRoot "..\artifacts\support")
)

$ErrorActionPreference = 'Stop'
Set-Location $RepoRoot
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$work = Join-Path $OutDir "bundle-$stamp"
New-Item -ItemType Directory -Force -Path $work | Out-Null

# collect: envs, doctor, pip, versions, queue, ledger, logs
$paths = @()
$envs = @(".env","tinysocs\.env") | % { if (Test-Path $_) { Copy-Item $_ -Destination (Join-Path $work ("$(Split-Path $_ -Leaf)")) ; $paths += (Join-Path $work (Split-Path $_ -Leaf)) } }

# run Doctor and save JSON
try {
  $doc = & "$PSScriptRoot\Doctor.ps1" -RepoRoot $RepoRoot
  ($doc | ConvertTo-Json -Depth 6) | Out-File -Encoding UTF8 -FilePath (Join-Path $work "doctor.json")
} catch {}

# pip freeze
try {
  $py = if (Test-Path ".venv\Scripts\python.exe") { ".venv\Scripts\python.exe" } else { "python" }
  & $py -V | Out-File -Encoding UTF8 (Join-Path $work "python_version.txt")
  & $py -m pip freeze | Out-File -Encoding UTF8 (Join-Path $work "pip_freeze.txt")
} catch {}

# copy queue
$queuePath = $env:TINYSOCS_QUEUE_PATH; if (-not $queuePath) { $queuePath = $env:ACTIONS_QUEUE_PATH }
if (-not $queuePath) { $queuePath = Join-Path $RepoRoot "tinysocs\actions_queue.jsonl" }
if (Test-Path $queuePath) { Copy-Item $queuePath (Join-Path $work "actions_queue.jsonl") }

# copy ledger
if (Test-Path "tinysocs\ledger") { Copy-Item "tinysocs\ledger\*" (Join-Path $work "ledger") -Recurse -Force }

# copy verify logs if exist
if (Test-Path "logs") { Copy-Item "logs\verify_ledger-*.json" (Join-Path $work "logs") -ErrorAction SilentlyContinue }

# zip
$zip = Join-Path $OutDir "bundle-$stamp.zip"
if (Test-Path $zip) { Remove-Item -Force $zip }
Compress-Archive -Path (Join-Path $work "*") -DestinationPath $zip
Write-Host "Support bundle -> $zip"