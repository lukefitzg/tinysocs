[CmdletBinding()]
param([switch]$Zip)
$ErrorActionPreference = "Stop"

$here     = Split-Path -Parent $MyInvocation.MyCommand.Path
$repo     = (Resolve-Path (Join-Path $here "..")).Path
$specPath = Join-Path $repo "packaging\tinysocs-quickstart.spec"
$distRoot = Join-Path $repo "artifacts\dist"
$venvPy   = Join-Path $repo ".venv\Scripts\python.exe"

if (-not (Test-Path $specPath)) { Write-Error "Spec not found at $specPath"; exit 1 }
New-Item -ItemType Directory -Force -Path $distRoot | Out-Null

# 0) Make sure flat packages AND their subpackages are real packages
$pkgInits = @(
  "api\__init__.py",
  "orchestrator\__init__.py",
  "agent\__init__.py",
  "agent\adapters\__init__.py",
  "agent\detections\__init__.py",
  "agent\models\__init__.py"
)
foreach ($rel in $pkgInits) {
  $p = Join-Path $repo $rel
  $d = Split-Path $p
  if (-not (Test-Path $d)) { New-Item -ItemType Directory -Force -Path $d | Out-Null }
  if (-not (Test-Path $p)) { New-Item -ItemType File -Force -Path $p | Out-Null }
}

# 1) Ensure PyInstaller & hooks contrib
$piCmd = Get-Command pyinstaller -ErrorAction SilentlyContinue
if (-not $piCmd) {
  Write-Host "Installing pyinstaller into venv..." -ForegroundColor Yellow
  if (Test-Path $venvPy) { & $venvPy -m pip install -U pip pyinstaller _pyinstaller_hooks_contrib | Out-Null }
  else { python -m pip install -U pip pyinstaller _pyinstaller_hooks_contrib | Out-Null }
}

# 2) Mirror flat rules.yaml into package if needed (engine uses packaged path)
$pkgRules  = Join-Path $repo "tinysocs\agent\detections\rules.yaml"
$flatRules = Join-Path $repo "agent\detections\rules.yaml"
if (-not (Test-Path $pkgRules) -and (Test-Path $flatRules)) {
  New-Item -ItemType Directory -Force -Path (Split-Path $pkgRules) | Out-Null
  Copy-Item $flatRules $pkgRules -Force
  Write-Host "Copied rules.yaml into package -> $pkgRules"
}

# 3) Clean & build
Remove-Item -Recurse -Force (Join-Path $repo "build") -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force (Join-Path $repo "dist")  -ErrorAction SilentlyContinue

Write-Host "Building TinySocs-Quickstart (onedir)..." -ForegroundColor Cyan
if (Get-Command pyinstaller -ErrorAction SilentlyContinue) {
  & pyinstaller -y --clean $specPath
} else {
  & $venvPy -m PyInstaller -y --clean $specPath
}

$builtDir = Join-Path $repo "dist\TinySocs-Quickstart"
if (-not (Test-Path $builtDir)) { Write-Error "Build failed; $builtDir not found"; exit 1 }

$outDir = Join-Path $distRoot "TinySocs-Quickstart"
Remove-Item -Recurse -Force $outDir -ErrorAction SilentlyContinue
Copy-Item -Recurse -Force $builtDir $outDir

Write-Host "Output folder: $outDir" -ForegroundColor Green
Write-Host "Run: $outDir\TinySocs-Quickstart.exe" -ForegroundColor Green

if ($Zip) {
  $zipPath = Join-Path $distRoot "TinySocs-Quickstart.zip"
  if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  [System.IO.Compression.ZipFile]::CreateFromDirectory($outDir, $zipPath)
  Write-Host "ZIP bundle: $zipPath" -ForegroundColor Green
}