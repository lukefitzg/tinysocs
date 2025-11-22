param(
  [string]$OutZip = "$(Join-Path (Split-Path $PSScriptRoot -Parent) 'tinysocs_package.zip')"
)

$ErrorActionPreference = 'Stop'

# Resolve repo root (parent of /scripts)
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path

# Stage dir
$stage = Join-Path $env:TEMP ("tinysocs_stage_{0:yyyyMMdd_HHmmss}" -f (Get-Date))
Write-Host "[*] Staging to $stage"
New-Item -ItemType Directory -Path $stage -Force | Out-Null

# Long-path safe prefixes
$src = "\\?\$RepoRoot"
$dst = "\\?\$stage"

# Log file
$robolog = Join-Path $stage 'robocopy.log'

Write-Host "[*] Copying repo minus build/venv/cache/noise..."
# Fail fast, no retries; avoid junction loops; quiet noise
$rc = $null
& robocopy `
  $src $dst `
  /E `
  /COPY:DAT /DCOPY:DAT `
  /R:0 /W:0 /MT:8 `
  /XJ /NFL /NDL /NP `
  /XD '.git' '.venv' 'artifacts' '__pycache__' '.mypy_cache' '.pytest_cache' '.ruff_cache' '.tox' 'dist' 'build' `
  /XF '*.pyc' '*.pyo' '*.log' '*.tmp' 'Thumbs.db' 'desktop.ini' `
  /TEE /LOG:$robolog | Out-Null
$rc = $LASTEXITCODE

# Robocopy exit codes < 8 are success (0..7 = OK-ish). 8+ = failure.
if ($rc -ge 8) {
  Write-Warning "Robocopy failed (exit $rc). See: $robolog"

  # Fallback: only tracked files, zero locks, super reliable
  if (Test-Path (Join-Path $RepoRoot '.git')) {
    Write-Host "[*] Falling back to 'git archive' of HEAD..."
    if (Test-Path $OutZip) { Remove-Item $OutZip -Force }
    git -C $RepoRoot archive -o $OutZip --format=zip HEAD
    Write-Host "[+] Done via git archive: $OutZip"
    exit 0
  }

  throw "Robocopy failed with exit code $rc. Inspect $robolog"
}

Write-Host "[*] Writing zip $OutZip"
if (Test-Path $OutZip) { Remove-Item $OutZip -Force }
Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $OutZip -Force

Write-Host "[*] Cleaning up"
Remove-Item $stage -Recurse -Force

Write-Host "[+] Done. Package at $OutZip"