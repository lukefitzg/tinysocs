# scripts/Download-Sysmon.ps1
# Download Sysmon from Microsoft Sysinternals and verify its signature.
# Used during build to bundle Sysmon64.exe in the installer.
#
# Usage:
#   .\scripts\Download-Sysmon.ps1
#   .\scripts\Download-Sysmon.ps1 -OutputDir C:\path\to\sysmon-bin

param(
    [string]$OutputDir = (Join-Path (Split-Path -Parent $PSScriptRoot) "sysmon-bin")
)

$ErrorActionPreference = "Stop"

$url = "https://download.sysinternals.com/files/Sysmon.zip"
$zipPath = Join-Path $OutputDir "Sysmon.zip"
$exePath = Join-Path $OutputDir "Sysmon64.exe"

# Skip download if already present and validly signed
if (Test-Path $exePath) {
    $sig = Get-AuthenticodeSignature -FilePath $exePath -ErrorAction SilentlyContinue
    if ($sig -and $sig.Status -eq 'Valid' -and ($sig.SignerCertificate.Subject -like '*CN=Microsoft*')) {
        $hash = (Get-FileHash -Path $exePath -Algorithm SHA256).Hash
        Write-Host "[Download-Sysmon] Sysmon64.exe already present and validly signed."
        Write-Host "[Download-Sysmon] SHA256: $hash"
        exit 0
    }
    Write-Host "[Download-Sysmon] Existing Sysmon64.exe has invalid signature. Re-downloading."
}

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
Write-Host "[Download-Sysmon] Downloading Sysmon from $url..."
Invoke-WebRequest -Uri $url -OutFile $zipPath -UseBasicParsing

Write-Host "[Download-Sysmon] Extracting..."
Expand-Archive -Path $zipPath -DestinationPath $OutputDir -Force

# Find Sysmon64.exe (may be in a subdirectory after extraction)
$candidate = Get-ChildItem -Recurse -File $OutputDir -Filter "Sysmon64.exe" | Select-Object -First 1
if (-not $candidate) { throw "[Download-Sysmon] Sysmon64.exe not found after extraction." }
if ($candidate.FullName -ne $exePath) {
    Copy-Item $candidate.FullName $exePath -Force
}

# Verify Microsoft Authenticode signature
$sig = Get-AuthenticodeSignature -FilePath $exePath
if ($sig.Status -ne 'Valid' -or -not ($sig.SignerCertificate.Subject -like '*CN=Microsoft*')) {
    throw "[Download-Sysmon] Downloaded Sysmon64.exe has invalid Microsoft signature! Status=$($sig.Status)"
}

# Record SHA-256 for audit trail
$hash = (Get-FileHash -Path $exePath -Algorithm SHA256).Hash
Write-Host "[Download-Sysmon] Sysmon64.exe SHA256: $hash"
Set-Content -Path (Join-Path $OutputDir "Sysmon64.exe.sha256") -Value $hash -Encoding ASCII

# Cleanup zip
Remove-Item $zipPath -Force -ErrorAction SilentlyContinue

Write-Host "[Download-Sysmon] Sysmon64.exe ready at $exePath"
