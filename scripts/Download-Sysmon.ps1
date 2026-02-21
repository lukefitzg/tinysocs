# scripts/Download-Sysmon.ps1
# Download Sysmon from Microsoft Sysinternals and verify its signature.
# Used during build to bundle Sysmon64.exe and Sysmon64a.exe in the installer.
# Sysmon64a.exe is the native ARM64 build required on ARM64 Windows hosts.
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
$exePath  = Join-Path $OutputDir "Sysmon64.exe"
$exePathA = Join-Path $OutputDir "Sysmon64a.exe"   # ARM64 native build

# Skip download if both binaries are already present and validly signed
$x64ok = $false
$arm64ok = $false
if (Test-Path $exePath) {
    $sig = Get-AuthenticodeSignature -FilePath $exePath -ErrorAction SilentlyContinue
    if ($sig -and $sig.Status -eq 'Valid' -and ($sig.SignerCertificate.Subject -like '*CN=Microsoft*')) {
        $x64ok = $true
    }
}
if (Test-Path $exePathA) {
    $sig = Get-AuthenticodeSignature -FilePath $exePathA -ErrorAction SilentlyContinue
    if ($sig -and $sig.Status -eq 'Valid' -and ($sig.SignerCertificate.Subject -like '*CN=Microsoft*')) {
        $arm64ok = $true
    }
}
if ($x64ok -and $arm64ok) {
    $hash  = (Get-FileHash -Path $exePath  -Algorithm SHA256).Hash
    $hashA = (Get-FileHash -Path $exePathA -Algorithm SHA256).Hash
    Write-Host "[Download-Sysmon] Sysmon64.exe and Sysmon64a.exe already present and validly signed."
    Write-Host "[Download-Sysmon] Sysmon64.exe  SHA256: $hash"
    Write-Host "[Download-Sysmon] Sysmon64a.exe SHA256: $hashA"
    exit 0
}
if (-not $x64ok) {
    Write-Host "[Download-Sysmon] Sysmon64.exe missing or has invalid signature. Will download."
}
if (-not $arm64ok) {
    Write-Host "[Download-Sysmon] Sysmon64a.exe missing or has invalid signature. Will download."
}

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
Write-Host "[Download-Sysmon] Downloading Sysmon from $url..."
$downloaded = $false
$curlExe = Get-Command curl.exe -ErrorAction SilentlyContinue
if ($curlExe) {
    & curl.exe -L --tlsv1.2 -o $zipPath $url
    if ($LASTEXITCODE -eq 0 -and (Test-Path $zipPath)) { $downloaded = $true }
}
if (-not $downloaded) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $url -OutFile $zipPath -UseBasicParsing
}

Write-Host "[Download-Sysmon] Extracting..."
Expand-Archive -Path $zipPath -DestinationPath $OutputDir -Force

# Find and copy Sysmon64.exe (x64) and Sysmon64a.exe (ARM64)
foreach ($filter in @("Sysmon64.exe", "Sysmon64a.exe")) {
    $dest = Join-Path $OutputDir $filter
    $candidate = Get-ChildItem -Recurse -File $OutputDir -Filter $filter |
                    Where-Object { $_.FullName -ne $dest } |
                    Select-Object -First 1
    if ($candidate) {
        Copy-Item $candidate.FullName $dest -Force
    }
    if (-not (Test-Path $dest)) {
        if ($filter -eq "Sysmon64.exe") {
            throw "[Download-Sysmon] $filter not found after extraction."
        } else {
            Write-Host "[Download-Sysmon] WARNING: $filter not found in archive (ARM64 install not supported on this build)."
        }
    }
}

# Verify Microsoft Authenticode signatures
foreach ($exe in @($exePath, $exePathA)) {
    if (-not (Test-Path $exe)) { continue }
    $sig = Get-AuthenticodeSignature -FilePath $exe
    if ($sig.Status -ne 'Valid' -or -not ($sig.SignerCertificate.Subject -like '*CN=Microsoft*')) {
        throw "[Download-Sysmon] $([System.IO.Path]::GetFileName($exe)) has invalid Microsoft signature! Status=$($sig.Status)"
    }
    $hash = (Get-FileHash -Path $exe -Algorithm SHA256).Hash
    $label = [System.IO.Path]::GetFileName($exe)
    Write-Host "[Download-Sysmon] $label SHA256: $hash"
    Set-Content -Path "$exe.sha256" -Value $hash -Encoding ASCII
}

# Cleanup zip
Remove-Item $zipPath -Force -ErrorAction SilentlyContinue

Write-Host "[Download-Sysmon] Sysmon64.exe ready at $exePath"
if (Test-Path $exePathA) {
    Write-Host "[Download-Sysmon] Sysmon64a.exe (ARM64) ready at $exePathA"
}
