# integrations/sysmon/install_sysmon.ps1
param(
  [string]$ConfigPath
)

$ErrorActionPreference = 'Stop'

# Resolve paths
$scriptDir = Split-Path -Parent $PSCommandPath               # ...\integrations\sysmon
$repoRoot  = (Get-Item $scriptDir).Parent.Parent.FullName    # repo root
$binDir    = Join-Path $repoRoot "sysmon-bin"
$sysmonExe = Join-Path $binDir "Sysmon64.exe"

# Default config
if (-not $ConfigPath) { $ConfigPath = Join-Path $scriptDir "sysmon-config.xml" }

Write-Host "Repo:     $repoRoot"
Write-Host "BinDir:   $binDir"
Write-Host "Sysmon:   $sysmonExe"
Write-Host "Config:   $ConfigPath"

# Ensure dirs
New-Item -ItemType Directory -Force -Path $binDir | Out-Null

# Download Sysmon if missing (official Sysinternals CDN)
function Get-Sysmon {
  param([string]$DestPath)

  $zipPath = Join-Path (Split-Path $DestPath -Parent) "Sysmon.zip"
  $url     = "https://download.sysinternals.com/files/Sysmon.zip"

  Write-Host "Downloading Sysmon from $url ..."
  Invoke-WebRequest -Uri $url -OutFile $zipPath -UseBasicParsing

  Write-Host "Extracting Sysmon64.exe ..."
  Expand-Archive -Path $zipPath -DestinationPath (Split-Path $DestPath -Parent) -Force

  # Locate Sysmon64.exe inside the extracted folder
  $candidate = Get-ChildItem -Recurse -File (Split-Path $DestPath -Parent) -Filter "Sysmon64.exe" | Select-Object -First 1
  if (-not $candidate) { throw "Sysmon64.exe not found after extraction." }

  Copy-Item $candidate.FullName $DestPath -Force
  Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
}

if (-not (Test-Path $sysmonExe)) {
  Get-Sysmon -DestPath $sysmonExe
}

# Verify Microsoft signature
$sig = Get-AuthenticodeSignature -FilePath $sysmonExe
if ($sig.Status -ne 'Valid' -or -not ($sig.SignerCertificate.Subject -like '*CN=Microsoft*')) {
  throw "Sysmon64.exe signature invalid or not Microsoft: $($sig.Status) [$($sig.SignerCertificate.Subject)]"
}

# Validate config presence
if (-not (Test-Path $ConfigPath)) { throw "Config not found: $ConfigPath" }

# Decide install/update mode
# If Sysmon service exists -> update config; else -> install fresh
$svc = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
if ($svc) {
  Write-Host "Sysmon service found — updating configuration..."
  & $sysmonExe -c "`"$ConfigPath`"" | Write-Host
} else {
  Write-Host "Installing Sysmon..."
  & $sysmonExe -accepteula -i "`"$ConfigPath`"" | Write-Host
}

Write-Host "Sysmon install/update finished."
