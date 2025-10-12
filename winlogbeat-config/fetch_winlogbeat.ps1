# Downloads and unpacks Winlogbeat for Windows x64 to C:\tinysocs\winlogbeat-bin
# Then preserves your config from winlogbeat-config\winlogbeat.yml

param(
  [string]$Version = "9.1.5"  # adjust if you need a different version
)

$ErrorActionPreference = "Stop"

$Base = "C:\tinysocs"
$Dest = Join-Path $Base "winlogbeat-bin"
$Zip  = Join-Path $Base "winlogbeat-$Version-windows-x86_64.zip"
$Url  = "https://artifacts.elastic.co/downloads/beats/winlogbeat/winlogbeat-$Version-windows-x86_64.zip"

Write-Host "Downloading Winlogbeat $Version ..."
if (!(Test-Path $Zip)) {
  Invoke-WebRequest -Uri $Url -OutFile $Zip
} else {
  Write-Host "Zip already exists: $Zip"
}

Write-Host "Extracting to $Dest ..."
if (Test-Path $Dest) { Remove-Item -Recurse -Force $Dest }
Expand-Archive -Path $Zip -DestinationPath $Base -Force

# The zip expands as: C:\tinysocs\winlogbeat-$Version-windows-x86_64
$Expanded = Join-Path $Base "winlogbeat-$Version-windows-x86_64"
Rename-Item -Path $Expanded -NewName "winlogbeat-bin" -Force

# Copy your config into place
$CfgSrc = Join-Path $Base "winlogbeat-config\winlogbeat.yml"
$CfgDst = Join-Path $Dest "winlogbeat.yml"
Copy-Item $CfgSrc $CfgDst -Force

Write-Host "Done. Binary at: $Dest\winlogbeat.exe"
Write-Host "Config at:      $CfgDst"

Write-Host ""
Write-Host "Install the service (PowerShell as Administrator):"
Write-Host "  cd `"$Dest`""
Write-Host "  .\install-service-winlogbeat.ps1"
Write-Host "  Start-Service winlogbeat"
