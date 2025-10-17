param([string]$ConfigPath)

$scriptDir = Split-Path -Parent $PSCommandPath               # ...\integrations\sysmon
$repo      = (Get-Item $scriptDir).Parent.Parent.FullName    # ...\tinysocs (repo root)

if (-not $ConfigPath) { $ConfigPath = Join-Path $scriptDir "sysmon-config.xml" }

$binDir    = Join-Path $repo "sysmon-bin"
$sysmonExe = Join-Path $binDir "Sysmon64.exe"

Write-Host "repo=$repo"
Write-Host "binDir=$binDir"
Write-Host "sysmonExe=$sysmonExe"
Write-Host "config=$ConfigPath"

if (-not (Test-Path $sysmonExe)) { Write-Error "Sysmon64.exe not found at $sysmonExe"; exit 1 }
if (-not (Test-Path $ConfigPath)) { Write-Error "Config not found at $ConfigPath"; exit 1 }

Start-Process -FilePath $sysmonExe -ArgumentList @('-accepteula','-i',"`"$ConfigPath`"") -Verb RunAs -Wait
Write-Host "Sysmon install/update finished."
