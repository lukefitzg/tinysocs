$here = Split-Path -Parent $PSCommandPath
$repo = Split-Path -Parent (Split-Path -Parent $PSCommandPath)

$binDir    = Join-Path $repo "sysmon-bin"
$sysmonExe = Join-Path $binDir "Sysmon64.exe"

if (-not (Test-Path $sysmonExe)) {
  Write-Host "Sysmon64.exe not found at $sysmonExe"
  Write-Host "Place Sysmon64.exe into sysmon-bin to uninstall cleanly."
  exit 1
}

Write-Host "Uninstalling Sysmon..."
Start-Process -FilePath $sysmonExe -ArgumentList '-u' -Verb RunAs -Wait
Start-Sleep -Seconds 2
Get-Service -Name 'Sysmon64' -ErrorAction SilentlyContinue | Format-Table Status,Name,DisplayName
Write-Host "Sysmon uninstall finished."
