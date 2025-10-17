Set-Location -Path (Split-Path $PSCommandPath)
. .\model_toggles.ps1
# Pin the version if you like; otherwise just call Ensure-TinySOCS-Agents
# Ensure-WinlogbeatSingleton -Version 9.1.5
Ensure-TinySOCS-Agents
