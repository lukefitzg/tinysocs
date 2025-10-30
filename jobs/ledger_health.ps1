Set-ExecutionPolicy -Scope Process Bypass -Force
$root = Split-Path -Parent $PSScriptRoot
. "$root\model_toggles.ps1"
Use-TinySocsDotEnv
& "$root\.venv\Scripts\python.exe" -m tinysocs.orchestrator.check_ledger --verify | Out-File "$root\logs\ledger-health.json" -Encoding utf8