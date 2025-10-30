Set-ExecutionPolicy -Scope Process Bypass -Force
$root = Split-Path -Parent $PSScriptRoot  # ...\tinysocs
. "$root\model_toggles.ps1"
Use-TinySocsDotEnv
& "$root\.venv\Scripts\python.exe" -m tinysocs.orchestrator.master --rules ps_script_block,proc_creation_lolbins --window 15m