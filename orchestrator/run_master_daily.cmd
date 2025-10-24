set TINYSOCS_NODES=http://localhost:8081
set MASTER_SHARED_SECRET=dev-secret-change-me
set PRIVACY_MODE=abstract
set TINYSOCS_INSECURE_SKIP_VERIFY=1
"C:\tinysocs\tinysocs\.venv\Scripts\python.exe" "C:\tinysocs\tinysocs\orchestrator\master.py" --rules ps_script_block,proc_creation_powershell_suspicious,proc_creation_lolbins,lolbin_execs --window 15m >> "C:\tinysocs\tinysocs\logs\master-daily.log" 2>&1
