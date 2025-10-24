set TINYSOCS_NODES=http://localhost:8081
set MASTER_SHARED_SECRET=dev-secret-change-me
set PRIVACY_MODE=abstract
set TINYSOCS_INSECURE_SKIP_VERIFY=1
"C:\tinysocs\tinysocs\.venv\Scripts\python.exe" "C:\tinysocs\tinysocs\orchestrator\check_ledger.py" > "C:\tinysocs\tinysocs\logs\ledger-health.json" 2>&1
