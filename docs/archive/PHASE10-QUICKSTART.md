# Phase 10 - Quick Start Guide

## Two Deployment Options

### Option 1: Fresh Install (Recommended for Testing Phase 10)
**Best for**: Clean validation that everything works from scratch

This is the "definition of done" test - proves that Phase 10 works on a clean install with zero manual steps.

```powershell
# 1. Build the agent
dotnet build src/TinySocs.Agent/TinySocs.Agent.csproj -c Release

# 2. Package installer (if you have an installer build process)
# Your installer should include:
#   - Agent binaries
#   - config/agent-config.yml → ProgramData/TinySocs/Collector/
#   - config/rules.yml → ProgramData/TinySocs/Collector/rules/
#   - packaging/opensearch/templates/*.json → ProgramFiles/TinySocs/OpenSearch/templates/
#   - packaging/opensearch/policies/*.json → ProgramFiles/TinySocs/OpenSearch/policies/

# 3. Run installer on a clean test VM
# The installer will now automatically:
#   - Stage templates to ProgramData
#   - Stage policies to ProgramData
#   - Bootstrap templates to OpenSearch
#   - Bootstrap ISM policies to OpenSearch
#   - Deploy agent config with detection enabled
#   - Deploy rules.yml
#   - Start services

# 4. Verify health
Import-Module .\modules\TinySocs.Installer.psm1 -Force
Test-TinySocsHealth

# 5. Test detection
1..6 | ForEach-Object { runas /user:fakeuser cmd 2>$null }
# (enter wrong password each time)

# 6. Check for alert
Start-Sleep -Seconds 10
Get-Content "C:\ProgramData\TinySocs\Collector\logs\alerts.log" -Tail 5
```

---

### Option 2: In-Place Upgrade (Faster for Dev/Testing)
**Best for**: Quick iteration on an existing install

This updates your current system without reinstalling everything.

```powershell
# 1. Stop services
Stop-Service -Name "TinySocsAgent" -Force
Stop-Service -Name "TinySocsOpenSearch" -Force

# 2. Build and deploy new agent
dotnet build src/TinySocs.Agent/TinySocs.Agent.csproj -c Release

# Copy new agent binary
$agentBin = "src/TinySocs.Agent/bin/Release/net8.0/win-x64/publish/TinySocs.Agent.exe"
Copy-Item $agentBin "C:\Program Files\TinySocs\Collector\TinySocs.Agent.exe" -Force

# 3. Deploy new config files
Copy-Item "config/agent-config.yml" "C:\ProgramData\TinySocs\Collector\agent-config.yml" -Force

# Create rules directory and deploy rules.yml
$rulesDir = "C:\ProgramData\TinySocs\Collector\rules"
New-Item -ItemType Directory -Force -Path $rulesDir | Out-Null
Copy-Item "config/rules.yml" "$rulesDir\rules.yml" -Force

# 4. Stage templates and policies to ProgramData
# Copy templates
$templatesDir = "C:\ProgramData\TinySocs\OpenSearch\templates"
New-Item -ItemType Directory -Force -Path $templatesDir | Out-Null
Copy-Item "packaging/opensearch/templates/*.json" $templatesDir -Force

# Copy policies
$policiesDir = "C:\ProgramData\TinySocs\OpenSearch\policies"
New-Item -ItemType Directory -Force -Path $policiesDir | Out-Null
Copy-Item "packaging/opensearch/policies/*.json" $policiesDir -Force

# 5. Start OpenSearch and bootstrap templates/policies
Start-Service -Name "TinySocsOpenSearch"
Start-Sleep -Seconds 30  # Wait for OpenSearch to be ready

# Import installer module
Import-Module .\modules\TinySocs.Installer.psm1 -Force

# Bootstrap templates
Invoke-TinySocsOpenSearchTemplatesBootstrap -TemplatesDir $templatesDir

# Bootstrap ISM policies
Invoke-TinySocsOpenSearchPoliciesBootstrap -PoliciesDir $policiesDir

# 6. Start agent
Start-Service -Name "TinySocsAgent"

# 7. Verify health
Test-TinySocsHealth

# 8. Test detection
1..6 | ForEach-Object { runas /user:fakeuser cmd 2>$null }
Start-Sleep -Seconds 10
Get-Content "C:\ProgramData\TinySocs\Collector\logs\alerts.log" -Tail 5
```

---

## What the Installer Now Does (Automatically)

The installer has been updated with these new functions:

### New Function: `Ensure-TinySocsOpenSearchPoliciesStaged`
- Copies `*.json` from `InstallRoot/OpenSearch/policies/` → `ProgramData/OpenSearch/policies/`
- Uses SHA256 hashing to only copy changed files (idempotent)
- Non-fatal if source dir doesn't exist (backward compatible)

### New Function: `Invoke-TinySocsOpenSearchPoliciesBootstrap`
- Loads all `*.json` from policies dir
- Creates/updates ISM policies via `PUT /_plugins/_ism/policies/{policy_id}`
- Runs after template bootstrap during install

### Integration Points
These are now called automatically during install at:
- **Step 4b**: Stage policies to ProgramData (after templates staging)
- **Step 8**: Bootstrap ISM policies to OpenSearch (after templates bootstrap)

---

## Verification Checklist

After deployment (fresh or in-place), verify:

### ✅ Files Deployed
```powershell
# Agent binary
Test-Path "C:\Program Files\TinySocs\Collector\TinySocs.Agent.exe"

# Config
Test-Path "C:\ProgramData\TinySocs\Collector\agent-config.yml"

# Rules
Test-Path "C:\ProgramData\TinySocs\Collector\rules\rules.yml"

# Templates staged
Get-ChildItem "C:\ProgramData\TinySocs\OpenSearch\templates" -Filter *.json

# Policies staged
Get-ChildItem "C:\ProgramData\TinySocs\OpenSearch\policies" -Filter *.json
```

### ✅ Services Running
```powershell
Get-Service "TinySocsOpenSearch" | Select-Object Status
Get-Service "TinySocsAgent" | Select-Object Status
```

### ✅ Templates Bootstrapped
```powershell
# Check via OpenSearch API
$auth = @{ Authorization = "Basic $(ConvertTo-Base64 'user:pass')" }
Invoke-RestMethod -Uri "https://localhost:9201/_index_template" -Headers $auth -SkipCertificateCheck `
  | ConvertTo-Json -Depth 3 | Select-String "tinysocs"
```

### ✅ ISM Policies Bootstrapped
```powershell
# Check via OpenSearch API
$auth = @{ Authorization = "Basic $(ConvertTo-Base64 'user:pass')" }
Invoke-RestMethod -Uri "https://localhost:9201/_plugins/_ism/policies" -Headers $auth -SkipCertificateCheck `
  | ConvertTo-Json -Depth 3
```

### ✅ Health Check Passes
```powershell
Import-Module .\modules\TinySocs.Installer.psm1 -Force
Test-TinySocsHealth
```

Expected: All checks PASS or WARN (no FAIL)

### ✅ Heartbeat Active
```powershell
$auth = @{ Authorization = "Basic $(ConvertTo-Base64 'user:pass')" }
Invoke-RestMethod -Uri "https://localhost:9201/tinysocs-heartbeat/_search?size=1&sort=@timestamp:desc" `
  -Headers $auth -SkipCertificateCheck | ConvertTo-Json -Depth 5
```

Expected: Recent heartbeat document (< 2 minutes old)

### ✅ Detection Active
```powershell
# Check agent log for detection initialization
Get-Content "C:\ProgramData\TinySocs\Collector\logs\agent.log" -Tail 50 `
  | Select-String "Detection engine initialized"
```

Expected: "Detection engine initialized. Rules file: C:\ProgramData\TinySocs\Collector\rules\rules.yml"

---

## Which Option Should You Use?

### Use Fresh Install If:
- ✅ You want to validate the full installer flow
- ✅ You're testing on a clean VM/system
- ✅ You want to prove "zero manual steps" requirement
- ✅ You're preparing for production deployment

### Use In-Place Upgrade If:
- ✅ You have an existing dev/test install
- ✅ You want to iterate quickly
- ✅ You're testing specific detection features
- ✅ You don't want to rebuild the entire environment

---

## Next Steps After Deployment

1. **Generate test alerts**: Use the brute force test (6 failed logons)
2. **Verify alerts appear**: Check `tinysocs-alerts-*` index and `alerts.log`
3. **Customize rules**: Edit `rules.yml` and wait 60s for auto-reload
4. **Monitor heartbeat**: Ensure agent is healthy over time
5. **Review logs**: Check for any errors or warnings

---

## Troubleshooting

### Detection Not Working
```powershell
# Check if detection is enabled in config
Get-Content "C:\ProgramData\TinySocs\Collector\agent-config.yml" | Select-String "detection:" -Context 5

# Check if rules file exists and is valid
Get-Content "C:\ProgramData\TinySocs\Collector\rules\rules.yml"

# Check agent log for errors
Get-Content "C:\ProgramData\TinySocs\Collector\logs\agent.log" -Tail 100 | Select-String "detection|alert|rule"
```

### ISM Policies Not Applied
```powershell
# Re-run bootstrap manually
Import-Module .\modules\TinySocs.Installer.psm1 -Force
Invoke-TinySocsOpenSearchPoliciesBootstrap -PoliciesDir "C:\ProgramData\TinySocs\OpenSearch\policies"
```

### Heartbeat Not Fresh
```powershell
# Check if agent is running and shipping
Get-Service "TinySocsAgent"
Get-Content "C:\ProgramData\TinySocs\Collector\logs\agent.log" -Tail 50
```

---

**Ready to deploy!** Choose your option and follow the steps above.
