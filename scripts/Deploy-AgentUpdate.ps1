<#
.SYNOPSIS
    Deploy updated TinySocs Agent binary, rules, and test harness to the VM.
    Must be run as Administrator on the target Windows machine.

.DESCRIPTION
    1. Stops the TinySocs-Quickstart watchdog (prevents auto-restart)
    2. Stops the TinySocs.Agent process
    3. Replaces the agent binary with the updated version
    4. Restores the full rules.yml (with mitre blocks)
    5. Clears any stuck queue segments
    6. Enables Windows audit policies (required for Security event generation)
    7. Restarts the agent via the quickstart
    8. Waits for rules to load and verifies detection engine is up
    9. Verifies audit policies are active

.PARAMETER SourceDir
    Directory containing the updated files (TinySocs.Agent.exe, rules.yml,
    Test-AtomicDetection.ps1, atomic-tests.yaml). Defaults to the script's
    parent directory.

.EXAMPLE
    # From the deploy staging directory:
    .\Deploy-AgentUpdate.ps1
#>
[CmdletBinding()]
param(
    [string]$SourceDir
)

$ErrorActionPreference = "Stop"

if (-not $SourceDir) {
    $SourceDir = Split-Path $PSScriptRoot -Parent
}
# Normalise to an absolute path so a relative "-SourceDir ." still resolves
# (Split-Path "." -Parent returns an empty string, which breaks Join-Path below).
$SourceDir = (Resolve-Path $SourceDir).Path

$agentBin = "C:\Program Files\TinySocs\bin"
$agentData = "C:\ProgramData\TinySocs\Collector"
$rulesDir = Join-Path $agentData "rules"
$queueDir = Join-Path $agentData "agent\queue"
$logDir = Join-Path $agentData "logs"

Write-Host ""
Write-Host "================================================"
Write-Host "  TinySocs Agent Update Deployment"
Write-Host "================================================"
Write-Host ""
Write-Host "[*] Source directory: $SourceDir"

# Verify source files exist
$newBinary = Join-Path $SourceDir "TinySocs.Agent.exe"
$newRules = Join-Path $SourceDir "rules.yml"

if (-not (Test-Path $newBinary)) {
    # Try publish subdirectory
    $newBinary = Join-Path $SourceDir "publish\win-x64\TinySocs.Agent.exe"
}

if (-not (Test-Path $newBinary)) {
    Write-Error "Cannot find TinySocs.Agent.exe in $SourceDir or $SourceDir\publish\win-x64\"
    exit 1
}

Write-Host "[*] New binary: $newBinary ($([math]::Round((Get-Item $newBinary).Length / 1MB, 1)) MB)"

# -- Step 1: Stop the watchdog (TinySocs-Quickstart) --
Write-Host ""
Write-Host "[1/9] Stopping TinySocs-Quickstart watchdog..."
$quickstart = Get-Process -Name "TinySocs-Quickstart" -ErrorAction SilentlyContinue
if ($quickstart) {
    Write-Host "      Watchdog PID: $($quickstart.Id)"
    Stop-Process -Name "TinySocs-Quickstart" -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    # Verify it's gone
    $quickstart2 = Get-Process -Name "TinySocs-Quickstart" -ErrorAction SilentlyContinue
    if ($quickstart2) {
        Write-Warning "      Watchdog still running. Trying taskkill..."
        cmd /c "taskkill /F /IM TinySocs-Quickstart.exe 2>nul"
        Start-Sleep -Seconds 2
    }
    Write-Host "      Watchdog stopped." -ForegroundColor Green
} else {
    Write-Host "      Watchdog not running (OK)"
}

# -- Step 2: Stop the agent --
# The agent runs as an NSSM-wrapped Windows service (TinySocsAgent). NSSM
# RESPAWNS TinySocs.Agent.exe the instant it exits, so killing the process just
# re-locks the binary. Stop the SERVICE first — that holds it down — then clear
# any lingering process before the swap.
Write-Host ""
Write-Host "[2/9] Stopping TinySocs.Agent (service TinySocsAgent)..."
$svc = Get-Service -Name "TinySocsAgent" -ErrorAction SilentlyContinue
if ($svc) {
    if ($svc.Status -ne 'Stopped') {
        Write-Host "      Stopping service TinySocsAgent..."
        Stop-Service -Name "TinySocsAgent" -Force -ErrorAction SilentlyContinue
        try {
            (Get-Service -Name "TinySocsAgent").WaitForStatus('Stopped', '00:00:30')
        } catch {
            Write-Warning "      Service did not report Stopped within 30s; forcing via sc.exe"
            cmd /c "sc stop TinySocsAgent >nul 2>&1"
            Start-Sleep -Seconds 3
        }
    }
    Write-Host "      Service stopped." -ForegroundColor Green
} else {
    Write-Host "      No TinySocsAgent service found (older/dev install?)."
}
# Clear any lingering process (NSSM won't respawn while the service is stopped).
$agent = Get-Process -Name "TinySocs.Agent" -ErrorAction SilentlyContinue
if ($agent) {
    Write-Host "      Killing lingering agent PID: $($agent.Id)"
    cmd /c "taskkill /F /IM TinySocs.Agent.exe 2>nul"
    Start-Sleep -Seconds 2
}
Write-Host "      Agent stopped." -ForegroundColor Green

# -- Step 3: Replace the binary --
Write-Host ""
Write-Host "[3/9] Replacing agent binary..."
$targetBinary = Join-Path $agentBin "TinySocs.Agent.exe"
if (Test-Path $targetBinary) {
    $backupPath = "$targetBinary.bak"
    Write-Host "      Backing up current binary to $backupPath"
    Copy-Item $targetBinary $backupPath -Force -ErrorAction SilentlyContinue
}
Copy-Item $newBinary $targetBinary -Force
Write-Host "      Binary replaced: $([math]::Round((Get-Item $targetBinary).Length / 1MB, 1)) MB" -ForegroundColor Green

# -- Step 4: Restore full rules.yml --
Write-Host ""
Write-Host "[4/9] Deploying rules.yml (with MITRE data)..."
if (-not (Test-Path $rulesDir)) {
    New-Item -ItemType Directory -Path $rulesDir -Force | Out-Null
}
if (Test-Path $newRules) {
    Copy-Item $newRules (Join-Path $rulesDir "rules.yml") -Force
    Write-Host "      rules.yml deployed from source" -ForegroundColor Green
} else {
    Write-Host "      No rules.yml in source dir; keeping existing rules"
}

# -- Step 5: Clear stuck queue segments --
Write-Host ""
Write-Host "[5/9] Clearing queue segments..."
if (Test-Path $queueDir) {
    $segments = Get-ChildItem $queueDir -Filter "segment-*.jsonl" -ErrorAction SilentlyContinue
    if ($segments.Count -gt 0) {
        Remove-Item (Join-Path $queueDir "segment-*.jsonl") -Force -ErrorAction SilentlyContinue
        Write-Host "      Removed $($segments.Count) queue segment(s)" -ForegroundColor Green
    } else {
        Write-Host "      Queue already clean"
    }
} else {
    Write-Host "      Queue directory doesn't exist yet (OK)"
}

# -- Step 6: Enable Windows audit policies --
Write-Host ""
Write-Host "[6/9] Enabling Windows audit policies..."
$auditPolicies = @(
    @{ Subcategory = 'Logon';                       Setting = '/failure:enable' },
    @{ Subcategory = 'Logoff';                      Setting = '/success:enable' },
    @{ Subcategory = 'Process Creation';             Setting = '/success:enable' },
    @{ Subcategory = 'Other Object Access Events';   Setting = '/success:enable' },
    @{ Subcategory = 'User Account Management';      Setting = '/success:enable' },
    @{ Subcategory = 'Audit Policy Change';          Setting = '/success:enable' },
    @{ Subcategory = 'Security State Change';        Setting = '/success:enable' },
    @{ Subcategory = 'File System';                  Setting = '/success:enable' },
    @{ Subcategory = 'Special Logon';                Setting = '/success:enable' }
)
$auditOk = 0
foreach ($p in $auditPolicies) {
    $r = auditpol /set /subcategory:"$($p.Subcategory)" $($p.Setting) 2>&1
    if ($LASTEXITCODE -eq 0) { $auditOk++ }
}
Write-Host "      Enabled $auditOk/$($auditPolicies.Count) audit subcategories" -ForegroundColor Green

# Enable command-line logging for 4688
$regPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
Set-ItemProperty -Path $regPath -Name 'ProcessCreationIncludeCmdLine_Enabled' -Value 1 -Type DWord -ErrorAction SilentlyContinue
Write-Host "      Process command-line logging enabled" -ForegroundColor Green

# -- Step 7: Start the agent service (NSSM relaunches the new binary) --
Write-Host ""
Write-Host "[7/9] Starting TinySocsAgent service..."
$svc = Get-Service -Name "TinySocsAgent" -ErrorAction SilentlyContinue
if ($svc) {
    Start-Service -Name "TinySocsAgent" -ErrorAction SilentlyContinue
    try {
        (Get-Service -Name "TinySocsAgent").WaitForStatus('Running', '00:00:30')
        Write-Host "      Service running." -ForegroundColor Green
    } catch {
        Write-Warning "      Service did not report Running within 30s; trying sc.exe start"
        cmd /c "sc start TinySocsAgent >nul 2>&1"
        Start-Sleep -Seconds 5
    }
    Start-Sleep -Seconds 5
    $newAgent = Get-Process -Name "TinySocs.Agent" -ErrorAction SilentlyContinue
    if ($newAgent) {
        Write-Host "      Agent process up (PID: $($newAgent.Id))" -ForegroundColor Green
    } else {
        Write-Warning "      Agent process not detected. Check logs at $logDir\agent.log"
    }
} else {
    # Fallback for a watchdog-only / dev install with no service registered.
    Write-Host "      No service; starting via TinySocs-Quickstart watchdog..."
    $quickstartExe = "C:\Program Files\TinySocs\TinySocs-Quickstart.exe"
    if (Test-Path $quickstartExe) {
        Start-Process -FilePath $quickstartExe -WindowStyle Hidden
        Start-Sleep -Seconds 10
    } else {
        $agentExe = Join-Path $agentBin "TinySocs.Agent.exe"
        Start-Process -FilePath $agentExe -WindowStyle Hidden
        Start-Sleep -Seconds 5
    }
    $newAgent = Get-Process -Name "TinySocs.Agent" -ErrorAction SilentlyContinue
    if ($newAgent) {
        Write-Host "      Agent running (PID: $($newAgent.Id))" -ForegroundColor Green
    } else {
        Write-Warning "      Agent failed to start. Check logs."
    }
}

# Restore the watchdog we stopped in Step 1 (best-effort; the service is the
# authoritative runner, so this only re-establishes the original topology).
$quickstartExe = "C:\Program Files\TinySocs\TinySocs-Quickstart.exe"
if ((Test-Path $quickstartExe) -and -not (Get-Process -Name "TinySocs-Quickstart" -ErrorAction SilentlyContinue)) {
    Start-Process -FilePath $quickstartExe -WindowStyle Hidden -ErrorAction SilentlyContinue
    Write-Host "      Watchdog restarted." -ForegroundColor Green
}

# -- Step 8: Verify detection engine --
Write-Host ""
Write-Host "[8/9] Verifying detection engine..."
Write-Host "      Waiting 15s for rule reload cycle..."
Start-Sleep -Seconds 15

# The agent runs under NSSM, which redirects stdout to TinySocsAgent.out.log.
# Fall back to the legacy agent.log name for non-service/dev installs.
$logFile = Join-Path $logDir "TinySocsAgent.out.log"
if (-not (Test-Path $logFile)) { $logFile = Join-Path $logDir "agent.log" }
if (Test-Path $logFile) {
    $recentLines = Get-Content $logFile -Tail 50 -ErrorAction SilentlyContinue
    $ruleLine = $recentLines | Where-Object { $_ -match "Detection engine updated with (\d+) rule" } | Select-Object -Last 1
    if ($ruleLine) {
        Write-Host "      $ruleLine" -ForegroundColor Green
    } else {
        Write-Host "      (No rule reload line found yet; may need more time)"
        # Check for errors
        $errorLines = $recentLines | Where-Object { $_ -match "ERROR|Failed" } | Select-Object -Last 3
        foreach ($line in $errorLines) {
            Write-Host "      ERROR: $line" -ForegroundColor Red
        }
    }

    # Check for mitre-related errors (the bug we fixed)
    $mitreErrors = $recentLines | Where-Object { $_ -match "mitre" -and $_ -match "not found|error" }
    if ($mitreErrors) {
        Write-Warning "      MITRE errors still present - binary may not have been replaced correctly"
    } else {
        Write-Host "      No MITRE parsing errors (fix confirmed)" -ForegroundColor Green
    }
} else {
    Write-Warning "      Log file not found at $logFile"
}

# -- Step 9: Verify audit policies are active --
Write-Host ""
Write-Host "[9/9] Verifying audit policies..."
$verifyPolicies = @('Logon', 'Process Creation', 'Other Object Access Events', 'User Account Management')
$auditOutput = auditpol /get /category:* 2>&1 | Out-String
foreach ($vp in $verifyPolicies) {
    $line = ($auditOutput -split "`n") | Where-Object { $_ -match "^\s+$vp\s+" } | Select-Object -First 1
    if ($line) {
        $setting = ($line -replace "^\s+$vp\s+", '').Trim()
        Write-Host "      $vp`: $setting" -ForegroundColor Green
    }
}

Write-Host ""
Write-Host "================================================"
Write-Host "  Deployment complete!"
Write-Host "================================================"
Write-Host ""
Write-Host 'Next: Run the ART test harness:'
Write-Host '  .\tests\Test-AtomicDetection.ps1 -SkipInstall'
Write-Host ""
