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
    6. Restarts the agent via the quickstart
    7. Waits for rules to load and verifies detection engine is up

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

$agentBin = "C:\Program Files\TinySocs\bin"
$agentData = "C:\ProgramData\TinySocs\Collector"
$rulesDir = Join-Path $agentData "rules"
$queueDir = Join-Path $agentData "agent\queue"
$logDir = Join-Path $agentData "logs"
$testsDir = Join-Path (Split-Path $SourceDir -Parent) "tests"

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
Write-Host "[1/7] Stopping TinySocs-Quickstart watchdog..."
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
Write-Host ""
Write-Host "[2/7] Stopping TinySocs.Agent..."
$agent = Get-Process -Name "TinySocs.Agent" -ErrorAction SilentlyContinue
if ($agent) {
    Write-Host "      Agent PID: $($agent.Id)"
    Stop-Process -Name "TinySocs.Agent" -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 3
    # Verify
    $agent2 = Get-Process -Name "TinySocs.Agent" -ErrorAction SilentlyContinue
    if ($agent2) {
        Write-Warning "      Agent still running. Trying taskkill..."
        cmd /c "taskkill /F /IM TinySocs.Agent.exe 2>nul"
        Start-Sleep -Seconds 2
    }
    Write-Host "      Agent stopped." -ForegroundColor Green
} else {
    Write-Host "      Agent not running (OK)"
}

# -- Step 3: Replace the binary --
Write-Host ""
Write-Host "[3/7] Replacing agent binary..."
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
Write-Host "[4/7] Deploying rules.yml (with MITRE data)..."
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
Write-Host "[5/7] Clearing queue segments..."
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

# -- Step 6: Start the quickstart (which starts the agent) --
Write-Host ""
Write-Host "[6/7] Starting TinySocs-Quickstart..."
$quickstartExe = "C:\Program Files\TinySocs\TinySocs-Quickstart.exe"
if (Test-Path $quickstartExe) {
    Start-Process -FilePath $quickstartExe -WindowStyle Hidden
    Write-Host "      Quickstart launched. Waiting for agent to start..."
    Start-Sleep -Seconds 10

    $newAgent = Get-Process -Name "TinySocs.Agent" -ErrorAction SilentlyContinue
    if ($newAgent) {
        Write-Host "      Agent running (PID: $($newAgent.Id))" -ForegroundColor Green
    } else {
        Write-Warning "      Agent not detected after 10s. Check logs at $logDir\agent.log"
    }
} else {
    # Fallback: start agent directly
    Write-Host "      Quickstart not found. Starting agent directly..."
    $agentExe = Join-Path $agentBin "TinySocs.Agent.exe"
    Start-Process -FilePath $agentExe -WindowStyle Hidden
    Start-Sleep -Seconds 5
    $newAgent = Get-Process -Name "TinySocs.Agent" -ErrorAction SilentlyContinue
    if ($newAgent) {
        Write-Host "      Agent running directly (PID: $($newAgent.Id))" -ForegroundColor Green
    } else {
        Write-Warning "      Agent failed to start. Check logs."
    }
}

# -- Step 7: Verify detection engine --
Write-Host ""
Write-Host "[7/7] Verifying detection engine..."
Write-Host "      Waiting 15s for rule reload cycle..."
Start-Sleep -Seconds 15

$logFile = Join-Path $logDir "agent.log"
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

Write-Host ""
Write-Host "================================================"
Write-Host "  Deployment complete!"
Write-Host "================================================"
Write-Host ""
Write-Host 'Next: Run the ART test harness:'
Write-Host '  .\tests\Test-AtomicDetection.ps1 -SkipInstall'
Write-Host ""
