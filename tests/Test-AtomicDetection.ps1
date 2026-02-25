# tests/Test-AtomicDetection.ps1
<#
.SYNOPSIS
    Validates TinySocs detection rules using Atomic Red Team techniques.

.DESCRIPTION
    Iterates through the tests defined in atomic-tests.yaml, executes each
    Atomic Red Team technique, waits for the TinySocs detection pipeline,
    then queries OpenSearch for the expected rule_id in tinysocs-alerts-*.

    Outputs a per-test DETECTED / MISSED / SKIP result and generates
    docs/detection-efficacy.md with the results.

.PARAMETER ConfigPath
    Path to the atomic-tests.yaml mapping file. Default: tests/atomic-tests.yaml

.PARAMETER SkipInstall
    Skip installing Invoke-AtomicRedTeam if already installed.

.PARAMETER SysmonAvailable
    Set to $true if Sysmon is installed. Tests requiring Sysmon will be
    skipped if this is $false. Auto-detected if not specified.

.PARAMETER DryRun
    List tests without executing them.

.EXAMPLE
    .\tests\Test-AtomicDetection.ps1
    .\tests\Test-AtomicDetection.ps1 -DryRun
    .\tests\Test-AtomicDetection.ps1 -SkipInstall -SysmonAvailable
#>
[CmdletBinding()]
param(
    [string]$ConfigPath,
    [switch]$SkipInstall,
    [Nullable[bool]]$SysmonAvailable,
    [switch]$DryRun,
    [string]$OutputJson
)

$ErrorActionPreference = "Stop"

# Resolve paths
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if (-not $ConfigPath) { $ConfigPath = Join-Path $repoRoot "tests\atomic-tests.yaml" }
$outputDoc = Join-Path $repoRoot "docs\detection-efficacy.md"
if (-not $OutputJson) { $OutputJson = Join-Path $repoRoot "tests\atomic-results.json" }

# ---------------------------------------------------------------------------
# Prerequisites
# ---------------------------------------------------------------------------
function Install-AtomicRedTeam {
    if ($SkipInstall) {
        Write-Host "[*] Skipping Invoke-AtomicRedTeam installation (-SkipInstall)"
        return
    }
    if (Get-Module -ListAvailable -Name "Invoke-AtomicRedTeam") {
        Write-Host "[*] Invoke-AtomicRedTeam already installed"
        return
    }
    Write-Host "[*] Installing Invoke-AtomicRedTeam..."
    IEX (Invoke-WebRequest -Uri "https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1" -UseBasicParsing).Content
    Install-AtomicRedTeam -getAtomics -Force
}

function Test-SysmonInstalled {
    if ($null -ne $SysmonAvailable) { return $SysmonAvailable }
    $svc = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
    if (-not $svc) { $svc = Get-Service -Name "Sysmon" -ErrorAction SilentlyContinue }
    return ($null -ne $svc -and $svc.Status -eq "Running")
}

# ---------------------------------------------------------------------------
# OpenSearch query helper
# ---------------------------------------------------------------------------
function Query-TinySocsAlerts {
    param(
        [string[]]$RuleIds,
        [int]$LookbackMinutes = 10
    )
    $dataDir = Join-Path $env:ProgramData "TinySocs"
    $envFile = Join-Path $dataDir "Assistant\assistant.env"
    $siemUrl  = "https://localhost:9201"
    $siemUser = "admin"
    $siemPass = "admin"
    $caCert   = Join-Path $dataDir "OpenSearch\config\root-ca.pem"

    # Try to read from assistant.env
    if (Test-Path $envFile) {
        foreach ($line in (Get-Content $envFile -ErrorAction SilentlyContinue)) {
            if ($line -match "^SIEM_URL=(.+)$")  { $siemUrl  = $Matches[1].Trim() }
            if ($line -match "^SIEM_USER=(.+)$") { $siemUser = $Matches[1].Trim() }
            if ($line -match "^SIEM_PASS=(.+)$") { $siemPass = $Matches[1].Trim() }
            if ($line -match "^SIEM_CA_CERT=(.+)$") { $caCert = $Matches[1].Trim() }
        }
    }

    $ruleFilter = ($RuleIds | ForEach-Object { "{`"term`":{`"alert.rule_id.keyword`":`"$_`"}}" }) -join ","
    $body = @"
{
  "size": 10,
  "query": {
    "bool": {
      "must": [
        {"range": {"timestamp": {"gte": "now-${LookbackMinutes}m", "lte": "now"}}},
        {"bool": {"should": [$ruleFilter], "minimum_should_match": 1}}
      ]
    }
  }
}
"@

    $pair = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${siemUser}:${siemPass}"))
    $headers = @{ "Authorization" = "Basic $pair"; "Content-Type" = "application/json" }

    $splat = @{
        Uri     = "$siemUrl/tinysocs-alerts-*/_search"
        Method  = "POST"
        Headers = $headers
        Body    = $body
    }

    # Handle TLS
    if (Test-Path $caCert -ErrorAction SilentlyContinue) {
        # PowerShell 7+ supports -Certificate, but for 5.1 we skip verification
    }
    # For self-signed certs: trust all (test environment only)
    try {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    } catch { }

    try {
        $resp = Invoke-RestMethod @splat -ErrorAction Stop
        $hits = @($resp.hits.hits)
        return $hits
    } catch {
        Write-Warning "OpenSearch query failed: $($_.Exception.Message)"
        return @()
    }
}

# ---------------------------------------------------------------------------
# Main execution
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "=============================================="
Write-Host "  TinySocs Atomic Red Team Detection Validator"
Write-Host "=============================================="
Write-Host ""

# Load config
if (-not (Test-Path $ConfigPath)) {
    Write-Error "Config not found: $ConfigPath"
    exit 1
}

# Parse YAML -- try powershell-yaml first, fall back to Python's yaml module
$yamlLoaded = $false
try {
    Import-Module powershell-yaml -ErrorAction Stop
    $yamlLoaded = $true
    Write-Host "[*] Using powershell-yaml module"
} catch {
    Write-Host "[*] powershell-yaml not available, trying to install..."
    try {
        Install-Module -Name powershell-yaml -Force -Scope CurrentUser -AllowClobber -ErrorAction Stop
        Import-Module powershell-yaml -ErrorAction Stop
        $yamlLoaded = $true
        Write-Host "[*] Installed and loaded powershell-yaml"
    } catch {
        Write-Host "[*] powershell-yaml install failed -- falling back to Python yaml parser"
    }
}

if ($yamlLoaded) {
    $config = Get-Content $ConfigPath -Raw | ConvertFrom-Yaml
    $tests = $config.tests
} else {
    # Fallback: use Python (from .venv-win or system) to convert YAML -> JSON
    $pythonCmd = $null
    $venvPython = Join-Path $repoRoot ".venv-win\Scripts\python.exe"
    if (Test-Path $venvPython) {
        $pythonCmd = $venvPython
    } elseif (Get-Command python -ErrorAction SilentlyContinue) {
        $pythonCmd = "python"
    } elseif (Get-Command python3 -ErrorAction SilentlyContinue) {
        $pythonCmd = "python3"
    }

    if (-not $pythonCmd) {
        Write-Error "Neither powershell-yaml nor Python is available. Cannot parse YAML config."
        exit 1
    }

    Write-Host "[*] Using Python ($pythonCmd) to parse YAML config"
    $helperScript = Join-Path $PSScriptRoot "yaml2json.py"
    if (-not (Test-Path $helperScript)) {
        Write-Error "Helper script not found: $helperScript"
        exit 1
    }

    try {
        $jsonOut = & $pythonCmd $helperScript $ConfigPath 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Python YAML parse failed: $jsonOut"
            exit 1
        }
        $config = $jsonOut | ConvertFrom-Json
        $tests = $config.tests
    } catch {
        Write-Error "Failed to parse YAML via Python: $($_.Exception.Message)"
        exit 1
    }
}

Write-Host "[*] Loaded $($tests.Count) test mappings from $ConfigPath"

# Check Sysmon
$hasSysmon = Test-SysmonInstalled
Write-Host "[*] Sysmon available: $hasSysmon"

# Install ART
if (-not $DryRun) {
    Install-AtomicRedTeam
    Import-Module Invoke-AtomicRedTeam -ErrorAction SilentlyContinue
}

# Run tests
$results = @()
foreach ($test in $tests) {
    $technique = $test.atomic_technique
    $testNum   = $test.atomic_test_number
    $rules     = $test.expected_rules
    $needsSysmon = $test.sysmon_required
    $timeout   = if ($test.timeout_seconds) { $test.timeout_seconds } else { 120 }
    $name      = $test.technique_name

    Write-Host ""
    Write-Host "--- [$technique] $name ---"

    # Skip if Sysmon required but not available
    if ($needsSysmon -and -not $hasSysmon) {
        Write-Host "  SKIP: Requires Sysmon (not installed)" -ForegroundColor Yellow
        $results += [PSCustomObject]@{
            Technique = $technique
            Name      = $name
            Status    = "SKIP"
            Reason    = "Sysmon not installed"
            Rules     = ($rules -join ", ")
            Detected  = @()
        }
        continue
    }

    if ($DryRun) {
        Write-Host "  DRY RUN: Would execute Atomic test #$testNum"
        Write-Host "  Expected rules: $($rules -join ', ')"
        $results += [PSCustomObject]@{
            Technique = $technique
            Name      = $name
            Status    = "DRY_RUN"
            Reason    = ""
            Rules     = ($rules -join ", ")
            Detected  = @()
        }
        continue
    }

    # Execute the Atomic test
    try {
        Write-Host "  Executing Atomic test #$testNum..."
        Invoke-AtomicTest $technique -TestNumbers $testNum -GetPrereqs -ErrorAction SilentlyContinue
        Invoke-AtomicTest $technique -TestNumbers $testNum -ErrorAction Stop
        Write-Host "  Test executed. Waiting for detection pipeline..."
    } catch {
        Write-Host "  ERROR executing test: $($_.Exception.Message)" -ForegroundColor Red
        $results += [PSCustomObject]@{
            Technique = $technique
            Name      = $name
            Status    = "ERROR"
            Reason    = $_.Exception.Message
            Rules     = ($rules -join ", ")
            Detected  = @()
        }
        # Cleanup
        try { Invoke-AtomicTest $technique -TestNumbers $testNum -Cleanup -ErrorAction SilentlyContinue } catch { }
        continue
    }

    # Wait for detection pipeline to process
    $detected = @()
    $deadline = (Get-Date).AddSeconds($timeout)
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 15
        $hits = Query-TinySocsAlerts -RuleIds $rules -LookbackMinutes 10
        if ($hits.Count -gt 0) {
            $detected = @($hits | ForEach-Object { $_._source.alert.rule_id } | Select-Object -Unique)
            break
        }
        Write-Host "  Waiting... ($([int](($deadline - (Get-Date)).TotalSeconds))s remaining)"
    }

    if ($detected.Count -gt 0) {
        Write-Host "  DETECTED: $($detected -join ', ')" -ForegroundColor Green
        $results += [PSCustomObject]@{
            Technique = $technique
            Name      = $name
            Status    = "DETECTED"
            Reason    = ""
            Rules     = ($rules -join ", ")
            Detected  = $detected
        }
    } else {
        Write-Host "  MISSED: No alerts found for expected rules" -ForegroundColor Red
        $results += [PSCustomObject]@{
            Technique = $technique
            Name      = $name
            Status    = "MISSED"
            Reason    = "No alerts within timeout"
            Rules     = ($rules -join ", ")
            Detected  = @()
        }
    }

    # Cleanup
    try {
        Write-Host "  Cleaning up..."
        Invoke-AtomicTest $technique -TestNumbers $testNum -Cleanup -ErrorAction SilentlyContinue
    } catch {
        Write-Host "  Cleanup warning: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "=============================================="
Write-Host "  Results Summary"
Write-Host "=============================================="
Write-Host ""

$detected = @($results | Where-Object { $_.Status -eq "DETECTED" })
$missed   = @($results | Where-Object { $_.Status -eq "MISSED" })
$skipped  = @($results | Where-Object { $_.Status -eq "SKIP" })
$errors   = @($results | Where-Object { $_.Status -eq "ERROR" })
$dryRuns  = @($results | Where-Object { $_.Status -eq "DRY_RUN" })

$executed = $detected.Count + $missed.Count
$efficacy = if ($executed -gt 0) { [math]::Round(($detected.Count / $executed) * 100, 1) } else { 0 }

Write-Host "  Total tests:  $($results.Count)"
Write-Host "  Detected:     $($detected.Count)" -ForegroundColor Green
Write-Host "  Missed:       $($missed.Count)" -ForegroundColor $(if ($missed.Count -gt 0) { "Red" } else { "Green" })
Write-Host "  Skipped:      $($skipped.Count)" -ForegroundColor Yellow
Write-Host "  Errors:       $($errors.Count)" -ForegroundColor $(if ($errors.Count -gt 0) { "Red" } else { "Gray" })
if ($dryRuns.Count -gt 0) {
    Write-Host "  Dry runs:     $($dryRuns.Count)" -ForegroundColor Cyan
}
Write-Host "  Efficacy:     $efficacy% ($($detected.Count)/$executed executed)" -ForegroundColor $(if ($efficacy -ge 80) { "Green" } elseif ($efficacy -ge 60) { "Yellow" } else { "Red" })

# Generate docs/detection-efficacy.md
$md = @"
# Detection Efficacy Report

Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss UTC" -AsUTC)

## Summary

| Metric | Value |
|--------|-------|
| Total Tests | $($results.Count) |
| Detected | $($detected.Count) |
| Missed | $($missed.Count) |
| Skipped | $($skipped.Count) |
| Errors | $($errors.Count) |
| **Efficacy** | **$efficacy%** ($($detected.Count)/$executed) |

## Detailed Results

| Technique | Name | Status | Expected Rules | Detected Rules |
|-----------|------|--------|----------------|----------------|
"@

foreach ($r in $results) {
    $detStr = if ($r.Detected -and $r.Detected.Count -gt 0) { $r.Detected -join ", " } else { "&mdash;" }
    $statusEmoji = switch ($r.Status) {
        "DETECTED" { "PASS" }
        "MISSED"   { "FAIL" }
        "SKIP"     { "SKIP" }
        "ERROR"    { "ERR" }
        "DRY_RUN"  { "DRY" }
        default    { $r.Status }
    }
    $md += "| $($r.Technique) | $($r.Name) | $statusEmoji | $($r.Rules) | $detStr |`n"
}

$md += @"

## Environment

- Sysmon installed: $hasSysmon
- Test config: ``$ConfigPath``
- Atomic Red Team: Invoke-AtomicRedTeam module

## How to Run

``````powershell
# Full run (requires admin, Atomic Red Team, and running TinySocs instance)
.\tests\Test-AtomicDetection.ps1

# Dry run (list tests without executing)
.\tests\Test-AtomicDetection.ps1 -DryRun

# Skip ART install (if already installed)
.\tests\Test-AtomicDetection.ps1 -SkipInstall
``````

## Tuning Guidance

For any MISSED detections:
1. Check that the relevant Windows event log channels are enabled
2. Verify Sysmon is installed and configured (for Sysmon-dependent rules)
3. Review rule thresholds in ``packaging/detection/rules.yml``
4. Check the detection pipeline latency — increase ``timeout_seconds`` in ``atomic-tests.yaml``
"@

try {
    $docsDir = Join-Path $repoRoot "docs"
    if (-not (Test-Path $docsDir)) { New-Item -ItemType Directory -Path $docsDir -Force | Out-Null }
    Set-Content -Path $outputDoc -Value $md -Encoding UTF8
    Write-Host ""
    Write-Host "[*] Report written to: $outputDoc"
} catch {
    Write-Warning "Failed to write report: $($_.Exception.Message)"
}

# Generate atomic-results.json for Navigator layer colouring
$jsonResults = @{
    generated_at = (Get-Date -Format "o")
    total_tests  = $results.Count
    efficacy_pct = $efficacy
    results      = @($results | ForEach-Object {
        @{
            technique_id = $_.Technique
            technique_name = $_.Name
            status = $_.Status
            reason = $_.Reason
            expected_rules = ($_.Rules -split ", ")
            detected_rules = @($_.Detected)
        }
    })
}

try {
    $jsonStr = $jsonResults | ConvertTo-Json -Depth 4
    Set-Content -Path $OutputJson -Value $jsonStr -Encoding UTF8
    Write-Host "[*] JSON results written to: $OutputJson"
} catch {
    Write-Warning "Failed to write JSON results: $($_.Exception.Message)"
}

Write-Host ""
Write-Host "Done."

# Return results for programmatic use
$results
