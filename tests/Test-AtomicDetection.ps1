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
    Write-Host "[*] Installing Invoke-AtomicRedTeam via git clone..."

    # Use git to clone ART repos (git handles TLS fine, unlike .NET on PS 5.1)
    $artBase = Join-Path $env:TEMP "AtomicRedTeam"
    $artModSrc = Join-Path $artBase "invoke-atomicredteam"
    $atomicsSrc = Join-Path $artBase "atomic-red-team"

    if (-not (Test-Path $artBase)) { New-Item -ItemType Directory -Path $artBase | Out-Null }

    # Clone invoke-atomicredteam module
    if (-not (Test-Path $artModSrc)) {
        Write-Host "[*] Cloning invoke-atomicredteam..."
        cmd /c "git clone --depth 1 `"https://github.com/redcanaryco/invoke-atomicredteam.git`" `"$artModSrc`" 2>nul"
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Failed to clone invoke-atomicredteam"
            return
        }
    }

    # Clone atomics library
    if (-not (Test-Path $atomicsSrc)) {
        Write-Host "[*] Cloning atomic-red-team (atomics)..."
        cmd /c "git clone --depth 1 `"https://github.com/redcanaryco/atomic-red-team.git`" `"$atomicsSrc`" 2>nul"
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Failed to clone atomic-red-team"
            return
        }
    }

    # Install powershell-yaml dependency (ART requires it)
    $userModDir = Join-Path $env:USERPROFILE "Documents\WindowsPowerShell\Modules"
    $yamlModDest = Join-Path $userModDir "powershell-yaml"
    if (-not (Test-Path (Join-Path $yamlModDest "powershell-yaml.psd1"))) {
        $yamlSrc = Join-Path $artBase "powershell-yaml"
        if (-not (Test-Path $yamlSrc)) {
            Write-Host "[*] Cloning powershell-yaml..."
            cmd /c "git clone --depth 1 `"https://github.com/cloudbase/powershell-yaml.git`" `"$yamlSrc`" 2>nul"
        }
        if (Test-Path $yamlSrc) {
            Write-Host "[*] Installing powershell-yaml module..."
            if (-not (Test-Path $yamlModDest)) { New-Item -ItemType Directory -Path $yamlModDest -Force | Out-Null }
            Copy-Item -Path (Join-Path $yamlSrc "*") -Destination $yamlModDest -Recurse -Force
            $yamlPsd1 = Join-Path $yamlModDest "powershell-yaml.psd1"
            if (Test-Path $yamlPsd1) { Import-Module $yamlPsd1 -Force }
        }
    } else {
        Import-Module (Join-Path $yamlModDest "powershell-yaml.psd1") -Force -ErrorAction SilentlyContinue
    }

    # Install ART module to user's PS module path
    $modDest = Join-Path $userModDir "Invoke-AtomicRedTeam"
    $modSrcDir = Join-Path $artModSrc "Invoke-AtomicRedTeam"
    if (-not (Test-Path $modSrcDir)) {
        # Fallback: module files might be at repo root
        $modSrcDir = $artModSrc
    }
    Write-Host "[*] Installing module from $modSrcDir to $modDest"
    if (-not (Test-Path $modDest)) { New-Item -ItemType Directory -Path $modDest -Force | Out-Null }
    Copy-Item -Path (Join-Path $modSrcDir "*") -Destination $modDest -Recurse -Force

    # Copy atomics to expected location (default: C:\AtomicRedTeam\atomics)
    $atomicsDefault = "C:\AtomicRedTeam\atomics"
    $atomicsSrcDir = Join-Path $atomicsSrc "atomics"
    if (Test-Path $atomicsSrcDir) {
        Write-Host "[*] Copying atomics library to $atomicsDefault..."
        if (-not (Test-Path $atomicsDefault)) { New-Item -ItemType Directory -Path $atomicsDefault -Force | Out-Null }
        Copy-Item -Path (Join-Path $atomicsSrcDir "*") -Destination $atomicsDefault -Recurse -Force
    }

    # Verify module loads (use full path in case PSModulePath doesn't include user modules)
    $psd1 = Join-Path $modDest "Invoke-AtomicRedTeam.psd1"
    if (Test-Path $psd1) {
        Import-Module $psd1 -Force -ErrorAction Stop
        Write-Host "[*] Invoke-AtomicRedTeam installed and loaded successfully"
    } else {
        Write-Error "Module manifest not found at $psd1 -- install may have failed"
        return
    }
}

function Test-SysmonInstalled {
    if ($null -ne $SysmonAvailable) { return $SysmonAvailable }
    # TinySocs installs Sysmon as Sysmon64a; also check standard names
    foreach ($name in @("Sysmon64a", "Sysmon64", "Sysmon")) {
        $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -eq "Running") { return $true }
    }
    return $false
}

# ---------------------------------------------------------------------------
# OpenSearch helpers
# ---------------------------------------------------------------------------

# Shared credential + TLS setup (called once, cached in script scope)
$script:_siemUrl  = $null
$script:_siemHeaders = $null

function Initialize-SiemConnection {
    if ($script:_siemUrl) { return }  # Already initialized

    $dataDir = Join-Path $env:ProgramData "TinySocs"
    $envFile = Join-Path $dataDir "Assistant\assistant.env"
    $siemUrl  = "https://localhost:9201"
    $siemUser = "admin"
    $siemPass = "admin"

    # Try to read from assistant.env
    if (Test-Path $envFile) {
        foreach ($line in (Get-Content $envFile -ErrorAction SilentlyContinue)) {
            if ($line -match "^SIEM_URL=(.+)$")  { $siemUrl  = $Matches[1].Trim() }
            if ($line -match "^SIEM_USER=(.+)$") { $siemUser = $Matches[1].Trim() }
            if ($line -match "^SIEM_PASS=(.+)$") { $siemPass = $Matches[1].Trim() }
        }
    }

    # For self-signed certs: trust all (test environment only)
    try {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    } catch { }

    $pair = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${siemUser}:${siemPass}"))
    $script:_siemUrl = $siemUrl
    $script:_siemHeaders = @{ "Authorization" = "Basic $pair"; "Content-Type" = "application/json" }

    Write-Host "[*] SIEM connection: url=$siemUrl, user=$siemUser, pass_len=$($siemPass.Length)"
}

function Invoke-SiemQuery {
    param([string]$Path, [string]$Body)

    Initialize-SiemConnection
    $splat = @{
        Uri     = "$($script:_siemUrl)$Path"
        Method  = "POST"
        Headers = $script:_siemHeaders
        Body    = $Body
    }
    $resp = Invoke-RestMethod @splat -ErrorAction Stop
    return $resp
}

# ---------------------------------------------------------------------------
# Pre-flight diagnostic: verify connectivity and inspect alert schema
# ---------------------------------------------------------------------------
function Test-AlertConnectivity {
    Initialize-SiemConnection
    Write-Host ""
    Write-Host "[*] Pre-flight: checking OpenSearch alerts index..."

    try {
        # Check if alerts index exists and get document count
        $countBody = '{"query":{"match_all":{}}}'
        $countResp = Invoke-SiemQuery -Path "/tinysocs-alerts-*/_count" -Body $countBody
        $totalAlerts = $countResp.count
        Write-Host "    Total alerts in index: $totalAlerts"

        if ($totalAlerts -eq 0) {
            Write-Warning "    No alerts found in tinysocs-alerts-*. Detection pipeline may not be generating alerts."
            Write-Warning "    Check: agent logs, detection.enabled config, rules.yml loading."
            return $false
        }

        # Fetch a sample alert to inspect field structure
        $sampleBody = '{"size":1,"sort":[{"_doc":"desc"}],"query":{"match_all":{}}}'
        $sampleResp = Invoke-SiemQuery -Path "/tinysocs-alerts-*/_search" -Body $sampleBody
        $sampleHits = @($sampleResp.hits.hits)
        if ($sampleHits.Count -gt 0) {
            $src = $sampleHits[0]._source
            $fieldNames = @($src | Get-Member -MemberType NoteProperty | ForEach-Object { $_.Name })
            Write-Host "    Sample alert fields: $($fieldNames -join ', ')"

            # Detect rule_id field path
            $ruleIdValue = $null
            $ruleIdPath = "unknown"
            if ($src.alert) {
                if ($src.alert.rule_id)  { $ruleIdValue = $src.alert.rule_id;  $ruleIdPath = "alert.rule_id" }
                elseif ($src.alert.ruleId)  { $ruleIdValue = $src.alert.ruleId;  $ruleIdPath = "alert.ruleId" }
                elseif ($src.alert.RuleId)  { $ruleIdValue = $src.alert.RuleId;  $ruleIdPath = "alert.RuleId" }
            }
            Write-Host "    Rule ID field path: $ruleIdPath = $ruleIdValue"

            # Show timestamp field info
            $ts = $null
            if ($src.timestamp) { $ts = $src.timestamp }
            elseif ($src.Timestamp) { $ts = $src.Timestamp }
            elseif ($src.'@timestamp') { $ts = $src.'@timestamp' }
            Write-Host "    Timestamp value: $ts"
        }

        # Get field mapping for alerts index
        try {
            $mappingSplat = @{
                Uri     = "$($script:_siemUrl)/tinysocs-alerts-*/_mapping"
                Method  = "GET"
                Headers = $script:_siemHeaders
            }
            $mappingResp = Invoke-RestMethod @mappingSplat -ErrorAction Stop
            # Extract first index mapping
            $firstIdx = ($mappingResp | Get-Member -MemberType NoteProperty | Select-Object -First 1).Name
            if ($firstIdx) {
                $alertMapping = $mappingResp.$firstIdx.mappings.properties.alert
                if ($alertMapping) {
                    $alertFields = $alertMapping.properties | Get-Member -MemberType NoteProperty | ForEach-Object { $_.Name }
                    Write-Host "    Alert sub-fields in mapping: $($alertFields -join ', ')"
                }
                $tsMapping = $mappingResp.$firstIdx.mappings.properties.timestamp
                if ($tsMapping) {
                    Write-Host "    Timestamp field type: $($tsMapping.type)"
                }
            }
        } catch {
            Write-Host "    (Could not read index mapping: $($_.Exception.Message))"
        }

        Write-Host "    Pre-flight check PASSED" -ForegroundColor Green
        return $true
    } catch {
        Write-Warning "    Pre-flight check FAILED: $($_.Exception.Message)"
        Write-Warning "    Cannot reach OpenSearch. Alerts will not be detected."
        return $false
    }
}

# ---------------------------------------------------------------------------
# Extract rule_id from a hit, handling multiple field name variants
# ---------------------------------------------------------------------------
function Get-HitRuleId {
    param($Hit)
    $src = $Hit._source
    if (-not $src -or -not $src.alert) { return $null }
    $a = $src.alert
    # Try all possible field name variants (snake_case, camelCase, PascalCase)
    if ($a.rule_id)  { return $a.rule_id }
    if ($a.ruleId)   { return $a.ruleId }
    if ($a.RuleId)   { return $a.RuleId }
    if ($a.ruleid)   { return $a.ruleid }
    return $null
}

# ---------------------------------------------------------------------------
# Query alerts with multi-strategy fallback
# ---------------------------------------------------------------------------
function Query-TinySocsAlerts {
    param(
        [string[]]$RuleIds,
        [int]$LookbackMinutes = 30
    )

    Initialize-SiemConnection

    # ── Strategy 1: Server-side term filter on alert.rule_id ──
    # The field is mapped as keyword type directly (no .keyword sub-field needed).
    try {
        $ruleFilter = ($RuleIds | ForEach-Object { "{`"term`":{`"alert.rule_id`":`"$_`"}}" }) -join ","
        $body = @"
{
  "size": 50,
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
        $resp = Invoke-SiemQuery -Path "/tinysocs-alerts-*/_search" -Body $body
        $hits = @($resp.hits.hits)
        if ($hits.Count -gt 0) { return $hits }
    } catch {
        Write-Host "    Strategy 1 (term+range) failed: $($_.Exception.Message)" -ForegroundColor DarkGray
    }

    # ── Strategy 2: Same rule filter but WITHOUT timestamp range ──
    # Handles case where timestamp field is mapped as text (not date).
    try {
        $ruleFilter2 = ($RuleIds | ForEach-Object { "{`"term`":{`"alert.rule_id`":`"$_`"}}" }) -join ","
        $body2 = @"
{
  "size": 50,
  "query": {
    "bool": {
      "should": [$ruleFilter2],
      "minimum_should_match": 1
    }
  }
}
"@
        $resp2 = Invoke-SiemQuery -Path "/tinysocs-alerts-*/_search" -Body $body2
        $hits2 = @($resp2.hits.hits)
        if ($hits2.Count -gt 0) { return $hits2 }
    } catch {
        Write-Host "    Strategy 2 (term, no range) failed: $($_.Exception.Message)" -ForegroundColor DarkGray
    }

    # ── Strategy 3: Fetch all alerts, match rule_id client-side ──
    # Handles field name mismatches (camelCase vs snake_case, missing .keyword).
    try {
        $body3 = @"
{
  "size": 500,
  "sort": [{"_doc": "desc"}],
  "query": {"match_all": {}}
}
"@
        $resp3 = Invoke-SiemQuery -Path "/tinysocs-alerts-*/_search" -Body $body3
        $allHits = @($resp3.hits.hits)

        if ($allHits.Count -gt 0) {
            $matched = @()
            foreach ($hit in $allHits) {
                $ruleId = Get-HitRuleId $hit
                if ($ruleId -and ($RuleIds -contains $ruleId)) {
                    $matched += $hit
                }
            }
            if ($matched.Count -gt 0) {
                Write-Host "    (Matched via client-side filter on $($allHits.Count) alerts)" -ForegroundColor DarkGray
                return $matched
            }
        }
    } catch {
        Write-Host "    Strategy 3 (match_all + client filter) failed: $($_.Exception.Message)" -ForegroundColor DarkGray
    }

    return @()
}

# ---------------------------------------------------------------------------
# Main execution
# ---------------------------------------------------------------------------
# Ensure TLS 1.2 for all outbound HTTPS (PS 5.1 defaults to old TLS)
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

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
    # Ensure module is loaded (use explicit path as fallback)
    if (-not (Get-Command Invoke-AtomicTest -ErrorAction SilentlyContinue)) {
        $artPsd1 = Join-Path $env:USERPROFILE "Documents\WindowsPowerShell\Modules\Invoke-AtomicRedTeam\Invoke-AtomicRedTeam.psd1"
        if (Test-Path $artPsd1) { Import-Module $artPsd1 -Force }
    }
}

# Pre-flight: check OpenSearch connectivity and alert schema
if (-not $DryRun) {
    $preflight = Test-AlertConnectivity
    if (-not $preflight) {
        Write-Warning "Pre-flight check failed. Tests will run but alert detection may not work."
        Write-Warning "Verify: (1) OpenSearch is running, (2) detection engine is enabled, (3) rules are loaded."
    }
}

# ---------------------------------------------------------------------------
# Enable Windows audit policies (required for Security event generation)
# ---------------------------------------------------------------------------
if (-not $DryRun) {
    Write-Host ""
    Write-Host "[*] Enabling Windows audit policies for detection..."
    $auditPolicies = @(
        @{ Sub = 'Logon';                       Flag = '/failure:enable' },
        @{ Sub = 'Logoff';                      Flag = '/success:enable' },
        @{ Sub = 'Process Creation';             Flag = '/success:enable' },
        @{ Sub = 'Other Object Access Events';   Flag = '/success:enable' },
        @{ Sub = 'User Account Management';      Flag = '/success:enable' },
        @{ Sub = 'Audit Policy Change';          Flag = '/success:enable' },
        @{ Sub = 'Security State Change';        Flag = '/success:enable' },
        @{ Sub = 'File System';                  Flag = '/success:enable' },
        @{ Sub = 'Special Logon';                Flag = '/success:enable' }
    )
    $auditOk = 0
    foreach ($ap in $auditPolicies) {
        $null = auditpol /set /subcategory:"$($ap.Sub)" $($ap.Flag) 2>&1
        if ($LASTEXITCODE -eq 0) { $auditOk++ }
    }
    Write-Host "    Enabled $auditOk/$($auditPolicies.Count) audit subcategories"

    # Enable command-line logging for 4688
    $regPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
    try {
        if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
        Set-ItemProperty -Path $regPath -Name 'ProcessCreationIncludeCmdLine_Enabled' -Value 1 -Type DWord
        Write-Host "    Process command-line logging enabled"
    } catch {
        Write-Host "    Warning: could not enable command-line logging: $($_.Exception.Message)" -ForegroundColor Yellow
    }
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

    # Execute the Atomic test (with fallback command support)
    # NOTE: Invoke-AtomicTest does NOT throw when it finds 0 applicable tests
    # or when the YAML file is missing. It prints messages and returns normally.
    # We must capture output and inspect it to detect these silent failures.
    $fallbackCmd = $test.fallback_command
    $usedFallback = $false
    $artSucceeded = $false
    $artError = $null

    try {
        Write-Host "  Executing Atomic test #$testNum..."
        Invoke-AtomicTest $technique -TestNumbers $testNum -GetPrereqs -ErrorAction SilentlyContinue

        # Capture ALL output (stdout + stderr + warning + verbose) to detect silent failures
        $artOutput = Invoke-AtomicTest $technique -TestNumbers $testNum -ErrorAction Stop *>&1
        $artOutputStr = ($artOutput | Out-String)

        # Check for patterns that indicate the test did NOT actually execute successfully.
        # Invoke-AtomicTest silently swallows many errors (no throw), so we must inspect output.
        $needsFallback = $false
        if ($artOutputStr -match "Found 0 atomic tests") {
            $artError = "No ART tests applicable to Windows for $technique"
            $needsFallback = $true
        } elseif ($artOutputStr -match "does not exist.*Check your Atomic") {
            $artError = "ART YAML file missing for $technique"
            $needsFallback = $true
        } elseif ($artOutputStr -match "'wmic' is not recognized") {
            $artError = "wmic tool not available (deprecated in this Windows version)"
            $needsFallback = $true
        } elseif ($artOutputStr -match "The specified service does not exist") {
            $artError = "Target service does not exist on this system"
            $needsFallback = $true
        } elseif ($artOutputStr -match "The network name cannot be found") {
            $artError = "Network target not reachable"
            $needsFallback = $true
        } elseif ($artOutputStr -match "Failed to meet prereq") {
            $artError = "ART prerequisite not met for $technique"
            $needsFallback = $true
        } else {
            $artSucceeded = $true
            Write-Host "  Test executed. Waiting for detection pipeline..."
        }
    } catch {
        $artError = $_.Exception.Message
        # "Access is denied" errors also qualify for fallback
        $needsFallback = $true
    }

    # If ART test didn't succeed, try fallback command
    if (-not $artSucceeded) {
        if ($fallbackCmd -and $needsFallback) {
            Write-Host "  ART test failed ($artError). Using fallback command..." -ForegroundColor Yellow
            try {
                Invoke-Expression $fallbackCmd
                $usedFallback = $true
                Write-Host "  Fallback command executed. Waiting for detection pipeline..."
            } catch {
                Write-Host "  ERROR executing fallback: $($_.Exception.Message)" -ForegroundColor Red
                $results += [PSCustomObject]@{
                    Technique = $technique
                    Name      = $name
                    Status    = "ERROR"
                    Reason    = "ART: $artError; Fallback: $($_.Exception.Message)"
                    Rules     = ($rules -join ", ")
                    Detected  = @()
                }
                continue
            }
        } else {
            Write-Host "  ERROR: $artError" -ForegroundColor Red
            $results += [PSCustomObject]@{
                Technique = $technique
                Name      = $name
                Status    = "ERROR"
                Reason    = $artError
                Rules     = ($rules -join ", ")
                Detected  = @()
            }
            # Cleanup
            try { Invoke-AtomicTest $technique -TestNumbers $testNum -Cleanup -ErrorAction SilentlyContinue } catch { }
            continue
        }
    }

    # Wait for detection pipeline to process
    $detected = @()
    $deadline = (Get-Date).AddSeconds($timeout)
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 15
        $hits = Query-TinySocsAlerts -RuleIds $rules -LookbackMinutes 30
        if ($hits.Count -gt 0) {
            $detected = @($hits | ForEach-Object { Get-HitRuleId $_ } | Where-Object { $_ } | Select-Object -Unique)
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

    # Cleanup (skip ART cleanup if we used the fallback command)
    if (-not $usedFallback) {
        try {
            Write-Host "  Cleaning up..."
            Invoke-AtomicTest $technique -TestNumbers $testNum -Cleanup -ErrorAction SilentlyContinue
        } catch {
            Write-Host "  Cleanup warning: $($_.Exception.Message)" -ForegroundColor Yellow
        }
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

Generated: $([System.DateTime]::UtcNow.ToString("yyyy-MM-dd HH:mm:ss")) UTC

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
