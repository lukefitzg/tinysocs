#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Diagnoses the TinySocs detection pipeline end-to-end.
    Checks Windows audit policies, event log channels, agent state, and detection flow.

.DESCRIPTION
    Run this script on the Windows VM to identify why certain detection rules
    are not firing. It checks:
    1. Windows audit policy configuration
    2. Event existence in Security/System logs
    3. Agent process state and log analysis
    4. Event data field extraction (verifies group_by fields resolve)
    5. Live pipeline test (generates an event and checks detection)
#>

param(
    [switch]$EnableAuditPolicies,
    [switch]$LiveTest
)

$ErrorActionPreference = 'Continue'

function Write-Section($title) {
    Write-Host "`n$('=' * 70)" -ForegroundColor Cyan
    Write-Host "  $title" -ForegroundColor Cyan
    Write-Host "$('=' * 70)" -ForegroundColor Cyan
}

function Write-Ok($msg)   { Write-Host "  [OK]   $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "  [WARN] $msg" -ForegroundColor Yellow }
function Write-Fail($msg) { Write-Host "  [FAIL] $msg" -ForegroundColor Red }
function Write-Info($msg)  { Write-Host "  [INFO] $msg" -ForegroundColor White }

# ─── 1. AGENT PROCESS STATE ─────────────────────────────────────────────────

Write-Section "1. Agent Process State"

$agentProc = Get-Process TinySocs.Agent -ErrorAction SilentlyContinue
if ($agentProc) {
    Write-Ok "TinySocs.Agent is running (PID: $($agentProc.Id), WS: $([math]::Round($agentProc.WorkingSet64/1MB, 1)) MB)"
} else {
    Write-Fail "TinySocs.Agent is NOT running!"
    $svc = Get-Service TinySocsAgent -ErrorAction SilentlyContinue
    if ($svc) {
        Write-Info "Service status: $($svc.Status)"
    }
}

# ─── 2. WINDOWS AUDIT POLICIES ──────────────────────────────────────────────

Write-Section "2. Windows Audit Policies"

$requiredPolicies = @{
    # subcategory → required setting
    'Logon'                       = 'Failure'   # Event 4625 (failed logon)
    'Process Creation'            = 'Success'   # Event 4688
    'Other Object Access Events'  = 'Success'   # Event 4698 (scheduled task)
    'User Account Management'     = 'Success'   # Event 4720 (account created)
    'Audit Policy Change'         = 'Success'   # Event 4719
    'Security State Change'       = 'Success'   # Event 4608
    'File System'                 = 'Success'   # Event 4663 (file access)
}

$auditOutput = auditpol /get /category:* 2>&1 | Out-String
$policyIssues = @()

foreach ($subcategory in $requiredPolicies.Keys) {
    $needed = $requiredPolicies[$subcategory]
    # Parse auditpol output for this subcategory
    $line = ($auditOutput -split "`n") | Where-Object { $_ -match "^\s+$subcategory\s+" } | Select-Object -First 1
    if ($line) {
        $setting = ($line -replace "^\s+$subcategory\s+", '').Trim()
        if ($setting -match $needed -or $setting -match 'Success and Failure') {
            Write-Ok "$subcategory`: $setting (need: $needed)"
        } else {
            Write-Fail "$subcategory`: $setting (need: $needed)"
            $policyIssues += $subcategory
        }
    } else {
        Write-Warn "$subcategory`: not found in auditpol output"
        $policyIssues += $subcategory
    }
}

# Check command-line logging for 4688
$cmdLineReg = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name 'ProcessCreationIncludeCmdLine_Enabled' -ErrorAction SilentlyContinue
if ($cmdLineReg -and $cmdLineReg.ProcessCreationIncludeCmdLine_Enabled -eq 1) {
    Write-Ok "Process command-line logging: ENABLED"
} else {
    Write-Warn "Process command-line logging: DISABLED (event 4688 won't include CommandLine)"
}

if ($policyIssues.Count -gt 0 -and -not $EnableAuditPolicies) {
    Write-Host ""
    Write-Warn "Re-run with -EnableAuditPolicies to fix these issues automatically."
}

# ─── 3. EVENT LOG CHANNEL HEALTH ────────────────────────────────────────────

Write-Section "3. Event Log Channel Health"

$channels = @(
    @{ Name = 'Security';                                        EventIds = @(4625, 4688, 4698, 4720, 1102) },
    @{ Name = 'System';                                          EventIds = @(7045) },
    @{ Name = 'Microsoft-Windows-PowerShell/Operational';        EventIds = @(4104) },
    @{ Name = 'Microsoft-Windows-Sysmon/Operational';            EventIds = @(1, 8, 10, 13) },
    @{ Name = 'Microsoft-Windows-Windows Defender/Operational';  EventIds = @(5001) }
)

foreach ($ch in $channels) {
    $chName = $ch.Name
    try {
        $log = Get-WinEvent -ListLog $chName -ErrorAction Stop
        $total = $log.RecordCount
        $maxSize = [math]::Round($log.MaximumSizeInBytes / 1MB, 1)
        Write-Ok "$chName`: enabled=$($log.IsEnabled), records=$total, maxSize=${maxSize}MB"

        # Check for recent events with the IDs we need
        foreach ($eid in $ch.EventIds) {
            try {
                $recent = Get-WinEvent -LogName $chName -FilterXPath "*[System[EventID=$eid]]" -MaxEvents 3 -ErrorAction Stop
                $newest = $recent[0].TimeCreated
                $age = [math]::Round(((Get-Date) - $newest).TotalMinutes, 1)
                Write-Ok "  Event $eid`: found (newest: $newest, ${age}min ago, count=3+)"
            } catch {
                Write-Fail "  Event $eid`: NO events found in $chName"
            }
        }
    } catch {
        Write-Fail "$chName`: channel NOT FOUND or inaccessible"
    }
}

# ─── 4. EVENT DATA FIELD EXTRACTION TEST ────────────────────────────────────

Write-Section "4. Event Data Field Extraction"
Write-Info "Testing that group_by fields resolve in actual events..."

$fieldTests = @(
    @{ Channel = 'Security';  EventId = 4625;  Field = 'TargetUserName';   Description = 'Failed logon user' },
    @{ Channel = 'Security';  EventId = 4688;  Field = 'SubjectUserName';  Description = 'Process creator' },
    @{ Channel = 'Security';  EventId = 4688;  Field = 'NewProcessName';   Description = 'New process path' },
    @{ Channel = 'Security';  EventId = 4720;  Field = 'TargetUserName';   Description = 'Created account name' },
    @{ Channel = 'Security';  EventId = 4698;  Field = 'SubjectUserName';  Description = 'Task scheduler user' },
    @{ Channel = 'System';    EventId = 7045;  Field = 'ServiceName';      Description = 'Installed service name' },
    @{ Channel = 'Microsoft-Windows-Sysmon/Operational'; EventId = 13; Field = 'Image'; Description = 'Sysmon reg modify image' },
    @{ Channel = 'Microsoft-Windows-Sysmon/Operational'; EventId = 8;  Field = 'SourceImage'; Description = 'Sysmon injection source' }
)

foreach ($test in $fieldTests) {
    try {
        $evt = Get-WinEvent -LogName $test.Channel -FilterXPath "*[System[EventID=$($test.EventId)]]" -MaxEvents 1 -ErrorAction Stop
        $xml = [xml]$evt.ToXml()
        $ns = New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
        $ns.AddNamespace('e', 'http://schemas.microsoft.com/win/2004/08/events/event')
        $dataNode = $xml.SelectSingleNode("//e:EventData/e:Data[@Name='$($test.Field)']", $ns)
        if ($dataNode) {
            $val = $dataNode.InnerText
            if ($val.Length -gt 50) { $val = $val.Substring(0, 50) + '...' }
            Write-Ok "$($test.Channel)/$($test.EventId)/$($test.Field) = '$val'"
        } else {
            Write-Fail "$($test.Channel)/$($test.EventId)/$($test.Field) = NOT FOUND in EventData"
        }
    } catch {
        Write-Warn "$($test.Channel)/$($test.EventId)/$($test.Field) = No event $($test.EventId) exists to test"
    }
}

# ─── 5. AGENT LOG ANALYSIS ──────────────────────────────────────────────────

Write-Section "5. Agent Log Analysis"

$logPaths = @(
    'C:\ProgramData\TinySocs\Collector\logs\agent.log',
    'C:\ProgramData\TinySocs\Collector\logs\TinySocsAgent.out.log'
)

foreach ($logPath in $logPaths) {
    if (Test-Path $logPath) {
        $logSize = [math]::Round((Get-Item $logPath).Length / 1KB, 1)
        Write-Ok "Found $logPath (${logSize}KB)"

        # Get last 200 lines
        $lines = Get-Content $logPath -Tail 200 -ErrorAction SilentlyContinue

        # Check for channel priming
        $primeLines = $lines | Where-Object { $_ -match 'Primed EventLog channel' }
        if ($primeLines) {
            foreach ($pl in $primeLines) {
                Write-Info "  PRIME: $($pl.Trim())"
            }
        } else {
            Write-Warn "  No channel priming messages found (agent may have started long ago)"
        }

        # Check for event reads
        $readLines = $lines | Where-Object { $_ -match 'Read \d+ new event' }
        $readCount = ($readLines | Measure-Object).Count
        if ($readCount -gt 0) {
            Write-Ok "  Found $readCount event-read log entries"
            # Show last 5
            $readLines | Select-Object -Last 5 | ForEach-Object {
                Write-Info "  READ: $($_.Trim())"
            }
        } else {
            Write-Fail "  NO event-read messages found! Agent may not be reading events."
        }

        # Check for alert fires
        $alertLines = $lines | Where-Object { $_ -match 'Alert fired' }
        $alertCount = ($alertLines | Measure-Object).Count
        if ($alertCount -gt 0) {
            Write-Ok "  Found $alertCount alert-fired entries"
            $alertLines | Select-Object -Last 5 | ForEach-Object {
                Write-Info "  ALERT: $($_.Trim())"
            }
        } else {
            Write-Warn "  No alert-fired messages found in recent logs"
        }

        # Check for errors
        $errorLines = $lines | Where-Object { $_ -match '\b(ERROR|Exception|FAIL)\b' -and $_ -notmatch 'SilentlyContinue' }
        $errorCount = ($errorLines | Measure-Object).Count
        if ($errorCount -gt 0) {
            Write-Warn "  Found $errorCount error entries:"
            $errorLines | Select-Object -Last 5 | ForEach-Object {
                Write-Info "  ERR: $($_.Trim())"
            }
        } else {
            Write-Ok "  No errors in recent log entries"
        }

        # Check for log clear detection
        $clearLines = $lines | Where-Object { $_ -match 'Log was likely cleared' }
        if ($clearLines) {
            foreach ($cl in $clearLines) {
                Write-Info "  LOG-CLEAR: $($cl.Trim())"
            }
        }

        # Check for rule loading
        $ruleLines = $lines | Where-Object { $_ -match 'Detection engine updated|rule\(s\)' }
        if ($ruleLines) {
            $ruleLines | Select-Object -Last 2 | ForEach-Object {
                Write-Info "  RULES: $($_.Trim())"
            }
        }

        # Check for missing channels
        $missingLines = $lines | Where-Object { $_ -match 'channel.*not found' }
        if ($missingLines) {
            foreach ($ml in $missingLines) {
                Write-Fail "  MISSING CHANNEL: $($ml.Trim())"
            }
        }
    } else {
        Write-Warn "$logPath not found"
    }
}

# ─── 6. RULES FILE CHECK ────────────────────────────────────────────────────

Write-Section "6. Detection Rules File"

$rulesPath = 'C:\ProgramData\TinySocs\Collector\rules\rules.yml'
if (Test-Path $rulesPath) {
    $rulesSize = [math]::Round((Get-Item $rulesPath).Length / 1KB, 1)
    $rulesContent = Get-Content $rulesPath -Raw
    $ruleCount = ([regex]::Matches($rulesContent, '(?m)^  - id:')).Count
    Write-Ok "Rules file: $rulesPath (${rulesSize}KB, $ruleCount rules)"

    # Check for key rules
    $keyRules = @('TS-001', 'TS-010', 'TS-020', 'TS-080', 'TS-090', 'TS-091', 'TS-130', 'TS-131', 'TS-133')
    foreach ($ruleId in $keyRules) {
        if ($rulesContent -match "id:\s*`"$ruleId`"") {
            # Check if enabled
            $idx = $rulesContent.IndexOf("`"$ruleId`"")
            $snippet = $rulesContent.Substring($idx, [math]::Min(300, $rulesContent.Length - $idx))
            if ($snippet -match 'enabled:\s*true') {
                Write-Ok "  Rule $ruleId`: present and enabled"
            } else {
                Write-Fail "  Rule $ruleId`: present but DISABLED"
            }
        } else {
            Write-Fail "  Rule $ruleId`: NOT FOUND in rules file"
        }
    }
} else {
    Write-Fail "Rules file not found at $rulesPath"
}

# ─── 7. OPENSEARCH CONNECTIVITY ─────────────────────────────────────────────

Write-Section "7. OpenSearch Connectivity"

# Read credentials
$envFile = Join-Path $env:ProgramData "TinySocs\Assistant\assistant.env"
$siemUrl  = "https://localhost:9201"
$siemUser = "admin"
$siemPass = ""

if (Test-Path $envFile) {
    Get-Content $envFile | ForEach-Object {
        if ($_ -match '^SIEM_PASS=(.+)$') { $siemPass = $Matches[1].Trim() }
        if ($_ -match '^SIEM_USER=(.+)$') { $siemUser = $Matches[1].Trim() }
        if ($_ -match '^SIEM_URL=(.+)$')  { $siemUrl  = $Matches[1].Trim() }
    }
    Write-Ok "Loaded credentials from $envFile"
} else {
    Write-Warn "assistant.env not found at $envFile"
}

[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
$pair = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${siemUser}:${siemPass}"))
$headers = @{ "Authorization" = "Basic $pair"; "Content-Type" = "application/json" }

try {
    $health = Invoke-RestMethod -Uri "$siemUrl/_cluster/health" -Headers $headers -Method GET -TimeoutSec 10
    Write-Ok "OpenSearch cluster: $($health.cluster_name), status=$($health.status)"
} catch {
    Write-Fail "OpenSearch not reachable: $($_.Exception.Message)"
}

# Check alerts index
try {
    $alertCount = Invoke-RestMethod -Uri "$siemUrl/tinysocs-alerts-*/_count" -Headers $headers -Method GET -TimeoutSec 10
    Write-Ok "Total alerts in OpenSearch: $($alertCount.count)"
} catch {
    Write-Warn "Could not count alerts: $($_.Exception.Message)"
}

# Check recent alerts (last 10 minutes)
try {
    $queryBody = @{
        size = 5
        sort = @(@{ "@timestamp" = @{ order = "desc" } })
        query = @{
            range = @{
                "@timestamp" = @{
                    gte = "now-10m"
                }
            }
        }
    } | ConvertTo-Json -Depth 10

    $recent = Invoke-RestMethod -Uri "$siemUrl/tinysocs-alerts-*/_search" -Headers $headers -Method POST -Body $queryBody -TimeoutSec 10
    $recentCount = $recent.hits.total.value
    Write-Info "Alerts in last 10 minutes: $recentCount"
    if ($recentCount -gt 0) {
        foreach ($hit in $recent.hits.hits) {
            $ruleId = $hit._source.alert.rule_id
            $ruleName = $hit._source.alert.rule_name
            $ts = $hit._source.'@timestamp'
            Write-Ok "  Recent alert: $ruleId ($ruleName) at $ts"
        }
    }
} catch {
    Write-Warn "Could not query recent alerts: $($_.Exception.Message)"
}

# ─── 8. LIVE PIPELINE TEST ──────────────────────────────────────────────────

if ($LiveTest) {
    Write-Section "8. Live Pipeline Test"
    Write-Info "Generating a known event and checking if the agent detects it..."
    Write-Info ""

    # Count current alerts before test
    $beforeCount = 0
    try {
        $beforeResult = Invoke-RestMethod -Uri "$siemUrl/tinysocs-alerts-*/_count" -Headers $headers -Method GET -TimeoutSec 10
        $beforeCount = $beforeResult.count
    } catch {}

    # Test 1: Generate failed logon events (4625) — should trigger TS-001 (threshold 5)
    Write-Info "Generating 6 failed logon events (Event 4625)..."
    1..6 | ForEach-Object {
        net use \\127.0.0.1\IPC$ /user:diagtest "WrongPass$_" 2>$null
        Start-Sleep -Milliseconds 500
    }
    Write-Info "  Generated 6 failed logon attempts."

    # Test 2: Create a scheduled task (4698)
    Write-Info "Creating a scheduled task (Event 4698)..."
    schtasks /create /tn "TinySocs-Diag-Test" /tr "cmd /c whoami" /sc once /st 23:59 /f 2>$null
    Start-Sleep -Seconds 2
    schtasks /delete /tn "TinySocs-Diag-Test" /f 2>$null

    # Test 3: Create a service (7045)
    Write-Info "Creating a test service (Event 7045)..."
    sc.exe create TinySocsDiagTest binPath= "C:\Windows\Temp\diag-test.exe" start= demand type= own 2>$null
    Start-Sleep -Seconds 2
    sc.exe delete TinySocsDiagTest 2>$null

    Write-Info ""
    Write-Info "Waiting 30 seconds for detection pipeline (2s poll + queue + ship)..."
    Start-Sleep -Seconds 30

    # Verify events were actually generated
    Write-Info ""
    Write-Info "Verifying events were generated in the log..."

    # Check for 4625 events
    try {
        $e4625 = Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4625 and TimeCreated[timediff(@SystemTime) <= 120000]]]" -MaxEvents 10 -ErrorAction Stop
        Write-Ok "Event 4625: found $($e4625.Count) events in last 2 minutes"
    } catch {
        Write-Fail "Event 4625: NO events generated!"
    }

    # Check for 4698 events
    try {
        $e4698 = Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4698 and TimeCreated[timediff(@SystemTime) <= 120000]]]" -MaxEvents 5 -ErrorAction Stop
        Write-Ok "Event 4698: found $($e4698.Count) events in last 2 minutes"
    } catch {
        Write-Fail "Event 4698: NO events generated! (Audit policy may be disabled)"
    }

    # Check for 7045 events
    try {
        $e7045 = Get-WinEvent -LogName System -FilterXPath "*[System[EventID=7045 and TimeCreated[timediff(@SystemTime) <= 120000]]]" -MaxEvents 5 -ErrorAction Stop
        Write-Ok "Event 7045: found $($e7045.Count) events in last 2 minutes"
    } catch {
        Write-Fail "Event 7045: NO events generated!"
    }

    # Check for new alerts
    $afterCount = 0
    try {
        $afterResult = Invoke-RestMethod -Uri "$siemUrl/tinysocs-alerts-*/_count" -Headers $headers -Method GET -TimeoutSec 10
        $afterCount = $afterResult.count
    } catch {}

    $newAlerts = $afterCount - $beforeCount
    if ($newAlerts -gt 0) {
        Write-Ok "NEW ALERTS GENERATED: $newAlerts"
    } else {
        Write-Fail "NO new alerts generated after live test!"
        Write-Info "Checking agent log for recent activity..."

        $agentLog = 'C:\ProgramData\TinySocs\Collector\logs\agent.log'
        if (Test-Path $agentLog) {
            $recentLog = Get-Content $agentLog -Tail 50
            $recentReads = $recentLog | Where-Object { $_ -match 'Read \d+ new event.*Security|Read \d+ new event.*System' }
            if ($recentReads) {
                Write-Ok "Agent IS reading from Security/System (but not alerting):"
                $recentReads | Select-Object -Last 3 | ForEach-Object { Write-Info "  $_" }
                Write-Warn "Events are read but not matched by rules. Check group_by field resolution."
            } else {
                Write-Fail "Agent is NOT reading from Security/System channels!"
                Write-Info "Check: Is the agent config correct? Is the agent recently restarted?"
            }
        }
    }
} else {
    Write-Section "8. Live Pipeline Test"
    Write-Info "Skipped. Re-run with -LiveTest to generate test events and verify pipeline."
}

# ─── 9. ENABLE AUDIT POLICIES (if requested) ────────────────────────────────

if ($EnableAuditPolicies) {
    Write-Section "9. Enabling Required Audit Policies"

    $policies = @(
        @{ Subcategory = 'Logon';                       Type = '/failure:enable' },
        @{ Subcategory = 'Logoff';                      Type = '/success:enable' },
        @{ Subcategory = 'Process Creation';             Type = '/success:enable' },
        @{ Subcategory = 'Other Object Access Events';   Type = '/success:enable' },
        @{ Subcategory = 'User Account Management';      Type = '/success:enable' },
        @{ Subcategory = 'Audit Policy Change';          Type = '/success:enable' },
        @{ Subcategory = 'Security State Change';        Type = '/success:enable' },
        @{ Subcategory = 'File System';                  Type = '/success:enable' },
        @{ Subcategory = 'Special Logon';                Type = '/success:enable' }
    )

    foreach ($p in $policies) {
        $result = auditpol /set /subcategory:"$($p.Subcategory)" $($p.Type) 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Ok "Enabled: $($p.Subcategory) $($p.Type)"
        } else {
            Write-Fail "Failed to enable: $($p.Subcategory) — $result"
        }
    }

    # Enable command-line logging for 4688
    Write-Info "Enabling process command-line logging (for Event 4688)..."
    $regPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
    if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }
    Set-ItemProperty -Path $regPath -Name 'ProcessCreationIncludeCmdLine_Enabled' -Value 1 -Type DWord
    Write-Ok "Command-line logging enabled via registry"

    Write-Host ""
    Write-Ok "Audit policies configured. Events should now be generated."
    Write-Info "Restart the TinySocs Agent to pick up events from the fresh audit state:"
    Write-Info "  Restart-Service TinySocsAgent"
}

# ─── SUMMARY ────────────────────────────────────────────────────────────────

Write-Section "DIAGNOSIS SUMMARY"

if ($policyIssues.Count -gt 0) {
    Write-Fail "$($policyIssues.Count) audit policy issue(s) found: $($policyIssues -join ', ')"
    Write-Info "Run: .\Diagnose-DetectionPipeline.ps1 -EnableAuditPolicies"
} else {
    Write-Ok "All required audit policies are configured"
}

Write-Host ""
Write-Info "Recommended next steps:"
Write-Info "  1. Run with -EnableAuditPolicies to fix audit policy gaps"
Write-Info "  2. Restart agent: Restart-Service TinySocsAgent"
Write-Info "  3. Run with -LiveTest to verify end-to-end pipeline"
Write-Info "  4. Re-run ART tests: .\Test-AtomicDetection.ps1"
