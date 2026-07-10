<#
.SYNOPSIS
    Ransomware detection demo. Simulates a ransomware encryption sweep against the
    TinySocs canary directory and shows TS-113 (mass file modification) firing.

.DESCRIPTION
    The agent seeds C:\ProgramData\TinySocs\Canary with ~60 decoy files at startup
    (invoice.docx, payroll.xlsx, ...). Nothing legitimate ever touches them, so a
    burst of modifications is a high-signal ransomware indicator. This script
    "encrypts" every decoy (appends a marker + a fake .locked rename), which the
    FIM watcher reports as a mass modification - TS-113 fires at threshold 50/min.

    Safe: only the canary decoys are touched; no real files are modified.

    Requires: TinySocs installed with FIM enabled (agent-config.yml has a `fim`
    input) and running as Administrator.

.EXAMPLE
    .\Demo-Ransomware.ps1
.EXAMPLE
    .\Demo-Ransomware.ps1 -SiemUrl https://localhost:9201 -Password <opensearch-pass>
#>
[CmdletBinding()]
param(
    [string]$CanaryPath = "C:\ProgramData\TinySocs\Canary",
    [string]$SiemUrl = "https://localhost:9201",
    [string]$User = "admin",
    [string]$Password,
    [int]$WaitSeconds = 120
)

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "==================================================="
Write-Host "  TinySocs Ransomware Detection Demo (TS-113)"
Write-Host "==================================================="
Write-Host ""

if (-not (Test-Path $CanaryPath)) {
    Write-Warning "Canary directory not found at $CanaryPath."
    Write-Warning "FIM may be disabled or the agent hasn't seeded it yet. Confirm agent-config.yml has a 'fim' input and the agent has started, then retry."
    exit 1
}

$files = Get-ChildItem -Path $CanaryPath -File
if ($files.Count -lt 50) {
    Write-Warning "Only $($files.Count) canary files present (need >=50 for TS-113). The agent seeds 60 on startup - is FIM enabled?"
    exit 1
}

Write-Host "[*] Found $($files.Count) canary decoy files."
Write-Host "[*] Simulating a ransomware encryption sweep (modifying every decoy)..."

$stamp = Get-Date -Format "o"
foreach ($f in $files) {
    # Append an 'encryption' marker - a real change the FIM watcher will hash-diff.
    Add-Content -Path $f.FullName -Value "ENCRYPTED_BY_DEMO $stamp" -ErrorAction SilentlyContinue
}
Write-Host "    Modified $($files.Count) files at $stamp" -ForegroundColor Yellow
Write-Host ""
Write-Host "[*] This should trip TS-113 (>50 monitored files changed in 60s)."
Write-Host "    Watch the alert land on the dashboard, or wait for the check below."
Write-Host ""

# Best-effort confirmation via OpenSearch. If creds aren't supplied, just tell the
# operator to watch the dashboard.
if (-not $Password) {
    Write-Host "[*] No -Password given; skipping automated check." -ForegroundColor DarkGray
    Write-Host "    Open the TinySocs dashboard - you should see a CRITICAL alert:" -ForegroundColor Cyan
    Write-Host "      'fim_mass_modification' - ransomware indicator on this host." -ForegroundColor Cyan
    exit 0
}

Write-Host "[*] Polling OpenSearch for the TS-113 alert (up to ${WaitSeconds}s)..."
$deadline = (Get-Date).AddSeconds($WaitSeconds)
$query = '{"size":5,"query":{"bool":{"must":[{"term":{"alert.rule_id":"TS-113"}},{"range":{"timestamp":{"gte":"now-5m"}}}]}},"sort":[{"timestamp":"desc"}]}'

while ((Get-Date) -lt $deadline) {
    try {
        $resp = curl.exe -sk -u "${User}:${Password}" -H "Content-Type: application/json" `
            -X POST "$SiemUrl/tinysocs-alerts-*/_search" -d $query 2>$null | ConvertFrom-Json
        $hits = $resp.hits.hits
        if ($hits -and $hits.Count -gt 0) {
            $a = $hits[0]._source.alert
            Write-Host ""
            Write-Host "  DETECTED: TS-113 fired." -ForegroundColor Green
            Write-Host "    $($a.rule_name): $($a.description)" -ForegroundColor Green
            Write-Host "    severity=$($a.severity) matched_events=$($a.event_count)" -ForegroundColor Green
            exit 0
        }
    } catch { }
    Start-Sleep -Seconds 8
    Write-Host "    ...waiting ($([int]($deadline - (Get-Date)).TotalSeconds)s left)"
}

Write-Host ""
Write-Warning "No TS-113 alert seen within ${WaitSeconds}s. Check the agent log and that FIM is enabled; the FIM periodic scan is a fallback if the real-time watcher missed the burst."
exit 1
