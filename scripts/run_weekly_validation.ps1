# scripts/run_weekly_validation.ps1
<#
.SYNOPSIS
    VM-side wrapper for the weekly continuous validation run.

.DESCRIPTION
    One-liner-clean entry point for the Windows Task Scheduler job. It:
      1. pulls the latest main,
      2. runs the Atomic Red Team harness to a raw run file (in logs/, which
         is gitignored),
      3. normalises that raw run into results/<iso-week>.json + latest.json
         via scripts/normalize_validation_run.py (the normaliser decides the
         filename from the run timestamp, so the week is computed in exactly
         one place),
      4. commits and pushes results/ — which triggers the Pages workflow to
         rebuild the public dashboard.

    Everything is logged to logs/validation-<timestamp>.log. A failure at any
    step aborts before the commit, so a broken run never publishes.

    See docs/operator/weekly-validation-setup.md for the Task Scheduler entry
    and the deploy-key setup.

.PARAMETER Branch
    Branch to pull/commit/push. Default: main.

.PARAMETER NoPush
    Run and commit locally but do not push (useful for a first dry run).

.PARAMETER SkipPull
    Skip the git pull (useful when testing local changes).

.PARAMETER HarnessArgs
    Extra arguments forwarded to Test-AtomicDetection.ps1 (e.g. -SkipInstall).

.EXAMPLE
    pwsh scripts/run_weekly_validation.ps1
    pwsh scripts/run_weekly_validation.ps1 -NoPush -SkipPull -HarnessArgs '-SkipInstall'
#>
[CmdletBinding()]
param(
    [string]$Branch = "main",
    [switch]$NoPush,
    [switch]$SkipPull,
    [string[]]$HarnessArgs = @()
)

$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$logDir   = Join-Path $repoRoot "logs"
if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }

$stamp   = Get-Date -Format "yyyyMMdd-HHmmss"
$logFile = Join-Path $logDir "validation-$stamp.log"
$rawFile = Join-Path $logDir "validation-raw.json"

function Log {
    param([string]$Message, [string]$Level = "INFO")
    $line = "{0} [{1}] {2}" -f (Get-Date -Format "o"), $Level, $Message
    $line | Tee-Object -FilePath $logFile -Append
}

function Resolve-Python {
    foreach ($cand in @("python3", "python")) {
        $cmd = Get-Command $cand -ErrorAction SilentlyContinue
        if ($cmd) { return $cmd.Source }
    }
    # Windows launcher fallback.
    if (Get-Command "py" -ErrorAction SilentlyContinue) { return "py" }
    throw "No Python interpreter found (tried python3, python, py)."
}

$exitCode = 0
try {
    Log "Weekly validation starting (repo=$repoRoot, branch=$Branch)"
    Set-Location $repoRoot

    if (-not $SkipPull) {
        Log "git pull --ff-only origin $Branch"
        git pull --ff-only origin $Branch 2>&1 | Tee-Object -FilePath $logFile -Append
        if ($LASTEXITCODE -ne 0) { throw "git pull failed (exit $LASTEXITCODE)" }
    } else {
        Log "Skipping git pull (-SkipPull)"
    }

    # 1. Run the harness -> raw run JSON (in gitignored logs/).
    $harness = Join-Path $repoRoot "tests\Test-AtomicDetection.ps1"
    if (-not (Test-Path $harness)) { throw "Harness not found: $harness" }
    Log "Running harness -> $rawFile"
    & $harness -OutputJson $rawFile @HarnessArgs 2>&1 | Tee-Object -FilePath $logFile -Append
    if (-not (Test-Path $rawFile)) { throw "Harness did not produce a raw run file: $rawFile" }

    # 2. Normalise -> results/<iso-week>.json + latest.json
    $python = Resolve-Python
    $normalizer = Join-Path $repoRoot "scripts\normalize_validation_run.py"
    Log "Normalising raw run via $python $normalizer"
    & $python $normalizer $rawFile 2>&1 | Tee-Object -FilePath $logFile -Append
    if ($LASTEXITCODE -ne 0) { throw "Normaliser failed (exit $LASTEXITCODE)" }

    $latest = Get-Content (Join-Path $repoRoot "results\latest.json") -Raw | ConvertFrom-Json
    $runId  = $latest.run_id
    $missed = $latest.summary.atomic_tests_missed
    Log "Run $runId complete: $($latest.summary.atomic_tests_detected) detected, $missed missed, $($latest.summary.atomic_tests_error) error"
    if ($missed -gt 0) {
        Log "MISS detected ($missed). Commit proceeds (honest record); investigate and add a postmortem under results/postmortems/." "WARN"
    }

    # 3. Commit results/ only. Anything staged?
    git add results 2>&1 | Tee-Object -FilePath $logFile -Append
    $staged = git diff --cached --name-only
    if (-not $staged) {
        Log "No result changes to commit (re-run of an existing week with identical output). Done."
    } else {
        $msg = "validation: $runId run"
        Log "git commit -m `"$msg`""
        git commit -m $msg 2>&1 | Tee-Object -FilePath $logFile -Append
        if ($LASTEXITCODE -ne 0) { throw "git commit failed (exit $LASTEXITCODE)" }

        if (-not $NoPush) {
            Log "git push origin $Branch"
            git push origin $Branch 2>&1 | Tee-Object -FilePath $logFile -Append
            if ($LASTEXITCODE -ne 0) { throw "git push failed (exit $LASTEXITCODE)" }
            Log "Pushed. The Pages workflow will rebuild the dashboard."
        } else {
            Log "Skipping push (-NoPush). Commit is local only."
        }
    }

    Log "Weekly validation finished OK."
}
catch {
    $exitCode = 1
    Log "FAILED: $($_.Exception.Message)" "ERROR"
    Log "No results were published for this run." "ERROR"
}

Log "Log written to $logFile"
exit $exitCode
