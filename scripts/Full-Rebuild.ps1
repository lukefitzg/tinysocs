<#
.SYNOPSIS
  Full rebuild script for TinySocs: purge old install, build all components,
  compile installer, and run it.

.DESCRIPTION
  Run this from an elevated (Admin) PowerShell prompt on the Windows VM.
  Set $RepoRoot to wherever the shared folder mounts the TinySocs repo.

.EXAMPLE
  .\scripts\Full-Rebuild.ps1 -RepoRoot "\\Mac\Home\.claude-worktrees\tinysocs\affectionate-babbage"
#>

[CmdletBinding()]
param(
    [string]$RepoRoot = ''
)

# Resolve RepoRoot: prefer $PSScriptRoot, then current directory
if (-not $RepoRoot) {
    if ($PSScriptRoot) {
        $RepoRoot = $PSScriptRoot
    } else {
        $RepoRoot = (Get-Location).Path
    }
}

# If launched from scripts/, go up one level
if ($RepoRoot -match 'scripts[\\\/]?$') {
    $RepoRoot = Split-Path $RepoRoot -Parent
}

# ISCC (Inno Setup compiler) cannot compile from UNC paths (\\Mac\...).
# If RepoRoot is a UNC path, robocopy to a local working directory first.
$UsingLocalCopy = $false
$OrigRepoRoot = $RepoRoot
if ($RepoRoot -match '^\\\\') {
    $LocalBuildDir = 'C:\TinySocs-Build'
    Write-Host ""
    Write-Host "  UNC path detected: $RepoRoot" -ForegroundColor Yellow
    Write-Host "  Inno Setup cannot compile from network shares."
    Write-Host "  Syncing to local build dir: $LocalBuildDir ..."

    if (-not (Test-Path $LocalBuildDir)) {
        New-Item -ItemType Directory -Path $LocalBuildDir -Force | Out-Null
    }

    # robocopy: /MIR = mirror, /XD = exclude dirs, /NFL /NDL /NJH /NJS = quiet output
    robocopy $RepoRoot $LocalBuildDir /MIR /XD .git .venv .venv-win __pycache__ node_modules build /XF *.pyc /NFL /NDL /NJH /NJS /R:1 /W:1 | Out-Null

    $RepoRoot = $LocalBuildDir
    $UsingLocalCopy = $true
    Write-Host "  Synced." -ForegroundColor Green
}

$ErrorActionPreference = 'Stop'

function Write-Step([string]$msg) {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  $msg" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
}

# ============================================================
# STEP 1: Purge old install
# ============================================================
Write-Step "STEP 1: Purging old TinySocs installation"

$svcs = @('TinySocsOpenSearch','TinySocsAgent','TinySocsNode','TinySocsMaster','TinySocsAnchors','TinySocsAssistant')
foreach ($s in $svcs) {
    $svc = Get-Service -Name $s -ErrorAction SilentlyContinue
    if ($svc) {
        Write-Host "  Stopping + deleting service: $s"
        Stop-Service -Name $s -Force -ErrorAction SilentlyContinue
        sc.exe stop $s 2>$null | Out-Null
        sc.exe delete $s 2>$null | Out-Null
    }
}

# Kill lingering Java/OpenSearch processes
Get-Process -Name java -ErrorAction SilentlyContinue | Where-Object {
    $_.Path -match 'TinySocs|OpenSearch'
} | Stop-Process -Force -ErrorAction SilentlyContinue

# Also kill any lingering TinySocs-Quickstart.exe (assistant PyInstaller bundle)
Get-Process -Name 'TinySocs-Quickstart' -ErrorAction SilentlyContinue |
    Stop-Process -Force -ErrorAction SilentlyContinue

# Brief pause to let file handles release after process kills
Start-Sleep -Seconds 2

# Purge install directory
$installDir = Join-Path $env:ProgramFiles 'TinySocs'
if (Test-Path $installDir) {
    Write-Host "  Removing $installDir"
    Remove-Item -Path $installDir -Recurse -Force -ErrorAction SilentlyContinue
}

# Purge ProgramData (retry once if file locks linger)
$dataDir = Join-Path $env:ProgramData 'TinySocs'
if (Test-Path $dataDir) {
    Write-Host "  Removing $dataDir"
    Remove-Item -Path $dataDir -Recurse -Force -ErrorAction SilentlyContinue
    if (Test-Path $dataDir) {
        Write-Host "  Retry removing $dataDir (files may have been locked)..."
        Start-Sleep -Seconds 2
        Remove-Item -Path $dataDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# Remove scheduled tasks
Unregister-ScheduledTask -TaskName 'TinySocs-DailySummary' -Confirm:$false -ErrorAction SilentlyContinue

# Clean credential manager (both slash- and colon-delimited target variants)
foreach ($t in @(
    'TinySocs/SIEM/Creds',   'TinySocs:SIEM/Creds',
    'TinySocs/OpenSearch/tinysocs', 'TinySocs:OpenSearch/tinysocs',
    'TinySocs/OpenSearch/Tls', 'TinySocs:OpenSearch/Tls'
)) { cmdkey /delete:$t 2>$null | Out-Null }

Write-Host "  Old TinySocs fully purged." -ForegroundColor Green

# ============================================================
# STEP 2: Build .NET Collector Agent
# ============================================================
Write-Step "STEP 2: Building .NET Collector Agent"

$agentProj = Join-Path $RepoRoot 'src\TinySocs.Agent'
if (Test-Path (Join-Path $agentProj 'TinySocs.Agent.csproj')) {
    dotnet publish $agentProj -c Release -r win-x64 --self-contained
    Write-Host "  Agent built." -ForegroundColor Green
} else {
    Write-Host "  Agent project not found at $agentProj - skipping." -ForegroundColor Yellow
}

# ============================================================
# STEP 2b: Ensure OpenSearch vendor payload
# ============================================================
$osVendorDir = Join-Path $RepoRoot 'vendor\opensearch-3.3.2-windows-x64\opensearch-3.3.2'
$osVendorCheck = Join-Path $osVendorDir 'bin\opensearch.bat'

if (-not (Test-Path $osVendorCheck)) {
    Write-Step "STEP 2b: Downloading OpenSearch vendor payload"

    $zipUrl = 'https://artifacts.opensearch.org/releases/bundle/opensearch/3.3.2/opensearch-3.3.2-windows-x64.zip'
    $vendorRoot = Join-Path $RepoRoot 'vendor'
    $zipDest = Join-Path $vendorRoot 'opensearch-3.3.2-windows-x64.zip'
    $extractDir = Join-Path $vendorRoot 'opensearch-3.3.2-windows-x64'

    if (-not (Test-Path $vendorRoot)) {
        New-Item -ItemType Directory -Path $vendorRoot -Force | Out-Null
    }

    if (-not (Test-Path $zipDest)) {
        Write-Host "  Downloading OpenSearch 3.3.2 (~300MB, one-time only)..."
        try {
            $ProgressPreference = 'SilentlyContinue'
            Invoke-WebRequest -Uri $zipUrl -OutFile $zipDest -UseBasicParsing
            Write-Host "  Downloaded." -ForegroundColor Green
        } catch {
            Write-Host "  Download failed: $($_.Exception.Message)" -ForegroundColor Red
            Write-Host "  Manual fix: download opensearch-3.3.2-windows-x64.zip from opensearch.org" -ForegroundColor Red
            Write-Host "  and extract into vendor\opensearch-3.3.2-windows-x64\" -ForegroundColor Red
            exit 1
        }
    }

    if (-not (Test-Path $extractDir)) {
        Write-Host "  Extracting..."
        Expand-Archive -Path $zipDest -DestinationPath $extractDir -Force
        Write-Host "  Extracted." -ForegroundColor Green
    }

    # Verify
    if (Test-Path $osVendorCheck) {
        Write-Host "  OpenSearch vendor payload ready." -ForegroundColor Green
    } else {
        Write-Host "  ERROR: opensearch.bat not found after extract!" -ForegroundColor Red
        Write-Host "  Expected at: $osVendorCheck" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "  OpenSearch vendor payload already present." -ForegroundColor Green
}

# ============================================================
# STEP 3: Build Python components (PyInstaller)
# ============================================================
Write-Step "STEP 3: Building Python components (PyInstaller)"

$savedLocation = Get-Location
Set-Location $RepoRoot
$ErrorActionPreference = 'Continue'

pip install pyinstaller --quiet 2>&1 | Out-Null

$specNames = @('TinySocsNode.spec','TinySocsMaster.spec','TinySocsAnchors.spec','packaging\tinysocs-quickstart.spec')
$distDir = Join-Path $RepoRoot 'dist'

foreach ($spec in $specNames) {
    $specPath = Join-Path $RepoRoot $spec
    if (Test-Path $specPath) {
        $name = [System.IO.Path]::GetFileNameWithoutExtension($spec)
        Write-Host "  Building $name..."
        $pyOut = pyinstaller $specPath --distpath $distDir --noconfirm 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "    $name built." -ForegroundColor Green
        } else {
            Write-Host "    $name build failed (exit=$LASTEXITCODE). Check output above." -ForegroundColor Yellow
        }
    } else {
        Write-Host "    $spec not found - skipping." -ForegroundColor Yellow
    }
}

$ErrorActionPreference = 'Stop'
Set-Location $savedLocation

# ============================================================
# STEP 3b: Download Sysmon (Phase 14 M2)
# ============================================================
$sysmonScript = Join-Path $RepoRoot 'scripts\Download-Sysmon.ps1'
$sysmonExe = Join-Path $RepoRoot 'sysmon-bin\Sysmon64.exe'
if (Test-Path $sysmonScript) {
    if (-not (Test-Path $sysmonExe)) {
        Write-Step "STEP 3b: Downloading Sysmon for installer bundle"
        try {
            & $sysmonScript -OutputDir (Join-Path $RepoRoot 'sysmon-bin')
            Write-Host "  Sysmon downloaded." -ForegroundColor Green
        } catch {
            Write-Host "  Sysmon download failed: $($_.Exception.Message)" -ForegroundColor Yellow
            Write-Host "  Installer will still work — Sysmon will be downloaded at install time." -ForegroundColor Yellow
        }
    } else {
        Write-Host "  Sysmon64.exe already present in sysmon-bin/." -ForegroundColor Green
    }
} else {
    Write-Host "  Download-Sysmon.ps1 not found — skipping Sysmon pre-bundle." -ForegroundColor Yellow
}

# ============================================================
# STEP 4: Compile Inno Setup installer
# ============================================================
Write-Step "STEP 4: Compiling Inno Setup installer"

$issFile = Join-Path $RepoRoot 'packaging\iss\Quickstart.iss'
$iscc = $null

# Find ISCC.exe
$pf86 = [Environment]::GetFolderPath('ProgramFilesX86')
$pf64 = $env:ProgramFiles

$candidates = @(
    (Join-Path $pf86 'Inno Setup 6\ISCC.exe'),
    (Join-Path $pf64 'Inno Setup 6\ISCC.exe'),
    (Join-Path $pf86 'Inno Setup 5\ISCC.exe')
)
foreach ($c in $candidates) {
    if (Test-Path $c) { $iscc = $c; break }
}

if (-not $iscc) {
    $found = Get-Command iscc.exe -ErrorAction SilentlyContinue
    if ($found) { $iscc = $found.Source }
}

if ($iscc) {
    Write-Host "  Using ISCC: $iscc"
    $setupExe = Join-Path (Split-Path $issFile) 'TinySocs-Setup.exe'
    # Remove stale exe so a failed compile can't launch an old installer
    if (Test-Path $setupExe) { Remove-Item $setupExe -Force }
    & $iscc $issFile
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  ISCC compile FAILED (exit code $LASTEXITCODE). Fix the errors above and re-run." -ForegroundColor Red
        exit 1
    }
    if (Test-Path $setupExe) {
        Write-Host "  Installer built: $setupExe" -ForegroundColor Green
    } else {
        Write-Host "  WARNING: ISCC ran but TinySocs-Setup.exe not found!" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "  ISCC.exe not found. Install Inno Setup 6 from https://jrsoftware.org/isdl.php" -ForegroundColor Red
    Write-Host "  Then re-run this script." -ForegroundColor Red
    exit 1
}

# ============================================================
# STEP 5: Run the installer
# ============================================================
Write-Step "STEP 5: Launching TinySocs-Setup.exe"

$setupExe = Join-Path $RepoRoot 'packaging\iss\TinySocs-Setup.exe'
if (Test-Path $setupExe) {
    Write-Host "  Starting installer... Follow the 6-page wizard:"
    Write-Host "    1. Role (TinyBox recommended)"
    Write-Host "    2. Security (shared secret + SIEM password)"
    Write-Host "    3. LLM Provider (OpenAI / Anthropic / Ollama / None)"
    Write-Host "    4. Notifications (webhook + email, optional)"
    Write-Host "    5. Dashboard Access (Localhost or Network+HTTPS)"
    Write-Host "    6. Enhanced Detection (Sysmon install, recommended)"
    Write-Host ""
    # Launch without -Wait and poll the process directly.
    # Start-Process -Wait hangs when Inno Setup's post-install scripts
    # spawn services/child processes that outlive the installer.
    $proc = Start-Process $setupExe -PassThru
    $proc.WaitForExit()
    Write-Host "  Installer finished (exit code $($proc.ExitCode))." -ForegroundColor Green
} else {
    Write-Host "  TinySocs-Setup.exe not found at $setupExe" -ForegroundColor Red
    exit 1
}

# ============================================================
# STEP 6: Smoke test
# ============================================================
Write-Step "STEP 6: Smoke testing"

Start-Sleep -Seconds 5

# Check services
Write-Host ""
Write-Host "  Services:"
Get-Service TinySocs* -ErrorAction SilentlyContinue | Format-Table Name, Status, StartType -AutoSize

# Check OpenSearch
Write-Host "  OpenSearch health:"
try {
    $health = curl.exe -k -s -u admin:admin https://127.0.0.1:9201/_cluster/health 2>$null
    Write-Host "    $health"
} catch {
    Write-Host "    Could not reach OpenSearch (may still be starting)" -ForegroundColor Yellow
}

# Check Dashboard
Write-Host ""
Write-Host "  Dashboard:"
try {
    $resp = Invoke-WebRequest -Uri 'http://localhost:8090/dashboard/' -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
    Write-Host "    http://localhost:8090/dashboard/ -> $($resp.StatusCode) OK" -ForegroundColor Green
} catch {
    Write-Host "    Dashboard not responding yet (assistant service may still be starting)" -ForegroundColor Yellow
}

# Check assistant.env
Write-Host ""
Write-Host "  assistant.env:"
$envFile = Join-Path $env:ProgramData 'TinySocs\Assistant\assistant.env'
if (Test-Path $envFile) {
    Get-Content $envFile | Where-Object { $_ -match '^(LLM_MODE|OPENAI_API_KEY|ANTHROPIC_API_KEY|SIEM_URL|SIEM_USER|SIEM_PASS|WEBHOOK_URL|WEBHOOK_ENABLED|BOT_PORT)=' } | ForEach-Object {
        # Mask secrets but show first/last 4 chars
        if ($_ -match '^(SIEM_PASS|OPENAI_API_KEY|ANTHROPIC_API_KEY)=(.+)$') {
            $key = $Matches[1]; $val = $Matches[2]
            if ($val.Length -gt 8) {
                $masked = $val.Substring(0,4) + ('*' * ($val.Length - 8)) + $val.Substring($val.Length - 4)
            } else { $masked = '****' }
            Write-Host "    ${key}=$masked"
        } else {
            Write-Host "    $_"
        }
    }

    # Test SIEM auth
    Write-Host ""
    Write-Host "  SIEM auth test:"
    $siemPass = (Get-Content $envFile | Where-Object { $_ -match '^SIEM_PASS=' }) -replace '^SIEM_PASS=',''
    $siemUser = (Get-Content $envFile | Where-Object { $_ -match '^SIEM_USER=' }) -replace '^SIEM_USER=',''
    if (-not $siemUser) { $siemUser = 'admin' }
    if ($siemPass) {
        try {
            $authHeader = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${siemUser}:${siemPass}"))
            $result = curl.exe -k -s -o NUL -w '%{http_code}' -H "Authorization: Basic $authHeader" https://127.0.0.1:9201/_cluster/health 2>$null
            if ($result -eq '200') {
                Write-Host "    SIEM auth OK (HTTP 200)" -ForegroundColor Green
            } else {
                Write-Host "    SIEM auth FAILED (HTTP $result) -- diagnosing..." -ForegroundColor Yellow
                # Probe for which password actually works (report only, no auto-fix)
                $foundPass = $null
                $foundSource = $null

                # Check OPENSEARCH_INITIAL_ADMIN_PASSWORD from service registry
                try {
                    $svcEnv = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\TinySocsOpenSearch' -Name Environment -ErrorAction SilentlyContinue).Environment
                    $initPass = ($svcEnv | Where-Object { $_ -match '^OPENSEARCH_INITIAL_ADMIN_PASSWORD=' }) -replace '^OPENSEARCH_INITIAL_ADMIN_PASSWORD=',''
                    if ($initPass -and $initPass -ne $siemPass) {
                        $tryAuth = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("admin:${initPass}"))
                        $tryResult = curl.exe -k -s -o NUL -w '%{http_code}' -H "Authorization: Basic $tryAuth" https://127.0.0.1:9201/_cluster/health 2>$null
                        if ($tryResult -eq '200') { $foundPass = $initPass; $foundSource = 'OPENSEARCH_INITIAL_ADMIN_PASSWORD (service registry)' }
                    }
                } catch { }

                if ($foundPass) {
                    Write-Host "    Working password found via: $foundSource" -ForegroundColor Yellow
                    Write-Host "    To fix, run:" -ForegroundColor Yellow
                    Write-Host "      `$f = Get-Content '$envFile' -Raw" -ForegroundColor White
                    Write-Host "      `$f = `$f -replace '(?m)^SIEM_PASS=.*$', 'SIEM_PASS=<password>'" -ForegroundColor White
                    Write-Host "      Set-Content -Path '$envFile' -Value `$f -Force" -ForegroundColor White
                    Write-Host "      Restart-Service TinySocsAssistant" -ForegroundColor White
                } else {
                    Write-Host "    Could not find a working password. Check postinstall logs:" -ForegroundColor Red
                    Write-Host "      Get-Content '$env:ProgramData\TinySocs\logs\postinstall-powershell*.log' -Tail 30" -ForegroundColor White
                }
            }
        } catch {
            Write-Host "    SIEM auth test error: $($_.Exception.Message)" -ForegroundColor Red
        }
    } else {
        Write-Host "    SIEM_PASS is empty in assistant.env!" -ForegroundColor Red
    }
} else {
    Write-Host "    assistant.env not found" -ForegroundColor Yellow
}

# Phase 14: Check Sysmon
Write-Host ""
Write-Host "  Sysmon:"
$sysmonSvc = Get-Service -Name 'Sysmon64' -ErrorAction SilentlyContinue
if (-not $sysmonSvc) { $sysmonSvc = Get-Service -Name 'Sysmon' -ErrorAction SilentlyContinue }
if ($sysmonSvc -and $sysmonSvc.Status -eq 'Running') {
    Write-Host "    Sysmon64 service: Running" -ForegroundColor Green
} elseif ($sysmonSvc) {
    Write-Host "    Sysmon64 service: $($sysmonSvc.Status)" -ForegroundColor Yellow
} else {
    Write-Host "    Sysmon not installed (skipped in wizard or not checked)" -ForegroundColor Yellow
}

# Phase 14: Check Dashboard TLS config
Write-Host ""
Write-Host "  Dashboard TLS:"
$dashBind = (Get-Content $envFile -ErrorAction SilentlyContinue | Where-Object { $_ -match '^DASHBOARD_BIND=' }) -replace '^DASHBOARD_BIND=',''
$dashCert = (Get-Content $envFile -ErrorAction SilentlyContinue | Where-Object { $_ -match '^DASHBOARD_TLS_CERT=' }) -replace '^DASHBOARD_TLS_CERT=',''
if ($dashBind -and $dashBind -ne '127.0.0.1') {
    if ($dashCert -and (Test-Path $dashCert)) {
        Write-Host "    Network mode (DASHBOARD_BIND=$dashBind), cert present" -ForegroundColor Green
    } elseif ($dashCert) {
        Write-Host "    Network mode but cert NOT found at: $dashCert" -ForegroundColor Red
    } else {
        Write-Host "    Network mode but DASHBOARD_TLS_CERT not set!" -ForegroundColor Red
    }
} else {
    Write-Host "    Localhost mode (no TLS needed)" -ForegroundColor Green
}

# Phase 14: Check compliance endpoint
Write-Host ""
Write-Host "  Compliance API:"
try {
    $compResp = Invoke-WebRequest -Uri 'http://localhost:8090/dashboard/api/compliance/frameworks' -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
    if ($compResp.StatusCode -eq 200) {
        Write-Host "    /api/compliance/frameworks -> 200 OK" -ForegroundColor Green
    } else {
        Write-Host "    /api/compliance/frameworks -> $($compResp.StatusCode)" -ForegroundColor Yellow
    }
} catch {
    Write-Host "    Compliance API not reachable (dashboard may require auth)" -ForegroundColor Yellow
}

# Phase 14: Run Test-TinySocsHealth
Write-Host ""
Write-Host "  Running Test-TinySocsHealth..."
try {
    Import-Module (Join-Path $env:ProgramFiles 'TinySocs\modules\TinySocs.Installer.psm1') -Force -ErrorAction Stop
    Test-TinySocsHealth
} catch {
    Write-Host "    Test-TinySocsHealth failed: $($_.Exception.Message)" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  Done! Open http://localhost:8090/dashboard/" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
