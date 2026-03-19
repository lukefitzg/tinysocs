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

# Uninstall Sysmon BEFORE deleting TinySocs directories.
# If we delete the binary first, the service/driver are left in a stale
# state that prevents clean reinstall (exit code 13 / driver not found).
# Detect processor architecture to try the correct Sysmon binary first
$_isArm64 = ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') -or ($env:PROCESSOR_ARCHITEW6432 -eq 'ARM64')
if (-not $_isArm64) {
    try {
        $regArch = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' -Name PROCESSOR_ARCHITECTURE -ErrorAction Stop).PROCESSOR_ARCHITECTURE
        $_isArm64 = ($regArch -eq 'ARM64')
    } catch { }
}
$_sysmonOrder = if ($_isArm64) { @('Sysmon64a.exe','Sysmon64.exe') } else { @('Sysmon64.exe','Sysmon64a.exe') }

$sysmonExe = $null
foreach ($name in $_sysmonOrder) {
    $p = Join-Path $env:ProgramFiles "TinySocs\bin\$name"
    if (Test-Path $p) { $sysmonExe = $p; break }
}
if (-not $sysmonExe) {
    # Check if Sysmon is in Windows root (older installs)
    foreach ($name in $_sysmonOrder) {
        $p = Join-Path $env:SystemRoot $name
        if (Test-Path $p) { $sysmonExe = $p; break }
    }
}
# Try uninstalling Sysmon via both arch binaries (correct arch first)
foreach ($exeName in $_sysmonOrder) {
    foreach ($searchDir in @((Join-Path $env:ProgramFiles 'TinySocs\bin'), $env:SystemRoot)) {
        $p = Join-Path $searchDir $exeName
        if (Test-Path $p) {
            Write-Host "  Uninstalling Sysmon via $p -u force..."
            try {
                & $p -u force 2>&1 | ForEach-Object { Write-Host "    $_" }
            } catch {
                Write-Host "    Sysmon uninstall warning: $($_.Exception.Message)" -ForegroundColor Yellow
            }
            Start-Sleep -Seconds 2
            break
        }
    }
}

# Try sc.exe cleanup for any remaining service registrations
# NOTE: Do NOT use Stop-Service on SysmonDrv — it's a kernel driver that
# blocks indefinitely. Use sc.exe with a timeout, then fall through to
# the registry nuke below.
foreach ($svcName in @('Sysmon64','Sysmon64a','SysmonDrv')) {
    $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
    if ($svc) {
        Write-Host "  Removing stale Sysmon service: $svcName"
        if ($svcName -ne 'SysmonDrv') {
            # Only stop user-mode services; driver requires -u or registry removal
            Stop-Service -Name $svcName -Force -ErrorAction SilentlyContinue
        }
        sc.exe stop $svcName 2>$null | Out-Null
        sc.exe delete $svcName 2>$null | Out-Null
    }
}

# Nuclear fallback: if services STILL exist (Sysmon driver protection blocks sc.exe),
# remove them directly from the registry. This is the only reliable method when the
# Sysmon kernel driver is loaded but the binary path is broken.
$needsReboot = $false
foreach ($svcName in @('Sysmon64','Sysmon64a','SysmonDrv')) {
    $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
    if ($svc) {
        Write-Host "  Service $svcName still present after sc.exe -- removing via registry..." -ForegroundColor Yellow
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$svcName"
        if (Test-Path $regPath) {
            Remove-Item $regPath -Recurse -Force -ErrorAction SilentlyContinue
            Write-Host "    Removed $regPath" -ForegroundColor Yellow
            $needsReboot = $true
        }
    }
}
if ($needsReboot) {
    Write-Host "  Registry cleanup done. A reboot may be needed for full effect." -ForegroundColor Yellow
    Write-Host "  Continuing with build -- Sysmon will be reinstalled fresh." -ForegroundColor Yellow
    Start-Sleep -Seconds 2
}

# Remove stale driver and executable files
$sysmonDrvPath = Join-Path $env:SystemRoot "System32\drivers\SysmonDrv.sys"
if (Test-Path $sysmonDrvPath) {
    Write-Host "  Removing stale driver file: $sysmonDrvPath"
    Remove-Item $sysmonDrvPath -Force -ErrorAction SilentlyContinue
}
foreach ($exeFile in @('Sysmon64.exe','Sysmon64a.exe','Sysmon.exe')) {
    $exePath = Join-Path $env:SystemRoot $exeFile
    if (Test-Path $exePath) {
        Write-Host "  Removing stale Sysmon binary: $exePath"
        Remove-Item $exePath -Force -ErrorAction SilentlyContinue
    }
}

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
        $downloaded = $false
        # Prefer curl.exe (built into Windows 10+) — handles TLS better than Invoke-WebRequest
        $curlExe = Get-Command curl.exe -ErrorAction SilentlyContinue
        if ($curlExe) {
            try {
                & curl.exe -L --tlsv1.2 -o $zipDest $zipUrl
                if ($LASTEXITCODE -eq 0 -and (Test-Path $zipDest)) { $downloaded = $true }
                else { Write-Host "  curl.exe failed (exit $LASTEXITCODE), trying fallback..." -ForegroundColor Yellow }
            } catch { Write-Host "  curl.exe error: $($_.Exception.Message)" -ForegroundColor Yellow }
        }
        if (-not $downloaded) {
            try {
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                $ProgressPreference = 'SilentlyContinue'
                Invoke-WebRequest -Uri $zipUrl -OutFile $zipDest -UseBasicParsing
                $downloaded = $true
            } catch {
                Write-Host "  Download failed: $($_.Exception.Message)" -ForegroundColor Red
                Write-Host "  Manual fix: download opensearch-3.3.2-windows-x64.zip from opensearch.org" -ForegroundColor Red
                Write-Host "  and extract into vendor\opensearch-3.3.2-windows-x64\" -ForegroundColor Red
                exit 1
            }
        }
        if ($downloaded) { Write-Host "  Downloaded." -ForegroundColor Green }
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
# STEP 3b: Download Sysmon (Phase 14 M2) — includes ARM64 binary (Sysmon64a.exe)
# ============================================================
$sysmonScript = Join-Path $RepoRoot 'scripts\Download-Sysmon.ps1'
$sysmonExe  = Join-Path $RepoRoot 'sysmon-bin\Sysmon64.exe'
$sysmonExeA = Join-Path $RepoRoot 'sysmon-bin\Sysmon64a.exe'
if (Test-Path $sysmonScript) {
    if (-not (Test-Path $sysmonExe) -or -not (Test-Path $sysmonExeA)) {
        Write-Step "STEP 3b: Downloading Sysmon for installer bundle (x64 + ARM64)"
        try {
            & $sysmonScript -OutputDir (Join-Path $RepoRoot 'sysmon-bin')
            Write-Host "  Sysmon downloaded." -ForegroundColor Green
        } catch {
            Write-Host "  Sysmon download failed: $($_.Exception.Message)" -ForegroundColor Yellow
            Write-Host "  Installer will still work - Sysmon will be downloaded at install time." -ForegroundColor Yellow
        }
    } else {
        Write-Host "  Sysmon64.exe + Sysmon64a.exe already present in sysmon-bin/." -ForegroundColor Green
    }
} else {
    Write-Host "  Download-Sysmon.ps1 not found - skipping Sysmon pre-bundle." -ForegroundColor Yellow
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
    # Remove stale exe so a failed compile can't launch an old installer.
    # The exe is often locked by Explorer preview, AV scanners, or a still-running
    # installer process. Try to kill the process, then rename as fallback.
    if (Test-Path $setupExe) {
        # Kill any running installer first
        Get-Process -ErrorAction SilentlyContinue | Where-Object {
            try { $_.MainModule.FileName -eq $setupExe } catch { $false }
        } | ForEach-Object {
            Write-Host "  Killing running TinySocs-Setup.exe (PID $($_.Id))..." -ForegroundColor Yellow
            Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 1
        }
        try {
            Remove-Item $setupExe -Force -ErrorAction Stop
        } catch {
            # File still locked — rename it out of the way
            $bakName = "TinySocs-Setup.exe.old-$(Get-Date -Format 'HHmmss')"
            $bakPath = Join-Path (Split-Path $setupExe) $bakName
            Write-Host "  Cannot delete locked Setup.exe — renaming to $bakName" -ForegroundColor Yellow
            try {
                Move-Item $setupExe $bakPath -Force -ErrorAction Stop
            } catch {
                Write-Host "  ERROR: TinySocs-Setup.exe is locked and cannot be renamed." -ForegroundColor Red
                Write-Host "  Close any Explorer windows showing the folder, or reboot and retry." -ForegroundColor Red
                exit 1
            }
        }
    }
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

# Check Dashboard (try HTTPS first, fall back to HTTP)
Write-Host ""
Write-Host "  Dashboard:"
$dashUrl = $null
try {
    # Skip cert validation for self-signed CA
    if (-not ([System.Management.Automation.PSTypeName]'TrustAll').Type) {
        Add-Type @"
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
public class TrustAll {
    public static void Enable() {
        ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
    }
}
"@
    }
    [TrustAll]::Enable()
    $resp = Invoke-WebRequest -Uri 'https://localhost:8090/dashboard/' -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
    Write-Host "    https://localhost:8090/dashboard/ -> $($resp.StatusCode) OK" -ForegroundColor Green
    $dashUrl = 'https://localhost:8090/dashboard/'
} catch {
    try {
        $resp = Invoke-WebRequest -Uri 'http://localhost:8090/dashboard/' -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
        Write-Host "    http://localhost:8090/dashboard/ -> $($resp.StatusCode) OK" -ForegroundColor Green
        $dashUrl = 'http://localhost:8090/dashboard/'
    } catch {
        Write-Host "    Dashboard not responding yet (assistant service may still be starting)" -ForegroundColor Yellow
        $dashUrl = 'https://localhost:8090/dashboard/'
    }
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

# Phase 14: Check Sysmon — prefer the Running service (ARM64 may have both
# Sysmon64 [Stopped/stale] and Sysmon64a [Running]).
Write-Host ""
Write-Host "  Sysmon:"
$sysmonSvc = $null
$sysmonAll = @()
foreach ($name in @('Sysmon64','Sysmon64a','Sysmon')) {
    $s = Get-Service -Name $name -ErrorAction SilentlyContinue
    if ($s) { $sysmonAll += $s }
}
# Pick the Running service first; fall back to any found service
$sysmonSvc = $sysmonAll | Where-Object { $_.Status -eq 'Running' } | Select-Object -First 1
if (-not $sysmonSvc) { $sysmonSvc = $sysmonAll | Select-Object -First 1 }
if ($sysmonSvc -and $sysmonSvc.Status -eq 'Running') {
    Write-Host "    $($sysmonSvc.Name) service: Running" -ForegroundColor Green
} elseif ($sysmonSvc) {
    Write-Host "    $($sysmonSvc.Name) service: $($sysmonSvc.Status)" -ForegroundColor Yellow
    # Show driver status for diagnostics
    $drv = Get-Service -Name 'SysmonDrv' -ErrorAction SilentlyContinue
    if ($drv) {
        Write-Host "    SysmonDrv driver: $($drv.Status)" -ForegroundColor Yellow
    } else {
        Write-Host "    SysmonDrv driver: not registered (driver failed to load)" -ForegroundColor Red
    }
    # Check installer log for Sysmon errors
    $logFile = Join-Path $env:ProgramData 'TinySocs\logs\installer.log'
    if (Test-Path $logFile) {
        $sysmonLines = Get-Content $logFile -Tail 50 | Where-Object { $_ -match 'Sysmon' } | Select-Object -Last 5
        if ($sysmonLines) {
            Write-Host "    Recent Sysmon log entries:" -ForegroundColor Yellow
            foreach ($line in $sysmonLines) {
                Write-Host "      $line" -ForegroundColor Gray
            }
        }
    }
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
    $compUrl = if ($dashUrl -and $dashUrl.StartsWith('https')) { 'https://localhost:8090/dashboard/api/compliance/frameworks' } else { 'http://localhost:8090/dashboard/api/compliance/frameworks' }
    $compResp = Invoke-WebRequest -Uri $compUrl -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
    if ($compResp.StatusCode -eq 200) {
        Write-Host "    /api/compliance/frameworks -> 200 OK" -ForegroundColor Green
    } else {
        Write-Host "    /api/compliance/frameworks -> $($compResp.StatusCode)" -ForegroundColor Yellow
    }
} catch {
    Write-Host "    Compliance API not reachable (dashboard may require auth)" -ForegroundColor Yellow
}

# Phase 15: Check version manifest
Write-Host ""
Write-Host "  Version manifest:"
$versionManifest = Join-Path $env:ProgramData 'TinySocs\version-manifest.json'
if (Test-Path $versionManifest) {
    try {
        $manifest = Get-Content $versionManifest -Raw | ConvertFrom-Json
        Write-Host "    current_version: $($manifest.current_version)" -ForegroundColor Green
        Write-Host "    minimum_compatible: $($manifest.minimum_compatible)" -ForegroundColor Green
    } catch {
        Write-Host "    version-manifest.json exists but failed to parse" -ForegroundColor Yellow
    }
} else {
    Write-Host "    version-manifest.json not found (expected at $versionManifest)" -ForegroundColor Yellow
}

# Phase 15: Check FIM rules deployed
Write-Host ""
Write-Host "  FIM rules (Phase 15):"
$rulesFile = Join-Path $env:ProgramData 'TinySocs\Collector\rules\rules.yml'
if (Test-Path $rulesFile) {
    $fimRules = Select-String -Path $rulesFile -Pattern 'TS-11[0-5]' -SimpleMatch | Select-Object -ExpandProperty Line
    $fimCount = ($fimRules | Measure-Object).Count
    if ($fimCount -ge 6) {
        Write-Host "    $fimCount FIM rules deployed (TS-110 through TS-115)" -ForegroundColor Green
    } elseif ($fimCount -gt 0) {
        Write-Host "    Only $fimCount/6 FIM rules found in rules.yml" -ForegroundColor Yellow
    } else {
        Write-Host "    No FIM rules (TS-110-115) found in rules.yml" -ForegroundColor Yellow
    }
    # Check MITRE annotations on rules
    $mitreCount = (Select-String -Path $rulesFile -Pattern 'technique_id:' | Measure-Object).Count
    Write-Host "    $mitreCount rules with MITRE annotations" -ForegroundColor $(if ($mitreCount -ge 20) { 'Green' } else { 'Yellow' })
} else {
    Write-Host "    rules.yml not found" -ForegroundColor Yellow
}

# Phase 15: Check MITRE coverage API
Write-Host ""
Write-Host "  MITRE ATT&CK API:"
try {
    $mitreUrl = if ($dashUrl -and $dashUrl.StartsWith('https')) { 'https://localhost:8090/dashboard/api/mitre/coverage' } else { 'http://localhost:8090/dashboard/api/mitre/coverage' }
    $mitreResp = Invoke-WebRequest -Uri $mitreUrl -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
    if ($mitreResp.StatusCode -eq 200) {
        $mitreData = $mitreResp.Content | ConvertFrom-Json
        if ($mitreData.ok) {
            Write-Host "    /api/mitre/coverage -> 200 OK" -ForegroundColor Green
            if ($mitreData.total_techniques) {
                Write-Host "    Techniques: $($mitreData.total_techniques), Tactics: $($mitreData.total_tactics)" -ForegroundColor Green
            }
        } else {
            Write-Host "    /api/mitre/coverage -> 200 but ok=false" -ForegroundColor Yellow
        }
    } else {
        Write-Host "    /api/mitre/coverage -> $($mitreResp.StatusCode)" -ForegroundColor Yellow
    }
} catch {
    Write-Host "    MITRE API not reachable (dashboard may require auth)" -ForegroundColor Yellow
}

# Phase 15: Check version status API
Write-Host ""
Write-Host "  Version status API:"
try {
    $verUrl = if ($dashUrl -and $dashUrl.StartsWith('https')) { 'https://localhost:8090/dashboard/api/version/status' } else { 'http://localhost:8090/dashboard/api/version/status' }
    $verResp = Invoke-WebRequest -Uri $verUrl -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
    if ($verResp.StatusCode -eq 200) {
        Write-Host "    /api/version/status -> 200 OK" -ForegroundColor Green
    } else {
        Write-Host "    /api/version/status -> $($verResp.StatusCode)" -ForegroundColor Yellow
    }
} catch {
    Write-Host "    Version API not reachable (dashboard may require auth)" -ForegroundColor Yellow
}

# Phase 15: Check threat intel provider config
Write-Host ""
Write-Host "  Threat intel providers:"
if (Test-Path $envFile) {
    $tiKeys = @('ABUSEIPDB_API_KEY', 'OTX_API_KEY', 'GREYNOISE_API_KEY')
    $configured = 0
    foreach ($k in $tiKeys) {
        $val = (Get-Content $envFile | Where-Object { $_ -match "^${k}=" }) -replace "^${k}=",''
        if ($val -and $val -ne 'your_key_here' -and $val.Length -gt 5) {
            Write-Host "    $k : configured" -ForegroundColor Green
            $configured++
        } else {
            Write-Host "    $k : not set (optional)" -ForegroundColor Gray
        }
    }
    if ($configured -eq 0) {
        Write-Host "    No threat intel providers configured (enrichment disabled -- add keys to assistant.env)" -ForegroundColor Yellow
    }
} else {
    Write-Host "    assistant.env not found" -ForegroundColor Yellow
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
if (-not $dashUrl) { $dashUrl = 'https://localhost:8090/dashboard/' }
Write-Host "  Done! Open $dashUrl" -ForegroundColor Green

# Show LAN URL + CA cert path if network mode is configured
$envFile = Join-Path $env:ProgramData 'TinySocs\Assistant\assistant.env'
if (Test-Path $envFile) {
    $bind = ((Get-Content $envFile | Where-Object { $_ -match '^DASHBOARD_BIND=' }) -replace '^DASHBOARD_BIND=','').Trim()
    if ($bind -eq '0.0.0.0') {
        try {
            $lanIp = ([System.Net.Dns]::GetHostAddresses([System.Net.Dns]::GetHostName()) |
                Where-Object { $_.AddressFamily -eq 'InterNetwork' -and $_.IPAddressToString -ne '127.0.0.1' } |
                Select-Object -First 1).IPAddressToString
            if ($lanIp) {
                Write-Host "  LAN:  https://${lanIp}:8090/dashboard/" -ForegroundColor Cyan
            }
        } catch { }
        $caCrt = Join-Path $env:ProgramData 'TinySocs\certs\TinySocs-CA.crt'
        if (Test-Path $caCrt) {
            Write-Host "  CA cert: $caCrt" -ForegroundColor Cyan
        }
    }
}

Write-Host "========================================" -ForegroundColor Green
