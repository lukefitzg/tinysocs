param(
  [string] $WinlogbeatHome = "C:\Program Files\Winlogbeat",
  [string] $RepoRoot       = "C:\tinysocs\tinysocs",
  [switch] $InstallTemplate,   # install/refresh index template (future indices)
  [switch] $PatchExisting      # add .keyword subfields on existing winlogbeat-* indices
)

# ─────────────────────────────────────────────────────────────────────────────
# Require admin (we need Program Files + service control)
# ─────────────────────────────────────────────────────────────────────────────
$curr  = [Security.Principal.WindowsIdentity]::GetCurrent()
$princ = New-Object Security.Principal.WindowsPrincipal($curr)
if (-not $princ.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
  throw "Please run this in an elevated Windows PowerShell (Run as Administrator)."
}

# ─────────────────────────────────────────────────────────────────────────────
# Load .env from repo (Process scope only)
# ─────────────────────────────────────────────────────────────────────────────
$dotenv = Join-Path $RepoRoot ".env"
if (Test-Path $dotenv) {
  Get-Content $dotenv | Where-Object { $_ -match '^\s*[^#]' } | ForEach-Object {
    $k,$v = $_ -split '=',2
    if ($k -and $v -ne $null) {
      [Environment]::SetEnvironmentVariable($k.Trim(), $v.Trim(), "Process")
    }
  }
}

# ─────────────────────────────────────────────────────────────────────────────
# Pull SIEM vars (defaults). Tip: set SIEM_URL to https://127.0.0.1:9201 in .env
# ─────────────────────────────────────────────────────────────────────────────
$SIEM_URL  = if ($env:SIEM_URL)  { $env:SIEM_URL }  else { "https://localhost:9201" }
$SIEM_USER = if ($env:SIEM_USER) { $env:SIEM_USER } else { "admin" }
$SIEM_PASS = if ($env:SIEM_PASS) { $env:SIEM_PASS } else { "changeme" }

# Translate SIEM_SSL_VERIFY -> Winlogbeat 'full'/'none'
$sslRaw        = if ($env:SIEM_SSL_VERIFY) { "$($env:SIEM_SSL_VERIFY)".ToLower() } else { "false" }
$WB_SSL_VERIFY = if (@("true","1","full") -contains $sslRaw) { "full" } else { "none" }

# curl.exe -k toggling for OpenSearch calls
$UseInsecureCurl = ($SIEM_URL -like "https*") -and ($WB_SSL_VERIFY -eq "none")

# ─────────────────────────────────────────────────────────────────────────────
# Helpers to manage SIEM-side artifacts (OpenSearch/Elasticsearch-compatible)
# ─────────────────────────────────────────────────────────────────────────────
function Install-WinlogbeatTemplate {
  param([string]$SiemUrl, [string]$User, [string]$Pass, [string]$RepoRoot, [bool]$InsecureCurl)

  $template = Join-Path $RepoRoot "integrations\winlogbeat\winlogbeat_template_priority500.json"
  if (!(Test-Path $template)) { throw "Template not found: $template" }

  $args = @()
  if ($InsecureCurl) { $args += "-k" }
  $args += @("-u","$User:$Pass","-H","Content-Type: application/json","-X","PUT",
             "$($SiemUrl.TrimEnd('/'))/_index_template/winlogbeat_keyword_template",
             "--data-binary","@$template")

  Write-Host "Installing/refreshing index template 'winlogbeat_keyword_template'..."
  $null = & curl.exe @args
}

function Patch-WinlogbeatExisting {
  param([string]$SiemUrl, [string]$User, [string]$Pass, [string]$RepoRoot, [bool]$InsecureCurl)

  $mapping = Join-Path $RepoRoot "integrations\winlogbeat\winlogbeat_keyword_mapping.json"
  if (!(Test-Path $mapping)) { throw "Mapping patch not found: $mapping" }

  # list indices
  $listArgs = @()
  if ($InsecureCurl) { $listArgs += "-k" }
  $listArgs += @("-s","-u","$User:$Pass","$($SiemUrl.TrimEnd('/'))/_cat/indices/winlogbeat-*?h=index&s=index")
  $resp = & curl.exe @listArgs
  if ($LASTEXITCODE -ne 0) { throw "Failed to list winlogbeat-* indices at $SiemUrl" }

  $indices = ($resp -split "`n") | Where-Object { $_ -and ($_ -notmatch '^\s*$') }
  if (-not $indices -or $indices.Count -eq 0) {
    Write-Host "No winlogbeat-* indices found; nothing to patch." -ForegroundColor DarkYellow
    return
  }

  foreach ($idx in $indices) {
    Write-Host "Patching $idx..."
    $patchArgs = @()
    if ($InsecureCurl) { $patchArgs += "-k" }
    $patchArgs += @("-u","$User:$Pass","-H","Content-Type: application/json","-X","PUT",
                    "$($SiemUrl.TrimEnd('/'))/$idx/_mapping",
                    "--data-binary","@$mapping")
    & curl.exe @patchArgs | Write-Host
  }

  # quick sanity check
  $fcArgs = @()
  if ($InsecureCurl) { $fcArgs += "-k" }
  $fcArgs += @("-u","$User:$Pass",
    "$($SiemUrl.TrimEnd('/'))/winlogbeat-*/_field_caps?fields=host.name.keyword,user.name.keyword,process.name.keyword,winlog.computer_name.keyword")
  Write-Host "Verifying field caps for *.keyword fields..."
  & curl.exe @fcArgs | Write-Host
}

# ─────────────────────────────────────────────────────────────────────────────
# Render template using literal string replacement (NO regex)
# ─────────────────────────────────────────────────────────────────────────────
$tmpl = Join-Path $RepoRoot "integrations\winlogbeat\winlogbeat.yml.tmpl"
if (!(Test-Path $tmpl)) { throw "Template not found: $tmpl" }

$rendered = Get-Content $tmpl -Raw
$rendered = $rendered.Replace('${SIEM_URL:https://127.0.0.1:9201}', $SIEM_URL)
$rendered = $rendered.Replace('${SIEM_USER:admin}',                 $SIEM_USER)
$rendered = $rendered.Replace('${SIEM_PASS:changeme}',              $SIEM_PASS)
$rendered = $rendered.Replace('${WB_SSL_VERIFY:none}',              $WB_SSL_VERIFY)

# ─────────────────────────────────────────────────────────────────────────────
# Write runtime config under Program Files
# ─────────────────────────────────────────────────────────────────────────────
$dest = Join-Path $WinlogbeatHome "winlogbeat.yml"
if (Test-Path $dest) { Copy-Item $dest "$dest.bak" -Force }
$rendered | Set-Content $dest -Encoding UTF8

# ─────────────────────────────────────────────────────────────────────────────
# Ensure Winlogbeat service exists (install if missing)
# ─────────────────────────────────────────────────────────────────────────────
$svc = Get-Service -Name Winlogbeat -ErrorAction SilentlyContinue
if (-not $svc) {
  $installer = Join-Path $WinlogbeatHome "install-service-winlogbeat.ps1"
  if (Test-Path $installer) {
    & $installer
  } else {
    throw "Winlogbeat service not found and installer missing at '$installer'. Check WinlogbeatHome."
  }
  $svc = Get-Service -Name Winlogbeat -ErrorAction SilentlyContinue
  if (-not $svc) { throw "Failed to install Winlogbeat service." }
}

# ─────────────────────────────────────────────────────────────────────────────
# Graceful stop with timeout; if stuck, kill PID (avoids infinite waits)
# ─────────────────────────────────────────────────────────────────────────────
$svcName = 'Winlogbeat'
try { sc.exe stop $svcName | Out-Null } catch {}

$sw = [Diagnostics.Stopwatch]::StartNew()
$state = ''
do {
  Start-Sleep -Milliseconds 300
  try {
    $state = (sc.exe query $svcName | Select-String 'STATE').ToString()
    if ($state -match 'STOPPED') { break }
  } catch {}
} while ($sw.Elapsed.TotalSeconds -lt 3)

if ($state -notmatch 'STOPPED') {
  $wbPidLine = (sc.exe queryex $svcName | Select-String 'PID').ToString()
  $wbPid = $null
  if ($wbPidLine) { $wbPid = $wbPidLine.Split(':')[-1].Trim() }
  if ($wbPid -and $wbPid -ne '0') {
    try {
      taskkill /PID $wbPid /F /T | Out-Null
      try { Wait-Process -Id [int]$wbPid -Timeout 10 } catch {}
    } catch {}
  }
}

# Clear stale lock (correct filename: winlogbeat.lock without leading dot)
$lock = "C:\ProgramData\winlogbeat\winlogbeat.lock"
if (Test-Path $lock) {
  try { Remove-Item $lock -Force } catch {}
}

# ─────────────────────────────────────────────────────────────────────────────
# Sanity tests targeting the exact config path — bail out ONLY on real config errors
# ─────────────────────────────────────────────────────────────────────────────
$cfgOk = (& "$WinlogbeatHome\winlogbeat.exe" test config -c "$dest") 2>&1
if ($LASTEXITCODE -ne 0) {
  Write-Host $cfgOk
  throw "Config test failed. Open '$dest' and check the line reported above."
}

# Beats 8.x 'test output' pokes /_license which OpenSearch rejects with 400.
# Treat that specific error as BENIGN; only fail for other errors.
$outText = (& "$WinlogbeatHome\winlogbeat.exe" test output -c "$dest") 2>&1
$exit = $LASTEXITCODE
Write-Host $outText

$licenseProbeError =
  ($outText -match 'could not connect to a compatible version of Elasticsearch') -and
  ($outText -match 'Invalid index name $begin:math:display$_license$end:math:display$') -and
  ($outText -match '400 Bad Request')

if (($exit -ne 0) -and (-not $licenseProbeError)) {
  throw "Output test failed (can’t reach $SIEM_URL)."
}

# ─────────────────────────────────────────────────────────────────────────────
# Start service and show status (with a short wait)
# ─────────────────────────────────────────────────────────────────────────────
try { Start-Service Winlogbeat } catch {}
Start-Sleep -Seconds 1

$waitSw = [Diagnostics.Stopwatch]::StartNew()
do {
  try {
    $svc = Get-Service -Name Winlogbeat -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq 'Running') { break }
  } catch {}
  Start-Sleep -Milliseconds 500
} while ($waitSw.Elapsed.TotalSeconds -lt 8)

(Get-Service Winlogbeat).Status | ForEach-Object { Write-Host "Winlogbeat service status: $_" }
Write-Host "Deployed to $dest (ssl.verification_mode=$WB_SSL_VERIFY) -> $SIEM_URL"

# ─────────────────────────────────────────────────────────────────────────────
# OPTIONAL: SIEM-side setup
# ─────────────────────────────────────────────────────────────────────────────
if ($InstallTemplate) {
  Install-WinlogbeatTemplate -SiemUrl $SIEM_URL -User $SIEM_USER -Pass $SIEM_PASS -RepoRoot $RepoRoot -InsecureCurl:$UseInsecureCurl
}
if ($PatchExisting) {
  Patch-WinlogbeatExisting  -SiemUrl $SIEM_URL -User $SIEM_USER -Pass $SIEM_PASS -RepoRoot $RepoRoot -InsecureCurl:$UseInsecureCurl
}