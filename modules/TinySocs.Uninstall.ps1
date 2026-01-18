# modules\TinySocs.Uninstall.ps1
[CmdletBinding()]
param(
  [switch]$FromInnoUninstall,
  [switch]$KeepData
)

$ErrorActionPreference = "SilentlyContinue"

function _Log([string]$m) {
  $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
  $line = "[TinySocs.Uninstall] $ts $m"
  try {
    $p = Join-Path $env:TEMP "tinysocs-uninstall.log"
    Add-Content -LiteralPath $p -Value $line -Encoding UTF8
  } catch { }
}

# HARD GUARD: refuse to run unless explicitly invoked by Inno Setup uninstaller
if (-not $FromInnoUninstall.IsPresent) {
  _Log "Refusing to run: -FromInnoUninstall was not provided. Exiting harmlessly."
  exit 0
}

function _GetParentCommandLine {
  try {
    $me = Get-CimInstance Win32_Process -Filter ("ProcessId=" + $PID)
    if (-not $me) { return $null }
    $ppid = $me.ParentProcessId
    if (-not $ppid) { return $null }
    $p = Get-CimInstance Win32_Process -Filter ("ProcessId=" + $ppid)
    return [string]$p.CommandLine
  } catch {
    return $null
  }
}

function _IsUpgradeUninstall {
  $cmd = _GetParentCommandLine
  if ([string]::IsNullOrWhiteSpace($cmd)) { return $false }
  return ($cmd -match '(?i)/UPGRADE|/UPDATE')
}

function _StopAndDeleteService([string]$name) {
  _Log "Stopping service $name"
  try { Stop-Service -Name $name -Force } catch { }
  try { sc.exe stop $name | Out-Null } catch { }

  _Log "Deleting service $name"
  try { sc.exe delete $name | Out-Null } catch { }
}

function _KillOpenSearchJava {
  _Log "Killing OpenSearch/java processes (best-effort)"
  try {
    Get-CimInstance Win32_Process -Filter "Name='java.exe'" |
      Where-Object { $_.CommandLine -match '(?i)TinySocs\\OpenSearch|\\OpenSearch\\|opensearch' } |
      ForEach-Object {
        try {
          _Log ("Stopping java.exe pid=" + $_.ProcessId)
          Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
        } catch { }
      }
  } catch { }

  # Also kill the service wrapper processes if present
  foreach ($p in @("opensearch-service-x64","opensearch-service-mgr")) {
    try {
      Get-Process -Name $p -ErrorAction SilentlyContinue | ForEach-Object {
        _Log ("Stopping process " + $p + " pid=" + $_.Id)
        try { Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue } catch { }
      }
    } catch { }
  }
}

# AppDir is one level up from {app}\modules
$appDir  = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$dataDir = Join-Path $env:ProgramData "TinySocs"
$flag    = Join-Path $dataDir "remove_on_uninstall.flag"

$upgrade = _IsUpgradeUninstall

# Decide KeepData:
# - If caller explicitly passed -KeepData, obey it.
# - Else if upgrade/uninstall during installer update, keep data.
# - Else if remove_on_uninstall.flag exists, remove data.
# - Else keep data (safe default).
$effectiveKeep = $true
if ($PSBoundParameters.ContainsKey("KeepData")) {
  $effectiveKeep = [bool]$KeepData
} elseif ($upgrade) {
  $effectiveKeep = $true
} elseif (Test-Path -LiteralPath $flag -PathType Leaf) {
  $effectiveKeep = $false
} else {
  $effectiveKeep = $true
}

_Log "Begin uninstall. AppDir=$appDir DataDir=$dataDir Upgrade=$upgrade KeepData(arg)=$KeepData EffectiveKeepData=$effectiveKeep FlagExists=$([bool](Test-Path -LiteralPath $flag -PathType Leaf))"

# Stop services first (and wrappers)
$svc = @(
  "TinySocsOpenSearch",
  "TinySocsAgent",
  "TinySocsNode",
  "TinySocsMaster",
  "TinySocsAnchors"
)

foreach ($s in $svc) {
  _StopAndDeleteService -name $s
}

_KillOpenSearchJava

# DO NOT delete $appDir here.
# The Inno uninstaller is running from {app}\unins*.exe and will remove {app} via [UninstallDelete].
_Log "Skipping deletion of AppDir in script; Inno will remove {app} via [UninstallDelete]."

if (-not $effectiveKeep) {
  _Log "Removing data directory: $dataDir"
  try { Remove-Item -LiteralPath $dataDir -Recurse -Force } catch { }
} else {
  _Log "Keeping data directory: $dataDir"
}

_Log "Uninstall complete."
exit 0