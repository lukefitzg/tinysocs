# scripts/Rotate-Queues.ps1
# TinySocs — Rotate the bot actions queue (JSONL)
# - Prefers TINYSOCS_QUEUE_PATH, then ACTIONS_QUEUE_PATH, else ProgramData TinySocs data dir
# - Rotates when size > MaxSizeMB or file age >= MaxAgeDays (and non-empty)
# - Keeps up to MaxFiles rotated copies under a sibling "queue-rot" dir
# - Emits always-on telemetry so scheduled task logs are diagnostic

[CmdletBinding()]
param(
  [string]$RepoRoot,
  [string]$QueuePath,
  [int]$MaxSizeMB = 5,
  [int]$MaxFiles = 7,
  [int]$MaxAgeDays = 14
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function _Log([string]$msg) {
  $ts = (Get-Date).ToString("s")
  Write-Output ("[{0}] {1}" -f $ts, $msg)
}

# --- establish ScriptPath/RepoRoot safely (avoid $PSScriptRoot in param defaults) ---
$scriptPath = $MyInvocation.MyCommand.Path
$scriptDir  = $null
try { if ($scriptPath) { $scriptDir = Split-Path -Parent $scriptPath } } catch { $scriptDir = $null }

if ([string]::IsNullOrWhiteSpace($RepoRoot)) {
  try {
    if ($scriptDir) {
      $RepoRoot = (Resolve-Path -LiteralPath (Join-Path $scriptDir "..")).Path
    } else {
      $RepoRoot = (Get-Location).Path
    }
  } catch {
    $RepoRoot = (Get-Location).Path
  }
}

# --- set location (best-effort) ---
try {
  if (Test-Path -LiteralPath $RepoRoot -PathType Container) {
    Set-Location -LiteralPath $RepoRoot
  } else {
    _Log "WARN RepoRoot not found as a directory: $RepoRoot (continuing without Set-Location)"
  }
} catch {
  _Log "WARN Failed to Set-Location RepoRoot=$RepoRoot : $($_.Exception.Message)"
}

# Resolve queue path (envs then default)
if ([string]::IsNullOrWhiteSpace($QueuePath)) {
  $QueuePath = $env:TINYSOCS_QUEUE_PATH
  if ([string]::IsNullOrWhiteSpace($QueuePath)) { $QueuePath = $env:ACTIONS_QUEUE_PATH }

  # Default for SYSTEM: ProgramData, not repo/ProgramFiles
  if ([string]::IsNullOrWhiteSpace($QueuePath)) {
    $QueuePath = Join-Path (Join-Path $env:ProgramData "TinySocs") "data\actions_queue.jsonl"
  }
}

# If relative, resolve against RepoRoot (PS 5.1-safe)
if (-not [System.IO.Path]::IsPathRooted($QueuePath)) {
  $QueuePath = Join-Path $RepoRoot $QueuePath
}

$dir    = Split-Path -Path $QueuePath -Parent
$base   = Split-Path -Path $QueuePath -Leaf
$rotDir = Join-Path $dir "queue-rot"

_Log "ScriptPath=$scriptPath"
_Log "ScriptDir=$scriptDir"
_Log "RepoRoot=$RepoRoot"
_Log "QueuePath=$QueuePath"
_Log "Dir=$dir"
_Log "RotDir=$rotDir"
_Log "Limits: MaxSizeMB=$MaxSizeMB MaxFiles=$MaxFiles MaxAgeDays=$MaxAgeDays"

# Ensure dirs + file exist
New-Item -ItemType Directory -Force -Path $dir    | Out-Null
New-Item -ItemType Directory -Force -Path $rotDir | Out-Null
if (-not (Test-Path -LiteralPath $QueuePath -PathType Leaf)) {
  New-Item -ItemType File -Force -Path $QueuePath | Out-Null
  _Log "Created queue file."
}

# Refresh stats
$item    = Get-Item -LiteralPath $QueuePath
$size    = [int64]$item.Length
$max     = [int64]($MaxSizeMB * 1MB)
$ageDays = ((Get-Date) - $item.LastWriteTime).TotalDays

$doRotate = $false
if ($size -gt $max) { $doRotate = $true }

# Also rotate if file older than MaxAgeDays and non-empty
if (($ageDays -ge $MaxAgeDays) -and ($size -gt 0)) { $doRotate = $true }

_Log ("Stats: sizeBytes={0} maxBytes={1} ageDays={2:N2} lastWrite={3}" -f $size, $max, $ageDays, $item.LastWriteTime.ToString("s"))
_Log ("Decision: doRotate={0}" -f $doRotate)

if ($doRotate) {
  $stamp  = Get-Date -Format "yyyyMMdd-HHmmss"
  $target = Join-Path $rotDir "$($base).$stamp"

  _Log "Rotating: Move-Item '$QueuePath' -> '$target'"
  Move-Item -LiteralPath $QueuePath -Destination $target -Force

  New-Item -ItemType File -Force -Path $QueuePath | Out-Null
  _Log "Rotated queue OK."
}

# Prune by count & age
$files = @()
try {
  $files = Get-ChildItem -LiteralPath $rotDir -File | Sort-Object LastWriteTime -Descending
} catch {
  _Log "WARN Failed to list rotDir '$rotDir': $($_.Exception.Message)"
  $files = @()
}

$toDelete = @()

if ($files.Count -gt $MaxFiles) {
  $toDelete += $files[$MaxFiles..($files.Count - 1)]
}

$toDelete += ($files | Where-Object { ((Get-Date) - $_.LastWriteTime).TotalDays -gt $MaxAgeDays })
$toDelete = $toDelete | Select-Object -Unique

foreach ($f in $toDelete) {
  try {
    Remove-Item -LiteralPath $f.FullName -Force
    _Log ("Pruned: {0}" -f $f.Name)
  } catch {
    _Log ("WARN Failed to prune {0}: {1}" -f $f.FullName, $_.Exception.Message)
  }
}

_Log "Done."