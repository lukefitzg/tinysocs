param(
  [string]$RepoRoot = (Resolve-Path "$PSScriptRoot\..").Path,
  [string]$QueuePath,
  [int]$MaxSizeMB = 5,
  [int]$MaxFiles = 7,
  [int]$MaxAgeDays = 14
)

$ErrorActionPreference = 'Stop'
Set-Location $RepoRoot

# resolve queue path (envs then default under repo)
if (-not $QueuePath) {
  $QueuePath = $env:TINYSOCS_QUEUE_PATH
  if (-not $QueuePath) { $QueuePath = $env:ACTIONS_QUEUE_PATH }
  if (-not $QueuePath) { $QueuePath = Join-Path $RepoRoot "tinysocs\actions_queue.jsonl" }
}

$dir = Split-Path $QueuePath -Parent
$base = Split-Path $QueuePath -Leaf
$rotDir = Join-Path $dir "queue-rot"
New-Item -ItemType Directory -Force -Path $dir | Out-Null
New-Item -ItemType Directory -Force -Path $rotDir | Out-Null
if (-not (Test-Path $QueuePath)) { New-Item -ItemType File -Path $QueuePath | Out-Null }

$size = (Get-Item $QueuePath).Length
$max = $MaxSizeMB * 1MB
$doRotate = ($size -gt $max)

# also rotate if file older than MaxAgeDays and non-empty
$ageDays = ((Get-Date) - (Get-Item $QueuePath).LastWriteTime).TotalDays
if ($ageDays -ge $MaxAgeDays -and $size -gt 0) { $doRotate = $true }

if ($doRotate) {
  $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
  $target = Join-Path $rotDir "$($base).$stamp"
  Move-Item -Path $QueuePath -Destination $target
  New-Item -ItemType File -Path $QueuePath | Out-Null
  Write-Host "Rotated queue -> $target"
}

# prune by count & age
$files = Get-ChildItem $rotDir -File | Sort-Object LastWriteTime -Descending
$toDelete = @()
if ($files.Count -gt $MaxFiles) { $toDelete += $files[$MaxFiles..($files.Count-1)] }
$toDelete += ($files | Where-Object { ((Get-Date) - $_.LastWriteTime).TotalDays -gt $MaxAgeDays })
$toDelete = $toDelete | Select-Object -Unique
foreach ($f in $toDelete) {
  Remove-Item -Force $f.FullName
  Write-Host "Pruned $($f.Name)"
}
