param([string]$QueuePath="$env:ProgramData\TinySocs\queue",[int]$MaxSizeMB=5,[int]$MaxFiles=7,[int]$MaxAgeDays=14)
$ErrorActionPreference='SilentlyContinue'
New-Item -ItemType Directory -Force $QueuePath | Out-Null
$cut=(Get-Date).AddDays(-$MaxAgeDays)
Get-ChildItem $QueuePath -File | Where-Object LastWriteTime -lt $cut | Remove-Item -Force
$files=Get-ChildItem $QueuePath -File | Sort-Object LastWriteTime
if($files.Count -gt $MaxFiles){ $files[0..($files.Count-$MaxFiles-1)] | Remove-Item -Force }
$cur=Join-Path $QueuePath "actions_queue.jsonl"
if(Test-Path $cur -and (Get-Item $cur).Length -gt ($MaxSizeMB*1MB)){
  $stamp=Get-Date -Format "yyyyMMdd_HHmmss"
  Move-Item $cur (Join-Path $QueuePath "actions_queue_$stamp.jsonl")
}