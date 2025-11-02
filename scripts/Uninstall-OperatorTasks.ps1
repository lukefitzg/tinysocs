$ErrorActionPreference = 'Stop'
$names = @("TinySocs-RotateQueues","TinySocs-NightlyVerifyLedger")
foreach ($n in $names) {
  try {
    Unregister-ScheduledTask -TaskName $n -Confirm:$false
    Write-Host "Removed: $n"
  } catch {
    Write-Host "Already absent: $n"
  }
}