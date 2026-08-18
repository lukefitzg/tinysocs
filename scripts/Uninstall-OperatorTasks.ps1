$ErrorActionPreference = 'Stop'
$names = @("TinySocs-RotateQueues", "TinySocs-NightlyVerifyLedger", "TinySocs-MasterHeartbeat")
foreach ($n in $names) {
  $t = Get-ScheduledTask -TaskName $n -ErrorAction SilentlyContinue
  if (-not $t) {
    Write-Host "Already absent: $n"
    continue
  }
  try {
    Unregister-ScheduledTask -TaskName $n -Confirm:$false
    Write-Host "Removed: $n"
  } catch {
    # Fall back to schtasks.exe (covers tasks created via Install-OperatorTasks.ps1's
    # schtasks fallback path or under a different provider)
    schtasks /Delete /TN $n /F | Out-Null
    Write-Host "Removed via schtasks: $n"
  }
}
