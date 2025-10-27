Start-Transcript -Path "C:\tinysocs\tinysocs\logs\setup-20251027-200240.log" -Append | Out-Null
try {
  Set-Location 'C:\tinysocs\tinysocs'
  . '.\model_toggles.ps1'
  $ErrorActionPreference = 'Continue'
  $ProgressPreference    = 'SilentlyContinue'
  $VerbosePreference     = 'SilentlyContinue'
  if ($PSStyle -and $PSStyle.PSObject.Properties['OutputRendering']) { $PSStyle.OutputRendering = 'Ansi' }
  Write-Host "[TinySOCS] Elevated session ready. Running: Ensure-TinySOCS-Agents" -ForegroundColor Cyan

  $global:TinySOCS_LogPath = "C:\tinysocs\tinysocs\logs\setup-20251027-200240.log"
  Ensure-TinySOCS-Agents
}
catch {
  Write-Error ("[TinySOCS] Unhandled error in elevated session: {0}" -f $_.Exception.Message)
  if ($_.ScriptStackTrace) { Write-Error $_.ScriptStackTrace }
}
finally {
  try { Stop-Transcript | Out-Null } catch {}
}
