# C:\Program Files\TinySocs\modules\PostInstall.ps1
$ErrorActionPreference = 'Stop'
$mod = "C:\Program Files\TinySocs\modules\TinySocs.Installer.psm1"
$log = "$env:ProgramData\TinySocs\install.log"

"=== TinySocs PostInstall $(Get-Date -Format o) ===" | Out-File -Encoding utf8 -FilePath $log -Append
try {
  Import-Module $mod -Force -ErrorAction Stop
  "Imported module: $mod" | Out-File -Encoding utf8 -FilePath $log -Append

  Install-TinySocs
  "Install-TinySocs done" | Out-File -Encoding utf8 -FilePath $log -Append

  if (Test-Path "C:\Program Files\TinySocs\bin\nssm.exe") {
    Register-TinySocsServices
    "Register-TinySocsServices done" | Out-File -Encoding utf8 -FilePath $log -Append
  } else {
    "nssm.exe not found; skipping service" | Out-File -Encoding utf8 -FilePath $log -Append
  }

  Register-TinySocsTasks
  "Register-TinySocsTasks done" | Out-File -Encoding utf8 -FilePath $log -Append

  "PostInstall OK" | Out-File -Encoding utf8 -FilePath $log -Append
}
catch {
  "PostInstall ERROR: $($_.Exception.Message)" | Out-File -Encoding utf8 -FilePath $log -Append
  "Stack: $($_.ScriptStackTrace)"               | Out-File -Encoding utf8 -FilePath $log -Append
  if ($_.InvocationInfo) {
    "At $($_.InvocationInfo.PositionMessage)"   | Out-File -Encoding utf8 -FilePath $log -Append
  }
  exit 1
}
