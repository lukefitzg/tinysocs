param(
  [switch]$Quiet
)

# Re-launch elevated if needed
$curr = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $curr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  $args = @("-NoLogo","-NoProfile","-ExecutionPolicy","Bypass","-File","`"$PSCommandPath`"")
  if ($Quiet) { $args += "-Quiet" }
  Start-Process -FilePath "powershell.exe" -Verb RunAs -ArgumentList $args | Out-Null
  exit
}

if (-not $Quiet) { Write-Host "[winlogbeat] Restarting service as Administrator..." }

# Ensure the active config is the TLS+auth one
Copy-Item "C:\tinysocs\tinysocs\winlogbeat-config\winlogbeat.opensearch-auth.yml" `
          "C:\tinysocs\winlogbeat-bin\winlogbeat.yml" -Force

# (re)install service to keep BinaryPathName correct, then start it
Set-Location "C:\tinysocs\winlogbeat-bin"
if (Get-Service winlogbeat -ErrorAction SilentlyContinue) {
  Try { Stop-Service winlogbeat -ErrorAction SilentlyContinue } Catch {}
}
.\install-service-winlogbeat.ps1
Start-Service winlogbeat

# Show status
Get-Service winlogbeat | Format-Table Name,Status,StartType
