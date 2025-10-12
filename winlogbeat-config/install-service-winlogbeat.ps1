<#
.SYNOPSIS
    Installs Winlogbeat Windows service.
.DESCRIPTION
    Installs Winlogbeat Windows service, the data and logs path are
    set as part of the command for the service.

    For Winlogbeat < 9.1.0 the data path used to be
    'C:\ProgramData\Winlogbeat' (set from '$env:ProgramData) for >= 9.1.0
    the new default is 'C:\Program Files\Winlogbeat-Data'
    (set from '$env:ProgramFiles').

    If the legacy data path exists, then the script will move it to the new place,
    regardless of Winlogbeat version.

    You can pass ForceLegacyPath to use the legacy data path.

    If the Windows service already exists, it will be stopped and deleted, then
    the new one will be installed.
#>

Param (
  # Force the usage of the legacy ( < 9.1.0) data path.
  [switch]$ForceLegacyPath

)

# Delete and stop the service if it already exists.
if (Get-Service winlogbeat -ErrorAction SilentlyContinue) {
  Stop-Service winlogbeat
  (Get-Service winlogbeat).WaitForStatus('Stopped')
  Start-Sleep -s 1
  sc.exe delete winlogbeat
}

# We need to support a new default path for the data folder, ideally
# automatically detecting if the old one is used and keeping it

$WorkDir = Split-Path $MyInvocation.MyCommand.Path
$BasePath = "$env:ProgramFiles\Winlogbeat-Data"
$LegacyDataPath = "$env:PROGRAMDATA\Winlogbeat"

# Move the data path from ProgramData to Program Files
If ($ForceLegacyPath -eq $True) {
  $BasePath = $LegacyDataPath
} elseif (Test-Path $LegacyDataPath) {
    Write-Output "Files found at $LegacyDataPath, moving them to $BasePath"
  Try {
    Move-Item $LegacyDataPath $BasePath -ErrorAction Stop
  } Catch {
    Write-Output "Could not move $LegacyDataPath to $BasePath"
    Write-Output "make sure the folder can be moved or set -ForceLegacyPath"
    Write-Output "to force using $LegacyDataPath as the data path"
    Throw $_.Exception
  }
}

$HomePath = "$BasePath\Winlogbeat"
$LogsPath = "$HomePath\logs"
$KeystorePath = "$WorkDir\data\Winlogbeat.keystore"

$FullCmd = "`"$WorkDir\winlogbeat.exe`" " +
           "--environment=windows_service " +
           "-c `"$WorkDir\winlogbeat.yml`" " +
           "--path.home `"$WorkDir`" " +
           "--path.data `"$HomePath`" " +
           "--path.logs `"$LogsPath`" " +
           "-E keystore.path=`"$KeyStorePath`" " +
           "-E logging.files.redirect_stderr=true"

# Create the new service.
New-Service -name winlogbeat `
  -displayName Winlogbeat `
  -binaryPathName $FullCmd

# Attempt to set the service to delayed start using sc config.
Try {
  Start-Process -FilePath sc.exe -ArgumentList 'config winlogbeat start= delayed-auto'
}
Catch { Write-Host -f red "An error occurred setting the service to delayed start." }
