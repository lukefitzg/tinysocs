param(
  [string]$window  = "15m",
  [int]   $deadline = 30,
  [string]$rules   = "auth_failed_burst,ps_script_block"
)

# Try to import the TinySocs installer module so we get Get-TSCredential, etc.
$installerModule = "C:\Program Files\TinySocs\modules\TinySocs.Installer.psm1"
if (Test-Path $installerModule) {
  try {
    Import-Module $installerModule -ErrorAction SilentlyContinue
  } catch {
    Write-Warning "[TinySocs] Launch-Master: failed to import TinySocs.Installer.psm1: $($_.Exception.Message)"
  }
}

# Hydrate secrets from CredMan if helpers are available
if (Get-Command Get-TSCredential -ErrorAction SilentlyContinue) {
  try {
    # MASTER_SHARED_SECRET
    $shared = Get-TSCredential -Name 'TinySocs/Master/SharedSecret'
    if ($shared) {
      $env:MASTER_SHARED_SECRET = $shared
    }

    # SIEM creds blob: { url, user, pass, sslVerify }
    $rawSiem = Get-TSCredential -Name 'TinySocs/SIEM/Creds'
    if ($rawSiem) {
      $siem = $null
      try {
        $siem = $rawSiem | ConvertFrom-Json
      } catch {
        Write-Warning "[TinySocs] Launch-Master: failed to parse TinySocs/SIEM/Creds JSON: $($_.Exception.Message)"
      }

      if ($siem) {
        # URL
        if ($siem.PSObject.Properties.Name -contains 'url' -and $siem.url) {
          $env:SIEM_URL = [string]$siem.url
        }

        # User
        if ($siem.PSObject.Properties.Name -contains 'user' -and $siem.user) {
          $env:SIEM_USER = [string]$siem.user
        }

        # Password
        if ($siem.PSObject.Properties.Name -contains 'pass' -and $siem.pass) {
          $env:SIEM_PASS = [string]$siem.pass
        }

        # sslVerify → "true"/"false"
        if ($siem.PSObject.Properties.Name -contains 'sslVerify') {
          $boolVal = [bool]$siem.sslVerify
          if ($boolVal) {
            $env:SIEM_SSL_VERIFY = "true"
          } else {
            $env:SIEM_SSL_VERIFY = "false"
          }
        }
      }
    }
  } catch {
    Write-Warning "[TinySocs] Launch-Master: CredMan hydration failed: $($_.Exception.Message)"
  }
}

# Optionally, you can uncomment this while debugging:
# Write-Host "[TinySocs] Launch-Master: SIEM_URL=$($env:SIEM_URL); SIEM_USER=$($env:SIEM_USER); MASTER_SHARED_SECRET=$($env:MASTER_SHARED_SECRET)"

# Finally, run TinySocsMaster.exe with the provided arguments, logging to ProgramData
$exe = "C:\Program Files\TinySocs\bin\TinySocsMaster.exe"
if (-not (Test-Path $exe)) {
  Write-Error "[TinySocs] Launch-Master: TinySocsMaster.exe not found at $exe"
  exit 1
}

# Ensure log directory exists
$logDir = Join-Path $env:ProgramData "TinySocs\logs"
if (-not (Test-Path $logDir)) {
  New-Item -ItemType Directory -Force -Path $logDir | Out-Null
}

$logOut = Join-Path $logDir "TinySocsMaster.out.log"
$logErr = Join-Path $logDir "TinySocsMaster.err.log"

# Run master and append both stdout and stderr to log files
& $exe --window $window --deadline $deadline --rules $rules `
  1>> $logOut `
  2>> $logErr