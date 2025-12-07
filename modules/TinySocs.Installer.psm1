# modules\TinySocs.Installer.psm1
# Windows-first installer helpers for TinySocs

# ── ProgramData layout ──────────────────────────────────────────────────────────
function Get-TinySocsDataRoot {
  $root = Join-Path $env:ProgramData "TinySocs"
  if (-not (Test-Path $root)) {
    try { New-Item -ItemType Directory -Force -Path $root | Out-Null } catch { }
  }
  return $root
}

function Write-TinySocsLog {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Message,
    [ValidateSet('INFO','WARN','ERROR','DEBUG')][string]$Level = 'INFO'
  )
  $ts   = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
  $line = "[TinySocs][$Level][$ts] $Message"
  Write-Host $line
  try {
    $logDir = Join-Path (Get-TinySocsDataRoot) "logs"
    New-Item -ItemType Directory -Force -Path $logDir | Out-Null
    Add-Content -Path (Join-Path $logDir "installer.log") -Value $line
  } catch {
    Write-Warning "[TinySocs] Failed to persist installer log: $($_.Exception.Message)"
  }
}

function New-ProgramDataLayout {
  $root = Get-TinySocsDataRoot
  "$root\logs","$root\queue","$root\ledger","$root\rules","$root\anchors\state","$root\config" |
    ForEach-Object { New-Item -ItemType Directory -Force -Path $_ | Out-Null }
}

function Install-TinySocs {
  New-ProgramDataLayout
  Write-TinySocsLog "ProgramData ensured at $(Get-TinySocsDataRoot)."
}

# ── Credential Manager helpers (TinySocs/Phase7) ──────────────────────────────
# We store secrets as Generic credentials so services and tasks can read them.
# Targets we use:
#   TinySocs/Node/Secret
#   TinySocs/Master/SharedSecret
#   TinySocs/SIEM/Creds

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

namespace TinySocs.Security
{
    public static class CredNative
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct CREDENTIAL
        {
            public uint Flags;
            public uint Type;
            public string TargetName;
            public string Comment;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
            public uint CredentialBlobSize;
            public IntPtr CredentialBlob;
            public uint Persist;
            public uint AttributeCount;
            public IntPtr Attributes;
            public string TargetAlias;
            public string UserName;
        }

        [DllImport("advapi32.dll", EntryPoint = "CredWriteW", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool CredWrite(ref CREDENTIAL userCredential, uint flags);

        [DllImport("advapi32.dll", EntryPoint = "CredReadW", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool CredRead(string target, uint type, uint reservedFlag, out IntPtr credentialPtr);

        [DllImport("advapi32.dll", EntryPoint = "CredFree", SetLastError = false)]
        public static extern void CredFree(IntPtr cred);

        [DllImport("advapi32.dll", EntryPoint = "CredDeleteW", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool CredDelete(string target, uint type, uint flags);
    }
}
"@

function Set-TSCredential {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][string]$Secret
  )
  $bytes = [System.Text.Encoding]::Unicode.GetBytes($Secret)
  $cred = New-Object TinySocs.Security.CredNative+CREDENTIAL
  $cred.Flags = 0
  $cred.Type  = 1           # CRED_TYPE_GENERIC
  $cred.TargetName = $Name
  $cred.CredentialBlobSize = $bytes.Length
  $cred.Persist = 2         # CRED_PERSIST_LOCAL_MACHINE
  $cred.AttributeCount = 0
  $cred.UserName = "TinySocs"
  $cred.CredentialBlob = [Runtime.InteropServices.Marshal]::AllocHGlobal($bytes.Length)
  [Runtime.InteropServices.Marshal]::Copy($bytes, 0, $cred.CredentialBlob, $bytes.Length)
  try {
    if (-not [TinySocs.Security.CredNative]::CredWrite([ref]$cred, 0)) {
      $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
      throw "CredWrite failed for $Name (Win32 $err)"
    }
  }
  finally {
    if ($cred.CredentialBlob -ne [IntPtr]::Zero) {
      [Runtime.InteropServices.Marshal]::FreeHGlobal($cred.CredentialBlob)
    }
  }
}

function Get-TSCredential {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Name
  )
  $ptr = [IntPtr]::Zero
  try {
    $ok = [TinySocs.Security.CredNative]::CredRead($Name, 1, 0, [ref]$ptr) # CRED_TYPE_GENERIC
    if (-not $ok -or $ptr -eq [IntPtr]::Zero) { return $null }
    $raw = [Runtime.InteropServices.Marshal]::PtrToStructure(
      $ptr,
      [Type][TinySocs.Security.CredNative+CREDENTIAL]
    )
    if ($raw.CredentialBlobSize -le 0 -or $raw.CredentialBlob -eq [IntPtr]::Zero) { return $null }
    $bytes = New-Object byte[] $raw.CredentialBlobSize
    [Runtime.InteropServices.Marshal]::Copy($raw.CredentialBlob, $bytes, 0, $raw.CredentialBlobSize)
    return [System.Text.Encoding]::Unicode.GetString($bytes)
  }
  finally {
    if ($ptr -ne [IntPtr]::Zero) {
      [TinySocs.Security.CredNative]::CredFree($ptr)
    }
  }
}

function Remove-TSCredential {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Name
  )
  [TinySocs.Security.CredNative]::CredDelete($Name, 1, 0) | Out-Null
}

function Set-TinySocsSiemCredential {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$SiemUrl,
    [Parameter(Mandatory)][string]$SiemUser,
    [Parameter(Mandatory)][string]$SiemPass,
    [bool]$SiemSslVerify = $true
  )

  # Normalise URL a bit (no trailing slash noise)
  $normUrl = $SiemUrl.TrimEnd('/')

  $payload = @{
    url       = $normUrl
    user      = $SiemUser
    pass      = $SiemPass
    sslVerify = $SiemSslVerify
  } | ConvertTo-Json -Compress

  # Write to CredMan as authoritative store
  Set-TSCredential -Name 'TinySocs/SIEM/Creds' -Secret $payload

  # Mirror into machine/env for compatibility + non-CredMan paths
  $verifyString = if ($SiemSslVerify) { 'true' } else { 'false' }

  Set-MachineEnv @{
    SIEM_URL        = $normUrl
    SIEM_USER       = $SiemUser
    SIEM_PASS       = $SiemPass
    SIEM_SSL_VERIFY = $verifyString
  }

  Write-Host "[TinySocs] SIEM credentials stored in CredMan and env (url=$normUrl, sslVerify=$verifyString)."
}

# Helper: Get install root
function Get-TinySocsInstallRoot {
  # Prefer the real installed location if it exists
  $defaultRoot = "C:\Program Files\TinySocs"
  if (Test-Path $defaultRoot -PathType Container) {
    return $defaultRoot
  }

  # Fallback for dev/testing when running from the repo
  if ($PSScriptRoot) {
    return (Split-Path -Parent $PSScriptRoot)
  }

  return $defaultRoot
}

# Helper: Write OpenSearch config file
function Write-TinySocsOpenSearchConfig {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$ConfigPath,
    [Parameter(Mandatory)][string]$ClusterName,
    [Parameter(Mandatory)][string]$NodeName,
    [Parameter(Mandatory)][int]$HttpPort,
    [Parameter(Mandatory)][string]$DataPath,
    [Parameter(Mandatory)][string]$LogsPath,
    [switch]$Force
  )

  if ((Test-Path $ConfigPath -PathType Leaf) -and -not $Force.IsPresent) {
    Write-TinySocsLog "opensearch.yml already exists and -ForceConfig not set; leaving as-is: $ConfigPath"
    return
  }

  $dataPathNormalized = $DataPath.Replace('\','/')
  $logsPathNormalized = $LogsPath.Replace('\','/')

  $configContent = @"
cluster.name: $ClusterName
node.name: $NodeName

network.host: 127.0.0.1
http.port: $HttpPort

discovery.type: single-node

path.data: $dataPathNormalized
path.logs: $logsPathNormalized

"@

  $configDir = Split-Path -Parent $ConfigPath
  if (-not (Test-Path $configDir)) {
    New-Item -ItemType Directory -Force -Path $configDir | Out-Null
  }

  $configContent | Out-File -FilePath $ConfigPath -Encoding UTF8 -Force
  Write-TinySocsLog "OpenSearch config written to $ConfigPath"
}

# Helper: Write Winlogbeat config pointing at TinySocs file-out (TinyBox or remote via forwarder)
function Write-TinySocsWinlogbeatConfig {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$ConfigPath,
    [string]$SiemUrl,
    [string]$IndexPrefix = "tinysocs-winlog",
    [switch]$Force
  )

  if ((Test-Path $ConfigPath -PathType Leaf) -and -not $Force.IsPresent) {
    Write-TinySocsLog "winlogbeat.yml already exists and -ForceConfig not set; leaving as-is: $ConfigPath"
    return
  }

  # We no longer send directly to OpenSearch from Winlogbeat. All events go to a local file
  # which the TinySocs forwarder reads and ships to the SIEM.
  $configContent = @"
winlogbeat.event_logs:
  - name: Security
  - name: System
  - name: Application
  - name: Windows PowerShell
  - name: Microsoft-Windows-PowerShell/Operational

  # Optional: if Sysmon is present
  - name: Microsoft-Windows-Sysmon/Operational
    ignore_older: 72h

processors:
  - add_host_metadata: ~
  - add_cloud_metadata: ~
  - add_process_metadata: ~
  - add_fields:
      target: ''
      fields:
        tinysocs_source: winlogbeat
  - add_fields:
      target: ''
      fields:
        tinysocs_node: \${COMPUTERNAME}

output.file:
  path: C:/ProgramData/TinySocs/Collector/winlogbeat/out
  filename: events
  rotate_every_kb: 10240
  number_of_files: 10

logging.to_files: true
logging.files:
  path: C:/ProgramData/TinySocs/Collector/logs
  name: winlogbeat
  keepfiles: 7
  rotateeverybytes: 10485760

logging.level: info
"@

  $configDir = Split-Path -Parent $ConfigPath
  if (-not (Test-Path $configDir)) {
    New-Item -ItemType Directory -Force -Path $configDir | Out-Null
  }

  $configContent | Out-File -FilePath $ConfigPath -Encoding UTF8 -Force
  Write-TinySocsLog "Winlogbeat config written to $ConfigPath (file-output -> TinySocs forwarder)."
}

# Helper: Ensure OpenSearch security plugin is disabled (plugins/opensearch-security)
function Disable-TinySocsOpenSearchSecurityPlugin {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$OpenSearchRoot
  )

  $pluginPath = Join-Path $OpenSearchRoot "plugins\opensearch-security"

  if (-not (Test-Path $pluginPath -PathType Container)) {
    Write-TinySocsLog "OpenSearch security plugin not present at $pluginPath; nothing to disable."
    return
  }

  # If the TinySocsOpenSearch service is running, stop it so we can remove locked JARs
  $svc = Get-Service -Name "TinySocsOpenSearch" -ErrorAction SilentlyContinue
  if ($null -ne $svc -and $svc.Status -eq 'Running') {
    try {
      Write-TinySocsLog "Stopping TinySocsOpenSearch service to remove security plugin at $pluginPath."
      Stop-Service -Name "TinySocsOpenSearch" -Force -ErrorAction Stop
      Start-Sleep -Seconds 5
    } catch {
      $errMsg = "Failed to stop TinySocsOpenSearch before removing security plugin at ${pluginPath}: $($_.Exception.Message)"
      Write-TinySocsLog -Level "WARN" -Message $errMsg
    }
  }

  try {
    # Force terminating errors so we can accurately log success/failure
    Remove-Item $pluginPath -Recurse -Force -ErrorAction Stop
    Write-TinySocsLog "OpenSearch security plugin removed at $pluginPath (TinyBox runs without SSL/auth)."
  } catch {
    $errMsg = "Failed to remove OpenSearch security plugin at ${pluginPath}: $($_.Exception.Message)"
    Write-TinySocsLog -Level "WARN" -Message $errMsg
  }
}

# Helper: Ensure OpenSearch service via NSSM
function Ensure-TinySocsOpenSearchService {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$OpenSearchRoot,
    [Parameter(Mandatory)][string]$NssmPath,
    [Parameter(Mandatory)][string]$ServiceName,
    [Parameter(Mandatory)][string]$DisplayName,
    [Parameter(Mandatory)][string]$Description
  )

  if (-not (Test-Path $NssmPath -PathType Leaf)) {
    throw "nssm.exe not found at '$NssmPath'. Ensure the TinySocs installer copies nssm.exe before installing the local SIEM."
  }

  $exePath = Join-Path $OpenSearchRoot "bin\opensearch.bat"
  if (-not (Test-Path $exePath -PathType Leaf)) {
    throw "OpenSearch executable not found at '$exePath'. Ensure OpenSearch is installed under '$OpenSearchRoot'."
  }

  $confPath = Join-Path $OpenSearchRoot "config"
  $confEnv  = "OPENSEARCH_PATH_CONF=$confPath"

  $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

  if ($null -eq $service) {
    Write-TinySocsLog "Creating NSSM service '$ServiceName' for TinySocs OpenSearch"
    & $NssmPath install $ServiceName $exePath | Out-Null
  }
  else {
    Write-TinySocsLog "Service '$ServiceName' already exists; updating NSSM configuration"
  }

  & $NssmPath set $ServiceName DisplayName  $DisplayName    | Out-Null
  & $NssmPath set $ServiceName Description  $Description    | Out-Null
  & $NssmPath set $ServiceName AppDirectory $OpenSearchRoot | Out-Null
  & $NssmPath set $ServiceName AppEnvironmentExtra $confEnv | Out-Null

  & $NssmPath set $ServiceName ObjectName "LocalSystem" | Out-Null
  & $NssmPath set $ServiceName Start "SERVICE_DELAYED_AUTO_START" | Out-Null

  & $NssmPath set $ServiceName AppStopMethodConsole 15000 | Out-Null
  & $NssmPath set $ServiceName AppStopMethodSkip    0     | Out-Null

  & $NssmPath set $ServiceName AppExit Default Restart | Out-Null

  Write-TinySocsLog "Service '$ServiceName' ensured via NSSM."
}

#
# Helper: Ensure TinySocsCollector (Winlogbeat) service via NSSM
function Ensure-TinySocsCollectorService {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$WinlogbeatRoot,
    [Parameter(Mandatory)][string]$NssmPath,
    [Parameter(Mandatory)][string]$ServiceName,
    [Parameter(Mandatory)][string]$DisplayName,
    [Parameter(Mandatory)][string]$Description
  )

  if (-not (Test-Path $NssmPath -PathType Leaf)) {
    throw "nssm.exe not found at '$NssmPath'. Ensure the TinySocs installer copies nssm.exe before installing the collector."
  }

  $exePath = Join-Path $WinlogbeatRoot "winlogbeat.exe"
  if (-not (Test-Path $exePath -PathType Leaf)) {
    Write-TinySocsLog -Level "WARN" -Message "winlogbeat.exe not found at '$exePath'. Collector service '$ServiceName' will not be installed. Ensure Winlogbeat is installed under '$WinlogbeatRoot'."
    return
  }

  $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

  if ($null -eq $service) {
    Write-TinySocsLog "Creating NSSM service '$ServiceName' for TinySocs Collector (Winlogbeat)"
    & $NssmPath install $ServiceName $exePath | Out-Null
  } else {
    Write-TinySocsLog "Service '$ServiceName' already exists; updating NSSM configuration"
  }

  & $NssmPath set $ServiceName DisplayName  $DisplayName    | Out-Null
  & $NssmPath set $ServiceName Description  $Description    | Out-Null
  & $NssmPath set $ServiceName AppDirectory $WinlogbeatRoot | Out-Null

  # Winlogbeat standard args: -c winlogbeat.yml -e (log to stderr)
  & $NssmPath set $ServiceName AppParameters "-c winlogbeat.yml -e" | Out-Null

  # Run as LocalSystem, delayed start, restart on exit
  & $NssmPath set $ServiceName ObjectName "LocalSystem"                           | Out-Null
  & $NssmPath set $ServiceName Start "SERVICE_DELAYED_AUTO_START"                 | Out-Null
  & $NssmPath set $ServiceName AppExit Default Restart                            | Out-Null
  & $NssmPath set $ServiceName AppStdout "C:\ProgramData\TinySocs\Collector\logs\winlogbeat.out.log" | Out-Null
  & $NssmPath set $ServiceName AppStderr "C:\ProgramData\TinySocs\Collector\logs\winlogbeat.err.log" | Out-Null

  Write-TinySocsLog "Service '$ServiceName' ensured via NSSM (Collector)."
}

# Helper: Ensure TinySocs Winlog forwarder service via NSSM
function Ensure-TinySocsWinlogForwarderService {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$ForwarderRoot,
    [Parameter(Mandatory)][string]$NssmPath,
    [Parameter(Mandatory)][string]$ServiceName,
    [Parameter(Mandatory)][string]$DisplayName,
    [Parameter(Mandatory)][string]$Description
  )

  if (-not (Test-Path $NssmPath -PathType Leaf)) {
    throw "nssm.exe not found at '$NssmPath'. Ensure the TinySocs installer copies nssm.exe before installing the forwarder."
  }

  $exePath = Join-Path $ForwarderRoot "tinysocs_forwarder_winlog.exe"
  if (-not (Test-Path $exePath -PathType Leaf)) {
    Write-TinySocsLog -Level "WARN" -Message "tinysocs_forwarder_winlog.exe not found at '$exePath'. Forwarder service '$ServiceName' will not be installed. Ensure the forwarder EXE is installed under '$ForwarderRoot'."
    return
  }

  $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

  if ($null -eq $service) {
    Write-TinySocsLog "Creating NSSM service '$ServiceName' for TinySocs Winlog forwarder"
    & $NssmPath install $ServiceName $exePath | Out-Null
  } else {
    Write-TinySocsLog "Service '$ServiceName' already exists; updating NSSM configuration"
  }

  & $NssmPath set $ServiceName DisplayName  $DisplayName   | Out-Null
  & $NssmPath set $ServiceName Description  $Description   | Out-Null
  & $NssmPath set $ServiceName AppDirectory $ForwarderRoot | Out-Null

  & $NssmPath set $ServiceName ObjectName "LocalSystem"                | Out-Null
  & $NssmPath set $ServiceName Start "SERVICE_DELAYED_AUTO_START"      | Out-Null
  & $NssmPath set $ServiceName AppExit Default Restart                 | Out-Null
  & $NssmPath set $ServiceName AppStdout "C:\ProgramData\TinySocs\Collector\logs\tinysocs_forwarder_winlog.out.log" | Out-Null
  & $NssmPath set $ServiceName AppStderr "C:\ProgramData\TinySocs\Collector\logs\tinysocs_forwarder_winlog.err.log" | Out-Null

  Write-TinySocsLog "Service '$ServiceName' ensured via NSSM (Winlog forwarder)."
}

# Helper: Wait for local SIEM HTTP to become ready
function Wait-TinySocsLocalSiemReady {
  [CmdletBinding()]
  param(
    [string]$Url = "http://127.0.0.1:9200",
    [int]$TimeoutSeconds = 60,
    [int]$IntervalSeconds = 3
  )

  $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
  Write-TinySocsLog "Waiting for local SIEM HTTP to become ready at $Url (timeout=${TimeoutSeconds}s)."

  while ((Get-Date) -lt $deadline) {
    try {
      $resp = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
      if ($resp.StatusCode -ge 200 -and $resp.StatusCode -lt 300) {
        Write-TinySocsLog "Local SIEM HTTP ready at $Url (status=$($resp.StatusCode))."
        return $true
      }
    } catch {
      # Swallow and retry until timeout
    }
    Start-Sleep -Seconds $IntervalSeconds
  }

  Write-TinySocsLog -Level "WARN" -Message "Local SIEM HTTP did not become ready at $Url within ${TimeoutSeconds}s."
  return $false
}

# ── Local SIEM (OpenSearch via NSSM service) ───────────────────────────────────
function Install-TinySocsLocalSiem {
  [CmdletBinding()]
  param(
    # Legacy params kept for compatibility; ApiPort now drives local HTTP port.
    [string]$SiemUser = "admin",
    [string]$SiemPass = "ChangeMe123!",
    [int]$ApiPort = 9200,
    [int]$DashboardsPort = 5602,
    [switch]$NoStart,

    # New TinyBox/OpenSearch-specific knobs
    [string]$ClusterName = "tinysocs-local",
    [string]$NodeName    = "tinysocs-node-1",
    [switch]$ForceConfig
  )

  $installRoot    = Get-TinySocsInstallRoot
  $openSearchRoot = Join-Path $installRoot "OpenSearch"
  $dataRoot       = Join-Path (Get-TinySocsDataRoot) "OpenSearch"
  $dataPath       = Join-Path $dataRoot "data"
  $logsPath       = Join-Path $dataRoot "logs"
  $nssmPath       = Join-Path $installRoot "bin\nssm.exe"

  Write-TinySocsLog "Local SIEM install starting (OpenSearchRoot=$openSearchRoot, DataRoot=$dataRoot, HttpPort=$ApiPort)."

  New-Item -ItemType Directory -Force -Path $dataPath | Out-Null
  New-Item -ItemType Directory -Force -Path $logsPath | Out-Null

  $configFile = Join-Path $openSearchRoot "config\opensearch.yml"
  Write-TinySocsOpenSearchConfig -ConfigPath $configFile `
    -ClusterName $ClusterName `
    -NodeName    $NodeName `
    -HttpPort    $ApiPort `
    -DataPath    $dataPath `
    -LogsPath    $logsPath `
    -Force:$ForceConfig

  # TinyBox runs local-only over HTTP; drop the security plugin so it stops demanding SSL.
  Disable-TinySocsOpenSearchSecurityPlugin -OpenSearchRoot $openSearchRoot

  $serviceName = "TinySocsOpenSearch"
  $displayName = "TinySocs OpenSearch (TinyBox Local SIEM)"
  $description = "Local OpenSearch instance for TinySocs TinyBox SIEM"

  Ensure-TinySocsOpenSearchService -OpenSearchRoot $openSearchRoot `
    -NssmPath $nssmPath `
    -ServiceName $serviceName `
    -DisplayName $displayName `
    -Description $description

  $siemUrl = "http://127.0.0.1:$ApiPort"

  if (-not $NoStart) {
    try {
      Start-Service -Name $serviceName -ErrorAction Stop
      Write-TinySocsLog "Local SIEM service '$serviceName' started."

      $ready = Wait-TinySocsLocalSiemReady -Url $siemUrl -TimeoutSeconds 60 -IntervalSeconds 3
      if (-not $ready) {
        Write-TinySocsLog -Level "WARN" -Message "Local SIEM service '$serviceName' started but HTTP is not responding at $siemUrl; check logs under $logsPath."
      }
    } catch {
      Write-TinySocsLog -Level "WARN" -Message "Failed to start local SIEM service '$serviceName': $($_.Exception.Message)"
    }
  } else {
    Write-TinySocsLog -Level "WARN" -Message "NoStart specified; service '$serviceName' configured but not started."
  }

  Set-MachineEnv @{
    SIEM_URL        = $siemUrl
    SIEM_SSL_VERIFY = "false"
  }

  Write-TinySocsLog "Local SIEM (OpenSearch) configured at $siemUrl (no auth, local-only)."
}

function Install-TinySocsCollector {
  [CmdletBinding()]
  param(
    [string]$IndexPrefix = "tinysocs-winlog",
    [switch]$NoStart,
    [switch]$ForceConfig
  )

  $installRoot    = Get-TinySocsInstallRoot
  $collectorRoot  = Join-Path $installRoot "Collector"
  $winlogbeatRoot = Join-Path $collectorRoot "winlogbeat"
  $dataRoot       = Join-Path (Get-TinySocsDataRoot) "Collector"
  $logsPath       = Join-Path $dataRoot "logs"
  $nssmPath       = Join-Path $installRoot "bin\nssm.exe"
  $forwarderRoot  = Join-Path $collectorRoot "forwarder"
  $outDir         = Join-Path $dataRoot "winlogbeat\out"

  New-Item -ItemType Directory -Force -Path $dataRoot | Out-Null
  New-Item -ItemType Directory -Force -Path $logsPath | Out-Null
  New-Item -ItemType Directory -Force -Path $outDir | Out-Null

  $configFile = Join-Path $winlogbeatRoot "winlogbeat.yml"
  Write-TinySocsWinlogbeatConfig -ConfigPath $configFile `
    -IndexPrefix $IndexPrefix `
    -Force:$ForceConfig

  $serviceName = "TinySocsCollector"
  $displayName = "TinySocs Collector (Winlogbeat)"
  $description = "Local Windows Event Log collector for TinySocs TinyBox SIEM"

  Ensure-TinySocsCollectorService -WinlogbeatRoot $winlogbeatRoot `
    -NssmPath $nssmPath `
    -ServiceName $serviceName `
    -DisplayName $displayName `
    -Description $description

  $fwdServiceName = "TinySocsWinlogForwarder"
  $fwdDisplayName = "TinySocs Winlog Forwarder"
  $fwdDescription = "TinySocs local forwarder from Winlogbeat file output into OpenSearch"

  Ensure-TinySocsWinlogForwarderService -ForwarderRoot $forwarderRoot `
    -NssmPath $nssmPath `
    -ServiceName $fwdServiceName `
    -DisplayName $fwdDisplayName `
    -Description $fwdDescription

  $collectorService = Get-Service -Name $serviceName      -ErrorAction SilentlyContinue
  $forwarderService = Get-Service -Name $fwdServiceName   -ErrorAction SilentlyContinue

  if (-not $NoStart) {
    if ($null -ne $collectorService) {
      try {
        Start-Service -Name $serviceName -ErrorAction Stop
        Write-TinySocsLog "Collector service '$serviceName' started."
      } catch {
        Write-TinySocsLog -Level "WARN" -Message "Failed to start collector service '$serviceName': $($_.Exception.Message)"
      }
    } else {
      Write-TinySocsLog -Level "WARN" -Message "Collector service '$serviceName' is not installed; nothing to start. Ensure Winlogbeat is present under '$winlogbeatRoot' before enabling the collector."
    }

    if ($null -ne $forwarderService) {
      try {
        Start-Service -Name $fwdServiceName -ErrorAction Stop
        Write-TinySocsLog "Forwarder service '$fwdServiceName' started."
      } catch {
        Write-TinySocsLog -Level "WARN" -Message "Failed to start forwarder service '$fwdServiceName': $($_.Exception.Message)"
      }
    } else {
      Write-TinySocsLog -Level "WARN" -Message "Forwarder service '$fwdServiceName' is not installed; nothing to start. Ensure tinysocs_forwarder_winlog.exe is present under '$forwarderRoot' before enabling the forwarder."
    }
  } else {
    Write-TinySocsLog -Level "WARN" -Message "NoStart specified; collector + forwarder services configured but not started."
  }

  Write-TinySocsLog "Collector configured (Winlogbeat file-output, index prefix '$IndexPrefix')."
}


# ── Service via NSSM ────────────────────────────────────────────────────────────
function Register-TinySocsNodeService {
  $binDir = "C:\Program Files\TinySocs\bin"
  $n      = Join-Path $binDir "nssm.exe"
  $e      = Join-Path $binDir "TinySocsNode.exe"
  $w      = "$env:ProgramData\TinySocs"

  if (!(Test-Path $n)) {
    Write-Warning "[TinySocs] nssm.exe missing; skipping service."
    return
  }

  # Ensure logs dir exists
  New-Item -ItemType Directory -Force -Path "$w\logs" | Out-Null

  # Install or update service config idempotently
  & $n install TinySocsNode $e | Out-Null
  & $n set TinySocsNode AppDirectory    $w                             | Out-Null
  & $n set TinySocsNode Start           SERVICE_AUTO_START             | Out-Null
  & $n set TinySocsNode AppStdout       "$w\logs\TinySocsNode.out.log" | Out-Null
  & $n set TinySocsNode AppStderr       "$w\logs\TinySocsNode.err.log" | Out-Null
  & $n set TinySocsNode AppNoConsole    1                              | Out-Null
  & $n set TinySocsNode AppRestartDelay 2000                           | Out-Null

  # We deliberately *don’t* push secrets into AppEnvironmentExtra.
  # Node picks up config from machine env, which Pair-TinySocs + CredMan own.

  Write-Host "[TinySocs] Node service registered."
}

function Register-TinySocsServices {
  Register-TinySocsNodeService
}


# ── Scheduled task helpers (PowerShell ScheduledTasks API) ─────────────────────
function Ensure-TaskFolder {
  param([string]$FolderPath = "\TinySocs")

  $svc  = New-Object -ComObject "Schedule.Service"
  $svc.Connect()
  $root = $svc.GetFolder("\")   # root of Task Scheduler

  # Normalise folder name: "\TinySocs\" -> "TinySocs"
  $folderName = $FolderPath.Trim('\')
  if ([string]::IsNullOrWhiteSpace($folderName)) {
    throw "Invalid task folder name '$FolderPath'"
  }

  # Try to get it first
  try {
    $null = $root.GetFolder("\$folderName")
    return
  } catch {
    # Fall through and try to create
  }

  try {
    $null = $root.CreateFolder($folderName)
  } catch {
    # If it already exists (0x800700B7), ignore; otherwise rethrow.
    $hr = $_.Exception.HResult
    if ($hr -ne -2147024713) {   # 0x800700B7 == -2147024713
      throw
    }
  }
}

function New-TinySocsTaskAction {
  param(
    [Parameter(Mandatory)][string]$ScriptPath,
    [string]$Args = ""
  )
  $ps  = "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe"
  $arg = "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`" $Args".Trim()
  New-ScheduledTaskAction -Execute $ps -Argument $arg
}

function New-TinySocsExeAction {
  param(
    [Parameter(Mandatory)][string]$ExePath,
    [string]$Args = ""
  )
  New-ScheduledTaskAction -Execute $ExePath -Argument $Args
}

function New-TinySocsRepeatTrigger {
  param([Parameter(Mandatory)][int]$EveryMinutes)
  $start = (Get-Date).AddMinutes(1)
  # Task Scheduler rejects infinite duration; pick something absurdly long (~10 years)
  $dur = New-TimeSpan -Days 3650
  New-ScheduledTaskTrigger -Once -At $start `
    -RepetitionInterval (New-TimeSpan -Minutes $EveryMinutes) `
    -RepetitionDuration $dur
}

function New-TinySocsDailyTrigger {
  param([Parameter(Mandatory)][string]$At) # "HH:mm"
  $time = [DateTime]::Today.Add([TimeSpan]::Parse($At))
  New-ScheduledTaskTrigger -Daily -At $time
}

function Register-TinySocsTasks {
  $taskPath  = "\TinySocs\"
  $modDir    = "C:\Program Files\TinySocs\modules"
  $binDir    = "C:\Program Files\TinySocs\bin"

  Ensure-TaskFolder -FolderPath $taskPath

  # Derive heartbeat + retention from env (with sane defaults)
  $hb = 15
  if ($env:HEARTBEAT_MINUTES) {
    [int]::TryParse($env:HEARTBEAT_MINUTES, [ref]$hb) | Out-Null
  }

  $retention = 45
  if ($env:ANCHORS_RETENTION_DAYS) {
    [int]::TryParse($env:ANCHORS_RETENTION_DAYS, [ref]$retention) | Out-Null
  }

  function _RegisterIdempotent {
    param(
      [string]$TaskName,
      [scriptblock]$ActionFactory,
      $Trigger
    )

    try {
      $existing = Get-ScheduledTask -TaskPath $taskPath -TaskName $TaskName -ErrorAction SilentlyContinue
      if ($existing) {
        Unregister-ScheduledTask -TaskName $TaskName -TaskPath $taskPath -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
      }
    } catch { }

    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
    $settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 60)

    $action = & $ActionFactory
    $task   = New-ScheduledTask -Action $action -Trigger $Trigger -Principal $principal -Settings $settings
    Register-ScheduledTask -TaskName $TaskName -TaskPath $taskPath -InputObject $task -Force | Out-Null
  }

  # Heartbeat: TinySocsMaster every $hb minutes via Launch-Master.ps1
  $masterScript = Join-Path $modDir "Launch-Master.ps1"
  $masterArgs   = ("-window {0}m -deadline 30 -rules 'auth_failed_burst,ps_script_block'" -f $hb)
  $masterTrigger = New-TinySocsRepeatTrigger -EveryMinutes $hb

  _RegisterIdempotent -TaskName "TinySocsHeartbeat" -ActionFactory {
    New-TinySocsTaskAction -ScriptPath $masterScript -Args $masterArgs
  } -Trigger $masterTrigger

  # Anchors ensure daily 03:10
  $anchorsExe   = Join-Path $binDir "TinySocsAnchors.exe"
  $ensureTrigger  = New-TinySocsDailyTrigger -At "03:10"
  _RegisterIdempotent -TaskName "TinySocsAnchorsEnsure" -ActionFactory {
    New-TinySocsExeAction -ExePath $anchorsExe -Args "--ensure"
  } -Trigger $ensureTrigger

  # Anchors prune daily 03:15
  $pruneTrigger = New-TinySocsDailyTrigger -At "03:15"
  _RegisterIdempotent -TaskName "TinySocsAnchorsPrune" -ActionFactory {
    New-TinySocsExeAction -ExePath $anchorsExe -Args ("--prune --retention-days {0}" -f $retention)
  } -Trigger $pruneTrigger

  # Queue rotation hourly via TinySocs.RotateQueue.ps1
  $rotateScript  = Join-Path $modDir "TinySocs.RotateQueue.ps1"
  $rotateTrigger = New-TinySocsRepeatTrigger -EveryMinutes 60
  _RegisterIdempotent -TaskName "TinySocsRotateQueue" -ActionFactory {
    New-TinySocsTaskAction -ScriptPath $rotateScript -Args ""
  } -Trigger $rotateTrigger

  Write-Host "[TinySocs] Scheduled tasks registered."
}

# ── Environment + pairing ──────────────────────────────────────────────────────
function Set-MachineEnv([hashtable]$Vars){
  foreach($k in $Vars.Keys){
    $v = [string]$Vars[$k]

    # Persisted at machine scope (for future sessions / services)
    [Environment]::SetEnvironmentVariable($k, $v, 'Machine')

    # Also update current process so anything we launch *now*
    # (TinySocsNode.exe, TinySocsMaster.exe, etc.) sees the new values.
    [Environment]::SetEnvironmentVariable($k, $v, 'Process')
  }
  $md='[DllImport("user32.dll")] public static extern IntPtr SendMessageTimeout(IntPtr h,int m,IntPtr w,string l,int f,int t,out IntPtr r);'
  $t=Add-Type -MemberDefinition $md -Name 'W' -Namespace 'U' -PassThru; $z=[intptr]::Zero
  [U.W]::SendMessageTimeout([intptr]0xffff,0x1A,[intptr]0,'Environment',2,5000,[ref]$z) | Out-Null
}

function Pair-TinySocs{
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][ValidateSet('Node','Master')]$Role,
    [Parameter(Mandatory)][string]$SharedSecret,

    # Node-ish knobs
    [string]$NodePort='8081',

    # SIEM connection (URL is shared by node+master; creds are usually master-only)
    [string]$SiemUrl='https://localhost:9201',
    [string]$SiemUser,
    [string]$SiemPass,
    [bool]  $SiemSslVerify = $false,

    # Master knobs
    [string]$Nodes,
    [int]$AnchorsRetentionDays=45,
    [int]$HeartbeatMinutes=15
  )
  Install-TinySocs

  if($Role -eq 'Node'){
    # Store shared secret in CredMan for the node
    Set-TSCredential -Name 'TinySocs/Node/Secret' -Secret $SharedSecret

    $verifyString = if ($SiemSslVerify) { 'true' } else { 'false' }

    # Node shares the same MASTER_SHARED_SECRET as the master and talks to SIEM directly
    Set-MachineEnv @{
      MASTER_SHARED_SECRET = $SharedSecret
      PORT                 = $NodePort
      SIEM_URL             = $SiemUrl.TrimEnd('/')
      SIEM_SSL_VERIFY      = $verifyString
      PRIVACY_MODE         = 'abstract'
    }

    # Ensure service exists, then restart to pick up env
    if (-not (Get-Service TinySocsNode -ErrorAction SilentlyContinue)) {
      Register-TinySocsServices
    }

    $n = "C:\Program Files\TinySocs\bin\nssm.exe"
    if (Test-Path $n) {
      try { & $n restart TinySocsNode 2>$null | Out-Null } catch { }
    }

    Write-Host "[TinySocs] Node paired: PORT=$NodePort SIEM_URL=$SiemUrl"
    return
  }

  if($Role -eq 'Master'){
    # Store shared secret for the master
    Set-TSCredential -Name 'TinySocs/Master/SharedSecret' -Secret $SharedSecret

    # Nodes list can live in env/config; not strictly secret
    if (-not $Nodes) {
      # Default to local node if none supplied
      $Nodes = "http://127.0.0.1:$NodePort"
    }

    # If SIEM creds are provided, write them via helper (CredMan + env)
    if ($SiemUser -and $SiemPass) {
      Set-TinySocsSiemCredential -SiemUrl $SiemUrl -SiemUser $SiemUser -SiemPass $SiemPass -SiemSslVerify:$SiemSslVerify
    } else {
      # Still at least set URL + verify flag in env
      $verifyString = if ($SiemSslVerify) { 'true' } else { 'false' }
      Set-MachineEnv @{
        SIEM_URL        = $SiemUrl.TrimEnd('/')
        SIEM_SSL_VERIFY = $verifyString
      }
    }

    Set-MachineEnv @{
      MASTER_SHARED_SECRET   = $SharedSecret
      TINYSOCS_NODES         = $Nodes
      HEARTBEAT_MINUTES      = $HeartbeatMinutes
      ANCHORS_RETENTION_DAYS = $AnchorsRetentionDays
    }

    # Tasks read schedule + retention from env
    Register-TinySocsTasks

    Write-Host "[TinySocs] Master paired: NODES=$Nodes SIEM_URL=$SiemUrl HEARTBEAT=$HeartbeatMinutes RETENTION=$AnchorsRetentionDays"
  }
}

function Rotate-TinySocsSecrets([Parameter(Mandatory)][string]$SharedSecret){
  # Single source of truth now lives in CredMan, env is just delivery.
  Set-TSCredential -Name 'TinySocs/Node/Secret'         -Secret $SharedSecret
  Set-TSCredential -Name 'TinySocs/Master/SharedSecret' -Secret $SharedSecret

  Set-MachineEnv @{
    MASTER_SHARED_SECRET = $SharedSecret
  }

  $n = "C:\Program Files\TinySocs\bin\nssm.exe"
  if (Test-Path $n) {
    try { & $n restart TinySocsNode 2>$null | Out-Null } catch { }
  }

  Write-Host "[TinySocs] Secrets rotated (CredMan + env)."
}

# ── Uninstall (service, tasks, env, optional data) ─────────────────────────────
function Uninstall-TinySocs {
  [CmdletBinding()]
  param(
    [switch]$KeepData
  )

  $svcNames = @(
    "TinySocsNode",
    "TinySocsCollector",
    "TinySocsWinlogForwarder",
    "TinySocsOpenSearch"
  )
  $taskPath = "\TinySocs\"
  $binDir  = "C:\Program Files\TinySocs\bin"
  $appData = "$env:ProgramData\TinySocs"

  Write-Host "[TinySocs] Uninstall starting (KeepData=$KeepData)..."

  # Best-effort cleanup of stored credentials
  try {
    Remove-TSCredential -Name 'TinySocs/Node/Secret'
    Remove-TSCredential -Name 'TinySocs/Master/SharedSecret'
    Remove-TSCredential -Name 'TinySocs/SIEM/Creds'
  } catch { }

  # Stop scheduled tasks
  try {
    Get-ScheduledTask -TaskPath $taskPath -ErrorAction SilentlyContinue |
      Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
  } catch { }

  # Stop and remove TinySocs services (node, collector, local SIEM)
  $n = Join-Path $binDir "nssm.exe"
  foreach ($svcName in $svcNames) {
    try {
      Stop-Service $svcName -ErrorAction SilentlyContinue
    } catch { }

    if (Test-Path $n) {
      try { & $n remove $svcName confirm | Out-Null } catch { }
    } else {
      try { sc.exe delete $svcName | Out-Null } catch { }
    }
  }

  # Kill any stray processes that might be holding files open
  $procNames = @(
    "TinySocsNode",
    "TinySocsMaster",
    "TinySocsAnchors",
    "winlogbeat",
    "opensearch-service-x64",
    "opensearch-service-mgr"
  )
  foreach ($p in $procNames) {
    try {
      Get-Process $p -ErrorAction SilentlyContinue |
        Stop-Process -Force -ErrorAction SilentlyContinue
    } catch { }
  }

  # Clear machine env we know we set
  $vars = @(
    "PORT","NODE_PORT","SIEM_URL","SIEM_SSL_VERIFY",
    "SIEM_USER",
    "SIEM_PASS",
    "PRIVACY_MODE","NODE_SECRET","MASTER_SHARED_SECRET",
    "TINYSOCS_NODES","HEARTBEAT_MINUTES","ANCHORS_RETENTION_DAYS",
    "ALWAYS_ANCHOR","MASTER_DEADLINE_SEC"
  )
  foreach ($v in $vars) {
    [Environment]::SetEnvironmentVariable($v, $null, 'Machine')
  }

  if (-not $KeepData) {
    try { Remove-Item -Recurse -Force $appData -ErrorAction SilentlyContinue } catch { }
  }

  # Best-effort removal of the actual install root (e.g. C:\Program Files\TinySocs)
  try {
    $installRoot = Get-TinySocsInstallRoot
    if ($installRoot -and (Test-Path $installRoot -PathType Container)) {
      Write-TinySocsLog "Removing TinySocs install root at $installRoot"
      Remove-Item -Recurse -Force $installRoot -ErrorAction SilentlyContinue
    }
  } catch {
    Write-TinySocsLog -Level "WARN" -Message ("Failed to remove TinySocs install root: {0}" -f $_.Exception.Message)
  }

  Write-Host "[TinySocs] Uninstall complete."
}

Export-ModuleMember -Function Install-TinySocs,Install-TinySocsLocalSiem,Install-TinySocsCollector,Register-TinySocsServices,Register-TinySocsTasks,Pair-TinySocs,Rotate-TinySocsSecrets,Uninstall-TinySocs,Set-TSCredential,Get-TSCredential,Remove-TSCredential,Set-TinySocsSiemCredential,Get-TinySocsDataRoot,Write-TinySocsLog
