<#
.SYNOPSIS
    Install and configure the TinySocs OpenSearch local SIEM instance ("TinyBox").

.DESCRIPTION
    - Assumes TinySocs is installed under: C:\Program Files\TinySocs
    - Assumes OpenSearch distro already laid out under: C:\Program Files\TinySocs\OpenSearch
      with bin\opensearch.bat present.
    - Assumes nssm.exe is available at: C:\Program Files\TinySocs\bin\nssm.exe

    What it does:
    - Creates ProgramData paths for OpenSearch data/logs.
    - Writes opensearch.yml (unless it already exists, unless -ForceConfig).
    - Registers/updates an NSSM-based Windows service: TinySocsOpenSearch.
    - Optionally starts the service.

    Idempotent:
    - Safe to run multiple times; it will reconcile state.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$ClusterName = "tinysocs-local",
    [string]$NodeName    = "tinysocs-node-1",
    [int]   $HttpPort    = 9200,

    # Overwrite existing opensearch.yml if present
    [switch]$ForceConfig,

    # Start the service after install/update
    [switch]$StartService = $true
)

function Get-TinySocsInstallRoot {
    # Assumes this script is installed under C:\Program Files\TinySocs\modules\
    if ($PSScriptRoot) {
        return (Split-Path -Parent $PSScriptRoot)
    }

    # Fallback for weird hosts: last resort guess.
    return "C:\Program Files\TinySocs"
}

function Write-TinySocsOpenSearchConfig {
    param(
        [string]$ConfigPath,
        [string]$ClusterName,
        [string]$NodeName,
        [int]   $HttpPort,
        [string]$DataPath,
        [string]$LogsPath
    )

    if (Test-Path $ConfigPath -PathType Leaf -and -not $ForceConfig.IsPresent) {
        Write-Verbose "opensearch.yml already exists and -ForceConfig not set; leaving as-is: $ConfigPath"
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

# TinyBox: local-only, no auth for now. Harden later.
plugins.security.disabled: true

"@

    $configDir = Split-Path -Parent $ConfigPath
    if (-not (Test-Path $configDir)) {
        New-Item -ItemType Directory -Force -Path $configDir | Out-Null
    }

    Write-Verbose "Writing OpenSearch config to $ConfigPath"
    $configContent | Out-File -FilePath $ConfigPath -Encoding UTF8 -Force
}

function Ensure-TinySocsOpenSearchService {
    param(
        [string]$InstallRoot,
        [string]$OpenSearchRoot,
        [string]$NssmPath,
        [string]$ServiceName,
        [string]$DisplayName,
        [string]$Description
    )

    if (-not (Test-Path $NssmPath -PathType Leaf)) {
        throw "nssm.exe not found at '$NssmPath'. Ensure the TinySocs installer copies nssm.exe to bin\ before running this."
    }

    $exePath = Join-Path $OpenSearchRoot "bin\opensearch.bat"
    if (-not (Test-Path $exePath -PathType Leaf)) {
        throw "OpenSearch executable not found at '$exePath'. Ensure OpenSearch is installed under '$OpenSearchRoot'."
    }

    $confPath = Join-Path $OpenSearchRoot "config"
    $confEnv  = "OPENSEARCH_PATH_CONF=$confPath"

    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

    if ($null -eq $service) {
        Write-Verbose "Creating NSSM service '$ServiceName' for TinySocs OpenSearch"

        & $NssmPath install $ServiceName $exePath | Out-Null
    }
    else {
        Write-Verbose "Service '$ServiceName' already exists; updating NSSM configuration"
    }

    # Common configuration (idempotent)
    & $NssmPath set $ServiceName DisplayName  $DisplayName  | Out-Null
    & $NssmPath set $ServiceName Description  $Description  | Out-Null
    & $NssmPath set $ServiceName AppDirectory $OpenSearchRoot | Out-Null
    & $NssmPath set $ServiceName AppEnvironmentExtra $confEnv | Out-Null

    # Service identity and startup type
    & $NssmPath set $ServiceName ObjectName "LocalSystem" | Out-Null
    & $NssmPath set $ServiceName Start "SERVICE_DELAYED_AUTO_START" | Out-Null

    # Reasonable stop behaviour
    & $NssmPath set $ServiceName AppStopMethodConsole 15000 | Out-Null
    & $NssmPath set $ServiceName AppStopMethodSkip    0     | Out-Null

    # Restart on failure (optional, but helpful)
    & $NssmPath set $ServiceName AppExit Default Restart | Out-Null
}

if (-not $IsWindows) {
    throw "Install-TinySocsLocalSiem can only be run on Windows."
}

$installRoot    = Get-TinySocsInstallRoot
$openSearchRoot = Join-Path $installRoot "OpenSearch"
$dataRoot       = "C:\ProgramData\TinySocs\OpenSearch"
$dataPath       = Join-Path $dataRoot "data"
$logsPath       = Join-Path $dataRoot "logs"

$nssmPath       = Join-Path $installRoot "bin\nssm.exe"
$serviceName    = "TinySocsOpenSearch"
$displayName    = "TinySocs OpenSearch (TinyBox Local SIEM)"
$description    = "Local OpenSearch instance for TinySocs TinyBox SIEM"

Write-Verbose "TinySocs install root: $installRoot"
Write-Verbose "OpenSearch root:      $openSearchRoot"
Write-Verbose "ProgramData root:     $dataRoot"
Write-Verbose "NSSM path:            $nssmPath"

# Ensure ProgramData directories
New-Item -ItemType Directory -Force -Path $dataPath | Out-Null
New-Item -ItemType Directory -Force -Path $logsPath | Out-Null

# Ensure OpenSearch config
$configFile = Join-Path $openSearchRoot "config\opensearch.yml"
Write-TinySocsOpenSearchConfig -ConfigPath $configFile `
    -ClusterName $ClusterName `
    -NodeName $NodeName `
    -HttpPort $HttpPort `
    -DataPath $dataPath `
    -LogsPath $logsPath

# Ensure service is present and configured
Ensure-TinySocsOpenSearchService -InstallRoot $installRoot `
    -OpenSearchRoot $openSearchRoot `
    -NssmPath $nssmPath `
    -ServiceName $serviceName `
    -DisplayName $displayName `
    -Description $description

if ($StartService.IsPresent) {
    if ($PSCmdlet.ShouldProcess($serviceName, "Start service")) {
        Write-Verbose "Starting service '$serviceName'"
        Start-Service -Name $serviceName -ErrorAction Stop
    }
}

Write-Verbose "Install-TinySocsLocalSiem completed."