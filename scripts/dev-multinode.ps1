param(
  [int]$NodeCount = 2,
  [string]$Rules = "auth_failed_burst,ps_script_block",
  [string]$Window = "15m",
  [string]$Host = ""
)

$ErrorActionPreference = "Stop"

# Shared secret for dev
if (-not $env:NODE_SECRET) { $env:NODE_SECRET = "dev-secret-change-me" }

# Base port & start nodes
$basePort = 8081
$nodeUrls = @()
for ($i = 0; $i -lt $NodeCount; $i++) {
  $port = $basePort + $i
  $env:NODE_ID = "node-$($i+1)"
  $env:PORT = "$port"
  if (-not $env:SIEM_BACKEND) { $env:SIEM_BACKEND = "opensearch" }
  if (-not $env:SIEM_URL)     { $env:SIEM_URL = "https://localhost:9201" }

  Write-Host "Starting $env:NODE_ID on port $port..."
  Start-Process -FilePath "python" -ArgumentList "tinysocs\api\node.py" -NoNewWindow | Out-Null
  $nodeUrls += "http://localhost:$port"
}

# Master env
$env:TINYSOCS_NODES = ($nodeUrls -join ",")
$env:MASTER_SHARED_SECRET = $env:NODE_SECRET

Start-Sleep -Seconds 1
Write-Host "Nodes: $($env:TINYSOCS_NODES)"

# Run master
$masterArgs = @("--rules", $Rules, "--window", $Window)
if ($Host) { $masterArgs += @("--host", $Host) }

Write-Host "Running master once: rules=$Rules window=$Window host=$Host"
python "tinysocs\orchestrator\master.py" @masterArgs
