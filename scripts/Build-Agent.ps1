# scripts/Build-Agent.ps1
# Deterministic C# agent build script for TinySocs.
# Produces a self-contained, single-file win-x64 executable.
#
# Usage:
#   .\scripts\Build-Agent.ps1
#   .\scripts\Build-Agent.ps1 -Configuration Debug -Runtime win-arm64

param(
    [string]$Configuration = "Release",
    [string]$Runtime = "win-x64"
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$projectPath = Join-Path $repoRoot "src" "TinySocs.Agent" "TinySocs.Agent.csproj"

if (-not (Test-Path $projectPath)) {
    throw "[Build-Agent] Agent project not found at: $projectPath"
}

Write-Host "[Build-Agent] Building $Configuration for $Runtime..."
Write-Host "[Build-Agent] Project: $projectPath"

dotnet publish $projectPath `
    -c $Configuration `
    -r $Runtime `
    --self-contained `
    -p:PublishSingleFile=true `
    -p:IncludeNativeLibrariesForSelfExtract=true

if ($LASTEXITCODE -ne 0) {
    throw "[Build-Agent] dotnet publish failed with exit code $LASTEXITCODE"
}

# Determine target framework from csproj
$csprojContent = Get-Content $projectPath -Raw
$tfm = "net8.0"
if ($csprojContent -match '<TargetFramework>([^<]+)</TargetFramework>') {
    $tfm = $Matches[1]
}

$outputDir = Join-Path $repoRoot "src" "TinySocs.Agent" "bin" $Configuration $tfm $Runtime "publish"
$exe = Join-Path $outputDir "TinySocs.Agent.exe"

if (Test-Path $exe) {
    $size = (Get-Item $exe).Length / 1MB
    Write-Host ("[Build-Agent] SUCCESS: {0} ({1:N1} MB)" -f $exe, $size)
} else {
    throw "[Build-Agent] FAILED: TinySocs.Agent.exe not found at $outputDir"
}
