param(
  [switch]$Ensure,
  [switch]$Prune,
  [int]$RetentionDays = 45
)

function Write-TS([string]$msg) {
  try { Write-Host "[TinySocs] Launch-Anchors: $msg" } catch { }
}

$installRoot = Join-Path $env:ProgramFiles "TinySocs"
$exe = Join-Path $installRoot "bin\TinySocsAnchors.exe"

if (-not (Test-Path $exe)) {
  Write-Error "[TinySocs] Launch-Anchors: TinySocsAnchors.exe not found at $exe"
  exit 1
}

$logDir = Join-Path $env:ProgramData "TinySocs\logs"
if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Force -Path $logDir | Out-Null }

$logOut = Join-Path $logDir "TinySocsAnchors.out.log"
$logErr = Join-Path $logDir "TinySocsAnchors.err.log"

try {
  if ($Ensure) {
    & $exe --ensure 1>> $logOut 2>> $logErr
  }
  elseif ($Prune) {
    & $exe --prune --retention-days $RetentionDays 1>> $logOut 2>> $logErr
  }
  else {
    & $exe --help 1>> $logOut 2>> $logErr
  }

  $code = 0
  if ($LASTEXITCODE -ne $null) { $code = [int]$LASTEXITCODE }

  # Normalize “benign/no-op” anchor return codes
  if ($code -in @(0,2)) { $code = 0 }

  Write-TS "ExitCode=$code (raw=$LASTEXITCODE)"
  exit $code
}
catch {
  Write-TS "Exception: $($_.Exception.Message)"
  exit 1
}
