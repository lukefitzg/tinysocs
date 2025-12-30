param(
  [string]$AdminUser = "admin",
  [string]$AdminPass = "secret",
  [int]$Port = 9201
)

$ErrorActionPreference = "Stop"

function Wait-OpenSearchReady {
  param([int]$Port = 9201, [int]$TimeoutSeconds = 180, [string]$User, [string]$Pass)

  $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
  while ((Get-Date) -lt $deadline) {
    try {
      # -sS kills the progress spam that was tripping your console
      $r = & curl.exe -sS -k -u ("{0}:{1}" -f $User,$Pass) "https://localhost:$Port/_cluster/health?pretty" 2>$null
      if ($LASTEXITCODE -eq 0 -and $r -match '"status"\s*:\s*"(green|yellow)"') { return $true }
    } catch { }
    Start-Sleep 2
  }
  return $false
}

function Assert-LeafFile([string]$Path) {
  if (Test-Path $Path -PathType Container) { throw "POISON: $Path is a directory, expected file." }
  if (-not (Test-Path $Path -PathType Leaf)) { throw "MISSING: $Path" }
}

# ---- Paths ----
$installRoot = "C:\Program Files\TinySocs"
$osRoot      = Join-Path $installRoot "OpenSearch"
$pdConf      = "C:\ProgramData\TinySocs\OpenSearch\config"
$yml         = Join-Path $pdConf "opensearch.yml"
$logsErr     = "C:\ProgramData\TinySocs\OpenSearch\logs\TinySocsOpenSearch.err.log"

# ---- Import module ----
$mod = Join-Path $installRoot "modules\TinySocs.Installer.psm1"
if (-not (Test-Path $mod)) { throw "Module not found at $mod" }
Import-Module $mod -Force

Write-Host "`n=== TEST 0: baseline seed + start ==="
Stop-Service TinySocsOpenSearch -Force -ErrorAction SilentlyContinue
Ensure-TinySocsOpenSearchProgramDataConfig -OpenSearchRoot $osRoot -ProgramDataConf $pdConf -Force
Start-Service TinySocsOpenSearch

if (-not (Wait-OpenSearchReady -Port $Port -TimeoutSeconds 180 -User $AdminUser -Pass $AdminPass)) {
  if (Test-Path $logsErr) { Get-Content $logsErr -Tail 200 }
  throw "OpenSearch did not become ready (baseline)."
}

& curl.exe -sS -k -u ("{0}:{1}" -f $AdminUser,$AdminPass) "https://localhost:$Port/_cluster/health?pretty"
Write-Host "OK: baseline health"

Write-Host "`n=== TEST 1: mandatory files are leaf files ==="
Assert-LeafFile (Join-Path $pdConf "jvm.options")
Assert-LeafFile (Join-Path $pdConf "log4j2.properties")
Assert-LeafFile (Join-Path $pdConf "opensearch.keystore")
Assert-LeafFile (Join-Path $pdConf "opensearch.yml")
Write-Host "OK: mandatory files present"

Write-Host "`n=== TEST 2: poison jvm.options (directory), then recover via ProgramData reseed ==="
Stop-Service TinySocsOpenSearch -Force -ErrorAction SilentlyContinue
$poison = Join-Path $pdConf "jvm.options"
if (Test-Path $poison) { Remove-Item -Recurse -Force -LiteralPath $poison -ErrorAction SilentlyContinue }
New-Item -ItemType Directory -Path $poison | Out-Null

# expected: start fails (or runner self-heals; either is fine)
try { Start-Service TinySocsOpenSearch } catch { }

# Force reseed should fix poison
Stop-Service TinySocsOpenSearch -Force -ErrorAction SilentlyContinue
Ensure-TinySocsOpenSearchProgramDataConfig -OpenSearchRoot $osRoot -ProgramDataConf $pdConf -Force
Start-Service TinySocsOpenSearch

if (-not (Wait-OpenSearchReady -Port $Port -TimeoutSeconds 180 -User $AdminUser -Pass $AdminPass)) {
  if (Test-Path $logsErr) { Get-Content $logsErr -Tail 200 }
  throw "Did not recover after ProgramData reseed from poisoned jvm.options."
}
Assert-LeafFile (Join-Path $pdConf "jvm.options")
Write-Host "OK: recovered from jvm.options poison"

Write-Host "`n=== TEST 3: duplicate YAML key injection, then repair with dedupe helper ==="
# backup yml
$ymlBak = "$yml.bak-" + (Get-Date -Format "yyyyMMdd-HHmmss")
Copy-Item -Force -LiteralPath $yml -Destination $ymlBak

$key = "plugins.security.allow_default_init_securityindex"

try {
  # inject duplicate
  Add-Content -LiteralPath $yml -Value ("`n{0}: true`n" -f $key)

  Stop-Service TinySocsOpenSearch -Force -ErrorAction SilentlyContinue
  try { Start-Service TinySocsOpenSearch } catch { }

  # if it *does* come up, injection didn't actually duplicate or parser behavior changed
  if (Wait-OpenSearchReady -Port $Port -TimeoutSeconds 45 -User $AdminUser -Pass $AdminPass) {
    Write-Host "NOTE: OpenSearch still came up after injection (either key not duplicated, or parsing behavior changed)."
  } else {
    # now repair
    Repair-TinySocsOpenSearchYamlKeyDedupe -ConfigPath $yml -Key $key -Value "true"

    Start-Service TinySocsOpenSearch
    if (-not (Wait-OpenSearchReady -Port $Port -TimeoutSeconds 180 -User $AdminUser -Pass $AdminPass)) {
      if (Test-Path $logsErr) { Get-Content $logsErr -Tail 200 }
      throw "Did not recover after YAML key dedupe repair."
    }

    $cnt = (Select-String -LiteralPath $yml -Pattern "^\s*$([regex]::Escape($key))\s*:" -AllMatches).Matches.Count
    if ($cnt -ne 1) { throw "Dedup check failed: expected 1 occurrence of $key, found $cnt" }

    Write-Host "OK: recovered from duplicate YAML key"
  }
}
finally {
  # restore original yml to avoid leaving the box mutated after the test
  Copy-Item -Force -LiteralPath $ymlBak -Destination $yml
}

Write-Host "`n=== FINAL: cluster health ==="
& curl.exe -sS -k -u ("{0}:{1}" -f $AdminUser,$AdminPass) "https://localhost:$Port/_cluster/health?pretty"
Write-Host "`nALL TESTS PASSED."