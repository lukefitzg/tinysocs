# Ensure-TinySocsOpenSearchDeterministic.ps1
# Run elevated (Administrator). Intended to be called by installer / upgrade.
# Deterministic OpenSearch bootstrap for TinySocs (ProgramData config + TLS + security index verification)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

# ---- Paths / service ----
$svc         = "TinySocsOpenSearch"
$nssm        = "C:\Program Files\TinySocs\bin\nssm.exe"
$osRoot      = "C:\Program Files\TinySocs\OpenSearch"
$osConf      = Join-Path $osRoot "config"
$osLogs      = Join-Path $osRoot "logs"
$pdRoot      = "C:\ProgramData\TinySocs\OpenSearch"
$pdConf      = Join-Path $pdRoot "config"
$pdLogs      = Join-Path $pdRoot "logs"
$keystoreBat = Join-Path $osRoot "bin\opensearch-keystore.bat"

# Canonical TinySocs HTTP port
$canonicalPort = 9201

# ---- Helpers ----
function Ensure-Dir([string]$p) {
  if (-not (Test-Path -LiteralPath $p -PathType Container)) {
    New-Item -ItemType Directory -Path $p | Out-Null
  }
}

function Write-Utf8NoBom([string]$Path, [string]$Text) {
  if ($Text.Length -gt 0 -and [int]$Text[0] -eq 0xFEFF) { $Text = $Text.Substring(1) }
  $enc = New-Object System.Text.UTF8Encoding($false)
  [System.IO.File]::WriteAllText($Path, $Text, $enc)
}

function Ensure-SingleYamlKey {
  param(
    [Parameter(Mandatory)] [string]$Path,
    [Parameter(Mandatory)] [string]$Key,
    [Parameter(Mandatory)] [string]$Value
  )
  $lines = @()
  if (Test-Path -LiteralPath $Path -PathType Leaf) {
    $lines = Get-Content -LiteralPath $Path -ErrorAction Stop
  }
  $rx = "^\s*" + [regex]::Escape($Key) + "\s*:"
  $filtered = $lines | Where-Object { $_ -notmatch $rx }
  $out = $filtered + ("{0}: {1}" -f $Key, $Value)
  Write-Utf8NoBom -Path $Path -Text ($out -join "`r`n")
}

function Remove-YamlKey {
  param(
    [Parameter(Mandatory)] [string]$Path,
    [Parameter(Mandatory)] [string]$Key
  )
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return }
  $lines = Get-Content -LiteralPath $Path -ErrorAction Stop
  $rx = "^\s*" + [regex]::Escape($Key) + "\s*:"
  $filtered = $lines | Where-Object { $_ -notmatch $rx }
  Write-Utf8NoBom -Path $Path -Text ($filtered -join "`r`n")
}

function Disable-Efs([string]$Path) {
  & cipher.exe /d /a "$Path" | Out-Null
  & cipher.exe /d /a /s:"$Path" | Out-Null
}

function Test-ReadableFile([string]$Path) {
  try {
    $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    $fs.Close()
    return $true
  } catch { return $false }
}

function Tail-File([string]$Path, [int]$Tail = 200) {
  if (Test-Path -LiteralPath $Path -PathType Leaf) {
    Write-Host ""
    Write-Host ("--- tail {0}: {1} ---" -f $Tail, $Path) -ForegroundColor Yellow
    Get-Content -LiteralPath $Path -Tail $Tail -ErrorAction SilentlyContinue
  }
}

function Rotate-Log([string]$Path, [string]$Stamp) {
  if (Test-Path -LiteralPath $Path -PathType Leaf) {
    $dir  = Split-Path -Parent $Path
    $name = Split-Path -Leaf $Path
    $dst  = Join-Path $dir ($name + ".bak." + $Stamp)
    try { Move-Item -LiteralPath $Path -Destination $dst -Force } catch {}
  }
}

function Normalize-Password([string]$s) {
  if ($null -eq $s) { return $null }
  return ($s.Trim() -replace "`0+$","")
}

function Read-DpapiStorePass([string]$DpapiPath) {
  if (-not (Test-Path -LiteralPath $DpapiPath -PathType Leaf)) { throw "DPAPI file not found: $DpapiPath" }
  if (-not (Test-ReadableFile $DpapiPath)) { throw "DPAPI file exists but is not readable (EFS/ACL). Path: $DpapiPath" }

  $raw = $null
  try { $raw = (Get-Content -LiteralPath $DpapiPath -Raw -ErrorAction Stop).Trim() } catch {}

  # Some builds store base64 text "AQAAANCM..." not raw DPAPI bytes
  if (-not [string]::IsNullOrWhiteSpace($raw) -and $raw -match '^[A-Za-z0-9+/=]+$') {
    $dpapiBytes = [Convert]::FromBase64String($raw)
    $passBytes  = [System.Security.Cryptography.ProtectedData]::Unprotect(
      $dpapiBytes, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine
    )
    return [System.Text.Encoding]::UTF8.GetString($passBytes)
  }

  $bytes     = [System.IO.File]::ReadAllBytes($DpapiPath)
  $passBytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
    $bytes, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine
  )
  return [System.Text.Encoding]::UTF8.GetString($passBytes)
}

function Test-Pkcs12Password([string]$P12Path, [string]$Password) {
  try {
    $col   = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
    $flags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::DefaultKeySet
    $col.Import($P12Path, $Password, $flags) | Out-Null
    return $true
  } catch { return $false }
}

function Find-CertBundles([string[]]$Roots) {
  $need = @("http.p12","transport.p12","trust.p12","opensearch-tls-storepass.dpapi")
  $bundles = @()

  foreach ($r in $Roots | Where-Object { $_ -and (Test-Path -LiteralPath $_) }) {
    $certDirs = Get-ChildItem -LiteralPath $r -Recurse -Directory -ErrorAction SilentlyContinue |
      Where-Object { $_.Name -ieq "certs" }

    foreach ($d in $certDirs) {
      $paths = @{}
      $ok = $true
      foreach ($f in $need) {
        $p = Join-Path $d.FullName $f
        if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { $ok = $false; break }
        if (-not (Test-ReadableFile $p)) { $ok = $false; break }
        $paths[$f] = $p
      }
      if ($ok) {
        $stamp = (Get-Item $paths["opensearch-tls-storepass.dpapi"]).LastWriteTime
        $bundles += [pscustomobject]@{
          CertDir   = $d.FullName
          Stamp     = $stamp
          Http      = $paths["http.p12"]
          Transport = $paths["transport.p12"]
          Trust     = $paths["trust.p12"]
          Dpapi     = $paths["opensearch-tls-storepass.dpapi"]
        }
      }
    }
  }

  $bundles | Sort-Object Stamp -Descending
}

function Wait-Port([int]$Port, [int]$TimeoutSeconds = 300) {
  $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
  while ((Get-Date) -lt $deadline) {
    try {
      if (Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction Stop) { return $true }
    } catch {}
    Start-Sleep 2
  }
  return $false
}

function Curl-Json([string]$url) {
  $out = & curl.exe -sk -u "admin:secret" $url
  if ($LASTEXITCODE -ne 0) { throw "curl failed (exit $LASTEXITCODE) for $url" }
  if ([string]::IsNullOrWhiteSpace($out)) { return $null }
  return $out | ConvertFrom-Json
}

function Test-SecurityIndexReady([int]$port) {
  try {
    $rows = Curl-Json "https://localhost:$port/_cat/indices/.opendistro_security?format=json"
    if (-not $rows -or $rows.Count -lt 1) { return $false }

    $r = $rows[0]
    $docs = 0
    [void][int]::TryParse([string]$r."docs.count", [ref]$docs)

    return ($r.status -eq "open" -and $docs -gt 0 -and $r.health -ne "red")
  } catch { return $false }
}

function Ensure-OpenSearchSecurityConfig([string]$PdConf, [string]$OsRoot) {
  $dst = Join-Path $PdConf "opensearch-security"
  if (Test-Path -LiteralPath $dst -PathType Container) { return }

  Ensure-Dir $dst
  Disable-Efs $dst

  $seed1 = Join-Path $OsRoot "plugins\opensearch-security\securityconfig"
  $seed2 = Join-Path $OsRoot "config\opensearch-security"

  $seed = $null
  if (Test-Path -LiteralPath $seed1 -PathType Container) { $seed = $seed1 }
  elseif (Test-Path -LiteralPath $seed2 -PathType Container) { $seed = $seed2 }

  if ($seed) {
    Copy-Item -LiteralPath (Join-Path $seed "*") -Destination $dst -Recurse -Force
  } else {
    Write-Host "WARNING: Could not find securityconfig seed dir to copy. Created empty: $dst" -ForegroundColor Yellow
  }
}

function Invoke-OpensearchKeystoreAddSecure {
  param(
    [Parameter(Mandatory)] [string]$KeystoreBat,
    [Parameter(Mandatory)] [string]$Key,
    [Parameter(Mandatory)] [string]$Value
  )
  if (-not (Test-Path -LiteralPath $KeystoreBat -PathType Leaf)) { throw "Keystore bat missing: $KeystoreBat" }

  # run .bat via cmd.exe so we can reliably feed stdin
  $p = New-Object System.Diagnostics.Process
  $p.StartInfo.FileName = "cmd.exe"
  $p.StartInfo.Arguments = "/c `"$KeystoreBat`" add -x -f $Key"
  $p.StartInfo.UseShellExecute = $false
  $p.StartInfo.RedirectStandardInput = $true
  $p.StartInfo.RedirectStandardOutput = $true
  $p.StartInfo.RedirectStandardError = $true
  $p.StartInfo.CreateNoWindow = $true

  [void]$p.Start()
  $p.StandardInput.WriteLine($Value)
  $p.StandardInput.Close()

  $stdout = $p.StandardOutput.ReadToEnd()
  $stderr = $p.StandardError.ReadToEnd()
  $p.WaitForExit()

  if ($p.ExitCode -ne 0) {
    throw "opensearch-keystore add failed for [$Key] (exit=$($p.ExitCode)). stderr=$stderr stdout=$stdout"
  }
}

try {
  $stamp = Get-Date -Format "yyyyMMdd-HHmmss"

  Write-Host "=== STOPPING SERVICE ==="
  if (Test-Path -LiteralPath $nssm) { & $nssm stop $svc 2>$null | Out-Null }
  Stop-Service $svc -Force -ErrorAction SilentlyContinue
  Start-Sleep 2

  Ensure-Dir $pdRoot
  Ensure-Dir $pdLogs

  Write-Host "=== ROTATE LOGS (SO TAIL IS THIS RUN) ==="
  Rotate-Log -Path (Join-Path $pdLogs "TinySocsOpenSearch.wrapper.err.log") -Stamp $stamp
  Rotate-Log -Path (Join-Path $pdLogs "TinySocsOpenSearch.err.log")         -Stamp $stamp
  Rotate-Log -Path (Join-Path $osLogs "opensearch.log")                     -Stamp $stamp

  Write-Host "=== BACKUP EXISTING ProgramData CONFIG ==="
  $backup = Join-Path $pdRoot ("config.bad." + $stamp)
  if (Test-Path -LiteralPath $pdConf -PathType Container) {
    Move-Item -LiteralPath $pdConf -Destination $backup -Force
  }

  Write-Host "=== RECREATE CLEAN CONFIG TREE ==="
  Ensure-Dir $pdConf
  Disable-Efs $pdConf

  Write-Host "=== SEED FROM Program Files CONFIG ==="
  if (-not (Test-Path -LiteralPath $osConf -PathType Container)) { throw "Seed config dir missing: $osConf" }
  Copy-Item -LiteralPath (Join-Path $osConf "*") -Destination $pdConf -Recurse -Force
  & attrib.exe -R -S -H "$pdConf\*" /S /D | Out-Null
  & icacls.exe "$pdConf" /inheritance:e /grant "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" /t /c | Out-Null

  Write-Host "=== ENSURE opensearch-security YAMLs EXIST ==="
  Ensure-OpenSearchSecurityConfig -PdConf $pdConf -OsRoot $osRoot

  Write-Host "=== FIX jvm.options + opensearch.yml ENCODING (NO BOM) ==="
  $jvmSrc = Join-Path $osConf "jvm.options"
  $jvmDst = Join-Path $pdConf "jvm.options"
  $ymlSrc = Join-Path $osConf "opensearch.yml"
  $ymlDst = Join-Path $pdConf "opensearch.yml"
  if (-not (Test-Path -LiteralPath $jvmSrc)) { throw "Missing $jvmSrc" }
  if (-not (Test-Path -LiteralPath $ymlSrc)) { throw "Missing $ymlSrc" }
  Write-Utf8NoBom -Path $jvmDst -Text (Get-Content -LiteralPath $jvmSrc -Raw)
  Write-Utf8NoBom -Path $ymlDst -Text (Get-Content -LiteralPath $ymlSrc -Raw)

  Write-Host "=== LOCATE CERT BUNDLE (http/transport/trust + dpapi) ==="
  $roots   = @($pdRoot,$osRoot,$osConf) | Where-Object { $_ -and (Test-Path -LiteralPath $_) }
  $bundles = Find-CertBundles -Roots $roots
  if (-not $bundles -or $bundles.Count -lt 1) {
    throw "No readable cert bundle found under: $($roots -join ', ')"
  }
  $b = $bundles | Select-Object -First 1
  Write-Host ("Using cert bundle: {0}" -f $b.CertDir)

  Write-Host "=== COPY CERTS + STOREPASS INTO ProgramData CONFIG ==="
  $certDir = Join-Path $pdConf "certs"
  Ensure-Dir $certDir
  Disable-Efs $certDir
  & icacls.exe "$certDir" /inheritance:e /grant "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" /t /c | Out-Null

  Copy-Item -LiteralPath $b.Http      -Destination (Join-Path $certDir "http.p12")      -Force
  Copy-Item -LiteralPath $b.Transport -Destination (Join-Path $certDir "transport.p12") -Force
  Copy-Item -LiteralPath $b.Trust     -Destination (Join-Path $certDir "trust.p12")     -Force
  $dpapiDst = Join-Path $certDir "opensearch-tls-storepass.dpapi"
  Copy-Item -LiteralPath $b.Dpapi -Destination $dpapiDst -Force

  Write-Host "=== DECRYPT STOREPASS + VALIDATE PKCS12 ==="
  $storePass = Normalize-Password (Read-DpapiStorePass -DpapiPath $dpapiDst)
  if ($null -eq $storePass -or $storePass.Length -lt 1) { throw "Decrypted storePass was empty/null." }

  foreach ($p in @(
    (Join-Path $certDir "http.p12"),
    (Join-Path $certDir "transport.p12"),
    (Join-Path $certDir "trust.p12")
  )) {
    if (-not (Test-Pkcs12Password -P12Path $p -Password $storePass)) {
      throw "DPAPI storepass does not open PKCS12: $p"
    }
  }
  Write-Host ("PKCS12 validation OK (storepass length = {0})." -f $storePass.Length)

  Write-Host "=== ENFORCE TLS + PORT + NO DUPLICATE YAML KEYS ==="
  Ensure-SingleYamlKey $ymlDst "http.port" "$canonicalPort"
  Ensure-SingleYamlKey $ymlDst "plugins.security.allow_default_init_securityindex" "true"

  Ensure-SingleYamlKey $ymlDst "plugins.security.ssl.http.enabled" "true"
  Ensure-SingleYamlKey $ymlDst "plugins.security.ssl.http.keystore_type" "PKCS12"
  Ensure-SingleYamlKey $ymlDst "plugins.security.ssl.http.truststore_type" "PKCS12"
  Ensure-SingleYamlKey $ymlDst "plugins.security.ssl.transport.keystore_type" "PKCS12"
  Ensure-SingleYamlKey $ymlDst "plugins.security.ssl.transport.truststore_type" "PKCS12"

  Ensure-SingleYamlKey $ymlDst "plugins.security.ssl.http.keystore_filepath" "certs/http.p12"
  Ensure-SingleYamlKey $ymlDst "plugins.security.ssl.http.truststore_filepath" "certs/trust.p12"
  Ensure-SingleYamlKey $ymlDst "plugins.security.ssl.transport.keystore_filepath" "certs/transport.p12"
  Ensure-SingleYamlKey $ymlDst "plugins.security.ssl.transport.truststore_filepath" "certs/trust.p12"

  Write-Host "=== RECREATE opensearch.keystore + OVERWRITE *_secure ENTRIES ==="
  $keystore = Join-Path $pdConf "opensearch.keystore"
  if (Test-Path -LiteralPath $keystore -PathType Leaf) {
    Remove-Item -LiteralPath $keystore -Force -ErrorAction SilentlyContinue
  }

  $old = $env:OPENSEARCH_PATH_CONF
  try {
    $env:OPENSEARCH_PATH_CONF = $pdConf

    & $keystoreBat create | Out-Null

    # Overwrite secure entries with decrypted storepass (this is the persistent fix)
    $secureKeys = @(
      "plugins.security.ssl.http.keystore_password_secure",
      "plugins.security.ssl.http.keystore_keypassword_secure",
      "plugins.security.ssl.http.truststore_password_secure",
      "plugins.security.ssl.transport.keystore_password_secure",
      "plugins.security.ssl.transport.keystore_keypassword_secure",
      "plugins.security.ssl.transport.truststore_password_secure"
    )

    foreach ($k in $secureKeys) {
      Invoke-OpensearchKeystoreAddSecure -KeystoreBat $keystoreBat -Key $k -Value $storePass
    }
  }
  finally {
    $env:OPENSEARCH_PATH_CONF = $old
  }

  Write-Host "=== ENSURE PLAINTEXT PASSWORDS ARE NOT LEFT IN YAML ==="
  foreach ($k in @(
    "plugins.security.ssl.http.keystore_password",
    "plugins.security.ssl.http.keystore_keypassword",
    "plugins.security.ssl.http.truststore_password",
    "plugins.security.ssl.transport.keystore_password",
    "plugins.security.ssl.transport.keystore_keypassword",
    "plugins.security.ssl.transport.truststore_password"
  )) {
    Remove-YamlKey -Path $ymlDst -Key $k
  }

  Write-Host "=== FINAL PERMISSIONS PASS ==="
  & icacls.exe "$pdConf" /inheritance:e /grant "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" /t /c | Out-Null
  Disable-Efs $pdConf

  Write-Host "=== START SERVICE ==="
  if (Test-Path -LiteralPath $nssm) { & $nssm start $svc | Out-Null } else { Start-Service $svc }

  Write-Host ("=== WAIT FOR LISTENER (port {0}) ===" -f $canonicalPort)
  if (-not (Wait-Port -Port $canonicalPort -TimeoutSeconds 300)) {
    # If 9200 comes up instead, call it drift and fail loudly.
    $drift = $false
    try { if (Get-NetTCPConnection -LocalPort 9200 -State Listen -ErrorAction Stop) { $drift = $true } } catch {}
    if ($drift) { throw "OpenSearch came up on 9200 (drift). Expected 9201. Check opensearch.yml in ProgramData." }
    throw "OpenSearch did not start listening on $canonicalPort."
  }

  Write-Host "=== HEALTH CHECK ==="
  $health = & curl.exe -sk -u "admin:secret" "https://localhost:$canonicalPort/_cluster/health?pretty"
  if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($health)) { throw "curl health check failed on $canonicalPort." }
  Write-Host $health

  Write-Host "=== VERIFY SECURITY INDEX ==="
  for ($i=0; $i -lt 60; $i++) {
    if (Test-SecurityIndexReady -port $canonicalPort) {
      $row = (Curl-Json "https://localhost:$canonicalPort/_cat/indices/.opendistro_security?format=json")[0]
      Write-Host "OK: .opendistro_security present (health=$($row.health), docs=$($row.'docs.count'))." -ForegroundColor Green
      Write-Host "`nOK: OpenSearch deterministic bootstrap complete."
      exit 0
    }
    Start-Sleep 2
  }
  throw "Security index (.opendistro_security) did not become ready in time."
}
catch {
  Write-Host ""
  Write-Host ("FAILED: " + $_.Exception.Message) -ForegroundColor Red
  Tail-File -Path (Join-Path $pdLogs "TinySocsOpenSearch.wrapper.err.log") -Tail 260
  Tail-File -Path (Join-Path $pdLogs "TinySocsOpenSearch.err.log")         -Tail 260
  Tail-File -Path (Join-Path $osLogs "opensearch.log")                     -Tail 320
  throw
}