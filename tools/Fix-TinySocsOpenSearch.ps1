# tools\Fix-TinySocsOpenSearch.ps1
# One-shot recovery: fix ACLs + rebuild opensearch.keystore with ASCII-safe secure settings
# Then start service and probe endpoint.

$ErrorActionPreference = 'Stop'

$Svc     = 'TinySocsOpenSearch'
$OS_HOME = 'C:\Program Files\TinySocs\OpenSearch'
$Conf    = Join-Path $env:ProgramData 'TinySocs\OpenSearch\config'
$Certs   = Join-Path $Conf 'certs'
$Dpapi   = Join-Path $Certs 'opensearch-tls-storepass.dpapi'
$KeystoreFile = Join-Path $Conf 'opensearch.keystore'

function Exec-Cmd {
  param([Parameter(Mandatory)][string]$Cmd)

  # Make sure we hand cmd.exe a single line.
  $oneLine = ($Cmd -replace "(\r\n|\n|\r)", " ").Trim()

  $outFile = Join-Path $env:TEMP 'tinysocs_cmd_out.txt'
  $errFile = Join-Path $env:TEMP 'tinysocs_cmd_err.txt'
  Remove-Item $outFile, $errFile -Force -ErrorAction SilentlyContinue

  # Wrap with an extra quoting layer so cmd parses it consistently.
  $p = Start-Process -FilePath "cmd.exe" `
    -ArgumentList "/d","/s","/c","""$oneLine""" `
    -Wait -PassThru -NoNewWindow `
    -RedirectStandardOutput $outFile -RedirectStandardError $errFile

  $out = (Get-Content $outFile -ErrorAction SilentlyContinue) -join "`n"
  $err = (Get-Content $errFile -ErrorAction SilentlyContinue) -join "`n"
  return [pscustomobject]@{ ExitCode=$p.ExitCode; Stdout=$out; Stderr=$err; Cmd=$oneLine }
}

function Assert-Ascii([string]$s, [string]$name) {
  if ([string]::IsNullOrEmpty($s)) { throw "$name is empty" }
  $bytes = [Text.Encoding]::ASCII.GetBytes($s)
  $round = [Text.Encoding]::ASCII.GetString($bytes)
  if ($round -ne $s) { throw "$name contains non-ASCII characters; OpenSearch will choke on it." }
  if ($s.IndexOf([char]0) -ge 0) { throw "$name contains NUL bytes (embedded \0). This usually means UTF-16 leakage." }
}

function Read-DpapiBase64LocalMachine([string]$path) {
  Add-Type -AssemblyName System.Security | Out-Null
  $b64 = (Get-Content -LiteralPath $path -Raw).Trim()
  $enc = [Convert]::FromBase64String($b64)
  $plain = [Security.Cryptography.ProtectedData]::Unprotect(
    $enc, $null, [Security.Cryptography.DataProtectionScope]::LocalMachine
  )
  # Try UTF-8 first, fall back to ASCII. We enforce ASCII afterwards.
  $s = [Text.Encoding]::UTF8.GetString($plain).Trim([char]0, "`r", "`n", " ")
  if (-not $s) { $s = [Text.Encoding]::ASCII.GetString($plain).Trim([char]0, "`r", "`n", " ") }
  return $s
}

function Test-P12([string]$p12Path, [string]$pass) {
  $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
  $cert.Import($p12Path, $pass, 'PersistKeySet')
  return $cert.Subject
}

function Set-OsSecureSetting([string]$key, [string]$value) {
  Assert-Ascii $value $key

  $tmp = [IO.Path]::Combine($env:TEMP, "tinysocs_keystore_" + [Guid]::NewGuid().ToString("N") + ".txt")
  # Write raw ASCII bytes + newline so input redirection stays byte-clean.
  [IO.File]::WriteAllBytes($tmp, [Text.Encoding]::ASCII.GetBytes($value + "`n"))

  # IMPORTANT: normal quoting + set "VAR=VALUE"
  $cmd = "set ""OPENSEARCH_PATH_CONF=$Conf"" && ""$OS_HOME\bin\opensearch-keystore.bat"" add -x -f $key < ""$tmp"""
  $res = Exec-Cmd $cmd

  Remove-Item $tmp -Force -ErrorAction SilentlyContinue

  if ($res.ExitCode -ne 0) {
    throw "Failed to write secure setting [$key]. exit=$($res.ExitCode) stderr=$($res.Stderr)"
  }
}

"=== 0) Stop service ==="
try { Stop-Service -Name $Svc -Force -ErrorAction SilentlyContinue } catch {}
Start-Sleep -Seconds 2

"=== 1) Fix ACLs on ProgramData config (SYSTEM must be able to read everything) ==="
if (-not (Test-Path $Conf)) { throw "Missing config dir: $Conf" }
& icacls $Conf /inheritance:e /grant "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" "Users:(OI)(CI)RX" /T | Out-Null

"=== 2) Load TLS storepass from DPAPI (base64 -> DPAPI LocalMachine) ==="
if (-not (Test-Path $Dpapi)) { throw "Missing DPAPI storepass file: $Dpapi" }
$storePass = Read-DpapiBase64LocalMachine $Dpapi
Assert-Ascii $storePass "TLS storepass"
"TLS storepass: ASCII OK, len=$($storePass.Length)"

"=== 3) Validate P12s open with storepass ==="
$httpP12      = Join-Path $Certs 'http.p12'
$transportP12 = Join-Path $Certs 'transport.p12'
$trustP12     = Join-Path $Certs 'trust.p12'
foreach ($p in @($httpP12,$transportP12,$trustP12)) {
  if (-not (Test-Path $p)) { throw "Missing expected P12: $p" }
}
"HTTP subject:      $(Test-P12 $httpP12 $storePass)"
"TRANSPORT subject: $(Test-P12 $transportP12 $storePass)"
"TRUST subject:     $(Test-P12 $trustP12 $storePass)"

"=== 4) Rebuild opensearch.keystore ==="
if (Test-Path $KeystoreFile) { Remove-Item $KeystoreFile -Force }
$res = Exec-Cmd "set ""OPENSEARCH_PATH_CONF=$Conf"" && ""$OS_HOME\bin\opensearch-keystore.bat"" create"
if ($res.ExitCode -ne 0) { throw "Failed to create keystore. stderr=$($res.Stderr)" }

$keys = @(
  'plugins.security.ssl.http.keystore_password_secure',
  'plugins.security.ssl.http.keystore_keypassword_secure',
  'plugins.security.ssl.http.truststore_password_secure',
  'plugins.security.ssl.transport.keystore_password_secure',
  'plugins.security.ssl.transport.keystore_keypassword_secure',
  'plugins.security.ssl.transport.truststore_password_secure'
)

foreach ($k in $keys) {
  "Writing: $k"
  Set-OsSecureSetting $k $storePass
}

"=== 5) Start service ==="
Start-Service -Name $Svc
Start-Sleep -Seconds 5
(sc.exe query $Svc) | Out-String

"=== 6) Probe endpoint ==="
[Net.ServicePointManager]::ServerCertificateValidationCallback = { param($s,$c,$ch,$e) $true }

function Get-HttpStatusAndBody([string]$url) {
  try {
    $r = Invoke-WebRequest -UseBasicParsing -Uri $url -Method GET -TimeoutSec 10
    return [pscustomobject]@{ Status=$r.StatusCode; Body=$r.Content }
  } catch {
    $resp = $_.Exception.Response
    if ($resp) {
      $sr = New-Object IO.StreamReader($resp.GetResponseStream())
      $body = $sr.ReadToEnd()
      return [pscustomobject]@{ Status=[int]$resp.StatusCode; Body=$body }
    }
    return [pscustomobject]@{ Status=-1; Body=$_.Exception.Message }
  }
}

$u = 'https://127.0.0.1:9201/'
$last = $null
for ($i=0; $i -lt 24; $i++) {
  $x = Get-HttpStatusAndBody $u
  "Attempt $i => HTTP $($x.Status)"
  if ($x.Status -eq 401 -or ($x.Status -ge 200 -and $x.Status -lt 300) -or $x.Status -eq 503) {
    $last = $x
    break
  }
  Start-Sleep -Seconds 5
}

if (-not $last) { throw "OpenSearch never responded at $u" }
"HTTP $($last.Status) body (first 200 chars): " + ($last.Body.Substring(0, [Math]::Min(200, $last.Body.Length)))

"=== Done ==="