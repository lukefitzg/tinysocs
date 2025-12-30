# OpenSearch.Persistence.ps1
# Ensures TinySocs OpenSearch TLS + ports are deterministic across installs/upgrades.

[CmdletBinding()]
param(
  [string]$ConfDir = "C:\ProgramData\TinySocs\OpenSearch\config",
  [string]$ServiceName = "TinySocsOpenSearch",
  [int]$HttpPort = 9201,
  [string]$NetworkHost = "127.0.0.1"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Log([string]$Msg) { Write-Host "[TinySocs][OpenSearch][Persist] $Msg" }

function Remove-YamlKeyAndBareValueLine {
  param([string[]]$Lines, [string]$KeyRegex)

  $out = New-Object System.Collections.Generic.List[string]
  for ($i=0; $i -lt $Lines.Count; $i++) {
    $line = $Lines[$i]

    if ($line -match $KeyRegex) {
      # Also skip “bare value on next line” (your YAML sometimes breaks like that)
      if ($i + 1 -lt $Lines.Count) {
        $n = $Lines[$i + 1]
        $looksLikeYamlKey = ($n -match '^\s*[\w\.\-]+\s*:')
        $isCommentOrBlank = ($n -match '^\s*(#.*)?$')
        if (-not $looksLikeYamlKey -and -not $isCommentOrBlank) { $i++ }
      }
      continue
    }

    $out.Add($line)
  }
  return ,$out.ToArray()
}

function Ensure-YamlKeySingleLine {
  param(
    [string]$Path,
    [string]$Key,           # e.g. http.port
    [string]$CanonicalLine  # e.g. http.port: 9201
  )

  $bak = "$Path.bak.$(Get-Date -Format yyyyMMdd-HHmmss)"
  Copy-Item $Path $bak -Force

  $lines = Get-Content $Path

  # remove all occurrences of key (handle bare value on next line too)
  $rx = '^\s*' + [regex]::Escape($Key) + '\s*:'
  $lines = Remove-YamlKeyAndBareValueLine -Lines $lines -KeyRegex $rx

  # insert after network.host if present, else at top
  $out = New-Object System.Collections.Generic.List[string]
  $inserted = $false

  for ($i=0; $i -lt $lines.Count; $i++) {
    $out.Add($lines[$i])

    if (-not $inserted -and $lines[$i] -match '^\s*network\.host\s*:') {
      $out.Add($CanonicalLine)
      $inserted = $true
    }
  }

  if (-not $inserted) {
    $out.Insert(0, $CanonicalLine)
  }

  $out | Set-Content -Path $Path -Encoding UTF8
  Write-Log "YAML canonicalized: $Key (backup: $bak)"
}

function Remove-PlaintextSslPasswordKeysFromYml {
  param([string]$YmlPath)

  $keysToRemove = @(
    "plugins.security.ssl.http.keystore_password",
    "plugins.security.ssl.http.keystore_keypassword",
    "plugins.security.ssl.http.truststore_password",
    "plugins.security.ssl.transport.keystore_password",
    "plugins.security.ssl.transport.keystore_keypassword",
    "plugins.security.ssl.transport.truststore_password"
  )

  $bak = "$YmlPath.bak.$(Get-Date -Format yyyyMMdd-HHmmss)"
  Copy-Item $YmlPath $bak -Force

  $lines = Get-Content $YmlPath
  foreach ($k in $keysToRemove) {
    $rx = '^\s*' + [regex]::Escape($k) + '\s*:'
    $lines = Remove-YamlKeyAndBareValueLine -Lines $lines -KeyRegex $rx
  }

  $lines | Set-Content -Path $YmlPath -Encoding UTF8

  # sanity: should be none (REGEX match; do NOT use -SimpleMatch)
  $hit = Select-String -Path $YmlPath -Pattern '^\s*plugins\.security\.ssl\..*(keystore_password|keystore_keypassword|truststore_password)\s*:' -ErrorAction SilentlyContinue
  if ($hit) {
    throw "Plaintext SSL password keys still present in opensearch.yml after sanitize. This must never happen."
  }

  Write-Log "Removed plaintext SSL password keys from opensearch.yml (backup: $bak)"
}

function Get-DpapiStorepassPlaintext {
  # search likely locations
  $candidates = @(
    "C:\ProgramData\TinySocs\config\secrets\opensearch-tls-storepass.dpapi",
    (Join-Path $ConfDir "certs\opensearch-tls-storepass.dpapi"),
    "C:\ProgramData\TinySocs\OpenSearch\config\certs\opensearch-tls-storepass.dpapi"
  ) | Select-Object -Unique

  $dp = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
  if (-not $dp) { throw "Could not find opensearch-tls-storepass.dpapi in expected locations." }

  Add-Type -AssemblyName System.Security | Out-Null

  $b64 = (Get-Content $dp -Raw).Trim()
  if (-not $b64) { throw "DPAPI storepass file is empty: $dp" }

  $enc = [Convert]::FromBase64String($b64)
  $plainBytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
    $enc, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine
  )

  $pass = [Text.Encoding]::UTF8.GetString($plainBytes).TrimEnd("`r","`n",[char]0)

  if (-not $pass) { throw "Decrypted storepass is empty (dpapi decode/unprotect failed): $dp" }

  $nonAscii = $pass.ToCharArray() | Where-Object { [int][char]$_ -gt 127 }
  if ($nonAscii) {
    throw "Decrypted storepass contains non-ASCII characters (OpenSearch PKCS12 chokes on this). DPAPI file or decode is wrong."
  }

  Write-Log "Decrypted storepass OK (len=$($pass.Length)) from: $dp"
  return $pass
}

function Ensure-OpenSearchKeystoreSecureEntries {
  param([string]$Pass)

  $ks = "C:\Program Files\TinySocs\OpenSearch\bin\opensearch-keystore.bat"
  if (-not (Test-Path $ks)) { throw "opensearch-keystore.bat not found: $ks" }

  $keystorePath = Join-Path $ConfDir "opensearch.keystore"

  # Use PowerShell piping (NOT cmd.exe echo) so special chars in password can't break the command.
  $env:OPENSEARCH_PATH_CONF = $ConfDir

  if (-not (Test-Path $keystorePath)) {
    Write-Log "Creating opensearch.keystore in $ConfDir"
    & $ks create | Out-Null
  }

  # Always remove any legacy plaintext keystore entries if present (ignore failures)
  $remove = @(
    "plugins.security.ssl.http.keystore_password",
    "plugins.security.ssl.http.keystore_keypassword",
    "plugins.security.ssl.http.truststore_password",
    "plugins.security.ssl.transport.keystore_password",
    "plugins.security.ssl.transport.keystore_keypassword",
    "plugins.security.ssl.transport.truststore_password"
  )
  foreach ($k in $remove) {
    try { & $ks remove $k | Out-Null } catch { }
  }

  # Secure keys we guarantee
  $secure = @(
    "plugins.security.ssl.http.keystore_password_secure",
    "plugins.security.ssl.http.keystore_keypassword_secure",
    "plugins.security.ssl.transport.keystore_password_secure",
    "plugins.security.ssl.transport.keystore_keypassword_secure",
    "plugins.security.ssl.http.truststore_password_secure",
    "plugins.security.ssl.transport.truststore_password_secure"
  )

  foreach ($k in $secure) {
    # -x reads from stdin
    ($Pass + "`n") | & $ks add -f $k -x | Out-Null
  }

  $listed = (& $ks list | Out-String)
  foreach ($k in $secure) {
    if ($listed -notmatch [regex]::Escape($k)) {
      throw "Expected secure keystore entry missing after write: $k"
    }
  }

  Write-Log "Keystore secure entries ensured in: $keystorePath"
}

function Restart-And-Wait {
  Write-Log "Restarting service: $ServiceName"
  try { Stop-Service $ServiceName -Force -ErrorAction SilentlyContinue } catch {}
  try { Start-Service $ServiceName } catch {}

  $deadline = (Get-Date).AddSeconds(120)
  do {
    Start-Sleep 2
    $ok = (Test-NetConnection 127.0.0.1 -Port $HttpPort -WarningAction SilentlyContinue).TcpTestSucceeded
  } while (-not $ok -and (Get-Date) -lt $deadline)

  if (-not $ok) {
    Write-Log "OpenSearch did not bind on $HttpPort within 120s. Last 120 log lines:"
    $log = "C:\Program Files\TinySocs\OpenSearch\logs\opensearch.log"
    if (Test-Path $log) { Get-Content $log -Tail 120 | ForEach-Object { Write-Host $_ } }
    throw "OpenSearch not listening on $HttpPort"
  }

  Write-Log "OpenSearch is listening on $HttpPort"
}

# ---- main ----
$yml = Join-Path $ConfDir "opensearch.yml"
if (-not (Test-Path $yml)) { throw "opensearch.yml not found: $yml" }

Write-Log "ConfDir=$ConfDir"

# 1) Enforce deterministic bind + port
Ensure-YamlKeySingleLine -Path $yml -Key "network.host" -CanonicalLine ("network.host: {0}" -f $NetworkHost)
Ensure-YamlKeySingleLine -Path $yml -Key "http.port"    -CanonicalLine ("http.port: {0}" -f $HttpPort)

# 2) Prevent the fatal “both password + password_secure” condition
Remove-PlaintextSslPasswordKeysFromYml -YmlPath $yml

# 3) Guarantee keystore secure entries match the DPAPI storepass
$pass = Get-DpapiStorepassPlaintext
Ensure-OpenSearchKeystoreSecureEntries -Pass $pass

# 4) Also dedupe the known problem key (you hit this earlier)
Ensure-YamlKeySingleLine -Path $yml -Key "plugins.security.allow_default_init_securityindex" -CanonicalLine "plugins.security.allow_default_init_securityindex: true"

# 5) Restart + confirm listener is up
Restart-And-Wait

Write-Log "Done."