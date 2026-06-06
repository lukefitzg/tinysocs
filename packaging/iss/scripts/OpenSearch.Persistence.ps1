# OpenSearch.Persistence.ps1
# Ensures TinySocs OpenSearch TLS + ports are deterministic across installs/upgrades.

[CmdletBinding()]
param(
  [string]$ConfDir = "C:\ProgramData\TinySocs\OpenSearch\config",
  [string]$ServiceName = "TinySocsOpenSearch",
  [int]$HttpPort = 9201,
  [string]$NetworkHost = "127.0.0.1",

  # PATCH: enforce deterministic HTTP TLS client auth mode.
  # OPTIONAL allows securityadmin to present admin client certs for bootstrap
  # without requiring client certs from normal HTTPS clients (curl, browsers).
  [ValidateSet("NONE","OPTIONAL","REQUIRE")]
  [string]$HttpClientAuthMode = "OPTIONAL",

  [string]$OpenSearchRoot = "",   # default: infer from script location (..\OpenSearch)
  [switch]$ForceRecreateKeystore  # if set: blow away opensearch.keystore and rebuild deterministically
)

# --- BEGIN PATCH: TLS resolver bootstrap for standalone -File execution ---
# When invoked via: powershell.exe -NoProfile -ExecutionPolicy Bypass -File OpenSearch.Persistence.ps1
# the session is clean and will NOT have module functions unless we import/define them.
#
# Goal: ensure Resolve-TinySocsTlsStorepass exists in THIS process.

if (-not (Get-Command Resolve-TinySocsTlsStorepass -ErrorAction SilentlyContinue)) {

  # Prefer the repo copy if we're running from the source tree:
  #   repo\packaging\iss\scripts\OpenSearch.Persistence.ps1  -> repo\modules\TinySocs.Installer.psm1
  $repoRootGuess = $null
  try {
    $repoRootGuess = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..\..\..")).Path
  } catch { }

  $installerCandidates = @(
    (Join-Path $PSScriptRoot "TinySocs.Installer.psm1"),
    ($(if ($repoRootGuess) { Join-Path (Join-Path $repoRootGuess "modules") "TinySocs.Installer.psm1" } else { $null })),
    "C:\Program Files\TinySocs\modules\TinySocs.Installer.psm1"
  ) | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Leaf) } | Select-Object -Unique

  if ($installerCandidates.Count -gt 0) {
    try {
      # PS 5.1 does NOT support -LiteralPath on Import-Module. Use the path as -Name.
      Import-Module ($installerCandidates | Select-Object -First 1) -Force -DisableNameChecking | Out-Null
    } catch {
      # fall through to local definition
    }
  }

  # If still missing, define a local fallback implementation (uses helper funcs in this script).
  if (-not (Get-Command Resolve-TinySocsTlsStorepass -ErrorAction SilentlyContinue)) {

    function Resolve-TinySocsTlsStorepass {
      [CmdletBinding()]
      param(
        [Parameter(Mandatory)][string]$ConfDir,
        [Parameter(Mandatory)][string]$OpenSearchRoot
      )

      # RESOLVER_FALLBACK_MARKER_20260112_PS51

      $certDir = Join-Path $ConfDir "certs"

      $candidatesRaw = @(
        (Join-Path $certDir "opensearch-tls-storepass.dpapi"),
        (Join-Path $env:ProgramData "TinySocs\config\secrets\opensearch-tls-storepass.dpapi"),
        (Join-Path (Join-Path $OpenSearchRoot "config\certs") "opensearch-tls-storepass.dpapi")
      ) | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Leaf) } | Select-Object -Unique

      $candidates = @($candidatesRaw)  # ALWAYS an array

      if ($candidates.Length -eq 0) {
        throw "No opensearch-tls-storepass.dpapi found in expected locations."
      }

      $p12sRaw = @("http.p12","transport.p12","trust.p12") |
        ForEach-Object { Join-Path $certDir $_ } |
        Where-Object { Test-Path -LiteralPath $_ -PathType Leaf }

      $p12s = @($p12sRaw)  # ALWAYS an array

      if ($p12s.Length -eq 0) {
        throw "No PKCS12 files present in $certDir to validate storepass against."
      }

      $errors = @()

      foreach ($dpapiPath in $candidates) {
        $info = Get-TinySocsStorepassFromDpapiFile -Path $dpapiPath

        $results = @(
          foreach ($p in $p12s) {
            Test-TinySocsPkcs12Password -P12Path $p -Password $info.Password
          }
        )

        $bad = @($results | Where-Object { -not $_.Ok })

        if ($bad.Length -eq 0) {
          return $info
        }

        $errors += "Candidate [$dpapiPath] failed P12 validation: " + (($bad | ForEach-Object {
          "$(Split-Path $_.Path -Leaf): $($_.Error)"
        }) -join " | ")
      }

      throw ("Unable to resolve TLS storepass. Tried: " + ($candidates -join ", ") + ". Errors: " + ($errors -join " || "))
    }

  }
}
# --- END PATCH ---

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# PATCH: bump version to reflect PS5.1 compat fixes (no ProtectedData assembly name; no assumed IsAscii7 property)
# PATCH(20260114): enforce deterministic http clientauth_mode
# PATCH(20260114): harden keystore writes on Windows (stale .tmp + file locks)
# PATCH(20260218): clientauth_mode default NONE->OPTIONAL so securityadmin can present admin cert
$script:PERSIST_VERSION = "0.0.20260218-clientauth-optional"

function Write-Log([string]$Msg) { Write-Host "[TinySocs][OpenSearch][Persist] $Msg" }

function Resolve-OpenSearchRoot {
  if (-not [string]::IsNullOrWhiteSpace($OpenSearchRoot)) {
    return (Resolve-Path -LiteralPath $OpenSearchRoot).Path
  }

  # Script lives under {app}\modules; OpenSearch payload is {app}\OpenSearch
  $appRootGuess = Split-Path -Parent $PSScriptRoot
  $osGuess = Join-Path $appRootGuess "OpenSearch"
  if (Test-Path $osGuess -PathType Container) {
    return (Resolve-Path -LiteralPath $osGuess).Path
  }

  throw "OpenSearchRoot not provided and could not be inferred. Tried: $osGuess"
}

function Get-ConfigDirs {
  param([Parameter(Mandatory)][string]$ResolvedOpenSearchRoot)

  $dirs = New-Object System.Collections.Generic.List[string]

  if (Test-Path $ConfDir -PathType Container) {
    $dirs.Add((Resolve-Path -LiteralPath $ConfDir).Path)
  }

  $pf = Join-Path $ResolvedOpenSearchRoot "config"
  if (Test-Path $pf -PathType Container) {
    $dirs.Add((Resolve-Path -LiteralPath $pf).Path)
  }

  # unique, preserve order
  $seen = @{}
  $out = @()
  foreach ($d in $dirs) {
    if (-not $seen.ContainsKey($d)) { $seen[$d] = $true; $out += $d }
  }
  return ,$out
}

function Remove-YamlKeyAndBareValueLine {
  param([string[]]$Lines, [string]$KeyRegex)

  $out = New-Object System.Collections.Generic.List[string]
  for ($i=0; $i -lt $Lines.Count; $i++) {
    $line = $Lines[$i]

    if ($line -match $KeyRegex) {
      # Also skip bare value on next line (YAML sometimes breaks like that)
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
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$Key,
    [Parameter(Mandatory)][string]$CanonicalLine
  )

  $bak = "$Path.bak.$(Get-Date -Format yyyyMMdd-HHmmss)"
  Copy-Item $Path $bak -Force

  $lines = Get-Content $Path

  $rx = '^\s*' + [regex]::Escape($Key) + '\s*:'
  $lines = Remove-YamlKeyAndBareValueLine -Lines $lines -KeyRegex $rx

  $out = New-Object System.Collections.Generic.List[string]
  $inserted = $false

  for ($i=0; $i -lt $lines.Count; $i++) {
    $out.Add($lines[$i])
    if (-not $inserted -and $lines[$i] -match '^\s*network\.host\s*:') {
      $out.Add($CanonicalLine)
      $inserted = $true
    }
  }

  if (-not $inserted) { $out.Insert(0, $CanonicalLine) }

  $out | Set-Content -Path $Path -Encoding UTF8
  Write-Log "YAML canonicalized: $Key (backup: $bak)"
}

function Convert-TinySocsUnprotectedBytesToString {
  [CmdletBinding()]
  param([Parameter(Mandatory)][byte[]]$Bytes)

  # Strip UTF-8 BOM if present
  if ($Bytes.Length -ge 3 -and $Bytes[0] -eq 0xEF -and $Bytes[1] -eq 0xBB -and $Bytes[2] -eq 0xBF) {
    $Bytes = $Bytes[3..($Bytes.Length-1)]
  }

  # Heuristic: if it looks like UTF-16LE (lots of 0x00 in odd bytes), decode as Unicode
  $looksUnicode = $false
  if ($Bytes.Length -ge 4) {
    $sampleLen = [Math]::Min($Bytes.Length, 64)
    $zeroOdd = 0
    for ($i=1; $i -lt $sampleLen; $i+=2) { if ($Bytes[$i] -eq 0) { $zeroOdd++ } }
    if ($zeroOdd -ge [Math]::Floor(($sampleLen/2) * 0.6)) { $looksUnicode = $true }
  }

  $s = if ($looksUnicode) {
    [Text.Encoding]::Unicode.GetString($Bytes)
  } else {
    # UTF8 will happily decode ASCII too
    [Text.Encoding]::UTF8.GetString($Bytes)
  }

  # Trim nulls + whitespace (DPAPI blobs often carry terminators/newlines)
  $s = $s.Trim([char]0x0000).Trim()

  # Also drop embedded NULs if any slipped through (rare, but catastrophic for Java PKCS12)
  if ($s.IndexOf([char]0x0000) -ge 0) { $s = $s -replace ([char]0x0000), "" }

  return $s
}

function Get-TinySocsStorepassFromDpapiFile {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Path)

  if (-not (Test-Path -LiteralPath $Path)) { throw "DPAPI file not found: $Path" }

  # PATCH: remove all whitespace, not just ends (base64 may contain CRLF)
  $b64 = (Get-Content -LiteralPath $Path -Raw)
  $b64 = ($b64 -replace '\s+', '').Trim()
  if ([string]::IsNullOrWhiteSpace($b64)) { throw "DPAPI file is empty: $Path" }

  try { $protected = [Convert]::FromBase64String($b64) }
  catch { throw "DPAPI file is not valid base64 text: $Path" }

  # PATCH: PS 5.1 friendly; do not reference nonexistent assembly names
  try { Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue | Out-Null } catch { }

  $bytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
    $protected,
    $null,
    [System.Security.Cryptography.DataProtectionScope]::LocalMachine
  )

  $pw = Convert-TinySocsUnprotectedBytesToString -Bytes $bytes

  $allAscii = $true
  foreach ($ch in $pw.ToCharArray()) { if ([int][char]$ch -gt 127) { $allAscii = $false; break } }

  [pscustomobject]@{
    Password   = $pw
    IsAscii7   = $allAscii
    Length     = $pw.Length
    SourcePath = $Path
  }
}

function Set-TinySocsStorepassDpapiFile {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$Password
  )

  try { Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue | Out-Null } catch { }

  # Store as UTF-8 bytes (no BOM) then DPAPI protect (LocalMachine)
  $plain = [Text.Encoding]::UTF8.GetBytes($Password)

  $protected = [System.Security.Cryptography.ProtectedData]::Protect(
    $plain,
    $null,
    [System.Security.Cryptography.DataProtectionScope]::LocalMachine
  )

  $b64 = [Convert]::ToBase64String($protected)

  $dir = Split-Path -Parent $Path
  if (-not (Test-Path -LiteralPath $dir -PathType Container)) {
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
  }

  # Write as ASCII text (base64)
  Set-Content -LiteralPath $Path -Value $b64 -Encoding Ascii
}

function Test-TinySocsPkcs12Password {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$P12Path,
    [Parameter(Mandatory)][string]$Password
  )

  if (-not (Test-Path -LiteralPath $P12Path -PathType Leaf)) {
    return [pscustomobject]@{ Ok=$false; Path=$P12Path; Error="Missing"; }
  }

  try {
    $flags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet
  } catch {
    $flags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::MachineKeySet
  }

  try {
    $null = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($P12Path, $Password, $flags)
    return [pscustomobject]@{ Ok=$true; Path=$P12Path; Error=$null; }
  } catch {
    return [pscustomobject]@{ Ok=$false; Path=$P12Path; Error=$_.Exception.Message; }
  }
}

function Remove-PlaintextSslPasswordKeysFromYml {
  param([Parameter(Mandatory)][string]$YmlPath)

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

  $hit = Select-String -Path $YmlPath -Pattern '^\s*plugins\.security\.ssl\..*(keystore_password|keystore_keypassword|truststore_password)\s*:' -ErrorAction SilentlyContinue
  if ($hit) { throw "Plaintext SSL password keys still present in opensearch.yml after sanitize." }

  Write-Log "Removed plaintext SSL password keys from opensearch.yml (backup: $bak)"
}

function Test-Pkcs12PasswordDotNet {
  param(
    [Parameter(Mandatory)][string]$P12Path,
    [Parameter(Mandatory)][string]$Password
  )

  if (-not (Test-Path -LiteralPath $P12Path -PathType Leaf)) { return $false }

  try {
    try { Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue | Out-Null } catch { }
    $bytes = [System.IO.File]::ReadAllBytes($P12Path)

    $flags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet
    try {
      $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($bytes, $Password, $flags)
      $cert.Dispose()
      return $true
    } catch {
      $flags2 = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::MachineKeySet `
              -bor [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable
      $cert2 = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($bytes, $Password, $flags2)
      $cert2.Dispose()
      return $true
    }
  } catch {
    return $false
  }
}

function Test-TinySocsPasswordAscii7 {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Password)

  if ([string]::IsNullOrEmpty($Password)) {
    return [pscustomobject]@{ Ok=$false; Reason="empty"; }
  }

  for ($i=0; $i -lt $Password.Length; $i++) {
    $c = [int][char]$Password[$i]
    if ($c -gt 127) {
      return [pscustomobject]@{ Ok=$false; Reason=("non-ascii char U+{0:X4} at index {1}" -f $c, $i); }
    }
  }

  return [pscustomobject]@{ Ok=$true; Reason="ok"; }
}

function New-TinySocsAsciiPassword {
  [CmdletBinding()]
  param([int]$Length = 32)

  $alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"  # avoid visually ambiguous
  $bytes = New-Object byte[] ($Length)
  [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)

  $sb = New-Object System.Text.StringBuilder
  for ($i=0; $i -lt $Length; $i++) {
    $idx = $bytes[$i] % $alphabet.Length
    [void]$sb.Append($alphabet[$idx])
  }
  return $sb.ToString()
}

function Set-TinySocsPkcs12PasswordDotNetCollection {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$P12Path,
    [Parameter(Mandatory)][string]$OldPassword,
    [Parameter(Mandatory)][string]$NewPassword
  )

  if (-not (Test-Path -LiteralPath $P12Path -PathType Leaf)) {
    throw "PKCS12 not found: $P12Path"
  }

  try { Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue | Out-Null } catch { }

  $bak = "$P12Path.bak.$(Get-Date -Format yyyyMMdd-HHmmss)"
  Copy-Item -LiteralPath $P12Path -Destination $bak -Force

  $col = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection

  # Import with exportable to allow re-export; prefer Ephemeral where possible
  $flags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable
  try { $flags = $flags -bor [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet } catch { }

  try {
    $col.Import($P12Path, $OldPassword, $flags)
  } catch {
    throw "Failed importing PKCS12 for rotation: $P12Path :: $($_.Exception.Message)"
  }

  try {
    $outBytes = $col.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12, $NewPassword)
  } catch {
    throw "Failed exporting PKCS12 for rotation: $P12Path :: $($_.Exception.Message)"
  }

  [System.IO.File]::WriteAllBytes($P12Path, $outBytes)

  # quick sanity: can we import back with new pass?
  $col2 = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
  $col2.Import($P12Path, $NewPassword, $flags) | Out-Null

  Write-Log ("Rotated PKCS12 password (DotNet) for {0} (backup: {1})" -f $P12Path, $bak)
}

function Ensure-ResolverShimModule {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$ModulesDir)

  # The wrapper log shows it's (wrongly) looking for "ensearch.persistence.psm1" beside the installer module.
  # We ship a tiny shim so Resolve-TinySocsTlsStorepass always exists for the wrapper, even if the installer module has a bad import.
  $shimName = "ensearch.persistence.psm1"
  $shimPath = Join-Path $ModulesDir $shimName
  $marker   = "TINYSOCS_ENSEARCH_PERSIST_SHIM_20260102"

  $need = $true
  if (Test-Path -LiteralPath $shimPath -PathType Leaf) {
    try {
      $txt = Get-Content -LiteralPath $shimPath -Raw -ErrorAction Stop
      if ($txt -match [regex]::Escape($marker)) { $need = $false }
    } catch { $need = $true }
  }

  if (-not $need) { return }

  $content = @"
# $shimName
# $marker
# Minimal shim for TinySocs wrapper: provides Resolve-TinySocsTlsStorepass without needing other modules.

Set-StrictMode -Version Latest
`$ErrorActionPreference = "Stop"

function Convert-TinySocsUnprotectedBytesToString {
  param([byte[]]`$Bytes)
  if (`$Bytes.Length -ge 3 -and `$Bytes[0] -eq 0xEF -and `$Bytes[1] -eq 0xBB -and `$Bytes[2] -eq 0xBF) {
    `$Bytes = `$Bytes[3..(`$Bytes.Length-1)]
  }
  `$looksUnicode = `$false
  if (`$Bytes.Length -ge 4) {
    `$sampleLen = [Math]::Min(`$Bytes.Length, 64)
    `$zeroOdd = 0
    for (`$i=1; `$i -lt `$sampleLen; `$i+=2) { if (`$Bytes[`$i] -eq 0) { `$zeroOdd++ } }
    if (`$zeroOdd -ge [Math]::Floor((`$sampleLen/2) * 0.6)) { `$looksUnicode = `$true }
  }
  `$s = if (`$looksUnicode) { [Text.Encoding]::Unicode.GetString(`$Bytes) } else { [Text.Encoding]::UTF8.GetString(`$Bytes) }
  `$s = `$s.Trim([char]0x0000).Trim()
  if (`$s.IndexOf([char]0x0000) -ge 0) { `$s = `$s -replace ([char]0x0000), "" }
  return `$s
}

function Get-TinySocsStorepassFromDpapiFile {
  param([string]`$Path)
  if (-not (Test-Path -LiteralPath `$Path -PathType Leaf)) { throw "DPAPI file not found: `$Path" }
  `$b64 = (Get-Content -LiteralPath `$Path -Raw)
  `$b64 = (`$b64 -replace '\s+','').Trim()
  if ([string]::IsNullOrWhiteSpace(`$b64)) { throw "DPAPI file is empty: `$Path" }
  try { `$protected = [Convert]::FromBase64String(`$b64) } catch { throw "DPAPI file is not valid base64 text: `$Path" }

  try { Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue | Out-Null } catch { }
  `$bytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
    `$protected, `$null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine
  )

  `$pw = Convert-TinySocsUnprotectedBytesToString -Bytes `$bytes
  `$allAscii = `$true
  foreach (`$ch in `$pw.ToCharArray()) { if ([int][char]`$ch -gt 127) { `$allAscii = `$false; break } }

  [pscustomobject]@{
    Password   = `$pw
    IsAscii7   = `$allAscii
    Length     = `$pw.Length
    SourcePath = `$Path
  }
}

function Test-TinySocsPkcs12Password {
  param([string]`$P12Path, [string]`$Password)
  if (-not (Test-Path -LiteralPath `$P12Path -PathType Leaf)) {
    return [pscustomobject]@{ Ok=`$false; Path=`$P12Path; Error="Missing"; }
  }
  try {
    `$flags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet
  } catch {
    `$flags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::MachineKeySet
  }
  try {
    `$null = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(`$P12Path, `$Password, `$flags)
    return [pscustomobject]@{ Ok=`$true; Path=`$P12Path; Error=`$null; }
  } catch {
    return [pscustomobject]@{ Ok=`$false; Path=`$P12Path; Error=`$_.Exception.Message; }
  }
}

function Resolve-TinySocsTlsStorepass {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]`$ConfDir,
    [Parameter(Mandatory)][string]`$OpenSearchRoot
  )

  `$certDir = Join-Path `$ConfDir "certs"
  `$candidates = @(
    (Join-Path `$certDir "opensearch-tls-storepass.dpapi"),
    (Join-Path `$env:ProgramData "TinySocs\config\secrets\opensearch-tls-storepass.dpapi"),
    (Join-Path (Join-Path `$OpenSearchRoot "config\certs") "opensearch-tls-storepass.dpapi")
  ) | Where-Object { `$_ -and (Test-Path -LiteralPath `$_ -PathType Leaf) } | Select-Object -Unique

  if (`$candidates.Count -eq 0) { throw "No opensearch-tls-storepass.dpapi found in expected locations." }

  `$p12s = @("http.p12","transport.p12","trust.p12") |
    ForEach-Object { Join-Path `$certDir `$_ } |
    Where-Object { Test-Path -LiteralPath `$_ -PathType Leaf }

  if (`$p12s.Count -eq 0) { throw "No PKCS12 files present in `$certDir to validate storepass against." }

  `$errors = @()
  foreach (`$dpapiPath in `$candidates) {
    `$info = Get-TinySocsStorepassFromDpapiFile -Path `$dpapiPath
    `$results = foreach (`$p in `$p12s) { Test-TinySocsPkcs12Password -P12Path `$p -Password `$info.Password }
    `$bad = @(`$results | Where-Object { -not `$_.Ok })
    if (`$bad.Count -eq 0) { return `$info }
    `$errors += "Candidate [`$dpapiPath] failed P12 validation: " + ((`$bad | ForEach-Object { "`$(Split-Path `$_.Path -Leaf): `$_.Error" }) -join " | ")
  }

  throw ("Unable to resolve TLS storepass. Tried: " + (`$candidates -join ", ") + ". Errors: " + (`$errors -join " || "))
}

Export-ModuleMember -Function Resolve-TinySocsTlsStorepass
"@

  try {
    if (-not (Test-Path -LiteralPath $ModulesDir -PathType Container)) {
      New-Item -ItemType Directory -Force -Path $ModulesDir | Out-Null
    }
    Set-Content -LiteralPath $shimPath -Value $content -Encoding UTF8
    Write-Log "Wrote resolver shim module: $shimPath"
  } catch {
    Write-Log "WARN: failed writing resolver shim module ($shimPath): $($_.Exception.Message)"
  }
}

function Invoke-OsKeystore {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$KeystoreBat,
    [Parameter(Mandatory)][string]$ArgsLine,
    [Parameter()][string]$StdinText = $null,
    [Parameter(Mandatory)][string]$ConfDirForChild,
    [int]$TimeoutMs = 45000
  )

  # PATCH(20260114): harden Windows keystore writes.
  # OpenSearch keystore uses opensearch.keystore.tmp then renames to opensearch.keystore.
  # If a prior run crashed, .tmp can remain and/or rename can fail due to file locks.
  $tmpKs = Join-Path $ConfDirForChild "opensearch.keystore.tmp"
  if (Test-Path -LiteralPath $tmpKs -PathType Leaf) {
    try { Remove-Item -LiteralPath $tmpKs -Force -ErrorAction SilentlyContinue } catch { }
  }

  $attempts = 2
  $last = $null

  for ($try = 1; $try -le $attempts; $try++) {

    $cmdArgs = '/d /c ""{0}" {1}"' -f $KeystoreBat, $ArgsLine

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName               = $env:ComSpec
    $psi.Arguments              = $cmdArgs
    $psi.WorkingDirectory       = (Split-Path -Parent $KeystoreBat)
    $psi.UseShellExecute        = $false
    $psi.RedirectStandardInput  = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $psi.CreateNoWindow         = $true
    $psi.EnvironmentVariables["OPENSEARCH_PATH_CONF"] = $ConfDirForChild

    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $psi
    if (-not $p.Start()) { throw "Failed to start keystore process: $ArgsLine" }

    if ($StdinText -ne $null) {
      # IMPORTANT: write UTF-8 bytes (no BOM).
      $bytes = [Text.Encoding]::UTF8.GetBytes($StdinText + "`n")
      $p.StandardInput.BaseStream.Write($bytes, 0, $bytes.Length)
      $p.StandardInput.BaseStream.Flush()
    }
    try { $p.StandardInput.Close() } catch { }

    if (-not $p.WaitForExit($TimeoutMs)) {
      try { $p.Kill($true) } catch { try { $p.Kill() } catch { } }
      throw "Keystore command timed out after ${TimeoutMs}ms: $ArgsLine"
    }

    $last = [pscustomobject]@{
      ExitCode = $p.ExitCode
      Stdout   = $p.StandardOutput.ReadToEnd()
      Stderr   = $p.StandardError.ReadToEnd()
      Args     = $ArgsLine
      Attempt  = $try
    }

    if ($last.ExitCode -eq 0) { return $last }

    $blob = (($last.Stderr + "`n" + $last.Stdout) -as [string])
    $isTmpExists = ($blob -match 'FileAlreadyExistsException:.*opensearch\.keystore\.tmp')
    $isMoveDenied = ($blob -match 'AccessDeniedException:.*opensearch\.keystore\.tmp\s*->\s*.*opensearch\.keystore')

    if ($try -lt $attempts -and ($isTmpExists -or $isMoveDenied)) {
      # best-effort cleanup + short backoff then retry once
      try { Remove-Item -LiteralPath $tmpKs -Force -ErrorAction SilentlyContinue } catch { }
      Start-Sleep -Milliseconds 400
      continue
    }

    return $last
  }

  return $last
}

function Ensure-OpenSearchKeystoreSecureEntries {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$OpenSearchRootResolved,
    [Parameter(Mandatory)][string]$TargetConfDir,
    [Parameter(Mandatory)][string]$Pass
  )

  $ksBat = Join-Path $OpenSearchRootResolved "bin\opensearch-keystore.bat"
  if (-not (Test-Path -LiteralPath $ksBat -PathType Leaf)) { throw "opensearch-keystore.bat not found: $ksBat" }

  $keystorePath = Join-Path $TargetConfDir "opensearch.keystore"

  if ($ForceRecreateKeystore) {
    if (Test-Path -LiteralPath $keystorePath -PathType Leaf) {
      $bak = "$keystorePath.bak.$(Get-Date -Format yyyyMMdd-HHmmss)"
      Copy-Item -LiteralPath $keystorePath -Destination $bak -Force
      Remove-Item -LiteralPath $keystorePath -Force
      Write-Log "ForceRecreateKeystore: backed up + removed existing keystore ($bak)"
    }
  }

  # PATCH(20260114): remove stale tmp before we do anything
  $tmpKs = Join-Path $TargetConfDir "opensearch.keystore.tmp"
  if (Test-Path -LiteralPath $tmpKs -PathType Leaf) {
    try { Remove-Item -LiteralPath $tmpKs -Force -ErrorAction SilentlyContinue } catch { }
  }

  if (-not (Test-Path -LiteralPath $keystorePath -PathType Leaf)) {
    Write-Log "Creating opensearch.keystore in $TargetConfDir"
    $rCreate = Invoke-OsKeystore -KeystoreBat $ksBat -ArgsLine "create" -ConfDirForChild $TargetConfDir
    if ($rCreate.ExitCode -ne 0 -and -not (Test-Path -LiteralPath $keystorePath -PathType Leaf)) {
      throw "Keystore create failed (exit=$($rCreate.ExitCode)). stderr=$($rCreate.Stderr)"
    }
  }

  $insecure = @(
    "plugins.security.ssl.http.keystore_password",
    "plugins.security.ssl.http.keystore_keypassword",
    "plugins.security.ssl.http.truststore_password",
    "plugins.security.ssl.transport.keystore_password",
    "plugins.security.ssl.transport.keystore_keypassword",
    "plugins.security.ssl.transport.truststore_password"
  )

  foreach ($k in $insecure) {
    try {
      $r = Invoke-OsKeystore -KeystoreBat $ksBat -ArgsLine ("remove {0}" -f $k) -ConfDirForChild $TargetConfDir
      if ($r.ExitCode -ne 0 -and ($r.Stderr -notmatch 'does not exist')) {
        Write-Log ("WARN: keystore remove {0} exit={1} stderr={2}" -f $k, $r.ExitCode, ($r.Stderr -replace "\r?\n"," | "))
      }
    } catch { }
  }

  $secure = @(
    "plugins.security.ssl.http.keystore_password_secure",
    "plugins.security.ssl.http.keystore_keypassword_secure",
    "plugins.security.ssl.http.truststore_password_secure",
    "plugins.security.ssl.transport.keystore_password_secure",
    "plugins.security.ssl.transport.keystore_keypassword_secure",
    "plugins.security.ssl.transport.truststore_password_secure"
  )

  foreach ($k in $secure) {
    $r1 = Invoke-OsKeystore -KeystoreBat $ksBat -ArgsLine ("add -f --stdin {0}" -f $k) -StdinText $Pass -ConfDirForChild $TargetConfDir
    if ($r1.ExitCode -ne 0) {
      $r2 = Invoke-OsKeystore -KeystoreBat $ksBat -ArgsLine ("add -xf {0}" -f $k) -StdinText $Pass -ConfDirForChild $TargetConfDir
      if ($r2.ExitCode -ne 0) {
        $e1 = ($r1.Stderr + "`n" + $r1.Stdout).Trim()
        $e2 = ($r2.Stderr + "`n" + $r2.Stdout).Trim()
        throw "Failed setting secure keystore entry [$k] in [$TargetConfDir]. Tried '--stdin' then '-xf'.`n---1---`n$e1`n---2---`n$e2"
      }
    }
  }

  # Verify with exact membership (no regex)
  $rList = Invoke-OsKeystore -KeystoreBat $ksBat -ArgsLine "list" -ConfDirForChild $TargetConfDir
  if ($rList.ExitCode -ne 0) { throw "Keystore list failed (exit=$($rList.ExitCode)). stderr=$($rList.Stderr)" }

  $set = New-Object 'System.Collections.Generic.HashSet[string]'
  foreach ($ln in ($rList.Stdout -split "\r?\n")) {
    $t = $ln.Trim()
    if (-not [string]::IsNullOrWhiteSpace($t)) { [void]$set.Add($t) }
  }

  foreach ($k in $secure) {
    if (-not $set.Contains($k)) { throw "Expected secure keystore entry missing after write: $k" }
  }
  foreach ($k in $insecure) {
    if ($set.Contains($k)) { throw "Insecure keystore entry is present (must be absent): $k" }
  }

  Write-Log "Keystore secure entries ensured in: $keystorePath"
}

function Get-P12PathsFromYml {
  param(
    [Parameter(Mandatory)][string]$YmlPath,
    [Parameter(Mandatory)][string]$BaseDir
  )

  $keys = @(
    "plugins.security.ssl.http.keystore_filepath",
    "plugins.security.ssl.http.truststore_filepath",
    "plugins.security.ssl.transport.keystore_filepath",
    "plugins.security.ssl.transport.truststore_filepath"
  )

  $lines = Get-Content -LiteralPath $YmlPath -ErrorAction Stop
  $found = @()

  foreach ($k in $keys) {
    $rx = '^\s*' + [regex]::Escape($k) + '\s*:\s*(.+?)\s*$'
    foreach ($ln in $lines) {
      if ($ln -match $rx) {
        $raw = $Matches[1].Trim().Trim('"').Trim("'")
        if ([string]::IsNullOrWhiteSpace($raw)) { continue }

        $p = $raw
        $p = $p -replace '\$\{OPENSEARCH_PATH_CONF\}', $BaseDir

        if (-not [System.IO.Path]::IsPathRooted($p)) {
          $p = Join-Path $BaseDir $p
        }

        $found += $p
      }
    }
  }

  $found | Select-Object -Unique
}

function Get-FallbackP12s {
  param([Parameter(Mandatory)][string]$CfgDir)

  $fallback = Join-Path $CfgDir "certs"
  @(
    (Join-Path $fallback "http.p12"),
    (Join-Path $fallback "transport.p12"),
    (Join-Path $fallback "trust.p12"),
    (Join-Path $fallback "truststore.p12")
  ) | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf }
}

function Ensure-CertsHydrated {
  param(
    [Parameter(Mandatory)][string]$PrimaryCfgDir,
    [Parameter(Mandatory)][string]$TargetCfgDir
  )

  if ($PrimaryCfgDir -eq $TargetCfgDir) { return }

  $srcCerts = Join-Path $PrimaryCfgDir "certs"
  $dstCerts = Join-Path $TargetCfgDir "certs"

  if (-not (Test-Path -LiteralPath $srcCerts -PathType Container)) { return }

  $srcP12s = Get-ChildItem -LiteralPath $srcCerts -Filter *.p12 -File -ErrorAction SilentlyContinue
  if (-not $srcP12s -or $srcP12s.Count -eq 0) { return }

  if (-not (Test-Path -LiteralPath $dstCerts -PathType Container)) {
    New-Item -ItemType Directory -Force -Path $dstCerts | Out-Null
  }

  Copy-Item -LiteralPath (Join-Path $srcCerts "*") -Destination $dstCerts -Recurse -Force
  Write-Log "Hydrated certs into [$TargetCfgDir] from primary [$PrimaryCfgDir]"
}

# PATCH: normalize store-info so callers can safely use .Password/.IsAscii7/.Length regardless of resolver implementation
function Normalize-TinySocsStoreInfo {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]$StoreInfoMaybe,
    [string]$DefaultSourcePath = $null
  )

  if ($null -eq $StoreInfoMaybe) {
    throw "TLS storepass resolver returned null."
  }

  $pw = $null
  $src = $DefaultSourcePath

  if ($StoreInfoMaybe -is [string]) {
    $pw = [string]$StoreInfoMaybe
  } else {
    # Prefer .Password if it exists
    if ($StoreInfoMaybe.PSObject.Properties.Name -contains 'Password') {
      $pw = [string]$StoreInfoMaybe.Password
    } elseif ($StoreInfoMaybe.PSObject.Properties.Name -contains 'Value') {
      $pw = [string]$StoreInfoMaybe.Value
    } elseif ($StoreInfoMaybe.PSObject.Properties.Name -contains 'Secret') {
      $pw = [string]$StoreInfoMaybe.Secret
    } else {
      # last resort
      try { $pw = [string]$StoreInfoMaybe.ToString() } catch { $pw = $null }
    }

    if ($StoreInfoMaybe.PSObject.Properties.Name -contains 'SourcePath') {
      $src = [string]$StoreInfoMaybe.SourcePath
    }
  }

  $pw = ($pw -replace "(\r|\n)+$","").Trim()
  if ([string]::IsNullOrWhiteSpace($pw)) {
    throw "TLS storepass resolved but was blank/whitespace."
  }

  $ascii = $true
  foreach ($ch in $pw.ToCharArray()) { if ([int][char]$ch -gt 127) { $ascii = $false; break } }

  [pscustomobject]@{
    Password   = $pw
    IsAscii7   = $ascii
    Length     = $pw.Length
    SourcePath = $src
  }
}

function Ensure-TlsStorepassJavaCompatible {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][pscustomobject]$StoreInfo,
    [Parameter(Mandatory)][string[]]$P12Paths,
    [Parameter(Mandatory)][string]$OpenSearchRootResolved
  )

  # OpenSearch (Java) PKCS12 loader will hard-fail if the PASSWORD contains any non-ASCII chars.
  # Your logs show: "Password is not ASCII" -> we MUST rotate the PKCS12 storepass to ASCII-only.
  $asciiCheck = Test-TinySocsPasswordAscii7 -Password $StoreInfo.Password
  if ($asciiCheck.Ok) {
    return $StoreInfo
  }

  Write-Log ("TLS storepass is not ASCII-7 ({0}). Rotating PKCS12 passwords to ASCII-only." -f $asciiCheck.Reason)

  $newPass = New-TinySocsAsciiPassword -Length 32

  # Rotate every referenced p12 (and be generous: also rotate all *.p12 in the same cert dir).
  $toRotate = New-Object System.Collections.Generic.HashSet[string]([StringComparer]::OrdinalIgnoreCase)
  foreach ($p in $P12Paths) {
    if ($p -and (Test-Path -LiteralPath $p -PathType Leaf)) { [void]$toRotate.Add((Resolve-Path -LiteralPath $p).Path) }
  }

  foreach ($p in @($toRotate)) {
    Set-TinySocsPkcs12PasswordDotNetCollection -P12Path $p -OldPassword $StoreInfo.Password -NewPassword $newPass
  }

  # Update DPAPI storepass in common locations (write-through if they exist; ensure primary exists).
  $primaryDpapi = $StoreInfo.SourcePath
  $candidates = @(
    $primaryDpapi,
    (Join-Path (Join-Path $ConfDir "certs") "opensearch-tls-storepass.dpapi"),
    (Join-Path $env:ProgramData "TinySocs\config\secrets\opensearch-tls-storepass.dpapi"),
    (Join-Path (Join-Path $OpenSearchRootResolved "config\certs") "opensearch-tls-storepass.dpapi")
  ) | Where-Object { $_ } | Select-Object -Unique

  foreach ($dp in $candidates) {
    try {
      # If the file exists, overwrite; if it's the primary, create if missing.
      if ((Test-Path -LiteralPath $dp -PathType Leaf) -or ($dp -eq $primaryDpapi) -or ($dp -like "*\OpenSearch\config\certs\opensearch-tls-storepass.dpapi")) {
        Set-TinySocsStorepassDpapiFile -Path $dp -Password $newPass
        Write-Log "Updated DPAPI TLS storepass: $dp"
      }
    } catch {
      Write-Log "WARN: failed updating DPAPI TLS storepass at $dp : $($_.Exception.Message)"
    }
  }

  # Verify we can open all p12 with the new pass (DotNet preflight)
  foreach ($p in @($toRotate)) {
    if (-not (Test-Pkcs12PasswordDotNet -P12Path $p -Password $newPass)) {
      throw "After rotation, DotNet preflight FAILED on $(Resolve-Path -LiteralPath $p). Aborting."
    }
  }

  # PATCH: return normalized store-info object
  return (Normalize-TinySocsStoreInfo -StoreInfoMaybe $newPass -DefaultSourcePath $primaryDpapi)
}

# --- BEGIN PATCH: public helper for "sync keystore" (drop-in compatible with earlier function) ---
function Sync-TinySocsOpenSearchTlsKeystore {
  [CmdletBinding()]
  param(
    [string]$OpenSearchHome = "C:\Program Files\TinySocs\OpenSearch",
    [string]$ConfDir        = (Join-Path $env:ProgramData "TinySocs\OpenSearch\config"),
    [string]$DpapiPath      = $null,
    [switch]$EnsureAsciiJavaCompatible
  )

  if ([string]::IsNullOrWhiteSpace($DpapiPath)) {
    $DpapiPath = Join-Path (Join-Path $ConfDir "certs") "opensearch-tls-storepass.dpapi"
  }

  $OpenSearchHomeResolved = (Resolve-Path -LiteralPath $OpenSearchHome -ErrorAction Stop).Path
  if (-not (Test-Path -LiteralPath $ConfDir -PathType Container)) { throw "OpenSearch conf dir not found: $ConfDir" }
  if (-not (Test-Path -LiteralPath $DpapiPath -PathType Leaf)) { throw "TLS storepass DPAPI file not found: $DpapiPath" }

  $yml = Join-Path $ConfDir "opensearch.yml"
  $p12s = @()
  if (Test-Path -LiteralPath $yml -PathType Leaf) {
    $p12s = @(Get-P12PathsFromYml -YmlPath $yml -BaseDir $ConfDir) | Where-Object { $_ -match '\.p12$' -and (Test-Path -LiteralPath $_ -PathType Leaf) }
  }
  if (-not $p12s -or $p12s.Count -eq 0) {
    $p12s = @(Get-FallbackP12s -CfgDir $ConfDir)
  }

  # Resolve password
  $resolver = Get-Command Resolve-TinySocsTlsStorepass -ErrorAction SilentlyContinue
  if (-not $resolver) { throw "Resolve-TinySocsTlsStorepass is not available in this session." }

  $infoRaw = $null
  if ($resolver.Parameters.ContainsKey("LiteralPath")) {
    $infoRaw = Resolve-TinySocsTlsStorepass -LiteralPath $DpapiPath
  } else {
    $infoRaw = Resolve-TinySocsTlsStorepass -ConfDir $ConfDir -OpenSearchRoot $OpenSearchHomeResolved
  }

  $info = Normalize-TinySocsStoreInfo -StoreInfoMaybe $infoRaw -DefaultSourcePath $DpapiPath

  # Optionally enforce Java ASCII compatibility (rotate PKCS12 + DPAPI if needed)
  if ($EnsureAsciiJavaCompatible -and $p12s -and $p12s.Count -gt 0) {
    $info = Ensure-TlsStorepassJavaCompatible -StoreInfo $info -P12Paths $p12s -OpenSearchRootResolved $OpenSearchHomeResolved
  }

  $pass = ($info.Password -replace "(\r|\n)+$","")

  # Apply deterministic keystore state
  Ensure-OpenSearchKeystoreSecureEntries -OpenSearchRootResolved $OpenSearchHomeResolved -TargetConfDir $ConfDir -Pass $pass

  [pscustomobject]@{
    OpenSearchHome       = $OpenSearchHomeResolved
    ConfDir              = $ConfDir
    DpapiPath            = $DpapiPath
    Ascii7               = $info.IsAscii7
    Length               = $info.Length
    SourcePath           = $info.SourcePath
    EnsuredSecureKeys    = @(
      "plugins.security.ssl.http.keystore_password_secure",
      "plugins.security.ssl.http.keystore_keypassword_secure",
      "plugins.security.ssl.http.truststore_password_secure",
      "plugins.security.ssl.transport.keystore_password_secure",
      "plugins.security.ssl.transport.keystore_keypassword_secure",
      "plugins.security.ssl.transport.truststore_password_secure"
    )
  }
}
# --- END PATCH ---

function Restart-And-Wait {
  Write-Log "Restarting service: $ServiceName"
  try { Stop-Service $ServiceName -Force -ErrorAction SilentlyContinue } catch {}
  try { Start-Service $ServiceName } catch {}

  # 300s, not 180: a cold first boot must initialize the .opendistro_security
  # index before the HTTP port opens, which alone can take ~2 min on a busy VM.
  # 180s lost that race on fresh installs; OpenSearch came up healthy seconds later.
  $waitSeconds = 300
  $deadline = (Get-Date).AddSeconds($waitSeconds)
  do {
    Start-Sleep 2
    $ok = (Test-NetConnection 127.0.0.1 -Port $HttpPort -WarningAction SilentlyContinue).TcpTestSucceeded
  } while (-not $ok -and (Get-Date) -lt $deadline)

  if (-not $ok) {
    Write-Log "OpenSearch not listening on $HttpPort within ${waitSeconds}s."
    throw "OpenSearch not listening on $HttpPort"
  }
  Write-Log "OpenSearch is listening on $HttpPort"
}

function Stop-OpenSearchForKeystoreWrites {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$ServiceName,
    [Parameter(Mandatory)][string]$OpenSearchRootResolved
  )

  # PATCH(20260114): deterministic keystore writes require that OpenSearch isn't holding the file open.
  try {
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -ne 'Stopped') {
      Write-Log "Stopping $ServiceName before keystore writes."
      Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
      Start-Sleep -Seconds 2
    }
  } catch { }

  # Best-effort: kill lingering Java launched from our OpenSearch tree (stale processes can lock keystore files)
  try {
    $osRootNorm = ($OpenSearchRootResolved.TrimEnd('\') + '\').ToLowerInvariant()
    Get-Process java -ErrorAction SilentlyContinue | ForEach-Object {
      try {
        $p = $_
        $path = $null
        try { $path = $p.Path } catch { $path = $null }
        if ($path -and ($path.ToLowerInvariant().StartsWith($osRootNorm))) {
          Write-Log ("Killing lingering java process (pid={0}) under OpenSearchRoot to release file locks." -f $p.Id)
          Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
        }
      } catch { }
    }
  } catch { }
}

# ---- main ----
$script:OpenSearchRootResolved = Resolve-OpenSearchRoot
Write-Log "PERSIST_VERSION=$script:PERSIST_VERSION"
Write-Log "OpenSearchRoot=$script:OpenSearchRootResolved"

# Ensure shim module exists for the wrapper's broken import path (ensearch.persistence.psm1)
try { Ensure-ResolverShimModule -ModulesDir $PSScriptRoot } catch { }

$configDirs = Get-ConfigDirs -ResolvedOpenSearchRoot $script:OpenSearchRootResolved
Write-Log ("ConfigDirs: {0}" -f ($configDirs -join " | "))
if (-not $configDirs -or $configDirs.Count -eq 0) { throw "No config directories resolved." }

$primaryCfg = $configDirs[0]

# Canonical TLS storepass resolution (and canonical log line)
$storeInfoRaw = Resolve-TinySocsTlsStorepass -ConfDir $ConfDir -OpenSearchRoot $script:OpenSearchRootResolved
$storeInfo = Normalize-TinySocsStoreInfo -StoreInfoMaybe $storeInfoRaw -DefaultSourcePath (Join-Path (Join-Path $ConfDir "certs") "opensearch-tls-storepass.dpapi")
Write-Log ("Decrypted storepass OK (ascii7={0}, len={1}) from: {2}" -f $storeInfo.IsAscii7, $storeInfo.Length, $storeInfo.SourcePath)

# Collect primary p12s for rotation decision (use primary config's yml if present; fallback to cert dir)
$primaryYml = Join-Path $primaryCfg "opensearch.yml"
$primaryP12s = @()
if (Test-Path -LiteralPath $primaryYml -PathType Leaf) {
  $primaryP12s = @(Get-P12PathsFromYml -YmlPath $primaryYml -BaseDir $primaryCfg) | Where-Object { $_ -match '\.p12$' -and (Test-Path -LiteralPath $_ -PathType Leaf) }
}
if (-not $primaryP12s -or $primaryP12s.Count -eq 0) {
  $primaryP12s = @(Get-FallbackP12s -CfgDir $primaryCfg)
}

# Enforce Java-compatible ASCII storepass (rotate PKCS12 + DPAPI if needed)
if ($primaryP12s -and $primaryP12s.Count -gt 0) {
  $storeInfo = Ensure-TlsStorepassJavaCompatible -StoreInfo $storeInfo -P12Paths $primaryP12s -OpenSearchRootResolved $script:OpenSearchRootResolved
}

$pass = $storeInfo.Password

# PATCH(20260114): stop OpenSearch before any keystore writes (prevents AccessDenied on rename opensearch.keystore.tmp -> opensearch.keystore)
Stop-OpenSearchForKeystoreWrites -ServiceName $ServiceName -OpenSearchRootResolved $script:OpenSearchRootResolved

foreach ($cfg in $configDirs) {
  $yml = Join-Path $cfg "opensearch.yml"
  if (-not (Test-Path -LiteralPath $yml -PathType Leaf)) {
    Write-Log "WARN: skipping config dir with no opensearch.yml: $cfg"
    continue
  }

  Ensure-YamlKeySingleLine -Path $yml -Key "network.host" -CanonicalLine ("network.host: {0}" -f $NetworkHost)
  Ensure-YamlKeySingleLine -Path $yml -Key "http.port"    -CanonicalLine ("http.port: {0}" -f $HttpPort)

  # PATCH: canonicalize clientauth_mode (OPTIONAL = accept admin client certs without requiring them)
  Ensure-YamlKeySingleLine -Path $yml -Key "plugins.security.ssl.http.clientauth_mode" -CanonicalLine ("plugins.security.ssl.http.clientauth_mode: {0}" -f $HttpClientAuthMode)

  Remove-PlaintextSslPasswordKeysFromYml -YmlPath $yml
  Ensure-YamlKeySingleLine -Path $yml -Key "plugins.security.allow_default_init_securityindex" -CanonicalLine "plugins.security.allow_default_init_securityindex: true"

  $p12s = @(Get-P12PathsFromYml -YmlPath $yml -BaseDir $cfg) | Where-Object { $_ -match '\.p12$' -and (Test-Path -LiteralPath $_ -PathType Leaf) }
  if (-not $p12s -or $p12s.Count -eq 0) {
    $p12s = @(Get-FallbackP12s -CfgDir $cfg)
  }

  if (-not $p12s -or $p12s.Count -eq 0) {
    # If this is the Program Files config dir, hydrate certs from primary and try again
    Ensure-CertsHydrated -PrimaryCfgDir $primaryCfg -TargetCfgDir $cfg

    $p12s = @(Get-P12PathsFromYml -YmlPath $yml -BaseDir $cfg) | Where-Object { $_ -match '\.p12$' -and (Test-Path -LiteralPath $_ -PathType Leaf) }
    if (-not $p12s -or $p12s.Count -eq 0) {
      $p12s = @(Get-FallbackP12s -CfgDir $cfg)
    }
  }

  if (-not $p12s -or $p12s.Count -eq 0) {
    Write-Log "WARN: No PKCS12 files found/referenced for config dir: $cfg (skipping preflight, but WILL still ensure keystore entries)"
  } else {
    foreach ($p12 in $p12s) {
      if (-not (Test-Pkcs12PasswordDotNet -P12Path $p12 -Password $pass)) {
        throw "PKCS12 preflight FAILED: resolved storepass does NOT open $(Resolve-Path -LiteralPath $p12). (cfg=$cfg)"
      }
    }
    Write-Log ("PKCS12 preflight OK ({0} files) for config dir: {1}" -f $p12s.Count, $cfg)
  }

  Ensure-OpenSearchKeystoreSecureEntries -OpenSearchRootResolved $script:OpenSearchRootResolved -TargetConfDir $cfg -Pass $pass
}

Restart-And-Wait
Write-Log "Done."

# Only export when *actually* running as a module (prevents noisy "Export-ModuleMember can only be called..." in -File runs)
$inModule = $false
try {
  if ($MyInvocation.MyCommand.Path -and ($MyInvocation.MyCommand.Path -like "*.psm1")) { $inModule = $true }
} catch { }
try {
  if ($ExecutionContext.SessionState.Module -and $ExecutionContext.SessionState.Module.Name) { $inModule = $true }
} catch { }

if ($inModule) {
  Export-ModuleMember -Function Resolve-TinySocsTlsStorepass, Sync-TinySocsOpenSearchTlsKeystore
}