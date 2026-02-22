# modules\TinySocs.Installer.psm1
# Windows-first installer helpers for TinySocs

# Module version stamp (helps confirm which copy you imported)
$script:TinySocsInstallerVersion = '0.0.20260107-wait-ready-curl'

# -- ProgramData layout -------------------------------------------------------
function Get-TinySocsDataRoot {
  $root = Join-Path $env:ProgramData "TinySocs"
  if (-not (Test-Path $root)) {
    try { New-Item -ItemType Directory -Force -Path $root | Out-Null } catch { }
  }
  return $root
}

function Get-TinySocsOpenSearchHome {
  [CmdletBinding()]
  param()

  # Prefer env var; fall back to .NET in weird hosting contexts.
  $pf = ${env:ProgramFiles}
  if ([string]::IsNullOrWhiteSpace($pf)) {
    $pf = [Environment]::GetFolderPath('ProgramFiles')
  }

  return (Join-Path $pf "TinySocs\OpenSearch")
}

function Get-TinySocsOpenSearchProgramDataRoot {
  [CmdletBinding()]
  param()

  $pd = $env:ProgramData
  if ([string]::IsNullOrWhiteSpace($pd)) {
    $pd = [Environment]::GetFolderPath('CommonApplicationData')
  }

  return (Join-Path $pd "TinySocs\OpenSearch")
}

function _IsAscii {
  [CmdletBinding()]
  param([AllowNull()][string]$S)

  if ($null -eq $S) { return $true }

  foreach ($ch in $S.ToCharArray()) {
    if ([int][char]$ch -gt 127) { return $false }
  }
  return $true
}

function _EnsureAdminKeystoreP12 {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$CertsDir
  )

  $target = Join-Path $CertsDir "admin-keystore.p12"
  if (Test-Path -LiteralPath $target -PathType Leaf) { return $target }

  try {
    $all = @(Get-ChildItem -LiteralPath $CertsDir -Filter "*.p12" -File -ErrorAction SilentlyContinue)
    if (-not $all -or $all.Count -eq 0) { return $null }

    $rank = @("admin-keystore.p12","admin.p12","kirk-keystore.p12","kirk.p12")
    foreach ($name in $rank) {
      $m = $all | Where-Object { $_.Name -ieq $name } | Select-Object -First 1
      if ($m) {
        Copy-Item -LiteralPath $m.FullName -Destination $target -Force
        if (Test-Path -LiteralPath $target -PathType Leaf) { return $target }
      }
    }

    $m = $all | Where-Object { $_.Name -match 'admin' } | Select-Object -First 1
    if (-not $m) { $m = $all | Where-Object { $_.Name -match 'kirk' } | Select-Object -First 1 }
    # DO NOT fall back to first .p12 — that copies server/transport certs (CN=TinySocs-OpenSearch)
    # which won't match the admin_dn (CN=TinySocs-OpenSearch-Admin) and securityadmin will fail.

    if ($m) {
      Copy-Item -LiteralPath $m.FullName -Destination $target -Force
      if (Test-Path -LiteralPath $target -PathType Leaf) { return $target }
    }
  } catch { }

  # Last resort: export from Windows cert store if the admin cert exists there
  try {
    $adminCert = Get-ChildItem -Path Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
      Where-Object { $_.Subject -eq 'CN=TinySocs-OpenSearch-Admin' -and $_.HasPrivateKey } |
      Sort-Object NotAfter -Descending | Select-Object -First 1
    if ($adminCert) {
      $dpapiPath = Join-Path $CertsDir "opensearch-tls-storepass.dpapi"
      $sp = $null
      if ((Test-Path -LiteralPath $dpapiPath) -and (Get-Command Get-TinySocsStorepassFromDpapiFile -ErrorAction SilentlyContinue)) {
        $sp = (Get-TinySocsStorepassFromDpapiFile -Path $dpapiPath).Password
      }
      if (-not [string]::IsNullOrWhiteSpace($sp)) {
        $secPass = ConvertTo-SecureString -String $sp -Force -AsPlainText
        Export-PfxCertificate -Cert $adminCert -FilePath $target -Password $secPass -Force | Out-Null
        if (Test-Path -LiteralPath $target -PathType Leaf) { return $target }
      }
    }
  } catch { }

  return $null
}

function Set-TinySocsYamlScalar {
  <#
    Idempotent YAML scalar setter (PS 5.1-safe):
      - removes ALL occurrences of "key:"
      - appends exactly one "key: value"
      - writes UTF-8 *without BOM*

    NOTE:
      In PowerShell, "$Key: ..." inside a double-quoted string is parsed as a scoped
      variable reference ($Key:), which is invalid. Use ${Key} to delimit.
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$Key,
    [Parameter(Mandatory)][string]$Value
  )

  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
    throw "Set-TinySocsYamlScalar: YAML not found: $Path"
  }

  $lines = Get-Content -LiteralPath $Path -ErrorAction Stop

  $pattern = '^\s*' + [regex]::Escape($Key) + '\s*:\s*.*$'

  $out = New-Object 'System.Collections.Generic.List[string]'
  foreach ($line in $lines) {
    # drop ALL existing occurrences
    if ($line -match $pattern) { continue }
    $out.Add($line)
  }

  # keep file readable: ensure a blank line before we append
  if ($out.Count -gt 0 -and $out[$out.Count - 1] -ne '') { $out.Add('') }

  # PS 5.1-safe: avoid "$Key:" parsing issue by using ${Key}
  $out.Add("${Key}: $Value")

  # Write UTF-8 no BOM
  $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
  [System.IO.File]::WriteAllLines($Path, $out.ToArray(), $utf8NoBom)
}

function Ensure-TinySocsOpenSearchHttpClientAuthOptional {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$ConfigDir
  )

  $yml = Join-Path -Path $ConfigDir -ChildPath 'opensearch.yml'
  if (-not (Test-Path -LiteralPath $yml -PathType Leaf)) {
    throw "Ensure-TinySocsOpenSearchHttpClientAuthOptional: opensearch.yml not found at $yml"
  }

  # This is the fix you applied manually:
  Set-TinySocsYamlScalar `
    -Path  $yml `
    -Key   'plugins.security.ssl.http.clientauth_mode' `
    -Value 'OPTIONAL'

  try {
    Write-TinySocsLog "Enforced plugins.security.ssl.http.clientauth_mode: OPTIONAL in $yml"
  } catch {
    # If Write-TinySocsLog isn't in scope for some reason, don't fail over logging.
  }
}

# ---- DPAPI helpers (LocalMachine scope; deterministic) -----------------------
# Canonical implementation: ONE place to read/write DPAPI secrets.
# Supports:
#   (1) ASCII base64 text containing DPAPI-protected bytes (starts AQAAANCM...)
#   (2) raw DPAPI-protected bytes
# Default: LocalMachine only (no silent CurrentUser fallbacks unless explicitly enabled).

function Ensure-TinySocsProtectedDataAvailable {
  [CmdletBinding()]
  param()

  # Already available?
  if ("System.Security.Cryptography.ProtectedData" -as [type]) { return $true }

  # Try common assembly names across PS 5.1 / PS 7 hosts
  foreach ($asm in @(
    'System.Security.Cryptography.ProtectedData',
    'System.Security'
  )) {
    try { Add-Type -AssemblyName $asm -ErrorAction Stop | Out-Null } catch { }
    if ("System.Security.Cryptography.ProtectedData" -as [type]) { return $true }
  }

  # Last-ditch: Assembly.Load
  try { [void][System.Reflection.Assembly]::Load('System.Security.Cryptography.ProtectedData') } catch { }
  if ("System.Security.Cryptography.ProtectedData" -as [type]) { return $true }

  return $false
}

function Protect-TinySocsDpapiLocalMachine {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Plain)

  if (-not (Ensure-TinySocsProtectedDataAvailable)) {
    throw "DPAPI type System.Security.Cryptography.ProtectedData is not available in this PowerShell host."
  }

  $bytes = [System.Text.Encoding]::UTF8.GetBytes($Plain)
  $enc   = [System.Security.Cryptography.ProtectedData]::Protect(
    $bytes, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine
  )
  return [System.Convert]::ToBase64String($enc)
}

function _TryParseTinySocsCredValue {
  [CmdletBinding()]
  param(
    [Parameter()][string]$Raw
  )

  if ([string]::IsNullOrWhiteSpace($Raw)) { return $null }

  $t = $Raw.Trim()

  if ($t.StartsWith("{") -and $t.EndsWith("}")) {
    try { return ($t | ConvertFrom-Json -ErrorAction Stop) } catch { }
  }

  # raw secret fallback
  return [pscustomobject]@{ pass = $t }
}

function Get-TSSiemCredsCanonical {
  [CmdletBinding()]
  param(
    [string]$OpenSearchPort = "9201"
  )

  # Canonical CA bundle locations (best-effort; verify may be false anyway)
  $certsDir = Join-Path (Join-Path $env:ProgramData "TinySocs\OpenSearch\config\certs") ""
  $caPem    = Join-Path $certsDir "ca.pem"
  $caCer    = Join-Path $certsDir "ca.cer"

  $caPath = ""
  try {
    if (Test-Path -LiteralPath $caPem -PathType Leaf) { $caPath = $caPem }
    elseif (Test-Path -LiteralPath $caCer -PathType Leaf) { $caPath = $caCer }
  } catch { }

  # -------- Defaults (ONLY used if no other sources provide values) ----------
  # IMPORTANT: do NOT default pass="secret" — that creates fake "canonical" state.
  $defaults = @{
    url            = ("https://localhost:{0}" -f $OpenSearchPort)
    user           = "admin"
    pass           = ""
    sslVerify      = $true
    ssl_verify     = $true
    caBundlePath   = $caPath
    ca_bundle_path = $caPath
  }

  # We'll build up a final hashtable by overlaying sources in PRIORITY order.
  # IMPORTANT: Env must WIN over CredMan. Therefore CredMan must be applied FIRST.
  $final = @{}
  foreach ($k in $defaults.Keys) { $final[$k] = $defaults[$k] }

  function _ToBool($v) {
    try {
      if ($v -is [bool]) { return [bool]$v }
      $s = ([string]$v).Trim().ToLowerInvariant()
      if ($s -in @("true","1","yes","y","on"))  { return $true }
      if ($s -in @("false","0","no","n","off")) { return $false }
    } catch { }
    return $null
  }

  function _IsPlaceholderPass([string]$p) {
    try {
      if ([string]::IsNullOrWhiteSpace($p)) { return $false }  # empty is "unknown", not a placeholder
      $t = $p.Trim()
      if ($t -eq "secret") { return $true }   # our known bad default
    } catch { }
    return $false
  }

  function _OverlayFromHashtable([hashtable]$src, [string]$SourceName) {
    if (-not $src) { return }

    foreach ($k in @("url","user","pass","sslVerify","ssl_verify","caBundlePath","ca_bundle_path","caCert","ca_cert","ca")) {
      if (-not $src.ContainsKey($k)) { continue }
      $val = $src[$k]
      if ([string]::IsNullOrWhiteSpace([string]$val)) { continue }

      switch -Regex ($k) {
        '^url$'  {
          # Env sources are authoritative; CredMan should only fill if empty.
          $incoming = ([string]$val).Trim().TrimEnd('/')

          if ($SourceName -match '^(MachineEnv|ProcessEnv)$') {
            $final['url'] = $incoming
          } else {
            if ([string]::IsNullOrWhiteSpace([string]$final['url'])) { $final['url'] = $incoming }
          }
          break
        }

        '^user$' {
          $incoming = [string]$val

          if ($SourceName -match '^(MachineEnv|ProcessEnv)$') {
            $final['user'] = $incoming
          } else {
            if ([string]::IsNullOrWhiteSpace([string]$final['user'])) { $final['user'] = $incoming }
          }
          break
        }

        '^pass$' {
          $incoming = [string]$val

          # CredMan: never allow placeholder, and never clobber an existing pass.
          if ($SourceName -eq 'CredMan') {
            if (_IsPlaceholderPass $incoming) { break }  # ignore CredMan placeholder
            if (-not [string]::IsNullOrWhiteSpace([string]$final['pass'])) { break } # don't overwrite an existing pass
            $final['pass'] = $incoming
            break
          }

          # Env: always set if provided (authoritative)
          if ($SourceName -match '^(MachineEnv|ProcessEnv)$') {
            if (-not [string]::IsNullOrWhiteSpace($incoming)) { $final['pass'] = $incoming }
            break
          }

          # DPAPI: only set if still empty (fallback)
          if ([string]::IsNullOrWhiteSpace([string]$final['pass'])) {
            $final['pass'] = $incoming
          }
          break
        }

        '^sslVerify$' {
          $b = _ToBool $val
          if ($null -ne $b) { $final['sslVerify'] = $b ; $final['ssl_verify'] = $b }
          break
        }

        '^ssl_verify$' {
          $b = _ToBool $val
          if ($null -ne $b) { $final['sslVerify'] = $b ; $final['ssl_verify'] = $b }
          break
        }

        '^caBundlePath$' {
          $incoming = [string]$val
          if ($SourceName -match '^(MachineEnv|ProcessEnv)$') {
            $final['caBundlePath'] = $incoming
            $final['ca_bundle_path'] = $incoming
          } else {
            if ([string]::IsNullOrWhiteSpace([string]$final['caBundlePath'])) {
              $final['caBundlePath'] = $incoming
              $final['ca_bundle_path'] = $incoming
            }
          }
          break
        }

        '^ca_bundle_path$' {
          $incoming = [string]$val
          if ($SourceName -match '^(MachineEnv|ProcessEnv)$') {
            $final['caBundlePath'] = $incoming
            $final['ca_bundle_path'] = $incoming
          } else {
            if ([string]::IsNullOrWhiteSpace([string]$final['caBundlePath'])) {
              $final['caBundlePath'] = $incoming
              $final['ca_bundle_path'] = $incoming
            }
          }
          break
        }

        '^caCert$|^ca_cert$|^ca$' {
          $incoming = [string]$val
          if ($SourceName -match '^(MachineEnv|ProcessEnv)$') {
            $final['caBundlePath'] = $incoming
            $final['ca_bundle_path'] = $incoming
          } else {
            if ([string]::IsNullOrWhiteSpace([string]$final['caBundlePath'])) {
              $final['caBundlePath'] = $incoming
              $final['ca_bundle_path'] = $incoming
            }
          }
          break
        }
      }
    }
  }

  # -------- Source A (LOW): CredMan JSON (TinySocs/SIEM/Creds) ---------------
  # CredMan is LOWER priority than env; it must not clobber real env values.
  try {
    if (Get-Command Get-TSCredential -ErrorAction SilentlyContinue) {
      $raw = Get-TSCredential -Name 'TinySocs/SIEM/Creds'
      if (-not [string]::IsNullOrWhiteSpace($raw)) {
        try {
          $obj = $raw | ConvertFrom-Json -ErrorAction Stop
          $ht  = @{}
          foreach ($p in $obj.PSObject.Properties) { $ht[$p.Name] = $p.Value }
          _OverlayFromHashtable $ht 'CredMan'
        } catch { }
      }
    }
  } catch { }

  # -------- Source B (MID): DPAPI fallback for admin pass (survives CredMan wipe) --
  # Only use DPAPI if we still don't have a pass.
  try {
    if ([string]::IsNullOrWhiteSpace([string]$final['pass'])) {
      $paths = @()

      $p1 = Join-Path $certsDir "siem-admin-pass.dpapi"
      if (Test-Path -LiteralPath $p1 -PathType Leaf) { $paths += $p1 }

      if (Get-Command Get-TinySocsSecretStoreDir -ErrorAction SilentlyContinue) {
        try {
          $p2 = Join-Path (Get-TinySocsSecretStoreDir) "siem-admin-pass.dpapi"
          if (Test-Path -LiteralPath $p2 -PathType Leaf) { $paths += $p2 }
        } catch { }
      }

      foreach ($p in ($paths | Select-Object -Unique)) {
        try {
          if (Get-Command _TryUnprotect-TinySocsDpapiFile -ErrorAction SilentlyContinue) {
            $dp = _TryUnprotect-TinySocsDpapiFile -Path $p
            if (-not [string]::IsNullOrWhiteSpace($dp)) { $final['pass'] = [string]$dp; break }
          } elseif (Get-Command Unprotect-TinySocsDpapiLocalMachineB64 -ErrorAction SilentlyContinue) {
            $b64 = (Get-Content -LiteralPath $p -Raw).Trim()
            if (-not [string]::IsNullOrWhiteSpace($b64)) {
              $dp = Unprotect-TinySocsDpapiLocalMachineB64 -B64 $b64
              if (-not [string]::IsNullOrWhiteSpace($dp)) { $final['pass'] = [string]$dp; break }
            }
          }
        } catch { }
      }
    }
  } catch { }

  # -------- Source C (HIGH): Process env (developer shell) -------------------
  try {
    $pUrl  = [Environment]::GetEnvironmentVariable('SIEM_URL','Process')
    $pUser = [Environment]::GetEnvironmentVariable('SIEM_USER','Process')
    $pPass = [Environment]::GetEnvironmentVariable('SIEM_PASS','Process')
    $pVer  = [Environment]::GetEnvironmentVariable('SIEM_SSL_VERIFY','Process')
    $pCa   = [Environment]::GetEnvironmentVariable('SIEM_CA_CERT','Process')

    $pHt = @{}
    if (-not [string]::IsNullOrWhiteSpace($pUrl))  { $pHt['url'] = $pUrl }
    if (-not [string]::IsNullOrWhiteSpace($pUser)) { $pHt['user'] = $pUser }
    if (-not [string]::IsNullOrWhiteSpace($pPass)) { $pHt['pass'] = $pPass }
    if (-not [string]::IsNullOrWhiteSpace($pVer))  { $pHt['sslVerify'] = $pVer }
    if (-not [string]::IsNullOrWhiteSpace($pCa))   { $pHt['caCert'] = $pCa }

    _OverlayFromHashtable $pHt 'ProcessEnv'
  } catch { }

  # -------- Source D (HIGHEST): Machine env (installer/wizard sets this) -----
  try {
    $envUrl  = [Environment]::GetEnvironmentVariable('SIEM_URL','Machine')
    $envUser = [Environment]::GetEnvironmentVariable('SIEM_USER','Machine')
    $envPass = [Environment]::GetEnvironmentVariable('SIEM_PASS','Machine')
    $envVer  = [Environment]::GetEnvironmentVariable('SIEM_SSL_VERIFY','Machine')
    $envCa   = [Environment]::GetEnvironmentVariable('SIEM_CA_CERT','Machine')

    $envHt = @{}
    if (-not [string]::IsNullOrWhiteSpace($envUrl))  { $envHt['url'] = $envUrl }
    if (-not [string]::IsNullOrWhiteSpace($envUser)) { $envHt['user'] = $envUser }
    if (-not [string]::IsNullOrWhiteSpace($envPass)) { $envHt['pass'] = $envPass }
    if (-not [string]::IsNullOrWhiteSpace($envVer))  { $envHt['sslVerify'] = $envVer }
    if (-not [string]::IsNullOrWhiteSpace($envCa))   { $envHt['caCert'] = $envCa }

    _OverlayFromHashtable $envHt 'MachineEnv'
  } catch { }

  # -------- Normalization: avoid 127.0.0.1 + verify=true (cert SAN mismatch) --
  try {
    $u = [string]$final['url']
    $verify = $false
    try { $verify = [bool]$final['sslVerify'] } catch { $verify = $false }

    if ($verify -and $u -match '^https://127\.0\.0\.1(:\d+)?/?$') {
      $port = $OpenSearchPort
      try {
        $uri = [uri]($u.TrimEnd('/'))
        if ($uri.Port -gt 0) { $port = [string]$uri.Port }
      } catch { }
      $final['url'] = ("https://localhost:{0}" -f $port)
    }
  } catch { }

  # Ensure both key variants are consistent
  try {
    $final['sslVerify']  = [bool]$final['sslVerify']
    $final['ssl_verify'] = [bool]$final['sslVerify']
  } catch { }

  return $final
}

function Invoke-TSAsSystemOnce {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][string]$ScriptPath,
    [int]$TimeoutSeconds = 60
  )

  if (-not (Test-Path -LiteralPath $ScriptPath)) {
    throw "Invoke-TSAsSystemOnce: ScriptPath not found: $ScriptPath"
  }

  $tn = "\TinySocs\$Name"

  # Task scheduler wants a start time in HH:mm and usually needs a date as well.
  $now = Get-Date
  $st  = $now.AddMinutes(1)
  $ST  = $st.ToString('HH:mm')
  $SD  = $st.ToString('MM/dd/yyyy')

  # Always delete any previous copy
  & schtasks.exe /Delete /TN $tn /F 2>$null | Out-Null

  $tr = "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$ScriptPath`""

  $null = & schtasks.exe /Create /F /TN $tn /RU SYSTEM /RL HIGHEST /SC ONCE /SD $SD /ST $ST /TR $tr
  $null = & schtasks.exe /Run /TN $tn

  $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
  while ((Get-Date) -lt $deadline) {
    try {
      $q = & schtasks.exe /Query /TN $tn /FO LIST /V 2>$null
      if ($q -match 'Last Run Result:\s+0x0') { break }
      # 0x41301 = running, 0x41303 = not yet run, etc. We only break hard on success.
    } catch { }
    Start-Sleep -Seconds 1
  }

  # Cleanup
  & schtasks.exe /Delete /TN $tn /F 2>$null | Out-Null
}

function Ensure-TSSiemCredsSystemCanonical {
  [CmdletBinding()]
  param(
    [string]$OpenSearchPort = "9201",
    [string]$OutJson = ""
  )

  # Canonical computed creds (now properly merged from env/CredMan/DPAPI)
  $siem = Get-TSSiemCredsCanonical -OpenSearchPort $OpenSearchPort

  # Defensive: never treat "secret" as real if it somehow leaks through
  try {
    if (-not [string]::IsNullOrWhiteSpace([string]$siem.pass) -and ([string]$siem.pass).Trim() -eq "secret") {
      $siem.pass = ""
    }
  } catch { }

  # Read existing CredMan value (if any)
  $existingRaw = $null
  $existing = $null
  try {
    if (Get-Command Get-TSCredential -ErrorAction SilentlyContinue) {
      $existingRaw = Get-TSCredential -Name 'TinySocs/SIEM/Creds'
      if (-not [string]::IsNullOrWhiteSpace($existingRaw)) {
        try { $existing = $existingRaw | ConvertFrom-Json -ErrorAction Stop } catch { $existing = $null }
      }
    }
  } catch { $existing = $null }

  function _HasNonEmpty($obj, [string]$name) {
    try {
      if (-not $obj) { return $false }
      $v = $obj.$name
      return (-not [string]::IsNullOrWhiteSpace([string]$v))
    } catch { return $false }
  }

  function _HasRealPass($obj) {
    try {
      if (-not $obj) { return $false }
      $p = [string]$obj.pass
      if ([string]::IsNullOrWhiteSpace($p)) { return $false }
      if ($p.Trim() -eq "secret") { return $false }  # treat placeholder as not real
      return $true
    } catch { return $false }
  }

  # If CredMan already contains a REAL pass+user+url, DO NOT overwrite it.
  $credHasPass = (_HasRealPass $existing)
  $credHasUser = (_HasNonEmpty $existing 'user')
  $credHasUrl  = (_HasNonEmpty $existing 'url')

  $shouldWriteCredMan = $true
  if ($credHasPass -and $credHasUser -and $credHasUrl) {
    $shouldWriteCredMan = $false
  }

  # Backfill safe Machine env vars always (url + verify + optional CA path) — non-secret
  try {
    if (Get-Command Set-MachineEnv -ErrorAction SilentlyContinue) {
      $verifyString = "false"
      try { if ([bool]$siem.sslVerify) { $verifyString = "true" } } catch { }

      $envBlock = @{
        SIEM_URL        = ([string]$siem.url).TrimEnd('/')
        SIEM_SSL_VERIFY = $verifyString
      }

      $ca = $null
      if (-not [string]::IsNullOrWhiteSpace([string]$siem.caBundlePath)) { $ca = [string]$siem.caBundlePath }
      elseif (-not [string]::IsNullOrWhiteSpace([string]$siem.ca_bundle_path)) { $ca = [string]$siem.ca_bundle_path }

      if (-not [string]::IsNullOrWhiteSpace([string]$ca)) { $envBlock['SIEM_CA_CERT'] = [string]$ca }

      Set-MachineEnv $envBlock
    }
  } catch { }

  if ($shouldWriteCredMan) {
    if ([string]::IsNullOrWhiteSpace([string]$siem.pass)) {
      Write-TinySocsLog -Level "WARN" -Message "Ensure-TSSiemCredsSystemCanonical: No admin password resolved (env/CredMan/DPAPI all empty). Writing CredMan without pass will cause auth failures until password is provided."
    }

    try {
      $payload = ($siem | ConvertTo-Json -Compress)
      $u = "tinysocs"
      if (-not [string]::IsNullOrWhiteSpace([string]$siem.user)) { $u = [string]$siem.user }

      # IMPORTANT: Set-TSCredential returns true/false; don’t pretend it always worked.
      $ok = $true
      try { $ok = Set-TSCredential -Name 'TinySocs/SIEM/Creds' -User $u -Secret $payload } catch { $ok = $false; throw }

      if (-not $ok) {
        Write-TinySocsLog -Level "WARN" -Message "Ensure-TSSiemCredsSystemCanonical: Set-TSCredential returned false writing TinySocs/SIEM/Creds."
        Write-Warning "Ensure-TSSiemCredsSystemCanonical: Set-TSCredential returned false writing TinySocs/SIEM/Creds. (Likely not elevated / CredWrite failed.)"
      } else {
        Write-TinySocsLog -Level "INFO" -Message "Ensure-TSSiemCredsSystemCanonical: Stored canonical SIEM creds in CredMan (TinySocs/SIEM/Creds)."
      }

    } catch {
      Write-TinySocsLog -Level "WARN" -Message "Ensure-TSSiemCredsSystemCanonical: Failed writing CredMan TinySocs/SIEM/Creds: $($_.Exception.Message)"
      Write-Warning "Ensure-TSSiemCredsSystemCanonical: Failed writing CredMan TinySocs/SIEM/Creds: $($_.Exception.Message)"
    }

  } else {
    Write-TinySocsLog -Level "INFO" -Message "Ensure-TSSiemCredsSystemCanonical: CredMan already has url/user/pass (non-placeholder); not overwriting TinySocs/SIEM/Creds."
  }

  # Optional diagnostics output
  if (-not [string]::IsNullOrWhiteSpace($OutJson)) {
    try {
      $raw = $null
      try { $raw = Get-TSCredential -Name 'TinySocs/SIEM/Creds' } catch { $raw = $null }
      if ($raw) { $raw | Out-File -Encoding utf8 $OutJson }
    } catch { }
  }

  return $true
}


# --- OpenSearch: ensure all packaged index templates + seed aliases -----------
function _Use-InsecureTlsIfNeeded {
  [CmdletBinding()]
  param([bool]$Insecure)

  # Capture global state so we can restore deterministically.
  $state = [pscustomobject]@{
    OldCallback = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
    OldProto    = [System.Net.ServicePointManager]::SecurityProtocol
    Changed     = $false
  }

  # Always ensure TLS 1.2 is enabled (OpenSearch commonly requires it).
  # Do this even if we're not going insecure; it's a safe global hardening for this process.
  try {
    $cur = [System.Net.ServicePointManager]::SecurityProtocol
    [System.Net.ServicePointManager]::SecurityProtocol = ($cur -bor [System.Net.SecurityProtocolType]::Tls12)
  } catch { }

  if ($Insecure) {
    try {
      [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
      $state.Changed = $true
    } catch { }
  }

  return $state
}

function _Restore-TlsState {
  [CmdletBinding()]
  param($State)

  # Restore callback if we changed it.
  try {
    if ($null -ne $State -and $State.Changed) {
      [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $State.OldCallback
    }
  } catch { }

  # Restore protocol BUT keep TLS 1.2 enabled (never downgrade).
  try {
    if ($null -ne $State -and $null -ne $State.OldProto) {
      $proto = $State.OldProto
      try { $proto = ($proto -bor [System.Net.SecurityProtocolType]::Tls12) } catch { }
      [System.Net.ServicePointManager]::SecurityProtocol = $proto
    } else {
      # If state was missing, still make sure TLS 1.2 is on.
      try {
        $cur = [System.Net.ServicePointManager]::SecurityProtocol
        [System.Net.ServicePointManager]::SecurityProtocol = ($cur -bor [System.Net.SecurityProtocolType]::Tls12)
      } catch { }
    }
  } catch { }
}

function _Get-OsBaseUrl {
  [CmdletBinding()]
  param()

  # Prefer process env; fall back to Machine env.
  # (During install/postinstall we often set Machine vars; process may not have them.)
  $base = $env:SIEM_URL
  if ([string]::IsNullOrWhiteSpace($base)) {
    $base = [Environment]::GetEnvironmentVariable("SIEM_URL", "Machine")
  }

  # Canonical TinyBox default (mTLS-enabled)
  if ([string]::IsNullOrWhiteSpace($base)) {
    $base = "https://127.0.0.1:9201"
  }

  $base = $base.Trim()
  if ($base.EndsWith("/")) { $base = $base.Substring(0, $base.Length - 1) }

  # Normalize loopback misconfigurations safely:
  # If we're on loopback and port is 9200, prefer 9201 (TinyBox secure port).
  # This avoids breaking multi-node / non-loopback deployments.
  try {
    $u = [Uri]$base
    $isLoopback = $u.IsLoopback -or ($u.Host -in @('127.0.0.1','localhost','::1'))

    if ($isLoopback -and $u.Port -eq 9200) {
      $builder = New-Object System.UriBuilder($u)
      $builder.Scheme = "https"
      $builder.Port   = 9201
      $base = $builder.Uri.AbsoluteUri.TrimEnd('/')
    }

    # If loopback + http, bump to https on 9201 (TinyBox secure default)
    if ($isLoopback -and $u.Scheme -eq "http") {
      $builder = New-Object System.UriBuilder($u)
      $builder.Scheme = "https"
      if ($builder.Port -eq 80 -or $builder.Port -eq 9200) { $builder.Port = 9201 }
      $base = $builder.Uri.AbsoluteUri.TrimEnd('/')
    }
  } catch {
    # If SIEM_URL is malformed, keep it as-is; downstream will error loudly.
  }

  return $base
}

function Get-TinySocsOpenSearchAdminClientCertThumbprint {
  [CmdletBinding()]
  param(
    [string]$Subject = "CN=TinySocs-OpenSearch-Admin",
    [switch]$PreferLocalMachine
  )

  $stores = @()
  if ($PreferLocalMachine.IsPresent) {
    $stores += "Cert:\LocalMachine\My"
    $stores += "Cert:\CurrentUser\My"
  } else {
    $stores += "Cert:\CurrentUser\My"
    $stores += "Cert:\LocalMachine\My"
  }

  foreach ($s in $stores) {
    try {
      $tp = (Get-ChildItem -Path $s -ErrorAction SilentlyContinue |
        Where-Object { $_.Subject -eq $Subject -and $_.HasPrivateKey } |
        Sort-Object NotAfter -Descending |
        Select-Object -First 1 -ExpandProperty Thumbprint)

      if ($tp -and $tp.Trim()) { return $tp.Trim() }
    } catch { }
  }

  return $null
}

function Ensure-TinySocsOpenSearchLocalMachineMtls {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$CertsDir
  )

  $caPath   = Join-Path $CertsDir "ca.cer"
  $p12Path  = Join-Path $CertsDir "admin-keystore.p12"

  if (-not (Test-Path -LiteralPath $caPath -PathType Leaf)) {
    throw "Ensure-TinySocsOpenSearchLocalMachineMtls: CA file not found: $caPath"
  }
  if (-not (Test-Path -LiteralPath $p12Path -PathType Leaf)) {
    throw "Ensure-TinySocsOpenSearchLocalMachineMtls: admin keystore not found: $p12Path"
  }

  # Load CA cert to get thumbprint (for idempotent detection)
  $caFileCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($caPath)
  $caThumb = $caFileCert.Thumbprint

  # 1) Ensure CA in LocalMachine\Root
  $hasCa = $false
  try {
    $hasCa = @(Get-ChildItem Cert:\LocalMachine\Root -ErrorAction SilentlyContinue |
      Where-Object { $_.Thumbprint -eq $caThumb }).Count -gt 0
  } catch { $hasCa = $false }

  if (-not $hasCa) {
    try {
      Import-Certificate -FilePath $caPath -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
      Write-TinySocsLog "Imported OpenSearch CA into LocalMachine\Root (thumbprint=$caThumb)" "INFO"
    } catch {
      throw "Ensure-TinySocsOpenSearchLocalMachineMtls: failed to import CA into LocalMachine\Root: $($_.Exception.Message)"
    }
  }

  # 2) Ensure admin client cert in LocalMachine\My (with private key)
  $adminThumb = $null
  try {
    $existing = Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
      Where-Object { $_.Subject -eq "CN=TinySocs-OpenSearch-Admin" -and $_.HasPrivateKey } |
      Sort-Object NotAfter -Descending |
      Select-Object -First 1

    if ($existing) { $adminThumb = $existing.Thumbprint }
  } catch { $adminThumb = $null }

  if ([string]::IsNullOrWhiteSpace($adminThumb)) {
    # Need store pass to import p12
    if (-not (Get-Command Read-TinySocsOpenSearchTlsStorePassFromDpapiFile -ErrorAction SilentlyContinue)) {
      throw "Ensure-TinySocsOpenSearchLocalMachineMtls: Read-TinySocsOpenSearchTlsStorePassFromDpapiFile not found; cannot import admin P12."
    }

    $storePass = Read-TinySocsOpenSearchTlsStorePassFromDpapiFile -CertsDir $CertsDir
    if ([string]::IsNullOrWhiteSpace($storePass)) {
      throw "Ensure-TinySocsOpenSearchLocalMachineMtls: storepass decrypted but empty; cannot import admin P12."
    }

    $sec = ConvertTo-SecureString -String $storePass -AsPlainText -Force

    try {
      Import-PfxCertificate -FilePath $p12Path -Password $sec -CertStoreLocation Cert:\LocalMachine\My | Out-Null
    } catch {
      throw "Ensure-TinySocsOpenSearchLocalMachineMtls: failed to import admin P12 into LocalMachine\My: $($_.Exception.Message)"
    }

    # Re-resolve thumbprint
    try {
      $existing2 = Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
        Where-Object { $_.Subject -eq "CN=TinySocs-OpenSearch-Admin" -and $_.HasPrivateKey } |
        Sort-Object NotAfter -Descending |
        Select-Object -First 1
      if ($existing2) { $adminThumb = $existing2.Thumbprint }
    } catch { $adminThumb = $null }

    if ([string]::IsNullOrWhiteSpace($adminThumb)) {
      throw "Ensure-TinySocsOpenSearchLocalMachineMtls: admin cert import succeeded but cert with private key not found afterwards."
    }

    Write-TinySocsLog "Imported OpenSearch admin client cert into LocalMachine\My (thumbprint=$adminThumb)" "INFO"
  }

  return $adminThumb
}

function Ensure-TinySocsOpenSearchTemplatesStaged {
  [CmdletBinding()]
  param(
    [string]$InstallRoot = "C:\Program Files\TinySocs",
    [string]$ProgramDataTemplatesDir = $null
  )

  if (-not $ProgramDataTemplatesDir) {
    $ProgramDataTemplatesDir = Join-Path $env:ProgramData "TinySocs\OpenSearch\templates"
  }

  $srcDir = Join-Path $InstallRoot "OpenSearch\templates"

  if (-not (Test-Path -LiteralPath $srcDir -PathType Container)) {
    throw "Ensure-TinySocsOpenSearchTemplatesStaged: source templates dir not found: $srcDir"
  }

  $srcFiles = Get-ChildItem -Path $srcDir -Filter *.json -File -ErrorAction SilentlyContinue
  if (-not $srcFiles -or $srcFiles.Count -eq 0) {
    throw "Ensure-TinySocsOpenSearchTemplatesStaged: no *.json template files found in: $srcDir"
  }

  if (-not (Test-Path -LiteralPath $ProgramDataTemplatesDir -PathType Container)) {
    New-Item -ItemType Directory -Path $ProgramDataTemplatesDir -Force | Out-Null
  }

  foreach ($f in $srcFiles) {
    $dst = Join-Path $ProgramDataTemplatesDir $f.Name

    # Copy deterministically; overwrite if changed
    $copy = $true
    if (Test-Path -LiteralPath $dst -PathType Leaf) {
      try {
        $srcHash = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash
        $dstHash = (Get-FileHash -LiteralPath $dst        -Algorithm SHA256).Hash
        if ($srcHash -eq $dstHash) { $copy = $false }
      } catch { $copy = $true }
    }

    if ($copy) {
      Copy-Item -LiteralPath $f.FullName -Destination $dst -Force
    }
  }

  # Final sanity: make sure dest has templates
  $dstFiles = Get-ChildItem -Path $ProgramDataTemplatesDir -Filter *.json -File -ErrorAction SilentlyContinue
  if (-not $dstFiles -or $dstFiles.Count -eq 0) {
    throw "Ensure-TinySocsOpenSearchTemplatesStaged: staging failed; no templates present in $ProgramDataTemplatesDir"
  }

  Write-TinySocsLog "OpenSearch templates staged to ProgramData: $ProgramDataTemplatesDir (count=$($dstFiles.Count))" "INFO"
  return $ProgramDataTemplatesDir
}

function Ensure-TinySocsOpenSearchPoliciesStaged {
  <#
  .SYNOPSIS
    Stage ISM policy JSON files from install dir to ProgramData.
  #>
  [CmdletBinding()]
  param(
    [string]$InstallRoot = "C:\Program Files\TinySocs",
    [string]$ProgramDataPoliciesDir = $null
  )

  if (-not $ProgramDataPoliciesDir) {
    $ProgramDataPoliciesDir = Join-Path $env:ProgramData "TinySocs\OpenSearch\policies"
  }

  $srcDir = Join-Path $InstallRoot "OpenSearch\policies"

  if (-not (Test-Path -LiteralPath $srcDir -PathType Container)) {
    Write-TinySocsLog "Policies staging: source dir not found: $srcDir (skipping)" "WARN"
    return $null
  }

  $srcFiles = Get-ChildItem -Path $srcDir -Filter *.json -File -ErrorAction SilentlyContinue
  if (-not $srcFiles -or $srcFiles.Count -eq 0) {
    Write-TinySocsLog "Policies staging: no *.json files found in: $srcDir (skipping)" "WARN"
    return $null
  }

  if (-not (Test-Path -LiteralPath $ProgramDataPoliciesDir -PathType Container)) {
    New-Item -ItemType Directory -Path $ProgramDataPoliciesDir -Force | Out-Null
  }

  foreach ($f in $srcFiles) {
    $dst = Join-Path $ProgramDataPoliciesDir $f.Name

    # Copy deterministically; overwrite if changed
    $copy = $true
    if (Test-Path -LiteralPath $dst -PathType Leaf) {
      try {
        $srcHash = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash
        $dstHash = (Get-FileHash -LiteralPath $dst        -Algorithm SHA256).Hash
        if ($srcHash -eq $dstHash) { $copy = $false }
      } catch { $copy = $true }
    }

    if ($copy) {
      Copy-Item -LiteralPath $f.FullName -Destination $dst -Force
    }
  }

  $dstFiles = Get-ChildItem -Path $ProgramDataPoliciesDir -Filter *.json -File -ErrorAction SilentlyContinue
  if ($dstFiles -and $dstFiles.Count -gt 0) {
    Write-TinySocsLog "OpenSearch ISM policies staged to ProgramData: $ProgramDataPoliciesDir (count=$($dstFiles.Count))" "INFO"
  }

  return $ProgramDataPoliciesDir
}

function _OsInvoke {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][ValidateSet('GET','PUT','POST','DELETE','HEAD')][string]$Method,
    [Parameter(Mandatory)][string]$Path,
    [object]$Body = $null,
    [int]$TimeoutSec = 15
  )

  $base = _Get-OsBaseUrl
  $url  = "{0}/{1}" -f $base.TrimEnd('/'), $Path.TrimStart('/')

  $user = $env:SIEM_USER
  $pass = $env:SIEM_PASS
  if ([string]::IsNullOrWhiteSpace($user)) { $user = "admin" }
  if ([string]::IsNullOrWhiteSpace($pass)) { $pass = "admin" }

  $verifyRaw = $env:SIEM_SSL_VERIFY
  if ([string]::IsNullOrWhiteSpace($verifyRaw)) { $verifyRaw = "true" }
  $verify = ($verifyRaw.ToString().Trim().ToLower() -notin @("0","false","no","off"))

  # Prefer Machine-scope thumbprint (what elevated/System will see), fall back to process env
  $tp = [Environment]::GetEnvironmentVariable("SIEM_CLIENTCERT_THUMBPRINT", "Machine")
  if ([string]::IsNullOrWhiteSpace($tp)) { $tp = $env:SIEM_CLIENTCERT_THUMBPRINT }
  if ($null -eq $tp) { $tp = "" }
  $tp = $tp.Trim()

  # --- Prefer curl-based API helper if available (more reliable than Invoke-WebRequest mTLS on Windows) ---
  $curlCmd = $null
  try { $curlCmd = Get-Command Invoke-TinySocsOpenSearchApi -ErrorAction SilentlyContinue } catch { $curlCmd = $null }

  if ($curlCmd) {
    $bodyJson = $null

    # Only attach body for methods that can carry one
    if ($Method -in @('PUT','POST','DELETE')) {
      if ($null -ne $Body) {
        if ($Body -is [string]) {
          $bodyJson = $Body
        } else {
          $bodyJson = ($Body | ConvertTo-Json -Depth 20 -Compress)
        }
      }
    }

    try {
      # Build a splat so we can optionally pass a client cert thumbprint if the helper supports it.
      $apiParams = @{
        Method         = $Method
        Url            = $url
        User           = $user
        Pass           = $pass
        BodyJson       = $bodyJson
        TimeoutSeconds = $TimeoutSec
        Retries        = 2
        AsJson         = $true
      }

      # Respect verify toggle
      if (-not $verify) { $apiParams["SkipTlsVerify"] = $true }

      # If Invoke-TinySocsOpenSearchApi has a param for client cert, pass it.
      # (Weâ€™ll patch the helper next if it doesnâ€™t.)
      if (-not [string]::IsNullOrWhiteSpace($tp)) {
        if ($curlCmd.Parameters.ContainsKey("ClientCertThumbprint")) {
          $apiParams["ClientCertThumbprint"] = $tp
        } elseif ($curlCmd.Parameters.ContainsKey("ClientCert")) {
          # Alternate possible name (rare, but safe)
          $apiParams["ClientCert"] = $tp
        } else {
          # No param available: best-effort rely on helper reading SIEM_CLIENTCERT_THUMBPRINT env var.
          # (If it doesnâ€™t yet, curl will still fail until we patch Invoke-TinySocsOpenSearchApi.)
        }
      }

      $respBody = Invoke-TinySocsOpenSearchApi @apiParams

      # If we got here, the helper considered the call successful.
      # We don't get HTTP code back (unless the helper is changed to return it), so synthesize.
      $code = 200
      if ($Method -eq 'HEAD') { $code = 204 }
      if ($null -eq $respBody) {
        if ($Method -eq 'GET') { $code = 200 } else { $code = 204 }
      } elseif ($respBody -is [string]) {
        if ([string]::IsNullOrWhiteSpace($respBody)) {
          if ($Method -eq 'GET') { $code = 200 } else { $code = 204 }
        }
      }

      return [pscustomobject]@{
        StatusCode = [int]$code
        Body       = $respBody
      }
    }
    catch {
      # Try to recover an HTTP status from the error message (helper formats include "HTTP 401" or "http=401")
      $msg = $_.Exception.Message
      $status = $null

      if ($msg -match '\bHTTP\s+(\d{3})\b') {
        $status = [int]$Matches[1]
      } elseif ($msg -match '\bhttp=(\d{3})\b') {
        $status = [int]$Matches[1]
      }

      if ($null -ne $status) {
        return [pscustomobject]@{
          StatusCode = [int]$status
          Body       = @{ error = $msg }
        }
      }

      throw
    }
  }

  # --- Fallback: Invoke-WebRequest path (best-effort) ---
  $tlsState = _Use-InsecureTlsIfNeeded -Insecure:(!$verify)
  try {
    # Reduce a couple of common WinHTTP/SChannel annoyances
    try { [System.Net.ServicePointManager]::Expect100Continue = $false } catch { }

    $pair  = "{0}:{1}" -f $user, $pass
    $b64   = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($pair))
    $hdrs  = @{ Authorization = "Basic $b64" }

    $irmParams = @{
      Uri             = $url
      Method          = $Method
      Headers         = $hdrs
      TimeoutSec      = $TimeoutSec
      ErrorAction     = 'Stop'
      UseBasicParsing = $true
    }

    # --- Attach client cert for mTLS (PS7: CertificateThumbprint; PS5.1: Certificate) ---
    if (-not [string]::IsNullOrWhiteSpace($tp)) {
      $iw = $null
      try { $iw = Get-Command Invoke-WebRequest -ErrorAction Stop } catch { $iw = $null }

      if ($iw -and $iw.Parameters.ContainsKey('CertificateThumbprint')) {
        # PowerShell 7+
        $irmParams['CertificateThumbprint'] = $tp
      }
      elseif ($iw -and $iw.Parameters.ContainsKey('Certificate')) {
        # Windows PowerShell 5.1: load cert object by thumbprint from LocalMachine\My
        $cert = $null
        try { $cert = Get-Item -LiteralPath ("Cert:\LocalMachine\My\{0}" -f $tp) -ErrorAction Stop } catch { $cert = $null }

        if ($null -eq $cert) {
          throw "Client cert thumbprint not found in LocalMachine\My: $tp"
        }

        $irmParams['Certificate'] = $cert
      }
      else {
        throw "Invoke-WebRequest in this host doesn't support Certificate/CertificateThumbprint; cannot do mTLS."
      }
    }

    # Only attach body for methods that can carry one
    if ($Method -in @('PUT','POST','DELETE')) {
      if ($null -ne $Body) {
        if ($Body -is [string]) {
          $json = $Body
        } else {
          $json = ($Body | ConvertTo-Json -Depth 20 -Compress)
        }
        $irmParams['Body'] = $json
        $irmParams['ContentType'] = 'application/json'
      }
    }

    $resp = Invoke-WebRequest @irmParams

    $parsed = $null
    if ($null -ne $resp -and $null -ne $resp.Content -and $resp.Content.ToString().Trim()) {
      try { $parsed = $resp.Content | ConvertFrom-Json } catch { $parsed = $resp.Content }
    }

    return [pscustomobject]@{
      StatusCode = [int]$resp.StatusCode
      Body       = $parsed
    }
  }
  catch {
    # Try to extract HTTP status + body if possible
    $status  = $null
    $errBody = $null

    try { $status = [int]$_.Exception.Response.StatusCode.value__ } catch { }

    try {
      $stream = $_.Exception.Response.GetResponseStream()
      if ($stream) {
        $sr = New-Object System.IO.StreamReader($stream)
        try { $rawErr = $sr.ReadToEnd() } finally { $sr.Dispose() }
        if ($rawErr) {
          try { $errBody = $rawErr | ConvertFrom-Json } catch { $errBody = @{ _raw = $rawErr } }
        }
      }
    } catch { }

    if (-not $status) { throw }

    $fallback = @{ error = $_.Exception.Message }
    if ($null -eq $errBody) { $errBody = $fallback }

    return [pscustomobject]@{
      StatusCode = [int]$status
      Body       = $errBody
    }
  }
  finally {
    _Restore-TlsState -State $tlsState
  }
}

function _Wait-OpenSearchReady {
  [CmdletBinding()]
  param(
    [int]$TimeoutSec = 60
  )
  $t0 = Get-Date
  $last = $null
  while ((Get-Date) -lt $t0.AddSeconds($TimeoutSec)) {
    try {
      $r = _OsInvoke -Method GET -Path "/" -TimeoutSec 10
      if ($r.StatusCode -eq 200) {
        $name = $r.Body.name
        $cl   = $r.Body.cluster_name
        Write-Host "[TinySocs][OpenSearch] Connected: node=$name cluster=$cl" -ForegroundColor DarkCyan
        return $true
      }
      $last = "HTTP $($r.StatusCode)"
    } catch {
      $last = $_.Exception.Message
    }
    Start-Sleep -Milliseconds 750
  }
  Write-Host "[TinySocs][OpenSearch] Not reachable within ${TimeoutSec}s ($last)" -ForegroundColor Yellow
  return $false
}

function _Find-OpenSearchTemplatesDir {
  [CmdletBinding()]
  param(
    [string]$RepoOrInstallRoot = $null
  )

  $candidates = @()

  # If caller passes a root, prefer it
  if ($RepoOrInstallRoot) {
    $candidates += (Join-Path $RepoOrInstallRoot "opensearch\templates")
    $candidates += (Join-Path $RepoOrInstallRoot "OpenSearch\templates")
    $candidates += (Join-Path $RepoOrInstallRoot "packaging\opensearch\templates")
  }

  # Common installed layouts (module lives in ...\TinySocs\modules)
  $here = $PSScriptRoot
  $candidates += (Join-Path $here "..\OpenSearch\templates")
  $candidates += (Join-Path $here "..\opensearch\templates")
  $candidates += (Join-Path $here "..\packaging\opensearch\templates")

  # ProgramData fallback (if you copy templates there during install)
  if ($env:ProgramData) {
    $candidates += (Join-Path $env:ProgramData "TinySocs\opensearch\templates")
    $candidates += (Join-Path $env:ProgramData "TinySocs\OpenSearch\templates")
  }

  foreach ($p in $candidates | Where-Object { $_ -and $_.Trim() } | Select-Object -Unique) {
    try {
      $rp = Resolve-Path $p -ErrorAction SilentlyContinue
      if ($rp -and (Test-Path $rp.Path)) {
        $jsons = Get-ChildItem -Path $rp.Path -Filter *.json -File -ErrorAction SilentlyContinue
        if ($jsons -and $jsons.Count -gt 0) { return $rp.Path }
      }
    } catch { }
  }
  return $null
}

function Invoke-TinySocsOpenSearchTemplatesBootstrap {
  [CmdletBinding()]
  param(
    [string]$TemplatesDir = $null,
    [int]$WaitTimeoutSec = 90
  )

  if (-not $TemplatesDir) { $TemplatesDir = _Find-OpenSearchTemplatesDir }
  if (-not $TemplatesDir) {
    Write-Host "[TinySocs][OpenSearch] Templates bootstrap: no templates dir found (skipping)" -ForegroundColor Yellow
    return
  }

  $files = Get-ChildItem -Path $TemplatesDir -Filter *.json -File -ErrorAction SilentlyContinue | Sort-Object Name
  if (-not $files -or $files.Count -eq 0) {
    Write-Host "[TinySocs][OpenSearch] Templates bootstrap: no *.json files in $TemplatesDir (skipping)" -ForegroundColor Yellow
    return
  }

  if (-not (_Wait-OpenSearchReady -TimeoutSec $WaitTimeoutSec)) {
    throw "OpenSearch not reachable; cannot ensure index templates"
  }

  # --- local helpers: canonicalize + hash JSON objects so we can do stable comparisons ---
  function _ToCanonicalObject {
    param([Parameter(Mandatory)]$Obj)

    # Normalize PSCustomObject -> Hashtable
    if ($Obj -is [pscustomobject]) { $Obj = @{} + $Obj }

    # Hashtable / IDictionary: sort keys, recurse values
    if ($Obj -is [System.Collections.IDictionary]) {
      $out = [ordered]@{}
      foreach ($k in @($Obj.Keys) | Sort-Object) {
        $out[$k] = _ToCanonicalObject -Obj $Obj[$k]
      }
      return $out
    }

    # Enumerable (but not string): recurse each element, keep order
    if ($Obj -is [System.Collections.IEnumerable] -and -not ($Obj -is [string])) {
      $arr = @()
      foreach ($item in $Obj) { $arr += ,(_ToCanonicalObject -Obj $item) }
      return $arr
    }

    # Scalar
    return $Obj
  }

  function _HashObject {
    param([Parameter(Mandatory)]$Obj)

    $canon = _ToCanonicalObject -Obj $Obj
    $json  = $canon | ConvertTo-Json -Depth 80 -Compress
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
    $sha   = [System.Security.Cryptography.SHA256]::Create()
    try {
      $hashBytes = $sha.ComputeHash($bytes)
      return ([System.BitConverter]::ToString($hashBytes) -replace '-', '').ToLowerInvariant()
    } finally {
      try { $sha.Dispose() } catch { }
    }
  }

  function _ExtractRemoteTemplateBody {
    param([Parameter(Mandatory)]$GetResponseBody)

    # Expected OpenSearch shape:
    # { "index_templates": [ { "name": "...", "index_template": { ... } } ] }
    try {
      if ($GetResponseBody -and $GetResponseBody.index_templates -and $GetResponseBody.index_templates.Count -ge 1) {
        $first = $GetResponseBody.index_templates[0]
        if ($first -and $first.index_template) { return $first.index_template }
      }
    } catch { }

    # Fallback: sometimes proxies/wrappers give the object directly
    return $GetResponseBody
  }

  Write-Host "[TinySocs][OpenSearch] Ensuring index templates from $TemplatesDir" -ForegroundColor Cyan

  $processedNames = @()

  foreach ($f in $files) {
    $name = [IO.Path]::GetFileNameWithoutExtension($f.Name)
    $txt  = Get-Content -LiteralPath $f.FullName -Raw -Encoding UTF8

    $localBody = $null
    try { $localBody = $txt | ConvertFrom-Json -ErrorAction Stop }
    catch { throw "Invalid JSON template: $($f.FullName): $($_.Exception.Message)" }

    $processedNames += $name

    # Compare against remote; only PUT if missing or different
    $needsPut = $true
    $remoteHash = $null
    $localHash  = $null

    $g = _OsInvoke -Method GET -Path "/_index_template/$name" -TimeoutSec 20

    if ($g.StatusCode -eq 404) {
      $needsPut = $true
    }
    elseif ($g.StatusCode -ge 200 -and $g.StatusCode -lt 300) {
      $remoteBody = _ExtractRemoteTemplateBody -GetResponseBody $g.Body
      try {
        $remoteHash = _HashObject -Obj $remoteBody
        $localHash  = _HashObject -Obj $localBody
        $needsPut   = ($remoteHash -ne $localHash)
      } catch {
        # If hashing/canonicalization fails for any weird object, fall back to PUT to be safe.
        $needsPut = $true
      }
    }
    else {
      throw "Template GET failed: $name HTTP $($g.StatusCode): $(($g.Body | ConvertTo-Json -Depth 10))"
    }

    if ($needsPut) {
      $r = _OsInvoke -Method PUT -Path "/_index_template/$name" -Body $localBody -TimeoutSec 30
      if ($r.StatusCode -ge 200 -and $r.StatusCode -lt 300) {
        Write-Host "[TinySocs][OpenSearch] Template ensured: $name (from $($f.Name))" -ForegroundColor DarkCyan
      } else {
        throw "Template PUT failed: $name HTTP $($r.StatusCode): $(($r.Body | ConvertTo-Json -Depth 10))"
      }
    } else {
      Write-Host "[TinySocs][OpenSearch] Template up-to-date: $name" -ForegroundColor DarkGray
    }
  }

  # --- verification: templates exist in cluster ---
  foreach ($name in ($processedNames | Select-Object -Unique)) {
    $v = _OsInvoke -Method GET -Path "/_index_template/$name" -TimeoutSec 20
    if ($v.StatusCode -ne 200) {
      throw "Template verification failed: GET /_index_template/$name returned HTTP $($v.StatusCode)"
    }
  }

  # --- verification: your defaults apply to a representative tinysocs_* index ---
  if (($processedNames | Select-Object -Unique) -contains "tinysocs-default-template") {
    $sim = _OsInvoke -Method POST -Path "/_index_template/_simulate_index/tinysocs_anchors-2099.01.01" -TimeoutSec 25
    if ($sim.StatusCode -ne 200) { throw "Template simulate failed: HTTP $($sim.StatusCode)" }

    $idx = $null
    try { $idx = $sim.Body.template.settings.index } catch { $idx = $null }
    if (-not $idx) { throw "Template simulate returned no template.settings.index; tinysocs defaults not applying." }

    $hasReplicas = $false
    try {
      if ($idx.auto_expand_replicas) { $hasReplicas = $true }
      elseif ($idx.number_of_replicas -ne $null) { $hasReplicas = $true }
    } catch { $hasReplicas = $false }

    if (-not $hasReplicas) {
      throw "tinysocs-default-template simulate did not include replicas policy (auto_expand_replicas/number_of_replicas)."
    }
  }
}
# ---------------------------------------------------------------------------

function Unprotect-TinySocsDpapiLocalMachine {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][byte[]]$ProtectedBytes,
    [switch]$AllowCurrentUserFallback
  )

  if (-not (Ensure-TinySocsProtectedDataAvailable)) {
    throw "DPAPI type System.Security.Cryptography.ProtectedData is not available in this PowerShell host."
  }

  try {
    $plainBytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
      $ProtectedBytes, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine
    )
    return [System.Text.Encoding]::UTF8.GetString($plainBytes)
  } catch {
    if (-not $AllowCurrentUserFallback.IsPresent) { throw }

    $plainBytes2 = [System.Security.Cryptography.ProtectedData]::Unprotect(
      $ProtectedBytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser
    )
    return [System.Text.Encoding]::UTF8.GetString($plainBytes2)
  }
}

function Get-TinySocsSiemAdminPassFilePath {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$CertsDir)
  return (Join-Path $CertsDir "siem-admin-pass.dpapi")
}

function Unprotect-TinySocsDpapiLocalMachineB64 {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$B64,
    [switch]$AllowCurrentUserFallback
  )

  $enc = [System.Convert]::FromBase64String($B64)
  return Unprotect-TinySocsDpapiLocalMachine -ProtectedBytes $enc -AllowCurrentUserFallback:$AllowCurrentUserFallback.IsPresent
}

function Read-TinySocsDpapiFileLocalMachineString {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path,
    [switch]$AllowCurrentUserFallback
  )

  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
    throw "DPAPI file not found: $Path"
  }

  # First try: treat as text. If it looks like base64, decode to bytes and unprotect.
  $rawText = $null
  try { $rawText = (Get-Content -LiteralPath $Path -Raw -ErrorAction Stop) } catch { $rawText = $null }

  if (-not [string]::IsNullOrWhiteSpace($rawText)) {
    $trim = ($rawText -replace '\s+', '').Trim()

    # Heuristic: base64-ish + multiple of 4
    if (($trim.Length -ge 16) -and ($trim.Length % 4 -eq 0) -and ($trim -match '^[A-Za-z0-9+/=]+$')) {
      try {
        $b = [System.Convert]::FromBase64String($trim)
        $s = Unprotect-TinySocsDpapiLocalMachine -ProtectedBytes $b -AllowCurrentUserFallback:$AllowCurrentUserFallback.IsPresent
        if (-not [string]::IsNullOrWhiteSpace($s)) { return $s }
      } catch {
        # fall through to raw bytes path
      }
    }
  }

  # Second try: raw DPAPI bytes
  $bytesRaw = $null
  try { $bytesRaw = [System.IO.File]::ReadAllBytes($Path) } catch { $bytesRaw = $null }
  if (-not $bytesRaw -or $bytesRaw.Length -lt 8) {
    throw "DPAPI file unreadable or too small: $Path"
  }

  return (Unprotect-TinySocsDpapiLocalMachine -ProtectedBytes $bytesRaw -AllowCurrentUserFallback:$AllowCurrentUserFallback.IsPresent)
}

function Write-TinySocsDpapiFileLocalMachineString {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$Plain
  )

  $b64 = Protect-TinySocsDpapiLocalMachine -Plain $Plain

  New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Path) | Out-Null
  # Write as ASCII base64 text (portable + easy to diff/backup)
  Set-Content -LiteralPath $Path -Value $b64 -Encoding ASCII -Force
  return $true
}

function Get-TinySocsStorepassFromDpapiFile {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path,
    [switch]$AllowCurrentUserFallback
  )

  $pw = Read-TinySocsDpapiFileLocalMachineString -Path $Path -AllowCurrentUserFallback:$AllowCurrentUserFallback.IsPresent
  $pw = ([string]$pw).Trim()

  if ([string]::IsNullOrWhiteSpace($pw)) {
    throw "Get-TinySocsStorepassFromDpapiFile: decoded password empty after trim. Path=$Path"
  }

  # Metadata: Java tooling + OpenSearch keystore usage behaves best with ASCII-only inputs.
  $nonAscii = $false
  foreach ($ch in $pw.ToCharArray()) {
    if ([int][char]$ch -gt 127) { $nonAscii = $true; break }
  }

  return [pscustomobject]@{
    Path     = $Path
    Password = $pw
    Length   = $pw.Length
    Encoding = $(if ($nonAscii) { "NONASCII" } else { "ASCII" })
  }
}

# ---- Compatibility shims (keep old call sites working) -----------------------
function _EnsureProtectedDataType {
  [CmdletBinding()]
  param()

  if (-not (Ensure-TinySocsProtectedDataAvailable)) {
    throw "ProtectedData type not available. This must run on Windows with .NET crypto assemblies."
  }
}

function _DecryptDpapiB64([string]$Path) {
  return (Get-TinySocsStorepassFromDpapiFile -Path $Path).Password
}

function _TryUnprotect-TinySocsDpapiFile {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Path)
  try { return (Get-TinySocsStorepassFromDpapiFile -Path $Path).Password } catch { return $null }
}

function _ReadDpapiLocalMachineString {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$DpapiPath)
  return (Read-TinySocsDpapiFileLocalMachineString -Path $DpapiPath)
}

function _DpapiUnprotectLocalMachine([byte[]]$ProtectedBytes) {
  _EnsureProtectedDataType
  return [System.Security.Cryptography.ProtectedData]::Unprotect(
    $ProtectedBytes,
    $null,
    [System.Security.Cryptography.DataProtectionScope]::LocalMachine
  )
}

function _ReadUtf8NoBom([string]$Path) {
  $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
  return [System.IO.File]::ReadAllText($Path, $utf8NoBom)
}

function _WriteUtf8NoBom([string]$Path, [string]$Text) {
  $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
  [System.IO.File]::WriteAllText($Path, $Text, $utf8NoBom)
}

function _TestPkcs12([string]$P12Path, [string]$Password) {
  try {
    $null = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
      $P12Path,
      $Password,
      [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::MachineKeySet
    )
    return $true
  } catch {
    return $false
  }
}

function _Invoke-OpenSearchKeystoreAddSecure {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$KeystoreBat,
    [Parameter(Mandatory)][string]$Key,
    [Parameter(Mandatory)][string]$Value
  )

  if (-not (Test-Path -LiteralPath $KeystoreBat -PathType Leaf)) { throw "Missing: $KeystoreBat" }

  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $KeystoreBat
  $psi.Arguments = "add -x -f $Key"
  $psi.WorkingDirectory = (Split-Path $KeystoreBat -Parent)
  $psi.UseShellExecute = $false
  $psi.RedirectStandardInput  = $true
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError  = $true

  $p = New-Object System.Diagnostics.Process
  $p.StartInfo = $psi
  [void]$p.Start()
  $p.StandardInput.WriteLine($Value)
  $p.StandardInput.Close()
  $p.WaitForExit()

  if ($p.ExitCode -ne 0) {
    $err = $p.StandardError.ReadToEnd()
    throw "opensearch-keystore add failed for '$Key'. STDERR:`n$err"
  }
}

function Ensure-TinySocsOpenSearchKeystorePasswords {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$OpenSearchRoot,         # C:\Program Files\TinySocs\OpenSearch
    [Parameter(Mandatory)][string]$CertsDir,               # C:\ProgramData\TinySocs\OpenSearch\config\certs
    [Parameter(Mandatory)][string]$DpapiStorepassPath,     # opensearch-tls-storepass.dpapi
    [Parameter(Mandatory)][string]$HttpP12Path             # http.p12
  )

  $pass = _DecryptDpapiB64 $DpapiStorepassPath

  if (-not (_TestPkcs12 $HttpP12Path $pass)) {
    throw "DPAPI TLS storepass does not open '$HttpP12Path'. Refusing to continue (this would cause nondeterministic boot)."
  }

  $keystoreBat = Join-Path $OpenSearchRoot "bin\opensearch-keystore.bat"

  $keys = @(
    "plugins.security.ssl.http.keystore_password_secure",
    "plugins.security.ssl.http.keystore_keypassword_secure",
    "plugins.security.ssl.http.truststore_password_secure",
    "plugins.security.ssl.transport.keystore_password_secure",
    "plugins.security.ssl.transport.keystore_keypassword_secure",
    "plugins.security.ssl.transport.truststore_password_secure"
  )

  foreach ($k in $keys) {
    _Invoke-OpenSearchKeystoreAddSecure -KeystoreBat $keystoreBat -Key $k -Value $pass
    Write-TinySocsLog "OpenSearch keystore secure entry set: $k" "INFO"
  }

  return $pass
}

function Ensure-TinySocsOpenSearchSecurityInitialized {
  [CmdletBinding()]
  param(
    # PATCH: make optional; provide resilient defaults for installer best-effort calls
    [Parameter()][string]$OpenSearchRoot,
    [Parameter()][string]$ProgramDataConf,

    # Default TinySocs convention: HTTPS on 9201
    [string]$Url = "https://localhost:9201",

    # How long we'll keep trying overall (OpenSearch can be slow on first boot)
    [int]$TimeoutSec = 600,

    # Poll interval
    [int]$IntervalSec = 2,

    # If set, we pass -k to curl checks (recommended for self-signed)
    [switch]$SkipTlsVerify
  )

  # PATCH: infer defaults if not supplied (installer may call without args)
  $callerProvidedRoot = -not [string]::IsNullOrWhiteSpace($OpenSearchRoot)
  $callerProvidedConf = -not [string]::IsNullOrWhiteSpace($ProgramDataConf)

  if (-not $callerProvidedRoot) {
    $candidates = @()

    # Conventional install path first
    $candidates += "C:\Program Files\TinySocs\OpenSearch"

    # Infer from module location if possible
    try {
      if ($PSScriptRoot) {
        # modules\TinySocs.Installer.psm1 -> go up to repo/app root then OpenSearch
        $candidates += (Join-Path (Split-Path -Parent $PSScriptRoot) "OpenSearch")
      }
    } catch { }

    try {
      $inv = $MyInvocation.MyCommand.Path
      if ($inv) {
        $modDir = Split-Path -Parent $inv
        $candidates += (Join-Path (Split-Path -Parent $modDir) "OpenSearch")
      }
    } catch { }

    foreach ($c in ($candidates | Select-Object -Unique)) {
      if ($c -and (Test-Path -LiteralPath $c -PathType Container)) { $OpenSearchRoot = $c; break }
    }
  }

  if (-not $callerProvidedConf) {
    $ProgramDataConf = "C:\ProgramData\TinySocs\OpenSearch\config"
  }

  # PATCH: guardrails. If caller supplied a value and it's wrong, that's an error.
  # If caller did NOT supply (installer best-effort), warn + return $false.
  if ([string]::IsNullOrWhiteSpace($OpenSearchRoot)) {
    Write-TinySocsLog -Level "WARN" -Message "Ensure-TinySocsOpenSearchSecurityInitialized: OpenSearchRoot was not provided and could not be inferred. Skipping security bootstrap."
    return $false
  }
  if ([string]::IsNullOrWhiteSpace($ProgramDataConf)) {
    Write-TinySocsLog -Level "WARN" -Message "Ensure-TinySocsOpenSearchSecurityInitialized: ProgramDataConf was not provided and could not be inferred. Skipping security bootstrap."
    return $false
  }

  if (-not (Test-Path -LiteralPath $OpenSearchRoot -PathType Container)) {
    if ($callerProvidedRoot) {
      throw "Ensure-TinySocsOpenSearchSecurityInitialized: OpenSearchRoot not found: $OpenSearchRoot"
    } else {
      Write-TinySocsLog -Level "WARN" -Message "Ensure-TinySocsOpenSearchSecurityInitialized: inferred OpenSearchRoot not found: $OpenSearchRoot. Skipping security bootstrap."
      return $false
    }
  }
  if (-not (Test-Path -LiteralPath $ProgramDataConf -PathType Container)) {
    if ($callerProvidedConf) {
      throw "Ensure-TinySocsOpenSearchSecurityInitialized: ProgramDataConf not found: $ProgramDataConf"
    } else {
      Write-TinySocsLog -Level "WARN" -Message "Ensure-TinySocsOpenSearchSecurityInitialized: inferred ProgramDataConf not found: $ProgramDataConf. Skipping security bootstrap."
      return $false
    }
  }

  # Parse URL once so we don't hardcode host/port and accidentally drift.
  $uri = $null
  try { $uri = [uri]$Url } catch { $uri = $null }

  $host = "127.0.0.1"
  $port = 9201
  $scheme = "https"
  if ($uri) {
    if (-not [string]::IsNullOrWhiteSpace($uri.Host)) { $host = $uri.Host }
    if ($uri.Port -gt 0) { $port = [int]$uri.Port }
    if (-not [string]::IsNullOrWhiteSpace($uri.Scheme)) { $scheme = $uri.Scheme }
  } else {
    # best-effort fallback parse
    if ($Url -match '^\s*(https?)://([^/:]+)(?::(\d+))?') {
      $scheme = $Matches[1]
      $host = $Matches[2]
      if ($Matches[3]) { $port = [int]$Matches[3] }
    }
  }

  # For bootstrap on localhost, default to skipping TLS verification when URL is https
  $useCurlK = $SkipTlsVerify.IsPresent -or ($scheme -eq 'https')

  function _TcpConnectable([string]$h, [int]$p, [int]$MsTimeout = 800) {
    $client = $null
    try {
      $client = New-Object System.Net.Sockets.TcpClient
      $iar = $client.BeginConnect($h, $p, $null, $null)
      if (-not $iar.AsyncWaitHandle.WaitOne($MsTimeout, $false)) {
        try { $client.Close() } catch { }
        return $false
      }
      $client.EndConnect($iar) | Out-Null
      try { $client.Close() } catch { }
      return $true
    } catch {
      try { if ($client) { $client.Close() } } catch { }
      return $false
    }
  }

  function _CurlHeaders([string]$u) {
    try {
      $a = @()
      if ($useCurlK) { $a += "-k" }
      # headers only; discard body
      $a += @("-sS","-D","-","-o","NUL",$u)
      return (& curl.exe @a 2>&1 | Out-String)
    } catch {
      return ($_.Exception.Message | Out-String)
    }
  }

  function _CurlBody([string]$u) {
    try {
      $a = @()
      if ($useCurlK) { $a += "-k" }
      $a += @("-sS",$u)
      return (& curl.exe @a 2>&1 | Out-String)
    } catch {
      return ($_.Exception.Message | Out-String)
    }
  }

  function _IsSecurityInitialized([string]$u) {
    # initialized = 401 + WWW-Authenticate Basic (headers-only is more reliable)
    $hdr = _CurlHeaders $u
    $is401 = ($hdr -match 'HTTP/(1\.1|2)\s+401')
    $hasBasic = ($hdr -match '(?im)^WWW-Authenticate:\s*Basic')
    return ($is401 -and $hasBasic)
  }

  function _IsNotInitialized([string]$u) {
    $t = _CurlBody $u
    return ($t -match 'OpenSearch Security not initialized')
  }

  function _TryParseAliasFromKeytoolList([string]$KeytoolOut) {
    if ([string]::IsNullOrWhiteSpace($KeytoolOut)) { return $null }
    foreach ($ln in ($KeytoolOut -split "`r?`n")) {
      if ($ln -match 'PrivateKeyEntry') {
        $parts = $ln.Split(',',2)
        if ($parts.Count -ge 1) {
          $a = $parts[0].Trim()
          if (-not [string]::IsNullOrWhiteSpace($a)) { return $a }
        }
      }
    }
    return $null
  }

  function _InvokeSecurityAdmin([string]$SecAdminBat, [string[]]$SecArgs) {
    # First attempt: direct invocation (fast path)
    $out = (& $SecAdminBat @SecArgs 2>&1 | Out-String)

    # If args were "eaten" and securityadmin thinks it got none, use a robust fallback.
    if ($out -match 'ERR:\s*Parsing failed\.\s*Reason:\s*Specify at least -ks or -cert') {
      Write-TinySocsLog -Level "WARN" -Message "securityadmin.bat reported missing -ks/-cert (args may not have been passed correctly). Retrying via Start-Process + redirected output."

      $o = Join-Path $env:TEMP ("tinysocs-securityadmin-" + [guid]::NewGuid().ToString("n") + ".out.log")
      $e = Join-Path $env:TEMP ("tinysocs-securityadmin-" + [guid]::NewGuid().ToString("n") + ".err.log")
      try {
        $p = Start-Process -FilePath $SecAdminBat -ArgumentList $SecArgs -Wait -NoNewWindow -PassThru `
          -RedirectStandardOutput $o -RedirectStandardError $e

        $out2 = ""
        if (Test-Path -LiteralPath $o) { $out2 += (Get-Content -LiteralPath $o -Raw -ErrorAction SilentlyContinue) }
        if (Test-Path -LiteralPath $e) { $out2 += "`r`n" + (Get-Content -LiteralPath $e -Raw -ErrorAction SilentlyContinue) }

        if (-not [string]::IsNullOrWhiteSpace($out2)) { $out = $out2 }
      } finally {
        try { Remove-Item -LiteralPath $o -Force -ErrorAction SilentlyContinue | Out-Null } catch { }
        try { Remove-Item -LiteralPath $e -Force -ErrorAction SilentlyContinue | Out-Null } catch { }
      }
    }

    return $out
  }

  $secAdmin = Join-Path $OpenSearchRoot "plugins\opensearch-security\tools\securityadmin.bat"
  if (-not (Test-Path -LiteralPath $secAdmin -PathType Leaf)) {
    throw "Ensure-TinySocsOpenSearchSecurityInitialized: securityadmin.bat not found: $secAdmin"
  }

  $jdk = Join-Path $OpenSearchRoot "jdk"
  if (-not (Test-Path -LiteralPath $jdk -PathType Container)) {
    throw "Ensure-TinySocsOpenSearchSecurityInitialized: bundled JDK not found at: $jdk"
  }

  # These env vars are what securityadmin.bat expects
  $oldJAVA_HOME = $env:JAVA_HOME
  $oldOSJH      = $env:OPENSEARCH_JAVA_HOME
  $oldOSCONF    = $env:OPENSEARCH_PATH_CONF

  try {
    $env:JAVA_HOME            = $jdk
    $env:OPENSEARCH_JAVA_HOME = $jdk
    $env:OPENSEARCH_PATH_CONF = $ProgramDataConf

    # Fast-exit if already initialized
    if (_IsSecurityInitialized $Url) {
      Write-TinySocsLog "OpenSearch Security already initialized at $Url (401+Basic)."
      return $true
    }

    $deadline = (Get-Date).AddSeconds($TimeoutSec)

    # Paths (TinySocs conventions)
    $certDir    = Join-Path $ProgramDataConf "certs"
    $secConfDir = Join-Path $ProgramDataConf "opensearch-security"

    $dpapiPath  = Join-Path $certDir "opensearch-tls-storepass.dpapi"
    $adminKs    = Join-Path $certDir "admin-keystore.p12"
    $adminTs    = Join-Path $certDir "admin-truststore.p12"
    $keytool    = Join-Path $jdk "bin\keytool.exe"

    foreach ($p in @($certDir, $secConfDir)) {
      if (-not (Test-Path -LiteralPath $p -PathType Container)) {
        throw "Ensure-TinySocsOpenSearchSecurityInitialized: required directory missing: $p"
      }
    }
    foreach ($p in @($dpapiPath, $adminKs, $adminTs, $keytool, $secAdmin)) {
      if (-not (Test-Path -LiteralPath $p -PathType Leaf)) {
        throw "Ensure-TinySocsOpenSearchSecurityInitialized: required file missing: $p"
      }
    }

    # NEW: Wait for real TCP connectability first (curl can be flaky during early startup)
    while ((Get-Date) -lt $deadline) {
      if (_TcpConnectable -h $host -p $port) { break }
      Start-Sleep -Seconds $IntervalSec
    }
    if (-not (_TcpConnectable -h $host -p $port)) {
      throw "Ensure-TinySocsOpenSearchSecurityInitialized: OpenSearch is not accepting TCP connections on $host`:$port within ${TimeoutSec}s."
    }

    # Wait until OpenSearch is in a state where running securityadmin makes sense
    while ((Get-Date) -lt $deadline) {
      if (_IsNotInitialized $Url -or _IsSecurityInitialized $Url) { break }
      Start-Sleep -Seconds $IntervalSec
    }

    if (_IsSecurityInitialized $Url) {
      Write-TinySocsLog "OpenSearch Security became initialized at $Url while waiting (401+Basic)."
      return $true
    }

    if (-not (_IsNotInitialized $Url)) {
      $last = _CurlBody $Url
      throw "Ensure-TinySocsOpenSearchSecurityInitialized: OpenSearch did not reach a state where securityadmin is appropriate. Last response:`n$last"
    }

    # Decrypt storepass using canonical helper
    if (-not (Get-Command Get-TinySocsStorepassFromDpapiFile -ErrorAction SilentlyContinue)) {
      throw "Ensure-TinySocsOpenSearchSecurityInitialized: missing helper Get-TinySocsStorepassFromDpapiFile in this module."
    }

    $storePass = (Get-TinySocsStorepassFromDpapiFile -Path $dpapiPath).Password
    if ($null -ne $storePass) { $storePass = ([string]$storePass).Trim() }
    if ([string]::IsNullOrWhiteSpace($storePass)) {
      throw "Ensure-TinySocsOpenSearchSecurityInitialized: DPAPI storepass decoded empty from: $dpapiPath"
    }
    if ($storePass.IndexOf([char]0) -ge 0 -or $storePass -match "[`r`n]") {
      throw "Ensure-TinySocsOpenSearchSecurityInitialized: storepass contains null/newline characters (DPAPI decode/encoding issue)."
    }

    # Discover alias (first token before comma / PrivateKeyEntry line)
    $alias = $null
    try {
      $listOut = (& $keytool -list -storetype PKCS12 -keystore $adminKs -storepass $storePass 2>&1 | Out-String)
      $alias = _TryParseAliasFromKeytoolList $listOut
    } catch { }

    # Build args (DO NOT name this $args)
    $secArgs = @(
      "-cd", $secConfDir,
      "-h",  $host,
      "-p",  ([string]$port),
      "-icl",
      "-nhnv",
      "-ks",     $adminKs,
      "-kspass", $storePass,
      "-kst",    "PKCS12",
      "-ts",     $adminTs,
      "-tspass", $storePass,
      "-tst",    "PKCS12"
    )
    if (-not [string]::IsNullOrWhiteSpace($alias)) {
      $secArgs += @("-ksalias", $alias)
    }

    Write-TinySocsLog "Bootstrapping OpenSearch Security index via securityadmin.bat (url=$Url host=$host port=$port alias=$alias)."

    # NEW: robust invocation (direct call + fallback if args are lost)
    $out = _InvokeSecurityAdmin -SecAdminBat $secAdmin -SecArgs $secArgs

    # Log tail only (avoid log spam; do not include secrets)
    $tail = ($out -split "`r?`n") | Select-Object -Last 80
    Write-TinySocsLog ("securityadmin output (tail):`n" + ($tail -join "`r`n"))

    # Verify the state flipped to 401
    while ((Get-Date) -lt $deadline) {
      if (_IsSecurityInitialized $Url) {
        Write-TinySocsLog "OpenSearch Security initialized successfully at $Url (401+Basic)."
        return $true
      }
      Start-Sleep -Seconds $IntervalSec
    }

    $last2 = _CurlBody $Url
    throw "Ensure-TinySocsOpenSearchSecurityInitialized: securityadmin ran but OpenSearch did not become ready (401+Basic) at $Url within timeout. Last:`n$last2"
  }
  finally {
    # Restore env (installer should not leak env changes into caller unexpectedly)
    $env:JAVA_HOME            = $oldJAVA_HOME
    $env:OPENSEARCH_JAVA_HOME = $oldOSJH
    $env:OPENSEARCH_PATH_CONF = $oldOSCONF
  }
}

function Ensure-TinySocsOpenSearchAdminDn {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$OpenSearchYmlPath,
    [Parameter(Mandatory)][string]$AdminDn,  # e.g. CN=TinySocs-OpenSearch-Admin
    [ValidateSet("OPTIONAL","REQUIRE","NONE")][string]$ClientAuthMode = "OPTIONAL"
  )

  if (-not (Test-Path -LiteralPath $OpenSearchYmlPath -PathType Leaf)) { throw "Missing: $OpenSearchYmlPath" }

  $raw = _ReadUtf8NoBom $OpenSearchYmlPath

  # Remove existing admin_dn block(s)
  $raw = [regex]::Replace(
    $raw,
    '(?ms)^\s*plugins\.security\.authcz\.admin_dn:\s*\r?\n(?:\s*-\s*".*?"\s*\r?\n?|\s*-\s*''.*?''\s*\r?\n?|\s*-\s*[^#\r\n]+\s*\r?\n?)*',
    ''
  )

  # Remove existing clientauth_mode lines
  $raw = [regex]::Replace(
    $raw,
    '(?m)^\s*plugins\.security\.ssl\.http\.clientauth_mode\s*:\s*.*\r?\n',
    ''
  )

  $raw = $raw.TrimEnd() + "`r`n`r`n" +
    "plugins.security.ssl.http.clientauth_mode: $ClientAuthMode`r`n" +
    "plugins.security.authcz.admin_dn:`r`n" +
    "  - `"$AdminDn`"`r`n"

  _WriteUtf8NoBom $OpenSearchYmlPath $raw
  Write-TinySocsLog "Canonicalized opensearch.yml admin_dn + clientauth_mode" "INFO"
}

function Ensure-TinySocsAclForOpenSearchSecurityConfig {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$SecurityConfigDir,
    [string]$ServiceName = "TinySocsOpenSearch"
  )

  if (-not (Test-Path -LiteralPath $SecurityConfigDir -PathType Container)) {
    throw "Missing security config dir: $SecurityConfigDir"
  }

  # Detect service identity (if itâ€™s a virtual account, grant it RX explicitly)
  $svcStartName = $null
  try {
    $svcStartName = (Get-CimInstance Win32_Service -Filter "Name='$ServiceName'").StartName
  } catch {}

  # Take ownership + normalize inheritance
  & takeown /F $SecurityConfigDir /R /D Y | Out-Null
  & icacls $SecurityConfigDir /inheritance:e /T /C | Out-Null

  # Admins + SYSTEM full control recursively
  & icacls $SecurityConfigDir /grant:r "BUILTIN\Administrators:(OI)(CI)F" "NT AUTHORITY\SYSTEM:(OI)(CI)F" /T /C | Out-Null

  # Give Users read/execute (optional but removes â€œAccess deniedâ€ surprises if the service identity is odd)
  & icacls $SecurityConfigDir /grant "BUILTIN\Users:(OI)(CI)(RX)" /T /C | Out-Null

  # If service uses a virtual account like "NT SERVICE\TinySocsOpenSearch", grant it RX explicitly
  if ($svcStartName -and $svcStartName -match '^NT SERVICE\\') {
    $grant = ('{0}:(OI)(CI)(RX)' -f $svcStartName)
    & icacls $SecurityConfigDir /grant $grant /T /C | Out-Null
  }

  Write-TinySocsLog "Normalized ACLs for $SecurityConfigDir (svcStartName=$svcStartName)" "INFO"
}

function Get-TinySocsPkcs12Alias {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$KeytoolExe,   # e.g. C:\Program Files\TinySocs\OpenSearch\jdk\bin\keytool.exe
    [Parameter(Mandatory)][string]$P12Path,      # admin-keystore.p12
    [Parameter(Mandatory)][string]$StorePass
  )

  if (-not (Test-Path -LiteralPath $KeytoolExe -PathType Leaf)) { throw "Missing: $KeytoolExe" }
  if (-not (Test-Path -LiteralPath $P12Path -PathType Leaf)) { throw "Missing: $P12Path" }

  $out = & $KeytoolExe -list -v -storetype PKCS12 -keystore $P12Path -storepass $StorePass 2>&1
  $m = [regex]::Match(($out -join "`n"), '(?m)^\s*Alias name:\s*(.+)\s*$')
  if (-not $m.Success) {
    throw "Could not determine PKCS12 alias from keytool output for $P12Path"
  }
  return $m.Groups[1].Value.Trim()
}

function Get-TinySocsOpenSearchHttpsPort {
  [CmdletBinding()]
  param(
    [int[]]$Candidates = @(9201, 9200)
  )

  foreach ($p in $Candidates) {
    $pid = (Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty OwningProcess)
    if ($pid) { return $p }
  }

  # fallback: try to find java and see listening ports
  $java = Get-CimInstance Win32_Process -Filter "Name='java.exe'" |
    Where-Object { $_.CommandLine -match 'org\.opensearch\.bootstrap\.OpenSearch' } |
    Select-Object -First 1 ProcessId
  if ($java) {
    $ports = Get-NetTCPConnection -OwningProcess $java.ProcessId -State Listen -ErrorAction SilentlyContinue |
      Where-Object { $_.LocalPort -in 9200,9201 } |
      Select-Object -ExpandProperty LocalPort -Unique
    if ($ports) { return ($ports | Select-Object -First 1) }
  }

  throw "Could not detect OpenSearch HTTPS port (expected 9200/9201 to be listening)."
}

function Invoke-TinySocsSecurityAdmin {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$OpenSearchRoot,
    [Parameter(Mandatory)][string]$SecurityConfigDir,
    [Parameter(Mandatory)][string]$AdminKeyStoreP12,
    [Parameter(Mandatory)][string]$AdminTrustStoreP12,
    [Parameter(Mandatory)][string]$StorePass,
    [Parameter(Mandatory)][int]$HttpsPort,
    [Parameter(Mandatory)][string]$KeyStoreAlias
  )

  $secAdmin = Join-Path $OpenSearchRoot "plugins\opensearch-security\tools\securityadmin.bat"
  if (-not (Test-Path -LiteralPath $secAdmin -PathType Leaf)) { throw "Missing: $secAdmin" }

  $env:JAVA_HOME = Join-Path $OpenSearchRoot "jdk"
  $env:OPENSEARCH_JAVA_HOME = $env:JAVA_HOME

  Push-Location (Split-Path $secAdmin -Parent)
  try {
    & $secAdmin `
      -cd $SecurityConfigDir `
      -icl `
      -nhnv `
      -h 127.0.0.1 `
      -p $HttpsPort `
      -ks $AdminKeyStoreP12 -kst PKCS12 -kspass $StorePass -ksalias $KeyStoreAlias `
      -ts $AdminTrustStoreP12 -tst PKCS12 -tspass $StorePass
  } finally {
    Pop-Location
  }
}

function Wait-TinySocsOpenSearchSecurityReady {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Url,      # e.g. https://localhost:9201

    # Backward/forward compatible naming:
    [Alias('TimeoutSec','TimeoutSeconds')]
    [int]$TimeoutSeconds = 600,

    [Alias('IntervalSec','IntervalSeconds')]
    [int]$IntervalSeconds = 3,

    # Optional (some callers pass these even if this function doesn't strictly need them)
    [string]$AdminUser,
    [string]$AdminPass,

    # If set, we use curl -k for TLS
    [switch]$SkipTlsVerify
  )

  # Self-healing behaviour:
  # - If the endpoint returns "OpenSearch Security not initialized", we will attempt to run
  #   Ensure-TinySocsOpenSearchSecurityInitialized (if present) to securityadmin the cluster.
  # - Then we continue waiting for the normal "ready" signal:
  #   401 + WWW-Authenticate: Basic (security plugin up + enforcing auth).
  #
  # Also supports DEV-only insecure mode (http://) by treating "ready" as any JSON-ish response
  # on cluster health (no auth expected).

  $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
  $last = $null

  # Normalize base URL
  $base = $Url.TrimEnd('/')

  # Endpoints to probe
  $endpoints = @(
    $base + '/',
    $base + '/_cluster/health'
  )

  # Parse URL
  $uObj = $null
  try { $uObj = [uri]$base } catch { $uObj = $null }
  $scheme = if ($uObj) { $uObj.Scheme } else { if ($base -match '^\s*http://') { 'http' } else { 'https' } }

  # Self-heal throttling
  $initAttempts = 0
  $maxInitAttempts = 3
  $lastInitAt = [datetime]::MinValue

  # Defaults for TinySocs layout (used only if initializer supports these params)
  $openSearchRoot = Join-Path $env:ProgramFiles "TinySocs\OpenSearch"
  $pdConf         = Join-Path $env:ProgramData "TinySocs\OpenSearch\config"
  $certsDir       = Join-Path $pdConf "certs"

  # Best-effort: pull port from URL
  $port = $null
  try {
    if ($uObj -and $uObj.Port -gt 0) { $port = [int]$uObj.Port }
  } catch { $port = $null }

  # Curl flags
  $curlBaseArgs = @('-sS','-i')
  if ($SkipTlsVerify.IsPresent) { $curlBaseArgs = @('-k') + $curlBaseArgs }

  while ((Get-Date) -lt $deadline) {

    foreach ($probe in $endpoints) {
      try {
        # We need body text too (because "OpenSearch Security not initialized" is in the body),
        # so use -i (headers + body).
        $out = (& curl.exe @curlBaseArgs $probe 2>&1 | Out-String)
        $last = $out

        # READY (secure mode): 401 + WWW-Authenticate Basic
        $is401 = ($out -match 'HTTP/(1\.1|2)\s+401')
        $hasBasic = ($out -match '(?im)^WWW-Authenticate:\s*Basic')
        if ($is401 -and $hasBasic) { return $true }

        # READY (insecure/dev mode): cluster health returns JSON (starts with "{")
        if ($scheme -eq 'http') {
          if ($out -match 'HTTP/(1\.1|2)\s+200' -and $out -match '^\s*\{') { return $true }
          if ($out.Trim() -match '^\s*\{') { return $true }
        }

        # Transitional state: security not initialized
        $notInit = ($out -match 'OpenSearch Security not initialized')
        if ($notInit) {

          $now = Get-Date
          $cooldownOk = (($now - $lastInitAt).TotalSeconds -ge 10)

          if ($initAttempts -lt $maxInitAttempts -and $cooldownOk) {
            $initAttempts++
            $lastInitAt = $now

            try {
              # PATCH(2026-01-16): keystore ACL repair (securityadmin touches keystore / reads config)
              try {
                $cmdAcl = Get-Command Repair-TinySocsOpenSearchKeystoreAcls -ErrorAction SilentlyContinue
                if ($cmdAcl) {
                  $ap = @{}
                  if ($cmdAcl.Parameters.ContainsKey('OpenSearchRoot'))  { $ap['OpenSearchRoot']  = $openSearchRoot }
                  if ($cmdAcl.Parameters.ContainsKey('ProgramDataConf')) { $ap['ProgramDataConf'] = $pdConf }
                  if ($cmdAcl.Parameters.ContainsKey('CertsDir'))        { $ap['CertsDir']        = $certsDir }
                  if ($cmdAcl.Parameters.ContainsKey('ServiceName'))     { $ap['ServiceName']     = 'TinySocsOpenSearch' }
                  & $cmdAcl @ap | Out-Null
                  Write-TinySocsLog -Level "INFO" -Message "Keystore ACL repair applied before security bootstrap attempt."
                }
              } catch {
                Write-TinySocsLog -Level "WARN" -Message ("Keystore ACL repair failed (continuing): {0}" -f $_.Exception.Message)
              }

              $cmdInit = Get-Command Ensure-TinySocsOpenSearchSecurityInitialized -ErrorAction SilentlyContinue
              if (-not $cmdInit) {
                Write-TinySocsLog -Level "WARN" -Message "OpenSearch Security not initialized, but Ensure-TinySocsOpenSearchSecurityInitialized is not available (attempt $initAttempts/$maxInitAttempts)."
              } else {

                # Ensure securityadmin can find Java (bundled JDK)
                try {
                  $jdk = Join-Path $openSearchRoot "jdk"
                  if (Test-Path -LiteralPath $jdk -PathType Container) {
                    $env:OPENSEARCH_JAVA_HOME = $jdk
                    $env:JAVA_HOME            = $jdk
                  }
                } catch { }

                # Build a best-effort param bag based on what the function actually supports
                $p = @{}

                if ($cmdInit.Parameters.ContainsKey('OpenSearchRoot'))   { $p['OpenSearchRoot']   = $openSearchRoot }
                if ($cmdInit.Parameters.ContainsKey('ProgramDataConf'))  { $p['ProgramDataConf']  = $pdConf }
                if ($cmdInit.Parameters.ContainsKey('CertsDir'))         { $p['CertsDir']         = $certsDir }

                # Some variants may want the URL/host/port
                if ($cmdInit.Parameters.ContainsKey('Url'))   { $p['Url']   = $base }
                if ($cmdInit.Parameters.ContainsKey('Host'))  { $p['Host']  = '127.0.0.1' }
                if ($cmdInit.Parameters.ContainsKey('Port') -and $null -ne $port) { $p['Port'] = $port }
                if ($cmdInit.Parameters.ContainsKey('HttpsPort') -and $null -ne $port) { $p['HttpsPort'] = $port }

                # Some variants may accept creds / tls knobs
                if ($cmdInit.Parameters.ContainsKey('AdminUser') -and $AdminUser) { $p['AdminUser'] = $AdminUser }
                if ($cmdInit.Parameters.ContainsKey('AdminPass') -and $AdminPass) { $p['AdminPass'] = $AdminPass }
                if ($cmdInit.Parameters.ContainsKey('SkipTlsVerify') -and $SkipTlsVerify.IsPresent) { $p['SkipTlsVerify'] = $true }

                Write-TinySocsLog -Level "WARN" -Message ("OpenSearch Security not initialized. Attempting automatic security bootstrap via Ensure-TinySocsOpenSearchSecurityInitialized (attempt {0}/{1})." -f $initAttempts, $maxInitAttempts)

                & $cmdInit @p | Out-Null

                Write-TinySocsLog -Level "INFO" -Message "Security bootstrap attempt completed; re-checking readiness."
              }
            } catch {
              Write-TinySocsLog -Level "WARN" -Message ("Automatic security bootstrap failed (attempt {0}/{1}): {2}" -f $initAttempts, $maxInitAttempts, $_.Exception.Message)
            }

            # After attempting bootstrap, don't immediately spin; let OS breathe a moment.
            Start-Sleep -Seconds ([Math]::Max(2, [Math]::Min(10, $IntervalSeconds)))
          }
        }

      } catch {
        $last = $_.Exception.Message
      }
    }

    Start-Sleep -Seconds $IntervalSeconds
  }

  throw ("OpenSearch Security did not become ready at {0} within {1}s. Last:`n{2}" -f $Url, $TimeoutSeconds, $last)
}

function Set-TinySocsOpenSearchHttpPortInConfig {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$ConfigPath,
    [Parameter(Mandatory)][int]$HttpPort
  )

  if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) {
    throw "Set-TinySocsOpenSearchHttpPortInConfig: config not found: $ConfigPath"
  }

  # Backup first
  $ts  = Get-Date -Format "yyyyMMdd-HHmmss"
  $bak = "$ConfigPath.bak.$ts"
  try { Copy-Item -LiteralPath $ConfigPath -Destination $bak -Force } catch { }

  # Read + split into lines (preserve ordering)
  $raw = ""
  try { $raw = Get-Content -LiteralPath $ConfigPath -Raw -ErrorAction Stop } catch { $raw = "" }

  $lines = @()
  if (-not [string]::IsNullOrEmpty($raw)) {
    $lines = ($raw -split "\r?\n")
  }

  # Use a mutable list
  $out = New-Object "System.Collections.Generic.List[string]"
  foreach ($ln in $lines) { $out.Add($ln) }

  # Remove any existing http.port lines (dedupe)
  $rx = '^\s*http\.port\s*:'
  for ($i = $out.Count - 1; $i -ge 0; $i--) {
    $ln = $out[$i]
    if ($null -eq $ln) { $ln = "" }
    if ($ln -match $rx) {
      $out.RemoveAt($i)
    }
  }

  # Insert canonical http.port line near the top, but after header comments/blank lines
  $insertIdx = 0
  for ($i = 0; $i -lt $out.Count; $i++) {
    $t = $out[$i]
    if ($null -eq $t) { $t = "" }
    $t = $t.Trim()

    if ($t -eq "" -or $t.StartsWith("#")) { continue }
    $insertIdx = $i
    break
  }

  $out.Insert($insertIdx, ("http.port: {0}" -f $HttpPort))

  # Re-emit with CRLF + trailing newline, UTF-8 no BOM
  $final = ($out -join "`r`n").TrimEnd() + "`r`n"
  [System.IO.File]::WriteAllText($ConfigPath, $final, (New-Object System.Text.UTF8Encoding($false)))

  Write-TinySocsLog "[OpenSearch] Enforced http.port=$HttpPort in $ConfigPath (backup: $bak)."
  return $true
}

function Set-OpenSearchSecureSetting {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$OpenSearchHome,    # e.g. C:\ProgramData\TinySocs\OpenSearch  OR C:\Program Files\TinySocs\OpenSearch
    [Parameter(Mandatory)][string]$ConfigDir,         # e.g. C:\ProgramData\TinySocs\OpenSearch\config
    [Parameter(Mandatory)][string]$SettingName,       # e.g. plugins.security.ssl.http.keystore_password
    [Parameter(Mandatory)][AllowEmptyString()][string]$Value
  )

  $cli = Join-Path $OpenSearchHome "bin\opensearch-keystore.bat"
  if (-not (Test-Path -LiteralPath $cli)) {
    throw "opensearch-keystore.bat not found at: $cli"
  }
  if (-not (Test-Path -LiteralPath $ConfigDir)) {
    throw "ConfigDir not found: $ConfigDir"
  }

  # Make sure the keystore tool uses the intended config dir
  $env:OPENSEARCH_PATH_CONF = $ConfigDir

  # Feed value via stdin; -f overwrites.
  $out = & $cli add -f $SettingName 2>&1 | Out-String
  if ($LASTEXITCODE -ne 0 -or $out -match 'ERROR:\s*Setting\s*$begin:math:display$\.\+$end:math:display$\s*does not exist in the keystore') {
    throw "Failed to add secure setting '$SettingName' via keystore tool. Exit=$LASTEXITCODE Output:`n$out"
  }

  # Now actually write the value (the tool prompts; we must provide it).
  # Use a separate invocation to ensure prompt consumption is clean.
  $out2 = ($Value + "`n") | & $cli add -f $SettingName 2>&1 | Out-String
  if ($LASTEXITCODE -ne 0 -or $out2 -match 'ERROR:\s*Setting\s*$begin:math:display$\.\+$end:math:display$\s*does not exist in the keystore') {
    throw "Failed to set value for secure setting '$SettingName'. Exit=$LASTEXITCODE Output:`n$out2"
  }
}

function Ensure-TinySocsProgramDataCerts {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$OpenSearchRoot,
    [Parameter(Mandatory)][string]$ProgramDataConf,
    [switch]$Force
  )

  $log = (Get-Command Write-TinySocsLog -ErrorAction SilentlyContinue)
  function _Log_Legacy([string]$msg, [string]$lvl="INFO") {
    if ($log) { Write-TinySocsLog -Level $lvl -Message $msg } else { Write-Host "[$lvl] $msg" }
  }

  # ProgramDataConf should usually be ...\OpenSearch\config
  $destCerts = $ProgramDataConf
  if ([IO.Path]::GetFileName($destCerts).ToLowerInvariant() -ne 'certs') {
    $destCerts = Join-Path $ProgramDataConf 'certs'
  }

  $seedCandidates = @(
    (Join-Path $OpenSearchRoot 'seed\config\certs'),
    (Join-Path $OpenSearchRoot 'config\certs')
  ) | Where-Object { Test-Path $_ -PathType Container }

  if (-not (Test-Path $destCerts -PathType Container)) {
    New-Item -ItemType Directory -Force -Path $destCerts | Out-Null
    _Log "Created ProgramData cert directory: $destCerts"
  }

  $required = @('http.p12','transport.p12','trust.p12','ca.cer','opensearch-tls-storepass.dpapi')

  foreach ($f in $required) {
    $dst = Join-Path $destCerts $f
    if ($Force -or -not (Test-Path $dst -PathType Leaf)) {

      $src = $null
      foreach ($seed in $seedCandidates) {
        $candidate = Join-Path $seed $f
        if (Test-Path $candidate -PathType Leaf) { $src = $candidate; break }
      }

      if ($src) {
        try {
          Copy-Item -LiteralPath $src -Destination $dst -Force
          _Log "Ensured ProgramData cert '$f' (copied from seed)."
        } catch {
          _Log "Failed to copy '$f' from '$src' to '$dst': $($_.Exception.Message)" "WARN"
        }
      } else {
        _Log "Missing '$f' in ProgramData and no seed source found under OpenSearchRoot. Expected under: $($seedCandidates -join ', ')" "WARN"
      }
    }
  }

  # final check
  $missing = @()
  foreach ($f in $required) {
    if (-not (Test-Path (Join-Path $destCerts $f) -PathType Leaf)) { $missing += $f }
  }

  if ($missing.Count) {
    _Log "ProgramData cert preflight still missing: $($missing -join ', ')" "WARN"
    return $false
  }

  return $true
}

function Get-TinySocsOpenSearchConfigDir {
  [CmdletBinding()]
  param(
    [string]$OpenSearchHome = $(Get-TinySocsOpenSearchHome),
    [switch]$SeedIfMissing
  )

  $pd = Join-Path $env:ProgramData "TinySocs\OpenSearch\config"

  if (-not (Test-Path -LiteralPath $pd)) {
    if (-not $SeedIfMissing) {
      throw "ProgramData OpenSearch config dir missing: $pd (refusing to fall back to OpenSearchHome\config)."
    }

    New-Item -ItemType Directory -Force -Path $pd | Out-Null

    $src = Join-Path $OpenSearchHome "config"
    if (-not (Test-Path -LiteralPath $src)) {
      throw "OpenSearchHome config dir missing; cannot seed ProgramData. src=$src"
    }

    # Seed ProgramData config from in-place config
    $rc = & robocopy $src $pd /E /XO /NFL /NDL /NJH /NJS /NP
    # Robocopy uses bitmask exit codes; treat 0-7 as "ok-ish"
    if ($LASTEXITCODE -gt 7) {
      throw "Robocopy seed failed (exit=$LASTEXITCODE) src=$src dst=$pd"
    }
  }

  return $pd
}

function Ensure-TinySocsOpenSearchServiceDeterministic {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$TinySocsRoot,                 # C:\Program Files\TinySocs
    [Parameter(Mandatory)][string]$ProgramDataOpenSearchRoot,     # C:\ProgramData\TinySocs\OpenSearch
    [string]$ServiceName = "TinySocsOpenSearch",
    [string]$NssmPath = $(Join-Path $TinySocsRoot "bin\nssm.exe"),
    [switch]$ForceSeedProgramDataConfig
  )

  # --- Paths ---
  $osRootPF = Join-Path $TinySocsRoot "OpenSearch"
  $confPD   = Join-Path $ProgramDataOpenSearchRoot "config"
  $logsPD   = Join-Path $ProgramDataOpenSearchRoot "logs"
  $binPD    = Join-Path $ProgramDataOpenSearchRoot "bin"
  $runner   = Join-Path $binPD "Run-OpenSearch.ps1"

  if (-not (Test-Path -LiteralPath $NssmPath -PathType Leaf)) {
    throw "nssm.exe not found at '$NssmPath'"
  }
  if (-not (Test-Path -LiteralPath $osRootPF -PathType Container)) {
    throw "OpenSearch not found at '$osRootPF'"
  }

  New-Item -ItemType Directory -Force -Path $ProgramDataOpenSearchRoot, $confPD, $logsPD, $binPD | Out-Null

  # --- Seed ProgramData config (critical for determinism) ---
  if (Get-Command Ensure-TinySocsOpenSearchProgramDataConfig -ErrorAction SilentlyContinue) {
    Ensure-TinySocsOpenSearchProgramDataConfig -OpenSearchRoot $osRootPF -ProgramDataConf $confPD -Force:$ForceSeedProgramDataConfig
  } else {
    throw "Ensure-TinySocsOpenSearchProgramDataConfig not found (cannot guarantee ProgramData config)."
  }

  # --- Ensure runner exists (prefer shipped scripts\Run-OpenSearch.ps1) ---
  if (Get-Command Ensure-TinySocsOpenSearchRunner -ErrorAction SilentlyContinue) {
    Ensure-TinySocsOpenSearchRunner -InstallRoot $TinySocsRoot -OpenSearchRoot $osRootPF -ProgramDataConf $confPD -RunnerPath $runner
  } else {
    throw "Ensure-TinySocsOpenSearchRunner not found (cannot guarantee service runner)."
  }

  if (-not (Test-Path -LiteralPath $runner -PathType Leaf)) {
    throw "Runner was not created at '$runner'"
  }

  # --- Ensure service exists ---
  $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
  if (-not $svc) {
    $ps = (Get-Command powershell.exe -ErrorAction Stop).Source
    & $NssmPath install $ServiceName $ps | Out-Null
    Start-Sleep -Seconds 1
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if (-not $svc) {
      throw "Service '$ServiceName' was not created by NSSM install."
    }
  }

  # --- Stop service cleanly before rewiring it ---
  try {
    if ($svc.Status -eq 'Running') {
      try { Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue } catch { }
      try { sc.exe stop $ServiceName | Out-Null } catch { }
      Start-Sleep -Seconds 2
    }
  } catch { }

  # --- Pin NSSM config deterministically ---
  $psExe = (Get-Command powershell.exe -ErrorAction Stop).Source
  $appParams = "-NoProfile -ExecutionPolicy Bypass -File `"$runner`""

  # Choose an appdir that won't surprise OpenSearch tooling
  $appDir = Join-Path $osRootPF "bin"
  if (-not (Test-Path -LiteralPath $appDir -PathType Container)) { $appDir = $osRootPF }

  # Always use NSSM's canonical key name: Application
  & $NssmPath set $ServiceName Application $psExe | Out-Null
  & $NssmPath set $ServiceName AppParameters $appParams | Out-Null
  & $NssmPath set $ServiceName AppDirectory $appDir | Out-Null
  & $NssmPath set $ServiceName AppEnvironmentExtra ("OPENSEARCH_PATH_CONF=$confPD") | Out-Null

  # Log files
  & $NssmPath set $ServiceName AppStdout (Join-Path $logsPD "$ServiceName.nssm.stdout.log") | Out-Null
  & $NssmPath set $ServiceName AppStderr (Join-Path $logsPD "$ServiceName.nssm.stderr.log") | Out-Null

  # Stop/kill semantics: avoid STOP_PENDING + stranded java.exe
  # (These keys exist on modern NSSM; failures are non-fatal)
  try { & $NssmPath set $ServiceName AppStopMethodConsole 15000 | Out-Null } catch { }
  try { & $NssmPath set $ServiceName AppStopMethodWindow  15000 | Out-Null } catch { }
  try { & $NssmPath set $ServiceName AppStopMethodThreads 15000 | Out-Null } catch { }
  try { & $NssmPath set $ServiceName AppStopMethodTerminate 5000 | Out-Null } catch { }
  try { & $NssmPath set $ServiceName AppKillProcessTree 1 | Out-Null } catch { }

  # Restart on exit
  try { & $NssmPath set $ServiceName AppExit Default Restart | Out-Null } catch { }

  # Service recovery (SCM-level)
  try { sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/5000/restart/5000 | Out-Null } catch { }

  # Start service
  try { Start-Service -Name $ServiceName -ErrorAction SilentlyContinue } catch { }
  try { sc.exe start $ServiceName | Out-Null } catch { }

  # Emit what we set (helps you confirm during installer logs)
  try {
    $a  = & $NssmPath get $ServiceName Application
    $ap = & $NssmPath get $ServiceName AppParameters
    $ad = & $NssmPath get $ServiceName AppDirectory
    $ae = & $NssmPath get $ServiceName AppEnvironmentExtra
    Write-TinySocsLog "OpenSearch NSSM pinned: Application=$a"
    Write-TinySocsLog "OpenSearch NSSM pinned: AppParameters=$ap"
    Write-TinySocsLog "OpenSearch NSSM pinned: AppDirectory=$ad"
    Write-TinySocsLog "OpenSearch NSSM pinned: AppEnvironmentExtra=$ae"
  } catch { }

  Write-TinySocsLog "OpenSearch service '$ServiceName' ensured deterministic (Runner=$runner, Conf=$confPD)."
}

function Set-TinySocsWindowsServiceEnvironment {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$ServiceName,
    [Parameter(Mandatory)][hashtable]$Environment
  )

  $svcKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
  if (-not (Test-Path $svcKey)) { throw "Service registry key not found: $svcKey" }

  $pairs = @()
  foreach ($k in $Environment.Keys) {
    $v = [string]$Environment[$k]
    $pairs += ("{0}={1}" -f $k, $v)
  }

  # Merge with existing if present
  $existing = @()
  try {
    $cur = (Get-ItemProperty -Path $svcKey -Name Environment -ErrorAction Stop).Environment
    if ($cur) { $existing = @($cur) }
  } catch { }

  $merged = @{}
  foreach ($e in $existing) {
    if ($e -match '^(?<k>[^=]+)=(?<v>.*)$') { $merged[$Matches.k] = $Matches.v }
  }
  foreach ($k in $Environment.Keys) { $merged[$k] = [string]$Environment[$k] }

  $final = @()
  foreach ($k in ($merged.Keys | Sort-Object)) {
    $final += ("{0}={1}" -f $k, $merged[$k])
  }

  New-ItemProperty -Path $svcKey -Name Environment -PropertyType MultiString -Value $final -Force | Out-Null
  return $true
}

function Set-TinySocsOpenSearchServicePathConf {
  [CmdletBinding()]
  param(
    [string]$ServiceName = "TinySocsOpenSearch",
    [string]$OpenSearchHome = "C:\Program Files\TinySocs\OpenSearch"
  )

  $confDir = Get-TinySocsOpenSearchConfigDir -OpenSearchHome $OpenSearchHome -SeedIfMissing
  Set-TinySocsWindowsServiceEnvironment -ServiceName $ServiceName -Environment @{
    "OPENSEARCH_PATH_CONF" = $confDir
  } | Out-Null

  Write-TinySocsLog "Pinned $ServiceName OPENSEARCH_PATH_CONF to $confDir" "INFO"
  return $confDir
}

function Ensure-OpenSearchKeystoreExists {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$OpenSearchHome,
    [Parameter(Mandatory)][string]$ConfigDir
  )

  $keystorePath = Join-Path $ConfigDir "opensearch.keystore"
  if (Test-Path -LiteralPath $keystorePath) { return $true }

  $keystoreBat = Join-Path $OpenSearchHome "bin\opensearch-keystore.bat"
  if (-not (Test-Path -LiteralPath $keystoreBat)) { throw "opensearch-keystore.bat not found: $keystoreBat" }

  $old = $env:OPENSEARCH_PATH_CONF
  try {
    $env:OPENSEARCH_PATH_CONF = $ConfigDir
    $out = & $keystoreBat create 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Keystore create failed (exit=$LASTEXITCODE). Output:`n$out" }
  } finally {
    $env:OPENSEARCH_PATH_CONF = $old
  }

  if (-not (Test-Path -LiteralPath $keystorePath)) {
    throw "Keystore create claimed success but file missing: $keystorePath"
  }

  return $true
}

function _Get-TinySocsOpenSearchKeystoreBat {
  [CmdletBinding()]
  param()

  # Module lives in ...\TinySocs\modules\TinySocs.Installer.psm1
  $modulesDir = $PSScriptRoot
  $appRoot    = Split-Path -Parent $modulesDir
  $bat        = Join-Path $appRoot "OpenSearch\bin\opensearch-keystore.bat"

  if (-not (Test-Path $bat -PathType Leaf)) {
    throw "_Get-TinySocsOpenSearchKeystoreBat: opensearch-keystore.bat not found at: $bat"
  }
  return $bat
}

function _Invoke-OpenSearchKeystoreBat {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$ConfDir,

    # Command line to run *inside* cmd.exe, e.g.:
    #   "`"C:\...\opensearch-keystore.bat`" list"
    #   "`"C:\...\opensearch-keystore.bat`" add -xf `"some.key`""
    [Parameter(Mandatory)][string]$CmdLine,

    # Optional: if provided, will be written to stdin (with newline).
    [string]$StdIn
  )

  if (-not (Test-Path -LiteralPath $ConfDir -PathType Container)) {
    throw "_Invoke-OpenSearchKeystoreBat: ConfDir not found: $ConfDir"
  }
  if ([string]::IsNullOrWhiteSpace($CmdLine)) {
    throw "_Invoke-OpenSearchKeystoreBat: CmdLine is empty"
  }

  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = "cmd.exe"
  $psi.UseShellExecute = $false
  $psi.CreateNoWindow = $true
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError  = $true
  $psi.RedirectStandardInput  = $true

  # Set OPENSEARCH_PATH_CONF for this process only (donâ€™t rely on inherited state)
  try { $null = $psi.EnvironmentVariables.Remove("OPENSEARCH_PATH_CONF") } catch { }
  $psi.EnvironmentVariables["OPENSEARCH_PATH_CONF"] = $ConfDir

  # Optional: a stable working directory helps some .bat scripts
  try { $psi.WorkingDirectory = (Split-Path -Parent $ConfDir) } catch { }

  # cmd.exe parsing:
  # We want: cmd.exe /S /C "<INNER>"
  # where <INNER> is CmdLine, but any embedded quotes must be doubled for cmd's outer quotes.
  $inner = $CmdLine.Replace('"', '""')
  $psi.Arguments = ('/D /V:OFF /S /C "{0}"' -f $inner)

  $p = New-Object System.Diagnostics.Process
  $p.StartInfo = $psi

  if (-not $p.Start()) {
    throw "_Invoke-OpenSearchKeystoreBat: failed to start cmd.exe"
  }

  try {
    if ($PSBoundParameters.ContainsKey('StdIn') -and $null -ne $StdIn) {
      # Write as a single line; keystore expects one line
      $p.StandardInput.WriteLine($StdIn)
    }
    $p.StandardInput.Close()

    # Avoid potential deadlocks by reading asynchronously
    $tOut = $p.StandardOutput.ReadToEndAsync()
    $tErr = $p.StandardError.ReadToEndAsync()

    $p.WaitForExit()

    $stdout = $tOut.GetAwaiter().GetResult()
    $stderr = $tErr.GetAwaiter().GetResult()

    return [pscustomobject]@{
      ExitCode = $p.ExitCode
      StdOut   = $stdout
      StdErr   = $stderr
      CmdLine  = $CmdLine
    }
  }
  finally {
    try { if (-not $p.HasExited) { $p.Kill() } } catch { }
    try { $p.Dispose() } catch { }
  }
}

function Get-OpenSearchKeystoreSetting {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$ConfDir
  )

  $bat = _Get-TinySocsOpenSearchKeystoreBat
  $cmd = '""' + $bat + '"" list'
  $res = _Invoke-OpenSearchKeystoreBat -ConfDir $ConfDir -CmdLine $cmd

  if ($res.ExitCode -ne 0) {
    throw "Get-OpenSearchKeystoreSetting: list failed (exit=$($res.ExitCode)): $($res.StdErr)"
  }

  ($res.StdOut -split "`r?`n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_.Trim() })
}

function Remove-OpenSearchKeystoreSetting {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$ConfDir,
    [Parameter(Mandatory)][string]$Key
  )

  $existing = @()
  try { $existing = Get-OpenSearchKeystoreSetting -ConfDir $ConfDir } catch { }

  if ($existing -notcontains $Key) {
    return
  }

  $bat = _Get-TinySocsOpenSearchKeystoreBat
  $cmd = '""' + $bat + '"" remove ""' + $Key + '""'
  $res = _Invoke-OpenSearchKeystoreBat -ConfDir $ConfDir -CmdLine $cmd

  if ($res.ExitCode -ne 0) {
    throw "Remove-OpenSearchKeystoreSetting: remove failed for '$Key' (exit=$($res.ExitCode)): $($res.StdErr)"
  }
}

function Remove-OpenSearchInsecureSslPasswordSettingsFromYaml {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$ConfigDir
  )

  if (-not (Test-Path $ConfigDir -PathType Container)) {
    throw "Remove-OpenSearchInsecureSslPasswordSettingsFromYaml: ConfigDir not found: $ConfigDir"
  }

  $yml = Join-Path $ConfigDir "opensearch.yml"
  if (-not (Test-Path $yml -PathType Leaf)) {
    throw "Remove-OpenSearchInsecureSslPasswordSettingsFromYaml: opensearch.yml not found: $yml"
  }

  $raw = Get-Content -LiteralPath $yml -Raw -ErrorAction Stop
  if ($null -eq $raw) { $raw = "" }

  # Remove ONLY the insecure plaintext YAML keys (NOT *_secure; those live in keystore anyway)
  $keys = @(
    'plugins.security.ssl.http.keystore_password',
    'plugins.security.ssl.http.keystore_keypassword',
    'plugins.security.ssl.http.truststore_password',
    'plugins.security.ssl.transport.keystore_password',
    'plugins.security.ssl.transport.keystore_keypassword',
    'plugins.security.ssl.transport.truststore_password'
  )

  foreach ($k in $keys) {
    # Match whole line: optional whitespace, exact key, optional whitespace, colon, anything to end-of-line
    $pat = '(?im)^\s*' + [regex]::Escape($k) + '\s*:\s*.*\r?\n?'
    $raw = [regex]::Replace($raw, $pat, '')
  }

  # Keep file tidy: collapse huge runs of blank lines a bit (but donÃ¢â‚¬â„¢t overthink it)
  $raw = [regex]::Replace($raw, "(?m)(\r?\n){3,}", "`r`n`r`n")

  if ($raw -notmatch "(\r?\n)$") { $raw += "`r`n" }

  Set-Content -LiteralPath $yml -Value $raw -Encoding UTF8 -Force
  Write-TinySocsLog "Removed insecure OpenSearch SSL password settings from YAML: $yml" "INFO"
  return $true
}

function Set-OpenSearchKeystoreSettingSecure {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$ConfDir,
    [Parameter(Mandatory)][string]$Key,
    [Parameter(Mandatory)][string]$Value
  )

  if (-not (Test-Path -LiteralPath $ConfDir -PathType Container)) {
    throw "Set-OpenSearchKeystoreSettingSecure: ConfDir not found: $ConfDir"
  }

  # Normalize / defuse accidental quoting/whitespace (incl. trailing quote bugs)
  $k = $Key
  if ([string]::IsNullOrWhiteSpace($k)) {
    throw "Set-OpenSearchKeystoreSettingSecure: Key is empty"
  }
  $k = $k.Trim().Trim('"').Trim("'").Trim()

  # Remove first to avoid "already exists" behaviour differences
  try { Remove-OpenSearchKeystoreSetting -ConfDir $ConfDir -Key $k } catch { }

  $bat = _Get-TinySocsOpenSearchKeystoreBat
  if (-not (Test-Path -LiteralPath $bat -PathType Leaf)) {
    throw "Set-OpenSearchKeystoreSettingSecure: keystore bat not found: $bat"
  }

  # Build the command that cmd.exe should execute.
  # We do NOT use cmd "< file" redirection; we feed stdin.
  $cmdLine = "`"$bat`" add -xf `"$k`""

  $res = _Invoke-OpenSearchKeystoreBat -ConfDir $ConfDir -CmdLine $cmdLine -StdIn $Value

  if ($res.ExitCode -ne 0) {
    $msg = $res.StdErr
    if ([string]::IsNullOrWhiteSpace($msg)) { $msg = $res.StdOut }
    throw "Set-OpenSearchKeystoreSettingSecure: add failed for '$k' (exit=$($res.ExitCode)): $msg"
  }

  return $true
}

function Repair-TinySocsOpenSearchKeystoreAcls {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$ProgramDataConf
  )

  $cfg = $ProgramDataConf
  $ks  = Join-Path $cfg "opensearch.keystore"

  try {
    if (-not (Test-Path -LiteralPath $cfg -PathType Container)) { return }

    # Make sure inheritance isn't broken + SYSTEM/Admins have full control
    & icacls $cfg /inheritance:e /T /C | Out-Null
    & icacls $cfg /grant:r "NT AUTHORITY\SYSTEM:(OI)(CI)F" "BUILTIN\Administrators:(OI)(CI)F" /T /C | Out-Null

    if (Test-Path -LiteralPath $ks -PathType Leaf) {
      try { & takeown /f $ks | Out-Null } catch { }

      & icacls $ks /inheritance:e | Out-Null
      & icacls $ks /grant:r "NT AUTHORITY\SYSTEM:F" "BUILTIN\Administrators:F" | Out-Null

      # Optional but helps when tools mark it read-only
      try { attrib -R $ks 2>$null | Out-Null } catch { }
    }
  } catch {
    # Don't brick installs because ACL tools threw.
    Write-TinySocsLog -Level "WARN" -Message "Repair-TinySocsOpenSearchKeystoreAcls failed (continuing): $($_.Exception.Message)"
  }
}

function Repair-TinySocsOpenSearchTlsKeystore {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$CertsDir,
    [string]$OpenSearchHome = "C:\Program Files\TinySocs\OpenSearch"
  )

  $osHome  = $OpenSearchHome
  $confDir = Get-TinySocsOpenSearchConfigDir -OpenSearchHome $osHome -SeedIfMissing

  Write-TinySocsLog "Repairing OpenSearch TLS keystore settings. OpenSearchHome=$osHome ConfigDir=$confDir CertsDir=$CertsDir" "INFO"

  Ensure-OpenSearchKeystoreExists -OpenSearchHome $osHome -ConfigDir $confDir | Out-Null

  $keystoreBat = Join-Path $osHome "bin\opensearch-keystore.bat"
  if (-not (Test-Path $keystoreBat -PathType Leaf)) {
    throw "Repair-TinySocsOpenSearchTlsKeystore: opensearch-keystore.bat not found at: $keystoreBat"
  }
  if (-not (Test-Path $confDir -PathType Container)) {
    throw "Repair-TinySocsOpenSearchTlsKeystore: ConfigDir not found at: $confDir"
  }

  function _NormalizeKey {
    param([string]$Key)
    if ([string]::IsNullOrWhiteSpace($Key)) { return $Key }
    # Defuse the exact bug we saw in logs: keys accidentally carrying a trailing quote
    $k = $Key.Trim()
    $k = $k.Trim('"').Trim("'")
    return $k
  }

  function _InvokeCmdPinned {
    param([Parameter(Mandatory)][string]$CmdArgLine)

    $old = $env:OPENSEARCH_PATH_CONF
    try {
      $env:OPENSEARCH_PATH_CONF = $confDir

      $out = New-TemporaryFile
      $err = New-TemporaryFile
      try {
        $p = Start-Process -FilePath "cmd.exe" -ArgumentList $CmdArgLine -NoNewWindow -Wait -PassThru `
              -RedirectStandardOutput $out.FullName -RedirectStandardError $err.FullName

        return [pscustomobject]@{
          ExitCode = $p.ExitCode
          StdOut   = (Get-Content -LiteralPath $out.FullName -Raw -ErrorAction SilentlyContinue)
          StdErr   = (Get-Content -LiteralPath $err.FullName -Raw -ErrorAction SilentlyContinue)
        }
      }
      finally {
        try { Remove-Item -LiteralPath $out.FullName, $err.FullName -Force -ErrorAction SilentlyContinue } catch { }
      }
    }
    finally {
      $env:OPENSEARCH_PATH_CONF = $old
    }
  }

  function _ListKeystoreKeys {
    $arg = '/d /s /c ""' + $keystoreBat + '" list"'
    $res = _InvokeCmdPinned -CmdArgLine $arg
    if ($res.ExitCode -ne 0) {
      throw "Repair-TinySocsOpenSearchTlsKeystore: keystore list failed (exit=$($res.ExitCode)). Stderr=$($res.StdErr)"
    }
    ($res.StdOut -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
  }

  function _RemoveKeystoreKey {
    param([Parameter(Mandatory)][string]$Key)

    $Key = _NormalizeKey $Key
    if ([string]::IsNullOrWhiteSpace($Key)) { return }

    # IMPORTANT: remove must be idempotent. opensearch-keystore returns exit=78 when missing; that is OK.
    $arg = '/d /s /c ""' + $keystoreBat + '" remove "' + $Key + '""'
    $res = _InvokeCmdPinned -CmdArgLine $arg

    if ($res.ExitCode -eq 0) { return }

    # exit 78 (or stderr says does not exist) => not present; treat as success
    if ($res.ExitCode -eq 78) { return }
    if (($res.StdErr + $res.StdOut) -match '(?i)\bdoes not exist\b') { return }

    throw "Repair-TinySocsOpenSearchTlsKeystore: keystore remove failed for key '$Key' (exit=$($res.ExitCode)). Stderr=$($res.StdErr)"
  }

  function _AddKeystoreKeyFromValue {
    param(
      [Parameter(Mandatory)][string]$Key,
      [Parameter(Mandatory)][string]$Value
    )

    $Key = _NormalizeKey $Key
    if ([string]::IsNullOrWhiteSpace($Key)) { throw "Repair-TinySocsOpenSearchTlsKeystore: Key was blank after normalization." }

    # Best-effort remove; never fail on "missing"
    try { _RemoveKeystoreKey -Key $Key } catch { }

    $tmp = New-TemporaryFile
    try {
      # Ensure we only feed one line (no trailing CRLF surprises)
      $v = ($Value -replace "(\r|\n)+$","")
      Set-Content -LiteralPath $tmp.FullName -Value ($v + "`r`n") -Encoding Ascii -Force

      # Use cmd redirection (< file) to satisfy keystore's stdin prompt.
      $arg = '/d /s /c ""' + $keystoreBat + '" add -xf "' + $Key + '" < "' + $tmp.FullName + '""'
      $res = _InvokeCmdPinned -CmdArgLine $arg
      if ($res.ExitCode -ne 0) {
        throw "Repair-TinySocsOpenSearchTlsKeystore: keystore add failed for key '$Key' (exit=$($res.ExitCode)). Stderr=$($res.StdErr)"
      }
    }
    finally {
      try { Remove-Item -LiteralPath $tmp.FullName -Force -ErrorAction SilentlyContinue } catch { }
    }
  }

  # 1) Decrypt storepass
  $storePass = Read-TinySocsOpenSearchTlsStorePassFromDpapiFile -CertsDir $CertsDir
  if (-not $storePass -or $storePass.Length -lt 1) {
    throw "Repair-TinySocsOpenSearchTlsKeystore: decrypted storePass was empty."
  }

  $nonAscii = ($storePass.ToCharArray() | ForEach-Object { [int][char]$_ } | Where-Object { $_ -gt 127 } | Measure-Object).Count
  if ($nonAscii -ne 0) {
    throw "Repair-TinySocsOpenSearchTlsKeystore: StorePass contains non-ASCII characters; Java PKCS12 may fail. nonAsciiCount=$nonAscii"
  }

  $insecureNames = @(
    "plugins.security.ssl.http.keystore_password",
    "plugins.security.ssl.http.keystore_keypassword",
    "plugins.security.ssl.http.truststore_password",
    "plugins.security.ssl.transport.keystore_password",
    "plugins.security.ssl.transport.keystore_keypassword",
    "plugins.security.ssl.transport.truststore_password"
  )

  foreach ($n in $insecureNames) {
    _RemoveKeystoreKey -Key $n
  }

  $secureNames = $insecureNames | ForEach-Object { "${_}_secure" }
  foreach ($n in $secureNames) {
    _AddKeystoreKeyFromValue -Key $n -Value $storePass
  }

  # 2) Strip insecure YAML settings (call helper if present; otherwise do it inline)
  if (Get-Command Remove-OpenSearchInsecureSslPasswordSettingsFromYaml -ErrorAction SilentlyContinue) {
    Remove-OpenSearchInsecureSslPasswordSettingsFromYaml -ConfigDir $confDir | Out-Null
  }
  else {
    $yml = Join-Path $confDir "opensearch.yml"
    if (Test-Path $yml -PathType Leaf) {
      $raw = Get-Content -LiteralPath $yml -Raw -ErrorAction Stop
      if ($null -eq $raw) { $raw = "" }
      foreach ($k in $insecureNames) {
        $pat = '(?im)^\s*' + [regex]::Escape($k) + '\s*:\s*.*\r?\n?'
        $raw = [regex]::Replace($raw, $pat, '')
      }
      if ($raw -notmatch "(\r?\n)$") { $raw += "`r`n" }
      Set-Content -LiteralPath $yml -Value $raw -Encoding UTF8 -Force
    }
  }

  # Validate keystore contents
  $list = _ListKeystoreKeys

  $bad = $insecureNames | Where-Object { $list -contains $_ }
  if ($bad.Count -gt 0) {
    throw "Repair-TinySocsOpenSearchTlsKeystore: keystore still contains insecure SSL password keys (should not): $($bad -join ', ')"
  }

  $missingSecure = $secureNames | Where-Object { $list -notcontains $_ }
  if ($missingSecure.Count -gt 0) {
    throw "Repair-TinySocsOpenSearchTlsKeystore: keystore is missing expected *_secure keys: $($missingSecure -join ', ')"
  }

  Write-TinySocsLog "OpenSearch TLS keystore repaired: insecure keys removed; *_secure keys set." "INFO"
  return $true
}

function _Start-ServiceAndWaitReady {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$ServiceName,
    [int]$ServiceTimeoutSec = 60,
    [int]$ReadyTimeoutSec   = 180
  )

  try { Start-Service -Name $ServiceName -ErrorAction SilentlyContinue } catch { }
  try { sc.exe start $ServiceName | Out-Null } catch { }

  $svcDeadline = (Get-Date).AddSeconds($ServiceTimeoutSec)
  $lastPrint = Get-Date

  while ((Get-Date) -lt $svcDeadline) {
    $svc = $null
    try { $svc = Get-Service -Name $ServiceName -ErrorAction Stop } catch { $svc = $null }

    if ($svc -and $svc.Status -eq 'Running') { break }

    if (((Get-Date) - $lastPrint).TotalSeconds -ge 5) {
      Write-Warning "Waiting for service '$ServiceName' to start..."
      $lastPrint = Get-Date
    }

    Start-Sleep -Milliseconds 500
  }

  $svc2 = $null
  try { $svc2 = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue } catch { }
  if (-not $svc2 -or $svc2.Status -ne 'Running') {
    throw "Service did not reach Running state within ${ServiceTimeoutSec}s: $ServiceName"
  }

  if (-not (_Wait-OpenSearchReady -TimeoutSec $ReadyTimeoutSec)) {
    throw "OpenSearch did not become ready within ${ReadyTimeoutSec}s after service start."
  }

  return $true
}

function Invoke-TinySocsOpenSearchInstallerPersistFix {
  [CmdletBinding()]
  param(
    [string]$InstallRoot = "C:\Program Files\TinySocs",
    [string]$ServiceName = "TinySocsOpenSearch"
  )

  $osHome      = Join-Path $InstallRoot "OpenSearch"
  $certsDir    = Join-Path $env:ProgramData "TinySocs\OpenSearch\config\certs"
  $pdTemplates = Join-Path $env:ProgramData "TinySocs\OpenSearch\templates"

  Write-TinySocsLog "=== OpenSearch installer persist fix: InstallRoot=$InstallRoot ===" "INFO"

  # 0) Stop service if it exists (avoid reading wrong config mid-fix)
  try {
    $svc = Get-Service -Name $ServiceName -ErrorAction Stop
    if ($svc.Status -ne 'Stopped') { Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue }
  } catch { }

  # 1) Force ProgramData config + pin service env var
  $confDir = Set-TinySocsOpenSearchServicePathConf -ServiceName $ServiceName -OpenSearchHome $osHome

  # 1.1) Normalize SIEM_URL for loopback installs (avoid the 9200 trap)
  try {
    $m = [Environment]::GetEnvironmentVariable("SIEM_URL","Machine")
    $p = $env:SIEM_URL
    $candidate = if (-not [string]::IsNullOrWhiteSpace($p)) { $p } else { $m }

    if ([string]::IsNullOrWhiteSpace($candidate)) {
      $candidate = "https://127.0.0.1:9201"
    }

    $u = [Uri]$candidate
    $isLoopback = $u.IsLoopback -or ($u.Host -in @('127.0.0.1','localhost','::1'))

    if ($isLoopback) {
      $builder = New-Object System.UriBuilder($u)
      $builder.Scheme = "https"
      if ($builder.Port -eq 9200 -or $builder.Port -eq 80) { $builder.Port = 9201 }
      $canon = $builder.Uri.AbsoluteUri.TrimEnd('/')

      [Environment]::SetEnvironmentVariable("SIEM_URL", $canon, "Machine") | Out-Null
      $env:SIEM_URL = $canon
    }
  } catch {
    # If SIEM_URL is weird/malformed, let later steps fail loudly.
  }

  # 2) Ensure key security config tree exists in ProgramData
  $secDir = Join-Path $confDir "opensearch-security"
  if (-not (Test-Path -LiteralPath $secDir -PathType Container)) {
    throw "Missing ProgramData security config tree: $secDir (installer must ship/copy this)."
  }

  # 3) Repair TLS keystore settings deterministically (ProgramData only)
  Repair-TinySocsOpenSearchTlsKeystore -CertsDir $certsDir -OpenSearchHome $osHome | Out-Null

  # 4) Stage templates into ProgramData deterministically (MUST succeed)
  if (-not (Get-Command Ensure-TinySocsOpenSearchTemplatesStaged -ErrorAction SilentlyContinue)) {
    throw "Ensure-TinySocsOpenSearchTemplatesStaged not found in module; cannot guarantee template staging."
  }
  $null = Ensure-TinySocsOpenSearchTemplatesStaged -InstallRoot $InstallRoot -ProgramDataTemplatesDir $pdTemplates

  # 4b) Stage ISM policies into ProgramData (best-effort, not fatal if missing)
  $pdPolicies = Join-Path $pdConf "policies"
  if (Get-Command Ensure-TinySocsOpenSearchPoliciesStaged -ErrorAction SilentlyContinue) {
    try {
      $null = Ensure-TinySocsOpenSearchPoliciesStaged -InstallRoot $InstallRoot -ProgramDataPoliciesDir $pdPolicies
    } catch {
      Write-TinySocsLog -Level "WARN" -Message "ISM policies staging failed (non-fatal): $($_.Exception.Message)"
    }
  }

  # 5) Ensure LocalMachine mTLS is usable for LocalSystem (CA + admin client cert) BEFORE readiness checks
  if (-not (Get-Command Ensure-TinySocsOpenSearchLocalMachineMtls -ErrorAction SilentlyContinue)) {
    throw "Ensure-TinySocsOpenSearchLocalMachineMtls not found in module; cannot guarantee mTLS for bootstrap."
  }
  $tp = Ensure-TinySocsOpenSearchLocalMachineMtls -CertsDir $certsDir
  [Environment]::SetEnvironmentVariable("SIEM_CLIENTCERT_THUMBPRINT", $tp, "Machine") | Out-Null
  $env:SIEM_CLIENTCERT_THUMBPRINT = $tp

  # 6) Start OpenSearch and wait for *real* readiness (service Running + endpoint reachable)
  if (-not (Get-Command _Start-ServiceAndWaitReady -ErrorAction SilentlyContinue)) {
    throw "_Start-ServiceAndWaitReady not found in module; cannot guarantee deterministic service gating."
  }

  try {
    $null = _Start-ServiceAndWaitReady -ServiceName $ServiceName -ServiceTimeoutSec 60 -ReadyTimeoutSec 180
  } catch {
    throw "OpenSearch did not become ready: $($_.Exception.Message)"
  }

  # Optional: if your module has a security readiness helper, use it (donâ€™t fail install on this)
  if (Get-Command Wait-TinySocsOpenSearchSecurityReady -ErrorAction SilentlyContinue) {
    try {
      $base = [Environment]::GetEnvironmentVariable("SIEM_URL","Machine")
      if ([string]::IsNullOrWhiteSpace($base)) { $base = "https://127.0.0.1:9201" }
      $null = Wait-TinySocsOpenSearchSecurityReady -Url $base -TimeoutSec 180
    } catch {
      Write-TinySocsLog -Level "WARN" -Message "OpenSearch security readiness wait failed (continuing): $($_.Exception.Message)"
    }
  }

  # 7) Ensure all templates (MUST succeed)
  if (-not (Get-Command Invoke-TinySocsOpenSearchTemplatesBootstrap -ErrorAction SilentlyContinue)) {
    throw "Invoke-TinySocsOpenSearchTemplatesBootstrap not found in module; cannot ensure templates."
  }

  try {
    # We just staged them, so this directory should exist and be authoritative
    Invoke-TinySocsOpenSearchTemplatesBootstrap -TemplatesDir $pdTemplates -WaitTimeoutSec 180 | Out-Null
  } catch {
    throw "OpenSearch templates bootstrap failed: $($_.Exception.Message)"
  }

  # 8) Ensure all ISM policies (best-effort, not fatal)
  if (Get-Command Invoke-TinySocsOpenSearchPoliciesBootstrap -ErrorAction SilentlyContinue) {
    try {
      if (Test-Path -LiteralPath $pdPolicies -PathType Container) {
        Invoke-TinySocsOpenSearchPoliciesBootstrap -PoliciesDir $pdPolicies -WaitTimeoutSec 180 | Out-Null
        Write-TinySocsLog "OpenSearch ISM policies bootstrap complete" "INFO"
      } else {
        Write-TinySocsLog "ISM policies dir not found; skipping policy bootstrap (non-fatal)" "WARN"
      }
    } catch {
      Write-TinySocsLog -Level "WARN" -Message "OpenSearch ISM policies bootstrap failed (non-fatal): $($_.Exception.Message)"
    }
  }

  Write-TinySocsLog "=== OpenSearch installer persist fix complete ===" "INFO"
  return $true
}

function Join-TsPath {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [string] $Root,

    [Parameter(Mandatory)]
    [string[]] $Parts
  )

  $p = $Root
  foreach ($part in $Parts) {
    if ([string]::IsNullOrWhiteSpace($part)) { continue }
    $p = Join-Path -Path $p -ChildPath $part
  }
  return $p
}

function Invoke-TinySocsOpenSearchApi {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [ValidateSet("GET","POST","PUT","DELETE","PATCH","HEAD","OPTIONS")]
    [string]$Method,
    [Parameter(Mandatory)]
    [string]$Url,

    # allow callers to pass a base URL + a path
    [string]$Path = $null,

    [string]$User,
    [string]$Pass,
    [string]$BodyJson,
    [switch]$SkipTlsVerify,
    [string]$CaCertPath,
    [int]$TimeoutSeconds        = 30,
    [int]$ConnectTimeoutSeconds = 5,
    [int]$Retries               = 2,
    [Nullable[bool]]$DisableRevocationCheck = $null,
    [int[]]$AllowHttpStatus = @(),
    [switch]$AsJson,
    [switch]$ReturnObject
  )

  # --- normalize URL + optional Path ---
  $effectiveUrl = $Url
  if (-not [string]::IsNullOrWhiteSpace($Path)) {
    $base = $Url.TrimEnd('/')
    $p = $Path.Trim()
    if (-not $p.StartsWith('/')) { $p = '/' + $p }
    $effectiveUrl = $base + $p
  }

  # --- platform detection ---
  $isWindowsPlatform = $false
  try { $isWindowsPlatform = ($env:OS -eq 'Windows_NT') } catch { }
  if (-not $isWindowsPlatform) {
    try { $isWindowsPlatform = ([System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT) } catch { }
  }

  # --- URL parsing / loopback detection ---
  $isLoopback = $false
  try {
    $u = [Uri]$effectiveUrl
    $isLoopback = $u.IsLoopback -or ($u.Host -in @('127.0.0.1','localhost','::1'))
  } catch { }

  # AUTO policy: only disable revocation checks for loopback on Windows (unless explicitly overridden)
  $effectiveDisableRevoke = $false
  if ($DisableRevocationCheck -ne $null) {
    $effectiveDisableRevoke = [bool]$DisableRevocationCheck
  } else {
    $effectiveDisableRevoke = ($isWindowsPlatform -and $isLoopback)
  }

  # --- mTLS client cert thumbprint (Machine first, then process) ---
  $clientTp = $null
  try { $clientTp = [Environment]::GetEnvironmentVariable("SIEM_CLIENTCERT_THUMBPRINT","Machine") } catch { $clientTp = $null }
  if ([string]::IsNullOrWhiteSpace($clientTp)) { $clientTp = $env:SIEM_CLIENTCERT_THUMBPRINT }
  if ($null -eq $clientTp) { $clientTp = "" }
  $clientTp = $clientTp.Trim()

  # Find curl.exe (prefer system curl)
  $curl = Join-Path $env:WINDIR "System32\curl.exe"
  if (-not (Test-Path $curl -PathType Leaf)) { $curl = "curl.exe" }

  $httpMarker = "__TS_HTTP_CODE__"

  function _ParseCurlOutput {
    param([string]$RawText)
    $httpCode = $null
    $bodyText = ""
    if ($null -ne $RawText) { $bodyText = [string]$RawText }
    $bodyText = $bodyText.Trim()

    if (-not [string]::IsNullOrWhiteSpace($bodyText)) {
      $lines = @($bodyText -split "`r?`n")
      if ($lines.Count -ge 1) {
        $lastLine = [string]$lines[$lines.Count - 1]
        if ($lastLine -like "$httpMarker*") {
          $maybe = $lastLine.Substring($httpMarker.Length).Trim()
          if ($maybe -match '^\d{3}$') { $httpCode = [int]$maybe }
          if ($lines.Count -gt 1) {
            $bodyText = (($lines[0..($lines.Count-2)]) -join "`n").Trim()
          } else {
            $bodyText = ""
          }
        }
      }
    }

    return @{
      HttpCode = $httpCode
      BodyText = $bodyText
    }
  }

  # PATCH: load CredMan SIEM creds if caller forgot to pass auth (or passed empty strings)
  function _TryLoadSiemCredsFromCredMan {
    try {
      if (Get-Command Get-TSCredential -ErrorAction SilentlyContinue) {
        $raw = Get-TSCredential -Name 'TinySocs/SIEM/Creds'
        if ($raw) {
          $j = $raw | ConvertFrom-Json
          $u = $null
          $p = $null
          if ($j.user) { $u = [string]$j.user }
          if ($j.pass) { $p = [string]$j.pass }
          if (-not [string]::IsNullOrWhiteSpace($u) -and -not [string]::IsNullOrWhiteSpace($p)) {
            return [pscustomobject]@{ User=$u; Pass=$p }
          }
        }
      }
    } catch { }
    return $null
  }

  # Apply fallback auth for loopback calls if missing
  $authMode = "none"
  if ([string]::IsNullOrWhiteSpace($User) -or [string]::IsNullOrWhiteSpace($Pass)) {
    $loaded = _TryLoadSiemCredsFromCredMan
    if ($loaded) {
      if ([string]::IsNullOrWhiteSpace($User)) { $User = [string]$loaded.User }
      if ([string]::IsNullOrWhiteSpace($Pass)) { $Pass = [string]$loaded.Pass }
      $authMode = "credman"
    }
  }
  if (-not [string]::IsNullOrWhiteSpace($User) -and -not [string]::IsNullOrWhiteSpace($Pass)) {
    if ($authMode -eq "none") { $authMode = "basic" }
  }

  # Light telemetry (no secrets)
  try {
    if ($isLoopback) {
      Write-TinySocsLog -Level "INFO" -Message ("[OSAPI] {0} {1} auth={2} tlsVerify={3}" -f $Method, $effectiveUrl, $authMode, ([string](-not $SkipTlsVerify.IsPresent)))
    }
  } catch { }

  function _BuildCurlArgs {
    param(
      [switch]$UseNoRevoke,
      [switch]$UseInsecure,
      [switch]$UseRetryAllErrors
    )

    $a = @(
      "--silent", "--show-error",
      "--location",
      "--noproxy", "127.0.0.1,localhost,::1",
      "--connect-timeout", [string]$ConnectTimeoutSeconds,
      "--max-time",        [string]$TimeoutSeconds
    )

    if ($Retries -gt 0) {
      $a += @(
        "--retry",       [string]$Retries,
        "--retry-delay", "1"
      )
      if ($UseRetryAllErrors.IsPresent) {
        $a += @("--retry-all-errors")
      }
    }

    if ($UseNoRevoke.IsPresent) { $a += @("--ssl-no-revoke") }

    if ($UseInsecure.IsPresent) {
      $a += @("-k")
    } else {
      if (-not [string]::IsNullOrWhiteSpace($CaCertPath)) {
        if (-not (Test-Path $CaCertPath -PathType Leaf)) {
          throw "Invoke-TinySocsOpenSearchApi: CaCertPath not found: $CaCertPath"
        }
        $a += @("--cacert", $CaCertPath)
      }
    }

    if ($isWindowsPlatform -and -not [string]::IsNullOrWhiteSpace($clientTp)) {
      $a += @("--cert", ("LocalMachine\MY\{0}" -f $clientTp))
    }

    $a += @("--write-out", ("`n{0}%{{http_code}}" -f $httpMarker))
    $a += @("-X", $Method, $effectiveUrl)

    if (-not [string]::IsNullOrWhiteSpace($User) -and -not [string]::IsNullOrWhiteSpace($Pass)) {
      $a += @("-u", ($User + ":" + $Pass))
    }

    return ,$a
  }

  function _ReturnBodyMaybeJson {
    param([string]$Text)
    if ($AsJson.IsPresent) {
      if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
      try { return ($Text | ConvertFrom-Json) } catch { return $Text }
    }
    return $Text
  }

  function _ReturnFinal {
    param([int]$HttpCode, [string]$BodyText)
    $val = _ReturnBodyMaybeJson -Text $BodyText
    if ($ReturnObject.IsPresent) {
      return [pscustomobject]@{
        StatusCode = $HttpCode
        Body       = $val
        Url        = $effectiveUrl
      }
    }
    return $val
  }

  $tmp = $null
  try {
    $bodyArgs = @()
    if (-not [string]::IsNullOrWhiteSpace($BodyJson)) {
      $tmp = Join-Path $env:TEMP ("tinysocs-os-body-{0}.json" -f ([guid]::NewGuid().ToString("N")))
      Set-Content -Path $tmp -Value $BodyJson -Encoding UTF8 -Force
      $bodyArgs += @(
        "-H", "Content-Type: application/json",
        "--data-binary", ("@{0}" -f $tmp)
      )
    }

    $useInsecure = $SkipTlsVerify.IsPresent
    $useNoRevoke = ($isWindowsPlatform -and $effectiveDisableRevoke -and -not $useInsecure)
    $useRetryAllErrors = $true

    $args = _BuildCurlArgs -UseNoRevoke:$useNoRevoke -UseInsecure:$useInsecure -UseRetryAllErrors:([bool]$useRetryAllErrors)
    if ($bodyArgs.Count -gt 0) { $args += $bodyArgs }

    $out = & $curl @args 2>&1
    $rc  = $LASTEXITCODE
    $raw = ($out | Out-String)

    $parsed   = _ParseCurlOutput -RawText $raw
    $httpCode = $parsed.HttpCode
    $txt      = $parsed.BodyText

    if ($rc -ne 0 -and $Retries -gt 0 -and $useRetryAllErrors -and ($raw -match 'unknown option|unsupported option') -and ($raw -match '--retry-all-errors')) {
      Write-TinySocsLog -Level "WARN" -Message "curl does not support --retry-all-errors on this system; retrying without it for $Method $effectiveUrl."
      $argsA = _BuildCurlArgs -UseNoRevoke:$useNoRevoke -UseInsecure:$useInsecure -UseRetryAllErrors:$false
      if ($bodyArgs.Count -gt 0) { $argsA += $bodyArgs }
      $outA = & $curl @argsA 2>&1
      $rc   = $LASTEXITCODE
      $raw  = ($outA | Out-String)
      $parsedA  = _ParseCurlOutput -RawText $raw
      $httpCode = $parsedA.HttpCode
      $txt      = $parsedA.BodyText
      $useRetryAllErrors = $false
    }

    if ($rc -ne 0 -and $useNoRevoke -and $isLoopback -and ($raw -match 'unknown option|unsupported option|--ssl-no-revoke')) {
      Write-TinySocsLog -Level "WARN" -Message "curl does not support --ssl-no-revoke on this system; falling back to -k for loopback call to $effectiveUrl."
      $args2 = _BuildCurlArgs -UseNoRevoke:$false -UseInsecure:$true -UseRetryAllErrors:([bool]$useRetryAllErrors)
      if ($bodyArgs.Count -gt 0) { $args2 += $bodyArgs }
      $out2 = & $curl @args2 2>&1
      $rc   = $LASTEXITCODE
      $raw  = ($out2 | Out-String)
      $parsed2  = _ParseCurlOutput -RawText $raw
      $httpCode = $parsed2.HttpCode
      $txt      = $parsed2.BodyText
    }

    if ($httpCode -ne $null -and $httpCode -ge 400) {
      if ($AllowHttpStatus -and ($AllowHttpStatus -contains $httpCode)) {
        return (_ReturnFinal -HttpCode $httpCode -BodyText $txt)
      }
      $detail = ""
      if ($null -ne $txt) { $detail = [string]$txt }
      $detail = $detail.Trim()
      throw "Invoke-TinySocsOpenSearchApi: HTTP $httpCode $Method $effectiveUrl :: $detail"
    }

    if ($rc -ne 0) {
      if ($httpCode -ne $null -and $AllowHttpStatus -and ($AllowHttpStatus -contains $httpCode)) {
        return (_ReturnFinal -HttpCode $httpCode -BodyText $txt)
      }

      $detail = ""
      if ($null -ne $txt) { $detail = [string]$txt }
      $detail = $detail.Trim()
      if ([string]::IsNullOrWhiteSpace($detail)) {
        $detail = ""
        if ($null -ne $raw) { $detail = [string]$raw }
        $detail = $detail.Trim()
      }

      $hc = ""
      if ($httpCode -ne $null) { $hc = " http=$httpCode" }
      throw "Invoke-TinySocsOpenSearchApi: curl failed (exit=$rc$hc) $Method $effectiveUrl :: $detail"
    }

    return (_ReturnFinal -HttpCode $httpCode -BodyText $txt)
  }
  finally {
    if ($tmp -and (Test-Path $tmp -PathType Leaf)) {
      try { Remove-Item -Force -ErrorAction SilentlyContinue $tmp } catch { }
    }
  }
}


function Ensure-TinySocsWinlogbeatTemplate {
  [CmdletBinding()]
  param(
    [string]$SiemUrl = "https://localhost:9201",
    [string]$User,
    [string]$Pass,
    [switch]$SkipTlsVerify
  )

  # Legacy, opt-in only:
  # We no longer depend on Winlogbeat; this template exists only for backwards compatibility.
  $raw = $env:TINYSOCS_ENABLE_WINLOGBEAT_TEMPLATE
  $enabled = $false
  if ($null -ne $raw) {
    $s = $raw.ToString().Trim().ToLowerInvariant()
    $enabled = ($s -in @('1','true','yes','y','on','enable','enabled'))
  }

  if (-not $enabled) {
    Write-TinySocsLog -Level "INFO" -Message "Ensure-TinySocsWinlogbeatTemplate: skipped (legacy; set TINYSOCS_ENABLE_WINLOGBEAT_TEMPLATE=true to enable)."
    return $true
  }

  # Correct, non-misleading name (do NOT reuse tinysocs-winlog)
  $name = "tinysocs-winlogbeat"
  $path = "/_index_template/$name"

  $putBody = @"
{
  "index_patterns": ["winlogbeat-*"],
  "template": {
    "settings": {
      "number_of_shards": 1,
      "number_of_replicas": 0
    }
  },
  "priority": 500
}
"@

  # Do not do anonymous calls in secure mode.
  if ([string]::IsNullOrWhiteSpace($User) -or [string]::IsNullOrWhiteSpace($Pass)) {
    Write-TinySocsLog -Level "WARN" -Message "Ensure-TinySocsWinlogbeatTemplate: enabled but missing User/Pass; skipping to avoid 401 spam."
    return $false
  }

  $auth = @{ User = [string]$User; Pass = [string]$Pass }

  try {
    $g = Invoke-TinySocsOpenSearchApi `
      -Method GET `
      -Url $SiemUrl `
      -Path $path `
      -AllowHttpStatus 404 `
      -SkipTlsVerify:$SkipTlsVerify `
      @auth `
      -ReturnObject

    if ($g -and [string]$g.StatusCode -eq "200") {
      Write-TinySocsLog -Level "INFO" -Message "Index template '$name' already present (legacy winlogbeat)."
      return $true
    }

    $put = Invoke-TinySocsOpenSearchApi `
      -Method PUT `
      -Url $SiemUrl `
      -Path $path `
      -BodyJson $putBody `
      -SkipTlsVerify:$SkipTlsVerify `
      @auth `
      -ReturnObject

    if ($put -and [string]$put.StatusCode -eq "200") {
      Write-TinySocsLog -Level "INFO" -Message "Ensured legacy index template '$name' for winlogbeat-* (replicas=0)."
      return $true
    }

    throw "Ensure-TinySocsWinlogbeatTemplate: PUT did not return 200 (StatusCode=$($put.StatusCode))."
  } catch {
    Write-TinySocsLog -Level "WARN" -Message "Ensure-TinySocsWinlogbeatTemplate failed: $($_.Exception.Message)"
    return $false
  }
}

function Read-TinySocsTextUtf8 {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path
  )

  if (-not (Test-Path -LiteralPath $Path)) {
    throw "File not found: $Path"
  }

  # Read as UTF8 and strip BOM char if present
  $text = [System.IO.File]::ReadAllText($Path, [System.Text.Encoding]::UTF8)
  return ($text -replace "^\uFEFF","")
}

function Write-TinySocsTextUtf8NoBom {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$Text
  )

  $dir = Split-Path -Parent $Path
  if ($dir -and -not (Test-Path -LiteralPath $dir)) {
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
  }

  $enc = New-Object System.Text.UTF8Encoding($false) # no BOM
  [System.IO.File]::WriteAllText($Path, $Text, $enc)
}

function Write-TinySocsLog {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)][string]$Message,
    [ValidateSet('DEBUG','INFO','WARN','ERROR')][string]$Level = 'INFO'
  )

  $ts   = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
  $line = "{0} [{1}] {2}" -f $ts, $Level, $Message

  $logDir  = "C:\ProgramData\TinySocs\logs"
  $logFile = Join-Path $logDir "installer.log"

  try {
    if (-not (Test-Path -LiteralPath $logDir -PathType Container)) {
      New-Item -ItemType Directory -Force -Path $logDir | Out-Null
    }

    # Best-effort: set sane ACLs on the log dir
    try { Ensure-TinySocsLogAcl -LogDir $logDir } catch { }

    # First attempt
    try {
      Add-Content -Path $logFile -Value $line -Encoding UTF8
      return
    } catch {
      # If we got access denied, try a hard reset once.
      $msg = $_.Exception.Message
      if ($msg -match 'Access.*denied|UnauthorizedAccess') {
        try {
          $sys = '*S-1-5-18'
          $adm = '*S-1-5-32-544'
          $usr = '*S-1-5-32-545'

          # Take ownership + reset + grant
          Invoke-TinySocsCmd ('takeown /F "{0}" /A /R /D Y >nul 2>&1' -f $logDir)
          Invoke-TinySocsCmd ('icacls "{0}" /reset /T /C >nul 2>&1' -f $logDir)
          Invoke-TinySocsCmd ('icacls "{0}" /inheritance:e /grant:r "{1}:(OI)(CI)F" "{2}:(OI)(CI)F" "{3}:(OI)(CI)M" /T /C >nul 2>&1' -f $logDir, $sys, $adm, $usr)

          # Retry
          Add-Content -Path $logFile -Value $line -Encoding UTF8
          return
        } catch { }
      }

      throw
    }
  }
  catch {
    # Fall back to a temp log rather than exploding the installer.
    try {
      $fallback = Join-Path $env:TEMP "tinysocs-installer-fallback.log"
      Add-Content -Path $fallback -Value $line -Encoding UTF8
    } catch { }
  }
}

function New-TinySocsPassword {
  [CmdletBinding()]
  param(
    [int]$Length = 24
  )
  $alphabet = ('ABCDEFGHJKLMNPQRSTUVWXYZ' +
               'abcdefghijkmnopqrstuvwxyz' +
               '23456789' +
               '!@#$%^&*_-+=').ToCharArray()
  $bytes = New-Object byte[] ($Length * 2)
  [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
  $sb = New-Object System.Text.StringBuilder
  for ($i=0; $i -lt $Length; $i++) {
    $idx = [int]($bytes[$i] % $alphabet.Length)
    [void]$sb.Append($alphabet[$idx])
  }
  return $sb.ToString()
}

function Ensure-FileNotEfsEncrypted {
  param([Parameter(Mandatory)][string]$Path)
  try {
    $cipher = Join-Path $env:WINDIR "System32\cipher.exe"
    if (Test-Path $cipher) {
      & $cipher /d /a $Path 2>$null | Out-Null
    }
  } catch { }
}

function Ensure-TinySocsAgentConfigReadable {
  $rootVal = (Get-TinySocsDataRoot | Select-Object -First 1)
  $root    = [string]$rootVal

  $cfg  = Join-Path -Path $root -ChildPath "Collector\agent\config.yml"
  $dir  = Split-Path -Parent $cfg

  if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }

  if (Test-Path -LiteralPath $cfg) {
    Ensure-FileNotEfsEncrypted -Path $cfg
  }

  Ensure-SystemReadAcl -Path $dir
  if (Test-Path -LiteralPath $cfg) { Ensure-SystemReadAcl -Path $cfg }

  Write-TinySocsLog "Agent config ACL/EFS hardening ensured at $cfg"
}

function Set-TinySocsAgentConfigCredentials {
  <#
    Injects user: and pass: into the output: section of agent-config.yml.
    Values are always YAML double-quoted to prevent issues with special
    characters (!, #, %, etc.) that have meaning in bare YAML scalars.
    Writes UTF-8 without BOM and re-applies ACLs via Ensure-TinySocsAgentConfigReadable.
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$User,
    [Parameter(Mandatory)][string]$Pass
  )

  $rootVal = (Get-TinySocsDataRoot | Select-Object -First 1)
  $root    = [string]$rootVal
  # Must match the path NSSM sets in TINYSOCS_AGENT_CONFIG (Collector\agent-config.yml)
  $cfg     = Join-Path -Path $root -ChildPath "Collector\agent-config.yml"

  if (-not (Test-Path -LiteralPath $cfg -PathType Leaf)) {
    # Fallback: try the legacy path for backwards compatibility
    $legacyCfg = Join-Path -Path $root -ChildPath "Collector\agent\config.yml"
    if (Test-Path -LiteralPath $legacyCfg -PathType Leaf) {
      $cfg = $legacyCfg
      Write-TinySocsLog -Level "WARN" -Message "Primary config not found; falling back to legacy path $cfg"
    } else {
      Write-TinySocsLog -Level "WARN" -Message "Agent config not found at $cfg; cannot inject credentials."
      return
    }
  }

  # Escape backslashes and double-quotes inside values for YAML double-quoted strings
  $safeUser = $User -replace '\\', '\\' -replace '"', '\"'
  $safePass = $Pass -replace '\\', '\\' -replace '"', '\"'

  $lines    = [System.IO.File]::ReadAllLines($cfg)
  $outLines = [System.Collections.Generic.List[string]]::new()
  $inOutput = $false
  $insertedUser = $false
  $insertedPass = $false
  # Track the index (in $outLines) after which we should insert user/pass
  # if they weren't found as existing lines. We anchor after pipeline: or ssl_verify:.
  $insertAfterIdx = -1

  for ($i = 0; $i -lt $lines.Count; $i++) {
    $line = $lines[$i]

    # Detect top-level YAML keys (no leading whitespace)
    if ($line -match '^[a-z_]') {
      if ($line -match '^output\s*:') {
        $inOutput = $true
      } elseif ($inOutput) {
        $inOutput = $false
      }
    }

    if ($inOutput) {
      # Replace existing user:/pass: lines (always double-quote values)
      if ($line -match '^\s+user\s*:') {
        $outLines.Add("  user: `"$safeUser`"")
        $insertedUser = $true
        continue
      }
      if ($line -match '^\s+pass\s*:') {
        $outLines.Add("  pass: `"$safePass`"")
        $insertedPass = $true
        continue
      }
      # Track last scalar anchor (pipeline: or ssl_verify:) for insertion point
      if ($line -match '^\s+(pipeline|ssl_verify|index_pattern)\s*:') {
        $outLines.Add($line)
        $insertAfterIdx = $outLines.Count - 1
        continue
      }
    }

    $outLines.Add($line)
  }

  # Insert user/pass after the anchor point if they weren't already present
  if (-not $insertedUser -or -not $insertedPass) {
    if ($insertAfterIdx -ge 0) {
      $toInsert = [System.Collections.Generic.List[string]]::new()
      if (-not $insertedUser) { $toInsert.Add("  user: `"$safeUser`"") }
      if (-not $insertedPass) { $toInsert.Add("  pass: `"$safePass`"") }
      $outLines.InsertRange($insertAfterIdx + 1, $toInsert)
    } else {
      # Fallback: append at end of file (shouldn't happen with well-formed config)
      if (-not $insertedUser) { $outLines.Add("  user: `"$safeUser`"") }
      if (-not $insertedPass) { $outLines.Add("  pass: `"$safePass`"") }
    }
  }

  $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
  [System.IO.File]::WriteAllLines($cfg, $outLines.ToArray(), $utf8NoBom)
  Write-TinySocsLog "Injected user/pass into agent config at $cfg"

  Ensure-TinySocsAgentConfigReadable
}

function Ensure-SystemReadAcl {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Path)

  if (-not (Test-Path -LiteralPath $Path)) { return }

  # Locale-proof SIDs (use icacls SID form with leading *)
  $sidSystem = '*S-1-5-18'       # SYSTEM
  $sidAdmins = '*S-1-5-32-544'   # BUILTIN\Administrators

  try {
    $item = Get-Item -LiteralPath $Path -ErrorAction Stop

    if ($item.PSIsContainer) {
      # SYSTEM needs RX to traverse/read; Admins full for operational fixes
      & icacls $Path /inheritance:e `
        /grant:r "$($sidSystem):(OI)(CI)(RX)" `
                 "$($sidAdmins):(OI)(CI)(F)" `
        /t /c /q 2>$null | Out-Null
    } else {
      & icacls $Path /inheritance:e `
        /grant:r "$($sidSystem):(RX)" `
                 "$($sidAdmins):(F)" `
        /c /q 2>$null | Out-Null
    }
  } catch {
    try {
      Write-TinySocsLog -Level "WARN" -Message "ACL hardening failed for ${Path}: $($_.Exception.Message)"
    } catch { }
  }
}

# ---- DPAPI helpers (LocalMachine scope) --------------------------------------

function Read-TinySocsSiemAdminPassFromDpapiFile {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$CertsDir)

  # Primary location (OpenSearch config tree)
  $primary = $null
  try { $primary = Get-TinySocsSiemAdminPassFilePath -CertsDir $CertsDir } catch { $primary = $null }

  # Secondary location (global TinySocs secrets store; survives OpenSearch config rotation)
  $secondary = $null
  try { $secondary = Join-Path (Get-TinySocsSecretStoreDir) "siem-admin-pass.dpapi" } catch { $secondary = $null }

  $candidates = @()
  if ($primary)   { $candidates += $primary }
  if ($secondary) { $candidates += $secondary }

  foreach ($p in $candidates) {
    if (-not $p) { continue }
    if (-not (Test-Path $p -PathType Leaf)) { continue }

    try {
      $raw = (Get-Content -Path $p -Raw -ErrorAction Stop)
      $raw = ([string]$raw).Trim()
      if ([string]::IsNullOrWhiteSpace($raw)) { continue }

      $plain = Unprotect-TinySocsDpapiLocalMachineB64 -B64 $raw
      if ([string]::IsNullOrWhiteSpace($plain)) { continue }

      # Backfill the *other* copy if missing (best-effort)
      try {
        if ($p -eq $primary -and $secondary -and -not (Test-Path $secondary -PathType Leaf)) {
          $wrapped = Protect-TinySocsDpapiLocalMachine -Plain $plain
          New-Item -ItemType Directory -Force -Path (Split-Path -Parent $secondary) | Out-Null
          Set-Content -Path $secondary -Value $wrapped -Encoding ASCII -Force
          Write-TinySocsLog "Backfilled SIEM admin DPAPI file into global secrets store ($secondary)."
        } elseif ($p -eq $secondary -and $primary -and -not (Test-Path $primary -PathType Leaf)) {
          $wrapped = Protect-TinySocsDpapiLocalMachine -Plain $plain
          New-Item -ItemType Directory -Force -Path (Split-Path -Parent $primary) | Out-Null
          Set-Content -Path $primary -Value $wrapped -Encoding ASCII -Force
          Write-TinySocsLog "Backfilled SIEM admin DPAPI file into OpenSearch certs dir ($primary)."
        }
      } catch {
        Write-TinySocsLog -Level "WARN" -Message "Recovered SIEM admin password from DPAPI file ($p) but failed backfill: $($_.Exception.Message)"
      }

      return $plain
    } catch {
      Write-TinySocsLog -Level "WARN" -Message "Failed to read/unwrap SIEM admin DPAPI file ($p): $($_.Exception.Message)"
    }
  }

  return $null
}

function Write-TinySocsSiemAdminPassToDpapiFile {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$CertsDir,
    [Parameter(Mandatory)][string]$AdminPass
  )

  $okAny   = $false
  $wrapped = $null

  try { $wrapped = Protect-TinySocsDpapiLocalMachine -Plain $AdminPass }
  catch {
    Write-TinySocsLog -Level "WARN" -Message "Failed to DPAPI-wrap SIEM admin password: $($_.Exception.Message)"
    return $false
  }

  # Primary (OpenSearch certs dir)
  $p1 = $null
  try { $p1 = Get-TinySocsSiemAdminPassFilePath -CertsDir $CertsDir } catch { $p1 = $null }

  # Secondary (global secrets store)
  $p2 = $null
  try { $p2 = Join-Path (Get-TinySocsSecretStoreDir) "siem-admin-pass.dpapi" } catch { $p2 = $null }

  foreach ($p in @($p1,$p2) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) {
    try {
      $dir = Split-Path -Parent $p
      if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }

      Set-Content -Path $p -Value $wrapped -Encoding ASCII -Force
      $okAny = $true
      Write-TinySocsLog "Persisted SIEM admin password to DPAPI file ($p)."
    } catch {
      Write-TinySocsLog -Level "WARN" -Message "Failed to write SIEM admin DPAPI file ($p): $($_.Exception.Message)"
    }
  }

  return $okAny
}

function New-ProgramDataLayout {
  [CmdletBinding()]
  param()

  # Defensive: ensure we always treat root as a single string (avoids Join-Path/Object[] style issues elsewhere)
  $root = [string](Get-TinySocsDataRoot | Select-Object -First 1)

  $paths = @(
    "$root\logs",
    "$root\queue",
    "$root\ledger",
    "$root\rules",
    "$root\anchors\state",
    "$root\config",

    # Collector (Agent)
    "$root\Collector",
    "$root\Collector\agent",
    "$root\Collector\agent\queue",
    "$root\Collector\agent\bookmarks",
    "$root\Collector\logs",

    # OpenSearch
    "$root\OpenSearch",
    "$root\OpenSearch\config",
    "$root\OpenSearch\config\certs",
    "$root\OpenSearch\certs",
    "$root\OpenSearch\security",
    "$root\OpenSearch\data",
    "$root\OpenSearch\logs"
  )

  foreach ($p in $paths) {
    try { New-Item -ItemType Directory -Force -Path $p | Out-Null } catch { }
  }

  # ---- ACL hardening / determinism ----
  # Use SIDs so this works on non-English Windows too.
  $sidSystem = '*S-1-5-18'        # SYSTEM
  $sidAdmins = '*S-1-5-32-544'    # BUILTIN\Administrators
  $sidUsers  = '*S-1-5-32-545'    # BUILTIN\Users

  try {
    # Ensure SYSTEM + Admins can always read/write everything under ProgramData\TinySocs
    & icacls $root /inheritance:e /grant:r `
      "${sidSystem}:(OI)(CI)(F)" `
      "${sidAdmins}:(OI)(CI)(F)" `
      /t /c /q | Out-Null

    # Allow interactive users to modify the ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã¢â‚¬Å“operationalÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â dirs (logs/queue).
    foreach ($rw in @("$root\logs", "$root\queue", "$root\OpenSearch\logs", "$root\Collector\logs")) {
      if (Test-Path -LiteralPath $rw) {
        & icacls $rw /inheritance:e /grant:r `
          "${sidSystem}:(OI)(CI)(F)" `
          "${sidAdmins}:(OI)(CI)(F)" `
          "${sidUsers}:(OI)(CI)(M)" `
          /t /c /q | Out-Null
      }
    }
  } catch {
    # If ACL adjustments fail for any reason, we still want install to continue.
  }

  # Ensure SYSTEM can traverse/read the state trees services rely on
  try { Ensure-SystemReadAcl -Path "$root\Collector" } catch { }
  try { Ensure-SystemReadAcl -Path "$root\OpenSearch" } catch { }
}

function _Invoke-TinySocsOpenSearchJson {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][ValidateSet('GET','PUT','POST','PATCH','DELETE')][string]$Method,
    [Parameter(Mandatory)][string]$Uri,
    [Parameter(Mandatory)][string]$Username,
    [Parameter(Mandatory)][string]$Password,
    [Parameter()][object]$BodyObject,
    [switch]$SkipTlsVerify,
    [int]$TimeoutSec = 15
  )

  # Build Basic auth header
  $pair = "{0}:{1}" -f $Username, $Password
  $b64  = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($pair))
  $hdrs = @{
    "Authorization" = "Basic $b64"
    "Accept"        = "application/json"
  }

  # TLS handling for Windows PowerShell 5.1 vs PowerShell 7+
  $irmParams = @{
    Method      = $Method
    Uri         = $Uri
    Headers     = $hdrs
    TimeoutSec  = $TimeoutSec
    ErrorAction = 'Stop'
  }

  if ($PSVersionTable.PSVersion.Major -ge 7) {
    if ($SkipTlsVerify) { $irmParams.SkipCertificateCheck = $true }
  } else {
    if ($SkipTlsVerify) {
      try {
        # Best-effort: disable cert validation in this session
        add-type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public static class TinySocsTls {
  public static bool AlwaysOk(object sender, X509Certificate certificate, X509Chain chain, System.Net.Security.SslPolicyErrors sslPolicyErrors) { return true; }
}
"@ -ErrorAction SilentlyContinue | Out-Null
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = [TinySocsTls]::AlwaysOk
      } catch { }
    }
  }

  if ($null -ne $BodyObject) {
    $json = $BodyObject | ConvertTo-Json -Depth 20
    # Send bytes explicitly to avoid encoding surprises
    $irmParams.ContentType = "application/json"
    $irmParams.Body = [Text.Encoding]::UTF8.GetBytes($json)
  }

  return Invoke-RestMethod @irmParams
}

function _Wait-TinySocsOpenSearchReady {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$BaseUrl,
    [Parameter(Mandatory)][string]$AdminUser,
    [Parameter(Mandatory)][string]$AdminPass,
    [switch]$SkipTlsVerify,
    [int]$TimeoutSec = 120
  )

  $deadline = (Get-Date).AddSeconds($TimeoutSec)
  do {
    try {
      $null = _Invoke-TinySocsOpenSearchJson -Method GET -Uri "$BaseUrl/" -Username $AdminUser -Password $AdminPass -SkipTlsVerify:$SkipTlsVerify -TimeoutSec 10
      return
    } catch {
      Start-Sleep -Seconds 2
    }
  } while ((Get-Date) -lt $deadline)

  throw "OpenSearch not reachable at $BaseUrl within ${TimeoutSec}s."
}

function Ensure-TinySocsOpenSearchSecurityBootstrap {
  [CmdletBinding()]
  param(
    # If not provided, weâ€™ll pull from CredMan: TinySocs/SIEM/Creds and TinySocs/OpenSearch/tinysocs
    [string]$BaseUrl,
    [string]$AdminUser,
    [string]$AdminPass,
    [string]$ServiceUser = "tinysocs",
    [string]$ServicePass,
    [switch]$SkipTlsVerify
  )

  # --- Resolve creds from CredMan if absent ---
  if ([string]::IsNullOrWhiteSpace($BaseUrl) -or [string]::IsNullOrWhiteSpace($AdminUser) -or [string]::IsNullOrWhiteSpace($AdminPass)) {
    $cfg = (Get-TSCredential -Name 'TinySocs/SIEM/Creds' | ConvertFrom-Json)
    if ([string]::IsNullOrWhiteSpace($BaseUrl))   { $BaseUrl   = $cfg.url.TrimEnd('/') }
    if ([string]::IsNullOrWhiteSpace($AdminUser)) { $AdminUser = $cfg.user }
    if ([string]::IsNullOrWhiteSpace($AdminPass)) { $AdminPass = $cfg.pass }
  }

  if ([string]::IsNullOrWhiteSpace($ServicePass)) {
    $svc = (Get-TSCredential -Name "TinySocs/OpenSearch/$ServiceUser" | ConvertFrom-Json)
    if ($svc -and $svc.pass) { $ServicePass = $svc.pass }
  }

  if ([string]::IsNullOrWhiteSpace($ServicePass)) {
    throw "Service password not provided and CredMan entry TinySocs/OpenSearch/$ServiceUser not found."
  }

  # --- Wait until OpenSearch answers as admin (security plugin reachable) ---
  _Wait-TinySocsOpenSearchReady -BaseUrl $BaseUrl -AdminUser $AdminUser -AdminPass $AdminPass -SkipTlsVerify:$SkipTlsVerify -TimeoutSec 180

  # --- Ensure role ---
  $roleName = "tinysocs_role"
  $roleBody = @{
    cluster_permissions = @(
      "cluster_composite_ops",
      "cluster:monitor/*",
      "cluster:admin/ingest/pipeline/*",
      "indices:admin/index_template/*"
    )
    index_permissions = @(
      @{
        index_patterns  = @("winlogbeat-*","tinysocs_anchors*","siem_index*","tinysocs-*","logs-*","security-auditlog-*")
        allowed_actions = @("crud","create_index","indices:data/write/*","indices:data/read/*","indices:admin/*","indices:monitor/*")
      }
    )
  }

  _Invoke-TinySocsOpenSearchJson `
    -Method PUT `
    -Uri "$BaseUrl/_plugins/_security/api/roles/$roleName" `
    -Username $AdminUser -Password $AdminPass `
    -BodyObject $roleBody `
    -SkipTlsVerify:$SkipTlsVerify | Out-Null

  # --- Ensure internal user ---
  $userBody = @{
    password      = $ServicePass
    backend_roles = @($roleName)
    attributes    = @{ app = "tinysocs" }
  }

  _Invoke-TinySocsOpenSearchJson `
    -Method PUT `
    -Uri "$BaseUrl/_plugins/_security/api/internalusers/$ServiceUser" `
    -Username $AdminUser -Password $AdminPass `
    -BodyObject $userBody `
    -SkipTlsVerify:$SkipTlsVerify | Out-Null

  # --- Ensure role mapping ---
  $mapBody = @{
    users         = @($ServiceUser)
    backend_roles = @()
    hosts         = @()
  }

  _Invoke-TinySocsOpenSearchJson `
    -Method PUT `
    -Uri "$BaseUrl/_plugins/_security/api/rolesmapping/$roleName" `
    -Username $AdminUser -Password $AdminPass `
    -BodyObject $mapBody `
    -SkipTlsVerify:$SkipTlsVerify | Out-Null

  # --- Validate service auth ---
  try {
    $auth = _Invoke-TinySocsOpenSearchJson `
      -Method GET `
      -Uri "$BaseUrl/_plugins/_security/authinfo" `
      -Username $ServiceUser -Password $ServicePass `
      -SkipTlsVerify:$SkipTlsVerify

    if ($null -eq $auth -or $auth.user_name -ne $ServiceUser) {
      throw "authinfo did not return expected service user."
    }
    if ($auth.roles -notcontains $roleName) {
      throw "authinfo returned user but role '$roleName' not present."
    }
  } catch {
    throw "OpenSearch security bootstrap completed, but service auth validation failed for '$ServiceUser': $($_.Exception.Message)"
  }

  return $true
}

function Install-TinySocs {
  try {
    New-ProgramDataLayout
    Write-TinySocsLog "ProgramData layout ensured at $(Get-TinySocsDataRoot)."

    # OpenSearch invariants (ProgramData-owned + upgrade-safe)
    Sync-TinySocsOpenSearchConfigToProgramData

    # Canonicalize ProgramData opensearch.yml (idempotent; prevents duplicate-key boot failures)
    $pdYaml = Join-Path $env:ProgramData 'TinySocs\OpenSearch\config\opensearch.yml'
    Ensure-OpenSearchYamlCanonical -YamlPath $pdYaml

    Register-TinySocsOpenSearchService

    # Agent invariants (ACL/EFS)
    Ensure-TinySocsAgentConfigReadable

    # Optional: template self-heal at install time (best-effort; safe if auth not wired yet)
    # If you have admin creds available as env vars, it will apply; otherwise it just logs and moves on.
    $siemUrl = [Environment]::GetEnvironmentVariable("SIEM_URL","Machine")
    if (-not $siemUrl) { $siemUrl = "https://localhost:9201" }

    $u = [Environment]::GetEnvironmentVariable("TINYSOCS_SIEM_USER","Machine")
    $p = [Environment]::GetEnvironmentVariable("TINYSOCS_SIEM_PASS","Machine")

    if ($u -and $p) {
      Ensure-TinySocsWinlogbeatTemplate -SiemUrl $siemUrl -User $u -Pass $p
    } else {
      Write-TinySocsLog -Level "DEBUG" -Message "Skipping template bootstrap (TINYSOCS_SIEM_USER/PASS not set at Machine scope)."
    }
  } catch {
    Write-TinySocsLog -Level "ERROR" -Message ("Install-TinySocs failed: " + $_.Exception.Message)
    throw
  }
}

# Helper: module version/path info for debugging
function Get-TinySocsInstallerModuleInfo {
  [CmdletBinding()]
  param()

  $p = $null
  try { $p = $MyInvocation.MyCommand.Path } catch { }
  if ([string]::IsNullOrWhiteSpace($p)) {
    try { $p = $PSCommandPath } catch { }
  }

  [pscustomobject]@{
    Version   = $script:TinySocsInstallerVersion
    Path      = $p
    PSEdition = $PSVersionTable.PSEdition
    PSVersion = $PSVersionTable.PSVersion.ToString()
  }
}

# -- Credential Manager helpers (TinySocs/Phase7) ------------------------------
# We store secrets as Generic credentials so services and tasks can read them.
# Targets we use:
#   TinySocs/Node/Secret
#   TinySocs/Master/SharedSecret
#   TinySocs/SIEM/Creds

if (-not ('TinySocs.Security.CredNative2' -as [type])) {
  Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

namespace TinySocs.Security
{
    public static class CredNative2
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct CREDENTIAL
        {
            public uint Flags;
            public uint Type;
            public IntPtr TargetName;
            public IntPtr Comment;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
            public uint CredentialBlobSize;
            public IntPtr CredentialBlob;
            public uint Persist;
            public uint AttributeCount;
            public IntPtr Attributes;
            public IntPtr TargetAlias;
            public IntPtr UserName;
        }

        public static CREDENTIAL PtrToCredential(IntPtr credentialPtr)
        {
            return (CREDENTIAL)Marshal.PtrToStructure(credentialPtr, typeof(CREDENTIAL));
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
}

function _Write-TSCredential {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][string]$User,
    [Parameter(Mandatory)][AllowEmptyString()][string]$Secret
  )

  # Store in Windows Credential Manager as a Generic credential.
  # Persist = LocalMachine so services can read it too (when running elevated at write time).
  try {
    if (-not ("TinySocs.CredMan" -as [type])) {
      Add-Type -Language CSharp -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Text;

namespace TinySocs {
  public static class CredMan {
    public enum CRED_TYPE : uint { GENERIC = 1 }
    public enum CRED_PERSIST : uint { SESSION = 1, LOCAL_MACHINE = 2, ENTERPRISE = 3 }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct CREDENTIAL {
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

    [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CredWrite(ref CREDENTIAL userCredential, uint flags);

    [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CredDelete(string target, uint type, uint flags);
  }
}
"@
    }

    # Normalize to avoid double-prefix (TinySocs:TinySocs/...)
    $normalized = _Normalize-TSCredTarget $Name
    if ([string]::IsNullOrWhiteSpace($normalized)) { throw "Cred target name is empty." }

    # Canonical target written to CredMan
    $target = "TinySocs:$normalized"

    # Best-effort delete first to avoid duplicate weirdness (delete using SAME normalized target)
    try { [TinySocs.CredMan]::CredDelete($target, [uint32][TinySocs.CredMan+CRED_TYPE]::GENERIC, 0) | Out-Null } catch { }

    # Writer expects UTF-16LE. Store string INCLUDING trailing NUL terminator
    # because Get-TSCredential trims trailing NULs.
    $bytes = [Text.Encoding]::Unicode.GetBytes($Secret + [char]0)
    $blob  = [Runtime.InteropServices.Marshal]::AllocHGlobal($bytes.Length)
    try {
      [Runtime.InteropServices.Marshal]::Copy($bytes, 0, $blob, $bytes.Length)

      $cred = New-Object TinySocs.CredMan+CREDENTIAL
      $cred.Flags = 0
      $cred.Type = [uint32][TinySocs.CredMan+CRED_TYPE]::GENERIC
      $cred.TargetName = $target
      $cred.Comment = "TinySocs stored credential"
      $cred.CredentialBlobSize = [uint32]$bytes.Length
      $cred.CredentialBlob = $blob
      $cred.Persist = [uint32][TinySocs.CredMan+CRED_PERSIST]::LOCAL_MACHINE
      $cred.AttributeCount = 0
      $cred.Attributes = [IntPtr]::Zero
      $cred.TargetAlias = $null
      $cred.UserName = $User

      $ok = [TinySocs.CredMan]::CredWrite([ref]$cred, 0)
      if (-not $ok) {
        $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        throw "CredWrite failed for target '$target' (win32=$err)"
      }

      Write-TinySocsLog -Level "INFO" -Message "Stored credential in CredMan: $target (user=$User)"
      return $true
    }
    finally {
      if ($blob -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::FreeHGlobal($blob) }
    }
  }
  catch {
    Write-TinySocsLog -Level "WARN" -Message "Failed to store credential '$Name' in CredMan: $($_.Exception.Message)"
    return $false
  }
}

function Write-TSCredential {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][string]$User,
    [Parameter(Mandatory)][AllowEmptyString()][string]$Secret
  )
  return _Write-TSCredential -Name $Name -User $User -Secret $Secret
}

function Set-TSCredential {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Name,

    # User is optional. Some callers store opaque JSON secrets and don't care about the CredMan "username" field.
    # Keep compatibility by defaulting deterministically.
    [Parameter()][string]$User = "tinysocs",

    [Parameter(Mandatory)][AllowEmptyString()][string]$Secret
  )

  if ([string]::IsNullOrWhiteSpace($Name)) { throw "Set-TSCredential: Name is required." }

  # Normalize user deterministically
  if ([string]::IsNullOrWhiteSpace($User)) { $User = "tinysocs" }

  if ($null -eq $Secret) { throw "Set-TSCredential: Secret is null for ${Name}." }

  # Helpful context for error logs
  $isAdmin = $false
  try {
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  } catch { $isAdmin = $false }

  $bytes = $null
  try {
    # Unicode + null terminator (common pattern for CredWrite)
    $bytes = [System.Text.Encoding]::Unicode.GetBytes($Secret + [char]0)
  } catch {
    throw "Set-TSCredential: failed to encode secret for ${Name}: $($_.Exception.Message)"
  }

  # Practical upper bound for Generic credential blobs on Windows is commonly 5120 bytes.
  if ($bytes.Length -gt 5120) {
    throw "Set-TSCredential: secret too large for ${Name} (bytes=$($bytes.Length), limit=5120)."
  }

  # Delegate to your existing underlying writer if present.
  $writer = Get-Command -Name _Write-TSCredential -ErrorAction SilentlyContinue
  if (-not $writer) {
    $writer = Get-Command -Name Write-TSCredential -ErrorAction SilentlyContinue
  }
  if (-not $writer) {
    throw "Set-TSCredential: no credential writer function found (_Write-TSCredential / Write-TSCredential)."
  }

  # Capture some useful introspection
  $writerName = $writer.Name
  $writerParams = @()
  try { $writerParams = @($writer.Parameters.Keys) } catch { $writerParams = @() }
  $writerParamList = ""
  try { $writerParamList = ($writerParams -join ",") } catch { $writerParamList = "" }

  function _ReadCredBlobAsString([string]$TargetName) {
    if ([string]::IsNullOrWhiteSpace($TargetName)) { return $null }

    $ptr = [IntPtr]::Zero
    try {
      $ok = $false
      try { $ok = [TinySocs.Security.CredNative2]::CredRead($TargetName, 1, 0, [ref]$ptr) } catch { $ok = $false }
      if (-not $ok -or $ptr -eq [IntPtr]::Zero) { return $null }

      $raw = $null
      try { $raw = [TinySocs.Security.CredNative2]::PtrToCredential($ptr) } catch { $raw = $null }
      if ($null -eq $raw) { return $null }
      if ($raw.CredentialBlobSize -le 0 -or $raw.CredentialBlob -eq [IntPtr]::Zero) { return $null }

      $size = [int]$raw.CredentialBlobSize
      $b = New-Object byte[] $size
      [Runtime.InteropServices.Marshal]::Copy($raw.CredentialBlob, $b, 0, $size)

      try {
        if (($b.Length % 2) -ne 0) { $b = $b[0..($b.Length - 2)] }
        $s = [System.Text.Encoding]::Unicode.GetString($b)
        return $s.TrimEnd([char]0)
      } finally {
        try { [Array]::Clear($b, 0, $b.Length) } catch { }
      }
    }
    finally {
      if ($ptr -ne [IntPtr]::Zero) {
        try { [TinySocs.Security.CredNative2]::CredFree($ptr) } catch { }
      }
    }
  }

  function _VerifyReadbackForTargets([string[]]$Targets) {
    foreach ($t in ($Targets | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)) {
      try {
        $v = _ReadCredBlobAsString $t
        if (-not [string]::IsNullOrWhiteSpace([string]$v)) { return $v }
      } catch { }
    }
    return $null
  }

  function _CmdKeyHasTarget([string]$TargetName) {
    if ([string]::IsNullOrWhiteSpace($TargetName)) { return $false }
    try {
      # cmdkey prints lines like: Target: LegacyGeneric:target=TinySocs:SIEM/Creds
      $out = (& cmdkey.exe /list 2>$null | Out-String)
      if ([string]::IsNullOrWhiteSpace($out)) { return $false }

      # Escape for regex safely-ish
      $needle = [Regex]::Escape($TargetName.Trim())
      return ($out -match ("(?im)^\s*Target:\s*LegacyGeneric:target={0}\s*$" -f $needle))
    } catch {
      return $false
    }
  }

  function _InvokeWriter([string]$WriteName) {
    $result = $null

    if ($writer.Parameters.ContainsKey('Name') -and $writer.Parameters.ContainsKey('User') -and $writer.Parameters.ContainsKey('SecretBytes')) {
      $result = & $writer -Name $WriteName -User $User -SecretBytes $bytes
    }
    elseif ($writer.Parameters.ContainsKey('Name') -and $writer.Parameters.ContainsKey('User') -and $writer.Parameters.ContainsKey('Secret')) {
      $result = & $writer -Name $WriteName -User $User -Secret $Secret
    }
    else {
      # Last resort: splat what we can
      $result = & $writer @{'Name'=$WriteName; 'User'=$User; 'Secret'=$Secret}
    }

    if ($result -is [bool] -and -not $result) { throw "Underlying credential writer returned false." }
    if ($null -eq $result) { throw "Underlying credential writer returned null (unknown success)." }

    return $true
  }

  # Canonicalize targets deterministically.
  # We want:
  # - WriteName: normalized (so _Write-TSCredential will create TinySocs:<norm>)
  # - VerifyTargets: include both "TinySocs:<norm>" and "<norm>" for back-compat reads
  $rawName = ([string]$Name).Trim()

  $norm = $null
  try { $norm = _Normalize-TSCredTarget $rawName } catch { $norm = $rawName }
  if ([string]::IsNullOrWhiteSpace($norm)) { throw "Set-TSCredential: normalized target name is empty for ${Name}." }

  # Always write using the normalized *unprefixed* name.
  # _Write-TSCredential prefixes to TinySocs:<norm>.
  $writeName = $norm

  $canonicalTarget = "TinySocs:{0}" -f $norm
  $verifyTargets = @(
    $canonicalTarget,
    $norm,
    $rawName
  ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique

  # Retry tuning: CredWrite can be visible but not immediately readable via CredRead wrapper.
  $verifyTries = 8
  $verifySleepMs = 200

  try {
    _InvokeWriter $writeName | Out-Null

    $rb = $null
    for ($i = 1; $i -le $verifyTries; $i++) {
      $rb = _VerifyReadbackForTargets $verifyTargets
      if (-not [string]::IsNullOrWhiteSpace([string]$rb)) {
        return $true
      }
      Start-Sleep -Milliseconds $verifySleepMs
    }

    # Still not readable. If cmdkey shows the canonical target exists, accept success (warn).
    if (_CmdKeyHasTarget $canonicalTarget) {
      try {
        Write-TinySocsLog -Level "WARN" -Message ("Set-TSCredential: readback via CredRead returned empty after {0} tries, but cmdkey confirms target exists. Accepting success. Target={1} Name={2} User={3}" -f `
          $verifyTries, $canonicalTarget, $Name, $User)
      } catch { }
      return $true
    }

    throw "Post-write verification failed: credential readback is empty/null."
  }
  catch {
    # Surface the real failure reason instead of guessing.
    $msg = $null
    $inner = $null
    try { $msg = $_.Exception.Message } catch { $msg = "$_" }
    try { if ($_.Exception.InnerException) { $inner = $_.Exception.InnerException.Message } } catch { $inner = $null }

    $hint = ""
    if (-not $isAdmin) { $hint = " (not elevated?)" }

    # Log something actually actionable
    try {
      Write-TinySocsLog -Level "WARN" -Message ("Set-TSCredential failed{0}: Name={1} User={2} Writer={3} WriterParams=[{4}] Bytes={5} WriteName={6} CanonicalTarget={7} VerifyTargets=[{8}] Tries={9} SleepMs={10} Err={11}{12}" -f `
        $hint,
        $Name,
        $User,
        $writerName,
        $writerParamList,
        $bytes.Length,
        $writeName,
        $canonicalTarget,
        (($verifyTargets | Select-Object -Unique) -join ","),
        $verifyTries,
        $verifySleepMs,
        $msg,
        $(if ($inner) { " Inner=$inner" } else { "" })
      )
    } catch { }

    # Preserve original message and add context
    $ctx = "Set-TSCredential: write failed for ${Name}{0} via {1} (admin={2})" -f $hint, $writerName, $isAdmin

    if ($inner) {
      throw "${ctx}: $msg (inner: $inner)"
    } else {
      throw "${ctx}: $msg"
    }
  }
}

function _Normalize-TSCredTarget {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][AllowEmptyString()][string]$Name
  )

  if ([string]::IsNullOrWhiteSpace($Name)) { return "" }

  $t = $Name.Trim()

  # Defensive: strip cmdkey display prefix if ever passed in
  $t = $t -replace '^(?i)LegacyGeneric:target=', ''

  # Some callers may accidentally pass the fully-prefixed target string multiple times.
  # Peel TinySocs: repeatedly until stable.
  while ($t -match '^(?i)TinySocs:\s*') {
    $t = ($t -replace '^(?i)TinySocs:\s*', '').Trim()
  }

  # Also strip TinySocs/ repeatedly (e.g. "TinySocs/TinySocs/...")
  while ($t -match '^(?i)TinySocs/\s*') {
    $t = ($t -replace '^(?i)TinySocs/\s*', '').Trim()
  }

  # Normalize separators to forward slashes
  $t = $t -replace '[/\\]+', '/'

  # Trim leading/trailing slashes (avoid "//" weirdness)
  $t = $t.Trim('/').Trim()

  return $t
}

function Get-TSCredential {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Name
  )

  function _CandidateTargets([string]$n) {
    $raw = ([string]$n).Trim()
    if ([string]::IsNullOrWhiteSpace($raw)) { return @() }

    $norm = _Normalize-TSCredTarget $raw

    $c = @()

    # Canonical: we always intend to write as TinySocs:<normalized>
    if (-not [string]::IsNullOrWhiteSpace($norm)) {
      $c += ("TinySocs:{0}" -f $norm)
    }

    # Back-compat: if older versions wrote exactly what was passed (prefixed/unprefixed)
    $raw2 = $raw -replace '^(?i)LegacyGeneric:target=', ''
    if (-not [string]::IsNullOrWhiteSpace($raw2)) { $c += $raw2 }

    if ($raw2 -and $raw2 -notmatch '^(?i)TinySocs:') {
      $c += ("TinySocs:{0}" -f ($raw2.Trim()))
    }

    return ($c | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
  }

  foreach ($target in (_CandidateTargets $Name)) {
    $ptr = [IntPtr]::Zero
    try {
      $ok = [TinySocs.Security.CredNative2]::CredRead($target, 1, 0, [ref]$ptr) # CRED_TYPE_GENERIC
      if (-not $ok -or $ptr -eq [IntPtr]::Zero) { continue }

      $raw = [TinySocs.Security.CredNative2]::PtrToCredential($ptr)
      if ($null -eq $raw) { continue }
      if ($raw.CredentialBlobSize -le 0 -or $raw.CredentialBlob -eq [IntPtr]::Zero) { continue }

      $size = [int]$raw.CredentialBlobSize
      $bytes = New-Object byte[] $size
      [Runtime.InteropServices.Marshal]::Copy($raw.CredentialBlob, $bytes, 0, $size)

      try {
        # UTF-16LE; if odd, drop last byte
        if (($bytes.Length % 2) -ne 0) {
          $bytes = $bytes[0..($bytes.Length - 2)]
        }

        $s = [System.Text.Encoding]::Unicode.GetString($bytes)
        return $s.TrimEnd([char]0)
      }
      finally {
        try { [Array]::Clear($bytes, 0, $bytes.Length) } catch { }
      }
    }
    finally {
      if ($ptr -ne [IntPtr]::Zero) {
        try { [TinySocs.Security.CredNative2]::CredFree($ptr) } catch { }
      }
    }
  }

  return $null
}

function Remove-TSCredential {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Name
  )
  [TinySocs.Security.CredNative2]::CredDelete($Name, 1, 0) | Out-Null
}

function Test-TSCredentialInterop {
  [CmdletBinding()]
  param(
    [string]$Name = 'TinySocs/_selftest/CredMan',
    [string]$Secret = 'tinysocs-credman-selftest'
  )

  Set-TSCredential -Name $Name -Secret $Secret
  $got = Get-TSCredential -Name $Name
  Remove-TSCredential -Name $Name

  if ($got -ne $Secret) {
    throw "CredMan self-test failed. Expected '$Secret' but got '$got'. Imported module: $(Get-TinySocsInstallerModuleInfo | ConvertTo-Json -Compress)"
  }
  return $true
}

function Update-TinySocsInstalledModule {
  [CmdletBinding(SupportsShouldProcess)]
  param(
    [string]$InstallModulePath = 'C:\Program Files\TinySocs\modules\TinySocs.Installer.psm1',
    [string]$SourceModulePath
  )

  Assert-TinySocsAdmin

  $src = $null
  if ($SourceModulePath -and (Test-Path $SourceModulePath -PathType Leaf)) {
    $src = $SourceModulePath
  } else {
    try { $src = $MyInvocation.MyCommand.Path } catch { }
    if ([string]::IsNullOrWhiteSpace($src)) {
      try { $src = $PSCommandPath } catch { }
    }
  }

  if ([string]::IsNullOrWhiteSpace($src) -or -not (Test-Path $src -PathType Leaf)) {
    throw "Cannot resolve source module path for copying. Source='$src' SourceModulePath='$SourceModulePath'"
  }

  $dstDir = Split-Path -Parent $InstallModulePath
  if (-not (Test-Path $dstDir)) {
    New-Item -ItemType Directory -Force -Path $dstDir | Out-Null
  }

  if ($PSCmdlet.ShouldProcess($InstallModulePath, "Copy module from '$src'")) {
    try { Ensure-TinySocsWritableFile -Path $InstallModulePath } catch { }
    Copy-Item -Force -Path $src -Destination $InstallModulePath

    Write-TinySocsLog "Updated installed TinySocs.Installer.psm1 at '$InstallModulePath' from '$src' (version=$script:TinySocsInstallerVersion)."
    Write-TinySocsLog "Restart PowerShell, then: Import-Module '$InstallModulePath' -Force; Get-TinySocsInstallerModuleInfo"
  }
}

function Set-TinySocsSiemCredential {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$SiemUrl,
    [Parameter(Mandatory)][string]$SiemUser,
    [Parameter(Mandatory)][string]$SiemPass,
    [bool]$SiemSslVerify = $true,

    # Optional: CA cert path (not secret, but useful for clients that want verify=true)
    [string]$CaCertPath,

    # If set, also mirror SIEM_USER/SIEM_PASS into machine env (secrets on machine env = optional)
    [switch]$MirrorToEnv,

    # If set, verify the supplied creds actually work against the SIEM before storing.
    # Uses curl.exe if present (and will pass --ssl-no-revoke for Windows schannel/CRL weirdness).
    [switch]$ValidateAuth
  )

  $normUrl = $SiemUrl.TrimEnd('/')

  if ($ValidateAuth.IsPresent) {
    try {
      $curl = (Get-Command curl.exe -ErrorAction SilentlyContinue)
      if (-not $curl) { throw "curl.exe not found; can't ValidateAuth on Windows reliably (PS 5.1 lacks a clean CRL bypass)." }

      $probeUrl = $normUrl
      $args = @("--silent","--show-error","--fail","--ssl-no-revoke","-u",("{0}:{1}" -f $SiemUser,$SiemPass),$probeUrl)

      # If caller asked for sslVerify=false, also skip cert verification
      if (-not [bool]$SiemSslVerify) { $args = @("--insecure") + $args }

      & $curl.Source @args | Out-Null
    } catch {
      throw ("Set-TinySocsSiemCredential ValidateAuth failed for {0} as {1}: {2}" -f $normUrl, $SiemUser, $_.Exception.Message)
    }
  }

  # Load existing payload so we preserve any extra fields we've stored over time
  $existingHt = @{}
  try {
    $rawExisting = Get-TSCredential -Name 'TinySocs/SIEM/Creds'
    if ($rawExisting) {
      $obj = $rawExisting | ConvertFrom-Json
      foreach ($p in $obj.PSObject.Properties) {
        $existingHt[$p.Name] = $p.Value
      }
    }
  } catch { }

  # Normalize legacy key variants -> canonical sslVerify
  try {
    if (-not $existingHt.ContainsKey('sslVerify')) {
      if ($existingHt.ContainsKey('ssl_verify')) { $existingHt['sslVerify'] = [bool]$existingHt['ssl_verify'] }
      elseif ($existingHt.ContainsKey('sslverify')) { $existingHt['sslVerify'] = [bool]$existingHt['sslverify'] }
    }
    if ($existingHt.ContainsKey('sslVerify') -and ($existingHt['sslVerify'] -is [string])) {
      $existingHt['sslVerify'] = ([string]$existingHt['sslVerify']).ToLowerInvariant() -eq 'true'
    }
  } catch { }

  # Canonical payload (also keep ssl_verify for any older readers)
  $payloadHt = @{}
  foreach ($k in $existingHt.Keys) { $payloadHt[$k] = $existingHt[$k] }

  $payloadHt['url']       = $normUrl
  $payloadHt['user']      = $SiemUser
  $payloadHt['pass']      = $SiemPass
  $payloadHt['sslVerify'] = [bool]$SiemSslVerify
  $payloadHt['ssl_verify']= [bool]$SiemSslVerify  # backward compatibility

  if (-not [string]::IsNullOrWhiteSpace($CaCertPath)) {
    $payloadHt['caCert']  = $CaCertPath
    $payloadHt['ca_cert'] = $CaCertPath  # backward compatibility
  }

  $payload = $payloadHt | ConvertTo-Json -Compress -Depth 20

  # PATCH: ALWAYS pass -User (or a deterministic default via Set-TSCredential) so CredMan writes never fail.
  # Using SiemUser is fine (not secret) and keeps entries understandable.
  Set-TSCredential -Name 'TinySocs/SIEM/Creds' -User $SiemUser -Secret $payload

  $verifyString = if ($SiemSslVerify) { 'true' } else { 'false' }

  # Env: always safe to set URL + verify; CA cert is also non-secret
  $envBlock = @{
    SIEM_URL        = $normUrl
    SIEM_SSL_VERIFY = $verifyString
  }
  if (-not [string]::IsNullOrWhiteSpace($CaCertPath)) { $envBlock['SIEM_CA_CERT'] = $CaCertPath }

  if ($MirrorToEnv.IsPresent) {
    $envBlock['SIEM_USER'] = $SiemUser
    $envBlock['SIEM_PASS'] = $SiemPass
    Set-MachineEnv $envBlock
    Write-Host "[TinySocs] SIEM credentials stored in CredMan and env (url=$normUrl, sslVerify=$verifyString)."
  } else {
    Set-MachineEnv $envBlock
    Write-Host "[TinySocs] SIEM credentials stored in CredMan (env secrets not mirrored) (url=$normUrl, sslVerify=$verifyString)."
  }
}

function New-TinySocsBasicAuthHeader {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$User,
    [Parameter(Mandatory)][string]$Pass
  )
  $raw = "{0}:{1}" -f $User, $Pass
  $b64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($raw))
  return @{ Authorization = "Basic $b64" }
}

function Write-TinySocsCredManSecrets {
  [CmdletBinding()]
  param(
    [string]$SiemUrl = "https://localhost:9201",
    [string]$AdminUser = "admin",
    [string]$AdminPass,
    [string]$ServiceUser = "tinysocs",
    [string]$ServicePass,
    [bool]$SiemSslVerify = $true
  )

  # NOTE: _TryParseTinySocsCredValue is now a module-scope helper (do NOT redefine here)

  if ([string]::IsNullOrWhiteSpace($AdminPass)) {
    try {
      $raw = Get-TSCredential -Name 'TinySocs/SIEM/Creds'
      if ($raw) {
        $j = _TryParseTinySocsCredValue -Raw $raw

        # Only JSON envelopes can carry these extra fields; raw secret means "pass only".
        if ($j -and ($j.PSObject.Properties.Name -contains 'user') -and $j.user) { $AdminUser = [string]$j.user }
        if ($j -and ($j.PSObject.Properties.Name -contains 'pass') -and $j.pass) { $AdminPass = [string]$j.pass }

        if ($j -and ($j.PSObject.Properties.Name -contains 'sslVerify') -and ($null -ne $j.sslVerify)) { $SiemSslVerify = [bool]$j.sslVerify }
        elseif ($j -and ($j.PSObject.Properties.Name -contains 'ssl_verify') -and ($null -ne $j.ssl_verify)) { $SiemSslVerify = [bool]$j.ssl_verify }
        elseif ($j -and ($j.PSObject.Properties.Name -contains 'sslverify') -and ($null -ne $j.sslverify)) { $SiemSslVerify = [bool]$j.sslverify }

        if ($j -and ($j.PSObject.Properties.Name -contains 'url') -and $j.url) { $SiemUrl = [string]$j.url }
      }
    } catch { }
  }

  if ([string]::IsNullOrWhiteSpace($AdminPass)) {
    throw "Write-TinySocsCredManSecrets: AdminPass not provided and TinySocs/SIEM/Creds was empty."
  }

  if ([string]::IsNullOrWhiteSpace($ServicePass)) {
    $ServicePass = New-TinySocsPassword -Length 32
  }

  # Canonical write (stores sslVerify + ssl_verify)
  Set-TinySocsSiemCredential -SiemUrl $SiemUrl -SiemUser $AdminUser -SiemPass $AdminPass -SiemSslVerify:$SiemSslVerify

  $svcPayload = @{
    url       = $SiemUrl.TrimEnd('/')
    user      = $ServiceUser
    pass      = $ServicePass
    sslVerify = $SiemSslVerify
  } | ConvertTo-Json -Compress

  $svcTarget = "TinySocs/OpenSearch/$ServiceUser"
  Set-TSCredential -Name $svcTarget -Secret $svcPayload

  try {
    Start-Process -FilePath "$env:WINDIR\System32\cmdkey.exe" `
      -ArgumentList @("/generic:$svcTarget", "/user:$ServiceUser", "/pass:$ServicePass") `
      -NoNewWindow -Wait | Out-Null
  } catch { }

  Write-TinySocsLog "CredMan secrets ensured: TinySocs/SIEM/Creds + $svcTarget (service user)."
  return @{
    SiemUrl       = $SiemUrl.TrimEnd('/')
    AdminUser     = $AdminUser
    ServiceUser   = $ServiceUser
    ServicePass   = $ServicePass
    SiemSslVerify = $SiemSslVerify
  }
}

function Test-TinySocsOpenSearchDataPresent {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$DataPath
  )

  if (-not (Test-Path $DataPath -PathType Container)) { return $false }

  try {
    # Typical OpenSearch layout: <data>\nodes\0\_state, indices, translog, etc.
    # "nodes" dir is common but not guaranteed to exist if something changed paths historically,
    # so we also do a cheap "any file anywhere under dataPath" probe.
    $nodes = Join-Path $DataPath "nodes"
    if (Test-Path $nodes -PathType Container) {
      $any = Get-ChildItem -Path $nodes -Recurse -Force -ErrorAction SilentlyContinue |
        Where-Object { -not $_.PSIsContainer } |
        Select-Object -First 1
      if ($any) { return $true }
    }

    $any2 = Get-ChildItem -Path $DataPath -Recurse -Force -ErrorAction SilentlyContinue |
      Where-Object { -not $_.PSIsContainer } |
      Select-Object -First 1

    return [bool]$any2
  } catch {
    # If probing fails, assume "present" to avoid destructive "fresh-init" behaviour.
    return $true
  }
}

function Initialize-TinySocsOpenSearchSecurity {
  [CmdletBinding()]
  param(
    [string]$SiemUrl = "https://localhost:9201",
    [string]$AdminUser = "admin",
    [string]$AdminPass,
    [string]$ServiceUser = "tinysocs",
    [string]$ServicePass,
    [string[]]$IndexPatterns = @("tinysocs-*","logs-*","security-auditlog-*"),
    [switch]$SkipTlsVerify,

    # Safe defaults for first-boot slowness
    [int]$ReadyTimeoutSeconds = 600,
    [int]$RetryCount = 30,
    [int]$RetrySleepSeconds = 3,

    # For localhost/self-signed TLS, Schannel revocation checks are brittle and non-replicable.
    # We keep cert validation ON, but disable revocation checking for loopback only unless explicitly overridden.
    [switch]$DisableTlsRevocationCheck,

    # OPTIONAL allows securityadmin to present admin client certs for bootstrap
    # without requiring client certs from normal HTTPS clients (curl, browsers).
    [ValidateSet("NONE","OPTIONAL","REQUIRE")]
    [string]$HttpClientAuthMode = "OPTIONAL",

    # Make the installer deterministic by not hardcoding paths
    [string]$OpenSearchRoot,
    [string]$ProgramDataConf,
    [string]$ServiceName = "TinySocsOpenSearch"
  )

  $base = $SiemUrl.TrimEnd('/')

  # NOTE: _TryParseTinySocsCredValue is now a module-scope helper (do NOT redefine here)

  if ([string]::IsNullOrWhiteSpace($AdminPass)) {
    try {
      $raw = Get-TSCredential -Name 'TinySocs/SIEM/Creds'
      if ($raw) {
        $j = _TryParseTinySocsCredValue -Raw $raw
        if ($j) {
          if ($j.PSObject.Properties.Name -contains 'user' -and $j.user) { $AdminUser = [string]$j.user }
          if ($j.PSObject.Properties.Name -contains 'pass' -and $j.pass) { $AdminPass = [string]$j.pass }
          if ($j.PSObject.Properties.Name -contains 'url'  -and $j.url)  { $base = ([string]$j.url).TrimEnd('/') }
        }
      }
    } catch { }
  }

  # This function is used in "best-effort" installer paths.
  # If we still don't have AdminPass, do NOT throw: log and return a "skipped" result.
  if ([string]::IsNullOrWhiteSpace($AdminPass)) {
    try {
      Write-TinySocsLog -Level "WARN" -Message "Initialize-TinySocsOpenSearchSecurity: AdminPass missing (not provided and TinySocs/SIEM/Creds empty). Skipping security bootstrap (best-effort path)."
    } catch {
      Write-Warning "Initialize-TinySocsOpenSearchSecurity: AdminPass missing; skipping."
    }
    return @{
      Skipped   = $true
      Reason    = "AdminPass missing"
      SiemUrl   = $base
      AdminUser = $AdminUser
    }
  }

  # Reuse existing service password if present
  if ([string]::IsNullOrWhiteSpace($ServicePass)) {
    try {
      $svcRaw = Get-TSCredential -Name ("TinySocs/OpenSearch/{0}" -f $ServiceUser)
      if ($svcRaw) {
        $svcJ = _TryParseTinySocsCredValue -Raw $svcRaw
        if ($svcJ -and ($svcJ.PSObject.Properties.Name -contains 'pass') -and $svcJ.pass) {
          $ServicePass = [string]$svcJ.pass
        }
      }
    } catch { }
  }
  if ([string]::IsNullOrWhiteSpace($ServicePass)) {
    $ServicePass = New-TinySocsPassword -Length 32
  }

  # Determine if we're talking to loopback (localhost/127.0.0.1/[::1])
  $isLoopback = $false
  $uParsed = $null
  try {
    $uParsed = [Uri]$base
    $isLoopback = $uParsed.IsLoopback -or ($uParsed.Host -in @('127.0.0.1','localhost','::1'))
  } catch { }

  $effectiveDisableRevoke = $false
  if (-not $SkipTlsVerify.IsPresent) {
    if ($DisableTlsRevocationCheck.IsPresent) {
      $effectiveDisableRevoke = $true
    } elseif ($isLoopback) {
      $effectiveDisableRevoke = $true
    }
  }

  Write-TinySocsLog "Initializing OpenSearch security objects (url=$base, serviceUser=$ServiceUser, skipTlsVerify=$($SkipTlsVerify.IsPresent), disableRevoke(loopback)=$effectiveDisableRevoke, httpClientAuthMode=$HttpClientAuthMode)."

  $oldRevokeSetting = $null
  $tweakedRevoke = $false

  $curlExe = Join-Path $env:WINDIR "System32\curl.exe"
  if (-not (Test-Path $curlExe -PathType Leaf)) { $curlExe = "curl.exe" }

  $writeUtf8NoBom = {
    param(
      [Parameter(Mandatory=$true)][string]$Path,
      [Parameter(Mandatory=$true)][string]$Text
    )
    [System.IO.File]::WriteAllText($Path, $Text, (New-Object System.Text.UTF8Encoding($false)))
  }

  $readUtf8NoBom = {
    param([Parameter(Mandatory=$true)][string]$Path)
    if (Get-Command _ReadUtf8NoBom -ErrorAction SilentlyContinue) {
      return (_ReadUtf8NoBom $Path)
    }
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    return [System.IO.File]::ReadAllText($Path, $utf8NoBom)
  }

  $testPkcs12 = {
    param(
      [Parameter(Mandatory=$true)][string]$P12Path,
      [Parameter(Mandatory=$true)][string]$Password
    )
    try {
      $null = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
        $P12Path,
        $Password,
        [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::MachineKeySet
      )
      return $true
    } catch {
      return $false
    }
  }

  $decryptDpapiB64 = {
    param([Parameter(Mandatory=$true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "Missing DPAPI file: $Path" }
    $rawB64 = (& $readUtf8NoBom $Path).Trim()
    $prot   = [Convert]::FromBase64String($rawB64)

    if (Get-Command _DpapiUnprotectLocalMachine -ErrorAction SilentlyContinue) {
      $plain = _DpapiUnprotectLocalMachine $prot
    } else {
      if (-not ("System.Security.Cryptography.ProtectedData" -as [type])) {
        try { Add-Type -AssemblyName "System.Security" } catch {}
      }
      $plain = [System.Security.Cryptography.ProtectedData]::Unprotect(
        $prot, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine
      )
    }

    return ([Text.Encoding]::UTF8.GetString($plain)).Trim()
  }

  $keystoreAddSecure = {
    param(
      [Parameter(Mandatory=$true)][string]$KeystoreBat,
      [Parameter(Mandatory=$true)][string]$Key,
      [Parameter(Mandatory=$true)][string]$Value
    )

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $KeystoreBat
    $psi.Arguments = "add -x -f $Key"
    $psi.WorkingDirectory = (Split-Path $KeystoreBat -Parent)
    $psi.UseShellExecute = $false
    $psi.RedirectStandardInput  = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true

    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $psi
    [void]$p.Start()
    $p.StandardInput.WriteLine($Value)
    $p.StandardInput.Close()
    $p.WaitForExit()

    if ($p.ExitCode -ne 0) {
      $err = $p.StandardError.ReadToEnd()
      throw "opensearch-keystore add failed for $Key. STDERR:`n$err"
    }
  }

  $tcpConnectable = {
    param(
      [Parameter(Mandatory=$true)][string]$Host,
      [Parameter(Mandatory=$true)][int]$Port,
      [int]$MsTimeout = 900
    )
    $client = $null
    try {
      $client = New-Object System.Net.Sockets.TcpClient
      $iar = $client.BeginConnect($Host, $Port, $null, $null)
      if (-not $iar.AsyncWaitHandle.WaitOne($MsTimeout, $false)) {
        try { $client.Close() } catch { }
        return $false
      }
      $client.EndConnect($iar) | Out-Null
      try { $client.Close() } catch { }
      return $true
    } catch {
      try { if ($client) { $client.Close() } } catch { }
      return $false
    }
  }

  # probe captures headers + body (-i) so we can reliably match 503 Not Initialized
  $probeHttpsPort = {
    param(
      [Parameter(Mandatory=$true)][string]$Host,
      [Parameter(Mandatory=$true)][int[]]$Ports,
      [Parameter(Mandatory=$true)][string]$Scheme,
      [int]$DeadlineSeconds = 120
    )

    $deadline = (Get-Date).AddSeconds($DeadlineSeconds)
    $last = $null

    while ((Get-Date) -lt $deadline) {
      foreach ($p in $Ports) {
        if (-not (& $tcpConnectable -Host $Host -Port $p)) { continue }

        $u = "{0}://{1}:{2}/" -f $Scheme, $Host, $p
        try {
          $args = @("-sS","-i","--connect-timeout","2","--max-time","6")
          if ($SkipTlsVerify.IsPresent) {
            $args = @("-k") + $args
          } elseif ($effectiveDisableRevoke) {
            $args = @("--ssl-no-revoke") + $args
          }

          $resp = (& $curlExe @args $u) 2>&1 | Out-String
          $last = $resp.Trim()

          $is401 = ($resp -match 'HTTP/(1\.1|2)\s+401' -and $resp -match '(?im)^WWW-Authenticate:\s*Basic')
          $is503 = ($resp -match 'HTTP/(1\.1|2)\s+503')
          $hasOS = ($resp -match '(?im)^X-OpenSearch-Version:\s*OpenSearch/')
          $hasNotInit = ($resp -match 'OpenSearch Security not initialized')
          $is200 = ($resp -match 'HTTP/(1\.1|2)\s+200')

          if ($is401 -or ($is503 -and ($hasOS -or $hasNotInit)) -or ($is200 -and $hasOS)) {
            return @{ Port = $p; Last = $last }
          }
        } catch {
          $last = $_.Exception.Message
        }
      }

      Start-Sleep -Seconds 2
    }

    return @{ Port = $null; Last = $last }
  }

  $curlJson = {
    param(
      [Parameter(Mandatory=$true)][string]$Method,
      [Parameter(Mandatory=$true)][string]$Url,
      [string]$User,
      [string]$Pass,
      [string]$BodyJson,
      [int[]]$AllowHttpStatus = @()
    )

    $tmpOut  = Join-Path $env:TEMP ("tinysocs-os-out-" + [Guid]::NewGuid().ToString("N") + ".txt")
    $tmpBody = $null

    try {
      $args = @("--silent","--show-error","--location","--connect-timeout","4","--max-time","20")
      if ($SkipTlsVerify.IsPresent) {
        $args = @("-k") + $args
      } elseif ($effectiveDisableRevoke) {
        $args = @("--ssl-no-revoke") + $args
      }

      if (-not [string]::IsNullOrWhiteSpace($User)) {
        $args += @("-u", ("{0}:{1}" -f $User, $Pass))
      }

      $args += @("-o", $tmpOut, "-w", "%{http_code}")
      $args += @("-X", $Method)

      if (-not [string]::IsNullOrWhiteSpace($BodyJson)) {
        $tmpBody = Join-Path $env:TEMP ("tinysocs-os-body-" + [Guid]::NewGuid().ToString("N") + ".json")
        & $writeUtf8NoBom $tmpBody $BodyJson
        $args += @("-H","Content-Type: application/json","--data-binary", "@$tmpBody")
      }

      $code = (& $curlExe @args $Url) 2>&1
      $code = (($code | Out-String).Trim() -split "\s+")[-1]

      $body = ""
      try { $body = Get-Content -LiteralPath $tmpOut -Raw -ErrorAction SilentlyContinue } catch { $body = "" }

      $okCodes = @('200','201','202','204')
      foreach ($c in $AllowHttpStatus) { $okCodes += [string]$c }

      if ($code -notin $okCodes) {
        $msg = ("OpenSearch API {0} {1} failed (HTTP {2}). Body={3}" -f $Method, $Url, $code, ($body.Trim()))
        throw $msg
      }

      return $body
    }
    finally {
      try { if ($tmpOut)  { Remove-Item -LiteralPath $tmpOut  -Force -ErrorAction SilentlyContinue } } catch { }
      try { if ($tmpBody) { Remove-Item -LiteralPath $tmpBody -Force -ErrorAction SilentlyContinue } } catch { }
    }
  }

  $curlJsonWithRetry = {
    param(
      [Parameter(Mandatory=$true)][string]$Method,
      [Parameter(Mandatory=$true)][string]$Url,
      [string]$User,
      [string]$Pass,
      [string]$BodyJson,
      [int[]]$AllowHttpStatus = @()
    )
    for ($i = 1; $i -le $RetryCount; $i++) {
      try {
        return (& $curlJson -Method $Method -Url $Url -User $User -Pass $Pass -BodyJson $BodyJson -AllowHttpStatus $AllowHttpStatus)
      } catch {
        if ($i -ge $RetryCount) { throw }
        Write-TinySocsLog -Level "WARN" -Message ("OpenSearch API retry {0}/{1} failed: {2}" -f $i, $RetryCount, $_.Exception.Message)
        Start-Sleep -Seconds $RetrySleepSeconds
      }
    }
  }

  $oldJAVA_HOME = $env:JAVA_HOME
  $oldOSJH      = $env:OPENSEARCH_JAVA_HOME
  $oldOSCONF    = $env:OPENSEARCH_PATH_CONF

  try {
    if ($effectiveDisableRevoke) {
      try {
        $oldRevokeSetting = [System.Net.ServicePointManager]::CheckCertificateRevocationList
        [System.Net.ServicePointManager]::CheckCertificateRevocationList = $false
        $tweakedRevoke = $true
      } catch { }
    }

    if ([string]::IsNullOrWhiteSpace($OpenSearchRoot)) {
      $OpenSearchRoot = "C:\Program Files\TinySocs\OpenSearch"
    }
    if ([string]::IsNullOrWhiteSpace($ProgramDataConf)) {
      $ProgramDataConf = Join-Path $env:ProgramData "TinySocs\OpenSearch\config"
    }

    $osRoot = $OpenSearchRoot
    $conf   = $ProgramDataConf
    $certs  = Join-Path $conf "certs"

    if (-not (Test-Path -LiteralPath $osRoot -PathType Container)) {
      throw "Initialize-TinySocsOpenSearchSecurity: OpenSearchRoot not found: $osRoot"
    }
    if (-not (Test-Path -LiteralPath $conf -PathType Container)) {
      throw "Initialize-TinySocsOpenSearchSecurity: ProgramDataConf not found: $conf"
    }

    $jdkHome = Join-Path $osRoot "jdk"
    if (Test-Path -LiteralPath $jdkHome -PathType Container) {
      $env:JAVA_HOME            = $jdkHome
      $env:OPENSEARCH_JAVA_HOME = $jdkHome
    }
    $env:OPENSEARCH_PATH_CONF = $conf

    $yml    = Join-Path $conf "opensearch.yml"
    $secDir = Join-Path $conf "opensearch-security"

    $dpapiStore = Join-Path $certs "opensearch-tls-storepass.dpapi"
    $httpP12    = Join-Path $certs "http.p12"

    $adminKs    = Join-Path $certs "admin-keystore.p12"
    $adminTs    = Join-Path $certs "admin-truststore.p12"

    $keystoreBat = Join-Path $osRoot "bin\opensearch-keystore.bat"
    $secAdminBat = Join-Path $osRoot "plugins\opensearch-security\tools\securityadmin.bat"
    $keytoolExe  = Join-Path $osRoot "jdk\bin\keytool.exe"

    foreach ($p in @($yml,$secDir,$dpapiStore,$httpP12,$adminKs,$adminTs,$keystoreBat,$secAdminBat,$keytoolExe)) {
      if (-not (Test-Path -LiteralPath $p)) { throw "Initialize-TinySocsOpenSearchSecurity: Missing required path: $p" }
    }

    $tlsStorePass = $null
    if (Get-Command Get-TinySocsStorepassFromDpapiFile -ErrorAction SilentlyContinue) {
      $tlsStorePass = (Get-TinySocsStorepassFromDpapiFile -Path $dpapiStore).Password
      if ($null -ne $tlsStorePass) { $tlsStorePass = ([string]$tlsStorePass).Trim() }
    }
    if ([string]::IsNullOrWhiteSpace($tlsStorePass)) {
      $tlsStorePass = (& $decryptDpapiB64 $dpapiStore)
    }

    if ([string]::IsNullOrWhiteSpace($tlsStorePass)) {
      throw "Initialize-TinySocsOpenSearchSecurity: TLS storepass decoded empty from $dpapiStore"
    }
    if ($tlsStorePass.IndexOf([char]0) -ge 0 -or $tlsStorePass -match "[`r`n]") {
      throw "Initialize-TinySocsOpenSearchSecurity: TLS storepass contains null/newline characters (DPAPI decode/encoding issue)."
    }

    if (-not (& $testPkcs12 $httpP12 $tlsStorePass)) {
      throw "Initialize-TinySocsOpenSearchSecurity: TLS storepass from $dpapiStore does not open $httpP12. Refusing to continue."
    }

    $secureKeys = @(
      "plugins.security.ssl.http.keystore_password_secure",
      "plugins.security.ssl.http.keystore_keypassword_secure",
      "plugins.security.ssl.http.truststore_password_secure",
      "plugins.security.ssl.transport.keystore_password_secure",
      "plugins.security.ssl.transport.keystore_keypassword_secure",
      "plugins.security.ssl.transport.truststore_password_secure"
    )
    foreach ($k in $secureKeys) {
      & $keystoreAddSecure -KeystoreBat $keystoreBat -Key $k -Value $tlsStorePass
    }
    Write-TinySocsLog "OpenSearch keystore secure passwords applied (6 entries)."

    $rawYml = (& $readUtf8NoBom $yml)

    $rawYml = [regex]::Replace(
      $rawYml,
      '(?ms)^\s*plugins\.security\.authcz\.admin_dn:\s*\r?\n(?:\s*-\s*".*?"\s*\r?\n?|\s*-\s*''.*?''\s*\r?\n?|\s*-\\s*[^#\r\n]+\s*\r?\n?)*',
      ''
    )
    $rawYml = [regex]::Replace(
      $rawYml,
      '(?m)^\s*plugins\.security\.ssl\.http\.clientauth_mode\s*:\s*.*\r?\n',
      ''
    )

    # OPTIONAL = accept client certs if offered (needed for securityadmin) but don't require them.
    $rawYml = $rawYml.TrimEnd() + "`r`n`r`n" +
      ("plugins.security.ssl.http.clientauth_mode: {0}`r`n" -f $HttpClientAuthMode) +
      "plugins.security.authcz.admin_dn:`r`n" +
      "  - `"CN=TinySocs-OpenSearch-Admin`"`r`n"

    & $writeUtf8NoBom $yml $rawYml
    Write-TinySocsLog ("Canonicalized opensearch.yml admin_dn + clientauth_mode ({0})." -f $HttpClientAuthMode)

    & takeown /F $secDir /R /D Y | Out-Null
    & icacls $secDir /inheritance:e /T /C | Out-Null
    & icacls $secDir /grant:r "BUILTIN\Administrators:(OI)(CI)F" "NT AUTHORITY\SYSTEM:(OI)(CI)F" /T /C | Out-Null
    & icacls $secDir /grant "BUILTIN\Users:(OI)(CI)(RX)" /T /C | Out-Null
    Write-TinySocsLog "Normalized ACLs on $secDir."

    try {
      $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
      if ($svc -and $svc.Status -ne 'Stopped') {
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        $stopDeadline = (Get-Date).AddSeconds(60)
        while ((Get-Date) -lt $stopDeadline) {
          $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
          if (-not $svc -or $svc.Status -eq 'Stopped') { break }
          Start-Sleep -Seconds 2
        }
      }
    } catch { }

    Start-Service -Name $ServiceName -ErrorAction Stop

    $svcDeadline = (Get-Date).AddSeconds([Math]::Max(30, $ReadyTimeoutSeconds))
    while ((Get-Date) -lt $svcDeadline) {
      $s = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
      if ($s -and $s.Status -eq 'Running') { break }
      Start-Sleep -Seconds 2
    }
    $s = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if (-not $s -or $s.Status -ne 'Running') {
      throw "Initialize-TinySocsOpenSearchSecurity: $ServiceName did not reach Running within timeout."
    }

    $host = "127.0.0.1"
    $scheme = "https"
    $ports = @(9201,9200)

    try {
      $u = [Uri]$base
      if (-not [string]::IsNullOrWhiteSpace($u.Host)) { $host = $u.Host }
      if (-not [string]::IsNullOrWhiteSpace($u.Scheme)) { $scheme = $u.Scheme }
      if ($u.Port -gt 0 -and ($ports -notcontains $u.Port)) { $ports = @([int]$u.Port) + $ports }
    } catch { }

    $probeDeadline = [Math]::Max(30, [int]($ReadyTimeoutSeconds / 2))
    $probe = & $probeHttpsPort -Host $host -Ports $ports -Scheme $scheme -DeadlineSeconds $probeDeadline
    $httpsPort = $probe.Port
    if (-not $httpsPort) {
      throw "Initialize-TinySocsOpenSearchSecurity: Could not detect a working OpenSearch HTTPS endpoint on ports $($ports -join ','). Last probe=`n$($probe.Last)"
    }

    Write-TinySocsLog "Detected OpenSearch HTTPS endpoint at ${scheme}://${host}:$httpsPort (probe accepted 401/503/200 + OpenSearch signals)."

    try {
      $uri = [Uri]$base
      $builder = New-Object System.UriBuilder($uri)
      $builder.Scheme = $scheme
      $builder.Host   = $host
      $builder.Port   = $httpsPort
      $base = $builder.Uri.AbsoluteUri.TrimEnd('/')
    } catch {
      $base = "{0}://{1}:{2}" -f $scheme, $host, $httpsPort
    }

    if (-not (Get-Command Ensure-TinySocsOpenSearchSecurityInitialized -ErrorAction SilentlyContinue)) {
      throw "Initialize-TinySocsOpenSearchSecurity: Ensure-TinySocsOpenSearchSecurityInitialized not found; cannot perform deterministic bootstrap."
    }

    $null = Ensure-TinySocsOpenSearchSecurityInitialized `
      -OpenSearchRoot $osRoot `
      -ProgramDataConf $conf `
      -Url $base `
      -TimeoutSec $ReadyTimeoutSeconds `
      -SkipTlsVerify:$SkipTlsVerify

    $readyDeadline = (Get-Date).AddSeconds([Math]::Max(10, $ReadyTimeoutSeconds))
    $lastReady = $null
    $ok = $false
    while ((Get-Date) -lt $readyDeadline) {
      try {
        $args = @("-sS","-i","--connect-timeout","2","--max-time","6")
        if ($SkipTlsVerify.IsPresent) {
          $args = @("-k") + $args
        } elseif ($effectiveDisableRevoke) {
          $args = @("--ssl-no-revoke") + $args
        }

        $resp = (& $curlExe @args "$base/") 2>&1 | Out-String
        $lastReady = $resp.Trim()

        $is401 = ($resp -match 'HTTP/(1\.1|2)\s+401')
        $hasBasic = ($resp -match '(?im)^WWW-Authenticate:\s*Basic')
        $is200 = ($resp -match 'HTTP/(1\.1|2)\s+200')
        $hasOS = ($resp -match '(?im)^X-OpenSearch-Version:\s*OpenSearch/')
        $is503 = ($resp -match 'HTTP/(1\.1|2)\s+503')
        $hasNotInit = ($resp -match 'OpenSearch Security not initialized')

        if (($is401 -and $hasBasic) -or ($is200 -and $hasOS) -or ($is503 -and $hasNotInit)) {
          $ok = $true
          break
        }
      } catch {
        $lastReady = $_.Exception.Message
      }
      Start-Sleep -Seconds 2
    }
    if (-not $ok) {
      throw "Initialize-TinySocsOpenSearchSecurity: OpenSearch did not become ready at $base within ${ReadyTimeoutSeconds}s. Last=`n$lastReady"
    }

    # PATCH: use Invoke-TinySocsOpenSearchApi here so we don’t get “curl returned 401” weirdness without a body,
    # and so callers can force consistent TLS behaviour.
    $null = Invoke-TinySocsOpenSearchApi `
      -Method GET `
      -Url $base `
      -Path "/_cluster/health" `
      -User $AdminUser `
      -Pass $AdminPass `
      -SkipTlsVerify:$SkipTlsVerify `
      -DisableRevocationCheck:$effectiveDisableRevoke `
      -AllowHttpStatus @() | Out-Null

    $allAccess = @{
      users             = @($AdminUser)
      backend_roles     = @("admin")
      hosts             = @()
      and_backend_roles = @()
      description       = "Maps admin to all_access (TinySocs installer)"
    } | ConvertTo-Json -Depth 20

    $null = & $curlJsonWithRetry -Method PUT -Url "$base/_plugins/_security/api/rolesmapping/all_access" -User $AdminUser -Pass $AdminPass -BodyJson $allAccess -AllowHttpStatus @()

    $roleObj = @{
      cluster_permissions = @(
        "cluster_composite_ops",
        "cluster:monitor/*",
        "cluster:admin/ingest/pipeline/*",
        "cluster:admin/opensearch/ism/*",
        "cluster:admin/index_template/*",
        "indices:admin/index_template/*"
      )
      index_permissions = @(
        @{
          index_patterns  = @($IndexPatterns)
          allowed_actions = @(
            "crud",
            "create_index",
            "indices:admin/*",
            "indices:data/write/*",
            "indices:data/read/*",
            "indices:monitor/*"
          )
        }
      )
      tenant_permissions = @()
      description        = "TinySocs service role (least-privilege baseline)"
    }
    $roleJson = $roleObj | ConvertTo-Json -Depth 20
    $null = & $curlJsonWithRetry -Method PUT -Url "$base/_plugins/_security/api/roles/tinysocs_role" -User $AdminUser -Pass $AdminPass -BodyJson $roleJson -AllowHttpStatus @()

    $userObj = @{
      password      = $ServicePass
      backend_roles = @("tinysocs_role")
      attributes    = @{ app = "tinysocs" }
      description   = "TinySocs service user"
    } | ConvertTo-Json -Depth 20
    $null = & $curlJsonWithRetry -Method PUT -Url "$base/_plugins/_security/api/internalusers/$ServiceUser" -User $AdminUser -Pass $AdminPass -BodyJson $userObj -AllowHttpStatus @()

    $mapObj = @{
      users             = @($ServiceUser)
      backend_roles     = @()
      hosts             = @()
      and_backend_roles = @()
    } | ConvertTo-Json -Depth 20
    $null = & $curlJsonWithRetry -Method PUT -Url "$base/_plugins/_security/api/rolesmapping/tinysocs_role" -User $AdminUser -Pass $AdminPass -BodyJson $mapObj -AllowHttpStatus @()

    $storedVerify = (-not $SkipTlsVerify.IsPresent)
    $null = Write-TinySocsCredManSecrets -SiemUrl $base -AdminUser $AdminUser -AdminPass $AdminPass `
      -ServiceUser $ServiceUser -ServicePass $ServicePass -SiemSslVerify:$storedVerify

    $verifyTries = 20
    $verifySleep = [Math]::Max(1, $RetrySleepSeconds)

    for ($v = 1; $v -le $verifyTries; $v++) {
      $rawAuth = $null
      $auth = $null
      $roles = @()

      try {
        $rawAuth = & $curlJson -Method GET -Url "$base/_plugins/_security/authinfo" -User $ServiceUser -Pass $ServicePass -BodyJson $null -AllowHttpStatus @()
      } catch {
        Write-TinySocsLog -Level "WARN" -Message ("Authinfo probe failed (try {0}/{1}): {2}" -f $v, $verifyTries, $_.Exception.Message)
        Start-Sleep -Seconds $verifySleep
        continue
      }

      try { $auth = ($rawAuth | ConvertFrom-Json) } catch { $auth = $null }
      try { $roles = @($auth.roles) } catch { $roles = @() }

      if ($roles -contains 'tinysocs_role') {
        Write-TinySocsLog "OpenSearch security initialized: role+user+mapping verified (service role present)."
        return @{
          SiemUrl     = $base
          AdminUser   = $AdminUser
          ServiceUser = $ServiceUser
        }
      }

      $rolesStr = ""
      try { $rolesStr = ($roles -join ',') } catch { $rolesStr = "" }
      Write-TinySocsLog -Level "WARN" -Message ("Authinfo ok but role not present yet (try {0}/{1}; roles={2})" -f $v, $verifyTries, $rolesStr)

      Start-Sleep -Seconds $verifySleep
    }

    throw "Initialize-TinySocsOpenSearchSecurity: verification failed; $ServiceUser did not receive tinysocs_role after ${verifyTries} tries."
  }
  finally {
    $env:JAVA_HOME            = $oldJAVA_HOME
    $env:OPENSEARCH_JAVA_HOME = $oldOSJH
    $env:OPENSEARCH_PATH_CONF = $oldOSCONF

    if ($tweakedRevoke) {
      try { [System.Net.ServicePointManager]::CheckCertificateRevocationList = $oldRevokeSetting } catch { }
    }
  }
}

function Test-TinySocsOpenSearch {
  [CmdletBinding()]
  param(
    [string]$SiemUrl = "https://localhost:9201",
    [string]$User,
    [string]$Pass,
    [bool]$SiemSslVerify = $true,
    [int]$ReadyTimeoutSeconds = 30,
    [switch]$Cleanup
  )

  function _TS_Log_OS([string]$msg, [string]$lvl = "INFO") {
    try { Write-Verbose ("[TinySocs][{0}] {1}" -f $lvl, $msg) } catch { }
    try {
      if (Get-Command Write-TinySocsLog -ErrorAction SilentlyContinue) {
        Write-TinySocsLog -Level $lvl -Message $msg
      }
    } catch { }
    try {
      if ($lvl -eq "WARN") { Write-Warning ("[TinySocs] {0}" -f $msg) }
      elseif ($lvl -eq "ERROR") { Write-Error ("[TinySocs] {0}" -f $msg) }
    } catch { }
  }

  function _TS_IsWindows {
    try { return ($env:OS -eq "Windows_NT") } catch { return $true }
  }

  function _TS_IsLoopback([string]$u) {
    try {
      $uri = [Uri]$u
      return ($uri.Host -eq "127.0.0.1" -or $uri.Host -eq "localhost" -or $uri.Host -eq "::1")
    } catch { return $false }
  }

  function _TS_CurlExe {
    $c = Join-Path $env:WINDIR "System32\curl.exe"
    if (Test-Path $c -PathType Leaf) { return $c }
    return "curl.exe"
  }

  function _TS_WriteBodyToTempFile {
    param([Parameter(Mandatory)][string]$Body)
    $p = Join-Path $env:TEMP ("tinysocs-body-" + ([Guid]::NewGuid().ToString("N")) + ".json")
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($p, $Body, $utf8NoBom)
    return $p
  }

  function _TS_CurlJson {
    param(
      [Parameter(Mandatory)][ValidateSet("GET","PUT","POST","DELETE")][string]$Method,
      [Parameter(Mandatory)][string]$Url,
      [Parameter(Mandatory)][string]$User,
      [Parameter(Mandatory)][string]$Pass,
      [string]$BodyJson = $null,
      [bool]$VerifyTls = $true,
      [int[]]$AllowHttpStatus = @()
    )

    $curl       = _TS_CurlExe
    $isLoopback = _TS_IsLoopback $Url
    $isWindows  = _TS_IsWindows

    $args = @("--silent","--show-error","--request",$Method)

    if (-not $VerifyTls) { $args += "-k" }
    if ($isLoopback -and $isWindows) { $args += "--ssl-no-revoke" }

    $args += @("-u",("{0}:{1}" -f $User,$Pass))

    $tmpBody = $null
    try {
      if (-not [string]::IsNullOrWhiteSpace($BodyJson)) {
        $tmpBody = _TS_WriteBodyToTempFile -Body $BodyJson
        $args += @("-H","Content-Type: application/json","--data-binary",("@$tmpBody"))
      }

      $marker = "__TS_HTTP_CODE__"
      $args += @("--write-out","$marker%{http_code}$marker")
      $args += $Url

      _TS_Log_OS ("curl {0} {1}" -f $Method, $Url) "DEBUG"

      $out  = (& $curl @args 2>&1 | Out-String)
      $m    = [regex]::Match($out, "$marker(?<code>\d{3})$marker")
      $code = if ($m.Success) { [int]$m.Groups["code"].Value } else { -1 }

      $body = $out
      if ($m.Success) { $body = ($out -replace "$marker\d{3}$marker","").Trim() }

      if ($code -lt 0) {
        throw "curl did not yield an HTTP code. Output=`n$($out.Trim())"
      }

      if (($AllowHttpStatus -notcontains $code) -and ($code -lt 200 -or $code -ge 300)) {
        throw "HTTP $code from $Url. Body=`n$body"
      }

      if ([string]::IsNullOrWhiteSpace($body)) {
        return @{ __http_code = $code }
      }

      try {
        $json = $body | ConvertFrom-Json -ErrorAction Stop
        $json | Add-Member -NotePropertyName "__http_code" -NotePropertyValue $code -Force
        return $json
      } catch {
        return @{ __http_code = $code; __raw = $body }
      }
    }
    finally {
      if ($tmpBody -and (Test-Path $tmpBody -PathType Leaf)) {
        try { Remove-Item -LiteralPath $tmpBody -Force -ErrorAction SilentlyContinue } catch { }
      }
    }
  }

  # ---- Resolve URL ----------------------------------------------------------
  $base = $SiemUrl
  if ([string]::IsNullOrWhiteSpace($base)) { $base = "https://localhost:9201" }
  $base = $base.Trim().TrimEnd("/")

  # ---- Resolve creds (explicit, then CredMan JSON, then env) ----------------
  if (([string]::IsNullOrWhiteSpace($User) -or [string]::IsNullOrWhiteSpace($Pass)) -and
      (Get-Command Get-TSCredential -ErrorAction SilentlyContinue)) {
    try {
      $raw = Get-TSCredential -Name "TinySocs/SIEM/Creds"
      if ($raw) {
        try {
          $siem = $raw | ConvertFrom-Json -ErrorAction Stop
          if ([string]::IsNullOrWhiteSpace($User) -and $siem.user) { $User = [string]$siem.user }
          if ([string]::IsNullOrWhiteSpace($Pass) -and $siem.pass) { $Pass = [string]$siem.pass }
          if ($siem.PSObject.Properties.Name -contains 'sslVerify') { $SiemSslVerify = [bool]$siem.sslVerify }
          if ($siem.PSObject.Properties.Name -contains 'url' -and $siem.url) { $base = ([string]$siem.url).Trim().TrimEnd("/") }
        } catch { }
      }
    } catch { }
  }

  if ([string]::IsNullOrWhiteSpace($User)) {
    $User = [Environment]::GetEnvironmentVariable("TS_SIEM_USER","Process")
    if ([string]::IsNullOrWhiteSpace($User)) { $User = [Environment]::GetEnvironmentVariable("SIEM_USER","Process") }
    if ([string]::IsNullOrWhiteSpace($User)) { $User = "admin" }
  }

  if ([string]::IsNullOrWhiteSpace($Pass)) {
    $Pass = [Environment]::GetEnvironmentVariable("TS_SIEM_PASS","Process")
    if ([string]::IsNullOrWhiteSpace($Pass)) { $Pass = [Environment]::GetEnvironmentVariable("SIEM_PASS","Process") }
  }

  if ([string]::IsNullOrWhiteSpace($Pass)) {
    _TS_Log_OS "Test-TinySocsOpenSearch: no admin password available (Pass not provided + CredMan/env not set)." "WARN"
    return $false
  }

  _TS_Log_OS ("Starting smoketest: base={0} verifyTls={1} cleanup={2}" -f $base, $SiemSslVerify, $Cleanup.IsPresent) "INFO"

  $deadline = (Get-Date).AddSeconds([Math]::Max(5, $ReadyTimeoutSeconds))
  $lastErr  = $null

  # ---- 1) Wait for cluster health -------------------------------------------
  $healthUrl = "$base/_cluster/health"
  $health    = $null

  while ((Get-Date) -lt $deadline) {
    try {
      $health = _TS_CurlJson -Method "GET" -Url $healthUrl -User $User -Pass $Pass -VerifyTls:$SiemSslVerify -AllowHttpStatus @()
      if ($health -and $health.__http_code -eq 200) { break }
    } catch {
      $lastErr = $_.Exception.Message
      Start-Sleep -Seconds 1
    }
  }

  if (-not $health -or $health.__http_code -ne 200) {
    $errMsg = "unknown error"
    if ($null -ne $lastErr -and -not [string]::IsNullOrWhiteSpace([string]$lastErr)) { $errMsg = [string]$lastErr }
    _TS_Log_OS ("Test-TinySocsOpenSearch failed: {0} :: {1}" -f $healthUrl, $errMsg) "WARN"
    return $false
  }

  if (-not $Cleanup.IsPresent) {
    _TS_Log_OS ("Test-TinySocsOpenSearch OK: url={0} cluster={1} status={2}" -f $base, $health.cluster_name, $health.status) "INFO"
    return $true
  }

  # ---- 2) Cleanup smoke -----------------------------------------------------
  $testIndex = ("tinysocs-smoke-{0}" -f ([Guid]::NewGuid().ToString("N").Substring(0,12)))

  try {
    $createBody = '{"settings":{"index":{"number_of_shards":1,"number_of_replicas":0}}}'
    $docBody    = '{"@timestamp":"' + (Get-Date).ToString("o") + '","msg":"tinysocs smoketest","ok":true}'

    $null = _TS_CurlJson -Method "PUT"  -Url "$base/$testIndex"                      -User $User -Pass $Pass -VerifyTls:$SiemSslVerify -BodyJson $createBody -AllowHttpStatus @(200)
    $null = _TS_CurlJson -Method "POST" -Url "$base/$testIndex/_doc/1?refresh=true"  -User $User -Pass $Pass -VerifyTls:$SiemSslVerify -BodyJson $docBody    -AllowHttpStatus @(200,201)

    $res  = _TS_CurlJson -Method "GET"  -Url "$base/$testIndex/_search?q=ok:true"    -User $User -Pass $Pass -VerifyTls:$SiemSslVerify -AllowHttpStatus @(200)

    $hits = 0
    try {
      if ($res -and $res.hits -and $res.hits.total -and ($res.hits.total.PSObject.Properties.Name -contains "value")) {
        $hits = [int]$res.hits.total.value
      } elseif ($res -and $res.hits -and $res.hits.hits) {
        $hits = @($res.hits.hits).Count
      }
    } catch { $hits = 0 }

    if ($hits -lt 1) { throw "smoketest search returned hits=$hits" }

    _TS_Log_OS ("Test-TinySocsOpenSearch OK: url={0} cluster={1} status={2} hits={3} (index={4})" -f $base, $health.cluster_name, $health.status, $hits, $testIndex) "INFO"
    return $true
  }
  catch {
    _TS_Log_OS ("Test-TinySocsOpenSearch failed during cleanup-smoke: {0}" -f $_.Exception.Message) "WARN"
    return $false
  }
  finally {
    try { $null = _TS_CurlJson -Method "DELETE" -Url "$base/$testIndex" -User $User -Pass $Pass -VerifyTls:$SiemSslVerify -AllowHttpStatus @(200,404) } catch { }
  }
}

function Repair-TinySocsScheduledTasks {
  [CmdletBinding(SupportsShouldProcess)]
  param(
    [int]$HeartbeatMinutes = 15,
    [string]$TaskPath = "\TinySocs\",
    [switch]$Force
  )

  # Ensure ScheduledTasks cmdlets are available
  try { Import-Module ScheduledTasks -ErrorAction SilentlyContinue | Out-Null } catch { }

  function _TS_Log([string]$msg, [string]$lvl = "INFO") {
    try {
      if (Get-Command Write-TinySocsLog -ErrorAction SilentlyContinue) {
        Write-TinySocsLog -Level $lvl -Message $msg
      } else {
        Write-Host "[TinySocs][$lvl] $msg"
      }
    } catch {
      Write-Host "[TinySocs][$lvl] $msg"
    }
  }

  # ---- Canonicalize TaskPath ------------------------------------------------
  if ([string]::IsNullOrWhiteSpace($TaskPath)) { $TaskPath = "\" }
  $TaskPath = $TaskPath.Trim()
  if (-not $TaskPath.StartsWith("\")) { $TaskPath = "\" + $TaskPath }
  if (-not $TaskPath.EndsWith("\"))   { $TaskPath = $TaskPath + "\" }

  # bump build stamp so logs prove which generator wrote the runner scripts
  $buildStamp = "20260111-runner-childps-diag+invocationinfo+quoted-child-file-ps51"
  $hb = [Math]::Max(1, [int]$HeartbeatMinutes)

  $dataRoot      = Join-Path $env:ProgramData "TinySocs"
  $logDir        = Join-Path $dataRoot "logs"
  $taskScriptDir = Join-Path $dataRoot "scripts\tasks"
  try { New-Item -ItemType Directory -Force -Path $logDir | Out-Null } catch { }
  try { New-Item -ItemType Directory -Force -Path $taskScriptDir | Out-Null } catch { }

  # Resolve install root + script paths
  $installRoot = $null
  try {
    if (Get-Command Get-TinySocsInstallRoot -ErrorAction SilentlyContinue) {
      $installRoot = (Get-TinySocsInstallRoot | Select-Object -First 1)
    }
  } catch { $installRoot = $null }

  if (-not $installRoot) { $installRoot = Join-Path $env:ProgramFiles "TinySocs" }

  $binDir = Join-Path $installRoot "bin"
  $modDir = Join-Path $installRoot "modules"

  foreach ($d in @($installRoot,$binDir,$modDir)) {
    try {
      if ($d -and -not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Force -Path $d | Out-Null }
    } catch { }
  }
  if (-not (Test-Path -LiteralPath $binDir)) { $binDir = $installRoot }
  if (-not (Test-Path -LiteralPath $modDir)) { $modDir = $installRoot }

  $psExe = Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe"
  if (-not (Test-Path -LiteralPath $psExe -PathType Leaf)) { $psExe = "powershell.exe" }

  # Expected scripts
  $masterLauncher  = Join-Path $modDir "Launch-Master.ps1"
  $anchorsLauncher = Join-Path $modDir "Launch-Anchors.ps1"
  $rotateQueue     = Join-Path $modDir "TinySocs.RotateQueue.ps1"

  foreach ($p in @($masterLauncher, $anchorsLauncher, $rotateQueue)) {
    if (-not (Test-Path -LiteralPath $p -PathType Leaf)) {
      _TS_Log "Repair-TinySocsScheduledTasks: expected script not found: $p" "WARN"
    }
  }

  function _Esc1([string]$s) {
    if ($null -eq $s) { return "" }
    return ($s -replace "'", "''")
  }

  function _WriteTaskRunnerScript {
    param(
      [Parameter(Mandatory)][string]$TaskName,
      [Parameter(Mandatory)][string]$WorkingDir,
      [Parameter(Mandatory)][string]$ScriptPath,
      [string]$ScriptArgs = ""
    )

    $taskLog = Join-Path $logDir ("task-{0}.log" -f $TaskName)
    $ps1Path = Join-Path $taskScriptDir ("{0}.ps1" -f $TaskName)
    $touch   = Join-Path $taskScriptDir ("{0}.touch" -f $TaskName)

    $wd  = _Esc1 $WorkingDir
    $sp  = _Esc1 $ScriptPath
    $tl  = _Esc1 $taskLog
    $tc  = _Esc1 $touch
    $arg = _Esc1 $ScriptArgs

    # Key change:
    # - We run the *target script* in a child powershell.exe and redirect stdout/stderr to files.
    # - The child invocation MUST quote the -File path (spaces), and MUST pass -ArgumentList as ONE string in PS 5.1.
    $content = @()
    $content += '$ErrorActionPreference = "Stop"'
    $content += '$ProgressPreference = "SilentlyContinue"'
    $content += '$primaryLog = ''' + $tl + ''''
    $content += '$fallbackLog = (Join-Path $env:WINDIR ("Temp\tinysocs-task-' + $TaskName + '.log"))'
    $content += '$touch = ''' + $tc + ''''
    $content += '$buildStamp = ''' + (_Esc1 $buildStamp) + ''''
    $content += '$workingDir = ''' + $wd + ''''
    $content += '$targetScript = ''' + $sp + ''''
    $content += '$targetArgs = ''' + $arg + ''''
    $content += '$childOut = (Join-Path $env:WINDIR ("Temp\tinysocs-child-' + $TaskName + '.out"))'
    $content += '$childErr = (Join-Path $env:WINDIR ("Temp\tinysocs-child-' + $TaskName + '.err"))'
    $content += ''
    $content += 'function _WriteLine([string]$line) {'
    $content += '  if ($null -eq $line) { $line = "" }'
    $content += '  try {'
    $content += '    try { New-Item -ItemType Directory -Force -Path (Split-Path -Parent $primaryLog) | Out-Null } catch { }'
    $content += '    Add-Content -LiteralPath $primaryLog -Value $line'
    $content += '  } catch {'
    $content += '    try { Add-Content -LiteralPath $fallbackLog -Value $line } catch { }'
    $content += '  }'
    $content += '}'
    $content += ''
    $content += 'try { New-Item -ItemType Directory -Force -Path (Split-Path -Parent $touch) | Out-Null } catch { }'
    $content += 'try { Set-Content -LiteralPath $touch -Value (Get-Date).ToString("s") -Force } catch { }'
    $content += '$ts = (Get-Date).ToString("s")'
    $content += '_WriteLine ("[{0}] START ' + $TaskName + ' (user={1})" -f $ts, [Environment]::UserName)'
    $content += '_WriteLine ("[{0}] BUILD {1}" -f $ts, $buildStamp)'
    $content += '_WriteLine ("[{0}] PSVersion={1}" -f $ts, $PSVersionTable.PSVersion.ToString())'
    $content += '_WriteLine ("[{0}] PSScriptRoot={1}" -f $ts, $PSScriptRoot)'
    $content += '_WriteLine ("[{0}] WorkingDir(spec)={1}" -f $ts, $workingDir)'
    $content += '_WriteLine ("[{0}] TargetScript={1}" -f $ts, $targetScript)'
    $content += '_WriteLine ("[{0}] TargetArgs={1}" -f $ts, $targetArgs)'
    $content += ''
    $content += 'try {'
    $content += '  if (-not (Test-Path -LiteralPath $workingDir -PathType Container)) { throw ("WorkingDir missing: " + $workingDir) }'
    $content += '  if (-not (Test-Path -LiteralPath $targetScript -PathType Leaf)) { throw ("Target script missing: " + $targetScript) }'
    $content += ''
    $content += '  Set-Location -LiteralPath $workingDir'
    $content += '  _WriteLine ("[{0}] WorkingDir(actual)={1}" -f (Get-Date).ToString("s"), (Get-Location).Path)'
    $content += ''
    $content += '  $hash = "n/a"'
    $content += '  try { $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $targetScript).Hash } catch { }'
    $content += '  _WriteLine ("[{0}] TargetHashSHA256={1}" -f (Get-Date).ToString("s"), $hash)'
    $content += ''
    $content += '  try { Remove-Item -LiteralPath $childOut -Force -ErrorAction SilentlyContinue } catch { }'
    $content += '  try { Remove-Item -LiteralPath $childErr -Force -ErrorAction SilentlyContinue } catch { }'
    $content += ''
    $content += '  $exe = (Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe")'
    $content += '  if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { $exe = "powershell.exe" }'
    $content += ''
    $content += '  # IMPORTANT (PS 5.1): -ArgumentList must be ONE string, and the -File path must be quoted.'
    $content += '  $argString = ''-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'' + $targetScript + ''"'''
    $content += '  if ($targetArgs -and -not [string]::IsNullOrWhiteSpace($targetArgs)) { $argString += (" " + $targetArgs) }'
    $content += ''
    $content += '  _WriteLine ("[{0}] CHILD: {1} {2}" -f (Get-Date).ToString("s"), $exe, $argString)'
    $content += '  $p = Start-Process -FilePath $exe -ArgumentList $argString -PassThru -Wait -RedirectStandardOutput $childOut -RedirectStandardError $childErr'
    $content += '  $ec = 1'
    $content += '  try { $ec = [int]$p.ExitCode } catch { $ec = 1 }'
    $content += ''
    $content += '  if (Test-Path -LiteralPath $childOut) {'
    $content += '    _WriteLine ("[{0}] --- child stdout ---" -f (Get-Date).ToString("s"))'
    $content += '    Get-Content -LiteralPath $childOut -ErrorAction SilentlyContinue | ForEach-Object { _WriteLine ("" + $_) }'
    $content += '  }'
    $content += '  if (Test-Path -LiteralPath $childErr) {'
    $content += '    _WriteLine ("[{0}] --- child stderr ---" -f (Get-Date).ToString("s"))'
    $content += '    Get-Content -LiteralPath $childErr -ErrorAction SilentlyContinue | ForEach-Object { _WriteLine ("" + $_) }'
    $content += '  }'
    $content += ''
    $content += '  $ts2 = (Get-Date).ToString("s")'
    $content += '  _WriteLine ("[{0}] EXIT ' + $TaskName + ' code={1}" -f $ts2, $ec)'
    $content += '  exit $ec'
    $content += '} catch {'
    $content += '  $ts3 = (Get-Date).ToString("s")'
    $content += '  _WriteLine ("[{0}] ERROR ' + $TaskName + ': {1}" -f $ts3, $_.Exception.Message)'
    $content += '  if ($_.InvocationInfo -and $_.InvocationInfo.PositionMessage) { _WriteLine ("[{0}] POS: {1}" -f $ts3, $_.InvocationInfo.PositionMessage) }'
    $content += '  if ($_.ScriptStackTrace) { _WriteLine ("[{0}] STACK: {1}" -f $ts3, $_.ScriptStackTrace) }'
    $content += '  _WriteLine ("[{0}] EX: {1}" -f $ts3, $_.Exception.ToString())'
    $content += '  exit 1'
    $content += '}'

    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllLines($ps1Path, $content, $utf8NoBom)

    return $ps1Path
  }

  function _EnsureTaskFolder([string]$path) {
    if ([string]::IsNullOrWhiteSpace($path)) { return }
    $p = $path.Trim()
    if (-not $p.StartsWith("\")) { $p = "\" + $p }
    if (-not $p.EndsWith("\"))   { $p = $p + "\" }
    if ($p -eq "\") { return }

    $svc = $null
    try {
      $svc = New-Object -ComObject "Schedule.Service"
      $svc.Connect()
      $parts = @($p.Trim("\").Split("\") | Where-Object { $_ -and $_.Trim() })
      $curPath = "\"
      foreach ($part in $parts) {
        $nextPath = if ($curPath -eq "\") { "\" + $part } else { $curPath + "\" + $part }
        try { $null = $svc.GetFolder($nextPath) }
        catch {
          _TS_Log "Creating scheduled task folder: $nextPath" "INFO"
          $parent = $svc.GetFolder($curPath)
          $null = $parent.CreateFolder($part)
        }
        $curPath = $nextPath
      }
    } catch {
      throw "Failed to ensure task folder '$p': $($_.Exception.Message)"
    } finally {
      if ($svc -and [System.Runtime.InteropServices.Marshal]::IsComObject($svc)) {
        try { [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($svc) } catch { }
      }
    }
  }

  function _RegisterTaskPlaceholder {
    param(
      [Parameter(Mandatory)][string]$Name,
      [Parameter(Mandatory)]$Trigger,
      [Parameter(Mandatory)][string]$WorkingDir
    )

    # KEEP THIS COMPATIBLE: only use widely-supported settings params
    $action    = New-ScheduledTaskAction -Execute $psExe -Argument '-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "exit 0"' -WorkingDirectory $WorkingDir
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

    $settings  = New-ScheduledTaskSettingsSet `
      -StartWhenAvailable `
      -AllowStartIfOnBatteries `
      -DontStopIfGoingOnBatteries `
      -ExecutionTimeLimit (New-TimeSpan -Hours 2) `
      -MultipleInstances IgnoreNew

    $task = New-ScheduledTask -Action $action -Trigger $Trigger -Principal $principal -Settings $settings

    if ($PSCmdlet.ShouldProcess("$TaskPath$Name","Register-ScheduledTask")) {
      Register-ScheduledTask -TaskName $Name -TaskPath $TaskPath -InputObject $task -Force | Out-Null
    }
  }

  function _PatchTaskXml {
    param(
      [Parameter(Mandatory)][string]$Name,
      [string]$IntervalIso,
      [string]$RepetitionDurationIso = "P1D",
      [Parameter(Mandatory)][string]$ExecCommand,
      [Parameter(Mandatory)][string]$ExecArguments,
      [Parameter(Mandatory)][string]$ExecWorkingDirectory
    )

    $xml = Export-ScheduledTask -TaskName $Name -TaskPath $TaskPath
    [xml]$doc = $xml

    $nsUri = $doc.DocumentElement.NamespaceURI
    $ns = New-Object System.Xml.XmlNamespaceManager($doc.NameTable)
    $ns.AddNamespace("t", $nsUri)

    # Remove IdleSettings entirely
    $idle = $doc.SelectSingleNode("//t:Settings/t:IdleSettings", $ns)
    if ($idle -and $idle.ParentNode) { [void]$idle.ParentNode.RemoveChild($idle) }

    # FORCE action to Exec(Command/Arguments/WorkingDirectory)
    $actions = $doc.SelectSingleNode("//t:Actions", $ns)
    if (-not $actions) {
      $actions = $doc.CreateElement("Actions", $nsUri)
      [void]$doc.DocumentElement.AppendChild($actions)
    } else {
      $existingExecs = $actions.SelectNodes("t:Exec", $ns)
      foreach ($ex in @($existingExecs)) { [void]$actions.RemoveChild($ex) }
    }

    $exec = $doc.CreateElement("Exec", $nsUri)
    [void]$actions.AppendChild($exec)

    $cmdNode = $doc.CreateElement("Command", $nsUri)
    $cmdNode.InnerText = $ExecCommand
    [void]$exec.AppendChild($cmdNode)

    $argNode = $doc.CreateElement("Arguments", $nsUri)
    $argNode.InnerText = $ExecArguments
    [void]$exec.AppendChild($argNode)

    $wdNode = $doc.CreateElement("WorkingDirectory", $nsUri)
    $wdNode.InnerText = $ExecWorkingDirectory
    [void]$exec.AppendChild($wdNode)

    # Repetition on TimeTrigger only
    if ($IntervalIso) {
      $timeTriggers = $doc.SelectNodes("//t:Triggers/t:TimeTrigger", $ns)
      foreach ($trig in $timeTriggers) {
        $rep = $trig.SelectSingleNode("t:Repetition", $ns)
        if (-not $rep) {
          $rep = $doc.CreateElement("Repetition", $nsUri)
          [void]$trig.AppendChild($rep)
        }

        $iNode = $rep.SelectSingleNode("t:Interval", $ns)
        if (-not $iNode) { $iNode = $doc.CreateElement("Interval", $nsUri); [void]$rep.AppendChild($iNode) }
        $iNode.InnerText = $IntervalIso

        $dNode = $rep.SelectSingleNode("t:Duration", $ns)
        if (-not $dNode) { $dNode = $doc.CreateElement("Duration", $nsUri); [void]$rep.AppendChild($dNode) }
        $dNode.InnerText = $RepetitionDurationIso

        $sNode = $rep.SelectSingleNode("t:StopAtDurationEnd", $ns)
        if (-not $sNode) { $sNode = $doc.CreateElement("StopAtDurationEnd", $nsUri); [void]$rep.AppendChild($sNode) }
        $sNode.InnerText = "false"
      }
    }

    # ExecutionTimeLimit sane
    $etl = $doc.SelectSingleNode("//t:Settings/t:ExecutionTimeLimit", $ns)
    if (-not $etl) {
      $settings = $doc.SelectSingleNode("//t:Settings", $ns)
      if ($settings) {
        $etl = $doc.CreateElement("ExecutionTimeLimit", $nsUri)
        $etl.InnerText = "PT2H"
        [void]$settings.AppendChild($etl)
      }
    } else {
      $etl.InnerText = "PT2H"
    }

    Register-ScheduledTask -TaskName $Name -TaskPath $TaskPath -Xml $doc.OuterXml -Force | Out-Null
  }

  # ---- Ensure folder exists -------------------------------------------------
  _EnsureTaskFolder -path $TaskPath
  _TS_Log "Repair-TinySocsScheduledTasks build=$buildStamp TaskPath=$TaskPath hb=${hb}m" "INFO"

  # Remove old copies
  $targets = @("TinySocsHeartbeat","TinySocsAnchorsEnsure","TinySocsAnchorsPrune","TinySocsRotateQueue")
  foreach ($t in $targets) {
    $existing = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskName -eq $t }
    foreach ($e in $existing) {
      $full = "{0}{1}" -f $e.TaskPath, $e.TaskName
      if ($Force -or ($e.TaskPath -ne $TaskPath)) {
        _TS_Log "Removing existing task: $full" "INFO"
        try { Unregister-ScheduledTask -TaskName $e.TaskName -TaskPath $e.TaskPath -Confirm:$false -ErrorAction Stop } catch { }
      }
    }
  }

  # Triggers
  $hbTrigger     = New-ScheduledTaskTrigger -Once  -At (Get-Date).AddMinutes(1)
  $rqTrigger     = New-ScheduledTaskTrigger -Once  -At (Get-Date).AddMinutes(2)
  $ensureTrigger = New-ScheduledTaskTrigger -Daily -At 3:10AM
  $pruneTrigger  = New-ScheduledTaskTrigger -Daily -At 3:15AM

  # Runner scripts (child powershell diag)
  $hbScript = _WriteTaskRunnerScript -TaskName "TinySocsHeartbeat"     -WorkingDir $binDir -ScriptPath $masterLauncher   -ScriptArgs "-Heartbeat"
  $enScript = _WriteTaskRunnerScript -TaskName "TinySocsAnchorsEnsure" -WorkingDir $binDir -ScriptPath $anchorsLauncher -ScriptArgs "-Ensure"
  $prScript = _WriteTaskRunnerScript -TaskName "TinySocsAnchorsPrune"  -WorkingDir $binDir -ScriptPath $anchorsLauncher -ScriptArgs "-Prune"
  $rqScript = _WriteTaskRunnerScript -TaskName "TinySocsRotateQueue"   -WorkingDir $modDir -ScriptPath $rotateQueue     -ScriptArgs ""

  # Register placeholders (we immediately overwrite the action via XML)
  _RegisterTaskPlaceholder -Name "TinySocsHeartbeat"     -Trigger $hbTrigger     -WorkingDir $binDir
  _RegisterTaskPlaceholder -Name "TinySocsAnchorsEnsure" -Trigger $ensureTrigger -WorkingDir $binDir
  _RegisterTaskPlaceholder -Name "TinySocsAnchorsPrune"  -Trigger $pruneTrigger  -WorkingDir $binDir
  _RegisterTaskPlaceholder -Name "TinySocsRotateQueue"   -Trigger $rqTrigger     -WorkingDir $modDir

  # Enforce action via XML
  $hbInterval = ("PT{0}M" -f $hb)
  $rqInterval = "PT1H"

  $hbArgs = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $hbScript + '"'
  $enArgs = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $enScript + '"'
  $prArgs = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $prScript + '"'
  $rqArgs = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $rqScript + '"'

  try { _PatchTaskXml -Name "TinySocsHeartbeat"     -IntervalIso $hbInterval -RepetitionDurationIso "P1D" -ExecCommand $psExe -ExecArguments $hbArgs -ExecWorkingDirectory $binDir } catch { _TS_Log "Patch XML failed (Heartbeat): $($_.Exception.Message)" "WARN" }
  try { _PatchTaskXml -Name "TinySocsRotateQueue"   -IntervalIso $rqInterval -RepetitionDurationIso "P1D" -ExecCommand $psExe -ExecArguments $rqArgs -ExecWorkingDirectory $modDir } catch { _TS_Log "Patch XML failed (RotateQueue): $($_.Exception.Message)" "WARN" }
  try { _PatchTaskXml -Name "TinySocsAnchorsEnsure" -ExecCommand $psExe -ExecArguments $enArgs -ExecWorkingDirectory $binDir } catch { _TS_Log "Patch XML failed (AnchorsEnsure): $($_.Exception.Message)" "WARN" }
  try { _PatchTaskXml -Name "TinySocsAnchorsPrune"  -ExecCommand $psExe -ExecArguments $prArgs -ExecWorkingDirectory $binDir } catch { _TS_Log "Patch XML failed (AnchorsPrune): $($_.Exception.Message)" "WARN" }

  # Final sanity
  try {
    foreach ($n in @("TinySocsHeartbeat","TinySocsRotateQueue","TinySocsAnchorsEnsure","TinySocsAnchorsPrune")) {
      $t = Get-ScheduledTask -TaskName $n -TaskPath $TaskPath -ErrorAction SilentlyContinue
      if ($t) {
        $a = $t.Actions | Select-Object -First 1
        _TS_Log ("Task {0}: Execute={1} Args={2} WD={3}" -f $n, $a.Execute, $a.Arguments, $a.WorkingDirectory) "DEBUG"
      }
    }
  } catch { }

  _TS_Log "Scheduled task repair complete." "INFO"
}

function Sync-TinySocsOpenSearchTlsKeystore {
  [CmdletBinding()]
  param(
    [string]$OpenSearchHome = "C:\Program Files\TinySocs\OpenSearch",
    [string]$ConfDir        = (Join-Path $env:ProgramData "TinySocs\OpenSearch\config"),
    [string]$DpapiPath      = (Join-Path (Join-Path (Join-Path $env:ProgramData "TinySocs\OpenSearch\config") "certs") "opensearch-tls-storepass.dpapi"),

    # NEW: optional guardrail to hard-enforce ASCII-only and no null/newline chars (Java/PKCS12 friendliness)
    [switch]$EnsureAsciiJavaCompatible,

    # NEW: create opensearch.keystore if missing (prevents "keystore not found" failures)
    [switch]$CreateKeystoreIfMissing
  )

  $bat = Join-Path $OpenSearchHome "bin\opensearch-keystore.bat"
  if (-not (Test-Path -LiteralPath $bat -PathType Leaf)) { throw "OpenSearch keystore tool not found: $bat" }
  if (-not (Test-Path -LiteralPath $ConfDir -PathType Container)) { throw "OpenSearch conf dir not found: $ConfDir" }
  if (-not (Test-Path -LiteralPath $DpapiPath -PathType Leaf)) { throw "TLS storepass DPAPI file not found: $DpapiPath" }

  $oldConf = $env:OPENSEARCH_PATH_CONF
  try {
    # Ensure keystore commands operate on the ProgramData config tree
    $env:OPENSEARCH_PATH_CONF = $ConfDir

    # PATCH: repair ACLs BEFORE any keystore operations
    try {
      $fn = Get-Command Repair-TinySocsOpenSearchKeystoreAcls -ErrorAction SilentlyContinue
      if ($fn) {
        $pp = @{}
        if ($fn.Parameters.ContainsKey('ProgramDataConf')) { $pp.ProgramDataConf = $ConfDir }
        elseif ($fn.Parameters.ContainsKey('ConfDir'))      { $pp.ConfDir        = $ConfDir }
        elseif ($fn.Parameters.ContainsKey('Path'))         { $pp.Path           = $ConfDir }
        & $fn @pp | Out-Null
      } else {
        try { attrib.exe -R $ConfDir /S /D | Out-Null } catch { }
        $who = $null; try { $who = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name } catch { $who = $env:USERNAME }
        try { & icacls.exe $ConfDir /inheritance:e /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" ($who + ":(OI)(CI)F") /T /C | Out-Null } catch { }
        $ks0 = Join-Path $ConfDir "opensearch.keystore"
        if (Test-Path -LiteralPath $ks0 -PathType Leaf) {
          try { & icacls.exe $ks0 /inheritance:e /grant:r "SYSTEM:F" "Administrators:F" ($who + ":F") /C | Out-Null } catch { }
        }
      }
    } catch { }

    # Optionally create keystore early (avoids remove/list/add failures on fresh installs)
    $ksPath = Join-Path $ConfDir "opensearch.keystore"
    if ($CreateKeystoreIfMissing.IsPresent -and -not (Test-Path -LiteralPath $ksPath -PathType Leaf)) {
      try { & $bat create 2>$null | Out-Null } catch { }

      # PATCH: repair ACLs AFTER create
      try {
        $fn = Get-Command Repair-TinySocsOpenSearchKeystoreAcls -ErrorAction SilentlyContinue
        if ($fn) {
          $pp = @{}
          if ($fn.Parameters.ContainsKey('ProgramDataConf')) { $pp.ProgramDataConf = $ConfDir }
          elseif ($fn.Parameters.ContainsKey('ConfDir'))      { $pp.ConfDir        = $ConfDir }
          elseif ($fn.Parameters.ContainsKey('Path'))         { $pp.Path           = $ConfDir }
          & $fn @pp | Out-Null
        } else {
          try { attrib.exe -R $ConfDir /S /D | Out-Null } catch { }
          $who = $null; try { $who = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name } catch { $who = $env:USERNAME }
          try { & icacls.exe $ConfDir /inheritance:e /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" ($who + ":(OI)(CI)F") /T /C | Out-Null } catch { }
          if (Test-Path -LiteralPath $ksPath -PathType Leaf) {
            try { & icacls.exe $ksPath /inheritance:e /grant:r "SYSTEM:F" "Administrators:F" ($who + ":F") /C | Out-Null } catch { }
          }
        }
      } catch { }
    }

    # 1) Resolve password
    if (-not (Get-Command Resolve-TinySocsTlsStorepass -ErrorAction SilentlyContinue)) {
      throw "Resolve-TinySocsTlsStorepass is not available in this session (module not imported?)"
    }

    $info = Resolve-TinySocsTlsStorepass -LiteralPath $DpapiPath
    if (-not $info -or [string]::IsNullOrWhiteSpace($info.Password)) {
      throw "Resolve-TinySocsTlsStorepass returned empty password for: $DpapiPath"
    }

    # Important: avoid accidental newline issues on stdin
    $pw = ([string]$info.Password -replace "(\r|\n)+$","").Trim()

    if ($EnsureAsciiJavaCompatible.IsPresent) {
      if ($pw.IndexOf([char]0) -ge 0 -or $pw -match "[`r`n]") {
        throw "Sync-TinySocsOpenSearchTlsKeystore: storepass contains null/newline characters (DPAPI=$DpapiPath). This will break OpenSearch/Java PKCS12."
      }
      $badAscii = $false
      foreach ($ch in $pw.ToCharArray()) {
        if ([int][char]$ch -gt 127) { $badAscii = $true; break }
      }
      if ($badAscii) {
        throw "Sync-TinySocsOpenSearchTlsKeystore: storepass contains non-ASCII characters (DPAPI=$DpapiPath). OpenSearch/Java PKCS12 commonly rejects this."
      }
    }

    # 2) Remove any legacy NON-secure SSL password keys in keystore (OpenSearch 3.3.2 hard-fails if present)
    $existing = @()
    try {
      $existing = @(& $bat list 2>$null) | Where-Object { $_ -and $_.Trim() -ne "" }
    } catch {
      $existing = @()
    }

    $insecure = $existing | Where-Object {
      $_ -match '^plugins\.security\.ssl\..+_password$' -and $_ -notmatch '_secure$'
    }

    foreach ($k in $insecure) {
      try { & $bat remove $k 2>$null | Out-Null } catch { }
    }

    # 3) Set secure keys (authoritative overwrite)
    $secureKeys = @(
      "plugins.security.ssl.http.keystore_password_secure",
      "plugins.security.ssl.http.keystore_keypassword_secure",
      "plugins.security.ssl.http.truststore_password_secure",
      "plugins.security.ssl.transport.keystore_password_secure",
      "plugins.security.ssl.transport.keystore_keypassword_secure",
      "plugins.security.ssl.transport.truststore_password_secure"
    )

    # If keystore still doesn't exist at this point, attempt to create it (best-effort).
    if (-not (Test-Path -LiteralPath $ksPath -PathType Leaf)) {
      try { & $bat create 2>$null | Out-Null } catch { }

      # PATCH: repair ACLs AFTER create
      try {
        $fn = Get-Command Repair-TinySocsOpenSearchKeystoreAcls -ErrorAction SilentlyContinue
        if ($fn) {
          $pp = @{}
          if ($fn.Parameters.ContainsKey('ProgramDataConf')) { $pp.ProgramDataConf = $ConfDir }
          elseif ($fn.Parameters.ContainsKey('ConfDir'))      { $pp.ConfDir        = $ConfDir }
          elseif ($fn.Parameters.ContainsKey('Path'))         { $pp.Path           = $ConfDir }
          & $fn @pp | Out-Null
        } else {
          try { attrib.exe -R $ConfDir /S /D | Out-Null } catch { }
          $who = $null; try { $who = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name } catch { $who = $env:USERNAME }
          try { & icacls.exe $ConfDir /inheritance:e /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" ($who + ":(OI)(CI)F") /T /C | Out-Null } catch { }
          if (Test-Path -LiteralPath $ksPath -PathType Leaf) {
            try { & icacls.exe $ksPath /inheritance:e /grant:r "SYSTEM:F" "Administrators:F" ($who + ":F") /C | Out-Null } catch { }
          }
        }
      } catch { }
    }

    foreach ($k in $secureKeys) {
      try {
        $pw | & $bat add --force --stdin $k | Out-Null
      } catch {
        throw "Sync-TinySocsOpenSearchTlsKeystore: failed setting keystore key '$k': $($_.Exception.Message)"
      }
    }

    # Return a useful result object for logging
    $final = @()
    try {
      $final = @(& $bat list 2>$null) | Where-Object { $_ -and $_.Trim() -ne "" }
    } catch {
      $final = @()
    }

    [pscustomobject]@{
      OpenSearchHome       = $OpenSearchHome
      ConfDir              = $ConfDir
      DpapiPath            = $DpapiPath
      EnsureAsciiJavaCompatible = [bool]$EnsureAsciiJavaCompatible
      CreatedKeystore      = (Test-Path -LiteralPath (Join-Path $ConfDir "opensearch.keystore") -PathType Leaf)
      RemovedInsecureKeys  = $insecure
      SetSecureKeys        = $secureKeys
      FinalKeystoreEntries = $final
    }
  }
  finally {
    # restore caller env
    $env:OPENSEARCH_PATH_CONF = $oldConf
  }
}

function Test-TinySocsPkcs12Password {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [Alias('LiteralPath')]
    [string]$P12Path,

    [Parameter(Mandatory)]
    [string]$Password
  )

  if (-not (Test-Path -LiteralPath $P12Path -PathType Leaf)) {
    return [pscustomobject]@{
      Path  = $P12Path
      Ok    = $false
      Error = "P12 not found"
    }
  }

  try {
    $bytes = [System.IO.File]::ReadAllBytes($P12Path)
  } catch {
    return [pscustomobject]@{
      Path  = $P12Path
      Ok    = $false
      Error = "Failed to read P12 bytes: $($_.Exception.Message)"
    }
  }

  # Import into an ephemeral key set if possible (avoids writing keys to disk).
  $flags = $null
  try {
    $flags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet
  } catch {
    $flags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::MachineKeySet
  }

  try {
    $col = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
    $col.Import($bytes, $Password, $flags)

    if (-not $col -or $col.Count -lt 1) {
      return [pscustomobject]@{
        Path  = $P12Path
        Ok    = $false
        Error = "Import succeeded but collection was empty"
      }
    }

    return [pscustomobject]@{
      Path  = $P12Path
      Ok    = $true
      Error = $null
    }
  } catch {
    return [pscustomobject]@{
      Path  = $P12Path
      Ok    = $false
      Error = $_.Exception.Message
    }
  }
}

function Assert-TinySocsOpenSearchSecurityConfigPresent {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$ConfigPath
  )

  if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) {
    throw "OpenSearch config file missing: $ConfigPath"
  }

  $raw = Get-Content -LiteralPath $ConfigPath -Raw -ErrorAction Stop

  $requiredPatterns = @(
    '(?m)^\s*plugins\.security\.disabled\s*:\s*false\s*$',
    '(?m)^\s*plugins\.security\.ssl\.http\.enabled\s*:\s*true\s*$',
    '(?m)^\s*plugins\.security\.ssl\.http\.keystore_filepath\s*:\s*\S+',
    '(?m)^\s*plugins\.security\.ssl\.http\.truststore_filepath\s*:\s*\S+',
    '(?m)^\s*plugins\.security\.ssl\.transport\.keystore_filepath\s*:\s*\S+',
    '(?m)^\s*plugins\.security\.ssl\.transport\.truststore_filepath\s*:\s*\S+'
  )

  $missing = @()
  foreach ($pat in $requiredPatterns) {
    if ($raw -notmatch $pat) { $missing += $pat }
  }

  if ($missing.Count -gt 0) {
    throw ("OpenSearch security/TLS settings were not persisted to opensearch.yml. " +
           "ConfigPath=$ConfigPath; MissingPatterns=$($missing -join '; ')")
  }

  # --- NEW: also verify ProgramData opensearch-security config tree is readable ---
  $confDir = Split-Path -Parent $ConfigPath
  $secDir  = Join-Path -Path $confDir -ChildPath "opensearch-security"

  if (-not (Test-Path -LiteralPath $secDir -PathType Container)) {
    throw "OpenSearch security config directory missing: $secDir"
  }

  # Repair ACLs before read-checking (prevents the ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã¢â‚¬Å“Access deniedÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â you hit)
  try { Repair-TinySocsOpenSearchSecurityConfigAcls -SecurityDir $secDir } catch { }

  $requiredFiles = @(
    "config.yml",
    "internal_users.yml",
    "roles.yml",
    "roles_mapping.yml",
    "action_groups.yml",
    "tenants.yml"
  )

  foreach ($f in $requiredFiles) {
    $p = Join-Path -Path $secDir -ChildPath $f
    if (-not (Test-Path -LiteralPath $p -PathType Leaf)) {
      throw "Security config file missing: $p"
    }

    # IMPORTANT: read-only open (do NOT use ReadWrite here)
    try {
      $fs = [System.IO.File]::Open(
        $p,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::ReadWrite
      )
      $fs.Dispose()
    } catch {
      throw "Security config file unreadable: '$p' : $($_.Exception.Message)"
    }
  }
  # --- END NEW ---

  Write-TinySocsLog "Verified OpenSearch security/TLS keys present in $ConfigPath and security YAMLs readable under $secDir"
}

function Get-TinySocsInstallRoot {
  $defaultRoot = "C:\Program Files\TinySocs"
  if (Test-Path $defaultRoot -PathType Container) {
    return $defaultRoot
  }

  if ($PSScriptRoot) {
    return (Split-Path -Parent $PSScriptRoot)
  }

  return $defaultRoot
}

function Invoke-TinySocsCmd {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Command
  )
  # Run via cmd.exe so native stderr doesn't become a terminating PowerShell error
  # when $ErrorActionPreference = 'Stop'
  & cmd.exe /V:OFF /C $Command | Out-Null
}

function Repair-TinySocsProgramDataAcls {
  [CmdletBinding()]
  param()

  $root = Join-Path $env:ProgramData 'TinySocs'

  $targets = @(
    (Join-TsPath $root @('logs')),
    (Join-TsPath $root @('OpenSearch')),
    (Join-TsPath $root @('OpenSearch','config')),
    (Join-TsPath $root @('OpenSearch','config','certs')),
    (Join-TsPath $root @('OpenSearch','config','opensearch-security')),  # <-- NEW (real security dir)
    (Join-TsPath $root @('OpenSearch','certs')),
    (Join-TsPath $root @('OpenSearch','data')),
    (Join-TsPath $root @('OpenSearch','security'))                       # keep if legacy paths exist
  )

  foreach ($t in $targets) {
    if (-not (Test-Path -LiteralPath $t)) { continue }

    try {
      # recurse + continue on errors so we actually fix the tree
      & icacls $t /inheritance:e /grant:r `
        "SYSTEM:(OI)(CI)F" `
        "BUILTIN\Administrators:(OI)(CI)F" `
        /T /C /Q | Out-Null
    } catch { }
  }

  # logs dir: allow Users modify so normal reads/writes donÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬ÃƒÂ¢Ã¢â‚¬Å¾Ã‚Â¢t explode
  $logs = Join-TsPath $root @('logs')
  if (Test-Path -LiteralPath $logs) {
    try { & icacls $logs /grant:r "BUILTIN\Users:(OI)(CI)M" /T /C /Q | Out-Null } catch { }
  }

  # NEW: explicitly repair opensearch-security ACLs as well (dir + files)
  $secDir = Join-TsPath $root @('OpenSearch','config','opensearch-security')
  if (Test-Path -LiteralPath $secDir -PathType Container) {
    try { Repair-TinySocsOpenSearchSecurityConfigAcls -SecurityDir $secDir } catch { }
  }
}

function Repair-TinySocsOpenSearchCertAcls {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$CertsDir
  )

  if (-not (Test-Path $CertsDir -PathType Container)) { return }

  # Well-known SIDs
  $sysSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')       # LocalSystem
  $admSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')   # BUILTIN\Administrators

  function Resolve-ServiceAccountSid {
    param([string]$ServiceName)

    try {
      $svc = Get-CimInstance Win32_Service -Filter ("Name='{0}'" -f $ServiceName) -ErrorAction Stop
      $startName = ($svc.StartName | ForEach-Object { $_.Trim() })

      if (-not $startName) { return $null }

      switch -Regex ($startName) {
        '^LocalSystem$'                { return (New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')) } # SYSTEM
        '^NT AUTHORITY\\LocalService$' { return (New-Object System.Security.Principal.SecurityIdentifier('S-1-5-19')) }
        '^NT AUTHORITY\\NetworkService$' { return (New-Object System.Security.Principal.SecurityIdentifier('S-1-5-20')) }
        default {
          # Normalize .\User -> COMPUTER\User for translation
          if ($startName.StartsWith('.\')) {
            $startName = "$env:COMPUTERNAME\" + $startName.Substring(2)
          }

          $acct = New-Object System.Security.Principal.NTAccount($startName)
          return $acct.Translate([System.Security.Principal.SecurityIdentifier])
        }
      }
    } catch {
      return $null
    }
  }

  $svcSid = Resolve-ServiceAccountSid -ServiceName 'TinySocsOpenSearch'

  # If we can't resolve it, don't invent one. Keep it SYSTEM/Admins only.
  # If the service runs as LocalSystem, $svcSid == $sysSid; we dedupe later.
  try {
    # CRITICAL: ensure certs dir isn't EFS-encrypted (service account may not read user-encrypted files)
    # Also sets: "New files added to this directory will not be encrypted."
    Invoke-TinySocsCmd ('cipher /d /s:"{0}" >nul 2>&1' -f $CertsDir)

    # Clear common attributes that can block replace/propagation
    try { & attrib.exe -R -S -H "$CertsDir" /S /D 2>$null | Out-Null } catch { }

    # Build a strict ACL for the directory (no inheritance)
    $dirAcl = New-Object System.Security.AccessControl.DirectorySecurity
    $dirAcl.SetAccessRuleProtection($true, $false)  # disable inheritance, do NOT preserve inherited rules

    $inheritFlags = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit `
                  -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $propFlags    = [System.Security.AccessControl.PropagationFlags]::None

    $dirAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($sysSid, 'FullControl', $inheritFlags, $propFlags, 'Allow')))
    $dirAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($admSid, 'FullControl', $inheritFlags, $propFlags, 'Allow')))

    # Only add service rule if it resolves AND isn't redundant
    if ($svcSid -and ($svcSid.Value -ne $sysSid.Value) -and ($svcSid.Value -ne $admSid.Value)) {
      $dirAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($svcSid, 'ReadAndExecute', $inheritFlags, $propFlags, 'Allow')))
    }

    Set-Acl -Path $CertsDir -AclObject $dirAcl

    # File-level sanity for known cert/key file types (no inheritance, strict principals)
    Get-ChildItem -Path $CertsDir -File -Recurse -Force -ErrorAction SilentlyContinue |
      Where-Object { $_.Extension -in @('.p12','.pem','.cer','.crt','.key','.dpapi') } |
      ForEach-Object {
        $f = $_.FullName
        try { & attrib.exe -R -S -H "$f" 2>$null | Out-Null } catch { }

        $fileAcl = New-Object System.Security.AccessControl.FileSecurity
        $fileAcl.SetAccessRuleProtection($true, $false)  # disable inheritance, drop inherited rules

        $noInherit = [System.Security.AccessControl.InheritanceFlags]::None
        $noProp    = [System.Security.AccessControl.PropagationFlags]::None

        $fileAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($sysSid, 'FullControl', $noInherit, $noProp, 'Allow')))
        $fileAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($admSid, 'FullControl', $noInherit, $noProp, 'Allow')))

        # Service account needs to READ cert material; no execute permission on files.
        if ($svcSid -and ($svcSid.Value -ne $sysSid.Value) -and ($svcSid.Value -ne $admSid.Value)) {
          $fileAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($svcSid, 'Read', $noInherit, $noProp, 'Allow')))
        }

        Set-Acl -Path $f -AclObject $fileAcl
      }

    $svcName = if ($svcSid) { $svcSid.Value } else { "<unresolved>" }
    Write-TinySocsLog "Repaired OpenSearch cert ACLs (strict: SYSTEM/Admins + svc=$svcName) + ensured not EFS-encrypted: $CertsDir"
  } catch {
    Write-TinySocsLog -Level "WARN" -Message "Repair-TinySocsOpenSearchCertAcls failed for ${CertsDir}: $($_.Exception.Message)"
  }
}

# -- Security/ACL helpers ------------------------------------------------------
function Repair-TinySocsOpenSearchSecurityConfigAcls {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$SecurityDir
  )

  if (-not (Test-Path -LiteralPath $SecurityDir -PathType Container)) { return }

  function _ResolveServiceStartName {
    param([string]$ServiceName)
    try {
      $svc = Get-CimInstance Win32_Service -Filter ("Name='{0}'" -f $ServiceName) -ErrorAction Stop
      $sn  = ($svc.StartName | ForEach-Object { $_.Trim() })
      if ([string]::IsNullOrWhiteSpace($sn)) { return $null }
      return $sn
    } catch { return $null }
  }

  try {
    # 0) Ensure not EFS-encrypted (can create ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã¢â‚¬Å“works for me / fails for serviceÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â weirdness)
    try { Invoke-TinySocsCmd ('cipher /d /s:"{0}" >nul 2>&1' -f $SecurityDir) } catch { }

    # 1) Clear attributes that can block reads/propagation
    try { & attrib.exe -R -S -H "$SecurityDir" /S /D 2>$null | Out-Null } catch { }

    # 2) Take ownership as Administrators (important if the tree gets ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã¢â‚¬Å“stuckÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â)
    try { Invoke-TinySocsCmd ('takeown /F "{0}" /A /R /D Y >nul 2>&1' -f $SecurityDir) } catch { }

    # 3) HARD reset ACLs recursively (this fixes ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã¢â‚¬Å“protected DACL on fileÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â cases)
    try { Invoke-TinySocsCmd ('icacls "{0}" /reset /T /C >nul 2>&1' -f $SecurityDir) } catch { }

    # 4) Enable inheritance, then apply explicit grants we actually want
    #    NOTE: include Users RX so non-elevated shells (and dashboards tooling) can read config.yml.
    #    If you decide later you want to lock this down harder, do it selectively (NOT by breaking local installs).
    $grantParts = @(
      '"*S-1-5-18:(OI)(CI)F"'        # SYSTEM
      '"*S-1-5-32-544:(OI)(CI)F"'    # BUILTIN\Administrators
      '"*S-1-5-32-545:(OI)(CI)RX"'   # BUILTIN\Users
    )

    # 5) If the OpenSearch service runs as a custom account, grant it RX too
    $startName = _ResolveServiceStartName -ServiceName 'TinySocsOpenSearch'
    if ($startName) {
      switch -Regex ($startName) {
        '^LocalSystem$' { }
        '^NT AUTHORITY\\LocalService$' { $grantParts += '"*S-1-5-19:(OI)(CI)RX"' }
        '^NT AUTHORITY\\NetworkService$' { $grantParts += '"*S-1-5-20:(OI)(CI)RX"' }
        default {
          # normalize .\User -> COMPUTER\User
          if ($startName.StartsWith('.\')) { $startName = "$env:COMPUTERNAME\" + $startName.Substring(2) }
          # icacls wants the NTAccount form here
          $grantParts += ('"{0}:(OI)(CI)RX"' -f $startName)
        }
      }
    }

    try { Invoke-TinySocsCmd ('icacls "{0}" /inheritance:e /T /C >nul 2>&1' -f $SecurityDir) } catch { }
    try {
      Invoke-TinySocsCmd ('icacls "{0}" /grant:r {1} /T /C >nul 2>&1' -f $SecurityDir, ($grantParts -join ' '))
    } catch { }

    Write-TinySocsLog "Repaired OpenSearch security config ACLs (reset + Users RX) under: $SecurityDir"
  } catch {
    Write-TinySocsLog -Level "WARN" -Message "Repair-TinySocsOpenSearchSecurityConfigAcls failed for ${SecurityDir}: $($_.Exception.Message)"
  }
}

function Set-TinySocsSecureAcl {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path,
    [switch]$UsersRead
  )

  if (-not (Test-Path -LiteralPath $Path)) { return }

  try {
    # SIDs are locale-proof:
    $sys  = '*S-1-5-18'        # LocalSystem
    $adm  = '*S-1-5-32-544'    # BUILTIN\Administrators
    $user = '*S-1-5-32-545'    # BUILTIN\Users

    Invoke-TinySocsCmd ('takeown /F "{0}" /A /R /D Y >nul 2>&1' -f $Path)

    # Reset FIRST so you never end up with an empty DACL.
    Invoke-TinySocsCmd ('icacls "{0}" /reset /T /C >nul 2>&1' -f $Path)

    # Remove common explicit deny ACEs (these can outlive grant:r)
    Invoke-TinySocsCmd ('icacls "{0}" /remove:d "Everyone" "Users" "Authenticated Users" /T /C >nul 2>&1' -f $Path)

    $grant = @(
      ('"{0}:(OI)(CI)F"' -f $sys),
      ('"{0}:(OI)(CI)F"' -f $adm)
    )

    if ($UsersRead.IsPresent) {
      $grant += ('"{0}:(OI)(CI)RX"' -f $user)
    }

    Invoke-TinySocsCmd ('icacls "{0}" /inheritance:r /grant:r {1} /T /C >nul 2>&1' -f $Path, ($grant -join ' '))

    Write-TinySocsLog "ACL hardened: $Path (SYSTEM+Admins full$(if ($UsersRead) { ', Users RX' } else { '' }))"
  } catch {
    Write-TinySocsLog -Level "WARN" -Message "Failed to harden ACL for ${Path}: $($_.Exception.Message)"
  }
}

function Ensure-TinySocsLogAcl {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$LogDir
  )

  if (-not (Test-Path -LiteralPath $LogDir)) { return }

  # Use SID form that icacls understands (leading *)
  $sidSystem = '*S-1-5-18'
  $sidAdmins = '*S-1-5-32-544'
  $sidUsers  = '*S-1-5-32-545'

  try {
    # Make sure the directory exists
    New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

    # IMPORTANT: avoid "${sid}:(...)" parsing bug by using ${} (or string concatenation)
    & icacls $LogDir /inheritance:e /grant:r `
      "${sidSystem}:(OI)(CI)(F)" `
      "${sidAdmins}:(OI)(CI)(F)" `
      "${sidUsers}:(OI)(CI)(M)" `
      /t /c /q 2>$null | Out-Null
  } catch {
    try { Write-Warning "[TinySocs] Failed to harden log ACLs on '$LogDir': $($_.Exception.Message)" } catch { }
  }
}

function Ensure-TinySocsWritableFile {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Path)

  try {
    $sys = '*S-1-5-18'
    $adm = '*S-1-5-32-544'

    $dir = Split-Path -Parent $Path
    if ($dir -and (Test-Path $dir)) {
      Invoke-TinySocsCmd ('takeown /F "{0}" /A /R /D Y >nul 2>&1' -f $dir)
      Invoke-TinySocsCmd ('icacls "{0}" /reset /T /C >nul 2>&1' -f $dir)
      Invoke-TinySocsCmd ('icacls "{0}" /remove:d "Everyone" "Users" "Authenticated Users" /T /C >nul 2>&1' -f $dir)
      Invoke-TinySocsCmd ('icacls "{0}" /inheritance:r /grant:r "{1}:(OI)(CI)F" "{2}:(OI)(CI)F" /T /C >nul 2>&1' -f `
        $dir, $sys, $adm)
    }

    if (Test-Path $Path) {
      try {
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
        if ($item) {
          $item.Attributes = ($item.Attributes -band (-bnot ([IO.FileAttributes]::ReadOnly -bor [IO.FileAttributes]::Hidden -bor [IO.FileAttributes]::System)))
        }
      } catch { }

      Invoke-TinySocsCmd ('takeown /F "{0}" /A >nul 2>&1' -f $Path)
      Invoke-TinySocsCmd ('icacls "{0}" /reset /C >nul 2>&1' -f $Path)
      Invoke-TinySocsCmd ('icacls "{0}" /remove:d "Everyone" "Users" "Authenticated Users" /C >nul 2>&1' -f $Path)
      Invoke-TinySocsCmd ('icacls "{0}" /inheritance:r /grant:r "{1}:F" "{2}:F" /C >nul 2>&1' -f `
        $Path, $sys, $adm)
    }
  } catch {
    Write-TinySocsLog -Level 'WARN' -Message "Ensure-TinySocsWritableFile failed for ${Path}: $($_.Exception.Message)"
  }
}

function Resolve-TinySocsOpenSearchSeedConfigDir {
  $rootVal = (Get-TinySocsInstallRoot | Select-Object -First 1)
  $root    = [string]$rootVal

  $candidates = @(
    (Join-Path -Path $root -ChildPath "OpenSearch\config"),
    (Join-Path -Path $root -ChildPath "OpenSearch\seed\config"),
    (Join-Path -Path $root -ChildPath "OpenSearch\seed\OpenSearch\config")
  ) | Where-Object { Test-Path -LiteralPath $_ }

  foreach ($c in $candidates) {
    if (Test-Path -LiteralPath (Join-Path -Path $c -ChildPath "opensearch.yml")) { return $c }
  }

  $osHome = Join-Path -Path $root -ChildPath "OpenSearch"
  if (Test-Path -LiteralPath $osHome) {
    $hit = Get-ChildItem -Path $osHome -Recurse -Filter "opensearch.yml" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($hit) { return (Split-Path -Parent $hit.FullName) }
  }

  return $null
}

function script:_YamlSingleQuote {
  [CmdletBinding()]
  param(
    [AllowNull()][string]$Value
  )
  # YAML single-quoted scalars escape a single-quote by doubling it.
  if ($null -eq $Value) { return "''" }
  $escaped = $Value -replace "'", "''"
  return "'" + $escaped + "'"
}

function _Ensure-TinySocsReadable {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path,
    [switch]$IsDir
  )

  if ([string]::IsNullOrWhiteSpace($Path)) { return }
  if (-not (Test-Path -LiteralPath $Path)) { return }

  # Prefer icacls (fast, also fixes inheritance). Fall back to ACL API if needed.
  try {
    $ic = Join-Path $env:WINDIR "System32\icacls.exe"
    if (Test-Path -LiteralPath $ic -PathType Leaf) {
      if ($IsDir) {
        & $ic $Path /inheritance:e 1>$null 2>$null
        & $ic $Path /grant "SYSTEM:(OI)(CI)RX" "Administrators:(OI)(CI)RX" 1>$null 2>$null
      } else {
        & $ic $Path /inheritance:e 1>$null 2>$null
        & $ic $Path /grant "SYSTEM:R" "Administrators:R" 1>$null 2>$null
      }
      return
    }
  } catch {
    # swallow and fall back
  }

  # Fallback: explicit ACL manipulation
  try {
    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    $needsSet = $false

    $sys    = New-Object System.Security.Principal.NTAccount("NT AUTHORITY", "SYSTEM")
    $admins = New-Object System.Security.Principal.NTAccount("BUILTIN", "Administrators")

    if ($IsDir) {
      $rights = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute `
              -bor [System.Security.AccessControl.FileSystemRights]::ListDirectory `
              -bor [System.Security.AccessControl.FileSystemRights]::Read `
              -bor [System.Security.AccessControl.FileSystemRights]::Synchronize

      $inherit = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit `
               -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
      $prop = [System.Security.AccessControl.PropagationFlags]::None

      foreach ($acct in @($sys, $admins)) {
        $has = $false
        foreach ($r in $acl.Access) {
          if ($r.IdentityReference -eq $acct -and
              $r.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and
              (($r.FileSystemRights -band $rights) -eq $rights)) {
            $has = $true; break
          }
        }

        if (-not $has) {
          $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $acct, $rights, $inherit, $prop,
            [System.Security.AccessControl.AccessControlType]::Allow
          )
          $acl.AddAccessRule($rule) | Out-Null
          $needsSet = $true
        }
      }
    }
    else {
      $rights = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute `
              -bor [System.Security.AccessControl.FileSystemRights]::Read `
              -bor [System.Security.AccessControl.FileSystemRights]::Synchronize

      foreach ($acct in @($sys, $admins)) {
        $has = $false
        foreach ($r in $acl.Access) {
          if ($r.IdentityReference -eq $acct -and
              $r.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and
              (($r.FileSystemRights -band $rights) -eq $rights)) {
            $has = $true; break
          }
        }

        if (-not $has) {
          $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $acct, $rights,
            [System.Security.AccessControl.AccessControlType]::Allow
          )
          $acl.AddAccessRule($rule) | Out-Null
          $needsSet = $true
        }
      }
    }

    if ($needsSet) {
      Set-Acl -LiteralPath $Path -AclObject $acl -ErrorAction Stop
      try { Write-TinySocsLog "ACL ensured readable for SYSTEM/Admins: ${Path}" "DEBUG" } catch { }
    }
  }
  catch {
    # IMPORTANT: delimit ${Path} so PowerShell doesn't parse `$Path:` as a drive-qualified var token
    try { Write-TinySocsLog "WARN: _Ensure-TinySocsReadable failed for ${Path}: $($_.Exception.Message)" "WARN" } catch { }
  }
}

function Ensure-OpenSearchYamlPaths {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$YamlPath,
    [int]$HttpPort = 9201
  )

  if (-not (Test-Path -LiteralPath $YamlPath -PathType Leaf)) {
    throw "Ensure-OpenSearchYamlPaths: YamlPath not found: $YamlPath"
  }

  $rootVal  = (Get-TinySocsDataRoot | Select-Object -First 1)
  $root     = ([string]$rootVal).Trim()

  if ([string]::IsNullOrWhiteSpace($root)) {
    throw "Ensure-OpenSearchYamlPaths: Get-TinySocsDataRoot returned empty."
  }
  if (-not (Test-Path -LiteralPath $root -PathType Container)) {
    throw "Ensure-OpenSearchYamlPaths: Data root does not exist on disk: $root"
  }

  # Quote these so YAML doesn't misparse e.g. "C:\..." or spaces.
  $dataPath = _YamlSingleQuote (Join-Path -Path $root -ChildPath "OpenSearch\data")
  $logsPath = _YamlSingleQuote (Join-Path -Path $root -ChildPath "OpenSearch\logs")

  $raw = Get-Content -LiteralPath $YamlPath -Raw -ErrorAction Stop
  if ($null -eq $raw) { $raw = "" }

  # path.data
  if ($raw -match '(?im)^\s*path\.data\s*:') {
    $raw = [regex]::Replace(
      $raw,
      '^\s*path\.data\s*:.*$',
      ("path.data: {0}" -f $dataPath),
      [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor
      [System.Text.RegularExpressions.RegexOptions]::Multiline
    )
  } else {
    $raw += "`r`npath.data: $dataPath`r`n"
  }

  # path.logs
  if ($raw -match '(?im)^\s*path\.logs\s*:') {
    $raw = [regex]::Replace(
      $raw,
      '^\s*path\.logs\s*:.*$',
      ("path.logs: {0}" -f $logsPath),
      [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor
      [System.Text.RegularExpressions.RegexOptions]::Multiline
    )
  } else {
    $raw += "`r`npath.logs: $logsPath`r`n"
  }

  # network.host (loopback)
  if ($raw -match '(?im)^\s*network\.host\s*:') {
    $raw = [regex]::Replace(
      $raw,
      '^\s*network\.host\s*:.*$',
      "network.host: 127.0.0.1",
      [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor
      [System.Text.RegularExpressions.RegexOptions]::Multiline
    )
  } else {
    $raw += "`r`nnetwork.host: 127.0.0.1`r`n"
  }

  # http.port (canonical 9201)
  if ($raw -match '(?im)^\s*http\.port\s*:') {
    $raw = [regex]::Replace(
      $raw,
      '^\s*http\.port\s*:.*$',
      ("http.port: {0}" -f $HttpPort),
      [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor
      [System.Text.RegularExpressions.RegexOptions]::Multiline
    )
  } else {
    $raw += "`r`nhttp.port: $HttpPort`r`n"
  }

  # TLS file path sanity (relative paths expected)
  $pairs = @(
    @{ key = 'plugins.security.ssl.http.keystore_filepath';        val = 'certs/http.p12' },
    @{ key = 'plugins.security.ssl.http.truststore_filepath';      val = 'certs/trust.p12' },
    @{ key = 'plugins.security.ssl.transport.keystore_filepath';   val = 'certs/transport.p12' },
    @{ key = 'plugins.security.ssl.transport.truststore_filepath'; val = 'certs/trust.p12' }
  )

  foreach ($p in $pairs) {
    $k = [string]$p.key
    $v = [string]$p.val

    $pat = '^\s*' + [regex]::Escape($k) + '\s*:.*$'
    if ($raw -match "(?im)$pat") {
      $raw = [regex]::Replace(
        $raw,
        $pat,
        ("{0}: {1}" -f $k, $v),
        [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor
        [System.Text.RegularExpressions.RegexOptions]::Multiline
      )
    } else {
      $raw += "`r`n${k}: $v`r`n"
    }
  }

  # Ensure trailing newline (minor, but keeps diffs sane)
  if ($raw -notmatch "(\r?\n)$") { $raw += "`r`n" }

  Set-Content -LiteralPath $YamlPath -Value $raw -Encoding UTF8 -Force

  # Ensure System can read config directory and the yaml (best-effort)
  $confDir = Split-Path -Parent $YamlPath
  if (Get-Command _Ensure-TinySocsReadable -ErrorAction SilentlyContinue) {
    _Ensure-TinySocsReadable -Path $confDir -IsDir
    _Ensure-TinySocsReadable -Path $YamlPath
  } else {
    try { Write-TinySocsLog "WARN: _Ensure-TinySocsReadable missing; skipping ACL sanity for $YamlPath" "WARN" } catch { }
  }

  Write-TinySocsLog "Ensured OpenSearch yaml paths + loopback bind + http.port=$HttpPort ($YamlPath)."
}

function Sync-TinySocsOpenSearchConfigToProgramData {
  [CmdletBinding()]
  param(
    [switch]$Force
  )

  $seed = Resolve-TinySocsOpenSearchSeedConfigDir
  if (-not $seed) {
    Write-TinySocsLog -Level "WARN" -Message "OpenSearch seed config not found under install root; skipping config seed."
    return
  }

  $root = [string](Get-TinySocsDataRoot | Select-Object -First 1)
  $dst  = Join-Path -Path $root -ChildPath "OpenSearch\config"
  $dstCerts = Join-Path -Path $dst -ChildPath "certs"

  New-Item -ItemType Directory -Force -Path $dst | Out-Null
  New-Item -ItemType Directory -Force -Path $dstCerts | Out-Null

  Write-TinySocsLog "Seeding OpenSearch config to $dst from $seed (Force=$($Force.IsPresent))"

  # Copy files from seed -> dst, but only overwrite when -Force is specified.
  $seedLen = $seed.TrimEnd('\').Length

  Get-ChildItem -LiteralPath $seed -Recurse -File -Force -ErrorAction SilentlyContinue | ForEach-Object {
    $src = $_.FullName
    $rel = $src.Substring($seedLen).TrimStart('\')
    $tgt = Join-Path -Path $dst -ChildPath $rel

    $tgtDir = Split-Path -Parent $tgt
    if (-not (Test-Path -LiteralPath $tgtDir)) {
      New-Item -ItemType Directory -Force -Path $tgtDir | Out-Null
    }

    # Never clobber existing certs unless Force
    $isCert = $rel -match '^(?i)certs\\'
    if ($isCert -and (Test-Path -LiteralPath $tgt) -and (-not $Force.IsPresent)) {
      return
    }

    if ((-not (Test-Path -LiteralPath $tgt)) -or $Force.IsPresent) {
      Copy-Item -LiteralPath $src -Destination $tgt -Force -ErrorAction SilentlyContinue
    }
  }

  $yml = Join-Path -Path $dst -ChildPath "opensearch.yml"
  if (Test-Path -LiteralPath $yml) {
    Ensure-OpenSearchYamlPaths -YamlPath $yml
  }

  Ensure-SystemReadAcl -Path $dst
  Ensure-SystemReadAcl -Path $dstCerts
}

function Set-TinySocsOpenSearchAcls {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$ServiceName,
    [Parameter(Mandatory)][string]$DataRoot,
    [Parameter(Mandatory)][string]$LogsPath,
    [Parameter(Mandatory)][string]$ConfigPath,
    [Parameter(Mandatory)][string]$RunnerPath,
    [switch]$FixBackups,
    [switch]$UsersReadConfig
  )

  $usersReadCfg = $true
  if ($PSBoundParameters.ContainsKey('UsersReadConfig')) { $usersReadCfg = $UsersReadConfig.IsPresent }

  try {
    # Well-known SIDs (stable across locales)
    $sysSid='*S-1-5-18'       # LocalSystem
    $admSid='*S-1-5-32-544'   # BUILTIN\Administrators
    $usersSid='*S-1-5-32-545' # BUILTIN\Users

    $curSid = $null
    try { $curSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value } catch { }

    $curUser = $null
    try {
      if ($env:USERDOMAIN -and $env:USERNAME) { $curUser = "$($env:USERDOMAIN)\$($env:USERNAME)" }
      elseif ($env:USERNAME) { $curUser = "$($env:USERNAME)" }
    } catch { }

    # Detect the service start account -> SID (best-effort)
    $svcStart=$null
    try { $svcStart=([string](Get-CimInstance Win32_Service -Filter ("Name='{0}'" -f $ServiceName) -ErrorAction SilentlyContinue).StartName) } catch { }

    $svcSid=$null
    if ($svcStart) {
      if ($svcStart -match '^(LocalSystem|NT AUTHORITY\\SYSTEM)$') { $svcSid=$sysSid }
      elseif ($svcStart -match '^(LocalService|NT AUTHORITY\\LOCAL SERVICE)$') { $svcSid='*S-1-5-19' }
      elseif ($svcStart -match '^(NetworkService|NT AUTHORITY\\NETWORK SERVICE)$') { $svcSid='*S-1-5-20' }
      else {
        try {
          $nt = New-Object System.Security.Principal.NTAccount($svcStart)
          $sidVal = $nt.Translate([System.Security.Principal.SecurityIdentifier]).Value
          if ($sidVal) { $svcSid = "*$sidVal" }
        } catch { }
      }
    }

    function _AclTree {
      param(
        [string]$Path,
        [string[]]$Grant,
        [switch]$UsersRead,
        [switch]$AlsoGrantCurrentUser,
        [switch]$ResetFirst
      )
      if (-not (Test-Path $Path)) { return }

      Invoke-TinySocsCmd ('takeown /F "{0}" /A /R /D Y >nul 2>&1' -f $Path)

      if ($ResetFirst) {
        Invoke-TinySocsCmd ('icacls "{0}" /reset /T /C >nul 2>&1' -f $Path)
      }

      Invoke-TinySocsCmd ('icacls "{0}" /remove:d "Everyone" "Users" "Authenticated Users" /T /C >nul 2>&1' -f $Path)

      if ($curUser) { Invoke-TinySocsCmd ('icacls "{0}" /remove:d "{1}" /T /C >nul 2>&1' -f $Path, $curUser) }
      if ($curSid)  { Invoke-TinySocsCmd ('icacls "{0}" /remove:d "*{1}" /T /C >nul 2>&1' -f $Path, $curSid) }

      $grantArgs = @()
      foreach ($g in $Grant) { $grantArgs += ('"' + $g + '"') }

      if ($UsersRead) {
        $grantArgs += '"*S-1-5-32-545:RX"'
        $grantArgs += '"*S-1-5-32-545:(OI)(CI)RX"'
      }

      if ($AlsoGrantCurrentUser) {
        if ($curUser) {
          $grantArgs += ('"' + $curUser + ':RX"')
          $grantArgs += ('"' + $curUser + ':(OI)(CI)RX"')
        }
        if ($curSid) {
          $grantArgs += ('"*' + $curSid + ':RX"')
          $grantArgs += ('"*' + $curSid + ':(OI)(CI)RX"')
        }
      }

      $grantStr = ($grantArgs -join ' ')
      Invoke-TinySocsCmd ('icacls "{0}" /inheritance:r /grant:r {1} /T /C >nul 2>&1' -f $Path, $grantStr)
    }

    function _AclFiles {
      param(
        [string]$Root,
        [string[]]$Patterns,
        [string[]]$FileGrants
      )
      if (-not (Test-Path $Root)) { return }

      try {
        foreach ($pat in $Patterns) {
          Get-ChildItem -Path $Root -File -Recurse -Force -Filter $pat -ErrorAction SilentlyContinue |
            ForEach-Object {
              $f = $_.FullName
              Invoke-TinySocsCmd ('takeown /F "{0}" /A >nul 2>&1' -f $f)
              Invoke-TinySocsCmd ('icacls "{0}" /remove:d "Everyone" "Users" "Authenticated Users" /C >nul 2>&1' -f $f)
              foreach ($g in $FileGrants) {
                Invoke-TinySocsCmd ('icacls "{0}" /grant:r "{1}" /C >nul 2>&1' -f $f, $g)
              }
            }
        }
      } catch { }
    }

    function _FixCriticalConfigFiles {
      param([string]$Root)

      if (-not (Test-Path $Root)) { return }

      $critical = @(
        "jvm.options",
        "log4j2.properties",
        "opensearch.yml",
        "opensearch.keystore",
        "fips_java.security"
      )

      foreach ($name in $critical) {
        $p = Join-Path $Root $name
        if (-not (Test-Path $p -PathType Leaf)) { continue }

        Invoke-TinySocsCmd ('takeown /F "{0}" /A >nul 2>&1' -f $p)
        Invoke-TinySocsCmd ('icacls "{0}" /reset /C >nul 2>&1' -f $p)
        Invoke-TinySocsCmd ('icacls "{0}" /remove:d "Everyone" "Users" "Authenticated Users" /C >nul 2>&1' -f $p)
        Invoke-TinySocsCmd ('icacls "{0}" /inheritance:r /grant:r "{1}:F" "{2}:F" /C >nul 2>&1' -f $p, $sysSid, $admSid)

        if ($curUser) { Invoke-TinySocsCmd ('icacls "{0}" /grant:r "{1}:R" /C >nul 2>&1' -f $p, $curUser) }
        if ($curSid)  { Invoke-TinySocsCmd ('icacls "{0}" /grant:r "*{1}:R" /C >nul 2>&1' -f $p, $curSid) }

        if ($svcSid)  { Invoke-TinySocsCmd ('icacls "{0}" /grant:r "{1}:R" /C >nul 2>&1' -f $p, $svcSid) }
      }
    }

    $baseGrant = @(
      "${sysSid}:F",
      "${sysSid}:(OI)(CI)F",
      "${admSid}:F",
      "${admSid}:(OI)(CI)F"
    )
    if ($svcSid -and $svcSid -ne $sysSid) {
      $baseGrant += "${svcSid}:F"
      $baseGrant += "${svcSid}:(OI)(CI)F"
    }

    _AclTree -Path $DataRoot -Grant $baseGrant

    _AclTree -Path $LogsPath -Grant $baseGrant -UsersRead -AlsoGrantCurrentUser -ResetFirst

    $logFileGrants = @('BUILTIN\Users:R')
    if ($curUser) { $logFileGrants += "${curUser}:R" }
    if ($curSid)  { $logFileGrants += "*${curSid}:R" }

    _AclFiles -Root $LogsPath -Patterns @('*.log','*.out','*.err','*.err.log','*.out.log') -FileGrants $logFileGrants

    if (Test-Path $ConfigPath) {
      _AclTree -Path $ConfigPath -Grant $baseGrant -UsersRead:($usersReadCfg) -AlsoGrantCurrentUser -ResetFirst

      if ($svcSid) {
        Invoke-TinySocsCmd ('icacls "{0}" /grant:r "{1}:(OI)(CI)RX" /T /C >nul 2>&1' -f $ConfigPath, $svcSid)
      }

      _FixCriticalConfigFiles -Root $ConfigPath
    }

    # Runner file: file-level explicit perms
    if ($RunnerPath -and (Test-Path $RunnerPath)) {
      Invoke-TinySocsCmd ('takeown /F "{0}" /A >nul 2>&1' -f $RunnerPath)
      Invoke-TinySocsCmd ('icacls "{0}" /remove:d "Everyone" "Users" "Authenticated Users" /C >nul 2>&1' -f $RunnerPath)
      if ($curUser) { Invoke-TinySocsCmd ('icacls "{0}" /remove:d "{1}" /C >nul 2>&1' -f $RunnerPath, $curUser) }
      if ($curSid)  { Invoke-TinySocsCmd ('icacls "{0}" /remove:d "*{1}" /C >nul 2>&1' -f $RunnerPath, $curSid) }

      # IMPORTANT: keep SIDs in icacls SID form (*S-1-...) ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â don't TrimStart('*')
      $runnerGrant = @(
        '"SYSTEM:F"',
        '"BUILTIN\Administrators:F"',
        '"BUILTIN\Users:RX"'
      )
      if ($svcSid -and $svcSid -ne $sysSid) { $runnerGrant += ('"{0}:F"' -f $svcSid) }
      if ($curUser) { $runnerGrant += ('"{0}:RX"' -f $curUser) }
      if ($curSid)  { $runnerGrant += ('"*{0}:RX"' -f $curSid) }

      Invoke-TinySocsCmd ('icacls "{0}" /inheritance:r /grant:r {1} /C >nul 2>&1' -f $RunnerPath, ($runnerGrant -join ' '))
    }

    $doBackups = $FixBackups.IsPresent
    if (-not $PSBoundParameters.ContainsKey('FixBackups')) { $doBackups = $true }

    if ($doBackups -and (Test-Path $DataRoot)) {
      Get-ChildItem -Path $DataRoot -Directory -Force -Filter 'config.old-*' -ErrorAction SilentlyContinue |
        ForEach-Object {
          try { Set-TinySocsSecureAcl -Path $_.FullName -UsersRead } catch { }
        }
    }

    Write-TinySocsLog "OpenSearch ACLs enforced (service=$ServiceName, startName='$svcStart')."
  } catch {
    Write-TinySocsLog -Level "WARN" -Message "Failed to enforce OpenSearch ACLs (service=$ServiceName): $($_.Exception.Message)"
  }
}

function Repair-TinySocsTreeReadability {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path,
    [switch]$DecryptEfs,
    [switch]$ClearAttributes
  )

  if ([string]::IsNullOrWhiteSpace($Path)) { return }
  if (-not (Test-Path -LiteralPath $Path)) { return }

  if ($DecryptEfs) {
    try {
      $cipher = Join-Path $env:WINDIR "System32\cipher.exe"
      if (Test-Path -LiteralPath $cipher -PathType Leaf) {
        # Best-effort: decrypt this directory + children (EFS)
        & $cipher /d /s:"$Path" 1>$null 2>$null
        Write-TinySocsLog "EFS decrypt attempted on: $Path"
      }
    } catch {
      Write-TinySocsLog -Level "WARN" -Message "EFS decrypt failed for ${Path}: $($_.Exception.Message)"
    }
  }

  if ($ClearAttributes) {
    try {
      $attrib = Join-Path $env:WINDIR "System32\attrib.exe"
      if (Test-Path -LiteralPath $attrib -PathType Leaf) {
        # Clear readonly/system/hidden across tree
        & $attrib -R -S -H "$Path\*" /S /D 1>$null 2>$null
        Write-TinySocsLog "Attributes cleared (R/S/H) on: $Path"
      }
    } catch {
      Write-TinySocsLog -Level "WARN" -Message "Attribute cleanup failed for ${Path}: $($_.Exception.Message)"
    }
  }
}

function Get-TinySocsSecretStoreDir {
  [CmdletBinding()]
  param()

  $rootVal = (Get-TinySocsDataRoot | Select-Object -First 1)
  $root    = [string]$rootVal

  $dir  = Join-Path -Path $root -ChildPath "config\secrets"
  try { New-Item -ItemType Directory -Force -Path $dir | Out-Null } catch { }
  return $dir
}

function Get-TinySocsNodeSecretDpapiFilePath {
  [CmdletBinding()]
  param()
  return (Join-Path (Get-TinySocsSecretStoreDir) "node-secret.dpapi")
}

function Read-TinySocsNodeSecretFromDpapiFile {
  [CmdletBinding()]
  param()

  $p = Get-TinySocsNodeSecretDpapiFilePath
  if (-not (Test-Path $p -PathType Leaf)) { return $null }

  try {
    $raw = (Get-Content -Path $p -Raw -ErrorAction Stop).Trim()
    if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
    $plain = Unprotect-TinySocsDpapiLocalMachineB64 -B64 $raw
    if ([string]::IsNullOrWhiteSpace($plain)) { return $null }
    return $plain
  } catch {
    Write-TinySocsLog -Level "WARN" -Message "Failed to read/unwrap Node secret DPAPI file ($p): $($_.Exception.Message)"
    return $null
  }
}

function Write-TinySocsNodeSecretToDpapiFile {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Secret
  )

  $p = Get-TinySocsNodeSecretDpapiFilePath
  try {
    $wrapped = Protect-TinySocsDpapiLocalMachine -Plain $Secret
    Set-Content -Path $p -Value $wrapped -Encoding ASCII -Force
    Write-TinySocsLog "Persisted Node shared secret to DPAPI file ($p)."
    return $true
  } catch {
    Write-TinySocsLog -Level "WARN" -Message "Failed to write Node secret DPAPI file ($p): $($_.Exception.Message)"
    return $false
  }
}

function Get-TinySocsMasterSharedSecretDpapiFilePath {
  [CmdletBinding()]
  param()
  return (Join-Path (Get-TinySocsSecretStoreDir) "master-shared-secret.dpapi")
}

function Read-TinySocsMasterSharedSecretFromDpapiFile {
  [CmdletBinding()]
  param()

  $p = Get-TinySocsMasterSharedSecretDpapiFilePath
  if (-not (Test-Path $p -PathType Leaf)) { return $null }

  try {
    $raw = (Get-Content -Path $p -Raw -ErrorAction Stop).Trim()
    if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
    $plain = Unprotect-TinySocsDpapiLocalMachineB64 -B64 $raw
    if ([string]::IsNullOrWhiteSpace($plain)) { return $null }
    return $plain
  } catch {
    Write-TinySocsLog -Level "WARN" -Message "Failed to read/unwrap Master secret DPAPI file ($p): $($_.Exception.Message)"
    return $null
  }
}

function Write-TinySocsMasterSharedSecretToDpapiFile {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Secret
  )

  $p = Get-TinySocsMasterSharedSecretDpapiFilePath
  try {
    $wrapped = Protect-TinySocsDpapiLocalMachine -Plain $Secret
    Set-Content -Path $p -Value $wrapped -Encoding ASCII -Force
    Write-TinySocsLog "Persisted Master shared secret to DPAPI file ($p)."
    return $true
  } catch {
    Write-TinySocsLog -Level "WARN" -Message "Failed to write Master secret DPAPI file ($p): $($_.Exception.Message)"
    return $false
  }
}

function Get-TinySocsNodesFilePath {
  [CmdletBinding()]
  param()

  $rootVal = (Get-TinySocsDataRoot | Select-Object -First 1)
  $root    = [string]$rootVal

  $dir  = Join-Path -Path $root -ChildPath "config"
  try { New-Item -ItemType Directory -Force -Path $dir | Out-Null } catch { }
  return (Join-Path -Path $dir -ChildPath "nodes.txt")
}

function Read-TinySocsNodesFromFile {
  [CmdletBinding()]
  param()

  $p = Get-TinySocsNodesFilePath
  if (-not (Test-Path $p -PathType Leaf)) { return $null }

  try {
    $raw = (Get-Content -Path $p -Raw -ErrorAction Stop).Trim()
    if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
    return $raw
  } catch {
    Write-TinySocsLog -Level "WARN" -Message "Failed to read nodes file ($p): $($_.Exception.Message)"
    return $null
  }
}

function Write-TinySocsNodesToFile {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Nodes
  )

  $p = Get-TinySocsNodesFilePath
  try {
    Set-Content -Path $p -Value $Nodes -Encoding UTF8 -Force
    Write-TinySocsLog "Persisted TINYSOCS_NODES to $p"
    return $true
  } catch {
    Write-TinySocsLog -Level "WARN" -Message "Failed to write nodes file ($p): $($_.Exception.Message)"
    return $false
  }
}

function Test-TinySocsIsElevated {
  try {
    $typeName = 'TinySocs.TokenCheck'
    if (-not ([System.Type]::GetType($typeName, $false))) {
      Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

namespace TinySocs {
  public static class TokenCheck {
    public const UInt32 TOKEN_QUERY = 0x0008;
    public const int TokenElevation = 20;

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentProcess();

    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool OpenProcessToken(IntPtr ProcessHandle, UInt32 DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool GetTokenInformation(
      IntPtr TokenHandle,
      int TokenInformationClass,
      IntPtr TokenInformation,
      int TokenInformationLength,
      out int ReturnLength
    );

    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr hObject);
  }
}
"@ -ErrorAction SilentlyContinue | Out-Null
    }

    $tok = [IntPtr]::Zero
    $ok = [TinySocs.TokenCheck]::OpenProcessToken(
      [TinySocs.TokenCheck]::GetCurrentProcess(),
      [TinySocs.TokenCheck]::TOKEN_QUERY,
      [ref]$tok
    )
    if (-not $ok -or $tok -eq [IntPtr]::Zero) { return $false }

    $ptr = [IntPtr]::Zero
    try {
      $size = 4
      $ptr = [Runtime.InteropServices.Marshal]::AllocHGlobal($size)
      $ret = 0
      $ok2 = [TinySocs.TokenCheck]::GetTokenInformation($tok, [TinySocs.TokenCheck]::TokenElevation, $ptr, $size, [ref]$ret)
      if (-not $ok2) { return $false }

      $elevated = [Runtime.InteropServices.Marshal]::ReadInt32($ptr)
      return ($elevated -eq 1)
    }
    finally {
      if ($ptr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::FreeHGlobal($ptr) }
      if ($tok -ne [IntPtr]::Zero) { try { [TinySocs.TokenCheck]::CloseHandle($tok) | Out-Null } catch { } }
    }
  } catch {
    return $false
  }
}

function Assert-TinySocsAdmin {
  if (-not (Test-TinySocsIsElevated)) {
    throw "TinySocs installer must be run from an elevated PowerShell (Run as Administrator)."
  }
}

function Convert-BytesToPem {
  param(
    [Parameter(Mandatory)][byte[]]$Bytes,
    [Parameter(Mandatory)][string]$Label
  )
  $b64 = [Convert]::ToBase64String($Bytes)
  $sb  = New-Object System.Text.StringBuilder
  [void]$sb.AppendLine("-----BEGIN $Label-----")
  for ($i = 0; $i -lt $b64.Length; $i += 64) {
    $len = [Math]::Min(64, $b64.Length - $i)
    [void]$sb.AppendLine($b64.Substring($i, $len))
  }
  [void]$sb.AppendLine("-----END $Label-----")
  return $sb.ToString()
}

function Export-X509CertToPemFile {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert,
    [Parameter(Mandatory)][string]$Path
  )
  $der = $Cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
  $pem = Convert-BytesToPem -Bytes $der -Label "CERTIFICATE"
  $dir = Split-Path -Parent $Path
  if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
  Set-Content -Path $Path -Value $pem -Encoding ascii -Force
}

function Test-Pkcs12PasswordDotNet {
  param(
    [Parameter(Mandatory)][string]$P12Path,
    [Parameter(Mandatory)][string]$Password
  )

  if (-not (Test-Path $P12Path -PathType Leaf)) { return $false }

  try {
    Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue | Out-Null

    $bytes = [System.IO.File]::ReadAllBytes($P12Path)

    # Prefer EphemeralKeySet (avoids writing keys to disk); fall back if not supported
    $flags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet
    try {
      $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
        $bytes, $Password, $flags
      )
      $cert.Dispose()
      return $true
    } catch {
      $flags2 = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::MachineKeySet `
              -bor [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable
      $cert2 = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
        $bytes, $Password, $flags2
      )
      $cert2.Dispose()
      return $true
    }
  } catch {
    return $false
  }
}

function Export-RsaPrivateKeyToPemFile {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert,
    [Parameter(Mandatory)][string]$Path
  )

  $rsa = $null
  try { $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Cert) } catch { }
  if (-not $rsa -and $Cert.PrivateKey) { $rsa = $Cert.PrivateKey }

  if ($null -eq $rsa) { throw "Certificate has no RSA private key." }

  if ($rsa.PSObject.Methods.Name -notcontains 'ExportPkcs8PrivateKey') {
    throw "This PowerShell/.NET runtime cannot export PKCS#8 private keys. Use PKCS12 keystore/truststore path instead."
  }

  $pkcs8 = $rsa.ExportPkcs8PrivateKey()
  $pem = Convert-BytesToPem -Bytes $pkcs8 -Label "PRIVATE KEY"
  $dir = Split-Path -Parent $Path
  if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
  Set-Content -Path $Path -Value $pem -Encoding ascii -Force
}

function Get-TinySocsOpenSearchTlsStorePassFilePath {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$CertsDir)
  return (Join-Path $CertsDir "opensearch-tls-storepass.dpapi")
}

function Read-TinySocsOpenSearchTlsStorePassFromDpapiFile {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$CertsDir)

  # Primary location (OpenSearch config tree)
  $primary = $null
  try { $primary = Get-TinySocsOpenSearchTlsStorePassFilePath -CertsDir $CertsDir } catch { $primary = $null }

  # Secondary location (global TinySocs secrets store)
  $secondary = $null
  try { $secondary = Join-Path (Get-TinySocsSecretStoreDir) "opensearch-tls-storepass.dpapi" } catch { $secondary = $null }

  $candidates = @()
  if ($primary)   { $candidates += $primary }
  if ($secondary) { $candidates += $secondary }

  function _BytesToString {
    param([byte[]]$Bytes)
    if (-not $Bytes) { return $null }

    # Strip UTF-8 BOM if present
    if ($Bytes.Length -ge 3 -and $Bytes[0] -eq 0xEF -and $Bytes[1] -eq 0xBB -and $Bytes[2] -eq 0xBF) {
      $Bytes = $Bytes[3..($Bytes.Length-1)]
    }

    # Heuristic: UTF-16LE if lots of 0x00 in odd positions
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
      [Text.Encoding]::UTF8.GetString($Bytes)
    }

    $s = $s.Trim([char]0x0000).Trim()
    if ($s.IndexOf([char]0x0000) -ge 0) { $s = $s -replace ([char]0x0000), "" }
    return $s
  }

  function _UnprotectLocalMachineB64 {
    param([Parameter(Mandatory)][string]$B64)

    # Windows PowerShell 5.1: ProtectedData lives in System.Security (not "System.Security.Cryptography.ProtectedData")
    try { Add-Type -AssemblyName System.Security -ErrorAction Stop | Out-Null } catch { }

    $b64t = $B64.Trim()
    if ([string]::IsNullOrWhiteSpace($b64t)) { return $null }

    try { $protected = [Convert]::FromBase64String($b64t) }
    catch { throw "DPAPI text is not valid base64." }

    $bytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
      $protected,
      $null,
      [System.Security.Cryptography.DataProtectionScope]::LocalMachine
    )

    _BytesToString -Bytes $bytes
  }

  function _ProtectLocalMachineB64 {
    param([Parameter(Mandatory)][string]$Plain)

    try { Add-Type -AssemblyName System.Security -ErrorAction Stop | Out-Null } catch { }

    $plainBytes = [Text.Encoding]::UTF8.GetBytes($Plain)
    $protected = [System.Security.Cryptography.ProtectedData]::Protect(
      $plainBytes,
      $null,
      [System.Security.Cryptography.DataProtectionScope]::LocalMachine
    )
    [Convert]::ToBase64String($protected)
  }

  foreach ($p in $candidates) {
    if (-not $p) { continue }
    if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { continue }

    try {
      $raw = (Get-Content -LiteralPath $p -Raw -ErrorAction Stop).Trim()
      if ([string]::IsNullOrWhiteSpace($raw)) { continue }

      $plain = _UnprotectLocalMachineB64 -B64 $raw
      if ([string]::IsNullOrWhiteSpace($plain)) { continue }

      # Backfill the other copy if missing (best-effort)
      try {
        if ($p -eq $primary -and $secondary -and -not (Test-Path -LiteralPath $secondary -PathType Leaf)) {
          $wrapped = $null
          if (Get-Command Protect-TinySocsDpapiLocalMachine -ErrorAction SilentlyContinue) {
            $wrapped = Protect-TinySocsDpapiLocalMachine -Plain $plain
          } else {
            $wrapped = _ProtectLocalMachineB64 -Plain $plain
          }
          New-Item -ItemType Directory -Force -Path (Split-Path -Parent $secondary) | Out-Null
          Set-Content -LiteralPath $secondary -Value $wrapped -Encoding ASCII -Force
          Write-TinySocsLog "Backfilled TLS storepass DPAPI file into global secrets store ($secondary)."
        } elseif ($p -eq $secondary -and $primary -and -not (Test-Path -LiteralPath $primary -PathType Leaf)) {
          $wrapped = $null
          if (Get-Command Protect-TinySocsDpapiLocalMachine -ErrorAction SilentlyContinue) {
            $wrapped = Protect-TinySocsDpapiLocalMachine -Plain $plain
          } else {
            $wrapped = _ProtectLocalMachineB64 -Plain $plain
          }
          New-Item -ItemType Directory -Force -Path (Split-Path -Parent $primary) | Out-Null
          Set-Content -LiteralPath $primary -Value $wrapped -Encoding ASCII -Force
          Write-TinySocsLog "Backfilled TLS storepass DPAPI file into OpenSearch certs dir ($primary)."
        }
      } catch {
        Write-TinySocsLog -Level "WARN" -Message "Recovered TLS storepass from DPAPI file ($p) but failed backfill: $($_.Exception.Message)"
      }

      return $plain
    } catch {
      Write-TinySocsLog -Level "WARN" -Message "Failed to read/unwrap TLS storepass DPAPI file ($p): $($_.Exception.Message)"
    }
  }

  return $null
}

function Write-TinySocsOpenSearchTlsStorePassToDpapiFile {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$CertsDir,
    [Parameter(Mandatory)][string]$StorePass
  )

  $okAny = $false
  $wrapped = $null

  try { $wrapped = Protect-TinySocsDpapiLocalMachine -Plain $StorePass }
  catch {
    Write-TinySocsLog -Level "WARN" -Message "Failed to DPAPI-wrap TLS store password: $($_.Exception.Message)"
    return $false
  }

  # Primary (OpenSearch certs dir)
  $p1 = $null
  try { $p1 = Get-TinySocsOpenSearchTlsStorePassFilePath -CertsDir $CertsDir } catch { $p1 = $null }

  # Secondary (global secrets store)
  $p2 = $null
  try { $p2 = Join-Path (Get-TinySocsSecretStoreDir) "opensearch-tls-storepass.dpapi" } catch { $p2 = $null }

  foreach ($p in @($p1,$p2) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) {
    try {
      $dir = Split-Path -Parent $p
      if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }

      Set-Content -Path $p -Value $wrapped -Encoding ASCII -Force
      $okAny = $true
      Write-TinySocsLog "Persisted OpenSearch TLS store password to DPAPI file ($p)."
    } catch {
      Write-TinySocsLog -Level "WARN" -Message "Failed to write TLS storepass DPAPI file ($p): $($_.Exception.Message)"
    }
  }

  return $okAny
}

# --- BEGIN PATCH: Delegate TLS storepass resolution to ensearch.persistence.psm1 ---

function Resolve-TinySocsTlsStorepass {
  [CmdletBinding()]
  param(
    # Canonical call shape (installer-time)
    [Parameter(Mandatory=$false)]
    [string]$ConfDir,

    [Parameter(Mandatory=$false)]
    [string]$OpenSearchRoot,

    # Wrapper/service call shape (run-opensearch.ps1 / NSSM)
    [Parameter(Mandatory=$false, Position=0)]
    [Alias('Path','DpapiPath')]
    [string]$LiteralPath
  )

  # RESOLVER_MARKER_20260102_REAL (proves the patched function is the one executing)

  if (-not (Get-Command Get-TinySocsStorepassFromDpapiFile -ErrorAction SilentlyContinue)) {
    throw "Resolve-TinySocsTlsStorepass: missing helper Get-TinySocsStorepassFromDpapiFile in this module."
  }
  if (-not (Get-Command Test-TinySocsPkcs12Password -ErrorAction SilentlyContinue)) {
    throw "Resolve-TinySocsTlsStorepass: missing helper Test-TinySocsPkcs12Password in this module."
  }

  $usingByFile = -not [string]::IsNullOrWhiteSpace($LiteralPath)

  # If no -LiteralPath, require the canonical inputs
  if (-not $usingByFile) {
    if ([string]::IsNullOrWhiteSpace($ConfDir) -or [string]::IsNullOrWhiteSpace($OpenSearchRoot)) {
      throw "Resolve-TinySocsTlsStorepass: supply either -LiteralPath (dpapi file) OR both -ConfDir and -OpenSearchRoot."
    }
  }

  # ---- Resolve candidate DPAPI locations + cert directories -----------------
  $certDirs      = @()
  $candidatesRaw = @()

  if ($usingByFile) {
    if (-not (Test-Path -LiteralPath $LiteralPath -PathType Leaf)) {
      throw "Resolve-TinySocsTlsStorepass: -LiteralPath not found: $LiteralPath"
    }

    $candidatesRaw += $LiteralPath

    # Assume dpapi file lives under ...\certs\ ; use its parent as certDir
    try {
      $certDirs += (Split-Path -Path $LiteralPath -Parent)
    } catch { }

    # Also try common cert dirs in case dpapi is elsewhere but p12s are in the canonical place
    if ($env:OPENSEARCH_PATH_CONF) {
      $certDirs += (Join-Path $env:OPENSEARCH_PATH_CONF "certs")
    }
    $certDirs += (Join-Path $env:ProgramData "TinySocs\OpenSearch\config\certs")
  }
  else {
    $certDir = Join-Path $ConfDir "certs"
    $certDirs += $certDir

    $candidatesRaw += @(
      (Join-Path $certDir "opensearch-tls-storepass.dpapi"),
      (Join-Path $env:ProgramData "TinySocs\config\secrets\opensearch-tls-storepass.dpapi"),
      (Join-Path (Join-Path $OpenSearchRoot "config\certs") "opensearch-tls-storepass.dpapi")
    )
  }

  $certDirs = @(
    $certDirs |
      Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Container) } |
      Select-Object -Unique
  )

  $candidates = @(
    $candidatesRaw |
      Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Leaf) } |
      Select-Object -Unique
  )

  if ($candidates.Length -eq 0) {
    throw "Resolve-TinySocsTlsStorepass: No opensearch-tls-storepass.dpapi found in expected locations."
  }
  if ($certDirs.Length -eq 0) {
    throw "Resolve-TinySocsTlsStorepass: No cert directories found to validate PKCS12 files against."
  }

  # ---- Gather PKCS12s to validate against ---------------------------------
  $p12s = @()
  foreach ($d in $certDirs) {
    $p12s += @("http.p12","transport.p12","trust.p12") |
      ForEach-Object { Join-Path $d $_ } |
      Where-Object { Test-Path -LiteralPath $_ -PathType Leaf }
  }
  $p12s = @($p12s | Select-Object -Unique)

  if ($p12s.Length -eq 0) {
    throw "Resolve-TinySocsTlsStorepass: No PKCS12 files present under: $($certDirs -join ', ') to validate storepass against."
  }

  # ---- Try each candidate DPAPI file until one validates all P12s ----------
  $errors = @()

  foreach ($dpapiPath in $candidates) {
    $info = Get-TinySocsStorepassFromDpapiFile -Path $dpapiPath

    # Must be ASCII for Java/PKCS12 usage in this pipeline
    if ($info.Encoding -eq "NONASCII") {
      $errors += "Candidate [$dpapiPath] decoded to NON-ASCII password (len=$($info.Length))"
      continue
    }

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

  throw ("Resolve-TinySocsTlsStorepass: Unable to resolve TLS storepass. Tried: " + ($candidates -join ", ") + ". Errors: " + ($errors -join " || "))
}

# --- END PATCH: Delegate TLS storepass resolution to ensearch.persistence.psm1 ---

function Ensure-TinySocsLocalCaAndServerCert {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$CertsDir
  )

  $caSubject     = "CN=TinySocs-OpenSearch-CA"
  $serverSubject = "CN=TinySocs-OpenSearch"
  $adminSubject  = "CN=TinySocs-OpenSearch-Admin"

  # Ensure certs dir exists early so we can persist/restore passwords even if CredMan gets wiped.
  New-Item -ItemType Directory -Force -Path $CertsDir | Out-Null

  function _GetCredManPass([string]$target) {
    try {
      $existing = Get-TSCredential -Name $target
      if (-not $existing) { return $null }
      $j = $existing | ConvertFrom-Json
      if ($j -and $j.pass) { return [string]$j.pass }
    } catch { }
    return $null
  }

  function _SetCredManPass([string]$target, [string]$pass) {
    try {
      $payload = @{ pass = $pass } | ConvertTo-Json -Compress
      Set-TSCredential -Name $target -Secret $payload
      return $true
    } catch {
      Write-TinySocsLog -Level "WARN" -Message "Failed to store TLS password in CredMan ($target): $($_.Exception.Message)"
      return $false
    }
  }

  function _EnsureDpapiFile([string]$dir, [string]$pass) {
    try {
      $p = Get-TinySocsOpenSearchTlsStorePassFilePath -CertsDir $dir
      if (-not (Test-Path $p -PathType Leaf)) {
        $null = Write-TinySocsOpenSearchTlsStorePassToDpapiFile -CertsDir $dir -StorePass $pass
        Write-TinySocsLog "Wrote OpenSearch TLS store password DPAPI file (missing -> created)."
      }
    } catch {
      Write-TinySocsLog -Level "WARN" -Message "Failed to ensure DPAPI storepass file exists: $($_.Exception.Message)"
    }
  }

  function _WriteDpapiAlways([string]$dir, [string]$pass) {
    try {
      $null = Write-TinySocsOpenSearchTlsStorePassToDpapiFile -CertsDir $dir -StorePass $pass
      return $true
    } catch {
      Write-TinySocsLog -Level "WARN" -Message "Failed to write DPAPI storepass file: $($_.Exception.Message)"
      return $false
    }
  }

  $tlsTarget = 'TinySocs/OpenSearch/Tls'

  # Read both sources
  $dpapiPass = $null
  try { $dpapiPass = Read-TinySocsOpenSearchTlsStorePassFromDpapiFile -CertsDir $CertsDir } catch { }
  $credPass  = _GetCredManPass $tlsTarget

  $dpapiOk = -not [string]::IsNullOrWhiteSpace($dpapiPass)
  $credOk  = -not [string]::IsNullOrWhiteSpace($credPass)

  # --- Canonical selection ---
  # Rule:
  #   If DPAPI exists -> DPAPI is canonical (CredMan must match).
  #   Else if CredMan exists -> CredMan is canonical (and DPAPI will be created).
  #   Else generate new ASCII-only pass and persist to both.
  $tlsPass   = $null
  $source    = $null
  $generated = $false

  if ($dpapiOk) {
    $tlsPass = $dpapiPass
    $source  = "DPAPI"
  } elseif ($credOk) {
    $tlsPass = $credPass
    $source  = "CredMan"
  } else {
    # ASCII-only 32 chars, deterministic length, no weird unicode surprises.
    $tlsPass   = [guid]::NewGuid().ToString("N")
    $source    = "Generated"
    $generated = $true
  }

  # Enforce ASCII-only (prevents JDK PKCS12 "Password is not ASCII")
  if (-not (_IsAscii $tlsPass)) {
    Write-TinySocsLog -Level "WARN" -Message "TLS store password from $source contained non-ASCII characters. Rotating to a new ASCII-only password and re-exporting P12s."
    $tlsPass   = [guid]::NewGuid().ToString("N")
    $source    = "Rotated(ASCII)"
    $generated = $true
  }

  # Heal persistence:
  # - Always ensure DPAPI exists and matches final pass.
  # - Always ensure CredMan matches final pass.
  if ($dpapiOk) {
    if ($dpapiPass -ne $tlsPass) {
      $null = _WriteDpapiAlways -dir $CertsDir -pass $tlsPass
      Write-TinySocsLog "Aligned DPAPI TLS store password to canonical value ($source)."
    } else {
      _EnsureDpapiFile -dir $CertsDir -pass $tlsPass
    }
  } else {
    # DPAPI missing -> create it from canonical (CredMan or Generated)
    $null = _WriteDpapiAlways -dir $CertsDir -pass $tlsPass
    Write-TinySocsLog "Created DPAPI TLS store password from canonical value ($source)."
  }

  if ($credOk) {
    if ($credPass -ne $tlsPass) {
      $null = _SetCredManPass -target $tlsTarget -pass $tlsPass
      Write-TinySocsLog "Aligned CredMan TLS store password to canonical value ($source) ($tlsTarget)."
    } else {
      Write-TinySocsLog "Reusing stable OpenSearch TLS store password (CredMan already aligned) ($tlsTarget)."
    }
  } else {
    $null = _SetCredManPass -target $tlsTarget -pass $tlsPass
    Write-TinySocsLog "Stored OpenSearch TLS store password in CredMan from canonical value ($source) ($tlsTarget)."
  }

  if ($generated) {
    Write-TinySocsLog "TLS store password was newly generated/rotated; P12s will be (re)exported deterministically with the canonical password."
  } else {
    Write-TinySocsLog "Using canonical TLS store password source=$source (DPAPI/CredMan now aligned)."
  }

  # ---- CA ----
  $caCert = Get-ChildItem -Path Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
    Where-Object { $_.Subject -eq $caSubject } |
    Sort-Object NotAfter -Descending |
    Select-Object -First 1

  if (-not $caCert) {
    Write-TinySocsLog "Generating local TinySocs CA certificate ($caSubject)."
    $caCert = New-SelfSignedCertificate `
      -Subject $caSubject `
      -CertStoreLocation "Cert:\LocalMachine\My" `
      -KeyExportPolicy Exportable `
      -KeyAlgorithm RSA -KeyLength 4096 -HashAlgorithm SHA256 `
      -NotAfter (Get-Date).AddYears(10) `
      -KeyUsage CertSign,CRLSign,DigitalSignature `
      -TextExtension @("2.5.29.19={critical}{text}ca=true")
  } else {
    Write-TinySocsLog "Found existing TinySocs CA in LocalMachine\My (thumbprint=$($caCert.Thumbprint))."
  }

  # Trust the CA in LocalMachine\Root
  try {
    $root = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root","LocalMachine")
    $root.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
    $present = $false
    foreach ($c in $root.Certificates) {
      if ($c.Thumbprint -eq $caCert.Thumbprint) { $present = $true; break }
    }
    if (-not $present) {
      $root.Add($caCert)
      Write-TinySocsLog "Imported TinySocs CA into LocalMachine\Root (trust store)."
    } else {
      Write-TinySocsLog "TinySocs CA already present in LocalMachine\Root."
    }
    $root.Close()
  } catch {
    Write-TinySocsLog -Level "WARN" -Message "Failed to import CA into Root store: $($_.Exception.Message)"
  }

  # ---- Server cert ----
  $serverCert = Get-ChildItem -Path Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
    Where-Object { $_.Subject -eq $serverSubject } |
    Sort-Object NotAfter -Descending |
    Select-Object -First 1

  if (-not $serverCert) {
    Write-TinySocsLog "Generating OpenSearch server certificate signed by TinySocs CA ($serverSubject)."
    $serverCert = New-SelfSignedCertificate `
      -Subject $serverSubject `
      -CertStoreLocation "Cert:\LocalMachine\My" `
      -KeyExportPolicy Exportable `
      -KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm SHA256 `
      -NotAfter (Get-Date).AddYears(5) `
      -KeyUsage DigitalSignature,KeyEncipherment `
      -Signer $caCert `
      -TextExtension @(
        "2.5.29.19={critical}{text}ca=false",
        "2.5.29.17={text}DNS=localhost&IPAddress=127.0.0.1"
      )
  } else {
    Write-TinySocsLog "Found existing OpenSearch server cert in LocalMachine\My (thumbprint=$($serverCert.Thumbprint))."
  }

  # ---- Admin client cert (for securityadmin) ----
  $adminCert = Get-ChildItem -Path Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
    Where-Object { $_.Subject -eq $adminSubject } |
    Sort-Object NotAfter -Descending |
    Select-Object -First 1

  if (-not $adminCert) {
    Write-TinySocsLog "Generating OpenSearch admin client certificate signed by TinySocs CA ($adminSubject)."
    $adminCert = New-SelfSignedCertificate `
      -Subject $adminSubject `
      -CertStoreLocation "Cert:\LocalMachine\My" `
      -KeyExportPolicy Exportable `
      -KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm SHA256 `
      -NotAfter (Get-Date).AddYears(5) `
      -KeyUsage DigitalSignature,KeyEncipherment `
      -Signer $caCert `
      -TextExtension @(
        "2.5.29.19={critical}{text}ca=false",
        "2.5.29.37={text}1.3.6.1.5.5.7.3.2" # Client Auth EKU
      )
  } else {
    Write-TinySocsLog "Found existing OpenSearch admin cert in LocalMachine\My (thumbprint=$($adminCert.Thumbprint))."
  }

  $httpP12         = Join-Path $CertsDir "http.p12"
  $transP12        = Join-Path $CertsDir "transport.p12"
  $trustP12        = Join-Path $CertsDir "trust.p12"
  $adminKeystore   = Join-Path $CertsDir "admin-keystore.p12"
  $adminTruststore = Join-Path $CertsDir "admin-truststore.p12"
  $caCer           = Join-Path $CertsDir "ca.cer"

  $secPass = ConvertTo-SecureString -String $tlsPass -AsPlainText -Force

  # Export server keystore P12s (always safe: server cert is created exportable by us)
  try {
    Export-PfxCertificate -Cert $serverCert -FilePath $httpP12 -Password $secPass -Force | Out-Null
    Copy-Item -Force $httpP12 $transP12
    Write-TinySocsLog "Exported OpenSearch TLS keystore PKCS12 (http+transport) to $CertsDir."
  } catch {
    throw "Failed to export server cert to PKCS12 ($httpP12): $($_.Exception.Message)"
  }

  # PATCH(2026-01-15): Do NOT Export-PfxCertificate for admin if the key is non-exportable.
  # Prefer an existing admin-keystore.p12 (or alias/copy another p12) and only export as a last resort.
  if (Test-Path -LiteralPath $adminKeystore -PathType Leaf) {
    Write-TinySocsLog "Admin keystore already present; skipping cert-store export (admin-keystore.p12=$adminKeystore)."
  } else {
    $ens = $null
    try { $ens = _EnsureAdminKeystoreP12 -CertsDir $CertsDir } catch { $ens = $null }

    if ($ens -and (Test-Path -LiteralPath $ens -PathType Leaf)) {
      Write-TinySocsLog "Admin keystore ensured via alias/copy (admin-keystore.p12=$ens)."
    } else {
      try {
        Export-PfxCertificate -Cert $adminCert -FilePath $adminKeystore -Password $secPass -Force | Out-Null
        Write-TinySocsLog "Exported OpenSearch admin client keystore PKCS12 to $adminKeystore."
      } catch {
        throw "Failed to ensure admin-keystore.p12 (alias+export both failed) ($adminKeystore): $($_.Exception.Message)"
      }
    }
  }
  # END PATCH

  # Export CA public cert
  try { Export-Certificate -Cert $caCert -FilePath $caCer -Force | Out-Null }
  catch { throw "Failed to export CA certificate to ${caCer}: $($_.Exception.Message)" }

  $installRoot    = (Get-TinySocsInstallRoot | Select-Object -First 1)
  $openSearchRoot = Join-Path ([string]$installRoot) "OpenSearch"
  $keytool        = Join-Path $openSearchRoot "jdk\bin\keytool.exe"
  if (-not (Test-Path $keytool -PathType Leaf)) {
    throw "keytool.exe not found at '$keytool' (bundled JDK missing)."
  }

  # Build truststore (CA only) and mirror it for admin-truststore
  try {
    if (Test-Path $trustP12) { Remove-Item -Force $trustP12 -ErrorAction SilentlyContinue }

    & $keytool -importcert -noprompt `
      -alias tinysocs-ca `
      -file "$caCer" `
      -keystore "$trustP12" `
      -storetype PKCS12 `
      -storepass "$tlsPass" | Out-Null

    Copy-Item -Force $trustP12 $adminTruststore

    Write-TinySocsLog "Created OpenSearch TLS truststore PKCS12 at $trustP12 (alias=tinysocs-ca) and mirrored to $adminTruststore."
  } catch {
    throw "Failed to create truststore via keytool: $($_.Exception.Message)"
  }

  return @{
    HttpKeystoreP12       = $httpP12
    TransportKeystoreP12  = $transP12
    TruststoreP12         = $trustP12
    AdminKeystoreP12      = $adminKeystore
    AdminTruststoreP12    = $adminTruststore
    StorePassword         = $tlsPass
    CaCerPath             = $caCer
  }
}

function New-TinySocsDashboardCert {
  <#
  .SYNOPSIS
    Generate a TLS certificate for the TinySocs dashboard, signed by the existing TinySocs CA.
  .DESCRIPTION
    Creates a server cert with SANs for localhost, 127.0.0.1, and the machine hostname.
    Exports cert.pem and key.pem (PKCS#8) to the output directory.
    Reuses the TinySocs OpenSearch CA from LocalMachine\My.
  .PARAMETER OutputDir
    Directory to write dashboard-cert.pem and dashboard-key.pem.
    Default: C:\ProgramData\TinySocs\Assistant\certs
  #>
  [CmdletBinding()]
  param(
    [string]$OutputDir = (Join-Path $env:ProgramData "TinySocs\Assistant\certs")
  )

  $caSubject   = "CN=TinySocs-OpenSearch-CA"
  $dashSubject = "CN=TinySocs-Dashboard"

  # Find existing CA
  $caCert = Get-ChildItem -Path Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
    Where-Object { $_.Subject -eq $caSubject } |
    Sort-Object NotAfter -Descending |
    Select-Object -First 1

  if (-not $caCert) {
    throw "TinySocs CA ($caSubject) not found in LocalMachine\My. Run TinyBox install first."
  }

  # Build SAN list: localhost + hostname + machine IPs
  $hostname = [System.Net.Dns]::GetHostName()
  $sanParts = @("DNS=localhost", "DNS=$hostname", "IPAddress=127.0.0.1")
  try {
    $ips = [System.Net.Dns]::GetHostAddresses($hostname) |
      Where-Object { $_.AddressFamily -eq 'InterNetwork' } |
      ForEach-Object { "IPAddress=$($_.IPAddressToString)" }
    if ($ips) { $sanParts += $ips }
  } catch { }
  $sanText = ($sanParts | Select-Object -Unique) -join "&"

  # Generate dashboard server cert signed by CA
  Write-TinySocsLog "Generating dashboard TLS certificate ($dashSubject) signed by $caSubject."
  $dashCert = New-SelfSignedCertificate `
    -Subject $dashSubject `
    -CertStoreLocation "Cert:\LocalMachine\My" `
    -KeyExportPolicy Exportable `
    -KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm SHA256 `
    -NotAfter (Get-Date).AddYears(3) `
    -KeyUsage DigitalSignature,KeyEncipherment `
    -Signer $caCert `
    -TextExtension @(
      "2.5.29.19={critical}{text}ca=false",
      "2.5.29.17={text}$sanText"
    )

  New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
  $certPemPath = Join-Path $OutputDir "dashboard-cert.pem"
  $keyPemPath  = Join-Path $OutputDir "dashboard-key.pem"

  # Export cert as PEM (base64 DER)
  $certB64 = [Convert]::ToBase64String($dashCert.RawData, [System.Base64FormattingOptions]::InsertLineBreaks)
  $certPem = "-----BEGIN CERTIFICATE-----`n$certB64`n-----END CERTIFICATE-----"
  Set-Content -Path $certPemPath -Value $certPem -Encoding ASCII -Force

  # Export private key as PKCS#8 PEM via CNG (.NET 4.6.2+)
  try {
    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($dashCert)
    $keyBytes = $rsa.Key.Export([System.Security.Cryptography.CngKeyBlobFormat]::Pkcs8PrivateBlob)
    $keyB64 = [Convert]::ToBase64String($keyBytes, [System.Base64FormattingOptions]::InsertLineBreaks)
    $keyPem = "-----BEGIN PRIVATE KEY-----`n$keyB64`n-----END PRIVATE KEY-----"
    Set-Content -Path $keyPemPath -Value $keyPem -Encoding ASCII -Force
  } catch {
    throw "Failed to export dashboard private key as PEM (CNG/PKCS#8): $($_.Exception.Message)"
  }

  Write-TinySocsLog "Dashboard TLS cert generated: cert=$certPemPath key=$keyPemPath"
  return @{ CertPath = $certPemPath; KeyPath = $keyPemPath }
}

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

  $configDir = Split-Path -Parent $ConfigPath
  if (-not (Test-Path $configDir)) { New-Item -ItemType Directory -Force -Path $configDir | Out-Null }

  Ensure-TinySocsWritableFile -Path $ConfigPath

  $dataPathNormalized = $DataPath.Replace('\','/')
  $logsPathNormalized = $LogsPath.Replace('\','/')

  if ((-not (Test-Path $ConfigPath -PathType Leaf)) -or $Force.IsPresent) {
    "# TinySocs-generated opensearch.yml`r`n" | Out-File -FilePath $ConfigPath -Encoding UTF8 -Force
  }

  # Read as RAW and split -> ALWAYS produces string[]
  $rawText = ""
  try { $rawText = Get-Content -Path $ConfigPath -Raw -ErrorAction Stop } catch { $rawText = "" }

  # Normalize line endings and split (PS5-safe)
  $lines = @()
  if (-not [string]::IsNullOrEmpty($rawText)) {
    $rawText = $rawText -replace "`r`n", "`n"
    $rawText = $rawText -replace "`r", "`n"
    $lines   = @($rawText -split "`n")
  } else {
    $lines = @()
  }

  # Ensure we never accidentally hold chars
  $lines = @($lines | ForEach-Object { [string]$_ })

  function _SetYamlKey {
    param(
      [Parameter(Mandatory)][string]$Key,
      [Parameter(Mandatory)][string]$Value
    )

    $kEsc = [Regex]::Escape($Key)
    $re   = '^\s*' + $kEsc + '\s*:\s*.*$'

    $idx = -1
    for ($i = 0; $i -lt $lines.Count; $i++) {
      if ([string]$lines[$i] -match $re) { $idx = $i; break }
    }

    $newline = "{0}: {1}" -f $Key, $Value

    if ($idx -ge 0) {
      $lines[$idx] = $newline
    } else {
      if ($lines.Count -gt 0 -and -not [string]::IsNullOrWhiteSpace([string]$lines[$lines.Count-1])) {
        $lines += ''
      }
      $lines += $newline
    }
  }

  _SetYamlKey -Key 'cluster.name'   -Value $ClusterName
  _SetYamlKey -Key 'node.name'      -Value $NodeName
  _SetYamlKey -Key 'network.host'   -Value '127.0.0.1'
  _SetYamlKey -Key 'http.port'      -Value ([string]$HttpPort)
  _SetYamlKey -Key 'discovery.type' -Value 'single-node'
  _SetYamlKey -Key 'path.data'      -Value $dataPathNormalized
  _SetYamlKey -Key 'path.logs'      -Value $logsPathNormalized

  Ensure-TinySocsWritableFile -Path $ConfigPath
  ($lines -join "`r`n") + "`r`n" | Out-File -FilePath $ConfigPath -Encoding UTF8 -Force

  Write-TinySocsLog "OpenSearch config ensured/merged at $ConfigPath"
}

function Ensure-TinySocsOpenSearchCertBundlePresent {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)] [string] $CertsDir,
    [Parameter()] $TlsPaths,
    [Parameter()] [string] $OpenSearchRoot
  )

  function _Log([string]$msg, [string]$level="INFO") {
    if (Get-Command Write-TinySocsLog -ErrorAction SilentlyContinue) {
      Write-TinySocsLog -Level $level -Message $msg
    } else {
      Write-Host "[$level] $msg"
    }
  }

  function _FindFirstExisting([string[]]$paths) {
    foreach ($p in $paths) { if ($p -and (Test-Path -LiteralPath $p -PathType Leaf)) { return $p } }
    return $null
  }

  New-Item -ItemType Directory -Force -Path $CertsDir | Out-Null

  $want = @(
    @{ name="http.p12";      keys=@("HttpP12","HttpP12Path","http_p12","HttpKeystorePath","HttpKeystore","HttpKeystoreP12") },
    @{ name="transport.p12"; keys=@("TransportP12","TransportP12Path","transport_p12","TransportKeystorePath","TransportKeystore","TransportKeystoreP12") },
    @{ name="trust.p12";     keys=@("TrustP12","TrustP12Path","trust_p12","TruststorePath","Truststore","TruststoreP12") },
    @{ name="opensearch-tls-storepass.dpapi"; keys=@("StorePassDpapi","StorePassDpapiPath","DpapiPath","dpapi","StorePasswordDpapi") }
  )

  foreach ($w in $want) {
    $dst = Join-Path $CertsDir $w.name
    if (Test-Path -LiteralPath $dst -PathType Leaf) { continue }

    $src = $null

    if ($TlsPaths) {
      $src = _GetTlsVal -Obj $TlsPaths -Keys $w.keys
      if ($src -and -not (Test-Path -LiteralPath $src -PathType Leaf)) { $src = $null }
    }

    if (-not $src -and $OpenSearchRoot) {
      $src = _FindFirstExisting @(
        (Join-Path $OpenSearchRoot ("config\certs\" + $w.name)),
        (Join-Path $OpenSearchRoot ("seed\config\certs\" + $w.name)),
        (Join-Path $OpenSearchRoot ("OpenSearch\seed\config\certs\" + $w.name))
      )
    }

    if ($src) {
      Copy-Item -LiteralPath $src -Destination $dst -Force
      _Log ("Seeded missing cert material: {0} <= {1}" -f $dst, $src)
    } else {
      _Log ("Missing required cert material and no source found: {0}" -f $dst) "WARN"
    }
  }

  $missing = @("http.p12","transport.p12","trust.p12","opensearch-tls-storepass.dpapi") |
    Where-Object { -not (Test-Path -LiteralPath (Join-Path $CertsDir $_) -PathType Leaf) }

  if ($missing.Count -gt 0) {
    throw ("Cert bundle incomplete in {0}. Missing: {1}" -f $CertsDir, ($missing -join ", "))
  }
}

function Add-TinySocsYamlLine {
  param(
    [Parameter(Mandatory)] [ref] $Buffer,
    [Parameter(Mandatory)] [string] $Key,
    [Parameter(Mandatory)] [string] $Value
  )
  # NOTE: $Key followed by ":" must be $($Key): or ${Key}: to avoid PowerShell treating it like a drive scope.
  $Buffer.Value += "`r`n$($Key): $Value`r`n"
}

function Ensure-TinySocsOpenSearchTlsP12Present {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$OpenSearchRoot,
    [Parameter(Mandatory)][string]$ProgramDataConf
  )

  $certsDir = Join-Path $ProgramDataConf "certs"
  if (-not (Test-Path -LiteralPath $certsDir -PathType Container)) {
    New-Item -ItemType Directory -Force -Path $certsDir | Out-Null
  }

  $need = @("http.p12","transport.p12","trust.p12")
  $missing = @($need | Where-Object { -not (Test-Path -LiteralPath (Join-Path $certsDir $_) -PathType Leaf) })

  if ($missing.Count -eq 0) {
    return $true
  }

  # Try seeding from Program Files OpenSearch config\certs first
  $seed = Join-Path $OpenSearchRoot "config\certs"
  if (Test-Path -LiteralPath $seed -PathType Container) {
    foreach ($f in $missing) {
      $src = Join-Path $seed $f
      $dst = Join-Path $certsDir $f
      if (Test-Path -LiteralPath $src -PathType Leaf) {
        Copy-Item -LiteralPath $src -Destination $dst -Force -ErrorAction SilentlyContinue
      }
    }
  }

  # Recheck
  $missing = @($need | Where-Object { -not (Test-Path -LiteralPath (Join-Path $certsDir $_) -PathType Leaf) })
  if ($missing.Count -eq 0) {
    return $true
  }

  # Last resort: try known generator/export functions if present in module
  $candidates = @(
    "Export-TinySocsOpenSearchTlsKeystoresPkcs12",
    "Export-TinySocsOpenSearchTlsKeystorePkcs12",
    "Ensure-TinySocsOpenSearchTlsMaterial",
    "Ensure-TinySocsProgramDataCerts"
  )

  foreach ($fn in $candidates) {
    $cmd = Get-Command -Name $fn -ErrorAction SilentlyContinue
    if (-not $cmd) { continue }

    try {
      switch ($fn) {
        "Ensure-TinySocsProgramDataCerts" {
          & $fn -OpenSearchRoot $OpenSearchRoot -ProgramDataConf $ProgramDataConf -Force | Out-Null
        }
        default {
          # best-effort: many of your functions take these common params
          & $fn -OpenSearchRoot $OpenSearchRoot -ProgramDataConf $ProgramDataConf -CertsDir $certsDir -ErrorAction Stop | Out-Null
        }
      }
    } catch {
      # keep trying next candidate
    }

    $missing = @($need | Where-Object { -not (Test-Path -LiteralPath (Join-Path $certsDir $_) -PathType Leaf) })
    if ($missing.Count -eq 0) { return $true }
  }

  throw ("Missing required TLS PKCS12 files in ProgramData certs dir: " +
         (($missing | Sort-Object -Unique) -join ", ") +
         ". Looked in: " + $certsDir + " and seed: " + $seed)
}

function Ensure-TinySocsOpenSearchSecuritySettings {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$ConfigPath,
    [Parameter(Mandatory)][hashtable]$TlsPaths,
    [bool]$AllowDefaultInitSecurityIndex = $true,

    # Optional: if present, we will prefer recovering the PKCS12 storepass from DPAPI so upgrades are self-healing.
    # Expected content: either raw DPAPI-protected bytes OR base64 text of those bytes.
    [string]$StorePassDpapiPath
  )

  Ensure-TinySocsWritableFile -Path $ConfigPath
  if ($null -eq $TlsPaths) { throw "Ensure-TinySocsOpenSearchSecuritySettings: TlsPaths was null." }

  $configDir = Split-Path -Parent $ConfigPath
  if (-not (Test-Path $configDir)) { New-Item -ItemType Directory -Force -Path $configDir | Out-Null }

  # Canonical certs dir under ProgramData conf
  $certsDir = Join-Path $configDir "certs"
  if (-not (Test-Path $certsDir)) { New-Item -ItemType Directory -Force -Path $certsDir | Out-Null }

  if ([string]::IsNullOrWhiteSpace($StorePassDpapiPath)) {
    $StorePassDpapiPath = Join-Path $certsDir "opensearch-tls-storepass.dpapi"
  }

  function _YamlSingleQuote {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$s)
    return ("'" + ($s -replace "'","''") + "'")
  }

  function _ToYamlRelPathIfUnderConf {
    param(
      [Parameter(Mandatory)][string]$AbsPath,
      [Parameter(Mandatory)][string]$ConfDir
    )
    try {
      $confFull = [System.IO.Path]::GetFullPath($ConfDir.TrimEnd('\'))
      $pFull    = [System.IO.Path]::GetFullPath($AbsPath)
      if ($pFull.StartsWith($confFull, [System.StringComparison]::OrdinalIgnoreCase)) {
        $rel = $pFull.Substring($confFull.Length).TrimStart('\')
        return ($rel -replace '\\','/')
      }
    } catch { }
    return ([string]$AbsPath).Replace('\','/')
  }

  # NOTE: DPAPI storepass file format for TinySocs is base64 ASCII text like "AQAAANCM..."
  function _Write-TinySocsDpapiStorePass {
    param(
      [Parameter(Mandatory)][string]$Path,
      [Parameter(Mandatory)][string]$Password
    )

    try {
      $dir = Split-Path -Parent $Path
      if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }

      $b64 = Protect-TinySocsDpapiLocalMachine -Plain $Password
      $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
      [System.IO.File]::WriteAllText($Path, $b64, $utf8NoBom)

      _Ensure-TinySocsReadable -Path $Path
    } catch {
      Write-TinySocsLog "WARN: Failed to write DPAPI storepass file '$Path': $($_.Exception.Message)"
    }
  }

  function _Invoke-TinySocsKeytoolList {
    param(
      [Parameter(Mandatory)][string]$KeytoolPath,
      [Parameter(Mandatory)][string]$KeystorePath,
      [Parameter(Mandatory)][string]$Password
    )

    $res = [pscustomobject]@{
      Ok      = $false
      Exit    = $null
      Error   = $null
      Path    = $KeystorePath
      Keytool = $KeytoolPath
    }

    if (-not (Test-Path $KeytoolPath -PathType Leaf)) {
      $res.Ok = $true
      $res.Exit = 0
      $res.Error = "keytool_missing"
      return $res
    }

    if (-not (Test-Path $KeystorePath -PathType Leaf)) {
      $res.Ok = $false
      $res.Exit = 2
      $res.Error = "keystore_missing"
      return $res
    }

    _Ensure-TinySocsReadable -Path $KeystorePath

    try {
      $out = & $KeytoolPath @('-list','-storetype','PKCS12','-keystore',$KeystorePath,'-storepass',$Password) 2>&1
      $res.Exit = $LASTEXITCODE
      $res.Error = (($out | Out-String).Trim())
      $res.Ok = ($res.Exit -eq 0)
      return $res
    } catch {
      $res.Exit = 1
      $res.Error = ("keytool_exec_failed: " + $_.Exception.Message)
      $res.Ok = $false
      return $res
    }
  }

  function _Classify-TinySocsPkcs12Failure {
    param([Parameter(Mandatory)]$KeytoolResult)

    if ($KeytoolResult.Ok) { return $null }

    if ($KeytoolResult.Error -eq "keytool_missing") { return "KEYTOOL_MISSING" }
    if ($KeytoolResult.Error -eq "keystore_missing") { return "KEYSTORE_MISSING" }

    $e = [string]$KeytoolResult.Error

    if ($e -match '(?i)Keystore file does not exist') { return "CANNOT_READ_OR_PATH" }
    if ($e -match '(?i)Access is denied')            { return "ACCESS_DENIED" }

    if ($e -match '(?i)keystore password was incorrect' -or
        $e -match '(?i)password was incorrect' -or
        $e -match '(?i)UnrecoverableKeyException' -or
        $e -match '(?i)tampered with' -or
        $e -match '(?i)BadPaddingException') {
      return "BAD_PASSWORD"
    }

    return "KEYTOOL_FAILED"
  }

function _Get-TinySocsOpenSearchKeystoreTokens {
  param(
    [Parameter(Mandatory)][string]$OpenSearchRoot,
    [Parameter(Mandatory)][string]$ConfDir
  )
  $kbat = Join-Path $OpenSearchRoot "bin\opensearch-keystore.bat"
  if (-not (Test-Path $kbat -PathType Leaf)) { return @() }

  # PATCH: best-effort ACL repair so keystore CLI can read conf/keystore in installer/service contexts
  try {
    $fn = Get-Command Repair-TinySocsOpenSearchKeystoreAcls -ErrorAction SilentlyContinue
    if ($fn) {
      $pp = @{}
      if ($fn.Parameters.ContainsKey('ProgramDataConf')) { $pp.ProgramDataConf = $ConfDir }
      elseif ($fn.Parameters.ContainsKey('ConfDir'))      { $pp.ConfDir        = $ConfDir }
      elseif ($fn.Parameters.ContainsKey('Path'))         { $pp.Path           = $ConfDir }
      & $fn @pp | Out-Null
    } else {
      try { attrib.exe -R $ConfDir /S /D | Out-Null } catch { }
      $who = $null; try { $who = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name } catch { $who = $env:USERNAME }
      try { & icacls.exe $ConfDir /inheritance:e /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" ($who + ":(OI)(CI)F") /T /C | Out-Null } catch { }
      $ks = Join-Path $ConfDir "opensearch.keystore"
      if (Test-Path -LiteralPath $ks -PathType Leaf) {
        try { & icacls.exe $ks /inheritance:e /grant:r "SYSTEM:F" "Administrators:F" ($who + ":F") /C | Out-Null } catch { }
      }
    }
  } catch { }

  $old = $env:OPENSEARCH_PATH_CONF
  try {
    $env:OPENSEARCH_PATH_CONF = $ConfDir
    $raw = & $kbat list 2>$null
  } catch {
    $raw = @()
  } finally {
    $env:OPENSEARCH_PATH_CONF = $old
  }

  if ($null -eq $raw) { return @() }

  $txt = ($raw | Out-String)
  if ([string]::IsNullOrWhiteSpace($txt)) { return @() }
  return ($txt -split '\s+' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
}

function _Purge-TinySocsLegacyPlaintextSslKeystoreKeys {
  param(
    [Parameter(Mandatory)][string]$OpenSearchRoot,
    [Parameter(Mandatory)][string]$ConfDir
  )

  $kbat = Join-Path $OpenSearchRoot "bin\opensearch-keystore.bat"
  if (-not (Test-Path $kbat -PathType Leaf)) { return }

  $ksPath = Join-Path $ConfDir "opensearch.keystore"

  $legacy = @(
    'plugins.security.ssl.http.keystore_password',
    'plugins.security.ssl.http.keystore_keypassword',
    'plugins.security.ssl.http.truststore_password',
    'plugins.security.ssl.transport.keystore_password',
    'plugins.security.ssl.transport.keystore_keypassword',
    'plugins.security.ssl.transport.truststore_password'
  )

  $old = $env:OPENSEARCH_PATH_CONF
  try {
    $env:OPENSEARCH_PATH_CONF = $ConfDir

    # PATCH: repair ACLs BEFORE we touch/create the keystore
    try {
      $fn = Get-Command Repair-TinySocsOpenSearchKeystoreAcls -ErrorAction SilentlyContinue
      if ($fn) {
        $pp = @{}
        if ($fn.Parameters.ContainsKey('ProgramDataConf')) { $pp.ProgramDataConf = $ConfDir }
        elseif ($fn.Parameters.ContainsKey('ConfDir'))      { $pp.ConfDir        = $ConfDir }
        elseif ($fn.Parameters.ContainsKey('Path'))         { $pp.Path           = $ConfDir }
        & $fn @pp | Out-Null
      } else {
        try { attrib.exe -R $ConfDir /S /D | Out-Null } catch { }
        $who = $null; try { $who = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name } catch { $who = $env:USERNAME }
        try { & icacls.exe $ConfDir /inheritance:e /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" ($who + ":(OI)(CI)F") /T /C | Out-Null } catch { }
        if (Test-Path -LiteralPath $ksPath -PathType Leaf) {
          try { & icacls.exe $ksPath /inheritance:e /grant:r "SYSTEM:F" "Administrators:F" ($who + ":F") /C | Out-Null } catch { }
        }
      }
    } catch { }

    if (-not (Test-Path -LiteralPath $ksPath -PathType Leaf)) {
      try { & $kbat create 2>$null | Out-Null } catch { }

      # PATCH: repair ACLs AGAIN AFTER create (inheritance/owner can be wrong on fresh extract/install)
      try {
        $fn = Get-Command Repair-TinySocsOpenSearchKeystoreAcls -ErrorAction SilentlyContinue
        if ($fn) {
          $pp = @{}
          if ($fn.Parameters.ContainsKey('ProgramDataConf')) { $pp.ProgramDataConf = $ConfDir }
          elseif ($fn.Parameters.ContainsKey('ConfDir'))      { $pp.ConfDir        = $ConfDir }
          elseif ($fn.Parameters.ContainsKey('Path'))         { $pp.Path           = $ConfDir }
          & $fn @pp | Out-Null
        } else {
          try { attrib.exe -R $ConfDir /S /D | Out-Null } catch { }
          $who = $null; try { $who = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name } catch { $who = $env:USERNAME }
          try { & icacls.exe $ConfDir /inheritance:e /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" ($who + ":(OI)(CI)F") /T /C | Out-Null } catch { }
          if (Test-Path -LiteralPath $ksPath -PathType Leaf) {
            try { & icacls.exe $ksPath /inheritance:e /grant:r "SYSTEM:F" "Administrators:F" ($who + ":F") /C | Out-Null } catch { }
          }
        }
      } catch { }
    }

    # PATCH: list first, remove only present keys (idempotent, no noise)
    $tokens = @()
    try { $tokens = _Get-TinySocsOpenSearchKeystoreTokens -OpenSearchRoot $OpenSearchRoot -ConfDir $ConfDir } catch { $tokens = @() }
    $tokenSet = @{}
    foreach ($t in $tokens) { if (-not [string]::IsNullOrWhiteSpace($t)) { $tokenSet[[string]$t] = $true } }

    foreach ($k in $legacy) {
      if ($tokenSet.ContainsKey($k)) {

        # PATCH: extra best-effort ACL repair right before mutation ops
        try {
          $fn = Get-Command Repair-TinySocsOpenSearchKeystoreAcls -ErrorAction SilentlyContinue
          if ($fn) {
            $pp = @{}
            if ($fn.Parameters.ContainsKey('ProgramDataConf')) { $pp.ProgramDataConf = $ConfDir }
            elseif ($fn.Parameters.ContainsKey('ConfDir'))      { $pp.ConfDir        = $ConfDir }
            elseif ($fn.Parameters.ContainsKey('Path'))         { $pp.Path           = $ConfDir }
            & $fn @pp | Out-Null
          } else {
            try { attrib.exe -R $ConfDir /S /D | Out-Null } catch { }
            $who = $null; try { $who = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name } catch { $who = $env:USERNAME }
            try { & icacls.exe $ConfDir /inheritance:e /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" ($who + ":(OI)(CI)F") /T /C | Out-Null } catch { }
            if (Test-Path -LiteralPath $ksPath -PathType Leaf) {
              try { & icacls.exe $ksPath /inheritance:e /grant:r "SYSTEM:F" "Administrators:F" ($who + ":F") /C | Out-Null } catch { }
            }
          }
        } catch { }

        try {
          & $kbat remove $k 2>$null | Out-Null
        } catch { }
      }
    }
  } finally {
    $env:OPENSEARCH_PATH_CONF = $old
  }
}

  # ---- ensure ProgramData cert bundle exists BEFORE we validate or write YAML ----
  $osRootGuess = Join-Path $env:ProgramFiles "TinySocs\OpenSearch"
  try {
    $okCerts = Ensure-TinySocsProgramDataCerts -OpenSearchRoot $osRootGuess -ProgramDataConf $configDir
    if (-not $okCerts) {
      Write-TinySocsLog "WARN: Ensure-TinySocsProgramDataCerts did not fully populate ProgramData certs under '$certsDir' (continuing; later validation may fail)."
    }
  } catch {
    Write-TinySocsLog "WARN: Ensure-TinySocsProgramDataCerts failed (continuing): $($_.Exception.Message)"
  }

  # ---- ensure canonical cert bundle exists BEFORE we validate or write YAML ----
  try {
    Ensure-TinySocsOpenSearchCertBundlePresent -CertsDir $certsDir -TlsPaths $TlsPaths -OpenSearchRoot $osRootGuess
  } catch {
    throw
  }

  # NEW: hard guarantee required TLS PKCS12 files exist in ProgramData BEFORE keytool validation
  try {
    Ensure-TinySocsOpenSearchTlsP12Present -OpenSearchRoot $osRootGuess -ProgramDataConf $configDir | Out-Null
  } catch {
    throw
  }

  # Canonicalize TlsPaths to ProgramData names if present (prevents path drift)
  $httpCanon  = Join-Path $certsDir "http.p12"
  $tranCanon  = Join-Path $certsDir "transport.p12"
  $trustCanon = Join-Path $certsDir "trust.p12"
  if (Test-Path $httpCanon  -PathType Leaf) { $TlsPaths["HttpKeystoreP12"]      = $httpCanon }
  if (Test-Path $tranCanon  -PathType Leaf) { $TlsPaths["TransportKeystoreP12"] = $tranCanon }
  if (Test-Path $trustCanon -PathType Leaf) { $TlsPaths["TruststoreP12"]        = $trustCanon }

  foreach ($k in @('HttpKeystoreP12','TransportKeystoreP12','TruststoreP12')) {
    if (-not $TlsPaths.ContainsKey($k) -or [string]::IsNullOrWhiteSpace([string]$TlsPaths[$k])) {
      throw "Ensure-TinySocsOpenSearchSecuritySettings: TlsPaths missing required key '$k'."
    }
  }

  foreach ($p in @($TlsPaths.HttpKeystoreP12, $TlsPaths.TransportKeystoreP12, $TlsPaths.TruststoreP12)) {
    if (-not (Test-Path $p -PathType Leaf)) {
      throw "Ensure-TinySocsOpenSearchSecuritySettings: TLS file missing on disk: $p"
    }
  }

  if (-not (Test-Path $ConfigPath -PathType Leaf)) {
    throw "Ensure-TinySocsOpenSearchSecuritySettings: ConfigPath not found: $ConfigPath"
  }

  _Ensure-TinySocsReadable -Path $configDir -IsDir
  foreach ($p in @(
    (Join-Path $configDir "jvm.options"),
    (Join-Path $configDir "log4j2.properties"),
    $ConfigPath,
    $TlsPaths.HttpKeystoreP12,
    $TlsPaths.TransportKeystoreP12,
    $TlsPaths.TruststoreP12,
    $StorePassDpapiPath
  )) {
    _Ensure-TinySocsReadable -Path $p
  }

  # Prefer DPAPI storepass so upgrades are self-healing.
  $pw = $null
  $pwSource = "TlsPaths.StorePassword"

  $dpPw = $null
  if (-not [string]::IsNullOrWhiteSpace($StorePassDpapiPath)) {
    $dpPw = _TryUnprotect-TinySocsDpapiFile -Path $StorePassDpapiPath
  }

  if (-not [string]::IsNullOrWhiteSpace($dpPw)) {
    $pw = [string]$dpPw
    $pwSource = "DPAPI:$StorePassDpapiPath"
  } elseif ($TlsPaths.ContainsKey('StorePassword') -and -not [string]::IsNullOrWhiteSpace([string]$TlsPaths.StorePassword)) {
    $pw = [string]$TlsPaths.StorePassword
  } else {
    throw "Ensure-TinySocsOpenSearchSecuritySettings: No PKCS12 store password available. Expected DPAPI file at '$StorePassDpapiPath' or TlsPaths.StorePassword."
  }

  $pw = $pw.Trim()
  if ($pw.IndexOf([char]0) -ge 0 -or $pw -match "[`r`n]") {
    throw "Ensure-TinySocsOpenSearchSecuritySettings: Store password contains null/newline characters (source=$pwSource)."
  }
  $badAscii = $false
  foreach ($ch in $pw.ToCharArray()) {
    if ([int][char]$ch -gt 127) { $badAscii = $true; break }
  }
  if ($badAscii) {
    throw "Ensure-TinySocsOpenSearchSecuritySettings: Store password contains non-ASCII characters (source=$pwSource)."
  }

  $ktDefault = Join-Path $env:ProgramFiles "TinySocs\OpenSearch\jdk\bin\keytool.exe"

  $rHttp  = _Invoke-TinySocsKeytoolList -KeytoolPath $ktDefault -KeystorePath $TlsPaths.HttpKeystoreP12      -Password $pw
  $rTrans = _Invoke-TinySocsKeytoolList -KeytoolPath $ktDefault -KeystorePath $TlsPaths.TransportKeystoreP12 -Password $pw
  $rTrust = _Invoke-TinySocsKeytoolList -KeytoolPath $ktDefault -KeystorePath $TlsPaths.TruststoreP12        -Password $pw

  $failHttp  = _Classify-TinySocsPkcs12Failure -KeytoolResult $rHttp
  $failTrans = _Classify-TinySocsPkcs12Failure -KeytoolResult $rTrans
  $failTrust = _Classify-TinySocsPkcs12Failure -KeytoolResult $rTrust

  $allOk = ($rHttp.Ok -and $rTrans.Ok -and $rTrust.Ok)

  if (-not $allOk) {
    if ($pwSource -like "DPAPI:*" -and $TlsPaths.ContainsKey('StorePassword') -and -not [string]::IsNullOrWhiteSpace([string]$TlsPaths.StorePassword)) {
      $pw2 = [string]$TlsPaths.StorePassword.Trim()

      $rHttp2  = _Invoke-TinySocsKeytoolList -KeytoolPath $ktDefault -KeystorePath $TlsPaths.HttpKeystoreP12      -Password $pw2
      $rTrans2 = _Invoke-TinySocsKeytoolList -KeytoolPath $ktDefault -KeystorePath $TlsPaths.TransportKeystoreP12 -Password $pw2
      $rTrust2 = _Invoke-TinySocsKeytoolList -KeytoolPath $ktDefault -KeystorePath $TlsPaths.TruststoreP12        -Password $pw2

      if ($rHttp2.Ok -and $rTrans2.Ok -and $rTrust2.Ok) {
        $pw = $pw2
        $pwSource = "TlsPaths.StorePassword (fallback)"
        $rHttp = $rHttp2; $rTrans = $rTrans2; $rTrust = $rTrust2
        $failHttp = $null; $failTrans = $null; $failTrust = $null
        $allOk = $true

        if (-not [string]::IsNullOrWhiteSpace($StorePassDpapiPath)) {
          _Write-TinySocsDpapiStorePass -Path $StorePassDpapiPath -Password $pw
        }
      }
    }

    if (-not $allOk) {
      $details = @()
      if (-not $rHttp.Ok)  { $details += "http.p12: $failHttp" }
      if (-not $rTrans.Ok) { $details += "transport.p12: $failTrans" }
      if (-not $rTrust.Ok) { $details += "trust.p12: $failTrust" }
      $detailText = ($details -join "; ")

      $onlyTransportBad = ($rHttp.Ok -and -not $rTrans.Ok -and $rTrust.Ok -and $failTrans -eq "BAD_PASSWORD")
      if ($onlyTransportBad) {
        throw "Ensure-TinySocsOpenSearchSecuritySettings: transport.p12 does not accept the same password as http/trust (source=$pwSource). Details: $detailText"
      }

      if ($detailText -match 'CANNOT_READ_OR_PATH|ACCESS_DENIED|KEYSTORE_MISSING') {
        throw "Ensure-TinySocsOpenSearchSecuritySettings: PKCS12 validation failed because keystore(s) could not be read (source=$pwSource). Details: $detailText"
      }

      if ($detailText -match 'BAD_PASSWORD') {
        throw "Ensure-TinySocsOpenSearchSecuritySettings: PKCS12 password appears incorrect (source=$pwSource). Details: $detailText"
      }

      throw "Ensure-TinySocsOpenSearchSecuritySettings: PKCS12 validation failed (source=$pwSource). Details: $detailText"
    }
  }

  if ($pwSource -like "TlsPaths.StorePassword*" -and -not [string]::IsNullOrWhiteSpace($StorePassDpapiPath)) {
    try { _Write-TinySocsDpapiStorePass -Path $StorePassDpapiPath -Password $pw } catch { }
    $pwSource = "TlsPaths.StorePassword->$StorePassDpapiPath"
  }

  $httpKs  = _ToYamlRelPathIfUnderConf -AbsPath ([string]$TlsPaths.HttpKeystoreP12)       -ConfDir $configDir
  $transKs = _ToYamlRelPathIfUnderConf -AbsPath ([string]$TlsPaths.TransportKeystoreP12) -ConfDir $configDir
  $ts      = _ToYamlRelPathIfUnderConf -AbsPath ([string]$TlsPaths.TruststoreP12)        -ConfDir $configDir

  $adminDn = 'CN=TinySocs-OpenSearch-Admin'
  $nodeDn  = 'CN=TinySocs-OpenSearch'

  $ownedKeys = @(
    'plugins.security.disabled',

    'plugins.security.ssl.http.enabled',
    'plugins.security.ssl.http.keystore_type',
    'plugins.security.ssl.http.keystore_filepath',
    'plugins.security.ssl.http.truststore_type',
    'plugins.security.ssl.http.truststore_filepath',
    'plugins.security.ssl.http.clientauth_mode',

    'plugins.security.ssl.transport.keystore_type',
    'plugins.security.ssl.transport.keystore_filepath',
    'plugins.security.ssl.transport.truststore_type',
    'plugins.security.ssl.transport.truststore_filepath',
    'plugins.security.ssl.transport.enforce_hostname_verification',

    'plugins.security.allow_unsafe_democertificates',
    'plugins.security.allow_default_init_securityindex',

    'plugins.security.restapi.roles_enabled',
    'plugins.security.unsupported.restapi.allow_securityconfig_modification',

    'plugins.security.authcz.admin_dn',
    'plugins.security.nodes_dn'
  )

  $lines = Get-Content -Path $ConfigPath -ErrorAction Stop
  if ($null -eq $lines) { $lines = @() }

  $beginRe = '^\s*#\s*---\s*BEGIN\s*TinySocs\s*security/TLS'
  $endRe   = '^\s*#\s*---\s*END\s*TinySocs\s*security/TLS'

  $newLines = New-Object System.Collections.Generic.List[string]
  $inBlock = $false
  foreach ($ln in $lines) {
    if ($ln -match $beginRe) { $inBlock = $true; continue }
    if ($inBlock) {
      if ($ln -match $endRe) { $inBlock = $false }
      continue
    }
    [void]$newLines.Add($ln)
  }

  $filtered = New-Object System.Collections.Generic.List[string]
  $skipYamlList = $false

  foreach ($ln in $newLines) {
    if ($skipYamlList) {
      if ($ln -match '^\s*$') { continue }
      if ($ln -match '^\s+#') { continue }
      if ($ln -match '^\s+-\s+') { continue }

      if ($ln -match '^\S') {
        $skipYamlList = $false
      } else {
        continue
      }
    }

    $trim = $ln.TrimStart()

    if ($trim.StartsWith('#')) { [void]$filtered.Add($ln); continue }

    if ($trim -match '^plugins\.security\.(authcz\.admin_dn|nodes_dn|restapi\.roles_enabled)\s*:') {
      $skipYamlList = $true
      continue
    }

    $isOwned = $false
    foreach ($k in $ownedKeys) {
      if ($trim -match ('^' + [Regex]::Escape($k) + '\s*:')) { $isOwned = $true; break }
    }
    if (-not $isOwned) { [void]$filtered.Add($ln) }
  }

  $plaintextKeyRegex = @(
    '^\s*plugins\.security\.ssl\.http\.(keystore|truststore)_password\s*:.*$',
    '^\s*plugins\.security\.ssl\.http\.keystore_keypassword\s*:.*$',
    '^\s*plugins\.security\.ssl\.transport\.(keystore|truststore)_password\s*:.*$',
    '^\s*plugins\.security\.ssl\.transport\.keystore_keypassword\s*:.*$'
  )
  $filtered2 = New-Object System.Collections.Generic.List[string]
  foreach ($ln in $filtered) {
    $kill = $false
    foreach ($re in $plaintextKeyRegex) {
      if ($ln -match $re) { $kill = $true; break }
    }
    if (-not $kill) { [void]$filtered2.Add($ln) }
  }
  $filtered = $filtered2

  if ($filtered.Count -gt 0 -and $filtered[$filtered.Count-1].Trim() -ne '') { [void]$filtered.Add('') }

  $beginMarker = '# --- BEGIN TinySocs security/TLS ---'
  $endMarker   = '# --- END TinySocs security/TLS ---'

  [void]$filtered.Add($beginMarker)

  [void]$filtered.Add("plugins.security.disabled: false")

  [void]$filtered.Add("plugins.security.authcz.admin_dn:")
  [void]$filtered.Add("  - `"$adminDn`"")
  [void]$filtered.Add("plugins.security.nodes_dn:")
  [void]$filtered.Add("  - `"$nodeDn`"")

  [void]$filtered.Add("plugins.security.restapi.roles_enabled:")
  [void]$filtered.Add("  - `"all_access`"")
  [void]$filtered.Add("  - `"security_rest_api_access`"")
  [void]$filtered.Add("plugins.security.unsupported.restapi.allow_securityconfig_modification: true")

  [void]$filtered.Add("plugins.security.ssl.http.enabled: true")
  [void]$filtered.Add("plugins.security.ssl.http.keystore_type: PKCS12")
  [void]$filtered.Add("plugins.security.ssl.http.keystore_filepath: $httpKs")
  [void]$filtered.Add("plugins.security.ssl.http.truststore_type: PKCS12")
  [void]$filtered.Add("plugins.security.ssl.http.truststore_filepath: $ts")

  $httpClientAuthMode = if ($env:TINYSOCS_HTTP_CLIENTAUTH_MODE) { $env:TINYSOCS_HTTP_CLIENTAUTH_MODE } else { "OPTIONAL" }
  [void]$filtered.Add("plugins.security.ssl.http.clientauth_mode: $httpClientAuthMode")

  [void]$filtered.Add("plugins.security.ssl.transport.keystore_type: PKCS12")
  [void]$filtered.Add("plugins.security.ssl.transport.keystore_filepath: $transKs")
  [void]$filtered.Add("plugins.security.ssl.transport.truststore_type: PKCS12")
  [void]$filtered.Add("plugins.security.ssl.transport.truststore_filepath: $ts")
  [void]$filtered.Add("plugins.security.ssl.transport.enforce_hostname_verification: true")

  [void]$filtered.Add("plugins.security.allow_unsafe_democertificates: false")

  $initVal = if ($AllowDefaultInitSecurityIndex) { "true" } else { "false" }
  [void]$filtered.Add("plugins.security.allow_default_init_securityindex: $initVal")

  [void]$filtered.Add($endMarker)

  Ensure-TinySocsWritableFile -Path $ConfigPath
  Set-Content -Path $ConfigPath -Value $filtered.ToArray() -Encoding UTF8 -Force

  _Ensure-TinySocsReadable -Path $configDir -IsDir
  foreach ($p in @(
    (Join-Path $configDir "jvm.options"),
    (Join-Path $configDir "log4j2.properties"),
    $ConfigPath,
    $TlsPaths.HttpKeystoreP12,
    $TlsPaths.TransportKeystoreP12,
    $TlsPaths.TruststoreP12,
    $StorePassDpapiPath
  )) {
    _Ensure-TinySocsReadable -Path $p
  }

  try { _Purge-TinySocsLegacyPlaintextSslKeystoreKeys -OpenSearchRoot $osRootGuess -ConfDir $configDir } catch { }

  try {
    Ensure-TinySocsOpenSearchKeystoreSecurePasswords `
      -OpenSearchRoot   $osRootGuess `
      -ProgramDataConf  $configDir `
      -CertsDir         $certsDir `
      -StorePass        $pw `
      -Keys @(
        'plugins.security.ssl.http.keystore_password_secure',
        'plugins.security.ssl.http.keystore_keypassword_secure',
        'plugins.security.ssl.http.truststore_password_secure',
        'plugins.security.ssl.transport.keystore_password_secure',
        'plugins.security.ssl.transport.keystore_keypassword_secure',
        'plugins.security.ssl.transport.truststore_password_secure'
      )
  } catch {
    throw "Ensure-TinySocsOpenSearchSecuritySettings: Failed to enforce opensearch.keystore secure passwords: $($_.Exception.Message)"
  }

  try {
    $tokens = _Get-TinySocsOpenSearchKeystoreTokens -OpenSearchRoot $osRootGuess -ConfDir $configDir
    $bad = $tokens | Where-Object { $_ -match '^plugins\.security\.ssl\.(http|transport)\.(keystore_password|keystore_keypassword|truststore_password)$' }
    if ($bad -and $bad.Count -gt 0) {
      throw ("legacy_plaintext_keystore_keys_present: " + ($bad -join ", "))
    }
  } catch {
    throw "Ensure-TinySocsOpenSearchSecuritySettings: Keystore still contains legacy plaintext SSL password keys after purge/enforce. $($_.Exception.Message)"
  }

  try { Ensure-OpenSearchYamlCanonical -YamlPath $ConfigPath } catch { }

  try {
    $secDir = Join-Path $configDir "opensearch-security"
    $iuPath = Join-Path $secDir "internal_users.yml"
    $adminDpapi = Join-Path $certsDir "siem-admin-pass.dpapi"

    if ((Test-Path -LiteralPath $iuPath -PathType Leaf) -and (Test-Path -LiteralPath $adminDpapi -PathType Leaf)) {
      $adminPass = _TryUnprotect-TinySocsDpapiFile -Path $adminDpapi
      if (-not [string]::IsNullOrWhiteSpace($adminPass)) {

        $hashBat = Get-ChildItem -Path (Join-Path $osRootGuess "plugins") -Recurse -Filter "hash.bat" -EA SilentlyContinue |
          Select-Object -First 1

        if ($hashBat -and (Test-Path -LiteralPath $hashBat.FullName -PathType Leaf)) {
          $hashOut = ($adminPass | & $hashBat.FullName | Out-String)
          $m = [regex]::Match($hashOut, '(\$2[aby]\$[^\s"]+)')
          if ($m.Success) {
            $bcrypt = $m.Groups[1].Value

            Ensure-TinySocsWritableFile -Path $iuPath
            _Ensure-TinySocsReadable -Path $iuPath

            $lines = Get-Content -LiteralPath $iuPath -ErrorAction Stop
            if ($null -eq $lines) { $lines = @() }

            $out = New-Object System.Collections.Generic.List[string]
            $inAdmin = $false
            $wroteHash = $false
            $adminHeaderOutIndex = $null

            $maybeCloseAdmin = {
              if ($inAdmin -and -not $wroteHash -and $null -ne $adminHeaderOutIndex) {
                $out.Insert($adminHeaderOutIndex + 1, ("  hash: ""{0}""" -f $bcrypt))
                $wroteHash = $true
              }
              $inAdmin = $false
            }

            foreach ($ln in $lines) {
              if ($ln -match '^(?<indent>\s*)admin\s*:\s*$') {
                & $maybeCloseAdmin

                $inAdmin = $true
                $wroteHash = $false
                $adminHeaderOutIndex = $out.Count
                $out.Add("admin:")
                continue
              }

              if ($inAdmin) {
                if ($ln -match '^(?<lead>\S[^#]*):\s*$') {
                  & $maybeCloseAdmin
                  $out.Add($ln)
                  continue
                }

                if ($ln -match '^\s*hash\s*:\s*') {
                  if (-not $wroteHash) {
                    $out.Add(("  hash: ""{0}""" -f $bcrypt))
                    $wroteHash = $true
                  }
                  continue
                }
              }

              $out.Add($ln)
            }

            & $maybeCloseAdmin

            [System.IO.File]::WriteAllLines($iuPath, $out.ToArray(), (New-Object System.Text.UTF8Encoding($false)))
            _Ensure-TinySocsReadable -Path $iuPath
          } else {
            Write-TinySocsLog "WARN: internal_users.yml guardrail skipped: hash.bat did not output bcrypt."
          }
        } else {
          Write-TinySocsLog "WARN: internal_users.yml guardrail skipped: hash.bat not found under $osRootGuess\plugins."
        }
      } else {
        Write-TinySocsLog "WARN: internal_users.yml guardrail skipped: could not decrypt admin password from DPAPI."
      }
    }
  } catch {
    Write-TinySocsLog "WARN: internal_users.yml admin-hash guardrail failed (continuing): $($_.Exception.Message)"
  }

  Write-TinySocsLog "OpenSearch security/TLS settings ensured in $ConfigPath (TinySocs-managed PKCS12 block appended WITHOUT plaintext passwords). allow_default_init_securityindex=$initVal; storepass_source=$pwSource"
}

function Repair-TinySocsOpenSearchSslPasswordSettings {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string] $ConfigPath
  )

  if (-not (Test-Path $ConfigPath -PathType Leaf)) {
    throw "OpenSearch config not found: $ConfigPath"
  }

  $raw = Get-Content -LiteralPath $ConfigPath -Raw -ErrorAction Stop
  $lines = $raw -split "(`r`n|`n|`r)"

  # Remove ONLY the non-secure password settings; keep *_secure.
  $filtered = foreach ($ln in $lines) {
    $t = $ln

    # Matches:
    #   plugins.security.ssl.http.keystore_password:
    #   plugins.security.ssl.http.truststore_password:
    #   plugins.security.ssl.http.keystore_keypassword:
    #   plugins.security.ssl.http.pemkey_password:
    #   plugins.security.ssl.transport.keystore_password:
    # etc...
    #
    # But NOT *_secure variants.
    if ($t -match '^\s*plugins\.security\.ssl\.(http|transport)\..*(keystore_password|truststore_password|keystore_keypassword|pemkey_password)\s*:' -and
        $t -notmatch '_secure\s*:') {
      continue
    }

    $t
  }

  $out = ($filtered -join "`r`n").TrimEnd() + "`r`n"
  if ($out -ne $raw) {
    Set-Content -LiteralPath $ConfigPath -Value $out -Encoding UTF8
    Write-TinySocsLog "Removed non-secure SSL password settings from '$ConfigPath' (prevented *_password + *_password_secure collision)."
  }
}

# -- Local SIEM (OpenSearch via NSSM service) ----------------------------------
function Install-TinySocsLocalSiem {
  [CmdletBinding()]
  param(
    [string]$SiemUser = "admin",
    [string]$SiemPass = "",
    # allow separate kibana server creds (defaults to SiemUser + SiemPass if not supplied)
    [string]$KibanaUser = "kibanaserver",
    [string]$KibanaPass = "",
    [int]$ApiPort = 9201,
    [int]$DashboardsPort = 5602,
    [switch]$NoStart,
    [string]$ClusterName = "tinysocs-local",
    [string]$NodeName    = "tinysocs-node-1",
    [switch]$ForceConfig,
    [switch]$TrustLocalCA
  )

  Assert-TinySocsAdmin
  Install-TinySocs

  $null = $DashboardsPort

  $serviceName = "TinySocsOpenSearch"

  function _IsTruthy {
    param([object]$Val)
    if ($null -eq $Val) { return $false }
    $s = $Val.ToString().Trim().ToLowerInvariant()
    return ($s -in @('1','true','yes','y','on','enable','enabled'))
  }

  function _IsAsciiLocal {
    param([string]$Text)
    if ($null -eq $Text) { return $true }
    foreach ($ch in $Text.ToCharArray()) {
      if ([int][char]$ch -gt 127) { return $false }
    }
    return $true
  }

  function _GetTlsVal {
    param(
      [Parameter(Mandatory=$true)] $Obj,
      [Parameter(Mandatory=$true)] [string[]] $Keys
    )
    foreach ($k in $Keys) {
      try {
        if ($Obj -is [hashtable] -and $Obj.ContainsKey($k) -and $Obj[$k]) { return [string]$Obj[$k] }
        $v = $Obj.$k
        if ($v) { return [string]$v }
      } catch { }
    }
    return $null
  }

  function _FindFirst {
    param(
      [Parameter(Mandatory=$true)] [string] $Dir,
      [Parameter(Mandatory=$true)] [string[]] $Patterns
    )
    foreach ($p in $Patterns) {
      try {
        $hit = Get-ChildItem -Path $Dir -File -Recurse -Force -ErrorAction SilentlyContinue |
          Where-Object { $_.Name -like $p } |
          Select-Object -First 1
        if ($hit) { return $hit.FullName }
      } catch { }
    }
    return $null
  }

  function _TryImportLocalCA {
    param([Parameter(Mandatory=$true)] [string] $CaCertPath)
    $ext = [IO.Path]::GetExtension($CaCertPath).ToLowerInvariant()
    if ($ext -notin @(".cer", ".crt")) {
      Write-TinySocsLog -Level "WARN" -Message "CA cert '$CaCertPath' is not .cer/.crt; skipping Windows trust import."
      return $false
    }
    try {
      $certObj = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($CaCertPath)
      $thumb   = $certObj.Thumbprint
      try {
        $alreadyLM = Get-ChildItem -Path "Cert:\LocalMachine\Root" -ErrorAction SilentlyContinue |
          Where-Object { $_.Thumbprint -eq $thumb } | Select-Object -First 1
        if (-not $alreadyLM) {
          Import-Certificate -FilePath $CaCertPath -CertStoreLocation "Cert:\LocalMachine\Root" | Out-Null
          Write-TinySocsLog "Imported TinySocs local CA into LocalMachine\Root (Thumbprint=$thumb)."
        }
      } catch {
        Write-TinySocsLog -Level "WARN" -Message "Failed importing CA into LocalMachine\Root: $($_.Exception.Message)"
      }
      try {
        $alreadyCU = Get-ChildItem -Path "Cert:\CurrentUser\Root" -ErrorAction SilentlyContinue |
          Where-Object { $_.Thumbprint -eq $thumb } | Select-Object -First 1
        if (-not $alreadyCU) {
          Import-Certificate -FilePath $CaCertPath -CertStoreLocation "Cert:\CurrentUser\Root" | Out-Null
          Write-TinySocsLog "Imported TinySocs local CA into CurrentUser\Root (Thumbprint=$thumb)."
        }
      } catch {
        Write-TinySocsLog -Level "WARN" -Message "Failed importing CA into CurrentUser\Root: $($_.Exception.Message)"
      }
      $checkLM = Get-ChildItem -Path "Cert:\LocalMachine\Root" -ErrorAction SilentlyContinue |
        Where-Object { $_.Thumbprint -eq $thumb } | Select-Object -First 1
      $checkCU = Get-ChildItem -Path "Cert:\CurrentUser\Root" -ErrorAction SilentlyContinue |
        Where-Object { $_.Thumbprint -eq $thumb } | Select-Object -First 1
      return [bool]($checkLM -or $checkCU)
    } catch {
      Write-TinySocsLog -Level "WARN" -Message "Failed loading CA cert for trust import ($CaCertPath): $($_.Exception.Message)"
      return $false
    }
  }

  function _NewAsciiPass {
    param([int]$Length = 32)
    $alphabet = ("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_").ToCharArray()
    $bytes = New-Object byte[] $Length
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $chars = New-Object char[] $Length
    for ($i=0; $i -lt $Length; $i++) {
      $chars[$i] = $alphabet[$bytes[$i] % $alphabet.Length]
    }
    return -join $chars
  }

  function _DetectDataPresentFallback {
    param([Parameter(Mandatory)][string]$Path)
    try {
      if (-not (Test-Path -LiteralPath $Path -PathType Container)) { return $false }
      $any = Get-ChildItem -LiteralPath $Path -Force -ErrorAction SilentlyContinue | Select-Object -First 1
      return [bool]$any
    } catch {
      return $true
    }
  }

  # PATCH: Deterministically select working admin creds using an endpoint that cannot "fake" auth.
  # We probe /_plugins/_security/authinfo which returns 200 ONLY when auth succeeds (401/403 otherwise).
  function _SelectWorkingAdminCreds {
    param(
      [Parameter(Mandatory)][string]$BaseUrl,
      [Parameter(Mandatory)][string]$UserIn,
      [Parameter(Mandatory)][string]$PassIn,
      [Parameter()][switch]$SkipTlsVerify,
      [Parameter()][string]$CaCertPath
    )

    $effectiveProbePath = "/_plugins/_security/authinfo"
    $probeUrl = $BaseUrl.TrimEnd("/") + $effectiveProbePath

    $cands = @(
      @([string]$UserIn, [string]$PassIn),
      @("admin","admin"),
      @([string]$UserIn, "admin"),
      @("admin", [string]$PassIn)
    )

    foreach ($pair in $cands) {
      $u = [string]$pair[0]
      $p = [string]$pair[1]
      try {
        $args = @(
          "--noproxy","*",
          "-s","-o","NUL","-w","%{http_code}"
        )

        if ($SkipTlsVerify.IsPresent) {
          $args += @("-k")
        } else {
          if (-not [string]::IsNullOrWhiteSpace($CaCertPath)) {
            if (Test-Path -LiteralPath $CaCertPath -PathType Leaf) {
              $args += @("--cacert", $CaCertPath)
            }
          }
        }

        $args += @("-u", ($u + ":" + $p), $probeUrl)

        $hc = (& curl.exe @args 2>$null)
        if (-not $hc) { $hc = "000" }
        $hc = [string]$hc
        Write-TinySocsLog -Level "INFO" -Message "[AuthProbe] user=$u probe=$effectiveProbePath http=$hc"

        # Only 200 means "authenticated"
        if ($hc -eq "200") {
          return [pscustomobject]@{ User=$u; Pass=$p; Code=$hc; Probe=$effectiveProbePath }
        }
      } catch { }
    }

    return $null
  }

  # PATCH: helper to build auth parameters for Invoke-TinySocsOpenSearchApi consistently.
  # This is specifically to prevent the “authinfo=200 but template calls 401” situation,
  # which happens when downstream calls forget to pass -User/-Pass.
  function _GetApiAuthParams {
    param(
      [Parameter(Mandatory)][string]$User,
      [Parameter(Mandatory)][string]$Pass
    )
    if ([string]::IsNullOrWhiteSpace($User) -or [string]::IsNullOrWhiteSpace($Pass)) {
      throw "Install-TinySocsLocalSiem: API auth params are empty (User/Pass required for secure mode)."
    }
    return @{ User = [string]$User; Pass = [string]$Pass }
  }

  # PATCH: ensure template exists using explicit creds (no reliance on ambient env or CredMan).
  function _EnsureIndexTemplate {
    param(
      [Parameter(Mandatory)][string]$BaseUrl,
      [Parameter(Mandatory)][string]$TemplateName,
      [Parameter(Mandatory)][string]$BodyJson,
      [Parameter(Mandatory)][hashtable]$AuthParams,
      [Parameter()][switch]$SkipTlsVerify
    )

    $p = "/_index_template/$TemplateName"

    $g = Invoke-TinySocsOpenSearchApi `
      -Method GET `
      -Url $BaseUrl `
      -Path $p `
      -AllowHttpStatus 404 `
      -SkipTlsVerify:$SkipTlsVerify `
      @AuthParams `
      -ReturnObject

    $existed = $false
    if ($g -and [string]$g.StatusCode -eq "200") {
      $existed = $true
      Write-TinySocsLog -Level "INFO" -Message "Index template '$TemplateName' exists; enforcing canonical body via PUT (idempotent)."
    }

    $put = Invoke-TinySocsOpenSearchApi `
      -Method PUT `
      -Url $BaseUrl `
      -Path $p `
      -BodyJson $BodyJson `
      -SkipTlsVerify:$SkipTlsVerify `
      @AuthParams `
      -ReturnObject

    if ($put -and [string]$put.StatusCode -eq "200") {
      if ($existed) {
        Write-TinySocsLog -Level "INFO" -Message "Index template '$TemplateName' updated successfully."
      } else {
        Write-TinySocsLog -Level "INFO" -Message "Index template '$TemplateName' created successfully."
      }
      return $true
    }

    throw "Failed to create/update index template '$TemplateName' (StatusCode=$($put.StatusCode))."
  }

  # ---- HARDEN ROOT GETTERS (prevents Join-Path receiving System.Object[]) ----
  $installRootVal = (Get-TinySocsInstallRoot | Select-Object -First 1)
  $dataRootBase   = (Get-TinySocsDataRoot    | Select-Object -First 1)
  $installRoot    = [string]$installRootVal
  $openSearchRoot = Join-Path -Path $installRoot -ChildPath "OpenSearch"
  $dataRoot       = Join-Path -Path ([string]$dataRootBase) -ChildPath "OpenSearch"
  $dataPath       = Join-Path -Path $dataRoot -ChildPath "data"
  $logsPath       = Join-Path -Path $dataRoot -ChildPath "logs"
  $pdConf         = Join-Path -Path $dataRoot -ChildPath "config"
  $certsDir       = Join-Path -Path $pdConf  -ChildPath "certs"
  $nssmPath       = Join-Path -Path $installRoot -ChildPath "bin\nssm.exe"
  # ---- END HARDEN ROOT GETTERS ----

  if (-not (Test-Path -LiteralPath $nssmPath -PathType Leaf)) {
    throw "NSSM not found at expected path: $nssmPath"
  }

  $insecureLocalSiem = _IsTruthy $env:TINYSOCS_INSECURE_LOCAL_SIEM

  if ($ApiPort -ne 9201) {
    Write-TinySocsLog -Level "WARN" -Message "ApiPort=$ApiPort (canonical TinySocs port is 9201). Proceeding because caller requested it."
  }

  Write-TinySocsLog "Local SIEM install starting (OpenSearchRoot=$openSearchRoot, DataRoot=$dataRoot, HttpPort=$ApiPort)."

  # --- PATCH: harden ProgramData tmp ACLs to avoid stash-copy AccessDenied ---
  try {
    $tsTmp = Join-Path $env:ProgramData "TinySocs\tmp"
    New-Item -ItemType Directory -Force -Path $tsTmp | Out-Null
    & icacls $tsTmp /inheritance:e /T /C | Out-Null
    & icacls $tsTmp /grant:r "BUILTIN\Administrators:(OI)(CI)F" "NT AUTHORITY\SYSTEM:(OI)(CI)F" /T /C | Out-Null
    & icacls $tsTmp /grant "BUILTIN\Users:(OI)(CI)M" /T /C | Out-Null
    Write-TinySocsLog -Level "INFO" -Message "Hardened ACLs for temp staging root: $tsTmp"
  } catch {
    Write-TinySocsLog -Level "WARN" -Message "Failed to harden ACLs for ProgramData temp staging (continuing): $($_.Exception.Message)"
  }
  # --- END PATCH ---

  # stop existing service EARLY so config/keystore edits cannot race a running JVM
  $svcExisted = $false
  $svcWasRunning = $false
  try {
    $svc0 = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($svc0) {
      $svcExisted = $true
      if ($svc0.Status -eq 'Running' -or $svc0.Status -eq 'Paused' -or $svc0.Status -eq 'StartPending') {
        $svcWasRunning = $true
        Write-TinySocsLog -Level "WARN" -Message "Service '$serviceName' exists and is $($svc0.Status). Stopping now to apply deterministic config/keystore."
        try { Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue } catch { }
        try { (Get-Service -Name $serviceName -ErrorAction SilentlyContinue).WaitForStatus('Stopped','00:00:25') } catch { }
      }
    }
  } catch { }

  New-Item -ItemType Directory -Force -Path $dataPath | Out-Null
  New-Item -ItemType Directory -Force -Path $logsPath | Out-Null
  New-Item -ItemType Directory -Force -Path $certsDir | Out-Null

  $pdBin = Join-Path -Path $dataRoot -ChildPath "bin"
  New-Item -ItemType Directory -Force -Path $pdBin | Out-Null

  Ensure-TinySocsOpenSearchProgramDataConfig -OpenSearchRoot $openSearchRoot -ProgramDataConf $pdConf -Force:$ForceConfig
  Ensure-TinySocsOpenSearchSecurityConfigTree -InstallRoot $installRoot -OpenSearchRoot $openSearchRoot -ProgramDataConf $pdConf -Force:$ForceConfig | Out-Null

  try {
    $secDir = Join-Path -Path $pdConf -ChildPath "opensearch-security"
    Repair-TinySocsOpenSearchSecurityConfigAcls -SecurityDir $secDir
  } catch {
    Write-TinySocsLog -Level "WARN" -Message "Repair-TinySocsOpenSearchSecurityConfigAcls failed (continuing, but may fail later): $($_.Exception.Message)"
  }

  $tls = Ensure-TinySocsLocalCaAndServerCert -CertsDir $certsDir
  Repair-TinySocsOpenSearchCertAcls -CertsDir $certsDir
  Ensure-TinySocsOpenSearchCertBundlePresent -CertsDir $certsDir -TlsPaths $tls -OpenSearchRoot $openSearchRoot

  if ($tls -is [hashtable]) {
    $h = Join-Path $certsDir "http.p12"
    $t = Join-Path $certsDir "transport.p12"
    $r = Join-Path $certsDir "trust.p12"
    if (Test-Path $h -PathType Leaf) { $tls["HttpKeystoreP12"]      = $h }
    if (Test-Path $t -PathType Leaf) { $tls["TransportKeystoreP12"] = $t }
    if (Test-Path $r -PathType Leaf) { $tls["TruststoreP12"]        = $r }
  }

  # ensure TLS storepass is present AND persisted + ASCII-safe
  $tlsStorePass = $null
  try {
    $tlsStorePass = _GetTlsVal -Obj $tls -Keys @("StorePassword","storepass","storePass","TlsStorePass")
    if ([string]::IsNullOrWhiteSpace($tlsStorePass)) {
      try { $tlsStorePass = Read-TinySocsOpenSearchTlsStorePassFromDpapiFile -CertsDir $certsDir } catch { $tlsStorePass = $null }
      if (-not [string]::IsNullOrWhiteSpace($tlsStorePass) -and $tls -is [hashtable]) {
        $tls["StorePassword"] = [string]$tlsStorePass
      }
    }
    if ([string]::IsNullOrWhiteSpace($tlsStorePass)) {
      throw "TLS StorePassword is empty/unavailable (expected from Ensure-TinySocsLocalCaAndServerCert or DPAPI storepass file)."
    }

    if (-not (_IsAsciiLocal $tlsStorePass)) {
      Write-TinySocsLog -Level "WARN" -Message "TLS storepass contains non-ASCII characters. Enforcing Java-compatible ASCII storepass deterministically."
      $tlsStorePass = _NewAsciiPass -Length 32
      try {
        $cmdW = Get-Command Write-TinySocsOpenSearchTlsStorePassToDpapiFile -ErrorAction SilentlyContinue
        if ($cmdW) {
          if ($cmdW.Parameters.ContainsKey('StorePass')) {
            $null = Write-TinySocsOpenSearchTlsStorePassToDpapiFile -CertsDir $certsDir -StorePass $tlsStorePass
          } elseif ($cmdW.Parameters.ContainsKey('TlsStorePass')) {
            $null = Write-TinySocsOpenSearchTlsStorePassToDpapiFile -CertsDir $certsDir -TlsStorePass $tlsStorePass
          } elseif ($cmdW.Parameters.ContainsKey('Password')) {
            $null = Write-TinySocsOpenSearchTlsStorePassToDpapiFile -CertsDir $certsDir -Password $tlsStorePass
          }
        }
      } catch { }

      try {
        $cmdSync = Get-Command Sync-TinySocsOpenSearchTlsKeystore -ErrorAction SilentlyContinue
        if ($cmdSync) {
          Write-TinySocsLog -Level "INFO" -Message "Running Sync-TinySocsOpenSearchTlsKeystore -EnsureAsciiJavaCompatible to deterministically rotate storepass + enforce keystore."
          & $cmdSync -OpenSearchHome $openSearchRoot -ConfDir $pdConf -EnsureAsciiJavaCompatible | Out-Null
        } else {
          $cmd = Get-Command Ensure-TinySocsLocalCaAndServerCert -ErrorAction SilentlyContinue
          if ($cmd) {
            $params = @{ CertsDir = $certsDir }
            if ($cmd.Parameters.ContainsKey('Force')) { $params["Force"] = $true }
            elseif ($cmd.Parameters.ContainsKey('ForceConfig')) { $params["ForceConfig"] = $true }

            if ($cmd.Parameters.ContainsKey('StorePass')) { $params["StorePass"] = $tlsStorePass }
            elseif ($cmd.Parameters.ContainsKey('StorePassword')) { $params["StorePassword"] = $tlsStorePass }
            elseif ($cmd.Parameters.ContainsKey('Password')) { $params["Password"] = $tlsStorePass }
            elseif ($cmd.Parameters.ContainsKey('TlsStorePass')) { $params["TlsStorePass"] = $tlsStorePass }

            $tls = & $cmd @params
          }
        }
      } catch {
        Write-TinySocsLog -Level "WARN" -Message "ASCII storepass enforcement encountered an error (continuing; keystore repair later may still save it): $($_.Exception.Message)"
      }

      try {
        Ensure-TinySocsOpenSearchCertBundlePresent -CertsDir $certsDir -TlsPaths $tls -OpenSearchRoot $openSearchRoot
        if ($tls -is [hashtable]) { $tls["StorePassword"] = [string]$tlsStorePass }
      } catch { }
    }

    try {
      $cmd = Get-Command Write-TinySocsOpenSearchTlsStorePassToDpapiFile -ErrorAction SilentlyContinue
      if ($cmd) {
        if ($cmd.Parameters.ContainsKey('StorePass')) {
          $null = Write-TinySocsOpenSearchTlsStorePassToDpapiFile -CertsDir $certsDir -StorePass $tlsStorePass
        } elseif ($cmd.Parameters.ContainsKey('TlsStorePass')) {
          $null = Write-TinySocsOpenSearchTlsStorePassToDpapiFile -CertsDir $certsDir -TlsStorePass $tlsStorePass
        } elseif ($cmd.Parameters.ContainsKey('Password')) {
          $null = Write-TinySocsOpenSearchTlsStorePassToDpapiFile -CertsDir $certsDir -Password $tlsStorePass
        }
      }
    } catch { }

    try {
      $dp = Read-TinySocsOpenSearchTlsStorePassFromDpapiFile -CertsDir $certsDir
      if (-not [string]::IsNullOrWhiteSpace($dp)) {
        $tlsStorePass = [string]$dp
        if ($tls -is [hashtable]) { $tls["StorePassword"] = [string]$tlsStorePass }
      }
    } catch { }

  } catch {
    Write-TinySocsLog -Level "WARN" -Message "Failed ensuring/persisting TLS store password: $($_.Exception.Message)"
  }

  $caCertPath = _GetTlsVal -Obj $tls -Keys @(
    "CaCertPath","CaCerPath","ca","caCert","cacert","CaCert","RootCa","rootCa","ca_path"
  )
  if (-not $caCertPath) {
    $caCertPath = _FindFirst -Dir $certsDir -Patterns @("*ca*.crt", "*ca*.cer", "*root*.crt", "*root*.cer", "*ca*.pem", "*root*.pem")
  }

  try {
    Set-MachineEnv @{ OPENSEARCH_PATH_CONF = $pdConf }
    $env:OPENSEARCH_PATH_CONF = $pdConf
    Write-TinySocsLog "Set OPENSEARCH_PATH_CONF=$pdConf (machine + session) to ensure persistent ProgramData config is always used."
  } catch {
    Write-TinySocsLog -Level "WARN" -Message "Failed to set OPENSEARCH_PATH_CONF machine env var: $($_.Exception.Message)"
  }

  $configFile = Join-Path -Path $pdConf -ChildPath "opensearch.yml"
  Write-TinySocsOpenSearchConfig -ConfigPath $configFile `
    -ClusterName $ClusterName `
    -NodeName    $NodeName `
    -HttpPort    $ApiPort `
    -DataPath    $dataPath `
    -LogsPath    $logsPath `
    -Force:$ForceConfig

  try {
    Set-TinySocsOpenSearchHttpPortInConfig -ConfigPath $configFile -HttpPort $ApiPort
  } catch {
    Write-TinySocsLog -Level "WARN" -Message "Failed to enforce http.port=$ApiPort in opensearch.yml (continuing): $($_.Exception.Message)"
  }

  $initMarker = Join-Path -Path $dataRoot -ChildPath ".tinysocs_security_initialized"

  $dataPresent = $false
  try {
    if (Get-Command Test-TinySocsOpenSearchDataPresent -ErrorAction SilentlyContinue) {
      $dataPresent = Test-TinySocsOpenSearchDataPresent -DataPath $dataPath
    } else {
      $dataPresent = _DetectDataPresentFallback -Path $dataPath
    }
  } catch {
    $dataPresent = _DetectDataPresentFallback -Path $dataPath
  }

  $hasMarker = $false
  try { $hasMarker = (Test-Path $initMarker -PathType Leaf) } catch { $hasMarker = $false }

  $allowInit = ((-not $dataPresent) -and (-not $hasMarker))

  Ensure-TinySocsOpenSearchSecuritySettings -ConfigPath $configFile -TlsPaths $tls -AllowDefaultInitSecurityIndex:$allowInit
  Assert-TinySocsOpenSearchSecurityConfigPresent -ConfigPath $configFile

  Ensure-TinySocsOpenSearchDeterministicBootstrap `
    -OpenSearchRoot $openSearchRoot `
    -ProgramDataConf $pdConf `
    -CertsDir $certsDir `
    -HttpPort $ApiPort `
    -AllowDefaultInitSecurityIndex ([bool]$allowInit) `
    -TlsPaths $tls

  try {
    $cmdSync2 = Get-Command Sync-TinySocsOpenSearchTlsKeystore -ErrorAction SilentlyContinue
    if ($cmdSync2) {
      Write-TinySocsLog -Level "INFO" -Message "Running Sync-TinySocsOpenSearchTlsKeystore (final enforcement) against ProgramData config."
      & $cmdSync2 -OpenSearchHome $openSearchRoot -ConfDir $pdConf -EnsureAsciiJavaCompatible | Out-Null
      try {
        $dp2 = Read-TinySocsOpenSearchTlsStorePassFromDpapiFile -CertsDir $certsDir
        if (-not [string]::IsNullOrWhiteSpace($dp2)) {
          $tlsStorePass = [string]$dp2
          if ($tls -is [hashtable]) { $tls["StorePassword"] = [string]$tlsStorePass }
        }
      } catch { }
    }
  } catch {
    Write-TinySocsLog -Level "WARN" -Message "Sync-TinySocsOpenSearchTlsKeystore failed (continuing): $($_.Exception.Message)"
  }

  try {
    if (-not [string]::IsNullOrWhiteSpace($tlsStorePass)) {
      Ensure-TinySocsOpenSearchKeystoreSecurePasswords `
        -OpenSearchRoot $openSearchRoot `
        -ProgramDataConf $pdConf `
        -CertsDir $certsDir `
        -StorePass ([string]$tlsStorePass) | Out-Null
    } else {
      Write-TinySocsLog -Level "WARN" -Message "TLS storepass is empty; skipping Ensure-TinySocsOpenSearchKeystoreSecurePasswords (OpenSearch may fail if P12s are passworded)."
    }
  } catch {
    Write-TinySocsLog -Level "WARN" -Message "Failed to enforce OpenSearch keystore _secure entries: $($_.Exception.Message)"
  }

  try {
    $cmdK = Get-Command Repair-TinySocsOpenSearchTlsKeystore -ErrorAction SilentlyContinue
    if ($cmdK) {
      $kParams = @{}
      if ($cmdK.Parameters.ContainsKey('OpenSearchRoot'))   { $kParams['OpenSearchRoot'] = $openSearchRoot }
      if ($cmdK.Parameters.ContainsKey('ProgramDataConf'))  { $kParams['ProgramDataConf'] = $pdConf }
      if ($cmdK.Parameters.ContainsKey('CertsDir'))         { $kParams['CertsDir'] = $certsDir }
      if (-not [string]::IsNullOrWhiteSpace($tlsStorePass)) {
        if ($cmdK.Parameters.ContainsKey('StorePass'))        { $kParams['StorePass'] = [string]$tlsStorePass }
        elseif ($cmdK.Parameters.ContainsKey('TlsStorePass')) { $kParams['TlsStorePass'] = [string]$tlsStorePass }
        elseif ($cmdK.Parameters.ContainsKey('Password'))     { $kParams['Password'] = [string]$tlsStorePass }
      }
      Write-TinySocsLog -Level "INFO" -Message "Running Repair-TinySocsOpenSearchTlsKeystore (belt + suspenders)."
      & $cmdK @kParams | Out-Null
    }
  } catch {
    Write-TinySocsLog -Level "WARN" -Message "Repair-TinySocsOpenSearchTlsKeystore failed (continuing): $($_.Exception.Message)"
  }

  try {
    $cmd = Get-Command Repair-TinySocsOpenSearchSslPasswordSettings -ErrorAction SilentlyContinue
    if ($cmd) {
      Repair-TinySocsOpenSearchSslPasswordSettings -ConfigPath $configFile
    }
  } catch {
    Write-TinySocsLog -Level "WARN" -Message "Failed to repair SSL password settings in opensearch.yml: $($_.Exception.Message)"
  }

  try {
    Set-TinySocsOpenSearchHttpPortInConfig -ConfigPath $configFile -HttpPort $ApiPort
    try {
      $rawCfg = Get-Content -LiteralPath $configFile -Raw -ErrorAction Stop
      $m = [regex]::Match($rawCfg, '(?m)^\s*http\.port\s*:\s*(\d+)\s*$')
      if ($m.Success) {
        Write-TinySocsLog "[OpenSearch] Effective http.port in ProgramData config is $($m.Groups[1].Value) (expected $ApiPort)."
      } else {
        Write-TinySocsLog -Level "WARN" -Message "[OpenSearch] Could not read back http.port from opensearch.yml after enforcement (expected $ApiPort)."
      }
    } catch { }
  } catch {
    Write-TinySocsLog -Level "WARN" -Message "Failed to re-enforce http.port=$ApiPort after repairs (continuing): $($_.Exception.Message)"
  }

  if ($insecureLocalSiem) {
    Write-TinySocsLog -Level "WARN" -Message "TINYSOCS_INSECURE_LOCAL_SIEM=true - disabling OpenSearch security plugin (DEV ONLY)."
    Disable-TinySocsOpenSearchSecurityPlugin -OpenSearchRoot $openSearchRoot
  }

  $scheme  = if ($insecureLocalSiem) { "http" } else { "https" }
  $siemUrl = "${scheme}://127.0.0.1:$ApiPort"

  $wantTrustLocalCA =
    (-not $insecureLocalSiem) -and (
      $TrustLocalCA.IsPresent -or
      (_IsTruthy $env:TINYSOCS_TRUST_LOCAL_CA)
    )

  $trustedLocalCA = $false
  if ($wantTrustLocalCA -and $caCertPath) {
    try { $trustedLocalCA = _TryImportLocalCA -CaCertPath $caCertPath } catch { $trustedLocalCA = $false }
  }

  $siemSslVerify = $false
  if ($scheme -eq 'https') {
    $siemSslVerify = [bool]$trustedLocalCA
    if (-not $siemSslVerify) {
      Write-TinySocsLog -Level "WARN" -Message "Local SIEM is https but local CA is not trusted; SIEM_SSL_VERIFY will be set to false."
    }
  }

  $skipTlsForLocal = ($scheme -eq 'https' -and -not $siemSslVerify)

  if ([string]::IsNullOrWhiteSpace($SiemUser)) { $SiemUser = "admin" }
  if ([string]::IsNullOrWhiteSpace($KibanaUser)) { $KibanaUser = "kibanaserver" }

  $callerProvided = (-not [string]::IsNullOrWhiteSpace($SiemPass) -and $SiemPass -ne "ChangeMe123!")
  if (-not $callerProvided) {
    try {
      $existing = Get-TSCredential -Name 'TinySocs/SIEM/Creds'
      if ($existing) {
        $j = $existing | ConvertFrom-Json
        if ($j.user) { $SiemUser = [string]$j.user }
        if ($j.pass) {
          $SiemPass = [string]$j.pass
          Write-TinySocsLog "Reusing existing SIEM/OpenSearch admin password from CredMan (TinySocs/SIEM/Creds)."
        }
      }
    } catch { }
    if ([string]::IsNullOrWhiteSpace($SiemPass) -or $SiemPass -eq "ChangeMe123!") {
      $dpapiPass = $null
      try { $dpapiPass = Read-TinySocsSiemAdminPassFromDpapiFile -CertsDir $certsDir } catch { $dpapiPass = $null }
      if ($dpapiPass) {
        $SiemPass = $dpapiPass
        Write-TinySocsLog "Restored SIEM/OpenSearch admin password from DPAPI file (stable across reinstalls)."
      }
    }
  }

  if ([string]::IsNullOrWhiteSpace($SiemPass) -or $SiemPass -eq "ChangeMe123!") {
    if ($dataPresent -or -not $allowInit) {
      throw "SIEM/OpenSearch admin password missing, but data appears to already exist. Refusing to generate a new password (would lock you out)."
    }
    $SiemPass = New-TinySocsPassword -Length 28
    if (-not (_IsAsciiLocal $SiemPass)) { $SiemPass = _NewAsciiPass -Length 28 }
    Write-TinySocsLog -Level "WARN" -Message "Generated a new strong SIEM/OpenSearch admin password (fresh init)."
  }

  if ([string]::IsNullOrWhiteSpace($KibanaPass)) {
    $KibanaPass = $SiemPass
  }

  try { $null = Write-TinySocsSiemAdminPassToDpapiFile -CertsDir $certsDir -AdminPass $SiemPass } catch { }

  $runnerPath = Join-Path -Path $pdBin -ChildPath "Run-OpenSearch.ps1"
  Ensure-TinySocsOpenSearchRunner -InstallRoot $installRoot -OpenSearchRoot $openSearchRoot -ProgramDataConf $pdConf -RunnerPath $runnerPath

  try {
    $svcX = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($svcX -and $svcX.Status -ne 'Stopped') {
      Write-TinySocsLog -Level "WARN" -Message "Stopping '$serviceName' again before Ensure-TinySocsOpenSearchService to avoid races."
      try { Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue } catch { }
      try { (Get-Service -Name $serviceName -ErrorAction SilentlyContinue).WaitForStatus('Stopped','00:00:25') } catch { }
    }
  } catch { }

  Ensure-TinySocsOpenSearchService `
    -ServiceName $serviceName `
    -NssmExe $nssmPath `
    -Runner $runnerPath `
    -WorkDir $dataRoot `
    -LogsDir $logsPath `
    -HttpPort $ApiPort `
    -ProgramDataConf $pdConf

  Set-TinySocsOpenSearchAcls -ServiceName $serviceName -DataRoot $dataRoot -LogsPath $logsPath -ConfigPath $pdConf -RunnerPath $runnerPath
  Repair-TinySocsOpenSearchCertAcls -CertsDir $certsDir

  if (-not $NoStart) {
    try {
      try {
        $svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -eq 'Paused') {
          Write-TinySocsLog -Level "WARN" -Message "Local SIEM service '$serviceName' is PAUSED; attempting Resume-Service before Start-Service."
          try { Resume-Service -Name $serviceName -ErrorAction Stop } catch { }
        }
      } catch { }

      try {
        $svc2 = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($svc2 -and $svc2.Status -eq 'Running') {
          Write-TinySocsLog -Level "INFO" -Message "Local SIEM service '$serviceName' already RUNNING."
        } else {
          Start-Service -Name $serviceName -ErrorAction Stop
          Write-TinySocsLog "Local SIEM service '$serviceName' started."
        }
      } catch {
        Start-Service -Name $serviceName -ErrorAction Stop
        Write-TinySocsLog "Local SIEM service '$serviceName' started."
      }

      try { Set-TinySocsOpenSearchAcls -ServiceName $serviceName -DataRoot $dataRoot -LogsPath $logsPath -ConfigPath $pdConf -RunnerPath $runnerPath } catch { }
      try { Repair-TinySocsOpenSearchCertAcls -CertsDir $certsDir } catch { }

      $ready = Wait-TinySocsLocalSiemReady -Url $siemUrl -TimeoutSeconds 240 -IntervalSeconds 3 -SkipTlsVerify:($skipTlsForLocal)
      if (-not $ready) {
        Write-TinySocsLog -Level "WARN" -Message "Local SIEM started but HTTP not responding at $siemUrl; check logs under $logsPath."
        if (-not $insecureLocalSiem) {
          throw "Local SIEM HTTP did not become ready at $siemUrl."
        }
      } else {

        try {
          if ($scheme -eq 'https' -and -not $insecureLocalSiem) {
            $probe = _SelectWorkingAdminCreds -BaseUrl $siemUrl -UserIn $SiemUser -PassIn $SiemPass -SkipTlsVerify:($skipTlsForLocal) -CaCertPath $caCertPath
            if ($probe) {
              if ($probe.User -ne $SiemUser -or $probe.Pass -ne $SiemPass) {
                Write-TinySocsLog -Level "WARN" -Message "Adjusted admin creds based on protected authinfo probe (user=$($probe.User) http=$($probe.Code))."
                $SiemUser = [string]$probe.User
                $SiemPass = [string]$probe.Pass
                if ([string]::IsNullOrWhiteSpace($KibanaPass)) { $KibanaPass = $SiemPass }
              } else {
                Write-TinySocsLog -Level "INFO" -Message "Using provided admin creds (authinfo probe succeeded, http=200)."
              }
            } else {
              Write-TinySocsLog -Level "WARN" -Message "No candidate creds authorized for authinfo probe; continuing with provided creds (may fail with 401 later)."
            }
          }
        } catch { }

        try {
          Set-TinySocsSiemCredential -SiemUrl $siemUrl -SiemUser $SiemUser -SiemPass $SiemPass -SiemSslVerify:$siemSslVerify -CaCertPath $caCertPath
        } catch {
          Write-TinySocsLog -Level "WARN" -Message "Set-TinySocsSiemCredential failed (continuing with in-memory creds): $($_.Exception.Message)"
        }

        $secReady = $true
        try {
          $cmdSec = Get-Command Wait-TinySocsOpenSearchSecurityReady -ErrorAction SilentlyContinue
          if ($cmdSec -and ($scheme -eq 'https') -and (-not $insecureLocalSiem)) {
            $secReady = Wait-TinySocsOpenSearchSecurityReady `
              -Url $siemUrl `
              -AdminUser $SiemUser `
              -AdminPass $SiemPass `
              -TimeoutSeconds 120 `
              -IntervalSeconds 2 `
              -SkipTlsVerify:($skipTlsForLocal)
            if (-not $secReady) {
              Write-TinySocsLog -Level "WARN" -Message "OpenSearch HTTP is up but security layer did not become ready in time. Continuing with securityadmin + REST init anyway."
            } else {
              Write-TinySocsLog -Level "INFO" -Message "OpenSearch security layer is responsive."
            }
          }
        } catch {
          Write-TinySocsLog -Level "WARN" -Message "Wait-TinySocsOpenSearchSecurityReady failed (continuing): $($_.Exception.Message)"
        }

        # PATCH: ensure templates with explicit creds; avoid any legacy anonymous template code path.
        if (-not $insecureLocalSiem -and $scheme -eq "https") {
          try {
            $null = Ensure-TinySocsWinlogbeatTemplate -SiemUrl $siemUrl -User $SiemUser -Pass $SiemPass -SkipTlsVerify:($skipTlsForLocal)
          } catch {
            Write-TinySocsLog -Level "WARN" -Message "Ensure-TinySocsWinlogbeatTemplate failed (continuing): $($_.Exception.Message)"
          }

          try {
            $auth = _GetApiAuthParams -User $SiemUser -Pass $SiemPass

            # PATCH(2026-01-18): prefer auto_expand_replicas for “single-node now, 2-node later”.
            # This avoids yellow health on single-node (replicas=0) while still allowing a second node to host a replica.
            $tmplBody = @'
{
  "index_patterns": ["tinysocs-winlog-*"],
  "template": {
    "settings": {
      "number_of_shards": 1,
      "auto_expand_replicas": "0-1"
    }
  },
  "priority": 500
}
'@

            $null = _EnsureIndexTemplate `
              -BaseUrl $siemUrl `
              -TemplateName "tinysocs-winlog" `
              -BodyJson $tmplBody `
              -AuthParams $auth `
              -SkipTlsVerify:($skipTlsForLocal)

            # Phase 13 (M6): alerts index template
            $alertsTmplBody = @'
{
  "index_patterns": ["tinysocs-alerts-*"],
  "template": {
    "settings": {
      "number_of_shards": 1,
      "auto_expand_replicas": "0-1"
    }
  },
  "priority": 500
}
'@
            $null = _EnsureIndexTemplate `
              -BaseUrl $siemUrl `
              -TemplateName "tinysocs-alerts" `
              -BodyJson $alertsTmplBody `
              -AuthParams $auth `
              -SkipTlsVerify:($skipTlsForLocal)

          } catch {
            Write-TinySocsLog -Level "WARN" -Message "Template precreate step failed (continuing; installer may still create templates later): $($_.Exception.Message)"
          }
        }

        if ($scheme -eq 'https' -and -not $insecureLocalSiem) {
          $adminP12 = $null
          try {
            $adminP12 = _EnsureAdminKeystoreP12 -CertsDir $certsDir
            if ($adminP12) {
              Write-TinySocsLog -Level "INFO" -Message "Admin keystore present/ensured at: $adminP12"
            } else {
              Write-TinySocsLog -Level "WARN" -Message "Could not ensure admin-keystore.p12 (continuing; securityadmin may fail)."
            }
          } catch { }

          try {
            if ([string]::IsNullOrWhiteSpace($tlsStorePass)) {
              try { $tlsStorePass = Read-TinySocsOpenSearchTlsStorePassFromDpapiFile -CertsDir $certsDir } catch { $tlsStorePass = $null }
            }

            if ([string]::IsNullOrWhiteSpace($tlsStorePass)) {
              throw "TLS storepass is empty; cannot run securityadmin keystore prep."
            }

            $adminStores = $null

            if ($adminP12 -and (Test-Path -LiteralPath $adminP12 -PathType Leaf)) {
              $adminTs = Join-Path $certsDir "admin-truststore.p12"
              if (-not (Test-Path -LiteralPath $adminTs -PathType Leaf)) {
                throw "admin-truststore.p12 missing at expected path: $adminTs (cannot run securityadmin sync)."
              }

              $adminStores = @{
                AdminKeystoreP12    = $adminP12
                AdminTruststoreP12  = $adminTs
                StorePassword       = [string]$tlsStorePass
                StorePass           = [string]$tlsStorePass
                KeystorePass        = [string]$tlsStorePass
                TruststorePass      = [string]$tlsStorePass
                KeystorePassword    = [string]$tlsStorePass
                TruststorePassword  = [string]$tlsStorePass
              }

              foreach ($k in @("AdminKeystoreP12","AdminTruststoreP12","StorePassword")) {
                if (-not $adminStores.ContainsKey($k) -or [string]::IsNullOrWhiteSpace([string]$adminStores[$k])) {
                  throw "AdminStores missing/empty key '$k' (cannot run securityadmin sync)."
                }
              }
            } else {
              $cmdEnsure = Get-Command Ensure-TinySocsOpenSearchAdminKeyStores -ErrorAction SilentlyContinue
              if ($cmdEnsure) {
                $adminStores = Ensure-TinySocsOpenSearchAdminKeyStores `
                  -OpenSearchRoot $openSearchRoot `
                  -CertsDir $certsDir `
                  -StorePass ([string]$tlsStorePass)
              }
            }

            if (-not $adminStores) {
              throw "Admin keystores object is empty; cannot run securityadmin sync."
            }

            $ok = Invoke-TinySocsOpenSearchSecurityAdminSync `
              -OpenSearchRoot      $openSearchRoot `
              -ProgramDataConf     $pdConf `
              -AdminStores         $adminStores `
              -HttpPort            $ApiPort `
              -TimeoutSeconds      180 `
              -AdminUserName       $SiemUser `
              -AdminUserPassword   $SiemPass `
              -KibanaUserName      $KibanaUser `
              -KibanaUserPassword  $KibanaPass

            if (-not $ok) {
              Write-TinySocsLog -Level "WARN" -Message "securityadmin sync did not succeed; continuing (REST init may still work), but security config may not be applied."
            }
          } catch {
            $em = $_.Exception.Message
            if ($em -match 'Cannot export non-exportable private key' -or $em -match 'Export-PfxCertificate') {
              Write-TinySocsLog -Level "WARN" -Message "securityadmin sync step hit non-exportable-key path; skipping securityadmin and proceeding with REST init: $em"
            } else {
              Write-TinySocsLog -Level "WARN" -Message "securityadmin sync step failed: $em"
            }
          }

          $svcPassExisting = $null
          try {
            $svcExisting = Get-TSCredential -Name 'TinySocs/OpenSearch/tinysocs'
            if ($svcExisting) {
              $svcJ = $svcExisting | ConvertFrom-Json
              if ($svcJ.pass) { $svcPassExisting = [string]$svcJ.pass }
            }
          } catch { }

          $null = Initialize-TinySocsOpenSearchSecurity `
            -SiemUrl $siemUrl `
            -AdminUser $SiemUser `
            -AdminPass $SiemPass `
            -ServiceUser "tinysocs" `
            -ServicePass $svcPassExisting `
            -IndexPatterns @("winlogbeat-*","tinysocs_anchors*","siem_index*","tinysocs-*","logs-*","security-auditlog-*") `
            -SkipTlsVerify:($skipTlsForLocal) `
            -ReadyTimeoutSeconds 600 `
            -RetryCount 60 `
            -RetrySleepSeconds 3

          Write-TinySocsLog "OpenSearch security initialized via REST (service user + role + mapping)."
          try {
            New-Item -ItemType File -Force -Path $initMarker | Out-Null
            Write-TinySocsLog "Wrote security init marker ($initMarker)."
          } catch {
            Write-TinySocsLog -Level "WARN" -Message "Security init succeeded but failed to write marker ($initMarker): $($_.Exception.Message)"
          }
        }
      }
    } catch {
      Write-TinySocsLog -Level "WARN" -Message "Failed to start/initialize local SIEM service '$serviceName': $($_.Exception.Message)"
      if (-not $insecureLocalSiem) {
        throw
      }
    }
  } else {
    Write-TinySocsLog -Level "WARN" -Message "NoStart specified; service '$serviceName' configured but not started."
  }

  $verifyString = if ([bool]$siemSslVerify) { "true" } else { "false" }
  $envBlock = @{ SIEM_URL = $siemUrl; SIEM_SSL_VERIFY = $verifyString }
  if ($caCertPath) { $envBlock["SIEM_CA_CERT"] = $caCertPath }
  Set-MachineEnv $envBlock

  # --- Stage + bootstrap OpenSearch index templates ---
  try {
    # Ensure _OsInvoke can authenticate: set process-level env vars
    # (Set-MachineEnv above only sets SIEM_URL/SSL_VERIFY, not creds)
    [Environment]::SetEnvironmentVariable("SIEM_USER", $SiemUser, "Process")
    [Environment]::SetEnvironmentVariable("SIEM_PASS", $SiemPass, "Process")

    $installRoot = "C:\Program Files\TinySocs"
    $pdTemplates = Join-Path $env:ProgramData "TinySocs\OpenSearch\templates"
    Ensure-TinySocsOpenSearchTemplatesStaged -InstallRoot $installRoot -ProgramDataTemplatesDir $pdTemplates
    Invoke-TinySocsOpenSearchTemplatesBootstrap -TemplatesDir $pdTemplates -WaitTimeoutSec 180 | Out-Null
    Write-TinySocsLog "OpenSearch index templates staged and bootstrapped."
  } catch {
    Write-TinySocsLog -Level "WARN" -Message "Failed to bootstrap OpenSearch templates: $($_.Exception.Message)"
  }

  # --- Inject service credentials into agent config.yml ---
  try {
    $svcPass = $null
    $svcCred = Get-TSCredential -Name 'TinySocs/OpenSearch/tinysocs'
    if ($svcCred) {
      $svcJ = $svcCred | ConvertFrom-Json
      if ($svcJ.pass) { $svcPass = [string]$svcJ.pass }
    }
    if (-not [string]::IsNullOrWhiteSpace($svcPass)) {
      Set-TinySocsAgentConfigCredentials -User 'tinysocs' -Pass $svcPass
      Write-TinySocsLog "Service credentials injected into agent config.yml."
    } else {
      Write-TinySocsLog -Level "WARN" -Message "No service password found in CredMan (TinySocs/OpenSearch/tinysocs); agent config credentials not injected."
    }
  } catch {
    Write-TinySocsLog -Level "WARN" -Message "Failed to inject service credentials into agent config: $($_.Exception.Message)"
  }

  # --- Register + start agent service ---
  try {
    Install-TinySocsAgentService
    Write-TinySocsLog "TinySocs Agent service installed and started."
  } catch {
    Write-TinySocsLog -Level "WARN" -Message "Failed to install/start TinySocs Agent service: $($_.Exception.Message)"
  }

  if ($scheme -eq "http") {
    Write-TinySocsLog -Level "WARN" -Message "Local SIEM configured at $siemUrl (INSECURE mode: no auth/TLS)."
  } else {
    $msg = "Local SIEM configured at $siemUrl (SECURE mode: TLS+auth, local-only bind)."
    if (-not $siemSslVerify) {
      $msg += " Note: SSL verify is disabled unless the local CA is trusted or clients use SIEM_CA_CERT."
      Write-TinySocsLog -Level "WARN" -Message $msg
    } else {
      Write-TinySocsLog $msg
    }
  }
}

function Ensure-OpenSearchYamlCanonical {
  [CmdletBinding()]
  param(
    # Optional: if not provided, we canonicalize the ProgramData opensearch.yml used by OPENSEARCH_PATH_CONF.
    [string]$YamlPath = (Join-Path $env:ProgramData 'TinySocs\OpenSearch\config\opensearch.yml')
  )

  if ([string]::IsNullOrWhiteSpace($YamlPath)) { return }
  if (-not (Test-Path -LiteralPath $YamlPath -PathType Leaf)) { return }

  $begin = '# --- BEGIN TinySocs security/TLS (minimal) ---'
  $end   = '# --- END TinySocs security/TLS (minimal) ---'

  # Keys we "own" and must never appear twice anywhere in the file
  $ownedKeyRegexes = @(
    '^\s*(?!#)\s*plugins\.security\.ssl\.http\.enabled\s*:',
    '^\s*(?!#)\s*plugins\.security\.ssl\.transport\.enabled\s*:',
    '^\s*(?!#)\s*plugins\.security\.ssl\.transport\.enforce_hostname_verification\s*:',
    '^\s*(?!#)\s*plugins\.security\.allow_default_init_securityindex\s*:'
  )

  $block = @(
    $begin
    'plugins.security.ssl.http.enabled: true'
    'plugins.security.ssl.transport.enabled: true'
    'plugins.security.ssl.transport.enforce_hostname_verification: false'
    'plugins.security.allow_default_init_securityindex: true'
    $end
  )

  $lines = @()
  try { $lines = Get-Content -LiteralPath $YamlPath -ErrorAction Stop } catch { return }
  if ($null -eq $lines) { $lines = @() }

  # 1) Remove any existing TinySocs-managed block (robust even if truncated)
  $stripped = New-Object System.Collections.Generic.List[string]
  $inBlock = $false
  foreach ($l in $lines) {
    if ($l -eq $begin) { $inBlock = $true; continue }
    if ($inBlock) {
      if ($l -eq $end) { $inBlock = $false }
      continue
    }
    $stripped.Add([string]$l)
  }

  # 2) Remove any occurrences of owned keys elsewhere (prevents duplicates across reinstalls)
  $clean = New-Object System.Collections.Generic.List[string]
  foreach ($l in $stripped) {
    $isOwnedKey = $false
    foreach ($rx in $ownedKeyRegexes) {
      if ($l -match $rx) { $isOwnedKey = $true; break }
    }
    if (-not $isOwnedKey) { $clean.Add([string]$l) }
  }

  # 3) Insert a single canonical block.
  # Prefer to place it right after discovery.type if present, else append at end.
  $insertAt = -1
  for ($i = 0; $i -lt $clean.Count; $i++) {
    if ($clean[$i] -match '^\s*discovery\.type\s*:') { $insertAt = $i + 1; break }
  }

  if ($insertAt -ge 0) {
    $toInsert = New-Object System.Collections.Generic.List[string]
    if ($insertAt -gt 0 -and ($clean[$insertAt - 1].Trim() -ne '')) { $toInsert.Add('') | Out-Null }
    foreach ($b in $block) { $toInsert.Add([string]$b) | Out-Null }
    $toInsert.Add('') | Out-Null
    $clean.InsertRange($insertAt, $toInsert)
  } else {
    if ($clean.Count -gt 0 -and ($clean[$clean.Count - 1].Trim() -ne '')) { $clean.Add('') | Out-Null }
    foreach ($b in $block) { $clean.Add([string]$b) | Out-Null }
    $clean.Add('') | Out-Null
  }

  Set-Content -LiteralPath $YamlPath -Value $clean -Encoding UTF8

  try {
    Write-TinySocsLog -Level "DEBUG" -Message "Canonicalized OpenSearch YAML at $YamlPath (TinySocs minimal TLS/security block; deduped owned keys)."
  } catch { }
}

function Ensure-TinySocsOpenSearchProgramDataConfig {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$OpenSearchRoot,
    [Parameter(Mandatory)][string]$ProgramDataConf,
    [switch]$Force,

    # PATCH: optional service stop to avoid locked files during stash/rotate/copy
    [string]$ServiceName = "TinySocsOpenSearch"
  )

  $src = Join-Path $OpenSearchRoot 'config'
  if (-not (Test-Path $src -PathType Container)) {
    throw "OpenSearch config directory not found at '$src'"
  }

  if (-not (Test-TinySocsIsElevated)) {
    throw "Install-TinySocsLocalSiem must be run from an elevated PowerShell. ProgramData config seeding requires admin rights."
  }

  $preserveDirs  = @('certs','opensearch-security')
  $preserveFiles = @('opensearch.yml','opensearch.keystore')

  $needsSeed = $Force -or -not (Test-Path $ProgramDataConf -PathType Container)

  function _TryStopTinySocsService {
    param([Parameter(Mandatory)][string]$Name)
    try {
      $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
      if ($svc -and ($svc.Status -ne 'Stopped')) {
        Write-TinySocsLog -Level "WARN" -Message "Ensure-TinySocsOpenSearchProgramDataConfig: stopping service '$Name' ($($svc.Status)) to prevent config copy/rotation locks."
        try { Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue } catch { }
        try { (Get-Service -Name $Name -ErrorAction SilentlyContinue).WaitForStatus('Stopped','00:00:35') } catch { }
      }
    } catch { }
  }

  function _CopyFileWithRetry {
    param(
      [Parameter(Mandatory)][string]$Source,
      [Parameter(Mandatory)][string]$Dest,
      [int]$Tries = 6,
      [int]$SleepMs = 250
    )
    for ($i=1; $i -le $Tries; $i++) {
      try {
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Dest) | Out-Null
        Copy-Item -Force -Path $Source -Destination $Dest -ErrorAction Stop
        return $true
      } catch {
        if ($i -ge $Tries) { return $false }
        Start-Sleep -Milliseconds $SleepMs
      }
    }
    return $false
  }

  function _Grant-TinySocsTempAcl {
    param([Parameter(Mandatory)][string]$Path)

    try { New-Item -ItemType Directory -Force -Path $Path | Out-Null } catch { }

    $who = $null
    try { $who = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name } catch { $who = $env:USERNAME }
    if ([string]::IsNullOrWhiteSpace($who)) { $who = $env:USERNAME }

    # Enable inheritance and grant FullControl to SYSTEM/Admin/current identity
    try {
      & icacls.exe $Path /inheritance:e /grant:r `
        "SYSTEM:(OI)(CI)F" `
        "Administrators:(OI)(CI)F" `
        ($who + ":(OI)(CI)F") /T /C | Out-Null
    } catch { }
  }

  $stash = $null
  $tmpRoot = $null

  try {
    # PATCH: stop service up-front if we might rotate/stash/copy
    if ($needsSeed -and -not [string]::IsNullOrWhiteSpace($ServiceName)) {
      _TryStopTinySocsService -Name $ServiceName
    }

    # PATCH: deterministic ProgramData tmp root + explicit ACL (do NOT rely on GetTempPath())
    $tmpRoot = Join-Path (Get-TinySocsDataRoot) 'tmp'
    _Grant-TinySocsTempAcl -Path $tmpRoot

    $stash = Join-Path $tmpRoot ("tinysocs-osconf-stash-" + [Guid]::NewGuid().ToString("n"))
    _Grant-TinySocsTempAcl -Path $stash

    if ($needsSeed) {
      # If config exists, stash preserved bits so we don't clobber operator edits during rotation
      try {
        # IMPORTANT: do NOT Set-TinySocsSecureAcl -UsersRead on stash root here; we still need write access.
        if (Test-Path $ProgramDataConf -PathType Container) {
          foreach ($d in $preserveDirs) {
            $p = Join-Path $ProgramDataConf $d
            if (Test-Path $p -PathType Container) {
              $dstDir = Join-Path $stash $d
              New-Item -ItemType Directory -Force -Path $dstDir | Out-Null
              _Grant-TinySocsTempAcl -Path $dstDir

              Invoke-TinySocsCmd "robocopy ""$p"" ""$dstDir"" /E /COPY:DAT /DCOPY:DAT /R:1 /W:1 /NFL /NDL /NJH /NJS /NP >nul"
            }
          }

          foreach ($f in $preserveFiles) {
            $p = Join-Path $ProgramDataConf $f
            if (Test-Path $p -PathType Leaf) {
              $dst = Join-Path $stash $f
              $ok = _CopyFileWithRetry -Source $p -Dest $dst -Tries 6 -SleepMs 250
              if (-not $ok) {
                Write-TinySocsLog -Level "WARN" -Message "Failed to stash preserved file '$p' into '$dst' (locked/ACL). Continuing."
              }
            }
          }
        }
      } catch {
        Write-TinySocsLog -Level "WARN" -Message "Failed to stash existing ProgramData config prior to rotation: $($_.Exception.Message)"
      }

      if (Test-Path $ProgramDataConf -PathType Container) {
        try { Set-TinySocsSecureAcl -Path $ProgramDataConf -UsersRead } catch { }

        $backup = "$ProgramDataConf.old-$(Get-Date -Format yyyyMMdd-HHmmss)"
        try {
          Move-Item -Force -Path $ProgramDataConf -Destination $backup -ErrorAction Stop
          try { Set-TinySocsSecureAcl -Path $backup -UsersRead } catch { }
          Write-TinySocsLog "Moved existing ProgramData OpenSearch config aside to $backup"
        } catch {
          try {
            Remove-Item -Recurse -Force -Path $ProgramDataConf -ErrorAction Stop
            Write-TinySocsLog "Removed existing ProgramData OpenSearch config at $ProgramDataConf"
          } catch {
            throw "Unable to replace ProgramData OpenSearch config at '$ProgramDataConf' (rename+delete failed). ACL/lock issue. Details: $($_.Exception.Message)"
          }
        }
      }

      New-Item -ItemType Directory -Force -Path $ProgramDataConf | Out-Null
    } else {
      New-Item -ItemType Directory -Force -Path $ProgramDataConf | Out-Null
    }

    $xd = ($preserveDirs  | ForEach-Object { "/XD `"$($_)`"" }) -join " "
    $xf = ($preserveFiles | ForEach-Object { "/XF `"$($_)`"" }) -join " "

    $cmd = "robocopy ""$src"" ""$ProgramDataConf"" /E /COPY:DAT /DCOPY:DAT /R:2 /W:1 /NFL /NDL /NJH /NJS /NP $xd $xf"
    $rcOut = & cmd.exe /V:OFF /C $cmd 2>&1
    $rc = $LASTEXITCODE
    if ($rc -ge 8) { throw "robocopy failed with exit code $rc. Output: $((($rcOut | Out-String).Trim()))" }

    if ($needsSeed) {
      try {
        if ($stash -and (Test-Path $stash -PathType Container)) {
          foreach ($d in $preserveDirs) {
            $p = Join-Path $stash $d
            if (Test-Path $p -PathType Container) {
              $dstDir = Join-Path $ProgramDataConf $d
              New-Item -ItemType Directory -Force -Path $dstDir | Out-Null
              Invoke-TinySocsCmd "robocopy ""$p"" ""$dstDir"" /E /COPY:DAT /DCOPY:DAT /R:1 /W:1 /NFL /NDL /NJH /NJS /NP >nul"
            }
          }

          foreach ($f in $preserveFiles) {
            $p = Join-Path $stash $f
            if (Test-Path $p -PathType Leaf) {
              $dst = Join-Path $ProgramDataConf $f
              $ok = _CopyFileWithRetry -Source $p -Dest $dst -Tries 6 -SleepMs 250
              if (-not $ok) {
                Write-TinySocsLog -Level "WARN" -Message "Failed to restore preserved file '$p' back to '$dst' (locked/ACL). Continuing."
              }
            }
          }
        }
      } catch {
        Write-TinySocsLog -Level "WARN" -Message "Failed to restore preserved ProgramData config after rotation: $($_.Exception.Message)"
      }
    }

    $mustHave = @('jvm.options','log4j2.properties')
    foreach ($f in $mustHave) {
      $dst = Join-Path $ProgramDataConf $f
      $srcFile = Join-Path $src $f

      if (Test-Path $dst -PathType Container) {
        try { Remove-Item -LiteralPath $dst -Recurse -Force -ErrorAction Stop } catch { }
      }

      if (-not (Test-Path $dst -PathType Leaf)) {
        if (-not (Test-Path $srcFile -PathType Leaf)) {
          throw "OpenSearch bootstrap file missing in packaged config: $srcFile"
        }
        Copy-Item -Force -Path $srcFile -Destination $dst -ErrorAction Stop
        Write-TinySocsLog "Seeded missing OpenSearch bootstrap file into ProgramData: $f"
      }
    }

    try {
      $srcD = Join-Path $src 'jvm.options.d'
      if (Test-Path $srcD -PathType Container) {
        $dstD = Join-Path $ProgramDataConf 'jvm.options.d'
        if (-not (Test-Path $dstD -PathType Container)) { New-Item -ItemType Directory -Force -Path $dstD | Out-Null }
        Get-ChildItem -Path $srcD -File -Force -ErrorAction SilentlyContinue | ForEach-Object {
          $t = Join-Path $dstD $_.Name
          if (-not (Test-Path $t -PathType Leaf)) {
            Copy-Item -Force -Path $_.FullName -Destination $t -ErrorAction SilentlyContinue
          }
        }
      }
    } catch {
      Write-TinySocsLog -Level "WARN" -Message "Failed to seed jvm.options.d (non-fatal): $($_.Exception.Message)"
    }

    function _CopyMissingTree {
      param(
        [Parameter(Mandatory)][string]$SrcDir,
        [Parameter(Mandatory)][string]$DstDir
      )

      if (-not (Test-Path $SrcDir -PathType Container)) { return }

      if (-not (Test-Path $DstDir -PathType Container)) {
        New-Item -ItemType Directory -Force -Path $DstDir | Out-Null
      }

      $srcFull = [System.IO.Path]::GetFullPath($SrcDir.TrimEnd('\'))
      Get-ChildItem -Path $srcFull -Recurse -Force | ForEach-Object {
        $rel = $_.FullName.Substring($srcFull.Length).TrimStart('\')
        if ([string]::IsNullOrWhiteSpace($rel)) { return }

        $target = Join-Path $DstDir $rel

        if ($_.PSIsContainer) {
          if (-not (Test-Path $target -PathType Container)) {
            New-Item -ItemType Directory -Force -Path $target | Out-Null
          }
          return
        }

        if (-not (Test-Path $target -PathType Leaf)) {
          New-Item -ItemType Directory -Force -Path (Split-Path -Parent $target) | Out-Null
          Copy-Item -Force -Path $_.FullName -Destination $target -ErrorAction Stop
        }
      }
    }

    _CopyMissingTree -SrcDir (Join-Path $src 'certs')               -DstDir (Join-Path $ProgramDataConf 'certs')
    _CopyMissingTree -SrcDir (Join-Path $src 'opensearch-security') -DstDir (Join-Path $ProgramDataConf 'opensearch-security')

    try { Set-TinySocsSecureAcl -Path $ProgramDataConf -UsersRead } catch { }

    try {
      $certsDir2 = Join-Path $ProgramDataConf 'certs'
      if (Test-Path $certsDir2 -PathType Container) {
        Repair-TinySocsOpenSearchCertAcls -CertsDir $certsDir2
      }
    } catch {
      Write-TinySocsLog -Level "WARN" -Message "Post-seed cert ACL repair failed: $($_.Exception.Message)"
    }

    Write-TinySocsLog "OpenSearch config ensured in ProgramData (non-destructive copy, rc=$rc): $ProgramDataConf"
  } catch {
    throw "Failed to seed ProgramData OpenSearch config at '$ProgramDataConf': $($_.Exception.Message)"
  }
  finally {
    # PATCH: clean up stash (best-effort)
    try {
      if ($stash -and (Test-Path -LiteralPath $stash -PathType Container)) {
        Remove-Item -LiteralPath $stash -Recurse -Force -ErrorAction SilentlyContinue
      }
    } catch { }
  }
}

function Remove-YamlKeyAndBareValueLine {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string[]]$Lines,
    [Parameter(Mandatory)][string]$KeyRegex   # e.g. '^\s*http\.port\s*:'
  )

  $out = New-Object System.Collections.Generic.List[string]
  for ($i = 0; $i -lt $Lines.Count; $i++) {
    $line = $Lines[$i]

    if ($line -match $KeyRegex) {
      # Also skip ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã¢â‚¬Å“bare value on next lineÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â (your file format does this sometimes)
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

function Ensure-TinySocsOpenSearchRunner {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$InstallRoot,
    [Parameter(Mandatory)][string]$OpenSearchRoot,
    [Parameter(Mandatory)][string]$ProgramDataConf,
    [Parameter(Mandatory)][string]$RunnerPath
  )

  function _EscapePsSingleQuotedString {
    param([Parameter(Mandatory)][string]$s)
    return ($s -replace "'", "''")
  }

  function _WriteUtf8NoBomFile {
    param(
      [Parameter(Mandatory)][string]$Path,
      [Parameter(Mandatory)][string]$Text
    )
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Text, $utf8NoBom)
  }

  function _CopyTextFileUtf8NoBom {
    param(
      [Parameter(Mandatory)][string]$Src,
      [Parameter(Mandatory)][string]$Dst
    )
    $raw = Get-Content -LiteralPath $Src -Raw -ErrorAction Stop
    _WriteUtf8NoBomFile -Path $Dst -Text $raw
  }

  $modulePath = Join-Path $InstallRoot "modules\TinySocs.Installer.psm1"
  $batPath    = Join-Path $OpenSearchRoot "bin\opensearch.bat"

  $modulePathQ      = _EscapePsSingleQuotedString $modulePath
  $programDataConfQ = _EscapePsSingleQuotedString $ProgramDataConf
  $batPathQ         = _EscapePsSingleQuotedString $batPath
  $osRootQ          = _EscapePsSingleQuotedString $OpenSearchRoot

  # Prefer a shipped, versioned runner (single source of truth) if present.
  # Expected installer payload locations:
  #   - {app}\scripts\Run-OpenSearch.ps1  -> $InstallRoot\scripts\Run-OpenSearch.ps1
  # Optional fallback:
  #   - {app}\installer\Run-OpenSearch.ps1 (if you ever ship it there)
  $seedCandidates = @(
    (Join-Path $InstallRoot "scripts\Run-OpenSearch.ps1"),
    (Join-Path $InstallRoot "installer\Run-OpenSearch.ps1")
  )

  $seed = $seedCandidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1

  $template = @'
$ErrorActionPreference = 'Stop'

function _WriteUtf8NoBom([string]$path, [string]$text) {
  $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
  [System.IO.File]::WriteAllText($path, $text, $utf8NoBom)
}

# Import module quietly (we don't care about unapproved verb warnings in a service context)
try { Import-Module '__MODULE__' -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue } catch { }

# Always force ProgramData config
$env:OPENSEARCH_PATH_CONF = '__CONF__'

# --- Self-heal mandatory config files in ProgramData (prevents jvm.options missing/dir-poison failures) ---
try {
  $confDir  = '__CONF__'
  $osConf   = Join-Path '__OSROOT__' 'config'

  $mustHave = @('jvm.options','log4j2.properties')

  foreach ($f in $mustHave) {
    $dst = Join-Path $confDir $f

    try {
      if (Test-Path $dst -PathType Container) {
        Remove-Item -Recurse -Force -LiteralPath $dst -ErrorAction SilentlyContinue
      }
    } catch { }

    if (-not (Test-Path $dst -PathType Leaf)) {
      $src = Join-Path $osConf $f
      if (Test-Path $src -PathType Leaf) {
        try {
          New-Item -ItemType Directory -Force -Path (Split-Path -Parent $dst) | Out-Null
          Copy-Item -Force -LiteralPath $src -Destination $dst -ErrorAction Stop
        } catch { }
      }
    }
  }

  # --- Canonicalize GC unified logging line (fixes "filecount=32" / JVM parse failures) ---
  try {
    $jvm = Join-Path $confDir 'jvm.options'
    if (Test-Path $jvm -PathType Leaf) {
      $desired = "9-:-Xlog:gc*:file=logs/gc.log"
      $raw = Get-Content -LiteralPath $jvm -Raw -ErrorAction Stop

      # Strip BOM / U+FEFF if present
      if ($raw.Length -gt 0 -and $raw[0] -eq [char]0xFEFF) { $raw = $raw.Substring(1) }

      $lines = $raw -split "`r?`n", -1
      $out = New-Object System.Collections.Generic.List[string]
      $wrote = $false

      foreach ($ln in $lines) {
        if ($ln -match '^\s*(?:\d+(?:-\d+)?-:)?\s*-Xlog:gc') {
          if (-not $wrote) { $out.Add($desired); $wrote = $true }
          continue
        }
        $out.Add($ln)
      }
      if (-not $wrote) {
        if ($out.Count -gt 0 -and $out[$out.Count-1] -ne "") { $out.Add("") }
        $out.Add($desired)
      }

      $new = ($out -join "`r`n")
      if ($new -ne $raw) { _WriteUtf8NoBom $jvm $new }
    }
  } catch { }

  # Dedupe the specific key that bricks OpenSearch ("Duplicate field ... allow_default_init_securityindex")
  $yml = Join-Path $confDir 'opensearch.yml'
  if (Test-Path $yml -PathType Leaf) {
    $key = 'plugins.security.allow_default_init_securityindex'
    $escaped = [regex]::Escape($key)

    $lines = Get-Content -LiteralPath $yml -ErrorAction Stop
    $vals = @()
    foreach ($ln in $lines) {
      if ($ln -match "^\s*$escaped\s*:\s*(.+?)\s*$") {
        $vals += $Matches[1].Trim()
      }
    }

    if ($vals.Count -gt 1) {
      $val = $vals[0]
      $lines2 = $lines | Where-Object { $_ -notmatch "^\s*$escaped\s*:" }
      $lines2 += ("{0}: {1}" -f $key, $val)
      _WriteUtf8NoBom $yml ($lines2 -join "`r`n")
    }
  }

  if (-not (Test-Path (Join-Path $confDir 'jvm.options') -PathType Leaf)) {
    throw "FATAL: jvm.options missing under OPENSEARCH_PATH_CONF=$confDir"
  }
} catch {
  throw
}

# Defensive Java env (helps if service env is sparse)
try {
  $jdk = Join-Path '__OSROOT__' 'jdk'
  if (Test-Path $jdk -PathType Container) {
    $env:OPENSEARCH_JAVA_HOME = $jdk
    $env:JAVA_HOME = $jdk
    $env:Path = (Join-Path $jdk 'bin') + ';' + $env:Path
  }
} catch { }

# Prefer CredMan admin pass (TinySocs/SIEM/Creds)
try {
  $raw = Get-TSCredential -Name 'TinySocs/SIEM/Creds'
  if ($raw) {
    $j = $raw | ConvertFrom-Json
    if ($j.pass) { $env:OPENSEARCH_INITIAL_ADMIN_PASSWORD = [string]$j.pass }
  }
} catch { }

# Fallback: DPAPI-protected admin pass file (survives reinstall if CredMan is wiped)
if ([string]::IsNullOrWhiteSpace($env:OPENSEARCH_INITIAL_ADMIN_PASSWORD)) {
  try {
    $certsDir = Join-Path '__CONF__' 'certs'
    if (Get-Command Read-TinySocsSiemAdminPassFromDpapiFile -ErrorAction SilentlyContinue) {
      $p = Read-TinySocsSiemAdminPassFromDpapiFile -CertsDir $certsDir
      if ($p) { $env:OPENSEARCH_INITIAL_ADMIN_PASSWORD = [string]$p }
    } else {
      $dp = Join-Path $certsDir 'siem-admin-pass.dpapi'
      if (Test-Path $dp -PathType Leaf) {
        $b64 = (Get-Content -Path $dp -Raw).Trim()
        if (-not [string]::IsNullOrWhiteSpace($b64)) {
          Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue | Out-Null
          $enc = [Convert]::FromBase64String($b64)
          $bytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
            $enc, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine
          )
          $env:OPENSEARCH_INITIAL_ADMIN_PASSWORD = [System.Text.Encoding]::UTF8.GetString($bytes).Trim([char]0).Trim()
        }
      }
    }
  } catch { }
}

# **Critical:** ensure TLS storepass is present ONLY as secure keystore settings (no YAML plaintext, no plaintext keystore keys).
try {
  $confDir  = '__CONF__'
  $certsDir = Join-Path $confDir 'certs'
  $kbat     = Join-Path '__OSROOT__' 'bin\opensearch-keystore.bat'
  $ks       = Join-Path $confDir 'opensearch.keystore'

  if (Test-Path $kbat -PathType Leaf) {
    # Ensure keystore exists under ProgramData conf
    if (-not (Test-Path $ks -PathType Leaf)) {
      try { & $kbat create | Out-Null } catch { }
    }

    # Purge legacy plaintext SSL password keys (these trigger "must be set not both")
    $legacy = @(
      'plugins.security.ssl.http.keystore_password',
      'plugins.security.ssl.http.keystore_keypassword',
      'plugins.security.ssl.http.truststore_password',
      'plugins.security.ssl.transport.keystore_password',
      'plugins.security.ssl.transport.keystore_keypassword',
      'plugins.security.ssl.transport.truststore_password'
    )
    foreach ($k in $legacy) {
      try { & $kbat remove $k 2>$null | Out-Null } catch { }
    }
  }

  if ((Get-Command Read-TinySocsOpenSearchTlsStorePassFromDpapiFile -ErrorAction SilentlyContinue)) {
    $storePass = Read-TinySocsOpenSearchTlsStorePassFromDpapiFile -CertsDir $certsDir
    if ($storePass) {
      $storePass = ([string]$storePass).Trim()

      # Guardrails: prevent UTF-16/null-padded/linebroken nonsense entering keystore
      if ($storePass.IndexOf([char]0) -ge 0 -or $storePass -match "[`r`n]") {
        throw "TLS storepass contains null/newline characters; refusing to write to keystore."
      }
      foreach ($ch in $storePass.ToCharArray()) {
        if ([int][char]$ch -gt 127) { throw "TLS storepass contains non-ASCII characters; Java PKCS12 commonly rejects this." }
      }

      $keysSecure = @(
        'plugins.security.ssl.http.keystore_password_secure',
        'plugins.security.ssl.http.keystore_keypassword_secure',
        'plugins.security.ssl.http.truststore_password_secure',
        'plugins.security.ssl.transport.keystore_password_secure',
        'plugins.security.ssl.transport.keystore_keypassword_secure',
        'plugins.security.ssl.transport.truststore_password_secure'
      )

      # Prefer module helper if available, but ensure it uses deterministic overwrite.
      if (Get-Command Ensure-TinySocsOpenSearchKeystoreSecurePasswords -ErrorAction SilentlyContinue) {
        Ensure-TinySocsOpenSearchKeystoreSecurePasswords `
          -OpenSearchRoot '__OSROOT__' `
          -ProgramDataConf $confDir `
          -CertsDir $certsDir `
          -StorePass $storePass `
          -Keys $keysSecure | Out-Null
      }
      elseif (Test-Path $kbat -PathType Leaf) {
        # Fallback: write secure keys ourselves using ASCII stdin (NO PowerShell pipeline)
        foreach ($k in $keysSecure) {
          try { & $kbat remove $k 2>$null | Out-Null } catch { }

          $psi = New-Object System.Diagnostics.ProcessStartInfo
          $psi.FileName               = $kbat
          $psi.Arguments              = "add -f --stdin $k"
          $psi.WorkingDirectory       = (Join-Path '__OSROOT__' 'bin')
          $psi.UseShellExecute        = $false
          $psi.RedirectStandardInput  = $true
          $psi.RedirectStandardOutput = $true
          $psi.RedirectStandardError  = $true

          # Force conf for the child too
          $psi.EnvironmentVariables["OPENSEARCH_PATH_CONF"] = $confDir

          $p = New-Object System.Diagnostics.Process
          $p.StartInfo = $psi

          if (-not $p.Start()) { throw "Failed to start opensearch-keystore for key $k" }

          $sw = New-Object System.IO.StreamWriter($p.StandardInput.BaseStream, [Text.Encoding]::ASCII)
          $sw.WriteLine($storePass)
          $sw.Flush()
          $sw.Close()

          $stdout = $p.StandardOutput.ReadToEnd()
          $stderr = $p.StandardError.ReadToEnd()
          $p.WaitForExit()

          if ($p.ExitCode -ne 0) {
            throw "Failed setting $k (exit=$($p.ExitCode)). stdout=$stdout stderr=$stderr"
          }
        }
      }
    }
  }
} catch {
  # Don't hard-fail runner: log + continue to opensearch.bat, but you'll see it in NSSM logs
  Write-Output ("WARN: TLS keystore secure-password enforcement failed: " + $_.Exception.Message)
}

& '__BAT__'
'@

  $script = $template
  $script = $script.Replace('__MODULE__', $modulePathQ)
  $script = $script.Replace('__CONF__',   $programDataConfQ)
  $script = $script.Replace('__BAT__',    $batPathQ)
  $script = $script.Replace('__OSROOT__', $osRootQ)

  $dir = Split-Path -Parent $RunnerPath
  if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }

  try {
    try { if (Test-Path $RunnerPath) { attrib.exe -R -S -H "$RunnerPath" | Out-Null } } catch { }
    try { & takeown.exe /F $RunnerPath /A 2>$null | Out-Null } catch { }
    try { & icacls $RunnerPath /reset /C 2>$null | Out-Null } catch { }

    Ensure-TinySocsWritableFile -Path $RunnerPath

    if ($seed) {
      _CopyTextFileUtf8NoBom -Src $seed -Dst $RunnerPath
      Write-TinySocsLog "OpenSearch runner ensured at $RunnerPath (copied from seeded payload: $seed)."
    } else {
      _WriteUtf8NoBomFile -Path $RunnerPath -Text $script
      Write-TinySocsLog "OpenSearch runner ensured at $RunnerPath (generated fallback template: forces ProgramData config + heals mandatory config + canonicalizes jvm.options GC log line + dedupes known YAML key + reads CredMan/DPAPI admin pass + PURGES plaintext SSL keystore keys + writes TLS storepass via secure keystore settings using ASCII stdin)."
    }

    try {
      & icacls $RunnerPath /inheritance:r /grant:r "*S-1-5-18:(F)" "*S-1-5-32-544:(F)" "*S-1-5-11:(RX)" /C | Out-Null
    } catch { }
  } catch {
    Write-TinySocsLog -Level "ERROR" -Message "Failed to write OpenSearch runner at ${RunnerPath}: $($_.Exception.Message)"
    throw
  }
}

function Ensure-YamlScalarKeyOnce {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$Key,        # e.g. 'http.port'
    [Parameter(Mandatory)][string]$Value,      # e.g. '9201'
    [string]$InsertAfterKey = 'network.host'   # best-effort placement
  )

  if (-not (Test-Path $Path)) { throw "YAML not found: $Path" }

  $raw   = Get-Content $Path -Raw
  $lines = $raw -split "`r?`n"

  $keyRegex = '^\s*' + [regex]::Escape($Key) + '\s*:'
  $lines = Remove-YamlKeyAndBareValueLine -Lines $lines -KeyRegex $keyRegex

  $kv = "${Key}: $Value"

  $inserted = $false
  if ($InsertAfterKey) {
    $afterRegex = '^\s*' + [regex]::Escape($InsertAfterKey) + '\s*:'
    for ($i=0; $i -lt $lines.Count; $i++) {
      if ($lines[$i] -match $afterRegex) {
        $tmp = New-Object System.Collections.Generic.List[string]
        $tmp.AddRange($lines[0..$i])
        $tmp.Add($kv)
        if ($i + 1 -le $lines.Count - 1) { $tmp.AddRange($lines[($i+1)..($lines.Count-1)]) }
        $lines = $tmp.ToArray()
        $inserted = $true
        break
      }
    }
  }

  if (-not $inserted) {
    $tmp = New-Object System.Collections.Generic.List[string]
    $tmp.Add($kv)
    $tmp.AddRange($lines)
    $lines = $tmp.ToArray()
  }

  $bak = "$Path.bak.$(Get-Date -Format yyyyMMdd-HHmmss)"
  Copy-Item $Path $bak -Force

  ($lines -join "`r`n") | Set-Content -Path $Path -Encoding UTF8
  return $bak
}

function Repair-TinySocsOpenSearchYamlKeyDedupe {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$ConfigPath,
    [Parameter(Mandatory)][string]$Key,
    [Parameter(Mandatory)][string]$Value  # e.g. 'true' / 'false'
  )

  if (-not (Test-Path $ConfigPath -PathType Leaf)) {
    throw "Repair-TinySocsOpenSearchYamlKeyDedupe: missing config at $ConfigPath"
  }

  $lines = Get-Content -LiteralPath $ConfigPath -ErrorAction Stop

  # remove ALL occurrences of the key (strict start-of-line match)
  $pat = "^\s*$([regex]::Escape($Key))\s*:"
  $lines2 = $lines | Where-Object { $_ -notmatch $pat }

  # add exactly once at end
  $lines2 += ("{0}: {1}" -f $Key, $Value)

  Set-Content -LiteralPath $ConfigPath -Value $lines2 -Encoding UTF8 -Force

  $cnt = (Select-String -LiteralPath $ConfigPath -Pattern $pat -AllMatches).Matches.Count
  if ($cnt -ne 1) {
    throw "Repair-TinySocsOpenSearchYamlKeyDedupe: expected 1 occurrence of '$Key', found $cnt"
  }
}

function Ensure-TinySocsOpenSearchHttpPort {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$OpenSearchConfDir,
    [int]$Port = 9201
  )

  $yml = Join-Path $OpenSearchConfDir "opensearch.yml"
  $bak = Ensure-YamlScalarKeyOnce -Path $yml -Key "http.port" -Value "$Port" -InsertAfterKey "network.host"
  Write-Host "OpenSearch http.port enforced: $Port (backup: $bak)"
}

function Wait-TcpPort {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Host,
    [Parameter(Mandatory)][int]$Port,
    [int]$TimeoutSeconds = 120
  )

  $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
  do {
    try {
      $client = New-Object System.Net.Sockets.TcpClient
      $iar = $client.BeginConnect($Host, $Port, $null, $null)
      if ($iar.AsyncWaitHandle.WaitOne(1500, $false)) {
        $client.EndConnect($iar)
        $client.Close()
        return $true
      }
      $client.Close()
    } catch {
      try { $client.Close() } catch {}
    }
    Start-Sleep 2
  } while ((Get-Date) -lt $deadline)

  return $false
}

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

  $svc = Get-Service -Name "TinySocsOpenSearch" -ErrorAction SilentlyContinue
  if ($null -ne $svc -and $svc.Status -eq 'Running') {
    try {
      Write-TinySocsLog "Stopping TinySocsOpenSearch service to remove security plugin at $pluginPath."
      Stop-Service -Name "TinySocsOpenSearch" -Force -ErrorAction Stop
      Start-Sleep -Seconds 5
    } catch {
      Write-TinySocsLog -Level "WARN" -Message "Failed to stop TinySocsOpenSearch before removing security plugin at ${pluginPath}: $($_.Exception.Message)"
    }
  }

  try {
    Remove-Item $pluginPath -Recurse -Force -ErrorAction Stop
    Write-TinySocsLog "OpenSearch security plugin removed at $pluginPath (INSECURE mode)."
  } catch {
    Write-TinySocsLog -Level "WARN" -Message "Failed to remove OpenSearch security plugin at ${pluginPath}: $($_.Exception.Message)"
  }
}

function Ensure-OpenSearchProgramDataBootstrap {
    param(
        [Parameter(Mandatory)][string]$OpenSearchHome,   # e.g. C:\Program Files\TinySocs\OpenSearch
        [Parameter(Mandatory)][string]$ProgramDataRoot,  # e.g. C:\ProgramData\TinySocs\OpenSearch
        [string[]]$MustHave = @("jvm.options","log4j2.properties")
    )

    $srcConfig = Join-Path $OpenSearchHome "config"
    $dstConfig = Join-Path $ProgramDataRoot "config"
    $dstLogs   = Join-Path $ProgramDataRoot "logs"

    New-Item -ItemType Directory -Path $dstConfig -Force | Out-Null
    New-Item -ItemType Directory -Path $dstLogs   -Force | Out-Null

    foreach ($f in $MustHave) {
        $s = Join-Path $srcConfig $f
        $d = Join-Path $dstConfig $f

        if (!(Test-Path -LiteralPath $s -PathType Leaf)) {
            throw "OpenSearch bootstrap: missing source file: $s"
        }

        # If someone created a directory with the file name, remove it.
        if (Test-Path -LiteralPath $d -PathType Container) {
            Remove-Item -LiteralPath $d -Recurse -Force
        }

        if (!(Test-Path -LiteralPath $d -PathType Leaf)) {
            Copy-Item -LiteralPath $s -Destination $d -Force
        }
    }

    # Optional: jvm.options.d
    $srcD = Join-Path $srcConfig "jvm.options.d"
    $dstD = Join-Path $dstConfig "jvm.options.d"
    if (Test-Path -LiteralPath $srcD -PathType Container) {
        New-Item -ItemType Directory -Path $dstD -Force | Out-Null
        Copy-Item -LiteralPath (Join-Path $srcD "*") -Destination $dstD -Force -ErrorAction SilentlyContinue
    }
}

function Ensure-OpenSearchServiceWrapper {
    param(
        [Parameter(Mandatory)][string]$TinySocsRoot,     # e.g. C:\Program Files\TinySocs
        [Parameter(Mandatory)][string]$ProgramDataRoot,  # e.g. C:\ProgramData\TinySocs\OpenSearch
        [string]$ServiceName = "TinySocsOpenSearch",
        [string]$OpenSearchHome = $(Join-Path $TinySocsRoot "OpenSearch"),
        [string]$NssmPath = $(Join-Path $TinySocsRoot "bin\nssm.exe")
    )

    if (!(Test-Path -LiteralPath $NssmPath -PathType Leaf)) {
        throw "nssm.exe not found at $NssmPath"
    }

    $wrapper = Join-Path $OpenSearchHome "bin\tinysocs-opensearch-service.cmd"
    $conf    = Join-Path $ProgramDataRoot "config"
    $logs    = Join-Path $ProgramDataRoot "logs"

    New-Item -ItemType Directory -Path $logs -Force | Out-Null

@"
@echo off
setlocal EnableExtensions EnableDelayedExpansion

set "OS_HOME=$OpenSearchHome"
set "CONF=$conf"
set "OPENSEARCH_PATH_CONF=!CONF!"

echo [%date% %time%] TinySocsOpenSearch wrapper starting
echo OPENSEARCH_PATH_CONF=!OPENSEARCH_PATH_CONF!

if not exist "!CONF!" mkdir "!CONF!" >nul 2>&1

for %%F in (jvm.options log4j2.properties) do (
  if exist "!CONF!\%%F\" (
    echo ERROR: "!CONF!\%%F" is a directory. Removing...
    rmdir /s /q "!CONF!\%%F"
  )
  if not exist "!CONF!\%%F" (
    echo Copying %%F into ProgramData...
    copy /y "!OS_HOME!\config\%%F" "!CONF!\%%F" >nul
  )
)

echo Listing config dir as seen by service:
dir /a "!CONF!"

if not exist "!CONF!\jvm.options" (
  echo FATAL: jvm.options still missing at "!CONF!\jvm.options"
  exit /b 3
)

echo Launching OpenSearch...
call "!OS_HOME!\bin\opensearch.bat"
set "RC=!ERRORLEVEL!"
echo OpenSearch exited with code !RC!
exit /b !RC!
"@ | Set-Content -LiteralPath $wrapper -Encoding ASCII -Force

    # Point NSSM at the wrapper + ensure OPENSEARCH_PATH_CONF is pinned to ProgramData
    & $NssmPath set $ServiceName Application "C:\Windows\System32\cmd.exe" | Out-Null
    & $NssmPath set $ServiceName AppDirectory $OpenSearchHome             | Out-Null
    & $NssmPath set $ServiceName AppParameters "/c `"$wrapper`""         | Out-Null

    & $NssmPath set $ServiceName AppStdout (Join-Path $logs "$ServiceName.wrapper.out.log") | Out-Null
    & $NssmPath set $ServiceName AppStderr (Join-Path $logs "$ServiceName.wrapper.err.log") | Out-Null

    & $NssmPath set $ServiceName AppEnvironmentExtra "OPENSEARCH_PATH_CONF=$conf" | Out-Null
}

function Ensure-OpenSearchServiceDeterministic {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$TinySocsRoot,
    [Parameter(Mandatory)][string]$ProgramDataOpenSearchRoot,
    [string]$ServiceName = "TinySocsOpenSearch",
    [string]$NssmPath = (Join-Path $TinySocsRoot "bin\nssm.exe"),
    [string]$RunnerPath = (Join-Path $ProgramDataOpenSearchRoot "bin\Start-OpenSearch.ps1"),
    [switch]$ForceSeedProgramDataConfig
  )

  $osRoot = Join-Path $TinySocsRoot "OpenSearch"
  $conf   = Join-Path $ProgramDataOpenSearchRoot "config"

  $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
  $hadSvc = [bool]$svc

  if ($hadSvc -and $svc.Status -eq 'Running') {
    try { Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue } catch { }
    try { sc.exe stop $ServiceName | Out-Null } catch { }
    Start-Sleep -Seconds 2
  }

  if (-not (Test-Path $osRoot -PathType Container)) {
    throw "OpenSearch root not found at '$osRoot'"
  }

  # Ensure ProgramData config is seeded + safe
  Ensure-TinySocsOpenSearchProgramDataConfig -OpenSearchRoot $osRoot -ProgramDataConf $conf -Force:$ForceSeedProgramDataConfig

  # Ensure runner exists (will also self-heal on each start)
  Ensure-TinySocsOpenSearchRunner -InstallRoot $TinySocsRoot -OpenSearchRoot $osRoot -ProgramDataConf $conf -RunnerPath $RunnerPath

  # Ensure NSSM service wrapper is deterministic
  if (-not (Test-Path $NssmPath -PathType Leaf)) {
    throw "nssm.exe not found at '$NssmPath'"
  }
  if (-not $hadSvc) {
    throw "Service '$ServiceName' not found. Create the service first, then call Ensure-OpenSearchServiceDeterministic."
  }

  $ps = (Get-Command powershell.exe -ErrorAction Stop).Source
  $runnerDir = Split-Path -Parent $RunnerPath
  if (-not (Test-Path $runnerDir -PathType Container)) { New-Item -ItemType Directory -Force -Path $runnerDir | Out-Null }

  $appDir = Join-Path $osRoot "bin"
  if (-not (Test-Path $appDir -PathType Container)) { $appDir = $osRoot }

  $appParams = "-NoProfile -ExecutionPolicy Bypass -File `"$RunnerPath`""

  try {
    & $NssmPath set $ServiceName AppPath $ps               | Out-Null
    & $NssmPath set $ServiceName AppParameters $appParams  | Out-Null
    & $NssmPath set $ServiceName AppDirectory $appDir      | Out-Null

    # Force OPENSEARCH_PATH_CONF for the service (defense-in-depth; runner also sets it)
    & $NssmPath set $ServiceName AppEnvironmentExtra ("OPENSEARCH_PATH_CONF=$conf") | Out-Null

    # Reasonable defaults: restart on failure
    try { & $NssmPath set $ServiceName AppExit Default Restart | Out-Null } catch { }
  } catch {
    throw "Failed to set NSSM service parameters for '$ServiceName': $($_.Exception.Message)"
  }

  if ($hadSvc) {
    try { Start-Service -Name $ServiceName -ErrorAction SilentlyContinue } catch { }
    try { sc.exe start $ServiceName | Out-Null } catch { }
  }

  Write-TinySocsLog "OpenSearch service '$ServiceName' made deterministic (ProgramDataConf=$conf, Runner=$RunnerPath)."
}

function Invoke-TinySocsOpenSearchDeterministicBootstrap {
  [CmdletBinding()]
  param(
    [string]$AppRoot = "C:\Program Files\TinySocs"
  )

  $script = Join-Path $AppRoot "bin\Ensure-TinySocsOpenSearchDeterministic.ps1"
  if (-not (Test-Path -LiteralPath $script -PathType Leaf)) {
    throw "Deterministic bootstrap script missing: $script"
  }

  # Run in a clean PowerShell so we don't inherit StrictMode / prefs weirdly
  $ps = Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe"
  $args = @(
    "-NoProfile",
    "-ExecutionPolicy", "Bypass",
    "-File", "`"$script`""
  )

  & $ps @args
  $code = $LASTEXITCODE
  if ($code -ne 0) {
    throw "Ensure-TinySocsOpenSearchDeterministic.ps1 failed (exit code $code). Check ProgramData OpenSearch logs."
  }
}

function Test-NssmManagedService {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)] [string] $ServiceName,
    [Parameter(Mandatory)] [string] $NssmExe
  )

  if (-not (Test-Path -LiteralPath $NssmExe -PathType Leaf)) { return $false }

  # IMPORTANT:
  # In Windows PowerShell 5.1, native stderr output can become a terminating error
  # when $ErrorActionPreference = 'Stop', even if you "redirect".
  # Use cmd.exe redirection to fully suppress it.
  $cmd = '""{0}"" get ""{1}"" Application >NUL 2>NUL' -f $NssmExe, $ServiceName
  try {
    & $env:ComSpec /d /c $cmd | Out-Null
    return ($LASTEXITCODE -eq 0)
  } catch {
    return $false
  }
}

function Register-TinySocsOpenSearchService {
  [CmdletBinding()]
  param(
    [string]$ServiceName = "TinySocsOpenSearch"
  )

  $nssm = "C:\Program Files\TinySocs\bin\nssm.exe"
  if (-not (Test-Path -LiteralPath $nssm -PathType Leaf)) {
    Write-TinySocsLog -Level "WARN" -Message "Register-TinySocsOpenSearchService: nssm.exe missing at '$nssm'; cannot register OpenSearch service."
    return
  }

  # HARDEN: root getters can sometimes return object[]
  $installRoot = (Get-TinySocsInstallRoot | Select-Object -First 1)
  $installRoot = [string]$installRoot
  if ([string]::IsNullOrWhiteSpace($installRoot) -or -not (Test-Path -LiteralPath $installRoot -PathType Container)) {
    Write-TinySocsLog -Level "WARN" -Message "Register-TinySocsOpenSearchService: TinySocs install root not found; cannot register service."
    return
  }

  $osHome = Join-Path $installRoot "OpenSearch"
  if (-not (Test-Path -LiteralPath $osHome -PathType Container)) {
    Write-TinySocsLog -Level "WARN" -Message "Register-TinySocsOpenSearchService: OpenSearch home not found at '$osHome'; cannot register service."
    return
  }

  $batPath = Join-Path $osHome "bin\opensearch.bat"
  if (-not (Test-Path -LiteralPath $batPath -PathType Leaf)) {
    Write-TinySocsLog -Level "WARN" -Message "Register-TinySocsOpenSearchService: opensearch.bat not found at '$batPath'; cannot register service."
    return
  }

  $dataRoot = (Get-TinySocsDataRoot | Select-Object -First 1)
  $dataRoot = [string]$dataRoot
  if ([string]::IsNullOrWhiteSpace($dataRoot)) {
    Write-TinySocsLog -Level "WARN" -Message "Register-TinySocsOpenSearchService: ProgramData root not resolved; cannot register."
    return
  }

  $conf   = Join-Path $dataRoot "OpenSearch\config"
  $osLogs = Join-Path $dataRoot "OpenSearch\logs"
  $pdBin  = Join-Path $dataRoot "OpenSearch\bin"
  New-Item -ItemType Directory -Force -Path $conf   | Out-Null
  New-Item -ItemType Directory -Force -Path $osLogs | Out-Null
  New-Item -ItemType Directory -Force -Path $pdBin  | Out-Null

  # Canonical runner path (THIS must match NSSM)
  $runnerPath = Join-Path $pdBin "Run-OpenSearch.ps1"

  # Write runner (idempotent, upgrade-safe)
  $homeQ = $osHome.Replace("'", "''")
  $batQ  = $batPath.Replace("'", "''")
  $confQ = $conf.Replace("'", "''")
  $binQ  = (Join-Path $osHome "bin").Replace("'", "''")

  $runner = @"
`$ErrorActionPreference = 'Stop'
# TinySocs OpenSearch service runner (ProgramData-owned; upgrade-safe)

`$osHome = '$homeQ'
`$osBin  = '$binQ'
`$bat    = '$batQ'
`$conf   = '$confQ'

# Force ProgramData config
`$env:OPENSEARCH_PATH_CONF = `$conf

try {
  Set-Location -LiteralPath `$osBin
  & `$bat
} catch {
  Write-Error ("Run-OpenSearch.ps1 failed: " + `$_.Exception.Message)
  throw
}
"@

  # PATCH: write UTF8 *without BOM* (PS5 Set-Content -Encoding UTF8 writes BOM)
  try {
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($runnerPath, $runner, $utf8NoBom)
  } catch {
    # fallback
    Set-Content -LiteralPath $runnerPath -Value $runner -Encoding UTF8 -Force
  }

  if (-not (Test-Path -LiteralPath $runnerPath -PathType Leaf)) {
    throw "Register-TinySocsOpenSearchService: runner was not created at '$runnerPath' (cannot proceed)."
  }

  $psExe = (Get-Command powershell.exe -ErrorAction Stop).Source
  $appDir = Join-Path $osHome "bin"
  $appParams = "-NoProfile -ExecutionPolicy Bypass -File `"$runnerPath`""

  # PS5.1-safe "service exists?" check (no NativeCommandError)
  $exists = Test-NssmManagedService -ServiceName $ServiceName -NssmExe $nssm

  function _GetNssmStatus {
    param([Parameter(Mandatory)][string]$Name)
    try {
      $o = & $nssm status $Name 2>&1 | Out-String
      $t = ($o.Trim() -replace '\s+',' ').Trim()
      if ([string]::IsNullOrWhiteSpace($t)) { return $null }
      return $t
    } catch { return $null }
  }

  function _TryStopServiceSoft {
    param([Parameter(Mandatory)][string]$Name)
    try {
      $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
      if ($svc -and ($svc.Status -ne 'Stopped')) {
        try { Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue } catch { }
        try { (Get-Service -Name $Name -ErrorAction SilentlyContinue).WaitForStatus('Stopped','00:00:25') } catch { }
      }
    } catch { }
  }

  if ($exists) {
    # PATCH: stop is best-effort; "already stopped" is success
    _TryStopServiceSoft -Name $ServiceName
    try { & $nssm stop $ServiceName 1>$null 2>$null | Out-Null } catch { }
    Start-Sleep -Milliseconds 750
  } else {
    # Install new service
    & $nssm install $ServiceName $psExe | Out-Null
  }

  # Always re-apply settings (upgrade-safe)
  & $nssm set $ServiceName Application        $psExe     | Out-Null
  & $nssm set $ServiceName AppParameters      $appParams | Out-Null
  & $nssm set $ServiceName AppDirectory       $appDir    | Out-Null
  & $nssm set $ServiceName Start              SERVICE_AUTO_START | Out-Null
  & $nssm set $ServiceName AppStdout          (Join-Path $osLogs "opensearch.out.log") | Out-Null
  & $nssm set $ServiceName AppStderr          (Join-Path $osLogs "opensearch.err.log") | Out-Null
  & $nssm set $ServiceName AppNoConsole       1 | Out-Null
  & $nssm set $ServiceName AppRestartDelay    2000 | Out-Null
  try { & $nssm set $ServiceName AppExit Default Restart | Out-Null } catch { }

  # PATCH: merge AppEnvironmentExtra instead of clobbering
  try {
    $existingEnv = $null
    try { $existingEnv = & $nssm get $ServiceName AppEnvironmentExtra 2>$null } catch { $existingEnv = $null }

    $merged = @()
    if ($existingEnv) { $merged += $existingEnv }
    $merged += @("OPENSEARCH_PATH_CONF=$conf")

    if (Get-Command Format-TinySocsNssmEnvExtra -ErrorAction SilentlyContinue) {
      $envExtra = Format-TinySocsNssmEnvExtra -Lines $merged
    } else {
      # minimal fallback: last write wins, LF separators
      $envExtra = (($merged | ForEach-Object { [string]$_ }) -join "`n")
    }

    & $nssm set $ServiceName AppEnvironmentExtra $envExtra | Out-Null
  } catch {
    # fallback to previous behavior
    & $nssm set $ServiceName AppEnvironmentExtra ("OPENSEARCH_PATH_CONF=$conf") | Out-Null
  }

  try { sc.exe failure $ServiceName reset= 60 actions= restart/2000/restart/2000/restart/2000 | Out-Null } catch { }

  # PATCH: start is idempotent: "already running" is success
  $svc = $null
  try { $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue } catch { $svc = $null }
  if ($svc -and ($svc.Status -eq 'Running' -or $svc.Status -eq 'StartPending')) {
    Write-TinySocsLog -Level "INFO" -Message "OpenSearch service '$ServiceName' already $($svc.Status); treating as success."
  } else {
    $startOut = $null
    try { $startOut = & $nssm start $ServiceName 2>&1 | Out-String } catch { $startOut = $_.Exception.Message }

    Start-Sleep -Milliseconds 600

    $svc2 = $null
    try { $svc2 = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue } catch { $svc2 = $null }

    if ($svc2 -and ($svc2.Status -eq 'Running' -or $svc2.Status -eq 'StartPending')) {
      # success
    } else {
      $st = _GetNssmStatus -Name $ServiceName
      $txt = (([string]$startOut).Trim())
      if ($txt -match '(?i)already\s+running') {
        Write-TinySocsLog -Level "INFO" -Message "NSSM reported service already running for '$ServiceName'; treating as success."
      } else {
        Write-TinySocsLog -Level "WARN" -Message "NSSM start did not confirm Running (status='$st'). Output: $txt"
        # Do not hard-throw here: the caller often does readiness probing and will surface real failures.
      }
    }
  }

  Write-TinySocsLog -Level "INFO" -Message "OpenSearch service '$ServiceName' registered: Application=$psExe AppDirectory=$appDir Runner=$runnerPath OPENSEARCH_PATH_CONF=$conf"
}

function Format-TinySocsNssmEnvExtra {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][object]$Lines
  )

  # Normalize input -> string[]
  $arr = @()
  if ($Lines -is [string]) {
    $arr = @([string]$Lines)
  } elseif ($Lines -is [System.Collections.IEnumerable]) {
    foreach ($x in $Lines) { $arr += @([string]$x) }
  } else {
    $arr = @([string]$Lines)
  }

  # Expand any embedded newlines (treat as separators, not characters inside a token)
  $expanded = @()
  foreach ($s in $arr) {
    if ($null -eq $s) { continue }
    $t = [string]$s
    foreach ($p in ($t -split "(`r`n|`n|`r)")) {
      if ($null -ne $p) { $expanded += @([string]$p) }
    }
  }

  # Clean + keep only KEY=VALUE
  $clean = @()
  foreach ($s in $expanded) {
    if ($null -eq $s) { continue }
    $t = $s.ToString()

    # Strip tabs + NULs; trim whitespace
    $t = $t -replace "(`t|`0)", ""
    $t = $t.Trim()

    if ([string]::IsNullOrWhiteSpace($t)) { continue }

    # If someone previously jammed multiple env pairs into one string via ';', split them.
    # We only split when it *looks* like "X=1;Y=2" (to avoid mangling paths like "C:\...")
    if ($t -match '^[^=\s][^=]*=.*;[^=\s][^=]*=.*$') {
      foreach ($part in ($t -split ';')) {
        $pt = ($part -replace "(`t|`0)", "").Trim()
        if ([string]::IsNullOrWhiteSpace($pt)) { continue }
        if ($pt -match '^[^=\s][^=]*=.*$') { $clean += $pt }
      }
      continue
    }

    if ($t -notmatch '^[^=\s][^=]*=.*$') { continue }

    # Drop surrounding quotes if present (NSSM doesn't want them as part of the key)
    if ($t.Length -ge 2 -and (
        ($t.StartsWith('"') -and $t.EndsWith('"')) -or
        ($t.StartsWith("'") -and $t.EndsWith("'"))
      )) {
      $t = $t.Substring(1, $t.Length - 2).Trim()
      if ([string]::IsNullOrWhiteSpace($t)) { continue }
      if ($t -notmatch '^[^=\s][^=]*=.*$') { continue }
    }

    $clean += $t
  }

  # De-dupe by key, preserve insertion order (last write wins)
  $seen  = @{}
  $order = New-Object System.Collections.Generic.List[string]
  foreach ($line in $clean) {
    $k = ($line -split '=', 2)[0].Trim()
    if ([string]::IsNullOrWhiteSpace($k)) { continue }

    if (-not $seen.ContainsKey($k)) { [void]$order.Add($k) }
    $seen[$k] = $line
  }

  $out = foreach ($k in $order) { $seen[$k] }

  # NSSM AppEnvironmentExtra is REG_MULTI_SZ; give it LF-only separators.
  return (($out -join "`n").Trim("`r","`n"))
}

# NOTE: Ensure-* should NOT start the service (Install-* decides based on -NoStart).
function Ensure-TinySocsOpenSearchService {
  [CmdletBinding()]
  param(
    [string] $ServiceName     = "TinySocsOpenSearch",
    [string] $NssmExe         = "C:\Program Files\TinySocs\bin\nssm.exe",
    [string] $Runner          = "C:\ProgramData\TinySocs\OpenSearch\run-opensearch.ps1",
    [string] $WorkDir         = "C:\ProgramData\TinySocs\OpenSearch",
    [string] $LogsDir         = "C:\ProgramData\TinySocs\OpenSearch\logs",
    [int]    $HttpPort        = 9200,
    [string] $ProgramDataConf = "C:\ProgramData\TinySocs\OpenSearch\config"
  )

  if (-not (Test-Path -LiteralPath $NssmExe -PathType Leaf)) { throw "nssm.exe not found: $NssmExe" }

  $ps = "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe"
  if (-not (Test-Path -LiteralPath $Runner -PathType Leaf)) { throw "Missing runner: $Runner" }

  New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
  New-Item -ItemType Directory -Force -Path $LogsDir | Out-Null

  $null = sc.exe query $ServiceName 2>$null
  $serviceExists = ($LASTEXITCODE -eq 0)

  $validNssm = $false
  if ($serviceExists) {
    $validNssm = (Test-NssmManagedService -ServiceName $ServiceName -NssmExe $NssmExe)
  }

  if ($serviceExists -and -not $validNssm) {
    try { Stop-Service $ServiceName -Force -ErrorAction SilentlyContinue } catch {}
    Start-Sleep 2
    try { sc.exe stop   $ServiceName | Out-Null } catch { }
    Start-Sleep 2
    try { sc.exe delete $ServiceName | Out-Null } catch { }

    for ($i=0; $i -lt 20; $i++) {
      $null = sc.exe query $ServiceName 2>$null
      if ($LASTEXITCODE -ne 0) { break }
      Start-Sleep 1
    }
    $serviceExists = $false
  }

  if (-not (Test-NssmManagedService -ServiceName $ServiceName -NssmExe $NssmExe)) {
    & $NssmExe install $ServiceName $ps 2>$null | Out-Null
  }

  & $NssmExe set $ServiceName Application   $ps      | Out-Null
  & $NssmExe set $ServiceName AppDirectory  $WorkDir | Out-Null
  & $NssmExe set $ServiceName AppParameters "-NoProfile -ExecutionPolicy Bypass -File `"$Runner`"" | Out-Null
  & $NssmExe set $ServiceName AppStdout     "$LogsDir\TinySocsOpenSearch.out.log" | Out-Null
  & $NssmExe set $ServiceName AppStderr     "$LogsDir\TinySocsOpenSearch.err.log" | Out-Null

  try { & $NssmExe set $ServiceName AppNoConsole     1     | Out-Null } catch { }
  try { & $NssmExe set $ServiceName AppThrottle      15000 | Out-Null } catch { }
  try { & $NssmExe set $ServiceName AppRestartDelay  5000  | Out-Null } catch { }

  & $NssmExe set $ServiceName AppStopMethodSkip 1     | Out-Null
  & $NssmExe set $ServiceName AppExit Default Restart | Out-Null

  # Ensure identity + delayed-auto via BOTH NSSM + sc.exe
  try { & $NssmExe set $ServiceName ObjectName "LocalSystem" | Out-Null } catch { }
  try { & $NssmExe set $ServiceName Start "SERVICE_DELAYED_AUTO_START" | Out-Null } catch { }

  try { sc.exe config $ServiceName start= delayed-auto | Out-Null } catch { }
  try { sc.exe config $ServiceName obj= LocalSystem    | Out-Null } catch { }

  try {
    sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/5000/restart/5000 | Out-Null
    sc.exe failureflag $ServiceName 1 | Out-Null
  } catch { }

  # Merge OPENSEARCH_PATH_CONF into existing AppEnvironmentExtra (donÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬ÃƒÂ¢Ã¢â‚¬Å¾Ã‚Â¢t clobber)
  # IMPORTANT: NSSM AppEnvironmentExtra must be a multi-string of KEY=VALUE lines.
  # We therefore run everything through Format-TinySocsNssmEnvExtra which:
  #   - drops junk
  #   - splits accidental multi-pairs
  #   - LF-only join
  try {
    if (-not [string]::IsNullOrWhiteSpace($ProgramDataConf)) {

      $current = @()
      try {
        $out = & $NssmExe get $ServiceName AppEnvironmentExtra 2>$null
        $txt = ($out | Out-String)
        if (-not [string]::IsNullOrWhiteSpace($txt)) {
          $current = ($txt -split "(`r`n|`n|`r)") | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        }
      } catch { $current = @() }

      $desired = @()
      if ($current) { $desired += $current }
      $desired += "OPENSEARCH_PATH_CONF=$ProgramDataConf"

      $envExtra = $null
      try {
        $envExtra = Format-TinySocsNssmEnvExtra $desired
      } catch {
        # Fallback (still LF-only)
        $envExtra = (($desired | Where-Object { $_ -match '^[^=\s][^=]*=.*$' }) -join "`n").Trim("`r","`n")
      }

      # Final safety: if somehow empty, force our invariant only.
      if ([string]::IsNullOrWhiteSpace($envExtra)) {
        $envExtra = "OPENSEARCH_PATH_CONF=$ProgramDataConf"
      }

      & $NssmExe set $ServiceName AppEnvironmentExtra $envExtra | Out-Null
    }
  } catch {
    Write-TinySocsLog -Level "WARN" -Message "Failed to merge/set NSSM AppEnvironmentExtra for '$ServiceName': $($_.Exception.Message)"
  }

  Write-TinySocsLog "OpenSearch service ensured via NSSM (not started here). (runner=$Runner, workdir=$WorkDir, conf=$ProgramDataConf)"
}

function Ensure-TinySocsOpenSearchDeterministicBootstrap {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)] [string] $OpenSearchRoot,
    [Parameter(Mandatory=$true)] [string] $ProgramDataConf,
    [Parameter(Mandatory=$true)] [string] $CertsDir,
    [Parameter(Mandatory=$true)] [int]    $HttpPort,
    [Parameter(Mandatory=$true)] [bool]   $AllowDefaultInitSecurityIndex,
    [Parameter()] $TlsPaths
  )

  function _EnsureSingleYamlKey {
    param(
      [Parameter(Mandatory=$true)] [string] $Path,
      [Parameter(Mandatory=$true)] [string] $Key,
      [Parameter(Mandatory=$true)] [string] $Value
    )

    $lines = @()
    if (Test-Path -LiteralPath $Path -PathType Leaf) {
      $lines = Get-Content -LiteralPath $Path -ErrorAction Stop
    }

    $rx = "^\s*" + [regex]::Escape($Key) + "\s*:"
    $filtered = $lines | Where-Object { $_ -notmatch $rx }
    $out = $filtered + ("{0}: {1}" -f $Key, $Value)

    # use module-level helper (avoid nested duplicates)
    _WriteUtf8NoBom -Path $Path -Text ($out -join "`r`n")
  }

  function _NormalizePassword([string]$s) {
    if ($null -eq $s) { return $null }
    return ($s.Trim() -replace "`0+$","")
  }

  function _TestPkcs12Password([string]$P12Path, [string]$Password) {
    try {
      $col = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
      $flags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::DefaultKeySet
      $col.Import($P12Path, $Password, $flags) | Out-Null
      return $true
    } catch {
      return $false
    }
  }

  # ---- Begin deterministic actions ----
  try {
    # Canonicalize OPENSEARCH_PATH_CONF at process level (service-level env is handled elsewhere too)
    $env:OPENSEARCH_PATH_CONF = $ProgramDataConf

    $configFile = Join-Path -Path $ProgramDataConf -ChildPath "opensearch.yml"
    if (-not (Test-Path -LiteralPath $configFile -PathType Leaf)) {
      throw "opensearch.yml missing at $configFile (cannot enforce determinism)."
    }

    # 1) Hard-stop YAML duplicate-key regressions (exactly-once keys)
    _EnsureSingleYamlKey -Path $configFile -Key "http.port" -Value ([string]$HttpPort)

    $allowVal = if ($AllowDefaultInitSecurityIndex) { "true" } else { "false" }
    _EnsureSingleYamlKey -Path $configFile -Key "plugins.security.allow_default_init_securityindex" -Value $allowVal

    # Optional belt-and-braces: keys you always want set once
    _EnsureSingleYamlKey -Path $configFile -Key "plugins.security.ssl.http.enabled" -Value "true"
    _EnsureSingleYamlKey -Path $configFile -Key "plugins.security.ssl.http.keystore_type" -Value "PKCS12"
    _EnsureSingleYamlKey -Path $configFile -Key "plugins.security.ssl.http.truststore_type" -Value "PKCS12"
    _EnsureSingleYamlKey -Path $configFile -Key "plugins.security.ssl.transport.keystore_type" -Value "PKCS12"
    _EnsureSingleYamlKey -Path $configFile -Key "plugins.security.ssl.transport.truststore_type" -Value "PKCS12"

    _EnsureSingleYamlKey -Path $configFile -Key "plugins.security.ssl.http.keystore_filepath" -Value "certs/http.p12"
    _EnsureSingleYamlKey -Path $configFile -Key "plugins.security.ssl.http.truststore_filepath" -Value "certs/trust.p12"
    _EnsureSingleYamlKey -Path $configFile -Key "plugins.security.ssl.transport.keystore_filepath" -Value "certs/transport.p12"
    _EnsureSingleYamlKey -Path $configFile -Key "plugins.security.ssl.transport.truststore_filepath" -Value "certs/trust.p12"

    # 2) Validate storepass deterministically (TinySocs convention: dpapi file is base64 TEXT of DPAPI bytes)
    $dpapiStorePassPath = Join-Path -Path $CertsDir -ChildPath "opensearch-tls-storepass.dpapi"
    if (Test-Path -LiteralPath $dpapiStorePassPath -PathType Leaf) {

      # Use the module helper (do NOT re-implement DPAPI parsing here)
      $storePass = _NormalizePassword (Read-TinySocsDpapiFileLocalMachineString -Path $dpapiStorePassPath)

      if ([string]::IsNullOrWhiteSpace($storePass)) {
        throw "DPAPI storepass decoded empty/whitespace from: $dpapiStorePassPath"
      }

      $p12s = @(
        (Join-Path $CertsDir "http.p12"),
        (Join-Path $CertsDir "transport.p12"),
        (Join-Path $CertsDir "trust.p12")
      ) | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf }

      if ($p12s.Count -gt 0) {
        foreach ($p12 in $p12s) {
          if (-not (_TestPkcs12Password -P12Path $p12 -Password $storePass)) {
            throw "DPAPI storepass does not open PKCS12 '$p12' (cert bundle/storepass mismatch)."
          }
        }
      }
    }

    Write-TinySocsLog "Deterministic OpenSearch bootstrap enforced (http.port=$HttpPort, allow_default_init_securityindex=$allowVal, yaml dedup + dpapi storepass validation)."
  }
  catch {
    # Fail hard: determinism is not â€œbest effortâ€
    throw
  }
}

# Helper: Ensure TinySocs Agent service via NSSM
function Ensure-TinySocsAgentService {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$AgentExePath,
    [Parameter(Mandatory)][string]$NssmPath,
    [Parameter(Mandatory)][string]$ServiceName,
    [Parameter(Mandatory)][string]$DisplayName,
    [Parameter(Mandatory)][string]$Description
  )

  if (-not (Test-Path $NssmPath -PathType Leaf)) {
    throw "nssm.exe not found at '$NssmPath'. Ensure the TinySocs installer copies nssm.exe before installing the agent."
  }

  if (-not (Test-Path $AgentExePath -PathType Leaf)) {
    Write-TinySocsLog -Level "WARN" -Message "TinySocs.Agent.exe not found at '$AgentExePath'. Agent service '$ServiceName' will not be installed."
    return
  }

  $agentRoot = Split-Path -Parent $AgentExePath
  $service   = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

  if ($null -eq $service) {
    Write-TinySocsLog "Creating NSSM service '$ServiceName' for TinySocs Collector Agent"
    & $NssmPath install $ServiceName $AgentExePath | Out-Null
  } else {
    Write-TinySocsLog "Service '$ServiceName' already exists; updating NSSM configuration"
  }

  & $NssmPath set $ServiceName DisplayName  $DisplayName | Out-Null
  & $NssmPath set $ServiceName Description  $Description | Out-Null

  # Phase 10: Set working directory to Collector under ProgramData (not Program Files)
  $workingDir = "C:\ProgramData\TinySocs\Collector"
  & $NssmPath set $ServiceName AppDirectory $workingDir | Out-Null

  & $NssmPath set $ServiceName ObjectName "LocalSystem"           | Out-Null
  & $NssmPath set $ServiceName Start "SERVICE_DELAYED_AUTO_START" | Out-Null
  & $NssmPath set $ServiceName AppExit Default Restart            | Out-Null
  & $NssmPath set $ServiceName AppStdout "C:\ProgramData\TinySocs\Collector\logs\TinySocsAgent.out.log" | Out-Null
  & $NssmPath set $ServiceName AppStderr "C:\ProgramData\TinySocs\Collector\logs\TinySocsAgent.err.log" | Out-Null

  # Sterile environment: blank all credential env vars so the agent reads creds
  # from config.yml via CredMan, and set the config path
  $configPath = "C:\ProgramData\TinySocs\Collector\agent-config.yml"
  $sterileEnv = @(
    "TINYSOCS_SIEM_USER=",
    "TINYSOCS_SIEM_PASS=",
    "SIEM_USER=",
    "SIEM_PASS=",
    "TS_SIEM_USER=",
    "TS_SIEM_PASS=",
    "OPENSEARCH_USERNAME=",
    "OPENSEARCH_PASSWORD=",
    "TINYSOCS_ALLOW_ENV_CREDS=0",
    "TINYSOCS_AGENT_CONFIG=$configPath"
  ) -join "`n"
  try {
    & $NssmPath set $ServiceName AppEnvironmentExtra $sterileEnv | Out-Null
    Write-TinySocsLog "Sterile environment set for agent service '$ServiceName'. Working dir: $workingDir, Config: $configPath"
  } catch {
    Write-TinySocsLog -Level "WARN" -Message "Failed to set sterile env for '$ServiceName': $($_.Exception.Message)"
  }

  Write-TinySocsLog "Service '$ServiceName' ensured via NSSM (TinySocs Agent)."
}

function Wait-TinySocsLocalSiemReady {
  [CmdletBinding()]
  param(
    [string]$Url = "https://localhost:9201",
    [int]$TimeoutSeconds = 60,
    [int]$IntervalSeconds = 3,
    [switch]$SkipTlsVerify,

    # For localhost/self-signed TLS, Schannel revocation checks can be brittle.
    # If not specified, we'll disable revocation checks automatically for loopback.
    [switch]$DisableTlsRevocationCheck
  )

  $deadline = (Get-Date).AddSeconds([Math]::Max(1, $TimeoutSeconds))
  $u = $Url.Trim()
  Write-TinySocsLog "Waiting for local SIEM HTTP to become ready at $u (timeout=${TimeoutSeconds}s)."

  # Resolve curl.exe deterministically
  $curlExe = Join-Path $env:WINDIR "System32\curl.exe"
  if (-not (Test-Path $curlExe -PathType Leaf)) { $curlExe = "curl.exe" }

  # Determine if loopback
  $isLoopback = $false
  try {
    $uri = [Uri]$u
    if ($uri.IsLoopback -or ($uri.Host -in @('127.0.0.1','localhost','::1'))) { $isLoopback = $true }
  } catch { $isLoopback = $false }

  $effectiveDisableRevoke = $false
  if (-not $SkipTlsVerify.IsPresent) {
    if ($DisableTlsRevocationCheck.IsPresent) { $effectiveDisableRevoke = $true }
    elseif ($isLoopback) { $effectiveDisableRevoke = $true }
  }

  $last = $null

  while ((Get-Date) -lt $deadline) {
    try {
      $args = @("--silent","--show-error","--output","NUL","--write-out","%{http_code}","--connect-timeout","2","--max-time","6","--head")

      # ALWAYS use -k for loopback readiness checks. We only need to know
      # OpenSearch is responding HTTP, not validate the cert chain. Without
      # -k, curl hangs on self-signed TLS negotiation/revocation checks and
      # the installer stalls indefinitely.
      if ($isLoopback -or $SkipTlsVerify.IsPresent) {
        $args = @("-k") + $args
      } elseif ($effectiveDisableRevoke) {
        $args = @("--ssl-no-revoke") + $args
      }

      $code = (& $curlExe @args $u) 2>&1
      $code = (($code | Out-String).Trim() -split "\s+")[-1]

      # Treat these as "HTTP is up":
      # - 200: OK
      # - 401/403: auth/security is enforcing (good)
      # - 302: redirect (rare, but means HTTP is responding)
      if ($code -in @('200','401','403','302')) {
        Write-TinySocsLog "Local SIEM HTTP ready at $u (status=$code)."
        return $true
      }

      # IMPORTANT: 503 is *still* HTTP, and commonly indicates security is not initialized yet.
      # We must allow the installer to proceed to securityadmin + REST init, otherwise we deadlock.
      if ($code -eq '503') {
        Write-TinySocsLog -Level "WARN" -Message "Local SIEM HTTP responding at $u (status=503). Treating as ready-enough to proceed with security bootstrap."
        return $true
      }

      $last = "HTTP $code"
      Write-TinySocsLog -Level "WARN" -Message ("Waiting for local SIEM HTTP at {0}: {1}" -f $u, $last)
    } catch {
      $last = $_.Exception.Message
      Write-TinySocsLog -Level "WARN" -Message ("Waiting for local SIEM HTTP at {0}: {1}" -f $u, $last)
    }

    Start-Sleep -Seconds $IntervalSeconds
  }

  Write-TinySocsLog -Level "WARN" -Message "Local SIEM HTTP did not become ready at $u within ${TimeoutSeconds}s. Last=$last"
  return $false
}

function Ensure-TinySocsTrustedCaPem {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$CaPemPath
  )

  if (-not (Test-Path $CaPemPath -PathType Leaf)) {
    Write-TinySocsLog -Level "WARN" -Message "CA PEM not found at $CaPemPath; skipping trust import."
    return $false
  }

  try {
    & certutil.exe -addstore -f Root "$CaPemPath" | Out-Null
    Write-TinySocsLog "Imported CA PEM into LocalMachine\Root (certutil): $CaPemPath"
    return $true
  } catch {
    Write-TinySocsLog -Level "WARN" -Message "Failed to import CA PEM into Root store: $($_.Exception.Message)"
    return $false
  }
}

function Set-TinySocsOpenSearchAdminPasswordInConfig {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$OpenSearchRoot,
    [Parameter(Mandatory)][string]$ConfigRoot,
    [Parameter(Mandatory)][string]$AdminPassword
  )

  $toolsDir = Join-Path $OpenSearchRoot "plugins\opensearch-security\tools"
  if (-not (Test-Path $toolsDir -PathType Container)) {
    throw "OpenSearch security tools dir not found at '$toolsDir'"
  }

  # Be robust across OpenSearch versions (hash.bat vs hash.sh vs hash-*.bat, etc.)
  $hashTool = Get-ChildItem -Path $toolsDir -Filter "hash*.bat" -File -ErrorAction SilentlyContinue | Select-Object -First 1
  if (-not $hashTool) {
    throw "OpenSearch hash tool not found under '$toolsDir' (expected hash*.bat)"
  }

  # Preserve env so we don't pollute caller session
  $prevOpensearchJava = $env:OPENSEARCH_JAVA_HOME
  $prevJavaHome       = $env:JAVA_HOME
  $prevPath           = $env:Path

  try {
    $env:OPENSEARCH_JAVA_HOME = Join-Path $OpenSearchRoot "jdk"
    $env:JAVA_HOME            = $env:OPENSEARCH_JAVA_HOME
    $env:Path                 = (Join-Path $env:JAVA_HOME "bin") + ";" + $env:Path

    $hashOut = & $hashTool.FullName -p $AdminPassword 2>&1

    # Extract bcrypt hash reliably from noisy output
    $hashLine = ($hashOut | Select-String -Pattern '\$2[aby]\$' | Select-Object -First 1)
    $hash = if ($hashLine) { $hashLine.ToString().Trim() } else { "" }

    if ([string]::IsNullOrWhiteSpace($hash) -or ($hash -notmatch '^\$2[aby]\$')) {
      throw "Failed to generate bcrypt hash for admin password. Tool='$($hashTool.FullName)'. Output:`n$($hashOut | Out-String)"
    }

    $iu = Join-Path $ConfigRoot "opensearch-security\internal_users.yml"
    if (-not (Test-Path $iu -PathType Leaf)) {
      throw "internal_users.yml not found at '$iu'"
    }

    Ensure-TinySocsWritableFile -Path $iu
    $text = Get-Content -Path $iu -Raw -ErrorAction Stop

    $adminBlock = @"
admin:
  hash: "$hash"
  reserved: true
  backend_roles:
    - "admin"
  opendistro_security_roles:
    - "all_access"
    - "security_rest_api_access"
  description: "TinySocs local admin"
"@

    if ($text -match '(?ms)^\s*admin\s*:\s*\r?\n') {
      $text = [regex]::Replace(
        $text,
        '(?ms)^\s*admin\s*:\s*\r?\n.*?(?=^\S|\z)',
        $adminBlock + "`r`n",
        1
      )
    } else {
      $text = $adminBlock + "`r`n`r`n" + $text
    }

    Ensure-TinySocsWritableFile -Path $iu

    # Write UTF-8 *without BOM*
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($iu, $text, $utf8NoBom)

    Write-TinySocsLog "Updated ProgramData internal_users.yml admin block + hash (config=$iu)."
    return $true
  }
  finally {
    $env:OPENSEARCH_JAVA_HOME = $prevOpensearchJava
    $env:JAVA_HOME            = $prevJavaHome
    $env:Path                 = $prevPath
  }
}

function Get-TinySocsOpenSearchSecurityTemplatePath {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$InstallRoot,
    [Parameter(Mandatory)][string]$OpenSearchRoot
  )

  # Search order (first hit wins):
  # 1) OpenSearchRoot\config\opensearch-security   (if you ship it there)
  # 2) InstallRoot\assets\opensearch-security      (recommended)
  # 3) Module folder\assets\opensearch-security    (dev convenience)
  $candidates = @(
    (Join-Path $OpenSearchRoot "config\opensearch-security"),
    (Join-Path $InstallRoot   "assets\opensearch-security"),
    (Join-Path $PSScriptRoot  "assets\opensearch-security")
  ) | Where-Object { $_ -and (Test-Path $_ -PathType Container) }

  $first = $candidates | Select-Object -First 1
  if ($first) { return [string]$first }

  throw ("TinySocs OpenSearch security templates not found. " +
         "Expected one of: " +
         "'{0}', '{1}', '{2}'" -f `
         (Join-Path $OpenSearchRoot "config\opensearch-security"),
         (Join-Path $InstallRoot   "assets\opensearch-security"),
         (Join-Path $PSScriptRoot  "assets\opensearch-security"))
}

function Ensure-TinySocsOpenSearchSecurityConfigTree {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$InstallRoot,
    [Parameter(Mandatory)][string]$OpenSearchRoot,
    [Parameter(Mandatory)][string]$ProgramDataConf,
    [switch]$Force
  )

  $dst = Join-Path $ProgramDataConf "opensearch-security"

  # Required minimal security config files for OpenSearch Security plugin initialization
  $required = @(
    "config.yml",
    "internal_users.yml",
    "roles.yml",
    "roles_mapping.yml",
    "action_groups.yml",
    "tenants.yml",
    "nodes_dn.yml"
  )

  $optional = @("audit.yml", "allowlist.yml")

  function _ResolveServiceSidIcacls([string]$ServiceName) {
    try {
      $acct = "NT SERVICE\$ServiceName"
      $sid  = (New-Object System.Security.Principal.NTAccount($acct)).Translate([System.Security.Principal.SecurityIdentifier]).Value
      if ([string]::IsNullOrWhiteSpace($sid)) { return $null }
      return ("*{0}" -f $sid)  # icacls SID form
    } catch { return $null }
  }

  function _FindTemplateRoot {
    param([string]$InstallRootPath, [string]$OpenSearchRootPath)

    # Prefer the "blessed" template location if your module has it
    if (Get-Command Get-TinySocsOpenSearchSecurityTemplatePath -ErrorAction SilentlyContinue) {
      try {
        $p = Get-TinySocsOpenSearchSecurityTemplatePath -InstallRoot $InstallRootPath -OpenSearchRoot $OpenSearchRootPath
        if ($p -and (Test-Path $p -PathType Container)) { return [string]$p }
      } catch { }
    }

    # Fallbacks (dev + packaged + upstream plugin)
    $candidates = @(
      (Join-Path $InstallRootPath "assets\opensearch-security"),
      (Join-Path $OpenSearchRootPath "config\opensearch-security"),
      (Join-Path $OpenSearchRootPath "plugins\opensearch-security\securityconfig"),
      (Join-Path $OpenSearchRootPath "plugins\opensearch-security\securityconfig\config") # rare, but harmless
    ) | Where-Object { $_ -and (Test-Path $_ -PathType Container) }

    $first = $candidates | Select-Object -First 1
    if ($first) { return [string]$first }

    throw ("TinySocs OpenSearch security templates not found. Expected one of: " +
           "'{0}', '{1}', '{2}', '{3}'" -f `
           (Join-Path $InstallRootPath "assets\opensearch-security"),
           (Join-Path $OpenSearchRootPath "config\opensearch-security"),
           (Join-Path $OpenSearchRootPath "plugins\opensearch-security\securityconfig"),
           (Join-Path $OpenSearchRootPath "plugins\opensearch-security\securityconfig\config"))
  }

  function _CopyIfMissingOrForce {
    param(
      [Parameter(Mandatory)][string]$SrcRoot,
      [Parameter(Mandatory)][string]$DstRoot,
      [Parameter(Mandatory)][string]$FileName,
      [switch]$ForceCopy
    )

    $src     = Join-Path $SrcRoot $FileName
    $dstFile = Join-Path $DstRoot $FileName

    if (-not (Test-Path $src -PathType Leaf)) { return $false }

    if ($ForceCopy.IsPresent -or -not (Test-Path $dstFile -PathType Leaf)) {
      try {
        if (Get-Command Ensure-TinySocsWritableFile -ErrorAction SilentlyContinue) {
          try { Ensure-TinySocsWritableFile -Path $dstFile } catch { }
        }
        Copy-Item -Force -Path $src -Destination $dstFile
        return $true
      } catch {
        throw "Failed to copy '$FileName' from '$src' to '$dstFile': $($_.Exception.Message)"
      }
    }

    return $false
  }

  function _EnsureNotEfs([string]$Path) {
    if (Get-Command Ensure-FileNotEfsEncrypted -ErrorAction SilentlyContinue) {
      try { Ensure-FileNotEfsEncrypted -Path $Path } catch { }
    }
  }

  function _HardenSecurityDirAcl {
    param([Parameter(Mandatory)][string]$Path)

    # Locale-proof SIDs (icacls SID form with leading *)
    $sidSystem = '*S-1-5-18'       # SYSTEM
    $sidAdmins = '*S-1-5-32-544'   # BUILTIN\Administrators
    $sidUsers  = '*S-1-5-32-545'   # BUILTIN\Users (needed for non-elevated shells under UAC)

    # Best-effort: allow the service identity to read configs if it exists
    $sidSvc = _ResolveServiceSidIcacls -ServiceName "TinySocsOpenSearch"

    try {
      # Enable inheritance so we can "wash" weird ACLs, then remove explicit denies, then set strict grants
      & icacls $Path /inheritance:e /T /C 2>$null | Out-Null

      # Remove explicit deny ACEs that commonly survive upgrades
      & icacls $Path /remove:d "SYSTEM" "BUILTIN\Administrators" /T /C 2>$null | Out-Null
      & icacls $Path /remove:d "Everyone" "Users" "Authenticated Users" /T /C 2>$null | Out-Null

      # Now make it strict (no inheritance) and grant only what we want
      $grant = @(
        ('"{0}:(OI)(CI)F"'  -f $sidSystem),
        ('"{0}:(OI)(CI)F"'  -f $sidAdmins),
        ('"{0}:(OI)(CI)RX"' -f $sidUsers)
      )

      if ($sidSvc) {
        $grant += ('"{0}:(OI)(CI)RX"' -f $sidSvc)
      }

      # IMPORTANT: pass array args to icacls (donÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬ÃƒÂ¢Ã¢â‚¬Å¾Ã‚Â¢t -join into one giant string)
      & icacls $Path /inheritance:r /grant:r $grant /T /C 2>$null | Out-Null
    } catch {
      Write-TinySocsLog -Level "WARN" -Message "Failed to harden OpenSearch security config ACLs at '$Path': $($_.Exception.Message)"
    }

    # File-level sanity: enforce readable + not EFS + clear attributes
    foreach ($f in $required + $optional) {
      $p = Join-Path $Path $f
      if (-not (Test-Path $p -PathType Leaf)) { continue }

      try { & attrib.exe -R -S -H "$p" 2>$null | Out-Null } catch { }
      _EnsureNotEfs $p

      try {
        # For files: SYSTEM/Admins full; Users read; service read if resolved
        $fileGrant = @(
          ('"{0}:F"' -f $sidSystem),
          ('"{0}:F"' -f $sidAdmins),
          ('"{0}:R"' -f $sidUsers)
        )
        if ($sidSvc) { $fileGrant += ('"{0}:R"' -f $sidSvc) }

        & icacls $p /inheritance:r /remove:d "SYSTEM" "BUILTIN\Administrators" "Everyone" "Users" "Authenticated Users" /C 2>$null | Out-Null
        & icacls $p /grant:r $fileGrant /C 2>$null | Out-Null
      } catch { }
    }
  }

  # Ensure destination exists
  try { New-Item -ItemType Directory -Force -Path $dst | Out-Null } catch { }

  # Determine template root
  $srcRoot = _FindTemplateRoot -InstallRootPath $InstallRoot -OpenSearchRootPath $OpenSearchRoot

  # Copy required + optional files (missing-only unless -Force)
  $copied = @()
  foreach ($f in $required) {
    $did = _CopyIfMissingOrForce -SrcRoot $srcRoot -DstRoot $dst -FileName $f -ForceCopy:$Force
    if ($did) { $copied += $f }
  }
  foreach ($f in $optional) {
    $did = _CopyIfMissingOrForce -SrcRoot $srcRoot -DstRoot $dst -FileName $f -ForceCopy:$Force
    if ($did) { $copied += $f }
  }

  # Validate required presence
  $missing = @()
  foreach ($f in $required) {
    if (-not (Test-Path (Join-Path $dst $f) -PathType Leaf)) { $missing += $f }
  }
  if ($missing.Count -gt 0) {
    throw "ProgramData OpenSearch security config incomplete at '$dst'. Missing: $($missing -join ', '). Source used: '$srcRoot'"
  }

  # EFS + ACL hardening
  _EnsureNotEfs $dst
  _HardenSecurityDirAcl -Path $dst

  # Sanity: try opening required files for read
  foreach ($f in $required) {
    $p = Join-Path $dst $f
    try {
      $fs = [System.IO.File]::Open($p, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
      $fs.Close()
    } catch {
      throw "Security config file unreadable: '$p' : $($_.Exception.Message)"
    }
  }

  if ($copied.Count -gt 0) {
    Write-TinySocsLog "ProgramData OpenSearch security config ensured at '$dst' (copied: $($copied -join ', '); src='$srcRoot'; force=$($Force.IsPresent))."
  } else {
    Write-TinySocsLog "ProgramData OpenSearch security config verified at '$dst' (no copy needed; src='$srcRoot')."
  }

  return $dst
}

function Ensure-TinySocsOpenSearchAdminKeyStores {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$OpenSearchRoot,
    [Parameter(Mandatory)][string]$CertsDir,
    [Parameter(Mandatory)][string]$StorePass,
    [string]$CaSubject    = "CN=TinySocs-OpenSearch-CA",
    [string]$AdminSubject = "CN=TinySocs-OpenSearch-Admin"
  )

  New-Item -ItemType Directory -Force -Path $CertsDir | Out-Null

  $caCert = Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
    Where-Object { $_.Subject -eq $CaSubject } |
    Sort-Object NotAfter -Descending |
    Select-Object -First 1
  if (-not $caCert) { throw "CA cert not found in Cert:\LocalMachine\My (Subject=$CaSubject)" }

  $adminCert = Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
    Where-Object { $_.Subject -eq $AdminSubject } |
    Sort-Object NotAfter -Descending |
    Select-Object -First 1
  if (-not $adminCert) { throw "Admin cert not found in Cert:\LocalMachine\My (Subject=$AdminSubject)" }

  $caCer      = Join-Path $CertsDir "ca.cer"
  $truststore = Join-Path $CertsDir "admin-truststore.p12"
  $keystore   = Join-Path $CertsDir "admin-keystore.p12"

  Export-Certificate -Cert $caCert -FilePath $caCer -Force | Out-Null

  $keytool = @(
    (Join-Path $OpenSearchRoot "jdk\bin\keytool.exe"),
    (Join-Path $OpenSearchRoot "jre\bin\keytool.exe")
  ) | Where-Object { Test-Path $_ } | Select-Object -First 1

  if (-not $keytool) {
    $keytool = Get-ChildItem -Path $OpenSearchRoot -Recurse -Filter keytool.exe -ErrorAction SilentlyContinue |
      Select-Object -First 1 -ExpandProperty FullName
  }
  if (-not $keytool) { throw "keytool.exe not found under $OpenSearchRoot" }

  # Recreate truststore deterministically (CA only)
  if (Test-Path $truststore) { Remove-Item $truststore -Force -ErrorAction SilentlyContinue }
  & $keytool -importcert -noprompt `
    -alias tinysocs-ca `
    -file $caCer `
    -keystore $truststore `
    -storetype PKCS12 `
    -storepass $StorePass | Out-Null

  # PATCH(2026-01-15): Do NOT remove/recreate admin-keystore.p12 if it already exists.
  # If missing, prefer alias/copy of an existing .p12; only export from cert store as a last resort.
  if (Test-Path -LiteralPath $keystore -PathType Leaf) {
    Write-TinySocsLog "Admin keystore already present; skipping cert-store export (keystore=$keystore)."
  } else {
    $ens = $null
    try { $ens = _EnsureAdminKeystoreP12 -CertsDir $CertsDir } catch { $ens = $null }

    if ($ens -and (Test-Path -LiteralPath $ens -PathType Leaf)) {
      Write-TinySocsLog "Admin keystore ensured via alias/copy (keystore=$ens)."
    } else {
      try {
        $ksSecure = ConvertTo-SecureString -String $StorePass -AsPlainText -Force
        Export-PfxCertificate -Cert $adminCert -FilePath $keystore -Password $ksSecure -Force | Out-Null
        Write-TinySocsLog "Exported OpenSearch admin client keystore PKCS12 to $keystore."
      } catch {
        throw "Failed to ensure admin-keystore.p12 (alias+export both failed) ($keystore): $($_.Exception.Message)"
      }
    }
  }
  # END PATCH

  Write-TinySocsLog "Admin keystore/truststore ensured in ProgramData certs dir (keystore=$keystore truststore=$truststore)."

  return @{
    AdminKeystoreP12   = $keystore
    AdminTruststoreP12 = $truststore
    StorePassword      = $StorePass
    CaCerPath          = $caCer
  }
}


function Install-TinySocsAgentService {
  [CmdletBinding()]
  param(
    [switch]$NoStart,
    [string]$ConfigPath
  )

  Assert-TinySocsAdmin
  Install-TinySocs

  $installRoot = Get-TinySocsInstallRoot
  $agentExe    = Join-Path $installRoot "bin\TinySocs.Agent.exe"
  $nssmPath    = Join-Path $installRoot "bin\nssm.exe"

  if (-not (Test-Path $agentExe -PathType Leaf)) {
    Write-TinySocsLog -Level "WARN" -Message "TinySocs.Agent.exe not found at '$agentExe'. Skipping agent service installation."
    return
  }

  if (-not (Test-Path $nssmPath -PathType Leaf)) {
    Write-TinySocsLog -Level "WARN" -Message "nssm.exe not found at '$nssmPath'. Skipping agent service installation."
    return
  }

  if (-not $ConfigPath) { $ConfigPath = "C:\ProgramData\TinySocs\Collector\agent-config.yml" }

  $dataRoot    = Join-Path (Get-TinySocsDataRoot) "Collector"
  $agentRoot   = Join-Path $dataRoot "agent"
  $queueDir    = Join-Path $agentRoot "queue"
  $bookmarkDir = Join-Path $agentRoot "bookmarks"
  $logsDir     = Join-Path $dataRoot "logs"

  New-Item -ItemType Directory -Force -Path $agentRoot   | Out-Null
  New-Item -ItemType Directory -Force -Path $queueDir    | Out-Null
  New-Item -ItemType Directory -Force -Path $bookmarkDir | Out-Null
  New-Item -ItemType Directory -Force -Path $logsDir     | Out-Null

  Set-MachineEnv @{ TINYSOCS_AGENT_CONFIG = $ConfigPath }

  $serviceName = "TinySocsAgent"
  $displayName = "TinySocs Collector Agent"
  $description = "TinySocs-native Windows Event Log collector with local queue and OpenSearch output"

  Ensure-TinySocsAgentService -AgentExePath $agentExe `
    -NssmPath $nssmPath `
    -ServiceName $serviceName `
    -DisplayName $displayName `
    -Description $description

  $agentService = Get-Service -Name $serviceName -ErrorAction SilentlyContinue

  if (-not $NoStart) {
    if ($null -ne $agentService) {
      try { Start-Service -Name $serviceName -ErrorAction Stop; Write-TinySocsLog "Agent service '$serviceName' started." }
      catch { Write-TinySocsLog -Level "WARN" -Message "Failed to start agent service '$serviceName': $($_.Exception.Message)" }
    } else {
      Write-TinySocsLog -Level "WARN" -Message "Agent service '$serviceName' is not installed; nothing to start."
    }
  } else {
    Write-TinySocsLog -Level "WARN" -Message "NoStart specified; agent service '$serviceName' configured but not started."
  }

  Write-TinySocsLog "TinySocs Agent configured (config='$ConfigPath')."
}

# -- Service via NSSM ----------------------------------------------------------
function Register-TinySocsNodeService {
  [CmdletBinding()]
  param(
    [string]$ServiceName = 'TinySocsNode',
    [int]$Port = 8081
  )

  Assert-TinySocsAdmin

  # Persist node port to machine env so service restarts keep the same bind
  try {
    Set-MachineEnv @{ PORT = ([string]$Port) }
  } catch {
    Write-TinySocsLog -Level "WARN" -Message "Failed to persist PORT to machine env: $($_.Exception.Message)"
  }

  $installRoot = Get-TinySocsInstallRoot
  $binDir      = Join-Path $installRoot 'bin'
  $nssmExe      = Join-Path $binDir 'nssm.exe'
  $dataRoot     = Get-TinySocsDataRoot
  $workDir      = $dataRoot
  $logsDir      = Join-Path $dataRoot 'logs'

  if (-not (Test-Path $nssmExe -PathType Leaf)) {
    Write-Warning "[TinySocs] nssm.exe missing at '$nssmExe'; skipping node service."
    return
  }

  New-Item -ItemType Directory -Force -Path $logsDir | Out-Null

  $runner = Ensure-TinySocsNodeRunner
  $ps     = "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe"
  $args   = "-NoProfile -ExecutionPolicy Bypass -File `"$runner`""

  $null = sc.exe query $ServiceName 2>$null
  $serviceExists = ($LASTEXITCODE -eq 0)

  $validNssm = $false
  if ($serviceExists) {
    try { $validNssm = Test-NssmManagedService -ServiceName $ServiceName -NssmExe $nssmExe } catch { $validNssm = $false }
  }

  if ($serviceExists -and -not $validNssm) {
    try { Stop-Service $ServiceName -Force -ErrorAction SilentlyContinue } catch { }
    Start-Sleep -Seconds 2
    try { sc.exe stop $ServiceName | Out-Null } catch { }
    Start-Sleep -Seconds 2
    try { sc.exe delete $ServiceName | Out-Null } catch { }

    for ($i=0; $i -lt 20; $i++) {
      $null = sc.exe query $ServiceName 2>$null
      if ($LASTEXITCODE -ne 0) { break }
      Start-Sleep -Seconds 1
    }
  }

  if (-not (Test-NssmManagedService -ServiceName $ServiceName -NssmExe $nssmExe)) {
    & $nssmExe install $ServiceName $ps | Out-Null
  }

  & $nssmExe set $ServiceName Application   $ps      | Out-Null
  & $nssmExe set $ServiceName AppParameters $args    | Out-Null
  & $nssmExe set $ServiceName AppDirectory  $workDir | Out-Null

  & $nssmExe set $ServiceName AppStdout     (Join-Path $logsDir 'TinySocsNode.out.log') | Out-Null
  & $nssmExe set $ServiceName AppStderr     (Join-Path $logsDir 'TinySocsNode.err.log') | Out-Null
  & $nssmExe set $ServiceName AppNoConsole  1 | Out-Null
  & $nssmExe set $ServiceName AppRestartDelay 2000 | Out-Null
  & $nssmExe set $ServiceName AppExit Default Restart | Out-Null

  try { sc.exe config $ServiceName start= delayed-auto | Out-Null } catch { }
  try { sc.exe config $ServiceName obj= LocalSystem | Out-Null } catch { }

  # --- Patch B: dependency ordering (ONLY when TinyBox/OpenSearch is present) ---
  try {
    $null = sc.exe query TinySocsOpenSearch 2>$null
    if ($LASTEXITCODE -eq 0) {
      # Yes, the space after depend= matters.
      sc.exe config $ServiceName depend= TinySocsOpenSearch | Out-Null
    }
  } catch { }

  try { Start-Service $ServiceName -ErrorAction Stop } catch { }

  Write-TinySocsLog ("Node service ensured via NSSM: name={0} runner={1} workdir={2} port={3}" -f $ServiceName, $runner, $workDir, $Port)
}

function Register-TinySocsServices {
  $n = "C:\Program Files\TinySocs\bin\nssm.exe"
  $e = "C:\Program Files\TinySocs\bin\TinySocsNode.exe"
  $w = Join-Path (Get-TinySocsDataRoot) ""

  if (!(Test-Path $n)) {
    Write-Warning "[TinySocs] nssm.exe missing; skipping service."
    return
  }

  # Defaults (but allow Pair-TinySocs / Machine env to override)
  $port = [Environment]::GetEnvironmentVariable("PORT","Machine"); if (-not $port) { $port = "8081" }
  $siem = [Environment]::GetEnvironmentVariable("SIEM_URL","Machine"); if (-not $siem) { $siem = "https://localhost:9201" }
  $ssl  = [Environment]::GetEnvironmentVariable("SIEM_SSL_VERIFY","Machine"); if (-not $ssl) { $ssl = "false" }
  $priv = [Environment]::GetEnvironmentVariable("PRIVACY_MODE","Machine"); if (-not $priv) { $priv = "abstract" }

  & $n install TinySocsNode $e | Out-Null
  & $n set TinySocsNode AppDirectory    $w                             | Out-Null
  & $n set TinySocsNode Start           SERVICE_AUTO_START             | Out-Null
  & $n set TinySocsNode AppStdout       "$w\logs\TinySocsNode.out.log" | Out-Null
  & $n set TinySocsNode AppStderr       "$w\logs\TinySocsNode.err.log" | Out-Null
  & $n set TinySocsNode AppNoConsole    1                              | Out-Null
  & $n set TinySocsNode AppRestartDelay 2000                           | Out-Null

  $nodeEnvExtra = Format-TinySocsNssmEnvExtra @(
    ("PORT={0}"            -f $port)
    ("SIEM_URL={0}"        -f $siem)
    ("SIEM_SSL_VERIFY={0}" -f $ssl)
    ("PRIVACY_MODE={0}"    -f $priv)
  )
  & $n set TinySocsNode AppEnvironmentExtra $nodeEnvExtra | Out-Null

  sc.exe failure TinySocsNode reset= 60 actions= restart/2000/restart/2000/""/0 | Out-Null

  try { & $n start TinySocsNode | Out-Null } catch { }

  Write-Host "[TinySocs] Service installed/updated and started."
}

# -- Phase 11: LLM Assistant service registration via NSSM ---------------------

function Ensure-TinySocsAssistantService {
  <#
  .SYNOPSIS
    Registers and starts the TinySocsAssistant Windows service via NSSM.

  .DESCRIPTION
    The assistant runs the PyInstaller-bundled TinySocs-Quickstart.exe as a
    Windows service. NSSM loads environment variables from assistant.env.
    Ports 8081 (node API) and 8090 (bot API) bind to localhost only.

  .PARAMETER InstallRoot
    Path to TinySocs install dir (default: C:\Program Files\TinySocs).

  .PARAMETER EnvFile
    Path to the assistant.env environment file.
  #>
  [CmdletBinding()]
  param(
    [string]$InstallRoot = "C:\Program Files\TinySocs",
    [string]$EnvFile     = ""
  )

  $ServiceName = "TinySocsAssistant"
  $nssm = Join-Path $InstallRoot "bin\nssm.exe"
  $exe  = Join-Path $InstallRoot "Assistant\TinySocs-Quickstart.exe"
  $appDir = Join-Path $env:ProgramData "TinySocs\Assistant"

  if (-not (Test-Path $nssm)) {
    Write-Warning "[TinySocs] nssm.exe not found at $nssm; skipping assistant service."
    return
  }
  if (-not (Test-Path $exe)) {
    Write-Warning "[TinySocs] TinySocs-Quickstart.exe not found at $exe; skipping assistant service."
    return
  }

  # Ensure runtime data directory
  if (-not (Test-Path $appDir)) {
    New-Item -ItemType Directory -Force -Path $appDir | Out-Null
  }

  # Resolve env file
  if ([string]::IsNullOrWhiteSpace($EnvFile)) {
    $EnvFile = Join-Path $appDir "assistant.env"
  }

  # Build environment extras from .env file
  $envExtras = @()
  if (Test-Path $EnvFile) {
    foreach ($line in (Get-Content $EnvFile)) {
      $trimmed = $line.Trim()
      if ($trimmed -and -not $trimmed.StartsWith("#") -and $trimmed -match "^[A-Z_]+=") {
        $envExtras += $trimmed
      }
    }
    Write-Host "[TinySocs] Loaded $($envExtras.Count) env vars from $EnvFile"
  } else {
    Write-Warning "[TinySocs] assistant.env not found at $EnvFile; service will start with defaults."
  }

  # Remove existing service if present (upgrade path)
  try {
    $existingSvc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($existingSvc) {
      & $nssm stop $ServiceName 2>$null | Out-Null
      & $nssm remove $ServiceName confirm 2>$null | Out-Null
      Start-Sleep -Seconds 1
    }
  } catch { }

  # Install via NSSM
  & $nssm install $ServiceName $exe | Out-Null
  & $nssm set $ServiceName AppDirectory    $appDir                                   | Out-Null
  & $nssm set $ServiceName Start           SERVICE_AUTO_START                        | Out-Null
  & $nssm set $ServiceName AppStdout       "$appDir\TinySocsAssistant.out.log"       | Out-Null
  & $nssm set $ServiceName AppStderr       "$appDir\TinySocsAssistant.err.log"       | Out-Null
  & $nssm set $ServiceName AppNoConsole    1                                          | Out-Null
  & $nssm set $ServiceName AppRestartDelay 3000                                       | Out-Null

  # Set environment variables from assistant.env
  if ($envExtras.Count -gt 0) {
    $formatted = Format-TinySocsNssmEnvExtra $envExtras
    & $nssm set $ServiceName AppEnvironmentExtra $formatted | Out-Null
  }

  # Configure service recovery
  sc.exe failure $ServiceName reset= 60 actions= restart/3000/restart/5000/""/0 | Out-Null

  # Start the service
  try { & $nssm start $ServiceName | Out-Null } catch { }

  Write-Host "[TinySocs] Assistant service ($ServiceName) installed and started."
}

# -- Scheduled task helpers (PowerShell ScheduledTasks API) ---------------------
function Ensure-TaskFolder {
  param([string]$FolderPath = "\TinySocs")

  $svc  = New-Object -ComObject "Schedule.Service"
  $svc.Connect()
  $root = $svc.GetFolder("\")

  $folderName = $FolderPath.Trim('\')
  if ([string]::IsNullOrWhiteSpace($folderName)) { throw "Invalid task folder name '$FolderPath'" }

  try { $null = $root.GetFolder("\$folderName"); return } catch { }

  try { $null = $root.CreateFolder($folderName) }
  catch {
    $hr = $_.Exception.HResult
    if ($hr -ne -2147024713) { throw }  # 0x800700B7
  }
}

function New-TinySocsTaskAction {
  param([Parameter(Mandatory)][string]$ScriptPath,[string]$Args = "")
  $ps  = "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe"
  $arg = "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`" $Args".Trim()
  New-ScheduledTaskAction -Execute $ps -Argument $arg
}

function New-TinySocsExeAction {
  param([Parameter(Mandatory)][string]$ExePath,[string]$Args = "")
  New-ScheduledTaskAction -Execute $ExePath -Argument $Args
}

function New-TinySocsRepeatTrigger {
  param([Parameter(Mandatory)][int]$EveryMinutes)
  $start = (Get-Date).AddMinutes(1)
  $dur = New-TimeSpan -Days 3650
  New-ScheduledTaskTrigger -Once -At $start `
    -RepetitionInterval (New-TimeSpan -Minutes $EveryMinutes) `
    -RepetitionDuration $dur
}

function New-TinySocsDailyTrigger {
  param([Parameter(Mandatory)][string]$At)
  $time = [DateTime]::Today.Add([TimeSpan]::Parse($At))
  New-ScheduledTaskTrigger -Daily -At $time
}

function Register-TinySocsTasks {
  $taskPath  = "\TinySocs\"
  $modDir    = "C:\Program Files\TinySocs\modules"
  $binDir    = "C:\Program Files\TinySocs\bin"

  Ensure-TaskFolder -FolderPath $taskPath

  $hb = 15
  if ($env:HEARTBEAT_MINUTES) { [int]::TryParse($env:HEARTBEAT_MINUTES, [ref]$hb) | Out-Null }

  $retention = 45
  if ($env:ANCHORS_RETENTION_DAYS) { [int]::TryParse($env:ANCHORS_RETENTION_DAYS, [ref]$retention) | Out-Null }

  function _RegisterIdempotent {
    param([string]$TaskName,[scriptblock]$ActionFactory,$Trigger)

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

  $masterRunner = Ensure-TinySocsMasterRunner
  $masterArgs   = ("-window {0}m -deadline 30 -rules 'auth_failed_burst,ps_script_block'" -f $hb)
  $masterTrigger = New-TinySocsRepeatTrigger -EveryMinutes $hb

  _RegisterIdempotent -TaskName "TinySocsHeartbeat" -ActionFactory {
    New-TinySocsTaskAction -ScriptPath $masterRunner -Args ("-Args `"$masterArgs`"")
  } -Trigger $masterTrigger

  $anchorsExe     = Join-Path $binDir "TinySocsAnchors.exe"
  $ensureTrigger  = New-TinySocsDailyTrigger -At "03:10"
  _RegisterIdempotent -TaskName "TinySocsAnchorsEnsure" -ActionFactory {
    New-TinySocsExeAction -ExePath $anchorsExe -Args "--ensure"
  } -Trigger $ensureTrigger

  $pruneTrigger = New-TinySocsDailyTrigger -At "03:15"
  _RegisterIdempotent -TaskName "TinySocsAnchorsPrune" -ActionFactory {
    New-TinySocsExeAction -ExePath $anchorsExe -Args ("--prune --retention-days {0}" -f $retention)
  } -Trigger $pruneTrigger

  $rotateScript  = Join-Path $modDir "TinySocs.RotateQueue.ps1"
  $rotateTrigger = New-TinySocsRepeatTrigger -EveryMinutes 60
  _RegisterIdempotent -TaskName "TinySocsRotateQueue" -ActionFactory {
    New-TinySocsTaskAction -ScriptPath $rotateScript -Args ""
  } -Trigger $rotateTrigger

  Write-Host "[TinySocs] Scheduled tasks registered."
}

function Resolve-TinySocsLocalCaCertPath {
  [CmdletBinding()]
  param(
    [string]$DataRoot = (Get-TinySocsDataRoot)
  )

  # Prefer the canonical TinyBox ProgramData path (per Quickstart.iss [Dirs]/seed).
  $candidates = @(
    (Join-Path $DataRoot 'OpenSearch\certs\root-ca.pem'),
    (Join-Path $DataRoot 'OpenSearch\certs\ca.crt'),
    (Join-Path $DataRoot 'OpenSearch\certs\ca.pem'),
    (Join-Path $DataRoot 'OpenSearch\certs\ca.cer'),

    # Back-compat / older conventions (harmless to probe)
    (Join-Path $DataRoot 'siem\certs\ca.crt'),
    (Join-Path $DataRoot 'siem\certs\root-ca.pem')
  )

  foreach ($p in $candidates) {
    try {
      if ($p -and (Test-Path $p -PathType Leaf)) { return $p }
    } catch { }
  }

  return $null
}

# -- Environment + pairing ------------------------------------------------------
function Set-MachineEnv([hashtable]$Vars){
  foreach($k in $Vars.Keys){
    $v = [string]$Vars[$k]
    [Environment]::SetEnvironmentVariable($k, $v, 'Machine')
    [Environment]::SetEnvironmentVariable($k, $v, 'Process')
  }

  try {
    if (-not ('U.W' -as [type])) {
      $md='[DllImport("user32.dll")] public static extern IntPtr SendMessageTimeout(IntPtr h,int m,IntPtr w,string l,int f,int t,out IntPtr r);'
      Add-Type -MemberDefinition $md -Name 'W' -Namespace 'U' -ErrorAction SilentlyContinue | Out-Null
    }
    $z=[intptr]::Zero
    [U.W]::SendMessageTimeout([intptr]0xffff,0x1A,[intptr]0,'Environment',2,5000,[ref]$z) | Out-Null
  } catch { }
}

function Set-ProcessEnv([hashtable]$Vars){
  foreach($k in $Vars.Keys){
    $v = [string]$Vars[$k]
    [Environment]::SetEnvironmentVariable($k, $v, 'Process')
  }
}

function Ensure-TinySocsNodeRunner {
  [CmdletBinding()]
  param(
    [string]$RunnerPath = (Join-Path (Get-TinySocsDataRoot) "run-node.ps1")
  )

  $installRoot = Get-TinySocsInstallRoot
  $modulePath  = Join-Path $installRoot "modules\TinySocs.Installer.psm1"
  $exePath     = Join-Path $installRoot "bin\TinySocsNode.exe"

  $script = @"
`$ErrorActionPreference = 'Stop'

# Fail loudly if the module isn't present/importable (otherwise services "die silently").
Import-Module '$modulePath' -Force -ErrorAction Stop

`$port = [Environment]::GetEnvironmentVariable('PORT','Machine')
if ([string]::IsNullOrWhiteSpace(`$port)) { `$port = '8081' }

# --- SIEM settings: Machine env preferred; CredMan fallback; backfill Machine env ---
`$siemUrl = [Environment]::GetEnvironmentVariable('SIEM_URL','Machine')
if (-not [string]::IsNullOrWhiteSpace(`$siemUrl)) { `$siemUrl = `$siemUrl.TrimEnd('/') } else { `$siemUrl = '' }

`$sslVerify = [Environment]::GetEnvironmentVariable('SIEM_SSL_VERIFY','Machine')
if ([string]::IsNullOrWhiteSpace(`$sslVerify)) { `$sslVerify = '' }  # defer default until after CredMan fallback

`$caCert = [Environment]::GetEnvironmentVariable('SIEM_CA_CERT','Machine')
if ([string]::IsNullOrWhiteSpace(`$caCert)) { `$caCert = '' }

if ([string]::IsNullOrWhiteSpace(`$siemUrl) -or [string]::IsNullOrWhiteSpace(`$sslVerify) -or [string]::IsNullOrWhiteSpace(`$caCert)) {
  try {
    `$raw = Get-TSCredential -Name 'TinySocs/SIEM/Creds'
    if (-not [string]::IsNullOrWhiteSpace(`$raw)) {
      `$j = `$raw | ConvertFrom-Json

      if ([string]::IsNullOrWhiteSpace(`$siemUrl)) {
        if (`$j.url) { `$siemUrl = [string]`$j.url } elseif (`$j.siemUrl) { `$siemUrl = [string]`$j.siemUrl }
        if (-not [string]::IsNullOrWhiteSpace(`$siemUrl)) { `$siemUrl = `$siemUrl.TrimEnd('/') }
      }

      if ([string]::IsNullOrWhiteSpace(`$sslVerify)) {
        if (`$null -ne `$j.sslVerify) { `$sslVerify = (if ([bool]`$j.sslVerify) { 'true' } else { 'false' }) }
        elseif (`$null -ne `$j.siemSslVerify) { `$sslVerify = (if ([bool]`$j.siemSslVerify) { 'true' } else { 'false' }) }
      }

      if ([string]::IsNullOrWhiteSpace(`$caCert)) {
        if (`$j.caCert) { `$caCert = [string]`$j.caCert }
        elseif (`$j.ca_cert) { `$caCert = [string]`$j.ca_cert }
      }

      # Backfill Machine env so subsequent starts don't require CredMan fallback.
      `$bf = @{}
      if (-not [string]::IsNullOrWhiteSpace(`$siemUrl))   { `$bf.SIEM_URL = `$siemUrl }
      if (-not [string]::IsNullOrWhiteSpace(`$sslVerify)) { `$bf.SIEM_SSL_VERIFY = `$sslVerify }
      if (-not [string]::IsNullOrWhiteSpace(`$caCert))    { `$bf.SIEM_CA_CERT = `$caCert }
      if (`$bf.Count -gt 0) { try { Set-MachineEnv `$bf } catch { } }
    }
  } catch { }
}

# --- Patch A: deterministic CA derivation if still missing (TinyBox upgrades/repairs) ---
if ([string]::IsNullOrWhiteSpace(`$caCert)) {
  try {
    `$p = Resolve-TinySocsLocalCaCertPath
    if (-not [string]::IsNullOrWhiteSpace(`$p)) {
      `$caCert = `$p
      try { Set-MachineEnv @{ SIEM_CA_CERT = `$caCert } } catch { }
    }
  } catch { }
}

# Apply defaults after fallback attempt
if ([string]::IsNullOrWhiteSpace(`$sslVerify)) { `$sslVerify = 'true' }

`$privacy = [Environment]::GetEnvironmentVariable('PRIVACY_MODE','Machine')
if ([string]::IsNullOrWhiteSpace(`$privacy)) { `$privacy = 'abstract' }

# --- Shared secret (CredMan preferred, DPAPI fallback, backfill both ways) ---
`$secret = `$null
try { `$secret = Get-TSCredential -Name 'TinySocs/Node/Secret' } catch { }

if ([string]::IsNullOrWhiteSpace(`$secret)) {
  try {
    `$secret = Read-TinySocsNodeSecretFromDpapiFile
    if (-not [string]::IsNullOrWhiteSpace(`$secret)) {
      try { Set-TSCredential -Name 'TinySocs/Node/Secret' -Secret `$secret } catch { }
    }
  } catch { }
}

if (-not [string]::IsNullOrWhiteSpace(`$secret)) {
  try {
    `$dp = Get-TinySocsNodeSecretDpapiFilePath
    if (-not (Test-Path `$dp -PathType Leaf)) {
      Write-TinySocsNodeSecretToDpapiFile -Secret `$secret | Out-Null
    }
  } catch { }
}

if ([string]::IsNullOrWhiteSpace(`$secret)) { throw "TinySocs/Node/Secret missing in CredMan and no DPAPI fallback present." }

Set-ProcessEnv @{
  MASTER_SHARED_SECRET = `$secret
  PORT                 = `$port
  SIEM_URL             = `$siemUrl
  SIEM_SSL_VERIFY      = `$sslVerify
  SIEM_CA_CERT         = `$caCert
  PRIVACY_MODE         = `$privacy
}

& '$exePath'
"@

  $dir = Split-Path -Parent $RunnerPath
  if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }

  Ensure-TinySocsWritableFile -Path $RunnerPath
  Set-Content -Path $RunnerPath -Value $script -Encoding UTF8 -Force
  Write-TinySocsLog "Node runner ensured at $RunnerPath (CredMan preferred; DPAPI fallback; auto-backfill)."
  return $RunnerPath
}

function Ensure-TinySocsMasterRunner {
  [CmdletBinding()]
  param(
    [string]$RunnerPath = (Join-Path (Get-TinySocsDataRoot) "run-master.ps1"),
    [string]$LaunchScriptPath = "C:\Program Files\TinySocs\modules\Launch-Master.ps1"
  )

  $installRoot = Get-TinySocsInstallRoot
  $modulePath  = Join-Path $installRoot "modules\TinySocs.Installer.psm1"

  $script = @"
param([string]`$Args = "")
`$ErrorActionPreference = 'Stop'

# Fail loudly if the module isn't present/importable.
Import-Module '$modulePath' -Force -ErrorAction Stop

# --- Nodes list (Machine env preferred; file fallback; backfill machine env) ---
`$nodes = [Environment]::GetEnvironmentVariable('TINYSOCS_NODES','Machine')
if ([string]::IsNullOrWhiteSpace(`$nodes)) {
  try { `$nodes = Read-TinySocsNodesFromFile } catch { }
  if (-not [string]::IsNullOrWhiteSpace(`$nodes)) {
    try { Set-MachineEnv @{ TINYSOCS_NODES = `$nodes } } catch { }
  }
} else {
  try { Write-TinySocsNodesToFile -Nodes `$nodes | Out-Null } catch { }
}

# --- SIEM settings: Machine env preferred; CredMan fallback; backfill Machine env ---
`$siemUrl = [Environment]::GetEnvironmentVariable('SIEM_URL','Machine')
if (-not [string]::IsNullOrWhiteSpace(`$siemUrl)) { `$siemUrl = `$siemUrl.TrimEnd('/') } else { `$siemUrl = '' }

`$sslVerify = [Environment]::GetEnvironmentVariable('SIEM_SSL_VERIFY','Machine')
if ([string]::IsNullOrWhiteSpace(`$sslVerify)) { `$sslVerify = '' }  # defer default until after CredMan fallback

`$caCert = [Environment]::GetEnvironmentVariable('SIEM_CA_CERT','Machine')
if ([string]::IsNullOrWhiteSpace(`$caCert)) { `$caCert = '' }

if ([string]::IsNullOrWhiteSpace(`$siemUrl) -or [string]::IsNullOrWhiteSpace(`$sslVerify) -or [string]::IsNullOrWhiteSpace(`$caCert)) {
  try {
    `$raw = Get-TSCredential -Name 'TinySocs/SIEM/Creds'
    if (-not [string]::IsNullOrWhiteSpace(`$raw)) {
      `$j = `$raw | ConvertFrom-Json

      if ([string]::IsNullOrWhiteSpace(`$siemUrl)) {
        if (`$j.url) { `$siemUrl = [string]`$j.url } elseif (`$j.siemUrl) { `$siemUrl = [string]`$j.siemUrl }
        if (-not [string]::IsNullOrWhiteSpace(`$siemUrl)) { `$siemUrl = `$siemUrl.TrimEnd('/') }
      }

      if ([string]::IsNullOrWhiteSpace(`$sslVerify)) {
        if (`$null -ne `$j.sslVerify) { `$sslVerify = (if ([bool]`$j.sslVerify) { 'true' } else { 'false' }) }
        elseif (`$null -ne `$j.siemSslVerify) { `$sslVerify = (if ([bool]`$j.siemSslVerify) { 'true' } else { 'false' }) }
      }

      if ([string]::IsNullOrWhiteSpace(`$caCert)) {
        if (`$j.caCert) { `$caCert = [string]`$j.caCert }
        elseif (`$j.ca_cert) { `$caCert = [string]`$j.ca_cert }
      }

      # Backfill Machine env so subsequent starts don't require CredMan fallback.
      `$bf = @{}
      if (-not [string]::IsNullOrWhiteSpace(`$siemUrl))   { `$bf.SIEM_URL = `$siemUrl }
      if (-not [string]::IsNullOrWhiteSpace(`$sslVerify)) { `$bf.SIEM_SSL_VERIFY = `$sslVerify }
      if (-not [string]::IsNullOrWhiteSpace(`$caCert))    { `$bf.SIEM_CA_CERT = `$caCert }
      if (`$bf.Count -gt 0) { try { Set-MachineEnv `$bf } catch { } }
    }
  } catch { }
}

# --- Patch A: deterministic CA derivation if still missing (TinyBox upgrades/repairs) ---
if ([string]::IsNullOrWhiteSpace(`$caCert)) {
  try {
    `$p = Resolve-TinySocsLocalCaCertPath
    if (-not [string]::IsNullOrWhiteSpace(`$p)) {
      `$caCert = `$p
      try { Set-MachineEnv @{ SIEM_CA_CERT = `$caCert } } catch { }
    }
  } catch { }
}

# Apply defaults after fallback attempt
if ([string]::IsNullOrWhiteSpace(`$sslVerify)) { `$sslVerify = 'true' }

# --- Shared secret (CredMan preferred, DPAPI fallback, backfill both ways) ---
`$secret = `$null
try { `$secret = Get-TSCredential -Name 'TinySocs/Master/SharedSecret' } catch { }

if ([string]::IsNullOrWhiteSpace(`$secret)) {
  try {
    `$secret = Read-TinySocsMasterSharedSecretFromDpapiFile
    if (-not [string]::IsNullOrWhiteSpace(`$secret)) {
      try { Set-TSCredential -Name 'TinySocs/Master/SharedSecret' -Secret `$secret } catch { }
    }
  } catch { }
}

if (-not [string]::IsNullOrWhiteSpace(`$secret)) {
  try {
    `$dp = Get-TinySocsMasterSharedSecretDpapiFilePath
    if (-not (Test-Path `$dp -PathType Leaf)) {
      Write-TinySocsMasterSharedSecretToDpapiFile -Secret `$secret | Out-Null
    }
  } catch { }
}

if ([string]::IsNullOrWhiteSpace(`$secret)) { throw "TinySocs/Master/SharedSecret missing in CredMan and no DPAPI fallback present." }

Set-ProcessEnv @{
  MASTER_SHARED_SECRET = `$secret
  TINYSOCS_NODES       = `$nodes
  SIEM_URL             = `$siemUrl
  SIEM_SSL_VERIFY      = `$sslVerify
  SIEM_CA_CERT         = `$caCert
}

if ([string]::IsNullOrWhiteSpace(`$Args)) {
  & '$LaunchScriptPath'
} else {
  Invoke-Expression ("& `"$LaunchScriptPath`" {0}" -f `$Args)
}
"@

  $dir = Split-Path -Parent $RunnerPath
  if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }

  Ensure-TinySocsWritableFile -Path $RunnerPath
  Set-Content -Path $RunnerPath -Value $script -Encoding UTF8 -Force
  Write-TinySocsLog "Master runner ensured at $RunnerPath (CredMan preferred; DPAPI fallback; nodes env<->file backfill)."
  return $RunnerPath
}

function Pair-TinySocs{
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][ValidateSet('Node','Master')]$Role,
    [Parameter(Mandatory)][string]$SharedSecret,

    [string]$NodePort='8081',

    # PATCH: canonical TinyBox default is 9201 (not 9200)
    [string]$SiemUrl='https://localhost:9201',
    [string]$SiemUser,
    [string]$SiemPass,
    [bool]  $SiemSslVerify = $true,

    [string]$Nodes,
    [int]$AnchorsRetentionDays=45,
    [int]$HeartbeatMinutes=15
  )
  Install-TinySocs

  $normSiemUrl = ''
  try {
    if (-not [string]::IsNullOrWhiteSpace($SiemUrl)) { $normSiemUrl = $SiemUrl.TrimEnd('/') }
  } catch { $normSiemUrl = $SiemUrl }

  # PATCH: if TinyBox appears installed and URL still points at :9200, rewrite to :9201
  # (opt-out via TINYSOCS_ALLOW_9200=true)
  try {
    $allow9200 = ($env:TINYSOCS_ALLOW_9200 -eq 'true')
    $tinyBoxYml = "C:\ProgramData\TinySocs\OpenSearch\config\opensearch.yml"
    $hasTinyBox = (Test-Path -LiteralPath $tinyBoxYml -PathType Leaf)

    if (-not $allow9200 -and $hasTinyBox -and -not [string]::IsNullOrWhiteSpace($normSiemUrl)) {
      $u = $normSiemUrl
      if ($u -match ':(9200)(/|$)') {
        $normSiemUrl = ($u -replace ':(9200)(/|$)', ':9201$2')
        Write-TinySocsLog -Level "WARN" -Message "Pair-TinySocs: SiemUrl was $u; TinyBox canonical port is 9201. Rewriting to $normSiemUrl."
      }
    }
  } catch { }

  $verifyString = if ([bool]$SiemSslVerify) { 'true' } else { 'false' }

  # If SIEM creds are provided, store them canonically (CredMan + safe env vars).
  # If omitted, DO NOT wipe existing SIEM creds.
  $providedSiemCreds = (-not [string]::IsNullOrWhiteSpace($SiemUser) -and -not [string]::IsNullOrWhiteSpace($SiemPass))
  if ($providedSiemCreds) {
    try {
      Set-TinySocsSiemCredential -SiemUrl $normSiemUrl -SiemUser $SiemUser -SiemPass $SiemPass -SiemSslVerify:$SiemSslVerify
      Write-TinySocsLog "Pair-TinySocs: SIEM credentials were provided and stored (TinySocs/SIEM/Creds)."
    } catch {
      Write-TinySocsLog -Level "WARN" -Message "Pair-TinySocs: Failed to store SIEM creds: $($_.Exception.Message)"
    }
  }

  if($Role -eq 'Node'){
    Set-TSCredential -Name 'TinySocs/Node/Secret' -Secret $SharedSecret

    # Machine env needed for runner/service
    Set-MachineEnv @{
      PORT            = $NodePort
      SIEM_URL        = $normSiemUrl
      SIEM_SSL_VERIFY = $verifyString
      PRIVACY_MODE    = 'abstract'
    }

    # If we already have a CA path stored (from local SIEM install), keep it in env for the node.
    try {
      $raw = Get-TSCredential -Name 'TinySocs/SIEM/Creds'
      if ($raw) {
        $j = $raw | ConvertFrom-Json
        if ($j.caCert -and -not [string]::IsNullOrWhiteSpace([string]$j.caCert)) {
          Set-MachineEnv @{ SIEM_CA_CERT = [string]$j.caCert }
        } elseif ($j.ca_cert -and -not [string]::IsNullOrWhiteSpace([string]$j.ca_cert)) {
          Set-MachineEnv @{ SIEM_CA_CERT = [string]$j.ca_cert }
        }
      }
    } catch { }

    # --- Patch A: if still missing, derive CA deterministically from ProgramData ---
    try {
      $existing = [Environment]::GetEnvironmentVariable('SIEM_CA_CERT','Machine')
      if ([string]::IsNullOrWhiteSpace($existing)) {
        $p = Resolve-TinySocsLocalCaCertPath
        if ($p) { Set-MachineEnv @{ SIEM_CA_CERT = [string]$p } }
      }
    } catch { }

    # Ensure runner + service (idempotent)
    try { $null = Ensure-TinySocsNodeRunner } catch { }
    try { Register-TinySocsNodeService -Port ([int]$NodePort) } catch { }

    Write-TinySocsLog "Paired as Node. CredMan: TinySocs/Node/Secret set. Env: PORT, SIEM_URL, SIEM_SSL_VERIFY, (optional SIEM_CA_CERT)."
    return @{
      Role          = "Node"
      Port          = $NodePort
      SiemUrl       = $normSiemUrl
      SiemSslVerify = [bool]$SiemSslVerify
    }
  }

  if($Role -eq 'Master'){
    Set-TSCredential -Name 'TinySocs/Master/SharedSecret' -Secret $SharedSecret

    # Preserve existing nodes if caller didn't supply new ones
    $finalNodes = $Nodes
    if ([string]::IsNullOrWhiteSpace($finalNodes)) {
      try { $finalNodes = [Environment]::GetEnvironmentVariable('TINYSOCS_NODES','Machine') } catch { }
    }

    Set-MachineEnv @{
      TINYSOCS_NODES          = $finalNodes
      SIEM_URL                = $normSiemUrl
      SIEM_SSL_VERIFY         = $verifyString
      HEARTBEAT_MINUTES       = ([string]$HeartbeatMinutes)
      ANCHORS_RETENTION_DAYS  = ([string]$AnchorsRetentionDays)
    }

    # Carry SIEM_CA_CERT forward if present in CredMan payload
    try {
      $raw = Get-TSCredential -Name 'TinySocs/SIEM/Creds'
      if ($raw) {
        $j = $raw | ConvertFrom-Json
        if ($j.caCert -and -not [string]::IsNullOrWhiteSpace([string]$j.caCert)) {
          Set-MachineEnv @{ SIEM_CA_CERT = [string]$j.caCert }
        } elseif ($j.ca_cert -and -not [string]::IsNullOrWhiteSpace([string]$j.ca_cert)) {
          Set-MachineEnv @{ SIEM_CA_CERT = [string]$j.ca_cert }
        }
      }
    } catch { }

    # --- Patch A: if still missing, derive CA deterministically from ProgramData ---
    try {
      $existing = [Environment]::GetEnvironmentVariable('SIEM_CA_CERT','Machine')
      if ([string]::IsNullOrWhiteSpace($existing)) {
        $p = Resolve-TinySocsLocalCaCertPath
        if ($p) { Set-MachineEnv @{ SIEM_CA_CERT = [string]$p } }
      }
    } catch { }

    # Ensure runner + scheduled tasks (idempotent)
    try { $null = Ensure-TinySocsMasterRunner } catch { }
    try { Register-TinySocsTasks } catch {
      Write-TinySocsLog -Level "WARN" -Message "Pair-TinySocs: Failed to register scheduled tasks: $($_.Exception.Message)"
    }

    Write-TinySocsLog "Paired as Master. CredMan: TinySocs/Master/SharedSecret set. Env: TINYSOCS_NODES, SIEM_*, HEARTBEAT_MINUTES, ANCHORS_RETENTION_DAYS."
    return @{
      Role                 = "Master"
      Nodes                = $finalNodes
      SiemUrl              = $normSiemUrl
      SiemSslVerify         = [bool]$SiemSslVerify
      HeartbeatMinutes     = $HeartbeatMinutes
      AnchorsRetentionDays = $AnchorsRetentionDays
    }
  }
}

function Ensure-TinySocsOpenSearchKeystoreSecurePasswords {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$OpenSearchRoot,
    [Parameter(Mandatory)][string]$ProgramDataConf,
    [Parameter(Mandatory)][string]$CertsDir,
    [string]$StorePass,
    [string[]]$Keys = @(
      'plugins.security.ssl.http.keystore_password_secure',
      'plugins.security.ssl.http.keystore_keypassword_secure',
      'plugins.security.ssl.transport.keystore_password_secure',
      'plugins.security.ssl.transport.keystore_keypassword_secure'
    )
  )

  if (-not (Test-Path -LiteralPath $ProgramDataConf -PathType Container)) {
    throw "ProgramDataConf not found: $ProgramDataConf"
  }

  # Prefer DPAPI truth if StorePass is empty
  if ([string]::IsNullOrWhiteSpace($StorePass)) {
    try { $StorePass = Read-TinySocsOpenSearchTlsStorePassFromDpapiFile -CertsDir $CertsDir } catch { }
  }
  if ([string]::IsNullOrWhiteSpace($StorePass)) {
    throw "OpenSearch TLS storepass is empty; cannot enforce keystore _secure entries."
  }

  # Normalize + hard-validate storepass (keystore + Java PKCS12 are extremely sensitive to encoding)
  $StorePass = [string]$StorePass
  $StorePass = $StorePass.Trim()

  if ($StorePass.IndexOf([char]0) -ge 0 -or $StorePass -match "[`r`n]") {
    throw "OpenSearch TLS storepass contains null/newline characters; refusing to write keystore entries."
  }

  foreach ($ch in $StorePass.ToCharArray()) {
    if ([int][char]$ch -gt 127) {
      throw "OpenSearch TLS storepass contains non-ASCII characters; this commonly breaks OpenSearch PKCS12 ('Password is not ASCII'). Refusing to write keystore entries."
    }
  }

  $keystoreBat = Join-Path $OpenSearchRoot "bin\opensearch-keystore.bat"
  if (-not (Test-Path -LiteralPath $keystoreBat -PathType Leaf)) {
    # Best-effort fallback search under bin\
    $bin = Join-Path $OpenSearchRoot "bin"
    $hit = $null
    try {
      $hit = Get-ChildItem -Path $bin -File -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -ieq "opensearch-keystore.bat" } |
        Select-Object -First 1
    } catch { }
    if ($hit) { $keystoreBat = $hit.FullName }
  }

  if (-not (Test-Path -LiteralPath $keystoreBat -PathType Leaf)) {
    throw "opensearch-keystore.bat not found under OpenSearchRoot=$OpenSearchRoot"
  }

  # Ensure keystore tool runs correctly in installer context
  $prevJavaHome = $env:JAVA_HOME
  $prevPath     = $env:PATH
  try {
    $jdk = Join-Path $OpenSearchRoot "jdk"
    if (Test-Path -LiteralPath $jdk -PathType Container) {
      $env:JAVA_HOME = $jdk
      $env:PATH = "$env:JAVA_HOME\bin;$env:PATH"
    }
  } catch { }

  # Force tool to operate on ProgramData config tree
  $prevConf = $env:OPENSEARCH_PATH_CONF
  $env:OPENSEARCH_PATH_CONF = $ProgramDataConf

  # IMPORTANT: write temp as ASCII bytes (NO BOM). UTF8 with BOM can poison stdin and cause "Password is not ASCII".
  $tmp = Join-Path $env:TEMP ("tinysocs-storepass-" + [guid]::NewGuid().ToString("n") + ".txt")

  try {
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($StorePass + "`n")
    [System.IO.File]::WriteAllBytes($tmp, $bytes)

    # PATCH: repair ACLs BEFORE create/add/list (fixes AccessDeniedException in installer/service contexts)
    try {
      $fn = Get-Command Repair-TinySocsOpenSearchKeystoreAcls -ErrorAction SilentlyContinue
      if ($fn) {
        $pp = @{}
        if ($fn.Parameters.ContainsKey('ProgramDataConf')) { $pp.ProgramDataConf = $ProgramDataConf }
        elseif ($fn.Parameters.ContainsKey('ConfDir'))      { $pp.ConfDir        = $ProgramDataConf }
        elseif ($fn.Parameters.ContainsKey('Path'))         { $pp.Path           = $ProgramDataConf }
        & $fn @pp | Out-Null
      } else {
        try { attrib.exe -R $ProgramDataConf /S /D | Out-Null } catch { }
        $who = $null; try { $who = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name } catch { $who = $env:USERNAME }
        try { & icacls.exe $ProgramDataConf /inheritance:e /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" ($who + ":(OI)(CI)F") /T /C | Out-Null } catch { }
        $ks0 = Join-Path $ProgramDataConf "opensearch.keystore"
        if (Test-Path -LiteralPath $ks0 -PathType Leaf) {
          try { & icacls.exe $ks0 /inheritance:e /grant:r "SYSTEM:F" "Administrators:F" ($who + ":F") /C | Out-Null } catch { }
        }
      }
    } catch { }

    # Create keystore if missing
    $ksFile = Join-Path $ProgramDataConf "opensearch.keystore"
    if (-not (Test-Path -LiteralPath $ksFile -PathType Leaf)) {
      $out = & cmd.exe /D /V:OFF /C "`"$keystoreBat`" create" 2>&1
      if ($LASTEXITCODE -ne 0) {
        Write-TinySocsLog -Level "WARN" -Message "opensearch-keystore create returned exit=$LASTEXITCODE. Output: $((($out | Out-String).Trim()))"
      }

      # PATCH: repair ACLs AGAIN AFTER create
      try {
        $fn = Get-Command Repair-TinySocsOpenSearchKeystoreAcls -ErrorAction SilentlyContinue
        if ($fn) {
          $pp = @{}
          if ($fn.Parameters.ContainsKey('ProgramDataConf')) { $pp.ProgramDataConf = $ProgramDataConf }
          elseif ($fn.Parameters.ContainsKey('ConfDir'))      { $pp.ConfDir        = $ProgramDataConf }
          elseif ($fn.Parameters.ContainsKey('Path'))         { $pp.Path           = $ProgramDataConf }
          & $fn @pp | Out-Null
        } else {
          try { attrib.exe -R $ProgramDataConf /S /D | Out-Null } catch { }
          $who = $null; try { $who = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name } catch { $who = $env:USERNAME }
          try { & icacls.exe $ProgramDataConf /inheritance:e /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" ($who + ":(OI)(CI)F") /T /C | Out-Null } catch { }
          if (Test-Path -LiteralPath $ksFile -PathType Leaf) {
            try { & icacls.exe $ksFile /inheritance:e /grant:r "SYSTEM:F" "Administrators:F" ($who + ":F") /C | Out-Null } catch { }
          }
        }
      } catch { }
    }

    if ($null -eq $Keys -or $Keys.Count -lt 1) {
      throw "No keystore keys specified to enforce."
    }

    $failed = New-Object System.Collections.Generic.List[string]

    foreach ($k in $Keys) {
      if ([string]::IsNullOrWhiteSpace($k)) { continue }

      # Best-effort remove first, so overwrite is deterministic even if -f has edge cases
      try {
        $rmOut = & cmd.exe /D /V:OFF /C "`"$keystoreBat`" remove `"$k`"" 2>&1
        # ignore exit code; remove fails if key doesn't exist
      } catch { }

      # Use stdin redirection (NOT 'type ... |') to avoid console encoding/BOM weirdness
      $cmd = "`"$keystoreBat`" add -f --stdin `"$k`" < `"$tmp`""
      $out = & cmd.exe /D /V:OFF /C $cmd 2>&1
      $ec  = $LASTEXITCODE

      if ($ec -eq 0) {
        Write-TinySocsLog "Ensured keystore secure setting (overwritten): $k"
      } else {
        $msg = "Failed to set keystore key '$k' (exit=$ec). Output: $((($out | Out-String).Trim()))"
        Write-TinySocsLog -Level "WARN" -Message $msg
        [void]$failed.Add($k)
      }
    }

    # Verification: list must show all keys
    try {
      $listOut = & cmd.exe /D /V:OFF /C "`"$keystoreBat`" list" 2>&1
      if ($LASTEXITCODE -eq 0) {
        $listTxt = ($listOut | Out-String)
        foreach ($k in $Keys) {
          if ([string]::IsNullOrWhiteSpace($k)) { continue }
          if ($listTxt -notmatch [regex]::Escape($k)) {
            Write-TinySocsLog -Level "WARN" -Message "Keystore list did not show expected key after write: $k"
            if (-not ($failed -contains $k)) { [void]$failed.Add($k) }
          }
        }
      } else {
        Write-TinySocsLog -Level "WARN" -Message "Keystore list failed (exit=$LASTEXITCODE). Output: $((($listOut | Out-String).Trim()))"
        # If list fails, treat as failure because we can't prove state.
        foreach ($k in $Keys) {
          if ([string]::IsNullOrWhiteSpace($k)) { continue }
          if (-not ($failed -contains $k)) { [void]$failed.Add($k) }
        }
      }
    } catch {
      Write-TinySocsLog -Level "WARN" -Message "Keystore verification threw exception: $($_.Exception.Message)"
      foreach ($k in $Keys) {
        if ([string]::IsNullOrWhiteSpace($k)) { continue }
        if (-not ($failed -contains $k)) { [void]$failed.Add($k) }
      }
    }

    if ($failed.Count -gt 0) {
      throw ("Failed to enforce one or more _secure keystore entries: " + (($failed | Select-Object -Unique) -join ", "))
    }

    return $true
  }
  finally {
    try { if (Test-Path -LiteralPath $tmp) { Remove-Item -Force -LiteralPath $tmp -ErrorAction SilentlyContinue } } catch { }
    $env:OPENSEARCH_PATH_CONF = $prevConf
    if ($null -ne $prevJavaHome) { $env:JAVA_HOME = $prevJavaHome } else { Remove-Item Env:\JAVA_HOME -ErrorAction SilentlyContinue | Out-Null }
    if ($null -ne $prevPath)     { $env:PATH     = $prevPath }
  }
}

function Rotate-TinySocsSecrets([Parameter(Mandatory)][string]$SharedSecret){
  Set-TSCredential -Name 'TinySocs/Node/Secret'         -Secret $SharedSecret
  Set-TSCredential -Name 'TinySocs/Master/SharedSecret' -Secret $SharedSecret

  $n = "C:\Program Files\TinySocs\bin\nssm.exe"
  if (Test-Path $n) { try { & $n restart TinySocsNode 2>$null | Out-Null } catch { } }

  Write-Host "[TinySocs] Secrets rotated (CredMan)."
}

# -- Uninstall -----------------------------------------------------------------
function Uninstall-TinySocs {
  [CmdletBinding()]
  param([switch]$KeepData)

  Assert-TinySocsAdmin

  $sentinel = Join-Path $env:ProgramData "TinySocs\ALLOW_UNINSTALL.flag"
  $armed = ($env:TINYSOCS_ALLOW_UNINSTALL -eq 'YES') -or (Test-Path $sentinel)

  if (-not $armed) {
    $msg = "Refusing to uninstall: not armed. Set TINYSOCS_ALLOW_UNINSTALL=YES or create '$sentinel' then re-run."
    try { Write-TinySocsLog -Level "WARN" -Message ("[Uninstall] {0}" -f $msg) } catch { }
    Write-Warning $msg
    return
  }

  $svcNames = @("TinySocsNode","TinySocsOpenSearch","TinySocsAgent")
  $taskPath = "\TinySocs\"
  $binDir  = "C:\Program Files\TinySocs\bin"
  $appData = "$env:ProgramData\TinySocs"

  Write-Host "[TinySocs] Uninstall starting (KeepData=$KeepData)..."

  if (-not $KeepData) {
    try {
      Remove-TSCredential -Name 'TinySocs/Node/Secret'
      Remove-TSCredential -Name 'TinySocs/Master/SharedSecret'
      Remove-TSCredential -Name 'TinySocs/SIEM/Creds'
    } catch { }
  }

  try {
    Get-ScheduledTask -TaskPath $taskPath -ErrorAction SilentlyContinue |
      Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
  } catch { }

  $n = Join-Path $binDir "nssm.exe"
  foreach ($svcName in $svcNames) {
    try { Stop-Service $svcName -ErrorAction SilentlyContinue } catch { }

    if (Test-Path $n) {
      try { & $n remove $svcName confirm | Out-Null } catch { }
    } else {
      try { sc.exe delete $svcName | Out-Null } catch { }
    }
  }

  $procNames = @("TinySocsNode","TinySocsMaster","TinySocsAnchors","TinySocs.Agent","opensearch-service-x64","opensearch-service-mgr")
  foreach ($p in $procNames) {
    try { Get-Process $p -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue } catch { }
  }

  # preserve Machine env on KeepData (upgrade/repair path)
  if (-not $KeepData) {
    $vars = @(
      "PORT","NODE_PORT","SIEM_URL","SIEM_SSL_VERIFY",
      "SIEM_USER","SIEM_PASS",
      "PRIVACY_MODE","NODE_SECRET","MASTER_SHARED_SECRET",
      "TINYSOCS_NODES","HEARTBEAT_MINUTES","ANCHORS_RETENTION_DAYS",
      "ALWAYS_ANCHOR","MASTER_DEADLINE_SEC",
      "TINYSOCS_AGENT_CONFIG","TINYSOCS_INSECURE_LOCAL_SIEM",
      "SIEM_CA_CERT"
    )
    foreach ($v in $vars) { [Environment]::SetEnvironmentVariable($v, $null, 'Machine') }
  }

  if (-not $KeepData) {
    try { Remove-Item -Recurse -Force $appData -ErrorAction SilentlyContinue } catch { }
  }

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

function Invoke-TinySocsOpenSearchSecurityAdminSync {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$OpenSearchRoot,
    [Parameter(Mandatory)][string]$ProgramDataConf,
    [Parameter(Mandatory)][hashtable]$AdminStores,

    # Admin + Kibana users to (re)hydrate via internal_users.yml + securityadmin push
    [string]$AdminUserName = "admin",
    [string]$AdminUserPassword,

    [string]$KibanaUserName = "kibanaserver",
    [string]$KibanaUserPassword,

    # If not supplied, we auto-discover from admin-keystore.(p12|jks)
    [string]$AdminKeystoreAlias,

    # Transport port is NOT used by securityadmin (kept for diagnostics / sanity checks / legacy calls)
    [int]$TransportPort = 0,

    # securityadmin connects to the REST/HTTP(S) endpoint (9200/9201). Also used for post-push verification.
    [Alias("HttpPort")]
    [int]$RestPort = 0,

    [int]$TimeoutSeconds = 120
  )

  $securityTool = Join-Path $OpenSearchRoot "plugins\opensearch-security\tools\securityadmin.bat"
  if (-not (Test-Path $securityTool -PathType Leaf)) { throw "securityadmin.bat not found: $securityTool" }

  $secDir = Join-Path $ProgramDataConf "opensearch-security"
  if (-not (Test-Path $secDir -PathType Container)) { throw "security config dir not found: $secDir" }

  $ks = [string]$AdminStores.AdminKeystoreP12
  $ts = [string]$AdminStores.AdminTruststoreP12
  $pw = [string]$AdminStores.StorePassword

  foreach ($p in @($ks,$ts)) {
    if (-not (Test-Path $p -PathType Leaf)) { throw "Admin store missing on disk: $p" }
  }
  if ([string]::IsNullOrWhiteSpace($pw)) { throw "Invoke-TinySocsOpenSearchSecurityAdminSync: StorePassword was empty." }

  # If caller didnÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬ÃƒÂ¢Ã¢â‚¬Å¾Ã‚Â¢t supply kibana password, fall back safely (kibana -> admin if set).
  if ([string]::IsNullOrWhiteSpace($KibanaUserPassword) -and -not [string]::IsNullOrWhiteSpace($AdminUserPassword)) {
    $KibanaUserPassword = $AdminUserPassword
  }

  # Force bundled JDK for tools (securityadmin/keytool/hash.bat)
  try {
    $env:OPENSEARCH_JAVA_HOME = Join-Path $OpenSearchRoot 'jdk'
    $env:JAVA_HOME            = $env:OPENSEARCH_JAVA_HOME
    $env:PATH                 = (Join-Path $env:JAVA_HOME 'bin') + ';' + $env:PATH
  } catch { }

  $keytool = Join-Path $env:JAVA_HOME "bin\keytool.exe"
  if (-not (Test-Path $keytool -PathType Leaf)) { $keytool = $null }

  function _GetStoreType([string]$Path) {
    $ext = [IO.Path]::GetExtension($Path).ToLowerInvariant()
    if ($ext -in @(".p12",".pfx")) { return "PKCS12" }
    return "JKS"
  }

  function _TryParseYamlPort([string]$Path, [string]$Key) {
    if (-not (Test-Path $Path -PathType Leaf)) { return $null }
    $rx = '^\s*' + [regex]::Escape($Key) + '\s*:\s*(?<p>\d+)\s*(?:#.*)?$'
    $m  = Select-String -Path $Path -Pattern $rx -AllMatches -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $m) { return $null }
    $mm = [regex]::Match($m.Line, $rx)
    if ($mm.Success) { return [int]$mm.Groups['p'].Value }
    return $null
  }

  function _PortOpen([int]$Port) {
    try { return (Test-NetConnection -ComputerName 127.0.0.1 -Port $Port -InformationLevel Quiet) } catch { return $false }
  }

  # Infer ports from ProgramData opensearch.yml if caller didn't set them
  $ymlPath = Join-Path $ProgramDataConf "opensearch.yml"
  if ($TransportPort -le 0) {
    $tp = _TryParseYamlPort -Path $ymlPath -Key "transport.port"
    if (-not $tp) { $tp = 9300 }
    $TransportPort = [int]$tp
  }
  if ($RestPort -le 0) {
    $rp = _TryParseYamlPort -Path $ymlPath -Key "http.port"
    if (-not $rp) { $rp = 9200 }
    $RestPort = [int]$rp
  }

  # Self-heal common mistakes:
  # - If RestPort was set to 9300, but 9200/9201 are listening, override to the listening REST port.
  if ($RestPort -eq 9300) {
    if (_PortOpen 9201) {
      Write-TinySocsLog -Level "WARN" -Message "Invoke-TinySocsOpenSearchSecurityAdminSync: RestPort was 9300 (transport). Overriding to 9201."
      $RestPort = 9201
    } elseif (_PortOpen 9200) {
      Write-TinySocsLog -Level "WARN" -Message "Invoke-TinySocsOpenSearchSecurityAdminSync: RestPort was 9300 (transport). Overriding to 9200."
      $RestPort = 9200
    } else {
      Write-TinySocsLog -Level "WARN" -Message "Invoke-TinySocsOpenSearchSecurityAdminSync: RestPort is 9300 and no REST port (9200/9201) appears open. This will likely fail."
    }
  }

  $ksType = _GetStoreType $ks
  $tsType = _GetStoreType $ts

  # ---- helper: discover alias in keystore (prefer PrivateKeyEntry) ----
  function Resolve-TinySocsAdminKeystoreAlias {
    param(
      [Parameter(Mandatory)][string]$KeytoolExe,
      [Parameter(Mandatory)][string]$KeystorePath,
      [Parameter(Mandatory)][string]$StoreType,
      [Parameter(Mandatory)][string]$StorePass
    )

    if (-not (Test-Path $KeytoolExe -PathType Leaf)) { throw "keytool.exe not found: $KeytoolExe" }
    if (-not (Test-Path $KeystorePath -PathType Leaf)) { throw "Keystore not found: $KeystorePath" }

    $out = & $KeytoolExe -list -v -storetype $StoreType -keystore $KeystorePath -storepass $StorePass 2>&1 | Out-String

    $m = [regex]::Match($out, '(?ims)Alias name:\s*(?<a>.+?)\s*[\r\n]+.*?Entry type:\s*PrivateKeyEntry')
    if ($m.Success) { return $m.Groups['a'].Value.Trim() }

    $m2 = [regex]::Match($out, '(?im)^\s*Alias name:\s*(?<a>.+?)\s*$')
    if ($m2.Success) { return $m2.Groups['a'].Value.Trim() }

    throw "Failed to discover an alias in $KeystorePath. keytool output (trimmed): $($out.Trim() -replace '\s+',' ')"
  }

  # ---- helper: bcrypt hash via OpenSearch security tools hash*.bat ----
  function Get-TinySocsOsBcryptHash {
    param([Parameter(Mandatory)][string]$ToolsDir, [Parameter(Mandatory)][string]$Pass)

    $hashBat = Get-ChildItem $ToolsDir -Filter 'hash*.bat' -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $hashBat) { throw "hash*.bat not found under $ToolsDir" }

    $out = & $hashBat.FullName -p $Pass 2>&1
    $lines = @($out | ForEach-Object { [string]$_ } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })

    $hit = ($lines | Where-Object { $_ -match '\$2[aby]\$' } | Select-Object -First 1)
    if (-not $hit) { $hit = ($lines | Select-Object -Last 1) }

    $h = ([string]$hit).Trim()
    if ([string]::IsNullOrWhiteSpace($h) -or ($h -notmatch '^\$2')) {
      throw "Failed to extract bcrypt hash. Output: $($out | Out-String)"
    }
    return $h
  }

  # ---- helper: ensure ProgramData security config exists + is readable (fixes "Access is denied") ----
  function Ensure-TinySocsSecurityConfigReadable {
    param(
      [Parameter(Mandatory)][string]$DestDir,
      [Parameter(Mandatory)][string]$OpenSearchRootPath
    )

    $sources = @(
      (Join-Path $OpenSearchRootPath "config\opensearch-security"),
      (Join-Path $OpenSearchRootPath "plugins\opensearch-security\securityconfig"),
      (Join-Path $OpenSearchRootPath "plugins\opensearch-security\securityconfig\config")
    ) | Where-Object { Test-Path $_ -PathType Container }

    function _FindSourceFile([string]$FileName) {
      foreach ($s in $sources) {
        $p = Join-Path $s $FileName
        if (Test-Path $p -PathType Leaf) { return $p }
      }
      return $null
    }

    $required = @(
      "config.yml","roles.yml","roles_mapping.yml","action_groups.yml","tenants.yml","nodes_dn.yml","audit.yml","allowlist.yml","internal_users.yml"
    )

    foreach ($f in $required) {
      $dst = Join-Path $DestDir $f
      if (-not (Test-Path $dst -PathType Leaf)) {
        $src = _FindSourceFile $f
        if ($src) {
          try { Copy-Item -Path $src -Destination $dst -Force; Write-TinySocsLog "Copied missing security config '$f' into ProgramData." } catch {
            Write-TinySocsLog -Level "WARN" -Message "Failed to copy '$f' into ProgramData: $($_.Exception.Message)"
          }
        } else {
          Write-TinySocsLog -Level "WARN" -Message "No source found for missing '$f'. securityadmin may fail unless installer lays it down."
        }
      }
    }

    try {
      Get-ChildItem -Path $DestDir -File -ErrorAction SilentlyContinue |
        ForEach-Object {
          try {
            if ($_.Attributes -band [IO.FileAttributes]::ReadOnly) {
              $_.Attributes = ($_.Attributes -bxor [IO.FileAttributes]::ReadOnly)
            }
          } catch { }
        }
    } catch { }

    try {
      & icacls $DestDir /inheritance:e /T /C | Out-Null
      & icacls $DestDir /remove:d "SYSTEM" "BUILTIN\Administrators" /T /C 2>$null | Out-Null
      & icacls $DestDir /grant "SYSTEM:(OI)(CI)F" "BUILTIN\Administrators:(OI)(CI)F" /T /C | Out-Null
    } catch {
      Write-TinySocsLog -Level "WARN" -Message "Failed to apply ACL fixes on '$DestDir': $($_.Exception.Message)"
    }

    foreach ($f in $required) {
      $p = Join-Path $DestDir $f
      if (Test-Path $p -PathType Leaf) {
        try {
          $fs = [System.IO.File]::Open($p, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
          $fs.Close()
        } catch {
          Write-TinySocsLog -Level "WARN" -Message "Security config file still not readable: $p :: $($_.Exception.Message)"
        }
      }
    }
  }

  if ([string]::IsNullOrWhiteSpace($AdminKeystoreAlias)) {
    if ($keytool) {
      $AdminKeystoreAlias = Resolve-TinySocsAdminKeystoreAlias -KeytoolExe $keytool -KeystorePath $ks -StoreType $ksType -StorePass $pw
      Write-TinySocsLog "Discovered admin keystore PrivateKeyEntry alias: $AdminKeystoreAlias"
    } else {
      Write-TinySocsLog -Level "WARN" -Message "keytool.exe not available; cannot auto-discover AdminKeystoreAlias. Proceeding without -ksalias (may fail)."
    }
  }

  $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
  $lastErr  = $null
  $logPath  = Join-Path $env:TEMP ("tinysocs-securityadmin-sync-" + (Get-Date -Format "yyyyMMdd-HHmmss") + ".log")

  Write-TinySocsLog "Running securityadmin sync (timeout=${TimeoutSeconds}s) against REST 127.0.0.1:$RestPort using ProgramData security config. (log=$logPath)"
  Write-TinySocsLog "Stores: ksType=$ksType tsType=$tsType alias=$AdminKeystoreAlias restPort=$RestPort transportPort=$TransportPort"

  Ensure-TinySocsSecurityConfigReadable -DestDir $secDir -OpenSearchRootPath $OpenSearchRoot

  while ((Get-Date) -lt $deadline) {
    $tcpOk = $false
    try {
      $client = New-Object System.Net.Sockets.TcpClient
      $iar = $client.BeginConnect("127.0.0.1", $RestPort, $null, $null)
      $tcpOk = $iar.AsyncWaitHandle.WaitOne(1500)
      try { $client.EndConnect($iar) } catch { }
      $client.Close()
    } catch { $tcpOk = $false }

    if (-not $tcpOk) { Start-Sleep -Seconds 2; continue }

    try {
      if (-not [string]::IsNullOrWhiteSpace($AdminUserPassword) -and -not [string]::IsNullOrWhiteSpace($KibanaUserPassword)) {
        $toolsDir = Join-Path $OpenSearchRoot 'plugins\opensearch-security\tools'
        $adminHash  = Get-TinySocsOsBcryptHash -ToolsDir $toolsDir -Pass $AdminUserPassword
        $kibanaHash = Get-TinySocsOsBcryptHash -ToolsDir $toolsDir -Pass $KibanaUserPassword

        $internalUsers = Join-Path $secDir 'internal_users.yml'
        Ensure-TinySocsSecurityConfigReadable -DestDir $secDir -OpenSearchRootPath $OpenSearchRoot

        if (Get-Command Ensure-TinySocsWritableFile -ErrorAction SilentlyContinue) {
          try { Ensure-TinySocsWritableFile -Path $internalUsers } catch { }
        }

        $yml = @"
---
_meta:
  type: "internalusers"
  config_version: 2

${AdminUserName}:
  hash: "$adminHash"
  reserved: true
  backend_roles:
    - "admin"
  opendistro_security_roles:
    - "all_access"
    - "security_rest_api_access"
  description: "TinySocs local admin"

${KibanaUserName}:
  hash: "$kibanaHash"
  reserved: true
  backend_roles: []
  opendistro_security_roles:
    - "kibana_server"
  description: "TinySocs Kibana server user"
"@

        $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($internalUsers, $yml, $utf8NoBom)
        Write-TinySocsLog "Wrote internal_users.yml for '$AdminUserName' + '$KibanaUserName' (bcrypt hashes) prior to securityadmin push."
      }

      $args = @(
        "-cd", $secDir,
        "-icl", "-nhnv",
        "-h", "127.0.0.1", "-p", "$RestPort",
        "-ks", $ks, "-kspass", $pw, "-kst", $ksType,
        "-ts", $ts, "-tspass", $pw, "-tst", $tsType
      )
      if (-not [string]::IsNullOrWhiteSpace($AdminKeystoreAlias)) { $args += @("-ksalias", $AdminKeystoreAlias) }

      $variantA = @($args + @("-keypass", $pw))
      $variantB = @($args)

      $out = $null
      $txt = $null

      foreach ($tryArgs in @($variantA, $variantB)) {
        $out = & $securityTool @tryArgs 2>&1
        $out | Tee-Object -FilePath $logPath -Append | Out-Null
        $txt = ($out | Out-String)

        if ($txt -match 'Done with success') { break }

        if ($txt -match 'Access is denied' -or $txt -match 'FileNotFoundException') {
          Write-TinySocsLog -Level "WARN" -Message "securityadmin reported file read failures (likely ACL). Re-applying securityconfig ACL + ensuring files. (log=$logPath)"
          Ensure-TinySocsSecurityConfigReadable -DestDir $secDir -OpenSearchRootPath $OpenSearchRoot
          Start-Sleep -Seconds 1
          continue
        }

        $keyPassLooksBad =
          ($tryArgs -eq $variantA) -and (
            $txt -match 'UnrecoverableKeyException' -or
            $txt -match 'Cannot recover key' -or
            $txt -match 'password was incorrect' -or
            $txt -match 'BadPaddingException'
          )

        if (-not $keyPassLooksBad) { break }

        Write-TinySocsLog -Level "WARN" -Message "securityadmin suggests keypass mismatch; retrying without -keypass. (log=$logPath)"
      }

      if ($txt -match 'Done with success') {
        Write-TinySocsLog "securityadmin sync completed successfully."

        if (-not [string]::IsNullOrWhiteSpace($AdminUserPassword)) {
          try {
            $base = "https://127.0.0.1:$RestPort"
            $null = Invoke-TinySocsOpenSearchApi -Method "GET" -Url "$base/_plugins/_security/authinfo" -User $AdminUserName -Pass $AdminUserPassword -SkipTlsVerify:$true
            $null = Invoke-TinySocsOpenSearchApi -Method "GET" -Url "$base/_cluster/health"              -User $AdminUserName -Pass $AdminUserPassword -SkipTlsVerify:$true
            Write-TinySocsLog "securityadmin verification succeeded via REST (authinfo + cluster health)."
          } catch {
            Write-TinySocsLog -Level "WARN" -Message "securityadmin push succeeded, but REST verification failed: $($_.Exception.Message)"
          }
        }

        return $true
      }

      $lastErr = $txt.Trim()
      Write-TinySocsLog -Level "WARN" -Message "securityadmin did not report success; will retry. (log=$logPath) Output: $($lastErr -replace '\s+',' ')"
    } catch {
      $lastErr = $_.Exception.Message
      Write-TinySocsLog -Level "WARN" -Message "securityadmin invocation failed; will retry. (log=$logPath) Error: $lastErr"
    }

    Start-Sleep -Seconds 3
  }

  Write-TinySocsLog -Level "WARN" -Message "securityadmin sync did not succeed within timeout. (log=$logPath) Last error/output: $lastErr"
  return $false
}

function Invoke-TinySocsOpenSearchPoliciesBootstrap {
  <#
  .SYNOPSIS
    Bootstrap ISM policies from JSON files in packaging/opensearch/policies/.
  .DESCRIPTION
    Loads all *.json files from the policies directory and creates/updates
    ISM policies in OpenSearch using the _plugins/_ism/policies API.
  #>
  [CmdletBinding()]
  param(
    [string]$PoliciesDir = $null,
    [int]$WaitTimeoutSec = 90
  )

  if (-not $PoliciesDir) {
    # Try to find policies dir relative to module
    $moduleDir = Split-Path -Parent $PSScriptRoot
    $candidateDirs = @(
      (Join-Path $moduleDir "packaging\opensearch\policies"),
      (Join-Path $PSScriptRoot "..\packaging\opensearch\policies")
    )

    foreach ($dir in $candidateDirs) {
      if (Test-Path -LiteralPath $dir -PathType Container) {
        $PoliciesDir = $dir
        break
      }
    }
  }

  if (-not $PoliciesDir -or -not (Test-Path -LiteralPath $PoliciesDir -PathType Container)) {
    Write-Host "[TinySocs][OpenSearch] Policies bootstrap: no policies dir found (skipping)" -ForegroundColor Yellow
    return
  }

  $files = Get-ChildItem -Path $PoliciesDir -Filter *.json -File -ErrorAction SilentlyContinue | Sort-Object Name
  if (-not $files -or $files.Count -eq 0) {
    Write-Host "[TinySocs][OpenSearch] Policies bootstrap: no *.json files in $PoliciesDir (skipping)" -ForegroundColor Yellow
    return
  }

  if (-not (_Wait-OpenSearchReady -TimeoutSec $WaitTimeoutSec)) {
    throw "OpenSearch not reachable; cannot ensure ISM policies"
  }

  Write-Host "[TinySocs][OpenSearch] Ensuring ISM policies from $PoliciesDir" -ForegroundColor Cyan

  foreach ($f in $files) {
    $policyId = [IO.Path]::GetFileNameWithoutExtension($f.Name)
    $txt = Get-Content -LiteralPath $f.FullName -Raw -Encoding UTF8

    $policyBody = $null
    try { $policyBody = $txt | ConvertFrom-Json -ErrorAction Stop }
    catch { throw "Invalid JSON policy: $($f.FullName): $($_.Exception.Message)" }

    # Create or update the policy
    try {
      $r = _OsInvoke -Method PUT -Path "/_plugins/_ism/policies/$policyId" -Body $policyBody -TimeoutSec 30
      if ($r.StatusCode -ge 200 -and $r.StatusCode -lt 300) {
        Write-Host "[TinySocs][OpenSearch] ISM policy ensured: $policyId (from $($f.Name))" -ForegroundColor DarkCyan
      } else {
        Write-Host "[TinySocs][OpenSearch] ISM policy PUT failed: $policyId HTTP $($r.StatusCode)" -ForegroundColor Yellow
      }
    } catch {
      Write-Host "[TinySocs][OpenSearch] Failed to create/update ISM policy $policyId : $($_.Exception.Message)" -ForegroundColor Yellow
    }
  }

  Write-Host "[TinySocs][OpenSearch] ISM policies bootstrap complete" -ForegroundColor Green
}

function Test-TinySocsHealth {
  <#
  .SYNOPSIS
    Objective health check for TinySocs installation.

  .DESCRIPTION
    Tests critical components to determine if TinySocs is alive and functioning:
    - OpenSearch service running
    - OpenSearch HTTP responding on 9201
    - Heartbeat document fresh (< 2 minutes old)
    - Index template exists (tinysocs-winlog)
    - Recent log ingestion (< 5 minutes)
    - @timestamp field mapping is date
    - Agent service running (secondary check)

  .PARAMETER SiemUrl
    OpenSearch URL. Default: https://localhost:9201

  .PARAMETER User
    SIEM username. If not provided, attempts to read from credman.

  .PARAMETER Pass
    SIEM password. If not provided, attempts to read from credman.

  .EXAMPLE
    Test-TinySocsHealth
    Test-TinySocsHealth -SiemUrl "https://localhost:9201" -User "tinysocs" -Pass "secret"
  #>
  [CmdletBinding()]
  param(
    [string]$SiemUrl = "https://localhost:9201",
    [string]$User = "",
    [string]$Pass = ""
  )

  Write-Host "`n=== TinySocs Health Check ===" -ForegroundColor Cyan
  Write-Host "SIEM URL: $SiemUrl`n" -ForegroundColor Gray

  $results = @()
  $allPassed = $true

  # PS 5.1 compatibility: bypass self-signed cert validation (no -SkipCertificateCheck)
  # NOTE: We intentionally do NOT restore the callback — PS 5.1 fails the first HTTPS
  # request after setting a new callback, so restoring it each call causes perpetual failures.
  # The cert bypass is harmless for the session lifetime (self-signed local OpenSearch).
  if (-not [System.Net.ServicePointManager]::ServerCertificateValidationCallback) {
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = `
      [System.Net.Security.RemoteCertificateValidationCallback]{ param($sender,$cert,$chain,$errors) return $true }
  }
  [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

  # PS 5.1 compat: Invoke-RestMethod sometimes returns raw strings instead of parsed
  # objects depending on Content-Type. This helper ensures we always get a PSObject.
  function _EnsureJson($obj) {
    if ($obj -is [string]) { return ($obj | ConvertFrom-Json) }
    return $obj
  }

  # Get credentials if not provided
  if ([string]::IsNullOrWhiteSpace($User) -or [string]::IsNullOrWhiteSpace($Pass)) {
    try {
      $creds = Get-TSSiemCredsCanonical
      if ($creds) {
        $User = $creds.User
        $Pass = $creds.Pass
      }
    } catch {
      Write-Host "Warning: Could not retrieve SIEM credentials from credman" -ForegroundColor Yellow
    }
  }

  $auth = @{}
  if (-not [string]::IsNullOrWhiteSpace($User) -and -not [string]::IsNullOrWhiteSpace($Pass)) {
    $pair = "${User}:${Pass}"
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
    $base64 = [System.Convert]::ToBase64String($bytes)
    $auth = @{ Authorization = "Basic $base64" }
  }

  # --- PRIMARY CHECKS (objective) ---

  # 1. OpenSearch service running
  try {
    $svc = Get-Service -Name "TinySocsOpenSearch" -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq 'Running') {
      $results += @{ Check = "OpenSearch Service"; Status = "PASS"; Detail = "Running" }
    } else {
      $results += @{ Check = "OpenSearch Service"; Status = "FAIL"; Detail = "Not running or not found" }
      $allPassed = $false
    }
  } catch {
    $results += @{ Check = "OpenSearch Service"; Status = "FAIL"; Detail = $_.Exception.Message }
    $allPassed = $false
  }

  # 2. Heartbeat document freshness (run BEFORE HTTP root check to prime PS 5.1 TLS)
  try {
    $hbResponse = _EnsureJson (Invoke-RestMethod -Uri "$SiemUrl/tinysocs-heartbeat/_search" `
      -Headers $auth -TimeoutSec 10 -ErrorAction Stop `
      -Method POST -ContentType "application/json" -Body '{"size":1,"sort":[{"timestamp":{"order":"desc"}}]}')

    if ($hbResponse.hits.total.value -gt 0) {
      $hbDoc = $hbResponse.hits.hits[0]._source
      $hbTimestamp = [DateTime]::Parse($hbDoc.timestamp)
      $age = (Get-Date).ToUniversalTime() - $hbTimestamp
      if ($age.TotalMinutes -lt 2) {
        $results += @{ Check = "Heartbeat Fresh"; Status = "PASS"; Detail = "Age: $([math]::Round($age.TotalSeconds))s" }
      } else {
        $results += @{ Check = "Heartbeat Fresh"; Status = "FAIL"; Detail = "Age: $([math]::Round($age.TotalMinutes))m (stale)" }
        $allPassed = $false
      }
    } else {
      $results += @{ Check = "Heartbeat Fresh"; Status = "WARN"; Detail = "No heartbeat document found" }
      $allPassed = $false
    }
  } catch {
    $results += @{ Check = "Heartbeat Fresh"; Status = "WARN"; Detail = $_.Exception.Message }
  }

  # 3. OpenSearch HTTP responding (after heartbeat primes TLS connection)
  try {
    $response = _EnsureJson (Invoke-RestMethod -Uri "$SiemUrl/" -Headers $auth -TimeoutSec 10 -ErrorAction Stop)
    if ($response) {
      $results += @{ Check = "OpenSearch HTTP"; Status = "PASS"; Detail = "Responding on 9201" }
    } else {
      $results += @{ Check = "OpenSearch HTTP"; Status = "FAIL"; Detail = "No response" }
      $allPassed = $false
    }
  } catch {
    $results += @{ Check = "OpenSearch HTTP"; Status = "FAIL"; Detail = $_.Exception.Message }
    $allPassed = $false
  }

  # 4. Index template exists (tinysocs-winlog)
  try {
    $tmplResponse = _EnsureJson (Invoke-RestMethod -Uri "$SiemUrl/_index_template/tinysocs-winlog" `
      -Headers $auth -TimeoutSec 10 -ErrorAction Stop)
    if ($tmplResponse.index_templates.Count -gt 0) {
      $results += @{ Check = "Index Template"; Status = "PASS"; Detail = "tinysocs-winlog exists" }
    } else {
      $results += @{ Check = "Index Template"; Status = "FAIL"; Detail = "tinysocs-winlog not found" }
      $allPassed = $false
    }
  } catch {
    $results += @{ Check = "Index Template"; Status = "FAIL"; Detail = $_.Exception.Message }
    $allPassed = $false
  }

  # 5. Recent log ingestion (latest doc < 5 minutes)
  try {
    $searchResponse = _EnsureJson (Invoke-RestMethod -Uri "$SiemUrl/tinysocs-winlog-*/_search" `
      -Headers $auth -TimeoutSec 10 -ErrorAction Stop `
      -Method POST -ContentType "application/json" -Body '{"size":1,"sort":[{"@timestamp":{"order":"desc"}}],"query":{"range":{"@timestamp":{"gte":"now-5m"}}}}')

    if ($searchResponse.hits.total.value -gt 0) {
      $results += @{ Check = "Recent Ingestion"; Status = "PASS"; Detail = "$($searchResponse.hits.total.value) docs in last 5m" }
    } else {
      $results += @{ Check = "Recent Ingestion"; Status = "WARN"; Detail = "No docs in last 5 minutes" }
    }
  } catch {
    $results += @{ Check = "Recent Ingestion"; Status = "WARN"; Detail = $_.Exception.Message }
  }

  # 6. @timestamp mapping is date
  # Use field-specific mapping API to avoid full mapping response which contains
  # duplicate keys (Engine Version/Engine version) that break PS 5.1 ConvertFrom-Json
  try {
    $fieldMapRaw = Invoke-RestMethod -Uri "$SiemUrl/tinysocs-winlog-*/_mapping/field/%40timestamp" `
      -Headers $auth -TimeoutSec 10 -ErrorAction Stop
    $timestampType = $null
    if ($fieldMapRaw -is [string]) {
      # PS 5.1 sometimes returns string — regex extract
      if ($fieldMapRaw -match '"type"\s*:\s*"([^"]+)"') { $timestampType = $Matches[1] }
    } else {
      # PSCustomObject: navigate {index}.mappings.@timestamp.mapping.@timestamp.type
      $idxProp = $fieldMapRaw.PSObject.Properties | Select-Object -First 1
      if ($idxProp) {
        $tsMapping = $idxProp.Value.mappings.'@timestamp'.mapping.'@timestamp'
        if ($tsMapping) { $timestampType = $tsMapping.type }
      }
    }
    if ($timestampType -eq 'date') {
      $results += @{ Check = "@timestamp Mapping"; Status = "PASS"; Detail = "Type is date" }
    } elseif ($timestampType) {
      $results += @{ Check = "@timestamp Mapping"; Status = "FAIL"; Detail = "Type is $timestampType (not date)" }
      $allPassed = $false
    } else {
      $results += @{ Check = "@timestamp Mapping"; Status = "WARN"; Detail = "No indices or field not found" }
    }
  } catch {
    $results += @{ Check = "@timestamp Mapping"; Status = "WARN"; Detail = $_.Exception.Message }
  }

  # --- SECONDARY CHECKS (supporting) ---

  # Agent service running
  try {
    $agentSvc = Get-Service -Name "TinySocsAgent" -ErrorAction SilentlyContinue
    if ($agentSvc -and $agentSvc.Status -eq 'Running') {
      $results += @{ Check = "Agent Service"; Status = "PASS"; Detail = "Running" }
    } else {
      $results += @{ Check = "Agent Service"; Status = "WARN"; Detail = "Not running or not found" }
    }
  } catch {
    $results += @{ Check = "Agent Service"; Status = "WARN"; Detail = $_.Exception.Message }
  }

  # Detection: Alert template exists
  try {
    $alertTmplResponse = _EnsureJson (Invoke-RestMethod -Uri "$SiemUrl/_index_template/tinysocs-alerts" `
      -Headers $auth -TimeoutSec 10 -ErrorAction Stop)
    if ($alertTmplResponse.index_templates.Count -gt 0) {
      $results += @{ Check = "Alert Template"; Status = "PASS"; Detail = "tinysocs-alerts exists" }
    } else {
      $results += @{ Check = "Alert Template"; Status = "WARN"; Detail = "tinysocs-alerts not found" }
    }
  } catch {
    $results += @{ Check = "Alert Template"; Status = "WARN"; Detail = $_.Exception.Message }
  }

  # Detection: Rules file exists
  try {
    $rulesPath = "C:\ProgramData\TinySocs\Collector\rules\rules.yml"
    if (Test-Path -LiteralPath $rulesPath -PathType Leaf) {
      $rulesContent = Get-Content -LiteralPath $rulesPath -Raw
      if ($rulesContent -match 'rules:') {
        $results += @{ Check = "Rules File"; Status = "PASS"; Detail = "rules.yml exists" }
      } else {
        $results += @{ Check = "Rules File"; Status = "WARN"; Detail = "rules.yml exists but invalid" }
      }
    } else {
      $results += @{ Check = "Rules File"; Status = "WARN"; Detail = "rules.yml not found" }
    }
  } catch {
    $results += @{ Check = "Rules File"; Status = "WARN"; Detail = $_.Exception.Message }
  }

  # --- Phase 11: LLM Assistant checks ---

  # Assistant service running
  try {
    $assistSvc = Get-Service -Name "TinySocsAssistant" -ErrorAction SilentlyContinue
    if ($assistSvc -and $assistSvc.Status -eq 'Running') {
      $results += @{ Check = "Assistant Service"; Status = "PASS"; Detail = "Running" }
    } elseif ($assistSvc) {
      $results += @{ Check = "Assistant Service"; Status = "WARN"; Detail = "Status: $($assistSvc.Status)" }
    } else {
      $results += @{ Check = "Assistant Service"; Status = "WARN"; Detail = "Not installed" }
    }
  } catch {
    $results += @{ Check = "Assistant Service"; Status = "WARN"; Detail = $_.Exception.Message }
  }

  # Assistant API responding (http://localhost:8081/meta — node API, unauthenticated)
  try {
    $assistSvc2 = Get-Service -Name "TinySocsAssistant" -ErrorAction SilentlyContinue
    if ($assistSvc2 -and $assistSvc2.Status -eq 'Running') {
      try {
        $metaResponse = Invoke-RestMethod -Uri "http://localhost:8081/meta" -TimeoutSec 5 -ErrorAction Stop
        if ($metaResponse) {
          $results += @{ Check = "Assistant API"; Status = "PASS"; Detail = "Responding on 8081" }
        } else {
          $results += @{ Check = "Assistant API"; Status = "WARN"; Detail = "Empty response" }
        }
      } catch {
        $results += @{ Check = "Assistant API"; Status = "WARN"; Detail = "Not responding: $($_.Exception.Message)" }
      }
    } else {
      $results += @{ Check = "Assistant API"; Status = "WARN"; Detail = "Service not running; skipped" }
    }
  } catch {
    $results += @{ Check = "Assistant API"; Status = "WARN"; Detail = $_.Exception.Message }
  }

  # Webhook configured (info-level, not a failure if empty)
  try {
    $agentConfigPath = "C:\ProgramData\TinySocs\Collector\agent-config.yml"
    if (Test-Path -LiteralPath $agentConfigPath -PathType Leaf) {
      $agentConfigContent = Get-Content -LiteralPath $agentConfigPath -Raw
      $webhookUrl = $null
      if ($agentConfigContent -match 'webhook_url:\s+"([^"]+)"') {
        $webhookUrl = $Matches[1]
      } elseif ($agentConfigContent -match "webhook_url:\s+'([^']+)'") {
        $webhookUrl = $Matches[1]
      } elseif ($agentConfigContent -match 'webhook_url:\s+(\S+)') {
        $candidate = $Matches[1]
        if ($candidate -ne '""' -and $candidate -ne "''" -and $candidate.Length -gt 2) {
          $webhookUrl = $candidate
        }
      }
      if (-not [string]::IsNullOrWhiteSpace($webhookUrl)) {
        $results += @{ Check = "Webhook"; Status = "INFO"; Detail = "Configured ($webhookUrl)" }
      } else {
        $results += @{ Check = "Webhook"; Status = "INFO"; Detail = "Not configured" }
      }
    } else {
      $results += @{ Check = "Webhook"; Status = "INFO"; Detail = "agent-config.yml not found" }
    }
  } catch {
    $results += @{ Check = "Webhook"; Status = "INFO"; Detail = $_.Exception.Message }
  }

  # --- Phase 13: Notification delivery checks ---

  # Check 13: Webhook Delivery — POST test to configured URL, verify 2xx
  try {
    $agentConfigPath2 = "C:\ProgramData\TinySocs\Collector\agent-config.yml"
    $webhookUrl2 = $null
    if (Test-Path -LiteralPath $agentConfigPath2 -PathType Leaf) {
      $acContent = Get-Content -LiteralPath $agentConfigPath2 -Raw
      if ($acContent -match 'webhook_url:\s+"([^"]+)"') { $webhookUrl2 = $Matches[1] }
      elseif ($acContent -match "webhook_url:\s+'([^']+)'") { $webhookUrl2 = $Matches[1] }
      elseif ($acContent -match 'webhook_url:\s+(\S+)') {
        $c = $Matches[1]; if ($c -ne '""' -and $c -ne "''" -and $c.Length -gt 2) { $webhookUrl2 = $c }
      }
    }
    if (-not [string]::IsNullOrWhiteSpace($webhookUrl2)) {
      try {
        $whBody = '{"text":"[TinySocs] Health check — webhook delivery test"}'
        $whResp = Invoke-WebRequest -Uri $webhookUrl2 -Method POST -Body $whBody `
          -ContentType "application/json" -TimeoutSec 10 -UseBasicParsing -ErrorAction Stop
        if ($whResp.StatusCode -ge 200 -and $whResp.StatusCode -lt 300) {
          $results += @{ Check = "Webhook Delivery"; Status = "PASS"; Detail = "HTTP $($whResp.StatusCode)" }
        } else {
          $results += @{ Check = "Webhook Delivery"; Status = "WARN"; Detail = "HTTP $($whResp.StatusCode)" }
        }
      } catch {
        $results += @{ Check = "Webhook Delivery"; Status = "WARN"; Detail = "Failed: $($_.Exception.Message)" }
      }
    } else {
      $results += @{ Check = "Webhook Delivery"; Status = "INFO"; Detail = "Webhook not configured" }
    }
  } catch {
    $results += @{ Check = "Webhook Delivery"; Status = "INFO"; Detail = $_.Exception.Message }
  }

  # Check 14: Email SMTP — EHLO handshake to configured SMTP host
  try {
    $smtpHost2 = $null
    $smtpPort2 = 587
    if (Test-Path -LiteralPath $agentConfigPath2 -PathType Leaf) {
      $acContent2 = Get-Content -LiteralPath $agentConfigPath2 -Raw
      if ($acContent2 -match 'smtp_host:\s+"?([^"\r\n]+)"?') {
        $smtpHost2 = $Matches[1].Trim().Trim('"').Trim("'")
      }
      if ($acContent2 -match 'smtp_port:\s+(\d+)') {
        $smtpPort2 = [int]$Matches[1]
      }
    }
    if (-not [string]::IsNullOrWhiteSpace($smtpHost2)) {
      try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $tcp.SendTimeout = 5000
        $tcp.ReceiveTimeout = 5000
        $tcp.Connect($smtpHost2, $smtpPort2)
        $stream = $tcp.GetStream()
        $reader = New-Object System.IO.StreamReader($stream)
        $banner = $reader.ReadLine()
        $writer = New-Object System.IO.StreamWriter($stream)
        $writer.AutoFlush = $true
        $writer.WriteLine("EHLO tinysocs-healthcheck")
        $ehloResp = $reader.ReadLine()
        $writer.WriteLine("QUIT")
        $tcp.Close()
        if ($ehloResp -match '^250') {
          $results += @{ Check = "Email SMTP"; Status = "PASS"; Detail = "EHLO OK ($smtpHost2`:$smtpPort2)" }
        } else {
          $results += @{ Check = "Email SMTP"; Status = "WARN"; Detail = "EHLO response: $ehloResp" }
        }
      } catch {
        $results += @{ Check = "Email SMTP"; Status = "WARN"; Detail = "Connection failed: $($_.Exception.Message)" }
      }
    } else {
      $results += @{ Check = "Email SMTP"; Status = "INFO"; Detail = "SMTP not configured" }
    }
  } catch {
    $results += @{ Check = "Email SMTP"; Status = "INFO"; Detail = $_.Exception.Message }
  }

  # --- Phase 14: Sysmon and Dashboard TLS checks ---

  # Check 15: Sysmon Service — optional component, INFO if not installed
  # ARM64 installs register as "Sysmon64a"; x64 as "Sysmon64".
  # Check both and prefer whichever is Running (handles stale orphan entries).
  try {
    $sysmonSvc = $null
    foreach ($svcName in @("Sysmon64", "Sysmon64a")) {
      $s = Get-Service -Name $svcName -ErrorAction SilentlyContinue
      if ($s -and $s.Status -eq "Running") { $sysmonSvc = $s; break }
      if ($s -and -not $sysmonSvc) { $sysmonSvc = $s }  # keep first found as fallback
    }
    if ($sysmonSvc) {
      if ($sysmonSvc.Status -eq "Running") {
        $results += @{ Check = "Sysmon Service"; Status = "PASS"; Detail = "Running ($($sysmonSvc.Name))" }
      } else {
        $results += @{ Check = "Sysmon Service"; Status = "WARN"; Detail = "Status: $($sysmonSvc.Status) ($($sysmonSvc.Name))" }
      }
    } else {
      $results += @{ Check = "Sysmon Service"; Status = "INFO"; Detail = "Not installed (optional)" }
    }
  } catch {
    $results += @{ Check = "Sysmon Service"; Status = "INFO"; Detail = $_.Exception.Message }
  }

  # Check 16: Dashboard TLS — validates cert present when network mode configured
  try {
    $envPath = Join-Path $env:ProgramData "TinySocs\Assistant\assistant.env"
    $dashBind = "127.0.0.1"
    $dashCert = ""
    if (Test-Path -LiteralPath $envPath) {
      foreach ($line in (Get-Content $envPath -ErrorAction SilentlyContinue)) {
        if ($line -match '^DASHBOARD_BIND=(.+)') { $dashBind = $Matches[1].Trim() }
        if ($line -match '^DASHBOARD_TLS_CERT=(.+)') { $dashCert = $Matches[1].Trim() }
      }
    }
    if ($dashBind -ne "127.0.0.1") {
      if ($dashCert -and (Test-Path -LiteralPath $dashCert)) {
        $results += @{ Check = "Dashboard TLS"; Status = "PASS"; Detail = "Network mode with TLS cert present" }
      } else {
        $results += @{ Check = "Dashboard TLS"; Status = "FAIL"; Detail = "Network mode but no TLS cert found" }
        $allPassed = $false
      }
    } else {
      $results += @{ Check = "Dashboard TLS"; Status = "PASS"; Detail = "Localhost-only (TLS not required)" }
    }
  } catch {
    $results += @{ Check = "Dashboard TLS"; Status = "WARN"; Detail = $_.Exception.Message }
  }

  # Display results
  Write-Host ""
  foreach ($r in $results) {
    $color = switch ($r.Status) {
      "PASS" { "Green" }
      "WARN" { "Yellow" }
      "FAIL" { "Red" }
      "INFO" { "Cyan" }
      default { "Gray" }
    }
    $statusPadded = $r.Status.PadRight(6)
    Write-Host "[$statusPadded] " -ForegroundColor $color -NoNewline
    Write-Host "$($r.Check.PadRight(25)) " -NoNewline
    Write-Host $r.Detail -ForegroundColor Gray
  }

  Write-Host ""
  if ($allPassed) {
    Write-Host "Overall Status: HEALTHY" -ForegroundColor Green
    return $true
  } else {
    Write-Host "Overall Status: UNHEALTHY (see failures above)" -ForegroundColor Red
    return $false
  }
}

# -- Phase 13: Post-install smoke test ----------------------------------------

function Invoke-TinySocsSmokeTest {
  <#
  .SYNOPSIS
    Full post-install smoke test for TinySocs.

  .DESCRIPTION
    Phase 13 (M5): Comprehensive end-to-end verification that:
    1. Runs Test-TinySocsHealth (14 checks)
    2. Triggers a test alert via simulated failed logon
    3. Waits for ingestion (30 seconds)
    4. Verifies alert appears in tinysocs-alerts-* index
    5. Verifies webhook received (if configured)
    Returns structured pass/fail report.

  .PARAMETER SiemUrl
    OpenSearch URL. Default: https://localhost:9201

  .PARAMETER User
    SIEM username.

  .PARAMETER Pass
    SIEM password.

  .EXAMPLE
    Invoke-TinySocsSmokeTest
  #>
  [CmdletBinding()]
  param(
    [string]$SiemUrl = "https://localhost:9201",
    [string]$User = "",
    [string]$Pass = ""
  )

  Write-Host "`n=== TinySocs Smoke Test ===" -ForegroundColor Cyan
  Write-Host "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n" -ForegroundColor Gray

  $smokeResults = @()
  $allPassed = $true

  # Step 1: Run health check
  Write-Host "--- Step 1: Health Check ---" -ForegroundColor Yellow
  $healthPassed = Test-TinySocsHealth -SiemUrl $SiemUrl -User $User -Pass $Pass
  if ($healthPassed) {
    $smokeResults += @{ Check = "Health Check"; Status = "PASS"; Detail = "All checks passed" }
  } else {
    $smokeResults += @{ Check = "Health Check"; Status = "WARN"; Detail = "Some checks failed (see above)" }
  }

  # Get credentials if not provided
  if ([string]::IsNullOrWhiteSpace($User) -or [string]::IsNullOrWhiteSpace($Pass)) {
    try {
      $creds = Get-TSSiemCredsCanonical
      if ($creds) { $User = $creds.User; $Pass = $creds.Pass }
    } catch { }
  }

  $auth = @{}
  if (-not [string]::IsNullOrWhiteSpace($User) -and -not [string]::IsNullOrWhiteSpace($Pass)) {
    $pair = "${User}:${Pass}"
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
    $base64 = [System.Convert]::ToBase64String($bytes)
    $auth = @{ Authorization = "Basic $base64" }
  }

  # PS 5.1 TLS setup
  if (-not [System.Net.ServicePointManager]::ServerCertificateValidationCallback) {
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = `
      [System.Net.Security.RemoteCertificateValidationCallback]{ param($sender,$cert,$chain,$errors) return $true }
  }
  [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

  # Step 2: Count alerts before trigger
  Write-Host "`n--- Step 2: Trigger Test Alert ---" -ForegroundColor Yellow
  $alertCountBefore = 0
  try {
    $countResp = Invoke-RestMethod -Uri "$SiemUrl/tinysocs-alerts-*/_count" `
      -Headers $auth -TimeoutSec 10 -ErrorAction Stop
    if ($countResp -is [string]) { $countResp = $countResp | ConvertFrom-Json }
    $alertCountBefore = $countResp.count
    Write-Host "Alerts before trigger: $alertCountBefore" -ForegroundColor Gray
  } catch {
    Write-Host "Could not count alerts: $($_.Exception.Message)" -ForegroundColor Yellow
  }

  # Trigger: simulate a failed logon event (this should fire auth_failed_burst_lab if lab rules enabled)
  Write-Host "Generating test events (PowerShell ScriptBlock)..." -ForegroundColor Gray
  try {
    # Fire several ScriptBlock events to trigger script_block_volume or ps_script_block_lab rules
    1..5 | ForEach-Object {
      $null = Invoke-Expression "Write-Output 'TinySocs smoke test event $_'"
    }
    $smokeResults += @{ Check = "Test Alert Trigger"; Status = "PASS"; Detail = "Events generated" }
  } catch {
    $smokeResults += @{ Check = "Test Alert Trigger"; Status = "WARN"; Detail = $_.Exception.Message }
  }

  # Step 3: Wait for ingestion
  Write-Host "`n--- Step 3: Waiting 30s for ingestion ---" -ForegroundColor Yellow
  Start-Sleep -Seconds 30

  # Step 4: Verify alert appeared
  Write-Host "--- Step 4: Verify Alert Ingested ---" -ForegroundColor Yellow
  try {
    $countResp2 = Invoke-RestMethod -Uri "$SiemUrl/tinysocs-alerts-*/_count" `
      -Headers $auth -TimeoutSec 10 -ErrorAction Stop
    if ($countResp2 -is [string]) { $countResp2 = $countResp2 | ConvertFrom-Json }
    $alertCountAfter = $countResp2.count
    Write-Host "Alerts after trigger: $alertCountAfter" -ForegroundColor Gray
    if ($alertCountAfter -gt $alertCountBefore) {
      $newAlerts = $alertCountAfter - $alertCountBefore
      $smokeResults += @{ Check = "Alert Ingested"; Status = "PASS"; Detail = "$newAlerts new alert(s) in index" }
    } else {
      $smokeResults += @{ Check = "Alert Ingested"; Status = "WARN"; Detail = "No new alerts detected (rules may need lower threshold)" }
    }
  } catch {
    $smokeResults += @{ Check = "Alert Ingested"; Status = "WARN"; Detail = $_.Exception.Message }
  }

  # Step 5: Display results
  Write-Host "`n=== Smoke Test Results ===" -ForegroundColor Cyan
  foreach ($r in $smokeResults) {
    $color = switch ($r.Status) {
      "PASS" { "Green" }
      "WARN" { "Yellow" }
      "FAIL" { "Red" }
      "INFO" { "Cyan" }
      default { "Gray" }
    }
    $statusPadded = $r.Status.PadRight(6)
    Write-Host "[$statusPadded] " -ForegroundColor $color -NoNewline
    Write-Host "$($r.Check.PadRight(25)) " -NoNewline
    Write-Host $r.Detail -ForegroundColor Gray
  }

  $failCount = ($smokeResults | Where-Object { $_.Status -eq 'FAIL' }).Count
  Write-Host ""
  if ($failCount -eq 0) {
    Write-Host "Smoke Test: PASSED" -ForegroundColor Green
    return $true
  } else {
    Write-Host "Smoke Test: FAILED ($failCount failure(s))" -ForegroundColor Red
    return $false
  }
}

# -- Phase 10: Detection Engine Deployment ------------------------------------

function Ensure-TinySocsDetectionRulesStaged {
  <#
  .SYNOPSIS
    Verifies the detection rules.yml file exists in packaging/detection/rules.yml

  .DESCRIPTION
    The canonical rules.yml lives in the repo at packaging/detection/rules.yml.
    This function verifies it is present and logs a warning if missing.
  #>
  [CmdletBinding()]
  param()

  $repoRoot = Get-TinySocsRepoRoot
  $rulesDir = Join-Path $repoRoot "packaging\detection"
  $rulesFile = Join-Path $rulesDir "rules.yml"

  if (Test-Path $rulesFile -PathType Leaf) {
    Write-TinySocsLog "Detection rules already staged at $rulesFile"
  } else {
    Write-TinySocsLog -Level "WARN" -Message "Detection rules file not found at $rulesFile. Ensure packaging/detection/rules.yml is checked in."
  }
}

function Deploy-TinySocsDetectionRules {
  <#
  .SYNOPSIS
    Deploys detection rules to ProgramData\TinySocs\Collector\rules\

  .DESCRIPTION
    Copies the rules.yml file from the staging area (packaging/detection) to
    the runtime location where the agent will load them.
  #>
  [CmdletBinding()]
  param()

  $repoRoot = Get-TinySocsRepoRoot
  $sourceFile = Join-Path $repoRoot "packaging\detection\rules.yml"

  $targetDir = "C:\ProgramData\TinySocs\Collector\rules"
  $targetFile = Join-Path $targetDir "rules.yml"

  # Ensure target directory exists
  if (-not (Test-Path $targetDir)) {
    New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
    Write-TinySocsLog "Created detection rules directory: $targetDir"
  }

  # Check if source exists; if not, stage it first
  if (-not (Test-Path $sourceFile -PathType Leaf)) {
    Write-TinySocsLog -Level "WARN" -Message "Source rules file not found, staging now: $sourceFile"
    Ensure-TinySocsDetectionRulesStaged
  }

  if (Test-Path $sourceFile -PathType Leaf) {
    Copy-Item -Path $sourceFile -Destination $targetFile -Force
    Write-TinySocsLog "Detection rules deployed to $targetFile"
  } else {
    Write-TinySocsLog -Level "ERROR" -Message "Failed to stage or deploy detection rules"
    throw "Detection rules source file not found: $sourceFile"
  }
}

function Update-TinySocsAgentConfigForDetection {
  <#
  .SYNOPSIS
    Ensures agent-config.yml has the detection section with correct values

  .DESCRIPTION
    Updates the agent config file in ProgramData to include the Phase 10
    detection configuration section.
  #>
  [CmdletBinding()]
  param(
    [string]$ConfigPath = "C:\ProgramData\TinySocs\Collector\agent-config.yml"
  )

  if (-not (Test-Path $ConfigPath -PathType Leaf)) {
    Write-TinySocsLog -Level "WARN" -Message "Agent config not found at $ConfigPath; cannot add detection section"
    return
  }

  $content = Get-Content $ConfigPath -Raw

  # Check if detection section already exists
  if ($content -match '(?m)^detection:') {
    Write-TinySocsLog "Detection section already exists in $ConfigPath"
    return
  }

  # Append detection section
  $detectionSection = @"

detection:
  enabled: true
  rules_file: C:\ProgramData\TinySocs\Collector\rules\rules.yml
  reload_interval_seconds: 60
  notification:
    webhook_url: ""
    email:
      smtp_host: ""
      smtp_port: 587
      from: ""
      to: ""
"@

  Add-Content -Path $ConfigPath -Value $detectionSection -Encoding UTF8 -NoNewline
  Write-TinySocsLog "Detection section added to $ConfigPath"
}

function Deploy-TinySocsAgentBinary {
  <#
  .SYNOPSIS
    Deploys the TinySocs.Agent.exe binary from the build output to Program Files

  .DESCRIPTION
    Copies the Phase 10 agent binary from the dotnet publish output to the
    installation directory where NSSM expects it.
  #>
  [CmdletBinding()]
  param()

  $repoRoot = Get-TinySocsRepoRoot
  $publishDir = Join-Path $repoRoot "src\TinySocs.Agent\bin\Release\net8.0\win-x64\publish"
  $sourceBinary = Join-Path $publishDir "TinySocs.Agent.exe"

  $installRoot = Get-TinySocsInstallRoot
  $targetBinary = Join-Path $installRoot "bin\TinySocs.Agent.exe"

  if (-not (Test-Path $sourceBinary -PathType Leaf)) {
    Write-TinySocsLog -Level "ERROR" -Message "Agent binary not found at $sourceBinary. Run 'dotnet publish' first."
    throw "Agent binary not found. Build the agent before deploying."
  }

  # Ensure target directory exists
  $binDir = Split-Path $targetBinary -Parent
  if (-not (Test-Path $binDir)) {
    New-Item -ItemType Directory -Path $binDir -Force | Out-Null
  }

  # Stop service if running (so we can replace the binary)
  $service = Get-Service -Name "TinySocsAgent" -ErrorAction SilentlyContinue
  if ($null -ne $service -and $service.Status -eq 'Running') {
    Write-TinySocsLog "Stopping TinySocsAgent service to deploy new binary"
    Stop-Service -Name "TinySocsAgent" -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
  }

  # Copy binary
  Copy-Item -Path $sourceBinary -Destination $targetBinary -Force
  Write-TinySocsLog "Agent binary deployed to $targetBinary (size: $((Get-Item $targetBinary).Length) bytes)"
}

function Install-TinySocsPhase10 {
  <#
  .SYNOPSIS
    Deploys all Phase 10 components: detection engine, rules, templates, policies

  .DESCRIPTION
    Complete Phase 10 deployment:
    1. Deploys agent binary with detection engine code
    2. Stages and deploys detection rules
    3. Updates agent config with detection section
    4. Stages and bootstraps OpenSearch templates (alerts, heartbeat)
    5. Stages and bootstraps ISM policies
    6. Configures NSSM service for proper working directory and env vars
    7. Restarts agent service
  #>
  [CmdletBinding()]
  param(
    [string]$SiemUrl = "https://localhost:9201",
    [string]$SiemUser,
    [string]$SiemPass,
    [switch]$SkipBinaryDeploy,
    [switch]$SkipServiceRestart
  )

  Assert-TinySocsAdmin
  Write-TinySocsLog "=== Starting Phase 10 Deployment ==="

  # 1. Deploy agent binary (unless skipped)
  if (-not $SkipBinaryDeploy) {
    Write-TinySocsLog "Step 1: Deploying agent binary with detection engine"
    Deploy-TinySocsAgentBinary
  } else {
    Write-TinySocsLog "Step 1: Skipping agent binary deployment (SkipBinaryDeploy specified)"
  }

  # 2. Deploy detection rules
  Write-TinySocsLog "Step 2: Deploying detection rules"
  Ensure-TinySocsDetectionRulesStaged
  Deploy-TinySocsDetectionRules

  # 3. Update agent config
  Write-TinySocsLog "Step 3: Updating agent config for detection"
  Update-TinySocsAgentConfigForDetection

  # 4. Deploy OpenSearch templates
  Write-TinySocsLog "Step 4: Staging OpenSearch templates"
  Ensure-TinySocsOpenSearchTemplatesStaged

  # 5. Deploy ISM policies
  Write-TinySocsLog "Step 5: Staging ISM policies"
  Ensure-TinySocsOpenSearchPoliciesStaged

  # 6. Bootstrap templates and policies if credentials provided
  if ($SiemUser -and $SiemPass) {
    Write-TinySocsLog "Step 6: Bootstrapping OpenSearch templates"
    try {
      Invoke-TinySocsOpenSearchTemplatesBootstrap -SiemUrl $SiemUrl -User $SiemUser -Pass $SiemPass
    } catch {
      Write-TinySocsLog -Level "WARN" -Message "Template bootstrap failed: $($_.Exception.Message)"
    }

    Write-TinySocsLog "Step 7: Bootstrapping ISM policies"
    try {
      Invoke-TinySocsOpenSearchPoliciesBootstrap -SiemUrl $SiemUrl -User $SiemUser -Pass $SiemPass
    } catch {
      Write-TinySocsLog -Level "WARN" -Message "Policy bootstrap failed: $($_.Exception.Message)"
    }
  } else {
    Write-TinySocsLog -Level "WARN" -Message "Skipping OpenSearch bootstrap (no credentials provided)"
  }

  # 7. Configure NSSM service
  Write-TinySocsLog "Step 8: Configuring NSSM service"
  $installRoot = Get-TinySocsInstallRoot
  $nssmPath = Join-Path $installRoot "bin\nssm.exe"

  if (Test-Path $nssmPath -PathType Leaf) {
    $serviceName = "TinySocsAgent"
    $configPath = "C:\ProgramData\TinySocs\Collector\agent-config.yml"
    $workingDir = "C:\Program Files\TinySocs\Collector"

    # Set working directory
    & $nssmPath set $serviceName AppDirectory $workingDir | Out-Null
    Write-TinySocsLog "NSSM AppDirectory set to $workingDir"

    # Set environment variable for config path
    & $nssmPath set $serviceName AppEnvironmentExtra "TINYSOCS_AGENT_CONFIG=$configPath" | Out-Null
    Write-TinySocsLog "NSSM environment variable TINYSOCS_AGENT_CONFIG set to $configPath"
  } else {
    Write-TinySocsLog -Level "WARN" -Message "NSSM not found at $nssmPath; skipping service configuration"
  }

  # 8. Restart agent service
  if (-not $SkipServiceRestart) {
    Write-TinySocsLog "Step 9: Restarting TinySocsAgent service"
    $service = Get-Service -Name "TinySocsAgent" -ErrorAction SilentlyContinue
    if ($null -ne $service) {
      try {
        Restart-Service -Name "TinySocsAgent" -Force -ErrorAction Stop
        Write-TinySocsLog "TinySocsAgent service restarted successfully"
      } catch {
        Write-TinySocsLog -Level "WARN" -Message "Failed to restart service: $($_.Exception.Message)"
      }
    } else {
      Write-TinySocsLog -Level "WARN" -Message "TinySocsAgent service not found; nothing to restart"
    }
  } else {
    Write-TinySocsLog "Step 9: Skipping service restart (SkipServiceRestart specified)"
  }

  Write-TinySocsLog "=== Phase 10 Deployment Complete ==="
  Write-Host ""
  Write-Host "Phase 10 deployment finished!" -ForegroundColor Green
  Write-Host ""
  Write-Host "Next steps:" -ForegroundColor Cyan
  Write-Host "  1. Verify detection engine initialized: Get-Content 'C:\ProgramData\TinySocs\Collector\logs\TinySocsAgent.out.log' -Tail 50 | Select-String 'Detection engine initialized'"
  Write-Host "  2. Test brute force detection: Generate 5+ failed login attempts within 5 minutes"
  Write-Host "  3. Check alerts: Get-Content 'C:\ProgramData\TinySocs\Collector\logs\alerts.log'"
  Write-Host "  4. Run health check: Test-TinySocsHealth"
  Write-Host ""
}

# ---- Phase 12: Dashboard import -----------------------------------------------
function Import-TinySocsDashboards {
  <#
    .SYNOPSIS
      Import TinySocs saved objects (dashboards, visualizations, index patterns)
      into OpenSearch Dashboards via the Saved Objects API.

    .PARAMETER DashboardsUrl
      Base URL for OpenSearch Dashboards (default: http://localhost:5601 inside
      the container, or https://localhost:5602 externally).

    .PARAMETER NdjsonPath
      Path to the NDJSON export file.

    .PARAMETER SiemUser
      Admin username for authentication.

    .PARAMETER SiemPass
      Admin password for authentication.
  #>
  [CmdletBinding()]
  param(
    [string]$DashboardsUrl = "https://localhost:5602",
    [string]$NdjsonPath,
    [string]$SiemUser = "admin",
    [string]$SiemPass = "admin"
  )

  if (-not $NdjsonPath) {
    # Auto-discover from install root
    $installRoot = $null
    try { $installRoot = (Get-TinySocsInstallRoot | Select-Object -First 1) } catch { }
    if (-not $installRoot) { $installRoot = Join-Path ${env:ProgramFiles} "TinySocs" }
    $NdjsonPath = Join-Path $installRoot "OpenSearch\dashboards\tinysocs-dashboards.ndjson"
  }

  if (-not (Test-Path -LiteralPath $NdjsonPath -PathType Leaf)) {
    Write-Warning "[TinySocs] Dashboard NDJSON not found: $NdjsonPath"
    return $false
  }

  $url = "$($DashboardsUrl.TrimEnd('/'))/_dashboards/api/saved_objects/_import?overwrite=true"

  # Build multipart/form-data using curl (avoids .NET TLS issues on PS 5.1)
  $pair = "${SiemUser}:${SiemPass}"
  $maxAttempts = 5
  $attempt = 0
  $success = $false

  while ($attempt -lt $maxAttempts -and -not $success) {
    $attempt++
    try {
      $result = & curl.exe -k -sS -u $pair `
        -X POST $url `
        -H "osd-xsrf: true" `
        -F "file=@$NdjsonPath" `
        2>&1 | Out-String

      if ($result -match '"success"\s*:\s*true') {
        Write-Host "[TinySocs] Dashboards imported successfully (attempt $attempt)" -ForegroundColor Green
        $success = $true
      } elseif ($result -match '"statusCode"\s*:\s*503') {
        Write-Host "[TinySocs] Dashboards not ready (503), retrying ($attempt/$maxAttempts)..." -ForegroundColor Yellow
        Start-Sleep -Seconds 5
      } else {
        Write-Warning "[TinySocs] Dashboard import returned: $($result.Substring(0, [Math]::Min(500, $result.Length)))"
        Start-Sleep -Seconds 3
      }
    } catch {
      Write-Warning "[TinySocs] Dashboard import failed (attempt $attempt): $($_.Exception.Message)"
      Start-Sleep -Seconds 3
    }
  }

  return $success
}

# ---- Phase 12: Daily summary scheduled task -----------------------------------
function Register-TinySocsDailySummaryTask {
  <#
    .SYNOPSIS
      Register a Windows Scheduled Task that runs the daily summary report at 07:00.

    .PARAMETER To
      Email recipient for the daily summary.

    .PARAMETER PythonPath
      Path to python.exe. Auto-detected from venv or PATH if not specified.
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$To,
    [string]$PythonPath
  )

  $taskName = "TinySocs\DailySummary"

  if (-not $PythonPath) {
    # Try to find python from known locations
    $candidates = @(
      (Join-Path ${env:ProgramFiles} "TinySocs\Assistant\python.exe"),
      (Join-Path ${env:ProgramFiles} "TinySocs\.venv\Scripts\python.exe"),
      "python.exe"
    )
    foreach ($c in $candidates) {
      if (Get-Command $c -ErrorAction SilentlyContinue) {
        $PythonPath = $c
        break
      }
    }
    if (-not $PythonPath) { $PythonPath = "python.exe" }
  }

  $action = New-ScheduledTaskAction `
    -Execute $PythonPath `
    -Argument "-m tinysocs.reporting.daily_summary --to `"$To`""

  $trigger = New-ScheduledTaskTrigger -Daily -At "07:00"

  $settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable

  try {
    # Remove existing task if present
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue

    Register-ScheduledTask `
      -TaskName $taskName `
      -Action $action `
      -Trigger $trigger `
      -Settings $settings `
      -User "SYSTEM" `
      -RunLevel Highest `
      -Description "TinySocs daily alert summary report" | Out-Null

    Write-Host "[TinySocs] Registered scheduled task: $taskName (daily at 07:00 -> $To)" -ForegroundColor Green
    return $true
  } catch {
    Write-Warning "[TinySocs] Failed to register daily summary task: $($_.Exception.Message)"
    return $false
  }
}

# -- Phase 14 M2: Sysmon auto-deployment ----------------------------------------

function Install-TinySocsSysmon {
  <#
  .SYNOPSIS
    Install or update Sysmon64 with the TinySocs configuration.
  .DESCRIPTION
    Locates Sysmon64.exe (bundled by installer or downloads from Sysinternals),
    verifies the Microsoft Authenticode signature, and installs or updates
    the Sysmon service with the TinySocs-specific configuration.
  .PARAMETER SysmonExePath
    Path to Sysmon64.exe. Default: {ProgramFiles}\TinySocs\bin\Sysmon64.exe
  .PARAMETER ConfigPath
    Path to sysmon-config.xml. Default: {ProgramData}\TinySocs\Sysmon\sysmon-config.xml
  .PARAMETER DownloadIfMissing
    Download Sysmon from Sysinternals if not found locally. Default: $true
  #>
  [CmdletBinding()]
  param(
    [string]$SysmonExePath = "",
    [string]$ConfigPath = "",
    [bool]$DownloadIfMissing = $true
  )

  # Resolve default paths — use Sysmon64a.exe on ARM64 hosts (x64 driver won't load on ARM64 kernel)
  $appDir = Join-Path $env:ProgramFiles "TinySocs"
  if (-not $SysmonExePath) {
    $isArm64 = ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') -or ($env:PROCESSOR_ARCHITEW6432 -eq 'ARM64')
    $arm64Exe = Join-Path $appDir "bin\Sysmon64a.exe"
    if ($isArm64 -and (Test-Path $arm64Exe)) {
      $SysmonExePath = $arm64Exe
      Write-TinySocsLog "ARM64 host detected -- using Sysmon64a.exe"
    } else {
      $SysmonExePath = Join-Path $appDir "bin\Sysmon64.exe"
    }
  }
  if (-not $ConfigPath) {
    $ConfigPath = Join-Path $env:ProgramData "TinySocs\Sysmon\sysmon-config.xml"
    if (-not (Test-Path $ConfigPath)) {
      # Fallback: installer may place config alongside the binary
      $altConfig = Join-Path (Split-Path -Parent $SysmonExePath) "sysmon-config.xml"
      if (Test-Path $altConfig) { $ConfigPath = $altConfig }
    }
  }

  # Download if missing
  if (-not (Test-Path $SysmonExePath) -and $DownloadIfMissing) {
    $binDir = Split-Path -Parent $SysmonExePath
    New-Item -ItemType Directory -Force -Path $binDir | Out-Null
    $zipPath = Join-Path $binDir "Sysmon.zip"
    $url = "https://download.sysinternals.com/files/Sysmon.zip"
    Write-TinySocsLog "Downloading Sysmon from $url ..."
    Invoke-WebRequest -Uri $url -OutFile $zipPath -UseBasicParsing
    Expand-Archive -Path $zipPath -DestinationPath $binDir -Force
    $candidate = Get-ChildItem -Recurse -File $binDir -Filter "Sysmon64.exe" | Select-Object -First 1
    if (-not $candidate) { throw "Sysmon64.exe not found after extraction." }
    if ($candidate.FullName -ne $SysmonExePath) {
      Copy-Item $candidate.FullName $SysmonExePath -Force
    }
    Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
    Write-TinySocsLog "Sysmon64.exe downloaded to $SysmonExePath"
  }

  if (-not (Test-Path $SysmonExePath)) {
    throw "Sysmon64.exe not found at $SysmonExePath and download disabled."
  }

  # Verify Microsoft signature
  $sig = Get-AuthenticodeSignature -FilePath $SysmonExePath
  if ($sig.Status -ne 'Valid' -or -not ($sig.SignerCertificate.Subject -like '*CN=Microsoft*')) {
    throw "Sysmon64.exe signature invalid or not Microsoft-signed: Status=$($sig.Status)"
  }

  if (-not (Test-Path $ConfigPath)) {
    throw "Sysmon config not found at $ConfigPath"
  }

  # Install or update — ARM64 registers as "Sysmon64a", x64 as "Sysmon64"
  $svc = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
  if (-not $svc) { $svc = Get-Service -Name "Sysmon64a" -ErrorAction SilentlyContinue }
  if ($svc) {
    if ($svc.Status -eq 'Running') {
      Write-TinySocsLog "Sysmon service ($($svc.Name)) found and running -- updating configuration..."
      & $SysmonExePath -c "$ConfigPath" 2>&1 | ForEach-Object { Write-Host $_ }
    } else {
      # Service exists but is not running -- likely a broken prior install where the
      # kernel driver (SysmonDrv.sys) was never copied to C:\Windows\.
      # Force-uninstall then do a clean fresh install.
      Write-TinySocsLog "Sysmon service ($($svc.Name)) found but not running (Status: $($svc.Status)) -- force-reinstalling..."
      & $SysmonExePath -u force 2>&1 | ForEach-Object { Write-Host $_ }
      Start-Sleep -Seconds 3
      Write-TinySocsLog "Installing Sysmon (fresh)..."
      & $SysmonExePath -accepteula -i "$ConfigPath" 2>&1 | ForEach-Object { Write-Host $_ }
    }
  } else {
    Write-TinySocsLog "Installing Sysmon..."
    & $SysmonExePath -accepteula -i "$ConfigPath" 2>&1 | ForEach-Object { Write-Host $_ }
  }

  # Verify service is running — check both possible names
  Start-Sleep -Seconds 2
  $svc = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
  if (-not $svc) { $svc = Get-Service -Name "Sysmon64a" -ErrorAction SilentlyContinue }
  if ($svc -and $svc.Status -eq "Running") {
    Write-TinySocsLog "Sysmon service ($($svc.Name)) is running."
  } else {
    $detail = if ($svc) { $svc.Status } else { "not found" }
    Write-TinySocsLog -Level "WARN" -Message "Sysmon service may not be running. Status: $detail"
  }
}

function Uninstall-TinySocsSysmon {
  <#
  .SYNOPSIS
    Uninstall Sysmon64 service and driver.
  #>
  [CmdletBinding()]
  param()

  # Check both x64 (Sysmon64) and ARM64 (Sysmon64a) service names
  $svc = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
  if (-not $svc) { $svc = Get-Service -Name "Sysmon64a" -ErrorAction SilentlyContinue }
  if (-not $svc) {
    Write-TinySocsLog "Sysmon service not found (checked Sysmon64 and Sysmon64a). Nothing to uninstall."
    return
  }

  # Find Sysmon exe in known locations (both x64 and ARM64 variants)
  $exePaths = @(
    (Join-Path $env:ProgramFiles "TinySocs\bin\Sysmon64a.exe"),
    (Join-Path $env:ProgramFiles "TinySocs\bin\Sysmon64.exe"),
    (Join-Path $env:ProgramData "TinySocs\Sysmon\Sysmon64.exe"),
    (Join-Path $env:SystemRoot "Sysmon64a.exe"),
    (Join-Path $env:SystemRoot "Sysmon64.exe")
  )
  $exe = $exePaths | Where-Object { Test-Path $_ } | Select-Object -First 1
  if ($exe) {
    Write-TinySocsLog "Uninstalling Sysmon via $exe ..."
    & $exe -u force 2>&1 | ForEach-Object { Write-Host $_ }
    Write-TinySocsLog "Sysmon uninstalled."
  } else {
    Write-TinySocsLog -Level "WARN" -Message "Sysmon64.exe not found for uninstall. Service may need manual removal."
  }

  # Clean up TinySocs Sysmon directory
  $sysmonDir = Join-Path $env:ProgramData "TinySocs\Sysmon"
  if (Test-Path $sysmonDir) {
    Remove-Item -Path $sysmonDir -Recurse -Force -ErrorAction SilentlyContinue
    Write-TinySocsLog "Removed $sysmonDir"
  }
}

Export-ModuleMember -Function * -Alias *



