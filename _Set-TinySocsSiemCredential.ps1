
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

