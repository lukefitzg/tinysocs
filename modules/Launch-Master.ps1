param(
  [string]$window   = "15m",
  [int]   $deadline = 30,
  [string]$rules    = "auth_failed_burst,ps_script_block",

  # Optional mode for scheduled task usage:
  [switch]$Heartbeat
)

function Write-TS([string]$msg) {
  try { Write-Host "[TinySocs] Launch-Master: $msg" } catch { }
}

function Get-TSBoolFromAny($value, [bool]$default = $false) {
  if ($null -eq $value) { return $default }
  try {
    if ($value -is [bool]) { return [bool]$value }

    if ($value -is [string]) {
      $s = $value.Trim()
      $tmp = $null
      if ([bool]::TryParse($s, [ref]$tmp)) { return [bool]$tmp }
      if ($s -eq "1") { return $true }
      if ($s -eq "0") { return $false }
      return $default
    }

    return [bool]$value
  } catch {
    return $default
  }
}

function Test-TSLocalUrl([string]$url) {
  if ([string]::IsNullOrWhiteSpace($url)) { return $false }
  try {
    $u = [Uri]$url
    $host = ""
    try { $host = [string]$u.Host } catch { $host = "" }
    $host = $host.ToLowerInvariant()
    return ($host -eq "127.0.0.1" -or $host -eq "localhost")
  } catch {
    return $false
  }
}

function Resolve-TSPath([string]$p) {
  if ([string]::IsNullOrWhiteSpace($p)) { return $null }
  try {
    $pp = $p.Trim()
    # strip surrounding quotes if present
    if (($pp.StartsWith('"') -and $pp.EndsWith('"')) -or ($pp.StartsWith("'") -and $pp.EndsWith("'"))) {
      $pp = $pp.Substring(1, $pp.Length - 2)
    }
    $pp = [Environment]::ExpandEnvironmentVariables($pp)

    try {
      $ri = Resolve-Path -LiteralPath $pp -ErrorAction Stop
      return [string]$ri.Path
    } catch {
      # fall back to original expanded path
      return $pp
    }
  } catch {
    return $p
  }
}

function Test-TSFileLooksPem([string]$path) {
  if (-not (Test-Path -LiteralPath $path)) { return $false }
  try {
    $head = Get-Content -LiteralPath $path -TotalCount 5 -ErrorAction Stop
    $txt = ($head -join "`n")
    return ($txt -match "BEGIN CERTIFICATE")
  } catch {
    # If it's binary/DER, Get-Content may throw depending on encoding -> treat as not-PEM
    return $false
  }
}

function Convert-TSCerToPem([string]$cerPath, [string]$pemPath) {
  if (-not (Test-Path -LiteralPath $cerPath)) { throw "CER not found: $cerPath" }
  $dir = Split-Path -Parent $pemPath
  if ($dir -and (-not (Test-Path -LiteralPath $dir))) {
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
  }

  # Use certutil to encode DER -> PEM (safe under SYSTEM)
  $null = & certutil -encode $cerPath $pemPath 2>&1
  if (-not (Test-Path -LiteralPath $pemPath)) {
    throw "certutil -encode did not produce PEM at: $pemPath"
  }

  if (-not (Test-TSFileLooksPem $pemPath)) {
    throw "PEM sanity check failed (missing BEGIN CERTIFICATE): $pemPath"
  }
}

function Normalize-TSUrlLocalhost([string]$url) {
  if ([string]::IsNullOrWhiteSpace($url)) { return $url }
  try {
    $u = [Uri]$url
    if ($u.Scheme -ne "https") { return $url }
    if ($u.Host -ne "127.0.0.1") { return $url }

    # honor explicit opt-out
    if (-not [string]::IsNullOrWhiteSpace($env:TINYSOCS_NO_URL_REWRITE)) {
      $b = Get-TSBoolFromAny $env:TINYSOCS_NO_URL_REWRITE $false
      if ($b) { return $url }
    }

    $ub = New-Object System.UriBuilder($u)
    $ub.Host = "localhost"
    return $ub.Uri.AbsoluteUri
  } catch {
    return $url
  }
}

# Resolve install root relative to this script if possible
$installRoot = $null
try {
  if ($PSScriptRoot -and (Test-Path -LiteralPath $PSScriptRoot)) {
    # script usually lives in ...\TinySocs\modules
    $parent = Split-Path $PSScriptRoot -Parent
    if ($parent -and (Test-Path -LiteralPath (Join-Path $parent "bin"))) {
      $installRoot = $parent
    }
  }
} catch {
  $installRoot = $null
}

if (-not $installRoot) {
  $installRoot = Join-Path $env:ProgramFiles "TinySocs"
}

$installerModule = Join-Path $installRoot "modules\TinySocs.Installer.psm1"
if (Test-Path -LiteralPath $installerModule) {
  try {
    Import-Module $installerModule -Force -DisableNameChecking -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
  } catch {
    Write-Warning "[TinySocs] Launch-Master: failed to import TinySocs.Installer.psm1: $($_.Exception.Message)"
  }
} else {
  Write-TS "Installer module not found at $installerModule (continuing without CredMan hydration)."
}

# Hydrate secrets from CredMan if helpers are available
$siemCaPath = $null

if (Get-Command Get-TSCredential -ErrorAction SilentlyContinue) {
  try {
    $shared = Get-TSCredential -Name 'TinySocs/Master/SharedSecret'
    if ($shared) { $env:MASTER_SHARED_SECRET = [string]$shared }

    $rawSiem = Get-TSCredential -Name 'TinySocs/SIEM/Creds'
    if ($rawSiem) {
      $siem = $null
      try {
        $siem = $rawSiem | ConvertFrom-Json
      } catch {
        Write-Warning "[TinySocs] Launch-Master: failed to parse TinySocs/SIEM/Creds JSON: $($_.Exception.Message)"
      }

      if ($siem) {
        # IMPORTANT: CredMan wins. Always overwrite env if the property exists.
        if ($siem.PSObject.Properties.Name -contains 'url'  -and $siem.url)  {
          $prev = $env:SIEM_URL
          $env:SIEM_URL  = [string]$siem.url
          if ($prev -and ($prev -ne $env:SIEM_URL)) { Write-TS "CredMan override: SIEM_URL '$prev' -> '$($env:SIEM_URL)'" }
        }
        if ($siem.PSObject.Properties.Name -contains 'user' -and $siem.user) {
          $prev = $env:SIEM_USER
          $env:SIEM_USER = [string]$siem.user
          if ($prev -and ($prev -ne $env:SIEM_USER)) { Write-TS "CredMan override: SIEM_USER '$prev' -> '$($env:SIEM_USER)'" }
        }
        if ($siem.PSObject.Properties.Name -contains 'pass' -and $siem.pass) {
          # do not log password changes
          $env:SIEM_PASS = [string]$siem.pass
        }

        # Pick up CA bundle path (support both keys)
        if ($siem.PSObject.Properties.Name -contains 'caBundlePath' -and $siem.caBundlePath) {
          $siemCaPath = [string]$siem.caBundlePath
        } elseif ($siem.PSObject.Properties.Name -contains 'ca_bundle_path' -and $siem.ca_bundle_path) {
          $siemCaPath = [string]$siem.ca_bundle_path
        }

        # SIEM_SSL_VERIFY from CredMan if present (CredMan wins)
        if ($siem.PSObject.Properties.Name -contains 'sslVerify') {
          $sv = Get-TSBoolFromAny $siem.sslVerify $false
          $env:SIEM_SSL_VERIFY = $(if ($sv) { "true" } else { "false" })
        } elseif ($siem.PSObject.Properties.Name -contains 'ssl_verify') {
          $sv2 = Get-TSBoolFromAny $siem.ssl_verify $false
          $env:SIEM_SSL_VERIFY = $(if ($sv2) { "true" } else { "false" })
        }
      }
    }
  } catch {
    Write-Warning "[TinySocs] Launch-Master: CredMan hydration failed: $($_.Exception.Message)"
  }
}

# If SIEM_SSL_VERIFY still not set, choose a sane default:
# - localhost/127.0.0.1 with https: default to false (self-signed dev cert is common)
# - otherwise: default to true
if ([string]::IsNullOrWhiteSpace($env:SIEM_SSL_VERIFY)) {
  $isLocal = Test-TSLocalUrl $env:SIEM_URL
  if ($isLocal) {
    $env:SIEM_SSL_VERIFY = "false"
    Write-TS "SIEM_SSL_VERIFY not set; SIEM_URL appears local -> defaulting to false."
  } else {
    $env:SIEM_SSL_VERIFY = "true"
    Write-TS "SIEM_SSL_VERIFY not set; defaulting to true."
  }
}

# If SIEM_URL is https://127.0.0.1:* rewrite to https://localhost:* (common cert mismatch)
if (-not [string]::IsNullOrWhiteSpace($env:SIEM_URL)) {
  $origUrl = [string]$env:SIEM_URL
  $normUrl = Normalize-TSUrlLocalhost $origUrl
  if ($normUrl -and ($normUrl -ne $origUrl)) {
    $env:SIEM_URL = $normUrl
    Write-TS "Rewrote SIEM_URL: $origUrl -> $normUrl"
  }
}

# Normalize CA path; if it's DER (.cer) convert to PEM so requests/curl/OpenSSL are happy.
$siemCaPath = Resolve-TSPath $siemCaPath

if (-not [string]::IsNullOrWhiteSpace($siemCaPath)) {
  try {
    if (Test-Path -LiteralPath $siemCaPath) {

      $finalCaPath = $siemCaPath

      # If the file doesn't look like PEM, convert it to PEM next to the original (or in ProgramData certs as fallback)
      $looksPem = Test-TSFileLooksPem $finalCaPath
      if (-not $looksPem) {
        $baseDir = Split-Path -Parent $finalCaPath
        $baseName = [IO.Path]::GetFileNameWithoutExtension($finalCaPath)
        $pemOut = Join-Path $baseDir ($baseName + ".pem")

        try {
          Convert-TSCerToPem -cerPath $finalCaPath -pemPath $pemOut
          $finalCaPath = $pemOut
          Write-TS "Converted CA to PEM: $finalCaPath"
        } catch {
          # fallback: place PEM under ProgramData\TinySocs\certs
          $fallbackDir = Join-Path (Join-Path $env:ProgramData "TinySocs") "certs"
          $fallbackPem = Join-Path $fallbackDir "siem-ca.pem"
          Convert-TSCerToPem -cerPath $finalCaPath -pemPath $fallbackPem
          $finalCaPath = $fallbackPem
          Write-TS "Converted CA to PEM (fallback): $finalCaPath"
        }
      }

      # Export CA bundle path for common TLS stacks (requests/curl/OpenSSL)
      $env:SIEM_CA_BUNDLE     = $finalCaPath
      $env:REQUESTS_CA_BUNDLE = $finalCaPath
      $env:SSL_CERT_FILE      = $finalCaPath
      $env:CURL_CA_BUNDLE     = $finalCaPath

      Write-TS "Using CA bundle: $finalCaPath"

    } else {
      Write-Warning "[TinySocs] Launch-Master: CA bundle path from CredMan does not exist: $siemCaPath"
    }
  } catch {
    Write-Warning "[TinySocs] Launch-Master: failed to apply CA bundle path: $($_.Exception.Message)"
  }
} else {
  Write-TS "No CA bundle path provided (caBundlePath/ca_bundle_path missing or empty)."
}

# One loud summary line so the task log proves what the child saw
Write-TS ("EnvSummary: SIEM_URL={0} SIEM_SSL_VERIFY={1} SIEM_CA_BUNDLE={2} REQUESTS_CA_BUNDLE={3}" -f `
  $env:SIEM_URL, $env:SIEM_SSL_VERIFY, $env:SIEM_CA_BUNDLE, $env:REQUESTS_CA_BUNDLE)

$exe = Join-Path $installRoot "bin\TinySocsMaster.exe"
if (-not (Test-Path -LiteralPath $exe)) {
  Write-Error "[TinySocs] Launch-Master: TinySocsMaster.exe not found at $exe"
  exit 1
}

$logDir = Join-Path $env:ProgramData "TinySocs\logs"
if (-not (Test-Path -LiteralPath $logDir)) {
  New-Item -ItemType Directory -Force -Path $logDir | Out-Null
}

$logOut = Join-Path $logDir "TinySocsMaster.out.log"
$logErr = Join-Path $logDir "TinySocsMaster.err.log"

# Build args
$args = @("--window", $window, "--deadline", $deadline, "--rules", $rules)

if ($Heartbeat) {
  Write-TS "Heartbeat mode enabled (exit code normalization: treat 0 and 1 as success)."
}

try {
  & $exe @args 1>> $logOut 2>> $logErr

  $code = 0
  if ($LASTEXITCODE -ne $null) { $code = [int]$LASTEXITCODE }

  if ($Heartbeat -and ($code -in @(0, 1))) { $code = 0 }

  Write-TS "ExitCode=$code (raw=$LASTEXITCODE) exe=$exe"
  exit $code
}
catch {
  Write-TS "Exception: $($_.Exception.Message)"
  exit 1
}