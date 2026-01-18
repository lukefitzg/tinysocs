# Run-OpenSearch.ps1
# TinySocs OpenSearch wrapper for NSSM
# - Self-heals ProgramData config
# - Canonicalizes known bad config drift (jvm.options GC line + opensearch.yml duplicate key)
# - Enforces TLS keystore *_secure entries from DPAPI storepass (base64->DPAPI)
# - Avoids deadlocks when invoking opensearch-keystore.bat
# - Ensures opensearch-security config tree exists under ProgramData

$ErrorActionPreference = 'Stop'

# -----------------------
# Install roots (no guessing beyond "where TinySocs is installed")
# -----------------------
$script:TinySocsProgramFilesRoot = Join-Path ${env:ProgramFiles} 'TinySocs'
$script:TinySocsProgramDataRoot  = Join-Path ${env:ProgramData}  'TinySocs'

$script:OpenSearchRootPF         = Join-Path $script:TinySocsProgramFilesRoot 'OpenSearch'
$script:OpenSearchRootPD         = Join-Path $script:TinySocsProgramDataRoot  'OpenSearch'

$script:OpenSearchConfPD         = Join-Path $script:OpenSearchRootPD 'config'
$script:OpenSearchDataPD         = Join-Path $script:OpenSearchRootPD 'data'
$script:OpenSearchLogsPD         = Join-Path $script:OpenSearchRootPD 'logs'

# --- Wrapper log (so NSSM has *something* to show even when OpenSearch dies early) ---
$global:RunLogPrimary  = Join-Path $script:OpenSearchLogsPD 'Run-OpenSearch.wrapper.log'
$global:RunLogFallback = 'C:\Windows\Temp\Run-OpenSearch.wrapper.log'

function _WriteTextNoBom([string]$path, [string]$text) {
  $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
  [System.IO.File]::WriteAllText($path, $text, $utf8NoBom)
}

function _Touch-RunLog([string]$path) {
  try {
    $dir = Split-Path -Parent $path
    if (-not [string]::IsNullOrWhiteSpace($dir)) {
      New-Item -ItemType Directory -Force -Path $dir | Out-Null
    }
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
      _WriteTextNoBom $path ""
    }
  } catch { }
}

_Touch-RunLog $global:RunLogPrimary
_Touch-RunLog $global:RunLogFallback

function Write-RunLog([string]$msg) {
  $line = "[{0}] {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"), $msg

  $wrote = $false
  try {
    Add-Content -LiteralPath $global:RunLogPrimary -Value $line -Encoding UTF8
    $wrote = $true
  } catch { }

  if (-not $wrote) {
    try {
      _Touch-RunLog $global:RunLogFallback
      Add-Content -LiteralPath $global:RunLogFallback -Value $line -Encoding UTF8
      $wrote = $true
    } catch { }
  }

  try { Write-Host $line } catch { }
}

# -----------------------
# Helpers
# -----------------------
function _Ensure-Dir([string]$p) {
  if ([string]::IsNullOrWhiteSpace($p)) { return }
  try { New-Item -ItemType Directory -Force -Path $p | Out-Null } catch { }
}

function _Clear-ReadOnly([string]$path) {
  try {
    if (Test-Path -LiteralPath $path) {
      $item = Get-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
      if ($item -and ($item.Attributes -band [IO.FileAttributes]::ReadOnly)) {
        $item.Attributes = ($item.Attributes -bxor [IO.FileAttributes]::ReadOnly)
      }
    }
  } catch { }
}

function _Get-OpenSearchJavaProcesses {
  # Matches "our" OpenSearch JVMs; keep broad enough to be resilient
  $needle = 'org\.opensearch\.bootstrap\.OpenSearch|opensearch\.path\.home|opensearch\.path\.conf|\\TinySocs\\OpenSearch'
  try {
    Get-CimInstance Win32_Process -Filter "Name='java.exe'" -ErrorAction Stop |
      Where-Object { $_.CommandLine -match $needle }
  } catch {
    @()
  }
}

function _Remove-StaleLocks([string]$dataRoot) {
  if (-not (Test-Path $dataRoot -PathType Container)) {
    Write-RunLog "STAGE 0: data root not found (no lock cleanup): $dataRoot"
    return
  }

  Write-RunLog "STAGE 0: removing stale lock files under $dataRoot"
  try {
    Get-ChildItem -LiteralPath $dataRoot -Recurse -Force -ErrorAction SilentlyContinue |
      Where-Object { $_.Name -in @('node.lock','write.lock') } |
      ForEach-Object {
        try {
          _Clear-ReadOnly $_.FullName
          Remove-Item -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue
          Write-RunLog "STAGE 0: removed lock: $($_.FullName)"
        } catch {
          Write-RunLog "STAGE 0: WARN: failed removing lock $($_.FullName): $($_.Exception.Message)"
        }
      }
  } catch {
    Write-RunLog "STAGE 0: WARN: lock cleanup failed: $($_.Exception.Message)"
  }
}

function _Canonicalize-JvmOptionsGcLog(
  [string]$jvmOptionsPath,
  [string]$logsDir
) {
  if (-not (Test-Path $jvmOptionsPath -PathType Leaf)) { return }

  _Ensure-Dir $logsDir

  # Robust rule: remove ANY non-comment line containing "Xlog:gc" EXCEPT our canonical line,
  # then ensure EXACTLY ONE canonical line exists.
  $desired = "9-:-Xlog:gc*:file=logs/gc.log"

  try {
    $bytes = [System.IO.File]::ReadAllBytes($jvmOptionsPath)
    $changed = $false

    # Strip UTF-8 BOM if present
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
      $bytes = $bytes[3..($bytes.Length-1)]
      $changed = $true
      Write-RunLog "STAGE 0: stripped UTF-8 BOM from jvm.options"
    }

    $raw = [System.Text.Encoding]::UTF8.GetString($bytes)

    # Strip U+FEFF if present
    if ($raw.Length -gt 0 -and $raw[0] -eq [char]0xFEFF) {
      $raw = $raw.Substring(1)
      $changed = $true
      Write-RunLog "STAGE 0: stripped U+FEFF from jvm.options"
    }

    # Fix common mangled-first-line case: "?## JVM configuration"
    $lines0 = $raw -split "`r?`n", -1
    if ($lines0.Count -gt 0 -and $lines0[0] -match '^\?##') {
      $lines0[0] = $lines0[0].Substring(1)
      $raw = ($lines0 -join "`r`n")
      $changed = $true
      Write-RunLog "STAGE 0: removed leading '?' from jvm.options line 1"
    }

    $lines = $raw -split "`r?`n", -1

    $out = New-Object System.Collections.Generic.List[string]
    $removed = 0
    $haveDesired = $false

    foreach ($ln in $lines) {
      $t = $ln.Trim()
      $ts = $ln.TrimStart()

      if ($ts.StartsWith("#")) { $out.Add($ln); continue }

      if ($t -eq $desired) { $haveDesired = $true; $out.Add($ln); continue }

      if ($ts -match "Xlog:gc") { $removed++; $changed = $true; continue }

      $out.Add($ln)
    }

    if (-not $haveDesired) {
      $out.Add($desired)
      $changed = $true
    }

    $raw2 = ($out -join "`r`n").TrimEnd() + "`r`n"

    if ($changed -or ($raw2 -ne $raw)) {
      _Clear-ReadOnly $jvmOptionsPath
      _WriteTextNoBom $jvmOptionsPath $raw2
      Write-RunLog "STAGE 0: wrote jvm.options (UTF-8 no BOM) + canonicalized GC log (removed=$removed, desiredPresent=$haveDesired) -> $desired"
    } else {
      Write-RunLog "STAGE 0: jvm.options unchanged (GC line already canonical)"
    }
  } catch {
    Write-RunLog "STAGE 0: WARN: failed canonicalizing jvm.options GC log: $($_.Exception.Message)"
  }
}

function _Monitor-ExistingOpenSearch([int]$pid) {
  Write-RunLog "STAGE 0: existing OpenSearch JVM detected (pid=$pid). Not starting a second instance; entering monitor loop."

  while ($true) {
    try {
      $p = Get-Process -Id $pid -ErrorAction SilentlyContinue
      if (-not $p) {
        Write-RunLog "STAGE 0: existing OpenSearch JVM pid=$pid is gone; will proceed to launch."
        break
      }
    } catch { }

    # Optional health poke (non-fatal)
    try {
      $conn = Get-NetTCPConnection -LocalPort 9201 -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
      if ($conn) {
        Write-RunLog ("STAGE 0: OpenSearch appears listening on 9201 (owning pid={0})" -f $conn.OwningProcess)
      } else {
        Write-RunLog "STAGE 0: OpenSearch JVM exists but 9201 not listening (yet?)"
      }
    } catch { }

    Start-Sleep 30
  }
}

function _Try-ImportInstallerModule {
  $m1 = Join-Path $script:TinySocsProgramFilesRoot 'modules\TinySocs.Installer.psm1'
  $m2 = Join-Path $PSScriptRoot 'TinySocs.Installer.psm1'

  foreach ($m in @($m1, $m2) | Where-Object { $_ -and (Test-Path $_ -PathType Leaf) }) {
    try {
      Import-Module $m -Force -ErrorAction Stop
      Write-RunLog "Imported module: $m"
      return $true
    } catch {
      Write-RunLog "WARN: failed importing module $m : $($_.Exception.Message)"
    }
  }

  Write-RunLog "WARN: TinySocs.Installer.psm1 not imported (CredMan + DPAPI helpers may be unavailable)."
  return $false
}

# -----------------------
# Main
# -----------------------
$mutex = $null

try {
  Write-RunLog "Run-OpenSearch.ps1 starting (PID=$PID)."
  try { Write-RunLog ("User={0}  CWD={1}" -f ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name), (Get-Location).Path) } catch { }

  # Prevent concurrent overlapping starts (NSSM can re-enter quickly on crash/restart)
  try {
    $mutex = New-Object System.Threading.Mutex($false, "Global\TinySocsOpenSearch.RunMutex")
    if (-not $mutex.WaitOne([TimeSpan]::FromMinutes(5))) {
      throw "Timed out waiting for OpenSearch start mutex."
    }
    Write-RunLog "STAGE 0: acquired start mutex"
  } catch {
    Write-RunLog ("STAGE 0: FATAL: cannot acquire mutex: {0}" -f $_.Exception.Message)
    throw
  }

  try {
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $isSystem = $false
    try { $isSystem = ($id.IsSystem -or $id.Name -eq 'NT AUTHORITY\SYSTEM') } catch { }
    Write-RunLog ("Context: isSystem={0}" -f $isSystem)
  } catch { }

  $null = _Try-ImportInstallerModule

  # Always force ProgramData config (and keep NSSM AppEnvironmentExtra consistent)
  $env:OPENSEARCH_PATH_CONF = $script:OpenSearchConfPD
  Write-RunLog "OPENSEARCH_PATH_CONF=$($env:OPENSEARCH_PATH_CONF)"

  # --- STAGE 0: preflight (locks + log paths) ---
  try {
    Write-RunLog "STAGE 0: preflight starting"

    $osHome   = $script:OpenSearchRootPF
    $confDir  = $script:OpenSearchConfPD
    $dataDir  = $script:OpenSearchDataPD
    $logsDir  = $script:OpenSearchLogsPD

    _Ensure-Dir $confDir
    _Ensure-Dir $dataDir
    _Ensure-Dir $logsDir

    _Clear-ReadOnly $logsDir

    # Ensure GC log line is safe + canonical in ProgramData config
    $jvm = Join-Path $confDir 'jvm.options'
    if (Test-Path $jvm -PathType Leaf) {
      _Canonicalize-JvmOptionsGcLog -jvmOptionsPath $jvm -logsDir $logsDir
    } else {
      Write-RunLog "STAGE 0: jvm.options not present yet (will be restored in STAGE 1); GC log canonicalization deferred."
    }

    # Also scrub baseline Program Files jvm.options (defensive; stops re-poisoning when copied back)
    $jvmBase = Join-Path $osHome 'config\jvm.options'
    if (Test-Path $jvmBase -PathType Leaf) {
      _Canonicalize-JvmOptionsGcLog -jvmOptionsPath $jvmBase -logsDir $logsDir
    }

    $existing = @(_Get-OpenSearchJavaProcesses)
    if ($existing.Count -gt 0) {
      Write-RunLog ("STAGE 0: found {0} OpenSearch-like java.exe processes already running." -f $existing.Count)
      $pid0 = [int]$existing[0].ProcessId
      _Monitor-ExistingOpenSearch -pid $pid0
    } else {
      _Remove-StaleLocks -dataRoot (Join-Path $dataDir 'nodes')
    }

    Write-RunLog "STAGE 0: preflight complete"
  } catch {
    Write-RunLog ("STAGE 0: WARN: preflight encountered error: {0}" -f $_.Exception.Message)
    # Not fatal; proceed
  }

  # --- STAGE 1: Self-heal ProgramData config + canonicalize opensearch.yml (streaming; no Get-Content hang) ---
  try {
    Write-RunLog "STAGE 1: entering ProgramData config self-heal"

    $confDir  = $script:OpenSearchConfPD
    $osConf   = Join-Path $script:OpenSearchRootPF 'config'

    Write-RunLog "STAGE 1: confDir=$confDir"
    Write-RunLog "STAGE 1: osConf=$osConf"
    Write-RunLog ("STAGE 1: baseline jvm.options exists? {0}" -f (Test-Path (Join-Path $osConf 'jvm.options') -PathType Leaf))
    Write-RunLog ("STAGE 1: baseline log4j2.properties exists? {0}" -f (Test-Path (Join-Path $osConf 'log4j2.properties') -PathType Leaf))

    $mustHave = @('jvm.options','log4j2.properties')

    foreach ($f in $mustHave) {
      $dst = Join-Path $confDir $f
      Write-RunLog "STAGE 1: ensuring $f -> $dst"

      try {
        if (Test-Path $dst -PathType Container) {
          Write-RunLog "Found poisoned directory at $dst; removing."
          Remove-Item -Recurse -Force -LiteralPath $dst -ErrorAction SilentlyContinue
        }
      } catch { }

      if (-not (Test-Path $dst -PathType Leaf)) {
        $src = Join-Path $osConf $f
        if (Test-Path $src -PathType Leaf) {
          try {
            New-Item -ItemType Directory -Force -Path (Split-Path -Parent $dst) | Out-Null
            Copy-Item -Force -LiteralPath $src -Destination $dst -ErrorAction Stop
            Write-RunLog "Restored $f into ProgramData config."
          } catch {
            Write-RunLog "WARN: failed restoring $f into ProgramData config: $($_.Exception.Message)"
          }
        } else {
          Write-RunLog "WARN: baseline $f not found at $src"
        }
      } else {
        Write-RunLog "STAGE 1: $f already present."
      }
    }

    # Ensure opensearch-security tree exists in ProgramData (this is what stops "Security not initialized" loops)
    try {
      $secSrc = Join-Path $osConf 'opensearch-security'
      $secDst = Join-Path $confDir 'opensearch-security'

      if (Test-Path $secSrc -PathType Container) {
        _Ensure-Dir $secDst

        $secFiles = @(
          'config.yml',
          'internal_users.yml',
          'roles.yml',
          'roles_mapping.yml',
          'action_groups.yml',
          'tenants.yml',
          'nodes_dn.yml'
        )

        foreach ($sf in $secFiles) {
          $s = Join-Path $secSrc $sf
          $d = Join-Path $secDst $sf

          if (-not (Test-Path $d -PathType Leaf)) {
            if (Test-Path $s -PathType Leaf) {
              try {
                Copy-Item -Force -LiteralPath $s -Destination $d -ErrorAction Stop
                Write-RunLog "STAGE 1: restored opensearch-security\$sf into ProgramData config."
              } catch {
                Write-RunLog "STAGE 1: WARN: failed restoring opensearch-security\$sf : $($_.Exception.Message)"
              }
            } else {
              Write-RunLog "STAGE 1: WARN: baseline opensearch-security\$sf missing at $s"
            }
          }
        }

        # If destination exists but is empty-ish, copy everything else as a last-resort.
        try {
          $count = @(Get-ChildItem -LiteralPath $secDst -File -Force -EA SilentlyContinue).Count
          if ($count -eq 0) {
            Copy-Item -LiteralPath (Join-Path $secSrc '*') -Destination $secDst -Recurse -Force -EA SilentlyContinue
            Write-RunLog "STAGE 1: opensearch-security directory was empty; copied baseline tree."
          }
        } catch { }
      } else {
        Write-RunLog "STAGE 1: WARN: baseline opensearch-security directory missing at $secSrc"
      }
    } catch {
      Write-RunLog "STAGE 1: WARN: failed ensuring opensearch-security tree: $($_.Exception.Message)"
    }

    # safe, two-pass, streaming YAML canonicalizer (NO -f in its own internals)
    function _Canonicalize-OpenSearchYaml(
      [string]$path,
      [string]$dedupeKey = 'plugins.security.allow_default_init_securityindex',
      [string]$defaultVal = 'true'
    ) {
      if (-not (Test-Path $path -PathType Leaf)) { return }

      try {
        $fi = Get-Item -LiteralPath $path -ErrorAction Stop
        Write-RunLog ("STAGE 1: opensearch.yml size=" + $fi.Length + " bytes")

        $alwaysCanonIfBytesOver = 262144
        $needCanon = ($fi.Length -ge $alwaysCanonIfBytesOver)

        $keyEsc = [regex]::Escape($dedupeKey)
        $reKey  = New-Object System.Text.RegularExpressions.Regex(
          "^\s*$keyEsc\s*:\s*(.+?)\s*$",
          [System.Text.RegularExpressions.RegexOptions]::Compiled
        )

        $dir = Split-Path -Parent $path
        $tmp = Join-Path $dir ("opensearch.yml.tmp." + ([Guid]::NewGuid().ToString("N")))
        $bak = Join-Path $dir ("opensearch.yml.bak." + (Get-Date -Format "yyyyMMdd-HHmmss"))

        $foundVal = $null
        $keyCount = 0

        # ---- PASS 1: count occurrences + capture first value ----
        $sr1 = $null
        try {
          $fs1 = [System.IO.File]::Open($path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
          $sr1 = New-Object System.IO.StreamReader($fs1, $true)

          while (-not $sr1.EndOfStream) {
            $ln = $sr1.ReadLine()
            $m  = $reKey.Match($ln)
            if ($m.Success) {
              $keyCount++
              if ($keyCount -eq 1) {
                $foundVal = $m.Groups[1].Value.Trim()
              }
            }
          }
        }
        finally {
          try { if ($sr1) { $sr1.Close() } } catch { }
        }

        # If key already appears exactly once and we don't need general canonicalization, leave file alone.
        if (-not $needCanon -and $keyCount -eq 1) {
          Write-RunLog ("STAGE 1: opensearch.yml OK (keyCount=" + $keyCount + "); no canonicalization needed.")
          return
        }

        if ([string]::IsNullOrWhiteSpace($foundVal)) { $foundVal = $defaultVal }

        $utf8NoBom = New-Object System.Text.UTF8Encoding($false)

        # ---- PASS 2: write new file, dropping ALL occurrences of key; optionally compress blank runs ----
        $sr2 = $null
        $sw2 = $null
        try {
          $fs2 = [System.IO.File]::Open($path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
          $sr2 = New-Object System.IO.StreamReader($fs2, $true)
          $sw2 = New-Object System.IO.StreamWriter($tmp, $false, $utf8NoBom)

          $blankRun = 0

          while (-not $sr2.EndOfStream) {
            $ln = $sr2.ReadLine()

            if ([string]::IsNullOrWhiteSpace($ln)) {
              $blankRun++
              if ($needCanon -and $blankRun -gt 1) { continue }
            } else {
              $blankRun = 0
            }

            $m = $reKey.Match($ln)
            if ($m.Success) {
              # Drop ALL occurrences; we'll re-add exactly once at end
              continue
            }

            $sw2.WriteLine($ln)
          }

          # Always ensure the key exists exactly once at the end
          $sw2.WriteLine($dedupeKey + ": " + $foundVal)
        }
        finally {
          try { if ($sw2) { $sw2.Flush(); $sw2.Close() } } catch { }
          try { if ($sr2) { $sr2.Close() } } catch { }
        }

        try {
          Copy-Item -LiteralPath $path -Destination $bak -Force
          Move-Item -LiteralPath $tmp -Destination $path -Force
          Write-RunLog ("STAGE 1: canonicalized opensearch.yml (keyCount=" + $keyCount + ", kept='" + $foundVal + "', backup='" + $bak + "').")
        } catch {
          Write-RunLog ("STAGE 1: WARN: failed replacing opensearch.yml: " + $_.Exception.Message)
          try { Remove-Item -LiteralPath $tmp -Force -EA SilentlyContinue } catch { }
        }
      }
      catch {
        Write-RunLog ("STAGE 1: WARN: canonicalize opensearch.yml failed: " + $_.Exception.Message)
      }
    }

    $yml = Join-Path $confDir 'opensearch.yml'
    Write-RunLog "STAGE 1: checking opensearch.yml for duplicate allow_default_init_securityindex"
    if (Test-Path $yml -PathType Leaf) {
      _Canonicalize-OpenSearchYaml -path $yml -dedupeKey 'plugins.security.allow_default_init_securityindex' -defaultVal 'true'
    } else {
      Write-RunLog "WARN: opensearch.yml not found at $yml"
    }

    if (-not (Test-Path (Join-Path $confDir 'jvm.options') -PathType Leaf)) {
      throw "FATAL: jvm.options missing under OPENSEARCH_PATH_CONF=$confDir"
    }

    # Now that jvm.options is guaranteed, re-apply GC canonicalization (covers any re-copy from baseline)
    try {
      _Canonicalize-JvmOptionsGcLog -jvmOptionsPath (Join-Path $confDir 'jvm.options') -logsDir $script:OpenSearchLogsPD
    } catch { }

    Write-RunLog "STAGE 1: self-heal complete"
  } catch {
    throw
  }

  # --- STAGE 2: Java env ---
  try {
    Write-RunLog "STAGE 2: configuring Java env"
    $jdk = Join-Path $script:OpenSearchRootPF 'jdk'
    if (Test-Path $jdk -PathType Container) {
      $env:OPENSEARCH_JAVA_HOME = $jdk
      $env:JAVA_HOME = $jdk
      $env:Path = (Join-Path $jdk 'bin') + ';' + $env:Path
      Write-RunLog "JAVA_HOME=$jdk"
    } else {
      Write-RunLog "WARN: bundled JDK not found at $jdk"
    }
  } catch { }

  # --- STAGE 3: admin pass ---
  try {
    Write-RunLog "STAGE 3: resolving OPENSEARCH_INITIAL_ADMIN_PASSWORD"
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $isSystem = $false
    try { $isSystem = ($id.IsSystem -or $id.Name -eq 'NT AUTHORITY\SYSTEM') } catch { }

    if (-not $isSystem) {
      if (Get-Command Get-TSCredential -ErrorAction SilentlyContinue) {
        $raw = Get-TSCredential -Name 'TinySocs/SIEM/Creds'
        if ($raw) {
          $j = $raw | ConvertFrom-Json
          if ($j.pass) { $env:OPENSEARCH_INITIAL_ADMIN_PASSWORD = [string]$j.pass }
        }
      } else {
        Write-RunLog "STAGE 3: Get-TSCredential not available; skipping CredMan read."
      }
    } else {
      Write-RunLog "STAGE 3: skipping CredMan under SYSTEM; will use DPAPI admin pass fallback if needed."
    }
  } catch { }

  if ([string]::IsNullOrWhiteSpace($env:OPENSEARCH_INITIAL_ADMIN_PASSWORD)) {
    try {
      Write-RunLog "STAGE 3: admin password not set; trying DPAPI file fallback"
      $certsDir = Join-Path $script:OpenSearchConfPD 'certs'
      if (Get-Command Read-TinySocsSiemAdminPassFromDpapiFile -ErrorAction SilentlyContinue) {
        $p = Read-TinySocsSiemAdminPassFromDpapiFile -CertsDir $certsDir
        if ($p) {
          $env:OPENSEARCH_INITIAL_ADMIN_PASSWORD = [string]$p
          Write-RunLog ("STAGE 3: set admin password from module DPAPI reader (len={0})" -f $env:OPENSEARCH_INITIAL_ADMIN_PASSWORD.Length)
        }
      } else {
        Write-RunLog "STAGE 3: DPAPI admin-pass reader not available."
      }
    } catch { }
  }

  # --- STAGE 4: TLS self-heal (ONLY *_secure keys in keystore; NEVER non-secure names) ---
  try {
    Write-RunLog "STAGE 4: TLS self-heal starting"

    $confDir  = $script:OpenSearchConfPD
    $certsDir = Join-Path $confDir 'certs'
    $dp       = Join-Path $certsDir 'opensearch-tls-storepass.dpapi'
    $cfg      = Join-Path $confDir 'opensearch.yml'

    Write-RunLog "STAGE 4: certsDir=$certsDir"
    Write-RunLog "STAGE 4: dpapi storepass path (primary)=$dp"
    Write-RunLog ("STAGE 4: opensearch.yml exists? {0}" -f (Test-Path $cfg -PathType Leaf))

    function _Is-AsciiOnly([string]$s) {
      if ([string]::IsNullOrEmpty($s)) { return $true }
      foreach ($ch in $s.ToCharArray()) {
        if ([int]$ch -gt 127) { return $false }
      }
      return $true
    }

    function _Remove-PlaintextTlsYaml([string]$path) {
      if (-not (Test-Path $path -PathType Leaf)) { return }

      $c = Get-Content -LiteralPath $path -Raw

      $dropPlainRegexes = @(
        '^\s*plugins\.security\.ssl\.http\.(keystore|truststore)_password\s*:.*$',
        '^\s*plugins\.security\.ssl\.http\.keystore_keypassword\s*:.*$',
        '^\s*plugins\.security\.ssl\.transport\.(keystore|truststore)_password\s*:.*$',
        '^\s*plugins\.security\.ssl\.transport\.keystore_keypassword\s*:.*$'
      )

      $lines = $c -split "(?:`r`n|`n|`r)"
      $fixed = foreach ($ln in $lines) {
        $kill = $false
        foreach ($re in $dropPlainRegexes) {
          if ($ln -match $re) { $kill = $true; break }
        }
        if (-not $kill) { $ln }
      }

      $c2 = ($fixed -join "`r`n")

      if ($c2.Contains('__TINYSOCS_TLS_STOREPASS__')) {
        $c2 = [regex]::Replace($c2, "(?m)^.*__TINYSOCS_TLS_STOREPASS__.*$\r?\n?", "")
      }

      if ($c2 -ne $c) {
        _Clear-ReadOnly $path
        _WriteTextNoBom $path $c2
        Write-RunLog "Sanitized plaintext TLS keys/placeholders in opensearch.yml"
      }
    }

    # PATCH 2026-01-02/03:
    # - Use cmd.exe /d /s /c with correct quoting
    # - Read stdout/stderr via ReadToEndAsync tasks to avoid event-handler weirdness
    # - Keep timeout kill + always log exit code
    function _Invoke-OsKeystore(
      [string]$kbat,
      [string]$argLine,
      [string]$stdinText = $null,
      [string]$confPath = $env:OPENSEARCH_PATH_CONF,
      [int]$timeoutMs = 180000
    ) {
      if (-not (Test-Path $kbat -PathType Leaf)) { throw "opensearch-keystore.bat not found at $kbat" }
      if ([string]::IsNullOrWhiteSpace($argLine)) { throw "Keystore argLine is empty." }

      # Force create to be non-interactive in any environment quirks.
      if ($stdinText -eq $null -and ($argLine -match '^\s*create(\s|$)')) {
        $stdinText = "y`n`n`n"
      }

      # cmd.exe needs the classic: /c ""C:\Path With Spaces\tool.bat" args"
      $cmdArgs = '/d /s /c ""{0}" {1}"' -f $kbat, $argLine
      Write-RunLog ("Keystore exec: cmd.exe {0}" -f $cmdArgs)

      $psi = New-Object System.Diagnostics.ProcessStartInfo
      $psi.FileName               = $env:ComSpec
      $psi.Arguments              = $cmdArgs
      $psi.WorkingDirectory       = $script:OpenSearchRootPF
      $psi.UseShellExecute        = $false
      $psi.RedirectStandardInput  = $true
      $psi.RedirectStandardOutput = $true
      $psi.RedirectStandardError  = $true
      $psi.CreateNoWindow         = $true

      if (-not [string]::IsNullOrWhiteSpace($confPath)) {
        $psi.EnvironmentVariables["OPENSEARCH_PATH_CONF"] = $confPath
      }
      if (-not [string]::IsNullOrWhiteSpace($env:JAVA_HOME)) {
        $psi.EnvironmentVariables["JAVA_HOME"] = $env:JAVA_HOME
      }

      $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
      try {
        $psi.StandardOutputEncoding = $utf8NoBom
        $psi.StandardErrorEncoding  = $utf8NoBom
      } catch { }

      $p = New-Object System.Diagnostics.Process
      $p.StartInfo = $psi

      $t0 = Get-Date
      if (-not $p.Start()) { throw "Failed to start keystore process ($argLine)" }

      # Begin reading immediately so buffers never block.
      $outTask = $p.StandardOutput.ReadToEndAsync()
      $errTask = $p.StandardError.ReadToEndAsync()

      if ($stdinText -ne $null) {
        try {
          $stdinText = ($stdinText -replace [string][char]0xFEFF, '')
          $p.StandardInput.Write($stdinText)
        } catch {
          try { $p.StandardInput.WriteLine($stdinText) } catch { }
        }
      }
      try { $p.StandardInput.Close() } catch { }

      $timedOut = $false
      if (-not $p.WaitForExit($timeoutMs)) {
        $timedOut = $true
        Write-RunLog ("Keystore TIMEOUT after {0}ms: {1}" -f $timeoutMs, $argLine)
        try { $p.Kill($true) } catch { try { $p.Kill() } catch { } }
      }

      try { $p.WaitForExit() } catch { }

      # Gather outputs (best-effort)
      $stdout = ""
      $stderr = ""
      try { $stdout = $outTask.GetAwaiter().GetResult() } catch { }
      try { $stderr = $errTask.GetAwaiter().GetResult() } catch { }

      $elapsedMs = [int]((Get-Date) - $t0).TotalMilliseconds

      $r = [pscustomobject]@{
        ExitCode  = $p.ExitCode
        Stdout    = $stdout
        Stderr    = $stderr
        Args      = $argLine
        TimedOut  = $timedOut
        ElapsedMs = $elapsedMs
      }

      Write-RunLog ("Keystore exit code: {0} (elapsed={1}ms, timedOut={2}) for: {3}" -f $r.ExitCode, $r.ElapsedMs, $r.TimedOut, $argLine)

      $alwaysLog = ($argLine -match '^\s*(create|list|has-passwd)\b') -or $r.ExitCode -ne 0 -or $r.TimedOut
      if ($alwaysLog) {
        $se = ($r.Stderr -replace "\r?\n", " | ").Trim()
        $so = ($r.Stdout -replace "\r?\n", " | ").Trim()
        if (-not [string]::IsNullOrWhiteSpace($se)) { Write-RunLog ("Keystore stderr: {0}" -f $se) }
        if (-not [string]::IsNullOrWhiteSpace($so)) { Write-RunLog ("Keystore stdout: {0}" -f $so) }
      }

      if ($r.TimedOut) {
        throw "Keystore command timed out after ${timeoutMs}ms: $argLine"
      }

      return $r
    }

    function _Ensure-OpenSearchKeystoreTls([string]$storePass) {
      if ([string]::IsNullOrWhiteSpace($storePass)) { throw "TLS storepass is empty." }

      $storePass = ($storePass -replace [string][char]0xFEFF, '').Trim()
      if ([string]::IsNullOrWhiteSpace($storePass)) { throw "TLS storepass is empty after trimming/BOM-strip." }
      if (-not (_Is-AsciiOnly $storePass)) { throw "TLS storepass contains non-ASCII characters (refusing to write keystore entries)." }

      Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue | Out-Null

      $p12s = @(
        (Join-Path $certsDir "http.p12"),
        (Join-Path $certsDir "transport.p12"),
        (Join-Path $certsDir "trust.p12"),
        (Join-Path $certsDir "truststore.p12")
      ) | Where-Object { Test-Path $_ -PathType Leaf }

      if (-not $p12s -or $p12s.Count -eq 0) {
        throw "FATAL: No P12s found under $certsDir (expected http.p12 / transport.p12 / trust.p12 or truststore.p12)."
      }

      foreach ($p12 in $p12s) {
        try {
          $null = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
            $p12, $storePass,
            [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet
          )
          Write-RunLog "TLS preflight OK: password opens $(Split-Path -Leaf $p12)"
        } catch {
          throw "FATAL: TLS storepass does NOT open $p12. $($_.Exception.Message)"
        }
      }

      $osRoot = $script:OpenSearchRootPF
      $k      = Join-Path $osRoot 'bin\opensearch-keystore.bat'
      $ks     = Join-Path $env:OPENSEARCH_PATH_CONF 'opensearch.keystore'

      function _Rebuild-KeystoreUnprotected {
        $bak = Join-Path $env:OPENSEARCH_PATH_CONF ("opensearch.keystore.bak.{0}" -f (Get-Date -Format "yyyyMMdd-HHmmss"))
        try {
          if (Test-Path $ks -PathType Leaf) {
            Copy-Item -LiteralPath $ks -Destination $bak -Force
            Remove-Item -LiteralPath $ks -Force
            Write-RunLog "Backed up + removed existing keystore: $bak"
          }
        } catch {
          throw "Failed to backup/remove existing keystore at ${ks}: $($_.Exception.Message)"
        }

        $rCreate = _Invoke-OsKeystore -kbat $k -argLine "create -f" -timeoutMs 180000
        if (-not (Test-Path $ks -PathType Leaf)) {
          throw "Keystore create did not produce $ks (exit=$($rCreate.ExitCode))"
        }

        try {
          $fi = Get-Item -LiteralPath $ks -EA SilentlyContinue
          if ($fi) { Write-RunLog ("Keystore created: len={0} bytes, mtime={1}" -f $fi.Length, $fi.LastWriteTime) }
        } catch { }
      }

      # Ensure keystore exists (create if missing)
      if (-not (Test-Path $ks -PathType Leaf)) {
        Write-RunLog "Keystore missing; creating: $ks"
        _Rebuild-KeystoreUnprotected
      } else {
        try {
          $fi0 = Get-Item -LiteralPath $ks -EA SilentlyContinue
          if ($fi0) { Write-RunLog ("Keystore exists (len={0} bytes, mtime={1})" -f $fi0.Length, $fi0.LastWriteTime) }
        } catch { }
      }

      # If keystore is password-protected, 'add -x' may prompt for password first and hang.
      $didRebuild = $false
      try {
        $hp = _Invoke-OsKeystore -kbat $k -argLine "has-passwd" -timeoutMs 60000
        # Common convention (Elastic-style): exit 0 => has password, exit 1 => no password.
        if ($hp.ExitCode -eq 0) {
          Write-RunLog "Keystore reports password is set (has-passwd exit=0). Rebuilding unprotected keystore to avoid interactive prompts."
          _Rebuild-KeystoreUnprotected
          $didRebuild = $true
        } elseif ($hp.ExitCode -eq 1) {
          Write-RunLog "Keystore reports no password (has-passwd exit=1). OK."
        } else {
          Write-RunLog ("WARN: has-passwd returned unexpected exit={0}; proceeding but will rebuild on first add failure." -f $hp.ExitCode)
        }
      } catch {
        Write-RunLog ("WARN: has-passwd probe failed: {0}. Proceeding but will rebuild on first add timeout/failure." -f $_.Exception.Message)
      }

      if (-not (Test-Path $ks -PathType Leaf)) {
        throw "Keystore missing after ensure step: $ks"
      }

      $secureKeys = @(
        'plugins.security.ssl.http.keystore_password_secure',
        'plugins.security.ssl.http.keystore_keypassword_secure',
        'plugins.security.ssl.http.truststore_password_secure',
        'plugins.security.ssl.transport.keystore_password_secure',
        'plugins.security.ssl.transport.keystore_keypassword_secure',
        'plugins.security.ssl.transport.truststore_password_secure'
      )

      $attempt = 1
      while ($attempt -le 2) {
        $failed = $false
        foreach ($kk in $secureKeys) {
          try {
            # Important: value goes to stdin; newline helps some windows console reads.
            $r = _Invoke-OsKeystore -kbat $k -argLine ("add -x -f {0}" -f $kk) -stdinText ($storePass + "`n") -timeoutMs 180000
            if ($r.ExitCode -ne 0) {
              throw "exit=$($r.ExitCode)"
            }
            Write-RunLog "Keystore wrote: $kk"
          } catch {
            $failed = $true
            Write-RunLog ("WARN: Keystore write failed for {0} on attempt {1}: {2}" -f $kk, $attempt, $_.Exception.Message)

            if (-not $didRebuild -and $attempt -eq 1) {
              Write-RunLog "Rebuilding keystore unprotected and retrying all secure writes once (first failure)."
              _Rebuild-KeystoreUnprotected
              $didRebuild = $true
            }
            break
          }
        }

        if (-not $failed) { break }
        $attempt++
      }

      # Final sanity log
      try {
        $fi1 = Get-Item -LiteralPath $ks -EA SilentlyContinue
        if ($fi1) { Write-RunLog ("Keystore after writes: len={0} bytes, mtime={1}" -f $fi1.Length, $fi1.LastWriteTime) }
      } catch { }

      Write-RunLog "Keystore secure TLS keys written ($($secureKeys.Count)/$($secureKeys.Count))."
    }

    $stageStart = Get-Date

    if (Test-Path $cfg -PathType Leaf) { _Remove-PlaintextTlsYaml -path $cfg }

    # Canonical TLS storepass resolution (DPAPI file may be base64 text)
    if (-not (Get-Command Resolve-TinySocsTlsStorepass -ErrorAction SilentlyContinue)) {
      $null = _Try-ImportInstallerModule
    }
    if (-not (Get-Command Resolve-TinySocsTlsStorepass -ErrorAction SilentlyContinue)) {
      throw "FATAL: Resolve-TinySocsTlsStorepass not available. Ensure TinySocs.Installer.psm1 exports it and is installed."
    }

    Write-RunLog "STAGE 4: resolving TLS storepass via Resolve-TinySocsTlsStorepass"

    $rt = Get-Command Resolve-TinySocsTlsStorepass -ErrorAction Stop
    $canLiteral = $false
    try { $canLiteral = $rt.Parameters.ContainsKey('LiteralPath') } catch { }

    if ($canLiteral -and (Test-Path -LiteralPath $dp -PathType Leaf)) {
      Write-RunLog "STAGE 4: using -LiteralPath resolver call (primary dpapi file exists)"
      $storeInfo = Resolve-TinySocsTlsStorepass -LiteralPath $dp
    } else {
      Write-RunLog ("STAGE 4: using canonical -ConfDir/-OpenSearchRoot resolver call (canLiteral={0}, dpExists={1})" -f $canLiteral, (Test-Path -LiteralPath $dp -PathType Leaf))
      $storeInfo = Resolve-TinySocsTlsStorepass -ConfDir $confDir -OpenSearchRoot $script:OpenSearchRootPF
    }

    $pw = $storeInfo.Password
    Write-RunLog ("[TinySocs][OpenSearch][Persist] Decrypted storepass OK (enc={0}, len={1}) from: {2}" -f $storeInfo.Encoding, $storeInfo.Length, $storeInfo.SourcePath)

    if ([string]::IsNullOrWhiteSpace($pw)) { throw "FATAL: TLS storepass resolution produced empty/whitespace password." }
    Write-RunLog "STAGE 4: ensuring keystore TLS entries"
    _Ensure-OpenSearchKeystoreTls -storePass $pw

    $ms = [int]((Get-Date) - $stageStart).TotalMilliseconds
    Write-RunLog "STAGE 4: TLS self-heal complete in ${ms}ms"
  } catch {
    try { Write-RunLog ("STAGE 4: FAILED: {0}" -f $_.Exception.Message) } catch { }
    throw
  }

  # IMPORTANT: Run OpenSearch with CWD = ProgramData so "file=logs/gc.log" lands in ProgramData logs.
  try { Set-Location -LiteralPath $script:OpenSearchRootPD } catch { }

  Write-RunLog "Launching OpenSearch..."
  $osBat = Join-Path $script:OpenSearchRootPF 'bin\opensearch.bat'
  & $osBat
  $exit = $LASTEXITCODE
  Write-RunLog "OpenSearch exited with code $exit"
  if ($exit -ne 0) { exit $exit }
}
catch {
  $msg = $_.Exception.Message
  Write-RunLog "FATAL: $msg"
  try { Write-Error $_ } catch { }
  exit 1
}
finally {
  try {
    if ($mutex) {
      $mutex.ReleaseMutex() | Out-Null
      $mutex.Dispose()
      Write-RunLog "STAGE 0: released start mutex"
    }
  } catch { }
}