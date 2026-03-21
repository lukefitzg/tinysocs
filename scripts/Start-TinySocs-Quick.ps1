# TinySocs Quickstart
# Brings the box to "ready" (Node + Bot + local SIEM shim), runs master once, verifies anchors, then runs Doctor.

Import-Module "$PSScriptRoot\TinySocs.Utils.psm1" -Force

$ErrorActionPreference = 'Stop'
Set-Location (Resolve-Path "$PSScriptRoot\..")  # repo root

function Import-DotEnv {
  param([string]$Path)

  if (-not $Path) { return }
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return }

  Get-Content -LiteralPath $Path | ForEach-Object {
    $line = $_
    if ($null -eq $line) { return }
    $line = $line.Trim()
    if (-not $line) { return }
    if ($line.StartsWith('#')) { return }

    # tolerate: "export KEY=VALUE"
    if ($line -match '^\s*export\s+') {
      $line = ($line -replace '^\s*export\s+', '').Trim()
    }

    # must look like KEY=VALUE
    if ($line -notmatch '=') { return }

    $k, $v = $line -split '=', 2
    $k = ($k ?? '').Trim()
    $v = ($v ?? '').Trim()

    if (-not $k) { return }

    # strip surrounding quotes
    if ($v.Length -ge 2) {
      if (($v.StartsWith('"') -and $v.EndsWith('"')) -or ($v.StartsWith("'") -and $v.EndsWith("'"))) {
        $v = $v.Substring(1, $v.Length - 2)
      }
    }

    # do not overwrite existing env vars
    if (-not (Test-Path -LiteralPath "Env:$k")) {
      try { Set-Item -Path "Env:$k" -Value $v } catch { }
    }
  }
}

function Get-PythonExe {
  param([string]$RepoRoot = (Resolve-Path ".").Path)
  $venvPy = Join-Path $RepoRoot ".venv\Scripts\python.exe"
  if (Test-Path -LiteralPath $venvPy -PathType Leaf) { return $venvPy }
  return "python"
}

function New-TinySocsHmacHeaders {
  param(
    [Parameter(Mandatory)][string]$Secret,
    [string]$Style = $env:TINYSOCS_HMAC_STYLE,
    [string]$SigPrefix = $env:TINYSOCS_SIG_PREFIX
  )

  if (-not $Style) { $Style = 'pipe' }   # default
  $Style = $Style.ToLowerInvariant()

  $ts    = [int][DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
  $nonce = [Guid]::NewGuid().ToString('N')

  $includeNonce = $false
  switch ($Style) {
    'dot'  { $msg = "$ts.$nonce"; $includeNonce = $true }
    'pipe' { $msg = "$ts|$nonce"; $includeNonce = $true }
    default { $msg = "$ts"; $includeNonce = $false } # 'ts'
  }

  $h = [System.Security.Cryptography.HMACSHA256]::new([Text.Encoding]::UTF8.GetBytes($Secret))
  try {
    $raw = -join ($h.ComputeHash([Text.Encoding]::UTF8.GetBytes($msg)) | ForEach-Object { $_.ToString('x2') })
  } finally { $h.Dispose() }

  # If a prefix is provided, prepend it (e.g. "sha256=") instead of hardcoding.
  $pfx = ''
  if ($null -ne $SigPrefix) { $pfx = $SigPrefix.Trim() }
  $sig = if ($pfx) { "$pfx$raw" } else { $raw }

  $hdr = @{
    'X-TinySOCS-Timestamp' = [string]$ts
    'X-TinySOCS-Signature' = [string]$sig
  }
  if ($includeNonce) { $hdr['X-TinySOCS-Nonce'] = [string]$nonce }
  return $hdr
}

function Test-HttpReady {
  param(
    [Parameter(Mandatory)] [string] $Url,
    [hashtable] $Headers,
    [int] $TimeoutSec = 20
  )
  $t0 = Get-Date
  while ((Get-Date) -lt $t0.AddSeconds($TimeoutSec)) {
    try {
      if ($null -ne $Headers) {
        $r = Invoke-WebRequest -Uri $Url -Headers $Headers -UseBasicParsing -TimeoutSec 4 -ErrorAction Stop
      } else {
        $r = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 4 -ErrorAction Stop
      }
      if ($r.StatusCode -ge 200 -and $r.StatusCode -lt 500) { return $true }
    } catch {
      Start-Sleep -Milliseconds 500
    }
  }
  return $false
}

function Test-LocalPortListening {
  param(
    [Parameter(Mandatory)][int]$Port,
    [string]$Host = '127.0.0.1',
    [int]$TimeoutMs = 300
  )

  # Prefer Get-NetTCPConnection if available, fall back to a quick TcpClient connect.
  try {
    if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) {
      $isListening = Get-NetTCPConnection -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalPort -eq $Port -and $_.State -eq 'Listen' } |
        Select-Object -First 1
      if ($isListening) { return $true }
    }
  } catch { }

  try {
    $client = New-Object System.Net.Sockets.TcpClient
    $iar = $client.BeginConnect($Host, $Port, $null, $null)
    $ok = $iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
    if ($ok -and $client.Connected) { $client.EndConnect($iar); $client.Close(); return $true }
    try { $client.Close() } catch { }
  } catch { }

  return $false
}

function Invoke-OpenSearchBootstrap {
  param(
    [Parameter(Mandatory)][string]$RepoRoot,
    [Parameter(Mandatory)][string]$PyExe
  )

  $tplDir = Join-Path $RepoRoot "packaging\opensearch\templates"
  if (-not (Test-Path -LiteralPath $tplDir -PathType Container)) {
    Write-Host "[TinySocs] OpenSearch bootstrap: templates dir not found: $tplDir (skipping)" -ForegroundColor Yellow
    return
  }

  if (-not $env:SIEM_URL)  { throw "SIEM_URL not set (OpenSearch bootstrap)" }
  if (-not $env:SIEM_USER) { throw "SIEM_USER not set (OpenSearch bootstrap)" }
  if (-not $env:SIEM_PASS) { throw "SIEM_PASS not set (OpenSearch bootstrap)" }

  $py = @'
import json, os, sys, time
from pathlib import Path

try:
    import requests
    from requests.auth import HTTPBasicAuth
except Exception as e:
    print(f"[os-bootstrap] ERROR: python dependency missing (requests): {e}", file=sys.stderr)
    sys.exit(3)

SIEM_URL = os.environ.get("SIEM_URL","").strip().rstrip("/")
SIEM_USER = os.environ.get("SIEM_USER","")
SIEM_PASS = os.environ.get("SIEM_PASS","")
VERIFY = str(os.environ.get("SIEM_SSL_VERIFY","true")).strip().lower() not in ("0","false","no","off")

TEMPLATES_DIR = Path(os.environ.get("TINYSOCS_OS_TEMPLATES_DIR","")).resolve()
if not TEMPLATES_DIR.exists():
    print(f"[os-bootstrap] ERROR: templates dir not found: {TEMPLATES_DIR}", file=sys.stderr)
    sys.exit(2)

if not VERIFY:
    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except Exception:
        pass

auth = HTTPBasicAuth(SIEM_USER, SIEM_PASS)

def req(method: str, path: str, json_body=None, timeout=15):
    url = f"{SIEM_URL}/{path.lstrip('/')}"
    r = requests.request(method, url, json=json_body, auth=auth, verify=VERIFY, timeout=timeout)
    return r

def wait_cluster(timeout_sec=45):
    t0 = time.time()
    last = None
    while time.time() - t0 < timeout_sec:
        try:
            r = req("GET", "/")
            if r.status_code == 200:
                try:
                    b = r.json()
                except Exception:
                    b = {}
                print(f"[os-bootstrap] Connected: node={b.get('name')!r} cluster={b.get('cluster_name')!r} verify={VERIFY}")
                return
            last = f"HTTP {r.status_code}: {r.text[:200]}"
        except Exception as e:
            last = str(e)
        time.sleep(1.0)
    print(f"[os-bootstrap] ERROR: OpenSearch not reachable: {last}", file=sys.stderr)
    sys.exit(1)

def ensure_templates():
    files = sorted([p for p in TEMPLATES_DIR.glob("*.json") if p.is_file()])
    if not files:
        print(f"[os-bootstrap] WARN: no template json files in {TEMPLATES_DIR}")
        return []

    ensured = []
    for p in files:
        name = p.stem  # filename without .json == template name
        try:
            body = json.loads(p.read_text(encoding="utf-8"))
        except Exception as e:
            print(f"[os-bootstrap] ERROR: failed to parse {p.name}: {e}", file=sys.stderr)
            sys.exit(2)

        r = req("PUT", f"/_index_template/{name}", json_body=body, timeout=30)
        if 200 <= r.status_code < 300:
            print(f"[os-bootstrap] Template ensured: {name} (from {p.name})")
            ensured.append((name, body))
        else:
            print(f"[os-bootstrap] ERROR: template PUT failed: {name} HTTP {r.status_code}: {r.text}", file=sys.stderr)
            sys.exit(2)
    return ensured

def seed_aliases(templates):
    # Best-effort: for each template, if it defines aliases, ensure they exist on existing indices matching its patterns.
    for (name, body) in templates:
        try:
            patterns = body.get("index_patterns") or []
            tpl = body.get("template") or {}
            aliases = (tpl.get("aliases") or {})
            alias_names = [a for a in aliases.keys() if isinstance(a, str) and a.strip()]
        except Exception:
            continue

        if not patterns or not alias_names:
            continue

        for pat in patterns:
            if not isinstance(pat, str) or not pat.strip():
                continue
            cat_pat = pat
            try:
                r = req("GET", f"/_cat/indices/{cat_pat}?format=json", timeout=20)
                if r.status_code == 404:
                    continue
                if not (200 <= r.status_code < 300):
                    print(f"[os-bootstrap] WARN: _cat/indices failed for {cat_pat}: HTTP {r.status_code}", file=sys.stderr)
                    continue
                rows = r.json()
                if not isinstance(rows, list):
                    continue
                indices = [row.get("index") for row in rows if isinstance(row, dict) and isinstance(row.get("index"), str)]
            except Exception as e:
                print(f"[os-bootstrap] WARN: _cat/indices error for {cat_pat}: {e}", file=sys.stderr)
                continue

            if not indices:
                continue

            actions = []
            for idx in indices:
                for a in alias_names:
                    actions.append({"add": {"index": idx, "alias": a}})

            try:
                r2 = req("POST", "/_aliases", json_body={"actions": actions}, timeout=30)
                if 200 <= r2.status_code < 300:
                    print(f"[os-bootstrap] Aliases seeded for pattern={cat_pat}: {', '.join(alias_names)} on {len(indices)} indices")
                else:
                    print(f"[os-bootstrap] WARN: alias seed failed for pattern={cat_pat}: HTTP {r2.status_code}: {r2.text[:200]}", file=sys.stderr)
            except Exception as e:
                print(f"[os-bootstrap] WARN: alias seed error for pattern={cat_pat}: {e}", file=sys.stderr)

def main():
    if not SIEM_URL or not SIEM_USER:
        print("[os-bootstrap] ERROR: SIEM_URL/SIEM_USER not set", file=sys.stderr)
        sys.exit(2)

    wait_cluster()
    templates = ensure_templates()
    seed_aliases(templates)
    print("[os-bootstrap] Done.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
'@

  Write-Host "[TinySocs] OpenSearch bootstrap: ensuring templates from $tplDir" -ForegroundColor Cyan

  $env:TINYSOCS_OS_TEMPLATES_DIR = $tplDir
  & $PyExe -c $py
  if ($LASTEXITCODE -ne 0) {
    throw "OpenSearch bootstrap failed (exit=$LASTEXITCODE)"
  }
}

function Start-TinySocs-Ready {
  param(
    [string] $RepoRoot = "$PSScriptRoot\..",
    [int]    $NodePort = 8081,
    [int]    $BotPort  = 8090
  )

  $RepoRoot = (Resolve-Path $RepoRoot).Path

  # 0) Load .env (repo/.env or tinysocs/.env)
  Import-DotEnv (Join-Path $RepoRoot ".env")
  Import-DotEnv (Join-Path $RepoRoot "tinysocs\.env")

  # 0.1) Honor env ports if provided
  if ($env:NODE_PORT) { try { $NodePort = [int]$env:NODE_PORT } catch {} }
  if ($env:BOT_PORT)  { try { $BotPort  = [int]$env:BOT_PORT  } catch {} }

  # 1) Elevation (if you kept Ensure-AdminOrRelaunch, use it)
  if (Get-Command Ensure-AdminOrRelaunch -ErrorAction SilentlyContinue) {
    Ensure-AdminOrRelaunch
  }

  # 2) Python venv + deps (best-effort)
  $PyExe = Get-PythonExe -RepoRoot $RepoRoot
  if (-not $env:VIRTUAL_ENV -and (Test-Path -LiteralPath "$RepoRoot\.venv\Scripts\Activate.ps1")) {
    & "$RepoRoot\.venv\Scripts\Activate.ps1"
  }
  if (Get-Command Ensure-PythonRequirements -ErrorAction SilentlyContinue) {
    Ensure-PythonRequirements
  }

  # 3) SIEM + Core defaults
  if (-not $env:SIEM_URL)               { Set-Item Env:SIEM_URL "https://127.0.0.1:9201" }
  if (-not $env:SIEM_USER)              { Set-Item Env:SIEM_USER "admin" }
  if (-not $env:SIEM_PASS) {
    Write-Error "SIEM_PASS must be set. Export it before running this script."
    exit 1
  }
  if (-not $env:SIEM_SSL_VERIFY)        { Set-Item Env:SIEM_SSL_VERIFY "0" }
  if (-not $env:TINYSOCS_NODES)         { Set-Item Env:TINYSOCS_NODES "http://localhost:$NodePort" }
  if (-not $env:MASTER_SHARED_SECRET) {
    # Generate a random secret for quickstart sessions
    $randomSecret = -join ((65..90) + (97..122) + (48..57) | Get-Random -Count 32 | ForEach-Object { [char]$_ })
    Write-Warning "MASTER_SHARED_SECRET not set — generating random secret for this session."
    Set-Item Env:MASTER_SHARED_SECRET $randomSecret
  }
  if (-not $env:NODE_SECRET)            { Set-Item Env:NODE_SECRET $env:MASTER_SHARED_SECRET }
  if (-not $env:BOT_SHARED_SECRET) {
    # Generate a random secret for quickstart sessions
    $randomBotSecret = -join ((65..90) + (97..122) + (48..57) | Get-Random -Count 32 | ForEach-Object { [char]$_ })
    Write-Warning "BOT_SHARED_SECRET not set — generating random secret for this session."
    Set-Item Env:BOT_SHARED_SECRET $randomBotSecret
  }
  if (-not $env:ENSURE_ANCHORS)         { Set-Item Env:ENSURE_ANCHORS "1" }
  if (-not $env:TINYSOCS_INSECURE_SKIP_VERIFY) { Set-Item Env:TINYSOCS_INSECURE_SKIP_VERIFY "1" }
  if (-not $env:TINYSOCS_HMAC_STYLE)    { Set-Item Env:TINYSOCS_HMAC_STYLE "pipe" }
  if ($null -eq $env:TINYSOCS_SIG_PREFIX) { Set-Item Env:TINYSOCS_SIG_PREFIX "" }

  # Canonical queue path default if not set
  if (-not $env:TINYSOCS_QUEUE_PATH) {
    Set-Item Env:TINYSOCS_QUEUE_PATH (Join-Path $RepoRoot 'data\actions_queue.jsonl')
  }

  # 3.1) OpenSearch templates + aliases bootstrap (idempotent)
  try {
    Invoke-OpenSearchBootstrap -RepoRoot $RepoRoot -PyExe $PyExe
  } catch {
    Write-Host "[TinySocs] ERROR: OpenSearch bootstrap failed: $_" -ForegroundColor Red
    throw
  }

  # 3.2) Preflight anchors alias/mapping via unified CLI (idempotent)
  $ensureAnchors =
    ($env:ENSURE_ANCHORS -and $env:ENSURE_ANCHORS.ToString().ToLowerInvariant() -in @('1','true','yes','on'))
  if ($ensureAnchors) {
    try { & $PyExe -m tinysocs.orchestrator.anchors --ensure 2>$null | Out-Null } catch {}
  }

  # 4) Local SIEM shim (optional, idempotent)
  if (Get-Command Start-OSShim -ErrorAction SilentlyContinue) { Start-OSShim }

  # 5) Start Node (background)
  $nodeUp = $false
  try {
    if (-not (Test-LocalPortListening -Port $NodePort)) {
      Start-Process -FilePath $PyExe -ArgumentList @("-m","tinysocs.api.node") -WorkingDirectory $RepoRoot -WindowStyle Minimized | Out-Null
    }

    # try ts-only first (widest compatibility), then env style if needed
    $hdrTsOnly = New-TinySocsHmacHeaders -Secret $env:MASTER_SHARED_SECRET -Style 'ts' -SigPrefix ''
    $nodeUp = Test-HttpReady -Url "http://localhost:$NodePort/evidence/head" -Headers $hdrTsOnly -TimeoutSec 20
    if (-not $nodeUp) {
      $hdrEnv = New-TinySocsHmacHeaders -Secret $env:MASTER_SHARED_SECRET -Style $env:TINYSOCS_HMAC_STYLE -SigPrefix $env:TINYSOCS_SIG_PREFIX
      $nodeUp = Test-HttpReady -Url "http://localhost:$NodePort/evidence/head" -Headers $hdrEnv -TimeoutSec 10
    }
  } catch { }

  # 6) Start Bot (background)
  $botUp = $false
  try {
    if (-not (Test-LocalPortListening -Port $BotPort)) {
      Start-Process -FilePath $PyExe -ArgumentList @("-m","tinysocs.api.bot") -WorkingDirectory $RepoRoot -WindowStyle Minimized | Out-Null
    }
    # docs isn't auth-protected; simple probe without headers
    $botUp = Test-HttpReady -Url "http://localhost:$BotPort/docs" -TimeoutSec 15
  } catch { }

  # 7) Gather optional status (PowerShell 5.1-safe)
  $shimPort = $null
  if (Get-Command Get-TinySOCSShimPort -ErrorAction SilentlyContinue) {
    try { $shimPort = Get-TinySOCSShimPort } catch { $shimPort = $null }
  }

  # 8) Return status object
  [pscustomobject]@{
    NodeUrl   = "http://localhost:$NodePort"
    BotUrl    = "http://localhost:$BotPort"
    NodeReady = $nodeUp
    BotReady  = $botUp
    ShimPort  = $shimPort
  }
}

function Invoke-TinySocs-Scan {
  param(
    [string] $Rules    = "ps_script_block_lab",
    [string] $Window   = "10m",
    [double] $Deadline = 30,
    [switch] $AlwaysAnchor
  )
  $RepoRoot = (Resolve-Path ".").Path
  $PyExe = Get-PythonExe -RepoRoot $RepoRoot
  $args = @("-m","tinysocs.orchestrator.master","--rules",$Rules,"--window",$Window,"--deadline",$Deadline)
  if ($AlwaysAnchor) { $args += "--always-anchor" }
  & $PyExe $args
  & $PyExe -m tinysocs.orchestrator.check_ledger --verify
}

# ---- Quickstart flow ----
$RepoRoot = (Resolve-Path "$PSScriptRoot\..").Path
$ready = Start-TinySocs-Ready -RepoRoot $RepoRoot
$ready | Format-List

$rules = if ($env:TSQ_RULES) { $env:TSQ_RULES } else { "ps_script_block_lab" }
$ensure = ($env:ENSURE_ANCHORS -and $env:ENSURE_ANCHORS.ToString().ToLowerInvariant() -in @('1','true','yes','on'))
Invoke-TinySocs-Scan -Rules $rules -Window "10m" -Deadline 30 -AlwaysAnchor:$ensure

Write-Host "`nTinySocs is up." -ForegroundColor Green
Write-Host "  Node: $($ready.NodeUrl)"
Write-Host "  Bot:  $($ready.BotUrl)"
Write-Host 'Stop with:  Get-Process python -ErrorAction SilentlyContinue | Stop-Process'

function Invoke-TinySocs {
  param(
    [Parameter(Mandatory)][string]$Path,
    [string]$Secret = $env:MASTER_SHARED_SECRET,
    [string]$BaseUrl = "http://localhost:8081"
  )
  $style = if ($env:TINYSOCS_HMAC_STYLE) { $env:TINYSOCS_HMAC_STYLE } else { 'pipe' }
  $hdr = New-TinySocsHmacHeaders -Secret $Secret -Style $style -SigPrefix $env:TINYSOCS_SIG_PREFIX
  Invoke-RestMethod -Uri ($BaseUrl.TrimEnd('/') + "/" + $Path.TrimStart('/')) -Headers $hdr
}

function Invoke-TinySocsBot {
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][hashtable]$Body,
    [string]$BaseUrl = "http://localhost:8090"
  )
  $style = if ($env:TINYSOCS_HMAC_STYLE) { $env:TINYSOCS_HMAC_STYLE } else { 'pipe' }
  $hdr = New-TinySocsHmacHeaders -Secret $env:BOT_SHARED_SECRET -Style $style -SigPrefix $env:TINYSOCS_SIG_PREFIX
  Invoke-RestMethod -Uri ($BaseUrl.TrimEnd('/') + "/" + $Path.TrimStart('/')) -Method Post `
    -Headers $hdr -ContentType application/json -Body ($Body | ConvertTo-Json -Compress)
}

# ---- Doctor (final gate) ----------------------------------------------------
try {
  # Doctor writes formatted lines to the pipeline before emitting the PSObject.
  # Select the *last* pipeline object, which is the structured summary we need.
  $doc = & "$PSScriptRoot\Doctor.ps1" -RepoRoot $RepoRoot | Select-Object -Last 1
} catch {
  Write-Error "Doctor.ps1 failed to execute: $($_.Exception.Message)"
  exit 2
}

# Core checks: if any are false → non-zero exit so CI/scripts can catch it
$critical = @('PythonReady','NodeReady','BotReady','BotAckQueued','SIEMReachable','AnchorsAliasOK','SecretsPresent')
$bad = @()
foreach ($k in $critical) {
  if (-not ($doc.PSObject.Properties.Name -contains $k)) { $bad += "$k(missing)"; continue }
  if (-not ($doc.$k)) { $bad += $k }
}

if ($bad.Count -gt 0) {
  Write-Error ("Doctor failed checks: " + ($bad -join ', '))
  exit 1
}

Write-Host "Doctor checks passed." -ForegroundColor Green