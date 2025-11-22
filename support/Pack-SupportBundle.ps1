param(
  [string]$RepoRoot = (Resolve-Path "$PSScriptRoot\..").Path,
  [string]$OutDir   = (Join-Path $PSScriptRoot "..\artifacts\support"),
  [int]$QueueTailLines = 1000
)

$ErrorActionPreference = 'Stop'
Set-Location $RepoRoot
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

# ---------- Privacy helpers ----------
# Coarsen IPv4 -> x.y.z.0/24
function Coarsen-IPv4 {
  param([string]$Text)
  if (-not $Text) { return $Text }
  $ipRe = [regex]'\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b'
  return $ipRe.Replace($Text, {
    param($m)
    $parts = $m.Value.Split('.')
    if ($parts.Count -eq 4) { ($parts[0..2] -join '.') + '.0/24' } else { $m.Value }
  })
}

# Mask emails: "u*@domain.tld" → "u***@domain.tld"
function Mask-Email {
  param([string]$Text)
  if (-not $Text) { return $Text }
  $emailRe = [regex]'\b([A-Za-z0-9._%+\-])([A-Za-z0-9._%+\-]*?)@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})\b'
  return $emailRe.Replace($Text, {
    param($m)
    $first = $m.Groups[1].Value
    $dom   = $m.Groups[3].Value
    "$first***@$dom"
  })
}

function Redact-PII {
  param([string]$Text)
  $t = $Text
  $t = Mask-Email $t
  $t = Coarsen-IPv4 $t
  return $t
}

# Scrub secrets in .env-style lines
function Scrub-EnvLines {
  param([string[]]$Lines)
  $sensitive = @(
    'OPENAI_API_KEY','SIEM_PASS','SMTP_PASS',
    'BOT_SHARED_SECRET','MASTER_SHARED_SECRET','NODE_SECRET',
    'GCHAT_WEBHOOK_URL','SLACK_WEBHOOK_URL','SMTP_USER','SMTP_FROM'
  )
  $out = @()
  foreach ($ln in $Lines) {
    if ($ln -match '^\s*#' -or -not ($ln -match '=')) { $out += $ln; continue }
    $k,$v = $ln.Split('=',2)
    $key = $k.Trim()
    $val = $v
    if ($sensitive -contains $key) {
      if ($val -match '^\s*"?(.+?)"?\s*$') {
        $orig = $Matches[1]
        $tail = ($orig.Length -ge 3) ? $orig.Substring($orig.Length-3) : $orig
        $val  = '"****' + $tail + '"'
      } else {
        $val = '"****"'
      }
      $out += "$key=$val"
    } else {
      $out += $ln
    }
  }
  return $out
}

function Write-RedactedFile {
  param(
    [string]$SourcePath,
    [string]$DestPath,
    [switch]$IsEnv
  )
  if (-not (Test-Path $SourcePath)) { return }
  $raw = Get-Content -Raw -Path $SourcePath -ErrorAction Stop
  $text = if ($IsEnv) {
    (Scrub-EnvLines -Lines ($raw -split "`r?`n")) -join "`r`n"
  } else {
    $raw
  }
  $text = Redact-PII $text
  New-Item -ItemType Directory -Force -Path (Split-Path $DestPath -Parent) | Out-Null
  $text | Out-File -FilePath $DestPath -Encoding UTF8
}

function Write-RedactedQueueTail {
  param(
    [string]$QueuePath,
    [string]$DestPath,
    [int]$TailLines = 1000
  )
  if (-not (Test-Path $QueuePath)) { return }
  $lines = Get-Content -Path $QueuePath -ErrorAction Stop
  if ($lines.Count -gt $TailLines) { $lines = $lines[-$TailLines..-1] }
  $joined = ($lines -join "`r`n")
  $joined = Redact-PII $joined
  New-Item -ItemType Directory -Force -Path (Split-Path $DestPath -Parent) | Out-Null
  $joined | Out-File -FilePath $DestPath -Encoding UTF8
}
# -------------------------------------

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$work  = Join-Path $OutDir "bundle-$stamp"
New-Item -ItemType Directory -Force -Path $work | Out-Null

# 1) Env snapshots (redacted)
$envOutDir = Join-Path $work "env_redacted"
Write-RedactedFile -SourcePath ".env"            -DestPath (Join-Path $envOutDir "env.txt")           -IsEnv
Write-RedactedFile -SourcePath "tinysocs\.env"   -DestPath (Join-Path $envOutDir "tinysocs.env.txt")  -IsEnv

# 2) Doctor output (JSON)
try {
  $doc = & "$PSScriptRoot\Doctor.ps1" -RepoRoot $RepoRoot
  ($doc | ConvertTo-Json -Depth 6) | Out-File -Encoding UTF8 -FilePath (Join-Path $work "doctor.json")
} catch {
  Write-Warning "Doctor.ps1 failed: $($_.Exception.Message)"
}

# 3) Python snapshot
try {
  $py = if (Test-Path ".venv\Scripts\python.exe") { ".venv\Scripts\python.exe" } else { "python" }
  & $py -V                    | Out-File -Encoding UTF8 (Join-Path $work "python_version.txt")
  & $py -m pip freeze         | Out-File -Encoding UTF8 (Join-Path $work "pip_freeze.txt")
} catch {
  Write-Warning "Python snapshot failed: $($_.Exception.Message)"
}

# 4) Action queue (tail + redacted)
$queuePath = $env:TINYSOCS_QUEUE_PATH
if (-not $queuePath) { $queuePath = $env:ACTIONS_QUEUE_PATH }
if (-not $queuePath) { $queuePath = Join-Path $RepoRoot "data\actions_queue.jsonl" }
Write-RedactedQueueTail -QueuePath $queuePath -DestPath (Join-Path $work "actions_queue.tail.jsonl") -TailLines $QueueTailLines

# 5) Ledger (structure only; typically PII-free)
if (Test-Path "ledger") {
  Copy-Item "ledger" (Join-Path $work "ledger") -Recurse -Force -ErrorAction SilentlyContinue
} elseif (Test-Path "tinysocs\ledger") {
  Copy-Item "tinysocs\ledger" (Join-Path $work "ledger") -Recurse -Force -ErrorAction SilentlyContinue
}

# 6) Verify logs (if present) — lightly redacted
$logsSrc = Join-Path $RepoRoot "logs"
$logsDst = Join-Path $work "logs"
if (Test-Path $logsSrc) {
  New-Item -ItemType Directory -Force -Path $logsDst | Out-Null
  Get-ChildItem $logsSrc -Filter "verify_ledger-*.json" -ErrorAction SilentlyContinue | ForEach-Object {
    $raw = Get-Content -Raw -Path $_.FullName
    (Redact-PII $raw) | Out-File -Encoding UTF8 -FilePath (Join-Path $logsDst $_.Name)
  }
}

# 7) Basic repo info (git rev if available)
try {
  $gitrev = (git rev-parse HEAD) 2>$null
  if ($gitrev) { $gitrev | Out-File -Encoding UTF8 (Join-Path $work "git_rev.txt") }
} catch { }

# 8) OpenSearch stats dump (anchors + incidents), privacy-aware
try {
  if (-not $py) {
    $py = if (Test-Path ".venv\Scripts\python.exe") { ".venv\Scripts\python.exe" } else { "python" }
  }
  $statsPy = @'
import os, json, re, requests

SIEM_URL  = os.getenv("SIEM_URL", "https://localhost:9201").rstrip("/")
SIEM_USER = os.getenv("SIEM_USER", "admin")
SIEM_PASS = os.getenv("SIEM_PASS", "ChangeMe123!")
_ssl_env  = (os.getenv("SIEM_SSL_VERIFY") or "").strip().lower()

verify: bool | str
if _ssl_env in ("0", "false", "no", "off", ""):
    verify = False
else:
    # If it's a file path to CA bundle, prefer that
    verify = _ssl_env
    if verify in ("1","true","yes","on"):
        verify = True

session = requests.Session()
session.auth = (SIEM_USER, SIEM_PASS)
session.verify = verify
session.headers.update({"User-Agent": "tinysocs/support-bundle/1"})

def _mask_email(s: str) -> str:
    if not isinstance(s, str) or not s: return s
    email_re = re.compile(r"\\b([A-Za-z0-9._%+\\-])([A-Za-z0-9._%+\\-]*?)@([A-Za-z0-9.\\-]+\\.[A-Za-z]{2,})\\b")
    def _m(m):
        return f"{m.group(1)}***@{m.group(3)}"
    return email_re.sub(_m, s)

def _coarsen_ip(s: str) -> str:
    if not isinstance(s, str) or not s: return s
    ip_re = re.compile(r"\\b(?:(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)\\.){3}(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)\\b")
    def _m(m):
        parts = m.group(0).split(".")
        return ".".join(parts[:3]) + ".0/24" if len(parts)==4 else m.group(0)
    return ip_re.sub(_m, s)

def _scrub_text(s: str) -> str:
    return _coarsen_ip(_mask_email(s or ""))

def _post(index: str, body: dict) -> dict:
    try:
        r = session.post(f"{SIEM_URL}/{index}/_search", json=body, timeout=12)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        return {"error": str(e), "index": index}

def anchors_stats():
    body = {
        "size": 0,
        "query": { "range": { "anchored_at": { "gte": "now-7d/d" } } },
        "aggs": {
            "by_node": { "terms": { "field": "node_id.keyword", "size": 100 } },
            "per_day": { "date_histogram": { "field": "anchored_at", "fixed_interval": "1d" } }
        }
    }
    return _post("tinysocs_anchors", body)

def incidents_stats():
    # aggregate counts by severity + per-day; also fetch last 10 TL;DRs (redacted)
    agg = {
        "size": 0,
        "query": { "range": { "@timestamp": { "gte": "now-7d/d" } } },
        "aggs": {
            "by_sev": { "terms": { "field": "severity.keyword", "size": 10 } },
            "per_day": { "date_histogram": { "field": "@timestamp", "fixed_interval": "1d" } }
        }
    }
    res = _post("siem_index", agg)

    # Try to pull recent incidents (best-effort)
    try:
        r = session.post(
            f"{SIEM_URL}/siem_index/_search",
            json={
                "size": 10,
                "sort": [{ "@timestamp": { "order": "desc" } }],
                "_source": ["@timestamp", "tldr", "severity"]
            },
            timeout=12
        )
        if r.status_code < 400:
            hits = r.json().get("hits", {}).get("hits", [])
            redacted = []
            for h in hits:
                src = h.get("_source", {})
                redacted.append({
                    "@timestamp": src.get("@timestamp"),
                    "severity": src.get("severity"),
                    "tldr": _scrub_text(src.get("tldr") or "")
                })
            res["recent"] = redacted
    except Exception:
        pass

    return res

out = {
    "anchors": anchors_stats(),
    "incidents": incidents_stats(),
}
print(json.dumps(out, ensure_ascii=False))
'@

  $statsOut = Join-Path $work "opensearch_stats.json"
  $statsRes = & $py - <<EOF 2>$null
$statsPy
EOF
  if ($LASTEXITCODE -eq 0 -and $statsRes) {
    # Double-check PII in the blob (belt-and-braces)
    ($statsRes | Out-String) | ForEach-Object { Redact-PII $_ } | Out-File -Encoding UTF8 -FilePath $statsOut
  } else {
    Write-Warning "OpenSearch stats collection failed."
  }
} catch {
  Write-Warning "OpenSearch stats step failed: $($_.Exception.Message)"
}

# 9) Zip
$zip = Join-Path $OutDir "bundle-$stamp.zip"
if (Test-Path $zip) { Remove-Item -Force $zip }
Compress-Archive -Path (Join-Path $work "*") -DestinationPath $zip -Force
Write-Host "Support bundle -> $zip"
