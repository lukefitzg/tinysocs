  $null = Invoke-ComposeSafe -Args @("stop","-t","5","elasticsearch","kibana")
  $running = (docker ps --format "{{.Names}}" 2>$null) -join ','
  if ($running -match "ts-es" -or $running -match "ts-kibana") {
    Write-Warning "[TinySOCS] Force-killing lingering Elastic containers"
    $null = Invoke-ComposeSafe -Args @("kill","elasticsearch","kibana")
    $null = Invoke-ComposeSafe -Args @("rm","-f","elasticsearch","kibana")
  }
  Write-Host "[TinySOCS] Elastic stack stopped." -ForegroundColor Green
}

# ===================== Test noise generators (messages updated) =====================
function New-EncodedCommand {
  param([Parameter(Mandatory=$true)][string]$Command)
  $bytes = [Text.Encoding]::Unicode.GetBytes($Command)
  return [Convert]::ToBase64String($bytes)
}

function Invoke-Noise-PSScriptBlock {
  try {
    $cmd = 'Write-Host "TinySOCS ScriptBlock test"'
    $enc = New-EncodedCommand -Command "Invoke-Expression '$cmd'"
    Start-Process -FilePath powershell.exe -ArgumentList '-NoProfile','-EncodedCommand', $enc -WindowStyle Hidden -Wait
    Write-Host "[TinySOCS] Generated PowerShell ScriptBlock (4104)" -ForegroundColor Green
  } catch { Write-Warning ("[TinySOCS] PSScriptBlock generation failed: {0}" -f $_.Exception.Message) }
}

function Invoke-Noise-SuspiciousPS {
  try {
    $inner = 'Write-Host "TinySOCS suspicious PS flags"'
    $enc = New-EncodedCommand -Command $inner
    Start-Process -FilePath powershell.exe -ArgumentList '-NoProfile','-EncodedCommand', $enc -WindowStyle Hidden -Wait
    Write-Host "[TinySOCS] Generated suspicious PowerShell process (-NoProfile -EncodedCommand)" -ForegroundColor Green
  } catch { Write-Warning ("[TinySOCS] Suspicious PowerShell generation failed: {0}" -f $_.Exception.Message) }
}

function Invoke-Noise-LOLBins {
  try { Start-Process -FilePath mshta.exe -ArgumentList 'javascript:close()' -WindowStyle Hidden -Wait } catch { Write-Warning ("[TinySOCS] mshta.exe failed: {0}" -f $_.Exception.Message) }
  try { Start-Process -FilePath rundll32.exe -ArgumentList 'shell32.dll,Control_RunDLL' -WindowStyle Hidden -Wait } catch { Write-Warning ("[TinySOCS] rundll32.exe failed: {0}" -f $_.Exception.Message) }
  Write-Host "[TinySOCS] Generated LOLBIN executions (mshta, rundll32)" -ForegroundColor Green
}

function Invoke-Noise-SysmonBurst {
  param([int]$Count = 12)
  for ($i=0; $i -lt $Count; $i++) {
    try { Start-Process -FilePath cmd.exe -ArgumentList '/c','echo TinySOCS sysmon burst' -WindowStyle Hidden -Wait } catch { Write-Warning ("[TinySOCS] Sysmon burst iteration {0} failed: {1}" -f $i, $_.Exception.Message) }
  }
  Write-Host ("[TinySOCS] Generated Sysmon process-creation burst x{0}" -f $Count) -ForegroundColor Green
}

function Invoke-Noise-AuthFailed4625 {
  param(
    [string]$TargetHost,
    [string]$UserName,
    [int]$Attempts = 6
  )
  if (-not $TargetHost -or -not $UserName) {
    Write-Warning "[TinySOCS] Skipping 4625 noise (TargetHost/UserName not provided)."
    return
  }
  Write-Warning ("[TinySOCS] Generating 4625 failed logons to \\{0} as {1} (Attempts={2}). Ensure this won't lock out the account." -f $TargetHost,$UserName,$Attempts)
  for ($i=0; $i -lt $Attempts; $i++) {
    try {
      cmd.exe /c "net use \\$TargetHost\IPC$ /user:$UserName WrongPassword$i" | Out-Null
      Start-Sleep -Milliseconds 300
    } catch { Write-Warning ("[TinySOCS] 4625 attempt {0} failed to execute: {1}" -f $i, $_.Exception.Message) }
  }
  Write-Host ("[TinySOCS] Attempted {0} failed network logons (4625)." -f $Attempts) -ForegroundColor Green
}

function Invoke-TinySOCS-TestNoise {
  param(
    [switch]$All,
    [switch]$ScriptBlock,
    [switch]$SuspiciousPS,
    [switch]$LOLBins,
    [switch]$SysmonBurst,
    [int]$SysmonCount = 12,
    [switch]$IncludeAuthFailed,
    [string]$AuthTargetHost,
    [string]$AuthUserName,
    [int]$AuthAttempts = 6
  )

  if (-not ($All -or $ScriptBlock -or $SuspiciousPS -or $LOLBins -or $SysmonBurst -or $IncludeAuthFailed)) {
@"
[TinySOCS] Nothing selected. Examples:
  Invoke-TinySOCS-TestNoise -All
  Invoke-TinySOCS-TestNoise -ScriptBlock -SuspiciousPS -LOLBins
  Invoke-TinySOCS-TestNoise -SysmonBurst -SysmonCount 15
"@ | Write-Host
    return
  }

  if ($All) { $ScriptBlock=$true; $SuspiciousPS=$true; $LOLBins=$true; $SysmonBurst=$true }

  if ($ScriptBlock)  { Invoke-Noise-PSScriptBlock }
  if ($SuspiciousPS) { Invoke-Noise-SuspiciousPS }
  if ($LOLBins)      { Invoke-Noise-LOLBins }
  if ($SysmonBurst)  { Invoke-Noise-SysmonBurst -Count $SysmonCount }
  if ($IncludeAuthFailed) {
    Invoke-Noise-AuthFailed4625 -TargetHost $AuthTargetHost -UserName $AuthUserName -Attempts $AuthAttempts
  }

  Write-Host "[TinySOCS] Noise generation complete. Winlogbeat ships directly to OpenSearch." -ForegroundColor Cyan
}

# ===================== Agent prerequisites (unchanged core) =========
$Global:TinySOCS_WinlogbeatDir  = "C:\Program Files\Winlogbeat"
$Global:TinySOCS_WinlogbeatData = "C:\ProgramData\winlogbeat"

function Resolve-NormalPath([string]$p) {
  if (-not $p) { return "" }
  try { return ([IO.Path]::GetFullPath($p)).TrimEnd('\').ToLowerInvariant() }
  catch { return ($p.TrimEnd('\').ToLowerInvariant()) }
}

function Get-TinySOCSLogPath {
  $dir = "C:\tinysocs\tinysocs\logs"
  try { New-Item -ItemType Directory -Path $dir -Force | Out-Null } catch {}
  return (Join-Path $dir ("setup-{0}.log" -f (Get-Date).ToString("yyyyMMdd-HHmmss")))
}

function Test-IsAdmin {
  try {
    $wi = [Security.Principal.WindowsIdentity]::GetCurrent()
    $wp = New-Object Security.Principal.WindowsPrincipal($wi)
    return $wp.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  } catch { return $false }
}

function Ensure-AdminOrRelaunch {
  param(
    [Parameter(Mandatory=$true)][string]$PostCommand,
    [switch]$NoExit
  )
  if (Test-IsAdmin) { return $true }

  $logPath = Get-TinySOCSLogPath
  Write-Host "[TinySOCS] Elevation required; relaunching as Administrator..." -ForegroundColor Yellow
  Write-Host ("[TinySOCS] Transcript will be saved to: {0}" -f $logPath) -ForegroundColor Yellow

  $tmpDir  = "C:\tinysocs\tinysocs\logs"
  try { New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null } catch {}
  $tmpFile = Join-Path $tmpDir ("elev-{0}.ps1" -f (Get-Date).ToString("yyyyMMdd-HHmmss"))

  $content = @'
Start-Transcript -Path "__LOG__" -Append | Out-Null
try {
  Set-Location 'C:\tinysocs\tinysocs'
  . '.\model_toggles.ps1'
  $ErrorActionPreference = 'Continue'
  $ProgressPreference    = 'SilentlyContinue'
  $VerbosePreference     = 'SilentlyContinue'
  if ($PSStyle -and $PSStyle.PSObject.Properties['OutputRendering']) { $PSStyle.OutputRendering = 'Ansi' }
  Write-Host "[TinySOCS] Elevated session ready. Running: __CMD__" -ForegroundColor Cyan

  $global:TinySOCS_LogPath = "__LOG__"
  __CMD__
}
catch {
  Write-Error ("[TinySOCS] Unhandled error in elevated session: {0}" -f $_.Exception.Message)
  if ($_.ScriptStackTrace) { Write-Error $_.ScriptStackTrace }
}
finally {
  try { Stop-Transcript | Out-Null } catch {}
}
'@

  $content = $content.Replace("__LOG__", $logPath).Replace("__CMD__", $PostCommand)
  Set-Content -Path $tmpFile -Value $content -Encoding UTF8

  $args = @('-NoProfile','-ExecutionPolicy','Bypass','-File', $tmpFile)
  if ($NoExit) { $args = @('-NoExit') + $args }

  Start-Process -FilePath "powershell.exe" -Verb RunAs -ArgumentList $args -Wait
  Write-Host ("[TinySOCS] Elevated command finished. Log: {0}" -f $logPath) -ForegroundColor Yellow
  return $false
}

# -------- Helpers (unchanged) --------
function Get-ExePathFromServicePathName {
  param([Parameter(Mandatory=$true)][string]$PathName)
  $s = $PathName.Trim()
  if ($s.StartsWith('"')) {
    $second = $s.IndexOf('"',1)
    if ($second -gt 1) { return $s.Substring(1, $second-1) }
  }
  $sp = $s.IndexOf(' ')
  if ($sp -gt 0) { return $s.Substring(0,$sp) }
  return $s
}

function Stop-And-Delete-ServiceSafely {
  param(
    [Parameter(Mandatory=$true)][string]$Name,
    [int]$TimeoutSec = 20
  )
  try {
    $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq 'Running') {
      Write-Warning ("Waiting for service '{0}' to stop..." -f $Name)
      try { Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue } catch {}
      $deadline = (Get-Date).AddSeconds($TimeoutSec)
      while ($svc.Status -ne 'Stopped' -and (Get-Date) -lt $deadline) {
        Start-Sleep -Milliseconds 500
        try { $svc.Refresh() } catch {}
      }
    }
  } catch {}
  try { sc.exe delete $Name | Out-Null } catch {}
}

# -------- Winlogbeat singleton helpers (trimmed messages) --------
function Stop-OtherWinlogbeatInstances {
  param([string]$TargetDir = $Global:TinySOCS_WinlogbeatDir)

  $targetNorm = Resolve-NormalPath $TargetDir

  try {
    $procs = Get-CimInstance Win32_Process -Filter "Name='winlogbeat.exe'" -ErrorAction SilentlyContinue
    foreach ($p in ($procs | ForEach-Object { [pscustomobject]@{ Id=$_.ProcessId; Path=$_.ExecutablePath } })) {
      $pNorm = Resolve-NormalPath (Split-Path ($p.Path) -Parent)
      if ($pNorm -and $pNorm -ne $targetNorm) {
        Write-Warning ("[TinySOCS] Stopping foreign Winlogbeat process (PID {0}) @ {1}" -f $p.Id, $p.Path)
        try { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } catch { Write-Warning $_.Exception.Message }
      }
    }
  } catch { Write-Warning ("[TinySOCS] Process probe failed: {0}" -f $_.Exception.Message) }

  try {
    $svcs = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match '(?i)winlogbeat' -or ($_.PathName -match 'winlogbeat\.exe') }

    foreach ($svc in ($svcs | Sort-Object Name -Unique)) {
      if ($svc.Name -eq 'winlogbeat') { continue }
      $exePath = Get-ExePathFromServicePathName -PathName $svc.PathName
      $svcDir  = Resolve-NormalPath (Split-Path $exePath -Parent)
      if ($svcDir -and $svcDir -ne $targetNorm) {
        Write-Warning ("[TinySOCS] Removing foreign Winlogbeat service '{0}'" -f $svc.Name)
        Stop-And-Delete-ServiceSafely -Name $svc.Name -TimeoutSec 20
      }
    }
  } catch { Write-Warning ("[TinySOCS] Service probe failed: {0}" -f $_.Exception.Message) }

  try {
    $tasks = Get-ScheduledTask -TaskName *winlogbeat* -ErrorAction SilentlyContinue
    foreach ($t in $tasks) {
      Write-Warning ("[TinySOCS] Removing scheduled task '{0}' related to winlogbeat" -f $t.TaskName)
      try { Unregister-ScheduledTask -TaskName $t.TaskName -Confirm:$false } catch { Write-Warning $_.Exception.Message }
    }
  } catch {}
}

function Stop-WinlogbeatConsoleFromDir {
  param([string]$TargetDir = $Global:TinySOCS_WinlogbeatDir, [int]$WaitSec = 10)
  $targetNorm = Resolve-NormalPath $TargetDir
  try {
    $procs = Get-CimInstance Win32_Process -Filter "Name='winlogbeat.exe'" -ErrorAction SilentlyContinue
    $killed = @()
    foreach ($p in $procs) {
      $dir = Resolve-NormalPath (Split-Path $p.ExecutablePath -Parent)
      if ($dir -eq $targetNorm) {
        Write-Warning ("[TinySOCS] Killing lingering console winlogbeat (PID {0}) @ {1}" -f $p.ProcessId, $p.ExecutablePath)
        try { Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue } catch { Write-Warning $_.Exception.Message }
        $killed += $p.ProcessId
      }
    }
    if ($killed.Count -gt 0) {
      $deadline = (Get-Date).AddSeconds($WaitSec)
      do {
        Start-Sleep -Milliseconds 300
        $still = Get-Process -Id $killed -ErrorAction SilentlyContinue
      } while ($still -and (Get-Date) -lt $deadline)
      Start-Sleep -Milliseconds 500
    }
  } catch { Write-Warning ("[TinySOCS] Probe/kill console winlogbeat failed: {0}" -f $_.Exception.Message) }
}

function Remove-WinlogbeatStaleLock {
  param([string]$DataPath = $Global:TinySOCS_WinlogbeatData)
  try {
    $lock = Join-Path $DataPath 'winlogbeat.lock'
    if (-not (Test-Path $lock)) { return }

    # Try exclusive open; if it fails, the lock is genuinely in use.
    $fs = $null
    try {
      $fs = [System.IO.File]::Open($lock, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
    } catch {
      Write-Host "[TinySOCS] winlogbeat.lock appears to be in use; leaving it." -ForegroundColor DarkYellow
      return
    } finally {
      if ($fs) { $fs.Close() }
    }

    Write-Warning "[TinySOCS] Removing stale winlogbeat.lock"
    Remove-Item -Path $lock -Force -ErrorAction SilentlyContinue
  } catch {
    Write-Warning ("[TinySOCS] Failed to evaluate/remove winlogbeat.lock: {0}" -f $_.Exception.Message)
  }
}

# -------- OpenSearch license shim --------
# Runs a tiny local HTTP proxy that fakes GET /_license and relays all other calls to OpenSearch.
# It also falls back to a high port if 9202 can’t be bound (e.g., WinError 10013).

function Test-PortBindable {
  param([int]$Port,[string]$Address='127.0.0.1')
  try {
    $listener = New-Object System.Net.Sockets.TcpListener ([System.Net.IPAddress]::Parse($Address), $Port)
    $listener.Start(); $listener.Stop(); return $true
  } catch { return $false }
}

function Get-TinySOCSShimPort {
  param(
    [int[]]$PreferredPorts = @(),
    [string]$Address = '127.0.0.1'
  )
  $candidates = @()

  # 1) Explicit parameter wins
  if ($PreferredPorts -and $PreferredPorts.Count -gt 0) { $candidates += $PreferredPorts }

  # 2) Env var (comma/space separated) e.g. TINYSOCS_SHIM_PREFERRED="40001,40002"
  if ($env:TINYSOCS_SHIM_PREFERRED) {
    $envPorts = $env:TINYSOCS_SHIM_PREFERRED -split '[,; ]+' | Where-Object { $_ } | ForEach-Object { [int]$_ }
    if ($envPorts.Count -gt 0) { $candidates += $envPorts }
  }

  # 3) Previously set env
  if ($env:TINYSOCS_SHIM_PORT -as [int]) { $candidates += [int]$env:TINYSOCS_SHIM_PORT }

  # 4) Legacy defaults
  $candidates += 9202,19202,29202

  $seen = @{}
  foreach ($p in $candidates) {
    if ($seen.ContainsKey($p)) { continue } $seen[$p] = $true
    if (Test-PortBindable -Port $p -Address $Address) { return $p }
  }
  throw "[TinySOCS] Could not find a free/bindable shim port (tried: $($candidates -join ', '))."
}

function Write-OSShimScript {
  param([string]$Path,[string]$TargetUrl,[int]$Port)
  $code = @"
import json, os
from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.parse as urlparse
import requests

TARGET = os.getenv("SIEM_URL", "$TargetUrl")
VERIFY_TLS = False
TIMEOUT = 30
SAFE_WRITE_INDEX = os.getenv("SIEM_INDEX_WRITE", "siem_index")

def _strip_query_param(path: str, name: str) -> str:
    if "?" not in path:
        return path
    base, qs = path.split("?", 1)
    q = urlparse.parse_qsl(qs, keep_blank_values=True)
    q = [(k, v) for (k, v) in q if k.lower() != name.lower()]
    return base if not q else base + "?" + urlparse.urlencode(q)

def _sanitize_outbound_headers(hdrs: dict) -> dict:
    drop = {"host", "content-length", "connection", "accept-encoding"}
    return {k: v for k, v in hdrs.items() if k.lower() not in drop}

def _try_json_loads(blob: bytes):
    try:
        return json.loads(blob.decode("utf-8"))
    except Exception:
        return None

def _flatten_typeful_mappings(body_bytes: bytes) -> bytes:
    obj = _try_json_loads(body_bytes)
    if not isinstance(obj, dict):
        return body_bytes
    m = obj.get("mappings")
    if isinstance(m, dict) and len(m) == 1:
        inner_key = next(iter(m.keys()))
        inner_val = m.get(inner_key)
        if isinstance(inner_val, dict):
            obj["mappings"] = inner_val
            return json.dumps(obj, separators=(",", ":")).encode("utf-8")
    return body_bytes

def _rewrite_index_wildcards_in_path(path: str) -> str:
    def _fix_segment(seg: str) -> str:
        return SAFE_WRITE_INDEX if "*" in seg else seg
    base, q = (path.split("?", 1) + [""])[:2]
    parts = [p for p in base.split("/") if p != ""]
    if not parts:
        return path
    if len(parts) >= 2 and parts[1] in ("_bulk", "_doc", "_create", "_update", "_delete"):
        parts[0] = _fix_segment(parts[0])
    new_base = "/" + "/".join(parts)
    return new_base + ("?" + q if q else "")

def _rewrite_bulk_typeless(ndjson: bytes) -> bytes:
    out_lines = []
    lines = ndjson.splitlines()
    i = 0
    while i < len(lines):
        raw = lines[i]
        line = raw if isinstance(raw, (bytes, bytearray)) else str(raw).encode("utf-8")
        stripped = line.strip()
        if not stripped:
            out_lines.append(b"")
            i += 1
            continue
        try:
            meta = json.loads(stripped.decode("utf-8"))
        except Exception:
            out_lines.append(line)
            i += 1
            continue
        if isinstance(meta, dict) and len(meta) == 1:
            action = next(iter(meta.keys()))
            meta_body = meta[action]
            if isinstance(meta_body, dict):
                meta_body.pop("_type", None)
                meta_body.pop("type", None)
                idx = meta_body.get("_index")
                if isinstance(idx, str) and "*" in idx:
                    meta_body["_index"] = SAFE_WRITE_INDEX
            out_lines.append(json.dumps({action: meta_body}, separators=(",", ":")).encode("utf-8"))
        else:
            out_lines.append(line)
        i += 1
        if 'action' in locals() and action in ("index", "create", "update"):
            if i < len(lines):
                src = lines[i]
                out_lines.append(src if isinstance(src, (bytes, bytearray)) else str(src).encode("utf-8"))
                i += 1
    blob = b"\n".join(out_lines)
    if not blob.endswith(b"\n"):
        blob += b"\n"
    return blob

class Shim(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _reply(self, code, body, headers=None):
        b = body if isinstance(body, (bytes, bytearray)) else str(body).encode("utf-8")
        try:
            self.send_response(code)
            if headers:
                for k, v in headers.items():
                    self.send_header(k, v)
            self.send_header("Content-Length", str(len(b)))
            self.send_header("Connection", "close")
            self.end_headers()
            try:
                self.wfile.write(b)
            except BrokenPipeError:
                pass
        except BrokenPipeError:
            pass

    def _proxy(self, method):
        if self.path.startswith("/_license"):
            payload = {"license":{"status":"active","type":"basic"},"features":{}}
            return self._reply(200, json.dumps(payload), {"Content-Type":"application/json"})

        path = _strip_query_param(self.path, "include_type_name")
        path = _rewrite_index_wildcards_in_path(path)
        url = TARGET + path

        length = int(self.headers.get("Content-Length","0") or "0")
        data = self.rfile.read(length) if length > 0 else None
        content_type = (self.headers.get("Content-Type") or "").lower()

        if data and "/_bulk" in path:
            data = _rewrite_bulk_typeless(data)
            content_type = "application/x-ndjson"
        elif data and any(s in path for s in ("/_template", "/_index_template", "/_component_template", "/_index")):
            if "json" in content_type or path.endswith((".json",)):
                data = _flatten_typeful_mappings(data)

        headers = _sanitize_outbound_headers({k: v for k, v in self.headers.items()})
        if data is not None:
            headers["Content-Length"] = str(len(data))
        if content_type:
            headers["Content-Type"] = content_type

        try:
            resp = requests.request(method, url, headers=headers, data=data, verify=VERIFY_TLS, timeout=TIMEOUT)
            resp_ct = resp.headers.get("Content-Type", "application/octet-stream")
            return self._reply(resp.status_code, resp.content, {"Content-Type": resp_ct})
        except requests.exceptions.RequestException as e:
            return self._reply(502, json.dumps({"error": str(e)}), {"Content-Type":"application/json"})

    def do_GET(self):   self._proxy("GET")
    def do_POST(self):  self._proxy("POST")
    def do_PUT(self):   self._proxy("PUT")
    def do_HEAD(self):  self._proxy("HEAD")
    def do_DELETE(self): self._proxy("DELETE")
    def log_message(self, fmt, *args): pass

if __name__ == "__main__":
    port = int(os.getenv("TINYSOCS_SHIM_PORT", "$Port"))
    httpd = HTTPServer(("127.0.0.1", port), Shim)
    print(f"OpenSearch shim listening on http://127.0.0.1:{port} -> {TARGET} (safe_write_index={SAFE_WRITE_INDEX})", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
"@
  New-Item -ItemType Directory -Force -Path (Split-Path $Path) | Out-Null
  $code | Set-Content -Path $Path -Encoding UTF8
}

function Start-OSShim {
  param(
    [string]$TargetUrl = $env:SIEM_URL,
    [int[]]$PreferredPorts = @(),
    [int]$Port
  )
  if (-not $TargetUrl) { $TargetUrl = "https://127.0.0.1:9201" }

  # Choose a port (honor explicit -Port first)
  if ($Port -le 0) { $Port = Get-TinySOCSShimPort -PreferredPorts $PreferredPorts }
  $env:TINYSOCS_SHIM_PORT = "$Port"

  $script = Join-Path $PSScriptRoot "tools\os_shim.py"
  # Write-OSShimScript -Path $script -TargetUrl $TargetUrl -Port $Port

  try { & netsh advfirewall firewall add rule name="TinySOCS OS Shim ($Port)" dir=in action=allow protocol=TCP localport=$Port | Out-Null } catch {}

  # If already listening on that port, consider it good
  if (Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue) { return $true }

  $venv = Join-Path $PSScriptRoot ".venv\Scripts\Activate.ps1"
  $cmd  = if (Test-Path $venv) { ". `"$venv`"; python `"$script`"" } else { "python `"$script`"" }
  Start-Process -WindowStyle Minimized powershell -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-Command', $cmd) | Out-Null

  $max = [DateTime]::UtcNow.AddSeconds(5)
  while ([DateTime]::UtcNow -lt $max) {
    Start-Sleep -Milliseconds 300
    if (Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue) { return $true }
  }
  Write-Warning "[TinySOCS] OS shim did not start listening on :$Port"
  return $false
}

function Stop-OSShim {
  param([int[]]$Ports = @())

  # Kill by bound port(s)
  if ($Ports.Count -gt 0) {
    $pids = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
      Where-Object { $_.LocalPort -in $Ports } |
      Select-Object -Expand OwningProcess -Unique
    foreach ($procId in $pids) {
      try { Stop-Process -Id $procId -Force } catch {}
    }
  }

  # Fallback: kill any python that launched our shim script
  Get-CimInstance Win32_Process -Filter "Name='python.exe' OR Name='python3.11.exe'" |
    Where-Object { $_.CommandLine -match 'os_shim\.py' } |
    ForEach-Object { try { Stop-Process -Id $_.ProcessId -Force } catch {} }
}

function Patch-WLBYaml-Local([string]$YamlPath, [int]$ShimPort) {
  $content = Get-Content $YamlPath -Raw

  # Prefer replacing an existing hosts line
  $hostsLine = "hosts: [`"http://127.0.0.1:$ShimPort`"]"
  $content = $content -replace 'hosts:\s*\[[^\]]+\]', $hostsLine

  # Remove ssl.verification_mode (shim is http)
  $content = $content -replace '(?m)^\s*ssl\.verification_mode:.*\r?\n?', ''

  # Ensure output.elasticsearch has hosts
  if ($content -notmatch '(?ms)output\.elasticsearch:\s*') {
    $content += "`r`noutput.elasticsearch:`r`n  $hostsLine`r`nallow_older_versions: true`r`n"
  } elseif ($content -notmatch '(?ms)output\.elasticsearch:.*?hosts:\s*\[') {
    $content = $content -replace '(?ms)(output\.elasticsearch:\s*)(\r?\n)', ('$1$2  ' + $hostsLine + "`r`n")
  }

  Set-Content -Path $YamlPath -Value $content -Encoding UTF8 -Force
  Write-Host ("[TinySOCS] Patched winlogbeat.yml -> http://127.0.0.1:{0}" -f $ShimPort) -ForegroundColor Green

  $svc = Get-Service -Name winlogbeat -ErrorAction SilentlyContinue
  if ($svc) { try { Restart-Service winlogbeat -Force -ErrorAction SilentlyContinue } catch {} }
}

function Ensure-OSShim-And-PointWinlogbeat {
  param(
    [string]$InstallDir = $Global:TinySOCS_WinlogbeatDir,
    [string]$TargetUrl  = $env:SIEM_URL,
    [int]   $ShimPort
  )

  # ── Persistence/lock: if set, never touch Winlogbeat again (no shim/yaml changes)
  if ($env:TINYSOCS_LOCK_WINLOGBEAT -eq '1') {
    Write-Host "[TinySOCS] Winlogbeat locked; skipping shim & YAML changes." -ForegroundColor Yellow
    return
  }

  if (-not $TargetUrl) { $TargetUrl = "https://127.0.0.1:9201" }

  # 1) Decide shim port (explicit > existing env > auto-pick)
  if ($ShimPort -le 0) {
    if ($env:TINYSOCS_SHIM_PORT -as [int]) { $ShimPort = [int]$env:TINYSOCS_SHIM_PORT }
  }
  if ($ShimPort -le 0) {
    # Start with default finder; Start-OSShim sets $env:TINYSOCS_SHIM_PORT
    Start-OSShim -TargetUrl $TargetUrl | Out-Null
    $ShimPort = [int]$env:TINYSOCS_SHIM_PORT
  } else {
    # Honor caller-specified port
    Start-OSShim -TargetUrl $TargetUrl -Port $ShimPort | Out-Null
  }

  if ($ShimPort -le 0) { throw "[TinySOCS] Shim port not set." }

  # 2) Persist shim port so future runs reuse it (no flapping)
  try { [Environment]::SetEnvironmentVariable("TINYSOCS_SHIM_PORT","$ShimPort","Machine") } catch {}

  # 3) Patch Winlogbeat YAML to use the shim and restart service
  try {
    $yml  = Join-Path $InstallDir "winlogbeat.yml"
    Patch-WLBYaml-Local -YamlPath $yml -ShimPort $ShimPort
  }
  catch [System.UnauthorizedAccessException] {
    # Self-elevate once and continue
    if (-not (Test-IsAdmin)) {
      $cmd = "Ensure-OSShim-And-PointWinlogbeat -InstallDir `"$InstallDir`" -TargetUrl `"$TargetUrl`" -ShimPort $ShimPort"
      [void](Ensure-AdminOrRelaunch -PostCommand $cmd)
      return
    }
    throw
  }
}

function Install-Winlogbeat {
  param(
    # Elastic fallback version (only used when NOT using the OpenSearch fork)
    [string]$Version    = "7.17.9",
    [string]$InstallDir = $Global:TinySOCS_WinlogbeatDir,
    [switch]$OpenSearchFork,                  # prefer OpenSearch-Beats build
    [string]$OpenSearchBeatsZipUrl            # optional direct URL to a Winlogbeat(OpenSearch) zip
  )

  if (Test-Path (Join-Path $InstallDir "winlogbeat.exe")) {
    Write-Host ("[TinySOCS] Winlogbeat already installed at {0}" -f $InstallDir) -ForegroundColor Green
    return
  }

  try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

  $arch     = if ([Environment]::Is64BitOperatingSystem) { "windows-x86_64" } else { "windows-x86" }
  $useOSB   = $OpenSearchFork -or $Global:TinySOCS_DefaultUseOpenSearchBeats -or ($env:TINYSOCS_USE_OPENSEARCH_BEATS -eq "1")
  $tmp      = Join-Path $env:TEMP ("winlogbeat-download-{0}.zip" -f ([guid]::NewGuid()))
  
  if ($useOSB) {
    # ---------- OpenSearch Beats fork ----------
    # EITHER supply a direct URL via -OpenSearchBeatsZipUrl or env:OPENSEARCH_BEATS_ZIP_URL,
    # OR drop the zip at .\tools\winlogbeat-opensearch-$arch.zip and we'll use that.
    $osbUrl = if ($OpenSearchBeatsZipUrl) { $OpenSearchBeatsZipUrl } elseif ($env:OPENSEARCH_BEATS_ZIP_URL) { $env:OPENSEARCH_BEATS_ZIP_URL } else { $null }
    $local  = Join-Path $PSScriptRoot ("tools\winlogbeat-opensearch-{0}.zip" -f $arch)
  
    if ($osbUrl) {
      Write-Host ("[TinySOCS] Downloading Winlogbeat (OpenSearch fork) from: {0}" -f $osbUrl) -ForegroundColor DarkCyan
      Invoke-WebRequest -Uri $osbUrl -OutFile $tmp -UseBasicParsing
    } elseif (Test-Path $local) {
      Write-Host ("[TinySOCS] Using bundled OpenSearch Winlogbeat archive: {0}" -f (Split-Path $local -Leaf)) -ForegroundColor DarkCyan
      Copy-Item $local $tmp -Force
    } else {
      throw "[TinySOCS] OpenSearch Beats zip not provided. Set -OpenSearchBeatsZipUrl or OPENSEARCH_BEATS_ZIP_URL, or place tools\winlogbeat-opensearch-$arch.zip"
    }
  } else {
    # ---------- Elastic 7.17.x fallback (works better with OpenSearch than 8.x) ----------
    $zip  = "winlogbeat-$Version-$arch.zip"
    $url  = "https://artifacts.elastic.co/downloads/beats/winlogbeat/$zip"
    Write-Host ("[TinySOCS] Downloading Winlogbeat {0} ({1})..." -f $Version, $arch) -ForegroundColor DarkCyan
    Invoke-WebRequest -Uri $url -OutFile $tmp -UseBasicParsing
  }

  Write-Host ("[TinySOCS] Extracting to {0}..." -f $InstallDir) -ForegroundColor DarkCyan
  $extractDir = Join-Path $env:TEMP ("wlb-extract-{0}" -f ([guid]::NewGuid()))
  Expand-Archive -Path $tmp -DestinationPath $extractDir -Force
  New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
  
  # If the zip contains a single top-level folder, dive into it; otherwise copy all.
  $rootEntries = Get-ChildItem $extractDir
  if ($rootEntries.Count -eq 1 -and $rootEntries[0].PSIsContainer) {
    Copy-Item -Path (Join-Path $rootEntries[0].FullName "*") -Destination $InstallDir -Recurse -Force
  } else {
    Copy-Item -Path (Join-Path $extractDir "*") -Destination $InstallDir -Recurse -Force
  }

  # Ensure runtime dirs exist so the service can start cleanly
  New-Item -ItemType Directory -Path $Global:TinySOCS_WinlogbeatData -Force | Out-Null
  New-Item -ItemType Directory -Path (Join-Path $Global:TinySOCS_WinlogbeatData "logs") -Force | Out-Null
  New-Item -ItemType Directory -Path (Join-Path $InstallDir "data") -Force | Out-Null

  # Minimal config -> OpenSearch direct (Phase 3 default)
$pass = if ($env:OPENSEARCH_INITIAL_ADMIN_PASSWORD) { $env:OPENSEARCH_INITIAL_ADMIN_PASSWORD } else { "ChangeMe123!" }
$hosts = if ($env:SIEM_URL) { $env:SIEM_URL } else { "https://127.0.0.1:9201" }

$yml = @"
winlogbeat.event_logs:
  - name: Security
  - name: System
  - name: Application
  - name: Microsoft-Windows-Sysmon/Operational
  - name: Microsoft-Windows-PowerShell/Operational

# --- Ship directly to OpenSearch (no Logstash) ---
output.opensearch:
  hosts: ["$hosts"]
  username: "$($env:SIEM_USER)"         # default 'admin'
  password: "$pass"
  ssl.verification_mode: none           # self-signed in dev
  index: "winlogbeat-%{+YYYY.MM.dd}"

  output.elasticsearch:
  hosts: ["http://127.0.0.1:${TINYSOCS_SHIM_PORT}"]  # set by Start-OSShim (defaults to 9202/19202 fallback)
  username: "admin"
  password: "$pass"
  allow_older_versions: true

setup.ilm.enabled: false
"@
$yml | Set-Content -Path (Join-Path $InstallDir "winlogbeat.yml") -Encoding UTF8
}

function Install-Or-Repair-WinlogbeatService {
  param([string]$InstallDir = $Global:TinySOCS_WinlogbeatDir)

  $targetNorm = Resolve-NormalPath $InstallDir
  $svcWmi = Get-CimInstance Win32_Service -Filter "Name='winlogbeat'" -ErrorAction SilentlyContinue

  if ($svcWmi) {
    $currExe = Get-ExePathFromServicePathName -PathName $svcWmi.PathName
    $currDir = Resolve-NormalPath (Split-Path $currExe -Parent)
    if ($currDir -ne $targetNorm) {
      Write-Warning ("[TinySOCS] 'winlogbeat' service points to '{0}' not '{1}' - replacing it." -f $currDir, $targetNorm)
      Stop-And-Delete-ServiceSafely -Name winlogbeat -TimeoutSec 20
      $svcWmi = $null
    } else {
      Write-Host "[TinySOCS] Existing 'winlogbeat' service already points to TinySOCS path; keeping it." -ForegroundColor Green
    }
  }

  $binPath = ('"{0}\winlogbeat.exe" --environment=windows_service -c "{0}\winlogbeat.yml" --path.home "{0}" --path.data "{1}" --path.logs "{1}\logs"' -f $InstallDir, $Global:TinySOCS_WinlogbeatData)

  if (-not $svcWmi) {
    sc.exe create winlogbeat binPath= $binPath start= auto | Out-Null
    sc.exe description winlogbeat "Winlogbeat (TinySOCS-managed)" | Out-Null
  } else {
    try { sc.exe config winlogbeat start= auto | Out-Null } catch {}
    try { sc.exe config winlogbeat binPath= $binPath | Out-Null } catch {}
  }

  New-Item -ItemType Directory -Path $Global:TinySOCS_WinlogbeatData -Force | Out-Null
  New-Item -ItemType Directory -Path (Join-Path $Global:TinySOCS_WinlogbeatData "logs") -Force | Out-Null
  New-Item -ItemType Directory -Path (Join-Path $InstallDir "data") -Force | Out-Null

  $exe = Join-Path $InstallDir "winlogbeat.exe"
  $yml = Join-Path $InstallDir "winlogbeat.yml"
  Write-Host "[TinySOCS] Validating winlogbeat config..." -ForegroundColor DarkCyan
  $stdOut = Join-Path $env:TEMP "wlb_test_out.txt"
  $stdErr = Join-Path $env:TEMP "wlb_test_err.txt"
  $argStr = ('test config -c "{0}"' -f $yml)
  $proc = Start-Process -FilePath $exe -WorkingDirectory $InstallDir `
           -ArgumentList $argStr -NoNewWindow -Wait -PassThru `
           -RedirectStandardOutput $stdOut -RedirectStandardError $stdErr
  if ($proc.ExitCode -ne 0) {
    Write-Error ("[TinySOCS] winlogbeat config validation failed (exit {0})." -f $proc.ExitCode)
    Get-Content $stdOut -ErrorAction SilentlyContinue | Select-Object -Last 40 | Write-Host
    Get-Content $stdErr -ErrorAction SilentlyContinue | Select-Object -Last 40 | Write-Host
    throw "winlogbeat test config failed"
  }
  Write-Host "[TinySOCS] Config OK." -ForegroundColor Green
  # Make sure the shim is up and Winlogbeat points to it
  Ensure-OSShim-And-PointWinlogbeat -InstallDir $InstallDir

  try { Set-Service winlogbeat -StartupType Automatic -ErrorAction SilentlyContinue } catch {}
  Start-WinlogbeatAndWaitHealthy -TimeoutSec 60 -InstallDir $InstallDir
}

function Invoke-WinlogbeatDiagnostic {
  param(
    [string]$InstallDir,
    [int]$Seconds = 12
  )
  try {
    $exe = Join-Path $InstallDir 'winlogbeat.exe'
    $yml = Join-Path $InstallDir 'winlogbeat.yml'
    $out = Join-Path $env:TEMP 'wlb_diag_out.txt'
    $err = Join-Path $env:TEMP 'wlb_diag_err.txt'
    $args = ('run -e -c "{0}" --path.home "{1}" --path.data "{2}" --path.logs "{2}\logs" -d "*"' -f $yml, $InstallDir, $Global:TinySOCS_WinlogbeatData)

    $p = Start-Process -FilePath $exe -WorkingDirectory $InstallDir `
          -ArgumentList $args -PassThru -RedirectStandardOutput $out -RedirectStandardError $err
    try { Wait-Process -Id $p.Id -Timeout $Seconds } catch {}
    if (-not $p.HasExited) { try { Stop-Process -Id $p.Id -Force } catch {} }

    Write-Host "[TinySOCS] Diagnostic (stdout tail):" -ForegroundColor Yellow
    Get-Content $out -ErrorAction SilentlyContinue | Select-Object -Last 60 | Write-Host
    Write-Host "[TinySOCS] Diagnostic (stderr tail):" -ForegroundColor Yellow
    Get-Content $err -ErrorAction SilentlyContinue | Select-Object -Last 60 | Write-Host
  } catch {
    Write-Warning ("[TinySOCS] Diagnostic run failed: {0}" -f $_.Exception.Message)
  }
}

function Start-WinlogbeatAndWaitHealthy {
  param(
    [int]$TimeoutSec = 60,
    [string]$InstallDir = $Global:TinySOCS_WinlogbeatDir,
    [int]$Attempts = 3
  )

  for ($try = 1; $try -le $Attempts; $try++) {
    if ($try -gt 1) {
      Write-Warning ("[TinySOCS] winlogbeat start retry {0}/{1} (clearing lock & ensuring no console instance)..." -f $try, $Attempts)
    }

    # Ensure no console instance from our dir; then clear lock if stale
    Stop-WinlogbeatConsoleFromDir -TargetDir $InstallDir
    Remove-WinlogbeatStaleLock -DataPath $Global:TinySOCS_WinlogbeatData

    # Stop service if stuck in 'Starting'/'Stopping'
    $svc = Get-Service -Name winlogbeat -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -in 'StartPending','StopPending') {
      try { Stop-Service winlogbeat -Force -ErrorAction SilentlyContinue } catch {}
      Start-Sleep -Milliseconds 800
    }

# Ensure the service actually exists before Start-Service is attempted
if (-not (Get-Service -Name winlogbeat -ErrorAction SilentlyContinue)) {
  try {
    # Create the service NOW if something removed it mid-run
    $exeDir = $InstallDir
    $binPath = ('"{0}\winlogbeat.exe" --environment=windows_service -c "{0}\winlogbeat.yml" --path.home "{0}" --path.data "{1}" --path.logs "{1}\logs"' -f $exeDir, $Global:TinySOCS_WinlogbeatData)
    sc.exe create winlogbeat binPath= $binPath start= auto | Out-Null
    sc.exe description winlogbeat "Winlogbeat (TinySOCS-managed)" | Out-Null
  } catch {}
}

    # Start (or re-start) the service
    try { Start-Service winlogbeat -ErrorAction SilentlyContinue } catch {}

    # Wait for Running
    $deadline = (Get-Date).AddSeconds([Math]::Ceiling($TimeoutSec / $Attempts))
    do {
      Start-Sleep -Milliseconds 700
      try { $svc = Get-Service -Name winlogbeat -ErrorAction Stop } catch {}
      if ($svc -and $svc.Status -eq 'Running') { break }
    } while ((Get-Date) -lt $deadline)

    if ($svc -and $svc.Status -eq 'Running') {
      # (Optional) quick hint from logs
      $logDir = Join-Path $Global:TinySOCS_WinlogbeatData 'logs'
      if (Test-Path $logDir) {
        try {
          $last = Get-ChildItem $logDir -Filter 'winlogbeat*.log' | Sort-Object LastWriteTime -Desc | Select-Object -First 1
          if ($last) {
            $lines = Get-Content $last.FullName -Tail 200 -ErrorAction SilentlyContinue
            $hint = ($lines | Where-Object { $_ -match 'Connection .*established|Beat .* start' } | Select-Object -Last 1)
            if ($hint) { Write-Host ("[TinySOCS] Log hint: {0}" -f $hint) -ForegroundColor DarkGray }
          }
        } catch {}
      }
      return  # success
    }

    # If not running yet: try to stop before next attempt
    try { Stop-Service winlogbeat -Force -ErrorAction SilentlyContinue } catch {}
    Start-Sleep -Milliseconds 600
  }

  # Hard failure path: print details + run the timed diagnostic
  Write-Error ("[TinySOCS] winlogbeat failed to reach Running state after {0} attempt(s)." -f $Attempts)

  Write-Host "[TinySOCS] Service configuration:" -ForegroundColor Yellow
  sc.exe qc winlogbeat | Write-Host

  Write-Host "[TinySOCS] Recent Application/SCM events mentioning winlogbeat:" -ForegroundColor Yellow
  try {
    Get-WinEvent -MaxEvents 200 -FilterHashtable @{ LogName='Application' } |
      Where-Object { $_.ProviderName -in @('winlogbeat','Service Control Manager') -and $_.Message -match 'winlogbeat' } |
      Select-Object -First 15 |
      ForEach-Object { $_.TimeCreated.ToString('u') + ' - ' + $_.Message } | Write-Host
  } catch {}

  Write-Host "[TinySOCS] Running timed diagnostic (capturing ~15s of startup output)..." -ForegroundColor Yellow
  Invoke-WinlogbeatDiagnostic -InstallDir $InstallDir -Seconds 15
  throw "winlogbeat not healthy"
}

function Get-WinlogbeatStatus {
  $svc  = Get-Service -Name winlogbeat -ErrorAction SilentlyContinue
  $img  = $null
  try { $img = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\winlogbeat' -Name ImagePath -ErrorAction Stop).ImagePath } catch {}

  $exePath = $null
  if ($img) { $exePath = Get-ExePathFromServicePathName -PathName $img }
  $dir  = if ($exePath) { Split-Path $exePath -Parent } else { $null }
  $ver  = if ($exePath -and (Test-Path $exePath)) { (Get-Item $exePath).VersionInfo.FileVersion } else { $null }
  $logs = Join-Path $Global:TinySOCS_WinlogbeatData 'Logs'

  $svcState = $null
  $svcName  = $null
  if ($svc) { $svcState = $svc.Status; $svcName = $svc.Name }

  [pscustomobject]@{
    ServiceState      = $svcState
    ServiceName       = $svcName
    ServiceImagePath  = $img
    ExePath           = $exePath
    ExeDir            = $dir
    FileVersion       = $ver
    LogsPath          = $logs
  }
}

function Ensure-WinlogbeatSingleton {
  param(
    [string]$InstallDir = $Global:TinySOCS_WinlogbeatDir,
    [string]$Version    = "8.14.3"
  )

  try { Stop-OtherWinlogbeatInstances -TargetDir $InstallDir } catch { Write-Warning ("[TinySOCS] Stop-OtherWinlogbeatInstances error: {0}" -f $_.Exception.Message) }

  if (!(Test-Path (Join-Path $InstallDir "winlogbeat.exe"))) {
    Write-Host ("[TinySOCS] Installing Winlogbeat to {0} ..." -f $InstallDir) -ForegroundColor Yellow
    try {
      $osb = $Global:TinySOCS_DefaultUseOpenSearchBeats -or ($env:TINYSOCS_USE_OPENSEARCH_BEATS -eq "1")
      if ($osb) {
        Install-Winlogbeat -InstallDir $InstallDir -OpenSearchFork `
          -OpenSearchBeatsZipUrl $env:OPENSEARCH_BEATS_ZIP_URL
      } else {
        Install-Winlogbeat -Version $Version -InstallDir $InstallDir
      }
    }    catch { Write-Error ("[TinySOCS] Install-Winlogbeat failed: {0}" -f $_.Exception.Message); return }
  } else {
    Write-Host ("[TinySOCS] TinySOCS Winlogbeat already present at {0}" -f $InstallDir) -ForegroundColor Green
  }

  Install-Or-Repair-WinlogbeatService -InstallDir $InstallDir
  Get-WinlogbeatStatus | Format-List
}

function Ensure-TinySOCS-Agents {
  if (-not (Test-IsAdmin)) {
    if (-not (Ensure-AdminOrRelaunch -PostCommand 'Ensure-TinySOCS-Agents')) { return }
  }

  if (-not $global:TinySOCS_LogPath) {
    $global:TinySOCS_LogPath = Get-TinySOCSLogPath
    try { Start-Transcript -Path $global:TinySOCS_LogPath -Append | Out-Null } catch {}
  }
  Write-Host ("[TinySOCS] Logging to: {0}" -f $global:TinySOCS_LogPath) -ForegroundColor Yellow

  $sysmon = Get-Service -Name Sysmon64 -ErrorAction SilentlyContinue
  if ($sysmon) {
    Write-Host ("[TinySOCS] Sysmon present: {0} - {1}" -f $sysmon.Status, $sysmon.Name)
  } else {
    Write-Warning "[TinySOCS] Sysmon not detected. TinySOCS will still work, but richer detections come with Sysmon."
  }

  try {
    Ensure-WinlogbeatSingleton
  } catch {
    Write-Error ("[TinySOCS] Ensure-WinlogbeatSingleton fatal: {0}" -f $_.Exception.Message)
    throw
  }

  Write-Host "[TinySOCS] Agents ready. Generate test noise with: Invoke-TinySOCS-TestNoise -All" -ForegroundColor Cyan
  try { Stop-Transcript | Out-Null } catch {}
}

# ===================== Routes (logstash-free) =====================
function Show-TinySOCS-Targets {
  Write-Host ("LLM_MODE              = {0}" -f $env:LLM_MODE)
  Write-Host ("SIEM_BACKEND          = {0}" -f $env:SIEM_BACKEND)
  Write-Host ("SIEM_URL              = {0}" -f $env:SIEM_URL)
  if ($env:SIEM_USER)            { Write-Host ("SIEM_USER             = {0}" -f $env:SIEM_USER) }
  if ($env:SIEM_SSL_VERIFY)      { Write-Host ("SIEM_SSL_VERIFY       = {0}" -f $env:SIEM_SSL_VERIFY) }
  if ($env:SIEM_TIMEOUT_SECONDS) { Write-Host ("SIEM_TIMEOUT_SECONDS  = {0}" -f $env:SIEM_TIMEOUT_SECONDS) }
}

function Route-To-OpenSearch {
  param([switch]$Full)
  if (-not (Ensure-DockerReady)) { Write-Warning "[TinySOCS] Docker engine not available."; return }
  Use-OpenSearchSIEM
  Stop-ElasticStack
  Start-OpenSearchStack -Dashboards:$Full
  $env:SIEM_TIMEOUT_SECONDS = "60"
}

### DEPRECATED (Phase-5): Route-To-Elastic
  # TLS + self-signed (local lab)
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

  $pair  = '{0}:{1}' -f $User, $Pass
  $basic = 'Basic ' + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($pair))

  # 1) Template (idempotent) — prevents bad auto-creation
  $tpl = @{
    index_patterns = @("tinysocs_anchors*")
    template = @{
      settings = @{ number_of_shards = 1 }
      mappings = @{
        dynamic = "false"
        properties = @{
          node_url    = @{ type = 'keyword' }
          node        = @{ type = 'keyword' }
          node_id     = @{ type = 'keyword' }
          sequence    = @{ type = 'integer' }
          head_sha256 = @{ type = 'keyword' }
          anchored_at = @{ type = 'date'; format = 'strict_date_optional_time||epoch_millis' }
        }
      }
    }
    priority = 500
  } | ConvertTo-Json -Depth 20 -Compress
  Invoke-RestMethod -Method Put -Uri "$SiemUrl/_index_template/tinysocs_anchors_template" `
    -Headers @{Authorization=$basic} -Body $tpl -ContentType 'application/json' | Out-Null

  # 2) Ensure alias exists and is writeable
  $aliasExists = $false
  try {
    $null = Invoke-RestMethod -Method Get -Uri "$SiemUrl/_alias/tinysocs_anchors" -Headers @{Authorization=$basic}
    $aliasExists = $true
  } catch {}

  if (-not $aliasExists) {
    # Pick latest tinysocs_anchors_vN if present, else create v1
    $indices = $null
    try {
      $indices = Invoke-RestMethod -Method Get -Uri "$SiemUrl/_cat/indices/tinysocs_anchors_v*?format=json" -Headers @{Authorization=$basic}
    } catch {}

    if ($indices) {
      $max = ($indices.index | ForEach-Object { if ($_ -match 'tinysocs_anchors_v(\d+)'){ [int]$Matches[1] } } | Measure-Object -Maximum).Maximum
      $target = "tinysocs_anchors_v$max"
    } else {
      $target = "tinysocs_anchors_v1"
      $mapping = @{
        settings = @{ number_of_shards = 1 }
        mappings = @{
          properties = @{
            node_url    = @{ type = 'keyword' }
            node        = @{ type = 'keyword' }
            node_id     = @{ type = 'keyword' }
            sequence    = @{ type = 'integer' }
            head_sha256 = @{ type = 'keyword' }
            anchored_at = @{ type = 'date'; format = 'strict_date_optional_time||epoch_millis' }
          }
        }
      } | ConvertTo-Json -Depth 20 -Compress
      Invoke-RestMethod -Method Put -Uri "$SiemUrl/$target" -Headers @{Authorization=$basic} `
        -Body $mapping -ContentType 'application/json' | Out-Null
    }

    $aliasAdd = '{"actions":[{"add":{"index":"' + $target + '","alias":"tinysocs_anchors","is_write_index":true}}]}'
    Invoke-RestMethod -Method Post -Uri "$SiemUrl/_aliases" -Headers @{Authorization=$basic} `
      -Body $aliasAdd -ContentType 'application/json' | Out-Null
  }

  # 3) Sanity: anchored_at is truly a date
  $fc = Invoke-RestMethod -Method Post -Uri "$SiemUrl/tinysocs_anchors/_field_caps?fields=anchored_at" `
        -Headers @{Authorization=$basic}
  $isDate = $false
  try { $isDate = $fc.fields.anchored_at.date.type -eq 'date' } catch {}
  if (-not $isDate) { throw "anchored_at is not 'date'. Check template/alias." }
}

function Ensure-TinySocsLedgerHealthScript {
  param([int]$AnchorRetentionDays = 30, [int]$LocalLedgerDays = 14)

  $root = (Resolve-Path "$PSScriptRoot").Path
  $p    = Join-Path $root 'scripts\Ledger_Health.ps1'
  if (-not (Test-Path (Split-Path $p))) { New-Item -ItemType Directory -Path (Split-Path $p) -Force | Out-Null }

  if (-not (Test-Path $p)) {
    $content = @"
# TinySOCS Ledger Health & Retention (idempotent)
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[Net.ServicePointManager]::ServerCertificateValidationCallback = { \$true }
\$pair  = '{0}:{1}' -f \$env:SIEM_USER, \$env:SIEM_PASS
\$basic = 'Basic ' + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(\$pair))

# prune anchors older than $AnchorRetentionDays days
\$body = '{{"query":{{"range":{{"anchored_at":{{"lt":"now-$AnchorRetentionDays`d/d"}}}}}}}}'
Invoke-RestMethod -Method Post -Uri "\$env:SIEM_URL/tinysocs_anchors/_delete_by_query?conflicts=proceed" `
  -Headers @{Authorization=\$basic} -Body \$body -ContentType 'application/json' | Out-Null

# prune local ledger *.jsonl older than $LocalLedgerDays days
if (-not \$env:TINYSOCS_LEDGER_DIR -or -not (Test-Path \$env:TINYSOCS_LEDGER_DIR)) {
  \$env:TINYSOCS_LEDGER_DIR = "C:\tinysocs\ledger"
}
Get-ChildItem "\$env:TINYSOCS_LEDGER_DIR\*.jsonl" -ErrorAction SilentlyContinue |
  Where-Object { \$_.LastWriteTime -lt (Get-Date).AddDays(-$LocalLedgerDays) } |
  Remove-Item -Force -ErrorAction SilentlyContinue
"@
    [System.IO.File]::WriteAllText($p, $content, [System.Text.UTF8Encoding]::new($false))
  }
  return $p
}

function Register-TinySocsLedgerHealthTask {
  $script = Ensure-TinySocsLedgerHealthScript
  $exists = Get-ScheduledTask -TaskName 'TinySOCS_Ledger_Health' -ErrorAction SilentlyContinue
  if (-not $exists) {
    $action  = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$script`""
    $trigger = New-ScheduledTaskTrigger -Daily -At 03:35
    $task    = New-ScheduledTask -Action $action -Trigger $trigger -Settings (New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries)
    Register-ScheduledTask -TaskName 'TinySOCS_Ledger_Health' -InputObject $task -Force | Out-Null
  }
}

### DEPRECATED (Phase-5): Start-TinySOCS
#>

  if (-not (Test-Path $env:TINYSOCS_LEDGER_DIR)) { New-Item -ItemType Directory -Force -Path $env:TINYSOCS_LEDGER_DIR | Out-Null }

  if (-not $env:TINYSOCS_INSECURE_SKIP_VERIFY) { $env:TINYSOCS_INSECURE_SKIP_VERIFY = "1" }  # local/self-signed
  if (-not $env:REQUEST_TIMEOUT_SEC)   { $env:REQUEST_TIMEOUT_SEC   = "30" }
  if (-not $env:MASTER_DEADLINE_SEC)   { $env:MASTER_DEADLINE_SEC   = "120" }
  if (-not $env:SIEM_TIMEOUT_SECONDS)  { $env:SIEM_TIMEOUT_SECONDS  = "30" }
  if (-not $env:TINYSOCS_NODE_WORKERS) { $env:TINYSOCS_NODE_WORKERS = "2" }

  # Persist ledger dir machine-wide for future sessions (best-effort; requires admin for /M)
  try {
    $mach = [Environment]::GetEnvironmentVariable("TINYSOCS_LEDGER_DIR","Machine")
    if (-not $mach -or $mach -ne $env:TINYSOCS_LEDGER_DIR) {
      # use cmd /c so quoting is handled reliably
      $cmd = 'setx TINYSOCS_LEDGER_DIR "{0}" /M' -f $env:TINYSOCS_LEDGER_DIR
      Start-Process -FilePath "cmd.exe" -ArgumentList "/c", $cmd -WindowStyle Hidden -Wait | Out-Null
    }
  } catch {
    Write-Verbose "[TinySOCS] setx (machine) skipped: $($_.Exception.Message)"
  }

  # WinPS 5.1 TLS defaults (no-op on PS7+)
  if ($PSVersionTable.PSVersion.Major -le 5) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
  }

  # --- harden anchors index/alias so retention always works ---
  if (Get-Command Initialize-TinySocsAnchorsIndex -ErrorAction SilentlyContinue) {
    try { Initialize-TinySocsAnchorsIndex } catch { Write-Warning "[TinySOCS] Anchors init failed: $($_.Exception.Message)" }
  }

  # --- ensure Ledger_Health daily task exists (anchors + local JSONL retention) ---
  if (Get-Command Register-TinySocsLedgerHealthTask -ErrorAction SilentlyContinue) {
    try { Register-TinySocsLedgerHealthTask } catch { Write-Warning "[TinySOCS] Ledger_Health task ensure failed: $($_.Exception.Message)" }
  }

  # --- hand off to the main launcher ---
  Start-TinySOCS -Backend opensearch -Full:$false -Role $Role -LocalLLM:$LocalLLM `
    -NodePort $NodePort -Nodes $Nodes -Rules $Rules -Window $Window -NoWBSetup:$NoWBSetup
}


