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


def _validate_session(token: str) -> bool:
    """Check if a session token is valid and not expired."""
    import time
    if not token:
        return False
    expiry = _active_sessions.get(token)
    if expiry is None:
        return False
    if time.time() > expiry:
        _active_sessions.pop(token, None)
        return False
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
# TLS CA cert resolution
# ---------------------------------------------------------------------------
_ca_pem_cache: Optional[str] = None


def _ensure_pem(cert_path: Path) -> str:
    """Return a PEM file path for the given cert. Converts DER->PEM if needed."""
    raw = cert_path.read_bytes()
    if raw[:27] == b"-----BEGIN CERTIFICATE-----":
        print(f"[dashboard] CA cert: already PEM -> {cert_path}")
        return str(cert_path)

    # DER-encoded: convert to PEM
    import base64, tempfile
    print(f"[dashboard] CA cert: DER detected ({len(raw)} bytes, first4={raw[:4].hex()}), converting to PEM")
    b64 = base64.encodebytes(raw).decode("ascii")
    pem = f"-----BEGIN CERTIFICATE-----\n{b64}-----END CERTIFICATE-----\n"
    # Try to write next to the original
    pem_path = cert_path.parent / "ca-converted.pem"
    try:
        pem_path.write_text(pem, encoding="ascii")
        print(f"[dashboard] CA cert: DER->PEM converted -> {pem_path}")
        return str(pem_path)
    except Exception as exc:
        print(f"[dashboard] CA cert: write to {pem_path} failed: {exc}")
        fd, tmp = tempfile.mkstemp(suffix=".pem", prefix="tinysocs-ca-")
        os.write(fd, pem.encode("ascii"))
        os.close(fd)
        print(f"[dashboard] CA cert: DER->PEM converted -> {tmp} (temp)")
        return tmp


def _resolve_ca_cert() -> Any:
    """Find the TinyBox CA certificate for OpenSearch TLS verification.

    Returns a path to a PEM file (str), True for system bundle, or False to skip.
    Converts DER-encoded certs to PEM automatically.
    """
    global _ca_pem_cache
    if _ca_pem_cache is not None:
        return _ca_pem_cache

    # 0. Explicit disable — honour SIEM_SSL_VERIFY=false before anything else
    verify_str = os.getenv("SIEM_SSL_VERIFY", "").lower()
    if verify_str in ("false", "0", "no"):
        print("[dashboard] CA cert: verification disabled (SIEM_SSL_VERIFY=false)")
        _ca_pem_cache = False  # type: ignore[assignment]
        return False

    # 1. Explicit CA cert path
    explicit = os.getenv("SIEM_CA_CERT", "")
    if explicit and Path(explicit).is_file():
        print(f"[dashboard] CA cert: SIEM_CA_CERT={explicit}")
        _ca_pem_cache = _ensure_pem(Path(explicit))
        return _ca_pem_cache

    if verify_str in ("true", "1", "yes"):
        print("[dashboard] CA cert: using system bundle (SIEM_SSL_VERIFY=true)")
        _ca_pem_cache = True  # type: ignore[assignment]
        return True

    # 2. Auto-discover TinyBox CA cert
    pd = os.getenv("ProgramData", "C:\\ProgramData")
    candidates = [
        Path(pd) / "TinySocs" / "OpenSearch" / "config" / "root-ca.pem",
        Path(pd) / "TinySocs" / "OpenSearch" / "config" / "certs" / "ca.pem",
        Path(pd) / "TinySocs" / "OpenSearch" / "config" / "certs" / "ca.cer",
    ]
    for cert_path in candidates:
        if not cert_path.is_file():
            continue
        print(f"[dashboard] CA cert: found {cert_path}")
        _ca_pem_cache = _ensure_pem(cert_path)
        return _ca_pem_cache

    # 3. No cert found — disable verification with a warning
    print(f"[dashboard] CA cert: NO cert found (SIEM_SSL_VERIFY={verify_str!r}); verify=False")
    _ca_pem_cache = False  # type: ignore[assignment]
    return False


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
    passwd = os.getenv("SIEM_PASS", "admin")
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


# ---------------------------------------------------------------------------
# Data API endpoints (no auth — local operator tool)
# ---------------------------------------------------------------------------
@dashboard_app.get("/api/alerts/timeline")
async def api_alert_timeline(hours: int = Query(24, ge=1, le=720)):
    """Alert counts bucketed by hour and severity."""
    body = {
        "query": {"range": {"timestamp": {"gte": f"now-{hours}h", "lte": "now"}}},
        "aggs": {
            "timeline": {
                "date_histogram": {"field": "timestamp", "fixed_interval": "1h", "min_doc_count": 0},
                "aggs": {
                    "by_severity": {"terms": {"field": "alert.severity.keyword", "size": 10}}
                },
            }
        },
    }
    resp = await _safe_query_async("tinysocs-alerts-*", body)
    buckets = resp.get("aggregations", {}).get("timeline", {}).get("buckets", [])
    return {
        "hours": hours,
        "buckets": [
            {
                "time": b.get("key_as_string", ""),
                "count": b.get("doc_count", 0),
                "severity": {
                    s["key"]: s["doc_count"]
                    for s in b.get("by_severity", {}).get("buckets", [])
                },
            }
            for b in buckets
        ],
        "error": resp.get("error"),
    }


@dashboard_app.get("/api/alerts/summary")
async def api_alert_summary(hours: int = Query(24, ge=1, le=720)):
    """Summary stats: total, by severity, top rules, top hosts."""
    # Total + severity
    body_sev = {
        "query": {"range": {"timestamp": {"gte": f"now-{hours}h", "lte": "now"}}},
        "aggs": {"by_severity": {"terms": {"field": "alert.severity.keyword", "size": 10}}},
    }
    resp_sev = await _safe_query_async("tinysocs-alerts-*", body_sev)

    total_hit = resp_sev.get("hits", {}).get("total", {})
    total = total_hit.get("value", 0) if isinstance(total_hit, dict) else int(total_hit)
    severity = {
        b["key"]: b["doc_count"]
        for b in resp_sev.get("aggregations", {}).get("by_severity", {}).get("buckets", [])
    }

    # Top rules
    body_rules = {
        "query": {"range": {"timestamp": {"gte": f"now-{hours}h", "lte": "now"}}},
        "aggs": {"by_rule": {"terms": {"field": "alert.rule_id.keyword", "size": 10, "order": {"_count": "desc"}}}},
    }
    resp_rules = await _safe_query_async("tinysocs-alerts-*", body_rules)
    top_rules = [
        {"rule": b["key"], "count": b["doc_count"]}
        for b in resp_rules.get("aggregations", {}).get("by_rule", {}).get("buckets", [])
    ]

    # Top hosts — alerts store host in source.computer_name
    body_hosts = {
        "query": {"range": {"timestamp": {"gte": f"now-{hours}h", "lte": "now"}}},
        "aggs": {"by_host": {"terms": {"field": "source.computer_name.keyword", "size": 10, "order": {"_count": "desc"}}}},
    }
    resp_hosts = await _safe_query_async("tinysocs-alerts-*", body_hosts)
    top_hosts = [
        {"host": b["key"], "count": b["doc_count"]}
        for b in resp_hosts.get("aggregations", {}).get("by_host", {}).get("buckets", [])
    ]

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
):
    """Fetch individual fired detections with full details."""
    body = {
        "query": {"range": {"timestamp": {"gte": f"now-{hours}h", "lte": "now"}}},
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
            "host": src.get("source", {}).get("computer_name", ""),
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
    passwd = os.getenv("SIEM_PASS", "admin")
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
    hostname: str = Query(..., description="Host to query"),
    hours: int = Query(24, ge=1, le=720),
):
    """Event count over time for a specific host, bucketed with channel breakdown."""
    # Determine interval based on time range
    if hours <= 6:
        interval = "5m"
    elif hours <= 48:
        interval = "1h"
    else:
        interval = "6h"

    body = {
        "query": {
            "bool": {
                "must": [
                    {"term": {"winlog.computer_name": hostname}},
                    {"range": {"@timestamp": {"gte": f"now-{hours}h", "lte": "now"}}},
                ]
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
            result = _chat_anthropic(prompt, session_id, ephemeral_messages, system_text, _chat_call_tool)
        elif llm_mode == "openai":
            result = _chat_openai(prompt, session_id, ephemeral_messages, system_text, _chat_call_tool)
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
    body = {
        "query": {"range": {"@timestamp": {"gte": "now-24h", "lte": "now"}}},
        "aggs": {
            "by_host": {
                "terms": {"field": "winlog.computer_name", "size": 50},
                "aggs": {
                    "last_seen": {"max": {"field": "@timestamp"}},
                    "first_seen": {"min": {"field": "@timestamp"}},
                    "event_count": {"value_count": {"field": "@timestamp"}},
                    "top_channels": {"terms": {"field": "winlog.channel", "size": 5}},
                    "top_event_ids": {"terms": {"field": "event.code", "size": 5}},
                },
            }
        },
    }
    # Run winlog + alerts queries in parallel via thread pool
    alert_body = {
        "query": {"range": {"timestamp": {"gte": "now-24h", "lte": "now"}}},
        "size": 100,
        "sort": [{"timestamp": {"order": "desc"}}],
        "aggs": {
            "by_host": {
                "terms": {"field": "source.computer_name.keyword", "size": 50},
                "aggs": {
                    "by_severity": {"terms": {"field": "alert.severity.keyword", "size": 5}},
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
        top_channels = [
            {"channel": ch["key"], "count": ch["doc_count"]}
            for ch in b.get("top_channels", {}).get("buckets", [])
        ]
        top_events = [
            {"event_id": str(ev["key"]), "count": ev["doc_count"]}
            for ev in b.get("top_event_ids", {}).get("buckets", [])
        ]
        hb = heartbeat_data.get(hostname, {})
        hosts.append({
            "hostname": hostname,
            "event_count": b.get("event_count", {}).get("value", b["doc_count"]),
            "last_seen": b.get("last_seen", {}).get("value_as_string", ""),
            "first_seen": b.get("first_seen", {}).get("value_as_string", ""),
            "alert_count": alert_counts.get(hostname, 0),
            "alert_severities": alert_severities.get(hostname, {}),
            "active_detections": host_detections.get(hostname, [])[:5],
            "top_channels": top_channels,
            "top_event_ids": top_events,
            "agent_version": hb.get("agent_version", ""),
            "uptime": hb.get("uptime", ""),
            "events_shipped": hb.get("events_shipped", 0),
            "queue_files": hb.get("queue_files", 0),
            "last_ship_time": hb.get("last_ship_time", ""),
            "heartbeat_ts": hb.get("heartbeat_ts", ""),
        })
    return {"hosts": hosts, "error": resp.get("error")}


# ---------------------------------------------------------------------------
# Version status API (Phase 15 M5)
# ---------------------------------------------------------------------------
@dashboard_app.get("/api/version/status")
async def api_version_status():
    """Return manifest data + fleet version comparison."""
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
    try:
        from tinysocs.reporting.mitre_coverage import (
            load_all_rules, extract_mitre_annotations, calculate_coverage,
        )
        rules = load_all_rules()
        annotations = extract_mitre_annotations(rules)
        coverage = calculate_coverage(annotations)
        return {"ok": True, **coverage}
    except Exception as exc:
        return JSONResponse(status_code=500, content={"ok": False, "error": str(exc)})


@dashboard_app.get("/api/mitre/navigator-layer")
async def api_mitre_navigator_layer():
    """Download ATT&CK Navigator JSON layer."""
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
    passwd = os.getenv("SIEM_PASS", "admin")
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
    return {"events": events, "total": len(events), "index": index, "error": resp.get("error")}


@dashboard_app.get("/api/actions")
def api_actions():
    """List guided response recommendations."""
    try:
        from tinysocs.actions.executor import list_actions
        items = list_actions(limit=50)
        return {"actions": items}
    except Exception as exc:
        return {"actions": [], "error": str(exc)}


@dashboard_app.post("/api/actions/{action_id}/approve")
def api_action_approve(action_id: str):
    """Acknowledge a recommendation — operator will handle it manually."""
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
        "- Do not retry a tool if it already returned data (even if 0 results)."
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
        result = _chat_anthropic(user_message, session_id, messages, system_text, _chat_call_tool)
    elif llm_mode == "openai":
        result = _chat_openai(user_message, session_id, messages, system_text, _chat_call_tool)
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
    model = os.getenv("ANTHROPIC_MODEL") or "claude-sonnet-4-20250514"

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
    _OAI_MODEL = os.getenv("OPENAI_MODEL") or "gpt-4o-mini"

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
        global _ca_pem_cache
        _ca_pem_cache = None

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
    passwd = os.getenv("SIEM_PASS", "admin")

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
.left-panels { flex: 1; min-width: 0; display: grid; grid-template-columns: 1fr 1fr; gap: 16px;
               margin-right: 400px; transition: margin-right 0.25s ease; }
.left-panels.expanded { margin-right: 52px; }
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
}
@media (max-width: 700px) { .left-panels { grid-template-columns: 1fr; } }

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

/* Collapsible card bodies */
.card-body { overflow: hidden; transition: max-height 0.25s ease; }
.card-body.collapsed { max-height: 0 !important; padding-top: 0; padding-bottom: 0; }
.card-body:not(.collapsed) { max-height: 4000px; }
#events-content { min-height: 420px; }
.collapse-chevron { cursor:pointer; font-size:16px; color:var(--muted); transition:transform 0.25s ease; user-select:none; padding:4px 8px; }
.collapse-chevron.collapsed { transform: rotate(-90deg); }

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

/* Fired Detections panel */
.detections-card { }
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
<div id="versionDriftBanner" style="display:none;background:#e67e22;color:#fff;padding:8px 24px;font-size:13px;font-weight:500;text-align:center;cursor:pointer" onclick="ensureCardExpanded('fleet');document.getElementById('body-fleet').scrollIntoView({behavior:'smooth'})">
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
        <div id="loginError"></div>
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
        <input type="text" id="s_OPENAI_MODEL" placeholder="gpt-4o-mini">
      </div>
      <div class="field" id="field_anthropic">
        <label>Anthropic API Key</label>
        <input type="text" id="s_ANTHROPIC_API_KEY" placeholder="sk-ant-...">
        <label>Anthropic Model</label>
        <input type="text" id="s_ANTHROPIC_MODEL" placeholder="claude-sonnet-4-20250514">
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
        <input type="text" id="s_GREYNOISE_API_KEY" placeholder="(free: 5,000/day)">
      </div>
      <div class="field">
        <button class="btn-save" onclick="testThreatIntel()" style="width:auto;background:var(--surface);color:var(--accent);border:1px solid var(--accent)">Test Providers</button>
        <span id="threatIntelTestStatus" style="font-size:12px;margin-left:8px"></span>
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

<div class="main-layout">
  <div class="left-panels">
    <!-- Alert Summary -->
    <div class="card">
      <div class="card-header-sticky" style="display:flex;align-items:center;gap:4px">
        <span class="collapse-chevron" onclick="toggleCardCollapse('summary')" id="chevron-summary">&#x25BC;</span>
        <h2 style="margin:0;cursor:pointer;flex:1" onclick="toggleCardCollapse('summary')">Alert Summary</h2>
      </div>
      <div class="card-body" id="body-summary">
        <div id="summary-content"><div class="loading">Loading...</div></div>
      </div>
    </div>

    <!-- Alert Timeline -->
    <div class="card">
      <div class="card-header-sticky" style="display:flex;align-items:center;gap:4px">
        <span class="collapse-chevron" onclick="toggleCardCollapse('timeline')" id="chevron-timeline">&#x25BC;</span>
        <h2 style="margin:0;cursor:pointer;flex:1" onclick="toggleCardCollapse('timeline')">Alert Timeline</h2>
      </div>
      <div class="card-body" id="body-timeline">
        <div id="timeline-content"><div class="loading">Loading...</div></div>
      </div>
    </div>

    <!-- Fired Detections (full width) -->
    <div class="card full detections-card">
      <div class="card-header-sticky" style="display:flex;align-items:center;gap:4px">
        <span class="collapse-chevron" onclick="toggleCardCollapse('detections')" id="chevron-detections">&#x25BC;</span>
        <h2 style="margin:0;white-space:nowrap;cursor:pointer" onclick="toggleCardCollapse('detections')">Fired Detections</h2>
        <select id="detStatusFilter" style="font-size:11px;padding:2px 6px;background:var(--bg);color:var(--text);border:1px solid var(--border);border-radius:4px;max-width:200px;margin-left:8px" onchange="_detectionsPage=0;_openDetectionIdx=-1;renderDetections()">
          <option value="active" selected>Active (new + ack)</option>
          <option value="all">All</option>
          <option value="new">New only</option>
          <option value="acknowledged">Acknowledged</option>
          <option value="dismissed">Dismissed</option>
        </select>
      </div>
      <div class="card-body" id="body-detections">
        <div id="detections-content"><div class="loading">Loading...</div></div>
      </div>
    </div>

    <!-- Fleet Health (full width) -->
    <div class="card full">
      <div class="card-header-sticky" style="display:flex;align-items:center;gap:4px">
        <span class="collapse-chevron" onclick="toggleCardCollapse('fleet')" id="chevron-fleet">&#x25BC;</span>
        <h2 style="margin:0;cursor:pointer;flex:1" onclick="toggleCardCollapse('fleet')">Fleet Health</h2>
      </div>
      <div class="card-body" id="body-fleet">
        <div id="fleet-content"><div class="loading">Loading...</div></div>
      </div>
    </div>

    <!-- Host Event Timeline (inline widget, hidden until a host is clicked) -->
    <div class="card full timeline-card" id="hostTimelineCard" style="display:none">
      <div style="display:flex;justify-content:space-between;align-items:center">
        <h2 id="hostTimelineTitle" style="margin:0;font-size:14px;color:var(--muted);text-transform:uppercase;letter-spacing:0.5px">Host Event Timeline</h2>
        <div style="display:flex;gap:6px;align-items:center">
          <select id="hostTimelineRange" onchange="refreshHostTimeline()" style="font-size:12px;padding:3px 8px;background:var(--bg);color:var(--text);border:1px solid var(--border);border-radius:4px">
            <option value="1">1 hour</option>
            <option value="6">6 hours</option>
            <option value="24" selected>24 hours</option>
            <option value="48">48 hours</option>
            <option value="168">7 days</option>
          </select>
          <button onclick="closeHostTimeline()" style="background:none;border:none;color:var(--muted);font-size:16px;cursor:pointer;padding:2px 6px" title="Hide">&times;</button>
        </div>
      </div>
      <div id="hostTimelineChart" style="margin-top:10px"><div class="empty">Click a hostname to view its event timeline</div></div>
      <div id="hostTimelineLegend" style="margin-top:8px;display:flex;flex-wrap:wrap;gap:10px;font-size:11px"></div>
    </div>

    <!-- Event Explorer -->
    <div class="card full" id="event-explorer-card">
      <div class="card-header-sticky" style="display:flex;align-items:center;gap:4px">
        <span class="collapse-chevron" onclick="toggleCardCollapse('explorer')" id="chevron-explorer">&#x25BC;</span>
        <h2 style="margin:0;cursor:pointer;flex:1" onclick="toggleCardCollapse('explorer')">Event Explorer</h2>
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
        <div id="events-content"><div class="loading">Loading...</div></div>
      </div>
    </div>

    <!-- Alert Rules -->
    <div class="card full rules-card" id="rules-card">
      <div class="card-header-sticky" style="display:flex;align-items:center;gap:4px">
        <span class="collapse-chevron" onclick="toggleCardCollapse('rules')" id="chevron-rules">&#x25BC;</span>
        <h2 style="margin:0;white-space:nowrap;cursor:pointer" onclick="toggleCardCollapse('rules')">Alert Rules</h2>
        <select id="rulesFilter" onchange="filterRules()" style="flex:1;margin-bottom:0;height:32px;margin-left:8px">
          <option value="all">All Rules</option>
          <option value="builtin">Built-in</option>
          <option value="custom">Custom</option>
          <option value="enabled">Enabled</option>
          <option value="disabled">Disabled</option>
        </select>
        <div style="display:flex;gap:6px;align-items:center;margin-left:auto">
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

    <!-- Compliance Reports (Phase 14 M4) -->
    <div class="card full" id="compliance-card">
      <div class="card-header-sticky" style="display:flex;align-items:center;gap:4px">
        <span class="collapse-chevron" onclick="toggleCardCollapse('compliance')" id="chevron-compliance">&#x25BC;</span>
        <h2 style="margin:0;white-space:nowrap;cursor:pointer" onclick="toggleCardCollapse('compliance')">Compliance Coverage</h2>
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
        <a id="complianceDownload" href="#" style="display:none;font-size:16px;padding:2px 8px;color:var(--muted);text-decoration:none;margin-left:auto;cursor:pointer" title="Download HTML report" download>&#x2B07;</a>
      </div>
      <div class="card-body" id="body-compliance">
      <div id="compliance-summary" style="display:none;gap:12px;margin:12px 0">
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
        <span class="collapse-chevron" onclick="toggleCardCollapse('mitre')" id="chevron-mitre">&#x25BC;</span>
        <h2 style="margin:0;cursor:pointer" onclick="toggleCardCollapse('mitre')">MITRE ATT&CK Coverage</h2>
        <a id="mitreDownload" href="#" style="font-size:16px;padding:2px 8px;color:var(--muted);text-decoration:none;margin-left:auto;cursor:pointer" title="Download Navigator layer JSON" onclick="downloadNavigatorLayer(event)">&#x2B07;</a>
      </div>
      <div class="card-body" id="body-mitre">
      <div id="mitre-summary" style="display:none;gap:12px;margin:12px 0">
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

  <div class="right-panel" id="rightPanel">
    <button class="assistant-toggle" onclick="toggleAssistant()" id="assistantToggle" title="Toggle assistant panel">&laquo;</button>
    <div class="card assistant-card">
      <div class="assistant-header-inner" style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px;padding-left:28px">
        <h2 style="margin:0">Assistant</h2>
        <button onclick="clearChat()" style="font-size:10px;padding:2px 8px;background:var(--bg);color:var(--muted);border:1px solid var(--border);border-radius:4px;cursor:pointer" title="Start a new conversation">New Chat</button>
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

async function fetchJSON(path) {
  try {
    const r = await fetch(BASE + path);
    return await r.json();
  } catch(e) {
    return { error: e.message };
  }
}

async function loadSummary() {
  const el = document.getElementById('summary-content');
  const d = await fetchJSON(`/api/alerts/summary?hours=${hours}`);
  if (d.error && !d.severity) { el.innerHTML = `<div class="empty">${d.error}</div>`; return; }

  const total = d.total || 0;
  const sev = d.severity || {};
  const sevOrder = ['critical','high','medium','low','info'];

  let html = '<div class="stat-row">';
  html += `<div class="stat"><div class="value">${total}</div><div class="label">Total Alerts</div></div>`;
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
  const d = await fetchJSON(`/api/alerts/timeline?hours=${hours}`);
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
const _DETECTIONS_PER_PAGE = 10;

async function loadDetections() {
  const el = document.getElementById('detections-content');
  const d = await fetchJSON(`/api/detections/fired?hours=${hours}&limit=50`);
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

  // Pager
  if (totalPages > 1) {
    html += `<div class="pager">`;
    html += `<button onclick="detectionsPagePrev()" ${_detectionsPage === 0 ? 'disabled' : ''}>&laquo; Prev</button>`;
    html += `<span>Page ${_detectionsPage + 1} of ${totalPages} (${totalItems} detections)</span>`;
    html += `<button onclick="detectionsPageNext()" ${_detectionsPage >= totalPages - 1 ? 'disabled' : ''}>Next &raquo;</button>`;
    html += '</div>';
  }

  el.innerHTML = html;
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
  ensureCardExpanded('explorer');
  if (explorer) explorer.scrollIntoView({behavior: 'smooth', block: 'start'});
}

let _fleetCache = [];
let _openFleetIdx = -1;
let _fleetPage = 0;
const _FLEET_PER_PAGE = 10;
let _fleetVersionMap = {};

async function loadFleet() {
  const el = document.getElementById('fleet-content');
  const d = await fetchJSON('/api/fleet/health');
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
    // Show/hide version drift banner
    const banner = document.getElementById('versionDriftBanner');
    const bannerText = document.getElementById('versionDriftText');
    if (banner && vs.has_outdated) {
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
  renderFleet();
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
    html += `<td style="font-weight:600"><a href="#" style="color:var(--accent);text-decoration:none" onclick="event.stopPropagation(); event.preventDefault(); openHostTimeline('${escapeHtml(h.hostname)}')">${escapeHtml(h.hostname)}</a></td>`;
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

    const channels = (h.top_channels || []).map(c => `${c.channel} (${c.count})`).join(', ') || 'None';
    html += `<div><span style="color:var(--muted)">Top Channels:</span> ${escapeHtml(channels)}</div>`;
    const evtIds = (h.top_event_ids || []).map(e => `${e.event_id} (${e.count})`).join(', ') || 'None';
    html += `<div><span style="color:var(--muted)">Top Event IDs:</span> ${escapeHtml(evtIds)}</div>`;

    const sevs = h.alert_severities || {};
    const sevStr = Object.entries(sevs).map(([k,v]) => `${k}: ${v}`).join(', ') || 'None';
    html += `<div><span style="color:var(--muted)">Alerts by Severity:</span> ${escapeHtml(sevStr)}</div>`;
    const dets = (h.active_detections || []).map(d => escapeHtml(d)).join(', ') || 'None';
    html += `<div><span style="color:var(--muted)">Active Detections:</span> ${dets}</div>`;
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
  }
}

function viewHostLogs(hostname) {
  document.getElementById('eventIndex').value = 'tinysocs-winlog-*';
  document.getElementById('eventQuery').value = `winlog.computer_name:"${hostname}"`;
  document.getElementById('eventTimeRange').value = '24h';
  loadEvents();
  const explorer = document.getElementById('event-explorer-card');
  ensureCardExpanded('explorer');
  if (explorer) explorer.scrollIntoView({behavior: 'smooth', block: 'start'});
}

function viewHostAlerts(hostname) {
  document.getElementById('eventIndex').value = 'tinysocs-alerts-*';
  document.getElementById('eventQuery').value = `source.computer_name:"${hostname}"`;
  document.getElementById('eventTimeRange').value = '24h';
  loadEvents();
  const explorer = document.getElementById('event-explorer-card');
  ensureCardExpanded('explorer');
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
const _EVENTS_PER_PAGE = 15;

function toggleEventsLive(on) { _eventsLive = on; }

function toggleCardCollapse(id) {
  const body = document.getElementById('body-' + id);
  const chevron = document.getElementById('chevron-' + id);
  if (!body || !chevron) return;
  body.classList.toggle('collapsed');
  chevron.classList.toggle('collapsed');
  const collapsed = JSON.parse(localStorage.getItem('tinysocs_collapsed') || '{}');
  collapsed[id] = body.classList.contains('collapsed');
  localStorage.setItem('tinysocs_collapsed', JSON.stringify(collapsed));
}

function restoreCollapseState() {
  const collapsed = JSON.parse(localStorage.getItem('tinysocs_collapsed') || '{}');
  for (const [id, isCollapsed] of Object.entries(collapsed)) {
    if (isCollapsed) {
      const body = document.getElementById('body-' + id);
      const chevron = document.getElementById('chevron-' + id);
      if (body) body.classList.add('collapsed');
      if (chevron) chevron.classList.add('collapsed');
    }
  }
}

function ensureCardExpanded(id) {
  const body = document.getElementById('body-' + id);
  const chevron = document.getElementById('chevron-' + id);
  if (body && body.classList.contains('collapsed')) {
    body.classList.remove('collapsed');
    if (chevron) chevron.classList.remove('collapsed');
    const collapsed = JSON.parse(localStorage.getItem('tinysocs_collapsed') || '{}');
    collapsed[id] = false;
    localStorage.setItem('tinysocs_collapsed', JSON.stringify(collapsed));
  }
}

async function loadEvents(background) {
  const el = document.getElementById('events-content');
  const q = document.getElementById('eventQuery').value;
  const idx = document.getElementById('eventIndex').value;
  const timeRange = document.getElementById('eventTimeRange').value;
  if (!background) el.innerHTML = '<div class="loading">Loading...</div>';
  let url = `/api/events/recent?limit=200&index=${encodeURIComponent(idx)}&q=${encodeURIComponent(q)}`;
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

  // Pagination
  const totalItems = events.length;
  const totalPages = Math.ceil(totalItems / _EVENTS_PER_PAGE);
  if (_eventsPage >= totalPages) _eventsPage = totalPages - 1;
  if (_eventsPage < 0) _eventsPage = 0;
  const pageStart = _eventsPage * _EVENTS_PER_PAGE;
  const pageEvents = events.slice(pageStart, pageStart + _EVENTS_PER_PAGE);

  const isAlerts = idx.includes('alerts');
  let html = isAlerts
    ? '<table><tr><th>Time</th><th>Host</th><th>Rule</th><th>Severity</th><th>Description</th></tr>'
    : '<table><tr><th>Time</th><th>Host</th><th>Channel</th><th>ID</th><th>Message</th></tr>';
  for (const e of pageEvents) {
    const t = e.timestamp ? new Date(e.timestamp).toLocaleString() : '';
    const msg = (e.message || '').substring(0, 120);
    const hostLink = e.host ? `<a href="#" style="color:var(--accent);text-decoration:none" onclick="event.preventDefault();openHostTimeline('${escapeHtml(e.host)}')">${escapeHtml(e.host)}</a>` : '';
    html += `<tr><td style="white-space:nowrap">${t}</td><td>${hostLink}</td><td>${e.channel}</td><td>${e.event_id}</td><td style="font-size:12px;color:var(--muted)">${msg}</td></tr>`;
  }
  html += '</table>';

  // Pager
  if (totalPages > 1) {
    html += `<div class="pager">`;
    html += `<button onclick="eventsPagePrev()" ${_eventsPage === 0 ? 'disabled' : ''}>&laquo; Prev</button>`;
    html += `<span>Page ${_eventsPage + 1} of ${totalPages} (${totalItems} events)</span>`;
    html += `<button onclick="eventsPageNext()" ${_eventsPage >= totalPages - 1 ? 'disabled' : ''}>Next &raquo;</button>`;
    html += '</div>';
  }

  el.innerHTML = html;
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
let _hostTimelineHost = '';
const _channelColors = [
  '#4a90d9', '#e67e22', '#2ecc71', '#e74c3c', '#9b59b6',
  '#1abc9c', '#f1c40f', '#e84393', '#00cec9', '#fd79a8',
];

function openHostTimeline(hostname) {
  _hostTimelineHost = hostname;
  const card = document.getElementById('hostTimelineCard');
  card.style.display = '';
  document.getElementById('hostTimelineTitle').textContent = hostname + ' \u2014 Event Flow';
  refreshHostTimeline();
  card.scrollIntoView({behavior: 'smooth', block: 'nearest'});
}

function closeHostTimeline() {
  document.getElementById('hostTimelineCard').style.display = 'none';
}

async function refreshHostTimeline() {
  const el = document.getElementById('hostTimelineChart');
  const legendEl = document.getElementById('hostTimelineLegend');
  const hrs = document.getElementById('hostTimelineRange').value;
  el.innerHTML = '<div class="loading">Loading...</div>';
  legendEl.innerHTML = '';

  const d = await fetchJSON(`/api/host/timeline?hostname=${encodeURIComponent(_hostTimelineHost)}&hours=${hrs}`);
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

  // SVG dimensions
  const W = 900, H = 220;
  const pad = {top: 16, right: 16, bottom: 28, left: 46};
  const plotW = W - pad.left - pad.right;
  const plotH = H - pad.top - pad.bottom;
  const n = buckets.length;

  // Y-axis ticks
  const yTicks = [];
  const step = Math.max(1, Math.ceil(maxY / 4));
  for (let t = 0; t <= maxY; t += step) yTicks.push(t);
  if (yTicks[yTicks.length - 1] < maxY) yTicks.push(Math.ceil(maxY));

  let svg = `<svg viewBox="0 0 ${W} ${H}" style="width:100%;max-height:220px" xmlns="http://www.w3.org/2000/svg">`;

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
const _RULES_PER_PAGE = 10;

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

  // Pager
  if (totalPages > 1) {
    html += `<div class="pager">`;
    html += `<button onclick="rulesPagePrev()" ${_rulesPage === 0 ? 'disabled' : ''}>&laquo; Prev</button>`;
    html += `<span>Page ${_rulesPage + 1} of ${totalPages} (${totalRules} rules)</span>`;
    html += `<button onclick="rulesPageNext()" ${_rulesPage >= totalPages - 1 ? 'disabled' : ''}>Next &raquo;</button>`;
    html += '</div>';
  }

  el.innerHTML = html;
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
  ensureCardExpanded('explorer');
  if (explorer) explorer.scrollIntoView({behavior: 'smooth', block: 'start'});
}

function refreshAll() {
  document.getElementById('lastUpdate').textContent = 'Refreshing...';
  // Load local data (rules) immediately — no SIEM dependency
  loadRules();
  // Load SIEM-dependent data; only refresh Event Explorer when Live is on
  const tasks = [loadSummary(), loadTimeline(), loadDetections(), loadFleet()];
  if (_eventsLive) tasks.push(loadEvents(true));
  Promise.all(tasks)
    .then(() => {
      document.getElementById('lastUpdate').textContent = 'Updated ' + new Date().toLocaleTimeString();
    })
    .catch(() => {
      document.getElementById('lastUpdate').textContent = 'SIEM not connected — ' + new Date().toLocaleTimeString();
    });
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

async function sendChat() {
  const input = document.getElementById('chatInput');
  const msg = input.value.trim();
  if (!msg) return;

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
  document.getElementById('loginError').innerHTML = '';
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
      document.getElementById('loginError').innerHTML = `<div class="status-msg err" style="margin-top:8px">${escapeHtml(msg)}</div>`;
      return;
    }
    settingsPassword = pw;
    document.getElementById('settingsLogin').style.display = 'none';
    document.getElementById('settingsForm').style.display = 'block';
    populateSettings(d);
  } catch(e) {
    document.getElementById('loginError').innerHTML = `<div class="status-msg err" style="margin-top:8px">${escapeHtml(e.message)}</div>`;
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
    'SIEM_URL','SIEM_USER'];
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
    'SIEM_URL','SIEM_USER','SIEM_PASS'];
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
  const firstCard = document.querySelector('.left-panels .card');
  const header = document.querySelector('.header');
  const panel = document.getElementById('rightPanel');
  if (firstCard && panel) {
    const rect = firstCard.getBoundingClientRect();
    const minTop = header ? header.getBoundingClientRect().bottom : 0;
    panel.style.top = Math.max(rect.top, minTop) + 'px';
  }
}

// Start up — dashboard is behind login gate; don't load data until authed
restoreAssistantState();
alignAssistantPanel();
window.addEventListener('resize', alignAssistantPanel);
window.addEventListener('scroll', alignAssistantPanel);
setInterval(() => { if (_authToken) refreshAll(); }, 30000);

// ---- M0: Dashboard Login Gate ----
let _authToken = null;

async function doLogin() {
  const pw = document.getElementById('loginPassword').value;
  const errEl = document.getElementById('loginError');
  errEl.textContent = '';
  if (!pw) { errEl.textContent = 'Please enter a password'; return; }
  try {
    const r = await fetch(BASE + '/api/auth/login', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({password: pw}),
    });
    const d = await r.json();
    if (d.error) { errEl.textContent = d.error; return; }
    _authToken = d.token;
    try { sessionStorage.setItem('tinysocs_auth', _authToken); } catch(e) {}
    unlockDashboard();
  } catch(e) { errEl.textContent = 'Connection error: ' + e.message; }
}

function unlockDashboard() {
  document.getElementById('loginGate').style.display = 'none';
  document.getElementById('dashboardContent').style.visibility = 'visible';
  restoreCollapseState();
  checkLlmStatus();
  restoreChat();
  loadComplianceFrameworks();
  loadMitreCoverage();
  loadEvents();
  refreshAll();
}

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
  setTimeout(() => document.getElementById('loginPassword').focus(), 100);
}

function doLogout() {
  _authToken = null;
  try { sessionStorage.removeItem('tinysocs_auth'); } catch(e) {}
  showLoginGate();
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
  el.innerHTML = '<div class="loading">Loading...</div>';
  try {
    const r = await fetch(BASE + '/api/compliance/report?framework=' + encodeURIComponent(fw) + '&hours=' + hrs, {headers:{'Authorization':'Bearer '+_authToken}});
    const d = await r.json();
    if (!d.ok) { el.innerHTML = '<div style="color:var(--muted);font-size:13px">Error: ' + escapeHtml(d.error||'Unknown') + '</div>'; return; }
    sumEl.style.display = 'flex';
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
    const d = await r.json();
    if (!d.ok) return;
    const sumEl = document.getElementById('mitre-summary');
    sumEl.style.display = 'flex';
    document.getElementById('mitre-techniques').textContent = d.total_techniques || 0;
    document.getElementById('mitre-tactics').textContent = (d.total_tactics || 0) + '/14';
    // Count total annotated rules
    let ruleCount = 0;
    for (const tid of Object.keys(d.techniques || {})) {
      ruleCount += (d.techniques[tid].rules || []).length;
    }
    document.getElementById('mitre-rules').textContent = ruleCount;
    // Build tactic heatmap
    const heatmap = document.getElementById('mitre-heatmap');
    let html = '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:8px">';
    for (const ts of (d.tactic_summary || [])) {
      const count = ts.techniques_covered || 0;
      const bg = count === 0 ? 'var(--bg)' : count <= 2 ? '#2d5a3d' : count <= 5 ? '#27ae60' : '#1e8449';
      const border = count === 0 ? '1px solid var(--border)' : 'none';
      html += '<div style="background:' + bg + ';border:' + border + ';border-radius:6px;padding:10px 12px;cursor:pointer" onclick="toggleMitreTacticDetail(this,\'' + escapeHtml(ts.tactic) + '\',' + JSON.stringify(ts.technique_ids||[]).replace(/"/g,'&quot;') + ')" title="' + escapeHtml(ts.label) + '">';
      html += '<div style="font-size:12px;font-weight:600;color:' + (count > 0 ? '#fff' : 'var(--muted)') + '">' + escapeHtml(ts.label) + '</div>';
      html += '<div style="font-size:18px;font-weight:700;color:' + (count > 0 ? '#fff' : 'var(--muted)') + ';margin-top:4px">' + count + '</div>';
      html += '<div style="font-size:10px;color:' + (count > 0 ? 'rgba(255,255,255,0.7)' : 'var(--muted)') + '">techniques</div>';
      html += '</div>';
    }
    html += '</div>';
    heatmap.innerHTML = html;
  } catch(e) {
    console.error('MITRE coverage load error:', e);
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
