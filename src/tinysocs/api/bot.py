# tinysocs/api/bot.py
"""
TinySocs Bot Bridge (FastAPI)

Purpose:
  - Accept chat/webhook intents and stage operator actions.
  - Append a compact bot_action record to the node ledger via /evidence/append.

Security:
  - HMAC headers with BOT_SHARED_SECRET.
  - Supports styles: 'pipe' (ts|nonce), 'dot' (ts.nonce), or 'ts' (timestamp only).
  - Signature may be raw hex or 'sha256=<hex>'.
  - ±300s clock skew, 5-minute replay cache keyed by the exact signed message.

Env:
  BOT_SHARED_SECRET              HMAC secret for inbound bot calls (required)
  TINYSOCS_HMAC_STYLE            'pipe' | 'dot' | 'ts'  (default 'pipe')
  TINYSOCS_SIG_PREFIX            if truthy, accept/emit 'sha256=<hex>' (server always accepts both)
  MASTER_SHARED_SECRET           Reused when calling node /evidence/append (fallback for NODE_SECRET)
  NODE_SECRET                    Optional override for the secret used to call /evidence/append
  TINYSOCS_NODES                 Comma list; first is used to append ledger (default http://localhost:8081)
  TINYSOCS_INSECURE_SKIP_VERIFY  "1" to skip TLS verify to node (default 1)
  TINYSOCS_QUEUE_PATH            Path to actions queue JSONL (fallback if local actions_queue module not present)
  ACTIONS_QUEUE_PATH             Legacy/fallback env name for queue path
  TINYSOCS_SKEW_SECS             Override inbound skew seconds (default 300)
  BOT_PORT                       Uvicorn port (default 8090)
  TINYSOCS_BOT_WORKERS           Uvicorn workers (default 1)

Run:
  python -m tinysocs.api.bot  (uvicorn)
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests
import urllib3
import uvicorn
from fastapi import Body, Depends, FastAPI, HTTPException, Query, Request
from pydantic import BaseModel, Field

# Suppress InsecureRequestWarning for federation connections (verify=False)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ---------- permissive .env autoload (repo/.env or tinysocs/.env) ----------
def _parse_dotenv_content(s: str) -> None:
    for raw in s.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        k, v = k.strip(), v.strip().strip('"').strip("'")
        if k and (k not in os.environ):
            os.environ[k] = v

def _read_text_permissive(p: Path) -> str:
    for enc in ("utf-8", "utf-8-sig", "cp1252", "latin-1"):
        try:
            return p.read_text(encoding=enc)
        except UnicodeDecodeError:
            continue
    return p.read_bytes().decode("utf-8", errors="ignore")

def _load_dotenv_inplace() -> None:
    here = Path(__file__).resolve()
    candidates = [
        here.parents[2] / ".env",   # <repo>/.env
        here.parents[1] / ".env",   # <repo>/tinysocs/.env
        Path.cwd() / ".env",        # CWD
    ]
    for p in candidates:
        if p.is_file():
            try:
                _parse_dotenv_content(_read_text_permissive(p))
            except Exception as e:
                print(f"[bot] WARN: dotenv load failed for {p}: {e}")
            break

_load_dotenv_inplace()
# ---------------------------------------------------------------------------

# ---------- Env / defaults ----------
def _env(name: str, default: Optional[str] = None) -> Optional[str]:
    v = os.getenv(name)
    return v if v is not None else default

BOT_SECRET = (_env("BOT_SHARED_SECRET", "") or "")
NODE_SECRET = (_env("NODE_SECRET", _env("MASTER_SHARED_SECRET", "dev-secret-change-me")) or "dev-secret-change-me")
NODES = [x.strip() for x in (_env("TINYSOCS_NODES", "https://localhost:8081") or "").split(",") if x.strip()]
NODE_URL = NODES[0] if NODES else "https://localhost:8081"
NODE_TLS_VERIFY = str(_env("TINYSOCS_INSECURE_SKIP_VERIFY", "1")).lower() not in ("1", "true", "yes", "on")

# Queue path (fallback if we can't import a project-level actions_queue module)
_queue_path_env = _env("TINYSOCS_QUEUE_PATH") or _env("ACTIONS_QUEUE_PATH")
FALLBACK_QUEUE_PATH = Path(_queue_path_env or str(Path(__file__).resolve().parents[1] / "actions_queue.jsonl"))

ALLOWED_SKEW_SECONDS = int(_env("TINYSOCS_SKEW_SECS", "300") or "300")
REPLAY_CACHE_SECONDS = 300

# HMAC style for inbound requests (default 'pipe' to match master & PS helpers)
HMAC_STYLE = (_env("TINYSOCS_HMAC_STYLE", "pipe") or "pipe").strip().lower()

# Replay cache keyed by the exact signed message (ts / ts|nonce / ts.nonce)
_recent_ts: Dict[str, int] = {}  # replay_key -> expiry epoch

# ---------- Try to use the project's existing actions_queue.py ---------------
_aq = None
_aq_queue_path: Optional[str] = None
try:
    # Preferred: package style
    from tinysocs.agent import actions_queue as _aq  # type: ignore
except Exception:
    try:
        # Fallback: top-level module (repo root)
        import actions_queue as _aq  # type: ignore
    except Exception:
        _aq = None

if _aq is not None:
    # Surface queue path if the module defines it
    _aq_queue_path = getattr(_aq, "QUEUE_PATH", None)
# ---------------------------------------------------------------------------

def _effective_queue_path() -> Path:
    """
    Return the JSONL queue path we should read/write.
    Precedence: actions_queue.QUEUE_PATH > TINYSOCS_QUEUE_PATH/ACTIONS_QUEUE_PATH > fallback file next to this module.
    """
    qp = _aq_queue_path or str(FALLBACK_QUEUE_PATH)
    p = Path(qp).expanduser()
    if not p.is_absolute():
        p = (Path.cwd() / p).resolve()
    p.parent.mkdir(parents=True, exist_ok=True)
    return p

# ---------- HMAC auth (inbound) ----------
def _gc(now: int) -> None:
    stale = [k for k, exp in _recent_ts.items() if exp <= now]
    for k in stale:
        _recent_ts.pop(k, None)

def verify_hmac(request: Request) -> None:
    if not BOT_SECRET:
        raise HTTPException(status_code=500, detail="BOT_SHARED_SECRET not set")

    ts_hdr  = request.headers.get("X-TinySOCS-Timestamp")
    sig_hdr = request.headers.get("X-TinySOCS-Signature", "")
    nonce   = request.headers.get("X-TinySOCS-Nonce")

    # For pipe/dot, nonce is required
    if not ts_hdr or not sig_hdr or (HMAC_STYLE in ("pipe", "dot") and not nonce):
        raise HTTPException(status_code=401, detail="Missing auth headers")

    try:
        ts = int(ts_hdr)
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid timestamp")

    now = int(time.time())
    if abs(now - ts) > ALLOWED_SKEW_SECONDS:
        raise HTTPException(status_code=401, detail="Timestamp skew too large")

    if HMAC_STYLE == "dot":
        msg = f"{ts}.{nonce}"
    elif HMAC_STYLE == "pipe":
        msg = f"{ts}|{nonce}"
    else:  # 'ts'
        msg = str(ts)

    calc = hmac.new(BOT_SECRET.encode("utf-8"), msg.encode("utf-8"), hashlib.sha256).hexdigest()
    provided = sig_hdr.split("=", 1)[1] if sig_hdr.startswith("sha256=") else sig_hdr
    if not hmac.compare_digest(calc, provided):
        raise HTTPException(status_code=401, detail="Bad signature")

    # Replay protection keyed by the exact message string
    _gc(now)
    exp = _recent_ts.get(msg)
    if exp and exp > now:
        raise HTTPException(status_code=401, detail="Replay detected")
    _recent_ts[msg] = now + REPLAY_CACHE_SECONDS

# ---------- Queue + ledger helpers ----------
def _fallback_queue_append(obj: Dict[str, Any]) -> Path:
    p = _effective_queue_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")
    return p

def _stage_entry(entry: Dict[str, Any]) -> Path:
    """
    Prefer the project's actions_queue.stage_actions if present.
    Otherwise, write to our fallback JSONL path.
    """
    if _aq is not None and hasattr(_aq, "stage_actions"):
        try:
            _aq.stage_actions([entry])  # your existing interface
            qp = getattr(_aq, "QUEUE_PATH", None)
            return Path(qp) if qp else _effective_queue_path()
        except Exception as e:
            print(f"[bot] WARN: actions_queue.stage_actions failed: {e} — using fallback queue")
            return _fallback_queue_append(entry)
    else:
        return _fallback_queue_append(entry)

def _read_queue_items(limit: int) -> List[Dict[str, Any]]:
    """
    Read up to `limit` newest items from the JSONL queue file. Newest-first.
    """
    p = _effective_queue_path()
    if not p.exists():
        return []
    try:
        with p.open("r", encoding="utf-8") as f:
            lines = [ln for ln in f.readlines() if ln.strip()]
    except Exception:
        return []
    # take tail, then reverse for newest-first
    tail = lines[-limit:] if limit > 0 else lines
    items: List[Dict[str, Any]] = []
    for ln in tail:
        try:
            items.append(json.loads(ln))
        except Exception:
            continue
    items.reverse()
    return items

def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

def _node_hmac_headers() -> Dict[str, str]:
    """
    Bot -> node ledger append uses timestamp-only HMAC (node accepts ts).
    If TINYSOCS_SIG_PREFIX is truthy, emit 'sha256=<hex>' form.
    """
    ts = str(int(time.time()))
    sig_hex = hmac.new(NODE_SECRET.encode("utf-8"), ts.encode("utf-8"), hashlib.sha256).hexdigest()
    pref = str(os.getenv("TINYSOCS_SIG_PREFIX", "1")).strip().lower()
    signature = f"sha256={sig_hex}" if pref in ("1", "true", "yes", "on") else sig_hex
    return {
        "X-TinySOCS-Timestamp": ts,
        "X-TinySOCS-Signature": signature,
        "User-Agent": "tinysocs/bot",
        "Content-Type": "application/json",
    }


def _ledger_attempts(entry: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
    """
    Try several body shapes against /evidence/append and return
    (success, details). details contains per-shape status + body.
    """
    url = f"{NODE_URL.rstrip('/')}/evidence/append"
    headers = _node_hmac_headers()

    shapes: List[Tuple[str, Any]] = [
        ("payload", {"payload": entry}),
        ("entry",   {"entry": entry}),
        ("raw",     entry),
        ("evidence",{"evidence": entry}),
    ]

    results: List[Dict[str, Any]] = []
    for name, body in shapes:
        try:
            r = requests.post(url, headers=headers, json=body, timeout=8, verify=NODE_TLS_VERIFY)
            ok = 200 <= r.status_code < 300
            results.append({
                "shape": name,
                "status": r.status_code,
                "ok": ok,
                "body": (r.text or "").strip()[:2000],
            })
            if ok:
                return True, {"shape": name, "status": r.status_code, "body": (r.text or "").strip()}
        except Exception as e:
            results.append({
                "shape": name,
                "status": None,
                "ok": False,
                "error": f"{type(e).__name__}: {e}",
            })
    return False, {"attempts": results}

def _post_ledger(entry: Dict[str, Any]) -> str:
    ok, details = _ledger_attempts(entry)
    if ok:
        return "ok"
    attempts = details.get("attempts", [])
    if attempts:
        last = attempts[-1]
        return f"ledger_append_failed: tried {len(attempts)} shapes; last_status={last.get('status')}; last_body={(last.get('body') or last.get('error') or '(no body)')}"
    return "ledger_append_failed: unknown"

# ---------- Models ----------
class AckBody(BaseModel):
    incident_id: str = Field(..., description="Incident identifier (opaque)")
    tldr: Optional[str] = Field(None, description="Short description/summary")
    who: Optional[str] = Field(None, description="Human display name (optional)")

ALLOWED_ACTIONS = {"block_ip", "disable_user", "isolate_host", "open_ticket", "ack_incident"}

class ExecBody(BaseModel):
    action: str = Field(..., description=f"One of: {', '.join(sorted(ALLOWED_ACTIONS))}")
    params: Dict[str, Any] = Field(default_factory=dict)
    who: Optional[str] = Field(None, description="Human display name (optional)")
    dry_run: Optional[bool] = True  # allow caller to specify, default True

class QueueItem(BaseModel):
    timestamp: str
    action: str
    params: Dict[str, Any] = Field(default_factory=dict)
    status: str = "staged"
    who: Optional[str] = None
    kind: Optional[str] = "bot_action"

class ActionsResponse(BaseModel):
    items: List[QueueItem]
    count: int
    next_cursor: Optional[str] = None

# ---------- Guards ----------
def _guard_params(action: str, params: Dict[str, Any]) -> None:
    if action == "block_ip":
        ip = str(params.get("ip", "")).strip()
        if not ip:
            raise HTTPException(status_code=400, detail="block_ip requires 'ip'")
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            raise HTTPException(status_code=400, detail="invalid IP")
        if ip_obj.is_loopback:
            raise HTTPException(status_code=400, detail="loopback IP not allowed")
    elif action == "disable_user":
        user = str(params.get("user", "")).strip()
        if not user:
            raise HTTPException(status_code=400, detail="disable_user requires 'user'")
    elif action == "isolate_host":
        host = str(params.get("host", "")).strip()
        if not host:
            raise HTTPException(status_code=400, detail="isolate_host requires 'host'")
    elif action == "open_ticket":
        # accept either 'title' or 'summary' for convenience
        title = str(params.get("title", "")).strip() or str(params.get("summary", "")).strip()
        if not title:
            raise HTTPException(status_code=400, detail="open_ticket requires 'title' or 'summary'")
    else:
        raise HTTPException(status_code=400, detail="unsupported action")

# ---------- App ----------
app = FastAPI(title="TinySocs Bot Bridge", version="0.2.0")

# ---------- Phase 17 M0: Early --demo detection (before dashboard import) ----------
# Must set env var BEFORE importing dashboard, since _DEMO_MODE and _DASHBOARD_HTML
# are evaluated at module load time.
import sys as _sys
if "--demo" in _sys.argv:
    os.environ["TINYSOCS_DEMO_MODE"] = "1"
    os.environ.setdefault("SIEM_PASS", "demo")

# ---------- Phase 12: Mount built-in operator dashboard ----------
try:
    from tinysocs.api.dashboard import dashboard_app
    app.mount("/dashboard", dashboard_app)
except ImportError:
    pass

# ---------- Action executor integration (Phase 12) ----------
try:
    from tinysocs.actions.executor import (
        stage_action as _executor_stage,
        approve_action as _executor_approve,
        get_action as _executor_get,
        list_actions as _executor_list,
    )
    _HAS_EXECUTOR = True
except ImportError:
    _HAS_EXECUTOR = False

class ApproveBody(BaseModel):
    action_id: str = Field(..., description="ID of the staged action to approve")
    approved_by: Optional[str] = Field("operator", description="Who is approving")

class ActionStatusResponse(BaseModel):
    action_id: str
    action: str
    status: str
    params: Dict[str, Any] = Field(default_factory=dict)
    dry_run: bool = True
    staged_at: Optional[str] = None
    approved_at: Optional[str] = None
    completed_at: Optional[str] = None
    result: Optional[Dict[str, Any]] = None

@app.post("/bot/ack", dependencies=[Depends(verify_hmac)])
def bot_ack(body: AckBody = Body(...)) -> Dict[str, Any]:
    entry = {
        "kind": "bot_action",
        "action": "ack_incident",
        "params": {"incident_id": body.incident_id, "tldr": body.tldr},
        "who": body.who,
        "ts": _now(),
        "status": "staged",
    }
    qpath = _stage_entry(entry)
    ledger_res = _post_ledger(entry)
    return {"queued": True, "ledger": ledger_res, "node": NODE_URL, "path": str(qpath)}

@app.post("/bot/exec", dependencies=[Depends(verify_hmac)])
def bot_exec(body: ExecBody = Body(...)) -> Dict[str, Any]:
    if body.action not in ALLOWED_ACTIONS:
        raise HTTPException(status_code=400, detail=f"action not allowed: {body.action}")
    _guard_params(body.action, body.params)
    entry = {
        "kind": "bot_action",
        "action": body.action,
        "params": body.params,
        "who": body.who,
        "ts": _now(),
        "dry_run": True if body.dry_run is None else bool(body.dry_run),
        "status": "staged",
    }
    qpath = _stage_entry(entry)
    ledger_res = _post_ledger(entry)

    # Also stage in executor for approval workflow (Phase 12)
    executor_id = None
    if _HAS_EXECUTOR:
        try:
            rec = _executor_stage(
                action=body.action,
                params=body.params,
                who=body.who,
                dry_run=True if body.dry_run is None else bool(body.dry_run),
            )
            executor_id = rec.get("action_id")
        except Exception as e:
            print(f"[bot] WARN: executor stage failed: {e}")

    return {"queued": True, "ledger": ledger_res, "node": NODE_URL, "path": str(qpath), "action_id": executor_id}

# ---- Action Approval (Phase 12) ----
@app.post("/bot/approve", dependencies=[Depends(verify_hmac)])
def bot_approve(body: ApproveBody = Body(...)) -> Dict[str, Any]:
    if not _HAS_EXECUTOR:
        raise HTTPException(status_code=501, detail="Action executor not available")
    try:
        record = _executor_approve(body.action_id, approved_by=body.approved_by or "operator")
        return {
            "action_id": record["action_id"],
            "status": record["status"],
            "result": record.get("result"),
            "dry_run": record.get("dry_run", True),
        }
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

# ---- Action Status (Phase 12) ----
@app.get("/bot/actions/{action_id}/status", dependencies=[Depends(verify_hmac)])
def bot_action_status(action_id: str) -> ActionStatusResponse:
    if not _HAS_EXECUTOR:
        raise HTTPException(status_code=501, detail="Action executor not available")
    record = _executor_get(action_id)
    if not record:
        raise HTTPException(status_code=404, detail=f"Action {action_id} not found")
    return ActionStatusResponse(
        action_id=record["action_id"],
        action=record["action"],
        status=record["status"],
        params=record.get("params", {}),
        dry_run=record.get("dry_run", True),
        staged_at=record.get("staged_at"),
        approved_at=record.get("approved_at"),
        completed_at=record.get("completed_at"),
        result=record.get("result"),
    )

# ---- Actions Review (read-only): newest-first listing with filters ----------
@app.get("/bot/actions", response_model=ActionsResponse, dependencies=[Depends(verify_hmac)])
def bot_actions(
    limit: int = Query(50, ge=1, le=500),
    action: Optional[str] = Query(None, description="Exact action filter"),
    since: Optional[str] = Query(None, description="ISO8601 (e.g., 2025-10-31T12:00:00Z)"),
    status: Optional[str] = Query(None, description="status filter, e.g. 'staged'"),
) -> ActionsResponse:
    # Read extra to allow filtering, then apply filters and cut to limit.
    items = _read_queue_items(limit * 5)
    # parse since (UTC)
    dt_cut = None
    if since:
        try:
            dt_cut = datetime.fromisoformat(since.replace("Z", "+00:00")).astimezone(timezone.utc)
        except Exception:
            dt_cut = None

    out: List[QueueItem] = []
    for it in items:
        # normalize missing fields
        act = it.get("action")
        st  = it.get("status", "staged")
        ts  = it.get("timestamp") or it.get("ts")  # accept either
        if not ts:
            # skip un-timestamped items
            continue

        if action and act != action:
            continue
        if status and st != status:
            continue
        if dt_cut:
            try:
                t = datetime.fromisoformat(str(ts).replace("Z", "+00:00")).astimezone(timezone.utc)
                if t < dt_cut:
                    continue
            except Exception:
                # if timestamp can't be parsed, skip it for since-filter
                continue

        # map to QueueItem fields
        out.append(QueueItem(
            timestamp=str(ts),
            action=str(act or ""),
            params=it.get("params") or {},
            status=str(st or "staged"),
            who=it.get("who"),
            kind=it.get("kind", "bot_action"),
        ))
        if len(out) >= limit:
            break

    return ActionsResponse(items=out, count=len(out), next_cursor=None)

# ---- Diagnostic endpoint: try all shapes and return their statuses (HMAC-protected) ----
@app.post("/bot/_diag/ledger-shapes", dependencies=[Depends(verify_hmac)])
def bot_diag_ledger_shapes(sample: Dict[str, Any] = Body(default=None)) -> Dict[str, Any]:
    """
    Test all body shapes against /evidence/append and return per-shape results.
    If no sample provided, a minimal bot_action ack is used.
    """
    entry = sample or {
        "kind": "bot_action",
        "action": "ack_incident",
        "params": {"incident_id": "diag-123", "tldr": "diag"},
        "who": "diag",
        "ts": _now(),
        "status": "staged",
    }
    url = f"{NODE_URL.rstrip('/')}/evidence/append"
    headers = _node_hmac_headers()
    shapes: List[Tuple[str, Any]] = [
        ("payload", {"payload": entry}),
        ("entry",   {"entry": entry}),
        ("raw",     entry),
        ("evidence",{"evidence": entry}),
    ]
    results: List[Dict[str, Any]] = []
    for name, body in shapes:
        try:
            r = requests.post(url, headers=headers, json=body, timeout=8, verify=NODE_TLS_VERIFY)
            results.append({
                "shape": name,
                "status": r.status_code,
                "ok": 200 <= r.status_code < 300,
                "body": (r.text or "").strip()[:4000],
            })
        except Exception as e:
            results.append({"shape": name, "status": None, "ok": False, "error": f"{type(e).__name__}: {e}"})
    return {"node": NODE_URL, "results": results}

# ---- Diagnostic endpoint: append /meta for health checks ----
@app.get("/meta", dependencies=[Depends(verify_hmac)])
def meta():
    from datetime import datetime, timezone
    return {
        "bot_id": os.getenv("BOT_ID", f"bot-{os.getenv('BOT_PORT', '8090')}"),
        "queue": str(_effective_queue_path()),
        "capabilities": ["exec-staging","actions-review"],
        "time_utc": datetime.now(timezone.utc).isoformat()
    }

# ---- Diagnostic endpoint: append sample queue items (HMAC-protected) ----
@app.post("/bot/_diag/queue-append-sample", dependencies=[Depends(verify_hmac)])
def bot_diag_queue_append_sample() -> Dict[str, Any]:
    """
    Append a couple of canned items to the queue for quick testing.
    Enable with BOT_ENABLE_DIAG=1 (or true/yes/on).
    """
    if str(os.getenv("BOT_ENABLE_DIAG", "0")).strip().lower() not in ("1", "true", "yes", "on"):
        raise HTTPException(status_code=403, detail="diag disabled")
    ts = _now()
    entries = [
        {
            "kind": "bot_action", "action": "block_ip",
            "params": {"ip": "203.0.113.10"}, "who": "diag", "ts": ts, "timestamp": ts, "status": "staged",
        },
        {
            "kind": "bot_action", "action": "disable_user",
            "params": {"user": "alice"}, "who": "diag", "ts": ts, "timestamp": ts, "status": "staged",
        },
    ]
    for e in entries:
        _stage_entry(e)
    return {"ok": True, "added": len(entries), "path": str(_effective_queue_path())}

def cli():
    import sys

    # Phase 17 M0: --demo flag for synthetic data mode
    demo_mode = "--demo" in sys.argv
    if demo_mode:
        os.environ["TINYSOCS_DEMO_MODE"] = "1"
        os.environ.setdefault("DASHBOARD_BIND", "127.0.0.1")
        os.environ.setdefault("SIEM_PASS", "demo")
        print("[bot] Demo mode — serving synthetic data at http://localhost:8090/dashboard")

    # Guard: if the project forgot to set BOT_SHARED_SECRET, fail loudly.
    if not demo_mode and not BOT_SECRET:
        raise SystemExit("BOT_SHARED_SECRET must be set (see .env).")
    port = int(os.getenv("BOT_PORT", "8090"))
    workers = int(os.getenv("TINYSOCS_BOT_WORKERS", "1"))
    loglvl = os.getenv("UVICORN_LOG_LEVEL", "info")

    # Dashboard TLS config (Phase 14 M0, Phase 19 M3: fallback to TINYSOCS_TLS_*)
    tls_cert = (os.getenv("DASHBOARD_TLS_CERT", "").strip()
                or os.getenv("TINYSOCS_TLS_CERT", "").strip())
    tls_key = (os.getenv("DASHBOARD_TLS_KEY", "").strip()
               or os.getenv("TINYSOCS_TLS_KEY", "").strip())
    bind_host = os.getenv("DASHBOARD_BIND", "127.0.0.1" if demo_mode else "0.0.0.0").strip()

    ssl_kwargs: dict = {}
    if tls_cert and tls_key:
        if not Path(tls_cert).is_file():
            raise SystemExit(f"TLS cert not found: {tls_cert}")
        if not Path(tls_key).is_file():
            raise SystemExit(f"TLS key not found: {tls_key}")
        ssl_kwargs = {"ssl_certfile": tls_cert, "ssl_keyfile": tls_key}
        print(f"[bot] TLS enabled: cert={tls_cert}")
    elif bind_host != "127.0.0.1":
        raise SystemExit(
            "DASHBOARD_TLS_CERT and DASHBOARD_TLS_KEY (or TINYSOCS_TLS_CERT/KEY) "
            "are required when DASHBOARD_BIND is not 127.0.0.1. Generate certs "
            "with the installer or set DASHBOARD_BIND=127.0.0.1 for localhost-only access."
        )
    else:
        print("[bot] TLS not configured — running HTTP (localhost only)")

    # Use import-string to avoid spawn/pickle issues in frozen builds
    uvicorn.run(
        APP_IMPORT,
        host=bind_host,
        port=port,
        reload=False,
        workers=workers,
        log_level=loglvl,
        **ssl_kwargs,
    )

APP_IMPORT = "tinysocs.api.bot:app"

if __name__ == "__main__":
    cli()
