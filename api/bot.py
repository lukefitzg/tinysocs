# tinysocs/api/bot.py
"""
TinySocs Bot Bridge (FastAPI)

Purpose:
  - Accept chat/webhook intents and stage operator actions.
  - Append a compact bot_action record to the node ledger via /evidence/append.

Security:
  - HMAC headers (raw-hex) with BOT_SHARED_SECRET.
  - ±300s clock skew, 5-minute replay cache on timestamp.

Env:
  BOT_SHARED_SECRET            HMAC secret for inbound bot calls (required)
  MASTER_SHARED_SECRET         Reused when calling node /evidence/append (fallback for NODE_SECRET)
  NODE_SECRET                  Optional override for the secret used to call /evidence/append
  TINYSOCS_NODES               Comma list; first is used to append ledger (default http://localhost:8081)
  TINYSOCS_INSECURE_SKIP_VERIFY  "1" to skip TLS verify to node (default 1)
  TINYSOCS_QUEUE_PATH          Path to actions queue JSONL (default: <repo>/tinysocs/actions_queue.jsonl)
  TINYSOCS_SKEW_SECS           Override inbound skew seconds (default 300)
  BOT_PORT                     Uvicorn port (default 8090)
  TINYSOCS_BOT_WORKERS         Uvicorn workers (default 1)

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
import uvicorn
from fastapi import Body, Depends, FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

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
NODES = [x.strip() for x in (_env("TINYSOCS_NODES", "http://localhost:8081") or "").split(",") if x.strip()]
NODE_URL = NODES[0] if NODES else "http://localhost:8081"
NODE_TLS_VERIFY = not str(_env("TINYSOCS_INSECURE_SKIP_VERIFY", "1")).lower() in ("1", "true", "yes", "on")
QUEUE_PATH = Path(_env("TINYSOCS_QUEUE_PATH", str(Path(__file__).resolve().parents[1] / "actions_queue.jsonl")))
ALLOWED_SKEW_SECONDS = int(_env("TINYSOCS_SKEW_SECS", "300") or "300")
REPLAY_CACHE_SECONDS = 300

_recent_ts: Dict[int, int] = {}  # timestamp -> expiry epoch

# ---------- HMAC auth (inbound) ----------
def _gc(now: int) -> None:
    stale = [t for t, exp in _recent_ts.items() if exp <= now]
    for t in stale:
        _recent_ts.pop(t, None)

def verify_hmac(request: Request) -> None:
    if not BOT_SECRET:
        raise HTTPException(status_code=500, detail="BOT_SHARED_SECRET not set")
    ts_hdr = request.headers.get("X-TinySOCS-Timestamp")
    sig_hdr = request.headers.get("X-TinySOCS-Signature", "")
    if not ts_hdr or not sig_hdr:
        raise HTTPException(status_code=401, detail="Missing auth headers")
    try:
        ts = int(ts_hdr)
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid timestamp")
    now = int(time.time())
    if abs(now - ts) > ALLOWED_SKEW_SECONDS:
        raise HTTPException(status_code=401, detail="Timestamp skew too large")
    calc = hmac.new(BOT_SECRET.encode("utf-8"), str(ts).encode("utf-8"), hashlib.sha256).hexdigest()
    provided = sig_hdr.split("=", 1)[1] if sig_hdr.startswith("sha256=") else sig_hdr
    if not hmac.compare_digest(calc, provided):
        raise HTTPException(status_code=401, detail="Bad signature")
    _gc(now)
    exp = _recent_ts.get(ts)
    if exp and exp > now:
        raise HTTPException(status_code=401, detail="Replay detected")
    _recent_ts[ts] = now + REPLAY_CACHE_SECONDS

# ---------- Queue + ledger helpers ----------
def _queue_append(obj: Dict[str, Any]) -> None:
    QUEUE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(QUEUE_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")

def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

def _node_hmac_headers() -> Dict[str, str]:
    ts = str(int(time.time()))
    sig = hmac.new(NODE_SECRET.encode("utf-8"), ts.encode("utf-8"), hashlib.sha256).hexdigest()
    return {
        "X-TinySOCS-Timestamp": ts,
        "X-TinySOCS-Signature": sig,
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
        ("payload", {"payload": entry}),   # common FastAPI pattern in this repo
        ("entry",   {"entry": entry}),     # alternative wrapper used in some modules
        ("raw",     entry),                # raw document
        ("evidence",{"evidence": entry}),  # belt-and-suspenders try
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
    # Compact human-readable failure
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

ALLOWED_ACTIONS = {"block_ip", "disable_user", "isolate_host", "open_ticket"}

class ExecBody(BaseModel):
    action: str = Field(..., description=f"One of: {', '.join(sorted(ALLOWED_ACTIONS))}")
    params: Dict[str, Any] = Field(default_factory=dict)
    who: Optional[str] = Field(None, description="Human display name (optional)")

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
        title = str(params.get("title", "")).strip()
        if not title:
            raise HTTPException(status_code=400, detail="open_ticket requires 'title'")
    else:
        raise HTTPException(status_code=400, detail="unsupported action")

# ---------- App ----------
app = FastAPI(title="TinySocs Bot Bridge", version="0.1.1")

@app.post("/bot/ack", dependencies=[Depends(verify_hmac)])
def bot_ack(body: AckBody = Body(...)) -> Dict[str, Any]:
    entry = {
        "kind": "bot_action",
        "action": "ack_incident",
        "params": {"incident_id": body.incident_id, "tldr": body.tldr},
        "who": body.who,
        "ts": _now(),
    }
    _queue_append(entry)
    ledger_res = _post_ledger(entry)
    return {"queued": True, "ledger": ledger_res, "node": NODE_URL, "path": str(QUEUE_PATH)}

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
        "dry_run": True,  # stage only; no live changes
    }
    _queue_append(entry)
    ledger_res = _post_ledger(entry)
    return {"queued": True, "ledger": ledger_res, "node": NODE_URL, "path": str(QUEUE_PATH)}

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
    }
    # Run attempts but return detailed results
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

def cli():
    port = int(os.getenv("BOT_PORT", "8090"))
    workers = int(os.getenv("TINYSOCS_BOT_WORKERS", "1"))
    uvicorn.run(app, host="0.0.0.0", port=port, reload=False, workers=workers)

if __name__ == "__main__":
    cli()