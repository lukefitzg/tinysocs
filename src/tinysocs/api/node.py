# tinysocs/api/node.py
import hashlib
import hmac
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, HTTPException, Request, Body, Query

# Expose a FastAPI app named 'app' so:
#   uvicorn tinysocs.api.node:app
# works as expected.
app = FastAPI(title="TinySOCS Node API")

# Minimal import string for external runners (kept for reference)
APP_IMPORT = "tinysocs.api.node:app"

# ---------------------------------------------------------------------------
# Config / paths
# ---------------------------------------------------------------------------

# Ledger directory: default "ledger" under the node's working directory.
# On Windows via NSSM we set AppDirectory to %ProgramData%\TinySocs,
# so by default this becomes C:\ProgramData\TinySocs\ledger.
LEDGER_DIR = Path(os.getenv("TINYSOCS_LEDGER_DIR", "ledger"))
LEDGER_DIR.mkdir(parents=True, exist_ok=True)
HEAD_FILE = LEDGER_DIR / "head.json"


def _load_secret() -> str:
    """
    Decide which secret to use for HMAC and log which source won.

    Precedence:
      1) MASTER_SHARED_SECRET   (set on both master and node)
      2) dev-secret-change-me   (dev fallback)
    """
    master_secret = os.getenv("MASTER_SHARED_SECRET")

    if master_secret:
        sha = hashlib.sha256(master_secret.encode("utf-8")).hexdigest()
        print(
            f"[tinysocs-node] using MASTER_SHARED_SECRET; secret_sha256={sha}",
            flush=True,
        )
        return master_secret

    dev = "dev-secret-change-me"
    sha = hashlib.sha256(dev.encode("utf-8")).hexdigest()
    print(
        "[tinysocs-node] WARNING: no MASTER_SHARED_SECRET; "
        f"falling back to dev-secret-change-me; secret_sha256={sha}",
        flush=True,
    )
    return dev


# HMAC secret:
# - MASTER_SHARED_SECRET: single source of truth for both master and node
# - dev-secret-change-me: last-resort fallback for dev
SECRET = _load_secret()

SKEW_SECS = int(os.getenv("TINYSOCS_SKEW_SECS", "300"))
NODE_ID = os.getenv("TINYSOCS_NODE_ID") or os.getenv("COMPUTERNAME") or "local"

# Simple per-process replay cache for HMAC tokens
_REPLAY_CACHE: set[str] = set()


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _normalize_sig(sig_hdr: str) -> str:
    """Accept 'sha256=<hex>' or raw '<hex>'."""
    if not sig_hdr:
        return ""
    if sig_hdr.startswith("sha256="):
        return sig_hdr.split("=", 1)[1]
    return sig_hdr


def _verify_hmac(req: Request) -> None:
    ts = req.headers.get("X-TinySOCS-Timestamp")
    sig_hdr = req.headers.get("X-TinySOCS-Signature")

    if not ts or not sig_hdr:
        raise HTTPException(status_code=401, detail="missing hmac headers")

    try:
        ts_int = int(ts)
    except ValueError:
        raise HTTPException(status_code=401, detail="bad timestamp")

    # Clock skew guard
    if abs(int(time.time()) - ts_int) > SKEW_SECS:
        raise HTTPException(status_code=401, detail="clock_skew")

    provided = _normalize_sig(sig_hdr).lower().strip()
    calc = hmac.new(
        SECRET.encode("utf-8"),
        ts.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest().lower()

    # Basic per-process replay protection on exact (ts, provided) pair
    token = f"{ts}:{provided}"
    if token in _REPLAY_CACHE:
        raise HTTPException(status_code=401, detail="replay")
    _REPLAY_CACHE.add(token)

    if not hmac.compare_digest(calc, provided):
        # Debug: log mismatch details without leaking the secret itself
        try:
            secret_sha = hashlib.sha256(SECRET.encode("utf-8")).hexdigest()
        except Exception:
            secret_sha = "error"
        print(
            f"[tinysocs-node] HMAC mismatch ts={ts} provided={provided} "
            f"calc={calc} secret_sha256={secret_sha}",
            flush=True,
        )
        raise HTTPException(status_code=401, detail="bad_signature")


def _append_jsonl(entry: dict) -> None:
    fpath = LEDGER_DIR / (datetime.now().strftime("%Y-%m-%d") + ".jsonl")
    with open(fpath, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, separators=(",", ":")) + "\n")


def _read_head() -> dict:
    if not HEAD_FILE.exists():
        return {"ok": False, "reason": "empty"}
    with open(HEAD_FILE, encoding="utf-8") as f:
        return json.load(f)


def _write_head(head: dict) -> None:
    with open(HEAD_FILE, "w", encoding="utf-8") as f:
        json.dump(head, f)


def _normalize_rules(rules: str) -> list[str]:
    return [r.strip() for r in (rules or "").split(",") if r.strip()]


def _get_int_env(name: str, default: Optional[int] = None) -> Optional[int]:
    """
    Robust int parser for env vars.

    Handles junk like:
      PORT="8081;SIEM_URL=https://localhost:9201;..."
    by splitting on ';' and taking the first token.
    """
    raw = os.getenv(name)
    if raw is None:
        return default

    # Strip any NSSM-style concatenation
    raw = raw.split(";", 1)[0].strip()

    try:
        return int(raw)
    except ValueError:
        return default


# ----------------------------- Meta -----------------------------
@app.get("/meta")
async def get_meta() -> dict:
    """Lightweight health + shape discovery for the node."""
    return {
        "ok": True,
        "node_id": NODE_ID,
        "version": os.getenv("TINYSOCS_VERSION", "dev"),
        "endpoints": ["/meta", "/agg", "/sample", "/evidence/head", "/evidence/append"],
        "hmac": {
            # Does *not* leak the secret, only whether we're still on the dev default.
            "secret_set": SECRET != "dev-secret-change-me",
            "skew_secs": SKEW_SECS,
        },
    }


# ------------------------- Agg / Sample -------------------------
# For now these are stubs that return empty results but keep the shapes
# that master expects (a list of evidence-ish dicts).

@app.get("/agg")
async def agg_get(
    rules: str = Query("default"),
    window: str = Query("15m"),
    host: Optional[str] = Query(None),
) -> list[dict[str, Any]]:
    _ = (_normalize_rules(rules), window, host)  # unused in stub
    return []


@app.post("/agg")
async def agg_post(payload: dict = Body(...)) -> list[dict[str, Any]]:
    _ = (payload.get("rules"), payload.get("window"), payload.get("host"))
    return []


@app.get("/sample")
async def sample_get(
    rules: str = Query("default"),
    window: str = Query("15m"),
    host: Optional[str] = Query(None),
    limit: int = Query(20),
) -> list[dict[str, Any]]:
    _ = (_normalize_rules(rules), window, host, limit)
    return []


@app.post("/sample")
async def sample_post(payload: dict = Body(...)) -> list[dict[str, Any]]:
    _ = (payload.get("rules"), payload.get("window"), payload.get("host"), payload.get("limit", 20))
    return []


# --------------------------- Evidence ---------------------------
@app.get("/evidence/head")
async def get_head() -> dict:
    head = _read_head()
    if not head.get("ok"):
        return {"ok": False, "reason": head.get("reason", "empty")}
    return head


@app.post("/evidence/append")
async def post_append(req: Request) -> dict:
    _verify_hmac(req)
    body = await req.json()
    # Expected body (compact): {"stable_hash": "sha256...", "rule": "...", "node_id": "..."}
    incoming = {
        "stable_hash": body.get("stable_hash"),
        "rule": body.get("rule"),
        "node_id": body.get("node_id") or NODE_ID,
        "timestamp": now_iso(),
    }
    prev = _read_head()
    sequence = (prev.get("sequence") or 0) + 1 if prev.get("ok") else 1
    entry = {
        "sequence": sequence,
        "timestamp": incoming["timestamp"],
        "rule": incoming["rule"],
        "stable_hash": incoming["stable_hash"],
        "prev_hash": prev.get("head_sha256"),
        "node_id": incoming["node_id"],
    }
    # head hash is over canonical entry
    blob = json.dumps(entry, sort_keys=True, separators=(",", ":")).encode("utf-8")
    head_sha = hashlib.sha256(blob).hexdigest()
    entry["head_sha256"] = head_sha

    _append_jsonl(entry)
    _write_head({"ok": True, "sequence": sequence, "head_sha256": head_sha, "updated_at": now_iso()})
    return {"ok": True, "sequence": sequence, "head_sha256": head_sha}


# Optional: tiny CLI so `python -m tinysocs.api.node` and the PyInstaller EXE just work
def cli() -> None:
    import uvicorn

    # Robust precedence:
    #   1) PORT
    #   2) NODE_PORT
    #   3) 8081
    port = _get_int_env("PORT") or _get_int_env("NODE_PORT") or 8081

    host = os.getenv("HOST", "0.0.0.0")
    loglvl = os.getenv("UVICORN_LOG_LEVEL", "info")
    reload = os.getenv("UVICORN_RELOAD", "0").strip().lower() in ("1", "true", "yes", "y")

    # IMPORTANT: when running from the PyInstaller EXE, dynamic import
    # of "tinysocs.api.node:app" breaks. Use the actual app object.
    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level=loglvl,
        reload=reload,
    )


if __name__ == "__main__":
    cli()