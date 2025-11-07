# node_api.py
import hashlib
import hmac
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request

APP = FastAPI(title="TinySOCS Node API - Ledger")
LEDGER_DIR = Path(os.getenv("TINYSOCS_LEDGER_DIR", "ledger"))
LEDGER_DIR.mkdir(parents=True, exist_ok=True)
HEAD_FILE = LEDGER_DIR / "head.json"
SECRET = os.getenv("MASTER_SHARED_SECRET", "dev-secret-change-me")
SKEW_SECS = int(os.getenv("TINYSOCS_SKEW_SECS", "300"))
REPLAY_CACHE = set()

def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def _verify_hmac(req: Request):
    ts = req.headers.get("X-TinySOCS-Timestamp")
    sig = req.headers.get("X-TinySOCS-Signature")
    if not ts or not sig:
        raise HTTPException(status_code=401, detail="missing hmac headers")
    try:
        ts_int = int(ts)
    except ValueError:
        raise HTTPException(status_code=401, detail="bad timestamp")

    if abs(int(time.time()) - ts_int) > SKEW_SECS:
        raise HTTPException(status_code=401, detail="clock_skew")

    calc = hmac.new(SECRET.encode("utf-8"), ts.encode("utf-8"), hashlib.sha256).hexdigest()
    token = f"{ts}:{sig}"
    if token in REPLAY_CACHE:
        raise HTTPException(status_code=401, detail="replay")
    REPLAY_CACHE.add(token)
    if calc != sig:
        raise HTTPException(status_code=401, detail="bad_signature")

def _append_jsonl(entry: dict):
    fpath = LEDGER_DIR / (datetime.now().strftime("%Y-%m-%d") + ".jsonl")
    with open(fpath, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, separators=(",", ":")) + "\n")

def _read_head():
    if not HEAD_FILE.exists():
        return {"ok": False, "reason": "empty"}
    with open(HEAD_FILE, encoding="utf-8") as f:
        return json.load(f)

def _write_head(head):
    with open(HEAD_FILE, "w", encoding="utf-8") as f:
        json.dump(head, f)

@APP.get("/evidence/head")
async def get_head():
    head = _read_head()
    if not head.get("ok"):
        return {"ok": False, "reason": head.get("reason", "empty")}
    return head

@APP.post("/evidence/append")
async def post_append(req: Request):
    _verify_hmac(req)
    body = await req.json()
    # Expected body (compact): {"stable_hash": "sha256...", "rule": "...", "node_id": "...", "sequence": optional}
    incoming = {
        "stable_hash": body.get("stable_hash"),
        "rule": body.get("rule"),
        "node_id": body.get("node_id", "local"),
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
