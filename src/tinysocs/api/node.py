# tinysocs/api/node.py
import hashlib
import hmac
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import requests
from fastapi import FastAPI, HTTPException, Request, Body, Query

from tinysocs.agent.detections.registry import RULES, Rule  # <-- NEW

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


# ---------------------------------------------------------------------------
# OpenSearch/SIEM helpers
# ---------------------------------------------------------------------------

def _env_bool(name: str, default: bool) -> bool:
    """
    Return a boolean from an env var.

    Accepts "0/false/no/off" (any case) as False, anything else as True.
    If the variable is unset, returns the provided default.
    """
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() not in ("0", "false", "no", "off")


def _get_siem_base_url() -> str:
    """
    Decide which base URL to use when talking to the SIEM / OpenSearch.

    Precedence:
      1) SIEM_URL
      2) OPENSEARCH_URL
      3) http://127.0.0.1:9200 (TinyBox local default)
    """
    url = (
        os.getenv("SIEM_URL")
        or os.getenv("OPENSEARCH_URL")
        or "http://127.0.0.1:9200"
    )
    return url.rstrip("/")


def _get_tls_verify_flag() -> bool:
    """
    Decide whether to verify TLS when calling the SIEM / OpenSearch.

    Precedence:
      1) SIEM_SSL_VERIFY
      2) OPENSEARCH_VERIFY_SSL
    Defaults to False (friendly to local/self-signed TinyBox clusters).
    """
    siem_var = "SIEM_SSL_VERIFY"
    os_var = "OPENSEARCH_VERIFY_SSL"
    if os.getenv(siem_var) is not None:
        return _env_bool(siem_var, False)
    elif os.getenv(os_var) is not None:
        return _env_bool(os_var, False)
    else:
        return False


def _os_search(index_pattern: str, body: dict, size: int = 20) -> list[dict[str, Any]]:
    """
    Minimal OpenSearch search helper.

    - Uses SIEM_URL/OPENSEARCH_URL for the base URL.
    - Honors SIEM_SSL_VERIFY/OPENSEARCH_VERIFY_SSL.
    - Flattens _source + a tiny bit of metadata into each returned doc.
    """
    base = _get_siem_base_url()
    url = f"{base}/{index_pattern}/_search"

    payload = dict(body)
    if "size" not in payload:
        payload["size"] = size

    verify = _get_tls_verify_flag()

    print(
        "[tinysocs-node] OpenSearch query url="
        f"{url} base={base} index_pattern={index_pattern} "
        f"size={payload.get('size', size)} verify={verify}",
        flush=True,
    )

    try:
        resp = requests.post(url, json=payload, timeout=10, verify=verify)
        resp.raise_for_status()
        try:
            text_preview = resp.text[:500]
        except Exception:
            text_preview = "<unreadable>"
        print(
            f"[tinysocs-node] OpenSearch HTTP {resp.status_code} body_preview={text_preview}",
            flush=True,
        )
    except Exception as e:  # pragma: no cover
        print(f"[tinysocs-node] OpenSearch query failed: {e}; url={url}", flush=True)
        return []

    try:
        data = resp.json()
    except Exception as e:  # pragma: no cover
        print(f"[tinysocs-node] Failed to parse OpenSearch JSON: {e}; url={url}", flush=True)
        return []

    total = data.get("hits", {}).get("total")
    if isinstance(total, dict):
        total_val = total.get("value")
    else:
        total_val = total
    hits = data.get("hits", {}).get("hits", [])
    hits_len = len(hits)
    print(
        f"[tinysocs-node] OpenSearch query ok url={url} total={total_val} hits={hits_len}",
        flush=True,
    )

    docs: list[dict[str, Any]] = []
    for h in hits:
        src = h.get("_source") or {}
        if not isinstance(src, dict):
            continue
        doc = dict(src)
        doc["_index"] = h.get("_index")
        doc["_id"] = h.get("_id")
        doc["_score"] = h.get("_score")
        docs.append(doc)

    return docs


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

    if abs(int(time.time()) - ts_int) > SKEW_SECS:
        raise HTTPException(status_code=401, detail="clock_skew")

    provided = _normalize_sig(sig_hdr).lower().strip()
    calc = hmac.new(
        SECRET.encode("utf-8"),
        ts.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest().lower()

    token = f"{ts}:{provided}"
    if token in _REPLAY_CACHE:
        raise HTTPException(status_code=401, detail="replay")
    _REPLAY_CACHE.add(token)

    if not hmac.compare_digest(calc, provided):
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

    raw = raw.split(";", 1)[0].strip()

    try:
        return int(raw)
    except ValueError:
        return default


# ---------------------------------------------------------------------------
# Rule execution helpers
# ---------------------------------------------------------------------------

def _normalize_window(window: str) -> str:
    """Normalize a TinySocs-style window string (e.g. '10m', '1h')."""
    win = (window or "15m") if isinstance(window, str) else "15m"
    if len(win) < 2:
        return "15m"
    num_part, unit_part = win[:-1], win[-1]
    if not (num_part.isdigit() and unit_part in ("s", "m", "h", "d")):
        return "15m"
    return win


def _run_rule(rule_id: str, window: str, host: Optional[str]) -> Optional[dict[str, Any]]:
    """
    Execute a single detection rule against the local SIEM.

    Returns a compact evidence dict if the rule is triggered (count >= threshold),
    otherwise returns None.
    """
    rule: Optional[Rule] = RULES.get(rule_id)  # type: ignore[assignment]
    if rule is None:
        print(f"[tinysocs-node] unknown rule_id={rule_id}", flush=True)
        return None

    win = _normalize_window(window)
    time_field = rule.time_field or "@timestamp"

    filter_clauses: list[dict[str, Any]] = [
        {"range": {time_field: {"gte": f"now-{win}"}}}
    ]

    if host:
        filter_clauses.append({"term": {"host.name": host}})

    must_clauses: list[dict[str, Any]] = []
    kql = (rule.kql or "*").strip()
    if kql not in ("*", "*:*", f"{time_field}:*"):
        must_clauses.append({"query_string": {"query": kql}})

    query: dict[str, Any] = {"bool": {}}
    if must_clauses:
        query["bool"]["must"] = must_clauses
    if filter_clauses:
        query["bool"]["filter"] = filter_clauses

    body: dict[str, Any] = {
        "query": query,
        "sort": [{time_field: {"order": "desc"}}],
    }

    fetch_size = max(rule.threshold * 4, rule.threshold, 20)
    docs = _os_search(rule.index, body, size=fetch_size)

    count = len(docs)
    print(
        f"[tinysocs-node] rule_id={rule.id} window={win} host={host} "
        f"threshold={rule.threshold} count={count}",
        flush=True,
    )

    if count < rule.threshold:
        return None

    first_ts = docs[-1].get(time_field) if docs else None
    last_ts = docs[0].get(time_field) if docs else None

    evidence: dict[str, Any] = {
        "rule": rule.id,
        "description": rule.description,
        "severity": rule.severity,
        "category": rule.category,
        "node_id": NODE_ID,
        "window": win,
        "threshold": rule.threshold,
        "count": count,
        "first_seen": first_ts,
        "last_seen": last_ts,
        "sample": docs[:5],
    }
    return evidence


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
            "secret_set": SECRET != "dev-secret-change-me",
            "skew_secs": SKEW_SECS,
        },
    }


# ------------------------- Agg / Sample -------------------------

@app.get("/agg")
async def agg_get(
    rules: str = Query("default"),
    window: str = Query("15m"),
    host: Optional[str] = Query(None),
) -> list[dict[str, Any]]:
    """
    Aggregate detections for one or more rules over a time window.

    Query params:
      - rules: comma-separated list of rule IDs (e.g. "auth_failed_burst").
               If set to "default" or empty, we run all known rules.
      - window: TinySocs-style duration (e.g. "10m", "1h").
      - host: optional hostname to scope the search.
    """
    rule_ids = _normalize_rules(rules)
    if not rule_ids or rules == "default":
        rule_ids = list(RULES.keys())

    evidence: list[dict[str, Any]] = []
    for rid in rule_ids:
        ev = _run_rule(rid, window, host)
        if ev:
            evidence.append(ev)

    return evidence


@app.post("/agg")
async def agg_post(payload: dict = Body(...)) -> list[dict[str, Any]]:
    """
    POST variant of /agg for JSON payloads.

    Expected body (all fields optional):
      {
        "rules": "rule_a,rule_b" or ["rule_a","rule_b"],
        "window": "15m",
        "host": "hostname"
      }
    """
    raw_rules = payload.get("rules", "default")
    if isinstance(raw_rules, list):
        rules_str = ",".join(str(r) for r in raw_rules)
    else:
        rules_str = str(raw_rules)

    window = str(payload.get("window", "15m"))
    host = payload.get("host")

    rule_ids = _normalize_rules(rules_str)
    if not rule_ids or rules_str == "default":
        rule_ids = list(RULES.keys())

    evidence: list[dict[str, Any]] = []
    for rid in rule_ids:
        ev = _run_rule(rid, window, host)
        if ev:
            evidence.append(ev)

    return evidence


@app.get("/sample")
async def sample_get(
    rules: str = Query("default"),
    window: str = Query("15m"),
    host: Optional[str] = Query(None),
    limit: int = Query(20, ge=1, le=500),
    index: Optional[str] = Query(None),
    index_pattern: Optional[str] = Query(None),
    kql: str = Query("*"),
) -> list[dict[str, Any]]:
    """
    Lightweight sampling helper against the local SIEM / OpenSearch.
    """
    pattern = index or index_pattern or "tinysocs-winlog-*"

    win = window or "15m"
    if not isinstance(win, str) or len(win) < 2:
        win = "15m"
    num_part, unit_part = win[:-1], win[-1]
    if not (num_part.isdigit() and unit_part in ("s", "m", "h", "d")):
        win = "15m"

    kql_norm = (kql or "*").strip()
    print(
        "[tinysocs-node] /sample called "
        f"pattern={pattern} window={win} kql={kql_norm} host={host} limit={limit}",
        flush=True,
    )

    time_filter = {"range": {"@timestamp": {"gte": f"now-{win}"}}}

    must_clauses: list[dict[str, Any]] = []
    filter_clauses: list[dict[str, Any]] = [time_filter]

    if host:
        filter_clauses.append({"term": {"host.name": host}})

    if kql_norm not in ("*", "*:*", "@timestamp:*"):
        must_clauses.append({"query_string": {"query": kql_norm}})

    query: dict[str, Any] = {"bool": {}}
    if must_clauses:
        query["bool"]["must"] = must_clauses
    if filter_clauses:
        query["bool"]["filter"] = filter_clauses

    body = {"query": query}

    docs = _os_search(pattern, body, size=limit)
    return docs


@app.post("/sample")
async def sample_post(payload: dict = Body(...)) -> list[dict[str, Any]]:
    rules = payload.get("rules", "default")
    window = payload.get("window", "15m")
    host = payload.get("host")
    limit = int(payload.get("limit", 20) or 20)
    index = payload.get("index")
    index_pattern = payload.get("index_pattern")
    kql = payload.get("kql", "*")

    docs = await sample_get(
        rules=rules,
        window=window,
        host=host,
        limit=limit,
        index=index,
        index_pattern=index_pattern,
        kql=kql,
    )
    return docs


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
    blob = json.dumps(entry, sort_keys=True, separators=(",", ":")).encode("utf-8")
    head_sha = hashlib.sha256(blob).hexdigest()
    entry["head_sha256"] = head_sha

    _append_jsonl(entry)
    _write_head({"ok": True, "sequence": sequence, "head_sha256": head_sha, "updated_at": now_iso()})
    return {"ok": True, "sequence": sequence, "head_sha256": head_sha}


def cli() -> None:
    import uvicorn

    port = _get_int_env("PORT") or _get_int_env("NODE_PORT") or 8081

    host = os.getenv("HOST", "0.0.0.0")
    loglvl = os.getenv("UVICORN_LOG_LEVEL", "info")
    reload = os.getenv("UVICORN_RELOAD", "0").strip().lower() in ("1", "true", "yes", "y")

    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level=loglvl,
        reload=reload,
    )


if __name__ == "__main__":
    cli()