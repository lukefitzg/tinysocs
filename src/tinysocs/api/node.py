# tinysocs/api/node.py
import hashlib
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import requests
import urllib3
from fastapi import Depends, FastAPI, HTTPException, Request, Body, Query

# Suppress InsecureRequestWarning for federation connections (verify=False)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse as StarletteJSONResponse

from tinysocs.agent.detections.registry import RULES, Rule  # <-- NEW

# Expose a FastAPI app named 'app' so:
#   uvicorn tinysocs.api.node:app
# works as expected.
app = FastAPI(title="TinySOCS Node API")

# Minimal import string for external runners (kept for reference)
APP_IMPORT = "tinysocs.api.node:app"

# ---------------------------------------------------------------------------
# Global request body size limit (5 MB)
# ---------------------------------------------------------------------------
_MAX_BODY_BYTES = 5 * 1024 * 1024


class _MaxBodySizeMiddleware(BaseHTTPMiddleware):
    """Reject requests whose Content-Length exceeds the limit before reading."""

    async def dispatch(self, request, call_next):
        cl = request.headers.get("content-length")
        if cl and int(cl) > _MAX_BODY_BYTES:
            return StarletteJSONResponse(
                {"error": f"Payload too large (max {_MAX_BODY_BYTES} bytes)"},
                status_code=413,
            )
        return await call_next(request)


app.add_middleware(_MaxBodySizeMiddleware)

# ---------------------------------------------------------------------------
# Rate limiting (per-IP, in-memory sliding window)
# ---------------------------------------------------------------------------
_RATE_WRITE_WINDOW = 60     # seconds
_RATE_WRITE_MAX = 100       # max write requests per window per IP
_RATE_READ_WINDOW = 60
_RATE_READ_MAX = 200        # max read requests per window per IP
_rate_write_buckets: dict[str, list[float]] = {}
_rate_read_buckets: dict[str, list[float]] = {}
_rate_gc_counter = 0


def _rate_limit(request: Request, buckets: dict, max_req: int, window: int) -> None:
    """Generic sliding-window rate limiter."""
    global _rate_gc_counter
    client_ip = request.client.host if request.client else "unknown"
    now = time.time()
    bucket = buckets.setdefault(client_ip, [])
    cutoff = now - window
    buckets[client_ip] = bucket = [t for t in bucket if t > cutoff]
    if len(bucket) >= max_req:
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    bucket.append(now)
    _rate_gc_counter += 1
    if _rate_gc_counter >= 100 or len(buckets) > 1000:
        _rate_gc_counter = 0
        stale = [k for k, v in buckets.items() if not v or v[-1] < cutoff]
        for k in stale:
            buckets.pop(k, None)


def _check_write_rate(request: Request) -> None:
    """Rate limiter for write endpoints (100/min)."""
    _rate_limit(request, _rate_write_buckets, _RATE_WRITE_MAX, _RATE_WRITE_WINDOW)


def _check_read_rate(request: Request) -> None:
    """Rate limiter for read endpoints (200/min)."""
    _rate_limit(request, _rate_read_buckets, _RATE_READ_MAX, _RATE_READ_WINDOW)

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
      2) FATAL error (no fallback)
    """
    master_secret = os.getenv("MASTER_SHARED_SECRET")

    if master_secret:
        sha = hashlib.sha256(master_secret.encode("utf-8")).hexdigest()
        print(
            f"[tinysocs-node] using MASTER_SHARED_SECRET; secret_sha256={sha}",
            flush=True,
        )
        return master_secret

    import sys
    print(
        "[tinysocs-node] FATAL: MASTER_SHARED_SECRET must be set. "
        "Refusing to start with no shared secret.",
        file=sys.stderr,
        flush=True,
    )
    sys.exit(1)


# HMAC secret:
# - MASTER_SHARED_SECRET: single source of truth for both master and node
SECRET = _load_secret()

SKEW_SECS = int(os.getenv("TINYSOCS_SKEW_SECS", "300"))
NODE_ID = os.getenv("TINYSOCS_NODE_ID") or os.getenv("COMPUTERNAME") or "local"


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


def _get_siem_auth():
    """Return (user, pass) tuple for OpenSearch Basic Auth, or None if unset."""
    user = os.getenv("SIEM_USER", "admin")
    pw = os.getenv("SIEM_PASS", "")
    if user:
        return (user, pw)
    return None


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
        or "https://127.0.0.1:9201"
    )
    return url.rstrip("/")


from tinysocs.tls import resolve_ca_cert, get_opensearch_session


def _os_search_raw(index_pattern: str, body: dict, size: int = 0) -> dict:
    """
    OpenSearch search helper returning the full JSON response.

    Includes hits, aggregations, total, etc. — needed for endpoints
    that use aggregation results rather than individual documents.
    Returns an empty-result dict on any failure.

    Mirrors dashboard.py's _os_query pattern: suppress InsecureRequestWarning,
    manual status-code check (no raise_for_status), log response body on errors.
    """
    base = _get_siem_base_url()
    url = f"{base}/{index_pattern}/_search?ignore_unavailable=true&allow_no_indices=true"

    payload = dict(body)
    if "size" not in payload:
        payload["size"] = size

    # Use the shared SSL-aware session (bypasses certifi, uses explicit SSLContext)
    session = get_opensearch_session()
    auth = _get_siem_auth()

    print(
        f"[tinysocs-node] OpenSearch query url={url} "
        f"index_pattern={index_pattern} size={payload.get('size', size)} "
        f"verify={session.verify} auth={'set' if auth else 'None'}",
        flush=True,
    )

    empty: dict = {"hits": {"total": {"value": 0}, "hits": []}, "aggregations": {}}

    try:
        resp = session.post(
            url, json=payload, timeout=(5, 15), auth=auth,
        )
        # Match dashboard.py: do NOT use raise_for_status().
        # Handle 4xx/5xx manually so we can log the response body for debugging.
        if resp.status_code >= 400:
            err_body = ""
            try:
                err_body = resp.text[:300]
            except Exception:
                pass
            print(
                f"[tinysocs-node] HTTP {resp.status_code} on "
                f"{index_pattern}: {err_body}",
                flush=True,
            )
            return {
                **empty,
                "error": f"OpenSearch query error (HTTP {resp.status_code})",
            }
    except Exception as e:  # pragma: no cover
        print(f"[tinysocs-node] OpenSearch query failed: {e}; url={url}", flush=True)
        return {**empty, "error": f"OpenSearch query failed: {e}"}

    try:
        data = resp.json()
    except Exception as e:  # pragma: no cover
        print(f"[tinysocs-node] Failed to parse OpenSearch JSON: {e}; url={url}", flush=True)
        return {**empty, "error": f"Failed to parse response: {e}"}

    return data


def _os_search(index_pattern: str, body: dict, size: int = 20) -> list[dict[str, Any]]:
    """
    Minimal OpenSearch search helper.

    - Uses SIEM_URL/OPENSEARCH_URL for the base URL.
    - Honors SIEM_SSL_VERIFY/OPENSEARCH_VERIFY_SSL.
    - Flattens _source + a tiny bit of metadata into each returned doc.
    """
    data = _os_search_raw(index_pattern, body, size=size)

    if data.get("error"):
        return []

    total = data.get("hits", {}).get("total")
    if isinstance(total, dict):
        total_val = total.get("value")
    else:
        total_val = total
    hits = data.get("hits", {}).get("hits", [])
    hits_len = len(hits)
    base = _get_siem_base_url()
    url = f"{base}/{index_pattern}/_search"
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


# HMAC verification — centralized in tinysocs.api.auth
from tinysocs.api.auth import make_verify_hmac as _make_verify_hmac

_verify_hmac = _make_verify_hmac(SECRET, skew_secs=SKEW_SECS)


# Optional HMAC auth for read endpoints (off by default for backward compat)
_NODE_AUTH_READS = _env_bool("TINYSOCS_NODE_AUTH_READS", False)


async def _verify_hmac_if_enabled(request: Request) -> None:
    """HMAC auth for read endpoints — only enforced if TINYSOCS_NODE_AUTH_READS=1."""
    if _NODE_AUTH_READS:
        await _verify_hmac(request)


# ---------------------------------------------------------------------------
# HEC Bearer Token management
# ---------------------------------------------------------------------------
import secrets as _secrets

_HEC_TOKENS_FILE = Path(os.getenv("TINYSOCS_DATA_DIR", os.getenv("PROGRAMDATA", "")))
if _HEC_TOKENS_FILE == Path(""):
    _HEC_TOKENS_FILE = Path(".")
_HEC_TOKENS_FILE = _HEC_TOKENS_FILE / "TinySocs" / "hec-tokens.json"

_hec_tokens: list[dict] = []
_hec_tokens_loaded = False


def _load_hec_tokens() -> list[dict]:
    """Load HEC tokens from disk."""
    global _hec_tokens, _hec_tokens_loaded
    if _hec_tokens_loaded:
        return _hec_tokens
    try:
        if _HEC_TOKENS_FILE.is_file():
            _hec_tokens = json.loads(_HEC_TOKENS_FILE.read_text())
        else:
            _hec_tokens = []
    except Exception:
        _hec_tokens = []
    _hec_tokens_loaded = True
    return _hec_tokens


def _save_hec_tokens() -> None:
    """Persist HEC tokens to disk."""
    _HEC_TOKENS_FILE.parent.mkdir(parents=True, exist_ok=True)
    _HEC_TOKENS_FILE.write_text(json.dumps(_hec_tokens, indent=2))


def _hash_token(raw: str) -> str:
    """SHA-256 hash of a raw token."""
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def create_hec_token(name: str) -> tuple[str, str]:
    """Create a new HEC token. Returns (token_id, raw_token)."""
    _load_hec_tokens()
    token_id = "tok_" + _secrets.token_hex(6)
    raw_token = _secrets.token_urlsafe(32)
    entry = {
        "id": token_id,
        "token_hash": _hash_token(raw_token),
        "name": name,
        "created": datetime.now(timezone.utc).isoformat(),
        "last_used": None,
    }
    _hec_tokens.append(entry)
    _save_hec_tokens()
    return token_id, raw_token


def revoke_hec_token(token_id: str) -> bool:
    """Revoke a HEC token by ID. Returns True if found and removed."""
    _load_hec_tokens()
    before = len(_hec_tokens)
    _hec_tokens[:] = [t for t in _hec_tokens if t["id"] != token_id]
    if len(_hec_tokens) < before:
        _save_hec_tokens()
        return True
    return False


def list_hec_tokens() -> list[dict]:
    """List HEC tokens (without hashes)."""
    _load_hec_tokens()
    return [
        {"id": t["id"], "name": t["name"], "created": t["created"], "last_used": t.get("last_used")}
        for t in _hec_tokens
    ]


def _verify_bearer_token(raw_token: str) -> bool:
    """Verify a bearer token against stored hashes. Updates last_used on success."""
    _load_hec_tokens()
    h = _hash_token(raw_token)
    for t in _hec_tokens:
        if hashlib.sha256(raw_token.encode()).hexdigest() == t["token_hash"]:
            t["last_used"] = datetime.now(timezone.utc).isoformat()
            try:
                _save_hec_tokens()
            except Exception:
                pass  # Best-effort last_used update
            return True
    return False


async def _verify_hec_auth(request: Request) -> None:
    """Verify HEC authentication: accepts Bearer token OR HMAC headers."""
    auth_hdr = request.headers.get("authorization", "")
    if auth_hdr.lower().startswith("bearer "):
        raw = auth_hdr.split(" ", 1)[1].strip()
        if not _verify_bearer_token(raw):
            raise HTTPException(status_code=401, detail="Invalid bearer token")
        return
    # Fall back to HMAC auth
    await _verify_hmac(request)


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
        "endpoints": [
            "/meta", "/agg", "/sample", "/evidence/head", "/evidence/append",
            "/alerts/summary", "/alerts/timeline", "/fleet/summary", "/fleet/health",
            "/detections/fired", "/events/recent", "/host/timeline",
        ],
        "hmac": {
            "secret_set": SECRET != "dev-secret-change-me",
            "skew_secs": SKEW_SECS,
        },
    }


# ------------------------- Agg / Sample -------------------------

@app.get("/agg", dependencies=[Depends(_verify_hmac_if_enabled), Depends(_check_read_rate)])
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


@app.post("/agg", dependencies=[Depends(_verify_hmac_if_enabled), Depends(_check_read_rate)])
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


@app.get("/sample", dependencies=[Depends(_verify_hmac_if_enabled), Depends(_check_read_rate)])
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


@app.post("/sample", dependencies=[Depends(_verify_hmac_if_enabled), Depends(_check_read_rate)])
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
@app.get("/evidence/head", dependencies=[Depends(_verify_hmac_if_enabled), Depends(_check_read_rate)])
async def get_head() -> dict:
    head = _read_head()
    if not head.get("ok"):
        return {"ok": False, "reason": head.get("reason", "empty")}
    return head


@app.post("/evidence/append", dependencies=[Depends(_verify_hmac), Depends(_check_write_rate)])
async def post_append(req: Request) -> dict:
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


# ---------------------------------------------------------------------------
# Federation summary & query endpoints (Phase 18 M0 + M2)
# ---------------------------------------------------------------------------
# All read-only, no HMAC required (same access level as /meta).
# Query patterns mirror dashboard.py so response shapes are compatible.
# ---------------------------------------------------------------------------


def _os_total(resp: dict) -> int:
    """Extract total hit count from an OpenSearch response."""
    total_hit = resp.get("hits", {}).get("total", 0)
    return total_hit.get("value", 0) if isinstance(total_hit, dict) else int(total_hit)


@app.get("/alerts/summary", dependencies=[Depends(_verify_hmac_if_enabled), Depends(_check_read_rate)])
async def alerts_summary(hours: int = Query(24, ge=1, le=720)) -> dict:
    """
    Alert summary for the local site: total, by severity, top rules, top hosts.

    Mirrors dashboard.py's /api/alerts/summary response shape.
    """
    # Severity counts
    body_sev = {
        "query": {"range": {"timestamp": {"gte": f"now-{hours}h", "lte": "now"}}},
        "aggs": {"by_severity": {"terms": {"field": "alert.severity", "size": 10}}},
    }
    resp_sev = _os_search_raw("tinysocs-alerts-*", body_sev)
    if resp_sev.get("error"):
        return {"hours": hours, "total": 0, "severity": {}, "top_rules": [], "top_hosts": [],
                "error": resp_sev["error"]}

    total = _os_total(resp_sev)
    severity = {
        b["key"].lower(): b["doc_count"]
        for b in resp_sev.get("aggregations", {}).get("by_severity", {}).get("buckets", [])
    }

    # Top rules
    body_rules = {
        "query": {"range": {"timestamp": {"gte": f"now-{hours}h", "lte": "now"}}},
        "aggs": {"by_rule": {"terms": {"field": "alert.rule_id", "size": 10, "order": {"_count": "desc"}}}},
    }
    resp_rules = _os_search_raw("tinysocs-alerts-*", body_rules)
    top_rules = [
        {"rule": b["key"], "count": b["doc_count"]}
        for b in resp_rules.get("aggregations", {}).get("by_rule", {}).get("buckets", [])
    ]

    # Top hosts
    body_hosts = {
        "query": {"range": {"timestamp": {"gte": f"now-{hours}h", "lte": "now"}}},
        "aggs": {"by_host": {"terms": {"field": "source.computer_name.keyword", "size": 10, "order": {"_count": "desc"}}}},
    }
    resp_hosts = _os_search_raw("tinysocs-alerts-*", body_hosts)
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
    }


@app.get("/fleet/summary", dependencies=[Depends(_verify_hmac_if_enabled), Depends(_check_read_rate)])
async def fleet_summary() -> dict:
    """
    Fleet composition: host count, total events (24h), per-host summary.

    Lightweight version of /fleet/health for Sites tab cards.
    """
    body = {
        "query": {"range": {"@timestamp": {"gte": "now-24h", "lte": "now"}}},
        "aggs": {
            "by_host": {
                "terms": {"field": "winlog.computer_name", "size": 50},
                "aggs": {
                    "last_seen": {"max": {"field": "@timestamp"}},
                    "event_count": {"value_count": {"field": "@timestamp"}},
                },
            }
        },
    }
    resp = _os_search_raw("tinysocs-winlog-*", body)
    if resp.get("error"):
        return {"host_count": 0, "total_events_24h": 0, "hosts": [], "error": resp["error"]}

    hosts = []
    total_events = 0
    for b in resp.get("aggregations", {}).get("by_host", {}).get("buckets", []):
        ec = b.get("event_count", {}).get("value", b["doc_count"])
        total_events += ec
        hosts.append({
            "hostname": b["key"],
            "events_24h": ec,
            "last_seen": b.get("last_seen", {}).get("value_as_string", ""),
        })

    return {
        "host_count": len(hosts),
        "total_events_24h": total_events,
        "hosts": hosts,
    }


@app.get("/alerts/timeline", dependencies=[Depends(_verify_hmac_if_enabled), Depends(_check_read_rate)])
async def alerts_timeline(hours: int = Query(24, ge=1, le=720)) -> dict:
    """
    Hourly bucketed alert counts with per-severity breakdown.

    Mirrors dashboard.py's /api/alerts/timeline response shape.
    """
    body = {
        "query": {"range": {"timestamp": {"gte": f"now-{hours}h", "lte": "now"}}},
        "aggs": {
            "timeline": {
                "date_histogram": {"field": "timestamp", "fixed_interval": "1h", "min_doc_count": 0},
                "aggs": {
                    "by_severity": {"terms": {"field": "alert.severity", "size": 10}}
                },
            }
        },
    }
    resp = _os_search_raw("tinysocs-alerts-*", body)
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
    }


@app.get("/detections/fired", dependencies=[Depends(_verify_hmac_if_enabled), Depends(_check_read_rate)])
async def detections_fired(
    hours: int = Query(24, ge=1, le=720),
    limit: int = Query(30, ge=1, le=200),
) -> dict:
    """
    Individual fired detection alerts with full details.

    Mirrors dashboard.py's /api/detections/fired response shape.
    """
    body: dict = {
        "query": {"range": {"timestamp": {"gte": f"now-{hours}h", "lte": "now"}}},
        "sort": [{"timestamp": {"order": "desc"}}],
        "size": limit,
    }
    resp = _os_search_raw("tinysocs-alerts-*", body, size=limit)
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
            "status": "new",
            "tags": [],
            "notes": "",
        })
    total = _os_total(resp)
    return {"detections": detections, "total": total}


@app.get("/fleet/health", dependencies=[Depends(_verify_hmac_if_enabled), Depends(_check_read_rate)])
async def fleet_health() -> dict:
    """
    Detailed per-host fleet status with alert counts.

    Mirrors dashboard.py's /api/fleet/health response shape.
    """
    # Event data by host
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
    # Alert data by host
    alert_body = {
        "query": {"range": {"timestamp": {"gte": "now-24h", "lte": "now"}}},
        "aggs": {
            "by_host": {
                "terms": {"field": "source.computer_name.keyword", "size": 50},
                "aggs": {
                    "by_severity": {"terms": {"field": "alert.severity", "size": 5}},
                },
            }
        },
    }
    resp = _os_search_raw("tinysocs-winlog-*", body)
    alert_resp = _os_search_raw("tinysocs-alerts-*", alert_body)

    # Build alert lookup
    alert_counts: dict[str, int] = {}
    alert_severities: dict[str, dict[str, int]] = {}
    for ab in alert_resp.get("aggregations", {}).get("by_host", {}).get("buckets", []):
        hname = ab["key"]
        alert_counts[hname] = ab["doc_count"]
        alert_severities[hname] = {
            s["key"]: s["doc_count"]
            for s in ab.get("by_severity", {}).get("buckets", [])
        }

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
        hosts.append({
            "hostname": hostname,
            "event_count": b.get("event_count", {}).get("value", b["doc_count"]),
            "last_seen": b.get("last_seen", {}).get("value_as_string", ""),
            "first_seen": b.get("first_seen", {}).get("value_as_string", ""),
            "alert_count": alert_counts.get(hostname, 0),
            "alert_severities": alert_severities.get(hostname, {}),
            "top_channels": top_channels,
            "top_event_ids": top_events,
        })
    return {"hosts": hosts}


@app.get("/events/recent", dependencies=[Depends(_verify_hmac_if_enabled), Depends(_check_read_rate)])
async def events_recent(
    limit: int = Query(50, ge=1, le=500),
    q: str = Query("", description="KQL filter"),
    index: str = Query("tinysocs-winlog-*", description="Index pattern"),
) -> dict:
    """
    Recent events from the local SIEM.

    Mirrors dashboard.py's /api/events/recent response shape.
    """
    allowed = ["tinysocs-winlog-*", "tinysocs-alerts-*"]
    if index not in allowed:
        index = "tinysocs-winlog-*"

    ts_field = "timestamp" if "alerts" in index else "@timestamp"

    # Build query
    if q:
        text_q: dict = {"query_string": {"query": q, "default_operator": "AND"}}
    else:
        text_q = {"match_all": {}}

    body: dict = {
        "query": text_q,
        "sort": [{ts_field: {"order": "desc"}}],
        "size": limit,
    }
    resp = _os_search_raw(index, body, size=limit)
    hits = resp.get("hits", {}).get("hits", [])
    events = []
    for h in hits:
        src = h.get("_source", {})
        if "alerts" in index:
            alert = src.get("alert", {})
            events.append({
                "timestamp": src.get("timestamp", ""),
                "host": (
                src.get("source", {}).get("computer_name")
                or src.get("host", {}).get("name")
                or alert.get("host")
                or ""
            ),
                "channel": alert.get("rule_id", ""),
                "event_id": alert.get("severity", ""),
                "message": (alert.get("description", "") or alert.get("rule_name", ""))[:300],
            })
        else:
            events.append({
                "timestamp": src.get("@timestamp", ""),
                "channel": (src.get("winlog", {}) or {}).get("channel", ""),
                "event_id": (src.get("winlog", {}) or {}).get(
                    "event_id", src.get("event", {}).get("code", "")),
                "message": (src.get("message", "") or "")[:300],
                "host": (src.get("winlog", {}) or {}).get(
                    "computer_name", (src.get("agent", {}) or {}).get("hostname", "")),
            })
    return {"events": events, "total": len(events), "index": index}


@app.get("/host/timeline", dependencies=[Depends(_verify_hmac_if_enabled), Depends(_check_read_rate)])
async def host_timeline(
    hostname: str = Query("", description="Host to query (blank = all hosts)"),
    hours: int = Query(24, ge=1, le=720),
) -> dict:
    """
    Event count over time for a host (or all), bucketed with channel breakdown.

    Mirrors dashboard.py's /api/host/timeline response shape.
    """
    if hours <= 6:
        interval = "5m"
    elif hours <= 48:
        interval = "1h"
    else:
        interval = "6h"

    must_clauses: list = [
        {"range": {"@timestamp": {"gte": f"now-{hours}h", "lte": "now"}}},
    ]
    if hostname:
        hosts_list = [h.strip() for h in hostname.split(",") if h.strip()]
        if len(hosts_list) == 1:
            must_clauses.append({"term": {"winlog.computer_name": hosts_list[0]}})
        elif len(hosts_list) > 1:
            must_clauses.append({"terms": {"winlog.computer_name": hosts_list}})

    body = {
        "query": {"bool": {"must": must_clauses}},
        "aggs": {
            "over_time": {
                "date_histogram": {
                    "field": "@timestamp",
                    "fixed_interval": interval,
                    "min_doc_count": 0,
                    "extended_bounds": {"min": f"now-{hours}h", "max": "now"},
                },
                "aggs": {
                    "by_channel": {"terms": {"field": "winlog.channel", "size": 10}},
                },
            }
        },
    }
    resp = _os_search_raw("tinysocs-winlog-*", body)

    # Collect all channels across all buckets
    all_channels: set = set()
    raw_buckets = resp.get("aggregations", {}).get("over_time", {}).get("buckets", [])
    for b in raw_buckets:
        for ch in b.get("by_channel", {}).get("buckets", []):
            all_channels.add(ch["key"])

    # Build output buckets with per-channel counts
    buckets = []
    for b in raw_buckets:
        entry: dict = {"time": b.get("key_as_string", ""), "total": b.get("doc_count", 0)}
        ch_map = {ch["key"]: ch["doc_count"] for ch in b.get("by_channel", {}).get("buckets", [])}
        for ch_name in sorted(all_channels):
            entry[ch_name] = ch_map.get(ch_name, 0)
        buckets.append(entry)

    return {"hostname": hostname, "hours": hours, "buckets": buckets}


# ---------------------------------------------------------------------------
# Storage stats (Phase 21)
# ---------------------------------------------------------------------------


def _parse_os_size(s: str) -> int:
    """Parse OpenSearch human size string (e.g. '1.2mb', '500kb') to bytes."""
    if not s:
        return 0
    s = s.strip().lower()
    multipliers = {"b": 1, "kb": 1024, "mb": 1024**2, "gb": 1024**3, "tb": 1024**4}
    for suffix, mult in multipliers.items():
        if s.endswith(suffix):
            try:
                return int(float(s[: -len(suffix)]) * mult)
            except ValueError:
                return 0
    try:
        return int(s)
    except ValueError:
        return 0


def _human_size(b: int) -> str:
    """Convert bytes to human-readable string."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(b) < 1024:
            return f"{b:.1f} {unit}" if unit != "B" else f"{b} {unit}"
        b /= 1024
    return f"{b:.1f} PB"


@app.get("/storage/stats", dependencies=[Depends(_verify_hmac_if_enabled), Depends(_check_read_rate)])
async def storage_stats() -> dict:
    """Return storage usage stats: index sizes, disk usage, cluster health."""
    siem_url = os.getenv("SIEM_URL", "https://localhost:9201").rstrip("/")
    try:
        session = get_opensearch_session()
        auth = (os.getenv("SIEM_USER", "admin"), os.getenv("SIEM_PASS", ""))
        timeout = 10

        # Index sizes
        idx_resp = session.get(
            f"{siem_url}/_cat/indices/tinysocs-*?format=json&h=index,docs.count,store.size",
            auth=auth, timeout=timeout,
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
                winlog_docs += docs; winlog_bytes += size; winlog_count += 1
            elif name.startswith("tinysocs-alerts-"):
                alert_docs += docs; alert_bytes += size; alert_count += 1
            elif name.startswith("tinysocs-custom-"):
                custom_docs += docs; custom_bytes += size; custom_count += 1
            else:
                other_docs += docs; other_bytes += size; other_count += 1

        total_docs = winlog_docs + alert_docs + custom_docs + other_docs
        total_bytes = winlog_bytes + alert_bytes + custom_bytes + other_bytes

        # Disk usage
        disk_resp = session.get(f"{siem_url}/_nodes/stats/fs", auth=auth, timeout=timeout)
        disk_total = disk_avail = 0
        if disk_resp.status_code == 200:
            for node in disk_resp.json().get("nodes", {}).values():
                fs = node.get("fs", {}).get("total", {})
                disk_total += fs.get("total_in_bytes", 0)
                disk_avail += fs.get("available_in_bytes", 0)

        disk_used_pct = round((1 - disk_avail / disk_total) * 100, 1) if disk_total > 0 else 0

        # Cluster health
        health_resp = session.get(f"{siem_url}/_cluster/health", auth=auth, timeout=timeout)
        cluster_status = health_resp.json().get("status", "unknown") if health_resp.status_code == 200 else "unknown"

        return {
            "indices": {
                "winlog": {"doc_count": winlog_docs, "size_bytes": winlog_bytes, "size_human": _human_size(winlog_bytes),
                           "retention_days": int(os.getenv("WINLOG_RETENTION_DAYS", os.getenv("RETENTION_DAYS", "30")))},
                "alerts": {"doc_count": alert_docs, "size_bytes": alert_bytes, "size_human": _human_size(alert_bytes),
                           "retention_days": int(os.getenv("ALERT_RETENTION_DAYS", "90"))},
                "custom": {"doc_count": custom_docs, "size_bytes": custom_bytes, "size_human": _human_size(custom_bytes),
                           "retention_days": int(os.getenv("CUSTOM_RETENTION_DAYS", os.getenv("RETENTION_DAYS", "30")))},
                "other": {"doc_count": other_docs, "size_bytes": other_bytes, "size_human": _human_size(other_bytes)},
                "total": {"doc_count": total_docs, "size_bytes": total_bytes, "size_human": _human_size(total_bytes)},
            },
            "disk": {
                "total_bytes": disk_total, "available_bytes": disk_avail,
                "used_percent": disk_used_pct,
                "total_human": _human_size(disk_total), "available_human": _human_size(disk_avail),
            },
            "cluster_status": cluster_status,
        }
    except Exception as exc:
        return {"error": str(exc)}


@app.post("/storage/purge", dependencies=[Depends(_verify_hmac_if_enabled)])
async def storage_purge(request: Request) -> dict:
    """Purge indices. Accepts optional older_than_days (0=everything)."""
    import datetime as _dt

    siem_url = os.getenv("SIEM_URL", "https://localhost:9201").rstrip("/")
    siem_pass = os.getenv("SIEM_PASS", "").strip()
    if not siem_pass:
        return {"ok": False, "error": "SIEM_PASS not configured"}

    # Parse optional older_than_days from request body
    try:
        body = await request.json()
    except Exception:
        body = {}
    override_days = body.get("older_than_days")  # None = use retention, 0 = everything

    winlog_days = int(os.getenv("WINLOG_RETENTION_DAYS", os.getenv("RETENTION_DAYS", "30")))
    alert_days = int(os.getenv("ALERT_RETENTION_DAYS", "90"))

    try:
        session = get_opensearch_session()
        auth = (os.getenv("SIEM_USER", "admin"), siem_pass)

        idx_resp = session.get(
            f"{siem_url}/_cat/indices/tinysocs-*?format=json&h=index,docs.count",
            auth=auth, timeout=15,
        )
        if idx_resp.status_code != 200:
            return {"ok": False, "error": f"Failed to list indices: HTTP {idx_resp.status_code}"}

        now = _dt.datetime.utcnow()
        deleted_events = 0
        deleted_alerts = 0
        deleted_custom = 0
        deleted_indices = []

        for idx in idx_resp.json():
            name = idx.get("index", "")
            # Skip system indices
            if name.startswith("."):
                continue
            docs = int(idx.get("docs.count", 0) or 0)

            # "Everything" mode — delete all tinysocs-* indices
            if override_days is not None and override_days == 0:
                r = session.delete(f"{siem_url}/{name}", auth=auth, timeout=15)
                if r.status_code == 200:
                    deleted_indices.append(name)
                    if "winlog" in name:
                        deleted_events += docs
                    elif "alert" in name:
                        deleted_alerts += docs
                    else:
                        deleted_custom += docs
                continue

            # Date-based deletion
            parts = name.rsplit("-", 1)
            if len(parts) < 2:
                continue
            try:
                idx_date = _dt.datetime.strptime(parts[-1], "%Y.%m.%d")
            except ValueError:
                continue

            age_days = (now - idx_date).days
            should_delete = False

            if override_days is not None:
                # Fixed day override — applies to all index types
                if age_days > override_days:
                    should_delete = True
            else:
                # Use configured retention per type
                if name.startswith("tinysocs-winlog-") and age_days > winlog_days:
                    should_delete = True
                elif name.startswith("tinysocs-alerts-") and age_days > alert_days:
                    should_delete = True

            if should_delete:
                r = session.delete(f"{siem_url}/{name}", auth=auth, timeout=15)
                if r.status_code == 200:
                    deleted_indices.append(name)
                    if "winlog" in name:
                        deleted_events += docs
                    elif "alert" in name:
                        deleted_alerts += docs
                    else:
                        deleted_custom += docs

        return {
            "ok": True,
            "deleted_events": deleted_events,
            "deleted_alerts": deleted_alerts,
            "deleted_custom": deleted_custom,
            "deleted_indices": deleted_indices,
        }
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


# ---------------------------------------------------------------------------
# Diagnostics (Phase 21)
# ---------------------------------------------------------------------------

@app.get("/diagnostics/health")
async def diagnostics_health() -> dict:
    """Local node health: OpenSearch cluster health + disk usage."""
    import time as _time
    import shutil

    result = {"ok": True, "opensearch": {"status": "unknown"}, "disk": {}}

    siem_url = os.getenv("SIEM_URL", "https://localhost:9201").rstrip("/")
    siem_pass = os.getenv("SIEM_PASS", "").strip()
    auth = (os.getenv("SIEM_USER", "admin"), siem_pass) if siem_pass else None

    try:
        session = get_opensearch_session()
        t0 = _time.monotonic()
        r = session.get(f"{siem_url}/_cluster/health", auth=auth, timeout=10)
        ms = round((_time.monotonic() - t0) * 1000)
        if r.status_code == 200:
            h = r.json()
            result["opensearch"] = {
                "status": h.get("status", "unknown"),
                "node_count": h.get("number_of_nodes", 0),
                "active_shards": h.get("active_primary_shards", 0),
                "response_ms": ms,
            }
    except Exception as exc:
        result["opensearch"]["error"] = str(exc)

    try:
        usage = shutil.disk_usage("/")
        result["disk"] = {
            "total": usage.total,
            "used": usage.used,
            "free": usage.free,
            "used_pct": round(usage.used / usage.total * 100, 1) if usage.total > 0 else 0,
        }
    except Exception:
        pass

    return result


# ---------------------------------------------------------------------------
# Hub auto-registration (Phase 21)
# ---------------------------------------------------------------------------

_HUB_URL = os.getenv("TINYSOCS_HUB_URL", "").strip().rstrip("/")
_REGISTER_INTERVAL = int(os.getenv("TINYSOCS_REGISTER_INTERVAL", "60"))


def _discover_self_url() -> str:
    """Discover our LAN IP by opening a UDP socket toward the Hub."""
    override = os.getenv("TINYSOCS_NODE_URL", "").strip()
    if override:
        return override.rstrip("/")

    import socket
    from urllib.parse import urlparse

    parsed = urlparse(_HUB_URL)
    hub_host = parsed.hostname or "8.8.8.8"
    hub_port = parsed.port or 8090

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((hub_host, hub_port))
        local_ip = s.getsockname()[0]
        s.close()
    except Exception:
        local_ip = "127.0.0.1"

    port = _get_int_env("PORT") or _get_int_env("NODE_PORT") or 8081
    # Use the correct scheme based on whether TLS is actually configured
    tls_cert = os.getenv("TINYSOCS_TLS_CERT", "").strip()
    tls_key = os.getenv("TINYSOCS_TLS_KEY", "").strip()
    scheme = "https" if (tls_cert and tls_key and Path(tls_cert).is_file() and Path(tls_key).is_file()) else "http"
    return f"{scheme}://{local_ip}:{port}"


def _registration_loop() -> None:
    """Background loop: register with the Hub until approved or rejected."""
    if not _HUB_URL:
        return

    register_url = f"{_HUB_URL}/dashboard/api/nodes/register"
    version = os.getenv("TINYSOCS_VERSION", "dev")

    # Wait a few seconds for the node API to start
    time.sleep(10)

    while True:
        try:
            my_url = _discover_self_url()
            ts = str(int(time.time()))
            sig = hmac.new(
                SECRET.encode("utf-8"),
                ts.encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()

            resp = requests.post(
                register_url,
                json={"node_id": NODE_ID, "url": my_url, "version": version},
                headers={
                    "X-TinySOCS-Timestamp": ts,
                    "X-TinySOCS-Signature": f"sha256={sig}",
                    "Content-Type": "application/json",
                },
                timeout=15,
                verify=False,  # Federation: Hub uses self-signed cert; verify=False is intentional
            )

            if resp.status_code == 401:
                error_detail = ""
                try:
                    error_detail = resp.json().get("error", "")
                except Exception:
                    error_detail = resp.text[:200]
                print(f"[tinysocs-node] *** REGISTRATION AUTH FAILED *** "
                      f"Hub rejected our shared secret. Detail: {error_detail}. "
                      f"Check that MASTER_SHARED_SECRET matches between this Site and the Hub.",
                      flush=True)
                # Keep retrying in case operator fixes the secret
            elif resp.status_code >= 400:
                print(f"[tinysocs-node] Registration error: HTTP {resp.status_code} — {resp.text[:200]}",
                      flush=True)
            else:
                data = resp.json()
                status = data.get("status", "")

                if status == "approved":
                    print(f"[tinysocs-node] Registration approved by Hub", flush=True)
                    # Pin the Hub's TLS cert for future connections
                    try:
                        from tinysocs.federation_certs import fetch_cert_info, save_pinned_certs, load_pinned_certs, _pinned_certs_path
                        hub_cert = fetch_cert_info(_HUB_URL)
                        if hub_cert:
                            pinned = load_pinned_certs()
                            pinned[_HUB_URL] = {
                                "node_id": "hub",
                                "fingerprint_sha256": hub_cert["fingerprint_sha256"],
                                "subject": hub_cert["subject"],
                                "not_after": hub_cert["not_after"],
                                "pinned_at": datetime.now(timezone.utc).isoformat(),
                                "pem": hub_cert["pem"],
                            }
                            save_pinned_certs(pinned)
                            print(f"[tinysocs-node] Pinned Hub cert: {hub_cert['fingerprint_sha256'][:20]}...", flush=True)
                    except Exception as pin_exc:
                        print(f"[tinysocs-node] Could not pin Hub cert (non-fatal): {pin_exc}", flush=True)
                    return
                elif status == "rejected":
                    print(f"[tinysocs-node] Registration rejected by Hub", flush=True)
                    return
                elif status == "pending":
                    print(f"[tinysocs-node] Registration pending Hub approval (url={my_url})",
                          flush=True)
                else:
                    print(f"[tinysocs-node] Registration response: {data}", flush=True)
        except Exception as e:
            print(f"[tinysocs-node] Registration attempt failed: {e}", flush=True)

        time.sleep(_REGISTER_INTERVAL)


def _start_registration_thread() -> None:
    """Start the Hub registration loop as a daemon thread."""
    if not _HUB_URL:
        print("[tinysocs-node] No TINYSOCS_HUB_URL set; skipping auto-registration", flush=True)
        return
    import threading
    t = threading.Thread(target=_registration_loop, daemon=True, name="hub-register")
    t.start()
    print(f"[tinysocs-node] Auto-registration started (hub={_HUB_URL})", flush=True)


# ---------------------------------------------------------------------------
# HEC (HTTP Event Collector) — generic log ingestion endpoint
# ---------------------------------------------------------------------------
# Accepts arbitrary JSON events and bulk-indexes them into tinysocs-custom-*.
# Auth: HMAC (same as /evidence/append).
# Max: 1000 events per request, 5 MB body.
# ---------------------------------------------------------------------------

_HEC_MAX_EVENTS = 1000
_HEC_MAX_BODY_BYTES = 5 * 1024 * 1024  # 5 MB


@app.post("/hec", dependencies=[Depends(_verify_hec_auth), Depends(_check_write_rate)])
async def post_hec(req: Request) -> dict:
    """Ingest custom log events via HTTP Event Collector."""
    body = await req.json()

    # Accept single event or batch
    events_raw: list
    if "events" in body and isinstance(body["events"], list):
        events_raw = body["events"]
    elif "event" in body:
        events_raw = [body]
    else:
        raise HTTPException(400, "Request must contain 'event' (single) or 'events' (batch)")

    if len(events_raw) > _HEC_MAX_EVENTS:
        raise HTTPException(
            400,
            f"Batch exceeds {_HEC_MAX_EVENTS} event limit (got {len(events_raw)})",
        )

    if not events_raw:
        return {"ok": True, "indexed": 0, "errors": []}

    # Build bulk request body
    now_iso_str = datetime.now(timezone.utc).isoformat()
    today_suffix = datetime.now(timezone.utc).strftime("%Y.%m.%d")
    index_name = f"tinysocs-custom-{today_suffix}"

    bulk_lines: list[str] = []
    for evt_wrapper in events_raw:
        evt = evt_wrapper.get("event") if isinstance(evt_wrapper, dict) else evt_wrapper
        if evt is None:
            continue

        # Build the document
        doc: dict[str, Any] = {}

        # Timestamp: preserve if present, otherwise use now
        ts = None
        if isinstance(evt, dict):
            ts = evt.get("@timestamp") or evt.get("timestamp")
        if isinstance(evt_wrapper, dict) and not ts:
            ts = evt_wrapper.get("timestamp")
        doc["@timestamp"] = ts or now_iso_str
        doc["timestamp"] = doc["@timestamp"]

        # Source metadata
        if isinstance(evt_wrapper, dict):
            if evt_wrapper.get("source"):
                doc["source"] = evt_wrapper["source"]
            if evt_wrapper.get("sourcetype"):
                doc["sourcetype"] = evt_wrapper["sourcetype"]

        # The actual event data
        doc["event"] = evt

        # TinySocs metadata
        doc["tinysocs"] = {
            "input_name": "hec",
            "node_id": NODE_ID,
            "hec_ingested": True,
        }

        bulk_lines.append(json.dumps({"index": {"_index": index_name}}))
        bulk_lines.append(json.dumps(doc))

    if not bulk_lines:
        return {"ok": True, "indexed": 0, "errors": []}

    bulk_body = "\n".join(bulk_lines) + "\n"

    # Send to OpenSearch
    siem_url = _get_siem_base_url()
    auth = _get_siem_auth()
    ca = resolve_ca_cert()

    try:
        sess = get_opensearch_session()
        resp = sess.post(
            f"{siem_url}/_bulk",
            data=bulk_body,
            headers={"Content-Type": "application/x-ndjson"},
            auth=auth,
            verify=ca if ca else False,
            timeout=30,
        )
        resp.raise_for_status()
        result = resp.json()

        indexed = 0
        errors: list[str] = []
        for item in result.get("items", []):
            action = item.get("index", {})
            if action.get("status") in (200, 201):
                indexed += 1
            else:
                err = action.get("error", {})
                err_msg = err.get("reason", str(err)) if isinstance(err, dict) else str(err)
                errors.append(err_msg[:200])

        return {"ok": len(errors) == 0, "indexed": indexed, "errors": errors[:10]}

    except Exception as exc:
        raise HTTPException(502, f"OpenSearch bulk index failed: {exc}")


@app.on_event("startup")
async def _on_startup():
    _start_registration_thread()


def cli() -> None:
    import uvicorn

    port = _get_int_env("PORT") or _get_int_env("NODE_PORT") or 8081

    host = os.getenv("HOST", "0.0.0.0")
    loglvl = os.getenv("UVICORN_LOG_LEVEL", "info")
    reload = os.getenv("UVICORN_RELOAD", "0").strip().lower() in ("1", "true", "yes", "y")

    # Phase 19 M3: TLS support
    tls_cert = os.getenv("TINYSOCS_TLS_CERT", "").strip()
    tls_key = os.getenv("TINYSOCS_TLS_KEY", "").strip()
    ssl_kwargs: dict = {}
    if tls_cert and tls_key:
        if not Path(tls_cert).is_file():
            raise SystemExit(f"TINYSOCS_TLS_CERT not found: {tls_cert}")
        if not Path(tls_key).is_file():
            raise SystemExit(f"TINYSOCS_TLS_KEY not found: {tls_key}")
        ssl_kwargs = {"ssl_certfile": tls_cert, "ssl_keyfile": tls_key}
        print(f"[node] TLS enabled: cert={tls_cert}")
    else:
        print("[node] TLS not configured — running HTTP (dev mode)")

    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level=loglvl,
        reload=reload,
        **ssl_kwargs,
    )


if __name__ == "__main__":
    cli()