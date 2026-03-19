# tinysocs/api/node.py
import hashlib
import hmac
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import sys
import requests
import urllib3
from fastapi import FastAPI, HTTPException, Request, Body, Query

# Suppress InsecureRequestWarning when verify=False
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Fix for PyInstaller-compiled binaries: the bundled certifi CA bundle
# can be corrupt or incompatible with the bundled OpenSSL, causing
# NO_CERTIFICATE_OR_CRL_FOUND even with verify=False.  Remove any
# env vars that force-load a cert bundle on startup.
if getattr(sys, "frozen", False):
    for _ev in ("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE"):
        os.environ.pop(_ev, None)

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


def _get_siem_auth():
    """Return (user, pass) tuple for OpenSearch Basic Auth, or None if unset."""
    user = os.getenv("SIEM_USER", "admin")
    pw = os.getenv("SIEM_PASS", "admin")
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


def _os_search_raw(index_pattern: str, body: dict, size: int = 0) -> dict:
    """
    OpenSearch search helper returning the full JSON response.

    Includes hits, aggregations, total, etc. — needed for endpoints
    that use aggregation results rather than individual documents.
    Returns an empty-result dict on any failure.

    Mirrors dashboard.py's _os_query pattern: suppress InsecureRequestWarning,
    manual status-code check (no raise_for_status), log response body on errors.
    """
    # Suppress InsecureRequestWarning (matches dashboard.py)
    try:
        import urllib3 as _u3
        _u3.disable_warnings(_u3.exceptions.InsecureRequestWarning)
    except Exception:
        pass

    base = _get_siem_base_url()
    url = f"{base}/{index_pattern}/_search?ignore_unavailable=true&allow_no_indices=true"

    payload = dict(body)
    if "size" not in payload:
        payload["size"] = size

    verify = _get_tls_verify_flag()
    auth = _get_siem_auth()

    print(
        f"[tinysocs-node] OpenSearch query url={url} "
        f"index_pattern={index_pattern} size={payload.get('size', size)} "
        f"verify={verify} auth={'set' if auth else 'None'}",
        flush=True,
    )

    empty: dict = {"hits": {"total": {"value": 0}, "hits": []}, "aggregations": {}}

    try:
        resp = requests.post(
            url, json=payload, timeout=(5, 15), verify=verify, auth=auth,
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


@app.get("/alerts/summary")
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


@app.get("/fleet/summary")
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


@app.get("/alerts/timeline")
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


@app.get("/detections/fired")
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


@app.get("/fleet/health")
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


@app.get("/events/recent")
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


@app.get("/host/timeline")
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
                verify=False,
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