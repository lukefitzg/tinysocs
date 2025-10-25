# tinysocs/api/node.py
"""
TinySocs Node API (FastAPI) — tailored to your current repo.

Endpoints:
  GET /meta
  GET /agg      (multi-rule aggregates, no exemplars; uses AGGS only)
  POST /agg     (JSON body; same behavior as GET /agg)
  GET /sample   (single rule with up to k exemplars; fetches small _source)
  POST /sample  (JSON body; same behavior as GET /sample)
  GET /evidence/head     (tamper-evidence: report current head + chain status)
  POST /evidence/append  (tamper-evidence: append compact payload anchor)

Auth (HMAC v1):
  X-TinySOCS-Timestamp: unix seconds
  X-TinySOCS-Signature: sha256=<HMAC_SHA256(NODE_SECRET, timestamp)>
  - Allowed skew: ±300s
  - 5-minute replay cache on the exact timestamp value

Backends:
  - Uses your adapters via `make_client()` and your `agent/detections/rules.yaml`.
  - Aggregation logic uses OpenSearch terms aggregations (no large _source loads).
"""

from __future__ import annotations

import hashlib
import hmac
import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import uvicorn
import yaml
from fastapi import Body, Depends, FastAPI, HTTPException, Query, Request
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from tinysocs.agent.adapters.select import make_client
from tinysocs.agent.detections.engine import _rules_path as rules_path_resolver
from tinysocs.agent.models.evidence import DetectionEvidence, EvidenceExemplar

# ----------- Limits / caps -----------
ALLOWED_SKEW_SECONDS = 300             # ±5 minutes
REPLAY_CACHE_SECONDS = 300             # reject re-use of the same timestamp for 5 minutes

# Hard caps for API behavior
AGG_TERMS_SIZE = int(os.getenv("TINYSOCS_AGG_TERMS_SIZE", "50"))    # top-N groups returned
SAMPLE_MAX_DOCS = int(os.getenv("TINYSOCS_SAMPLE_MAX_DOCS", "20"))  # per /sample cap
NODE_MAX_HITS = int(os.getenv("NODE_MAX_HITS", "800"))              # absolute safety clamp for any fetch

# ---------- Env ----------
def _env(name: str, default: Optional[str] = None) -> Optional[str]:
    v = os.getenv(name)
    return v if v is not None else default


NODE_ID = _env("NODE_ID", "node-1")
NODE_SECRET = _env("NODE_SECRET", "dev-secret-change-me")
SIEM_BACKEND = (_env("SIEM_BACKEND", "opensearch") or "").lower()
SIEM_URL = _env("SIEM_URL", "https://localhost:9201")
RULESET = _env("RULESET", "default")
CAPABILITIES = ["agg", "sample"]

_client = make_client()

# ---------- Optional ledger imports (tamper-evidence) ----------
LEDGER_AVAILABLE = True
try:
    from tinysocs.agent.models.ledger import (
        append_entry as _ledger_append,
        _read_head as _ledger_read_head,
        verify_chain as _ledger_verify_chain,
    )
    # Advertise capability when present
    CAPABILITIES = CAPABILITIES + ["ledger"]
except Exception:
    LEDGER_AVAILABLE = False

# ---------- Simple replay cache (timestamp -> expires_at_epoch) ----------
_recent_timestamps: Dict[int, int] = {}


def _replay_cache_gc(now: int) -> None:
    stale = [ts for ts, exp in _recent_timestamps.items() if exp <= now]
    for ts in stale:
        _recent_timestamps.pop(ts, None)


# ---------- Auth ----------
def verify_hmac(request: Request) -> None:
    ts_hdr = request.headers.get("X-TinySOCS-Timestamp")
    sig_hdr = request.headers.get("X-TinySOCS-Signature")

    if not ts_hdr or not sig_hdr or not sig_hdr.startswith("sha256="):
        raise HTTPException(status_code=401, detail="Missing or malformed auth headers")

    try:
        ts = int(ts_hdr)
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid timestamp")

    now = int(time.time())
    if abs(now - ts) > ALLOWED_SKEW_SECONDS:
        raise HTTPException(status_code=401, detail="Timestamp skew too large")

    mac = hmac.new(
        key=(NODE_SECRET or "").encode("utf-8"),
        msg=str(ts).encode("utf-8"),
        digestmod=hashlib.sha256,
    ).hexdigest()

    expected = f"sha256={mac}"
    if not hmac.compare_digest(expected, sig_hdr):
        raise HTTPException(status_code=401, detail="Bad signature")

    _replay_cache_gc(now)
    exp = _recent_timestamps.get(ts)
    if exp and exp > now:
        raise HTTPException(status_code=401, detail="Replay detected")
    _recent_timestamps[ts] = now + REPLAY_CACHE_SECONDS


# ---------- Rule path + loading (robust) ----------
def _guess_rules_path() -> Optional[Path]:
    env_path = os.getenv("TINYSOCS_RULES_PATH")
    if env_path:
        p = Path(env_path).expanduser()
        if p.is_file():
            return p

    try:
        p = Path(rules_path_resolver("detections/rules.yaml"))
        if p.is_file():
            return p
    except Exception:
        pass

    try:
        p = Path(rules_path_resolver("agent/detections/rules.yaml"))
        if p.is_file():
            return p
    except Exception:
        pass

    repo_root = Path(__file__).resolve().parents[1]  # <repo>/tinysocs
    direct_candidates = [
        repo_root / "agent" / "detections" / "rules.yaml",
        repo_root / "detections" / "rules.yaml",
    ]
    for p in direct_candidates:
        if p.is_file():
            return p

    for p in repo_root.rglob("rules.yaml"):
        lower = str(p.as_posix()).lower()
        if "/agent/detections/" in lower or "\\agent\\detections\\" in str(p):
            return p

    return None


def _load_rules() -> List[Dict[str, Any]]:
    path = _guess_rules_path()
    if not path:
        print(
            "[node] WARN: could not locate 'agent/detections/rules.yaml' — set TINYSOCS_RULES_PATH to override.",
            flush=True,
        )
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or []
            return data
    except Exception as e:
        print(f"[node] ERROR: failed loading rules from {path}: {type(e).__name__}: {e}", flush=True)
        return []


def _find_rule(rule_id: str, rules: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    for r in rules:
        if r.get("id") == rule_id:
            return r
    return None


# ---------- Time window helpers ----------
def _parse_window(window: str) -> timedelta:
    """
    Parse simple windows like '15m', '1h', '24h', '7d'.
    Also accepts 'now-15m' style and returns 15m.
    """
    w = (window or "").strip().lower()
    if not w:
        return timedelta(minutes=15)
    if w.startswith("now-"):
        w = w[4:]
    unit = w[-1]
    try:
        value = float(w[:-1])
    except Exception:
        # fallback: minutes
        return timedelta(minutes=15)
    if unit == "s":
        return timedelta(seconds=value)
    if unit == "m":
        return timedelta(minutes=value)
    if unit == "h":
        return timedelta(hours=value)
    if unit == "d":
        return timedelta(days=value)
    # default minutes when unknown
    return timedelta(minutes=value)


def _time_bounds_iso(window: str) -> Tuple[str, str]:
    """Return (gte_iso, lte_iso) in UTC ISO8601 with Z."""
    now = datetime.now(timezone.utc)
    delta = _parse_window(window)
    gte = now - delta
    # strip microseconds for nicer query_string
    gte_s = gte.replace(microsecond=0).isoformat().replace("+00:00", "Z")
    lte_s = now.replace(microsecond=0).isoformat().replace("+00:00", "Z")
    return gte_s, lte_s


def _add_time_to_kql(kql: str, window: str) -> str:
    """Append an @timestamp range to the Lucene query_string we send to OS."""
    gte, lte = _time_bounds_iso(window)
    time_clause = f'@timestamp:[{gte} TO {lte}]'
    if not kql:
        return time_clause
    return f"({kql}) AND {time_clause}"


def _add_time_to_kql_kibana(kql: str, window: str) -> str:
    """
    Append a KQL-native time clause for adapters that expect Kibana KQL (not Lucene):
      @timestamp >= now-15m and @timestamp <= now
    """
    w = (window or "15m").strip().lower()
    time_clause = f'@timestamp >= now-{w} and @timestamp <= now'
    k = (kql or "").strip()
    if not k:
        return time_clause
    return f"({k}) and ({time_clause})"


def _range_filter(window: str) -> Dict[str, Any]:
    gte, lte = _time_bounds_iso(window)
    return {"range": {"@timestamp": {"gte": gte, "lte": lte}}}


# ---------- Count helper (agg-only, adapter-agnostic) ----------
def _count_for_kql(index: str, kql: str, window: str) -> int:
    # Use DSL range filter; do NOT inject Lucene time into the query_string.
    dsl: Dict[str, Any] = {
        "query": {
            "bool": {
                "must": [{"query_string": {"query": (kql or "")}}],
                "filter": [_range_filter(window)],
            }
        },
        "size": 0,
        "aggs": {"q": {"filter": {"match_all": {}}}},
        "stored_fields": "_none_",
    }
    try:
        aggs = _client.aggregate(index=index, dsl=dsl) or {}
        return int(aggs.get("q", {}).get("doc_count", 0))
    except Exception:
        return 0


# --------------------- Aggregation-first execution ---------------------
def _agg_for_rule(rule: Dict[str, Any], window: str, host: Optional[str]) -> Tuple[int, Dict[str, Any]]:
    index = rule.get("index", "winlogbeat-*")
    kql = rule["kql"]

    # Prefer keyword fields for aggregations
    def _kw(field: str) -> str:
        f = (field or "").strip()
        if f.endswith(".keyword") or f.endswith(".raw"):
            return f
        return f + ".keyword"

    # host filter (as keyword)
    if host:
        host_clause = f'(host.name.keyword:"{host}" OR winlog.computer_name.keyword:"{host}")'
        kql = f"({kql}) AND {host_clause}"

    # NOTE: do not append Lucene time to kql here; rely on DSL range instead.

    base_query = {
        "query": {
            "bool": {
                "must": [{"query_string": {"query": (kql or "")}}],
                "filter": [_range_filter(window)],
            }
        },
        "size": 0,
        "stored_fields": "_none_",
    }

    summary: Dict[str, Any] = {"index": index}
    group_by = rule.get("group_by")
    threshold = rule.get("threshold")

    # Normalize group_by and produce an "effective" keyword version
    gb_list: Optional[List[str]] = None
    gb_effective: Optional[List[str]] = None
    if group_by:
        if isinstance(group_by, str):
            gb_list = [group_by]
        elif isinstance(group_by, list):
            gb_list = [str(x) for x in group_by]
        else:
            gb_list = [str(group_by)]
        gb_effective = [_kw(f) for f in gb_list]

    total_count = _count_for_kql(index, kql, window)

    if gb_effective and threshold:
        def build_terms(fields: List[str], min_count: int, size: int) -> Dict[str, Any]:
            head, *rest = fields
            node = {
                "terms": {
                    "field": head,
                    "size": size,
                    "min_doc_count": min_count
                }
            }
            if rest:
                node["aggs"] = {"inner": build_terms(rest, min_count, size)}
            return node

        dsl = dict(base_query)
        dsl["aggs"] = {"groups": build_terms(gb_effective, int(threshold), AGG_TERMS_SIZE)}

        # Helper to transform .keyword → .raw (or append .raw) for a retry
        def _kw_to_raw(node: Dict[str, Any]) -> None:
            if "terms" in node and "field" in node["terms"]:
                f = node["terms"]["field"]
                if isinstance(f, str):
                    if f.endswith(".keyword"):
                        node["terms"]["field"] = f[:-8] + ".raw"
                    elif not f.endswith(".raw"):
                        node["terms"]["field"] = f + ".raw"
            if "aggs" in node and isinstance(node["aggs"], dict):
                for child in node["aggs"].values():
                    if isinstance(child, dict):
                        _kw_to_raw(child)

        try:
            aggs = _client.aggregate(index=index, dsl=dsl) or {}
        except Exception as e:
            msg = str(e)
            # Retry once with .raw if mapping lacks keyword fields / fielddata disabled
            if ("text fields are not" in msg.lower()) or ("fielddata=true" in msg.lower()) or ("not optimised" in msg.lower()):
                dsl_retry = dict(base_query)
                dsl_retry["aggs"] = {"groups": build_terms(gb_effective, int(threshold), AGG_TERMS_SIZE)}
                _kw_to_raw(dsl_retry["aggs"]["groups"])
                try:
                    aggs = _client.aggregate(index=index, dsl=dsl_retry) or {}
                    # Also reflect the effective fields we actually used
                    gb_effective = []
                    def _collect_fields(node: Dict[str, Any]) -> None:
                        if "terms" in node and "field" in node["terms"]:
                            gb_effective.append(node["terms"]["field"])
                        if "aggs" in node and isinstance(node["aggs"], dict):
                            for child in node["aggs"].values():
                                if isinstance(child, dict):
                                    _collect_fields(child)
                    _collect_fields(dsl_retry["aggs"]["groups"])
                except Exception as e2:
                    return total_count, {
                        "index": index,
                        "group_by": gb_list,
                        "group_by_effective": gb_effective,
                        "error": f"agg_failed_after_retry: {type(e2).__name__}: {e2}"
                    }
            else:
                return total_count, {
                    "index": index,
                    "group_by": gb_list,
                    "group_by_effective": gb_effective,
                    "error": f"agg_failed: {type(e).__name__}: {e}"
                }

        groups_over: List[Dict[str, Any]] = []

        def flatten_buckets(buckets: List[Dict[str, Any]], fields_left: List[str], acc: List[Any]):
            if not fields_left:
                return
            for b in buckets:
                key = b.get("key")
                doc_count = b.get("doc_count", 0)
                if len(fields_left) == 1:
                    groups_over.append({"group": acc + [key], "count": doc_count})
                else:
                    inner = b.get("inner", {}).get("buckets", [])
                    flatten_buckets(inner, fields_left[1:], acc + [key])

        buckets = (aggs.get("groups", {}) or {}).get("buckets", []) or []
        flatten_buckets(buckets, gb_effective, [])
        groups_over.sort(key=lambda x: x["count"], reverse=True)
        summary.update({
            "group_by": gb_list,
            "group_by_effective": gb_effective,
            "threshold": threshold,
            "groups_over_threshold": groups_over[:AGG_TERMS_SIZE],
            "total_groups": len(groups_over),
        })
    else:
        dsl2 = dict(base_query)
        dsl2["aggs"] = {
            "top_users": {"terms": {"field": _kw("user.name"), "size": 5}},
            "top_processes": {"terms": {"field": _kw("process.name"), "size": 5}},
        }
        try:
            a2 = _client.aggregate(index=index, dsl=dsl2) or {}
            summary.update({
                "top_users": [b["key"] for b in (a2.get("top_users", {}) or {}).get("buckets", [])],
                "top_processes": [b["key"] for b in (a2.get("top_processes", {}) or {}).get("buckets", [])],
            })
        except Exception:
            pass

    return total_count, summary


def _make_exemplars(docs: List[Dict[str, Any]], k: int, host: Optional[str]) -> List[EvidenceExemplar]:
    ex: List[EvidenceExemplar] = []
    now = datetime.now(timezone.utc)
    for i, d in enumerate(docs[:k]):
        s = d.get("_source", d)
        ts = s.get("@timestamp")
        try:
            ts_dt = datetime.fromisoformat(ts.replace("Z", "+00:00")) if ts else now
        except Exception:
            ts_dt = now
        ex.append(EvidenceExemplar(
            timestamp=ts_dt,
            id=str(d.get("_id") or f"doc-{i}"),
            message=(s.get("message") or s.get("winlog", {}).get("event_data", {}).get("CommandLine") or None),
            fields={
                "host": host or s.get("host", {}).get("name") or s.get("winlog", {}).get("computer_name"),
                "event.code": s.get("event", {}).get("code"),
                "user.name": s.get("user", {}).get("name"),
                "process.name": s.get("process", {}).get("name"),
            }
        ))
    return ex


# ---------- Pydantic request bodies for POST parity ----------
class AggRequest(BaseModel):
    rules: str = Field(..., description="Comma-separated rule IDs")
    window: str = Field(..., description="Time window, e.g., 15m")
    host: Optional[str] = Field(None, description="Optional host filter")


class SampleRequest(BaseModel):
    rule: str
    window: str
    host: Optional[str] = None
    k: int = Field(5, ge=1, le=SAMPLE_MAX_DOCS)


class LedgerAppendRequest(BaseModel):
    payload: Dict[str, Any]


# ---------- App ----------
app = FastAPI(title="TinySocs Node API", version="0.5.1")


@app.get("/meta")
async def meta(_: None = Depends(verify_hmac)) -> Dict[str, Any]:
    return {
        "node_id": NODE_ID,
        "backend": SIEM_BACKEND,
        "url": SIEM_URL,
        "ruleset": RULESET,
        "capabilities": CAPABILITIES,
        "time_utc": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/agg")
async def agg_get(
    _: None = Depends(verify_hmac),
    rules: str = Query(..., description="Comma-separated rule IDs"),
    window: str = Query(..., description="Time window, e.g., 15m"),
    host: Optional[str] = Query(None),
) -> List[DetectionEvidence]:
    return await _agg_impl(rules, window, host)


@app.post("/agg")
async def agg_post(_: None = Depends(verify_hmac), body: AggRequest = Body(...)) -> List[DetectionEvidence]:
    return await _agg_impl(body.rules, body.window, body.host)


async def _agg_impl(rules: str, window: str, host: Optional[str]) -> List[DetectionEvidence]:
    ruleset = _load_rules()
    if not ruleset:
        rule_list = [r.strip() for r in rules.split(",") if r.strip()]
        out: List[DetectionEvidence] = []
        for rid in rule_list:
            ev = DetectionEvidence(rule=rid, window=window, host=host, count=0, summary={"error": "ruleset_not_loaded"}).materialize()
            out.append(ev)
        return JSONResponse(content=jsonable_encoder([e.dict() for e in out]))

    rule_list = [r.strip() for r in rules.split(",") if r.strip()]
    out: List[DetectionEvidence] = []
    for rid in rule_list:
        r = _find_rule(rid, ruleset)
        if not r:
            ev = DetectionEvidence(rule=rid, window=window, host=host, count=0, summary={"error": "rule_not_found"}).materialize()
            out.append(ev)
            continue
        try:
            count, summary = _agg_for_rule(r, window, host)
        except Exception as e:
            count, summary = 0, {"error": f"agg_unhandled: {type(e).__name__}: {e}"}
        ev = DetectionEvidence(rule=rid, window=window, host=host, count=count, summary=summary, exemplars=[]).materialize()
        out.append(ev)
    return JSONResponse(content=jsonable_encoder([e.dict() for e in out]))


@app.get("/sample")
async def sample_get(
    _: None = Depends(verify_hmac),
    rule: str = Query(...),
    window: str = Query(...),
    host: Optional[str] = Query(None),
    k: int = Query(5, ge=1, le=SAMPLE_MAX_DOCS),
) -> DetectionEvidence:
    return await _sample_impl(rule, window, host, k)


@app.post("/sample")
async def sample_post(_: None = Depends(verify_hmac), body: SampleRequest = Body(...)) -> DetectionEvidence:
    return await _sample_impl(body.rule, body.window, body.host, body.k)


async def _sample_impl(rule: str, window: str, host: Optional[str], k: int) -> DetectionEvidence:
    ruleset = _load_rules()
    if not ruleset:
        ev = DetectionEvidence(rule=rule, window=window, host=host, count=0, summary={"error": "ruleset_not_loaded"}, exemplars=[]).materialize()
        return JSONResponse(content=jsonable_encoder(ev.dict()))

    r = _find_rule(rule, ruleset)
    if not r:
        ev = DetectionEvidence(rule=rule, window=window, host=host, count=0, summary={"error": "rule_not_found"}, exemplars=[]).materialize()
        return JSONResponse(content=jsonable_encoder(ev.dict()))

    index = r.get("index", "winlogbeat-*")
    kql = r["kql"]

    if host:
        host_clause = f'(host.name.keyword:"{host}" OR winlog.computer_name.keyword:"{host}")'
        kql = f"({kql}) AND {host_clause}"

    # Apply time with KQL-native date math so adapters that expect KQL return hits
    kql_with_time = _add_time_to_kql_kibana(kql, window)

    fetch_n = min(k, SAMPLE_MAX_DOCS, NODE_MAX_HITS)
    try:
        # Prefer KQL search for exemplars (adapter interface), with KQL-native time
        docs = _client.search_kql(index=index, kql=kql_with_time, size=fetch_n) or []
    except Exception as e:
        ev = DetectionEvidence(
            rule=rule, window=window, host=host, count=0,
            summary={"error": f"sample_failed: {type(e).__name__}: {e}"},
            exemplars=[]
        ).materialize()
        return JSONResponse(content=jsonable_encoder(ev.dict()))

    try:
        total_count = _count_for_kql(index, kql, window)
    except Exception:
        total_count = len(docs)

    try:
        _, summary = _agg_for_rule(r, window, host)
    except Exception as e:
        summary = {"error": f"agg_for_sample_failed: {type(e).__name__}: {e}"}

    exemplars = _make_exemplars(docs, fetch_n, host)
    ev = DetectionEvidence(rule=rule, window=window, host=host, count=total_count, summary=summary, exemplars=exemplars).materialize()
    return JSONResponse(content=jsonable_encoder(ev.dict()))


# ---------- Tamper-evidence endpoints ----------
@app.get("/evidence/head")
async def evidence_head(_: None = Depends(verify_hmac)) -> Dict[str, Any]:
    if not LEDGER_AVAILABLE:
        raise HTTPException(status_code=501, detail="Ledger not available on this node")
    seq, head = _ledger_read_head(NODE_ID)
    ok, last_seq, last_head = _ledger_verify_chain(NODE_ID)
    return {
        "node_id": NODE_ID,
        "ok": ok,
        "sequence": (last_seq if ok else seq),
        "head_sha256": (last_head if ok else head),
        "capability": "ledger",
    }


@app.post("/evidence/append")
async def evidence_append(_: None = Depends(verify_hmac), body: LedgerAppendRequest = Body(...)) -> Dict[str, Any]:
    if not LEDGER_AVAILABLE:
        raise HTTPException(status_code=501, detail="Ledger not available on this node")
    entry = _ledger_append(NODE_ID, body.payload)
    return {"node_id": NODE_ID, "entry": entry.to_json()}


if __name__ == "__main__":
    port = int(os.getenv("PORT", "8081"))
    uvicorn.run(app, host="0.0.0.0", port=port, reload=False)