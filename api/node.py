# tinysocs/api/node.py
"""
TinySocs Node API (FastAPI) — tailored to your current repo.

Endpoints:
  GET /meta
  GET /agg      (multi-rule aggregates, no exemplars; uses AGGS only)
  GET /sample   (single rule with up to k exemplars; fetches small _source)

Auth (HMAC v1):
  X-TinySOCS-Timestamp: unix seconds
  X-TinySOCS-Signature: sha256=<HMAC_SHA256(NODE_SECRET, timestamp)>

Backends:
  - Uses your adapters via `make_client()` and your `agent/detections/rules.yaml`.
  - Aggregation logic uses OpenSearch/ES terms aggregations (no large _source loads).
"""

from __future__ import annotations

from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parent.parent  # C:\tinysocs\tinysocs
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import hashlib
import hmac
import os
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from fastapi import FastAPI, Request, HTTPException, Depends, Query
from fastapi.responses import JSONResponse
from fastapi.encoders import jsonable_encoder
import uvicorn
import yaml

from agent.adapters.select import make_client
from agent.detections.engine import _rules_path as rules_path_resolver
from agent.models.evidence import DetectionEvidence, EvidenceExemplar

# ----------- Limits / caps -----------
ALLOWED_SKEW_SECONDS = 300

# Hard caps for API behavior
AGG_TERMS_SIZE   = int(os.getenv("TINYSOCS_AGG_TERMS_SIZE", "50"))   # top-N groups returned
SAMPLE_MAX_DOCS  = int(os.getenv("TINYSOCS_SAMPLE_MAX_DOCS", "20"))  # per /sample cap
NODE_MAX_HITS    = int(os.getenv("NODE_MAX_HITS", "800"))            # absolute safety clamp for any fetch

# ---------- Env ----------
def _env(name: str, default: Optional[str] = None) -> Optional[str]:
    v = os.getenv(name)
    return v if v is not None else default

NODE_ID      = _env("NODE_ID", "node-1")
NODE_SECRET  = _env("NODE_SECRET", "dev-secret-change-me")
SIEM_BACKEND = (_env("SIEM_BACKEND", "opensearch") or "").lower()
SIEM_URL     = _env("SIEM_URL", "https://localhost:9201")
RULESET      = _env("RULESET", "default")
CAPABILITIES = ["agg", "sample"]

_client = make_client()


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


# ---------- Rule path + loading (robust) ----------
def _guess_rules_path() -> Optional[Path]:
    """
    Find agent/detections/rules.yaml robustly, avoiding double 'agent/' prefixing.
    Order:
      1) TINYSOCS_RULES_PATH env (if set)
      2) rules_path_resolver('detections/rules.yaml')
      3) rules_path_resolver('agent/detections/rules.yaml')  # fallback
      4) Common direct paths under REPO_ROOT
      5) Targeted search within REPO_ROOT for '/agent/detections/rules.yaml'
    """
    # 1) explicit override
    env_path = os.getenv("TINYSOCS_RULES_PATH")
    if env_path:
        p = Path(env_path).expanduser()
        if p.is_file():
            return p

    # 2) resolver without leading 'agent/'
    try:
        p = Path(rules_path_resolver("detections/rules.yaml"))
        if p.is_file():
            return p
    except Exception:
        pass

    # 3) resolver with 'agent/' (older helpers expect this)
    try:
        p = Path(rules_path_resolver("agent/detections/rules.yaml"))
        if p.is_file():
            return p
    except Exception:
        pass

    # 4) direct common locations
    direct_candidates = [
        REPO_ROOT / "agent" / "detections" / "rules.yaml",
        REPO_ROOT / "detections" / "rules.yaml",
    ]
    for p in direct_candidates:
        if p.is_file():
            return p

    # 5) targeted walk (cheap — depth is shallow)
    for p in REPO_ROOT.rglob("rules.yaml"):
        # Prefer the canonical path containing agent/detections
        lower = str(p.as_posix()).lower()
        if "/agent/detections/" in lower or "\\agent\\detections\\" in str(p):
            return p

    return None


def _load_rules() -> List[Dict[str, Any]]:
    """
    Try hard to find & load rules; if not found, return [] and let endpoints
    report 'ruleset_not_loaded' instead of raising 500.
    """
    path = _guess_rules_path()
    if not path:
        print("[node] WARN: could not locate 'agent/detections/rules.yaml' — set TINYSOCS_RULES_PATH to override.", flush=True)
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


# ---------- Count helper (agg-only, adapter-agnostic) ----------
def _count_for_kql(index: str, kql: str) -> int:
    """
    Compute total hits for a query without relying on adapter-specific return shapes.
    Trick: run the query with size:0 and a 'filter' aggregation over match_all().
    The filter agg doc_count equals hits.total for the parent query.
    """
    dsl: Dict[str, Any] = {
        "query": {"query_string": {"query": kql}},
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
    """
    Execute an aggregate-only view of a rule:
      - returns (total_count, summary) using 'size:0' + 'filter' agg + terms aggs.
      - never pulls _source -> safe on small OpenSearch heaps.
    """
    index = rule.get("index", "winlogbeat-*")
    kql = rule["kql"]

    if host:
        host_clause = f'(host.name:"{host}" OR winlog.computer_name:"{host}")'
        kql = f"({kql}) AND {host_clause}"

    # Base DSL scaffold (we will add aggs below)
    base_query = {"query": {"query_string": {"query": kql}}, "size": 0, "stored_fields": "_none_"}

    summary: Dict[str, Any] = {"index": index}
    group_by = rule.get("group_by")
    threshold = rule.get("threshold")

    # First: get total matches via filter-agg trick
    total_count = _count_for_kql(index, kql)

    # If rule has grouping+threshold, push it into a terms agg
    if group_by and threshold:
        def build_terms(fields: List[str], min_count: int, size: int) -> Dict[str, Any]:
            if not fields:
                return {}
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
        dsl["aggs"] = {"groups": build_terms(group_by, int(threshold), AGG_TERMS_SIZE)}

        try:
            aggs = _client.aggregate(index=index, dsl=dsl) or {}
        except Exception as e:
            return total_count, {"index": index, "error": f"agg_failed: {type(e).__name__}: {e}"}

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
        flatten_buckets(buckets, group_by, [])
        groups_over.sort(key=lambda x: x["count"], reverse=True)
        summary.update({
            "group_by": group_by,
            "threshold": threshold,
            "groups_over_threshold": groups_over[:AGG_TERMS_SIZE],
            "total_groups": len(groups_over),
        })
    else:
        # Lightweight sketch using aggs on common fields (no _source):
        dsl2 = dict(base_query)
        dsl2["aggs"] = {
            "top_users": {"terms": {"field": "user.name", "size": 5}},
            "top_processes": {"terms": {"field": "process.name", "size": 5}},
        }
        try:
            a2 = _client.aggregate(index=index, dsl=dsl2) or {}
            summary.update({
                "top_users": [b["key"] for b in (a2.get("top_users", {}) or {}).get("buckets", [])],
                "top_processes": [b["key"] for b in (a2.get("top_processes", {}) or {}).get("buckets", [])],
            })
        except Exception:
            # ignore if fields unmapped
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


# ---------- App ----------
app = FastAPI(title="TinySocs Node API", version="0.3.2")


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
async def agg(
    _: None = Depends(verify_hmac),
    rules: str = Query(..., description="Comma-separated rule IDs"),
    window: str = Query(..., description="Time window, e.g., 15m"),
    host: Optional[str] = Query(None),
) -> List[DetectionEvidence]:
    ruleset = _load_rules()
    if not ruleset:
        # If the ruleset failed to load, report per-rule errors instead of 500
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
            # ultra-defensive – should be caught inside _agg_for_rule, but keep node alive
            count, summary = 0, {"error": f"agg_unhandled: {type(e).__name__}: {e}"}
        ev = DetectionEvidence(rule=rid, window=window, host=host, count=count, summary=summary, exemplars=[]).materialize()
        out.append(ev)
    # Ensure JSON-safe output (datetimes -> ISO)
    return JSONResponse(content=jsonable_encoder([e.dict() for e in out]))


@app.get("/sample")
async def sample(
    _: None = Depends(verify_hmac),
    rule: str = Query(...),
    window: str = Query(...),
    host: Optional[str] = Query(None),
    k: int = Query(5, ge=1, le=SAMPLE_MAX_DOCS),
) -> DetectionEvidence:
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
        host_clause = f'(host.name:"{host}" OR winlog.computer_name:"{host}")'
        kql = f"({kql}) AND {host_clause}"

    # For sampling, fetch small _source sets only; clamp by NODE_MAX_HITS too
    fetch_n = min(k, SAMPLE_MAX_DOCS, NODE_MAX_HITS)
    try:
        # Adapters return list of _source dicts here
        docs = _client.search_kql(index=index, kql=kql, size=fetch_n) or []
    except Exception as e:
        ev = DetectionEvidence(
            rule=rule, window=window, host=host, count=0,
            summary={"error": f"sample_failed: {type(e).__name__}: {e}"},
            exemplars=[]
        ).materialize()
        return JSONResponse(content=jsonable_encoder(ev.dict()))

    # Get an exact-ish count via the same agg trick (no adapter special cases)
    try:
        total_count = _count_for_kql(index, kql)
    except Exception:
        total_count = len(docs)

    # Provide a minimal summary (re-use AGG-based quick sketch)
    try:
        _, summary = _agg_for_rule(r, window, host)
    except Exception as e:
        summary = {"error": f"agg_for_sample_failed: {type(e).__name__}: {e}"}

    exemplars = _make_exemplars(docs, fetch_n, host)
    ev = DetectionEvidence(rule=rule, window=window, host=host, count=total_count, summary=summary, exemplars=exemplars).materialize()
    return JSONResponse(content=jsonable_encoder(ev.dict()))


if __name__ == "__main__":
    port = int(os.getenv("PORT", "8081"))
    uvicorn.run(app, host="0.0.0.0", port=port, reload=False)