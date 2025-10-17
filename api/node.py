# tinysocs/api/node.py
"""
TinySocs Node API (FastAPI) — tailored to your current repo.

Endpoints:
  GET /meta
  GET /agg      (multi-rule aggregates, no exemplars)
  GET /sample   (single rule with up to k exemplars)

Auth (HMAC v1):
  X-TinySOCS-Timestamp: unix seconds
  X-TinySOCS-Signature: sha256=<HMAC_SHA256(NODE_SECRET, timestamp)>

Backends:
  - Uses your adapters via `make_client()` and your `agent/detections/rules.yaml`.
  - Aggregation logic mirrors your threshold/grouping style in detections/agent.py.
"""

from __future__ import annotations

# --- Bootstrapping so running from C:\tinysocs\tinysocs works ---
import sys
from pathlib import Path

# This file lives at: <REPO_ROOT>/tinysocs/api/node.py
# Ensure <REPO_ROOT> is on sys.path so `import tinysocs...` resolves,
# even when CWD is <REPO_ROOT>/tinysocs.
_REPO_ROOT = Path(__file__).resolve().parents[2]  # go from .../tinysocs/api/node.py -> .../
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
# ----------------------------------------------------------------

import hashlib
import hmac
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from fastapi import FastAPI, Request, HTTPException, Depends, Query
from fastapi.responses import JSONResponse
from fastapi.encoders import jsonable_encoder
import uvicorn
import yaml

from tinysocs.agent.adapters.select import make_client
from tinysocs.agent.models.evidence import DetectionEvidence, EvidenceExemplar

ALLOWED_SKEW_SECONDS = 300

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

# Absolute path to rules.yaml (…/tinysocs/agent/detections/rules.yaml)
RULES_PATH = Path(__file__).resolve().parents[1] / "agent" / "detections" / "rules.yaml"


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


# ---------- Rule helpers ----------
def _load_rules() -> List[Dict[str, Any]]:
    if not RULES_PATH.exists():
        raise HTTPException(status_code=500, detail=f"rules.yaml not found at {RULES_PATH}")
    with open(RULES_PATH, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or []


def _find_rule(rule_id: str, rules: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    for r in rules:
        if r.get("id") == rule_id:
            return r
    return None


def _run_rule(rule: Dict[str, Any], window: str, host: Optional[str]) -> Tuple[int, Dict[str, Any], List[Dict[str, Any]]]:
    """
    Execute a rule locally using your client:
      - returns (count, summary, hits) where hits are trimmed raw docs for exemplar extraction.
    """
    index = rule.get("index", "winlogbeat-*")
    kql = rule["kql"]

    # Optional host scoping: append to KQL if host provided
    if host:
        # conservative: host.name OR winlog.computer_name
        host_clause = f'(host.name:"{host}" OR winlog.computer_name:"{host}")'
        kql = f"({kql}) AND {host_clause}"

    # Limit hits to 2000 for aggregate view
    docs = _client.search_kql(index=index, kql=kql, size=2000) or []

    # Count = total hits
    count = len(docs)

    # Threshold/group_by summary (mirror your agent/detections/agent.py approach)
    summary: Dict[str, Any] = {"index": index}
    group_by = rule.get("group_by")
    threshold = rule.get("threshold")

    if group_by and threshold:
        from collections import Counter

        def get_field(d: Dict[str, Any], path: str) -> Any:
            # dot-path into nested dicts
            cur = d
            for part in path.split("."):
                cur = cur.get(part) if isinstance(cur, dict) else None
                if cur is None:
                    break
            return cur

        ctr = Counter(
            tuple(get_field(d.get("_source", d), f) for f in group_by)
            for d in docs
        )
        groups_over = [{"group": list(k), "count": n} for k, n in ctr.items() if n >= threshold]
        groups_over.sort(key=lambda x: x["count"], reverse=True)
        summary.update({
            "group_by": group_by,
            "threshold": threshold,
            "groups_over_threshold": groups_over[:10],
            "total_groups": len(ctr),
        })
    else:
        # simple top users/processes sketch (best-effort)
        def gx(field: str, topn=5):
            from collections import Counter
            vals = []
            for d in docs:
                s = d.get("_source", d)
                # try both ECS and winlog fields
                v = s.get(field) or s.get("winlog", {}).get(field.split(".")[-1])
                if v:
                    vals.append(v if not isinstance(v, list) else v[0])
            return [k for k, _ in Counter(vals).most_common(topn)]

        summary.update({
            "top_users": gx("user.name", 5),
            "top_processes": gx("process.name", 5),
        })

    return count, summary, docs


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
app = FastAPI(title="TinySocs Node API", version="0.1.3")


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
    rule_list = [r.strip() for r in rules.split(",") if r.strip()]
    out: List[DetectionEvidence] = []
    for rid in rule_list:
        r = _find_rule(rid, ruleset)
        if not r:
            # unknown rule -> empty evidence object with count 0
            ev = DetectionEvidence(rule=rid, window=window, host=host, count=0, summary={"error": "rule_not_found"}).materialize()
            out.append(ev)
            continue
        count, summary, _ = _run_rule(r, window, host)
        ev = DetectionEvidence(rule=rid, window=window, host=host, count=count, summary=summary, exemplars=[]).materialize()
        out.append(ev)
    return JSONResponse(content=jsonable_encoder([e.dict() for e in out]))


@app.get("/sample")
async def sample(
    _: None = Depends(verify_hmac),
    rule: str = Query(...),
    window: str = Query(...),
    host: Optional[str] = Query(None),
    k: int = Query(5, ge=1, le=20),
) -> DetectionEvidence:
    ruleset = _load_rules()
    r = _find_rule(rule, ruleset)
    if not r:
        ev = DetectionEvidence(rule=rule, window=window, host=host, count=0, summary={"error": "rule_not_found"}, exemplars=[]).materialize()
        return JSONResponse(content=jsonable_encoder(ev.dict()))
    count, summary, docs = _run_rule(r, window, host)
    exemplars = _make_exemplars(docs, k, host)
    ev = DetectionEvidence(rule=rule, window=window, host=host, count=count, summary=summary, exemplars=exemplars).materialize()
    return JSONResponse(content=jsonable_encoder(ev.dict()))


if __name__ == "__main__":
    port = int(os.getenv("PORT", "8081"))
    uvicorn.run("tinysocs.api.node:app", host="0.0.0.0", port=port, reload=False)