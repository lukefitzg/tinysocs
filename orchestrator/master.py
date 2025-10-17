# tinysocs/orchestrator/master.py
"""
TinySocs Master Aggregator — tailored to your current repo.

- Fans out /agg to nodes, merges DetectionEvidence, then calls your existing summarizer:
    from tinysocs.agent.llm_select import summarize
- Persistence stays inside your summarizer (OpenAI tools path) to `siem_index` if enabled.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import time
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime, timezone

import requests

from tinysocs.agent.models.evidence import DetectionEvidence
from tinysocs.agent.llm_select import summarize as summarize_findings

ALLOWED_SKEW_SECONDS = 300
REQUEST_TIMEOUT_SEC = int(os.getenv("REQUEST_TIMEOUT_SEC", "6"))

NODES = [u.strip() for u in (os.getenv("TINYSOCS_NODES", "")).split(",") if u.strip()]
SECRET = os.getenv("MASTER_SHARED_SECRET", "dev-secret-change-me")


def _sign(ts: int) -> str:
    mac = hmac.new((SECRET or "").encode("utf-8"), str(ts).encode("utf-8"), hashlib.sha256).hexdigest()
    return f"sha256={mac}"


def _headers() -> Dict[str, str]:
    ts = int(time.time())
    return {"X-TinySOCS-Timestamp": str(ts), "X-TinySOCS-Signature": _sign(ts)}


def fetch_agg(node_url: str, rules: List[str], window: str, host: Optional[str]) -> List[DetectionEvidence]:
    params = {"rules": ",".join(rules), "window": window}
    if host: params["host"] = host
    r = requests.get(f"{node_url.rstrip('/')}/agg", headers=_headers(), params=params, timeout=REQUEST_TIMEOUT_SEC)
    r.raise_for_status()
    return [DetectionEvidence(**e) for e in r.json()]


def merge_evidence(batches: List[List[DetectionEvidence]]) -> List[DetectionEvidence]:
    def deep_union(a: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, Any]:
        out: Dict[str, Any] = dict(a)
        for k, v in b.items():
            if k not in out:
                out[k] = v
            else:
                av = out[k]
                if isinstance(av, list) and isinstance(v, list):
                    seen = set(); merged = []
                    for item in av + v:
                        key = json.dumps(item, sort_keys=True, ensure_ascii=False) if isinstance(item, (dict, list)) else item
                        if key not in seen:
                            seen.add(key); merged.append(item)
                    out[k] = merged
                elif isinstance(av, dict) and isinstance(v, dict):
                    out[k] = deep_union(av, v)
                else:
                    out[k] = v
        return out

    by_key: Dict[Tuple[str, Optional[str]], DetectionEvidence] = {}
    for ev in (e for batch in batches for e in batch):
        key = (ev.rule, ev.host)
        if key not in by_key:
            by_key[key] = DetectionEvidence(
                rule=ev.rule, window=ev.window, host=ev.host, count=ev.count, summary=ev.summary, exemplars=ev.exemplars[:]
            )
        else:
            cur = by_key[key]
            cur.count = max(cur.count, ev.count)
            cur.summary = deep_union(cur.summary, ev.summary)
            if len(cur.exemplars) < 10:
                take = 10 - len(cur.exemplars)
                cur.exemplars.extend(ev.exemplars[:take])
    return [v.materialize() for v in by_key.values()]


def _to_findings(ev_list: List[DetectionEvidence]) -> List[Dict[str, Any]]:
    """Convert DetectionEvidence → your summarizer's 'findings' shape."""
    findings: List[Dict[str, Any]] = []
    for ev in ev_list:
        f: Dict[str, Any] = {
            "rule": ev.rule,
            "summary": f"Fleet aggregate for {ev.rule} in {ev.window}",
            "evidence": {
                "host": ev.host,
                "count": ev.count,
                **(ev.summary or {}),
            },
        }
        if ev.exemplars:
            # summarizer expects arbitrary evidence; include as 'sample'
            f["sample"] = [ex.dict() for ex in ev.exemplars]
        findings.append(f)
    return findings


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rules", required=True, help="Comma separated rule IDs")
    ap.add_argument("--window", required=True, help="Window, e.g., 15m")
    ap.add_argument("--host", default=None, help="Optional host filter")
    args = ap.parse_args()

    if not NODES:
        raise SystemExit("TINYSOCS_NODES is empty; set it to comma-separated node URLs.")

    rules = [r.strip() for r in args.rules.split(",") if r.strip()]
    batches: List[List[DetectionEvidence]] = []
    for node in NODES:
        try:
            evs = fetch_agg(node, rules=rules, window=args.window, host=args.host)
            print(f"[master] {node} -> {len(evs)} evidences")
            batches.append(evs)
        except Exception as e:
            print(f"[master] WARN: failed to fetch from {node}: {e}")

    merged = merge_evidence(batches)
    print(f"[master] merged groups: {len(merged)}")

    findings = _to_findings(merged)
    incident = summarize_findings(findings)  # uses your existing LLM + optional persistence
    print("----- Fleet Incident (Markdown-ish preview) -----")
    print(f"Severity: {incident.get('severity')}\nTL;DR: {incident.get('tldr')}\nItems: {len(incident.get('evidence', []))}")


if __name__ == "__main__":
    main()
