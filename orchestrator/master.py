# tinysocs/orchestrator/master.py
"""
TinySocs Master Aggregator — runs from tinysocs/tinysocs just fine.

- Fans out /agg to nodes, merges DetectionEvidence, calls your existing summarizer.
- Persistence remains inside your summarizer path (OpenAI/Ollama tools) the same way solo mode does.
- Privacy toggle integrated via agent.summarizer_adapter:
    - PRIVACY_MODE=abstract (default) -> send masked, compact payload to summarizer
    - PRIVACY_MODE=raw               -> legacy behavior (send findings)

Robustness:
- --deadline <sec>: overall wall-clock budget; stops waiting when exhausted.
- Per-node errors collected and surfaced in preview (partial success visible).
"""

from __future__ import annotations

# --- Bootstrapping so running from C:\tinysocs\tinysocs works ---
import sys
from pathlib import Path

# This file lives at: <REPO_ROOT>/tinysocs/orchestrator/master.py
_REPO_ROOT = Path(__file__).resolve().parents[2]
_PKG_ROOT  = _REPO_ROOT / "tinysocs"
_AGENT_DIR = _PKG_ROOT / "agent"

for p in (str(_REPO_ROOT), str(_PKG_ROOT), str(_AGENT_DIR)):
    if p not in sys.path:
        sys.path.insert(0, p)
# ----------------------------------------------------------------

# -- .env support --
from dotenv import load_dotenv
_ENV_ROOT = _REPO_ROOT
for candidate in (Path.cwd(), _ENV_ROOT):
    env_file = candidate / ".env"
    if env_file.exists():
        load_dotenv(dotenv_path=env_file, override=False)
        break
# ---------------

import argparse
import hashlib
import hmac
import json
import os
import time
from typing import Any, Dict, List, Optional, Tuple

import requests

from tinysocs.agent.models.evidence import DetectionEvidence

# Privacy adapter (new)
try:
    from tinysocs.agent.summarizer_adapter import (
        prepare_payload as _prepare_privacy_payload,
        annotate_report_header as _annotate_header,
        PRIVACY_MODE,
    )
except Exception as _e:
    # Fallback if file not present yet
    def _prepare_privacy_payload(evidences: List[Dict[str, Any]], window: str) -> Dict[str, Any]:
        return {"mode": "raw", "window": window, "evidences": evidences}
    def _annotate_header(md: str, llm_mode: str = "openai") -> str:
        return md
    PRIVACY_MODE = os.getenv("PRIVACY_MODE", "raw").strip().lower()
    print(f"[master] WARN: summarizer_adapter not available: {_e}. Using raw fallback.")

# Resilient summarizer import (support either `summarize` or `summarize_findings`)
try:
    from tinysocs.agent.llm_select import summarize as _summarize
except Exception:
    try:
        from tinysocs.agent.llm_select import summarize_findings as _summarize  # type: ignore
    except Exception as e:
        _summarize = None
        print(f"[master] WARN: could not import summarizer from agent.llm_select: {e}")

REQUEST_TIMEOUT_SEC = int(os.getenv("REQUEST_TIMEOUT_SEC", "6"))
NODES = [u.strip() for u in (os.getenv("TINYSOCS_NODES", "")).split(",") if u.strip()]
SECRET = os.getenv("MASTER_SHARED_SECRET", "dev-secret-change-me")


def _sign(ts: int) -> str:
    mac = hmac.new((SECRET or "").encode("utf-8"), str(ts).encode("utf-8"), hashlib.sha256).hexdigest()
    return f"sha256={mac}"


def _headers() -> Dict[str, str]:
    ts = int(time.time())
    return {"X-TinySOCS-Timestamp": str(ts), "X-TinySOCS-Signature": _sign(ts)}


def fetch_agg(node_url: str, rules: List[str], window: str, host: Optional[str], timeout: float) -> List[DetectionEvidence]:
    params = {"rules": ",".join(rules), "window": window}
    if host:
        params["host"] = host
    r = requests.get(
        f"{node_url.rstrip('/')}/agg",
        headers=_headers(),
        params=params,
        timeout=timeout,
        verify=False if os.getenv("TINYSOCS_INSECURE_SKIP_VERIFY","1") == "1" else True,
    )
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
                    seen = set()
                    merged = []
                    for item in av + v:
                        key = json.dumps(item, sort_keys=True, ensure_ascii=False) if isinstance(item, (dict, list)) else item
                        if key not in seen:
                            seen.add(key)
                            merged.append(item)
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
    """Convert DetectionEvidence → summarizer 'findings' shape (legacy/raw path)."""
    findings: List[Dict[str, Any]] = []
    for ev in ev_list:
        f: Dict[str, Any] = {
            "rule": ev.rule,
            "summary": f"Fleet aggregate for {ev.rule} in {ev.window}",
            "evidence": {"host": ev.host, "count": ev.count, **(ev.summary or {})},
        }
        if ev.exemplars:
            f["sample"] = [ex.dict() for ex in ev.exemplars]
        findings.append(f)
    return findings


def _minimal_local_summary(merged: List[DetectionEvidence], window: str) -> Dict[str, Any]:
    """PII-safe, offline summary used only if PRIVACY_MODE=abstract and summarizer rejects payload."""
    by_rule: Dict[str, Dict[str, Any]] = {}
    for e in merged:
        r = by_rule.setdefault(e.rule, {"total": 0, "hosts": set()})
        r["total"] += int(e.count or 0)
        if e.host:
            r["hosts"].add(e.host)
    md_lines = [
        "# TinySocs Incident Report",
        "**Severity:** Low",
        f"**TL;DR:** {sum(v['total'] for v in by_rule.values())} event(s) across {len(by_rule)} rule(s) in {window}.",
        "",
        "## Evidence (aggregated)",
    ]
    for rule, d in sorted(by_rule.items()):
        hosts = ", ".join(sorted(d["hosts"])) if d["hosts"] else "(various)"
        md_lines.append(f"- **{rule}**: count={d['total']} hosts={hosts}")
    md = "\n".join(md_lines)
    md = _annotate_header(md, llm_mode=os.getenv("LLM_MODE", "openai"))
    return {"severity": "low", "tldr": f"Aggregated counts over {len(by_rule)} rules.", "markdown": md}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rules", required=True, help="Comma separated rule IDs")
    ap.add_argument("--window", required=True, help="Window, e.g., 15m")
    ap.add_argument("--host", default=None, help="Optional host filter")
    ap.add_argument(
        "--deadline",
        type=float,
        default=float(os.getenv("MASTER_DEADLINE_SEC", "15")),
        help="Overall wall-clock deadline in seconds (default from MASTER_DEADLINE_SEC or 15).",
    )
    args = ap.parse_args()

    if not NODES:
        raise SystemExit("TINYSOCS_NODES is empty; set it to comma-separated node URLs.")

    rules = [r.strip() for r in args.rules.split(",") if r.strip()]
    batches: List[List[DetectionEvidence]] = []
    errors: List[Dict[str, str]] = []

    t0 = time.time()
    for node in NODES:
        # Stop if deadline exhausted
        elapsed = time.time() - t0
        remaining = max(0.0, args.deadline - elapsed)
        if remaining <= 0:
            errors.append({"node": node, "error": "deadline_exhausted"})
            print(f"[master] DEADLINE: skipping {node} (overall deadline hit)")
            break

        # Clamp per-node timeout to remaining budget
        per_node_timeout = min(REQUEST_TIMEOUT_SEC, remaining)

        try:
            evs = fetch_agg(node, rules=rules, window=args.window, host=args.host, timeout=per_node_timeout)
            print(f"[master] {node} -> {len(evs)} evidences")
            batches.append(evs)
        except Exception as e:
            err = f"{type(e).__name__}: {e}"
            errors.append({"node": node, "error": err})
            print(f"[master] WARN: failed to fetch from {node}: {err}")

        # If next loop would certainly exceed deadline, bail early
        if (time.time() - t0) >= args.deadline:
            print("[master] DEADLINE: stopping fan-out loop")
            break

    merged = merge_evidence(batches)
    print(f"[master] merged groups: {len(merged)} (errors={len(errors)})")

    # ---------- Privacy-aware summarizer call ----------
    if _summarize is None:
        print("[master] WARN: summarizer not available; printing merged evidence only.")
        print(json.dumps({"evidence": [e.dict() for e in merged], "errors": errors}, indent=2, ensure_ascii=False))
        return

    incident: Dict[str, Any] | str
    llm_label = f"{os.getenv('LLM_MODE','openai')}"

    try:
        if PRIVACY_MODE == "raw":
            findings = _to_findings(merged)
            try:
                incident = _summarize(findings)
            except TypeError:
                incident = _summarize(findings=findings)  # type: ignore
        else:
            ev_dicts = [(e.model_dump() if hasattr(e, "model_dump") else e.dict()) for e in merged]
            payload = _prepare_privacy_payload(ev_dicts, args.window)

            called = False
            for attempt in (
                lambda: _summarize(payload),
                lambda: _summarize(data=payload),
                lambda: _summarize(findings=payload),
            ):
                try:
                    incident = attempt()
                    called = True
                    break
                except TypeError:
                    continue

            if not called:
                print("[master] WARN: summarizer rejected abstract payload; using local minimal summary.")
                incident = _minimal_local_summary(merged, args.window)

        # Annotate privacy banner if body present
        if isinstance(incident, dict):
            for k in ("markdown", "report", "body"):
                if k in incident and isinstance(incident[k], str):
                    incident[k] = _annotate_header(incident[k], llm_mode=llm_label)
                    break
        elif isinstance(incident, str):
            incident = _annotate_header(incident, llm_mode=llm_label)

    except Exception as e:
        print(f"[master] ERROR: summarizer failed: {e}")
        incident = _minimal_local_summary(merged, args.window)
    # ---------------------------------------------------

    # Compact preview so you see it worked
    sev  = incident.get("severity") if isinstance(incident, dict) else None
    tldr = incident.get("tldr") if isinstance(incident, dict) else None
    preview = {
        "severity": sev,
        "tldr": tldr,
        "items": len(merged),
        "privacy_mode": PRIVACY_MODE,
        "errors": errors,  # surfaced to operator
    }
    print("----- Fleet Incident (preview) -----")
    print(json.dumps(preview, indent=2))


if __name__ == "__main__":
    main()