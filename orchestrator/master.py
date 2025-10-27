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

Tamper-evidence (Phase 3.5):
- After each run, post a compact anchor payload to each node: POST /evidence/append

Operator polish:
- Append "## Candidate Actions" (from agent/actions.yaml) to the incident markdown.

Notifications (Phase 3.6):
- Optional Slack / Google Chat / Email preview notifications via env flags.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import textwrap
import time
import smtplib
from email.message import EmailMessage
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests
import yaml  # actions.yaml
import uvicorn
from pydantic import BaseModel, Field
from fastapi import FastAPI, Request, HTTPException
from fastapi.encoders import jsonable_encoder
from requests.auth import HTTPBasicAuth
from datetime import datetime, timezone

# --- path bootstrap so script runs from either C:\tinysocs or C:\tinysocs\tinysocs ---
import sys

_HERE = Path(__file__).resolve()
_PKG_ROOT = _HERE.parents[1]   # .../tinysocs
_REPO_ROOT = _HERE.parents[2]  # repo root containing /tinysocs
APP = FastAPI(title="TinySOCS Node API - Ledger")
LEDGER_DIR = Path(os.getenv("TINYSOCS_LEDGER_DIR", "ledger"))
LEDGER_DIR.mkdir(parents=True, exist_ok=True)
HEAD_FILE = LEDGER_DIR / "head.json"
SECRET = os.getenv("MASTER_SHARED_SECRET", "dev-secret-change-me")
SKEW_SECS = int(os.getenv("TINYSOCS_SKEW_SECS", "300"))
REPLAY_CACHE = set()

# Let 'import tinysocs.*' work (repo root) and 'import agent.*' work (package dir)
for p in (str(_REPO_ROOT), str(_PKG_ROOT)):
    if p not in sys.path:
        sys.path.insert(0, p)

# Try package-style first, then package-internal
try:
    from tinysocs.agent.models.evidence import DetectionEvidence
except ModuleNotFoundError:
    from agent.models.evidence import DetectionEvidence  # type: ignore

# ---------------- Path constants (no sys.path surgery) ----------------
PKG_ROOT = Path(__file__).resolve().parents[1]   # <repo>/tinysocs
REPO_ROOT = Path(__file__).resolve().parents[2]  # <repo>
AGENT_DIR = PKG_ROOT / "agent"
# ---------------------------------------------------------------------

# Privacy adapter (new)
# We want PRIVACY_MODE available regardless of import success.
PRIVACY_MODE = os.getenv("PRIVACY_MODE", "abstract").strip().lower()

try:
    from tinysocs.agent.summarizer_adapter import (
        prepare_payload as _prepare_privacy_payload,
        annotate_report_header as _annotate_header,
        PRIVACY_MODE as _ADAPTER_PRIVACY_MODE,
    )
    # If adapter provides a value, prefer it.
    if _ADAPTER_PRIVACY_MODE:
        PRIVACY_MODE = (_ADAPTER_PRIVACY_MODE or PRIVACY_MODE).strip().lower()
except Exception as _e:
    # Fallback if file not present yet
    def _prepare_privacy_payload(evidences: List[Dict[str, Any]], window: str) -> Dict[str, Any]:
        return {"mode": "raw", "window": window, "evidences": evidences}

    def _annotate_header(md: str, llm_mode: str = "openai") -> str:
        return md

    print(f"[master] WARN: summarizer_adapter not available: {_e}. Using raw fallback.")
    # In fallback we keep PRIVACY_MODE from env (default abstract), but the payload we prepare is raw-ish.

# Resilient summarizer import (support either summarize or summarize_findings)
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


def _display_privacy_mode() -> str:
    """
    Normalize PRIVACY_MODE for operator preview. Only 'raw' or 'abstract'.
    """
    m = (PRIVACY_MODE or "abstract").strip().split()[0].lower()
    return "raw" if m == "raw" else "abstract"


def _sign(ts: int) -> str:
    mac = hmac.new((SECRET or "").encode("utf-8"), str(ts).encode("utf-8"), hashlib.sha256).hexdigest()
    return f"sha256={mac}"


def _headers() -> Dict[str, str]:
    ts = int(time.time())
    return {"X-TinySOCS-Timestamp": str(ts), "X-TinySOCS-Signature": _sign(ts)}


def _post_json(url: str, secret: str, obj: Dict[str, Any], timeout: float = 5.0) -> None:
    """HMAC-signed POST helper (used for /evidence/append anchors)."""
    ts = int(time.time())
    sig = hmac.new((secret or "").encode("utf-8"), str(ts).encode("utf-8"), hashlib.sha256).hexdigest()

    # IMPORTANT: bare hex digest (no "sha256=" prefix) to match node_api.py
    headers = {
        "X-TinySOCS-Timestamp": str(ts),
        "X-TinySOCS-Signature": sig,
    }

    requests.post(
        url,
        headers=headers,
        json=obj,
        timeout=timeout,
        verify=False if os.getenv("TINYSOCS_INSECURE_SKIP_VERIFY", "1") == "1" else True,
    )


def fetch_agg(node_url: str, rules: List[str], window: str, host: Optional[str], timeout: float) -> List[DetectionEvidence]:
    params = {"rules": ",".join(rules), "window": window}
    if host:
        params["host"] = host
    r = requests.get(
        f"{node_url.rstrip('/')}/agg",
        headers=_headers(),
        params=params,
        timeout=timeout,
        verify=False if os.getenv("TINYSOCS_INSECURE_SKIP_VERIFY", "1") == "1" else True,
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
                        key = json.dumps(item, sort_keys=True, ensure_ascii=False, default=str) if isinstance(item, (dict, list)) else item
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
    """Convert DetectionEvidence -> summarizer 'findings' shape (legacy/raw path)."""
    findings: List[Dict[str, Any]] = []
    for ev in ev_list:
        f: Dict[str, Any] = {
            "rule": ev.rule,
            "summary": f"Fleet aggregate for {ev.rule} in {ev.window}",
            "evidence": {"host": ev.host, "count": ev.count, **(ev.summary or {})},
        }
        if ev.exemplars:
            # pydantic v1/v2 compat
            ex_list = [ex.model_dump() if hasattr(ex, "model_dump") else ex.dict() for ex in ev.exemplars]
            f["sample"] = ex_list
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
        "*Severity:* Low",
        f"*TL;DR:* {sum(v['total'] for v in by_rule.values())} event(s) across {len(by_rule)} rule(s) in {window}.",
        "",
        "## Evidence (aggregated)",
    ]
    for rule, d in sorted(by_rule.items()):
        hosts = ", ".join(sorted(d["hosts"])) if d["hosts"] else "(various)"
        md_lines.append(f"- *{rule}*: count={d['total']} hosts={hosts}")
    md = "\n".join(md_lines)
    md = _annotate_header(md, llm_mode=os.getenv("LLM_MODE", "openai"))
    return {"severity": "low", "tldr": f"Aggregated counts over {len(by_rule)} rules.", "markdown": md}


# -------- Actions renderer (from agent/actions.yaml) --------
def _actions_path() -> Optional[Path]:
    # Allow override
    env_p = os.getenv("TINYSOCS_ACTIONS_PATH")
    if env_p:
        p = Path(env_p).expanduser()
        if p.is_file():
            return p
    # Typical locations
    candidates = [
        AGENT_DIR / "actions.yaml",
        PKG_ROOT / "agent" / "actions.yaml",
        REPO_ROOT / "tinysocs" / "agent" / "actions.yaml",
    ]
    for c in candidates:
        if c.is_file():
            return c
    # Fallback: search
    for p in REPO_ROOT.rglob("actions.yaml"):
        if "agent" in p.as_posix().lower():
            return p
    return None


def _load_actions() -> Dict[str, List[Dict[str, str]]]:
    path = _actions_path()
    if not path:
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
            # Expect mapping: rule_id -> list[{label, cmd}]
            if isinstance(data, dict):
                return data
            return {}
    except Exception as e:
        print(f"[master] WARN: failed to load actions.yaml: {e}")
        return {}


def _render_actions_md(merged: List[DetectionEvidence]) -> str:
    actions = _load_actions()
    if not actions:
        return ""
    # Pick rules that actually fired (count > 0)
    fired = [e for e in merged if (e.count or 0) > 0 and e.rule in actions]
    if not fired:
        return ""

    lines: List[str] = []
    lines.append("## Candidate Actions")
    for ev in sorted(fired, key=lambda x: x.rule):
        items = actions.get(ev.rule) or []
        if not items:
            continue
        lines.append(f"### {ev.rule} (count={int(ev.count or 0)})")
        for it in items:
            label = str(it.get("label") or "Action")
            cmd = str(it.get("cmd") or "").strip()
            if cmd:
                lines.append(f"- [ ] {label}: `{cmd}`")
            else:
                lines.append(f"- [ ] {label}")
        lines.append("")  # spacer between rules

    return "\n".join(lines).strip()
# ------------------------------------------------------------

# --------------------- Notifications (opt-in) ---------------------
def _privacy_share_body() -> bool:
    """Return True if we are allowed to include full report text in a notification."""
    mode = os.getenv("PRIVACY_MODE", "abstract").strip().lower()
    allow_raw = os.getenv("ALLOW_NOTIFY_IN_RAW", "0") == "1"
    return mode != "raw" or allow_raw


def notify_slack(preview: Dict[str, Any], incident: Optional[Dict[str, Any]]) -> None:
    """Send a compact Slack message via Incoming Webhook URL (SLACK_WEBHOOK_URL)."""
    url = os.getenv("SLACK_WEBHOOK_URL")
    if not url:
        return
    sev = preview.get("severity") or "unknown"
    tldr = preview.get("tldr") or "(no TL;DR)"
    items = preview.get("items", 0)
    text = f"TinySocs: {sev} · {items} item(s)\n- {tldr}"

    if incident and _privacy_share_body():
        more = incident.get("markdown") or incident.get("report") or incident.get("body")
        if more:
            text = text + "\n\n" + textwrap.shorten(more, width=3000, placeholder=" ...")
    try:
        requests.post(url, json={"text": text}, timeout=4)
    except Exception as e:
        print(f"[master] WARN: slack notify failed: {e}")


def notify_gchat(preview: Dict[str, Any], incident: Optional[Dict[str, Any]]) -> None:
    """Send a compact Google Chat message via webhook (GCHAT_WEBHOOK_URL)."""
    url = os.getenv("GCHAT_WEBHOOK_URL")
    if not url:
        return
    sev = preview.get("severity") or "unknown"
    tldr = preview.get("tldr") or "(no TL;DR)"
    items = preview.get("items", 0)
    text = f"TinySocs: {sev} · {items} item(s)\n- {tldr}"

    if incident and _privacy_share_body():
        more = incident.get("markdown") or incident.get("report") or incident.get("body")
        if more:
            text = text + "\n\n" + textwrap.shorten(more, width=3000, placeholder=" ...")
    try:
        requests.post(url, json={"text": text}, timeout=4)
    except Exception as e:
        print(f"[master] WARN: gchat notify failed: {e}")


def notify_email(preview: Dict[str, Any], incident: Optional[Dict[str, Any]]) -> None:
    """Send a basic email using SMTP_* envs."""
    to_addr = os.getenv("NOTIFY_EMAIL_TO")
    host = os.getenv("SMTP_HOST")
    if not to_addr or not host:
        return
    port = int(os.getenv("SMTP_PORT", "25"))
    use_tls = os.getenv("SMTP_STARTTLS", "0") == "1"
    user = os.getenv("SMTP_USER")
    pwd = os.getenv("SMTP_PASS")

    sev = preview.get("severity") or "unknown"
    tldr = preview.get("tldr") or "(no TL;DR)"
    items = preview.get("items", 0)
    subject = f"[TinySocs] {sev} · {items} items"
    body = f"{tldr}\n\n{json.dumps(preview, indent=2, default=str)}"

    if incident and _privacy_share_body():
        more = incident.get("markdown") or incident.get("report") or incident.get("body")
        if more:
            body += "\n\n" + more

    msg = EmailMessage()
    msg["From"] = os.getenv("SMTP_FROM", "tinysocs@localhost")
    msg["To"] = to_addr
    msg["Subject"] = subject
    msg.set_content(body)

    try:
        with smtplib.SMTP(host, port, timeout=6) as s:
            if use_tls:
                s.starttls()
            if user and pwd:
                s.login(user, pwd)
            s.send_message(msg)
    except Exception as e:
        print(f"[master] WARN: email notify failed: {e}")
# ---------------------------------------------------------------

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
    with open(HEAD_FILE, "r", encoding="utf-8") as f:
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

# --- Phase 4: Anchor heads to OpenSearch ---
from requests.auth import HTTPBasicAuth
from datetime import datetime, timezone

def _es_auth() -> HTTPBasicAuth:
    return HTTPBasicAuth(os.getenv("SIEM_USER", "admin"), os.getenv("SIEM_PASS", "admin"))

def _es_verify() -> bool:
    return str(os.getenv("SIEM_SSL_VERIFY", "true")).strip().lower() in ("1","true","yes","on")

def _ensure_anchors_index() -> None:
    base = os.getenv("SIEM_URL", "https://127.0.0.1:9201").rstrip("/")
    idx  = "tinysocs_anchors"
    try:
        # HEAD index; create if missing
        r = requests.head(f"{base}/{idx}", auth=_es_auth(), verify=_es_verify(), timeout=6)
        if r.status_code == 200:
            return
        # create with minimal mapping
        mapping = {
            "settings": {"index": {"number_of_shards": 1, "number_of_replicas": 0}},
            "mappings": {
                "properties": {
                    "node_url":    {"type": "keyword"},
                    "node_id":     {"type": "keyword"},
                    "head_sha256": {"type": "keyword"},
                    "sequence":    {"type": "long"},
                    "ok":          {"type": "boolean"},
                    "capability":  {"type": "keyword"},
                    "anchored_at": {"type": "date"}
                }
            }
        }
        cr = requests.put(f"{base}/{idx}", auth=_es_auth(), verify=_es_verify(), json=mapping, timeout=8)
        cr.raise_for_status()
    except Exception as e:
        print(f"[master] WARN: ensure anchors index failed: {e}")

def anchor_all_nodes_after_run(rules: list[str] | str, window: str, items: int, privacy_mode: str) -> None:
    """Fetch each node's head and index a compact anchor doc into OpenSearch."""
    _ensure_anchors_index()
    base = os.getenv("SIEM_URL", "https://127.0.0.1:9201").rstrip("/")
    idx  = "tinysocs_anchors"
    ts   = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Normalize rules to a short string for display
    if isinstance(rules, str):
        rules_str = rules
    else:
        rules_str = ",".join(rules)

    for node in NODES:
        try:
            # read node head
            r = requests.get(
                f"{node.rstrip('/')}/evidence/head",
                headers=_headers(),
                timeout=10,
                verify=False if os.getenv("TINYSOCS_INSECURE_SKIP_VERIFY", "1") == "1" else True,
            )
            if r.status_code == 501:
                head = {"ok": False, "sequence": None, "head_sha256": None, "capability": "no-ledger"}
            else:
                r.raise_for_status()
                head = r.json()
            doc = {
                "node_url": node,
                "node_id":  head.get("node_id") or os.getenv("NODE_ID", None),
                "ok":       bool(head.get("ok")),
                "sequence": head.get("sequence"),
                "head_sha256": head.get("head_sha256"),
                "capability": head.get("capability") or "ledger",
                "anchored_at": ts,
                # context (optional)
                "run": {"rules": rules_str, "window": window, "items": items, "privacy_mode": privacy_mode},
            }
            # index anchor
            ir = requests.post(f"{base}/{idx}/_doc", auth=_es_auth(), verify=_es_verify(), json=doc, timeout=10)
            ir.raise_for_status()
        except Exception as e:
            print(f"[master] WARN: anchoring node {node} failed: {e}")

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
        # pydantic v1/v2 compat
        ev_dump = [(e.model_dump() if hasattr(e, "model_dump") else e.dict()) for e in merged]
        print(json.dumps({"evidence": ev_dump, "errors": errors}, indent=2, ensure_ascii=False, default=str))
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
            # Pydantic v1/v2 compatibility
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

    # ---------- Append Candidate Actions ----------
    try:
        actions_md = _render_actions_md(merged)
        if actions_md:
            if isinstance(incident, dict):
                for k in ("markdown", "report", "body"):
                    if k in incident and isinstance(incident[k], str):
                        incident[k] = incident[k].rstrip() + "\n\n" + actions_md + "\n"
                        break
                else:
                    # no known body key; attach as 'actions_markdown'
                    incident["actions_markdown"] = actions_md
            elif isinstance(incident, str):
                incident = incident.rstrip() + "\n\n" + actions_md + "\n"
    except Exception as e:
        print(f"[master] WARN: failed to render actions: {e}")
    # ---------------------------------------------------

    # ---------- Post-run anchors to nodes (tamper-evidence) ----------
    try:
        anchor_payload = {
            "rules": rules,
            "window": args.window,
            "items": len(merged),
            "privacy_mode": PRIVACY_MODE,
            "errors": [{"node": x.get("node"), "error": "…"} for x in errors] if errors else [],
        }
        for node in NODES:
            _post_json(f"{node.rstrip('/')}/evidence/append", SECRET, {"payload": anchor_payload})
    except Exception as _e:
        print(f"[master] WARN: failed to anchor evidence: {_e}")
    # -----------------------------------------------------------------

    # Compact preview so you see it worked
    sev = incident.get("severity") if isinstance(incident, dict) else None
    tldr = incident.get("tldr") if isinstance(incident, dict) else None
    preview = {
        "severity": sev,
        "tldr": tldr,
        "items": len(merged),
        "privacy_mode": _display_privacy_mode(),
        "errors": errors,  # surfaced to operator
    }
    print("----- Fleet Incident (preview) -----")
    print(json.dumps(preview, indent=2, default=str))

    # ---------- Notifications (opt-in) ----------
    try:
        inc_obj = incident if isinstance(incident, dict) else None
        if os.getenv("NOTIFY_SLACK", "0") == "1":
            notify_slack(preview, inc_obj)
        if os.getenv("NOTIFY_GCHAT", "0") == "1":
            notify_gchat(preview, inc_obj)
        if os.getenv("NOTIFY_EMAIL", "0") == "1":
            notify_email(preview, inc_obj)
    except Exception as e:
        print(f"[master] WARN: notifications failed: {e}")
    # -------------------------------------------

    try:
        anchor_all_nodes_after_run(rules=args.rules, window=args.window, items=len(merged), privacy_mode=_display_privacy_mode())
    except Exception as e:
        print(f"[master] WARN: failed anchoring to OpenSearch: {e}")

if __name__ == "__main__":
    main()
