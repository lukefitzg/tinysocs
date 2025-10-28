# tinysocs/orchestrator/master.py
#!/usr/bin/env python3
"""
TinySOCS Master — fan-out, aggregate, summarize, and anchor.

What this master does (lean + hardened):
- Fans out to Node API /agg for evidence (GET first, then POST as fallback)
- Merges DetectionEvidence and calls your existing summarizer (privacy-aware)
- Anchors one doc per node to OpenSearch alias 'tinysocs_anchors' (anchored_at is a proper date)
- All network calls use retry + jitter (env-tunable) and an overall --deadline

Env knobs (with sensible defaults):
  TINYSOCS_NODES                 Comma-separated node URLs (e.g., http://localhost:8081)
  MASTER_SHARED_SECRET           HMAC shared secret (string)
  REQUEST_TIMEOUT_SEC            Per-call timeout seconds (default 30)
  MASTER_RETRIES                 Total tries per call (default 3)
  MASTER_RETRY_MIN_MS            Min backoff in ms (default 250)
  MASTER_RETRY_MAX_MS            Max backoff in ms (default 750)
  TINYSOCS_INSECURE_SKIP_VERIFY  "1" to skip TLS verify for node calls (default 1 for lab)
  PRIVACY_MODE                   "abstract" (default) | "raw" | "redact" (passed to anchor metadata)

OpenSearch (anchor store):
  SIEM_URL        e.g. https://localhost:9201
  SIEM_USER       e.g. admin
  SIEM_PASS       e.g. ChangeMe123!
  SIEM_SSL_VERIFY "false"/"0" to disable verify; anything else enables

CLI:
  python -m tinysocs.orchestrator.master --rules ps_script_block,auth_failed_burst --window 15m
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import random
import textwrap
import time
import smtplib
from email.message import EmailMessage
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import requests
import yaml  # actions.yaml
from requests.auth import HTTPBasicAuth
# ------------------------------------------------

# ---------------- Path constants ----------------
_HERE = Path(__file__).resolve()
PKG_ROOT = _HERE.parents[1]          # <repo>/tinysocs
REPO_ROOT = _HERE.parents[2]         # <repo>
AGENT_DIR = PKG_ROOT / "agent"
# ------------------------------------------------

# --- best-effort .env loader (no dependency on python-dotenv) ---
def _load_dotenv_inplace():
    # search: repo root (…/tinysocs/..), then current dir
    here = Path(__file__).resolve()
    candidates = [
        here.parents[2] / ".env",  # <repo>/.env
        here.parents[1] / ".env",  # <repo>/tinysocs/.env (fallback)
        Path.cwd() / ".env",
    ]
    for p in candidates:
        if p.is_file():
            for line in p.read_text(encoding="utf-8").splitlines():
                if not line or line.strip().startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k, v = k.strip(), v.strip()
                if k and v and (k not in os.environ):
                    os.environ[k] = v
            break

_load_dotenv_inplace()
# ------------------------------------------------

# ---------------- Env helpers ----------------
def _env_bool(name: str, default: bool = False) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return str(v).strip().lower() in ("1", "true", "yes", "y", "on")

def _tls_verify_from(name: str, default: bool = True) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return str(v).strip().lower() not in ("0", "false", "no", "off")

def _now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

def _derive_node_id(node_url: str) -> str:
    """Best-effort stable id from URL (matches check_ledger expectation: node-<port>)."""
    try:
        p = urlparse(node_url)
        if p.port:
            return f"node-{p.port}"
        host = (p.hostname or "node").split(".")[0]
        return f"node-{host}"
    except Exception:
        return "node-unknown"
# ------------------------------------------------

# ---------------- Config ----------------
NODES: List[str] = [x.strip() for x in os.getenv("TINYSOCS_NODES", "http://localhost:8081").split(",") if x.strip()]
SECRET: str = os.getenv("MASTER_SHARED_SECRET", "dev-secret-change-me")
NODE_TLS_VERIFY: bool = not _env_bool("TINYSOCS_INSECURE_SKIP_VERIFY", True)  # default skip verify (lab)

REQUEST_TIMEOUT_SEC: float = float(os.getenv("REQUEST_TIMEOUT_SEC", "30"))
MASTER_RETRIES: int = int(os.getenv("MASTER_RETRIES", "3"))
MASTER_RETRY_MIN_MS: int = int(os.getenv("MASTER_RETRY_MIN_MS", "250"))
MASTER_RETRY_MAX_MS: int = int(os.getenv("MASTER_RETRY_MAX_MS", "750"))

PRIVACY_MODE: str = os.getenv("PRIVACY_MODE", "abstract")

SIEM_URL: str = os.getenv("SIEM_URL", "https://localhost:9201")
SIEM_USER: str = os.getenv("SIEM_USER", "admin")
SIEM_PASS: str = os.getenv("SIEM_PASS", "admin")
SIEM_VERIFY: bool = _tls_verify_from("SIEM_SSL_VERIFY", default=True)

# silence local TLS warnings if verify is disabled for either SIEM or node calls
try:
    import urllib3  # type: ignore
    if (not SIEM_VERIFY) or (not NODE_TLS_VERIFY):
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass
# ------------------------------------------------

# ---------------- Privacy adapter + summarizer ----------------
try:
    from tinysocs.agent.summarizer_adapter import (
        prepare_payload as _prepare_privacy_payload,
        annotate_report_header as _annotate_header,
        PRIVACY_MODE as _ADAPTER_PRIVACY_MODE,
    )
    if _ADAPTER_PRIVACY_MODE:
        PRIVACY_MODE = (_ADAPTER_PRIVACY_MODE or PRIVACY_MODE).strip().lower()
except Exception as _e:
    def _prepare_privacy_payload(evidences: List[Dict[str, Any]], window: str) -> Dict[str, Any]:
        return {"mode": "raw", "window": window, "evidences": evidences}
    def _annotate_header(md: str, llm_mode: str = "openai") -> str:
        return md
    print(f"[master] WARN: summarizer_adapter not available: {_e}. Using raw fallback.")

try:
    from tinysocs.agent.llm_select import summarize as _summarize
except Exception:
    try:
        from tinysocs.agent.llm_select import summarize_findings as _summarize  # type: ignore
    except Exception as e:
        _summarize = None
        print(f"[master] WARN: could not import summarizer from agent.llm_select: {e}")
# ------------------------------------------------

def _display_privacy_mode() -> str:
    m = (PRIVACY_MODE or "abstract").strip().split()[0].lower()
    return "raw" if m == "raw" else "abstract"

# ---------------- HMAC headers (raw hex) ----------------
def _headers() -> Dict[str, str]:
    ts = str(int(time.time()))
    mac = hmac.new((SECRET or "").encode("utf-8"), ts.encode("utf-8"), hashlib.sha256).hexdigest()  # RAW HEX ONLY
    return {
        "X-TinySOCS-Timestamp": ts,
        "X-TinySOCS-Signature": mac,
        "User-Agent": "tinysocs/master",
    }
# --------------------------------------------------------

# ---------------- Retry + jitter helpers ----------------
def _sleep_jitter(min_ms: int, max_ms: int) -> None:
    ms = random.randint(min_ms, max_ms)
    time.sleep(ms / 1000.0)

def _try_call(fn, *, tries: int, min_ms: int, max_ms: int, label: str):
    last_exc = None
    for attempt in range(1, tries + 1):
        try:
            return fn()
        except Exception as e:
            last_exc = e
            if attempt >= tries:
                break
            _sleep_jitter(min_ms, max_ms)
    raise RuntimeError(f"{label} failed after {tries} tries: {last_exc}")
# --------------------------------------------------------

# ---------------- Node client calls ----------------
def _agg_get(node: str, rules: str, window: str, host: Optional[str]) -> Dict[str, Any]:
    url = node.rstrip("/") + "/agg"
    params = {"rules": rules, "window": window}
    if host:
        params["host"] = host
    r = requests.get(url, headers=_headers(), params=params, timeout=REQUEST_TIMEOUT_SEC, verify=NODE_TLS_VERIFY)
    r.raise_for_status()
    return r.json()

def _agg_post(node: str, rules: str, window: str, host: Optional[str]) -> Dict[str, Any]:
    url = node.rstrip("/") + "/agg"
    body = {"rules": rules, "window": window}
    if host:
        body["host"] = host
    r = requests.post(url, headers=_headers(), json=body, timeout=REQUEST_TIMEOUT_SEC, verify=NODE_TLS_VERIFY)
    r.raise_for_status()
    return r.json()

def _get_head(node: str) -> Dict[str, Any]:
    url = node.rstrip("/") + "/evidence/head"
    r = requests.get(url, headers=_headers(), timeout=REQUEST_TIMEOUT_SEC, verify=NODE_TLS_VERIFY)
    if r.status_code == 501:
        return {"ok": None, "sequence": None, "head_sha256": None, "capability": "no-ledger"}
    r.raise_for_status()
    return r.json()

def _post_json(node_url: str, obj: Dict[str, Any], timeout: float = 6.0) -> None:
    """HMAC-signed POST helper for /evidence/append anchors (raw hex signature)."""
    ts = str(int(time.time()))
    sig = hmac.new((SECRET or "").encode("utf-8"), ts.encode("utf-8"), hashlib.sha256).hexdigest()
    headers = {"X-TinySOCS-Timestamp": ts, "X-TinySOCS-Signature": sig}
    requests.post(
        node_url.rstrip("/") + "/evidence/append",
        headers=headers,
        json=obj,
        timeout=timeout,
        verify=NODE_TLS_VERIFY,
    )
# ----------------------------------------------------

# ---------------- Evidence merge helpers ----------------
try:
    from tinysocs.agent.models.evidence import DetectionEvidence
except Exception:
    class DetectionEvidence(dict):  # very light fallback
        pass

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
        rule = getattr(ev, "rule", None) or ev.get("rule")
        host = getattr(ev, "host", None) or ev.get("host")
        window = getattr(ev, "window", None) or ev.get("window")
        count = getattr(ev, "count", None) or ev.get("count", 0)
        summary = getattr(ev, "summary", None) or ev.get("summary", {})
        exemplars = getattr(ev, "exemplars", None) or ev.get("exemplars", [])

        key = (rule, host)
        if key not in by_key:
            by_key[key] = DetectionEvidence(rule=rule, window=window, host=host, count=count, summary=summary, exemplars=list(exemplars))
        else:
            cur = by_key[key]
            cur["count"] = max(int(cur.get("count", 0)), int(count or 0))
            cur["summary"] = deep_union(cur.get("summary", {}), summary or {})
            if len(cur.get("exemplars", [])) < 10:
                take = 10 - len(cur["exemplars"])
                cur["exemplars"].extend(list(exemplars)[:take])

    return [DetectionEvidence(**dict(v)) if isinstance(v, DetectionEvidence) else v for v in by_key.values()]
# ---------------------------------------------------------

# ---------------- Summarizer helpers ----------------
def _to_findings(ev_list: List[DetectionEvidence]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for ev in ev_list:
        asdict = ev.model_dump() if hasattr(ev, "model_dump") else (ev if isinstance(ev, dict) else ev.__dict__)
        rule = asdict.get("rule")
        window = asdict.get("window")
        host = asdict.get("host")
        count = int(asdict.get("count") or 0)
        summary = asdict.get("summary") or {}
        exemplars = asdict.get("exemplars") or []
        findings.append(
            {
                "rule": rule,
                "summary": f"Fleet aggregate for {rule} in {window}",
                "evidence": {"host": host, "count": count, **summary},
                "sample": exemplars,
            }
        )
    return findings

def _minimal_local_summary(merged: List[DetectionEvidence], window: str) -> Dict[str, Any]:
    by_rule: Dict[str, Dict[str, Any]] = {}
    for e in merged:
        asdict = e.model_dump() if hasattr(e, "model_dump") else (e if isinstance(e, dict) else e.__dict__)
        rule = asdict.get("rule")
        host = asdict.get("host")
        r = by_rule.setdefault(rule, {"total": 0, "hosts": set()})
        r["total"] += int(asdict.get("count", 0))
        if host:
            r["hosts"].add(host)

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
# ----------------------------------------------------

# ---------------- Actions renderer ----------------
def _actions_path() -> Optional[Path]:
    env_p = os.getenv("TINYSOCS_ACTIONS_PATH")
    if env_p:
        p = Path(env_p).expanduser()
        if p.is_file():
            return p
    candidates = [
        AGENT_DIR / "actions.yaml",
        PKG_ROOT / "agent" / "actions.yaml",
        REPO_ROOT / "tinysocs" / "agent" / "actions.yaml",
    ]
    for c in candidates:
        if c.is_file():
            return c
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
            return data if isinstance(data, dict) else {}
    except Exception as e:
        print(f"[master] WARN: failed to load actions.yaml: {e}")
        return {}

def _render_actions_md(merged: List[DetectionEvidence]) -> str:
    actions = _load_actions()
    if not actions:
        return ""
    # normalize every item to dict (avoid Pydantic .get() errors)
    norm: List[Dict[str, Any]] = []
    for e in merged:
        if isinstance(e, dict):
            norm.append(e)
        elif hasattr(e, "model_dump"):
            norm.append(e.model_dump())
        elif hasattr(e, "dict"):
            norm.append(e.dict())
        else:
            norm.append({"rule": getattr(e, "rule", None), "count": getattr(e, "count", 0)})

    fired = [e for e in norm if (e.get("count") or 0) > 0 and e.get("rule") in actions]
    if not fired:
        return ""
    lines: List[str] = ["## Candidate Actions"]
    for ev in sorted(fired, key=lambda x: x.get("rule")):
        items = actions.get(ev.get("rule")) or []
        if not items:
            continue
        lines.append(f"### {ev.get('rule')} (count={int(ev.get('count') or 0)})")
        for it in items:
            label = str(it.get("label") or "Action")
            cmd = str(it.get("cmd") or "").strip()
            lines.append(f"- [ ] {label}: `{cmd}`" if cmd else f"- [ ] {label}")
        lines.append("")
    return "\n".join(lines).strip()
# ----------------------------------------------------

# ---------------- Notifications (opt-in) ----------------
def _privacy_share_body() -> bool:
    mode = os.getenv("PRIVACY_MODE", "abstract").strip().lower()
    allow_raw = os.getenv("ALLOW_NOTIFY_IN_RAW", "0") == "1"
    return mode != "raw" or allow_raw

def notify_slack(preview: Dict[str, Any], incident: Optional[Dict[str, Any]]) -> None:
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
# --------------------------------------------------------

# ---------------- OpenSearch helpers ----------------
def _es_auth() -> HTTPBasicAuth:
    return HTTPBasicAuth(SIEM_USER, SIEM_PASS)

def _es_index(doc: Dict[str, Any]) -> None:
    """Index one doc into the tinysocs_anchors alias (write index should be true)."""
    post_url = urljoin(SIEM_URL.rstrip("/") + "/", "tinysocs_anchors/_doc")
    r = requests.post(post_url, auth=_es_auth(), verify=SIEM_VERIFY, json=doc, timeout=REQUEST_TIMEOUT_SEC)
    r.raise_for_status()
# ----------------------------------------------------

def run_master(rules: str, window: str, host: Optional[str], deadline_sec: float) -> Dict[str, Any]:
    t0 = time.time()
    summary = {
        "rules": rules,
        "window": window,
        "nodes": [],
        "errors": 0,
        "anchored": 0,
        "ts": _now_utc_iso(),
        "privacy_mode": _display_privacy_mode(),
    }

    print(f"[master] fan-out to {','.join(NODES)}; rules={rules}; window={window}")

    for node in NODES:
        # Deadline guard
        if (time.time() - t0) >= deadline_sec:
            print(f"[master] DEADLINE hit — skipping remaining nodes.")
            break

        node_row: Dict[str, Any] = {"node": node, "ok": False}

        # 1) fetch evidence with retry (GET then POST fallback)
        def _fetch():
            try:
                return _agg_get(node, rules, window, host)
            except Exception:
                return _agg_post(node, rules, window, host)

        try:
            agg = _try_call(
                _fetch,
                tries=MASTER_RETRIES,
                min_ms=MASTER_RETRY_MIN_MS,
                max_ms=MASTER_RETRY_MAX_MS,
                label=f"{node} /agg",
            )
            items = int(agg.get("items", 0)) if isinstance(agg, dict) else 0
            node_row.update({"ok": True, "items": items})
            print(f"[master] {node} -> {items} evidences")
        except Exception as e:
            node_row.update({"ok": False, "error": f"agg_failed: {e}"})
            summary["errors"] += 1
            print(f"[master] {node} agg error: {e}")

        # 2) append compact payload to node ledger (tamper trail) FIRST, then read head
        try:
            _try_call(
                lambda: _post_json(node, {"payload": {"rules": rules, "window": window, "items": int(node_row.get("items", 0)), "privacy_mode": _display_privacy_mode()}}),
                tries=MASTER_RETRIES,
                min_ms=MASTER_RETRY_MIN_MS,
                max_ms=MASTER_RETRY_MAX_MS,
                label=f"{node} /evidence/append",
            )
        except Exception as _e:
            # best-effort; we still proceed to read whatever head exists
            node_row["append_warn"] = f"append_failed: {_e}"

        # 3) read current head with retry (should now reflect the append)
        try:
            head = _try_call(
                lambda: _get_head(node),
                tries=MASTER_RETRIES,
                min_ms=MASTER_RETRY_MIN_MS,
                max_ms=MASTER_RETRY_MAX_MS,
                label=f"{node} /evidence/head",
            )
        except Exception as e:
            node_row.update({"head_error": f"head_failed: {e}"})
            summary["errors"] += 1
            summary["nodes"].append(node_row)
            print(f"[master] {node} head error: {e}")
            continue

        # 4) anchor to OpenSearch (alias) with the CURRENT head
        anchor_doc = {
            "node": node,  # <— legacy compatibility (verify script may filter on 'node')
            "node_url": node,
            "node_id": head.get("node_id") or os.getenv("NODE_ID") or _derive_node_id(node),
            "ok": bool(head.get("ok", True)),
            "sequence": head.get("sequence"),
            "head_sha256": head.get("head_sha256"),
            "capability": head.get("capability", "ledger"),
            "anchored_at": _now_utc_iso(),
            "run": {
                "rules": rules,
                "window": window,
                "items": int(node_row.get("items", 0)),
                "privacy_mode": _display_privacy_mode(),
            },
        }
        try:
            _try_call(
                lambda: _es_index(anchor_doc),
                tries=MASTER_RETRIES,
                min_ms=MASTER_RETRY_MIN_MS,
                max_ms=MASTER_RETRY_MAX_MS,
                label=f"{node} anchor_index",
            )
            summary["anchored"] += 1
            print(f"[master] anchored {node} @ {anchor_doc['anchored_at']} (seq={anchor_doc.get('sequence')})")
        except Exception as e:
            node_row.update({"anchor_error": f"anchor_failed: {e}"})
            summary["errors"] += 1
            print(f"[master] {node} anchor error: {e}")

        summary["nodes"].append(node_row)

    # ---------- Summarize ----------
    # Minimal synthetic merged for preview (items per node grouped under a pseudo-rule "fleet_total")
    pseudo = DetectionEvidence(rule="fleet_total", window=window, host=None, count=sum(int(n.get("items", 0)) for n in summary["nodes"]), summary={}, exemplars=[])
    merged = [pseudo]

    if _summarize is None:
        incident = _minimal_local_summary(merged, window)
    else:
        try:
            if PRIVACY_MODE == "raw":
                findings = _to_findings(merged)
                try:
                    incident = _summarize(findings)
                except TypeError:
                    incident = _summarize(findings=findings)  # type: ignore
            else:
                payload = _prepare_privacy_payload(
                    [m.model_dump() if hasattr(m, "model_dump") else (m if isinstance(m, dict) else m.__dict__) for m in merged],
                    window
                )
                called = False
                for attempt in (lambda: _summarize(payload),
                                lambda: _summarize(data=payload),
                                lambda: _summarize(findings=payload)):
                    try:
                        incident = attempt()
                        called = True
                        break
                    except TypeError:
                        continue
                if not called:
                    incident = _minimal_local_summary(merged, window)
        except Exception as e:
            print(f"[master] ERROR: summarizer failed: {e}")
            incident = _minimal_local_summary(merged, window)

    # Append candidate actions (if any)
    try:
        actions_md = _render_actions_md(merged)
        if actions_md:
            if isinstance(incident, dict):
                for k in ("markdown", "report", "body"):
                    if k in incident and isinstance(incident[k], str):
                        incident[k] = incident[k].rstrip() + "\n\n" + actions_md + "\n"
                        break
                else:
                    incident["actions_markdown"] = actions_md
            elif isinstance(incident, str):
                incident = incident.rstrip() + "\n\n" + actions_md + "\n"
    except Exception as e:
        print(f"[master] WARN: failed to render actions: {e}")

    sev = incident.get("severity") if isinstance(incident, dict) else None
    tldr = incident.get("tldr") if isinstance(incident, dict) else None
    preview = {
        "severity": sev,
        "tldr": tldr,
        "items": sum(int(n.get("items", 0)) for n in summary["nodes"]),
        "privacy_mode": _display_privacy_mode(),
        "anchored": summary["anchored"],
        "errors": summary["errors"],
    }
    print("----- Fleet Incident (preview) -----")
    print(json.dumps(preview, indent=2, default=str))

    # Notifications (opt-in)
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

    return summary

def main() -> None:
    ap = argparse.ArgumentParser(description="TinySOCS Master (fan-out + summarize + anchor)")
    ap.add_argument("--rules", type=str, required=True, help="Comma separated rule IDs")
    ap.add_argument("--window", type=str, required=True, help="Window, e.g., 15m")
    ap.add_argument("--host", type=str, default=None, help="Optional host filter")
    ap.add_argument(
        "--deadline",
        type=float,
        default=float(os.getenv("MASTER_DEADLINE_SEC", "30")),
        help="Overall wall-clock deadline in seconds (default from MASTER_DEADLINE_SEC or 30).",
    )
    args = ap.parse_args()

    if not NODES:
        raise SystemExit("TINYSOCS_NODES is empty; set it to comma-separated node URLs.")

    run_master(args.rules, args.window, args.host, args.deadline)

if __name__ == "__main__":
    main()