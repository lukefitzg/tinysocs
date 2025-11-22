# tinysocs/orchestrator/master.py
#!/usr/bin/env python3
"""
TinySOCS Master — fan-out, aggregate, summarize, and anchor.

What this master does (lean + hardened):
- Fans out to Node API /agg for evidence (GET first, then POST as fallback)
- Merges DetectionEvidence and calls your existing summarizer (privacy-aware)
- Anchors one doc per node to OpenSearch alias 'tinysocs_anchors' (anchored_at is a proper date)
- All network calls use retry + jitter (env-tunable) and an overall --deadline
- NEW in Phase 5: concurrent fan-out so one slow/bad node never blocks others
- NEW in Phase 5: optional pre-flight ensure of the anchors alias/mapping

Env knobs (with sensible defaults):
  TINYSOCS_NODES                 Comma-separated node URLs (e.g., http://localhost:8081)
  MASTER_SHARED_SECRET           HMAC shared secret (string)
  NODE_SECRET                    Optional; if set, preferred over MASTER_SHARED_SECRET
  REQUEST_TIMEOUT_SEC            Per-call timeout seconds (default 30)
  MASTER_RETRIES                 Total tries per call (default 3)
  MASTER_RETRY_MIN_MS            Min backoff in ms (default 250)
  MASTER_RETRY_MAX_MS            Max backoff in ms (default 750)
  MASTER_DEADLINE_SEC            Overall deadline seconds (default 30 if not provided via --deadline)
  TINYSOCS_INSECURE_SKIP_VERIFY  "1" to skip TLS verify for node calls (default 1 for lab)
  PRIVACY_MODE                   "abstract" (default) | "raw" | "redact" (passed to anchor metadata)
  ENSURE_ANCHORS                 "1" (default) to pre-flight create alias/mapping if missing
  FANOUT_WAIT_ALL                "1" to wait for all nodes (until deadline) instead of returning after first result
  HIDE_ZERO_RULES                "1" (default) to suppress zero-count rules in TL;DR headline
  TINYSOCS_SIG_PREFIX            "1"/"true"/"sha256" => use "sha256=<hex>" signature header

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
import asyncio
import hashlib
import hmac
import json
import os
import random
import secrets
import smtplib
import textwrap
import time
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import httpx
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

# --- Evidence class shim (import or fallback) ---
try:
    from tinysocs.agent.models.evidence import DetectionEvidence  # type: ignore
except Exception:
    class DetectionEvidence(dict):  # type: ignore
        __slots__ = ()
        def model_dump(self):
            return dict(self)

# --- centralized .env loader (replaces ad-hoc loader) ---
from pathlib import Path

from tinysocs.env import load_dotenv_if_present

load_dotenv_if_present(Path(__file__).resolve().parents[1])
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

def _load_secret() -> str:
    """
    Decide which secret to use for HMAC and log which source won.

    Precedence:
      1) NODE_SECRET            (if present; useful when secrets rotated symmetrically)
      2) MASTER_SHARED_SECRET   (typical master-side var)
      3) dev-secret-change-me   (lab fallback only)
    """
    node_secret = os.getenv("NODE_SECRET")
    master_secret = os.getenv("MASTER_SHARED_SECRET")

    if node_secret:
        sha = hashlib.sha256(node_secret.encode("utf-8")).hexdigest()
        print(f"[master] using NODE_SECRET; secret_sha256={sha}")
        return node_secret

    if master_secret:
        sha = hashlib.sha256(master_secret.encode("utf-8")).hexdigest()
        print(f"[master] using MASTER_SHARED_SECRET; secret_sha256={sha}")
        return master_secret

    dev = "dev-secret-change-me"
    sha = hashlib.sha256(dev.encode("utf-8")).hexdigest()
    print(
        f"[master] WARNING: no NODE_SECRET/MASTER_SHARED_SECRET; "
        f"falling back to dev-secret-change-me; secret_sha256={sha}"
    )
    return dev


NODES: List[str] = [x.strip() for x in os.getenv("TINYSOCS_NODES", "http://localhost:8081").split(",") if x.strip()]
SECRET: str = _load_secret()
NODE_TLS_VERIFY: bool = not _env_bool("TINYSOCS_INSECURE_SKIP_VERIFY", True)  # default skip verify (lab)

REQUEST_TIMEOUT_SEC: float = float(os.getenv("REQUEST_TIMEOUT_SEC", "30"))
MASTER_RETRIES: int = int(os.getenv("MASTER_RETRIES", "3"))
MASTER_RETRY_MIN_MS: int = int(os.getenv("MASTER_RETRY_MIN_MS", "250"))
MASTER_RETRY_MAX_MS: int = int(os.getenv("MASTER_RETRY_MAX_MS", "750"))

PRIVACY_MODE: str = os.getenv("PRIVACY_MODE", "abstract")
FANOUT_WAIT_ALL: bool = _env_bool("FANOUT_WAIT_ALL", False)
HIDE_ZERO_RULES: bool = _env_bool("HIDE_ZERO_RULES", True)

SIEM_URL: str = os.getenv("SIEM_URL", "https://localhost:9201")
SIEM_USER: str = os.getenv("SIEM_USER", "admin")
SIEM_PASS: str = os.getenv("SIEM_PASS", "admin")
SIEM_VERIFY: bool = _tls_verify_from("SIEM_SSL_VERIFY", default=True)

# Optional ensure-anchors pre-flight (import lazily)
try:
    from .anchors import ensure_anchors_if_missing as _ensure_anchors
except Exception:
    _ensure_anchors = None  # fallback; Start-TinySocs-Quick also ensures

# silence local TLS warnings if verify is disabled
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
        PRIVACY_MODE as _ADAPTER_PRIVACY_MODE,
    )
    from tinysocs.agent.summarizer_adapter import (
        annotate_report_header as _annotate_header,
    )
    from tinysocs.agent.summarizer_adapter import (
        prepare_payload as _prepare_privacy_payload,
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

# ---------------- HMAC headers (ts-only; raw hex or "sha256=<hex>") ----------------
def _headers() -> Dict[str, str]:
    """
    Generate TinySOCS HMAC headers.

    Canonical scheme (must match node):
      MAC = HMAC_SHA256(secret, ts_str)

    - X-TinySOCS-Timestamp: "<unix_ts>"
    - X-TinySOCS-Signature: "<hex>" or "sha256=<hex>"

    The node accepts both raw hex and "sha256=<hex>" forms.
    """
    ts = str(int(time.time()))
    secret = SECRET or ""

    mac_hex = hmac.new(
        secret.encode("utf-8"),
        ts.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()

    # Optional prefix for backwards/interop: "sha256=<hex>"
    use_prefix = str(os.getenv("TINYSOCS_SIG_PREFIX", "0")).strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
        "sha256",
    )
    sig_value = f"sha256={mac_hex}" if use_prefix else mac_hex

    return {
        "X-TinySOCS-Timestamp": ts,
        "X-TinySOCS-Signature": sig_value,
        "User-Agent": "tinysocs/master",
    }

# ---------------- Retry + jitter helpers ----------------
def _sleep_jitter(min_ms: int, max_ms: int) -> None:
    ms = random.randint(min_ms, max_ms)
    time.sleep(ms / 1000.0)

async def _async_sleep_jitter(min_ms: int, max_ms: int) -> None:
    ms = random.randint(min_ms, max_ms)
    await asyncio.sleep(ms / 1000.0)

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

# ---------------- Node client calls (sync) ----------------
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

# ---------------- Node client calls (sync) ----------------
def _post_json(node_url: str, obj: Dict[str, Any], timeout: float = 6.0) -> None:
    """
    Best-effort POST (uses same HMAC headers as /agg and /evidence/head).
    """
    requests.post(
        node_url.rstrip("/") + "/evidence/append",
        headers=_headers(),
        json=obj,
        timeout=timeout,
        verify=NODE_TLS_VERIFY,
    )
# ----------------------------------------------------

# ---------------- Async fan-out helpers (Phase 5) ----------------
async def _fetch_node_agg_async(client: httpx.AsyncClient, node_url: str, rules: str, window: str, host: Optional[str], per_timeout: float) -> Dict[str, Any]:
    last_exc: Optional[Exception] = None
    params = {"rules": rules, "window": window}
    if host:
        params["host"] = host
    for attempt in range(1, MASTER_RETRIES + 1):
        try:
            r = await client.get(f"{node_url.rstrip('/')}/agg", headers=_headers(), params=params, timeout=per_timeout)
            r.raise_for_status()
            return {"node": node_url, "ok": True, "data": r.json()}
        except Exception as e1:
            last_exc = e1
            try:
                r = await client.post(f"{node_url.rstrip('/')}/agg", headers=_headers(), json=params, timeout=per_timeout)
                r.raise_for_status()
                return {"node": node_url, "ok": True, "data": r.json()}
            except Exception as e2:
                last_exc = e2
                if attempt >= MASTER_RETRIES:
                    break
                await _async_sleep_jitter(MASTER_RETRY_MIN_MS, MASTER_RETRY_MAX_MS)
    return {"node": node_url, "ok": False, "error": f"{type(last_exc).__name__}: {last_exc}" if last_exc else "unknown"}

async def _fanout_agg_async(nodes: List[str], rules: str, window: str, host: Optional[str], deadline_sec: float) -> List[Dict[str, Any]]:
    """
    Fire all node requests concurrently.

    If FANOUT_WAIT_ALL=1: wait for all nodes to return or the deadline to hit.
    If FANOUT_WAIT_ALL=0: short-circuit only after the FIRST SUCCESS arrives;
                          errors alone won't cancel the remaining tasks.
    """
    start = time.monotonic()
    results: List[Dict[str, Any]] = []

    async with httpx.AsyncClient(verify=NODE_TLS_VERIFY, follow_redirects=True) as client:
        tasks: Dict[asyncio.Task, str] = {}
        for n in nodes:
            remaining = max(0.2, deadline_sec - (time.monotonic() - start))
            per_timeout = min(REQUEST_TIMEOUT_SEC, remaining)
            t = asyncio.create_task(_fetch_node_agg_async(client, n, rules, window, host, per_timeout))
            tasks[t] = n

        while tasks:
            remaining = max(0.0, deadline_sec - (time.monotonic() - start))
            if remaining <= 0:
                break

            done, pending = await asyncio.wait(
                tasks.keys(),
                timeout=remaining,
                return_when=asyncio.FIRST_COMPLETED
            )

            for d in done:
                node_name = tasks.get(d, "unknown")
                try:
                    results.append(d.result())
                except Exception as e:
                    results.append({"node": node_name, "ok": False, "error": f"task_error: {e}"})
                finally:
                    tasks.pop(d, None)

            # Short-circuit only if NOT waiting for all AND at least one success has arrived
            if not FANOUT_WAIT_ALL and tasks:
                if any((isinstance(r, dict) and r.get("ok") is True) for r in results):
                    for p, n in list(tasks.items()):
                        p.cancel()
                        results.append({"node": n, "ok": False, "error": "deadline"})
                    tasks.clear()

        # Deadline elapsed or loop ended with pending tasks — cancel & mark as deadline
        if tasks:
            for p, n in list(tasks.items()):
                p.cancel()
                results.append({"node": n, "ok": False, "error": "deadline"})
            tasks.clear()

    results_ok  = [r for r in results if r.get("ok")]
    results_bad = [r for r in results if not r.get("ok")]
    return results_ok + results_bad

def merge_evidence(batches: List[List[DetectionEvidence]]) -> List[DetectionEvidence]:
    def deep_union(a: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, Any]:
        out: Dict[str, Any] = dict(a)
        for k, v in (b or {}).items():
            if k not in out:
                out[k] = v
            else:
                av = out[k]
                if isinstance(av, list) and isinstance(v, list):
                    seen = set()
                    merged_list = []
                    for item in av + v:
                        key = json.dumps(item, sort_keys=True, ensure_ascii=False, default=str) if isinstance(item, (dict, list)) else item
                        if key not in seen:
                            seen.add(key)
                            merged_list.append(item)
                    out[k] = merged_list
                elif isinstance(av, dict) and isinstance(v, dict):
                    out[k] = deep_union(av, v)
                else:
                    out[k] = v
        return out

    def as_dict(ev: Any) -> Dict[str, Any]:
        if isinstance(ev, dict):
            return ev
        if hasattr(ev, "model_dump"):
            return ev.model_dump()
        if hasattr(ev, "dict"):
            try:
                return ev.dict()  # type: ignore[attr-defined]
            except Exception:
                pass
        try:
            return dict(ev)
        except Exception:
            return {
                "rule": getattr(ev, "rule", None),
                "window": getattr(ev, "window", None),
                "host": getattr(ev, "host", None),
                "count": getattr(ev, "count", 0),
                "summary": getattr(ev, "summary", {}) or {},
                "exemplars": getattr(ev, "exemplars", []) or [],
            }

    by_key: Dict[Tuple[Optional[str], Optional[str]], Dict[str, Any]] = {}

    for ev in (e for batch in batches for e in batch):
        d = as_dict(ev)
        rule = d.get("rule")
        host = d.get("host")
        window = d.get("window")
        count = int(d.get("count") or 0)
        summary = d.get("summary") or {}
        exemplars = list(d.get("exemplars") or [])

        key = (rule, host)
        if key not in by_key:
            by_key[key] = {
                "rule": rule,
                "window": window,
                "host": host,
                "count": count,
                "summary": summary,
                "exemplars": exemplars[:10],
            }
        else:
            cur = by_key[key]
            cur["count"] = max(int(cur.get("count", 0)), count)
            cur["summary"] = deep_union(cur.get("summary", {}), summary)
            if len(cur.get("exemplars", [])) < 10 and exemplars:
                take = 10 - len(cur["exemplars"])
                cur["exemplars"].extend(exemplars[:take])

    return list(by_key.values())
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
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
            return data if isinstance(data, dict) else {}
    except Exception as e:
        print(f"[master] WARN: failed to load actions.yaml: {e}")
        return {}

def _render_actions_md(merged: List[DetectionEvidence]) -> str:
    actions = _load_actions()
    if not actions:
        return ""
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

def _pack_preview_extras(merged: List[DetectionEvidence], *, max_rules: int = 5, top_hosts: int = 3) -> Dict[str, Any]:
    def _asdict(e: Any) -> Dict[str, Any]:
        if isinstance(e, dict):
            return e
        if hasattr(e, "model_dump"):
            return e.model_dump()
        return e.__dict__

    def _extract_hosts(summary: Dict[str, Any]) -> List[Tuple[str, int]]:
        if not isinstance(summary, dict):
            return []
        candidates = (
            summary.get("groups_over_threshold")
            or summary.get("groups")
            or summary.get("buckets")
        )
        if isinstance(candidates, dict) and "buckets" in candidates:
            candidates = candidates.get("buckets")

        out: List[Tuple[str, int]] = []
        if isinstance(candidates, list):
            for g in candidates:
                if not isinstance(g, dict):
                    continue
                host = (
                    g.get("key")
                    or g.get("key_as_string")
                    or g.get("host.name")
                    or g.get("host")
                    or (g.get("term") if isinstance(g.get("term"), str) else None)
                )
                if isinstance(host, dict):
                    host = host.get("host.name") or host.get("key") or host.get("name")
                cnt = (g.get("count") or g.get("doc_count") or g.get("value") or 0)
                try:
                    cnt = int(cnt)
                except Exception:
                    cnt = 0
                if host and cnt > 0:
                    out.append((str(host), cnt))
        out.sort(key=lambda x: x[1], reverse=True)
        return out[:top_hosts]

    rule_totals: Dict[str, int] = {}
    hosts_by_rule: Dict[str, List[Tuple[str, int]]] = {}

    for ev in merged:
        d = _asdict(ev)
        rule = d.get("rule") or "unknown"
        if rule == "fleet_total":
            continue
        count = int(d.get("count") or 0)
        rule_totals[rule] = rule_totals.get(rule, 0) + count
        if "summary" in d:
            hosts = _extract_hosts(d["summary"])
            if hosts:
                hosts_by_rule[rule] = hosts

    rule_counts = sorted(rule_totals.items(), key=lambda x: x[1], reverse=True)
    if HIDE_ZERO_RULES:
        rule_counts = [(r, c) for (r, c) in rule_counts if c > 0]
    rule_counts = rule_counts[:max_rules]

    return {"rule_counts": rule_counts, "top_hosts": hosts_by_rule}

def notify_slack(preview: Dict[str, Any], incident: Optional[Dict[str, Any]]) -> None:
    url = os.getenv("SLACK_WEBHOOK_URL")
    if not url:
        return

    sev   = (preview.get("severity") or "unknown")
    items = int(preview.get("items") or 0)
    tldr  = preview.get("tldr") or "(no TL;DR)"

    rule_counts: List[Tuple[str, int]] = preview.get("rule_counts") or []
    top_hosts: Dict[str, List[Tuple[str, int]]] = preview.get("top_hosts") or {}

    lines = [
        f"TinySocs: {sev} · {items} item(s)",
        f"- {tldr}",
    ]

    if rule_counts:
        rules_line = ", ".join(f"{r} ({c})" for r, c in rule_counts)
        lines.append(f"- Rules: {rules_line}")

    for r, _ in rule_counts[:3]:
        hosts = top_hosts.get(r) or []
        if hosts:
            host_line = ", ".join(f"{h} ({c})" for h, c in hosts)
            lines.append(f"• {r} → {host_line}")

    text = "\n".join(lines)

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
    post_url = urljoin(SIEM_URL.rstrip("/") + "/", "tinysocs_anchors/_doc")
    r = requests.post(post_url, auth=_es_auth(), verify=SIEM_VERIFY, json=doc, timeout=REQUEST_TIMEOUT_SEC)
    r.raise_for_status()
# ----------------------------------------------------

def run_master(rules: str, window: str, host: Optional[str], deadline_sec: float, always_anchor: bool) -> Dict[str, Any]:
    t0 = time.time()
    deadline_at = t0 + max(0.1, deadline_sec)
    summary = {
        "rules": rules,
        "window": window,
        "nodes": [],
        "errors": 0,
        "anchored": 0,
        "ts": _now_utc_iso(),
        "privacy_mode": _display_privacy_mode(),
    }

    # optional heartbeat rate-limit (mostly no-op for single-pass runs; kept for completeness)
    try:
        heartbeat_sec = int(os.getenv("ANCHOR_HEARTBEAT_SEC", "0") or "0")
    except Exception:
        heartbeat_sec = 0
    _last_anchor_ts: Dict[str, float] = {}

    print(f"[master] fan-out to {','.join(NODES)}; rules={rules}; window={window}")

    try:
        results = asyncio.run(_fanout_agg_async(NODES, rules, window, host, deadline_sec))
    except Exception as e:
        print(f"[master] WARN: async fan-out failed, falling back to sequential: {e}")
        results = []
        for node in NODES:
            try:
                data = _try_call(
                    lambda: (_agg_get(node, rules, window, host)),
                    tries=MASTER_RETRIES, min_ms=MASTER_RETRY_MIN_MS, max_ms=MASTER_RETRY_MAX_MS, label=f"{node} /agg"
                )
                results.append({"node": node, "ok": True, "data": data})
            except Exception as e2:
                results.append({"node": node, "ok": False, "error": f"agg_failed: {e2}"})

    results = sorted(results, key=lambda r: r.get("node") or "")
    results_ok  = [r for r in results if r.get("ok")]
    results_bad = [r for r in results if not r.get("ok")]
    results = results_ok + results_bad

    all_rule_rows: List[DetectionEvidence] = []

    for res in results:
        node = res.get("node")
        node_row: Dict[str, Any] = {"node": node, "ok": False}

        if res.get("ok"):
            agg = res.get("data")
            items: int = 0
            rule_count: int = 0

            if isinstance(agg, list):
                norm: List[Dict[str, Any]] = []
                for e in agg:
                    if hasattr(e, "model_dump"):
                        norm.append(e.model_dump())
                    elif isinstance(e, dict):
                        norm.append(e)
                    else:
                        try:
                            norm.append(dict(e))
                        except Exception:
                            continue
                rule_count = len(norm)
                items = sum(int(d.get("count") or 0) for d in norm)
                for d in norm:
                    all_rule_rows.append(
                        DetectionEvidence(
                            rule=d.get("rule"),
                            window=d.get("window") or window,
                            host=d.get("host"),
                            count=int(d.get("count") or 0),
                            summary=d.get("summary") or {},
                            exemplars=d.get("exemplars") or [],
                        )
                    )
            elif isinstance(agg, dict):
                items = int((agg.get("items") if agg.get("items") is not None else agg.get("count", 0)) or 0)
                rule_count = 1 if agg else 0
                if "rule" in agg:
                    all_rule_rows.append(
                        DetectionEvidence(
                            rule=agg.get("rule"),
                            window=agg.get("window") or window,
                            host=agg.get("host"),
                            count=int(agg.get("count") or 0),
                            summary=agg.get("summary") or {},
                            exemplars=agg.get("exemplars") or [],
                        )
                    )
            else:
                items = 0
                rule_count = 0

            node_row.update({"ok": True, "items": items, "rules": rule_count})
            print(f"[master] {node} -> {items} item(s) across {rule_count} rule(s)")
        else:
            node_row.update({"ok": False, "error": res.get("error") or "agg_failed"})
            summary["errors"] += 1
            print(f"[master] {node} agg error: {node_row['error']}")
            summary["nodes"].append(node_row)
            continue  # <-- fixed: removed stray ')'

        # Record a minimal run marker into node ledger (best-effort)
        try:
            _try_call(
                lambda: _post_json(node, {"payload": {"rules": rules, "window": window, "items": int(node_row.get("items", 0)), "privacy_mode": _display_privacy_mode()}}),
                tries=MASTER_RETRIES, min_ms=MASTER_RETRY_MIN_MS, max_ms=MASTER_RETRY_MAX_MS, label=f"{node} /evidence/append",
            )
        except Exception as _e:
            node_row["append_warn"] = f"append_failed: {_e}"

        # Decide whether to write an anchor for this node
        items_for_node = int(node_row.get("items", 0))
        should_anchor = (items_for_node > 0) or always_anchor
        if should_anchor and heartbeat_sec > 0:
            last = _last_anchor_ts.get(node, 0.0)
            if (time.time() - last) < float(heartbeat_sec):
                should_anchor = False

        if not should_anchor:
            summary["nodes"].append(node_row)
            print(f"[master] no-anchor {node} (items={items_for_node}, always_anchor={always_anchor})")
            continue

        # Fetch the latest ledger head and index the anchor
        try:
            head = _try_call(
                lambda: _get_head(node),
                tries=MASTER_RETRIES, min_ms=MASTER_RETRY_MIN_MS, max_ms=MASTER_RETRY_MAX_MS, label=f"{node} /evidence/head",
            )
        except Exception as e:
            node_row.update({"head_error": f"head_failed: {e}"})
            summary["errors"] += 1
            summary["nodes"].append(node_row)
            print(f"[master] {node} head error: {e}")
            continue

        anchor_doc = {
            "node": node,
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
                "items": items_for_node,
                "privacy_mode": _display_privacy_mode(),
            },
        }
        try:
            _try_call(lambda: _es_index(anchor_doc),
                      tries=MASTER_RETRIES, min_ms=MASTER_RETRY_MIN_MS, max_ms=MASTER_RETRY_MAX_MS,
                      label=f"{node} anchor_index")
            summary["anchored"] += 1
            _last_anchor_ts[node] = time.time()
            print(f"[master] anchored {node} @ {anchor_doc['anchored_at']} (seq={anchor_doc['sequence']})")
        except Exception as e:
            node_row.update({"anchor_error": f"anchor_failed: {e}"})
            summary["errors"] += 1
            print(f"[master] {node} anchor error: {e}")

        summary["nodes"].append(node_row)

    if all_rule_rows:
        merged = merge_evidence([all_rule_rows])
        total_items = sum(int((e.get("count") if isinstance(e, dict) else getattr(e, "count", 0)) or 0)
                          for e in merged)
        # Take top-3 by count, then optionally hide zeros in the headline
        top_rules_all = sorted(
            (((e.get("rule") if isinstance(e, dict) else getattr(e, "rule", None)),
               int((e.get("count") if isinstance(e, dict) else getattr(e, "count", 0)) or 0)) for e in merged),
            key=lambda x: x[1], reverse=True
        )[:3]
        top_rules = [(r, c) for (r, c) in top_rules_all if r and ((not HIDE_ZERO_RULES) or c > 0)]
        nonzero_rule_count = len(top_rules)
        preview_tldr = None
        if top_rules:
            pretty = ", ".join(f"{r} ({c})" for r, c in top_rules)
            preview_tldr = f"Detected {total_items} event(s) across {nonzero_rule_count} rule(s): {pretty}"
    else:
        pseudo = DetectionEvidence(rule="fleet_total", window=window, host=None,
                                   count=sum(int(n.get("items", 0)) for n in summary["nodes"]),
                                   summary={}, exemplars=[])
        merged = [pseudo]
        total_items = int(pseudo.get("count") if isinstance(pseudo, dict) else getattr(pseudo, "count", 0))
        preview_tldr = f"Detected {total_items} event(s) across 1 rule(s): fleet_total."

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

    sev = incident.get("severity") if isinstance(incident, dict) else None
    tldr = incident.get("tldr") if isinstance(incident, dict) else None
    if preview_tldr and 'total_items' in locals() and total_items > 0:
        tldr = preview_tldr

    extras = _pack_preview_extras(merged, max_rules=5, top_hosts=3)

    preview = {
        "severity": sev,
        "tldr": tldr or f"{total_items} item(s) total.",
        "items": total_items,
        "privacy_mode": _display_privacy_mode(),
        "anchored": summary["anchored"],
        "errors": summary["errors"],
        **extras,
    }
    print("----- Fleet Incident (preview) -----")
    print(json.dumps(preview, indent=2, default=str))

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

def cli() -> None:
    import argparse
    ap = argparse.ArgumentParser(
        prog="tinysocs-master",
        description="TinySOCS Master (fan-out + summarize + anchor)"
    )
    ap.add_argument("--rules", type=str, required=True, help="Comma separated rule IDs")
    ap.add_argument("--window", type=str, required=True, help="Window, e.g., 15m")
    ap.add_argument("--host", type=str, default=None, help="Optional host filter")
    ap.add_argument(
        "--deadline",
        type=float,
        default=float(os.getenv("MASTER_DEADLINE_SEC", "30")),
        help="Overall wall-clock deadline in seconds (default from MASTER_DEADLINE_SEC or 30).",
    )
    ap.add_argument(
        "--always-anchor",
        action="store_true",
        help="Anchor even when a node returns 0 items (heartbeat anchors). Env fallback: ALWAYS_ANCHOR=1.",
    )
    args = ap.parse_args()

    if not NODES:
        raise SystemExit("TINYSOCS_NODES is empty; set it to comma-separated node URLs.")

    # env fallback (keeps current behavior unless explicitly disabled)
    env_always = _env_bool("ALWAYS_ANCHOR", False)
    always_anchor = args.always_anchor or env_always

    # Pre-flight ensure of anchors alias/mapping using unified module (idempotent)
    if os.getenv("ENSURE_ANCHORS", "1").strip().lower() not in ("0", "false", "no", "off"):
        try:
            if _ensure_anchors:
                _ensure_anchors()  # anchors.ensure_anchors_if_missing()
            else:
                print("[master] WARN: anchors.ensure_anchors_if_missing not available")
        except Exception as e:
            print(f"[master] WARN: anchors ensure failed: {e}")

    run_master(args.rules, args.window, args.host, args.deadline, always_anchor)


# Back-compat shim for old entry point
def main() -> None:
    cli()


if __name__ == "__main__":
    cli()