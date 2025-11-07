# orchestrator/check_ledger.py
#!/usr/bin/env python3
"""
TinySocs — quick ledger health check across nodes, with optional verification
against the latest anchor stored in OpenSearch.

Reads env:
  - TINYSOCS_NODES                (comma-separated URLs; e.g. http://localhost:8081)
  - MASTER_SHARED_SECRET          (HMAC secret)
  - TINYSOCS_INSECURE_SKIP_VERIFY (default "1" → skip TLS verify for local/self-signed)
  - TINYSOCS_HMAC_STYLE           (pipe | dot | ts)  [default: pipe]
  - TINYSOCS_SIG_PREFIX           (truthy → emit 'sha256=<hex>'; else raw hex)
  - TINYSOCS_ANCHORS_ALIAS        (OpenSearch alias for anchors; default tinysocs_anchors)
  - SIEM_URL                      (e.g. https://localhost:9201)
  - SIEM_USER                     (e.g. admin)
  - SIEM_PASS                     (password)
  - SIEM_SSL_VERIFY               ("false"/"0" to disable TLS verify; otherwise enabled)

Usage:
  # Health probe (current heads only)
  python tinysocs/orchestrator/check_ledger.py

  # Verify local chain health and compare current heads against latest anchors
  python tinysocs/orchestrator/check_ledger.py --verify
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

import requests
from requests.auth import HTTPBasicAuth


# ---------------- Env helpers ----------------
def _env_bool(name: str, default: bool = False) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return str(v).strip().lower() in ("1", "true", "yes", "y", "on")

def _tls_verify_from(name: str, default: bool = True) -> bool:
    # For SIEM_SSL_VERIFY: accept "0/false/no/off" as disable
    v = os.getenv(name)
    if v is None:
        return default
    return str(v).strip().lower() not in ("0", "false", "no", "off")

# --- best-effort .env loader (tolerant encodings) ---
def _parse_dotenv_content(s: str) -> None:
    for raw in s.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")  # only the first '=' splits key/value
        k, v = (k or "").strip(), (v or "").strip()
        # strip simple quotes users often paste in
        if v.startswith(("'", '"')) and v.endswith(("'", '"')) and len(v) >= 2:
            v = v[1:-1]
        if k and (k not in os.environ):
            os.environ[k] = v

def _read_text_permissive(p: Path) -> str:
    for enc in ("utf-8", "utf-8-sig", "cp1252", "latin-1"):
        try:
            return p.read_text(encoding=enc)
        except UnicodeDecodeError:
            continue
    # final fallback: ignore undecodable bytes
    return p.read_bytes().decode("utf-8", errors="ignore")

def _load_dotenv_inplace():
    here = Path(__file__).resolve()
    candidates = [
        here.parents[2] / ".env",  # <repo>/.env
        here.parents[1] / ".env",  # <repo>/tinysocs/.env (fallback)
        Path.cwd() / ".env",
    ]
    for p in candidates:
        if p.is_file():
            try:
                content = _read_text_permissive(p)
                _parse_dotenv_content(content)
            except Exception as e:
                print(f"[ledger-check] WARN: failed to load {p}: {e}")
            break

_load_dotenv_inplace()

# Optional: silence InsecureRequestWarning if verify is disabled
try:
    import urllib3  # type: ignore
    if (not _tls_verify_from("SIEM_SSL_VERIFY", True)) or _env_bool("TINYSOCS_INSECURE_SKIP_VERIFY", True):
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass

# ---------------- Config ----------------
NODES: List[str] = [x.strip() for x in (os.getenv("TINYSOCS_NODES", "")).split(",") if x.strip()]
SECRET: str = os.getenv("MASTER_SHARED_SECRET", "dev-secret-change-me")
NODE_TLS_VERIFY: bool = not _env_bool("TINYSOCS_INSECURE_SKIP_VERIFY", True)  # default skip verify (local lab)

SIEM_URL: str = os.getenv("SIEM_URL", "https://localhost:9201")
SIEM_USER: str = os.getenv("SIEM_USER", "admin")
SIEM_PASS: str = os.getenv("SIEM_PASS", "admin")
SIEM_VERIFY: bool = _tls_verify_from("SIEM_SSL_VERIFY", True)
SIEM_TIMEOUT: float = float(os.getenv("SIEM_TIMEOUT_SECONDS", "30"))

REQUEST_TIMEOUT: float = float(os.getenv("REQUEST_TIMEOUT_SEC", "30"))

# HMAC style/prefix + anchors alias (parity with master/bot)
HMAC_STYLE: str = (os.getenv("TINYSOCS_HMAC_STYLE", "pipe") or "pipe").strip().lower()  # pipe|dot|ts
USE_PREFIX: bool = str(os.getenv("TINYSOCS_SIG_PREFIX", "")).strip().lower() in ("1", "true", "yes", "on", "sha256")
ANCHORS_ALIAS: str = os.getenv("TINYSOCS_ANCHORS_ALIAS", "tinysocs_anchors")

# ---------------- HMAC headers (supports pipe|dot|ts; raw or prefixed) ----------------
def _headers() -> Dict[str, str]:
    import secrets
    ts = str(int(time.time()))
    if HMAC_STYLE == "dot":
        nonce = secrets.token_hex(8)
        msg = f"{ts}.{nonce}"
        include_nonce = True
    elif HMAC_STYLE == "ts":
        msg = ts
        include_nonce = False
        nonce = None
    else:  # pipe (default)
        nonce = secrets.token_hex(8)
        msg = f"{ts}|{nonce}"
        include_nonce = True

    mac_hex = hmac.new((SECRET or "").encode("utf-8"), msg.encode("utf-8"), hashlib.sha256).hexdigest()
    sig_val = f"sha256={mac_hex}" if USE_PREFIX else mac_hex

    h = {
        "X-TinySOCS-Timestamp": ts,
        "X-TinySOCS-Signature": sig_val,
        "User-Agent": "tinysocs/ledger-check",
    }
    if include_nonce and nonce:
        h["X-TinySOCS-Nonce"] = nonce
    return h

# ---------------- Node helpers ----------------
def _derive_node_id(node_url: str) -> str:
    """Canonical node_id: 'node-<port>' if present, else 'node-<host>' (host only)."""
    p = urlparse(node_url)
    if p.port:
        return f"node-{p.port}"
    host = (p.hostname or "node").split(".")[0]
    return f"node-{host}"

def _alt_node_urls(node_url: str) -> Set[str]:
    """Return a set of equivalent URLs to match anchors (localhost ↔ 127.0.0.1)."""
    p = urlparse(node_url)
    variants = set([node_url.rstrip("/")])
    if p.hostname in ("localhost", "127.0.0.1"):
        swap = "127.0.0.1" if p.hostname == "localhost" else "localhost"
        swapped = f"{p.scheme}://{swap}:{p.port}" if p.port else f"{p.scheme}://{swap}"
        variants.add(swapped.rstrip("/"))
    return variants

# ---------------- Node head fetch ----------------
def _get_head(node_url: str) -> Dict[str, Any]:
    url = node_url.rstrip("/") + "/evidence/head"
    try:
        r = requests.get(url, headers=_headers(), timeout=REQUEST_TIMEOUT, verify=NODE_TLS_VERIFY)
        if r.status_code == 501:
            return {"ok": None, "sequence": None, "head_sha256": None, "capability": "no-ledger", "node_id": None}
        r.raise_for_status()
        data = r.json()
        return {
            "ok": bool(data.get("ok")),
            "sequence": data.get("sequence"),
            "head_sha256": data.get("head_sha256"),
            "capability": data.get("capability", "ledger"),
            "node_id": data.get("node_id") or _derive_node_id(node_url),
        }
    except Exception as e:
        return {"ok": False, "sequence": None, "head_sha256": None, "capability": f"error: {e}", "node_id": None}

# ---------------- Anchor query (OpenSearch) ----------------
def _es_auth() -> HTTPBasicAuth:
    return HTTPBasicAuth(SIEM_USER, SIEM_PASS)

def _search_latest_anchor(node_url: str, node_id: str) -> Optional[Dict[str, Any]]:
    """
    Return the most recent anchor doc for this node from the anchors alias.
    Tries node_url (with localhost/127.0.0.1 variants) OR node_id.
    """
    search_url = SIEM_URL.rstrip('/') + f'/{ANCHORS_ALIAS}/_search'
    should = []
    for u in _alt_node_urls(node_url):
        # Try both keyword and non-keyword to be resilient to mapping differences
        should.append({"term": {"node_url.keyword": {"value": u}}})
        should.append({"term": {"node_url": {"value": u}}})
    should.append({"term": {"node_id": {"value": node_id}}})

    q = {
        "size": 1,
        "sort": [{"anchored_at": {"order": "desc"}}],
        "query": {"bool": {"should": should, "minimum_should_match": 1}},
    }
    r = requests.post(search_url, auth=_es_auth(), verify=SIEM_VERIFY, json=q, timeout=SIEM_TIMEOUT)
    r.raise_for_status()
    hits = r.json().get("hits", {}).get("hits", [])
    if not hits:
        return None
    return hits[0].get("_source") or {}

# ---------------- Main ----------------
def main() -> None:
    ap = argparse.ArgumentParser(description="TinySocs ledger health / verification")
    ap.add_argument(
        "--verify",
        action="store_true",
        help="Validate local ledger chain, then compare each node's current head to the last anchored head in OpenSearch",
    )
    args = ap.parse_args()

    if not NODES:
        raise SystemExit("Set TINYSOCS_NODES (comma-separated).")

    rows: List[Dict[str, Any]] = []

    if not args.verify:
        # Health-only path (current node heads)
        for node in NODES:
            head = _get_head(node)
            rows.append({"node": node, **head})
        print(json.dumps(rows, indent=2, default=str))
        return

    # Verify path: (1) local chain health; (2) compare current head vs latest anchor (if local is healthy)
    from tinysocs.agent.models import ledger as _ledger  # imported only in verify mode

    for node in NODES:
        head = _get_head(node)
        node_id = head.get("node_id") or _derive_node_id(node)

        if head.get("ok") is False:
            rows.append({
                "node": node,
                "ok": False,
                "reason": head.get("capability") or "head_fetch_failed",
                "node_id": node_id,
            })
            continue
        if head.get("capability") == "no-ledger":
            rows.append({"node": node, "ok": False, "reason": "no_ledger_capability", "node_id": node_id})
            continue

        # (1) Local chain verification (gives exact reason if tampered)
        local_ok, local_seq, local_head_or_reason = _ledger.verify_chain(node_id)
        ledger_path = str((_ledger.LEDGER_DIR / f"{node_id}.jsonl").resolve())

        if not local_ok:
            rows.append({
                "node": node,
                "node_id": node_id,
                "ok": False,
                "reason": local_head_or_reason,   # e.g., 'prev_link_mismatch', 'head_mismatch', 'sequence_gap'
                "sequence": local_seq,
                "ledger_path": ledger_path,
                "current_head": head.get("head_sha256"),
            })
            continue  # Don't compare to anchor if the local chain is already invalid

        # (2) Local chain is healthy → compare current head to the latest anchor
        try:
            anchor = _search_latest_anchor(node, node_id)
        except Exception as e:
            rows.append({
                "node": node,
                "node_id": node_id,
                "ok": False,
                "reason": f"anchor_query_failed: {e}",
                "ledger_path": ledger_path,
            })
            continue

        if not anchor:
            rows.append({
                "node": node,
                "node_id": node_id,
                "ok": False,
                "reason": "no_anchor",
                "sequence": head.get("sequence"),
                "current_head": head.get("head_sha256"),
                "ledger_path": ledger_path,
            })
            continue

        current = head.get("head_sha256")
        anchored = anchor.get("head_sha256") or anchor.get("head")
        ok = (current is not None) and (current == anchored)

        rows.append({
            "node": node,
            "node_id": node_id,
            "ok": ok,
            "reason": None if ok else "anchor_mismatch",
            "sequence": head.get("sequence"),
            "current_head": current,
            "anchored_head": anchored,
            "anchored_at": anchor.get("anchored_at"),
            "ledger_path": ledger_path,
        })

    print(json.dumps(rows, indent=2, default=str))


if __name__ == "__main__":
    main()
