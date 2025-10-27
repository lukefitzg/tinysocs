# orchestrator/check_ledger.py
#!/usr/bin/env python3
"""
TinySocs — quick ledger health check across nodes, with optional verification
against the latest anchor stored in OpenSearch.

Reads env:
  - TINYSOCS_NODES            (comma-separated URLs; e.g. http://localhost:8081)
  - MASTER_SHARED_SECRET      (HMAC secret)
  - TINYSOCS_INSECURE_SKIP_VERIFY (default "1" → skip TLS verify for local/self-signed)
  - SIEM_URL                  (e.g. https://localhost:9201)
  - SIEM_USER                 (e.g. admin)
  - SIEM_PASS                 (password)
  - SIEM_SSL_VERIFY           ("false"/"0" to disable TLS verify; otherwise enabled)

Usage:
  # Health probe (current heads only)
  python tinysocs/orchestrator/check_ledger.py

  # Verify current heads against the latest anchors in OpenSearch
  python tinysocs/orchestrator/check_ledger.py --verify
"""
from __future__ import annotations

import argparse
import json
import os
import time
import hmac
import hashlib
from typing import Dict, Any, List, Optional
from urllib.parse import urljoin

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


# ---------------- Config ----------------
NODES: List[str] = [x.strip() for x in (os.getenv("TINYSOCS_NODES", "")).split(",") if x.strip()]
SECRET: str = os.getenv("MASTER_SHARED_SECRET", "dev-secret-change-me")
NODE_TLS_VERIFY: bool = not _env_bool("TINYSOCS_INSECURE_SKIP_VERIFY", True)  # default skip verify (local lab)


# ---------------- HMAC headers (no "sha256=" prefix) ----------------
def _headers() -> Dict[str, str]:
    ts = str(int(time.time()))
    mac = hmac.new((SECRET or "").encode("utf-8"), ts.encode("utf-8"), hashlib.sha256).hexdigest()
    # Node API compares raw hex digest; do NOT prefix with "sha256="
    return {"X-TinySOCS-Timestamp": ts, "X-TinySOCS-Signature": mac, "User-Agent": "tinysocs/ledger-check"}


# ---------------- Node head fetch ----------------
def _get_head(node_url: str) -> Dict[str, Any]:
    url = node_url.rstrip("/") + "/evidence/head"
    try:
        r = requests.get(url, headers=_headers(), timeout=8, verify=NODE_TLS_VERIFY)
        if r.status_code == 501:
            return {"ok": None, "sequence": None, "head_sha256": None, "capability": "no-ledger"}
        r.raise_for_status()
        data = r.json()
        return {
            "ok": bool(data.get("ok")),
            "sequence": data.get("sequence"),
            "head_sha256": data.get("head_sha256"),
            "capability": data.get("capability", "ledger"),
        }
    except Exception as e:
        return {"ok": False, "sequence": None, "head_sha256": None, "capability": f"error: {e}"}


# ---------------- Anchor query (OpenSearch) ----------------
def _es_auth() -> HTTPBasicAuth:
    return HTTPBasicAuth(os.getenv("SIEM_USER", "admin"), os.getenv("SIEM_PASS", "admin"))


def _es_verify() -> bool:
    return _tls_verify_from("SIEM_SSL_VERIFY", default=True)


def _search_latest_anchor(siem_url: str, node_url: str) -> Optional[Dict[str, Any]]:
    """
    Return the most recent anchor doc for this node from 'tinysocs_anchors'.
    Tries node_url, node, or node_id (any one matching).
    """
    search_url = urljoin(siem_url.rstrip('/') + '/', "tinysocs_anchors/_search")
    should = [
        {"term": {"node_url.keyword": node_url}},
        {"term": {"node.keyword": node_url}},
        {"term": {"node_id.keyword": os.getenv("NODE_ID","node-1")}},
    ]
    q = {
        "size": 1,
        "sort": [{"anchored_at": {"order": "desc"}}],
        "query": {"bool": {"should": should, "minimum_should_match": 1}},
    }
    try:
        r = requests.post(search_url, auth=_es_auth(), verify=_es_verify(), json=q, timeout=12)
        r.raise_for_status()
        hits = r.json().get("hits", {}).get("hits", [])
        if not hits:
            return None
        return hits[0]["_source"]
    except Exception as e:
        return {"error": str(e)}


# ---------------- Main ----------------
def main() -> None:
    ap = argparse.ArgumentParser(description="TinySocs ledger health / verification")
    ap.add_argument("--verify", action="store_true", help="Compare each node's current head to the last anchored head in OpenSearch")
    args = ap.parse_args()

    if not NODES:
        raise SystemExit("Set TINYSOCS_NODES (comma-separated).")

    rows: List[Dict[str, Any]] = []

    if not args.verify:
        # Health-only path (original behavior)
        for node in NODES:
            head = _get_head(node)
            rows.append({"node": node, **head})
        print(json.dumps(rows, indent=2))
        return

    # Verify path: compare current head vs latest anchor
    siem_url = os.getenv("SIEM_URL", "https://localhost:9201")

    for node in NODES:
        head = _get_head(node)
        if head.get("ok") is False:
            rows.append({"node": node, "ok": False, "reason": head.get("capability") or "head_fetch_failed"})
            continue
        if head.get("capability") == "no-ledger":
            rows.append({"node": node, "ok": False, "reason": "no_ledger_capability"})
            continue

        anchor = _search_latest_anchor(siem_url, node)
        if anchor is None:
            rows.append({"node": node, "ok": False, "reason": "no_anchor", "sequence": head.get("sequence"), "current_head": head.get("head_sha256")})
            continue
        if isinstance(anchor, dict) and anchor.get("error"):
            rows.append({"node": node, "ok": False, "reason": f"anchor_query_failed: {anchor['error']}"})
            continue

        current = head.get("head_sha256")
        anchored = anchor.get("head_sha256") or anchor.get("head")
        ok = (current is not None) and (current == anchored)

        rows.append({
            "node": node,
            "ok": ok,
            "reason": None if ok else "head_mismatch",
            "sequence": head.get("sequence"),
            "current_head": current,
            "anchored_head": anchored,
            "anchored_at": anchor.get("anchored_at"),
        })

    print(json.dumps(rows, indent=2))


if __name__ == "__main__":
    main()