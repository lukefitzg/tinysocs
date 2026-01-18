#!/usr/bin/env python3
"""
TinySocs — Anchors index manager (ensure + prune)

What it does
  • Ensures alias points to today's daily index: <ALIAS>-YYYY.MM.DD
  • Creates index with mapping if missing
  • Prunes old daily indices by age (index-level, fast)
  • Works with self-signed clusters (SIEM_SSL_VERIFY=false)

Replica behaviour (noise reduction on single-node TinyBox)
  • If SIEM_URL host is localhost / 127.0.0.1 / ::1, create indices with:
      number_of_replicas: 0
    and best-effort enforce that setting on the current daily index.
  • Otherwise defaults to replicas=1.
  • You can override via env:
      TINYSOCS_ANCHORS_REPLICAS=0|1|2...

Env
  TINYSOCS_ANCHORS_ALIAS      Alias/prefix (default: tinysocs_anchors)
  SIEM_URL                    http://127.0.0.1:9200
  SIEM_USER                   admin
  SIEM_PASS                   admin
  SIEM_SSL_VERIFY             "false"/"0" to disable verify (default: verify enabled)
  TINYSOCS_ANCHORS_REPLICAS   Optional override for replica count

CLI
  python -m tinysocs.orchestrator.anchors --ensure --retention-days 30
  python -m tinysocs.orchestrator.anchors --prune --retention-days 45 --dry-run
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import sys
from typing import Any, Dict, List, Tuple
from urllib.parse import urljoin, urlparse

from pathlib import Path
from tinysocs.env import load_dotenv_if_present

import requests
from requests.auth import HTTPBasicAuth

load_dotenv_if_present(Path(__file__).resolve().parents[1])

ALIAS = os.getenv("TINYSOCS_ANCHORS_ALIAS", "tinysocs_anchors")

SIEM_URL    = os.getenv("SIEM_URL", "http://127.0.0.1:9200")
SIEM_USER   = os.getenv("SIEM_USER", "admin")
SIEM_PASS   = os.getenv("SIEM_PASS", "admin")
VERIFY_TLS  = str(os.getenv("SIEM_SSL_VERIFY", "true")).strip().lower() not in ("0", "false", "no", "off")

def _is_local_siem(url: str) -> bool:
    """
    Treat localhost / loopback SIEM_URL as single-node TinyBox for replica defaults.
    """
    try:
        host = (urlparse(url).hostname or "").strip().lower()
    except Exception:
        host = ""
    return host in ("localhost", "127.0.0.1", "::1")

def _parse_int_env(name: str) -> int | None:
    v = os.getenv(name)
    if v is None:
        return None
    v = str(v).strip()
    if v == "":
        return None
    try:
        return int(v)
    except Exception:
        return None

DEFAULT_REPLICAS = 0 if _is_local_siem(SIEM_URL) else 1
ANCHORS_REPLICAS = _parse_int_env("TINYSOCS_ANCHORS_REPLICAS")
if ANCHORS_REPLICAS is None:
    ANCHORS_REPLICAS = DEFAULT_REPLICAS

print(f"[anchors] SIEM_URL={SIEM_URL} verify={VERIFY_TLS} user={SIEM_USER} replicas={ANCHORS_REPLICAS}")

try:
    import urllib3  # type: ignore
    if not VERIFY_TLS:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass

def _auth() -> HTTPBasicAuth:
    return HTTPBasicAuth(SIEM_USER, SIEM_PASS)

MAPPING: Dict[str, Any] = {
    "settings": {
        "number_of_replicas": ANCHORS_REPLICAS,
    },
    "mappings": {
        "dynamic": True,
        "properties": {
            "node_url":     {"type": "keyword"},
            "node_id":      {"type": "keyword"},
            "ok":           {"type": "boolean"},
            "sequence":     {"type": "long"},
            "head_sha256":  {"type": "keyword"},
            "capability":   {"type": "keyword"},
            "anchored_at":  {"type": "date"},
            "run": {
                "properties": {
                    "rules":        {"type": "keyword"},
                    "window":       {"type": "keyword"},
                    "items":        {"type": "long"},
                    "privacy_mode": {"type": "keyword"},
                }
            }
        }
    }
}

DATE_FMT = "%Y.%m.%d"
INDEX_RE = re.compile(rf"^{re.escape(ALIAS)}-(\d{{4}}\.\d{{2}}\.\d{{2}})$")

def today_index() -> str:
    return f"{ALIAS}-{dt.datetime.utcnow().strftime(DATE_FMT)}"

def _get_alias_indices() -> List[str]:
    """Return indices currently holding the alias (empty if alias doesn't exist)."""
    url = urljoin(SIEM_URL.rstrip("/") + "/", f"_alias/{ALIAS}")
    try:
        r = requests.get(url, auth=_auth(), verify=VERIFY_TLS, timeout=15)
        if r.status_code == 404:
            return []
        r.raise_for_status()
        data = r.json()  # {index: {aliases:{ALIAS:{}}}, ...}
        return list(data.keys())
    except requests.HTTPError as e:
        if e.response is not None and e.response.status_code == 404:
            return []
        raise

def _index_exists(name: str) -> bool:
    url = urljoin(SIEM_URL.rstrip("/") + "/", name)
    r = requests.head(url, auth=_auth(), verify=VERIFY_TLS, timeout=10)
    return r.status_code == 200

def _create_index(name: str) -> None:
    url = urljoin(SIEM_URL.rstrip("/") + "/", name)
    r = requests.put(url, auth=_auth(), json=MAPPING, verify=VERIFY_TLS, timeout=20)
    if not (200 <= r.status_code < 300):
        raise RuntimeError(f"create_index failed: HTTP {r.status_code}: {r.text}")

def _ensure_replicas(name: str) -> None:
    """
    Best-effort enforce number_of_replicas, so single-node doesn't go yellow
    even if the index already existed or was created with defaults.
    """
    url = urljoin(SIEM_URL.rstrip("/") + "/", f"{name}/_settings")
    payload = {"index": {"number_of_replicas": ANCHORS_REPLICAS}}
    try:
        r = requests.put(url, auth=_auth(), json=payload, verify=VERIFY_TLS, timeout=20)
        if not (200 <= r.status_code < 300):
            # Don't hard-fail the whole ensure path for a tuning setting.
            print(f"[anchors] WARN: set replicas failed for {name}: HTTP {r.status_code}: {(r.text or '').strip()}", file=sys.stderr)
    except Exception as e:
        print(f"[anchors] WARN: set replicas failed for {name}: {e}", file=sys.stderr)

def _update_alias_exclusive(target_index: str, current_indices: List[str]) -> None:
    """Atomically move alias to only point to target_index."""
    actions: List[Dict[str, Any]] = []
    for idx in current_indices:
        if idx != target_index:
            actions.append({"remove": {"index": idx, "alias": ALIAS, "must_exist": False}})
    actions.append({"add": {"index": target_index, "alias": ALIAS}})
    url = urljoin(SIEM_URL.rstrip("/") + "/", "_aliases")
    r = requests.post(url, auth=_auth(), json={"actions": actions}, verify=VERIFY_TLS, timeout=20)
    if not (200 <= r.status_code < 300):
        raise RuntimeError(f"_aliases update failed: HTTP {r.status_code}: {r.text}")

def _list_daily_indices() -> List[Tuple[str, dt.date]]:
    """Return list of (index_name, date) for indices matching ALIAS-YYYY.MM.DD."""
    url = urljoin(SIEM_URL.rstrip("/") + "/", f"_cat/indices/{ALIAS}-*?h=index&s=index&format=json")
    r = requests.get(url, auth=_auth(), verify=VERIFY_TLS, timeout=20)
    r.raise_for_status()
    out: List[Tuple[str, dt.date]] = []
    for row in r.json():
        name = str(row.get("index", ""))
        m = INDEX_RE.match(name)
        if not m:
            continue
        try:
            d = dt.datetime.strptime(m.group(1), DATE_FMT).date()
            out.append((name, d))
        except ValueError:
            continue
    return out

def ensure_alias_today() -> Dict[str, Any]:
    idx = today_index()
    existed = _index_exists(idx)
    if not existed:
        _create_index(idx)

    # Best-effort enforce replica setting so single-node doesn't go yellow.
    _ensure_replicas(idx)

    current = _get_alias_indices()
    _update_alias_exclusive(idx, current)
    return {"alias": ALIAS, "index": idx, "created": (not existed), "switched_from": [x for x in current if x != idx], "replicas": ANCHORS_REPLICAS}

def prune_old_indices(retention_days: int, dry: bool) -> Dict[str, Any]:
    """Delete whole daily indices older than retention_days."""
    cutoff = (dt.datetime.utcnow().date() - dt.timedelta(days=retention_days))
    pairs = _list_daily_indices()
    victims = [name for (name, d) in pairs if d < cutoff]
    deleted: List[str] = []
    errors: List[Dict[str, Any]] = []
    if not dry:
        for name in victims:
            url = urljoin(SIEM_URL.rstrip("/") + "/", name)
            r = requests.delete(url, auth=_auth(), verify=VERIFY_TLS, timeout=60)
            if 200 <= r.status_code < 300:
                deleted.append(name)
            else:
                errors.append({"index": name, "status": r.status_code, "body": (r.text or "").strip()})
    return {
        "alias": ALIAS,
        "cutoff": cutoff.isoformat(),
        "matches": victims if dry else deleted,
        "dry_run": dry,
        "errors": errors,
    }

# ---- Compatibility shims for master & callers --------------------------------
def ensure_alias_and_mapping() -> Dict[str, Any]:
    """Back-compat: same as ensure_alias_today()."""
    return ensure_alias_today()

def ensure_anchors_if_missing() -> None:
    """Back-compat: invoked by master; ensures alias+mapping exist for today."""
    ensure_alias_today()
# ------------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(description="Ensure anchors alias & prune old daily indices.")
    ap.add_argument("--ensure", action="store_true", help="Ensure alias points to today's daily index")
    ap.add_argument("--prune", action="store_true", help="Prune old daily indices")
    ap.add_argument("--retention-days", type=int, default=None, help="Age threshold for pruning (required for --prune)")
    ap.add_argument("--dry-run", action="store_true", help="Don't delete; show which indices would be removed")
    args = ap.parse_args()

    try:
        results: Dict[str, Any] = {}
        # Default behavior: if neither flag provided, just --ensure
        do_ensure = args.ensure or (not args.prune)
        if do_ensure:
            results["ensure"] = ensure_alias_today()
        if args.prune:
            if args.retention_days is None:
                raise SystemExit("--prune requires --retention-days")
            results["prune"] = prune_old_indices(args.retention_days, args.dry_run)
        print(json.dumps(results, indent=2))
    except Exception as e:
        print(f"[anchors] ERROR: {e}", file=sys.stderr)
        sys.exit(2)

if __name__ == "__main__":
    main()