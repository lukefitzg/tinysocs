# tinysocs/orchestrator/anchors_retention.py
#!/usr/bin/env python3
"""
TinySocs — anchors_retention
Delete old anchor docs from the tinysocs_anchors alias by anchored_at age.

Env:
  SIEM_URL             e.g. https://localhost:9201
  SIEM_USER            e.g. admin
  SIEM_PASS            e.g. admin
  SIEM_SSL_VERIFY      "false"/"0" to disable verify (default: verify)
  RETENTION_ASYNC      "1" to submit _delete_by_query as a background task (default: 0)
  RETENTION_SLICES     Number of slices or "auto" for parallelization (default: auto)

Usage:
  python -m tinysocs.orchestrator.anchors_retention --days 30 --dry-run
  python -m tinysocs.orchestrator.anchors_retention --days 45
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict
from urllib.parse import urljoin

import requests
from requests.auth import HTTPBasicAuth

# ---------------- best-effort .env loader (permissive) ----------------
def _parse_dotenv_content(s: str) -> None:
    for raw in s.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        k, v = k.strip(), v.strip().strip('"').strip("'")
        if k and (k not in os.environ):
            os.environ[k] = v

def _read_text_permissive(path: str) -> str:
    for enc in ("utf-8", "utf-8-sig", "cp1252", "latin-1"):
        try:
            with open(path, "r", encoding=enc) as f:
                return f.read()
        except UnicodeDecodeError:
            continue
        except FileNotFoundError:
            break
    try:
        with open(path, "rb") as f:
            return f.read().decode("utf-8", errors="ignore")
    except Exception:
        return ""

def _load_dotenv_inplace() -> None:
    here = os.path.abspath(__file__)
    candidates = [
        os.path.abspath(os.path.join(here, "..", "..", "..", ".env")),   # <repo>/.env
        os.path.abspath(os.path.join(here, "..", "..", ".env")),         # <repo>/tinysocs/.env
        os.path.abspath(os.path.join(os.getcwd(), ".env")),              # CWD
    ]
    for p in candidates:
        if os.path.isfile(p):
            try:
                _parse_dotenv_content(_read_text_permissive(p))
            except Exception as e:
                print(f"[anchors_retention] WARN: dotenv load failed for {p}: {e}")
            break

_load_dotenv_inplace()
# ----------------------------------------------------------------------

ALIAS = os.getenv("TINYSOCS_ANCHORS_ALIAS", "tinysocs_anchors")

def _env_bool(name: str, default: bool = False) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return str(v).strip().lower() in ("1", "true", "yes", "on")

def _tls_verify_from(name: str, default: bool = True) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return str(v).strip().lower() not in ("0", "false", "no", "off")

SIEM_URL     = os.getenv("SIEM_URL", "https://localhost:9201")
SIEM_USER    = os.getenv("SIEM_USER", "admin")
SIEM_PASS    = os.getenv("SIEM_PASS", "admin")
SIEM_VERIFY  = _tls_verify_from("SIEM_SSL_VERIFY", True)

RET_ASYNC    = _env_bool("RETENTION_ASYNC", False)
RET_SLICES   = os.getenv("RETENTION_SLICES", "auto")

# Silence TLS warnings when verify is disabled
try:
    import urllib3  # type: ignore
    if not SIEM_VERIFY:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass

def _auth() -> HTTPBasicAuth:
    return HTTPBasicAuth(SIEM_USER, SIEM_PASS)

def _search_count(days: int) -> int:
    """
    Return count of docs older than now-{days}d.
    Treat alias-not-found (404) as 0 to be idempotent on fresh clusters.
    """
    url = urljoin(SIEM_URL.rstrip("/") + "/", f"{ALIAS}/_search")
    body: Dict[str, Any] = {
        "size": 0,
        "track_total_hits": True,
        "query": {"range": {"anchored_at": {"lt": f"now-{days}d"}}},
    }
    try:
        r = requests.post(url, auth=_auth(), json=body, verify=SIEM_VERIFY, timeout=20)
        if r.status_code == 404:
            return 0
        r.raise_for_status()
        data = r.json()
        total = data.get("hits", {}).get("total", 0)
        if isinstance(total, dict):
            return int(total.get("value", 0))
        return int(total or 0)
    except requests.HTTPError as e:
        if e.response is not None and e.response.status_code == 404:
            return 0
        raise

def _delete_by_query(days: int) -> Dict[str, Any]:
    """
    Delete docs older than now-{days}d.
    - If RET_ASYNC=1: submit as background task (wait_for_completion=false) with slices=auto (or RET_SLICES).
      Returns task info.
    - Else: run synchronously and return standard DBQ stats (deleted, took, batches, etc.).
    Gracefully treat alias-not-found (404) as a no-op.
    """
    url = urljoin(SIEM_URL.rstrip("/") + "/", f"{ALIAS}/_delete_by_query")
    body: Dict[str, Any] = {
        "query": {"range": {"anchored_at": {"lt": f"now-{days}d"}}},
        "conflicts": "proceed",
        "refresh": True,
    }
    params: Dict[str, Any] = {"slices": RET_SLICES}
    if RET_ASYNC:
        params["wait_for_completion"] = "false"

    try:
        r = requests.post(url, auth=_auth(), json=body, params=params, verify=SIEM_VERIFY, timeout=120)
        if r.status_code == 404:
            return {"deleted": 0, "note": "alias_not_found"}
        r.raise_for_status()
        return r.json()
    except requests.HTTPError as e:
        if e.response is not None and e.response.status_code == 404:
            return {"deleted": 0, "note": "alias_not_found"}
        raise

def main() -> None:
    ap = argparse.ArgumentParser(description="Purge old anchors by age.")
    ap.add_argument("--days", type=int, required=True, help="Delete anchors older than this many days.")
    ap.add_argument("--dry-run", action="store_true", help="Only count matching docs; do not delete.")
    args = ap.parse_args()

    try:
        count = _search_count(args.days)
        if args.dry_run:
            print(json.dumps({"alias": ALIAS, "days": args.days, "matches": count, "dry_run": True}, indent=2))
            return
        if count == 0:
            print(json.dumps({"alias": ALIAS, "days": args.days, "deleted": 0, "dry_run": False}, indent=2))
            return

        res = _delete_by_query(args.days)

        if RET_ASYNC and "task" in res:
            out = {
                "alias": ALIAS,
                "days": args.days,
                "submitted_task": res.get("task"),
                "slices": RET_SLICES,
                "async": True,
                "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            }
        else:
            out = {
                "alias": ALIAS,
                "days": args.days,
                "deleted": res.get("deleted", 0),
                "took_ms": res.get("took"),
                "batches": res.get("batches"),
                "slices": RET_SLICES,
                "async": False,
                "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            }
        print(json.dumps(out, indent=2))
    except requests.HTTPError as e:
        print(f"[anchors_retention] HTTP {e.response.status_code}: {e.response.text or '(no body)'}", file=sys.stderr)
        sys.exit(2)
    except Exception as e:
        print(f"[anchors_retention] ERROR: {e}", file=sys.stderr)
        sys.exit(2)

if __name__ == "__main__":
    main()