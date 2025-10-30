# tinysocs/orchestrator/anchors_rollover.py
#!/usr/bin/env python3
"""
TinySocs — anchors_rollover
Create a monthly backing index (tinysocs_anchors-YYYY.MM) with minimal mapping
and set it as the alias write index. Also sanitize the alias so only a single
write index exists.

Idempotent: if the monthly index exists, we only adjust alias routing.

Usage:
  python -m tinysocs.orchestrator.anchors_rollover
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List
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
                print(f"[anchors_rollover] WARN: dotenv load failed for {p}: {e}")
            break

_load_dotenv_inplace()
# ----------------------------------------------------------------------

ALIAS = os.getenv("TINYSOCS_ANCHORS_ALIAS", "tinysocs_anchors")

def _tls_verify_from(name: str, default: bool = True) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return str(v).strip().lower() not in ("0", "false", "no", "off")

SIEM_URL    = os.getenv("SIEM_URL", "https://localhost:9201")
SIEM_USER   = os.getenv("SIEM_USER", "admin")
SIEM_PASS   = os.getenv("SIEM_PASS", "admin")
SIEM_VERIFY = _tls_verify_from("SIEM_SSL_VERIFY", True)

# Silence TLS warnings when verify is disabled
try:
    import urllib3  # type: ignore
    if not SIEM_VERIFY:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass

def _auth() -> HTTPBasicAuth:
    return HTTPBasicAuth(SIEM_USER, SIEM_PASS)

def _index_exists(name: str) -> bool:
    r = requests.head(urljoin(SIEM_URL.rstrip('/')+'/', name), auth=_auth(), verify=SIEM_VERIFY, timeout=10)
    return r.status_code == 200

def _create_index(name: str) -> None:
    url = urljoin(SIEM_URL.rstrip('/')+'/', name)
    body: Dict[str, Any] = {
        # Dev-friendly settings: single node = no replicas to avoid yellow
        "settings": {
            "number_of_shards": 1,
            "number_of_replicas": 0
        },
        "mappings": {
            "properties": {
                "node": {"type": "keyword"},
                "node_url": {"type": "keyword"},
                "node_id": {"type": "keyword"},
                "ok": {"type": "boolean"},
                "head_sha256": {"type": "keyword"},
                "sequence": {"type": "long"},
                "capability": {"type": "keyword"},
                "anchored_at": {"type": "date"},
                "run": {
                    "properties": {
                        "rules": {"type": "keyword"},
                        "window": {"type": "keyword"},
                        "items": {"type": "integer"},
                        "privacy_mode": {"type": "keyword"},
                    }
                },
            }
        }
    }
    r = requests.put(url, auth=_auth(), json=body, verify=SIEM_VERIFY, timeout=20)
    r.raise_for_status()

def _get_alias_state(alias: str) -> Dict[str, Dict[str, Any]]:
    """Return {index: alias_meta} for all indices currently in alias."""
    url = urljoin(SIEM_URL.rstrip('/')+'/', f"_alias/{alias}")
    r = requests.get(url, auth=_auth(), verify=SIEM_VERIFY, timeout=20)
    if r.status_code == 404:
        return {}
    r.raise_for_status()
    data = r.json() or {}
    out: Dict[str, Dict[str, Any]] = {}
    for index, meta in data.items():
        aliases = meta.get("aliases", {})
        if alias in aliases:
            out[index] = aliases[alias] or {}
    return out

def _build_actions_to_sanitize(alias: str, new_index: str) -> List[Dict[str, Any]]:
    """
    Ensure only new_index is write for alias, others become non-write members.
    """
    actions: List[Dict[str, Any]] = []
    state = _get_alias_state(alias)
    # Flip any existing write index (that isn't the new one) to non-write
    for idx, meta in state.items():
        is_write = bool(meta.get("is_write_index"))
        if idx != new_index and is_write:
            actions.append({"add": {"index": idx, "alias": alias, "is_write_index": False}})
    # Finally ensure the target is write index
    actions.append({"add": {"index": new_index, "alias": alias, "is_write_index": True}})
    return actions

def _apply_alias(actions: List[Dict[str, Any]]) -> Dict[str, Any]:
    url = urljoin(SIEM_URL.rstrip('/')+'/', "_aliases")
    r = requests.post(url, auth=_auth(), json={"actions": actions}, verify=SIEM_VERIFY, timeout=30)
    r.raise_for_status()
    return r.json() if r.text else {"acknowledged": True}

def _apply_alias_with_fallback(new_index: str) -> Dict[str, Any]:
    """
    First try to sanitize by flipping old writes to non-write and add new.
    If the server still complains, hard reset: remove alias from all then re-add.
    """
    try:
        actions = _build_actions_to_sanitize(ALIAS, new_index)
        return _apply_alias(actions)
    except requests.HTTPError as e:
        text = (e.response.text or "").lower()
        if "more than one write index" not in text:
            raise
        # Hard reset path
        state = _get_alias_state(ALIAS)
        actions: List[Dict[str, Any]] = []
        for idx in state.keys():
            actions.append({"remove": {"index": idx, "alias": ALIAS}})
        # Re-add all previous indices as non-write
        for idx in state.keys():
            if idx != new_index:
                actions.append({"add": {"index": idx, "alias": ALIAS, "is_write_index": False}})
        # Add target as write
        actions.append({"add": {"index": new_index, "alias": ALIAS, "is_write_index": True}})
        return _apply_alias(actions)

def main() -> None:
    month_id = datetime.utcnow().strftime("%Y.%m")
    idx_name = f"{ALIAS}-{month_id}"
    created = False
    try:
        if not _index_exists(idx_name):
            _create_index(idx_name)
            created = True
        res = _apply_alias_with_fallback(idx_name)
        print(json.dumps({
            "alias": ALIAS,
            "index": idx_name,
            "created": created,
            "alias_ack": res.get("acknowledged", True),
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        }, indent=2))
    except requests.HTTPError as e:
        body = e.response.text or "(no body)"
        print(f"[anchors_rollover] HTTP {e.response.status_code}: {body}", file=sys.stderr)
        sys.exit(2)
    except Exception as e:
        print(f"[anchors_rollover] ERROR: {e}", file=sys.stderr)
        sys.exit(2)

if __name__ == "__main__":
    main()