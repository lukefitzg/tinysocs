#orchestrator/check_ledger.py
#!/usr/bin/env python3
"""
TinySocs — quick ledger health check across nodes.

Reads:
  - TINYSOCS_NODES           (comma-separated URLs; e.g. http://localhost:8081)
  - MASTER_SHARED_SECRET     (HMAC secret)

Usage:
  python tinysocs/orchestrator/check_ledger.py
"""
from __future__ import annotations
import os, time, hmac, hashlib, json
from typing import Dict, Any, List
import requests

NODES  = [x.strip() for x in (os.getenv("TINYSOCS_NODES","")).split(",") if x.strip()]
SECRET = os.getenv("MASTER_SHARED_SECRET", "dev-secret-change-me")

def _headers() -> Dict[str, str]:
    ts = int(time.time())
    mac = hmac.new((SECRET or "").encode("utf-8"), str(ts).encode("utf-8"), hashlib.sha256).hexdigest()
    return {"X-TinySOCS-Timestamp": str(ts), "X-TinySOCS-Signature": f"sha256={mac}"}

def main() -> None:
    if not NODES:
        raise SystemExit("Set TINYSOCS_NODES (comma-separated).")
    rows: List[Dict[str, Any]] = []
    for node in NODES:
        try:
            r = requests.get(
                f"{node.rstrip('/')}/evidence/head",
                headers=_headers(),
                timeout=6,
                verify=False if os.getenv("TINYSOCS_INSECURE_SKIP_VERIFY","1") == "1" else True,
            )
            if r.status_code == 501:
                rows.append({"node": node, "ok": None, "sequence": None, "head_sha256": None, "capability": "no-ledger"})
                continue
            r.raise_for_status()
            data = r.json()
            rows.append({
                "node": node,
                "ok": data.get("ok"),
                "sequence": data.get("sequence"),
                "head_sha256": data.get("head_sha256"),
                "capability": data.get("capability","ledger")
            })
        except Exception as e:
            rows.append({"node": node, "ok": False, "sequence": None, "head_sha256": None, "capability": f"error: {e}"})
    # pretty print
    print(json.dumps(rows, indent=2))

if __name__ == "__main__":
    main()