# tinysocs/agent/detections/engine.py
from __future__ import annotations

import os
import collections
import ipaddress
from typing import Any, Dict, List, Optional

import yaml

from tinysocs.agent.adapters.select import make_client
from tinysocs.agent.enrich import rdns

client = make_client()


def _rules_path(default: str = "rules.yaml") -> str:
    """
    Resolve rules.yaml in a stable order:
    1) TINYSOCS_RULES env var, if set
    2) <repo_root>/rules.yaml
    3) <repo_root>/detections/rules.yaml
    """
    env_path = os.getenv("TINYSOCS_RULES")
    if env_path and os.path.exists(env_path):
        return env_path

    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    root_candidate = os.path.join(repo_root, default)
    det_candidate = os.path.join(repo_root, "detections", default)

    if os.path.exists(root_candidate):
        return root_candidate
    if os.path.exists(det_candidate):
        return det_candidate

    return root_candidate


# -------------------------
# Helpers
# -------------------------
def _normalize_ip(raw: Any) -> Optional[str]:
    """Normalize loopback; pass through valid IPs/hostnames; tolerate None."""
    if raw in (None, "", "-"):
        return None
    s = str(raw).strip()
    if s in ("::1", "0:0:0:0:0:0:0:1"):
        return "127.0.0.1"
    try:
        ipaddress.ip_address(s)
        return s
    except ValueError:
        return s  # hostname or junk; return as-is


def _extract(doc: Dict[str, Any], path: str) -> Any:
    """Dot-path lookup with forgiveness."""
    cur: Any = doc
    for part in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def _short_sample(hits: List[Dict[str, Any]], limit: int = 10) -> List[Dict[str, Any]]:
    """Pretty sample for non-threshold rules (4688 etc)."""
    out: List[Dict[str, Any]] = []
    for h in hits[:limit]:
        ts = h.get("@timestamp") or "-"
        proc = (h.get("process") or {}).get("name") or "-"
        cmd = (
            (h.get("winlog") or {}).get("event_data", {}).get("CommandLine")
            or (h.get("process") or {}).get("command_line")
            or "-"
        )
        if isinstance(cmd, str) and len(cmd) > 140:
            cmd = cmd[:140] + "â€¦"
        out.append({"@timestamp": ts, "process": proc, "cmd": cmd})
    return out


def run_detections(rules_path: Optional[str] = None) -> List[Dict[str, Any]]:
    path = rules_path or _rules_path()
    print(f"[DEBUG] rules path -> {path}")
    with open(path, "r", encoding="utf-8") as f:
        rules = yaml.safe_load(f) or []

    findings: List[Dict[str, Any]] = []

    for r in rules:
        index = r.get("index", "")
        kql = r["kql"]
        hits = client.search_kql(index, kql, size=2000)
        print(f"[DEBUG] rule={r.get('id','(no-id)')} hits={len(hits)} index={index}")

        if r.get("threshold"):
            # Dynamic bucketing: default to (source.ip, user.name), but allow any list
            group_fields: List[str] = r.get("group_by") or ["source.ip", "user.name"]

            def key_for(doc: Dict[str, Any]) -> tuple:
                vals: List[Any] = []
                for fld in group_fields:
                    v = _extract(doc, fld)
                    # Normalize IP-ish fields
                    if fld.endswith(".ip"):
                        v = _normalize_ip(v)
                    vals.append(v)
                return tuple(vals)

            ctr = collections.Counter(key_for(doc) for doc in hits)

            # Debug top buckets
            top = sorted(ctr.items(), key=lambda kv: kv[1], reverse=True)[:3]
            if top:
                print(f"[DEBUG] top buckets: {top}")

            # Build findings for buckets over threshold
            for key_tuple, n in ctr.items():
                if n < r["threshold"]:
                    continue

                # Evidence map from group fields -> values
                ev: Dict[str, Any] = {}
                ip_for_rdns: Optional[str] = None
                for fld, val in zip(group_fields, key_tuple):
                    # Flatten known common names for readability
                    if fld == "source.ip":
                        ev["ip"] = val
                        ip_for_rdns = val or ip_for_rdns
                    elif fld == "user.name":
                        ev["user"] = val
                    else:
                        # generic, but readable key
                        ev[fld.replace(".", "_")] = val

                # rDNS if we have an IP
                if ip_for_rdns:
                    try:
                        ev["ip_rdns"] = rdns(ip_for_rdns)
                    except Exception:
                        ev["ip_rdns"] = None

                ev["count"] = n

                findings.append(
                    {
                        "rule": r["id"],
                        "summary": r["description"],
                        "evidence": ev,
                        "sample": hits[:10],  # raw sample; LLM/renderer can pretty it
                    }
                )

        else:
            if hits:
                findings.append(
                    {
                        "rule": r["id"],
                        "summary": r["description"],
                        "count": len(hits),
                        "sample": _short_sample(hits, 10),
                    }
                )

    return findings
