# tinysocs/agent/privacy.py
from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any, Dict, List, Set

_email_re = re.compile(r"\b([A-Za-z0-9._%+-])([A-Za-z0-9._%+-]*?)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")
_ipv4_re  = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_userish_re = re.compile(r"(?i)\b(user|usr|account|acct|login|owner|u|samaccountname)\b[:=]\s*([A-Za-z0-9._-]+)")
_hostname_re = re.compile(r"\b([A-Za-z0-9][A-Za-z0-9._-]{1,63})\b")

def mask_email(s: str) -> str:
    def _m(m):
        first = m.group(1)
        rest  = m.group(2)
        dom   = m.group(3)
        return f"{first}***@{dom}"
    return _email_re.sub(_m, s)

def _ip_to_cidr24(ip: str) -> str:
    parts = ip.split(".")
    if len(parts) == 4:
        return ".".join(parts[:3]) + ".0/24"
    return ip

def coarse_mask(s: str) -> str:
    if not s: return s
    s2 = mask_email(s)
    s2 = _ipv4_re.sub(lambda m: _ip_to_cidr24(m.group(0)), s2)
    return s2

def mask_entities(evidences: Iterable[Dict[str, Any]]) -> Dict[str, List[str]]:
    users: Set[str] = set()
    hosts: Set[str] = set()
    for e in evidences:
        # pull from summaries if present, otherwise exemplars
        summ = e.get("summary") or {}
        # common buckets
        for u in summ.get("top_users", []) or []:
            users.add(str(u))
        for ex in e.get("exemplars") or []:
            fields = ex.get("fields") or {}
            if fields.get("user.name"): users.add(str(fields["user.name"]))
            if fields.get("host"):      hosts.add(str(fields["host"]))
        # try free-form message too
        for ex in e.get("exemplars") or []:
            msg = (ex.get("message") or "")[:500]
            for m in _email_re.finditer(msg):
                users.add(m.group(1) + "***@" + m.group(3))
            for m in _userish_re.finditer(msg):
                users.add(str(m.group(2)))
            for m in _hostname_re.finditer(msg):
                h = m.group(1)
                if "." in h or "-" in h: hosts.add(h)

    # render masked lists
    masked_users = sorted({ coarse_mask(u) for u in users })
    masked_hosts = sorted({ coarse_mask(h) for h in hosts })
    return {"users": masked_users[:20], "hosts": masked_hosts[:20]}

def extract_tokens(evidences: Iterable[Dict[str, Any]]) -> Dict[str, List[str]]:
    procs: Set[str] = set()
    nets:  Set[str] = set()
    for e in evidences:
        for ex in e.get("exemplars") or []:
            fields = ex.get("fields") or {}
            if fields.get("process.name"): procs.add(str(fields["process.name"]))
            msg = (ex.get("message") or "")[:500]
            for m in _ipv4_re.finditer(msg):
                nets.add(_ip_to_cidr24(m.group(0)))
    return {
        "process_names": sorted(list(procs))[:20],
        "networks": sorted(list(nets))[:20]
    }
