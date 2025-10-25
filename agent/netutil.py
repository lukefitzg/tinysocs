# tinysocs/agent/netutil.py
"""
Compat shim + loopback helper.

- If the canonical module `tinysocs.netutil` exists, re-export from there
  to keep one source of truth across the codebase.
- Otherwise, fall back to a local, robust `is_loopback` implementation that:
    * treats IPv4 127.0.0.0/8 and IPv6 ::1 as loopback
    * tolerates redacted placeholders like '127.0.x.x'
    * strips IPv6 zone IDs (e.g., 'fe80::1%eth0')
    * handles IPv4-mapped IPv6 (e.g., '::ffff:127.0.0.1')
"""

from __future__ import annotations

# 1) Prefer the canonical implementation if present
try:
    # re-export everything so legacy imports continue to work:
    #   from tinysocs.agent.netutil import is_loopback
    from ..netutil import *  # type: ignore  # noqa: F401,F403
except Exception:
    # 2) Fallback: local implementation
    from ipaddress import ip_address, IPv6Address

    __all__ = ["is_loopback"]

    def is_loopback(raw: str | None) -> bool:
        """
        True for IPv4/IPv6 loopback (127.0.0.0/8, ::1).
        Also returns True for redacted placeholders like '127.0.x.x'.
        IPv6 zone IDs are ignored. IPv4-mapped IPv6 loopback is treated as loopback.
        """
        if not raw:
            return False

        s = raw.strip().lower()

        # tolerate redacted placeholders we sometimes emit (e.g. '127.0.x.x', '127.0.0.x')
        if s.startswith("127.0.") and ("x" in s):
            return True

        # common literal loopback strings
        if s in {"::1", "0:0:0:0:0:0:0:1"}:
            return True

        # strip IPv6 zone id if present (e.g., '::1%lo0')
        if "%" in s:
            s = s.split("%", 1)[0]

        # proper parse
        try:
            addr = ip_address(s)
            if addr.is_loopback:
                return True
            # Consider IPv4-mapped IPv6 (e.g., ::ffff:127.0.0.1) as loopback if mapped part is loopback
            if isinstance(addr, IPv6Address):
                v4 = addr.ipv4_mapped
                if v4 is not None and v4.is_loopback:
                    return True
            return False
        except ValueError:
            # Not a strict IP (maybe hostname). Fail safe = not loopback.
            return False