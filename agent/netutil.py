# netutil.py
from __future__ import annotations
from ipaddress import ip_address

def is_loopback(raw: str | None) -> bool:
    """
    True for IPv4/IPv6 loopback (127.0.0.0/8, ::1).
    Also returns True for redacted placeholders like '127.0.x.x'.
    """
    if not raw:
        return False

    s = raw.strip().lower()

    # tolerate redacted placeholders we emit (e.g. '127.0.x.x')
    if s.startswith("127.0.") and (".x." in s or s.endswith(".x")):
        return True
    if s in {"::1", "0:0:0:0:0:0:0:1"}:
        return True

    # try proper parsing
    try:
        return ip_address(s).is_loopback
    except ValueError:
        # Not a strict IP (maybe hostname). Fail safe = not loopback.
        return False
