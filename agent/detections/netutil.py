# agent/netutil.py
import ipaddress

def is_loopback(ip: str) -> bool:
    """
    Treat obvious redactions like 127.0.x.x as loopback; support IPv6 and v4-mapped too.
    """
    if not ip:
        return False
    try:
        # crude but effective: catch redacted localhost variants
        if ip.startswith("127.0.") or ip in {"127.0.x.x"}:
            return True
        # strip zone id from IPv6 if present
        ip_clean = ip.split("%")[0]
        ip_obj = ipaddress.ip_address(ip_clean)
        return ip_obj.is_loopback
    except ValueError:
        # e.g. 'kubernetes.docker.internal' — not an IP; treat as non-loopback
        return False
