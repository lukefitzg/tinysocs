from __future__ import annotations
import os

# Re-export the real implementation that already lives under agent/
try:
    from .agent.netutil import is_loopback  # noqa: F401
except Exception:
    # Minimal fallback (never used if the above succeeds)
    def is_loopback(ip: str | None) -> bool:
        if not ip:
            return False
        s = str(ip).strip().lower()
        return s.startswith("127.0.") or s in {"::1", "0:0:0:0:0:0:0:1"}

def env_str(name: str, default: str | None = None) -> str | None:
    """Read an env var, returning default if unset/empty."""
    v = os.getenv(name)
    return v if v not in (None, "") else default

__all__ = ["is_loopback", "env_str"]
