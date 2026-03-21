# tinysocs/api/auth.py
"""
Centralized HMAC authentication for TinySocs API endpoints.

All endpoints that need HMAC verification should import from here
rather than implementing their own verification logic.

Supports three HMAC styles:
  - 'pipe': "{ts}|{nonce}"  (default)
  - 'dot':  "{ts}.{nonce}"
  - 'ts':   "{ts}" only

When verifying, the flexible mode tries all three formats so that
any caller style is accepted.

Replay protection uses a TTL-based dict cache with periodic garbage
collection.  The cache is per-process; in multi-worker deployments
a replay could succeed across workers.
"""

from __future__ import annotations

import hashlib
import hmac as _hmac
import time

from fastapi import HTTPException, Request

# ---------------------------------------------------------------------------
# Replay cache (in-process, TTL-based)
# ---------------------------------------------------------------------------
_replay_cache: dict[str, int] = {}       # signed_message -> expiry_epoch
_REPLAY_TTL_SECS = 300                   # 5 minutes
_GC_INTERVAL_SECS = 60
_last_gc: float = 0.0


def _gc(now: int) -> None:
    """Remove expired entries from the replay cache."""
    global _last_gc
    if now - _last_gc < _GC_INTERVAL_SECS:
        return
    _last_gc = now
    expired = [k for k, exp in _replay_cache.items() if exp <= now]
    for k in expired:
        _replay_cache.pop(k, None)


# ---------------------------------------------------------------------------
# Signature helpers
# ---------------------------------------------------------------------------

def _normalize_sig(sig: str) -> str:
    """Strip optional 'sha256=' prefix and whitespace."""
    sig = sig.strip()
    if sig.lower().startswith("sha256="):
        sig = sig.split("=", 1)[1]
    return sig.lower()


def _calc_mac(secret: str, msg: str) -> str:
    return _hmac.new(
        secret.encode("utf-8"),
        msg.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest().lower()


# ---------------------------------------------------------------------------
# Public verification helpers
# ---------------------------------------------------------------------------

def make_verify_hmac(
    secret: str,
    *,
    skew_secs: int = 300,
    replay_protect: bool = True,
):
    """
    Factory that returns a FastAPI dependency for HMAC verification.

    Parameters
    ----------
    secret : str
        The shared HMAC secret.
    skew_secs : int
        Allowed clock skew in seconds (default 300).
    replay_protect : bool
        Whether to enforce replay detection (default True).
    """

    async def verify_hmac(request: Request) -> None:
        ts_hdr = request.headers.get("X-TinySOCS-Timestamp", "").strip()
        sig_hdr = request.headers.get("X-TinySOCS-Signature", "").strip()
        nonce = request.headers.get("X-TinySOCS-Nonce", "").strip()

        if not ts_hdr or not sig_hdr:
            raise HTTPException(status_code=401, detail="Missing HMAC headers")

        # --- timestamp validation ---
        try:
            ts_int = int(ts_hdr)
        except ValueError:
            raise HTTPException(status_code=401, detail="Invalid timestamp")

        now = int(time.time())
        if abs(now - ts_int) > skew_secs:
            raise HTTPException(status_code=401, detail="Timestamp out of range")

        # --- build candidate messages (flexible: accept any style) ---
        candidates = [ts_hdr]                       # 'ts' style
        if nonce:
            candidates.append(f"{ts_hdr}|{nonce}")  # 'pipe' style
            candidates.append(f"{ts_hdr}.{nonce}")   # 'dot' style

        provided = _normalize_sig(sig_hdr)
        matched_msg = None
        for msg in candidates:
            calc = _calc_mac(secret, msg)
            if _hmac.compare_digest(calc, provided):
                matched_msg = msg
                break

        if matched_msg is None:
            raise HTTPException(status_code=401, detail="Bad signature")

        # --- replay detection ---
        if replay_protect:
            _gc(now)
            if matched_msg in _replay_cache and _replay_cache[matched_msg] > now:
                raise HTTPException(status_code=401, detail="Replay detected")
            _replay_cache[matched_msg] = now + _REPLAY_TTL_SECS

    return verify_hmac


def sign_request_headers(
    secret: str,
    *,
    style: str = "pipe",
    nonce: str = "",
) -> dict[str, str]:
    """
    Build HMAC signature headers for outbound requests.

    Returns a dict of headers to merge into the request.
    """
    import secrets as _secrets

    ts = str(int(time.time()))
    if not nonce and style != "ts":
        nonce = _secrets.token_hex(8)

    if style == "dot":
        msg = f"{ts}.{nonce}"
    elif style == "pipe":
        msg = f"{ts}|{nonce}"
    else:
        msg = ts

    sig = _calc_mac(secret, msg)

    headers: dict[str, str] = {
        "X-TinySOCS-Timestamp": ts,
        "X-TinySOCS-Signature": sig,
    }
    if nonce:
        headers["X-TinySOCS-Nonce"] = nonce
    return headers
