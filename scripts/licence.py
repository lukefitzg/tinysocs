#!/usr/bin/env python3
"""Licence keys and tier entitlement for the content feed.

Implements docs/design/signed-feed.md -> "Part 4: Licence key and entitlement
gate". A licence key is a signed, self-describing token (mini-JWT shape):

    base64url(payload) + "." + base64url(ed25519_sign(payload))

so the agent can read its tier OFFLINE (for channel selection + UI) while the
feed server still verifies authenticity. The licensing keypair is SEPARATE from
the pack-signing keypair (different blast radius) -- by convention key-id
`licensing-2026`, managed by scripts/pack_sign.py gen-key.

This module is pure local logic: no Stripe, no network, no secrets beyond the
ed25519 keys on disk. The Stripe webhook that *issues* keys is designed but not
built (signed-feed.md -> Part 6).

Subcommands:
    issue       mint + sign a licence key for a tier
    inspect     verify a key and print its decoded payload + entitlement
    entitlement print the entitlement for a bare tier name (no key)

Demo:
    python3 scripts/pack_sign.py gen-key --key-id licensing-2026
    python3 scripts/licence.py issue --tier pro --sites 5 --sub cus_demo --key-id licensing-2026
    python3 scripts/licence.py inspect <key> --key-id licensing-2026
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
import time
from pathlib import Path

# Reuse the ed25519 key io from the signing tool -- same key format, same dir.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import pack_sign as ps  # noqa: E402

from cryptography.exceptions import InvalidSignature  # noqa: E402

TIERS = ("free", "pro", "msp")

# Default subscription period for a freshly-issued key (Stripe drives the real
# value; this is just the offline-demo default). 365 days.
_DEFAULT_PERIOD_DAYS = 365


# ---- entitlement (the pure function the whole gate hangs on) ----------------

def entitlement(tier: str) -> dict:
    """tier -> {packs, channel, premium}. Total, side-effect-free.

    Mirrors the table in signed-feed.md -> Part 4. Anything that isn't a known
    paid tier collapses to `free` -- billing state never hard-locks the agent.
    """
    if tier == "pro":
        return {"packs": ["base", "m365-pack", "persistence-premium"],
                "channel": "live", "premium": True}
    if tier == "msp":
        return {"packs": ["base", "m365-pack", "persistence-premium", "federation"],
                "channel": "live", "premium": True}
    # free + any unknown/expired/invalid input
    return {"packs": ["base"], "channel": "snapshot", "premium": False}


def can_access(tier: str, pack_id: str, channel: str) -> bool:
    """Server-side gate decision: may this tier pull this pack on this channel?"""
    ent = entitlement(tier)
    if pack_id not in ent["packs"]:
        return False
    if channel == "live" and ent["channel"] != "live":
        return False
    return True


# ---- token codec ------------------------------------------------------------

def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _canonical_payload(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def issue(tier: str, key_id: str, key_dir: Path, *, sub: str, sites: int,
          period_days: int = _DEFAULT_PERIOD_DAYS, now: int | None = None) -> str:
    if tier not in TIERS:
        raise ValueError(f"tier must be one of {TIERS}, got {tier!r}")
    now = int(now if now is not None else time.time())
    payload = {
        "k": key_id,
        "tier": tier,
        "sub": sub,
        "sites": sites,
        "iat": now,
        "exp": now + period_days * 86400,
        "nonce": _b64url(_os_random(9)),
    }
    priv = ps.load_private(key_dir, key_id)
    sig = priv.sign(_canonical_payload(payload))
    return _b64url(_canonical_payload(payload)) + "." + _b64url(sig)


def _os_random(n: int) -> bytes:
    import os
    return os.urandom(n)


def verify_key(token: str, key_dir: Path, *, now: int | None = None) -> tuple[bool, str, dict]:
    """Returns (ok, reason, payload). ok means signature valid AND not expired.

    An expired-but-authentic key returns ok=False with reason 'expired' but a
    populated payload, so the caller can apply grace (signed-feed.md -> grace).
    """
    try:
        p_b64, sig_b64 = token.strip().split(".", 1)
    except ValueError:
        return False, "malformed token", {}
    try:
        payload = json.loads(_b64url_decode(p_b64))
    except Exception:
        return False, "undecodable payload", {}

    key_id = payload.get("k")
    if not key_id:
        return False, "payload missing key_id", payload
    try:
        pub = ps.load_public(key_dir, key_id)
    except FileNotFoundError:
        return False, f"no public key for {key_id!r}", payload
    try:
        pub.verify(_b64url_decode(sig_b64), _canonical_payload(payload))
    except InvalidSignature:
        return False, "signature does not verify", payload

    now = int(now if now is not None else time.time())
    if payload.get("exp", 0) < now:
        return False, "expired", payload
    return True, "valid", payload


def effective_tier(token: str, key_dir: Path, *, grace_days: int = 14,
                   now: int | None = None) -> tuple[str, str]:
    """Resolve a token to the tier the agent should actually use, with grace.

    Returns (tier, note). Degrades freshness/breadth, never function:
      - valid               -> the key's tier
      - expired within grace -> the key's tier (still paid), note='grace'
      - expired past grace   -> 'free'
      - invalid / missing    -> 'free'
    """
    if not token:
        return "free", "no key"
    ok, reason, payload = verify_key(token, key_dir, now=now)
    if ok:
        return payload["tier"], "valid"
    if reason == "expired":
        now = int(now if now is not None else time.time())
        if payload.get("exp", 0) + grace_days * 86400 >= now:
            return payload.get("tier", "free"), "grace"
        return "free", "expired past grace"
    return "free", reason


# ---- subcommands ------------------------------------------------------------

def cmd_issue(args) -> int:
    token = issue(args.tier, args.key_id, Path(args.key_dir),
                  sub=args.sub, sites=args.sites)
    print(token)
    return 0


def cmd_inspect(args) -> int:
    ok, reason, payload = verify_key(args.token, Path(args.key_dir))
    print(f"signature/validity: {'OK' if ok else 'FAIL'} ({reason})")
    if payload:
        print("payload:")
        print(json.dumps(payload, indent=2, sort_keys=True))
    tier, note = effective_tier(args.token, Path(args.key_dir))
    ent = entitlement(tier)
    print(f"effective tier: {tier}  ({note})")
    print(f"entitlement: channel={ent['channel']} premium={ent['premium']} packs={ent['packs']}")
    return 0 if ok else 2


def cmd_entitlement(args) -> int:
    ent = entitlement(args.tier)
    print(json.dumps(ent, indent=2))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                      formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)

    i = sub.add_parser("issue", help="mint + sign a licence key")
    i.add_argument("--tier", required=True, choices=TIERS)
    i.add_argument("--sub", default="cus_demo", help="Stripe customer id (opaque)")
    i.add_argument("--sites", type=int, default=1)
    i.add_argument("--key-id", default="licensing-2026")
    i.add_argument("--key-dir", default=str(ps._DEFAULT_KEY_DIR))
    i.set_defaults(func=cmd_issue)

    n = sub.add_parser("inspect", help="verify a key + show entitlement")
    n.add_argument("token")
    n.add_argument("--key-id", default="licensing-2026")  # accepted, not required for verify
    n.add_argument("--key-dir", default=str(ps._DEFAULT_KEY_DIR))
    n.set_defaults(func=cmd_inspect)

    e = sub.add_parser("entitlement", help="print entitlement for a bare tier")
    e.add_argument("tier")
    e.set_defaults(func=cmd_entitlement)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
