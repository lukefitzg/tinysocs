"""Content-feed HTTP server: entitlement gate + Stripe licence issuance.

DORMANT (2026-08-18): the paid-feed strategy was abandoned before this server was
ever deployed; see docs/design/strategy-zero-support.md. Retained with passing
tests as the reopening option on inbound demand. Not installed as a console
script; not part of the free release. Don't extend, don't delete.

Implements docs/design/signed-feed.md -> Part 4.5 (feed server auth layer) and
Part 6 (Stripe -> licence issuance) as one small always-on FastAPI app. Two
routers, one process -- a part-time founder runs one thing:

  feed router    GET /feed/{pack_id}/{channel}
                 - reads the licence token from a header
                 - runs the SAME gate the agent uses (scripts/licence.py) plus a
                   server-only revocation check
                 - on allow: 302 -> a short-TTL signed URL for the exact pack
                 - the bytes themselves come from the blob route (a stand-in for
                   the CDN/object store; in production the redirect points at
                   S3/R2 and this app never touches pack payload)

  stripe router  POST /stripe/webhook
                 - verifies the Stripe-Signature HMAC (no Stripe SDK)
                 - maps price_id -> tier, quantity -> sites (scripts/stripe_pricing.py)
                 - mints + signs a licence key (scripts/licence.py issue)
                 - records the nonce for revocation; updates/cancels revoke first

The licensing decision is code we control (immediate revocation, stateful
checks); the bulk bytes are a dumb static serve. `metadata.tier` in a pack is
advisory -- this server is the truth.

No secrets in the repo: the URL-signing secret, the Stripe webhook secret, the
Stripe price ids, and the signing keys all come from the environment. Run:

    TINYSOCS_FEED_URL_SECRET=... TINYSOCS_STRIPE_WEBHOOK_SECRET=... \\
    python -m tinysocs.api.feed
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sys
import time
from pathlib import Path

from fastapi import APIRouter, FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse

from tinysocs.api.feed_store import LicenceStore
from tinysocs.env import load_dotenv_if_present

# Reuse the CLI trust primitives verbatim -- same decision on server and agent.
# They live under scripts/ (not the installed package); add it to the path the
# way scripts/licence.py already imports scripts/pack_sign.py.
_REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(_REPO_ROOT / "scripts"))
import licence as lic  # noqa: E402
import stripe_pricing as pricing  # noqa: E402

load_dotenv_if_present(_REPO_ROOT)

# ---- configuration (all from env; no secrets, prices, or keys in code) ------

_KEY_DIR = Path(os.getenv("TINYSOCS_KEY_DIR", str(_REPO_ROOT / "keys")))
_PACKS_DIR = Path(os.getenv("TINYSOCS_PACKS_DIR", str(_REPO_ROOT / "packs")))
_LICENSING_KEY_ID = os.getenv("TINYSOCS_LICENSING_KEY_ID", "licensing-2026")
_URL_TTL_SECS = int(os.getenv("TINYSOCS_FEED_URL_TTL", "120"))
_GRACE_DAYS = int(os.getenv("TINYSOCS_GRACE_DAYS", "14"))

_store = LicenceStore()

feed_router = APIRouter()
stripe_router = APIRouter()


# ---- short-TTL signed URLs (HMAC stand-in for an object-store signer) --------

def _url_secret() -> str:
    secret = os.getenv("TINYSOCS_FEED_URL_SECRET", "").strip()
    if not secret:
        # Fail closed: without a signing secret we cannot mint trustworthy URLs.
        raise HTTPException(status_code=503, detail="feed URL signing not configured")
    return secret


def _sign_blob_url(pack_id: str, version: str, exp: int) -> str:
    msg = f"{pack_id}/{version}/{exp}"
    sig = hmac.new(_url_secret().encode(), msg.encode(), hashlib.sha256).hexdigest()
    return f"/feed/blob/{pack_id}/{version}/pack.yml?exp={exp}&sig={sig}"


def _verify_blob_url(pack_id: str, version: str, exp: int, sig: str) -> bool:
    if exp < int(time.time()):
        return False
    msg = f"{pack_id}/{version}/{exp}"
    want = hmac.new(_url_secret().encode(), msg.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(want, sig)


# ---- version resolution (index.json pointer, with a filesystem fallback) -----

def _resolve_version(pack_id: str, channel: str) -> str | None:
    """live -> newest version; snapshot -> the deliberately-lagged pointer.

    Prefers packs/{pack_id}/index.json ({latest, snapshot, versions}). Falls
    back to scanning version directories so the demo works before an index is
    published: latest = max version, snapshot = the previous one (or latest if
    only one exists).
    """
    pack_dir = _PACKS_DIR / pack_id
    index = pack_dir / "index.json"
    if index.exists():
        try:
            data = json.loads(index.read_text(encoding="utf-8"))
            return data.get("latest" if channel == "live" else "snapshot")
        except (ValueError, OSError):
            pass

    if not pack_dir.is_dir():
        return None
    versions = sorted(p.name for p in pack_dir.iterdir() if p.is_dir())
    if not versions:
        return None
    if channel == "live":
        return versions[-1]
    return versions[-2] if len(versions) >= 2 else versions[-1]


# ---- the gate (exactly scripts/licence.py, server-side + revocation) ---------

def _resolve_tier(licence_key: str) -> tuple[str, str | None]:
    """Return (tier, nonce) for a presented key, applying grace and never
    hard-locking. nonce is needed for the revocation check."""
    if not licence_key:
        return "free", None
    ok, reason, payload = lic.verify_key(licence_key, _KEY_DIR)
    nonce = payload.get("nonce") if payload else None
    if ok:
        return payload.get("tier", "free"), nonce
    if reason == "expired":
        tier, _ = lic.effective_tier(licence_key, _KEY_DIR, grace_days=_GRACE_DAYS)
        return tier, nonce
    return "free", nonce


@feed_router.get("/feed/{pack_id}/{channel}")
def feed_mint(pack_id: str, channel: str,
              x_tinysocs_licence: str = Header(default="")):
    if channel not in ("live", "snapshot"):
        raise HTTPException(status_code=400, detail="channel must be live or snapshot")

    tier, nonce = _resolve_tier(x_tinysocs_licence)
    if _store.is_revoked(nonce):
        tier = "free"  # killed mid-period; offline token can't self-revoke

    if not lic.can_access(tier, pack_id, channel):
        raise HTTPException(
            status_code=403,
            detail=f"tier '{tier}' not entitled to '{pack_id}' on '{channel}'")

    version = _resolve_version(pack_id, channel)
    if version is None:
        raise HTTPException(status_code=404, detail=f"no pack for {pack_id}/{channel}")

    exp = int(time.time()) + _URL_TTL_SECS
    url = _sign_blob_url(pack_id, version, exp)
    # 302: the agent follows it to the (stand-in) object store. The redirect
    # proves entitlement; the pack's own ed25519 signature proves authenticity.
    return RedirectResponse(url=url, status_code=302)


@feed_router.get("/feed/blob/{pack_id}/{version}/pack.yml")
def feed_blob(pack_id: str, version: str, exp: int, sig: str):
    """Stand-in for the CDN/object store: serve pack bytes behind a signed URL.

    In production the mint redirect points straight at S3/R2 and this route does
    not exist -- it is here so the feed is demoable end-to-end without cloud
    infra. The agent loads pack.yml.canonical, so serve that when present.
    """
    if not _verify_blob_url(pack_id, version, exp, sig):
        raise HTTPException(status_code=403, detail="invalid or expired signed URL")
    base = _PACKS_DIR / pack_id / version
    canonical = base / "pack.yml.canonical"
    target = canonical if canonical.exists() else base / "pack.yml"
    if not target.exists():
        raise HTTPException(status_code=404, detail="pack bytes not found")
    return FileResponse(target, media_type="application/octet-stream",
                        filename=f"{pack_id}-{version}-pack.yml")


# ---- Stripe webhook (signature verify without the Stripe SDK) ----------------

def _verify_stripe_signature(payload: bytes, sig_header: str, secret: str,
                             *, tolerance_secs: int = 300) -> bool:
    """Verify a Stripe-Signature header: 't=<ts>,v1=<hexmac>[,v1=...]'.

    signed_payload = '{t}.{raw_body}', HMAC-SHA256 with the webhook secret.
    Mirrors Stripe's own scheme so we need no Stripe library to authenticate the
    event. Constant-time compare; any v1 candidate may match (key rotation).
    """
    if not sig_header or not secret:
        return False
    parts = dict(
        kv.split("=", 1) for kv in sig_header.split(",") if "=" in kv
    )
    ts = parts.get("t", "")
    if not ts.isdigit():
        return False
    if abs(int(time.time()) - int(ts)) > tolerance_secs:
        return False
    signed = f"{ts}.".encode() + payload
    want = hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()
    candidates = [v for k, v in (
        kv.split("=", 1) for kv in sig_header.split(",") if "=" in kv
    ) if k == "v1"]
    return any(hmac.compare_digest(want, c) for c in candidates)


@stripe_router.post("/stripe/webhook")
async def stripe_webhook(request: Request,
                         stripe_signature: str = Header(default="")):
    secret = os.getenv("TINYSOCS_STRIPE_WEBHOOK_SECRET", "").strip()
    if not secret:
        raise HTTPException(status_code=503, detail="stripe webhook not configured")

    body = await request.body()
    if not _verify_stripe_signature(body, stripe_signature, secret):
        raise HTTPException(status_code=401, detail="bad stripe signature")

    try:
        event = json.loads(body)
    except ValueError:
        raise HTTPException(status_code=400, detail="event is not JSON")

    etype = event.get("type", "")
    obj = event.get("data", {}).get("object", {})
    customer = obj.get("customer", "")

    if etype == "customer.subscription.deleted":
        revoked = _store.revoke_subscription(customer)
        return JSONResponse({"ok": True, "action": "revoked", "nonces": revoked})

    if etype in ("customer.subscription.created", "customer.subscription.updated"):
        item = _first_item(obj)
        if item is None:
            raise HTTPException(status_code=400, detail="subscription has no items")
        price_id = item.get("price", {}).get("id", "")
        quantity = int(item.get("quantity", 1))
        period_end = int(obj.get("current_period_end", 0))

        req = pricing.resolve_subscription(price_id, quantity, customer, period_end)
        if req.tier == "free":
            # Unknown price id -> nothing to sell. Don't mint a free "key".
            raise HTTPException(status_code=422,
                                detail=f"price '{price_id}' not in configured price map")

        # An update supersedes the prior key for this customer: revoke first.
        _store.revoke_subscription(customer)
        token = lic.issue(req.tier, _LICENSING_KEY_ID, _KEY_DIR,
                          sub=req.sub, sites=req.sites, exp=req.exp)
        _, _, payload = lic.verify_key(token, _KEY_DIR)
        _store.record_issue(payload, token)
        return JSONResponse({
            "ok": True, "action": "issued",
            "tier": req.tier, "sites": req.sites,
            "licence_key": token,  # demo: real flow emails / dashboard-delivers
        })

    # Events we don't act on (payment_failed etc.) are acknowledged, not errored
    # -- a 2xx tells Stripe to stop retrying.
    return JSONResponse({"ok": True, "action": "ignored", "type": etype})


def _first_item(subscription: dict) -> dict | None:
    items = subscription.get("items", {}).get("data", [])
    return items[0] if items else None


# ---- app + launcher ----------------------------------------------------------

def create_app() -> FastAPI:
    app = FastAPI(title="TinySOCs Content Feed", version="0.1.0")
    app.include_router(feed_router)
    app.include_router(stripe_router)

    @app.get("/healthz")
    def healthz() -> dict:
        return {"ok": True, "packs_dir": str(_PACKS_DIR)}

    return app


app = create_app()


def cli() -> None:
    import uvicorn

    port = int(os.getenv("FEED_PORT", "8095"))
    host = os.getenv("HOST", "0.0.0.0")
    loglvl = os.getenv("UVICORN_LOG_LEVEL", "info")
    print(f"[feed] serving packs from {_PACKS_DIR} on {host}:{port}", flush=True)
    uvicorn.run(app, host=host, port=port, log_level=loglvl)


if __name__ == "__main__":
    cli()
