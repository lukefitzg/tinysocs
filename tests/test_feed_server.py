"""Feed server: entitlement gate, signed-URL serving, and Stripe issuance.

Mirrors docs/design/signed-feed.md Part 4.5 + Part 6. Uses the repo's real demo
licensing key (keys/licensing-2026) to mint tokens and a temp store so nothing
touches operational state. No Stripe account, no network.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sys
import time
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[1]

# Configure the server BEFORE importing it (module reads env at import time).
os.environ["TINYSOCS_FEED_URL_SECRET"] = "test-url-secret"
os.environ["TINYSOCS_STRIPE_WEBHOOK_SECRET"] = "whsec_test"
os.environ["TINYSOCS_PRICE_PRO"] = "price_test_pro"
os.environ["TINYSOCS_FEED_STORE"] = str(_REPO_ROOT / "data" / "feed" / "_pytest_store.json")

sys.path.insert(0, str(_REPO_ROOT / "scripts"))
import licence as lic  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from tinysocs.api import feed  # noqa: E402

_KEY_DIR = _REPO_ROOT / "keys"


def _ensure_test_signing_key() -> None:
    """Generate the licensing-2026 ed25519 keypair if it isn't already present.

    keys/ is gitignored (private keys never live in the repo — see CLAUDE.md),
    so a clean checkout (CI, a fresh clone) has no key on disk. On a dev
    machine that already generated one via `pack_sign.py gen-key`, this is a
    no-op and the existing key is reused.
    """
    import base64

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    priv_path = _KEY_DIR / "licensing-2026.key"
    pub_path = _KEY_DIR / "licensing-2026.pub"
    if priv_path.exists() and pub_path.exists():
        return

    _KEY_DIR.mkdir(parents=True, exist_ok=True)
    priv = Ed25519PrivateKey.generate()
    priv_raw = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_raw = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    priv_path.write_text(base64.b64encode(priv_raw).decode(), encoding="utf-8")
    priv_path.chmod(0o600)
    pub_path.write_text(base64.b64encode(pub_raw).decode(), encoding="utf-8")


_ensure_test_signing_key()


@pytest.fixture(autouse=True)
def _clean_store():
    store_path = Path(os.environ["TINYSOCS_FEED_STORE"])
    store_path.parent.mkdir(parents=True, exist_ok=True)
    if store_path.exists():
        store_path.unlink()
    feed._store = feed.LicenceStore(store_path)
    yield
    if store_path.exists():
        store_path.unlink()


@pytest.fixture
def client():
    return TestClient(feed.app, follow_redirects=False)


def _pro_token() -> str:
    exp = int(time.time()) + 86400
    return lic.issue("pro", "licensing-2026", _KEY_DIR, sub="cus_x", sites=1, exp=exp)


def _sign_stripe(body: bytes) -> str:
    ts = int(time.time())
    signed = f"{ts}.".encode() + body
    mac = hmac.new(b"whsec_test", signed, hashlib.sha256).hexdigest()
    return f"t={ts},v1={mac}"


# ---- entitlement gate -------------------------------------------------------

def test_free_denied_premium_live(client):
    r = client.get("/feed/persistence-premium/live")
    assert r.status_code == 403


def test_free_gets_base_snapshot(client):
    r = client.get("/feed/base/snapshot")
    assert r.status_code == 302
    blob = r.headers["location"]
    got = client.get(blob)
    assert got.status_code == 200
    assert len(got.content) > 0


def test_pro_token_unlocks_live(client):
    r = client.get("/feed/base/live",
                   headers={"X-TinySOCS-Licence": _pro_token()})
    assert r.status_code == 302


def test_free_cannot_pull_base_live(client):
    # base exists for free but only on the snapshot channel.
    r = client.get("/feed/base/live")
    assert r.status_code == 403


def test_tampered_signed_url_rejected(client):
    r = client.get("/feed/base/snapshot")
    blob = r.headers["location"]
    tampered = blob.replace("sig=", "sig=deadbeef")
    assert client.get(tampered).status_code == 403


def test_expired_signed_url_rejected(client):
    # Hand-mint a URL that expired in the past.
    url = feed._sign_blob_url("base", "2026.23", int(time.time()) - 1)
    assert client.get(url).status_code == 403


# ---- Stripe webhook ---------------------------------------------------------

def _subscription_event(etype: str, *, price="price_test_pro", qty=1,
                        customer="cus_acme", period_end=None) -> dict:
    period_end = period_end or int(time.time()) + 30 * 86400
    return {
        "type": etype,
        "data": {"object": {
            "customer": customer,
            "current_period_end": period_end,
            "items": {"data": [{"price": {"id": price}, "quantity": qty}]},
        }},
    }


def test_webhook_requires_signature(client):
    body = json.dumps(_subscription_event("customer.subscription.created")).encode()
    r = client.post("/stripe/webhook", content=body)
    assert r.status_code == 401


def test_webhook_bad_signature(client):
    body = json.dumps(_subscription_event("customer.subscription.created")).encode()
    r = client.post("/stripe/webhook", content=body,
                    headers={"Stripe-Signature": "t=1,v1=bad"})
    assert r.status_code == 401


def test_webhook_issues_usable_key(client):
    body = json.dumps(_subscription_event("customer.subscription.created")).encode()
    r = client.post("/stripe/webhook", content=body,
                    headers={"Stripe-Signature": _sign_stripe(body)})
    assert r.status_code == 200
    token = r.json()["licence_key"]
    assert r.json()["tier"] == "pro"

    # The freshly-minted key unlocks the live channel.
    g = client.get("/feed/base/live", headers={"X-TinySOCS-Licence": token})
    assert g.status_code == 302


def test_webhook_unknown_price_rejected(client):
    body = json.dumps(
        _subscription_event("customer.subscription.created", price="price_nope")
    ).encode()
    r = client.post("/stripe/webhook", content=body,
                    headers={"Stripe-Signature": _sign_stripe(body)})
    assert r.status_code == 422


def test_subscription_deleted_revokes(client):
    # Issue, confirm it works, then cancel -> the key falls back to free.
    body = json.dumps(_subscription_event("customer.subscription.created")).encode()
    issued = client.post("/stripe/webhook", content=body,
                         headers={"Stripe-Signature": _sign_stripe(body)})
    token = issued.json()["licence_key"]
    assert client.get("/feed/base/live",
                      headers={"X-TinySOCS-Licence": token}).status_code == 302

    cancel = json.dumps(
        _subscription_event("customer.subscription.deleted")
    ).encode()
    r = client.post("/stripe/webhook", content=cancel,
                    headers={"Stripe-Signature": _sign_stripe(cancel)})
    assert r.status_code == 200
    assert r.json()["action"] == "revoked"

    # Same token now downgraded to free (revoked nonce) -> denied the live channel.
    assert client.get("/feed/base/live",
                      headers={"X-TinySOCS-Licence": token}).status_code == 403
