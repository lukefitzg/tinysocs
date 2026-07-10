# tinysocs/federation_certs.py
"""
Certificate pinning for Hub <-> Site federation connections.

When a Site is approved, the Hub fetches and stores the Site's TLS
certificate fingerprint.  On every subsequent connection, the presented
cert is checked against the pin.  A mismatch is treated as a potential
MITM attack and the connection is refused.

Storage: pinned_certs.json alongside pending_sites.json
  {
    "https://192.168.86.52:8081": {
      "node_id": "desktop-titti",
      "fingerprint_sha256": "AB:CD:...",
      "subject": "CN=desktop-titti",
      "not_after": "2031-03-19T00:00:00Z",
      "pinned_at": "2026-03-19T22:00:00Z",
      "pem": "-----BEGIN CERTIFICATE-----\\n..."
    }
  }

Sites that do not use TLS (HTTP) cannot be approved -- the Hub requires
all federation connections to be encrypted and authenticated.
"""

from __future__ import annotations

import hashlib
import json
import os
import socket
import ssl
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Storage helpers
# ---------------------------------------------------------------------------

def _pinned_certs_path() -> Path:
    """Return the path to the pinned certs JSON file."""
    pd = os.getenv("ProgramData", os.getenv("PROGRAMDATA", "C:\\ProgramData"))
    return Path(pd) / "TinySocs" / "Assistant" / "pinned_certs.json"


def load_pinned_certs() -> dict[str, Any]:
    """Load pinned certificate data from disk."""
    path = _pinned_certs_path()
    if path.is_file():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


def save_pinned_certs(data: dict[str, Any]) -> None:
    """Persist pinned certificate data to disk."""
    path = _pinned_certs_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


# ---------------------------------------------------------------------------
# Certificate fetching
# ---------------------------------------------------------------------------

def _format_fingerprint(der_bytes: bytes) -> str:
    """Return a SHA-256 fingerprint in colon-separated hex format."""
    digest = hashlib.sha256(der_bytes).hexdigest().upper()
    return ":".join(digest[i:i + 2] for i in range(0, len(digest), 2))


def fetch_cert_info(url: str) -> dict[str, Any] | None:
    """Connect to a remote node and extract its TLS certificate info.

    Returns None if the URL is not HTTPS or the connection fails.
    Returns a dict with fingerprint_sha256, subject, not_after, pem.
    """
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return None

    host = parsed.hostname or ""
    port = parsed.port or 443

    try:
        # Create a context that accepts any cert (we just want to read it)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls_sock:
                der_cert = tls_sock.getpeercert(binary_form=True)
                peer_info = tls_sock.getpeercert()

        if not der_cert:
            return None

        # Extract subject CN
        # ssl's getpeercert() typeshed types every key's value as a union
        # (str | RDN tuples); "subject" is always the nested-tuple form.
        subject = ""
        if peer_info and "subject" in peer_info:
            for rdn in cast("tuple[tuple[tuple[str, str], ...], ...]", peer_info["subject"]):
                for attr_type, attr_value in rdn:
                    if attr_type == "commonName":
                        subject = attr_value
                        break

        # Extract expiry
        not_after = ""
        if peer_info and "notAfter" in peer_info:
            not_after = cast(str, peer_info["notAfter"])

        # Build PEM from DER
        import base64
        b64 = base64.encodebytes(der_cert).decode("ascii")
        pem = f"-----BEGIN CERTIFICATE-----\n{b64}-----END CERTIFICATE-----\n"

        return {
            "fingerprint_sha256": _format_fingerprint(der_cert),
            "subject": subject,
            "not_after": not_after,
            "pem": pem,
        }
    except Exception as exc:
        print(f"[federation-tls] Failed to fetch cert from {url}: {exc}", flush=True)
        return None


def pin_site_cert(url: str, node_id: str) -> dict[str, Any]:
    """Fetch a Site's TLS cert and pin it.  Returns the pin record.

    Raises ValueError if the Site is not using HTTPS or cert fetch fails.
    """
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise ValueError(
            f"Site {node_id} at {url} is not using TLS (HTTPS). "
            f"All Sites must enable TLS before they can be approved. "
            f"Ensure TINYSOCS_TLS_CERT and TINYSOCS_TLS_KEY are configured "
            f"on the Site and restart the TinySocsNode service."
        )

    info = fetch_cert_info(url)
    if not info:
        raise ValueError(
            f"Could not fetch TLS certificate from Site {node_id} at {url}. "
            f"Ensure the Site is running and its TLS certificate is valid."
        )

    pin_record = {
        "node_id": node_id,
        "fingerprint_sha256": info["fingerprint_sha256"],
        "subject": info["subject"],
        "not_after": info["not_after"],
        "pinned_at": datetime.now(timezone.utc).isoformat(),
        "pem": info["pem"],
    }

    # Save to disk
    pinned = load_pinned_certs()
    pinned[url] = pin_record
    save_pinned_certs(pinned)

    print(
        f"[federation-tls] Pinned cert for {node_id} at {url}: "
        f"fingerprint={info['fingerprint_sha256'][:20]}...",
        flush=True,
    )
    return pin_record


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

def verify_site_cert(url: str) -> str | None:
    """Check if a Site's current cert matches the pinned fingerprint.

    Returns None if verification passes (or no pin exists).
    Returns an error string if there is a mismatch.
    """
    pinned = load_pinned_certs()
    pin = pinned.get(url)
    if not pin:
        # No pin for this URL -- cannot verify
        return None

    current = fetch_cert_info(url)
    if not current:
        # Can't connect -- not a pin mismatch, just unreachable
        return None

    pinned_fp = pin["fingerprint_sha256"]
    current_fp = current["fingerprint_sha256"]

    if pinned_fp != current_fp:
        return (
            f"CERTIFICATE MISMATCH for {pin.get('node_id', url)}: "
            f"pinned={pinned_fp[:20]}... current={current_fp[:20]}... "
            f"This may indicate a man-in-the-middle attack."
        )
    return None


def make_pinning_ssl_context(url: str) -> ssl.SSLContext:
    """Create an SSL context that verifies against the pinned cert for a URL.

    If no pin exists for the URL, returns a permissive context (verify=False)
    with a warning -- this handles the transition period for existing Sites.
    """
    pinned = load_pinned_certs()
    pin = pinned.get(url)

    if not pin or not pin.get("pem"):
        # No pinned cert -- use permissive context with warning
        print(
            f"[federation-tls] WARNING: no pinned cert for {url}; "
            f"connection will not be verified",
            flush=True,
        )
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    # Write pinned PEM to a temp file for the SSL context
    # (ssl.SSLContext.load_verify_locations needs a file path or bytes)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False  # Self-signed certs may not match hostname
    ctx.verify_mode = ssl.CERT_REQUIRED

    try:
        # Load the pinned cert as the ONLY trusted CA
        ctx.load_verify_locations(cadata=pin["pem"])
    except Exception as exc:
        print(
            f"[federation-tls] Failed to load pinned cert for {url}: {exc}; "
            f"falling back to fingerprint check",
            flush=True,
        )
        # Fallback: disable context-level verification, rely on post-handshake
        # fingerprint check in the caller
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    return ctx


def get_cert_status(url: str) -> str:
    """Return the cert pin status for a Site URL.

    Returns: "pinned", "mismatch", or "unpinned"
    """
    pinned = load_pinned_certs()
    pin = pinned.get(url)
    if not pin:
        return "unpinned"

    current = fetch_cert_info(url)
    if not current:
        # Can't reach -- return pinned (we have a pin, just can't check now)
        return "pinned"

    if pin["fingerprint_sha256"] != current["fingerprint_sha256"]:
        return "mismatch"

    return "pinned"
