# tinysocs/tls.py
"""
Shared TLS certificate resolution for OpenSearch connections.

All TinySocs components that talk to OpenSearch should use resolve_ca_cert()
to determine the correct TLS verification mode. This avoids duplicating
cert-discovery logic across dashboard.py, node.py, master.py, etc.

Returns:
  - str:  path to a PEM CA certificate file
  - True: use the system certificate bundle
  - False: disable verification (only when explicitly requested or no cert found)

Env vars (in precedence order):
  SIEM_SSL_VERIFY   "false" disables, "true" uses system bundle
  SIEM_CA_CERT      explicit path to a CA cert file (PEM or DER)

Auto-discovery paths (Windows TinyBox installs):
  %ProgramData%\\TinySocs\\OpenSearch\\config\\root-ca.pem
  %ProgramData%\\TinySocs\\OpenSearch\\config\\certs\\ca.pem
  %ProgramData%\\TinySocs\\OpenSearch\\config\\certs\\ca.cer
  %ProgramData%\\TinySocs\\OpenSearch\\config\\certs\\ca-converted.pem

NOTE: Federation connections (Hub<->Site) use self-signed node certs and
intentionally bypass this module. Only OpenSearch connections should use
resolve_ca_cert().
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Optional, Union

_ca_pem_cache: Optional[Union[str, bool]] = None


def _ensure_pem(cert_path: Path) -> str:
    """Return a PEM file path for the given cert. Converts DER->PEM if needed."""
    raw = cert_path.read_bytes()
    if raw[:27] == b"-----BEGIN CERTIFICATE-----":
        print(f"[tls] CA cert: already PEM -> {cert_path}")
        return str(cert_path)

    # DER-encoded: convert to PEM
    import base64
    import tempfile

    print(f"[tls] CA cert: DER detected ({len(raw)} bytes, first4={raw[:4].hex()}), converting to PEM")
    b64 = base64.encodebytes(raw).decode("ascii")
    pem = f"-----BEGIN CERTIFICATE-----\n{b64}-----END CERTIFICATE-----\n"

    # Try to write next to the original
    pem_path = cert_path.parent / "ca-converted.pem"
    try:
        pem_path.write_text(pem, encoding="ascii")
        print(f"[tls] CA cert: DER->PEM converted -> {pem_path}")
        return str(pem_path)
    except Exception as exc:
        print(f"[tls] CA cert: write to {pem_path} failed: {exc}")
        fd, tmp = tempfile.mkstemp(suffix=".pem", prefix="tinysocs-ca-")
        os.write(fd, pem.encode("ascii"))
        os.close(fd)
        print(f"[tls] CA cert: DER->PEM converted -> {tmp} (temp)")
        return tmp


def resolve_ca_cert() -> Any:
    """Find the TinyBox CA certificate for OpenSearch TLS verification.

    Returns a path to a PEM file (str), True for system bundle, or False to skip.
    Converts DER-encoded certs to PEM automatically.
    Result is cached after first call.
    """
    global _ca_pem_cache
    if _ca_pem_cache is not None:
        return _ca_pem_cache

    # 0. Explicit disable -- honour SIEM_SSL_VERIFY=false before anything else
    verify_str = os.getenv("SIEM_SSL_VERIFY", "").lower()
    if verify_str in ("false", "0", "no"):
        print("[tls] CA cert: verification disabled (SIEM_SSL_VERIFY=false)")
        _ca_pem_cache = False
        return False

    # 1. Explicit CA cert path
    explicit = os.getenv("SIEM_CA_CERT", "")
    if explicit and Path(explicit).is_file():
        print(f"[tls] CA cert: SIEM_CA_CERT={explicit}")
        _ca_pem_cache = _ensure_pem(Path(explicit))
        return _ca_pem_cache

    if verify_str in ("true", "1", "yes"):
        print("[tls] CA cert: using system bundle (SIEM_SSL_VERIFY=true)")
        _ca_pem_cache = True
        return True

    # 2. Auto-discover TinyBox CA cert
    pd = os.getenv("ProgramData", os.getenv("PROGRAMDATA", "C:\\ProgramData"))
    candidates = [
        Path(pd) / "TinySocs" / "OpenSearch" / "config" / "root-ca.pem",
        Path(pd) / "TinySocs" / "OpenSearch" / "config" / "certs" / "ca.pem",
        Path(pd) / "TinySocs" / "OpenSearch" / "config" / "certs" / "ca.cer",
        Path(pd) / "TinySocs" / "OpenSearch" / "config" / "certs" / "ca-converted.pem",
    ]
    for cert_path in candidates:
        if not cert_path.is_file():
            continue
        print(f"[tls] CA cert: found {cert_path}")
        _ca_pem_cache = _ensure_pem(cert_path)
        return _ca_pem_cache

    # 3. No cert found -- disable verification with a warning
    print(f"[tls] CA cert: NO cert found (SIEM_SSL_VERIFY={verify_str!r}); verify=False")
    _ca_pem_cache = False
    return False
