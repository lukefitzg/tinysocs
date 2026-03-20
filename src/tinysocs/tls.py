# tinysocs/tls.py
"""
Shared TLS certificate resolution and SSL-aware HTTP for OpenSearch.

All TinySocs components that talk to OpenSearch should use:
  - resolve_ca_cert()     to find the CA cert (returns PEM path, True, or False)
  - make_ssl_context()    to build an ssl.SSLContext from the resolved cert
  - get_opensearch_session()  to get a requests.Session with proper TLS

This avoids duplicating cert-discovery logic across dashboard.py, node.py,
master.py, etc. and ensures PyInstaller-bundled OpenSSL never uses certifi
(which may be corrupt in frozen builds).

Env vars (in precedence order):
  SIEM_SSL_VERIFY   "false" disables, "true" uses system bundle
  SIEM_CA_CERT      explicit path to a CA cert file (PEM or DER)

Auto-discovery paths (Windows TinyBox installs):
  %ProgramData%\\TinySocs\\OpenSearch\\config\\root-ca.pem
  %ProgramData%\\TinySocs\\OpenSearch\\config\\certs\\ca.pem
  %ProgramData%\\TinySocs\\OpenSearch\\config\\certs\\ca.cer
  %ProgramData%\\TinySocs\\OpenSearch\\config\\certs\\ca-converted.pem

NOTE: Federation connections (Hub<->Site) use certificate pinning via
federation_certs.py and intentionally bypass this module.
"""

from __future__ import annotations

import os
import ssl
from pathlib import Path
from typing import Any, Optional, Union

_ca_pem_cache: Optional[Union[str, bool]] = None
_ssl_ctx_cache: Optional[ssl.SSLContext] = None
_session_cache: Optional[Any] = None


def _ensure_pem(cert_path: Path) -> str:
    """Return a PEM file path for the given cert. Converts DER->PEM if needed."""
    raw = cert_path.read_bytes()
    if raw[:27] == b"-----BEGIN CERTIFICATE-----":
        print(f"[tls] CA cert: already PEM -> {cert_path}")
        return str(cert_path)

    # DER-encoded: check if the installer already converted it via certutil
    pre_converted = cert_path.parent / "ca-converted.pem"
    if pre_converted.is_file():
        pre_raw = pre_converted.read_bytes()
        if pre_raw[:27] == b"-----BEGIN CERTIFICATE-----":
            print(f"[tls] CA cert: DER detected, using pre-converted PEM -> {pre_converted}")
            return str(pre_converted)

    # Fallback: convert DER->PEM via certutil (Windows) or Python base64
    import subprocess
    import tempfile

    print(f"[tls] CA cert: DER detected ({len(raw)} bytes, first4={raw[:4].hex()}), converting to PEM")
    pem_path = cert_path.parent / "ca-converted.pem"

    # Prefer certutil (Windows native) -- produces PEM that all OpenSSL builds can load
    try:
        r = subprocess.run(
            ["certutil", "-encode", str(cert_path), str(pem_path)],
            capture_output=True, timeout=10,
        )
        if r.returncode == 0 and pem_path.is_file():
            print(f"[tls] CA cert: DER->PEM converted via certutil -> {pem_path}")
            return str(pem_path)
    except Exception as exc:
        print(f"[tls] CA cert: certutil conversion failed: {exc}")

    # Last resort: Python base64 conversion
    import base64
    b64 = base64.encodebytes(raw).decode("ascii")
    pem = f"-----BEGIN CERTIFICATE-----\n{b64}-----END CERTIFICATE-----\n"
    try:
        pem_path.write_text(pem, encoding="ascii")
        print(f"[tls] CA cert: DER->PEM converted via Python -> {pem_path}")
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

    # 3. No cert found -- use system certificate bundle (secure default).
    # Only SIEM_SSL_VERIFY=false (checked above) disables verification.
    # The system bundle will verify against OS-trusted CAs, which is the
    # correct secure fallback for production installs.
    print(
        f"[tls] CA cert: no TinyBox CA cert found; using system certificate "
        f"bundle for verification (set SIEM_SSL_VERIFY=false to disable)"
    )
    _ca_pem_cache = True
    return True


def make_ssl_context() -> ssl.SSLContext:
    """Build an SSLContext from resolve_ca_cert() result.

    This bypasses certifi entirely -- critical for PyInstaller frozen builds
    where the bundled certifi CA bundle may be corrupt or missing.
    """
    global _ssl_ctx_cache
    if _ssl_ctx_cache is not None:
        return _ssl_ctx_cache

    tls_result = resolve_ca_cert()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    if tls_result is False:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    elif isinstance(tls_result, str):
        ctx.load_verify_locations(tls_result)
    # else True: uses system trust store (default for PROTOCOL_TLS_CLIENT)

    _ssl_ctx_cache = ctx
    return ctx


def get_opensearch_session():
    """Return a requests.Session with proper TLS for OpenSearch.

    Uses a custom HTTPAdapter that injects our SSLContext, bypassing
    certifi.where() which is broken in PyInstaller frozen builds.

    Also overrides merge_environment_settings to prevent REQUESTS_CA_BUNDLE
    and CURL_CA_BUNDLE env vars from overriding our verify setting (these
    may point to DER files that requests cannot read).

    All OpenSearch HTTP calls should use this session.
    """
    global _session_cache
    if _session_cache is not None:
        return _session_cache

    import requests
    from requests.adapters import HTTPAdapter

    ssl_ctx = make_ssl_context()
    tls_result = resolve_ca_cert()

    # Determine the correct verify value from our TLS config
    if tls_result is False:
        _verify = False
    elif isinstance(tls_result, str):
        _verify = tls_result
    else:
        _verify = True

    class _OpenSearchAdapter(HTTPAdapter):
        """HTTPS adapter using our explicit SSLContext."""
        def init_poolmanager(self, *args, **kwargs):
            kwargs["ssl_context"] = ssl_ctx
            return super().init_poolmanager(*args, **kwargs)

    class _OpenSearchSession(requests.Session):
        """Session that prevents env vars from overriding our TLS config.

        The requests library reads REQUESTS_CA_BUNDLE / CURL_CA_BUNDLE from
        the environment in merge_environment_settings() and uses them to
        override session.verify.  These env vars may point to DER certs that
        requests cannot read.  We override the method to always use our
        resolve_ca_cert() result instead.
        """
        def merge_environment_settings(self, url, proxies, stream, verify, cert):
            # Let requests handle proxies/stream normally, but always
            # use our TLS verify setting
            settings = super().merge_environment_settings(
                url, proxies, stream, verify, cert,
            )
            settings["verify"] = _verify
            return settings

    session = _OpenSearchSession()
    session.mount("https://", _OpenSearchAdapter())
    session.verify = _verify

    # Suppress InsecureRequestWarning when verify is disabled
    if tls_result is False:
        try:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except Exception:
            pass

    _session_cache = session
    return session
