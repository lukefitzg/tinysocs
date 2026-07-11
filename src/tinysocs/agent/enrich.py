"""
Enrichment pipeline for TinySocs alerts.

Extracts IOCs (IPs, domains, hashes) from alert documents and enriches them
with threat intelligence data from configured providers.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import socket
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Original utility
# ---------------------------------------------------------------------------


def rdns(ip: str) -> str | None:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


# ---------------------------------------------------------------------------
# IOC extraction helpers
# ---------------------------------------------------------------------------

_HASH_RE = re.compile(r"\b[a-fA-F0-9]{32,64}\b")
_DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)"
    r"+[a-zA-Z]{2,}\b"
)

# Private / reserved IP ranges to skip enrichment
_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fe80::/10"),
]


def _is_public_ip(ip_str: str) -> bool:
    """Return True if the IP is a routable public address worth enriching."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return not any(addr in net for net in _PRIVATE_NETS)
    except ValueError:
        return False


def extract_ips(doc: dict[str, Any]) -> set[str]:
    """Extract unique public IP addresses from alert fields."""
    ips: set[str] = set()
    # Common field paths for IPs in alert documents
    for key in ("source_ip", "dest_ip", "src_ip", "dst_ip", "ip", "remote_ip",
                "source.ip", "destination.ip"):
        val = _deep_get(doc, key)
        if val and isinstance(val, str) and _is_public_ip(val):
            ips.add(val)
    # Check winlog body fields
    body = doc.get("body", {})
    if isinstance(body, dict):
        for key in ("IpAddress", "SourceAddress", "DestinationIp", "SourceIp",
                     "TargetServerName"):
            val = body.get(key, "")
            if val and isinstance(val, str):
                try:
                    if _is_public_ip(val):
                        ips.add(val)
                except Exception:
                    pass
    return ips


def extract_domains(doc: dict[str, Any]) -> set[str]:
    """Extract unique domain names from alert fields."""
    domains: set[str] = set()
    for key in ("domain", "hostname", "dest_domain", "dns.query"):
        val = _deep_get(doc, key)
        if val and isinstance(val, str) and "." in val:
            domains.add(val.lower())
    body = doc.get("body", {})
    if isinstance(body, dict):
        for key in ("TargetServerName", "QueryName", "DestinationHostname"):
            val = body.get(key, "")
            if val and isinstance(val, str) and "." in val:
                # Skip IPs
                try:
                    ipaddress.ip_address(val)
                except ValueError:
                    domains.add(val.lower())
    return domains


def extract_hashes(doc: dict[str, Any]) -> set[str]:
    """Extract file hashes (MD5/SHA1/SHA256) from alert fields."""
    hashes: set[str] = set()
    for key in ("file_hash", "hash", "sha256", "sha1", "md5"):
        val = _deep_get(doc, key)
        if val and isinstance(val, str) and _HASH_RE.fullmatch(val):
            hashes.add(val.lower())
    body = doc.get("body", {})
    if isinstance(body, dict):
        for key in ("Hashes", "FileHash", "SHA256", "MD5", "SHA1"):
            val = body.get(key, "")
            if val and isinstance(val, str):
                # Sysmon Hashes field: "SHA256=abc123,MD5=def456"
                for part in val.split(","):
                    clean = part.split("=", 1)[-1].strip()
                    if _HASH_RE.fullmatch(clean):
                        hashes.add(clean.lower())
    return hashes


def _deep_get(d: dict[str, Any], dotted_key: str) -> Any:
    """Resolve dotted key paths like 'source.ip' in nested dicts."""
    parts = dotted_key.split(".")
    current = d
    for part in parts:
        if isinstance(current, dict):
            current = current.get(part)
        else:
            return None
    return current


# ---------------------------------------------------------------------------
# Alert enrichment pipeline
# ---------------------------------------------------------------------------


async def enrich_alert(
    alert_doc: dict[str, Any],
    cache: Any = None,
    providers: list | None = None,
) -> dict[str, Any]:
    """
    Enrich an alert document with threat intelligence data.

    Extracts IOCs, queries providers in parallel, and returns an enrichment
    dict suitable for merging into the alert document.

    Returns:
        {"source_ip": {"abuseipdb": {...}, ...}, "threat_level": "high"}
    """
    from .threat_intel import enrich_ioc, get_available_providers

    if providers is None:
        providers = get_available_providers()

    if not providers:
        return {}

    enrichment: dict[str, Any] = {}
    tasks = []

    # Extract IOCs
    ips = extract_ips(alert_doc)
    domains = extract_domains(alert_doc)
    hashes = extract_hashes(alert_doc)

    for ip in ips:
        tasks.append(("ip", ip, enrich_ioc("ip", ip, providers, cache)))
    for domain in domains:
        tasks.append(("domain", domain, enrich_ioc("domain", domain, providers, cache)))
    for h in hashes:
        tasks.append(("hash", h, enrich_ioc("hash", h, providers, cache)))

    if not tasks:
        return {}

    # Run all enrichments in parallel
    results = await asyncio.gather(
        *[t for _, _, t in tasks],
        return_exceptions=True,
    )

    max_threat = "none"
    threat_order = {"none": 0, "low": 1, "medium": 2, "high": 3}

    for (ioc_type, ioc_value, _), result in zip(tasks, results):
        if isinstance(result, BaseException):
            logger.warning("Enrichment failed for %s %s: %s", ioc_type, ioc_value, result)
            continue
        if result and result.results:
            key = ioc_value  # Use the IOC value as the key
            enrichment[key] = result.to_dict()
            if threat_order.get(result.threat_level, 0) > threat_order.get(max_threat, 0):
                max_threat = result.threat_level

    if enrichment:
        enrichment["threat_level"] = max_threat

    return enrichment


def format_enrichment_for_llm(enrichment: dict[str, Any]) -> str:
    """
    Format enrichment data as a human-readable string for LLM context.

    Example output:
        IP 203.0.113.5: AbuseIPDB reports 87% malicious (47 abuse reports,
        country: RU, ISP: Evil Corp). GreyNoise: malicious scanner.
        Overall threat level: HIGH.
    """
    if not enrichment:
        return ""

    parts: list[str] = []
    threat_level = enrichment.get("threat_level", "none")

    for key, value in enrichment.items():
        if key == "threat_level":
            continue
        if not isinstance(value, dict):
            continue

        provider_parts: list[str] = []

        for provider, data in value.items():
            if provider == "threat_level" or not isinstance(data, dict):
                continue

            if provider == "abuseipdb":
                score = data.get("score", 0)
                reports = data.get("reports", 0)
                country = data.get("country", "")
                isp = data.get("isp", "")
                details = f"AbuseIPDB: {score}% confidence"
                if reports:
                    details += f", {reports} reports"
                if country:
                    details += f", country: {country}"
                if isp:
                    details += f", ISP: {isp}"
                if data.get("is_tor"):
                    details += " (Tor exit node)"
                provider_parts.append(details)

            elif provider == "otx":
                pulses = data.get("pulses", 0)
                rep = data.get("reputation", 0)
                details = f"OTX: {pulses} threat pulses"
                if rep:
                    details += f", reputation: {rep}"
                provider_parts.append(details)

            elif provider == "greynoise":
                classification = data.get("classification", "unknown")
                name = data.get("name", "")
                details = f"GreyNoise: {classification}"
                if name:
                    details += f" ({name})"
                provider_parts.append(details)

        if provider_parts:
            parts.append(f"IOC {key}: {'; '.join(provider_parts)}")

    if parts:
        parts.append(f"Overall threat level: {threat_level.upper()}")

    return "\n".join(parts)
