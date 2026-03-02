"""
Threat intelligence provider framework.

Supports AbuseIPDB, AlienVault OTX, and GreyNoise Community.
Each provider implements a common interface for IP/domain/hash enrichment.
Providers degrade gracefully when unconfigured, rate-limited, or unavailable.

CLI usage:
    python -m tinysocs.agent.threat_intel --ip 1.2.3.4
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class EnrichmentResult:
    """Result from a single provider for a single IOC."""
    provider: str
    ioc_type: str          # ip, domain, hash
    ioc_value: str
    data: Dict[str, Any]   # provider-specific payload
    error: Optional[str] = None
    cached: bool = False


@dataclass
class CompositeEnrichment:
    """Merged enrichment results for a single IOC from all providers."""
    ioc_type: str
    ioc_value: str
    results: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    threat_level: str = "none"  # none, low, medium, high

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = dict(self.results)
        d["threat_level"] = self.threat_level
        return d


# ---------------------------------------------------------------------------
# Provider base class
# ---------------------------------------------------------------------------

class ThreatIntelProvider(ABC):
    """Base class for threat intelligence providers."""

    name: str = "base"
    _rate_window: float = 86400.0  # 24h window for rate tracking
    _rate_limit: int = 1000        # default daily limit

    def __init__(self) -> None:
        self._call_timestamps: list[float] = []

    @abstractmethod
    def is_configured(self) -> bool:
        """Return True if the provider has required credentials."""
        ...

    def is_available(self) -> bool:
        """Return True if the provider is configured and not rate-limited."""
        return self.is_configured() and not self._is_rate_limited()

    def quota_remaining(self) -> int:
        """Approximate remaining calls in the current window."""
        now = time.time()
        recent = [t for t in self._call_timestamps if now - t < self._rate_window]
        return max(0, self._rate_limit - len(recent))

    def _record_call(self) -> None:
        now = time.time()
        self._call_timestamps.append(now)
        # GC old entries
        cutoff = now - self._rate_window
        self._call_timestamps = [t for t in self._call_timestamps if t > cutoff]

    def _is_rate_limited(self) -> bool:
        return self.quota_remaining() <= 0

    async def enrich_ip(self, ip: str) -> Optional[EnrichmentResult]:
        return None

    async def enrich_domain(self, domain: str) -> Optional[EnrichmentResult]:
        return None

    async def enrich_hash(self, file_hash: str) -> Optional[EnrichmentResult]:
        return None

    async def health_check(self) -> Dict[str, Any]:
        """Return provider health status."""
        return {
            "provider": self.name,
            "configured": self.is_configured(),
            "available": self.is_available(),
            "quota_remaining": self.quota_remaining(),
        }


# ---------------------------------------------------------------------------
# AbuseIPDB provider
# ---------------------------------------------------------------------------

def _get_env(key: str) -> str:
    """Read env var, falling back to assistant.env file."""
    val = os.getenv(key, "").strip()
    if val:
        return val
    for p in [
        Path(os.getenv("ProgramData", "C:\\ProgramData")) / "TinySocs" / "Assistant" / "assistant.env",
        Path("/var/lib/tinysocs/assistant.env"),
    ]:
        if p.is_file():
            for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if line.startswith(f"{key}="):
                    return line.split("=", 1)[1].strip()
    return ""


class AbuseIPDBProvider(ThreatIntelProvider):
    """AbuseIPDB IP reputation lookups. Free tier: 1,000 checks/day."""

    name = "abuseipdb"
    _rate_limit = 1000

    def __init__(self) -> None:
        super().__init__()
        self._api_key = _get_env("ABUSEIPDB_API_KEY")

    def is_configured(self) -> bool:
        return bool(self._api_key)

    async def enrich_ip(self, ip: str) -> Optional[EnrichmentResult]:
        if not self.is_available():
            return None
        self._record_call()
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                r = await client.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    params={"ipAddress": ip, "maxAgeInDays": "90"},
                    headers={"Key": self._api_key, "Accept": "application/json"},
                )
                r.raise_for_status()
                data = r.json().get("data", {})
                return EnrichmentResult(
                    provider=self.name,
                    ioc_type="ip",
                    ioc_value=ip,
                    data={
                        "score": data.get("abuseConfidenceScore", 0),
                        "reports": data.get("totalReports", 0),
                        "country": data.get("countryCode", ""),
                        "isp": data.get("isp", ""),
                        "last_reported": data.get("lastReportedAt", ""),
                        "is_tor": data.get("isTor", False),
                        "is_whitelisted": data.get("isWhitelisted", False),
                        "usage_type": data.get("usageType", ""),
                    },
                )
        except Exception as e:
            logger.warning("AbuseIPDB lookup failed for %s: %s", ip, e)
            return EnrichmentResult(
                provider=self.name, ioc_type="ip", ioc_value=ip,
                data={}, error=str(e),
            )


# ---------------------------------------------------------------------------
# AlienVault OTX provider
# ---------------------------------------------------------------------------

class AlienVaultOTXProvider(ThreatIntelProvider):
    """AlienVault OTX IP/domain/hash enrichment. Free tier: unlimited."""

    name = "otx"
    _rate_limit = 100000  # effectively unlimited

    def __init__(self) -> None:
        super().__init__()
        self._api_key = _get_env("OTX_API_KEY")

    def is_configured(self) -> bool:
        return bool(self._api_key)

    async def _otx_get(self, path: str) -> Optional[dict]:
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.get(
                f"https://otx.alienvault.com/api/v1{path}",
                headers={"X-OTX-API-KEY": self._api_key},
            )
            r.raise_for_status()
            return r.json()

    async def enrich_ip(self, ip: str) -> Optional[EnrichmentResult]:
        if not self.is_available():
            return None
        self._record_call()
        try:
            general = await self._otx_get(f"/indicators/IPv4/{ip}/general")
            return EnrichmentResult(
                provider=self.name,
                ioc_type="ip",
                ioc_value=ip,
                data={
                    "pulses": general.get("pulse_info", {}).get("count", 0),
                    "reputation": general.get("reputation", 0),
                    "country": general.get("country_code", ""),
                    "asn": general.get("asn", ""),
                },
            )
        except Exception as e:
            logger.warning("OTX IP lookup failed for %s: %s", ip, e)
            return EnrichmentResult(
                provider=self.name, ioc_type="ip", ioc_value=ip,
                data={}, error=str(e),
            )

    async def enrich_domain(self, domain: str) -> Optional[EnrichmentResult]:
        if not self.is_available():
            return None
        self._record_call()
        try:
            general = await self._otx_get(f"/indicators/domain/{domain}/general")
            return EnrichmentResult(
                provider=self.name,
                ioc_type="domain",
                ioc_value=domain,
                data={
                    "pulses": general.get("pulse_info", {}).get("count", 0),
                    "reputation": general.get("reputation", 0),
                },
            )
        except Exception as e:
            logger.warning("OTX domain lookup failed for %s: %s", domain, e)
            return EnrichmentResult(
                provider=self.name, ioc_type="domain", ioc_value=domain,
                data={}, error=str(e),
            )

    async def enrich_hash(self, file_hash: str) -> Optional[EnrichmentResult]:
        if not self.is_available():
            return None
        self._record_call()
        try:
            general = await self._otx_get(f"/indicators/file/{file_hash}/general")
            return EnrichmentResult(
                provider=self.name,
                ioc_type="hash",
                ioc_value=file_hash,
                data={
                    "pulses": general.get("pulse_info", {}).get("count", 0),
                    "malware_families": [
                        p.get("name", "") for p in general.get("pulse_info", {}).get("pulses", [])[:5]
                    ],
                },
            )
        except Exception as e:
            logger.warning("OTX hash lookup failed for %s: %s", file_hash, e)
            return EnrichmentResult(
                provider=self.name, ioc_type="hash", ioc_value=file_hash,
                data={}, error=str(e),
            )


# ---------------------------------------------------------------------------
# GreyNoise Community provider
# ---------------------------------------------------------------------------

class GreyNoiseCommunityProvider(ThreatIntelProvider):
    """GreyNoise Community IP classification.

    Works unauthenticated (10 lookups/day) or with a free API key
    (50 lookups/week).  The API key is optional.
    """

    name = "greynoise"

    def __init__(self) -> None:
        super().__init__()
        self._api_key = _get_env("GREYNOISE_API_KEY")
        # Authenticated: 50/week (~7/day); unauthenticated: 10/day
        self._rate_limit = 50 if self._api_key else 10

    def is_configured(self) -> bool:
        # Always configured — works without an API key (unauthenticated)
        return True

    async def enrich_ip(self, ip: str) -> Optional[EnrichmentResult]:
        if not self.is_available():
            return None
        self._record_call()
        try:
            headers = {"Accept": "application/json"}
            if self._api_key:
                headers["key"] = self._api_key
            async with httpx.AsyncClient(timeout=10.0) as client:
                r = await client.get(
                    f"https://api.greynoise.io/v3/community/{ip}",
                    headers=headers,
                )
                r.raise_for_status()
                data = r.json()
                return EnrichmentResult(
                    provider=self.name,
                    ioc_type="ip",
                    ioc_value=ip,
                    data={
                        "classification": data.get("classification", "unknown"),
                        "noise": data.get("noise", False),
                        "riot": data.get("riot", False),
                        "name": data.get("name", ""),
                        "link": data.get("link", ""),
                        "last_seen": data.get("last_seen", ""),
                    },
                )
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                # 404 = IP not found in GreyNoise dataset (benign/unknown)
                return EnrichmentResult(
                    provider=self.name, ioc_type="ip", ioc_value=ip,
                    data={"classification": "unknown", "noise": False, "riot": False},
                )
            logger.warning("GreyNoise lookup failed for %s: %s", ip, e)
            return EnrichmentResult(
                provider=self.name, ioc_type="ip", ioc_value=ip,
                data={}, error=str(e),
            )
        except Exception as e:
            logger.warning("GreyNoise lookup failed for %s: %s", ip, e)
            return EnrichmentResult(
                provider=self.name, ioc_type="ip", ioc_value=ip,
                data={}, error=str(e),
            )


# ---------------------------------------------------------------------------
# Provider registry
# ---------------------------------------------------------------------------

_ALL_PROVIDERS: List[ThreatIntelProvider] = []


def get_providers() -> List[ThreatIntelProvider]:
    """Return singleton list of all provider instances."""
    global _ALL_PROVIDERS
    if not _ALL_PROVIDERS:
        _ALL_PROVIDERS = [
            AbuseIPDBProvider(),
            AlienVaultOTXProvider(),
            GreyNoiseCommunityProvider(),
        ]
    return _ALL_PROVIDERS


def get_configured_providers() -> List[ThreatIntelProvider]:
    """Return only providers that have API keys configured."""
    return [p for p in get_providers() if p.is_configured()]


def get_available_providers() -> List[ThreatIntelProvider]:
    """Return only providers that are configured and not rate-limited."""
    return [p for p in get_providers() if p.is_available()]


# ---------------------------------------------------------------------------
# Composite threat level calculation
# ---------------------------------------------------------------------------

def compute_threat_level(results: Dict[str, Dict[str, Any]]) -> str:
    """
    Compute composite threat level from provider results.
    high:   any provider reports malicious + score > 75
    medium: suspicious or score 25-75
    low:    unknown or score < 25
    none:   all providers report clean or no results
    """
    if not results:
        return "none"

    max_score = 0
    has_malicious = False

    for provider, data in results.items():
        if not data or data.get("error"):
            continue

        # AbuseIPDB score
        score = data.get("score", 0)
        if isinstance(score, (int, float)):
            max_score = max(max_score, score)

        # GreyNoise classification
        classification = data.get("classification", "").lower()
        if classification == "malicious":
            has_malicious = True

        # OTX pulse count as signal
        pulses = data.get("pulses", 0)
        if isinstance(pulses, (int, float)) and pulses > 5:
            max_score = max(max_score, 50)

        # OTX negative reputation
        rep = data.get("reputation", 0)
        if isinstance(rep, (int, float)) and rep < -1:
            max_score = max(max_score, 60)

    if has_malicious or max_score > 75:
        return "high"
    if max_score > 25:
        return "medium"
    if max_score > 0:
        return "low"
    return "none"


# ---------------------------------------------------------------------------
# Async enrichment of a single IOC
# ---------------------------------------------------------------------------

async def enrich_ioc(
    ioc_type: str,
    ioc_value: str,
    providers: Optional[List[ThreatIntelProvider]] = None,
    cache: Any = None,
    timeout: float = 15.0,
) -> CompositeEnrichment:
    """
    Enrich a single IOC (IP, domain, or hash) across all available providers.
    Uses cache when available. Runs providers in parallel with a timeout.
    """
    if providers is None:
        providers = get_available_providers()

    composite = CompositeEnrichment(ioc_type=ioc_type, ioc_value=ioc_value)

    # Check cache first
    if cache:
        for p in providers:
            cached = cache.get(ioc_type, ioc_value, p.name)
            if cached is not None:
                composite.results[p.name] = cached

    # Identify which providers still need live lookups
    uncached = [p for p in providers if p.name not in composite.results]

    if uncached:
        method_map = {
            "ip": "enrich_ip",
            "domain": "enrich_domain",
            "hash": "enrich_hash",
        }
        method_name = method_map.get(ioc_type)
        if method_name:
            tasks = []
            for p in uncached:
                fn = getattr(p, method_name, None)
                if fn:
                    tasks.append((p.name, fn(ioc_value)))

            if tasks:
                results = await asyncio.gather(
                    *[asyncio.wait_for(t, timeout=timeout) for _, t in tasks],
                    return_exceptions=True,
                )
                for (pname, _), result in zip(tasks, results):
                    if isinstance(result, Exception):
                        logger.warning("Provider %s timed out or errored: %s", pname, result)
                        continue
                    if result and not result.error:
                        composite.results[pname] = result.data
                        # Store in cache
                        if cache:
                            ttl = 86400 if ioc_type == "ip" else 604800  # 24h or 7d
                            cache.put(ioc_type, ioc_value, pname, result.data, ttl)

    composite.threat_level = compute_threat_level(composite.results)
    return composite


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def _cli():
    """CLI for testing threat intel lookups."""
    import argparse
    import json

    parser = argparse.ArgumentParser(description="TinySocs Threat Intelligence Lookup")
    parser.add_argument("--ip", help="IP address to look up")
    parser.add_argument("--domain", help="Domain to look up")
    parser.add_argument("--hash", help="File hash to look up")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    args = parser.parse_args()

    if not any([args.ip, args.domain, args.hash]):
        parser.error("Specify at least one of: --ip, --domain, --hash")

    logging.basicConfig(level=logging.INFO)
    providers = get_providers()

    configured = [p for p in providers if p.is_configured()]
    if not configured:
        print("No threat intelligence providers configured.")
        print("Set API keys in assistant.env: ABUSEIPDB_API_KEY, OTX_API_KEY, GREYNOISE_API_KEY")
        return

    print(f"Configured providers: {', '.join(p.name for p in configured)}")
    print()

    async def run():
        from .threat_cache import ThreatCache
        cache = ThreatCache()
        results = []
        if args.ip:
            r = await enrich_ioc("ip", args.ip, configured, cache)
            results.append(r)
        if args.domain:
            r = await enrich_ioc("domain", args.domain, configured, cache)
            results.append(r)
        if args.hash:
            r = await enrich_ioc("hash", args.hash, configured, cache)
            results.append(r)
        return results

    enrichments = asyncio.run(run())

    for e in enrichments:
        if args.json:
            print(json.dumps(e.to_dict(), indent=2))
        else:
            print(f"--- {e.ioc_type.upper()}: {e.ioc_value} ---")
            print(f"Threat Level: {e.threat_level}")
            for pname, data in e.results.items():
                print(f"  {pname}:")
                for k, v in data.items():
                    print(f"    {k}: {v}")
            print()


if __name__ == "__main__":
    _cli()
