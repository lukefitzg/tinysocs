"""Tests for threat intelligence providers, cache, and enrichment pipeline."""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tinysocs.agent.threat_cache import ThreatCache
from tinysocs.agent.threat_intel import (
    AbuseIPDBProvider,
    AlienVaultOTXProvider,
    CompositeEnrichment,
    EnrichmentResult,
    GreyNoiseCommunityProvider,
    compute_threat_level,
    enrich_ioc,
)
from tinysocs.agent.enrich import (
    extract_ips,
    extract_domains,
    extract_hashes,
    enrich_alert,
    format_enrichment_for_llm,
    _is_public_ip,
)


# ---------------------------------------------------------------------------
# Cache tests
# ---------------------------------------------------------------------------

class TestThreatCache:
    def setup_method(self):
        self._tmpfile = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self._tmpfile.close()
        self.cache = ThreatCache(db_path=self._tmpfile.name)

    def teardown_method(self):
        os.unlink(self._tmpfile.name)

    def test_put_and_get(self):
        data = {"score": 87, "reports": 47}
        self.cache.put("ip", "1.2.3.4", "abuseipdb", data, ttl_seconds=3600)
        result = self.cache.get("ip", "1.2.3.4", "abuseipdb")
        assert result == data

    def test_cache_miss(self):
        result = self.cache.get("ip", "5.6.7.8", "abuseipdb")
        assert result is None

    def test_ttl_expiry(self):
        data = {"score": 50}
        self.cache.put("ip", "1.2.3.4", "test", data, ttl_seconds=1)
        # Immediately should be valid
        assert self.cache.get("ip", "1.2.3.4", "test") == data
        # After TTL, should be expired
        time.sleep(1.1)
        assert self.cache.get("ip", "1.2.3.4", "test") is None

    def test_upsert(self):
        self.cache.put("ip", "1.2.3.4", "test", {"v": 1}, ttl_seconds=3600)
        self.cache.put("ip", "1.2.3.4", "test", {"v": 2}, ttl_seconds=3600)
        result = self.cache.get("ip", "1.2.3.4", "test")
        assert result == {"v": 2}

    def test_different_providers(self):
        self.cache.put("ip", "1.2.3.4", "abuseipdb", {"score": 87}, ttl_seconds=3600)
        self.cache.put("ip", "1.2.3.4", "greynoise", {"classification": "malicious"}, ttl_seconds=3600)
        assert self.cache.get("ip", "1.2.3.4", "abuseipdb")["score"] == 87
        assert self.cache.get("ip", "1.2.3.4", "greynoise")["classification"] == "malicious"

    def test_stats(self):
        self.cache.put("ip", "1.2.3.4", "a", {"x": 1}, ttl_seconds=3600)
        self.cache.put("ip", "5.6.7.8", "a", {"x": 2}, ttl_seconds=3600)
        self.cache.put("domain", "evil.com", "b", {"x": 3}, ttl_seconds=3600)
        stats = self.cache.stats()
        assert stats["total_entries"] == 3
        assert stats["valid_entries"] == 3

    def test_cleanup_expired(self):
        self.cache.put("ip", "1.2.3.4", "test", {"v": 1}, ttl_seconds=1)
        self.cache.put("ip", "5.6.7.8", "test", {"v": 2}, ttl_seconds=3600)
        time.sleep(1.1)
        removed = self.cache.cleanup_expired()
        assert removed == 1
        stats = self.cache.stats()
        assert stats["valid_entries"] == 1

    def test_clear(self):
        self.cache.put("ip", "1.2.3.4", "test", {"v": 1}, ttl_seconds=3600)
        self.cache.clear()
        stats = self.cache.stats()
        assert stats["total_entries"] == 0


# ---------------------------------------------------------------------------
# Provider tests
# ---------------------------------------------------------------------------

class TestProviderConfiguration:
    def test_abuseipdb_unconfigured(self):
        with patch.dict(os.environ, {}, clear=False):
            # Force re-read by creating new instance
            with patch("tinysocs.agent.threat_intel._get_env", return_value=""):
                p = AbuseIPDBProvider()
                p._api_key = ""
                assert not p.is_configured()
                assert not p.is_available()

    def test_abuseipdb_configured(self):
        p = AbuseIPDBProvider()
        p._api_key = "test-key-123"
        assert p.is_configured()
        assert p.is_available()

    def test_rate_limit_tracking(self):
        p = AbuseIPDBProvider()
        p._api_key = "test-key"
        p._rate_limit = 3
        assert p.quota_remaining() == 3
        p._record_call()
        p._record_call()
        assert p.quota_remaining() == 1
        p._record_call()
        assert p.quota_remaining() == 0
        assert not p.is_available()

    def test_health_check(self):
        p = AbuseIPDBProvider()
        p._api_key = "test-key"
        result = asyncio.run(p.health_check())
        assert result["provider"] == "abuseipdb"
        assert result["configured"] is True

    def test_greynoise_configured_without_key(self):
        """GreyNoise should be configured even without an API key (unauthenticated mode)."""
        with patch("tinysocs.agent.threat_intel._get_env", return_value=""):
            p = GreyNoiseCommunityProvider()
            assert p.is_configured()
            assert p.is_available()
            assert p._rate_limit == 10  # unauthenticated limit

    def test_greynoise_configured_with_key(self):
        """GreyNoise with an API key should have a higher rate limit."""
        with patch("tinysocs.agent.threat_intel._get_env", return_value="test-key"):
            p = GreyNoiseCommunityProvider()
            assert p.is_configured()
            assert p.is_available()
            assert p._rate_limit == 50  # authenticated limit


# ---------------------------------------------------------------------------
# Threat level calculation
# ---------------------------------------------------------------------------

class TestThreatLevel:
    def test_no_results(self):
        assert compute_threat_level({}) == "none"

    def test_high_abuseipdb(self):
        results = {"abuseipdb": {"score": 87, "reports": 47}}
        assert compute_threat_level(results) == "high"

    def test_high_greynoise(self):
        results = {"greynoise": {"classification": "malicious"}}
        assert compute_threat_level(results) == "high"

    def test_medium_score(self):
        results = {"abuseipdb": {"score": 50, "reports": 10}}
        assert compute_threat_level(results) == "medium"

    def test_low_score(self):
        results = {"abuseipdb": {"score": 10, "reports": 2}}
        assert compute_threat_level(results) == "low"

    def test_none_clean(self):
        results = {"abuseipdb": {"score": 0, "reports": 0}}
        assert compute_threat_level(results) == "none"

    def test_otx_pulses_contribute(self):
        results = {"otx": {"pulses": 10, "reputation": -3}}
        assert compute_threat_level(results) == "medium"

    def test_error_results_ignored(self):
        results = {"abuseipdb": {"error": "timeout"}}
        assert compute_threat_level(results) == "none"

    def test_composite_high(self):
        results = {
            "abuseipdb": {"score": 90, "reports": 100},
            "greynoise": {"classification": "malicious"},
            "otx": {"pulses": 15, "reputation": -5},
        }
        assert compute_threat_level(results) == "high"


# ---------------------------------------------------------------------------
# IOC extraction tests
# ---------------------------------------------------------------------------

class TestIOCExtraction:
    def test_extract_public_ip(self):
        doc = {"source_ip": "8.8.8.8", "dest_ip": "192.168.1.1"}
        ips = extract_ips(doc)
        assert "8.8.8.8" in ips
        assert "192.168.1.1" not in ips  # private

    def test_extract_ip_from_body(self):
        doc = {"body": {"IpAddress": "1.2.3.4"}}
        ips = extract_ips(doc)
        assert "1.2.3.4" in ips

    def test_skip_private_ips(self):
        assert not _is_public_ip("10.0.0.1")
        assert not _is_public_ip("172.16.0.1")
        assert not _is_public_ip("192.168.1.1")
        assert not _is_public_ip("127.0.0.1")
        assert _is_public_ip("8.8.8.8")

    def test_extract_domains(self):
        doc = {"domain": "evil.example.com", "body": {"QueryName": "malware.bad.org"}}
        domains = extract_domains(doc)
        assert "evil.example.com" in domains
        assert "malware.bad.org" in domains

    def test_extract_hashes(self):
        doc = {"body": {"Hashes": "SHA256=abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"}}
        hashes = extract_hashes(doc)
        assert "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234" in hashes

    def test_extract_sysmon_hashes(self):
        doc = {"body": {"Hashes": "SHA256=aabb1122aabb1122aabb1122aabb1122aabb1122aabb1122aabb1122aabb1122,MD5=11223344556677889900aabbccddeeff"}}
        hashes = extract_hashes(doc)
        assert len(hashes) == 2


# ---------------------------------------------------------------------------
# LLM formatting tests
# ---------------------------------------------------------------------------

class TestLLMFormatting:
    def test_empty_enrichment(self):
        assert format_enrichment_for_llm({}) == ""

    def test_format_abuseipdb(self):
        enrichment = {
            "1.2.3.4": {
                "abuseipdb": {"score": 87, "reports": 47, "country": "RU", "isp": "Evil Corp"},
                "threat_level": "high",
            },
            "threat_level": "high",
        }
        text = format_enrichment_for_llm(enrichment)
        assert "1.2.3.4" in text
        assert "87%" in text
        assert "47 reports" in text
        assert "RU" in text
        assert "HIGH" in text

    def test_format_greynoise(self):
        enrichment = {
            "5.6.7.8": {
                "greynoise": {"classification": "malicious", "name": "scanner"},
                "threat_level": "high",
            },
            "threat_level": "high",
        }
        text = format_enrichment_for_llm(enrichment)
        assert "malicious" in text
        assert "scanner" in text


# ---------------------------------------------------------------------------
# Enrichment pipeline integration (mocked providers)
# ---------------------------------------------------------------------------

class TestEnrichmentPipeline:
    def test_enrich_ioc_with_cache(self):
        tmpf = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        tmpf.close()
        try:
            cache = ThreatCache(db_path=tmpf.name)
            # Pre-populate cache
            cache.put("ip", "1.2.3.4", "abuseipdb", {"score": 87}, ttl_seconds=3600)

            mock_provider = MagicMock()
            mock_provider.name = "abuseipdb"
            mock_provider.is_configured.return_value = True
            mock_provider.is_available.return_value = True

            result = asyncio.run(enrich_ioc("ip", "1.2.3.4", [mock_provider], cache))
            assert result.results["abuseipdb"]["score"] == 87
            # Provider should NOT have been called (cache hit)
            mock_provider.enrich_ip.assert_not_called()
        finally:
            os.unlink(tmpf.name)
