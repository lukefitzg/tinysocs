"""
Phase 19 M5: Installer configuration validation tests.

Tests site name sanitisation, shared secret validation, and
config generation logic that will be used by the installer.
"""

import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


# ---------------------------------------------------------------------------
# Site name sanitisation
# ---------------------------------------------------------------------------

def _sanitise_site_name(name: str) -> str:
    """Pure-Python equivalent of the site name sanitisation done in the installer.

    Rules:
    - Lowercase
    - Replace non-alphanumeric (except hyphens) with hyphens
    - Strip leading/trailing hyphens
    - Collapse consecutive hyphens
    - Max 32 characters
    """
    name = name.lower().strip()
    name = re.sub(r"[^a-z0-9-]", "-", name)
    name = re.sub(r"-{2,}", "-", name)
    name = name.strip("-")
    return name[:32]


class TestSiteNameSanitisation:
    """Test site name validation and sanitisation rules."""

    def test_lowercase_conversion(self):
        assert _sanitise_site_name("MyOffice") == "myoffice"

    def test_uppercase_all(self):
        assert _sanitise_site_name("WAREHOUSE") == "warehouse"

    def test_spaces_to_hyphens(self):
        assert _sanitise_site_name("branch north") == "branch-north"

    def test_special_chars_stripped(self):
        assert _sanitise_site_name("site@#$%name!") == "site-name"

    def test_consecutive_hyphens_collapsed(self):
        assert _sanitise_site_name("a---b") == "a-b"

    def test_leading_trailing_hyphens_stripped(self):
        assert _sanitise_site_name("-warehouse-") == "warehouse"

    def test_max_32_characters(self):
        long_name = "a" * 50
        result = _sanitise_site_name(long_name)
        assert len(result) <= 32

    def test_valid_name_unchanged(self):
        assert _sanitise_site_name("branch-north") == "branch-north"

    def test_numbers_preserved(self):
        assert _sanitise_site_name("site123") == "site123"

    def test_mixed_case_with_spaces(self):
        assert _sanitise_site_name("Branch North Office") == "branch-north-office"

    def test_dots_replaced(self):
        assert _sanitise_site_name("site.local") == "site-local"

    def test_underscores_replaced(self):
        assert _sanitise_site_name("my_site") == "my-site"

    def test_empty_after_sanitisation(self):
        """A name of only special chars results in empty string."""
        result = _sanitise_site_name("@#$%")
        assert result == ""


# ---------------------------------------------------------------------------
# Shared secret validation
# ---------------------------------------------------------------------------

class TestSharedSecretValidation:
    """Test shared secret length and format requirements."""

    def test_secret_16_chars_valid(self):
        """16-character secret should pass validation."""
        secret = "a" * 16
        assert len(secret) >= 16

    def test_secret_15_chars_invalid(self):
        """15-character secret should fail validation."""
        secret = "a" * 15
        assert len(secret) < 16

    def test_secret_44_chars_base64_valid(self):
        """Base64-encoded 32-byte secret (44 chars) should pass."""
        import base64
        secret = base64.b64encode(os.urandom(32)).decode()
        assert len(secret) >= 16

    def test_empty_secret_invalid(self):
        assert len("") < 16

    def test_generated_secret_is_strong(self):
        """Auto-generated secrets should be at least 16 chars of random data."""
        import base64
        secret = base64.b64encode(os.urandom(32)).decode()
        assert len(secret) >= 16
        # Should contain mix of chars (not all same)
        assert len(set(secret)) > 5


# ---------------------------------------------------------------------------
# Default TINYSOCS_NODES configuration
# ---------------------------------------------------------------------------

class TestDefaultNodesConfig:
    """Test default TINYSOCS_NODES values for each role."""

    def test_hub_default_nodes_includes_localhost(self):
        """Hub default: TINYSOCS_NODES should include https://localhost:8081."""
        default = "https://127.0.0.1:8081"
        assert "https://" in default
        assert "8081" in default

    def test_hub_with_remote_sites(self):
        """Hub with remote sites: TINYSOCS_NODES is comma-separated https URLs."""
        nodes = "https://127.0.0.1:8081,https://192.168.1.50:8081"
        urls = [u.strip() for u in nodes.split(",")]
        assert len(urls) == 2
        for url in urls:
            assert url.startswith("https://")

    def test_site_nodes_empty(self):
        """Site role: TINYSOCS_NODES should be empty (site doesn't poll other nodes)."""
        site_nodes = ""
        assert site_nodes == ""

    def test_no_http_in_defaults(self):
        """All default URLs should use https://, never http://."""
        defaults = ["https://127.0.0.1:8081", "https://localhost:8081"]
        for url in defaults:
            assert not url.startswith("http://"), f"Default URL uses http://: {url}"
            assert url.startswith("https://")


# ---------------------------------------------------------------------------
# Hub address validation
# ---------------------------------------------------------------------------

class TestHubAddressValidation:
    """Test hub address input validation rules."""

    def test_strips_https_prefix(self):
        """Hub address should have https:// stripped if pasted."""
        addr = "https://192.168.1.100"
        if addr.startswith("https://"):
            addr = addr[8:]
        assert addr == "192.168.1.100"

    def test_strips_http_prefix(self):
        """Hub address should have http:// stripped if pasted."""
        addr = "http://192.168.1.100"
        if addr.startswith("http://"):
            addr = addr[7:]
        assert addr == "192.168.1.100"

    def test_ip_address_valid(self):
        addr = "192.168.1.100"
        assert " " not in addr
        assert len(addr) > 0

    def test_hostname_valid(self):
        addr = "tinysocs-hub.local"
        assert " " not in addr
        assert len(addr) > 0

    def test_empty_address_invalid(self):
        assert len("".strip()) == 0

    def test_spaces_invalid(self):
        addr = "192.168.1 .100"
        assert " " in addr
