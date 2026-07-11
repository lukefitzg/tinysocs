"""
Phase 19 M5: TLS configuration tests.

Validates that node.py and bot.py correctly handle TLS certificate
environment variables and pass them to uvicorn.
"""

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

os.environ.setdefault("MASTER_SHARED_SECRET", "test-secret-for-unit-tests")
os.environ.setdefault("BOT_SHARED_SECRET", "test-bot-secret-1234567890")


# ---------------------------------------------------------------------------
# node.py TLS tests
# ---------------------------------------------------------------------------

class TestNodeTlsConfig:
    """Test node.py cli() TLS certificate handling."""

    def test_cli_with_tls_cert_passes_ssl_kwargs(self, tmp_path, monkeypatch):
        """When TINYSOCS_TLS_CERT and TINYSOCS_TLS_KEY are set to valid files,
        uvicorn.run should be called with ssl_certfile and ssl_keyfile."""
        cert_file = tmp_path / "cert.pem"
        key_file = tmp_path / "key.pem"
        cert_file.write_text("-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----")
        key_file.write_text("-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----")

        monkeypatch.setenv("TINYSOCS_TLS_CERT", str(cert_file))
        monkeypatch.setenv("TINYSOCS_TLS_KEY", str(key_file))
        monkeypatch.setenv("PORT", "18081")

        mock_run = MagicMock()
        with patch("uvicorn.run", mock_run):
            # Reimport to pick up env changes
            import importlib

            import tinysocs.api.node as node_mod
            importlib.reload(node_mod)
            node_mod.cli()

        mock_run.assert_called_once()
        call_kwargs = mock_run.call_args
        assert call_kwargs.kwargs.get("ssl_certfile") == str(cert_file) or \
               (len(call_kwargs.args) > 0 and "ssl_certfile" in str(call_kwargs))
        # Check via keyword args
        all_kwargs = call_kwargs.kwargs if call_kwargs.kwargs else {}
        assert "ssl_certfile" in all_kwargs
        assert all_kwargs["ssl_certfile"] == str(cert_file)
        assert all_kwargs["ssl_keyfile"] == str(key_file)

    def test_cli_without_tls_no_ssl_kwargs(self, monkeypatch):
        """When no TLS env vars are set, uvicorn.run should not include ssl_*."""
        monkeypatch.delenv("TINYSOCS_TLS_CERT", raising=False)
        monkeypatch.delenv("TINYSOCS_TLS_KEY", raising=False)
        monkeypatch.setenv("PORT", "18082")

        mock_run = MagicMock()
        with patch("uvicorn.run", mock_run):
            import importlib

            import tinysocs.api.node as node_mod
            importlib.reload(node_mod)
            node_mod.cli()

        mock_run.assert_called_once()
        all_kwargs = mock_run.call_args.kwargs if mock_run.call_args.kwargs else {}
        assert "ssl_certfile" not in all_kwargs
        assert "ssl_keyfile" not in all_kwargs

    def test_cli_missing_cert_file_raises(self, monkeypatch):
        """When TINYSOCS_TLS_CERT points to a nonexistent file, cli() should exit."""
        monkeypatch.setenv("TINYSOCS_TLS_CERT", "/nonexistent/cert.pem")
        monkeypatch.setenv("TINYSOCS_TLS_KEY", "/nonexistent/key.pem")

        import importlib

        import tinysocs.api.node as node_mod
        importlib.reload(node_mod)

        with pytest.raises(SystemExit, match="TINYSOCS_TLS_CERT not found"):
            node_mod.cli()


# ---------------------------------------------------------------------------
# bot.py TLS tests
# ---------------------------------------------------------------------------

class TestBotTlsConfig:
    """Test bot.py cli() TLS certificate fallback handling."""

    def test_bot_uses_tinysocs_tls_cert_as_fallback(self, tmp_path, monkeypatch):
        """bot.py should use TINYSOCS_TLS_CERT when DASHBOARD_TLS_CERT is not set."""
        cert_file = tmp_path / "cert.pem"
        key_file = tmp_path / "key.pem"
        cert_file.write_text("-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----")
        key_file.write_text("-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----")

        monkeypatch.delenv("DASHBOARD_TLS_CERT", raising=False)
        monkeypatch.delenv("DASHBOARD_TLS_KEY", raising=False)
        monkeypatch.setenv("TINYSOCS_TLS_CERT", str(cert_file))
        monkeypatch.setenv("TINYSOCS_TLS_KEY", str(key_file))
        monkeypatch.setenv("DASHBOARD_BIND", "127.0.0.1")
        monkeypatch.setenv("BOT_PORT", "18090")

        mock_run = MagicMock()
        with patch("uvicorn.run", mock_run):
            import importlib

            import tinysocs.api.bot as bot_mod
            importlib.reload(bot_mod)
            bot_mod.cli()

        mock_run.assert_called_once()
        all_kwargs = mock_run.call_args.kwargs if mock_run.call_args.kwargs else {}
        assert all_kwargs.get("ssl_certfile") == str(cert_file)
        assert all_kwargs.get("ssl_keyfile") == str(key_file)

    def test_dashboard_tls_cert_takes_precedence(self, tmp_path, monkeypatch):
        """DASHBOARD_TLS_CERT should take precedence over TINYSOCS_TLS_CERT."""
        dash_cert = tmp_path / "dash-cert.pem"
        dash_key = tmp_path / "dash-key.pem"
        node_cert = tmp_path / "node-cert.pem"
        node_key = tmp_path / "node-key.pem"
        for f in [dash_cert, dash_key, node_cert, node_key]:
            f.write_text("fake")

        monkeypatch.setenv("DASHBOARD_TLS_CERT", str(dash_cert))
        monkeypatch.setenv("DASHBOARD_TLS_KEY", str(dash_key))
        monkeypatch.setenv("TINYSOCS_TLS_CERT", str(node_cert))
        monkeypatch.setenv("TINYSOCS_TLS_KEY", str(node_key))
        monkeypatch.setenv("DASHBOARD_BIND", "127.0.0.1")
        monkeypatch.setenv("BOT_PORT", "18091")

        mock_run = MagicMock()
        with patch("uvicorn.run", mock_run):
            import importlib

            import tinysocs.api.bot as bot_mod
            importlib.reload(bot_mod)
            bot_mod.cli()

        mock_run.assert_called_once()
        all_kwargs = mock_run.call_args.kwargs if mock_run.call_args.kwargs else {}
        assert all_kwargs.get("ssl_certfile") == str(dash_cert)


# ---------------------------------------------------------------------------
# Default URL tests
# ---------------------------------------------------------------------------

class TestDefaultUrls:
    """Test that default TINYSOCS_NODES uses https://."""

    def test_bot_default_nodes_uses_https(self, monkeypatch):
        """Default TINYSOCS_NODES should use https:// prefix."""
        monkeypatch.delenv("TINYSOCS_NODES", raising=False)

        import importlib

        import tinysocs.api.bot as bot_mod
        importlib.reload(bot_mod)

        assert bot_mod.NODES[0].startswith("https://"), \
            f"Default node URL should use https://, got: {bot_mod.NODES[0]}"

    def test_bot_default_node_url_uses_https(self, monkeypatch):
        """Default NODE_URL should use https:// prefix."""
        monkeypatch.delenv("TINYSOCS_NODES", raising=False)

        import importlib

        import tinysocs.api.bot as bot_mod
        importlib.reload(bot_mod)

        assert bot_mod.NODE_URL.startswith("https://"), \
            f"Default NODE_URL should use https://, got: {bot_mod.NODE_URL}"
