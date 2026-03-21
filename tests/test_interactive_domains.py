"""Tests for interactive domain prompts in agentcage run."""

import json
import threading
from io import StringIO
from unittest.mock import MagicMock, patch

import pytest

from agentcage.run import _extract_parent_domain, _monitor_proxy


class _NoCloseStringIO(StringIO):
    """StringIO that ignores close() so we can read after _monitor_proxy finishes."""

    def close(self):
        pass  # keep the buffer accessible for assertions


class TestExtractParentDomain:
    """Verify parent domain extraction from hostnames."""

    def test_simple_subdomain(self):
        assert _extract_parent_domain("api.stripe.com") == "stripe.com"

    def test_deep_subdomain(self):
        assert _extract_parent_domain("a.b.c.example.com") == "example.com"

    def test_already_parent(self):
        assert _extract_parent_domain("stripe.com") == "stripe.com"

    def test_single_label(self):
        assert _extract_parent_domain("localhost") == "localhost"

    def test_compound_tld_co_uk(self):
        assert _extract_parent_domain("cdn.example.co.uk") == "example.co.uk"

    def test_compound_tld_com_au(self):
        assert _extract_parent_domain("api.example.com.au") == "example.com.au"

    def test_compound_tld_co_jp(self):
        assert _extract_parent_domain("shop.example.co.jp") == "example.co.jp"

    def test_compound_tld_com_br(self):
        assert _extract_parent_domain("api.example.com.br") == "example.com.br"

    def test_compound_tld_co_nz(self):
        assert _extract_parent_domain("mail.example.co.nz") == "example.co.nz"

    def test_bare_compound_tld(self):
        assert _extract_parent_domain("example.co.uk") == "example.co.uk"

    def test_ip_address_passthrough(self):
        # IP-like strings should just return the last 2 parts
        assert _extract_parent_domain("192.168.1.1") == "1.1"


class TestMonitorProxyInteractive:
    """Test the interactive domain prompt behaviour in _monitor_proxy."""

    def _make_log_lines(self, entries):
        """Create newline-delimited JSON lines from dicts."""
        return "\n".join(json.dumps(e) for e in entries) + "\n"

    @patch("agentcage.run.subprocess.run")
    @patch("agentcage.run.subprocess.Popen")
    def test_prompts_for_blocked_domain(self, mock_popen, mock_run):
        """Interactive mode prompts on domain blocks and calls domain add."""
        log_line = json.dumps({
            "decision": "blocked", "host": "api.stripe.com", "reason": "domain",
        }) + "\n"

        mock_proc = MagicMock()
        mock_proc.stdout = iter([log_line])
        mock_proc.wait.return_value = 0
        mock_popen.return_value = mock_proc

        tty_output = _NoCloseStringIO()
        tty_input = _NoCloseStringIO("y\n")

        stop = threading.Event()

        with patch("builtins.open") as mock_open:
            def open_side_effect(path, mode="r"):
                if path == "/dev/tty" and mode == "w":
                    return tty_output
                if path == "/dev/tty" and mode == "r":
                    return tty_input
                raise OSError("unexpected open")
            mock_open.side_effect = open_side_effect

            _monitor_proxy(
                ["fake", "log", "cmd"], stop,
                cage_name="test-cage", interactive=True,
            )

        # Should have called domain add
        mock_run.assert_called_once_with(
            ["agentcage", "domain", "add", "test-cage", "stripe.com"],
            capture_output=True,
        )

        output = tty_output.getvalue()
        assert "blocked" in output
        assert "stripe.com" in output
        assert "Add stripe.com to allowlist?" in output

    @patch("agentcage.run.subprocess.run")
    @patch("agentcage.run.subprocess.Popen")
    def test_no_prompt_when_not_interactive(self, mock_popen, mock_run):
        """Non-interactive mode does not prompt."""
        log_line = json.dumps({
            "decision": "blocked", "host": "api.stripe.com", "reason": "domain",
        }) + "\n"

        mock_proc = MagicMock()
        mock_proc.stdout = iter([log_line])
        mock_proc.wait.return_value = 0
        mock_popen.return_value = mock_proc

        tty_output = _NoCloseStringIO()
        stop = threading.Event()

        with patch("builtins.open") as mock_open:
            def open_side_effect(path, mode="r"):
                if path == "/dev/tty" and mode == "w":
                    return tty_output
                raise OSError("no tty_r in non-interactive")
            mock_open.side_effect = open_side_effect

            _monitor_proxy(
                ["fake", "log", "cmd"], stop,
                cage_name="test-cage", interactive=False,
            )

        # Should NOT have called domain add
        mock_run.assert_not_called()
        output = tty_output.getvalue()
        assert "blocked" in output
        assert "Add" not in output

    @patch("agentcage.run.subprocess.run")
    @patch("agentcage.run.subprocess.Popen")
    def test_no_prompt_for_non_domain_reason(self, mock_popen, mock_run):
        """Blocks with reason != 'domain' are not prompted."""
        log_line = json.dumps({
            "decision": "blocked", "host": "evil.com", "reason": "entropy",
        }) + "\n"

        mock_proc = MagicMock()
        mock_proc.stdout = iter([log_line])
        mock_proc.wait.return_value = 0
        mock_popen.return_value = mock_proc

        tty_output = _NoCloseStringIO()
        tty_input = _NoCloseStringIO("")
        stop = threading.Event()

        with patch("builtins.open") as mock_open:
            def open_side_effect(path, mode="r"):
                if path == "/dev/tty" and mode == "w":
                    return tty_output
                if path == "/dev/tty" and mode == "r":
                    return tty_input
                raise OSError("unexpected open")
            mock_open.side_effect = open_side_effect

            _monitor_proxy(
                ["fake", "log", "cmd"], stop,
                cage_name="test-cage", interactive=True,
            )

        mock_run.assert_not_called()

    @patch("agentcage.run.subprocess.run")
    @patch("agentcage.run.subprocess.Popen")
    def test_dedup_same_domain(self, mock_popen, mock_run):
        """Same domain is not prompted twice."""
        lines = [
            json.dumps({"decision": "blocked", "host": "api.stripe.com", "reason": "domain"}) + "\n",
            json.dumps({"decision": "blocked", "host": "api.stripe.com", "reason": "domain"}) + "\n",
        ]

        mock_proc = MagicMock()
        mock_proc.stdout = iter(lines)
        mock_proc.wait.return_value = 0
        mock_popen.return_value = mock_proc

        tty_output = _NoCloseStringIO()
        tty_input = _NoCloseStringIO("n\n")
        stop = threading.Event()

        with patch("builtins.open") as mock_open:
            def open_side_effect(path, mode="r"):
                if path == "/dev/tty" and mode == "w":
                    return tty_output
                if path == "/dev/tty" and mode == "r":
                    return tty_input
                raise OSError("unexpected open")
            mock_open.side_effect = open_side_effect

            _monitor_proxy(
                ["fake", "log", "cmd"], stop,
                cage_name="test-cage", interactive=True,
            )

        # Only one prompt despite two blocked entries
        assert tty_output.getvalue().count("Add stripe.com to allowlist?") == 1

    @patch("agentcage.run.subprocess.run")
    @patch("agentcage.run.subprocess.Popen")
    def test_dedup_subdomain_after_parent(self, mock_popen, mock_run):
        """If parent domain was prompted, subdomains are not re-prompted."""
        lines = [
            json.dumps({"decision": "blocked", "host": "api.stripe.com", "reason": "domain"}) + "\n",
            json.dumps({"decision": "blocked", "host": "cdn.stripe.com", "reason": "domain"}) + "\n",
        ]

        mock_proc = MagicMock()
        mock_proc.stdout = iter(lines)
        mock_proc.wait.return_value = 0
        mock_popen.return_value = mock_proc

        tty_output = _NoCloseStringIO()
        tty_input = _NoCloseStringIO("n\n")
        stop = threading.Event()

        with patch("builtins.open") as mock_open:
            def open_side_effect(path, mode="r"):
                if path == "/dev/tty" and mode == "w":
                    return tty_output
                if path == "/dev/tty" and mode == "r":
                    return tty_input
                raise OSError("unexpected open")
            mock_open.side_effect = open_side_effect

            _monitor_proxy(
                ["fake", "log", "cmd"], stop,
                cage_name="test-cage", interactive=True,
            )

        # Only one prompt — cdn.stripe.com resolves to stripe.com which was already prompted
        assert tty_output.getvalue().count("Add stripe.com to allowlist?") == 1

    @patch("agentcage.run.subprocess.Popen")
    def test_graceful_tty_error(self, mock_popen):
        """Monitor handles TTY open failure gracefully."""
        stop = threading.Event()

        with patch("builtins.open", side_effect=OSError("no tty")):
            # Should not raise
            _monitor_proxy(
                ["fake", "log", "cmd"], stop,
                cage_name="test-cage", interactive=True,
            )

    @patch("agentcage.run.subprocess.run")
    @patch("agentcage.run.subprocess.Popen")
    def test_decline_does_not_add(self, mock_popen, mock_run):
        """Answering 'n' or empty does not call domain add."""
        log_line = json.dumps({
            "decision": "blocked", "host": "api.stripe.com", "reason": "domain",
        }) + "\n"

        mock_proc = MagicMock()
        mock_proc.stdout = iter([log_line])
        mock_proc.wait.return_value = 0
        mock_popen.return_value = mock_proc

        tty_output = _NoCloseStringIO()
        tty_input = _NoCloseStringIO("n\n")
        stop = threading.Event()

        with patch("builtins.open") as mock_open:
            def open_side_effect(path, mode="r"):
                if path == "/dev/tty" and mode == "w":
                    return tty_output
                if path == "/dev/tty" and mode == "r":
                    return tty_input
                raise OSError("unexpected open")
            mock_open.side_effect = open_side_effect

            _monitor_proxy(
                ["fake", "log", "cmd"], stop,
                cage_name="test-cage", interactive=True,
            )

        mock_run.assert_not_called()


class TestInteractiveDomainsCliFlag:
    """Test that the -i flag is accepted by the CLI."""

    def test_flag_accepted(self):
        """The -i flag should be recognized by the run command."""
        from click.testing import CliRunner
        from agentcage.cli import main

        runner = CliRunner()
        # Just check the flag is parsed — the command will fail because
        # the scaffold doesn't exist, but it should not fail on the flag.
        result = runner.invoke(main, ["run", "-i", "nonexistent-scaffold"])
        # Should fail with "Unknown scaffold" not "no such option: -i"
        assert "no such option" not in (result.output or "")
