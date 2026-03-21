"""Tests for the agentcage update command."""

from __future__ import annotations

from unittest.mock import patch, MagicMock

from click.testing import CliRunner

from agentcage.cli import main, _fetch_latest_pypi_version, _detect_installer


def _runner():
    return CliRunner()


class TestFetchLatestVersion:
    @patch("urllib.request.urlopen")
    def test_returns_version(self, mock_urlopen):
        import json
        resp = MagicMock()
        resp.read.return_value = json.dumps({"info": {"version": "1.2.3"}}).encode()
        resp.__enter__ = lambda s: s
        resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = resp

        assert _fetch_latest_pypi_version() == "1.2.3"

    @patch("urllib.request.urlopen", side_effect=OSError("no network"))
    def test_returns_none_on_error(self, _mock):
        assert _fetch_latest_pypi_version() is None


class TestDetectInstaller:
    @patch("shutil.which")
    @patch("subprocess.run")
    def test_detects_uv(self, mock_run, mock_which):
        mock_which.side_effect = lambda x: "/usr/bin/uv" if x == "uv" else None
        mock_run.return_value = MagicMock(returncode=0, stdout="agentcage 0.10.0\n")

        assert _detect_installer() == "uv"

    @patch("shutil.which")
    @patch("subprocess.run")
    def test_detects_pipx(self, mock_run, mock_which):
        # uv not found, only pipx is available
        mock_which.side_effect = lambda x: "/usr/bin/pipx" if x == "pipx" else None
        mock_run.return_value = MagicMock(returncode=0, stdout="agentcage 0.10.0\n")

        assert _detect_installer() == "pipx"

    @patch("shutil.which", return_value=None)
    def test_returns_none_when_no_tool(self, _mock):
        assert _detect_installer() is None


class TestUpdateCommand:
    @patch("agentcage.cli._fetch_latest_pypi_version", return_value="0.10.0")
    def test_already_up_to_date(self, _mock):
        result = _runner().invoke(main, ["update"])
        assert result.exit_code == 0
        assert "Already up to date" in result.output

    @patch("agentcage.cli._fetch_latest_pypi_version", return_value="99.0.0")
    def test_check_only(self, _mock):
        result = _runner().invoke(main, ["update", "--check"])
        assert result.exit_code == 0
        assert "New version available: 99.0.0" in result.output

    @patch("agentcage.cli._fetch_latest_pypi_version", return_value=None)
    def test_pypi_unreachable(self, _mock):
        result = _runner().invoke(main, ["update"])
        assert result.exit_code != 0
        assert "could not reach PyPI" in result.output

    @patch("subprocess.run", return_value=MagicMock(returncode=0))
    @patch("agentcage.cli._detect_installer", return_value="uv")
    @patch("agentcage.cli._fetch_latest_pypi_version", return_value="99.0.0")
    def test_updates_via_uv(self, _pypi, _inst, mock_run):
        result = _runner().invoke(main, ["update"])
        assert result.exit_code == 0
        assert "Updated agentcage to 99.0.0" in result.output
        mock_run.assert_called_once_with(
            ["uv", "tool", "install", "--upgrade", "agentcage"]
        )

    @patch("agentcage.cli._detect_installer", return_value=None)
    @patch("agentcage.cli._fetch_latest_pypi_version", return_value="99.0.0")
    def test_no_installer_detected(self, _pypi, _inst):
        result = _runner().invoke(main, ["update"])
        assert result.exit_code != 0
        assert "Could not detect installer" in result.output
