"""Unit tests for the apple-container backend (offline; mocks subprocess)."""

from __future__ import annotations

import json
import platform
from unittest.mock import MagicMock, patch

import pytest

from agentcage.apple_container import cli as ac_cli
from agentcage.apple_container import prerequisites as ac_prereq
from agentcage.apple_container import scaffold as ac_scaffold
from agentcage.apple_container import wrapper as ac_wrapper
from agentcage.backends.apple_container import AppleContainerBackend
from agentcage.config import Config, default_isolation, validate_config


# ---------------------------------------------------------------------------
# prerequisites
# ---------------------------------------------------------------------------

def test_prereqs_non_darwin_blocks():
    with patch.object(platform, "system", return_value="Linux"):
        issues = ac_prereq.check_prerequisites()
    assert issues
    assert "macOS" in issues[0]


def test_prereqs_wrong_arch_flagged():
    with patch.object(platform, "system", return_value="Darwin"), \
         patch.object(platform, "machine", return_value="x86_64"), \
         patch.object(platform, "mac_ver", return_value=("26.0.0", ("", "", ""), "x86_64")), \
         patch.object(ac_cli, "container_binary", return_value="/usr/local/bin/container"), \
         patch.object(ac_cli, "system_running", return_value=True):
        issues = ac_prereq.check_prerequisites()
    assert any("Apple Silicon" in s for s in issues)


def test_prereqs_macos_too_old_flagged():
    with patch.object(platform, "system", return_value="Darwin"), \
         patch.object(platform, "machine", return_value="arm64"), \
         patch.object(platform, "mac_ver", return_value=("15.6.1", ("", "", ""), "arm64")), \
         patch.object(ac_cli, "container_binary", return_value="/usr/local/bin/container"), \
         patch.object(ac_cli, "system_running", return_value=True):
        issues = ac_prereq.check_prerequisites()
    assert any("macOS 26+" in s for s in issues)


def test_prereqs_cli_missing_flagged():
    with patch.object(platform, "system", return_value="Darwin"), \
         patch.object(platform, "machine", return_value="arm64"), \
         patch.object(platform, "mac_ver", return_value=("26.0.0", ("", "", ""), "arm64")), \
         patch.object(ac_cli, "container_binary", return_value=None):
        issues = ac_prereq.check_prerequisites()
    assert any("'container' CLI not found" in s for s in issues)


def test_prereqs_apiserver_stopped_distinct_from_missing():
    """We want different hints for 'not installed' vs 'installed but stopped'."""
    with patch.object(platform, "system", return_value="Darwin"), \
         patch.object(platform, "machine", return_value="arm64"), \
         patch.object(platform, "mac_ver", return_value=("26.0.0", ("", "", ""), "arm64")), \
         patch.object(ac_cli, "container_binary", return_value="/usr/local/bin/container"), \
         patch.object(ac_cli, "system_running", return_value=False):
        issues = ac_prereq.check_prerequisites()
    assert any("apiserver is not running" in s for s in issues)


# ---------------------------------------------------------------------------
# config validation
# ---------------------------------------------------------------------------

def test_apple_container_isolation_value_accepted():
    cfg = Config(name="t", isolation="apple-container")
    cfg.container.image = "alpine:3.20"
    with patch.object(platform, "system", return_value="Darwin"), \
         patch.object(platform, "machine", return_value="arm64"):
        validate_config(cfg)  # should not raise


def test_apple_container_isolation_rejects_linux():
    cfg = Config(name="t", isolation="apple-container")
    cfg.container.image = "alpine:3.20"
    with patch.object(platform, "system", return_value="Linux"):
        with pytest.raises(ValueError, match="requires macOS"):
            validate_config(cfg)


def test_apple_container_isolation_rejects_intel():
    cfg = Config(name="t", isolation="apple-container")
    cfg.container.image = "alpine:3.20"
    with patch.object(platform, "system", return_value="Darwin"), \
         patch.object(platform, "machine", return_value="x86_64"):
        with pytest.raises(ValueError, match="Apple Silicon"):
            validate_config(cfg)


def test_default_isolation_linux_is_container():
    with patch.object(platform, "system", return_value="Linux"):
        assert default_isolation() == "container"


def test_default_isolation_intel_mac_is_vm():
    with patch.object(platform, "system", return_value="Darwin"), \
         patch.object(platform, "machine", return_value="x86_64"):
        assert default_isolation() == "vm"


def test_default_isolation_old_macos_is_vm():
    with patch.object(platform, "system", return_value="Darwin"), \
         patch.object(platform, "machine", return_value="arm64"), \
         patch.object(platform, "mac_ver", return_value=("15.6.1", ("", "", ""), "arm64")):
        assert default_isolation() == "vm"


def test_default_isolation_macos_26_without_container_cli_is_vm():
    with patch.object(platform, "system", return_value="Darwin"), \
         patch.object(platform, "machine", return_value="arm64"), \
         patch.object(platform, "mac_ver", return_value=("26.0.0", ("", "", ""), "arm64")), \
         patch.object(ac_cli, "container_binary", return_value=None):
        assert default_isolation() == "vm"


def test_default_isolation_macos_26_with_container_cli_is_apple_container():
    with patch.object(platform, "system", return_value="Darwin"), \
         patch.object(platform, "machine", return_value="arm64"), \
         patch.object(platform, "mac_ver", return_value=("26.3.2", ("", "", ""), "arm64")), \
         patch.object(ac_cli, "container_binary", return_value="/usr/local/bin/container"):
        assert default_isolation() == "apple-container"


def test_unknown_isolation_rejected():
    cfg = Config(name="t", isolation="banana")
    cfg.container.image = "alpine:3.20"
    with pytest.raises(ValueError, match="isolation must be"):
        validate_config(cfg)


# ---------------------------------------------------------------------------
# wrapper rendering
# ---------------------------------------------------------------------------

def test_render_wrapper_embeds_user_image():
    out = ac_wrapper.render_wrapper_containerfile(
        "docker.io/library/alpine:3.20",
        user_cmd=["sh", "-c", "echo hi"],
    )
    assert "FROM docker.io/library/alpine:3.20" in out
    # CMD is no longer in the Containerfile — it's written to cage-cmd.json
    # in the build context and COPY'd in. The Containerfile just declares
    # the COPY + the ENTRYPOINT.
    assert "COPY cage-cmd.json /etc/agentcage/cage-cmd.json" in out
    assert 'ENTRYPOINT ["/opt/agentcage/supervisor"]' in out


def test_stage_build_context_writes_cmd_json(tmp_path):
    ac_wrapper.stage_build_context(tmp_path, ["sh", "-c", "echo $FOO & wait"])
    assert (tmp_path / "supervisor.sh").exists()
    cmd_json = (tmp_path / "cage-cmd.json").read_text()
    assert json.loads(cmd_json) == ["sh", "-c", "echo $FOO & wait"]


def test_render_wrapper_requires_glibc_base():
    """The wrapper template hard-errors at build time on non-apt bases.

    mitmproxy's bundled binary is built against glibc; alpine/musl bases
    can't run it. The Containerfile contains an explicit check.
    """
    out = ac_wrapper.render_wrapper_containerfile(
        "alpine:3.20", user_cmd=["sh"],
    )
    assert "apt-get" in out
    assert "requires a glibc-based user image" in out
    assert "exit 78" in out


def test_stage_build_context_writes_allowlist(tmp_path):
    ac_wrapper.stage_build_context(
        tmp_path, ["sh"], allowlist=["example.com", "api.github.com"]
    )
    lines = (tmp_path / "allowlist.txt").read_text().splitlines()
    assert lines == ["example.com", "api.github.com"]


def test_stage_build_context_empty_allowlist_means_block_all(tmp_path):
    """Empty allowlist file is intentional — supervisor reads it as 'block all'."""
    ac_wrapper.stage_build_context(tmp_path, ["sh"], allowlist=None)
    assert (tmp_path / "allowlist.txt").read_text() == ""


def test_stage_build_context_includes_dnsmasq_conf(tmp_path):
    ac_wrapper.stage_build_context(tmp_path, ["sh"], allowlist=["a.com"])
    assert (tmp_path / "dnsmasq.conf").exists()
    # dnsmasq must forward to a real upstream so cage gets real IPs
    # (transparent mitmproxy needs SO_ORIGINAL_DST = real IP, not 127.0.0.1)
    assert "server=1.1.1.1" in (tmp_path / "dnsmasq.conf").read_text()


def test_stage_build_context_includes_allowlist_addon(tmp_path):
    """The mitmproxy addon that enforces the allowlist must be staged in."""
    ac_wrapper.stage_build_context(tmp_path, ["sh"], allowlist=["a.com"])
    assert (tmp_path / "allowlist_addon.py").exists()
    addon = (tmp_path / "allowlist_addon.py").read_text()
    assert "AllowlistAddon" in addon
    assert "403" in addon  # must respond with 403, not silently pass


def test_supervisor_resolves_cage_user_dynamically(tmp_path):
    """REGRESSION: capsh's `--user=` resolves by NAME, so a hard-coded
    `--user=cage` blows up on images that already have a different uid-1000
    user (ubuntu → `ubuntu`, node → `node`, claude-code → `claude`). The
    supervisor must look up the uid-1000 name at runtime before exec'ing
    capsh, otherwise stage 90 dies with `User [cage] not known` and the
    whole container exits before any cage workload starts."""
    ac_wrapper.stage_build_context(tmp_path, ["sh"], allowlist=["a.com"])
    sup = (tmp_path / "supervisor.sh").read_text()
    # The name MUST be resolved from /etc/passwd at runtime.
    assert "getent passwd 1000" in sup
    # The capsh invocation that drops caps + switches to the cage user
    # MUST reference the resolved variable, not the literal `cage`. We
    # find the line by looking for the `--user=` argument that follows
    # `--drop=all` (the capsh pattern unique to stage 90).
    lines = sup.splitlines()
    cage_user_idx = next(
        (i for i, ln in enumerate(lines)
         if ln.strip().startswith("--drop=all") and not ln.lstrip().startswith("#")),
        None,
    )
    assert cage_user_idx is not None, (
        "supervisor.sh has no executable `--drop=all` (stage 90 capsh)"
    )
    # The `--user=` argument follows on the next non-blank line.
    follow = lines[cage_user_idx + 1].strip()
    assert follow.startswith("--user="), (
        f"expected --user= to follow --drop=all, got: {follow!r}"
    )
    assert "${CAGE_USER}" in follow, (
        f"capsh --user= for the cage workload must reference $CAGE_USER, "
        f"got: {follow!r}"
    )


def test_ubuntu_scaffold_ca_install_tolerates_eacces():
    """REGRESSION: the ubuntu scaffold's `command` runs `cp` into a root-only
    directory. On the container backend the cage runs as root so it works;
    on apple-container the supervisor forces the cage workload to uid 1000,
    which can't write to /usr/local/share/ca-certificates. Without the
    `|| true` swallow the cp's EACCES would propagate, the cage CMD would
    exit non-zero, and the container would stop before `sleep infinity` —
    making `agentcage run ubuntu` look like an instant exit."""
    from pathlib import Path
    scaffold = (
        Path(__file__).resolve().parent.parent
        / "src" / "agentcage" / "scaffolds" / "ubuntu" / "cage.yaml.j2"
    )
    content = scaffold.read_text()
    # The whole cp+update-ca-certificates pair must be guarded by `|| true`
    # so a permission error doesn't kill the cage on apple-container.
    assert "|| true" in content
    # `exec sleep infinity` must still be reachable after the guard.
    assert "exec sleep infinity" in content


def test_user_cmd_missing_image_raises():
    with patch.object(ac_cli, "image_inspect", return_value=None):
        with pytest.raises(ValueError, match="cannot inspect"):
            ac_wrapper._user_cmd("missing:tag")


def test_user_cmd_no_entrypoint_or_cmd_raises():
    with patch.object(ac_cli, "image_inspect", return_value={"config": {}}):
        with pytest.raises(ValueError, match="neither ENTRYPOINT nor CMD"):
            ac_wrapper._user_cmd("empty:tag")


def test_user_cmd_combines_entrypoint_and_cmd():
    inspect = {"config": {"entrypoint": ["mitmdump", "-s"], "cmd": ["/app/addon.py"]}}
    with patch.object(ac_cli, "image_inspect", return_value=inspect):
        cmd = ac_wrapper._user_cmd("img:tag")
    assert cmd == ["mitmdump", "-s", "/app/addon.py"]


def test_user_cmd_handles_apple_variants_schema():
    """Apple's actual `image inspect` nests config under variants[i].config.config."""
    inspect = {
        "name": "img:tag",
        "variants": [
            {
                "platform": {"os": "linux", "architecture": "arm64"},
                "config": {"config": {"Cmd": ["sh", "-c", "echo hi"]}},
            }
        ],
    }
    with patch.object(ac_cli, "image_inspect", return_value=inspect):
        cmd = ac_wrapper._user_cmd("img:tag")
    assert cmd == ["sh", "-c", "echo hi"]


def test_user_cmd_prefers_arm64_variant():
    inspect = {
        "variants": [
            {"platform": {"architecture": "amd64"},
             "config": {"config": {"Cmd": ["x86only"]}}},
            {"platform": {"architecture": "arm64"},
             "config": {"config": {"Cmd": ["arm64only"]}}},
        ],
    }
    with patch.object(ac_cli, "image_inspect", return_value=inspect):
        cmd = ac_wrapper._user_cmd("img:tag")
    assert cmd == ["arm64only"]


def test_user_cmd_handles_capitalized_keys():
    """Apple's inspect schema may use 'Config' / 'Cmd' (OCI-style)."""
    inspect = {"Config": {"Cmd": ["node", "server.js"]}}
    with patch.object(ac_cli, "image_inspect", return_value=inspect):
        cmd = ac_wrapper._user_cmd("img:tag")
    assert cmd == ["node", "server.js"]


# ---------------------------------------------------------------------------
# cli helpers
# ---------------------------------------------------------------------------

def test_inspect_returns_first_when_list():
    fake_cp = type("CP", (), {"returncode": 0, "stdout": '[{"a": 1}]'})()
    with patch.object(ac_cli, "run", return_value=fake_cp):
        result = ac_cli.inspect("x")
    assert result == {"a": 1}


def test_inspect_returns_none_on_nonzero_exit():
    fake_cp = type("CP", (), {"returncode": 1, "stdout": ""})()
    with patch.object(ac_cli, "run", return_value=fake_cp):
        assert ac_cli.inspect("x") is None


# ---------------------------------------------------------------------------
# build_artifacts: cage.yaml command precedence + ordering
# ---------------------------------------------------------------------------


def _ok_run(*args, **kwargs):  # noqa: ARG001
    """Fake subprocess.CompletedProcess-ish for ac_cli.run that always succeeds."""
    return type("CP", (), {"returncode": 0, "stdout": "", "stderr": ""})()


def test_build_artifacts_prefers_cage_yaml_command():
    """cage.yaml `container.command:` wins over the user image's OCI CMD.

    Regression test for the bug where the apple-container backend silently
    ignored cage.yaml `command:` and exec'd the base image's CMD (e.g.
    ubuntu → `/bin/bash`), causing `agentcage run ubuntu` to exit instantly.
    """
    cfg = Config(name="t", isolation="apple-container")
    cfg.container.image = "docker.io/library/ubuntu:24.04"
    cfg.container.command = ["sh", "-c", "exec sleep infinity"]

    with patch.object(ac_cli, "run", side_effect=_ok_run) as run_mock, \
         patch.object(ac_cli, "image_inspect", return_value={"config": {"Cmd": ["/bin/bash"]}}), \
         patch.object(ac_wrapper, "_user_cmd", return_value=["/bin/bash"]) as user_cmd_mock, \
         patch.object(ac_wrapper, "build_wrapper", return_value="img") as build_mock:
        AppleContainerBackend().build_artifacts(cfg, "deploy", quiet=True)

    # When cage.yaml sets command, we must NOT fall through to image inspect.
    user_cmd_mock.assert_not_called()
    # And the wrapper build must receive the cage.yaml command verbatim.
    assert build_mock.call_count == 1
    kwargs = build_mock.call_args.kwargs
    assert kwargs["user_cmd"] == ["sh", "-c", "exec sleep infinity"]
    # `image pull` must still have run.
    assert any(
        call.args and call.args[0][:2] == ["image", "pull"]
        for call in run_mock.call_args_list
    )


def test_build_artifacts_falls_back_to_user_cmd_when_unset():
    """No cage.yaml command → inspect the user image's OCI CMD as before."""
    cfg = Config(name="t", isolation="apple-container")
    cfg.container.image = "docker.io/library/alpine:3.20"
    # command is the default empty list — falsy.
    assert cfg.container.command == []

    with patch.object(ac_cli, "run", side_effect=_ok_run), \
         patch.object(ac_cli, "image_inspect", return_value={"config": {"Cmd": ["/bin/sh"]}}), \
         patch.object(ac_wrapper, "_user_cmd", return_value=["/bin/sh"]) as user_cmd_mock, \
         patch.object(ac_wrapper, "build_wrapper", return_value="img") as build_mock:
        AppleContainerBackend().build_artifacts(cfg, "deploy", quiet=True)

    user_cmd_mock.assert_called_once_with("docker.io/library/alpine:3.20")
    assert build_mock.call_args.kwargs["user_cmd"] == ["/bin/sh"]


def test_build_artifacts_orders_scaffold_then_pull_then_wrapper():
    """Scaffold images must build BEFORE pull, and pull BEFORE wrapper build.

    The wrapper's `FROM <user_image>` references a scaffold-produced tag, so
    flipping these would leave the wrapper build referencing a tag that
    doesn't yet exist.
    """
    cfg = Config(name="t", isolation="apple-container")
    cfg.container.image = "localhost/agentcage-ubuntu:latest"
    cfg.scaffold = "ubuntu"

    calls: list[str] = []

    def scaffold_side_effect(scaffold, *, quiet=False):  # noqa: ARG001
        calls.append("scaffold")

    def run_side_effect(argv, **kwargs):  # noqa: ARG001
        if argv[:2] == ["image", "pull"]:
            calls.append("pull")
        return type("CP", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    def build_wrapper_side_effect(*args, **kwargs):  # noqa: ARG001
        calls.append("wrapper")
        return "img"

    with patch.object(ac_scaffold, "build_scaffold_images", side_effect=scaffold_side_effect), \
         patch.object(ac_cli, "run", side_effect=run_side_effect), \
         patch.object(ac_cli, "image_inspect", return_value={"config": {"Cmd": ["/bin/bash"]}}), \
         patch.object(ac_wrapper, "_user_cmd", return_value=["/bin/bash"]), \
         patch.object(ac_wrapper, "build_wrapper", side_effect=build_wrapper_side_effect):
        AppleContainerBackend().build_artifacts(cfg, "deploy", quiet=True)

    # Only the first occurrence of each matters; pull can be called more than
    # once depending on internal retries, but the ordering invariant is fixed.
    first_idx = {step: calls.index(step) for step in ("scaffold", "pull", "wrapper")}
    assert first_idx["scaffold"] < first_idx["pull"] < first_idx["wrapper"]


def test_build_artifacts_no_cmd_anywhere_raises_helpful_error():
    """If neither cage.yaml nor the image declare a CMD, fail with a clear hint."""
    cfg = Config(name="t", isolation="apple-container")
    cfg.container.image = "docker.io/library/scratch:latest"

    with patch.object(ac_cli, "run", side_effect=_ok_run), \
         patch.object(ac_cli, "image_inspect", return_value={"config": {}}), \
         patch.object(
             ac_wrapper, "_user_cmd",
             side_effect=ValueError("image has neither ENTRYPOINT nor CMD"),
         ), \
         patch.object(ac_wrapper, "build_wrapper", new=MagicMock()):
        with pytest.raises(RuntimeError, match="cannot determine cage entrypoint"):
            AppleContainerBackend().build_artifacts(cfg, "deploy", quiet=True)


def test_run_streaming_pauses_active_spinner():
    """``ac_cli.run(capture_output=False)`` must wrap subprocess.run in
    ``output.pause_active_spinner()`` so Apple's CLI progress doesn't fight
    our braille spinner for the same terminal line.
    """
    from agentcage import output as ac_output

    events: list[str] = []

    fake_spinner = type(
        "FakeSpinner", (), {
            "pause": lambda self: events.append("pause"),
            "resume": lambda self: events.append("resume"),
        },
    )()

    def fake_subprocess_run(*_args, **_kwargs):
        events.append("subprocess.run")
        return type("CP", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    with patch.object(ac_cli, "container_binary", return_value="/usr/local/bin/container"), \
         patch.object(ac_output, "_active", fake_spinner), \
         patch("agentcage.apple_container.cli.subprocess.run", side_effect=fake_subprocess_run):
        ac_cli.run(["image", "pull", "alpine"], check=False, capture_output=False)

    # pause must happen before the subprocess starts, resume after it returns.
    assert events == ["pause", "subprocess.run", "resume"]


def test_run_capturing_does_not_pause_active_spinner():
    """The capturing path is silent on stderr -- no need to pause the spinner."""
    from agentcage import output as ac_output

    events: list[str] = []

    fake_spinner = type(
        "FakeSpinner", (), {
            "pause": lambda self: events.append("pause"),
            "resume": lambda self: events.append("resume"),
        },
    )()

    def fake_subprocess_run(*_args, **_kwargs):
        events.append("subprocess.run")
        return type("CP", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    with patch.object(ac_cli, "container_binary", return_value="/usr/local/bin/container"), \
         patch.object(ac_output, "_active", fake_spinner), \
         patch("agentcage.apple_container.cli.subprocess.run", side_effect=fake_subprocess_run):
        ac_cli.run(["inspect", "x"], check=False, capture_output=True)

    assert events == ["subprocess.run"]
