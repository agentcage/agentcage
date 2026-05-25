"""Unit tests for the apple-container backend (offline; mocks subprocess)."""

from __future__ import annotations

import importlib.util
import json
import platform
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from agentcage.apple_container import cli as ac_cli
from agentcage.apple_container import prerequisites as ac_prereq
from agentcage.apple_container import scaffold as ac_scaffold
from agentcage.apple_container import wrapper as ac_wrapper
from agentcage.backends.apple_container import AppleContainerBackend
from agentcage.config import Config, default_isolation, validate_config


# ── allowlist_addon import helper ────────────────────────────
# The addon file ships inside the wheel as a data file (it runs
# *inside* the cage's mitmproxy process, not in the host Python).
# To unit-test ``AllowlistAddon`` from the host, we load it by
# absolute path; conftest.py already stubs ``mitmproxy`` so the
# import succeeds without the real proxy bundle being installed.

_ADDON_PATH = (
    Path(__file__).parent.parent
    / "src" / "agentcage" / "data" / "apple-container" / "allowlist_addon.py"
)


def _load_addon_module():
    spec = importlib.util.spec_from_file_location(
        "_test_allowlist_addon", _ADDON_PATH,
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


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


def test_render_wrapper_handles_apk_and_non_apt():
    """The wrapper template detects apk (alpine) explicitly with a
    pointer to the workaround, and falls through with a clear error
    for unknown distros. Both still `exit 78` at build time — the
    apple-container backend cannot run on non-glibc images today
    (mitmproxy's PyInstaller bundle is glibc-only; the musl pip
    install path needs rust 1.88+ which alpine doesn't ship even in
    3.22). Tracked in #120 with the multi-stage builder design."""
    out = ac_wrapper.render_wrapper_containerfile(
        "alpine:3.20", user_cmd=["sh"],
    )
    assert "apt-get" in out
    assert "apk" in out
    # Alpine path: actionable error with workaround.
    assert "does not yet support alpine" in out
    assert "vm" in out  # vm isolation listed as workaround
    # Fallthrough for other distros (no apt + no apk).
    assert "alpine/musl and other distros not yet wired" in out
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


def test_stage_build_context_includes_secret_injection_rules(tmp_path):
    """secret_injection rules baked into the wrapper image at build time —
    the actual secret VALUES are env-passed at container run time so the
    image stays free of credentials. The mitmproxy addon reads the rule
    list from /etc/agentcage/secret_injection.json at startup and resolves
    each `env` against os.environ."""
    rules = [
        {"env": "API_KEY", "placeholder": "{{API_KEY}}",
         "inject_to": ["api.example.com"]},
    ]
    ac_wrapper.stage_build_context(
        tmp_path, ["sh"], allowlist=["a.com"], secret_injection_rules=rules,
    )
    si = json.loads((tmp_path / "secret_injection.json").read_text())
    assert si == rules


def test_stage_build_context_empty_secret_injection(tmp_path):
    """No rules → empty list (NOT a missing file), so the addon's loader
    can read+parse unconditionally."""
    ac_wrapper.stage_build_context(tmp_path, ["sh"], allowlist=["a.com"])
    assert (tmp_path / "secret_injection.json").exists()
    assert json.loads((tmp_path / "secret_injection.json").read_text()) == []


def test_stage_build_context_writes_transform_field(tmp_path):
    """Rules with a ``transform`` field flow through the build context.

    The in-cage addon dispatches on this string at startup to mint a
    derived substitution value (e.g. a Google OAuth bearer) instead of
    using the raw env-passed credential. ``transform_config`` rides
    along so transforms like google-jwt-bearer can configure their
    scopes/audience without leaking the SA key into the image layer.
    """
    rules = [
        {
            "env": "GCP_SA_KEY",
            "placeholder": "{{GCP_BEARER}}",
            "inject_to": ["googleapis.com"],
            "transform": "google-jwt-bearer",
            "transform_config": {
                "scopes": ["https://www.googleapis.com/auth/calendar.readonly"],
            },
        },
    ]
    ac_wrapper.stage_build_context(
        tmp_path, ["sh"], allowlist=["googleapis.com"],
        secret_injection_rules=rules,
    )
    si = json.loads((tmp_path / "secret_injection.json").read_text())
    assert si == rules
    # The transforms package must be staged as a tarball so the in-cage
    # addon can ``import transforms`` after ADD-extraction. (Plain COPY
    # of a directory silently empties the target on Apple's container
    # build 0.5+; the tarball ADD path dodges that quirk.)
    archive = tmp_path / "transforms.tar.gz"
    assert archive.exists()
    import tarfile as _tf
    with _tf.open(archive) as tar:
        names = sorted(tar.getnames())
    assert "__init__.py" in names
    assert "google_jwt_bearer.py" in names


def test_stage_build_context_stages_transforms_even_without_rules(tmp_path):
    """The transforms tarball is unconditionally staged — cheap, and
    avoids a class of "transform added in cage.yaml after image build →
    silent skip" bugs. The addon will still no-op on an empty rule list."""
    ac_wrapper.stage_build_context(tmp_path, ["sh"], allowlist=["a.com"])
    assert (tmp_path / "transforms.tar.gz").exists()


def test_stage_build_context_excludes_pycache_from_transforms(tmp_path, monkeypatch):
    """__pycache__ is host-local Python bytecode — packing it into the
    image layer wastes space and ruins layer determinism. The tarball
    must filter it out."""
    # Create a fake transforms src with a __pycache__ subdir so we can
    # observe the filter without touching the real package on disk.
    fake_src = tmp_path / "fake_src"
    fake_src.mkdir()
    (fake_src / "__init__.py").write_text("# real")
    (fake_src / "google_jwt_bearer.py").write_text("# real")
    (fake_src / "__pycache__").mkdir()
    (fake_src / "__pycache__" / "garbage.pyc").write_bytes(b"\x00\x00\x00")

    monkeypatch.setattr(ac_wrapper, "_TRANSFORMS_SRC", fake_src)

    ac_wrapper.stage_build_context(tmp_path, ["sh"], allowlist=["a.com"])

    import tarfile as _tf
    with _tf.open(tmp_path / "transforms.tar.gz") as tar:
        names = tar.getnames()
    assert not any("__pycache__" in n for n in names), names


def test_wrapper_containerfile_adds_transforms_tarball():
    """The Containerfile must ADD the transforms tarball (auto-extracted
    by OCI build) so ``from transforms import get`` resolves at runtime.
    We deliberately don't `COPY transforms /opt/agentcage/transforms`
    because Apple's container build silently drops the contents of a
    directory COPY — the target dir exists but is empty."""
    out = ac_wrapper.render_wrapper_containerfile(
        "docker.io/library/alpine:3.20",
        user_cmd=["sh", "-c", "echo hi"],
    )
    assert "ADD transforms.tar.gz /opt/agentcage/transforms/" in out
    # And we must NOT regress to the broken directory-COPY form.
    assert "COPY transforms /opt/agentcage/transforms" not in out


def test_backend_threads_transform_into_build_artifacts(tmp_path, monkeypatch):
    """The apple-container backend must forward ``transform`` and
    ``transform_config`` from the parsed Config through to wrapper.
    Catches the silent-drop regression: rule loaded fine, image built
    fine, but the cage saw only ``env/placeholder/inject_to``."""
    captured: dict = {}

    def fake_build_wrapper(_name, _image, **kwargs):
        captured["secret_injection_rules"] = kwargs.get("secret_injection_rules")
        return "localhost/agentcage-apple-test:latest"

    # Patch the wrapper as imported by the backend module — it does
    # ``from agentcage.apple_container import wrapper as ac_wrapper`` so
    # the backend's own binding is what we need to override.
    from agentcage.backends import apple_container as backend_mod
    monkeypatch.setattr(backend_mod.ac_wrapper, "build_wrapper", fake_build_wrapper)
    monkeypatch.setattr(
        ac_cli, "image_inspect",
        lambda _img: {"config": {"cmd": ["/bin/sh"]}},
    )
    # `build_artifacts` shells out to `container image pull`; fake it.
    monkeypatch.setattr(
        ac_cli, "run",
        lambda *_a, **_kw: type(
            "CP", (), {"returncode": 0, "stdout": "", "stderr": ""},
        )(),
    )

    from agentcage.config import SecretInjectionRule
    cfg = Config(name="t", isolation="apple-container")
    cfg.container.image = "localhost/test:latest"
    # Set a command so _user_cmd isn't consulted.
    cfg.container.command = ["/bin/sh"]
    cfg.secret_injection = [
        SecretInjectionRule(
            env="GCP_SA_KEY",
            placeholder="{{GCP_BEARER}}",
            inject_to=["googleapis.com"],
            transform="google-jwt-bearer",
            transform_config={"scopes": ["a"]},
        ),
    ]
    cfg.domains.allow = ["googleapis.com"]

    AppleContainerBackend().build_artifacts(cfg, "deploy", quiet=True)

    rules = captured["secret_injection_rules"]
    assert len(rules) == 1
    assert rules[0]["transform"] == "google-jwt-bearer"
    assert rules[0]["transform_config"] == {"scopes": ["a"]}


def test_allowlist_addon_runs_transform_at_request_time(monkeypatch, tmp_path):
    """End-to-end addon test: a rule with ``transform`` set must inject
    the transform's return value into the outbound request — NOT the
    raw env-passed credential. This is the load-bearing assertion for
    the whole feature.

    Uses a fake transform registered in-process so we don't need
    cryptography or network access.
    """
    # Write a rule list with a transform; point the addon at it.
    rules = [{
        "env": "SECRET_INPUT",
        "placeholder": "{{TOKEN}}",
        "inject_to": ["api.example.com"],
        "transform": "_test_marker",
        "transform_config": {"marker": "transformed-output-marker"},
    }]
    rule_file = tmp_path / "secret_injection.json"
    rule_file.write_text(json.dumps(rules))
    (tmp_path / "allowlist.txt").write_text("api.example.com\n")

    # Set the raw env input that the cage agent would normally send;
    # the test asserts the upstream sees the TRANSFORMED value instead.
    monkeypatch.setenv("SECRET_INPUT", "raw-input-value")
    monkeypatch.setenv("AGENTCAGE_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("AGENTCAGE_CAPTURE", str(tmp_path / "capture.jsonl"))

    # Import the addon AFTER setting the env so module-level path constants
    # resolve to tmp_path. The addon is read from data/apple-container/.
    import importlib
    import sys
    addon_dir = (
        # tests/  -> repo root -> src/agentcage/data/apple-container/
        __import__("pathlib").Path(__file__).resolve().parent.parent
        / "src" / "agentcage" / "data" / "apple-container"
    )
    transforms_src = (
        addon_dir.parent / "proxy" / "transforms"
    )
    monkeypatch.syspath_prepend(str(addon_dir))
    monkeypatch.syspath_prepend(str(transforms_src.parent))

    # Register a no-op transform that returns the configured marker so
    # we don't need cryptography / network. This is the SAME registry the
    # addon uses; the registration must happen before AllowlistAddon's
    # __init__ runs (which is where transforms are bound).
    import transforms as _t  # noqa: WPS433  (test-only)
    importlib.reload(_t)

    class _MarkerTransform:
        def __init__(self, secret: str, config: dict) -> None:
            self._marker = config["marker"]
            self._secret = secret

        def get_value(self) -> str:
            return self._marker

    _t.register("_test_marker", _MarkerTransform)

    # Point the addon's module-level paths at our tmp files BEFORE import.
    sys.modules.pop("allowlist_addon", None)
    allowlist_addon = importlib.import_module("allowlist_addon")
    allowlist_addon.SECRET_INJECTION_PATH = str(rule_file)
    allowlist_addon.ALLOWLIST_PATH = str(tmp_path / "allowlist.txt")

    addon = allowlist_addon.AllowlistAddon()

    # Sanity: rule was resolved AND a transform_fn was bound.
    assert len(addon._resolved_secrets) == 1
    resolved = addon._resolved_secrets[0]
    assert resolved["transform"] == "_test_marker"
    assert resolved["transform_fn"] is not None
    # The raw env value is still cached on the resolved rule (so the
    # original injection path stays available for non-transform rules)
    # — but it MUST NOT be the value sent on the wire.
    assert resolved["value"] == "raw-input-value"

    # Build a fake flow with the placeholder in the Authorization header.
    fake_flow = MagicMock()
    fake_flow.request.pretty_host = "api.example.com"
    fake_flow.request.headers = {"Authorization": "Bearer {{TOKEN}}"}

    # `headers` needs the in-place mutation pattern the real addon uses.
    class _Headers(dict):
        def items(self):
            return list(super().items())

    fake_flow.request.headers = _Headers(
        {"Authorization": "Bearer {{TOKEN}}"}
    )
    fake_flow.request.get_text = lambda strict=False: ""
    fake_flow.request.set_text = lambda _t: None

    injected, transforms_map = addon._maybe_inject(fake_flow)

    # The transform's marker — NOT the raw env value — landed in the header.
    assert (
        fake_flow.request.headers["Authorization"]
        == "Bearer transformed-output-marker"
    )
    assert "raw-input-value" not in fake_flow.request.headers["Authorization"]
    assert injected == ["SECRET_INPUT"]
    assert transforms_map == {"SECRET_INPUT": "_test_marker"}


def test_allowlist_addon_skips_rule_on_transform_init_failure(
    monkeypatch, tmp_path,
):
    """A transform that raises during ``__init__`` must drop the rule at
    startup (with a warning) — NOT crash the whole addon and NOT fall
    back to substituting the raw env-passed credential. Failing closed
    is the safety-critical contract."""
    rules = [{
        "env": "SECRET_INPUT",
        "placeholder": "{{TOKEN}}",
        "inject_to": ["api.example.com"],
        "transform": "_test_broken_init",
        "transform_config": {},
    }]
    rule_file = tmp_path / "secret_injection.json"
    rule_file.write_text(json.dumps(rules))
    (tmp_path / "allowlist.txt").write_text("api.example.com\n")
    monkeypatch.setenv("SECRET_INPUT", "raw-input-value")
    monkeypatch.setenv("AGENTCAGE_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("AGENTCAGE_CAPTURE", str(tmp_path / "capture.jsonl"))

    import importlib
    import sys
    addon_dir = (
        __import__("pathlib").Path(__file__).resolve().parent.parent
        / "src" / "agentcage" / "data" / "apple-container"
    )
    transforms_src = addon_dir.parent / "proxy" / "transforms"
    monkeypatch.syspath_prepend(str(addon_dir))
    monkeypatch.syspath_prepend(str(transforms_src.parent))

    import transforms as _t
    importlib.reload(_t)

    class _BrokenInit:
        def __init__(self, *_a, **_kw):
            raise RuntimeError("intentional test failure")

        def get_value(self) -> str:  # pragma: no cover
            return "unreachable"

    _t.register("_test_broken_init", _BrokenInit)

    sys.modules.pop("allowlist_addon", None)
    allowlist_addon = importlib.import_module("allowlist_addon")
    allowlist_addon.SECRET_INJECTION_PATH = str(rule_file)
    allowlist_addon.ALLOWLIST_PATH = str(tmp_path / "allowlist.txt")
    addon = allowlist_addon.AllowlistAddon()

    # Rule dropped, NOT substituted with raw value.
    assert addon._resolved_secrets == []


def test_allowlist_addon_skips_request_on_transform_runtime_failure(
    monkeypatch, tmp_path,
):
    """If the transform raises at substitution time, the placeholder is
    left in place — the upstream request fails closed with an auth error
    rather than smuggling the raw credential through. No fallback to the
    raw env value (which is the point of having a transform in the first
    place)."""
    rules = [{
        "env": "SECRET_INPUT",
        "placeholder": "{{TOKEN}}",
        "inject_to": ["api.example.com"],
        "transform": "_test_runtime_fail",
        "transform_config": {},
    }]
    rule_file = tmp_path / "secret_injection.json"
    rule_file.write_text(json.dumps(rules))
    (tmp_path / "allowlist.txt").write_text("api.example.com\n")
    monkeypatch.setenv("SECRET_INPUT", "raw-input-value")
    monkeypatch.setenv("AGENTCAGE_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("AGENTCAGE_CAPTURE", str(tmp_path / "capture.jsonl"))

    import importlib
    import sys
    addon_dir = (
        __import__("pathlib").Path(__file__).resolve().parent.parent
        / "src" / "agentcage" / "data" / "apple-container"
    )
    transforms_src = addon_dir.parent / "proxy" / "transforms"
    monkeypatch.syspath_prepend(str(addon_dir))
    monkeypatch.syspath_prepend(str(transforms_src.parent))

    import transforms as _t
    importlib.reload(_t)

    class _RuntimeFail:
        def __init__(self, *_a, **_kw):
            pass

        def get_value(self) -> str:
            raise RuntimeError("mint failed")

    _t.register("_test_runtime_fail", _RuntimeFail)

    sys.modules.pop("allowlist_addon", None)
    allowlist_addon = importlib.import_module("allowlist_addon")
    allowlist_addon.SECRET_INJECTION_PATH = str(rule_file)
    allowlist_addon.ALLOWLIST_PATH = str(tmp_path / "allowlist.txt")
    addon = allowlist_addon.AllowlistAddon()

    class _Headers(dict):
        def items(self):
            return list(super().items())

    fake_flow = MagicMock()
    fake_flow.request.pretty_host = "api.example.com"
    fake_flow.request.headers = _Headers(
        {"Authorization": "Bearer {{TOKEN}}"}
    )
    fake_flow.request.get_text = lambda strict=False: ""
    fake_flow.request.set_text = lambda _t: None

    injected, transforms_map = addon._maybe_inject(fake_flow)

    # Header UNCHANGED — placeholder stays, raw value never leaks.
    assert (
        fake_flow.request.headers["Authorization"] == "Bearer {{TOKEN}}"
    )
    assert "raw-input-value" not in fake_flow.request.headers["Authorization"]
    assert injected == []
    assert transforms_map == {}


def test_generate_units_persists_autostart_flag():
    """`apple_container_autostart: true` in cage.yaml flows into the unit
    JSON's `autostart` field. `start()` reads this to decide whether to
    install a launchd plist."""
    cfg = Config(name="t", isolation="apple-container")
    cfg.container.image = "x"
    cfg.apple_container_autostart = True

    units = AppleContainerBackend().generate_units(
        cfg, "/cfg", "/patches", "deploy",
    )
    meta = json.loads(units["deploy.json"])
    assert meta["autostart"] is True


def test_generate_units_autostart_default_false():
    """Autostart is opt-in. Cages that don't set the flag get
    `autostart: false` in the unit JSON; `start()` skips the plist."""
    cfg = Config(name="t", isolation="apple-container")
    cfg.container.image = "x"
    units = AppleContainerBackend().generate_units(
        cfg, "/cfg", "/patches", "deploy",
    )
    meta = json.loads(units["deploy.json"])
    assert meta["autostart"] is False


def test_launchd_plist_path_is_under_user_launchagents():
    """plist file goes under ~/Library/LaunchAgents — user-scope so no
    sudo, runs at the user's login session."""
    p = AppleContainerBackend()._launchd_plist_path("demo")
    assert str(p).endswith("/Library/LaunchAgents/io.agentcage.demo.plist")


def test_install_launchd_plist_writes_well_formed_xml(tmp_path, monkeypatch):
    """`_install_launchd_plist` writes a valid Apple plist XML with the
    expected ProgramArguments shape and the cage name in the Label."""
    backend = AppleContainerBackend()
    monkeypatch.setattr(backend, "_launchd_plist_path",
                        lambda name: tmp_path / f"io.agentcage.{name}.plist")
    monkeypatch.setattr(backend, "_state_dir",
                        lambda name: tmp_path / f"state-{name}")
    with patch.object(ac_cli, "container_binary",
                       return_value="/usr/local/bin/container"), \
         patch("subprocess.run",
               return_value=type("CP", (), {"returncode": 0, "stdout": "", "stderr": ""})()):
        backend._install_launchd_plist("demo")

    plist_text = (tmp_path / "io.agentcage.demo.plist").read_text()
    assert "<key>Label</key>" in plist_text
    assert "<string>io.agentcage.demo</string>" in plist_text
    assert "<string>/usr/local/bin/container</string>" in plist_text
    assert "<string>start</string>" in plist_text
    assert "<string>demo</string>" in plist_text
    # Well-formedness: round-trip via plistlib.
    import plistlib
    parsed = plistlib.loads(plist_text.encode())
    assert parsed["Label"] == "io.agentcage.demo"
    assert parsed["RunAtLoad"] is True
    assert parsed["ProgramArguments"][-1] == "demo"


def test_start_argv_uses_file_delivery_when_placeholders_known(
    tmp_path, monkeypatch,
):
    """0.21.1+ hardened path: when the unit JSON carries
    ``secret_env_placeholders``, start() writes the resolved value to
    ``<secrets_dir>/<env-name>`` (mode 0600) and passes
    ``-e <env>={{<env>}}`` (the placeholder, NOT the cleartext value) to
    `container run`. This is the entire point — host `ps`, `container
    inspect`, and `cage exec ... -- env` all see only the placeholder.
    """
    backend = AppleContainerBackend()
    unit_dir = tmp_path / "apple-container"
    unit_dir.mkdir()
    (unit_dir / "demo.json").write_text(json.dumps({
        "name": "demo",
        "user_image": "x",
        "cpus": "",
        "memory": "",
        "lifecycle": "interactive",
        "secret_envs": ["API_KEY", "MISSING_KEY"],
        "secret_env_placeholders": {
            "API_KEY": "{{API_KEY}}",
            "MISSING_KEY": "{{MISSING_KEY}}",
        },
    }))
    monkeypatch.setenv("API_KEY", "sk-real-1234")
    monkeypatch.delenv("MISSING_KEY", raising=False)

    captured_argv = []

    def fake_run(argv, **_kwargs):
        captured_argv.append(list(argv))
        return type("CP", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    logs_dir = tmp_path / "logs"
    secrets_dir = tmp_path / "secrets"

    with patch.object(backend, "unit_dir", return_value=unit_dir), \
         patch.object(backend, "logs_dir", return_value=logs_dir), \
         patch.object(backend, "secrets_dir", return_value=secrets_dir), \
         patch.object(ac_cli, "image_inspect", return_value={"config": {}}), \
         patch.object(ac_cli, "inspect", return_value=None), \
         patch.object(ac_cli, "run", side_effect=fake_run):
        backend.start("demo", quiet=True)

    run_argv = next(a for a in captured_argv if a[0] == "run")
    # The cage env carries the placeholder, NEVER the raw value.
    assert "API_KEY={{API_KEY}}" in run_argv
    assert "sk-real-1234" not in " ".join(run_argv)
    # The bind mount is present.
    assert any(
        a == f"{secrets_dir}:/run/agentcage/secrets:ro" for a in run_argv
    )
    # The secret file exists on the host, mode 0600, containing the real value.
    secret_file = secrets_dir / "API_KEY"
    assert secret_file.is_file()
    assert secret_file.read_text() == "sk-real-1234"
    assert oct(secret_file.stat().st_mode & 0o777) == "0o600"
    # The missing env has NO file (skipped) and isn't in argv.
    assert not (secrets_dir / "MISSING_KEY").exists()
    assert "MISSING_KEY=" not in " ".join(run_argv)
    # The secrets dir itself is mode 0700 (only host user can read).
    assert oct(secrets_dir.stat().st_mode & 0o777) == "0o700"


def test_start_argv_drops_stale_secrets_from_prior_starts(
    tmp_path, monkeypatch,
):
    """start() removes pre-existing files in <secrets_dir> so a rule
    that's been removed from cage.yaml doesn't linger in the bind mount
    after `cage update`. Keeps the secrets dir an accurate reflection
    of the current rule list."""
    backend = AppleContainerBackend()
    unit_dir = tmp_path / "apple-container"
    unit_dir.mkdir()
    (unit_dir / "demo.json").write_text(json.dumps({
        "name": "demo",
        "user_image": "x",
        "cpus": "",
        "memory": "",
        "lifecycle": "interactive",
        "secret_envs": ["NEW_KEY"],
        "secret_env_placeholders": {"NEW_KEY": "{{NEW_KEY}}"},
    }))
    monkeypatch.setenv("NEW_KEY", "new-value")

    secrets_dir = tmp_path / "secrets"
    secrets_dir.mkdir()
    # Stale leftover from a previous create where OLD_KEY was a rule.
    (secrets_dir / "OLD_KEY").write_text("old-stale-value")

    def fake_run(argv, **_kwargs):  # noqa: ARG001
        return type("CP", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    with patch.object(backend, "unit_dir", return_value=unit_dir), \
         patch.object(backend, "logs_dir", return_value=tmp_path / "logs"), \
         patch.object(backend, "secrets_dir", return_value=secrets_dir), \
         patch.object(ac_cli, "image_inspect", return_value={"config": {}}), \
         patch.object(ac_cli, "inspect", return_value=None), \
         patch.object(ac_cli, "run", side_effect=fake_run):
        backend.start("demo", quiet=True)

    # OLD_KEY removed; NEW_KEY present.
    assert not (secrets_dir / "OLD_KEY").exists()
    assert (secrets_dir / "NEW_KEY").read_text() == "new-value"


def test_start_argv_backcompat_pre_021_1_cleartext(tmp_path, monkeypatch):
    """Backward compat: unit JSON without ``secret_env_placeholders``
    (cage last started under 0.21.0) falls back to the old
    ``-e NAME=value`` cleartext path so existing cages keep starting
    after upgrade without a `cage update`."""
    backend = AppleContainerBackend()
    unit_dir = tmp_path / "apple-container"
    unit_dir.mkdir()
    (unit_dir / "demo.json").write_text(json.dumps({
        "name": "demo",
        "user_image": "x",
        "cpus": "",
        "memory": "",
        "lifecycle": "interactive",
        "secret_envs": ["API_KEY"],
        # no secret_env_placeholders — pre-0.21.1 shape
    }))
    monkeypatch.setenv("API_KEY", "sk-real-1234")

    captured_argv = []

    def fake_run(argv, **_kwargs):
        captured_argv.append(list(argv))
        return type("CP", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    with patch.object(backend, "unit_dir", return_value=unit_dir), \
         patch.object(backend, "logs_dir", return_value=tmp_path / "logs"), \
         patch.object(backend, "secrets_dir", return_value=tmp_path / "secrets"), \
         patch.object(ac_cli, "image_inspect", return_value={"config": {}}), \
         patch.object(ac_cli, "inspect", return_value=None), \
         patch.object(ac_cli, "run", side_effect=fake_run):
        backend.start("demo", quiet=True)

    run_argv = next(a for a in captured_argv if a[0] == "run")
    # Backward-compat: cleartext value via -e, no bind mount.
    assert "API_KEY=sk-real-1234" in run_argv
    assert not any("secrets:ro" in a for a in run_argv)


def test_generate_units_persists_secret_env_placeholders():
    """generate_units writes the env→placeholder map for start() to use."""
    from agentcage.config import SecretInjectionRule
    cfg = Config(name="t", isolation="apple-container")
    cfg.container.image = "x"
    cfg.secret_injection = [
        SecretInjectionRule(env="API_KEY", placeholder="{{API_KEY}}"),
        SecretInjectionRule(env="DB_URL", placeholder="{{DATABASE_URL}}"),
    ]
    units = AppleContainerBackend().generate_units(cfg, "/cfg", "/p", "deploy")
    meta = json.loads(units["deploy.json"])
    assert meta["secret_env_placeholders"] == {
        "API_KEY": "{{API_KEY}}",
        "DB_URL": "{{DATABASE_URL}}",
    }
    # secret_envs still present for backward compat.
    assert meta["secret_envs"] == ["API_KEY", "DB_URL"]


def test_supervisor_restages_secrets_for_uid_200(tmp_path):
    """REGRESSION: supervisor.sh stage 35 must copy /run/agentcage/secrets/*
    into /home/acproxy/secrets/* with chown 200:200 mode 0400, so mitmproxy
    can read them but the cage workload (uid 1000) cannot.

    Without stage 35, mitmproxy (uid 200) can't open the bind-mounted
    files (virtiofs maps them to root-owned mode 0600), and the cage
    workload (uid 1000) ALSO can't open them — secret_injection silently
    no-ops."""
    ac_wrapper.stage_build_context(tmp_path, ["sh"], allowlist=["a.com"])
    sup = (tmp_path / "supervisor.sh").read_text()
    assert "stage 35" in sup
    assert "/run/agentcage/secrets" in sup
    assert "/home/acproxy/secrets" in sup
    assert "chown acproxy:acproxy" in sup
    assert "chmod 0400" in sup


def test_supervisor_umounts_secrets_after_restaging(tmp_path):
    """REGRESSION: supervisor must `umount /run/agentcage/secrets` after
    re-staging to /home/acproxy/secrets. Without the unmount, virtiofs
    keeps the host-side files visible at the bind-mount path, and the
    cage workload (uid 1000 — but virtiofs maps host owner through
    identity so the file shows as workload-owned) can `cat` them.

    Mac e2e verification (with the umount):
      $ cage exec ubuntu-sec -- su ubuntu -s /bin/sh -c \\
            'cat /run/agentcage/secrets/AGENTCAGE_SECFILE_SECRET'
      cat: /run/agentcage/secrets/AGENTCAGE_SECFILE_SECRET: No such
      file or directory   ← pass

    Without the umount, the same command returns the secret value
    cleartext — a silent end-run around the file-based delivery model.
    `die` on umount failure so a broken stage 35 fails closed rather
    than booting a cage that leaks."""
    ac_wrapper.stage_build_context(tmp_path, ["sh"], allowlist=["a.com"])
    sup = (tmp_path / "supervisor.sh").read_text()
    assert "umount /run/agentcage/secrets" in sup
    # Failure must abort the cage; otherwise the leak is silent.
    assert 'die "could not unmount /run/agentcage/secrets' in sup


def test_start_argv_forwards_secret_envs(tmp_path, monkeypatch):
    """start() reads secret_envs from the unit metadata and forwards each
    via `-e NAME=value`. Missing env vars are skipped (with a warning)."""
    backend = AppleContainerBackend()
    unit_dir = tmp_path / "apple-container"
    unit_dir.mkdir()
    (unit_dir / "demo.json").write_text(json.dumps({
        "name": "demo",
        "user_image": "x",
        "cpus": "",
        "memory": "",
        "lifecycle": "interactive",
        "secret_envs": ["API_KEY", "MISSING_KEY"],
    }))
    monkeypatch.setenv("API_KEY", "sk-real-1234")
    monkeypatch.delenv("MISSING_KEY", raising=False)

    captured_argv = []

    def fake_run(argv, **_kwargs):
        captured_argv.append(list(argv))
        return type("CP", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    logs_dir = tmp_path / "logs"

    with patch.object(backend, "unit_dir", return_value=unit_dir), \
         patch.object(backend, "logs_dir", return_value=logs_dir), \
         patch.object(ac_cli, "image_inspect", return_value={"config": {}}), \
         patch.object(ac_cli, "inspect", return_value=None), \
         patch.object(ac_cli, "run", side_effect=fake_run):
        backend.start("demo", quiet=True)

    run_argv = next(a for a in captured_argv if a[0] == "run")
    assert "-e" in run_argv
    assert "API_KEY=sk-real-1234" in run_argv
    # Missing env name MUST NOT appear (no `-e MISSING_KEY=` with empty value).
    assert "MISSING_KEY=" not in " ".join(run_argv)


def test_nat_redirect_excludes_proxy_and_dns_not_only_uid_1000(tmp_path):
    """REGRESSION: NAT REDIRECT for tcp/80 and tcp/443 must catch every
    uid except the egress components (uid 200 = mitmproxy, uid 201 = dnsmasq),
    not only the cage workload at uid 1000. `container exec` enters as the
    image's default USER — root on every popular base — so an interactive
    `agentcage cage exec ubuntu02 -- apt-get update` runs as uid 0. Before
    this fix the REDIRECT only matched uid 1000, so root's port-80/443
    egress skipped the proxy entirely and hit the default-DROP filter chain.
    """
    ac_wrapper.stage_build_context(tmp_path, ["sh"], allowlist=["a.com"])
    sup = (tmp_path / "supervisor.sh").read_text()
    # The OLD (buggy) form was: `--uid-owner 1000 -j REDIRECT`. Forbid it.
    assert "--uid-owner 1000 -j REDIRECT" not in sup
    assert "--uid-owner 1000 \\\n    -j REDIRECT" not in sup
    # The NEW form excludes uid 200 (mitmproxy) and uid 201 (dnsmasq) so
    # their upstream connections aren't redirected back to themselves.
    assert "! --uid-owner 200" in sup
    assert "! --uid-owner 201" in sup


def test_dnsmasq_strips_aaaa_records(tmp_path):
    """REGRESSION: dnsmasq must `filter-AAAA` so clients don't waste time
    trying IPv6 addresses they can never reach (IPv6 is killed at the
    netfilter + sysctl level by supervisor.sh stage 80). Without this the
    cage still gets AAAA records back, curl/apt try IPv6 first, fail
    instantly with "Cannot assign requested address", then fall back to v4."""
    ac_wrapper.stage_build_context(tmp_path, ["sh"], allowlist=["a.com"])
    conf = (tmp_path / "dnsmasq.conf").read_text()
    assert "filter-AAAA" in conf


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


# ---------------------------------------------------------------------------
# generate_units / start: container.cpus + container.memory precedence
# ---------------------------------------------------------------------------


def test_generate_units_prefers_container_cpus_memory_over_vm():
    """REGRESSION: cage.yaml's `container.cpus` / `container.memory` (the
    per-cage cap users actually write) must win over `vm.vcpus` /
    `vm.mem_mb` on apple-container. Pre-fix, the backend read only the
    vm.* fields and silently dropped container.* — meaning a Mac user
    who wrote `container: { memory: 2g, cpus: 1.5 }` got Apple's default
    resource allocation, not the cap they asked for."""
    cfg = Config(name="t", isolation="apple-container")
    cfg.container.image = "x"
    cfg.container.cpus = "1.5"
    cfg.container.memory = "2g"
    cfg.vm.vcpus = 8       # set but should be overridden
    cfg.vm.mem_mb = 16384  # set but should be overridden

    units = AppleContainerBackend().generate_units(
        cfg, "/cfg", "/patches", "deploy",
    )
    meta = json.loads(units["deploy.json"])
    assert meta["cpus"] == "1.5"
    assert meta["memory"] == "2g"


def test_generate_units_falls_back_to_vm_when_container_unset():
    """vm.vcpus / vm.mem_mb are the fallback when cage.yaml doesn't set
    container.*. Backward compatibility: existing cages that only had
    the vm section keep working."""
    cfg = Config(name="t", isolation="apple-container")
    cfg.container.image = "x"
    cfg.container.cpus = ""
    cfg.container.memory = ""
    cfg.vm.vcpus = 4
    cfg.vm.mem_mb = 4096

    units = AppleContainerBackend().generate_units(
        cfg, "/cfg", "/patches", "deploy",
    )
    meta = json.loads(units["deploy.json"])
    assert meta["cpus"] == "4"
    assert meta["memory"] == "4096m"


def test_start_argv_includes_normalized_cpus_memory(tmp_path):
    """`start()` reads the unit metadata and constructs the `container run`
    argv with normalized --cpus (integer; Apple rejects fractions) and
    --memory (uppercase suffix; Apple rejects lowercase). Original cage.yaml
    value "1.5" → "2", "2g" → "2G"."""
    backend = AppleContainerBackend()
    unit_dir = tmp_path / "apple-container"
    unit_dir.mkdir()
    (unit_dir / "demo.json").write_text(json.dumps({
        "name": "demo",
        "user_image": "x",
        "cpus": "1.5",   # fractional → ceil to 2
        "memory": "2g",  # lowercase → uppercase to 2G
        "lifecycle": "interactive",
    }))
    captured_argv = []

    def fake_run(argv, **_kwargs):
        captured_argv.append(list(argv))
        return type("CP", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    with patch.object(backend, "unit_dir", return_value=unit_dir), \
         patch.object(ac_cli, "image_inspect", return_value={"config": {}}), \
         patch.object(ac_cli, "inspect", return_value=None), \
         patch.object(ac_cli, "run", side_effect=fake_run):
        backend.start("demo", quiet=True)

    run_argv = next(a for a in captured_argv if a[0] == "run")
    assert run_argv[run_argv.index("--cpus") + 1] == "2"
    assert run_argv[run_argv.index("--memory") + 1] == "2G"


def test_normalize_cpus_ceils_fractions():
    from agentcage.backends.apple_container import _normalize_cpus
    assert _normalize_cpus("0.5") == "1"
    assert _normalize_cpus("1.0") == "1"
    assert _normalize_cpus("1.1") == "2"
    assert _normalize_cpus("4") == "4"
    assert _normalize_cpus("not-a-number") == "not-a-number"  # pass through


def test_normalize_memory_uppercases_suffix():
    from agentcage.backends.apple_container import _normalize_memory
    assert _normalize_memory("512m") == "512M"
    assert _normalize_memory("2g") == "2G"
    assert _normalize_memory("1024M") == "1024M"  # already uppercase
    assert _normalize_memory("2Gi") == "2GI"      # uppercase the i too
    assert _normalize_memory("512") == "512"      # no suffix, pass through
    assert _normalize_memory("garbage") == "garbage"  # doesn't match → pass through


def test_start_creates_logs_dir_and_bind_mounts_it(tmp_path):
    """`start()` must create the per-cage logs dir on the host and pass
    --volume <host_logs>:/var/log/agentcage to `container run` so the
    supervisor's proxy.log / capture.jsonl / dnsmasq.log are visible to
    the host. This unlocks `cage audit` and `cage har` on apple-container
    (both gated unsupported pre-bind-mount because they had no host path
    to read)."""
    backend = AppleContainerBackend()
    unit_dir = tmp_path / "apple-container"
    unit_dir.mkdir()
    (unit_dir / "demo.json").write_text(json.dumps({
        "name": "demo",
        "user_image": "x",
        "cpus": "",
        "memory": "",
        "lifecycle": "interactive",
    }))
    captured_argv = []

    def fake_run(argv, **_kwargs):
        captured_argv.append(list(argv))
        return type("CP", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    logs_dir = tmp_path / "logs"

    with patch.object(backend, "unit_dir", return_value=unit_dir), \
         patch.object(backend, "logs_dir", return_value=logs_dir), \
         patch.object(ac_cli, "image_inspect", return_value={"config": {}}), \
         patch.object(ac_cli, "inspect", return_value=None), \
         patch.object(ac_cli, "run", side_effect=fake_run):
        backend.start("demo", quiet=True)

    # Host logs dir created.
    assert logs_dir.is_dir()
    # --volume <logs_dir>:/var/log/agentcage in the run argv.
    run_argv = next(a for a in captured_argv if a[0] == "run")
    vol_idx = run_argv.index("--volume")
    assert run_argv[vol_idx + 1] == f"{logs_dir}:/var/log/agentcage"


def test_logs_dir_lives_under_per_cage_state_dir():
    """logs_dir(name) is `<state-dir>/<name>/logs/` so destroy_resources's
    recursive rmtree of _state_dir(name) sweeps it up automatically."""
    backend = AppleContainerBackend()
    logs = backend.logs_dir("demo")
    state = backend._state_dir("demo")
    assert logs.parent == state
    assert logs.name == "logs"


def test_start_argv_backward_compat_pre_0_20_6_mem_mb(tmp_path):
    """Pre-0.20.6 unit JSON used integer `mem_mb` + `cpus` (no `memory`
    string). Cages created before this PR must keep starting on a fresh
    agentcage — so `start()` falls back to the old `mem_mb` field when
    `memory` is absent. The fallback uses the uppercase M suffix Apple
    requires."""
    backend = AppleContainerBackend()
    unit_dir = tmp_path / "apple-container"
    unit_dir.mkdir()
    (unit_dir / "demo.json").write_text(json.dumps({
        "name": "demo",
        "user_image": "x",
        "cpus": 4,        # old integer form
        "mem_mb": 4096,   # old field
        "lifecycle": "interactive",
    }))
    captured_argv = []

    def fake_run(argv, **_kwargs):
        captured_argv.append(list(argv))
        return type("CP", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    with patch.object(backend, "unit_dir", return_value=unit_dir), \
         patch.object(ac_cli, "image_inspect", return_value={"config": {}}), \
         patch.object(ac_cli, "inspect", return_value=None), \
         patch.object(ac_cli, "run", side_effect=fake_run):
        backend.start("demo", quiet=True)

    run_argv = next(a for a in captured_argv if a[0] == "run")
    assert run_argv[run_argv.index("--memory") + 1] == "4096M"


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


# ---------------------------------------------------------------------------
# allowlist_addon: response-side {{SECRET}} redaction
#
# These exercise the addon's response() hook end-to-end with a mocked
# mitmproxy HTTPFlow. The conftest.py stub of `mitmproxy` lets the addon
# module import cleanly on the host; we never spin up real mitmproxy.
# ---------------------------------------------------------------------------


def _build_addon(monkeypatch, tmp_path, *, secret_value="redact-test-xyz",
                 inject_to=("httpbin.org",), allowlist=("httpbin.org",)):
    """Construct an AllowlistAddon wired to a one-rule config in tmp_path.

    Returns ``(module, addon)``. Audit + capture logs are redirected
    into tmp_path so tests can assert on the JSONL output.
    """
    addon_mod = _load_addon_module()
    # Resolve secret via env so the addon's startup-time os.environ lookup
    # picks it up (the same way `agentcage cage create -e ...` works in prod).
    monkeypatch.setenv("AGENTCAGE_REDACT_SECRET", secret_value)
    rules = [{
        "env": "AGENTCAGE_REDACT_SECRET",
        "placeholder": "{{AGENTCAGE_REDACT_SECRET}}",
        "inject_to": list(inject_to),
    }]
    allow_path = tmp_path / "allowlist.txt"
    allow_path.write_text("\n".join(allowlist) + "\n")
    si_path = tmp_path / "secret_injection.json"
    si_path.write_text(json.dumps(rules))
    monkeypatch.setattr(addon_mod, "ALLOWLIST_PATH", str(allow_path))
    monkeypatch.setattr(addon_mod, "SECRET_INJECTION_PATH", str(si_path))
    monkeypatch.setattr(addon_mod, "AUDIT_LOG_PATH", str(tmp_path / "audit.jsonl"))
    monkeypatch.setattr(addon_mod, "CAPTURE_PATH", str(tmp_path / "capture.jsonl"))
    return addon_mod, addon_mod.AllowlistAddon()


def _make_response_flow(*, host, body, status=200, resp_headers=None,
                        method="GET", path="/headers"):
    """Build a minimal mock mitmproxy HTTPFlow with a response attached.

    ``body`` may be ``str`` (text body) or ``bytes`` (binary). For text
    bodies we set ``flow.response.get_text`` to return it; the addon's
    redactor calls ``set_text`` to mutate, which writes back into
    ``flow.response.text``.
    """
    flow = MagicMock()
    flow.request.pretty_host = host
    flow.request.pretty_url = f"https://{host}{path}"
    flow.request.path = path
    flow.request.port = 443
    flow.request.method = method
    flow.request.headers = {}

    flow.response = MagicMock()
    flow.response.status_code = status
    flow.response.reason = "OK"
    flow.response.headers = dict(resp_headers or {})
    flow.response.content = body.encode() if isinstance(body, str) else body

    if isinstance(body, str):
        # Stash text in a closure so set_text() updates what get_text()
        # returns on subsequent calls — matches mitmproxy's behaviour.
        state = {"text": body}
        flow.response.get_text.side_effect = lambda strict=True: state["text"]
        def _set_text(new):
            state["text"] = new
            flow.response.content = new.encode()
        flow.response.set_text.side_effect = _set_text
    else:
        # Binary body — mimic mitmproxy raising on undecodable bytes.
        flow.response.get_text.side_effect = UnicodeDecodeError(
            "utf-8", body, 0, 1, "binary body",
        )
    return flow


def test_response_redaction_happy_path(tmp_path, monkeypatch):
    """End-to-end: a response body that echoes the real secret value gets
    rewritten back to ``{{AGENTCAGE_REDACT_SECRET}}``. The audit JSONL
    records the env name under ``secrets_redacted``.

    Mirrors the live-Mac smoke test against httpbin/headers — the upstream
    sees the real key, the cage sees the placeholder."""
    addon_mod, addon = _build_addon(monkeypatch, tmp_path)
    flow = _make_response_flow(
        host="httpbin.org",
        # Shape mimics httpbin /headers JSON output.
        body='{"headers": {"X-Echo": "redact-test-xyz"}}',
    )

    addon.response(flow)

    # Body has the placeholder, not the real value.
    assert "redact-test-xyz" not in flow.response.content.decode()
    assert "{{AGENTCAGE_REDACT_SECRET}}" in flow.response.content.decode()

    # Audit log records the redaction.
    audit_lines = (tmp_path / "audit.jsonl").read_text().splitlines()
    inbound = [json.loads(l) for l in audit_lines
               if json.loads(l).get("direction") == "inbound"]
    assert len(inbound) == 1
    assert inbound[0]["secrets_redacted"] == ["AGENTCAGE_REDACT_SECRET"]
    assert inbound[0]["host"] == "httpbin.org"
    assert inbound[0]["reason"] == "secret-redaction"


def test_response_redaction_in_response_headers(tmp_path, monkeypatch):
    """Headers (not just body) get redacted. Some upstreams echo bearer
    tokens into custom response headers; the cage must never see them."""
    _, addon = _build_addon(monkeypatch, tmp_path)
    flow = _make_response_flow(
        host="httpbin.org",
        body="ok",
        resp_headers={"X-Reflected-Auth": "Bearer redact-test-xyz"},
    )

    addon.response(flow)

    assert flow.response.headers["X-Reflected-Auth"] == (
        "Bearer {{AGENTCAGE_REDACT_SECRET}}"
    )


def test_response_redaction_scoped_to_inject_to_host(tmp_path, monkeypatch):
    """Defense-in-depth: a response from a host NOT in ``inject_to`` is
    NOT redacted even when its body coincidentally contains the secret
    value as a substring. Otherwise unrelated allowlisted upstreams could
    have legitimate text mangled (e.g. a UUID that happened to match)."""
    addon_mod, addon = _build_addon(
        monkeypatch, tmp_path,
        inject_to=("httpbin.org",),
        allowlist=("httpbin.org", "example.com"),
    )
    flow = _make_response_flow(
        host="example.com",  # allowlisted but not in inject_to
        body="here is a coincidence: redact-test-xyz appears in this body",
    )

    addon.response(flow)

    # Real value still present — scope guard worked.
    assert "redact-test-xyz" in flow.response.content.decode()
    assert "{{AGENTCAGE_REDACT_SECRET}}" not in flow.response.content.decode()

    # No inbound audit entry emitted (nothing was redacted).
    audit_path = tmp_path / "audit.jsonl"
    if audit_path.exists():
        for line in audit_path.read_text().splitlines():
            assert json.loads(line).get("direction") != "inbound"


def test_response_redaction_skips_binary_body(tmp_path, monkeypatch):
    """Binary responses (images, archives) pass through unchanged — the
    addon catches ``UnicodeDecodeError`` from ``get_text(strict=False)``
    and never touches the body bytes. Headers are still scanned."""
    _, addon = _build_addon(monkeypatch, tmp_path)
    binary = bytes([0xff, 0xd8, 0xff]) + b"redact-test-xyz" + bytes([0x00, 0xfe])
    flow = _make_response_flow(
        host="httpbin.org",
        body=binary,
        resp_headers={"X-Trace": "echo redact-test-xyz back"},
    )

    addon.response(flow)

    # Body untouched.
    assert flow.response.content == binary
    # Header still got redacted.
    assert flow.response.headers["X-Trace"] == "echo {{AGENTCAGE_REDACT_SECRET}} back"
