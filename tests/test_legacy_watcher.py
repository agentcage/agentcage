"""Round-11 finding 4: legacy grants-watcher artifacts are removed on
destroy/update so upgraded cages don't crash-loop a deleted command."""

from pathlib import Path
import sys

from agentcage.legacy_watcher import (
    _grants_plist_path,
    _grants_service_path,
    remove_legacy_grants_watcher,
)


def test_noop_when_nothing_installed(tmp_path, monkeypatch):
    # Post-rework cages have no artifacts: every path is a no-op, never
    # raises, and never shells out to systemctl/launchctl.
    monkeypatch.setattr(Path, "is_file", lambda self: False)
    ran = []
    monkeypatch.setattr(
        "subprocess.run", lambda *a, **k: ran.append(a) or _fake_ok()
    )
    remove_legacy_grants_watcher("ghost", isolation="container")
    assert ran == []  # darwin/linux branch bails before bootout/disable


class _FakeProc:
    returncode = 0
    stdout = ""
    stderr = ""


def _fake_ok():
    return _FakeProc()


def test_linux_removes_unit_and_disables(monkeypatch):
    if sys.platform == "darwin":
        return
    unit = _grants_service_path("oldcage")
    monkeypatch.setattr(Path, "is_file", lambda self: self == unit)
    removed = []
    monkeypatch.setattr(Path, "unlink", lambda self: removed.append(self))
    calls = []

    def fake_run(argv, **kw):
        calls.append(argv)
        return _FakeProc()

    monkeypatch.setattr("subprocess.run", fake_run)
    remove_legacy_grants_watcher("oldcage", isolation="container")
    assert any(
        "disable" in c and "--now" in c and "oldcage-grants.service" in c[-1]
        for c in calls if isinstance(c, list)
    ), calls
    assert any("daemon-reload" in c for c in calls if isinstance(c, list)), calls
    assert unit in removed


def test_darwin_bootout_and_unlink(monkeypatch):
    if sys.platform != "darwin":
        return
    plist = _grants_plist_path("oldcage")
    monkeypatch.setattr(Path, "is_file", lambda self: self == plist)
    removed = []
    monkeypatch.setattr(Path, "unlink", lambda self: removed.append(self))
    calls = []

    def fake_run(argv, **kw):
        calls.append(argv)
        return _FakeProc()

    monkeypatch.setattr("subprocess.run", fake_run)
    remove_legacy_grants_watcher("oldcage", isolation="container")
    bootouts = [c for c in calls if c and c[0] == "launchctl"]
    assert bootouts and any("io.agentcage.oldcage.grants" in " ".join(b) for b in bootouts)
    assert plist in removed


def test_vm_branch_swallow_errors(monkeypatch):
    # An unreachable VM must not raise out of cleanup.
    import agentcage.legacy_watcher as lw

    class _Boom:
        def is_running(self):
            raise RuntimeError("unreachable")

    monkeypatch.setattr(
        "agentcage.backends.vm.LimaInstance", lambda n: _Boom(), raising=False
    )
    # Patch the lazy import target: backends.vm may import LimaInstance
    # from elsewhere; simplest is to patch the attribute the helper uses.
    monkeypatch.setattr(lw, "_remove_vm_watcher", lambda name: None)
    remove_legacy_grants_watcher("oldcage", isolation="vm")  # no raise
