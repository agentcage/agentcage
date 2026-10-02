"""Tests for tmpfs-mask mount points materialized on the host (issue #320).

A ``tmpfs:`` entry whose target lives under a host bind-mount forces the OCI
runtime to create the mount point, and a bind shares inodes with its source,
so the ``mkdir -p`` lands in the operator's project directory on the host. On
a project that is not a git repo, the standard ``/workspace/.git/hooks/`` mask
therefore leaves a stray host ``.git/`` that ``test -d .git`` misreads as a
repository.

The masks themselves stay unconditional — dropping one when ``.git`` is absent
would reopen the #170 cage->host git-hook pivot for a ``.git`` created later.
Instead the cage quadlet records which mount points were absent immediately
before start and removes exactly those, and only while still empty, on stop.
"""

from __future__ import annotations

import base64
import subprocess
import textwrap

import pytest

from agentcage import quadlets, volume_mounts
from agentcage.config import load_config
from agentcage.quadlets import generate_quadlets
from tests.markers import REQUIRES_GNU_REALPATH

MASKS = [
    "/tmp:rw,noexec,nosuid,size=256M",
    "/workspace/.git/hooks/:rw,noexec,nosuid,nodev,size=64M",
    "/workspace/.claude/:rw,noexec,nosuid,nodev,size=64M",
]


@pytest.fixture(autouse=True)
def _home(tmp_path, monkeypatch):
    """Make ``~`` resolve to tmp_path so volume host paths pass the $HOME check."""
    monkeypatch.setattr(
        quadlets.os.path, "expanduser", lambda path: path.replace("~", str(tmp_path))
    )


def _cage_unit(tmp_path, volumes, tmpfs=MASKS, named_volumes=None):
    body = textwrap.dedent("""\
        name: test
        dns_servers: [1.1.1.1]
        container:
          image: test:latest
          volumes:
    """)
    body += "".join(f'    - "{volume}"\n' for volume in volumes)
    if named_volumes:
        body += "  named_volumes:\n"
        body += "".join(f'    {k}: "{v}"\n' for k, v in named_volumes.items())
    body += "  tmpfs:\n"
    body += "".join(f'    - "{entry}"\n' for entry in tmpfs)
    config_path = tmp_path / "cage.yaml"
    config_path.write_text(body)
    cfg = load_config(str(config_path))
    return generate_quadlets(cfg, "/cage.yaml", "/patches")["test-cage.container"]


def _mask_hooks(unit: str) -> list[str]:
    """The rendered ExecStartPre/ExecStopPost pair for mask bookkeeping."""
    return [
        line for line in unit.splitlines()
        if line.startswith(("ExecStartPre=", "ExecStopPost=")) and "/masks/" in line
    ]


def _recorded_dirs(unit: str) -> list[str]:
    """Decode the host paths baked into the ExecStartPre blob."""
    start = next(line for line in _mask_hooks(unit) if line.startswith("ExecStartPre="))
    blob = start.split("echo ", 1)[1].split(" |", 1)[0]
    return base64.b64decode(blob).decode().splitlines()


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------


def test_mask_under_a_bind_gets_start_and_stop_bookkeeping(tmp_path):
    (tmp_path / "repo").mkdir()
    unit = _cage_unit(tmp_path, ["~/repo:/workspace:rw"])

    hooks = _mask_hooks(unit)
    assert len(hooks) == 2
    assert hooks[0].startswith("ExecStartPre=/bin/bash -c ")
    # Leading `-`: a cleanup that cannot complete must never fail `cage stop`.
    assert hooks[1].startswith("ExecStopPost=-/bin/bash -c ")
    assert "%t/agentcage/test/masks/root-0" in hooks[0]
    assert "%t/agentcage/test/masks/root-0" in hooks[1]
    # rmdir is the whole "only if empty" guarantee — never rm -rf.
    assert "rmdir " in hooks[1]
    assert "rm -rf" not in hooks[1]


def test_recorded_paths_are_project_local_and_deepest_first(tmp_path):
    """`<repo>/.git/hooks` must be retired before the `<repo>/.git` it created."""
    (tmp_path / "repo").mkdir()
    unit = _cage_unit(tmp_path, ["~/repo:/workspace:rw"])

    repo = f"{tmp_path}/repo"
    assert _recorded_dirs(unit) == [
        f"{repo}/.git/hooks",
        f"{repo}/.git",
        f"{repo}/.claude",
    ]


def test_masks_are_still_emitted_when_the_project_has_no_git(tmp_path):
    """REGRESSION GUARD: #320 must not be "fixed" by dropping the mask.

    Skipping `/workspace/.git/hooks/` on a non-git project would reopen the
    #170 cage->host pivot for any `.git` created later, including one the
    cage creates itself.
    """
    (tmp_path / "repo").mkdir()
    assert not (tmp_path / "repo" / ".git").exists()
    unit = _cage_unit(tmp_path, ["~/repo:/workspace:rw"])

    assert "Tmpfs=/workspace/.git/hooks/:rw,noexec,nosuid,nodev,size=64M" in unit
    assert "Tmpfs=/workspace/.claude/:rw,noexec,nosuid,nodev,size=64M" in unit


def test_mask_outside_any_bind_is_not_tracked(tmp_path):
    """`/tmp` is created in the container's own layer — nothing reaches the host."""
    (tmp_path / "repo").mkdir()
    unit = _cage_unit(
        tmp_path,
        ["~/repo:/workspace:rw"],
        tmpfs=["/tmp:rw,noexec,nosuid,size=256M"],
    )

    assert _mask_hooks(unit) == []


def test_mask_covering_a_whole_bind_is_not_tracked(tmp_path):
    """No sub-path to create, so the runtime materializes nothing on the host."""
    (tmp_path / "repo").mkdir()
    unit = _cage_unit(
        tmp_path,
        ["~/repo:/workspace:rw"],
        tmpfs=["/workspace:rw,noexec,nosuid,size=64M"],
    )

    assert _mask_hooks(unit) == []


def test_np_bind_masks_are_not_tracked(tmp_path):
    """An `np` bind writes to a %t upperdir, so the host source is untouched."""
    (tmp_path / "repo").mkdir()
    unit = _cage_unit(tmp_path, ["~/repo:/workspace:rw,np"])

    assert "upperdir=" in unit
    assert _mask_hooks(unit) == []


def test_named_volume_nested_in_a_bind_wins_longest_prefix(tmp_path):
    """A mask under a named volume is created in the volume, not on the host."""
    (tmp_path / "repo").mkdir()
    unit = _cage_unit(
        tmp_path,
        ["~/repo:/workspace:rw"],
        tmpfs=["/workspace/.claude/:rw,size=64M"],
        named_volumes={"test-claude": "/workspace/.claude"},
    )

    assert _mask_hooks(unit) == []


def test_two_binds_get_independent_containment_roots(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    unit = _cage_unit(
        tmp_path,
        ["~/a:/workspace:rw", "~/b:/srv:rw"],
        tmpfs=["/workspace/.claude/:rw,size=64M", "/srv/.git/hooks/:rw,size=64M"],
    )

    hooks = _mask_hooks(unit)
    assert len(hooks) == 4
    assert len([h for h in hooks if "/masks/root-0" in h]) == 2
    assert len([h for h in hooks if "/masks/root-1" in h]) == 2


def test_host_paths_are_base64_encoded_not_quoted(tmp_path):
    """A systemd Exec line quotes before bash does, so no single escaping of a
    path like `~/My Project` survives both layers — paths travel base64."""
    (tmp_path / "My Project").mkdir()
    unit = _cage_unit(tmp_path, ["~/My Project:/workspace:rw"])

    assert str(tmp_path) not in "\n".join(_mask_hooks(unit))
    assert f"{tmp_path}/My Project/.claude" in _recorded_dirs(unit)


def test_paths_with_newlines_are_skipped_with_a_warning(
    tmp_path, monkeypatch, capsys
):
    """A newline is the one thing the line-oriented state file cannot carry."""
    (tmp_path / "repo").mkdir()
    monkeypatch.setattr(
        quadlets,
        "mask_mountpoint_dirs",
        lambda tmpfs, mounts: {
            f"{tmp_path}/re\npo": [f"{tmp_path}/re\npo/.claude"],
        },
    )
    unit = _cage_unit(tmp_path, ["~/repo:/workspace:rw"])

    assert _mask_hooks(unit) == []
    assert "skipping tmpfs mask cleanup" in capsys.readouterr().err
    # The mask itself is still applied.
    assert "Tmpfs=/workspace/.git/hooks/:rw,noexec,nosuid,nodev,size=64M" in unit


def test_helper_ignores_paths_that_escape_the_bind_source():
    """Defense in depth: a `..` component never yields a removable path."""
    assert volume_mounts.mask_mountpoint_dirs(
        ["/workspace/../../etc:rw"], [("/workspace", "/home/u/repo")]
    ) == {}


# --------------------------------------------------------------------------
# Behavior of the rendered shell
# --------------------------------------------------------------------------


def _hook_commands(tmp_path, volume, runtime):
    unit = _cage_unit(tmp_path, [f"{volume}:/workspace:rw"])
    return [
        line.split("=", 1)[1].lstrip("-").replace("%t", str(runtime))
        for line in _mask_hooks(unit)
    ]


def _run(command):
    result = subprocess.run(
        command, shell=True, capture_output=True, text=True, executable="/bin/bash"
    )
    assert result.returncode == 0, result.stderr
    return result


def _materialize_mountpoints(project):
    """What the OCI runtime does on the host side of the bind."""
    (project / ".git" / "hooks").mkdir(parents=True, exist_ok=True)
    (project / ".claude").mkdir(exist_ok=True)


@pytest.fixture
def hooks(tmp_path):
    """(project dir, callable returning the rendered [start, stop] commands)."""
    project = tmp_path / "repo"
    project.mkdir()
    runtime = tmp_path / "run"
    runtime.mkdir()
    return project, lambda: _hook_commands(tmp_path, "~/repo", runtime)


@REQUIRES_GNU_REALPATH
def test_teardown_removes_only_what_agentcage_created(hooks):
    project, build = hooks
    (project / "f").write_text("")
    start, stop = build()

    _run(start)
    _materialize_mountpoints(project)
    _run(stop)

    assert sorted(p.name for p in project.iterdir()) == ["f"]


@REQUIRES_GNU_REALPATH
def test_teardown_keeps_a_real_repository_intact(hooks):
    project, build = hooks
    (project / ".git" / "hooks").mkdir(parents=True)
    (project / ".git" / "config").write_text("")
    (project / ".git" / "hooks" / "pre-commit").write_text("")
    start, stop = build()

    _run(start)
    _materialize_mountpoints(project)
    _run(stop)

    assert (project / ".git" / "config").exists()
    assert (project / ".git" / "hooks" / "pre-commit").exists()


@REQUIRES_GNU_REALPATH
def test_teardown_keeps_a_preexisting_empty_directory(hooks):
    """Empty is not enough — it must also have been created by agentcage."""
    project, build = hooks
    (project / ".claude").mkdir()
    start, stop = build()

    _run(start)
    _materialize_mountpoints(project)
    _run(stop)

    assert (project / ".claude").is_dir()


@REQUIRES_GNU_REALPATH
def test_teardown_keeps_a_mountpoint_that_is_not_empty(hooks):
    project, build = hooks
    start, stop = build()

    _run(start)
    _materialize_mountpoints(project)
    (project / ".git" / "hooks" / "leftover").write_text("")
    result = _run(stop)

    assert (project / ".git" / "hooks" / "leftover").exists()
    assert "not empty" in result.stderr


@REQUIRES_GNU_REALPATH
def test_teardown_does_not_follow_a_symlink_out_of_the_project(hooks, tmp_path):
    project, build = hooks
    outside = tmp_path / "outside"
    outside.mkdir()
    start, stop = build()

    _run(start)
    _materialize_mountpoints(project)
    (project / ".claude").rmdir()
    (project / ".claude").symlink_to(outside)
    _run(stop)

    assert outside.is_dir()
    assert (project / ".claude").is_symlink()


@REQUIRES_GNU_REALPATH
def test_teardown_is_idempotent_and_survives_a_start_that_never_ran(hooks):
    project, build = hooks
    start, stop = build()

    # Stop without a preceding start: no state file, clean no-op.
    _run(stop)

    _run(start)
    _materialize_mountpoints(project)
    _run(stop)
    _run(stop)

    assert list(project.iterdir()) == []


@REQUIRES_GNU_REALPATH
def test_a_restart_cycle_still_cleans_up(hooks):
    """The second start re-records from scratch, so the second stop cleans too."""
    project, build = hooks
    start, stop = build()

    for _ in range(2):
        _run(start)
        _materialize_mountpoints(project)
        _run(stop)

    assert list(project.iterdir()) == []


@REQUIRES_GNU_REALPATH
def test_teardown_handles_a_project_path_with_a_space_and_a_quote(tmp_path):
    project = tmp_path / "we're a project"
    project.mkdir()
    runtime = tmp_path / "run"
    runtime.mkdir()
    start, stop = _hook_commands(tmp_path, "~/we're a project", runtime)

    _run(start)
    _materialize_mountpoints(project)
    _run(stop)

    assert list(project.iterdir()) == []



class TestUnmaskableMasks:
    """A mask whose mount point cannot be created *at all*.

    The companion to everything above. That machinery assumes the runtime
    can `mkdir` the mount point through the bind, which holds when the
    path is absent. It does not hold when an ancestor exists and is **not
    a directory**: the runtime answers ENOTDIR and the cage never starts.

    A git **worktree** or **submodule** is exactly that case — `.git` is a
    file holding a `gitdir:` pointer — so every shipped scaffold's
    `/workspace/.git/hooks` mask made `agentcage run <scaffold>` fail
    there, with a runtime error naming neither the mask nor the reason.
    """

    TMPFS = ["/workspace/.git/hooks:rw,size=64M"]
    MOUNTS = [("/workspace", "/proj")]

    def test_a_git_file_blocks_the_mask(self):
        assert volume_mounts.unmaskable_masks(
            self.TMPFS, self.MOUNTS,
            lexists=lambda p: p == "/proj/.git", isdir=lambda _p: False,
        ) == [("/workspace/.git/hooks", "/proj/.git")]

    def test_an_absent_path_is_maskable(self):
        """The common case, and the one that must not regress: the runtime
        creates the whole chain, and #320's bookkeeping retires it."""
        assert volume_mounts.unmaskable_masks(
            self.TMPFS, self.MOUNTS,
            lexists=lambda _p: False, isdir=lambda _p: False,
        ) == []

    def test_a_real_git_directory_is_maskable(self):
        assert volume_mounts.unmaskable_masks(
            self.TMPFS, self.MOUNTS,
            lexists=lambda p: p == "/proj/.git",
            isdir=lambda p: p == "/proj/.git",
        ) == []

    def test_a_dangling_symlink_blocks_it_too(self):
        """`lexists`, not `exists`: the runtime cannot mkdir through a
        dangling symlink either, and `exists` would call it absent."""
        assert volume_mounts.unmaskable_masks(
            self.TMPFS, self.MOUNTS,
            lexists=lambda p: p == "/proj/.git", isdir=lambda _p: False,
        ) == [("/workspace/.git/hooks", "/proj/.git")]

    def test_the_outermost_blocker_is_named(self):
        """Name the shallowest blocker: it is the one the operator has to
        look at, and the deeper ones are consequences of it."""
        assert volume_mounts.unmaskable_masks(
            ["/workspace/a/b/c:rw"], [("/workspace", "/proj")],
            lexists=lambda p: p in ("/proj/a", "/proj/a/b"),
            isdir=lambda _p: False,
        ) == [("/workspace/a/b/c", "/proj/a")]

    def test_a_mask_with_no_host_bind_is_never_blocked(self):
        """No enclosing mount, or one that does not write through to the
        host, means the mount point lands in the container's own layer —
        nothing on the host can block it. An `np` bind reports an empty
        source for exactly that reason."""
        assert volume_mounts.unmaskable_masks(
            ["/tmp/scratch:rw"], self.MOUNTS,
            lexists=lambda _p: True, isdir=lambda _p: False,
        ) == []
        assert volume_mounts.unmaskable_masks(
            self.TMPFS, [("/workspace", "")],
            lexists=lambda _p: True, isdir=lambda _p: False,
        ) == []

    def test_it_shares_one_mapping_with_the_bookkeeping(self):
        """Both answer about the same host paths, via `mask_target_chains`.
        If they drifted, a mask could be skipped at start while its
        cleanup candidates were still recorded for teardown."""
        assert volume_mounts.mask_mountpoint_dirs(self.TMPFS, self.MOUNTS) == {
            "/proj": ["/proj/.git/hooks", "/proj/.git"],
        }
