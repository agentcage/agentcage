"""Tests for tmpfs-mask copy-up semantics (#328).

Nothing in agentcage used to say whether a mask should come up empty or
holding a copy of what it covers, so each runtime's default decided: podman
appends ``tmpcopyup`` to every tmpfs (``pkg/util/mountOpts.go``) and the masks
came up full, while apple-container's bare ``--tmpfs`` has no option channel
and they came up empty. Generation now pins ``notmpcopyup`` on mask entries
that declare neither, and a mask that opts into ``tmpcopyup`` additionally
gets an ExecStartPost that hands the runtime's root-owned copy to the cage
user — otherwise the agent can read the seeded content but not edit it.

The apple-container half (emulated seeding from a read-only lower) lives in
tests/test_apple_container.py next to the rest of that backend's mount wiring.
"""

from __future__ import annotations

import base64
import textwrap

from agentcage import quadlets
from agentcage.config import load_config
from agentcage.quadlets import (
    _apply_tmpfs_mask_options,
    _mask_copyup_owner,
    generate_quadlets,
)
from agentcage.volume_mounts import mask_copyup_entries, tmpfs_wants_copyup

WORKSPACE = "~/repo:/workspace:rw"
SCRATCH = "/tmp:rw,noexec,nosuid,size=256M"
HOOKS = "/workspace/.git/hooks/:rw,noexec,nosuid,nodev,size=64M,notmpcopyup"
CLAUDE = "/workspace/.claude/:rw,noexec,nosuid,nodev,size=64M,tmpcopyup"


def _config(tmp_path, volumes, tmpfs, user='"1000:1000"'):
    config_path = tmp_path / "cage.yaml"
    body = textwrap.dedent(f"""\
        name: test
        dns_servers: [1.1.1.1]
        container:
          image: test:latest
          user: {user}
          userns: "keep-id"
          volumes:
    """)
    body += "\n".join(f"    - {volume}" for volume in volumes) + "\n"
    body += "  tmpfs:\n"
    body += "\n".join(f'    - "{entry}"' for entry in tmpfs) + "\n"
    config_path.write_text(body)
    return load_config(str(config_path))


def _cage_unit(tmp_path, monkeypatch, volumes, tmpfs, **kwargs):
    (tmp_path / "repo").mkdir(exist_ok=True)
    cfg = _config(tmp_path, volumes, tmpfs, **kwargs)
    monkeypatch.setattr(
        quadlets.os.path, "expanduser",
        lambda path: path.replace("~", str(tmp_path)),
    )
    return generate_quadlets(cfg, "/cage.yaml", "/patches")["test-cage.container"]


def _chown_lines(unit):
    """ExecStartPost lines that hand a copy-up mask to the cage user."""
    return [
        line for line in unit.splitlines()
        if line.startswith("ExecStartPost=") and "chown" in line
    ]


def _b64(value):
    return base64.b64encode(value.encode()).decode()


class TestCopyUpDefault:
    """"Unspecified" must mean the same thing on both backends: empty."""

    def test_mask_without_a_copyup_option_is_pinned_notmpcopyup(self):
        assert _apply_tmpfs_mask_options(
            ["/workspace/.git/hooks/:rw,noexec,size=64M"],
            [("/workspace", "/home/u/repo")],
        ) == ["/workspace/.git/hooks/:rw,noexec,size=64M,notmpcopyup,mode=1777"]

    def test_explicit_tmpcopyup_is_preserved(self):
        assert _apply_tmpfs_mask_options(
            ["/workspace/.claude/:rw,tmpcopyup"],
            [("/workspace", "/home/u/repo")],
        ) == ["/workspace/.claude/:rw,tmpcopyup,mode=1777"]

    def test_explicit_notmpcopyup_is_not_duplicated(self):
        assert _apply_tmpfs_mask_options(
            ["/workspace/.claude/:rw,notmpcopyup"],
            [("/workspace", "/home/u/repo")],
        ) == ["/workspace/.claude/:rw,notmpcopyup,mode=1777"]

    def test_mode_stays_last_after_the_copyup_pin(self):
        """Both runtimes prepend the mount point's inherited mode and the
        kernel takes the last ``mode=`` it parses, so the copy-up option must
        not be appended after it."""
        line = _apply_tmpfs_mask_options(
            ["/workspace/.claude/:rw"], [("/workspace", "/home/u/repo")],
        )[0]
        assert line.split(",")[-1] == "mode=1777"

    def test_image_directory_tmpfs_is_left_alone(self):
        """A tmpfs over a plain image directory has no enclosing mount. Its
        contents are the image author's intent — agentcage must not decide
        copy-up for it in either direction."""
        entry = "/tmp:rw,noexec,nosuid,size=256M"
        assert _apply_tmpfs_mask_options(
            [entry], [("/workspace", "/home/u/repo")],
        ) == [entry]

    def test_scaffold_shape_round_trips(self, tmp_path, monkeypatch):
        unit = _cage_unit(
            tmp_path, monkeypatch, [WORKSPACE], [SCRATCH, HOOKS, CLAUDE],
        )
        assert f"Tmpfs={HOOKS},mode=1777" in unit
        assert f"Tmpfs={CLAUDE},mode=1777" in unit
        assert f"Tmpfs={SCRATCH}\n" in unit + "\n"


class TestMaskCopyUpEntries:
    BIND = [("/workspace", "/home/u/repo")]

    def test_source_is_the_host_path_the_mask_covers(self):
        assert mask_copyup_entries(
            ["/workspace/.claude/:rw,tmpcopyup"], self.BIND,
        ) == [("/workspace/.claude", "/home/u/repo/.claude", "/home/u/repo")]

    def test_mask_over_the_whole_bind_seeds_from_the_bind_root(self):
        assert mask_copyup_entries(["/workspace:rw,tmpcopyup"], self.BIND) == [
            ("/workspace", "/home/u/repo", "/home/u/repo")
        ]

    def test_entry_without_tmpcopyup_is_not_returned(self):
        assert mask_copyup_entries(
            ["/workspace/.claude/:rw", "/workspace/.git/hooks/:rw,notmpcopyup"],
            self.BIND,
        ) == []

    def test_non_mask_is_not_returned(self):
        """No enclosing mount: there is no host directory to seed from and
        the runtime's own copy-up already expresses the image's content."""
        assert mask_copyup_entries(["/tmp:rw,tmpcopyup"], self.BIND) == []

    def test_named_volume_mask_has_no_host_source(self):
        assert mask_copyup_entries(
            ["/data/cache:rw,tmpcopyup"], [("/data", "")],
        ) == [("/data/cache", "", "")]

    def test_notmpcopyup_wins_over_a_stray_tmpcopyup(self):
        assert not tmpfs_wants_copyup("/x:tmpcopyup,notmpcopyup")


class TestCopyUpOwnershipHook:
    """The runtime copies up as the userns root and does not replay the
    source's ownership, so the copy lands 0:0 and `mode=1777` only buys the
    workload the right to create NEW entries."""

    def test_copyup_mask_gets_a_chown_execstartpost(self, tmp_path, monkeypatch):
        unit = _cage_unit(tmp_path, monkeypatch, [WORKSPACE], [HOOKS, CLAUDE])
        lines = _chown_lines(unit)
        assert len(lines) == 1
        assert _b64("/workspace/.claude") in lines[0]
        assert "chown -Rh 1000:1000" in lines[0]
        # The chown reaches into the CONTAINER's mount tree, never the host
        # directory the copy came from.
        assert '"/proc/$PID/root$d"' in lines[0]
        assert str(tmp_path) not in lines[0]

    def test_the_hook_joins_only_the_user_namespace(self, tmp_path, monkeypatch):
        """`podman exec` cannot do this: the cage drops every capability, so
        root in an exec session has no CAP_CHOWN, and `--privileged` would run
        the cage IMAGE's own chown with a full capability set. `nsenter -U`
        runs the host's chown with the caps this unit's user already owns."""
        unit = _cage_unit(tmp_path, monkeypatch, [WORKSPACE], [CLAUDE])
        line = _chown_lines(unit)[0]
        assert 'nsenter -t "$PID" -U -- chown' in line
        assert "-m" not in line.split("nsenter")[1].split("--")[0]
        assert "podman exec" not in line
        assert "--privileged" not in line

    def test_the_hook_never_fails_the_cage(self, tmp_path, monkeypatch):
        """A cosmetic ownership repair must not keep a cage from starting."""
        line = _chown_lines(
            _cage_unit(tmp_path, monkeypatch, [WORKSPACE], [CLAUDE])
        )[0]
        assert line.startswith("ExecStartPost=-/bin/bash -c")
        assert line.rstrip("'").endswith("exit 0")

    def test_no_hook_without_copyup(self, tmp_path, monkeypatch):
        unit = _cage_unit(
            tmp_path, monkeypatch, [WORKSPACE], [SCRATCH, HOOKS],
        )
        assert _chown_lines(unit) == []

    def test_image_tmpfs_asking_for_copyup_gets_no_hook(
        self, tmp_path, monkeypatch,
    ):
        """`/tmp` is not a mask. Its copy-up is the image author's business
        and its content is already in the cage's own uid space."""
        unit = _cage_unit(
            tmp_path, monkeypatch, [WORKSPACE], ["/tmp:rw,tmpcopyup"],
        )
        assert _chown_lines(unit) == []

    def test_owner_follows_container_user(self, tmp_path, monkeypatch):
        unit = _cage_unit(
            tmp_path, monkeypatch, [WORKSPACE], [CLAUDE], user='"1500:1600"',
        )
        assert "chown -Rh 1500:1600" in _chown_lines(unit)[0]

    def test_root_cage_gets_no_hook(self, tmp_path, monkeypatch):
        """A cage running as uid 0 already owns the copy."""
        unit = _cage_unit(
            tmp_path, monkeypatch, [WORKSPACE], [CLAUDE], user='"0"',
        )
        assert _chown_lines(unit) == []

    def test_mask_containment_is_unchanged(self, tmp_path, monkeypatch):
        """#170/#173 regression guard: seeding changes what the cage can
        READ. The tmpfs still overlays the bind with its hardening options
        intact, so cage writes never reach the host."""
        unit = _cage_unit(tmp_path, monkeypatch, [WORKSPACE], [HOOKS, CLAUDE])
        line = next(
            e for e in unit.splitlines()
            if e.startswith("Tmpfs=/workspace/.claude/")
        )
        options = line.split(":", 1)[1].split(",")
        for option in ("rw", "noexec", "nosuid", "nodev", "size=64M"):
            assert option in options
        assert f"Volume={tmp_path}/repo:/workspace:rw" in unit


class TestMaskCopyUpOwner:
    def test_image_default_user_falls_back_to_1000(self):
        assert _mask_copyup_owner("") == "1000:1000"

    def test_uid_only_mirrors_the_gid(self):
        assert _mask_copyup_owner("1000") == "1000:1000"

    def test_uid_gid_pair_is_used_verbatim(self):
        assert _mask_copyup_owner("1500:20") == "1500:20"

    def test_root_needs_no_chown(self):
        assert _mask_copyup_owner("0") == ""
        assert _mask_copyup_owner("0:0") == ""

    def test_a_user_name_cannot_be_resolved_host_side(self):
        """The cage image's /etc/passwd is not readable from the host, and
        guessing would chown the copy to the wrong uid."""
        assert _mask_copyup_owner("node") == ""
        assert _mask_copyup_owner("node:node") == ""
