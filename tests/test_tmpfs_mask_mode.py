"""Tests for the tmpfs mask-mode pin (#321).

A tmpfs that masks a path inside a host bind-mount — the #170
``/workspace/.git/hooks/`` and #173 ``/workspace/.claude/`` masks — is given
the mode of the *host* directory it covers by both OCI runtimes (runc
``createOpenMountpoint``, crun ``append_tmpfs_mode_if_missing``) unless the
spec carries an explicit ``mode=``. Combined with a root-owned tmpfs root
that made the mask unwritable for the cage's non-root ``user:``. Generation
now pins ``mode=1777`` on exactly those entries.
"""

from __future__ import annotations

import textwrap

from agentcage import quadlets
from agentcage.config import load_config
from agentcage.quadlets import _apply_tmpfs_mask_mode, generate_quadlets


def _config(tmp_path, volumes, tmpfs):
    config_path = tmp_path / "cage.yaml"
    body = textwrap.dedent("""\
        name: test
        dns_servers: [1.1.1.1]
        container:
          image: test:latest
          user: "1000:1000"
          userns: "keep-id"
          volumes:
    """)
    body += "\n".join(f"    - {volume}" for volume in volumes) + "\n"
    body += "  tmpfs:\n"
    body += "\n".join(f'    - "{entry}"' for entry in tmpfs) + "\n"
    config_path.write_text(body)
    return load_config(str(config_path))


def _cage_unit(tmp_path, monkeypatch, volumes, tmpfs):
    (tmp_path / "repo").mkdir(exist_ok=True)
    cfg = _config(tmp_path, volumes, tmpfs)
    monkeypatch.setattr(
        quadlets.os.path, "expanduser", lambda path: path.replace("~", str(tmp_path))
    )
    return generate_quadlets(cfg, "/cage.yaml", "/patches")["test-cage.container"]


def _tmpfs_lines(unit):
    return [
        line[len("Tmpfs="):]
        for line in unit.splitlines()
        if line.startswith("Tmpfs=")
    ]


class TestScaffoldMaskShape:
    """The shape every first-party scaffold and workspace-mask.yaml ships."""

    WORKSPACE = "~/repo:/workspace:rw"
    SCRATCH = "/tmp:rw,noexec,nosuid,size=256M"
    HOOKS = "/workspace/.git/hooks/:rw,noexec,nosuid,nodev,size=64M"
    CLAUDE = "/workspace/.claude/:rw,noexec,nosuid,nodev,size=64M"

    def test_masks_get_the_sticky_world_writable_mode(self, tmp_path, monkeypatch):
        unit = _cage_unit(
            tmp_path, monkeypatch,
            [self.WORKSPACE], [self.SCRATCH, self.HOOKS, self.CLAUDE],
        )
        assert f"Tmpfs={self.HOOKS},mode=1777" in unit
        assert f"Tmpfs={self.CLAUDE},mode=1777" in unit

    def test_mode_is_appended_last(self, tmp_path, monkeypatch):
        """Both runtimes *prepend* the inherited mountpoint mode to the mount
        data, and the kernel takes the last ``mode=`` it parses — so the pin
        only wins if it stays at the end of the option list."""
        unit = _cage_unit(
            tmp_path, monkeypatch, [self.WORKSPACE], [self.HOOKS],
        )
        line = next(e for e in _tmpfs_lines(unit) if ".git/hooks" in e)
        assert line.split(",")[-1] == "mode=1777"

    def test_image_scratch_tmpfs_is_untouched(self, tmp_path, monkeypatch):
        """/tmp is not inside a bind-mount: its mode comes from the image, which
        is the image author's intent and already sane in the cage's uid space."""
        unit = _cage_unit(
            tmp_path, monkeypatch,
            [self.WORKSPACE], [self.SCRATCH, self.HOOKS],
        )
        assert f"Tmpfs={self.SCRATCH}\n" in unit + "\n"
        assert "mode=" not in next(
            e for e in _tmpfs_lines(unit) if e.startswith("/tmp:")
        )

    def test_mask_keeps_its_hardening_options_and_the_bind(
        self, tmp_path, monkeypatch
    ):
        """The pin must not relax anything the mask relies on: the tmpfs stays
        noexec/nosuid/nodev (nothing planted there is executable) and the host
        bind-mount it overlays is unchanged, so writes still never reach the
        host."""
        unit = _cage_unit(
            tmp_path, monkeypatch, [self.WORKSPACE], [self.HOOKS],
        )
        line = next(e for e in _tmpfs_lines(unit) if ".git/hooks" in e)
        options = line.split(":", 1)[1].split(",")
        for option in ("rw", "noexec", "nosuid", "nodev", "size=64M"):
            assert option in options
        assert f"Volume={tmp_path}/repo:/workspace:rw" in unit


class TestApplyTmpfsMaskMode:
    BIND = ["/home/u/repo:/workspace:rw"]

    def test_operator_mode_is_never_overridden(self):
        entry = "/workspace/.git/hooks/:rw,mode=0700"
        assert _apply_tmpfs_mask_mode([entry], self.BIND) == [entry]

    def test_masking_the_bind_target_itself_is_pinned(self):
        assert _apply_tmpfs_mask_mode(["/workspace:rw"], self.BIND) == [
            "/workspace:rw,mode=1777"
        ]

    def test_option_less_entry_gets_the_mode(self):
        assert _apply_tmpfs_mask_mode(["/workspace/.claude"], self.BIND) == [
            "/workspace/.claude:mode=1777"
        ]

    def test_sibling_prefix_is_not_a_mask(self):
        """``/workspace-scratch`` is not under ``/workspace``."""
        entry = "/workspace-scratch:rw"
        assert _apply_tmpfs_mask_mode([entry], self.BIND) == [entry]

    def test_without_bind_mounts_nothing_is_rewritten(self):
        entries = ["/tmp:rw", "/workspace/.git/hooks/:rw"]
        assert _apply_tmpfs_mask_mode(entries, []) == entries

    def test_root_bind_does_not_capture_every_tmpfs(self):
        entry = "/tmp:rw"
        assert _apply_tmpfs_mask_mode([entry], ["/host:/:rw"]) == [entry]

    def test_non_absolute_target_is_left_alone(self):
        entry = "relative:rw"
        assert _apply_tmpfs_mask_mode([entry], self.BIND) == [entry]

    def test_unnormalized_target_is_matched_but_emitted_verbatim(self):
        """Podman gets the operator's literal path back; only the comparison
        is normalized."""
        assert _apply_tmpfs_mask_mode(
            ["/workspace/./.git/hooks/:rw"], self.BIND
        ) == ["/workspace/./.git/hooks/:rw,mode=1777"]


class TestNonPersistentBind:
    def test_mask_over_an_np_bind_is_pinned(self, tmp_path, monkeypatch):
        """An ``np`` bind reaches the template as an overlay spec, but its
        container-side target is still ``/workspace`` — a mask above it has the
        same inherited-mode problem."""
        unit = _cage_unit(
            tmp_path, monkeypatch,
            ["~/repo:/workspace:rw,np"],
            ["/workspace/.git/hooks/:rw,noexec,nosuid,nodev,size=64M"],
        )
        assert (
            "Tmpfs=/workspace/.git/hooks/:rw,noexec,nosuid,nodev,size=64M,mode=1777"
            in unit
        )
