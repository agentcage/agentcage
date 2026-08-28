"""Tests for the per-bind non-persistent ``np`` volume option."""

from __future__ import annotations

import textwrap

import pytest

from agentcage import quadlets
from agentcage.config import load_config, validate_config
from agentcage.quadlets import generate_quadlets


def _config(tmp_path, volumes):
    config_path = tmp_path / "cage.yaml"
    config_path.write_text(textwrap.dedent(f"""\
        name: test
        dns_servers: [1.1.1.1]
        container:
          image: test:latest
          volumes:
    """) + "\n".join(f"    - {volume}" for volume in volumes) + "\n")
    return load_config(str(config_path))


def test_np_volume_is_an_ephemeral_overlay_bind(tmp_path, monkeypatch):
    (tmp_path / "repo").mkdir()
    cfg = _config(tmp_path, ["~/repo:/workspace:rw,np"])
    monkeypatch.setattr(
        quadlets.os.path, "expanduser", lambda path: path.replace("~", str(tmp_path))
    )

    cage = generate_quadlets(cfg, "/cage.yaml", "/patches")["test-cage.container"]
    volume = next(line for line in cage.splitlines() if "upperdir=" in line)
    assert "Volume=" in volume
    assert ":O,upperdir=" in volume
    assert ",workdir=" in volume
    assert "/workspace" in volume
    assert ",np" not in volume
    assert "ExecStartPre=/bin/bash -c 'rm -rf %t/agentcage/test/mounts" in cage
    assert "ExecStopPost=/bin/bash -c 'rm -rf %t/agentcage/test/mounts'" in cage


def test_non_np_volume_stays_a_direct_writable_bind(tmp_path, monkeypatch):
    (tmp_path / "repo").mkdir()
    cfg = _config(tmp_path, ["~/repo:/workspace:rw"])
    monkeypatch.setattr(
        quadlets.os.path, "expanduser", lambda path: path.replace("~", str(tmp_path))
    )

    cage = generate_quadlets(cfg, "/cage.yaml", "/patches")["test-cage.container"]
    assert f"Volume={tmp_path}/repo:/workspace:rw" in cage
    assert "upperdir=" not in cage
    assert "ExecStopPost=/bin/bash -c 'rm -rf %t/agentcage/test/mounts'" not in cage


@pytest.mark.parametrize("options", ["ro,np", "rw,Z,np", "rw,z,np", "rw,U,np", "rw,O,np", "rw,np,noexec"])
def test_np_rejects_incompatible_or_nonportable_options(tmp_path, options):
    cfg = _config(tmp_path, [f"~/repo:/workspace:{options}"])
    with pytest.raises(ValueError, match="only rw,np is supported"):
        validate_config(cfg)
