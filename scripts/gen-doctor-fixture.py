#!/usr/bin/env python3
"""Generate the doctor fixtures under tests/fixtures/doctor/.

``agentcage doctor`` is a sequence of "is this installed, and does it
work". Its output is therefore a function of the machine it runs on,
which is exactly what a golden-output test cannot be. Recording what the
doctor says on *this* laptop would pin the laptop, not the code.

So the environment is faked instead. Every probe the doctor makes --
``subprocess.run``, ``shutil.which``, ``shutil.disk_usage``,
``socket.getaddrinfo``, ``socket.socket``, ``Path.read_text`` /
``Path.exists``, ``os.environ``, ``os.geteuid``, ``sys.platform`` via
``doctor._IS_MACOS`` -- is answered from a declared environment, and the
REAL ``run_doctor`` is then run against it and its bytes recorded. The
expectations are never typed.

That is the same technique ``tests/test_doctor.py`` already uses, widened
from one check at a time to the whole run, and it is what the Rust port
(RUST-PORT-PLAN.md, Track D, PR D15) is held to. The port's equivalent of
these patches is ``FakeRunner`` -- ``CommandRunner::which`` is on the
trait precisely so the missing-binary branches stay reachable from a
Linux CI runner that has podman, systemd and no Lima.

The declared environment is written into the fixture alongside the
output, so the Rust test builds the same world from the same data rather
than from a second, hand-kept copy of it.

``check_python_version`` is DELETED by the port, not reproduced: the
whole point of the port is that the host no longer needs Python
(RUST-PORT-PLAN.md §2.4). It still runs here, because this drives the
unmodified Python, so each case records both what the Python printed and
what the port must print -- the same text minus that one line. The
generator refuses to write a case where dropping it would change
anything else (it asserts the dropped result is a ``pass`` with no hint,
so the summary counts cannot move).

Usage:
    uv run python scripts/gen-doctor-fixture.py          # write
    uv run python scripts/gen-doctor-fixture.py --check  # fail if stale

See tests/fixtures/doctor/README.md.
"""

from __future__ import annotations

import argparse
import contextlib
import functools
import io
import json
import os
import socket as _socket
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from unittest.mock import patch

_ROOT = Path(__file__).resolve().parent.parent
_OUT = _ROOT / "tests" / "fixtures" / "doctor"

sys.path.insert(0, str(_ROOT / "src"))

import click  # noqa: E402

from agentcage import doctor, secret_resolver  # noqa: E402


# The Python version the recorded runs report. Pinned so the fixture is
# byte-identical on 3.12, 3.13 and 3.14 -- and so the line the port drops
# is a constant, rather than whatever interpreter regenerated the file.
# `doctor._python_version_info` exists to be replaced like this; its
# docstring says "split out for testability".
_PINNED_PYTHON = (3, 12, 5)


# ---------------------------------------------------------------------------
# The declared environment
# ---------------------------------------------------------------------------

# Every subprocess the doctor can make, keyed by a short name. The key is
# what the fixture carries and what the Rust test turns back into an argv
# prefix for `FakeRunner::on`; the matcher below is the only place that
# knows the argv, on this side.
_COMMAND_KEYS = {
    "podman-version": ["podman", "--version"],
    "podman-rootless": ["podman", "info", "--format", "{{.Host.Security.Rootless}}"],
    "podman-networks": ["podman", "network", "ls", "--format", "json"],
    "limactl-version": ["limactl", "--version"],
    "qemu-version": ["qemu-system-x86_64", "--version"],
    "loginctl-linger": ["loginctl", "show-user"],
    "systemctl-version": ["systemctl", "--version"],
    "systemd-creds-user": ["systemd-creds", "--user", "encrypt"],
    "systemd-creds-system": ["systemd-creds", "encrypt"],
    "ss-8080": ["ss", "-tlnp", "sport = :8080"],
    "ss-3000": ["ss", "-tlnp", "sport = :3000"],
    "ss-18789": ["ss", "-tlnp", "sport = :18789"],
}


def _classify(cmd: list[str]) -> str:
    """Which `_COMMAND_KEYS` entry this argv is, or raise."""
    for key, prefix in _COMMAND_KEYS.items():
        if cmd[: len(prefix)] == prefix:
            return key
    raise AssertionError(
        f"unmodelled subprocess in doctor: {cmd!r}. Add it to _COMMAND_KEYS "
        "(and to the Rust test's key table) rather than letting it fall "
        "through to a default -- a default is how a new probe goes unnoticed."
    )


def ok(stdout: str = "") -> dict:
    """The process ran and exited 0."""
    return {"kind": "ok", "stdout": stdout}


def rc(code: int, stdout: str = "") -> dict:
    """The process ran and exited non-zero."""
    return {"kind": "rc", "code": code, "stdout": stdout}


def missing() -> dict:
    """The binary is not installed (`FileNotFoundError`)."""
    return {"kind": "missing"}


def timed_out() -> dict:
    """The probe outlived its timeout (`subprocess.TimeoutExpired`)."""
    return {"kind": "timeout"}


@dataclass
class Env:
    """One faked host.

    Everything the doctor can ask about, with defaults that describe a
    healthy Arch box, so a case only has to say how it differs.
    """

    id: str
    why: str
    macos: bool = False
    # /etc/os-release, or None for "the file is unreadable".
    os_release: str | None = 'ID=arch\nNAME="Arch Linux"\n'
    existing_paths: list[str] = field(
        default_factory=lambda: ["/sys/fs/cgroup/cgroup.controllers"]
    )
    # shutil.which answers. Absent name => not installed.
    which: dict[str, str | None] = field(
        default_factory=lambda: {
            "podman": "/usr/bin/podman",
            "systemd-creds": "/usr/bin/systemd-creds",
        }
    )
    commands: dict[str, dict] = field(default_factory=dict)
    # shutil.disk_usage(~).free, or an error.
    disk: dict = field(default_factory=lambda: {"kind": "free", "bytes": 50 * 1024**3})
    dns: dict = field(default_factory=lambda: {"kind": "ok"})
    # True = the bind succeeded, i.e. the port is free.
    ports: dict[int, bool] = field(
        default_factory=lambda: {8080: True, 3000: True, 18789: True}
    )
    env_vars: dict[str, str] = field(default_factory=lambda: {"USER": "testuser"})
    euid: int = 1000
    # What apple_container.prerequisites.check_prerequisites() answers.
    apple_issues: list[str] = field(
        default_factory=lambda: [
            "apple-container isolation requires macOS; current platform is Linux"
        ]
    )
    # False when the Rust port cannot reproduce this case, with the reason.
    ported: bool = True
    not_ported_because: str = ""

    def command(self, key: str) -> dict:
        return self.commands.get(key, missing())

    def to_json(self) -> dict:
        return {
            "macos": self.macos,
            "os_release": self.os_release,
            "existing_paths": sorted(self.existing_paths),
            "which": {k: self.which[k] for k in sorted(self.which)},
            "commands": {k: self.commands[k] for k in sorted(self.commands)},
            "disk": self.disk,
            "dns": self.dns,
            "ports": {str(p): self.ports[p] for p in sorted(self.ports)},
            "env_vars": self.env_vars,
            "euid": self.euid,
            "apple_issues": list(self.apple_issues),
        }


# The healthy-host command set, which most cases start from.
def _healthy_commands(**overrides: dict) -> dict[str, dict]:
    base = {
        "podman-version": ok("podman version 4.9.3\n"),
        "podman-rootless": ok("true\n"),
        "podman-networks": ok("[]"),
        "limactl-version": ok("limactl version 1.0.2\n"),
        "qemu-version": ok("QEMU emulator version 8.2.0 (Debian 1:8.2.0)\n"),
        "loginctl-linger": ok("Linger=yes\n"),
        "systemctl-version": ok("systemd 256 (256.11-1-arch)\n"),
        "systemd-creds-user": ok(""),
        "systemd-creds-system": ok(""),
        "ss-8080": ok(""),
        "ss-3000": ok(""),
        "ss-18789": ok(""),
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# The fake world
# ---------------------------------------------------------------------------

class _FakePath:
    """Stands in for `doctor.Path`.

    Only two paths are ever constructed: `/etc/os-release`, which
    `_detect_distro` reads, and `/sys/fs/cgroup/cgroup.controllers`,
    whose mere existence is the cgroup-v2 answer. Faking the class rather
    than the two functions keeps the real parser and the real branch in
    the recording.
    """

    def __init__(self, env: Env, p) -> None:
        self._env = env
        self._p = str(p)

    def read_text(self) -> str:
        if self._p == "/etc/os-release":
            if self._env.os_release is None:
                raise OSError(2, "No such file or directory", self._p)
            return self._env.os_release
        raise AssertionError(f"unmodelled read_text: {self._p}")

    def exists(self) -> bool:
        if "cgroup-crash" in self._env.existing_paths:
            raise OSError("permission denied")
        return self._p in self._env.existing_paths


class _FakeSocket:
    """`socket.socket(AF_INET, SOCK_STREAM)` for `check_port`."""

    def __init__(self, env: Env, *args, **kwargs) -> None:
        self._env = env

    def __enter__(self):
        return self

    def __exit__(self, *exc) -> bool:
        return False

    def bind(self, addr) -> None:
        _host, port = addr
        if not self._env.ports.get(port, True):
            raise OSError(98, "Address already in use")


def _fake_run(env: Env, cmd, **kwargs):
    spec = env.command(_classify(list(cmd)))
    kind = spec["kind"]
    if kind == "missing":
        raise FileNotFoundError(2, "No such file or directory", cmd[0])
    if kind == "timeout":
        raise subprocess.TimeoutExpired(cmd, kwargs.get("timeout", 5))
    code = spec.get("code", 0)
    return subprocess.CompletedProcess(cmd, code, stdout=spec.get("stdout", ""))


def _fake_getaddrinfo(env: Env, *args, **kwargs):
    spec = env.dns
    kind = spec["kind"]
    if kind == "ok":
        return [(_socket.AF_INET, _socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80))]
    if kind == "gaierror":
        raise _socket.gaierror(-2, "Name or service not known")
    if kind == "timeout":
        raise TimeoutError("timed out")
    raise OSError(spec["message"])


def _fake_disk_usage(env: Env, _path):
    spec = env.disk
    if spec["kind"] == "error":
        raise OSError(spec["message"])
    if spec["kind"] == "crash":
        # Not an OSError, so `check_disk_space` does not catch it and
        # `_safe_check` does. See the case's `why`.
        raise ValueError(spec["message"])
    return _Usage(spec["bytes"])


class _Usage:
    """`shutil.disk_usage`'s named tuple, reduced to the field read."""

    def __init__(self, free: int) -> None:
        self.free = free


class _FakeWhich:
    def __init__(self, env: Env) -> None:
        self._env = env

    def __call__(self, program, *a, **kw):
        return self._env.which.get(program)


class _TtyStringIO(io.StringIO):
    """A stream click believes is a terminal, so it keeps the escapes."""

    def isatty(self) -> bool:
        return True


@contextlib.contextmanager
def _world(env: Env):
    """Install every patch this environment implies."""
    # `secret_resolver` memoizes its capability answers for the life of
    # the process. Without this, case 2 sees case 1's host.
    for fn in (
        secret_resolver.detect_default_backend,
        secret_resolver.detect_default_scope,
        secret_resolver._systemd_creds_works,
    ):
        fn.cache_clear()

    from agentcage.apple_container import prerequisites as ac_prereq

    with contextlib.ExitStack() as stack:
        p = stack.enter_context
        p(patch.object(doctor, "_IS_MACOS", env.macos))
        p(patch.object(doctor, "_python_version_info", return_value=_PINNED_PYTHON))
        p(patch.object(doctor, "Path", functools.partial(_FakePath, env)))
        # `subprocess`, `shutil`, `socket` and `os` are the real modules
        # under `doctor.<name>`, so one patch each also covers
        # `secret_resolver`'s uses of them -- which is what the secret
        # backend check needs.
        p(patch("subprocess.run", side_effect=functools.partial(_fake_run, env)))
        p(patch("shutil.which", new=_FakeWhich(env)))
        p(
            patch(
                "shutil.disk_usage",
                side_effect=functools.partial(_fake_disk_usage, env),
            )
        )
        p(
            patch(
                "socket.getaddrinfo",
                side_effect=functools.partial(_fake_getaddrinfo, env),
            )
        )
        p(patch("socket.socket", new=functools.partial(_FakeSocket, env)))
        p(patch("os.geteuid", return_value=env.euid))
        p(patch.dict("os.environ", env.env_vars, clear=True))
        p(
            patch.object(
                ac_prereq, "check_prerequisites", return_value=list(env.apple_issues)
            )
        )
        yield


def _capture(env: Env, *, tty: bool):
    """Run the real `run_doctor` against `env` and keep what it wrote."""
    make = _TtyStringIO if tty else io.StringIO
    out = make()
    saved = sys.stdout
    sys.stdout = out
    try:
        with _world(env):
            results = doctor.run_doctor()
    finally:
        sys.stdout = saved
    return out.getvalue(), results


# ---------------------------------------------------------------------------
# What the port must print: the same thing, minus the Python check
# ---------------------------------------------------------------------------

def _drop_python_line(text: str, results: list) -> tuple[str, list[str]]:
    """Remove the `check_python_version` line from a recorded run.

    Returns the remaining text and the lines removed. Raises if the line
    is not found exactly once, so a change to how the check prints fails
    here rather than silently leaving the port's expectation wrong.
    """
    major, minor, micro = _PINNED_PYTHON
    needle = f"Python {major}.{minor}.{micro}"
    kept, dropped = [], []
    for line in text.splitlines(keepends=True):
        if needle in line:
            dropped.append(line)
        else:
            kept.append(line)
    if len(dropped) != 1:
        raise AssertionError(
            f"expected exactly one {needle!r} line, found {len(dropped)}"
        )
    return "".join(kept), dropped


def _check_drop_is_safe(results: list) -> None:
    """The dropped check must not be able to move the summary counts.

    The summary is a count of errors and warnings. Removing a `pass`
    with no hint changes one line and nothing else -- which is what makes
    "the port's output is the Python's minus this line" an equality
    rather than a re-render.
    """
    hits = [r for r in results if r.message.startswith("Python ")]
    assert len(hits) == 1, f"expected one Python result, got {hits!r}"
    got = hits[0]
    assert got.level == "pass", (
        "the pinned Python version no longer passes its own check, so "
        "dropping it would change the summary counts"
    )
    assert got.hint == "", "the dropped check grew a hint line"


def _result_json(r) -> dict:
    return {"level": r.level, "message": r.message, "hint": r.hint}


# ---------------------------------------------------------------------------
# The environments
# ---------------------------------------------------------------------------

def _environments() -> list[Env]:
    envs: list[Env] = []
    e = envs.append

    # ── the baseline ──
    e(Env(
        id="linux-healthy",
        why="every prerequisite present and working: the run that must "
            "print no error and exit 0",
        commands=_healthy_commands(),
    ))

    # ── podman ──
    e(Env(
        id="linux-podman-missing",
        why="the headline failure. Podman missing is a hard error, the "
            "rootless check is SKIPPED (it is gated on the previous "
            "result being a pass), and the subnet check degrades to its "
            "'podman not available' pass",
        which={"systemd-creds": "/usr/bin/systemd-creds"},
        commands=_healthy_commands(
            **{
                "podman-version": missing(),
                "podman-rootless": missing(),
                "podman-networks": missing(),
            }
        ),
    ))
    e(Env(
        id="linux-podman-rootful",
        why="podman answers the rootless probe with 'false' -- running "
            "as root, which is a warning and not an error",
        commands=_healthy_commands(**{"podman-rootless": ok("false\n")}),
    ))
    e(Env(
        id="linux-podman-rootless-unverifiable",
        why="`podman info` exits non-zero. Neither branch of the 'true'/"
            "'false' test is taken and the check falls through to its "
            "hintless 'could not verify' warning",
        commands=_healthy_commands(**{"podman-rootless": rc(125, "")}),
    ))
    e(Env(
        id="linux-podman-old",
        why="an old podman. Recorded because doctor does NOT version-gate "
            "podman: 3.4.4 prints as a pass, exactly like 4.9.3. The "
            "port must reproduce that, including the "
            "'podman version ' prefix strip",
        commands=_healthy_commands(
            **{"podman-version": ok("podman version 3.4.4\n")}
        ),
    ))
    e(Env(
        id="linux-probes-time-out",
        why="every external probe hangs. `subprocess.TimeoutExpired` is "
            "caught in the same `except` as `FileNotFoundError`, so a "
            "wedged podman is indistinguishable from an absent one",
        which={"systemd-creds": "/usr/bin/systemd-creds"},
        commands={k: timed_out() for k in _COMMAND_KEYS},
    ))

    # ── lima / qemu / linger, and the distro hint tables ──
    e(Env(
        id="linux-lima-and-qemu-missing",
        why="the common Linux container-only host: no VM tooling, two "
            "warnings, still exit 0",
        commands=_healthy_commands(
            **{"limactl-version": missing(), "qemu-version": missing()}
        ),
    ))
    for distro_id, os_release in [
        ("debian", 'ID=ubuntu\nID_LIKE=debian\nNAME="Ubuntu"\n'),
        ("fedora", "ID=fedora\n"),
        ("rhel", 'ID=rocky\nID_LIKE="rhel"\n'),
        ("opensuse", "ID=opensuse-tumbleweed\n"),
        ("unknown", 'ID=plan9\nNAME="Plan 9"\n'),
    ]:
        e(Env(
            id=f"linux-nothing-installed-{distro_id}",
            why=f"the remediation hints for the {distro_id} family, which "
                "are three separate lookup tables keyed on a distro "
                "string `_detect_distro` derives from ID and ID_LIKE",
            os_release=os_release,
            which={},
            commands={k: missing() for k in _COMMAND_KEYS},
        ))
    e(Env(
        id="linux-nothing-installed-rhel-like-fedora",
        why="a Rocky box whose ID_LIKE names fedora as well as rhel. "
            "`_detect_distro` tests fedora BEFORE rhel, so this host is "
            "offered qemu-system-x86-core and not qemu-kvm -- the one "
            "place the two dnf families' hint tables differ, and the "
            "ordering a port would plausibly get wrong",
        os_release='ID=rocky\nID_LIKE="rhel centos fedora"\n',
        which={},
        commands={k: missing() for k in _COMMAND_KEYS},
    ))
    e(Env(
        id="linux-os-release-unreadable",
        why="/etc/os-release cannot be read, so the distro is 'unknown' "
            "and every hint falls back to its generic form",
        os_release=None,
        which={},
        commands={k: missing() for k in _COMMAND_KEYS},
    ))
    e(Env(
        id="linux-linger-disabled",
        why="`loginctl show-user` says Linger=no -- the single most "
            "common real finding on a fresh host, because without it "
            "user units die at logout",
        commands=_healthy_commands(**{"loginctl-linger": ok("Linger=no\n")}),
    ))
    e(Env(
        id="linux-no-systemd",
        why="no systemd at all: loginctl absent (a different warning from "
            "linger-disabled, and hintless), and the secret backend "
            "falls all the way back to unencrypted podman",
        which={"podman": "/usr/bin/podman"},
        commands=_healthy_commands(
            **{
                "loginctl-linger": missing(),
                "systemctl-version": missing(),
                "systemd-creds-user": missing(),
                "systemd-creds-system": missing(),
            }
        ),
    ))
    e(Env(
        id="linux-no-user-env",
        why="USER is unset -- a systemd service, a container, a cron job. "
            "The linger check cannot name a user and gives up before "
            "running loginctl at all",
        env_vars={},
        commands=_healthy_commands(),
    ))

    # ── system ──
    e(Env(
        id="linux-cgroup-v1",
        why="no cgroup v2 controller file. Rootless podman needs v2, so "
            "this is the warning that explains an otherwise baffling "
            "failure later",
        existing_paths=[],
        commands=_healthy_commands(),
    ))
    e(Env(
        id="linux-cgroup-unreadable",
        why="the `exists()` call itself raises -- the OSError branch, "
            "which prints the exception text",
        existing_paths=["cgroup-crash"],
        commands=_healthy_commands(),
    ))
    e(Env(
        id="linux-disk-low",
        why="under the 2GB floor: an error, and the only place the "
            "doctor formats a float (one decimal, against the pass "
            "branch's zero)",
        disk={"kind": "free", "bytes": int(1.23 * 1024**3)},
        commands=_healthy_commands(),
    ))
    e(Env(
        id="linux-disk-just-over",
        why="exactly 2GB free. `>= 2` is the comparison, so this passes "
            "and rounds to '2GB' -- the boundary a port that used `>` "
            "or truncation would get wrong",
        disk={"kind": "free", "bytes": 2 * 1024**3},
        commands=_healthy_commands(),
    ))
    e(Env(
        id="linux-disk-unreadable",
        why="`disk_usage` raises OSError (a home directory on a dead NFS "
            "mount); the message carries the exception text",
        disk={"kind": "error", "message": "Permission denied"},
        commands=_healthy_commands(),
    ))
    e(Env(
        id="linux-check-crashes",
        why="`disk_usage` raises something that is NOT an OSError, so the "
            "check's own `except` misses it and `_safe_check` catches it "
            "instead: '<label> crashed: <exc>'. Recorded to pin the "
            "Python behaviour -- the port does not reproduce it, because "
            "its checks are total functions with no exception path, "
            "which is the one divergence this fixture states out loud",
        disk={"kind": "crash", "message": "not an OSError"},
        commands=_healthy_commands(),
        ported=False,
        not_ported_because="`_safe_check` wraps each check in a bare "
                           "`except Exception`. The Rust checks return a "
                           "`CheckResult` on every path and cannot raise, "
                           "so there is nothing for a port of `_safe_check` "
                           "to catch and no way to drive this branch.",
    ))

    # ── secrets ──
    e(Env(
        id="linux-secrets-system-scope",
        why="a root invoker: `detect_default_scope` skips the per-user "
            "key entirely (root's is not the operator's) and lands on "
            "the host key, which is the other pass message",
        euid=0,
        commands=_healthy_commands(),
    ))
    e(Env(
        id="linux-secrets-creds-present-but-unusable",
        why="modern systemd, systemd-creds installed, and neither scope "
            "encrypts -- a container host with no TPM and no host key. "
            "The one branch that names the `systemd-creds setup` fix",
        commands=_healthy_commands(
            **{
                "systemd-creds-user": rc(1, ""),
                "systemd-creds-system": rc(1, ""),
            }
        ),
    ))
    e(Env(
        id="linux-secrets-old-systemd",
        why="systemd 249: below the 250 floor, so the backend probe stops "
            "before trying to encrypt and the hint asks for an upgrade "
            "rather than for `systemd-creds setup`",
        commands=_healthy_commands(
            **{"systemctl-version": ok("systemd 249 (249.11-0ubuntu3)\n")}
        ),
    ))
    e(Env(
        id="linux-secrets-systemctl-garbage",
        why="`systemctl --version` prints something unparseable. "
            "`_systemd_version` swallows it and answers 0, which reads "
            "as 'too old' -- and the 0 is printed in the hint-less "
            "unencrypted branch",
        which={"podman": "/usr/bin/podman"},
        commands=_healthy_commands(
            **{"systemctl-version": ok("not systemd at all\n")}
        ),
    ))

    # ── network ──
    e(Env(
        id="linux-dns-failing",
        why="`getaddrinfo` raises gaierror: an error, because a cage "
            "whose DNS does not resolve cannot reach anything",
        dns={"kind": "gaierror"},
        commands=_healthy_commands(),
    ))
    e(Env(
        id="linux-dns-timeout",
        why="the `socket.timeout` branch. Recorded for completeness and "
            "worth knowing about: `check_dns` sets a 5s DEFAULT socket "
            "timeout, which `getaddrinfo` does not consult, so on a real "
            "host this branch is unreachable -- see the README",
        dns={"kind": "timeout"},
        commands=_healthy_commands(),
    ))
    e(Env(
        id="linux-dns-oserror",
        why="a non-gaierror OSError (no route to host); the message "
            "carries the exception text",
        dns={"kind": "oserror", "message": "[Errno 101] Network is unreachable"},
        commands=_healthy_commands(),
    ))
    e(Env(
        id="linux-subnet-conflicts",
        why="two existing podman networks already hold 10.89.x.0/24, "
            "which is where new cages are allocated. Pins the joined, "
            "comma-separated message and the gateway-vs-subnet match",
        commands=_healthy_commands(
            **{
                "podman-networks": ok(json.dumps([
                    {"name": "bridge", "subnets": [
                        {"subnet": "10.88.0.0/16", "gateway": "10.88.0.1"}]},
                    {"name": "old-cage", "subnets": [
                        {"subnet": "10.89.1.0/24", "gateway": "10.89.1.1"}]},
                    {"name": "stale-cage", "subnets": [
                        {"subnet": "10.89.7.0/24", "gateway": "10.89.7.1"}]},
                    {"name": "no-subnets"},
                ]))
            }
        ),
    ))
    e(Env(
        id="linux-subnet-query-fails",
        why="`podman network ls` exits non-zero rather than being absent: "
            "a different early return, with its own parenthetical",
        commands=_healthy_commands(**{"podman-networks": rc(125, "")}),
    ))
    e(Env(
        id="linux-subnet-json-garbage",
        why="`podman network ls --format json` exits 0 but prints "
            "something that is not JSON (a warning line ahead of the "
            "payload is the real-world shape). `json.loads` raises, the "
            "check does not catch it, and `_safe_check` reports a crash. "
            "The second and last case the port does not reproduce: with "
            "no exception to catch, unparseable output reads as 'no "
            "networks'",
        commands=_healthy_commands(
            **{"podman-networks": ok("Error: unable to connect\n")}
        ),
        ported=False,
        not_ported_because="`json.loads` raises `JSONDecodeError`, which "
                           "`check_subnet_conflicts` does not catch and "
                           "`_safe_check` turns into a warning. The port "
                           "has no exception path; it reads unparseable "
                           "output as an empty network list, which is the "
                           "same answer its non-zero-exit branch gives.",
    ))
    e(Env(
        id="linux-ports-in-use",
        why="all three common ports are taken. 8080 is held by a process "
            "`ss` names (the pid= regex), 3000 by one it does not, and "
            "18789 -- the proxy's own port -- by a process `ss` cannot "
            "see at all because it is absent",
        ports={8080: False, 3000: False, 18789: False},
        commands=_healthy_commands(
            **{
                "ss-8080": ok(
                    "State  Recv-Q Send-Q Local Address:Port Peer Address:Port\n"
                    "LISTEN 0      4096       127.0.0.1:8080       0.0.0.0:*    "
                    'users:(("node",pid=4242,fd=23))\n'
                ),
                "ss-3000": ok(
                    "State  Recv-Q Send-Q Local Address:Port Peer Address:Port\n"
                    "LISTEN 0      4096       127.0.0.1:3000       0.0.0.0:*\n"
                ),
                "ss-18789": missing(),
            }
        ),
    ))

    # ── the worst case ──
    e(Env(
        id="linux-nothing-works",
        why="a host with nothing on it and no network: the maximal error "
            "and warning counts, and the plural forms in the summary",
        os_release=None,
        existing_paths=[],
        which={},
        commands={k: missing() for k in _COMMAND_KEYS},
        disk={"kind": "free", "bytes": 512 * 1024**2},
        dns={"kind": "gaierror"},
        ports={8080: False, 3000: False, 18789: False},
        env_vars={},
    ))

    # ── macOS ──
    # `_IS_MACOS` is a module constant read at call time, so a Linux CI
    # runner reaches every one of these -- the same trick
    # `test_doctor.py` and `test_apple_container.py` already play.
    e(Env(
        id="macos-healthy",
        why="a fully set-up Mac: Lima for vm isolation, host podman for "
            "`secret set`, apple-container ready. QEMU, linger and "
            "cgroup checks must not appear at all",
        macos=True,
        os_release=None,
        existing_paths=[],
        which={"podman": "/opt/homebrew/bin/podman"},
        commands=_healthy_commands(
            **{
                "qemu-version": missing(),
                "loginctl-linger": missing(),
                "systemctl-version": missing(),
                "systemd-creds-user": missing(),
                "systemd-creds-system": missing(),
            }
        ),
        apple_issues=[],
    ))
    e(Env(
        id="macos-no-host-podman",
        why="podman is not installed on the Mac. That is a PASS, not an "
            "error -- containers run inside the VM -- but the secret "
            "check warns, because `agentcage secret set` is the one "
            "thing that needs host podman",
        macos=True,
        os_release=None,
        existing_paths=[],
        which={},
        commands=_healthy_commands(
            **{
                "podman-version": missing(),
                "podman-rootless": missing(),
                "podman-networks": missing(),
                "qemu-version": missing(),
                "loginctl-linger": missing(),
                "systemctl-version": missing(),
                "systemd-creds-user": missing(),
                "systemd-creds-system": missing(),
            }
        ),
        apple_issues=[],
    ))
    e(Env(
        id="macos-apple-container-only",
        why="issue #215: Lima absent but apple-container ready. Lima must "
            "degrade to a WARNING so the run exits 0 -- the host can "
            "still run cages",
        macos=True,
        os_release=None,
        existing_paths=[],
        which={"podman": "/opt/homebrew/bin/podman"},
        commands=_healthy_commands(
            **{
                "limactl-version": missing(),
                "qemu-version": missing(),
                "loginctl-linger": missing(),
                "systemctl-version": missing(),
                "systemd-creds-user": missing(),
                "systemd-creds-system": missing(),
            }
        ),
        apple_issues=[],
    ))
    e(Env(
        id="macos-no-isolation-backend",
        why="neither Lima nor apple-container: the only case where a "
            "missing Lima stays a hard error, and the apple-container "
            "check reports the FIRST unmet prerequisite as its hint",
        macos=True,
        os_release=None,
        existing_paths=[],
        which={},
        commands={k: missing() for k in _COMMAND_KEYS},
        apple_issues=[
            "Apple container apiserver is not running — run "
            "'container system start --enable-kernel-install'",
            "a second issue, which must NOT be printed",
        ],
    ))

    return envs


# ---------------------------------------------------------------------------
# Generation
# ---------------------------------------------------------------------------

def _case(env: Env) -> dict:
    color_text, results = _capture(env, tty=True)
    plain_text, plain_results = _capture(env, tty=False)

    assert [_result_json(r) for r in results] == [
        _result_json(r) for r in plain_results
    ], f"{env.id}: the results depend on whether stdout is a terminal"
    assert click.unstyle(color_text) == plain_text, (
        f"{env.id}: colour does more than add escapes"
    )

    _check_drop_is_safe(results)
    expected_color, dropped_color = _drop_python_line(color_text, results)
    expected_plain, _ = _drop_python_line(plain_text, results)
    assert click.unstyle(expected_color) == expected_plain, (
        f"{env.id}: dropping the Python line left the two modes disagreeing"
    )

    expected_results = [r for r in results if not r.message.startswith("Python ")]
    exit_code = 1 if any(r.level == "error" for r in results) else 0
    expected_exit = 1 if any(r.level == "error" for r in expected_results) else 0
    assert exit_code == expected_exit, (
        f"{env.id}: dropping the Python check changed the exit code"
    )

    case = {
        "id": env.id,
        "why": env.why,
        "ported": env.ported,
        "env": env.to_json(),
        "python": {"color": color_text, "plain": plain_text},
        "expected": {"color": expected_color, "plain": expected_plain},
        "dropped": dropped_color,
        "results": [_result_json(r) for r in results],
        "expected_results": [_result_json(r) for r in expected_results],
        "exit_code": exit_code,
    }
    if not env.ported:
        case["not_ported_because"] = env.not_ported_because
    return case


def _build() -> dict:
    envs = _environments()
    ids = [e.id for e in envs]
    assert len(ids) == len(set(ids)), "duplicate environment id"
    cases = [_case(e) for e in envs]
    return {
        "fixture": "doctor",
        "module": "agentcage.doctor",
        "generator": "scripts/gen-doctor-fixture.py",
        "summary": (
            f"{len(cases)} faked host environments, each recorded by running "
            "the real `agentcage.doctor.run_doctor` with every probe it "
            "makes answered from the declared environment. `python` is what "
            "the Python printed; `expected` is what the Rust port must "
            "print -- the same bytes minus the `check_python_version` line, "
            "which the port deletes rather than ports (RUST-PORT-PLAN.md "
            "§2.4: Python is not a host dependency)."
        ),
        "pinned_python_version": ".".join(str(n) for n in _PINNED_PYTHON),
        "command_keys": {k: v for k, v in sorted(_COMMAND_KEYS.items())},
        "common_ports": list(doctor._COMMON_PORTS),
        "cases": cases,
    }


def _render(doc: dict) -> str:
    return json.dumps(doc, indent=2, ensure_ascii=True, sort_keys=False) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true",
                    help="exit non-zero if the committed fixture is stale")
    args = ap.parse_args()

    text = _render(_build())
    path = _OUT / "environments.json"

    if args.check:
        if not path.exists():
            print(f"missing: {path}", file=sys.stderr)
            return 1
        if path.read_text() != text:
            print(
                f"STALE: {path.relative_to(_ROOT)} does not match the current "
                "Python. Regenerate with:\n"
                "    uv run python scripts/gen-doctor-fixture.py\n"
                "then READ the diff -- a one-symbol change should be a "
                "one-line diff.",
                file=sys.stderr,
            )
            return 1
        print(f"current: {path.relative_to(_ROOT)}")
        return 0

    _OUT.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    print(f"wrote {path.relative_to(_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
