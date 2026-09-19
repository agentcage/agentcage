# Doctor fixtures

Everything in this directory except this file is **generated**. Do not hand-edit it.

```sh
uv run python scripts/gen-doctor-fixture.py
uv run python scripts/gen-doctor-fixture.py --check   # what CI runs
```

## The problem this solves

`agentcage doctor` is fourteen questions of the form "is this installed, and does
it work". Its output is therefore a function of the *machine*, which makes it the
one command whose golden output cannot be recorded from the machine. What the
doctor prints on the CI runner pins the runner: podman present, systemd present,
Lima absent, not a Mac. That is one host. The hosts worth testing are the broken
ones.

So the environment is faked and the output is recorded per environment.
`scripts/gen-doctor-fixture.py` answers every probe `doctor.py` makes —
`subprocess.run`, `shutil.which`, `shutil.disk_usage`, `socket.getaddrinfo`,
`socket.socket`, `Path.read_text` / `Path.exists`, `os.environ`, `os.geteuid`,
and `doctor._IS_MACOS` — from a declared environment, runs the **real**
`run_doctor`, and records what came out. No expectation is typed.

The declared environment is written into the fixture next to the output, so the
Rust test builds the same host from the same data rather than from a second,
hand-kept copy of it. On the Rust side those answers come from
`agentcage_exec::FakeRunner` and a fake `DoctorHost`;
`CommandRunner::which` is on the trait (PR D1) precisely so the missing-binary
branches stay reachable from a Linux CI runner.

## What is covered

**39 environments**, 37 of which the Rust port reproduces byte for byte. The
matrix is built from what `tests/test_doctor.py` already simulated one check at a
time, widened to whole runs:

| Group | Environments |
| :-- | :-- |
| Healthy | everything present and working |
| Podman | missing, rootful, unverifiable rootless, an old version, every probe timing out |
| Distro hints | debian, fedora, rhel, opensuse, unknown, an unreadable `/etc/os-release`, and a Rocky box whose `ID_LIKE` names fedora |
| systemd | linger disabled, no systemd at all, `USER` unset |
| System | cgroup v1, an `exists()` that raises, low disk, exactly 2GB, an unreadable `$HOME` |
| Secrets | user scope, system scope (root), `systemd-creds` present but unusable, systemd 249, unparseable `systemctl --version` |
| Network | DNS gaierror / timeout / other `OSError`, subnet conflicts, a failed network query, non-JSON network output, all three ports taken |
| Worst case | a host with nothing on it and no network |
| macOS | healthy, no host podman, apple-container-only (issue #215), no isolation backend at all |

`_IS_MACOS` is a module constant read at call time, so the four macOS cases run
on the Linux CI — the same trick `test_apple_container.py` uses.

## What `check_python_version` has to do with it

The port **deletes** that check rather than porting it. RUST-PORT-PLAN.md §2.4
makes "Python is not an agentcage runtime dependency anywhere except inside the
egress image" an invariant, and §2.5 has `install.sh` shedding its
Python-detection section with it. A ported check would assert the dependency the
port removes, and would fail on exactly the hosts the port exists to serve.

The fixture is generated from the unmodified Python, so it records both:

* `python` — what `run_doctor` printed, Python-version line and all.
* `expected` — what the Rust port must print: the same bytes, minus that line.
* `dropped` — the line itself.

The generator refuses to write a case unless dropping it is provably harmless:
the dropped result must be a `pass` with no hint, so the summary counts cannot
move, and the recorded exit code must be the same with and without it. The
Python version reported is pinned to 3.12.5 (via `doctor._python_version_info`,
which exists to be replaced) so the fixture is byte-identical on 3.12, 3.13 and
3.14.

## The two cases the port does not reproduce

Both are `_safe_check`, which wraps every check in a bare `except Exception` and
reports `"<label> crashed: <exc>"`:

* `linux-check-crashes` — `shutil.disk_usage` raises something that is not an
  `OSError`, so `check_disk_space`'s own `except` misses it.
* `linux-subnet-json-garbage` — `podman network ls --format json` exits 0 and
  prints something `json.loads` refuses.

The ported checks are total functions: every path returns a `CheckResult` and
none can raise, so there is nothing for a port of `_safe_check` to catch. Those
two carry `"ported": false` and a reason; `golden_doctor.rs` pins the unported
set by name, so a third case cannot be excused by flipping the flag.

## Python behaviour recorded here that is arguably wrong

Recorded and reproduced rather than fixed, per RUST-PORT-PLAN.md §2.9 — a port
that quietly diverges is worse than one that carries a known wart.

* **`check_dns`'s timeout branch is dead.** It sets
  `socket.setdefaulttimeout(5)`, which applies to socket *objects* and not to
  `getaddrinfo`, so `socket.timeout` is never raised there. `linux-dns-timeout`
  records what it would print if it were.
* **`check_cgroup_v2`'s `except OSError` is dead too.** `Path.exists()` swallows
  `OSError` and answers `False`. `linux-cgroup-unreadable` drives the branch
  through the fake; a real host cannot.
* **Nothing version-gates podman.** `linux-podman-old` records podman 3.4.4
  passing exactly like 4.9.3, although `egress.container.j2` documents needing
  4.7+ for `podman secret inspect --showsecret`.
* **`_detect_distro` tests fedora before rhel.** A Rocky host with
  `ID_LIKE="rhel centos fedora"` is offered `qemu-system-x86-core` rather than
  `qemu-kvm`. `linux-nothing-installed-rhel-like-fedora` pins it.
* **A wedged binary is indistinguishable from an absent one.**
  `subprocess.TimeoutExpired` shares an `except` with `FileNotFoundError`, so a
  hung podman prints "Podman not found". `linux-probes-time-out` records it.

## Who reads them

* `rust/agentcage-cli/tests/golden_doctor.rs` — rebuilds each host and requires
  the bytes back, in both colour modes, plus the structured results and the exit
  code.
* `scripts/gen-doctor-fixture.py --check` — CI's staleness guard. It is what
  notices when `doctor.py` changes and the committed recording does not.

## Re-blessing

Deliberate, never reflexive. Regenerate, then read the diff: a one-symbol change
should be a one-line diff, repeated across the environments that reach it.
