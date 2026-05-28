"""Smoke test for the agentcage-egress container image.

PR 1 of the unify-to-2-containers refactor sequence. The test builds the
image and verifies the supervisor (a) brings up dnsmasq + mitmproxy with
the right uids and dropped CapBnd, (b) applies the FORWARD-chain iptables
shape, and (c) writes /var/log/agentcage/ready once everything's up.

Skipped if podman is not on PATH (e.g. typical macOS dev host); runs in
CI where podman is available. Build cost is ~minutes (mitmproxy bundle
is ~120MB) so the container-required tests share a module-scope fixture.
"""

from __future__ import annotations

import shutil
import subprocess
import time
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
CONTAINERFILE = REPO_ROOT / "src" / "agentcage" / "data" / "containers" / "Containerfile.egress"
BUILD_CONTEXT = REPO_ROOT / "src" / "agentcage" / "data"
IMAGE_TAG = "agentcage-egress:test"
CONTAINER_NAME = "egress-smoke"


def _have_podman() -> bool:
    return shutil.which("podman") is not None


pytestmark = pytest.mark.skipif(not _have_podman(), reason="podman not available")


def _podman(*args: str, check: bool = True, timeout: int = 600) -> subprocess.CompletedProcess[str]:
    """Run a podman command with text=True + capture_output=True."""
    return subprocess.run(
        ["podman", *args],
        capture_output=True,
        text=True,
        check=check,
        timeout=timeout,
    )


def _podman_logs(container: str) -> str:
    """Best-effort logs capture for failure messages."""
    try:
        result = subprocess.run(
            ["podman", "logs", container],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        return f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    except Exception as e:  # noqa: BLE001
        return f"(failed to capture logs: {e})"


def _stop(container: str) -> None:
    """Best-effort container stop — tolerates already-stopped containers."""
    subprocess.run(
        ["podman", "stop", "-t", "5", container],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )


# ── Build test ──────────────────────────────────────────────────────


def test_image_builds() -> None:
    """`podman build` of Containerfile.egress completes with exit 0."""
    result = subprocess.run(
        [
            "podman", "build",
            "-f", str(CONTAINERFILE),
            "-t", IMAGE_TAG,
            str(BUILD_CONTEXT),
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=1800,  # mitmproxy bundle download + extract
    )
    if result.returncode != 0:
        pytest.fail(
            f"podman build failed (exit {result.returncode}):\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )


# ── Module-scope running-container fixture ─────────────────────────


@pytest.fixture(scope="module")
def egress_container() -> str:
    """Build the image (if not already built) and start a container for the
    duration of the module. Tests share the same container so we only pay
    the ~120MB-bundle build cost once."""
    # Build (idempotent — podman is content-addressed and will fast-skip).
    build = subprocess.run(
        [
            "podman", "build",
            "-f", str(CONTAINERFILE),
            "-t", IMAGE_TAG,
            str(BUILD_CONTEXT),
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=1800,
    )
    if build.returncode != 0:
        pytest.fail(
            f"fixture: podman build failed (exit {build.returncode}):\n"
            f"stdout:\n{build.stdout}\nstderr:\n{build.stderr}"
        )

    # Clean up any leftover container from a previous run.
    _stop(CONTAINER_NAME)

    # Start the container detached, with the four caps the supervisor
    # needs (the Quadlet template adds the same set — keep these in sync
    # with egress.container.j2):
    #   NET_ADMIN          → sysctl ip_forward, iptables -P FORWARD DROP
    #   NET_BIND_SERVICE   → defense-in-depth for dnsmasq :53 (also set
    #                        via file cap, but explicit at run time is
    #                        kinder to non-Linux container runtimes).
    #   SETUID + SETGID    → setpriv --reuid/--regid for the per-process
    #                        privilege drop. Needed when the host's
    #                        `containers.conf` sets
    #                        `default_capabilities = []` (hardened
    #                        deployments); a no-op on default rootless
    #                        podman where these are already in the
    #                        default cap set.
    run = subprocess.run(
        [
            "podman", "run", "-d", "--rm",
            "--cap-add", "NET_ADMIN",
            "--cap-add", "NET_BIND_SERVICE",
            "--cap-add", "SETUID",
            "--cap-add", "SETGID",
            "--cap-add", "SETPCAP",
            "--cap-add", "KILL",
            "--name", CONTAINER_NAME,
            IMAGE_TAG,
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    if run.returncode != 0:
        pytest.fail(
            f"fixture: podman run failed (exit {run.returncode}):\n"
            f"stdout:\n{run.stdout}\nstderr:\n{run.stderr}"
        )

    # Poll for /var/log/agentcage/ready (max 60s).
    deadline = time.monotonic() + 60.0
    last_err = ""
    while time.monotonic() < deadline:
        check = subprocess.run(
            ["podman", "exec", CONTAINER_NAME, "test", "-f", "/var/log/agentcage/ready"],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        if check.returncode == 0:
            break
        last_err = f"stdout:\n{check.stdout}\nstderr:\n{check.stderr}"
        time.sleep(1)
    else:
        logs = _podman_logs(CONTAINER_NAME)
        _stop(CONTAINER_NAME)
        pytest.fail(
            f"fixture: /var/log/agentcage/ready never appeared within 60s.\n"
            f"last exec error: {last_err}\nlogs:\n{logs}"
        )

    yield CONTAINER_NAME

    _stop(CONTAINER_NAME)


# ── Tests that share the running container ─────────────────────────


def test_image_starts_and_becomes_ready(egress_container: str) -> None:
    """Container reaches /var/log/agentcage/ready (verified by the fixture)."""
    # If we got here, the fixture's polling loop succeeded. Re-assert
    # explicitly so the test is self-documenting and a stale ready file
    # from a prior aborted fixture is caught.
    result = _podman("exec", egress_container, "test", "-f", "/var/log/agentcage/ready", check=False)
    if result.returncode != 0:
        logs = _podman_logs(egress_container)
        pytest.fail(f"ready marker missing after fixture; logs: {logs}")


def test_dnsmasq_listening(egress_container: str) -> None:
    """dnsmasq binds :53 on both udp and tcp."""
    udp = _podman("exec", egress_container, "ss", "-lnup", check=False)
    if ":53 " not in udp.stdout:
        logs = _podman_logs(egress_container)
        pytest.fail(
            f"dnsmasq not listening on udp :53.\n"
            f"ss -lnup stdout:\n{udp.stdout}\nstderr:\n{udp.stderr}\nlogs:\n{logs}"
        )
    tcp = _podman("exec", egress_container, "ss", "-lnt", check=False)
    if ":53 " not in tcp.stdout:
        logs = _podman_logs(egress_container)
        pytest.fail(
            f"dnsmasq not listening on tcp :53.\n"
            f"ss -lnt stdout:\n{tcp.stdout}\nstderr:\n{tcp.stderr}\nlogs:\n{logs}"
        )


def test_mitmproxy_listening(egress_container: str) -> None:
    """mitmproxy binds both :8443 (transparent) and :8080 (regular)."""
    tcp = _podman("exec", egress_container, "ss", "-lnt", check=False)
    missing = []
    if ":8443 " not in tcp.stdout:
        missing.append(":8443 (transparent)")
    if ":8080 " not in tcp.stdout:
        missing.append(":8080 (regular)")
    if missing:
        logs = _podman_logs(egress_container)
        pytest.fail(
            f"mitmproxy not listening on: {missing}.\n"
            f"ss -lnt stdout:\n{tcp.stdout}\nstderr:\n{tcp.stderr}\nlogs:\n{logs}"
        )


def test_iptables_rules_applied(egress_container: str) -> None:
    """FORWARD chain has DROP policy; NAT PREROUTING has REDIRECTs for 80+443."""
    fwd = _podman("exec", egress_container, "iptables", "-L", "FORWARD", "-v", check=False)
    if "policy DROP" not in fwd.stdout:
        logs = _podman_logs(egress_container)
        pytest.fail(
            f"FORWARD chain missing DROP policy.\n"
            f"iptables -L FORWARD -v stdout:\n{fwd.stdout}\nlogs:\n{logs}"
        )

    nat = _podman("exec", egress_container, "iptables", "-t", "nat", "-L", "PREROUTING", "-v", check=False)
    # The brief specifies inspected_tcp_ports default of "80 443" — verify both REDIRECTs.
    # iptables -L renders well-known ports by name (http/https) by default,
    # but the smoke test should be robust to either form.
    out = nat.stdout
    has_80 = ("dpt:http" in out and "REDIRECT" in out) or ("dpt:80" in out and "REDIRECT" in out)
    has_443 = ("dpt:https" in out and "REDIRECT" in out) or ("dpt:443" in out and "REDIRECT" in out)
    if not (has_80 and has_443):
        logs = _podman_logs(egress_container)
        pytest.fail(
            f"PREROUTING missing REDIRECT for tcp 80 and/or 443.\n"
            f"iptables -t nat -L PREROUTING -v stdout:\n{out}\nlogs:\n{logs}"
        )


def test_dnsmasq_uid_and_capbnd(egress_container: str) -> None:
    """dnsmasq runs as uid 201 with CapBnd = {net_bind_service} only.

    The bounding set isn't fully cleared because dnsmasq needs to bind :53
    via the file cap (cap_net_bind_service=+ep set in the Containerfile).
    Per capabilities(7), file caps require the cap to be in the process's
    bounding set at execve. The supervisor uses
    `setpriv --bounding-set=-all,+net_bind_service` — strictly stronger
    than the Docker default cap set (which leaves SETUID, CHOWN, etc).
    cap_net_bind_service is bit 10 → 0x400.
    """
    # dnsmasq may take a moment to write its pidfile after exec; the
    # supervisor's step-C readiness check (poll :53) doesn't strictly
    # require the pidfile to exist.
    for _ in range(10):
        check = _podman(
            "exec", egress_container,
            "test", "-s", "/home/acdns/dnsmasq.pid",
            check=False,
        )
        if check.returncode == 0:
            break
        time.sleep(0.5)
    status = _podman(
        "exec", egress_container,
        "sh", "-c", 'cat /proc/$(cat /home/acdns/dnsmasq.pid)/status | grep -E "^(Uid|CapBnd):"',
        check=False,
    )
    if status.returncode != 0:
        logs = _podman_logs(egress_container)
        pytest.fail(
            f"could not read /proc/<dnsmasq>/status.\n"
            f"stdout:\n{status.stdout}\nstderr:\n{status.stderr}\nlogs:\n{logs}"
        )
    uid_line = ""
    capbnd_line = ""
    for line in status.stdout.splitlines():
        if line.startswith("Uid:"):
            uid_line = line
        elif line.startswith("CapBnd:"):
            capbnd_line = line
    # /proc/<pid>/status Uid: format is `Uid:\t<ruid>\t<euid>\t<suid>\t<fsuid>`
    uid_parts = uid_line.split()
    if len(uid_parts) < 2 or uid_parts[1] != "201":
        logs = _podman_logs(egress_container)
        pytest.fail(
            f"dnsmasq ruid != 201 (got line: {uid_line!r}).\nlogs:\n{logs}"
        )
    # CapBnd: dnsmasq retains cap_net_bind_service (bit 10 = 0x400) only.
    # Any other bit set means the supervisor's bounding-set filter is broken.
    capbnd_parts = capbnd_line.split()
    if len(capbnd_parts) < 2 or capbnd_parts[1] != "0000000000000400":
        logs = _podman_logs(egress_container)
        pytest.fail(
            f"dnsmasq CapBnd != cap_net_bind_service-only (got: {capbnd_line!r}; "
            f"expected 0000000000000400).\nlogs:\n{logs}"
        )


def test_mitmproxy_uid_and_capbnd(egress_container: str) -> None:
    """mitmproxy runs as uid 200 with CapBnd cleared."""
    # mitmdump is a PyInstaller bundle: the main process re-execs, so we
    # find PIDs by name + filter by uid 200 to dodge transient bootstraps.
    pgrep = _podman("exec", egress_container, "pgrep", "-f", "mitmdump", check=False)
    if pgrep.returncode != 0 or not pgrep.stdout.strip():
        logs = _podman_logs(egress_container)
        pytest.fail(
            f"could not find mitmdump pid.\n"
            f"pgrep stdout:\n{pgrep.stdout}\nstderr:\n{pgrep.stderr}\nlogs:\n{logs}"
        )

    # Walk all matching pids — at least one must be uid 200 with CapBnd=0.
    # (PyInstaller's bootstrap can fork a child briefly; we want the
    # long-running worker.)
    pids = [p for p in pgrep.stdout.split() if p.strip().isdigit()]
    if not pids:
        logs = _podman_logs(egress_container)
        pytest.fail(f"pgrep produced no numeric pids: {pgrep.stdout!r}\nlogs:\n{logs}")

    found_match = False
    last_report = ""
    for pid in pids:
        status = _podman(
            "exec", egress_container,
            "sh", "-c", f'cat /proc/{pid}/status | grep -E "^(Uid|CapBnd):"',
            check=False,
        )
        if status.returncode != 0:
            continue
        uid_line = ""
        capbnd_line = ""
        for line in status.stdout.splitlines():
            if line.startswith("Uid:"):
                uid_line = line
            elif line.startswith("CapBnd:"):
                capbnd_line = line
        uid_parts = uid_line.split()
        capbnd_parts = capbnd_line.split()
        uid_ok = len(uid_parts) >= 2 and uid_parts[1] == "200"
        capbnd_ok = len(capbnd_parts) >= 2 and capbnd_parts[1] == "0000000000000000"
        last_report = (
            f"pid {pid}: Uid line={uid_line!r} (ok={uid_ok}); "
            f"CapBnd line={capbnd_line!r} (ok={capbnd_ok})"
        )
        if uid_ok and capbnd_ok:
            found_match = True
            break

    if not found_match:
        logs = _podman_logs(egress_container)
        pytest.fail(
            f"no mitmdump pid had uid=200 + CapBnd=0.\n"
            f"last checked: {last_report}\nall pids: {pids}\nlogs:\n{logs}"
        )


def test_supervisor_publishes_public_cert_only():
    """CTF F1 (0.22.5): supervisor-egress.sh must publish the *public*
    cert to /home/acproxy/public-certs/ after Step E, so the
    apple-container backend can mount a dir that DOES NOT contain
    mitmproxy-ca.pem (the CA private key) on the cage. Static check on
    the script content — running the cage would be the strongest
    assertion but the script content is the load-bearing piece.
    """
    from pathlib import Path
    repo_root = Path(__file__).resolve().parent.parent
    script = (
        repo_root / "src/agentcage/data/containers/supervisor-egress.sh"
    ).read_text()
    # The install line publishes ONLY the public cert. Asserting on
    # the exact target path keeps a future "let's also copy the .p12"
    # edit from re-leaking the private key.
    assert (
        'install -m 0644 "$CA_PATH" /home/acproxy/public-certs/mitmproxy-ca-cert.pem'
        in script
    ), "supervisor-egress.sh missing the public-cert publish step"
    # Defense-in-depth: no line in the script should copy the CA
    # private key (.p12 or mitmproxy-ca.pem without the -cert suffix)
    # to the public-certs dir.
    for line in script.splitlines():
        if "/home/acproxy/public-certs" not in line:
            continue
        # mitmproxy-ca.pem is the private key; mitmproxy-ca-cert.pem is
        # the public cert. The former must never appear here without
        # the latter substring being the actual target.
        if "mitmproxy-ca.pem" in line and "mitmproxy-ca-cert.pem" not in line:
            raise AssertionError(
                f"supervisor-egress.sh copies the CA *private* key "
                f"into public-certs: {line!r}"
            )
        assert "mitmproxy-ca.p12" not in line, (
            f"supervisor-egress.sh copies CA .p12 into public-certs: "
            f"{line!r}"
        )
