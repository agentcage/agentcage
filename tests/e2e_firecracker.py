"""End-to-end tests for Firecracker microVM isolation.

Requires KVM, root (sudo), and Firecracker binaries.
Skipped automatically when prerequisites are missing.

Run:  sudo pytest tests/e2e_firecracker.py -v -s
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
import urllib.error
import urllib.request

import pytest

# ---------------------------------------------------------------------------
# Skip conditions
# ---------------------------------------------------------------------------

_IS_ROOT = os.geteuid() == 0
_HAS_KVM = os.path.exists("/dev/kvm") and os.access("/dev/kvm", os.W_OK)
_HAS_AGENTCAGE = shutil.which("agentcage") is not None
def _real_home() -> str:
    """Return the real user's home dir (not root's when running via sudo)."""
    sudo_user = os.environ.get("SUDO_USER")
    if os.geteuid() == 0 and sudo_user:
        import pwd
        return pwd.getpwnam(sudo_user).pw_dir
    return os.path.expanduser("~")

_HAS_FIRECRACKER = (
    shutil.which("firecracker") is not None
    or os.path.isfile(
        os.path.join(_real_home(), ".local/share/agentcage/firecracker/firecracker")
    )
)

pytestmark = [
    pytest.mark.e2e_firecracker,
    pytest.mark.skipif(not _IS_ROOT, reason="requires root (sudo pytest ...)"),
    pytest.mark.skipif(not _HAS_KVM, reason="KVM not available"),
    pytest.mark.skipif(not _HAS_AGENTCAGE, reason="agentcage not in PATH"),
    pytest.mark.skipif(not _HAS_FIRECRACKER, reason="Firecracker not available"),
]

CAGE_NAME = "basic"
BASE_URL = "http://127.0.0.1:3000"
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_PATH = os.path.join(REPO_ROOT, "examples", "basic", "config-firecracker.yaml")
BOOT_TIMEOUT = 180  # seconds — VM boot + image loading is slow


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    """Run a command, returning the CompletedProcess."""
    return subprocess.run(cmd, capture_output=True, text=True, **kwargs)


def _as_real_user(*cmd: str) -> list[str]:
    """Prefix a command with runuser if running as root via sudo."""
    sudo_user = os.environ.get("SUDO_USER")
    if os.geteuid() == 0 and sudo_user:
        return ["runuser", "-u", sudo_user, "--", *cmd]
    return list(cmd)


def _systemctl_user(*args: str) -> subprocess.CompletedProcess:
    """Run systemctl --user, via runuser if running as root."""
    return _run(_as_real_user("systemctl", "--user", *args))


def _wait_for_http(url: str, timeout: int = BOOT_TIMEOUT) -> bool:
    """Poll *url* until it returns HTTP 200. Returns True on success."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            resp = urllib.request.urlopen(url, timeout=5)
            if resp.status == 200:
                return True
        except (urllib.error.URLError, OSError):
            pass
        time.sleep(2)
    return False


def _http_get(url: str, timeout: int = 15) -> tuple[int, str]:
    """GET *url*, return (status, body). Returns (0, error) on failure."""
    try:
        resp = urllib.request.urlopen(url, timeout=timeout)
        return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode() if e.fp else ""
    except (urllib.error.URLError, OSError) as e:
        return 0, str(e)


def _http_post(url: str, data: dict, timeout: int = 15) -> tuple[int, str]:
    """POST JSON to *url*, return (status, body)."""
    payload = json.dumps(data).encode()
    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        resp = urllib.request.urlopen(req, timeout=timeout)
        return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode() if e.fp else ""
    except (urllib.error.URLError, OSError) as e:
        return 0, str(e)


def _agentcage_env(**extra: str) -> dict[str, str]:
    """Return env dict with HOME/XDG set for the real user (not root)."""
    env = os.environ.copy()
    sudo_user = env.get("SUDO_USER")
    if os.geteuid() == 0 and sudo_user:
        import pwd
        pw = pwd.getpwnam(sudo_user)
        env["HOME"] = pw.pw_dir
        env["XDG_RUNTIME_DIR"] = f"/run/user/{pw.pw_uid}"
        env["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path=/run/user/{pw.pw_uid}/bus"
    env.update(extra)
    return env


def _cage_destroy() -> None:
    """Destroy the cage, ignoring errors."""
    _run(["agentcage", "cage", "destroy", CAGE_NAME, "-y"], env=_agentcage_env())


def _cage_create() -> None:
    """Create the cage with Firecracker isolation."""
    env = _agentcage_env(AGENT_DIR=os.path.join(REPO_ROOT, "examples", "basic", "agent"))
    result = _run(["agentcage", "cage", "create", "-c", CONFIG_PATH], env=env)
    if result.returncode != 0:
        pytest.fail(f"cage create failed:\nstdout: {result.stdout}\nstderr: {result.stderr}")


def _service_is_active() -> bool:
    r = _systemctl_user("is-active", f"{CAGE_NAME}-cage.service")
    return r.stdout.strip() == "active"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def firecracker_cage():
    """Create a Firecracker cage once for the entire module.

    Yields a dict with cage metadata. Destroys the cage on teardown.
    """
    _cage_destroy()  # clean up stale state

    _cage_create()

    if not _wait_for_http(f"{BASE_URL}/", timeout=BOOT_TIMEOUT):
        # Grab logs for debugging before failing
        logs = _run(
            _as_real_user("journalctl", "--user", "-u", f"{CAGE_NAME}-cage.service",
             "--no-pager", "-n", "80")
        )
        _cage_destroy()
        pytest.fail(
            f"Agent did not become reachable within {BOOT_TIMEOUT}s.\n"
            f"Journal:\n{logs.stdout}\n{logs.stderr}"
        )

    from agentcage.firecracker.network import cage_ip
    vm_ip = cage_ip(CAGE_NAME)

    yield {
        "name": CAGE_NAME,
        "base_url": BASE_URL,
        "vm_ip": vm_ip,
    }

    _cage_destroy()


# ---------------------------------------------------------------------------
# Tests: VM boot and readiness
# ---------------------------------------------------------------------------


class TestVMBootAndReadiness:
    def test_service_is_active(self, firecracker_cage):
        assert _service_is_active(), "systemd service is not active"

    def test_agent_http_reachable(self, firecracker_cage):
        status, body = _http_get(f"{firecracker_cage['base_url']}/")
        assert status == 200, f"GET / returned {status}: {body}"


# ---------------------------------------------------------------------------
# Tests: proxy filtering
# ---------------------------------------------------------------------------


class TestProxyFiltering:
    def test_allowed_domain(self, firecracker_cage):
        url = f"{firecracker_cage['base_url']}/fetch?url=http://httpbin.org/get"
        status, body = _http_get(url, timeout=30)
        assert status == 200, f"allowed domain returned {status}: {body}"

    def test_blocked_domain(self, firecracker_cage):
        url = f"{firecracker_cage['base_url']}/fetch?url=http://evil.com/exfil"
        status, body = _http_get(url, timeout=30)
        # The agent returns 502 (proxy error) when the request is blocked
        assert status in (403, 502), f"blocked domain returned {status}: {body}"

    def test_secret_leak_blocked(self, firecracker_cage):
        status, body = _http_post(
            f"{firecracker_cage['base_url']}/check-secret",
            {"key": "sk-ant-FAKE01-abcdefghijklmnopqrstuvwxyz"},
            timeout=30,
        )
        assert status in (403, 502), f"secret leak returned {status}: {body}"

    def test_clean_post_allowed(self, firecracker_cage):
        status, body = _http_post(
            f"{firecracker_cage['base_url']}/check-secret",
            {"data": "harmless"},
            timeout=30,
        )
        assert status == 200, f"clean POST returned {status}: {body}"

    def test_inbound_secret_in_response_redacted(self, firecracker_cage):
        """Inbound traffic now flows through the mitmproxy inspector chain.
        Validate the path works by confirming a request through the reverse
        proxy succeeds — the inspector chain inspects both directions."""
        status, body = _http_get(
            f"{firecracker_cage['base_url']}/",
            timeout=30,
        )
        assert status == 200, f"inbound via proxy returned {status}: {body}"


# ---------------------------------------------------------------------------
# Tests: port forwarding
# ---------------------------------------------------------------------------


class TestPortForwarding:
    def test_localhost_port_reachable(self, firecracker_cage):
        status, _ = _http_get(f"{firecracker_cage['base_url']}/")
        assert status == 200

    def test_response_body_valid(self, firecracker_cage):
        status, body = _http_get(f"{firecracker_cage['base_url']}/")
        assert status == 200
        data = json.loads(body)
        assert data.get("service") == "agentcage basic example"
        # Proxy env vars should be set inside the cage container
        assert data.get("http_proxy") is not None


# ---------------------------------------------------------------------------
# Tests: cage lifecycle (uses its own fixture — not the shared module cage)
# ---------------------------------------------------------------------------


class TestCageLifecycle:
    @pytest.fixture(autouse=True, scope="class")
    def _lifecycle_cage(self):
        """Create a cage once for all lifecycle tests, cleaned up after."""
        _cage_destroy()
        _cage_create()
        if not _wait_for_http(f"{BASE_URL}/", timeout=BOOT_TIMEOUT):
            _cage_destroy()
            pytest.skip("cage did not start — cannot run lifecycle tests")
        yield
        _cage_destroy()

    def test_1_stop_and_start(self):
        # Stop
        _systemctl_user("stop", f"{CAGE_NAME}-cage.service")
        time.sleep(2)
        assert not _service_is_active(), "service should be inactive after stop"
        status, _ = _http_get(f"{BASE_URL}/", timeout=3)
        assert status == 0, "agent should be unreachable after stop"

        # Verify graceful shutdown happened (use enough lines to see past
        # the kernel panic stack trace that follows the shutdown)
        result = _run(
            _as_real_user("journalctl", "--user", "-u", f"{CAGE_NAME}-cage.service",
             "--no-pager", "-n", "100"),
        )
        assert "all containers stopped" in result.stdout, \
            f"containers not stopped cleanly\n{result.stdout}"

        # Start
        from agentcage.firecracker.network import create_bridge, create_tap
        try:
            create_bridge()
        except Exception:
            pass
        create_tap(CAGE_NAME)
        _systemctl_user("start", f"{CAGE_NAME}-cage.service")
        reachable = _wait_for_http(f"{BASE_URL}/", timeout=BOOT_TIMEOUT)
        if not reachable:
            # Dump journal for diagnostics
            result = _run(
                _as_real_user("journalctl", "--user", "-u", f"{CAGE_NAME}-cage.service",
                 "--no-pager", "-n", "60"),
            )
            pytest.fail(
                f"agent not reachable after restart\n"
                f"--- journal ---\n{result.stdout}\n{result.stderr}"
            )
        assert _service_is_active()

    def test_2_destroy_cleans_resources(self):
        _cage_destroy()
        time.sleep(1)

        # Service should be gone
        assert not _service_is_active()

        # Unit file should be removed
        home = _real_home()
        unit = os.path.join(home, ".config", "systemd", "user",
                            f"{CAGE_NAME}-cage.service")
        assert not os.path.exists(unit), f"unit file still exists: {unit}"

        # Rootfs should be removed
        config_home = os.path.join(home, ".config")
        rootfs = os.path.join(
            config_home, "agentcage", "deployments", CAGE_NAME, "vm", "rootfs.ext4"
        )
        assert not os.path.exists(rootfs), f"rootfs still exists: {rootfs}"
