"""Auto-download Firecracker binary from GitHub releases."""

from __future__ import annotations

import hashlib
import os
import platform
import stat
import tarfile

_FIRECRACKER_VERSION = "v1.14.1"

_URL_TEMPLATE = (
    "https://github.com/firecracker-microvm/firecracker/releases/download/"
    "{version}/firecracker-{version}-{arch}.tgz"
)

# SHA-256 checksums from official .sha256.txt files on the GitHub release
_TARBALL_SHA256 = {
    "x86_64": "ea66dc1fbdb2473bbb95a1e822ae7884cd575a891a8f801258723258d36b7c7c",
    "aarch64": "65a39256b9dd741e20c3a3fe5055cb38e5159049b5ede2015604951521000a04",
}


def default_firecracker_path() -> str:
    """Return the default Firecracker binary path under XDG_DATA_HOME."""
    data_home = os.environ.get(
        "XDG_DATA_HOME", os.path.expanduser("~/.local/share")
    )
    return os.path.join(
        data_home, "agentcage", "firecracker",
        f"firecracker-{_FIRECRACKER_VERSION}",
    )


def firecracker_tarball_url() -> str:
    """Return the GitHub release tarball URL for the current architecture."""
    arch = platform.machine()
    if arch not in ("x86_64", "aarch64"):
        raise RuntimeError(
            f"unsupported architecture for Firecracker binary: {arch}"
        )
    return _URL_TEMPLATE.format(version=_FIRECRACKER_VERSION, arch=arch)


def ensure_firecracker(path: str | None = None) -> str:
    """Ensure the Firecracker binary exists at *path*, downloading if needed.

    Downloads the release tarball, extracts just the firecracker binary,
    and makes it executable.  Returns the resolved path.
    """
    if path is None:
        path = default_firecracker_path()

    if os.path.isfile(path) and os.access(path, os.X_OK):
        return path

    from agentcage.firecracker.kernel import download_with_progress

    url = firecracker_tarball_url()
    os.makedirs(os.path.dirname(path), exist_ok=True)

    tarball = path + ".tgz"
    tmp = path + ".tmp"
    try:
        download_with_progress(url, tarball)

        # Verify tarball integrity
        arch = platform.machine()
        expected = _TARBALL_SHA256.get(arch)
        if expected:
            actual = hashlib.sha256(open(tarball, "rb").read()).hexdigest()
            if actual != expected:
                raise RuntimeError(
                    f"Firecracker tarball checksum mismatch: "
                    f"expected {expected}, got {actual}"
                )

        # Tarball contains: release-v1.14.1-{arch}/firecracker-v1.14.1-{arch}
        member_name = (
            f"release-{_FIRECRACKER_VERSION}-{arch}/"
            f"firecracker-{_FIRECRACKER_VERSION}-{arch}"
        )
        with tarfile.open(tarball) as tf:
            member = tf.getmember(member_name)
            with tf.extractfile(member) as src, open(tmp, "wb") as dst:
                while True:
                    chunk = src.read(256 * 1024)
                    if not chunk:
                        break
                    dst.write(chunk)

        os.chmod(tmp, os.stat(tmp).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        os.rename(tmp, path)
    except BaseException:
        for f in (tmp, tarball):
            try:
                os.unlink(f)
            except OSError:
                pass
        raise
    else:
        try:
            os.unlink(tarball)
        except OSError:
            pass

    return path
