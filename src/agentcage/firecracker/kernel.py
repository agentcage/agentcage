"""Auto-download Firecracker kernel binary."""

from __future__ import annotations

import hashlib
import os
import platform
import sys
import urllib.request

_KERNEL_VERSION = "6.1.128"
_FIRECRACKER_CI_VERSION = "v1.12"

_URL_TEMPLATE = (
    "https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/"
    "{ci_version}/{arch}/vmlinux-{kernel_version}"
)

# SHA-256 checksums computed from upstream S3 objects
_KERNEL_SHA256 = {
    "x86_64": "27a8310b9a727517e9eb02044524b6ceb77de5728e3491b6974d5c846227ecc8",
    "aarch64": "cb1291c66bca75bc11cb9c8357fcef9965bb1786dffcb42a60923c3e0e49f319",
}


def default_kernel_path() -> str:
    """Return the default kernel path under XDG_DATA_HOME."""
    data_home = os.environ.get(
        "XDG_DATA_HOME", os.path.expanduser("~/.local/share")
    )
    return os.path.join(
        data_home, "agentcage", "firecracker", f"vmlinux-{_KERNEL_VERSION}"
    )


def kernel_url() -> str:
    """Return the S3 download URL for the current architecture."""
    arch = platform.machine()
    if arch not in ("x86_64", "aarch64"):
        raise RuntimeError(
            f"unsupported architecture for Firecracker kernel: {arch}"
        )
    return _URL_TEMPLATE.format(
        ci_version=_FIRECRACKER_CI_VERSION,
        arch=arch,
        kernel_version=_KERNEL_VERSION,
    )


def download_with_progress(url: str, dest: str) -> None:
    """Download *url* to *dest* with a progress indicator on stderr."""
    resp = urllib.request.urlopen(url)  # noqa: S310
    total = resp.headers.get("Content-Length")
    total = int(total) if total else None

    downloaded = 0
    chunk_size = 256 * 1024  # 256 KiB

    with open(dest, "wb") as f:
        while True:
            chunk = resp.read(chunk_size)
            if not chunk:
                break
            f.write(chunk)
            downloaded += len(chunk)
            if total:
                pct = downloaded * 100 // total
                mb = downloaded / (1024 * 1024)
                total_mb = total / (1024 * 1024)
                sys.stderr.write(
                    f"\r  downloading kernel: {mb:.1f}/{total_mb:.1f} MB ({pct}%)"
                )
            else:
                mb = downloaded / (1024 * 1024)
                sys.stderr.write(f"\r  downloading kernel: {mb:.1f} MB")
            sys.stderr.flush()

    sys.stderr.write("\n")
    sys.stderr.flush()


def ensure_kernel(path: str | None = None) -> str:
    """Ensure the kernel binary exists at *path*, downloading if needed.

    Returns the resolved path.
    """
    if path is None:
        path = default_kernel_path()

    if os.path.isfile(path):
        return path

    url = kernel_url()
    os.makedirs(os.path.dirname(path), exist_ok=True)

    tmp = path + ".tmp"
    try:
        download_with_progress(url, tmp)

        # Verify kernel integrity
        arch = platform.machine()
        expected = _KERNEL_SHA256.get(arch)
        if expected:
            actual = hashlib.sha256(open(tmp, "rb").read()).hexdigest()
            if actual != expected:
                raise RuntimeError(
                    f"Kernel checksum mismatch: "
                    f"expected {expected}, got {actual}"
                )

        os.rename(tmp, path)
    except BaseException:
        # Clean up partial download
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise

    return path
