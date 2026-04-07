#!/usr/bin/env python3
"""Check for dependency updates across the agentcage project.

Usage:
    ./scripts/update-deps.py              # check all, report only
    ./scripts/update-deps.py --update     # check all, apply updates
    ./scripts/update-deps.py containers   # check only container images
    ./scripts/update-deps.py containers   # check only container images

Categories: python, containers, pip
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.request

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

ALL_CATEGORIES = ("python", "containers", "pip")

# ── Helpers ──────────────────────────────────────────────────────────────────


def _json_get(url: str) -> dict:
    """Fetch a URL and return parsed JSON."""
    req = urllib.request.Request(url)
    req.add_header("User-Agent", "agentcage-update-deps/1.0")
    with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
        return json.loads(resp.read())



def _print_status(
    category: str, name: str, current: str, latest: str, extra: str = ""
):
    print(f"\n[{category}] {name}")
    print(f"  current: {current}")
    print(f"  latest:  {latest}")
    if extra:
        print(f"  {extra}")


# ── Python (uv.lock) ────────────────────────────────────────────────────────


def check_python(update: bool) -> tuple[int, int]:
    """Check/update uv.lock. Returns (updates_available, up_to_date)."""
    print("\n[python] uv.lock")

    r = subprocess.run(
        ["uv", "lock", "--check"],
        capture_output=True, text=True, cwd=REPO_ROOT,
    )
    if r.returncode == 0:
        # Lock is fresh; check for upgradeable packages
        r2 = subprocess.run(
            ["uv", "lock", "--upgrade", "--dry-run"],
            capture_output=True, text=True, cwd=REPO_ROOT,
        )
        if "Updated" in r2.stderr or "Updated" in r2.stdout:
            output = r2.stderr + r2.stdout
            updates = [
                ln.strip() for ln in output.splitlines() if "Updated" in ln
            ]
            summary = "; ".join(updates[:5])
            if len(updates) > 5:
                summary += f"; ... and {len(updates) - 5} more"
            print(f"  current: locked (fresh)")
            print(f"  latest:  updates available ({summary})")
            if update:
                subprocess.run(
                    ["uv", "lock", "--upgrade"],
                    cwd=REPO_ROOT, check=True,
                )
                print("  -> updated uv.lock")
            else:
                print("  -> run with --update to apply")
            return (1, 0)
        else:
            print("  current: locked (fresh)")
            print("  latest:  up to date")
            return (0, 1)
    else:
        print("  current: lock is stale")
        print("  latest:  needs refresh")
        if update:
            subprocess.run(["uv", "lock", "--upgrade"], cwd=REPO_ROOT, check=True)
            print("  -> updated uv.lock")
        else:
            print("  -> run with --update to apply")
        return (1, 0)


# ── Containers ───────────────────────────────────────────────────────────────


def _skopeo_inspect_digest(image_ref: str) -> str | None:
    """Run skopeo inspect and return the digest."""
    r = subprocess.run(
        ["skopeo", "inspect", f"docker://{image_ref}"],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        print(f"  error: skopeo inspect failed for {image_ref}: {r.stderr.strip()}")
        return None
    data = json.loads(r.stdout)
    return data.get("Digest", "")



def _check_digest_pinned(
    containerfile: str, update: bool
) -> tuple[int, int]:
    """Check a Containerfile with # update-from: comment + digest pin."""
    path = os.path.join(REPO_ROOT, containerfile)
    content = open(path).read()
    name = os.path.basename(containerfile)

    # Find update-from comment
    m_comment = re.search(r"^# update-from:\s*(.+)$", content, re.MULTILINE)
    if not m_comment:
        print(f"\n[containers] {name}")
        print(f"  skipped: no # update-from: comment found")
        return (0, 0)

    source_ref = m_comment.group(1).strip()

    # Find current digest
    m_from = re.search(r"^FROM\s+(\S+)@(sha256:[0-9a-f]+)", content, re.MULTILINE)
    if not m_from:
        print(f"\n[containers] {name}")
        print(f"  skipped: no digest-pinned FROM found")
        return (0, 0)

    image_base = m_from.group(1)
    current_digest = m_from.group(2)

    # Get latest digest
    latest_digest = _skopeo_inspect_digest(source_ref)
    if latest_digest is None:
        return (0, 0)

    short_current = current_digest[:20] + "..."
    short_latest = latest_digest[:20] + "..."

    if latest_digest == current_digest:
        _print_status("containers", f"{name}", short_current, f"{short_latest} (up to date)")
        return (0, 1)
    else:
        _print_status("containers", f"{name}", short_current, short_latest)
        if update:
            new_content = content.replace(
                f"{image_base}@{current_digest}",
                f"{image_base}@{latest_digest}",
            )
            with open(path, "w") as f:
                f.write(new_content)
            print(f"  -> updated digest in {name}")
        else:
            print(f"  -> update available")
        return (1, 0)



def check_containers(update: bool) -> tuple[int, int]:
    """Check all container image pins. Returns (updates, up_to_date)."""
    total_updates = 0
    total_current = 0

    for cf in (
        "src/agentcage/data/containers/Containerfile.proxy",
        "src/agentcage/data/containers/Containerfile.dns",
        "src/agentcage/data/containers/Containerfile.helper",
        "src/agentcage/data/containers/Containerfile.nested",
    ):
        u, c = _check_digest_pinned(cf, update)
        total_updates += u
        total_current += c

    return (total_updates, total_current)


# ── pip (pyyaml in Containerfile.proxy) ──────────────────────────────────────


def check_pip(update: bool) -> tuple[int, int]:
    """Check pip package versions in Containerfiles. Returns (updates, up_to_date)."""
    containerfile = os.path.join(
        REPO_ROOT, "src/agentcage/data/containers/Containerfile.proxy"
    )
    content = open(containerfile).read()

    m = re.search(r"pyyaml==([\d.]+)", content, re.IGNORECASE)
    if not m:
        print("\n[pip] pyyaml (Containerfile.proxy)")
        print("  error: could not parse pyyaml version")
        return (0, 0)

    current = m.group(1)

    try:
        data = _json_get("https://pypi.org/pypi/pyyaml/json")
        latest = data.get("info", {}).get("version", "")
    except Exception as e:
        print("\n[pip] pyyaml (Containerfile.proxy)")
        print(f"  error: PyPI request failed: {e}")
        return (0, 0)

    if latest == current:
        _print_status("pip", "pyyaml (Containerfile.proxy)", current, f"{latest} (up to date)")
        return (0, 1)

    _print_status("pip", "pyyaml (Containerfile.proxy)", current, latest)

    if update:
        new_content = re.sub(
            r"pyyaml==[\d.]+",
            f"pyyaml=={latest}",
            content,
            flags=re.IGNORECASE,
        )
        with open(containerfile, "w") as f:
            f.write(new_content)
        print(f"  -> updated pyyaml to {latest} in Containerfile.proxy")
    else:
        print(f"  -> update available")

    return (1, 0)


# ── Main ─────────────────────────────────────────────────────────────────────

CHECKERS = {
    "python": check_python,
    "containers": check_containers,
    "pip": check_pip,
}


def main():
    parser = argparse.ArgumentParser(
        description="Check for dependency updates across the agentcage project.",
    )
    parser.add_argument(
        "categories",
        nargs="*",
        choices=list(ALL_CATEGORIES),
        metavar="CATEGORY",
        help=f"categories to check ({', '.join(ALL_CATEGORIES)}); omit for all",
    )
    parser.add_argument(
        "--update",
        action="store_true",
        help="apply updates in-place (default: report only)",
    )
    args = parser.parse_args()

    categories = args.categories or list(ALL_CATEGORIES)

    print("Checking dependencies...")

    total_updates = 0
    total_current = 0
    errors = 0

    for cat in categories:
        checker = CHECKERS[cat]
        try:
            u, c = checker(args.update)
            total_updates += u
            total_current += c
        except Exception as e:
            print(f"\n[{cat}] error: {e}")
            errors += 1

    # Summary
    parts = []
    if total_updates:
        parts.append(f"{total_updates} update{'s' if total_updates != 1 else ''} available")
    if total_current:
        parts.append(f"{total_current} up to date")
    if errors:
        parts.append(f"{errors} error{'s' if errors != 1 else ''}")

    print(f"\nSummary: {', '.join(parts)}")

    return 1 if total_updates > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
