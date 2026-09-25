#!/bin/sh
# Verify that every place the agentcage version appears agrees with the
# root VERSION file.
#
# The version is written down once, in VERSION. Everything else derives
# from it: pyproject declares it `dynamic` and hatchling reads the file,
# the Cargo workspace carries a copy that the Rust crates inherit, the
# CHANGELOG heading is matched against it, and a release tag has to name
# it. This script is the thing that notices when one of those drifts.
#
# It is deliberately POSIX sh with no dependencies -- not pytest, not
# Python -- so it runs in the Release workflow before anything is built
# or installed, and so it keeps working unchanged once the CLI is Rust
# and there is no Python toolchain on the host to lean on.
#
# Usage:
#   scripts/check-version.sh              # check VERSION vs pyproject, Cargo + CHANGELOG
#   scripts/check-version.sh v0.40.1      # ... and require the tag to match
#
# In GitHub Actions the tag is picked up from GITHUB_REF_NAME on a tag
# push, so the workflow needs no argument.

set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
fail=0

err() {
    echo "check-version: $*" >&2
    fail=1
}

# ── 1. VERSION itself ────────────────────────────────────────
version_file="$root/VERSION"
if [ ! -f "$version_file" ]; then
    err "missing $version_file"
    exit 1
fi

lines=$(wc -l < "$version_file" | tr -d ' ')
if [ "$lines" != "1" ]; then
    err "VERSION must be exactly one line ending in a newline (got $lines)"
fi

version=$(head -n 1 "$version_file" | tr -d ' \t\r')
if [ -z "$version" ]; then
    err "VERSION is empty"
    exit 1
fi

# Same shape PyPI and `git tag` both accept. Pre-release suffixes are
# allowed (0.41.0rc1) because uv build will happily produce one.
if ! echo "$version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+([.-]?(a|b|rc|alpha|beta|dev)[0-9]+)?$'; then
    err "VERSION '$version' is not a valid semantic version"
fi

# ── 2. pyproject must NOT carry its own copy ─────────────────
# A static `version = "..."` under [project] would be a second source of
# truth that silently wins over VERSION.
if awk '/^\[project\]/{p=1;next} /^\[/{p=0} p && /^version[[:space:]]*=/{found=1} END{exit !found}' \
        "$root/pyproject.toml"; then
    err "pyproject.toml [project] sets a static version; it must declare dynamic = [\"version\"] and let hatchling read VERSION"
fi

if ! grep -q 'path = "VERSION"' "$root/pyproject.toml"; then
    err "pyproject.toml does not point [tool.hatch.version] at the VERSION file"
fi

# ── 3. Cargo workspace ───────────────────────────────────────
# Cargo cannot read a version out of a file, so the root Cargo.toml
# carries a copy of VERSION under [workspace.package] and the member
# crates inherit it with `version.workspace = true`. That copy is the
# number `agentcage --version` prints once the CLI is Rust, and it is
# also the egress image tag and the quadlet Image= pin -- so it drifting
# is not cosmetic. This is the guard that makes the copy safe.
cargo_toml="$root/Cargo.toml"
if [ -f "$cargo_toml" ]; then
    cargo_version=$(awk '
        /^\[workspace\.package\]/ { p = 1; next }
        /^\[/                       { p = 0 }
        p && /^version[[:space:]]*=/ {
            sub(/^version[[:space:]]*=[[:space:]]*/, "")
            gsub(/["\r]/, "")
            sub(/[[:space:]]*(#.*)?$/, "")
            print
            exit
        }
    ' "$cargo_toml")

    if [ -z "$cargo_version" ]; then
        err "Cargo.toml has no [workspace.package] version"
    elif [ "$cargo_version" != "$version" ]; then
        err "Cargo.toml [workspace.package] version is '$cargo_version' but VERSION is '$version'"
    fi

    # A member crate with its own `version = "..."` would silently win
    # over the workspace copy for that crate alone -- the binary would
    # report one number while the image tag used another.
    for member in "$root"/rust/*/Cargo.toml; do
        [ -f "$member" ] || continue
        if awk '
            /^\[package\]/              { p = 1; next }
            /^\[/                       { p = 0 }
            p && /^version[[:space:]]*=[[:space:]]*"/ { found = 1 }
            END { exit !found }
        ' "$member"; then
            err "${member#"$root"/} sets a static version; it must use version.workspace = true"
        fi
        if ! grep -q '^version\.workspace[[:space:]]*=[[:space:]]*true' "$member"; then
            err "${member#"$root"/} does not inherit version.workspace = true"
        fi
    done
fi

# ── 4. CHANGELOG ─────────────────────────────────────────────
# publish.yml pulls the release body out of the `## [VERSION]` section,
# so a missing or misnamed heading ships a release with no notes. Check
# the newest released heading, skipping an [Unreleased] section if one
# is open.
changelog="$root/CHANGELOG.md"
newest=$(grep -E '^## \[' "$changelog" \
         | grep -v -i '^## \[Unreleased\]' \
         | head -n 1 \
         | sed -E 's/^## \[([^]]+)\].*/\1/')

if [ -z "$newest" ]; then
    err "CHANGELOG.md has no released '## [x.y.z]' heading"
elif [ "$newest" != "$version" ]; then
    err "CHANGELOG.md's newest release heading is '$newest' but VERSION is '$version'"
fi

# ── 5. Release tag, when there is one ────────────────────────
tag="${1:-}"
if [ -z "$tag" ] && [ "${GITHUB_REF_TYPE:-}" = "tag" ]; then
    tag="${GITHUB_REF_NAME:-}"
fi

if [ -n "$tag" ]; then
    case "$tag" in
        v*) tag_version="${tag#v}" ;;
        *)  err "release tag '$tag' does not start with 'v'"
            tag_version="$tag" ;;
    esac
    if [ "$tag_version" != "$version" ]; then
        err "tag '$tag' does not match VERSION '$version'"
    fi
fi

if [ "$fail" -ne 0 ]; then
    exit 1
fi

echo "check-version: ok ($version)"
