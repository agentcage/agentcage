#!/bin/sh
# agentcage installer — installs agentcage and all prerequisites.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/agentcage/agentcage/master/install.sh | sh
#   curl -fsSL https://raw.githubusercontent.com/agentcage/agentcage/master/install.sh | sh -s -- --with-lima
#
# POSIX sh compatible. No bashisms.

set -eu

# Save original PATH before we modify it, for the end-of-script PATH check
_ORIG_PATH="$PATH"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

info() {
    printf '[+] %s\n' "$*"
}

warn() {
    printf '[!] %s\n' "$*"
}

err() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

need_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        err "need '$1' (command not found)"
    fi
}

# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------

detect_os() {
    case "$(uname -s)" in
        Linux)  OS=linux ;;
        Darwin) OS=macos ;;
        *)      err "unsupported operating system: $(uname -s)" ;;
    esac

    IS_WSL=false
    if [ "$OS" = "linux" ] && [ -f /proc/version ]; then
        if grep -qi microsoft /proc/version 2>/dev/null; then
            IS_WSL=true
        fi
    fi

    # macOS 26+ Apple Silicon → apple-container is the default isolation
    # (Lima becomes optional). Detect both axes once here.
    APPLE_SILICON=false
    MACOS_MAJOR=0
    if [ "$OS" = "macos" ]; then
        [ "$(uname -m)" = "arm64" ] && APPLE_SILICON=true
        # sw_vers prints e.g. "26.3.2"
        MACOS_MAJOR=$(sw_vers -productVersion 2>/dev/null | cut -d. -f1)
        : "${MACOS_MAJOR:=0}"
    fi
}

detect_distro() {
    if [ "$OS" = "macos" ]; then
        DISTRO=macos
        return
    fi

    DISTRO=unknown
    if [ -f /etc/os-release ]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        case "$ID" in
            arch|archarm)           DISTRO=arch ;;
            debian|ubuntu|pop|mint|elementary|zorin|kali|raspbian)
                                    DISTRO=debian ;;
            fedora)                 DISTRO=fedora ;;
            rhel|centos|rocky|alma|ol)
                                    DISTRO=rhel ;;
            opensuse*|sles)         DISTRO=opensuse ;;
            *)
                # Fall back to ID_LIKE
                case "${ID_LIKE:-}" in
                    *arch*)         DISTRO=arch ;;
                    *debian*|*ubuntu*)
                                    DISTRO=debian ;;
                    *fedora*)       DISTRO=fedora ;;
                    *rhel*|*centos*)
                                    DISTRO=rhel ;;
                    *suse*)         DISTRO=opensuse ;;
                esac
                ;;
        esac
    fi

    if [ "$DISTRO" = "unknown" ]; then
        err "unsupported Linux distribution (could not parse /etc/os-release)"
    fi
}

# ---------------------------------------------------------------------------
# Sudo handling
# ---------------------------------------------------------------------------

setup_sudo() {
    SUDO=""
    if [ "$(id -u)" -eq 0 ]; then
        SUDO=""
    elif command -v sudo >/dev/null 2>&1; then
        SUDO="sudo"
    elif command -v doas >/dev/null 2>&1; then
        SUDO="doas"
    else
        err "need root privileges to install system packages (no sudo or doas found)"
    fi
}

run_pkg() {
    if [ -n "$SUDO" ]; then
        $SUDO "$@"
    else
        "$@"
    fi
}

# ---------------------------------------------------------------------------
# Version checks
# ---------------------------------------------------------------------------

has_podman() {
    command -v podman >/dev/null 2>&1
}

# The release asset's target triple for this machine.
#
# Linux is built against musl and linked statically — the workspace has
# no C dependencies, so that costs nothing and removes the glibc version
# coupling that decides whether a binary built on CI runs on the
# operator's distro.
detect_target() {
    arch=$(uname -m)
    case "$OS:$arch" in
        linux:x86_64|linux:amd64)   TARGET=x86_64-unknown-linux-musl ;;
        linux:aarch64|linux:arm64)  TARGET=aarch64-unknown-linux-musl ;;
        macos:arm64)                TARGET=aarch64-apple-darwin ;;
        macos:x86_64)               TARGET=x86_64-apple-darwin ;;
        *) err "no agentcage binary for $OS/$arch — build from source: https://github.com/agentcage/agentcage#building" ;;
    esac
}

# sha256 of a file, on either platform. Linux has sha256sum, macOS has
# shasum; neither has both.
sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | cut -d' ' -f1
    else
        err "need 'sha256sum' or 'shasum' to verify the download"
    fi
}

has_agentcage() {
    command -v agentcage >/dev/null 2>&1
}

# ---------------------------------------------------------------------------
# Install: Homebrew (macOS only)
# ---------------------------------------------------------------------------

install_homebrew() {
    # Homebrew may already be installed but not yet on PATH (common right
    # after a fresh install, or in a non-login shell). Pick it up first.
    if ! command -v brew >/dev/null 2>&1; then
        if [ -x /opt/homebrew/bin/brew ]; then
            eval "$(/opt/homebrew/bin/brew shellenv)"
        elif [ -x /usr/local/bin/brew ]; then
            eval "$(/usr/local/bin/brew shellenv)"
        fi
    fi

    if command -v brew >/dev/null 2>&1; then
        info "Homebrew is already installed"
        return
    fi

    info "Homebrew not found — installing it (required on macOS)..."
    need_cmd curl

    # The Homebrew installer is run with NONINTERACTIVE=1 below so it does not
    # block on prompts when this script is piped from curl. A side effect of
    # that mode: Homebrew probes for sudo with `sudo -n` and will NOT prompt
    # for a password — so on a genuinely fresh Mac with no cached sudo
    # credentials it aborts with "Need sudo access on macOS" even though the
    # user is an administrator. Prime the sudo credential cache here, with a
    # single prompt, so Homebrew's non-interactive probe succeeds.
    if ! sudo -n true 2>/dev/null; then
        info "Homebrew needs administrator access — you may be prompted for your password."
        if ! sudo -v; then
            err "could not obtain sudo access, which Homebrew requires. Run 'sudo -v' in this terminal and re-run the installer, or install Homebrew manually from https://brew.sh"
        fi
    fi

    NONINTERACTIVE=1 /bin/bash -c \
        "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

    # Put brew on PATH for the rest of this script (Apple Silicon, then Intel).
    if [ -x /opt/homebrew/bin/brew ]; then
        eval "$(/opt/homebrew/bin/brew shellenv)"
    elif [ -x /usr/local/bin/brew ]; then
        eval "$(/usr/local/bin/brew shellenv)"
    fi

    if ! command -v brew >/dev/null 2>&1; then
        err "Homebrew installation failed. Install it manually from https://brew.sh and re-run."
    fi
    info "Homebrew installed"
}

# ---------------------------------------------------------------------------
# Install: Podman
# ---------------------------------------------------------------------------

install_podman() {
    # On macOS, Podman is optional (only needed for 'agentcage secret set').
    # VM mode runs Podman inside the Lima VM instead.
    if [ "$OS" = "macos" ]; then
        if has_podman; then
            info "Podman is already installed ($(podman --version)) — optional on macOS"
        else
            info "Skipping Podman on macOS (optional — only needed for 'agentcage secret set')"
        fi
        return
    fi

    if has_podman; then
        info "Podman is already installed ($(podman --version))"
    else
        info "Installing Podman..."
        case "$DISTRO" in
            arch)     run_pkg pacman -S --noconfirm --needed podman ;;
            debian)   run_pkg apt-get update -qq && run_pkg apt-get install -y -qq podman ;;
            fedora)   run_pkg dnf install -y -q podman ;;
            rhel)     run_pkg dnf install -y -q podman ;;
            opensuse) run_pkg zypper install -y podman ;;
        esac

        if ! has_podman; then
            err "Podman installation failed"
        fi
        info "Podman installed ($(podman --version))"
    fi

    # skopeo is used by 'cage update' to resolve latest image tags
    if command -v skopeo >/dev/null 2>&1; then
        info "skopeo is already installed"
    else
        info "Installing skopeo..."
        case "$DISTRO" in
            arch)     run_pkg pacman -S --noconfirm --needed skopeo ;;
            debian)   run_pkg apt-get install -y -qq skopeo ;;
            fedora)   run_pkg dnf install -y -q skopeo ;;
            rhel)     run_pkg dnf install -y -q skopeo ;;
            opensuse) run_pkg zypper install -y skopeo ;;
        esac

        if command -v skopeo >/dev/null 2>&1; then
            info "skopeo installed"
        else
            warn "skopeo installation failed (image version pinning will be unavailable)"
        fi
    fi
}

# ---------------------------------------------------------------------------
# Install: agentcage
# ---------------------------------------------------------------------------
#
# agentcage is a single static binary. There is no interpreter and no
# package manager in this path: the host CLI stopped being Python at the
# Rust cutover, and the only Python left in the product ships inside the
# egress container image, where the image installs it.

AGENTCAGE_REPO="${AGENTCAGE_REPO:-agentcage/agentcage}"

# The version to install: $AGENTCAGE_VERSION, or the latest release.
#
# Resolved through the redirect on /releases/latest rather than the JSON
# API, because the API is rate-limited per IP (60/hour unauthenticated)
# and a shared NAT or a CI runner reaches that without trying.
resolve_version() {
    if [ -n "${AGENTCAGE_VERSION:-}" ]; then
        VERSION="${AGENTCAGE_VERSION#v}"
        return
    fi
    info "Resolving the latest release..."
    location=$(curl -fsSLI -o /dev/null -w '%{url_effective}' \
        "https://github.com/$AGENTCAGE_REPO/releases/latest" 2>/dev/null) \
        || err "could not reach github.com to resolve the latest release"
    VERSION="${location##*/tag/v}"
    case "$VERSION" in
        "$location"|"") err "could not parse a version out of '$location'" ;;
    esac
}

install_agentcage() {
    need_cmd curl
    need_cmd tar
    detect_target
    resolve_version

    bindir="${AGENTCAGE_BIN_DIR:-$HOME/.local/bin}"
    asset="agentcage-$VERSION-$TARGET.tar.gz"
    # Overridable for a private mirror, an air-gapped install, or a test
    # against a local directory (curl reads file:// too). Resolving
    # "latest" needs github, so a custom base also needs
    # $AGENTCAGE_VERSION.
    base="${AGENTCAGE_DOWNLOAD_BASE:-https://github.com/$AGENTCAGE_REPO/releases/download/v$VERSION}"

    tmp=$(mktemp -d)
    # `trap ... 0` rather than EXIT: POSIX sh, and the script may not
    # reach the end.
    trap 'rm -rf "$tmp"' 0

    info "Downloading agentcage $VERSION ($TARGET)..."
    curl -fsSL -o "$tmp/$asset" "$base/$asset" \
        || err "download failed: $base/$asset"

    # The checksum is published beside the tarball and is not optional.
    # A truncated or tampered download that still untars would otherwise
    # install a binary nobody built.
    curl -fsSL -o "$tmp/$asset.sha256" "$base/$asset.sha256" \
        || err "no checksum published for $asset — refusing to install unverified"
    expected=$(cut -d' ' -f1 < "$tmp/$asset.sha256")
    actual=$(sha256_of "$tmp/$asset")
    if [ "$expected" != "$actual" ]; then
        err "checksum mismatch for $asset
  expected: $expected
  actual:   $actual
This is either a corrupted download or a tampered release. Not installing."
    fi
    info "Checksum verified"

    tar -C "$tmp" -xzf "$tmp/$asset" \
        || err "could not unpack $asset"
    unpacked="$tmp/agentcage-$VERSION-$TARGET/agentcage"
    [ -f "$unpacked" ] || err "$asset does not contain an agentcage binary"

    mkdir -p "$bindir"
    # Install by rename, so a running agentcage is never a half-written
    # file: the rename is atomic within one filesystem, and $tmp is
    # moved into place rather than copied over the target.
    cp "$unpacked" "$bindir/.agentcage.new"
    chmod 755 "$bindir/.agentcage.new"
    mv -f "$bindir/.agentcage.new" "$bindir/agentcage"

    export PATH="$bindir:$PATH"
    if ! has_agentcage; then
        err "agentcage was installed to $bindir but is not on PATH"
    fi
    info "agentcage installed to $bindir ($("$bindir/agentcage" --version))"
}

# ---------------------------------------------------------------------------
# macOS: Podman machine (not needed — VM mode uses Lima instead)
# ---------------------------------------------------------------------------

setup_podman_machine() {
    # No-op: macOS uses Lima for VM isolation, not Podman machine.
    return
}

# ---------------------------------------------------------------------------
# Apple `container` (macOS 26+ Apple Silicon, default isolation on that host)
# ---------------------------------------------------------------------------

has_apple_container() {
    command -v container >/dev/null 2>&1 \
        || [ -x /usr/local/bin/container ] \
        || [ -x /opt/homebrew/bin/container ]
}

install_apple_container() {
    # Only macOS 26+ on Apple Silicon. Earlier macOS or Intel falls through
    # to install_lima below.
    if [ "$OS" != "macos" ] || [ "$APPLE_SILICON" = false ]; then
        return
    fi
    if [ "$MACOS_MAJOR" -lt 26 ] 2>/dev/null; then
        return
    fi

    if has_apple_container; then
        info "Apple 'container' is already installed ($(container --version 2>/dev/null | head -1))"
    else
        info "Installing Apple 'container' (macOS 26+ Apple Silicon default isolation)..."
        need_cmd curl
        # Latest release .pkg URL from the apple/container GitHub releases API.
        PKG_URL=$(curl -fsSL https://api.github.com/repos/apple/container/releases/latest \
                  | grep -oE 'https://github.com/apple/container/releases/download/[^"]+\.pkg' \
                  | head -1)
        if [ -z "$PKG_URL" ]; then
            warn "could not resolve apple/container latest release URL — install manually from https://github.com/apple/container/releases"
            warn "apple-container isolation will not be available; falling back to Lima."
            WANT_LIMA=true
            return
        fi
        PKG_FILE=$(basename "$PKG_URL")
        TMPDIR_PKG=$(mktemp -d)
        info "Downloading $PKG_FILE ..."
        if ! curl -fsSL -o "$TMPDIR_PKG/$PKG_FILE" "$PKG_URL"; then
            warn "download failed; falling back to Lima."
            WANT_LIMA=true
            return
        fi
        # The pkg installer needs admin rights.
        if ! sudo -n true 2>/dev/null; then
            info "Apple 'container' install needs administrator access — you may be prompted for your password."
            sudo -v || { warn "sudo unavailable; falling back to Lima."; WANT_LIMA=true; return; }
        fi
        sudo installer -pkg "$TMPDIR_PKG/$PKG_FILE" -target /
        rm -rf "$TMPDIR_PKG"
        # /usr/local/bin is not always on PATH for the calling shell.
        if ! has_apple_container; then
            warn "container CLI not on PATH; check /usr/local/bin/container"
            WANT_LIMA=true
            return
        fi
        info "Apple 'container' installed"
    fi

    # Start the apiserver + install the recommended Linux kernel.
    # `container system start --enable-kernel-install` is idempotent:
    # - apiserver already up + kernel installed -> fast no-op
    # - apiserver down + kernel installed       -> starts apiserver
    # - no kernel                                -> downloads + installs + starts
    # We used to gate this on a `container system status | grep -q running`
    # check, but the *stopped* state prints "apiserver is **not running**
    # and not registered with launchd" which matches the literal "running"
    # token and made the conditional take the wrong branch on every fresh
    # install (#131). The check was never worth its own complexity given
    # the start command is already idempotent — just always call it.
    CONTAINER_BIN=$(command -v container 2>/dev/null || echo /usr/local/bin/container)
    info "Ensuring Apple 'container' apiserver is running (one-time kernel install on first run)..."
    "$CONTAINER_BIN" system start --enable-kernel-install >/dev/null 2>&1 || \
        warn "container system start failed; run 'container system start --enable-kernel-install' manually before using apple-container isolation"
}

# ---------------------------------------------------------------------------
# Lima (optional, for VM isolation mode)
# ---------------------------------------------------------------------------

install_lima() {
    # On macOS, Lima used to be required (only isolation option). Starting
    # in 0.20 the default on macOS 26+ Apple Silicon is apple-container,
    # which makes Lima OPTIONAL on that platform. Older macOS, Intel Macs,
    # and macOS 26 hosts where Apple's container CLI failed to install
    # still need Lima.
    if [ "$OS" = "macos" ]; then
        if [ "$APPLE_SILICON" = true ] && [ "$MACOS_MAJOR" -ge 26 ] 2>/dev/null \
           && has_apple_container; then
            # apple-container handles macOS isolation; only install Lima
            # if the user explicitly asked for it via --with-lima.
            :
        else
            WANT_LIMA=true
        fi
    fi

    if [ "$WANT_LIMA" = false ]; then
        return
    fi

    if command -v limactl >/dev/null 2>&1; then
        info "Lima is already installed ($(limactl --version 2>/dev/null || echo 'unknown version'))"
        return
    fi

    info "Installing Lima..."
    case "$DISTRO" in
        arch)     run_pkg pacman -S --noconfirm --needed lima ;;
        debian)   run_pkg apt-get install -y -qq lima ;;
        fedora)   run_pkg dnf install -y -q lima ;;
        rhel)     run_pkg dnf install -y -q lima ;;
        opensuse) run_pkg zypper install -y lima ;;
        macos)    brew install lima ;;
    esac

    if ! command -v limactl >/dev/null 2>&1; then
        warn "Lima installation failed. Install it manually from https://lima-vm.io"
        warn "VM isolation mode will not be available until Lima is installed."
    else
        info "Lima installed"
    fi
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

parse_args() {
    WANT_LIMA=false

    while [ $# -gt 0 ]; do
        case "$1" in
            --with-lima)
                WANT_LIMA=true
                shift
                ;;
            --help|-h)
                cat <<'HELP'
agentcage installer

Installs the agentcage binary and its prerequisite, Podman. agentcage is
a single static executable -- no interpreter, no package manager, no
virtualenv. The download's published sha256 is verified before anything
is installed.

On macOS 26+ Apple Silicon also installs Apple's 'container' CLI (the
default isolation backend on that platform). On older macOS / Intel Macs
falls back to installing Lima (the only isolation option there).

Usage:
  curl -fsSL https://raw.githubusercontent.com/agentcage/agentcage/master/install.sh | sh
  curl -fsSL ... | sh -s -- --with-lima

Options:
  --with-lima   Also install Lima (required for isolation: vm mode).
                Auto-set on macOS hosts where apple-container is unavailable.
  --help, -h    Show this help message

Environment:
  AGENTCAGE_VERSION   Install this version instead of the latest release.
  AGENTCAGE_BIN_DIR   Where to put the binary (default: ~/.local/bin).
  AGENTCAGE_REPO      Source repository (default: agentcage/agentcage).
  AGENTCAGE_DOWNLOAD_BASE
                      Where the release assets live, for a private
                      mirror or an air-gapped install. Needs
                      AGENTCAGE_VERSION too, since resolving
                      'latest' still asks github.
HELP
                exit 0
                ;;
            *)
                err "unknown option: $1 (use --help for usage)"
                ;;
        esac
    done
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
    parse_args "$@"

    info "agentcage installer"
    info ""

    detect_os
    detect_distro

    if [ "$OS" = "macos" ]; then
        info "Detected macOS"
        install_homebrew
    elif [ "$IS_WSL" = true ]; then
        info "Detected Linux ($DISTRO) under WSL2"
    else
        info "Detected Linux ($DISTRO)"
    fi

    # System packages need sudo (except on macOS where brew runs as user)
    if [ "$OS" != "macos" ]; then
        setup_sudo
    fi

    install_podman
    install_agentcage

    setup_podman_machine
    install_apple_container
    install_lima

    # --- Success message ---
    info ""
    info "agentcage is ready!"
    info ""
    info "Get started:"
    info "  agentcage init my-cage             # scaffold a new config"
    info "  agentcage init --list-scaffolds     # show available scaffolds"
    info "  agentcage --help"
    info ""
    info "Docs: https://github.com/agentcage/agentcage"

    if [ "$IS_WSL" = true ]; then
        info ""
        info "Note: Podman uses the WSL2 Linux kernel for containers."
    fi

    if [ "$OS" = "macos" ] && [ "$APPLE_SILICON" = true ] \
       && [ "$MACOS_MAJOR" -ge 26 ] 2>/dev/null && has_apple_container; then
        info ""
        info "macOS isolation default: apple-container (Apple 'container' microVM per cage)."
        info "Set 'isolation: vm' in cage.yaml to force Lima instead."
    elif [ "$WANT_LIMA" = true ]; then
        info ""
        if [ "$OS" = "macos" ]; then
            info "Lima is set up. On this macOS host, all cages use VM isolation (Lima)."
        else
            info "Lima is set up. Use 'isolation: vm' in cage.yaml for VM-level isolation."
        fi
    fi

    # Check if agentcage is on PATH for future shells (use original PATH,
    # not the one we modified during installation)
    agentcage_path="$(command -v agentcage 2>/dev/null)" || true
    case "$agentcage_path" in
        "$HOME"/.local/bin/*)
            if ! echo "$_ORIG_PATH" | tr ':' '\n' | grep -qx "$HOME/.local/bin" 2>/dev/null; then
                info ""
                info "To use agentcage, restart your shell or run:"
                info "  source \"\$HOME/.local/bin/env\"    # for sh/bash/zsh"
            fi
            ;;
    esac
}

main "$@"
