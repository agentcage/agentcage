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

# Check for Python >= 3.12 and set PYTHON_BIN
has_python() {
    for py in python3.13 python3.12 python3; do
        if command -v "$py" >/dev/null 2>&1; then
            ver=$("$py" -c 'import sys; print("{}.{}".format(sys.version_info.major, sys.version_info.minor))' 2>/dev/null) || continue
            major=$(echo "$ver" | cut -d. -f1)
            minor=$(echo "$ver" | cut -d. -f2)
            if [ "$major" -ge 3 ] && [ "$minor" -ge 12 ]; then
                PYTHON_BIN="$py"
                return 0
            fi
        fi
    done
    return 1
}

has_uv() {
    command -v uv >/dev/null 2>&1
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
# Install: Python
# ---------------------------------------------------------------------------

install_python() {
    if has_python; then
        info "Python >= 3.12 found ($PYTHON_BIN)"
        return
    fi

    info "Installing Python..."
    case "$DISTRO" in
        arch)     run_pkg pacman -S --noconfirm --needed python ;;
        debian)   run_pkg apt-get update -qq && run_pkg apt-get install -y -qq python3 ;;
        fedora)   run_pkg dnf install -y -q python3 ;;
        rhel)
            # Try python3.12 package first (EPEL/AppStream), fall back to python3
            if ! run_pkg dnf install -y -q python3.12 2>/dev/null; then
                run_pkg dnf install -y -q python3
            fi
            ;;
        opensuse)
            if ! run_pkg zypper install -y python312 2>/dev/null; then
                run_pkg zypper install -y python3
            fi
            ;;
        macos)    brew install python ;;
    esac

    if ! has_python; then
        err "Python >= 3.12 installation failed (installed version may be too old)"
    fi
    info "Python >= 3.12 installed ($PYTHON_BIN)"
}

# ---------------------------------------------------------------------------
# Install: uv
# ---------------------------------------------------------------------------

install_uv() {
    if has_uv; then
        info "uv is already installed ($(uv --version))"
        return
    fi

    info "Installing uv..."
    installed_via_pkg=false

    case "$DISTRO" in
        arch)
            run_pkg pacman -S --noconfirm --needed uv
            installed_via_pkg=true
            ;;
        fedora)
            if run_pkg dnf install -y -q uv 2>/dev/null; then
                installed_via_pkg=true
            fi
            ;;
        macos)
            brew install uv
            installed_via_pkg=true
            ;;
    esac

    if [ "$installed_via_pkg" = false ] || ! has_uv; then
        info "Installing uv via official installer..."
        need_cmd curl
        curl -LsSf https://astral.sh/uv/install.sh | sh
        # Add common install locations to PATH for this session
        export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"
    fi

    if ! has_uv; then
        err "uv installation failed"
    fi
    info "uv installed ($(uv --version))"
}

# ---------------------------------------------------------------------------
# Install: agentcage
# ---------------------------------------------------------------------------

install_agentcage() {
    if has_agentcage; then
        info "agentcage is already installed, upgrading..."
        uv tool install --upgrade agentcage
    else
        info "Installing agentcage..."
        uv tool install agentcage
    fi

    # Ensure uv tool bin dir is on PATH for this session
    if [ -d "$HOME/.local/bin" ]; then
        export PATH="$HOME/.local/bin:$PATH"
    fi

    if ! has_agentcage; then
        err "agentcage installation failed"
    fi
    info "agentcage installed ($(agentcage --version))"
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

    # Start the apiserver + install the recommended Linux kernel. Both are
    # idempotent (--enable-kernel-install skips re-install if the kernel
    # symlink already exists).
    CONTAINER_BIN=$(command -v container 2>/dev/null || echo /usr/local/bin/container)
    if "$CONTAINER_BIN" system status 2>/dev/null | grep -q running; then
        info "Apple 'container' apiserver already running"
    else
        info "Starting Apple 'container' apiserver (one-time, installs Kata kernel)..."
        "$CONTAINER_BIN" system start --enable-kernel-install >/dev/null 2>&1 || \
            warn "container system start failed; run it manually before using apple-container isolation"
    fi
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

Installs agentcage and all prerequisites (Podman, Python 3.12+, uv).

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
    install_python
    install_uv
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
