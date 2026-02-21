#!/bin/sh
# agentcage installer — installs agentcage and all prerequisites.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/agentcage/agentcage/master/install.sh | sh
#   curl -fsSL https://raw.githubusercontent.com/agentcage/agentcage/master/install.sh | sh -s -- --with-firecracker
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
# Install: Podman
# ---------------------------------------------------------------------------

install_podman() {
    if has_podman; then
        info "Podman is already installed ($(podman --version))"
        return
    fi

    info "Installing Podman..."
    case "$DISTRO" in
        arch)     run_pkg pacman -S --noconfirm --needed podman ;;
        debian)   run_pkg apt-get update -qq && run_pkg apt-get install -y -qq podman ;;
        fedora)   run_pkg dnf install -y -q podman ;;
        rhel)     run_pkg dnf install -y -q podman ;;
        opensuse) run_pkg zypper install -y podman ;;
        macos)    brew install podman ;;
    esac

    if ! has_podman; then
        err "Podman installation failed"
    fi
    info "Podman installed ($(podman --version))"
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
# macOS: Podman machine
# ---------------------------------------------------------------------------

setup_podman_machine() {
    if [ "$OS" != "macos" ]; then
        return
    fi

    # Check if any machine exists
    if ! podman machine list --format '{{.Name}}' 2>/dev/null | grep -q .; then
        info "Initializing Podman machine..."
        podman machine init
        podman machine start
    elif ! podman machine list --format '{{.Running}}' 2>/dev/null | grep -qi true; then
        info "Starting Podman machine..."
        podman machine start
    else
        info "Podman machine is already running"
    fi
}

# ---------------------------------------------------------------------------
# Firecracker
# ---------------------------------------------------------------------------

setup_firecracker() {
    if [ "$WANT_FIRECRACKER" = false ]; then
        return
    fi

    if [ "$OS" = "macos" ]; then
        err "Firecracker mode requires Linux with /dev/kvm (not supported on macOS)"
    fi

    if [ ! -e /dev/kvm ]; then
        msg="Firecracker requires /dev/kvm but it was not found."
        if [ "$IS_WSL" = true ]; then
            msg="$msg
  WSL2 requires nestedVirtualization=true in your .wslconfig:
    [wsl2]
    nestedVirtualization=true
  Then restart WSL: wsl --shutdown"
        else
            msg="$msg
  Ensure KVM is enabled in BIOS and the kvm kernel module is loaded:
    sudo modprobe kvm_intel  # or kvm_amd"
        fi
        err "$msg"
    fi

    info "Setting up Firecracker (via agentcage firecracker setup)..."
    agentcage_bin="$(command -v agentcage)"
    sudo "$agentcage_bin" firecracker setup
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

parse_args() {
    WANT_FIRECRACKER=false

    while [ $# -gt 0 ]; do
        case "$1" in
            --with-firecracker)
                WANT_FIRECRACKER=true
                shift
                ;;
            --help|-h)
                cat <<'HELP'
agentcage installer

Installs agentcage and all prerequisites (Podman, Python 3.12+, uv).

Usage:
  curl -fsSL https://raw.githubusercontent.com/agentcage/agentcage/master/install.sh | sh
  curl -fsSL ... | sh -s -- --with-firecracker

Options:
  --with-firecracker  Also set up Firecracker (requires Linux + /dev/kvm)
  --help, -h          Show this help message
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
        if ! command -v brew >/dev/null 2>&1; then
            err "Homebrew is required on macOS. Install it from https://brew.sh"
        fi
        info "Detected macOS with Homebrew"
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
    setup_firecracker

    # --- Success message ---
    info ""
    info "agentcage is ready!"
    info ""
    info "Get started:"
    info "  agentcage --help"
    info "  agentcage init my-agent          # scaffold a new config"
    info ""
    info "Docs: https://github.com/agentcage/agentcage"

    if [ "$IS_WSL" = true ]; then
        info ""
        info "Note: Podman uses the WSL2 Linux kernel for containers."
    fi

    if [ "$WANT_FIRECRACKER" = true ]; then
        info ""
        info "Firecracker is set up. Use 'isolation: firecracker' in config.yaml."
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
