#!/usr/bin/env bash
# ============================================================
#  OpenForensics — Ubuntu / Debian Startup Script
#  Installs Python 3 + tkinter if missing, then launches app
# ============================================================

set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

GREEN='\033[0;32m'
AMBER='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m'

info()  { echo -e "${GREEN}[OpenForensics]${NC} $*"; }
warn()  { echo -e "${AMBER}[WARNING]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

echo ""
echo "  ██████  ██████  ███████ ███    ██ ███████  ██████  ██████  ███████ "
echo " ██    ██ ██   ██ ██      ████   ██ ██      ██    ██ ██   ██ ██      "
echo " ██    ██ ██████  █████   ██ ██  ██ █████   ██    ██ ██████  ███████ "
echo " ██    ██ ██      ██      ██  ██ ██ ██      ██    ██ ██   ██      ██ "
echo "  ██████  ██      ███████ ██   ████ ██       ██████  ██   ██ ███████ "
echo ""
echo "  Educational Digital Forensics Tool  |  Ubuntu / Debian"
echo "  ────────────────────────────────────────────────────────"
echo ""

# ── 1. Detect distro ─────────────────────────────────────────────────────
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    info "Distro: $NAME ${VERSION:-}"
fi

# ── 2. Check for sudo / apt ───────────────────────────────────────────────
if ! command -v apt-get &>/dev/null; then
    warn "apt-get not found. This script targets Ubuntu/Debian."
    warn "For RPM-based distros (Fedora/CentOS), install python3 and python3-tkinter via dnf/yum."
fi

# ── 3. Check / install Python 3.8+ ───────────────────────────────────────
PYTHON=""
for cmd in python3.12 python3.11 python3.10 python3.9 python3.8 python3; do
    if command -v "$cmd" &>/dev/null; then
        VER=$("$cmd" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
        MAJOR=${VER%%.*}
        MINOR=${VER##*.}
        if [[ $MAJOR -ge 3 && $MINOR -ge 8 ]]; then
            PYTHON="$cmd"
            break
        fi
    fi
done

if [[ -z "$PYTHON" ]]; then
    warn "Python 3.8+ not found. Installing …"
    if command -v apt-get &>/dev/null; then
        sudo apt-get update -qq
        sudo apt-get install -y python3 python3-tk
        PYTHON=python3
    else
        error "Cannot install Python automatically on this distro.\nPlease install python3 and python3-tk manually."
    fi
    info "Python installed: $($PYTHON --version)"
else
    info "Found Python: $($PYTHON --version)"
fi

# ── 4. Check / install tkinter ───────────────────────────────────────────
if ! "$PYTHON" -c "import tkinter" &>/dev/null; then
    warn "tkinter missing — installing python3-tk …"
    if command -v apt-get &>/dev/null; then
        # Match the exact python version for the tk package
        PY_VER=$("$PYTHON" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
        sudo apt-get install -y "python${PY_VER}-tk" 2>/dev/null || \
        sudo apt-get install -y python3-tk || \
        error "Could not install tkinter. Run: sudo apt-get install python3-tk"
    fi
fi
info "tkinter OK"

# ── 5. Check / install ADB ───────────────────────────────────────────────
if ! command -v adb &>/dev/null; then
    warn "ADB not found — installing android-tools-adb …"
    if command -v apt-get &>/dev/null; then
        sudo apt-get install -y android-tools-adb 2>/dev/null || true
    fi
    if command -v adb &>/dev/null; then
        info "ADB installed: $(adb version | head -1)"
    else
        warn "ADB install failed. The app will offer to download it on first launch."
    fi
else
    info "ADB: $(adb version | head -1)"
fi

# ── 6. udev rules for Android (so non-root user can use ADB) ─────────────
UDEV_FILE="/etc/udev/rules.d/51-android.rules"
if ! [[ -f "$UDEV_FILE" ]]; then
    warn "Android udev rules not found (needed for ADB over USB without sudo)"
    read -rp "  Install udev rules now? [y/N] " ans
    if [[ "${ans,,}" == "y" ]]; then
        sudo tee "$UDEV_FILE" > /dev/null <<'UDEV'
# Android USB devices — allows non-root ADB access
SUBSYSTEM=="usb", ATTR{idVendor}=="18d1", MODE="0666", GROUP="plugdev"  # Google
SUBSYSTEM=="usb", ATTR{idVendor}=="04e8", MODE="0666", GROUP="plugdev"  # Samsung
SUBSYSTEM=="usb", ATTR{idVendor}=="22b8", MODE="0666", GROUP="plugdev"  # Motorola
SUBSYSTEM=="usb", ATTR{idVendor}=="0bb4", MODE="0666", GROUP="plugdev"  # HTC
SUBSYSTEM=="usb", ATTR{idVendor}=="12d1", MODE="0666", GROUP="plugdev"  # Huawei
SUBSYSTEM=="usb", ATTR{idVendor}=="1004", MODE="0666", GROUP="plugdev"  # LG
SUBSYSTEM=="usb", ATTR{idVendor}=="2916", MODE="0666", GROUP="plugdev"  # Lava / Generic
SUBSYSTEM=="usb", ATTR{idVendor}=="*",    MODE="0666", GROUP="plugdev"  # All others
UDEV
        sudo chmod a+r "$UDEV_FILE"
        sudo udevadm control --reload-rules 2>/dev/null || true
        sudo udevadm trigger 2>/dev/null || true
        # Add current user to plugdev group
        sudo usermod -aG plugdev "$USER" 2>/dev/null || true
        info "udev rules installed. You may need to log out and back in for group changes to take effect."
    fi
fi

# ── 7. Check display (headless detection) ────────────────────────────────
if [[ -z "${DISPLAY:-}" ]] && [[ -z "${WAYLAND_DISPLAY:-}" ]]; then
    warn "No display detected (\$DISPLAY and \$WAYLAND_DISPLAY are unset)."
    warn "If running over SSH, use: ssh -X user@host  or  ssh -Y user@host"
    warn "Or run: export DISPLAY=:0  if you are on the local machine."
fi

# ── 8. Launch ────────────────────────────────────────────────────────────
echo ""
info "Launching OpenForensics …"
exec "$PYTHON" "$DIR/main.py"
