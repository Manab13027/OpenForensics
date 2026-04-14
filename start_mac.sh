#!/usr/bin/env bash
# ============================================================
#  OpenForensics — macOS Startup Script
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
echo "  Educational Digital Forensics Tool  |  macOS"
echo "  ─────────────────────────────────────────────"
echo ""

# ── 1. Check macOS version ────────────────────────────────────────────────
MACOS_VER=$(sw_vers -productVersion)
info "macOS $MACOS_VER detected"

# ── 2. Check / install Python 3.8+ ───────────────────────────────────────
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
    warn "Python 3.8+ not found. Installing via Homebrew …"

    # Install Homebrew if missing
    if ! command -v brew &>/dev/null; then
        info "Installing Homebrew …"
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
        # Add Homebrew to PATH for Apple Silicon
        if [[ -f /opt/homebrew/bin/brew ]]; then
            eval "$(/opt/homebrew/bin/brew shellenv)"
        fi
    fi

    brew install python@3.12
    PYTHON=$(brew --prefix python@3.12)/bin/python3.12
    info "Python installed: $($PYTHON --version)"
else
    info "Found Python: $($PYTHON --version)"
fi

# ── 3. Check tkinter ─────────────────────────────────────────────────────
if ! "$PYTHON" -c "import tkinter" &>/dev/null; then
    warn "tkinter not found. Attempting fix …"
    # On macOS, tkinter requires Tcl/Tk — install via Homebrew
    if command -v brew &>/dev/null; then
        brew install python-tk 2>/dev/null || brew install tcl-tk 2>/dev/null || true
    fi
    # Try python.org installer as fallback guidance
    if ! "$PYTHON" -c "import tkinter" &>/dev/null; then
        error "tkinter still missing.\nPlease install Python from https://www.python.org/downloads/macos/\n(The official installer includes tkinter / Tcl-Tk automatically)"
    fi
fi
info "tkinter OK"

# ── 4. Check / grant Full Disk Access hint ───────────────────────────────
info "Tip: For Safari history, grant Full Disk Access to Terminal:"
info "     System Settings → Privacy & Security → Full Disk Access → add Terminal"
echo ""

# ── 5. Launch ────────────────────────────────────────────────────────────
info "Launching OpenForensics …"
exec "$PYTHON" "$DIR/main.py"
