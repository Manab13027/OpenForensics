"""
ADB Auto-installer
==================
On first run, checks whether 'adb' is on PATH.
If missing, attempts to install it automatically using the
platform's native package manager, then falls back to a
direct download of the official Android Platform Tools zip.

Supported platforms:
  macOS   : Homebrew  →  brew install android-platform-tools
  Ubuntu  : APT       →  apt-get install adb
  Windows : Downloads platform-tools zip from Google and
            extracts it next to this script, then updates PATH.
"""

import io
import os
import platform
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path
from tkinter import messagebox


# ── Official Google download URLs ──────────────────────────────────────────
_PLATFORM_TOOLS_URLS = {
    "Darwin":  "https://dl.google.com/android/repository/platform-tools-latest-darwin.zip",
    "Linux":   "https://dl.google.com/android/repository/platform-tools-latest-linux.zip",
    "Windows": "https://dl.google.com/android/repository/platform-tools-latest-windows.zip",
}

_INSTALL_DIR = Path(__file__).parent / "platform-tools"


def _add_known_adb_paths():
    """Add well-known ADB locations to PATH so shutil.which can find it."""
    candidates = [
        # Local platform-tools downloaded by this app
        Path(__file__).parent / "platform-tools",
        # Homebrew (Apple Silicon and Intel)
        Path("/opt/homebrew/bin"),
        Path("/usr/local/bin"),
        # Android Studio default SDK locations
        Path.home() / "Library/Android/sdk/platform-tools",
        Path.home() / "Android/Sdk/platform-tools",
        Path("C:/Users") / os.environ.get("USERNAME", "") / "AppData/Local/Android/Sdk/platform-tools",
    ]
    extra = [str(p) for p in candidates if p.exists() and str(p) not in os.environ.get("PATH", "")]
    if extra:
        os.environ["PATH"] = os.pathsep.join(extra) + os.pathsep + os.environ.get("PATH", "")


def adb_on_path() -> bool:
    _add_known_adb_paths()
    return shutil.which("adb") is not None


def adb_path() -> str:
    """Return the full path to the adb binary, or 'adb' if on PATH."""
    _add_known_adb_paths()
    found = shutil.which("adb")
    return found or "adb"


def _run(cmd, timeout=120) -> tuple:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout + p.stderr
    except Exception as e:
        return -1, str(e)


# ── macOS via Homebrew ──────────────────────────────────────────────────────

def _install_mac(log) -> bool:
    brew = shutil.which("brew")
    if not brew:
        log("Homebrew not found — falling back to direct download …")
        return False
    log("Installing android-platform-tools via Homebrew …")
    rc, out = _run(["brew", "install", "android-platform-tools"], timeout=300)
    log(out[:400])
    return rc == 0 and adb_on_path()


# ── Ubuntu/Debian via APT ───────────────────────────────────────────────────

def _install_linux(log) -> bool:
    apt = shutil.which("apt-get") or shutil.which("apt")
    if not apt:
        log("APT not found — falling back to direct download …")
        return False
    log("Installing adb via apt-get (may ask for sudo password) …")
    rc, out = _run(["sudo", apt, "install", "-y", "adb"], timeout=120)
    log(out[:400])
    return rc == 0 and adb_on_path()


# ── All platforms: direct zip download ─────────────────────────────────────

def _install_via_download(log) -> bool:
    url = _PLATFORM_TOOLS_URLS.get(platform.system())
    if not url:
        log("No download URL for this platform.")
        return False

    try:
        import urllib.request
        log(f"Downloading platform-tools from Google …")
        log(f"  {url}")

        with urllib.request.urlopen(url, timeout=120) as resp:  # nosec
            data = resp.read()

        log(f"Downloaded {len(data):,} bytes — extracting …")
        _INSTALL_DIR.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            zf.extractall(_INSTALL_DIR.parent)

        # The zip always extracts to a folder named 'platform-tools'
        extracted = _INSTALL_DIR.parent / "platform-tools"
        adb_bin = extracted / ("adb.exe" if platform.system() == "Windows" else "adb")
        if not adb_bin.exists():
            log("Extraction succeeded but adb binary not found.")
            return False

        # Make executable on Unix
        if platform.system() != "Windows":
            adb_bin.chmod(0o755)

        # Add to PATH for this session
        os.environ["PATH"] = str(extracted) + os.pathsep + os.environ.get("PATH", "")
        log(f"ADB installed at: {adb_bin}")
        log("PATH updated for this session.")
        return adb_on_path()

    except Exception as e:
        log(f"Download failed: {e}")
        return False


# ── Public entry point ──────────────────────────────────────────────────────

def ensure_adb(log=print, ask_user=True) -> bool:
    """
    Check for ADB; install if missing.
    log      : callable(str) for progress messages
    ask_user : if True, show a messagebox asking permission before installing
    Returns True if ADB is available after the call.
    """
    if adb_on_path():
        return True

    if ask_user:
        answer = messagebox.askyesno(
            "ADB not found",
            "Android Debug Bridge (ADB) is required for Android scanning.\n\n"
            "Would you like OpenForensics to install it automatically?\n\n"
            "• macOS  : via Homebrew (or direct download)\n"
            "• Ubuntu : via apt-get  (or direct download)\n"
            "• Windows: direct download from Google\n\n"
            "The official Google Platform Tools zip will be downloaded\n"
            "if the package manager method fails.",
        )
        if not answer:
            log("ADB installation skipped by user.")
            return False

    log("ADB not found — starting installation …")
    system = platform.system()

    success = False
    if system == "Darwin":
        success = _install_mac(log) or _install_via_download(log)
    elif system == "Linux":
        success = _install_linux(log) or _install_via_download(log)
    elif system == "Windows":
        success = _install_via_download(log)
    else:
        log(f"Unsupported platform: {system}")

    if success:
        log("ADB installed successfully.")
    else:
        log("ADB installation failed. Install manually: https://developer.android.com/tools/releases/platform-tools")

    return success
