"""
Deleted / Uninstalled Application Detector
===========================================
Finds evidence of applications that were previously installed but have since
been removed.  Works differently per platform:

  macOS   : /var/log/install.log  (OS installer events)
            ~/.Trash              (deleted .app bundles still in Trash)
            Spotlight quarantine remnants
  Windows : MuiCache registry     (every GUI exe ever launched, survives uninstall)
            UserAssist registry   (ROT13-encoded paths of run apps)
            Prefetch directory    (executed program names, survives uninstall)
            Event log 11707/11724 (MSI install/uninstall events)
  Linux   : /var/log/dpkg.log     (remove / purge actions)
            /var/log/apt/history.log (apt Remove: lines)
            /var/log/dnf.log / yum.log (rpm-based distros)
  Android : dumpsys package history (some vendors log deletions)
  iPhone  : parsed separately from iphone.py; hook provided here

All sources return dicts with keys:
  name, version, removed_date, install_date, reason, source, platform
"""

import codecs
import os
import platform
import re
import subprocess
from datetime import datetime
from pathlib import Path


# ═══════════════════════════════════════════════════════════════════════════ #
#  Helpers
# ═══════════════════════════════════════════════════════════════════════════ #

def _fmt(dt_str: str) -> str:
    """Normalise a date string to YYYY-MM-DD HH:MM:SS where possible."""
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%b %d %H:%M:%S",
                "%d/%m/%Y %H:%M:%S", "%Y/%m/%d %H:%M:%S"):
        try:
            return datetime.strptime(dt_str.strip(), fmt).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            pass
    return dt_str.strip()


def _make(name, version="", removed_date="", install_date="",
          reason="", source="", plat=""):
    return {
        "name":         name,
        "version":      version,
        "removed_date": removed_date,
        "install_date": install_date,
        "reason":       reason,
        "source":       source,
        "platform":     plat or platform.system(),
    }


# ═══════════════════════════════════════════════════════════════════════════ #
#  macOS
# ═══════════════════════════════════════════════════════════════════════════ #

def _mac_install_log() -> list:
    """Parse /var/log/install.log for removal/uninstall events."""
    results = []
    log = Path("/var/log/install.log")
    if not log.exists():
        return results

    # Patterns that indicate a real app removal (not just log noise)
    # Example real lines:
    #   PackageKit: ----- Uninstalling com.adobe.Reader (version 9.4.6) -----
    #   PackageKit: Removing receipt for com.apple.pkg.Safari
    #   installd: Uninstalling /Applications/Foo.app
    SIGNAL_PATTERNS = [
        re.compile(r"installd.*[Uu]ninstall.*?(/Applications/[^\s]+\.app)", re.I),
        re.compile(r"PackageKit.*[Uu]ninstall.*?(com\.[^\s,)]+)", re.I),
        re.compile(r"PackageKit.*[Rr]emoving receipt.*?(com\.[^\s,)]+)", re.I),
        re.compile(r"PackageKit.*[Rr]emoving.+?:\s+(.+?)\s*$", re.I),
        re.compile(r"-{3,}\s*[Uu]ninstalling\s+(.+?)\s*-{3,}", re.I),
    ]

    try:
        with open(log, "r", errors="ignore") as f:
            for line in f:
                for pat in SIGNAL_PATTERNS:
                    m = pat.search(line)
                    if m:
                        raw_name = m.group(1).strip(".,;:()")
                        # Use last path component if it's a path
                        name = Path(raw_name).stem if "/" in raw_name else raw_name
                        if not name or len(name) < 3:
                            continue
                        # Date from line prefix (format: YYYY-MM-DD HH:MM:SS...)
                        date_m = re.match(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", line)
                        date_str = date_m.group(1) if date_m else ""
                        results.append(_make(
                            name=name,
                            removed_date=date_str,
                            source="/var/log/install.log",
                            reason="Found in install.log removal/uninstall event",
                            plat="macOS",
                        ))
                        break  # only one match per line
    except PermissionError:
        results.append(_make(
            name="⚠ /var/log/install.log — Permission denied",
            source="/var/log/install.log",
            reason="Run with sudo or grant Full Disk Access to Terminal",
            plat="macOS",
        ))
    except Exception:
        pass
    return results


def _mac_trash() -> list:
    """Find deleted .app bundles still sitting in ~/.Trash."""
    results = []
    trash = Path.home() / ".Trash"
    if not trash.exists():
        return results
    try:
        for item in trash.glob("*.app"):
            try:
                stat = item.stat()
                removed = datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                removed = ""
            results.append(_make(
                name=item.stem,
                removed_date=removed,
                source=str(trash),
                reason=".app bundle found in Trash",
                plat="macOS",
            ))
    except Exception:
        pass
    return results


def _mac_spotlight_remnants() -> list:
    """
    Use mdfind to look for apps whose Spotlight metadata still exists
    but whose bundle path no longer exists on disk.
    This catches recently deleted apps whose index hasn't been purged yet.
    """
    results = []
    try:
        proc = subprocess.run(
            ["mdfind", "kMDItemContentType == 'com.apple.application-bundle'"],
            capture_output=True, text=True, timeout=20,
        )
        if proc.returncode != 0:
            return results
        for path in proc.stdout.splitlines():
            p = Path(path.strip())
            if path and not p.exists():
                results.append(_make(
                    name=p.stem,
                    removed_date="",
                    source="Spotlight index (stale entry)",
                    reason="Spotlight still knows about this app but it no longer exists on disk",
                    plat="macOS",
                ))
    except Exception:
        pass
    return results


# ═══════════════════════════════════════════════════════════════════════════ #
#  Windows
# ═══════════════════════════════════════════════════════════════════════════ #

def _windows_muicache() -> list:
    """
    MuiCache stores the display name of every GUI executable ever launched,
    even after the app is uninstalled.  Cross-reference with installed apps
    to find entries that are no longer installed.
    """
    results = []
    try:
        import winreg
        key_path = (r"Software\Classes\Local Settings\Software"
                    r"\Microsoft\Windows\Shell\MuiCache")
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path)
        count = winreg.QueryInfoKey(key)[1]  # number of values
        for i in range(count):
            try:
                vname, vdata, _ = winreg.EnumValue(key, i)
                # vname is the exe path, vdata is the friendly name
                if vname.endswith(".FriendlyAppName") and not vname.startswith("@"):
                    exe_path = vname.replace(".FriendlyAppName", "")
                    if not Path(exe_path).exists():
                        results.append(_make(
                            name=vdata or Path(exe_path).stem,
                            removed_date="",
                            install_date="",
                            source="Registry MuiCache",
                            reason=f"Exe no longer present: {exe_path}",
                            plat="Windows",
                        ))
            except Exception:
                pass
    except Exception:
        pass
    return results


def _windows_userassist() -> list:
    """
    UserAssist tracks every GUI app launched via Explorer.
    Keys are ROT13-encoded; decoding reveals the exe path.
    """
    results = []
    try:
        import winreg
        base = (r"Software\Microsoft\Windows\CurrentVersion"
                r"\Explorer\UserAssist")
        root = winreg.OpenKey(winreg.HKEY_CURRENT_USER, base)
        for i in range(winreg.QueryInfoKey(root)[0]):
            try:
                guid = winreg.EnumKey(root, i)
                count_key = winreg.OpenKey(root, f"{guid}\\Count")
                for j in range(winreg.QueryInfoKey(count_key)[1]):
                    try:
                        vname, _, _ = winreg.EnumValue(count_key, j)
                        decoded = codecs.decode(vname, "rot_13")
                        if decoded.lower().endswith(".exe"):
                            exe_path = decoded.split("\\")[-1]
                            if not Path(decoded).exists():
                                results.append(_make(
                                    name=Path(decoded).stem,
                                    removed_date="",
                                    source="Registry UserAssist",
                                    reason=f"Previously launched, now missing: {decoded}",
                                    plat="Windows",
                                ))
                    except Exception:
                        pass
            except Exception:
                pass
    except Exception:
        pass
    return results


def _windows_prefetch() -> list:
    """
    Prefetch files survive app uninstallation.
    Their existence proves the app was executed on this machine.
    """
    results = []
    prefetch = Path("C:/Windows/Prefetch")
    if not prefetch.exists():
        return results
    # Build set of running executables to exclude
    running = set()
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                             r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")
        for i in range(winreg.QueryInfoKey(key)[0]):
            try:
                sub = winreg.OpenKey(key, winreg.EnumKey(key, i))
                loc, _ = winreg.QueryValueEx(sub, "InstallLocation")
                running.add(loc.lower())
            except Exception:
                pass
    except Exception:
        pass

    try:
        for pf in prefetch.glob("*.pf"):
            # Prefetch name: APPNAME-HASH.pf
            app_name = pf.stem.rsplit("-", 1)[0]
            stat = pf.stat()
            last_run = datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
            results.append(_make(
                name=app_name,
                removed_date="",
                install_date="",
                source="Windows Prefetch",
                reason=f"Was executed on this machine (last seen {last_run})",
                plat="Windows",
            ))
    except Exception:
        pass
    return results


def _windows_event_log() -> list:
    """Parse Windows Event Log for MSI uninstall events (ID 11724)."""
    results = []
    try:
        proc = subprocess.run(
            ["wevtutil", "qe", "Application",
             "/q:*[System[EventID=11724]]",
             "/f:text", "/c:200"],
            capture_output=True, text=True, timeout=20,
        )
        if proc.returncode != 0:
            return results
        current_date = ""
        for line in proc.stdout.splitlines():
            line = line.strip()
            if line.startswith("Date:"):
                current_date = line.split("Date:")[-1].strip()
            elif "successfully removed" in line.lower() or "uninstalled" in line.lower():
                name = line.strip()
                results.append(_make(
                    name=name,
                    removed_date=current_date,
                    source="Windows Event Log (ID 11724)",
                    reason="MSI uninstall event",
                    plat="Windows",
                ))
    except Exception:
        pass
    return results


# ═══════════════════════════════════════════════════════════════════════════ #
#  Linux
# ═══════════════════════════════════════════════════════════════════════════ #

def _linux_dpkg_removed() -> list:
    """Extract 'remove' and 'purge' entries from /var/log/dpkg.log*"""
    results = []
    logs = sorted(Path("/var/log").glob("dpkg.log*"), reverse=True)
    for log in logs:
        try:
            opener = __import__("gzip").open if log.suffix == ".gz" else open
            with opener(log, "rt", errors="ignore") as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 4 and parts[2] in ("remove", "purge"):
                        pkg = parts[3].split(":")[0]
                        results.append(_make(
                            name=pkg,
                            version=parts[4] if len(parts) > 4 else "",
                            removed_date=f"{parts[0]} {parts[1]}",
                            source=str(log),
                            reason=f"dpkg action: {parts[2]}",
                            plat="Linux",
                        ))
        except Exception:
            pass
    return results


def _linux_apt_history() -> list:
    """Parse /var/log/apt/history.log for Remove: entries."""
    results = []
    logs = sorted(Path("/var/log/apt").glob("history.log*"), reverse=True) \
        if Path("/var/log/apt").exists() else []
    for log in logs:
        try:
            opener = __import__("gzip").open if log.suffix == ".gz" else open
            with opener(log, "rt", errors="ignore") as f:
                content = f.read()
            # Each transaction block starts with Start-Date:
            blocks = re.split(r"(?=Start-Date:)", content)
            for block in blocks:
                if "Remove:" not in block and "Purge:" not in block:
                    continue
                date_m = re.search(r"Start-Date:\s*(.+)", block)
                date_str = date_m.group(1).strip() if date_m else ""
                cmd_m = re.search(r"Commandline:\s*(.+)", block)
                reason = cmd_m.group(1).strip() if cmd_m else "apt remove/purge"
                for key in ("Remove:", "Purge:"):
                    pkg_m = re.search(rf"{key}\s*(.+?)(?:\n[A-Z]|\Z)", block, re.S)
                    if not pkg_m:
                        continue
                    for entry in pkg_m.group(1).split(","):
                        entry = entry.strip()
                        if not entry:
                            continue
                        pkg_name = entry.split(":")[0].strip()
                        ver_m = re.search(r"\((.+?)\)", entry)
                        version = ver_m.group(1) if ver_m else ""
                        results.append(_make(
                            name=pkg_name,
                            version=version,
                            removed_date=date_str,
                            source=str(log),
                            reason=reason,
                            plat="Linux",
                        ))
        except Exception:
            pass
    return results


def _linux_dnf_removed() -> list:
    """Parse dnf.log / yum.log for Erase/Remove operations."""
    results = []
    for log_path in ["/var/log/dnf.log", "/var/log/yum.log"]:
        p = Path(log_path)
        if not p.exists():
            continue
        try:
            with open(p, "r", errors="ignore") as f:
                for line in f:
                    low = line.lower()
                    if "erased" in low or "removed" in low:
                        parts = line.strip().split()
                        if len(parts) >= 3:
                            results.append(_make(
                                name=parts[-1],
                                removed_date=" ".join(parts[:2]),
                                source=log_path,
                                reason="dnf/yum erase/remove",
                                plat="Linux",
                            ))
        except Exception:
            pass
    return results


# ═══════════════════════════════════════════════════════════════════════════ #
#  Android (ADB) — called from android.py results
# ═══════════════════════════════════════════════════════════════════════════ #

def android_deleted_from_adb(serial=None) -> list:
    """
    Try to find deleted app evidence on a connected Android device.
    dumpsys package on some vendors logs 'deleted packages'.
    """
    results = []
    cmd = ["adb"] + (["-s", serial] if serial else []) + ["shell", "dumpsys", "package"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if proc.returncode != 0:
            return results
        # Look for 'Hidden system packages' and 'Shared libraries' sections
        # Some ROMs include a 'Deleted packages' section
        in_deleted = False
        for line in proc.stdout.splitlines():
            if "Deleted packages" in line or "Recently deleted" in line:
                in_deleted = True
            elif in_deleted:
                if line.strip().startswith("Package ["):
                    pkg = line.strip().split("[")[1].split("]")[0]
                    results.append(_make(
                        name=pkg,
                        source="adb dumpsys package",
                        reason="Found in 'Deleted packages' section",
                        plat="Android",
                    ))
                elif line and not line[0].isspace() and ":" in line:
                    in_deleted = False  # new section started
    except Exception:
        pass
    return results


# ═══════════════════════════════════════════════════════════════════════════ #
#  Public API
# ═══════════════════════════════════════════════════════════════════════════ #

class DeletedAppAnalyzer:

    def __init__(self):
        self.os = platform.system()
        self.results = []

    def analyze(self, callback=None, existing_app_data=None) -> list:
        """
        Collect deleted-app evidence from all available OS sources.
        existing_app_data: list of app dicts already gathered — any with
                           status=='Removed' are included automatically.
        """
        results = []

        # Always include anything already flagged Removed from main app scan
        if existing_app_data:
            removed = [r for r in existing_app_data if r.get("status") == "Removed"]
            for r in removed:
                results.append(_make(
                    name=r.get("name", ""),
                    version=r.get("version", ""),
                    removed_date=r.get("install_date", ""),  # dpkg logs removal date here
                    source=r.get("source", ""),
                    reason="Flagged as Removed in package manager log",
                    plat=self.os,
                ))
            if callback and removed:
                callback(f"Found {len(removed)} removed entries in package logs.")

        if self.os == "Darwin":
            if callback:
                callback("Scanning macOS removal logs …")
            results.extend(_mac_install_log())
            results.extend(_mac_trash())
            if callback:
                callback("Checking Spotlight for stale app entries …")
            results.extend(_mac_spotlight_remnants())

        elif self.os == "Windows":
            if callback:
                callback("Scanning MuiCache for ghost apps …")
            results.extend(_windows_muicache())
            if callback:
                callback("Scanning UserAssist …")
            results.extend(_windows_userassist())
            if callback:
                callback("Scanning Prefetch …")
            results.extend(_windows_prefetch())
            if callback:
                callback("Scanning Windows Event Log …")
            results.extend(_windows_event_log())

        else:  # Linux
            if callback:
                callback("Scanning dpkg removal logs …")
            results.extend(_linux_dpkg_removed())
            if callback:
                callback("Scanning apt history …")
            results.extend(_linux_apt_history())
            if callback:
                callback("Scanning dnf/yum logs …")
            results.extend(_linux_dnf_removed())

        # Deduplicate by name+source
        seen = set()
        deduped = []
        for r in results:
            key = (r["name"].lower(), r["source"])
            if key not in seen:
                seen.add(key)
                deduped.append(r)

        self.results = deduped
        if callback:
            callback(f"Deleted apps: {len(self.results)} entries found.")
        return self.results
