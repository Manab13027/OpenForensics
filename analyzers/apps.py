"""
Application Inventory Analyzer
Lists installed applications and (on Linux) removed packages from logs.
Supports Windows (registry), macOS (Applications + system_profiler), Linux (dpkg/rpm).
"""

import json
import os
import platform
import subprocess
from datetime import datetime
from pathlib import Path


class AppAnalyzer:

    def __init__(self):
        self.os = platform.system()
        self.results = []

    # ------------------------------------------------------------------ #
    # Windows
    # ------------------------------------------------------------------ #

    def _windows_apps(self):
        results = []
        try:
            import winreg  # Only available on Windows
            hives = [
                (winreg.HKEY_LOCAL_MACHINE,
                 r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
                (winreg.HKEY_LOCAL_MACHINE,
                 r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
                (winreg.HKEY_CURRENT_USER,
                 r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            ]
            for hive, key_path in hives:
                try:
                    key = winreg.OpenKey(hive, key_path)
                    for i in range(winreg.QueryInfoKey(key)[0]):
                        try:
                            sub_name = winreg.EnumKey(key, i)
                            sub = winreg.OpenKey(key, sub_name)

                            def val(name, default=""):
                                try:
                                    return winreg.QueryValueEx(sub, name)[0]
                                except Exception:
                                    return default

                            name = val("DisplayName")
                            if not name:
                                continue
                            results.append({
                                "name": name,
                                "version": val("DisplayVersion"),
                                "publisher": val("Publisher"),
                                "install_date": val("InstallDate"),
                                "location": val("InstallLocation"),
                                "status": "Installed",
                                "source": "Registry:" + key_path,
                            })
                        except Exception:
                            pass
                except Exception:
                    pass
        except ImportError:
            pass
        return results

    # ------------------------------------------------------------------ #
    # macOS
    # ------------------------------------------------------------------ #

    def _mac_apps(self):
        results = []
        seen = set()

        def add_app(name, version, publisher, install_date, location, source):
            if name and name not in seen:
                seen.add(name)
                results.append({
                    "name": name,
                    "version": version,
                    "publisher": publisher,
                    "install_date": install_date,
                    "location": location,
                    "status": "Installed",
                    "source": source,
                })

        # Scan /Applications and ~/Applications
        for apps_dir in [Path("/Applications"), Path.home() / "Applications"]:
            if apps_dir.exists():
                for app in sorted(apps_dir.glob("*.app")):
                    stat = app.stat()
                    birth = ""
                    if hasattr(stat, "st_birthtime"):
                        birth = datetime.fromtimestamp(stat.st_birthtime).strftime("%Y-%m-%d")
                    add_app(app.stem, "", "", birth, str(app), str(apps_dir))

        # system_profiler gives richer metadata
        try:
            proc = subprocess.run(
                ["system_profiler", "SPApplicationsDataType", "-json"],
                capture_output=True, text=True, timeout=45,
            )
            if proc.returncode == 0:
                data = json.loads(proc.stdout)
                for app in data.get("SPApplicationsDataType", []):
                    add_app(
                        app.get("_name", ""),
                        app.get("version", ""),
                        app.get("info", ""),
                        app.get("lastModified", ""),
                        app.get("path", ""),
                        "system_profiler",
                    )
        except Exception:
            pass

        return results

    # ------------------------------------------------------------------ #
    # Linux
    # ------------------------------------------------------------------ #

    def _linux_apps(self):
        results = []

        # dpkg log (Debian / Ubuntu)
        dpkg_log = Path("/var/log/dpkg.log")
        if dpkg_log.exists():
            try:
                with open(dpkg_log, "r", errors="ignore") as f:
                    for line in f:
                        parts = line.strip().split()
                        if len(parts) >= 4 and parts[2] in ("install", "remove", "purge"):
                            pkg = parts[3].split(":")[0]
                            results.append({
                                "name": pkg,
                                "version": parts[4] if len(parts) > 4 else "",
                                "publisher": "",
                                "install_date": f"{parts[0]} {parts[1]}",
                                "location": "",
                                "status": "Installed" if parts[2] == "install" else "Removed",
                                "source": "dpkg.log",
                            })
            except Exception:
                pass

        # RPM (Fedora / CentOS / RHEL)
        try:
            proc = subprocess.run(
                ["rpm", "-qa", "--queryformat", "%{NAME}|%{VERSION}|%{INSTALLTIME:date}\n"],
                capture_output=True, text=True, timeout=20,
            )
            if proc.returncode == 0:
                for line in proc.stdout.splitlines():
                    parts = line.split("|")
                    if len(parts) >= 3 and parts[0]:
                        results.append({
                            "name": parts[0],
                            "version": parts[1],
                            "publisher": "",
                            "install_date": parts[2],
                            "location": "",
                            "status": "Installed",
                            "source": "rpm",
                        })
        except Exception:
            pass

        # Snap
        try:
            proc = subprocess.run(
                ["snap", "list"], capture_output=True, text=True, timeout=15,
            )
            if proc.returncode == 0:
                lines = proc.stdout.splitlines()[1:]  # skip header
                for line in lines:
                    parts = line.split()
                    if parts:
                        results.append({
                            "name": parts[0],
                            "version": parts[1] if len(parts) > 1 else "",
                            "publisher": parts[4] if len(parts) > 4 else "",
                            "install_date": "",
                            "location": "",
                            "status": "Installed",
                            "source": "snap",
                        })
        except Exception:
            pass

        # Flatpak
        try:
            proc = subprocess.run(
                ["flatpak", "list", "--columns=application,version,installation"],
                capture_output=True, text=True, timeout=15,
            )
            if proc.returncode == 0:
                for line in proc.stdout.splitlines():
                    parts = line.split("\t")
                    if parts:
                        results.append({
                            "name": parts[0],
                            "version": parts[1] if len(parts) > 1 else "",
                            "publisher": "",
                            "install_date": "",
                            "location": "",
                            "status": "Installed",
                            "source": "flatpak",
                        })
        except Exception:
            pass

        return results

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def analyze(self, callback=None):
        if callback:
            callback("Scanning application inventory...")
        if self.os == "Windows":
            self.results = self._windows_apps()
        elif self.os == "Darwin":
            self.results = self._mac_apps()
        else:
            self.results = self._linux_apps()
        return self.results
