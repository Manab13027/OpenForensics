"""
File Artifact Analyzer
Collects recently accessed files, downloads, and other filesystem artifacts.
Supports Windows (Recent Items / LNK files), macOS (Recent Items plist),
and Linux (recently-used.xbel).
"""

import os
import platform
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path


class FileAnalyzer:

    def __init__(self):
        self.os = platform.system()
        self.results = []

    # ------------------------------------------------------------------ #
    # Windows
    # ------------------------------------------------------------------ #

    def _windows_artifacts(self):
        results = []

        # Recent Items (LNK shortcuts)
        recent = Path(os.environ.get("APPDATA", "")) / "Microsoft/Windows/Recent"
        if recent.exists():
            for lnk in sorted(recent.glob("*.lnk"),
                               key=lambda x: x.stat().st_mtime, reverse=True)[:200]:
                results.append({
                    "name": lnk.stem,
                    "type": "Recent Item (LNK)",
                    "accessed": datetime.fromtimestamp(lnk.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                    "path": str(lnk),
                    "source": "Windows Recent",
                })

        # Downloads folder
        downloads = Path.home() / "Downloads"
        if downloads.exists():
            for item in sorted(downloads.iterdir(),
                                key=lambda x: x.stat().st_mtime, reverse=True)[:100]:
                results.append({
                    "name": item.name,
                    "type": "Downloaded File",
                    "accessed": datetime.fromtimestamp(item.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                    "path": str(item),
                    "source": "Downloads",
                })

        # Prefetch (indicates executed programs)
        prefetch = Path("C:/Windows/Prefetch")
        if prefetch.exists():
            for pf in sorted(prefetch.glob("*.pf"),
                              key=lambda x: x.stat().st_mtime, reverse=True)[:100]:
                results.append({
                    "name": pf.stem,
                    "type": "Prefetch (Executed Program)",
                    "accessed": datetime.fromtimestamp(pf.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                    "path": str(pf),
                    "source": "Windows Prefetch",
                })

        return results

    # ------------------------------------------------------------------ #
    # macOS
    # ------------------------------------------------------------------ #

    def _mac_artifacts(self):
        results = []

        # macOS Recent Items via defaults
        try:
            proc = subprocess.run(
                ["defaults", "read", "com.apple.recentitems"],
                capture_output=True, text=True, timeout=10,
            )
            if proc.returncode == 0:
                for line in proc.stdout.splitlines():
                    if "_CFURLString" in line and "file://" in line:
                        raw = line.split("file://")[-1].strip().rstrip(";").strip('"')
                        from urllib.parse import unquote
                        path = unquote(raw)
                        results.append({
                            "name": Path(path).name,
                            "type": "Recent Item",
                            "accessed": "",
                            "path": path,
                            "source": "macOS Recent Items",
                        })
        except Exception:
            pass

        # Downloads
        downloads = Path.home() / "Downloads"
        if downloads.exists():
            try:
                items = sorted(downloads.iterdir(),
                               key=lambda x: x.stat().st_mtime, reverse=True)[:100]
            except PermissionError:
                items = []
            for item in items:
                try:
                    results.append({
                        "name": item.name,
                        "type": "Downloaded File",
                        "accessed": datetime.fromtimestamp(item.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                        "path": str(item),
                        "source": "Downloads",
                    })
                except Exception:
                    pass

        # Quarantine database (tracks files downloaded from the internet)
        quarantine_db = Path.home() / "Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2"
        if quarantine_db.exists():
            import sqlite3, shutil, tempfile
            tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
            tmp.close()
            try:
                shutil.copy2(quarantine_db, tmp.name)
                con = sqlite3.connect(tmp.name)
                con.row_factory = sqlite3.Row
                cur = con.cursor()
                cur.execute("""
                    SELECT LSQuarantineDataURLString, LSQuarantineOriginURLString,
                           LSQuarantineAgentName, LSQuarantineTimeStamp
                    FROM LSQuarantineEvent
                    ORDER BY LSQuarantineTimeStamp DESC
                    LIMIT 500
                """)
                for row in cur.fetchall():
                    ts = row["LSQuarantineTimeStamp"]
                    date_str = ""
                    if ts:
                        try:
                            date_str = datetime.fromtimestamp(ts + 978_307_200).strftime("%Y-%m-%d %H:%M:%S")
                        except Exception:
                            pass
                    url = row["LSQuarantineDataURLString"] or ""
                    results.append({
                        "name": url.split("/")[-1] or url[:60],
                        "type": f"Quarantine Download ({row['LSQuarantineAgentName'] or 'Unknown'})",
                        "accessed": date_str,
                        "path": row["LSQuarantineOriginURLString"] or url,
                        "source": "QuarantineEventsV2",
                    })
                con.close()
            except Exception:
                pass
            finally:
                try:
                    os.unlink(tmp.name)
                except Exception:
                    pass

        return results

    # ------------------------------------------------------------------ #
    # Linux
    # ------------------------------------------------------------------ #

    def _linux_artifacts(self):
        results = []

        # GTK recently-used.xbel
        xbel = Path.home() / ".local/share/recently-used.xbel"
        if xbel.exists():
            try:
                tree = ET.parse(xbel)
                root = tree.getroot()
                for bm in root.findall("bookmark"):
                    href = bm.get("href", "")
                    modified = bm.get("modified", "")
                    if href.startswith("file://"):
                        path = href[7:]
                        results.append({
                            "name": Path(path).name,
                            "type": "Recent File",
                            "accessed": modified,
                            "path": path,
                            "source": "recently-used.xbel",
                        })
            except Exception:
                pass

        # Downloads
        downloads = Path.home() / "Downloads"
        if downloads.exists():
            for item in sorted(downloads.iterdir(),
                                key=lambda x: x.stat().st_mtime, reverse=True)[:100]:
                try:
                    results.append({
                        "name": item.name,
                        "type": "Downloaded File",
                        "accessed": datetime.fromtimestamp(item.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                        "path": str(item),
                        "source": "Downloads",
                    })
                except Exception:
                    pass

        # Bash history (reveals commands run)
        bash_hist = Path.home() / ".bash_history"
        if bash_hist.exists():
            try:
                with open(bash_hist, "r", errors="ignore") as f:
                    for line in f.readlines()[-200:]:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            results.append({
                                "name": line[:80],
                                "type": "Shell Command",
                                "accessed": "",
                                "path": str(bash_hist),
                                "source": ".bash_history",
                            })
            except Exception:
                pass

        return results

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def analyze(self, callback=None):
        if callback:
            callback("Scanning file artifacts...")
        if self.os == "Windows":
            self.results = self._windows_artifacts()
        elif self.os == "Darwin":
            self.results = self._mac_artifacts()
        else:
            self.results = self._linux_artifacts()
        return self.results
