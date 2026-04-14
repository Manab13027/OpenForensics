"""
iPhone / iOS Forensics Analyzer (via iTunes / Finder Backups)
==============================================================
Parses iTunes or Finder backup files stored on this Mac / Windows PC.
No jailbreak required — works on any unencrypted backup.

Backup locations:
  macOS   : ~/Library/Application Support/MobileSync/Backup/
  Windows : %APPDATA%\\Apple Computer\\MobileSync\\Backup\\

What is extracted:
  - Safari browser history
  - Chrome for iOS history
  - Installed app list (from Manifest)
  - Downloaded files (Media / Documents from backup)

How backups work:
  Each file in the backup is stored as {fileID[0:2]}/{fileID}
  where fileID is a 40-char hex string. Manifest.db maps
  fileID → (domain, relativePath).

LEGAL NOTICE: Only analyse backups from devices you own or have
written authorisation to examine.
"""

import os
import plistlib
import platform
import shutil
import sqlite3
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Backup discovery
# ---------------------------------------------------------------------------

def find_backups() -> list[dict]:
    """Return a list of iTunes/Finder backup info dicts."""
    if platform.system() == "Windows":
        base = Path(os.environ.get("APPDATA", "")) / "Apple Computer/MobileSync/Backup"
    else:
        base = Path.home() / "Library/Application Support/MobileSync/Backup"

    if not base.exists():
        return []

    try:
        entries = list(base.iterdir())
    except PermissionError:
        # Requires Full Disk Access: System Settings → Privacy & Security → Full Disk Access → add Terminal
        return [{"path": "", "udid": "PERMISSION_DENIED",
                 "encrypted": False, "device_name": "⚠ Permission denied",
                 "ios_version": "", "backup_date": "",
                 "serial": "Grant Full Disk Access to Terminal in System Settings"}]

    backups = []
    for d in entries:
        if not d.is_dir():
            continue
        manifest_db   = d / "Manifest.db"
        manifest_plist = d / "Manifest.plist"
        info_plist    = d / "Info.plist"
        if not manifest_db.exists():
            continue

        info = {
            "path":      str(d),
            "udid":      d.name,
            "encrypted": False,
            "device_name": "",
            "ios_version": "",
            "backup_date": "",
            "serial": "",
        }

        # Info.plist — device metadata
        if info_plist.exists():
            try:
                with open(info_plist, "rb") as f:
                    data = plistlib.load(f)
                info["device_name"] = data.get("Device Name", "")
                info["ios_version"] = data.get("Product Version", "")
                info["serial"]      = data.get("Serial Number", "")
                last_backup = data.get("Last Backup Date")
                if last_backup:
                    info["backup_date"] = str(last_backup)[:19]
            except Exception:
                pass

        # Manifest.plist — encryption flag
        if manifest_plist.exists():
            try:
                with open(manifest_plist, "rb") as f:
                    mdata = plistlib.load(f)
                info["encrypted"] = bool(mdata.get("IsEncrypted", False))
            except Exception:
                pass

        backups.append(info)

    return backups


# ---------------------------------------------------------------------------
# Main analyzer
# ---------------------------------------------------------------------------

class iPhoneAnalyzer:

    # (domain_pattern, relative_path_pattern, browser_name, db_type)
    BROWSER_FILES = [
        ("AppDomain-com.apple.mobilesafari",
         "Library/Safari/History.db",
         "Safari", "safari"),

        ("AppDomain-com.google.chrome.ios",
         "Library/Application Support/Google/Chrome/Default/History",
         "Chrome (iOS)", "chromium"),

        ("AppDomain-com.google.chrome.ios",
         "Documents/History",
         "Chrome (iOS) alt", "chromium"),

        ("AppDomain-org.mozilla.ios.Firefox",
         "profile.profile/places.sqlite",
         "Firefox (iOS)", "firefox"),

        ("AppDomain-com.microsoft.Office.Outlook",
         "Library/Application Support/Edge/Default/History",
         "Edge (iOS)", "chromium"),
    ]

    def __init__(self, backup_path: str):
        self.backup_path     = Path(backup_path)
        self.manifest_db     = self.backup_path / "Manifest.db"
        self.browser_results: list = []
        self.app_results:     list = []
        self.file_results:    list = []
        self.errors:          list = []

    # ------------------------------------------------------------------ #
    #  Internal helpers
    # ------------------------------------------------------------------ #

    def _open_manifest(self):
        tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        tmp.close()
        shutil.copy2(self.manifest_db, tmp.name)
        return tmp.name

    def _get_file_path(self, file_id: str) -> Path:
        """Resolve a fileID to its actual path in the backup."""
        return self.backup_path / file_id[:2] / file_id

    def _copy_backup_file(self, file_id: str) -> Optional[str]:
        """Copy a backup file to a temp location. Returns temp path or None."""
        src = self._get_file_path(file_id)
        if not src.exists():
            return None
        tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        tmp.close()
        shutil.copy2(src, tmp.name)
        return tmp.name

    # ------------------------------------------------------------------ #
    #  File lookup in Manifest
    # ------------------------------------------------------------------ #

    def _find_file(self, domain: str, relative_path: str) -> Optional[str]:
        """Return fileID for a given domain+relativePath, or None."""
        tmp = self._open_manifest()
        file_id = None
        try:
            con = sqlite3.connect(tmp)
            cur = con.cursor()
            cur.execute(
                "SELECT fileID FROM Files WHERE domain=? AND relativePath=?",
                (domain, relative_path),
            )
            row = cur.fetchone()
            if row:
                file_id = row[0]
            con.close()
        except Exception:
            pass
        finally:
            try:
                os.unlink(tmp)
            except Exception:
                pass
        return file_id

    def _find_files_like(self, domain_like: str, path_like: str) -> list[tuple]:
        """Return [(fileID, domain, relativePath)] matching LIKE patterns."""
        tmp = self._open_manifest()
        results = []
        try:
            con = sqlite3.connect(tmp)
            cur = con.cursor()
            cur.execute(
                """SELECT fileID, domain, relativePath FROM Files
                   WHERE domain LIKE ? AND relativePath LIKE ?""",
                (domain_like, path_like),
            )
            results = cur.fetchall()
            con.close()
        except Exception:
            pass
        finally:
            try:
                os.unlink(tmp)
            except Exception:
                pass
        return results

    # ------------------------------------------------------------------ #
    #  Browser parsers
    # ------------------------------------------------------------------ #

    @staticmethod
    def _safari_ts(ts):
        try:
            return datetime.fromtimestamp(ts + 978_307_200).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            return "Unknown"

    @staticmethod
    def _chrome_ts(ts):
        try:
            return datetime.fromtimestamp(
                (ts - 11_644_473_600_000_000) / 1_000_000
            ).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            return "Unknown"

    @staticmethod
    def _firefox_ts(ts):
        try:
            return datetime.fromtimestamp(ts / 1_000_000).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            return "Unknown"

    def _parse_safari(self, tmp_path: str, browser: str, source: str) -> list:
        rows = []
        try:
            con = sqlite3.connect(tmp_path)
            con.row_factory = sqlite3.Row
            cur = con.cursor()
            cur.execute("""
                SELECT i.url, v.title, i.visit_count, v.visit_time
                FROM history_items i
                LEFT JOIN history_visits v ON i.id = v.history_item
                ORDER BY v.visit_time DESC LIMIT 2000
            """)
            for r in cur.fetchall():
                rows.append({
                    "browser": browser, "url": r["url"] or "",
                    "title": r["title"] or "",
                    "visit_count": r["visit_count"] or 0,
                    "last_visit": self._safari_ts(r["visit_time"]) if r["visit_time"] else "Unknown",
                    "source": source,
                })
            con.close()
        except Exception as e:
            self.errors.append(f"{browser}: {e}")
        return rows

    def _parse_chromium(self, tmp_path: str, browser: str, source: str) -> list:
        rows = []
        try:
            con = sqlite3.connect(tmp_path)
            con.row_factory = sqlite3.Row
            cur = con.cursor()
            cur.execute("""
                SELECT url, title, visit_count, last_visit_time
                FROM urls ORDER BY last_visit_time DESC LIMIT 2000
            """)
            for r in cur.fetchall():
                rows.append({
                    "browser": browser, "url": r["url"] or "",
                    "title": r["title"] or "",
                    "visit_count": r["visit_count"] or 0,
                    "last_visit": self._chrome_ts(r["last_visit_time"]),
                    "source": source,
                })
            con.close()
        except Exception as e:
            self.errors.append(f"{browser}: {e}")
        return rows

    def _parse_firefox(self, tmp_path: str, browser: str, source: str) -> list:
        rows = []
        try:
            con = sqlite3.connect(tmp_path)
            con.row_factory = sqlite3.Row
            cur = con.cursor()
            cur.execute("""
                SELECT p.url, p.title, p.visit_count, v.visit_date
                FROM moz_places p
                LEFT JOIN moz_historyvisits v ON p.id = v.place_id
                ORDER BY v.visit_date DESC LIMIT 2000
            """)
            for r in cur.fetchall():
                rows.append({
                    "browser": browser, "url": r["url"] or "",
                    "title": r["title"] or "",
                    "visit_count": r["visit_count"] or 0,
                    "last_visit": self._firefox_ts(r["visit_date"]) if r["visit_date"] else "Unknown",
                    "source": source,
                })
            con.close()
        except Exception as e:
            self.errors.append(f"{browser}: {e}")
        return rows

    def _get_browser_history(self, callback=None) -> list:
        results = []
        for domain, rel_path, browser, db_type in self.BROWSER_FILES:
            if callback:
                callback(f"Looking for {browser} history in backup …")
            file_id = self._find_file(domain, rel_path)
            if not file_id:
                continue
            tmp = self._copy_backup_file(file_id)
            if not tmp:
                continue
            try:
                if db_type == "safari":
                    results.extend(self._parse_safari(tmp, browser, rel_path))
                elif db_type == "firefox":
                    results.extend(self._parse_firefox(tmp, browser, rel_path))
                else:
                    results.extend(self._parse_chromium(tmp, browser, rel_path))
            finally:
                try:
                    os.unlink(tmp)
                except Exception:
                    pass
        return results

    # ------------------------------------------------------------------ #
    #  Installed apps
    # ------------------------------------------------------------------ #

    def _get_apps(self, callback=None) -> list:
        results = []
        if callback:
            callback("Reading app list from backup manifest …")

        tmp = self._open_manifest()
        try:
            con = sqlite3.connect(tmp)
            cur = con.cursor()
            # Each app has its own domain: AppDomain-com.bundle.id
            cur.execute("""
                SELECT DISTINCT domain FROM Files
                WHERE domain LIKE 'AppDomain-%'
                ORDER BY domain
            """)
            for (domain,) in cur.fetchall():
                pkg = domain.replace("AppDomain-", "")
                results.append({
                    "name":         pkg,
                    "version":      "",
                    "publisher":    "",
                    "install_date": "",
                    "status":       "Installed (in backup)",
                    "source":       "Manifest.db",
                })
            con.close()
        except Exception as e:
            self.errors.append(f"App list error: {e}")
        finally:
            try:
                os.unlink(tmp)
            except Exception:
                pass

        return results

    # ------------------------------------------------------------------ #
    #  File artifacts
    # ------------------------------------------------------------------ #

    def _get_file_artifacts(self, callback=None) -> list:
        results = []
        if callback:
            callback("Scanning file artifacts in backup …")

        # Look for media and documents across all app domains
        patterns = [
            ("%", "%.pdf",  "PDF Document"),
            ("%", "%.jpg",  "Image (JPEG)"),
            ("%", "%.jpeg", "Image (JPEG)"),
            ("%", "%.png",  "Image (PNG)"),
            ("%", "%.mp4",  "Video (MP4)"),
            ("%", "%.mov",  "Video (MOV)"),
            ("%", "%.docx", "Word Document"),
            ("%", "%.xlsx", "Excel Document"),
            ("%", "%.zip",  "ZIP Archive"),
            ("AppDomain-com.apple.MobileSMS", "%.db", "SMS Database"),
            ("HomeDomain", "Library/CallHistoryDB/%", "Call History"),
        ]

        tmp = self._open_manifest()
        try:
            con = sqlite3.connect(tmp)
            cur = con.cursor()
            seen = set()
            for domain_like, path_like, ftype in patterns:
                cur.execute(
                    """SELECT fileID, domain, relativePath FROM Files
                       WHERE domain LIKE ? AND relativePath LIKE ?
                       LIMIT 200""",
                    (domain_like, path_like),
                )
                for file_id, domain, rel_path in cur.fetchall():
                    if file_id in seen:
                        continue
                    seen.add(file_id)
                    actual = self._get_file_path(file_id)
                    size = actual.stat().st_size if actual.exists() else 0
                    results.append({
                        "name":     Path(rel_path).name,
                        "type":     ftype,
                        "accessed": "",
                        "path":     f"{domain}/{rel_path}",
                        "source":   f"iOS Backup ({size:,} bytes)",
                    })
            con.close()
        except Exception as e:
            self.errors.append(f"File scan error: {e}")
        finally:
            try:
                os.unlink(tmp)
            except Exception:
                pass

        return results

    # ------------------------------------------------------------------ #
    #  Public API
    # ------------------------------------------------------------------ #

    def analyze(self, callback=None) -> dict:
        if not self.manifest_db.exists():
            msg = f"Manifest.db not found in: {self.backup_path}"
            if callback:
                callback(f"ERROR: {msg}")
            return {"browser": [], "apps": [], "files": [], "errors": [msg]}

        self.browser_results = self._get_browser_history(callback)
        self.app_results     = self._get_apps(callback)
        self.file_results    = self._get_file_artifacts(callback)

        if callback:
            callback(
                f"iPhone scan complete — "
                f"Browser: {len(self.browser_results)}, "
                f"Apps: {len(self.app_results)}, "
                f"Files: {len(self.file_results)}"
            )

        return {
            "browser": self.browser_results,
            "apps":    self.app_results,
            "files":   self.file_results,
            "errors":  self.errors,
        }
