"""
Browser History Analyzer
Parses SQLite databases from Chrome, Firefox, Edge, and Safari.
Works on Windows, macOS, and Linux.
"""

import os
import sqlite3
import shutil
import tempfile
import platform
from datetime import datetime
from pathlib import Path


class BrowserAnalyzer:

    def __init__(self, base_path=None):
        self.base_path = Path(base_path) if base_path else Path.home()
        self.os = platform.system()
        self.results = []

    # ------------------------------------------------------------------ #
    # Path discovery
    # ------------------------------------------------------------------ #

    def _chromium_base(self, vendor_path_win, vendor_path_mac, vendor_path_linux):
        if self.os == "Windows":
            return Path(os.environ.get("LOCALAPPDATA", "")) / vendor_path_win
        elif self.os == "Darwin":
            return self.base_path / "Library/Application Support" / vendor_path_mac
        else:
            return self.base_path / vendor_path_linux

    def _find_chromium_dbs(self, browser_name, win_path, mac_path, linux_path):
        base = self._chromium_base(win_path, mac_path, linux_path)
        found = []
        if base.exists():
            for profile in ["Default", "Profile 1", "Profile 2", "Profile 3", "Profile 4"]:
                db = base / profile / "History"
                if db.exists():
                    found.append((browser_name, profile, db))
        return found

    def _chrome_paths(self):
        return self._find_chromium_dbs(
            "Chrome",
            "Google/Chrome/User Data",
            "Google/Chrome",
            ".config/google-chrome",
        )

    def _edge_paths(self):
        return self._find_chromium_dbs(
            "Edge",
            "Microsoft/Edge/User Data",
            "Microsoft Edge",
            ".config/microsoft-edge",
        )

    def _brave_paths(self):
        return self._find_chromium_dbs(
            "Brave",
            "BraveSoftware/Brave-Browser/User Data",
            "BraveSoftware/Brave-Browser",
            ".config/BraveSoftware/Brave-Browser",
        )

    def _firefox_paths(self):
        if self.os == "Windows":
            base = Path(os.environ.get("APPDATA", "")) / "Mozilla/Firefox/Profiles"
        elif self.os == "Darwin":
            base = self.base_path / "Library/Application Support/Firefox/Profiles"
        else:
            base = self.base_path / ".mozilla/firefox"
        found = []
        if base.exists():
            for profile_dir in base.iterdir():
                if profile_dir.is_dir():
                    db = profile_dir / "places.sqlite"
                    if db.exists():
                        found.append(("Firefox", profile_dir.name, db))
        return found

    def _safari_paths(self):
        found = []
        if self.os == "Darwin":
            db = self.base_path / "Library/Safari/History.db"
            if db.exists():
                found.append(("Safari", "Default", db))
        return found

    # ------------------------------------------------------------------ #
    # DB querying
    # ------------------------------------------------------------------ #

    @staticmethod
    def _copy_db(db_path):
        """Copy locked DB to a temp file so we can read it safely."""
        tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        tmp.close()
        shutil.copy2(db_path, tmp.name)
        return tmp.name

    @staticmethod
    def _chrome_ts(ts):
        """Convert Chrome/Edge microseconds-since-1601 to readable string."""
        try:
            unix = (ts - 11_644_473_600_000_000) / 1_000_000
            return datetime.fromtimestamp(unix).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            return "Unknown"

    @staticmethod
    def _firefox_ts(ts):
        """Convert Firefox microseconds-since-epoch to readable string."""
        try:
            return datetime.fromtimestamp(ts / 1_000_000).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            return "Unknown"

    @staticmethod
    def _safari_ts(ts):
        """Convert Safari seconds-since-2001-01-01 to readable string."""
        try:
            return datetime.fromtimestamp(ts + 978_307_200).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            return "Unknown"

    def _query_chromium(self, browser, profile, db_path):
        tmp = self._copy_db(db_path)
        rows = []
        try:
            con = sqlite3.connect(tmp)
            con.row_factory = sqlite3.Row
            cur = con.cursor()
            cur.execute("""
                SELECT url, title, visit_count, last_visit_time, typed_count
                FROM urls
                ORDER BY last_visit_time DESC
                LIMIT 2000
            """)
            for r in cur.fetchall():
                rows.append({
                    "browser": browser,
                    "profile": profile,
                    "url": r["url"] or "",
                    "title": r["title"] or "",
                    "visit_count": r["visit_count"] or 0,
                    "last_visit": self._chrome_ts(r["last_visit_time"]),
                    "typed": bool(r["typed_count"]),
                    "source": str(db_path),
                })
            con.close()
        except Exception as e:
            rows.append({"browser": browser, "profile": profile, "url": f"[Error: {e}]",
                         "title": "", "visit_count": 0, "last_visit": "", "typed": False,
                         "source": str(db_path)})
        finally:
            try:
                os.unlink(tmp)
            except Exception:
                pass
        return rows

    def _query_firefox(self, browser, profile, db_path):
        tmp = self._copy_db(db_path)
        rows = []
        try:
            con = sqlite3.connect(tmp)
            con.row_factory = sqlite3.Row
            cur = con.cursor()
            cur.execute("""
                SELECT p.url, p.title, p.visit_count, v.visit_date
                FROM moz_places p
                LEFT JOIN moz_historyvisits v ON p.id = v.place_id
                ORDER BY v.visit_date DESC
                LIMIT 2000
            """)
            for r in cur.fetchall():
                rows.append({
                    "browser": browser,
                    "profile": profile,
                    "url": r["url"] or "",
                    "title": r["title"] or "",
                    "visit_count": r["visit_count"] or 0,
                    "last_visit": self._firefox_ts(r["visit_date"]) if r["visit_date"] else "Unknown",
                    "typed": False,
                    "source": str(db_path),
                })
            con.close()
        except Exception as e:
            rows.append({"browser": browser, "profile": profile, "url": f"[Error: {e}]",
                         "title": "", "visit_count": 0, "last_visit": "", "typed": False,
                         "source": str(db_path)})
        finally:
            try:
                os.unlink(tmp)
            except Exception:
                pass
        return rows

    def _query_safari(self, browser, profile, db_path):
        try:
            tmp = self._copy_db(db_path)
        except (PermissionError, OSError):
            # Safari DB requires Full Disk Access on macOS 10.14+.
            # Fix: System Settings → Privacy & Security → Full Disk Access
            #      → click (+) → add Terminal (or your Python app)
            return [{
                "browser": "Safari",
                "profile": profile,
                "url": "⚠ Permission denied",
                "title": "Grant Full Disk Access to Terminal: "
                         "System Settings → Privacy & Security → Full Disk Access → add Terminal",
                "visit_count": 0,
                "last_visit": "",
                "typed": False,
                "source": str(db_path),
            }]
        rows = []
        try:
            con = sqlite3.connect(tmp)
            con.row_factory = sqlite3.Row
            cur = con.cursor()
            cur.execute("""
                SELECT i.url, v.title, i.visit_count, v.visit_time
                FROM history_items i
                LEFT JOIN history_visits v ON i.id = v.history_item
                ORDER BY v.visit_time DESC
                LIMIT 2000
            """)
            for r in cur.fetchall():
                rows.append({
                    "browser": browser,
                    "profile": profile,
                    "url": r["url"] or "",
                    "title": r["title"] or "",
                    "visit_count": r["visit_count"] or 0,
                    "last_visit": self._safari_ts(r["visit_time"]) if r["visit_time"] else "Unknown",
                    "typed": False,
                    "source": str(db_path),
                })
            con.close()
        except Exception:
            pass  # Safari often has permission restrictions
        finally:
            try:
                os.unlink(tmp)
            except Exception:
                pass
        return rows

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def analyze(self, callback=None):
        all_paths = (
            self._chrome_paths()
            + self._edge_paths()
            + self._brave_paths()
            + self._firefox_paths()
            + self._safari_paths()
        )

        if not all_paths:
            if callback:
                callback("No browser databases found.")
            self.results = []
            return []

        self.results = []
        for browser, profile, db_path in all_paths:
            if callback:
                callback(f"Reading {browser} — {profile} ...")
            if browser == "Firefox":
                self.results.extend(self._query_firefox(browser, profile, db_path))
            elif browser == "Safari":
                self.results.extend(self._query_safari(browser, profile, db_path))
            else:
                self.results.extend(self._query_chromium(browser, profile, db_path))

        return self.results
