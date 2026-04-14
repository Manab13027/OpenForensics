"""
Android Forensics Analyzer (via ADB)
=====================================
Connects to an Android device over USB/WiFi using ADB and extracts:
  - Installed & uninstalled package history
  - Browser history (Chrome, Firefox, Samsung Browser)
  - Call log, SMS metadata (if accessible)
  - Files on external storage / sdcard

Requirements:
  - ADB installed and on PATH  (https://developer.android.com/tools/adb)
  - USB Debugging enabled on the device
    (Settings → Developer Options → USB Debugging)
  - For browser SQLite databases: root OR a debug build of the browser
    (production Chrome on non-rooted devices blocks direct DB access)

LEGAL NOTICE: Only analyse devices you own or have written authorisation to examine.
"""

import os
import platform
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path

# Use adb_setup to resolve the real adb binary path (handles platform-tools folder)
sys.path.insert(0, str(Path(__file__).parent.parent))
try:
    from adb_setup import adb_path, adb_on_path
except ImportError:
    def adb_path(): return "adb"
    def adb_on_path(): return shutil.which("adb") is not None


# ---------------------------------------------------------------------------
# ADB helper
# ---------------------------------------------------------------------------

def _run(cmd: list, timeout=20) -> tuple:
    """Run an ADB command and return (returncode, stdout, stderr)."""
    # Replace bare 'adb' with the resolved full path
    if cmd and cmd[0] == "adb":
        cmd = [adb_path()] + cmd[1:]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout, errors="replace",
        )
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except FileNotFoundError:
        return -1, "", f"adb not found at: {adb_path()}"
    except subprocess.TimeoutExpired:
        return -1, "", "adb command timed out"
    except Exception as e:
        return -1, "", str(e)


def adb_available() -> bool:
    return adb_on_path()


def raw_devices_output() -> str:
    """Return the raw 'adb devices -l' output for diagnostics."""
    _, out, err = _run(["adb", "devices", "-l"])
    return (out + "\n" + err).strip()


def list_devices() -> list:
    """
    Return list of authorised connected devices.
    Also detects unauthorized / offline states and returns them
    with a descriptive model string so the UI can show guidance.
    """
    rc, out, err = _run(["adb", "devices", "-l"])
    if rc != 0:
        return []

    devices = []
    for line in out.splitlines()[1:]:
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue

        serial = parts[0]
        state  = parts[1]

        if state == "device":
            model = ""
            for part in parts[2:]:
                if part.startswith("model:"):
                    model = part.split(":", 1)[1].replace("_", " ")
            devices.append({"serial": serial, "model": model or serial,
                            "state": "ready"})

        elif state == "unauthorized":
            devices.append({"serial": serial,
                            "model": f"[UNAUTHORIZED — check phone screen]",
                            "state": "unauthorized"})

        elif state == "offline":
            devices.append({"serial": serial,
                            "model": f"[OFFLINE — try reconnecting USB]",
                            "state": "offline"})

    return devices


# ---------------------------------------------------------------------------
# Main analyzer
# ---------------------------------------------------------------------------

class AndroidAnalyzer:

    # Browser SQLite paths on-device
    BROWSER_DBS = [
        ("Chrome",          "com.android.chrome",
         "/data/data/com.android.chrome/app_chrome/Default/History"),
        ("Chrome (alt)",    "com.android.chrome",
         "/data/data/com.android.chrome/databases/History"),
        ("Firefox",         "org.mozilla.firefox",
         "/data/data/org.mozilla.firefox/databases/places.sqlite"),
        ("Firefox Beta",    "org.mozilla.firefox_beta",
         "/data/data/org.mozilla.firefox_beta/databases/places.sqlite"),
        ("Samsung Browser", "com.sec.android.app.sbrowser",
         "/data/data/com.sec.android.app.sbrowser/databases/BrowserHistoryDB"),
        ("Brave",           "com.brave.browser",
         "/data/data/com.brave.browser/app_chrome/Default/History"),
        ("Edge",            "com.microsoft.emmx",
         "/data/data/com.microsoft.emmx/app_chrome/Default/History"),
        ("Opera",           "com.opera.browser",
         "/data/data/com.opera.browser/app_chrome/Default/History"),
    ]

    def __init__(self, serial: str = None):
        self.serial  = serial
        self.adb_cmd = ["adb"] + (["-s", serial] if serial else [])
        self.browser_results: list = []
        self.app_results:     list = []
        self.file_results:    list = []
        self.errors:          list = []

    def _shell(self, cmd: str, timeout=30) -> tuple[int, str]:
        rc, out, err = _run(self.adb_cmd + ["shell", cmd], timeout=timeout)
        return rc, out

    def _pull(self, remote: str, local: str, timeout=60) -> bool:
        rc, _, err = _run(self.adb_cmd + ["pull", remote, local], timeout=timeout)
        return rc == 0

    # ------------------------------------------------------------------ #
    #  Device info
    # ------------------------------------------------------------------ #

    def device_info(self) -> dict:
        info = {}
        for prop, key in [
            ("ro.product.model",        "model"),
            ("ro.product.manufacturer", "manufacturer"),
            ("ro.build.version.release","android_version"),
            ("ro.serialno",             "serial"),
        ]:
            rc, out = self._shell(f"getprop {prop}")
            if rc == 0 and out:
                info[key] = out
        return info

    def is_rooted(self) -> bool:
        rc, out = self._shell("id")
        return rc == 0 and "uid=0" in out

    # ------------------------------------------------------------------ #
    #  Installed packages
    # ------------------------------------------------------------------ #

    def _get_packages(self, callback=None) -> list:
        results = []
        if callback:
            callback("Listing installed packages …")

        # All packages with installer source
        rc, out = self._shell("pm list packages -i -f", timeout=30)
        if rc != 0:
            self.errors.append("Could not list packages via pm")
            return results

        for line in out.splitlines():
            line = line.strip()
            if not line.startswith("package:"):
                continue
            # Format: package:/path/to/apk=com.package.name  installer=com.android.vending
            try:
                rest = line[len("package:"):]
                if "=" in rest:
                    path_part, pkg_part = rest.rsplit("=", 1)
                    pkg_name = pkg_part.split()[0]
                    apk_path = path_part
                else:
                    pkg_name = rest.strip()
                    apk_path = ""
                installer = ""
                if "installer=" in line:
                    installer = line.split("installer=")[-1].strip()
                results.append({
                    "name":         pkg_name,
                    "apk_path":     apk_path,
                    "installer":    installer,
                    "install_date": "",
                    "status":       "Installed",
                    "source":       "adb pm list packages",
                })
            except Exception:
                pass

        # Try to get install dates via dumpsys
        if callback:
            callback(f"Fetching install dates for {len(results)} packages …")
        rc2, dump = self._shell("dumpsys package", timeout=60)
        if rc2 == 0:
            pkg_map = {r["name"]: r for r in results}
            current_pkg = None
            for line in dump.splitlines():
                line = line.strip()
                if line.startswith("Package ["):
                    current_pkg = line.split("[")[1].split("]")[0]
                elif current_pkg and "firstInstallTime=" in line:
                    date_str = line.split("firstInstallTime=")[-1].split()[0]
                    if current_pkg in pkg_map:
                        pkg_map[current_pkg]["install_date"] = date_str

        return results

    # ------------------------------------------------------------------ #
    #  Browser history
    # ------------------------------------------------------------------ #

    # ------------------------------------------------------------------ #
    #  Method 1: Content providers (no root needed on most devices)
    # ------------------------------------------------------------------ #

    def _parse_content_query_output(self, out: str, browser: str, uri: str) -> list:
        """Parse 'adb shell content query' row output into history dicts."""
        rows = []
        for line in out.splitlines():
            line = line.strip()
            if not line.startswith("Row:"):
                continue
            # Format: Row: 0 col1=val1, col2=val2, ...
            def _field(name):
                import re
                m = re.search(rf'\b{name}=([^,\n]+)', line)
                return m.group(1).strip() if m else ""

            url   = _field("url") or _field("address") or _field("URL")
            title = _field("title")
            visits = _field("visits") or _field("visit_count") or "1"
            date_raw = _field("date") or _field("last_visit_time") or ""

            if not url or url == "NULL":
                continue

            # Convert milliseconds-since-epoch to readable date
            date_str = ""
            try:
                ts = int(date_raw)
                # Android stores in ms; detect by magnitude
                if ts > 1_000_000_000_000:
                    ts //= 1000
                date_str = datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                date_str = date_raw

            rows.append({
                "browser": browser, "url": url, "title": title,
                "visit_count": visits, "last_visit": date_str,
                "source": f"content://{uri}",
            })
        return rows

    CONTENT_PROVIDERS = [
        # Samsung Browser (works without root on Samsung devices)
        ("Samsung Browser",
         "com.sec.android.provider.browser/history",
         "url,title,date,visits"),
        # Stock Android browser (Android 4–5)
        ("Android Browser",
         "browser/history",
         "url,title,date,visits"),
        # Some OEM browsers expose this URI
        ("Browser (OEM)",
         "com.android.browser/history",
         "url,title,date,visits"),
        # Huawei browser
        ("Huawei Browser",
         "com.huawei.browser/browser_history",
         "url,title,date,visit_count"),
        # MIUI browser (Xiaomi)
        ("MIUI Browser",
         "com.android.browser/browser_history",
         "url,title,date,visit_count"),
    ]

    def _history_via_content_providers(self, callback=None) -> list:
        results = []
        for browser, uri, projection in self.CONTENT_PROVIDERS:
            if callback:
                callback(f"Querying {browser} content provider …")
            rc, out = self._shell(
                f"content query --uri content://{uri} --projection {projection} 2>/dev/null",
                timeout=20,
            )
            if rc == 0 and "Row:" in out:
                rows = self._parse_content_query_output(out, browser, uri)
                if rows:
                    results.extend(rows)
                    if callback:
                        callback(f"  {browser}: {len(rows)} URLs via content provider")
        return results

    # ------------------------------------------------------------------ #
    #  Method 2: Copy DB via run-as or root, then parse
    # ------------------------------------------------------------------ #

    def _history_via_db_pull(self, callback=None, rooted=False) -> list:
        results = []
        for browser, pkg, remote_path in self.BROWSER_DBS:
            if callback:
                callback(f"Trying DB pull: {browser} …")

            target_path = remote_path

            if not rooted:
                fname = remote_path.split("/")[-1]
                sdcard_path = f"/sdcard/.of_tmp_{fname}"

                # Try run-as (works for debuggable apps / some OEM builds)
                rc, _ = self._shell(
                    f"run-as {pkg} cp '{remote_path}' '{sdcard_path}' 2>/dev/null"
                )
                if rc == 0:
                    target_path = sdcard_path
                else:
                    # Try su copy (rooted but su not in id yet)
                    rc2, _ = self._shell(
                        f"su -c 'cp \"{remote_path}\" \"{sdcard_path}\"' 2>/dev/null"
                    )
                    if rc2 == 0:
                        target_path = sdcard_path
                    else:
                        continue  # can't access — skip

            with tempfile.TemporaryDirectory() as tmpdir:
                local = os.path.join(tmpdir, "db_file")
                if not self._pull(target_path, local):
                    continue
                if target_path.startswith("/sdcard"):
                    self._shell(f"rm -f '{target_path}' 2>/dev/null")

                if "firefox" in browser.lower():
                    rows = self._pull_and_parse_firefox(browser, local)
                    # pass local path directly, not remote
                    rows = self._parse_local_firefox(browser, local, remote_path)
                elif "samsung" in browser.lower():
                    rows = self._parse_local_samsung(browser, local, remote_path)
                else:
                    rows = self._parse_local_chromium(browser, local, remote_path)

                if rows:
                    results.extend(rows)
                    if callback:
                        callback(f"  {browser}: {len(rows)} URLs via DB pull")

        return results

    def _parse_local_chromium(self, browser, local_path, source) -> list:
        rows = []
        try:
            con = sqlite3.connect(local_path)
            con.row_factory = sqlite3.Row
            cur = con.cursor()
            cur.execute("""
                SELECT url, title, visit_count, last_visit_time
                FROM urls ORDER BY last_visit_time DESC LIMIT 2000
            """)
            for r in cur.fetchall():
                try:
                    ts = (r["last_visit_time"] - 11_644_473_600_000_000) / 1_000_000
                    date_str = datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
                except Exception:
                    date_str = "Unknown"
                rows.append({"browser": browser, "url": r["url"] or "",
                             "title": r["title"] or "",
                             "visit_count": r["visit_count"] or 0,
                             "last_visit": date_str, "source": source})
            con.close()
        except Exception as e:
            self.errors.append(f"{browser}: {e}")
        return rows

    def _parse_local_firefox(self, browser, local_path, source) -> list:
        rows = []
        try:
            con = sqlite3.connect(local_path)
            con.row_factory = sqlite3.Row
            cur = con.cursor()
            cur.execute("""
                SELECT p.url, p.title, p.visit_count, v.visit_date
                FROM moz_places p
                LEFT JOIN moz_historyvisits v ON p.id = v.place_id
                ORDER BY v.visit_date DESC LIMIT 2000
            """)
            for r in cur.fetchall():
                try:
                    date_str = datetime.fromtimestamp(
                        r["visit_date"] / 1_000_000).strftime("%Y-%m-%d %H:%M:%S")
                except Exception:
                    date_str = "Unknown"
                rows.append({"browser": browser, "url": r["url"] or "",
                             "title": r["title"] or "",
                             "visit_count": r["visit_count"] or 0,
                             "last_visit": date_str, "source": source})
            con.close()
        except Exception as e:
            self.errors.append(f"{browser}: {e}")
        return rows

    def _parse_local_samsung(self, browser, local_path, source) -> list:
        rows = []
        try:
            con = sqlite3.connect(local_path)
            con.row_factory = sqlite3.Row
            cur = con.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [r[0] for r in cur.fetchall()]
            for t in ["history", "visits", "url", "browser_history"]:
                if t in tables:
                    cur.execute(f"SELECT * FROM {t} LIMIT 2000")
                    for r in cur.fetchall():
                        d = dict(r)
                        rows.append({
                            "browser": browser,
                            "url": d.get("url", d.get("address", "")),
                            "title": d.get("title", ""),
                            "visit_count": d.get("visit_count", d.get("visits", 0)),
                            "last_visit": str(d.get("date", "")),
                            "source": source,
                        })
                    break
            con.close()
        except Exception as e:
            self.errors.append(f"{browser}: {e}")
        return rows

    # ------------------------------------------------------------------ #
    #  Method 3: Recent tasks / activity manager (no root)
    # ------------------------------------------------------------------ #

    def _history_via_recents(self, callback=None) -> list:
        """
        Parse 'dumpsys activity recents' and 'dumpsys activity activities'.
        Android stores recently opened URLs in the task stack — works
        on ALL devices without root.
        """
        if callback:
            callback("Scanning recent app tasks for URLs …")
        import re
        results = []
        seen = set()
        url_re = re.compile(r'https?://[^\s\'"<>{}\[\]]{6,}')

        for cmd in [
            "dumpsys activity recents 2>/dev/null",
            "dumpsys activity activities 2>/dev/null",
            "dumpsys activity top 2>/dev/null",
        ]:
            rc, out = self._shell(cmd, timeout=30)
            if rc != 0:
                continue
            for line in out.splitlines():
                for url in url_re.findall(line):
                    url = url.rstrip(".,;)\"'")
                    if url in seen or len(url) < 10:
                        continue
                    seen.add(url)
                    # Guess browser from surrounding context
                    browser = "Unknown"
                    ll = line.lower()
                    for b in ["chrome", "firefox", "brave", "opera",
                              "edge", "samsung", "browser"]:
                        if b in ll:
                            browser = b.capitalize()
                            break
                    results.append({
                        "browser": f"{browser} (recent tasks)",
                        "url": url, "title": "",
                        "visit_count": 1, "last_visit": "",
                        "source": "dumpsys activity",
                    })

        if callback and results:
            callback(f"  Recent tasks: {len(results)} URLs found")
        return results

    # ------------------------------------------------------------------ #
    #  Method 4: Logcat — capture URLs from live browser logs
    # ------------------------------------------------------------------ #

    def _history_via_logcat(self, callback=None) -> list:
        """
        Grab recent logcat and extract URLs. Works without root.
        Captures browser activity from the last few hours of usage.
        """
        if callback:
            callback("Scanning logcat for browser URLs …")
        import re
        results = []
        seen = set()
        url_re = re.compile(r'https?://[^\s\'"<>]{8,}')

        # Focus on browser-related log tags first, then fall back to full log
        for cmd in [
            "logcat -d -t 2000 -s chromium:* cr_Tab:* cr_BrowserStartup:* "
            "cr_BrowserActivity:* ActivityManager:* 2>/dev/null",
            "logcat -d -t 1000 2>/dev/null",
        ]:
            rc, out = self._shell(cmd, timeout=30)
            if rc != 0:
                continue
            for line in out.splitlines():
                for url in url_re.findall(line):
                    url = url.rstrip(".,;)\"'")
                    if url in seen:
                        continue
                    seen.add(url)
                    ts_m = re.match(r'(\d{2}-\d{2} \d{2}:\d{2}:\d{2})', line)
                    results.append({
                        "browser": "Logcat",
                        "url": url, "title": "",
                        "visit_count": 1,
                        "last_visit": ts_m.group(1) if ts_m else "",
                        "source": "adb logcat",
                    })
            if results:
                break  # stop if first targeted search worked

        if callback and results:
            callback(f"  Logcat: {len(results)} URLs found")
        return results

    # ------------------------------------------------------------------ #
    #  Method 5: Downloads folder inference
    # ------------------------------------------------------------------ #

    def _history_via_downloads(self, callback=None) -> list:
        """
        List files in Download folders. Downloaded files imply the URL
        they came from (shown as inferred source). No root needed.
        """
        if callback:
            callback("Scanning Downloads for file artifacts …")
        results = []
        for folder in ["/sdcard/Download", "/sdcard/Downloads",
                       "/storage/emulated/0/Download"]:
            rc, out = self._shell(f"ls -la {folder} 2>/dev/null")
            if rc != 0 or not out:
                continue
            for line in out.splitlines():
                parts = line.split()
                if len(parts) < 8 or parts[0].startswith("d"):
                    continue
                name = " ".join(parts[7:])
                size = parts[4] if len(parts) > 4 else ""
                date = f"{parts[5]} {parts[6]}" if len(parts) > 6 else ""
                results.append({
                    "browser": "Downloads",
                    "url": f"[Downloaded file] {name} ({size} bytes)",
                    "title": name, "visit_count": 1,
                    "last_visit": date,
                    "source": folder,
                })
        if callback and results:
            callback(f"  Downloads: {len(results)} files found")
        return results

    # ------------------------------------------------------------------ #
    #  Orchestrator
    # ------------------------------------------------------------------ #

    def _get_browser_history(self, callback=None) -> list:
        results = []
        seen_urls = set()
        rooted = self.is_rooted()
        if callback:
            callback(f"Device rooted: {'YES' if rooted else 'NO — using non-root extraction methods'}")

        def _merge(new_rows):
            for r in new_rows:
                url = r.get("url", "")
                if url and url not in seen_urls:
                    seen_urls.add(url)
                    results.append(r)

        # Method 1: Content providers (Samsung, stock browser, OEM)
        _merge(self._history_via_content_providers(callback))

        # Method 2: DB pull (root or run-as)
        _merge(self._history_via_db_pull(callback, rooted=rooted))

        # Method 3: Recent tasks / activity manager (works on ALL devices)
        _merge(self._history_via_recents(callback))

        # Method 4: Logcat URL scan
        _merge(self._history_via_logcat(callback))

        # Method 5: Downloads folder
        _merge(self._history_via_downloads(callback))

        # Clean up sdcard temp files
        self._shell("rm -f /sdcard/.of_tmp_* 2>/dev/null")

        if not results:
            results.append({
                "browser": "No data",
                "url": "⚠ No browser history accessible.",
                "title": "Root the device for full DB extraction, or browse something and scan again.",
                "visit_count": 0, "last_visit": "", "source": "adb",
            })
        elif callback:
            callback(f"Total Android browser records: {len(results)}")

        return results

    # ------------------------------------------------------------------ #
    #  File artifacts (sdcard — no root needed)
    # ------------------------------------------------------------------ #

    def _get_file_artifacts(self, callback=None) -> list:
        results = []
        if callback:
            callback("Scanning external storage …")

        dirs_to_scan = [
            "/sdcard/Download",
            "/sdcard/Downloads",
            "/sdcard/DCIM",
            "/sdcard/Documents",
            "/sdcard/WhatsApp",
        ]

        for d in dirs_to_scan:
            rc, out = self._shell(f"ls -la {d} 2>/dev/null")
            if rc != 0 or not out:
                continue
            for line in out.splitlines():
                parts = line.split()
                if len(parts) < 8:
                    continue
                perms = parts[0]
                if perms.startswith("d") or perms.startswith("l"):
                    continue  # skip dirs and symlinks
                name = " ".join(parts[7:])
                date_str = f"{parts[5]} {parts[6]}" if len(parts) > 6 else ""
                results.append({
                    "name":     name,
                    "type":     "External Storage File",
                    "accessed": date_str,
                    "path":     f"{d}/{name}",
                    "source":   "adb ls",
                })

        return results

    # ------------------------------------------------------------------ #
    #  Public API
    # ------------------------------------------------------------------ #

    def analyze(self, callback=None) -> dict:
        if not adb_available():
            msg = "ADB not found. Install Android Platform Tools and add to PATH."
            if callback:
                callback(f"ERROR: {msg}")
            return {"browser": [], "apps": [], "files": [], "errors": [msg],
                    "device": {}}

        devices = list_devices()
        if not devices:
            msg = ("No Android device detected. "
                   "Enable USB Debugging and connect via USB.")
            if callback:
                callback(f"ERROR: {msg}")
            return {"browser": [], "apps": [], "files": [], "errors": [msg],
                    "device": {}}

        device = devices[0]
        if callback:
            callback(f"Connected: {device.get('model', device['serial'])}")

        info    = self.device_info()
        rooted  = self.is_rooted()
        if callback:
            callback(f"Android {info.get('android_version','?')} | "
                     f"Root: {'YES' if rooted else 'NO'}")

        self.app_results     = self._get_packages(callback)
        self.browser_results = self._get_browser_history(callback)
        self.file_results    = self._get_file_artifacts(callback)

        return {
            "browser": self.browser_results,
            "apps":    self.app_results,
            "files":   self.file_results,
            "errors":  self.errors,
            "device":  {**device, **info, "rooted": rooted},
        }
