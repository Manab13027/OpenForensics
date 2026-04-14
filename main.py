"""
OpenForensics — Educational Digital Forensics Tool
===================================================
Supports: macOS · Windows · Ubuntu/Linux · Android (via ADB) · iPhone (via iTunes backup)

Run:  python main.py
Requires: Python 3.8+  (no third-party packages needed)

LEGAL NOTICE
------------
This tool is intended for digital forensics education and authorised
investigations only. Only analyse systems you own or have written
permission to examine.
"""

import os
import platform
import threading
import tkinter as tk
import webbrowser
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, ttk

from analyzers.android import AndroidAnalyzer, adb_available, list_devices, raw_devices_output
from analyzers.apps import AppAnalyzer
from analyzers.browser import BrowserAnalyzer
from analyzers.deleted_apps import DeletedAppAnalyzer, android_deleted_from_adb
from analyzers.files import FileAnalyzer
from analyzers.iphone import iPhoneAnalyzer, find_backups
from adb_setup import ensure_adb
from report import ReportGenerator


# ═══════════════════════════════════════════════════════════════════════════ #
#  Theme constants
# ═══════════════════════════════════════════════════════════════════════════ #

BG      = "#0d0d0d"
FG      = "#00ff41"
FG2     = "#00cc33"
FG3     = "#4488ff"   # blue accent for mobile
SEL_BG  = "#0a2a0a"
HDR_BG  = "#001800"
ENTRY   = "#111111"
RED     = "#ff5555"
AMBER   = "#ffaa00"
FONT    = ("Courier New", 11)
FONT_SM = ("Courier New", 9)


# ═══════════════════════════════════════════════════════════════════════════ #
#  Widget helpers
# ═══════════════════════════════════════════════════════════════════════════ #

def apply_dark_theme():
    """Apply a consistent dark theme to ALL ttk widgets."""
    style = ttk.Style()
    style.theme_use("clam")

    # Treeview
    style.configure("Treeview",
                    background=BG, foreground=FG,
                    fieldbackground=BG, rowheight=22, font=FONT_SM,
                    borderwidth=0)
    style.configure("Treeview.Heading",
                    background=HDR_BG, foreground=FG,
                    font=("Courier New", 9, "bold"), relief="flat",
                    borderwidth=1)
    style.map("Treeview",
              background=[("selected", SEL_BG)],
              foreground=[("selected", FG)])

    # Notebook
    style.configure("TNotebook",
                    background=BG, borderwidth=0, tabmargins=0)
    style.configure("TNotebook.Tab",
                    background=HDR_BG, foreground=FG,
                    font=FONT, padding=[10, 4],
                    borderwidth=0)
    style.map("TNotebook.Tab",
              background=[("selected", SEL_BG), ("active", "#0a1a0a")],
              foreground=[("selected", FG), ("active", FG)])

    # Combobox — prevents white field background
    style.configure("TCombobox",
                    fieldbackground=ENTRY, background=HDR_BG,
                    foreground=FG, selectbackground=SEL_BG,
                    selectforeground=FG, arrowcolor=FG,
                    borderwidth=1, relief="flat")
    style.map("TCombobox",
              fieldbackground=[("readonly", ENTRY), ("disabled", BG)],
              foreground=[("readonly", FG), ("disabled", "#444444")],
              selectbackground=[("readonly", SEL_BG)],
              selectforeground=[("readonly", FG)],
              background=[("active", HDR_BG)])

    # Scrollbars
    style.configure("TScrollbar",
                    background=HDR_BG, troughcolor=BG,
                    arrowcolor=FG, borderwidth=0,
                    relief="flat")
    style.map("TScrollbar",
              background=[("active", SEL_BG), ("pressed", FG2)])

    # Frame / LabelFrame
    style.configure("TFrame", background=BG)
    style.configure("TLabel", background=BG, foreground=FG)
    style.configure("TLabelframe",
                    background=BG, foreground=FG, borderwidth=1)
    style.configure("TLabelframe.Label", background=BG, foreground=FG)

    # Progressbar (used for any future additions)
    style.configure("TProgressbar",
                    background=FG2, troughcolor=HDR_BG,
                    borderwidth=0, thickness=6)


def _apply_tv_style():
    apply_dark_theme()


def make_treeview(parent, columns, widths):
    frame = tk.Frame(parent, bg=BG)
    frame.pack(fill="both", expand=True, padx=4, pady=4)

    sy = ttk.Scrollbar(frame, orient="vertical")
    sx = ttk.Scrollbar(frame, orient="horizontal")

    tv = ttk.Treeview(frame, columns=columns, show="headings",
                      yscrollcommand=sy.set, xscrollcommand=sx.set)
    _apply_tv_style()
    tv.tag_configure("removed", foreground=RED)
    tv.tag_configure("warn",    foreground=AMBER)
    tv.tag_configure("even",    background="#060f06")

    sy.config(command=tv.yview)
    sx.config(command=tv.xview)

    for col, w in zip(columns, widths):
        tv.heading(col, text=col.upper().replace("_", " "))
        tv.column(col, width=w, minwidth=40, anchor="w")

    sy.pack(side="right",  fill="y")
    sx.pack(side="bottom", fill="x")
    tv.pack(fill="both", expand=True)
    return tv


def populate(tv: ttk.Treeview, data: list, keys: list):
    tv.delete(*tv.get_children())
    for i, row in enumerate(data):
        values = [str(row.get(k, "")) for k in keys]
        if row.get("status") == "Removed":
            tag = "removed"
        elif "⚠" in str(row.get("url", "")) or "⚠" in str(row.get("name", "")):
            tag = "warn"
        else:
            tag = "even" if i % 2 == 0 else ""
        tv.insert("", "end", values=values, tags=(tag,))


def labeled_frame(parent, label, fg=FG2):
    lf = tk.LabelFrame(parent, text=f"  {label}  ",
                        bg=BG, fg=fg, font=FONT,
                        bd=1, relief="groove",
                        labelanchor="nw")
    return lf


# ═══════════════════════════════════════════════════════════════════════════ #
#  Main window
# ═══════════════════════════════════════════════════════════════════════════ #

class OpenForensicsApp:

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("OpenForensics v1.2 — Educational Digital Forensics Tool")
        self.root.configure(bg=BG)
        self.root.geometry("1280x820")
        self.root.minsize(960, 640)

        # Apply full dark theme before any widgets are created
        apply_dark_theme()

        # Fix Combobox dropdown list (Listbox) colours — must be done via option_add
        self.root.option_add("*TCombobox*Listbox.background",    ENTRY)
        self.root.option_add("*TCombobox*Listbox.foreground",    FG)
        self.root.option_add("*TCombobox*Listbox.selectBackground", SEL_BG)
        self.root.option_add("*TCombobox*Listbox.selectForeground", FG)
        self.root.option_add("*TCombobox*Listbox.font",          FONT_SM)

        # Data stores
        self.browser_data:  list = []
        self.app_data:      list = []
        self.file_data:     list = []
        self.deleted_data:  list = []
        self.droid_data:    dict = {}
        self.ios_data:      dict = {}
        self.scan_target          = "Local Machine"

        self._build_ui()
        self._refresh_mobile_status()

        # Auto-install ADB on first run (after window is visible)
        self.root.after(800, self._check_and_install_adb)

    # ------------------------------------------------------------------ #
    #  UI
    # ------------------------------------------------------------------ #

    def _build_ui(self):
        # ── Top bar ──────────────────────────────────────────────────────
        top = tk.Frame(self.root, bg=BG)
        top.pack(fill="x", padx=12, pady=(12, 0))
        tk.Label(top, text="OpenForensics",
                 font=("Courier New", 18, "bold"), bg=BG, fg=FG).pack(side="left")
        tk.Label(top, text="  Educational Digital Forensics Tool  v1.1",
                 font=FONT, bg=BG, fg=FG2).pack(side="left")
        tk.Label(top, text=f"[{platform.system()} {platform.release()}]",
                 font=FONT_SM, bg=BG, fg="#334433").pack(side="right")

        # ── Local scan controls ──────────────────────────────────────────
        ctrl = tk.Frame(self.root, bg=BG, bd=1, relief="groove")
        ctrl.pack(fill="x", padx=12, pady=(8, 2))

        tk.Label(ctrl, text="LOCAL TARGET:", font=FONT, bg=BG, fg=FG).pack(side="left", padx=8)
        self.target_var = tk.StringVar(value="local")
        tk.Radiobutton(ctrl, text="This Machine", variable=self.target_var,
                       value="local", bg=BG, fg=FG, selectcolor=HDR_BG,
                       activebackground=BG, font=FONT).pack(side="left", padx=4)
        tk.Radiobutton(ctrl, text="Custom Path (forensic copy / disk mount)",
                       variable=self.target_var, value="custom",
                       bg=BG, fg=FG, selectcolor=HDR_BG,
                       activebackground=BG, font=FONT).pack(side="left", padx=4)

        self.path_entry = tk.Entry(ctrl, width=30, bg=ENTRY, fg=FG,
                                   insertbackground=FG, font=FONT)
        self.path_entry.pack(side="left", padx=4)
        tk.Button(ctrl, text="Browse…", bg=HDR_BG, fg=FG, font=FONT,
                  relief="flat", cursor="hand2",
                  command=self._browse_path).pack(side="left", padx=2)

        self.scan_btn = tk.Button(ctrl, text="▶  SCAN LOCAL",
                                  bg="#004400", fg=FG,
                                  font=("Courier New", 11, "bold"),
                                  relief="flat", cursor="hand2", padx=10,
                                  command=self._run_local_scan)
        self.scan_btn.pack(side="right", padx=8)

        tk.Button(ctrl, text="Export HTML Report", bg=HDR_BG, fg=FG2,
                  font=FONT, relief="flat", cursor="hand2",
                  command=self._export_report).pack(side="right", padx=4)

        # ── Android controls ─────────────────────────────────────────────
        droid_ctrl = tk.Frame(self.root, bg=BG, bd=1, relief="groove")
        droid_ctrl.pack(fill="x", padx=12, pady=2)

        tk.Label(droid_ctrl, text="ANDROID (ADB):", font=FONT,
                 bg=BG, fg=FG3).pack(side="left", padx=8)

        self.adb_status_var = tk.StringVar(value="Checking ADB …")
        tk.Label(droid_ctrl, textvariable=self.adb_status_var,
                 font=FONT_SM, bg=BG, fg=AMBER).pack(side="left", padx=6)

        self.device_var = tk.StringVar(value="")
        self.device_menu = ttk.Combobox(droid_ctrl, textvariable=self.device_var,
                                        width=28, font=FONT_SM, state="readonly")
        self.device_menu.pack(side="left", padx=4)

        tk.Button(droid_ctrl, text="↺ Refresh", bg=HDR_BG, fg=FG3,
                  font=FONT_SM, relief="flat", cursor="hand2",
                  command=self._refresh_mobile_status).pack(side="left", padx=2)

        tk.Button(droid_ctrl, text="⚙ Diagnose", bg=HDR_BG, fg=AMBER,
                  font=FONT_SM, relief="flat", cursor="hand2",
                  command=self._diagnose_adb).pack(side="left", padx=2)

        self.droid_btn = tk.Button(droid_ctrl, text="▶  SCAN ANDROID",
                                   bg="#001833", fg=FG3,
                                   font=("Courier New", 11, "bold"),
                                   relief="flat", cursor="hand2", padx=10,
                                   command=self._run_android_scan)
        self.droid_btn.pack(side="right", padx=8)

        # ── iPhone controls ──────────────────────────────────────────────
        ios_ctrl = tk.Frame(self.root, bg=BG, bd=1, relief="groove")
        ios_ctrl.pack(fill="x", padx=12, pady=(2, 6))

        tk.Label(ios_ctrl, text="iPHONE (iTunes Backup):", font=FONT,
                 bg=BG, fg=FG3).pack(side="left", padx=8)

        self.backup_var = tk.StringVar(value="")
        self.backup_menu = ttk.Combobox(ios_ctrl, textvariable=self.backup_var,
                                        width=50, font=FONT_SM, state="readonly")
        self.backup_menu.pack(side="left", padx=4)

        tk.Button(ios_ctrl, text="Browse backup…", bg=HDR_BG, fg=FG3,
                  font=FONT_SM, relief="flat", cursor="hand2",
                  command=self._browse_backup).pack(side="left", padx=2)

        self.ios_btn = tk.Button(ios_ctrl, text="▶  SCAN iPHONE",
                                 bg="#001833", fg=FG3,
                                 font=("Courier New", 11, "bold"),
                                 relief="flat", cursor="hand2", padx=10,
                                 command=self._run_ios_scan)
        self.ios_btn.pack(side="right", padx=8)

        self.ios_status_var = tk.StringVar(value="")
        tk.Label(ios_ctrl, textvariable=self.ios_status_var,
                 font=FONT_SM, bg=BG, fg=AMBER).pack(side="right", padx=6)

        # ── Notebook ─────────────────────────────────────────────────────
        nb = ttk.Notebook(self.root)
        nb.pack(fill="both", expand=True, padx=12, pady=(0, 4))

        # Tab: Browser History (all sources)
        self.tab_browser = tk.Frame(nb, bg=BG)
        nb.add(self.tab_browser, text="  Browser History  ")
        self.browser_count = tk.StringVar(value="Browser History  [0 records]")
        tk.Label(self.tab_browser, textvariable=self.browser_count,
                 font=FONT, bg=BG, fg=FG2).pack(anchor="w", padx=6, pady=(6, 0))
        self.browser_tv = make_treeview(
            self.tab_browser,
            ["browser", "profile", "last_visit", "url", "title", "visit_count"],
            [90, 90, 140, 360, 200, 60],
        )

        # Tab: Applications
        self.tab_apps = tk.Frame(nb, bg=BG)
        nb.add(self.tab_apps, text="  Applications  ")
        self.apps_count = tk.StringVar(value="Applications  [0 records]")
        tk.Label(self.tab_apps, textvariable=self.apps_count,
                 font=FONT, bg=BG, fg=FG2).pack(anchor="w", padx=6, pady=(6, 0))
        self.apps_tv = make_treeview(
            self.tab_apps,
            ["name", "version", "publisher", "install_date", "status", "source"],
            [240, 100, 160, 130, 90, 140],
        )

        # Tab: File Artifacts
        self.tab_files = tk.Frame(nb, bg=BG)
        nb.add(self.tab_files, text="  File Artifacts  ")
        self.files_count = tk.StringVar(value="File Artifacts  [0 records]")
        tk.Label(self.tab_files, textvariable=self.files_count,
                 font=FONT, bg=BG, fg=FG2).pack(anchor="w", padx=6, pady=(6, 0))
        self.files_tv = make_treeview(
            self.tab_files,
            ["name", "type", "accessed", "path", "source"],
            [200, 180, 140, 360, 140],
        )

        # Tab: Deleted Apps
        self.tab_deleted = tk.Frame(nb, bg=BG)
        nb.add(self.tab_deleted, text="  Deleted Apps  ")

        del_top = tk.Frame(self.tab_deleted, bg=BG)
        del_top.pack(fill="x", padx=6, pady=(6, 2))

        self.deleted_count = tk.StringVar(value="Deleted / Uninstalled Apps  [0 records]")
        tk.Label(del_top, textvariable=self.deleted_count,
                 font=FONT, bg=BG, fg=RED).pack(side="left")

        tk.Label(del_top,
                 text="  Sources: package logs · MuiCache · UserAssist · Prefetch · Trash · Spotlight · install.log",
                 font=FONT_SM, bg=BG, fg="#555555").pack(side="left", padx=8)

        self.deleted_tv = make_treeview(
            self.tab_deleted,
            ["name", "version", "removed_date", "install_date", "reason", "source", "platform"],
            [200, 80, 140, 120, 280, 180, 80],
        )

        # Tab: Android
        self.tab_android = tk.Frame(nb, bg=BG)
        nb.add(self.tab_android, text="  Android  ")

        android_nb = ttk.Notebook(self.tab_android)
        android_nb.pack(fill="both", expand=True)

        sub_droid_browser = tk.Frame(android_nb, bg=BG)
        android_nb.add(sub_droid_browser, text=" Browser History ")
        self.droid_browser_count = tk.StringVar(value="[0 records]")
        tk.Label(sub_droid_browser, textvariable=self.droid_browser_count,
                 font=FONT_SM, bg=BG, fg=FG3).pack(anchor="w", padx=6, pady=(4, 0))
        self.droid_browser_tv = make_treeview(
            sub_droid_browser,
            ["browser", "url", "title", "visit_count", "last_visit", "source"],
            [100, 380, 200, 60, 140, 180],
        )

        sub_droid_apps = tk.Frame(android_nb, bg=BG)
        android_nb.add(sub_droid_apps, text=" Installed Apps ")
        self.droid_apps_count = tk.StringVar(value="[0 records]")
        tk.Label(sub_droid_apps, textvariable=self.droid_apps_count,
                 font=FONT_SM, bg=BG, fg=FG3).pack(anchor="w", padx=6, pady=(4, 0))
        self.droid_apps_tv = make_treeview(
            sub_droid_apps,
            ["name", "install_date", "installer", "status", "apk_path"],
            [260, 160, 180, 90, 300],
        )

        sub_droid_files = tk.Frame(android_nb, bg=BG)
        android_nb.add(sub_droid_files, text=" File Artifacts ")
        self.droid_files_count = tk.StringVar(value="[0 records]")
        tk.Label(sub_droid_files, textvariable=self.droid_files_count,
                 font=FONT_SM, bg=BG, fg=FG3).pack(anchor="w", padx=6, pady=(4, 0))
        self.droid_files_tv = make_treeview(
            sub_droid_files,
            ["name", "type", "accessed", "path", "source"],
            [200, 160, 120, 360, 120],
        )

        # Tab: iPhone
        self.tab_ios = tk.Frame(nb, bg=BG)
        nb.add(self.tab_ios, text="  iPhone  ")

        ios_nb = ttk.Notebook(self.tab_ios)
        ios_nb.pack(fill="both", expand=True)

        sub_ios_browser = tk.Frame(ios_nb, bg=BG)
        ios_nb.add(sub_ios_browser, text=" Browser History ")
        self.ios_browser_count = tk.StringVar(value="[0 records]")
        tk.Label(sub_ios_browser, textvariable=self.ios_browser_count,
                 font=FONT_SM, bg=BG, fg=FG3).pack(anchor="w", padx=6, pady=(4, 0))
        self.ios_browser_tv = make_treeview(
            sub_ios_browser,
            ["browser", "url", "title", "visit_count", "last_visit", "source"],
            [100, 380, 200, 60, 140, 180],
        )

        sub_ios_apps = tk.Frame(ios_nb, bg=BG)
        ios_nb.add(sub_ios_apps, text=" Installed Apps ")
        self.ios_apps_count = tk.StringVar(value="[0 records]")
        tk.Label(sub_ios_apps, textvariable=self.ios_apps_count,
                 font=FONT_SM, bg=BG, fg=FG3).pack(anchor="w", padx=6, pady=(4, 0))
        self.ios_apps_tv = make_treeview(
            sub_ios_apps,
            ["name", "version", "publisher", "install_date", "status", "source"],
            [300, 80, 140, 120, 140, 120],
        )

        sub_ios_files = tk.Frame(ios_nb, bg=BG)
        ios_nb.add(sub_ios_files, text=" File Artifacts ")
        self.ios_files_count = tk.StringVar(value="[0 records]")
        tk.Label(sub_ios_files, textvariable=self.ios_files_count,
                 font=FONT_SM, bg=BG, fg=FG3).pack(anchor="w", padx=6, pady=(4, 0))
        self.ios_files_tv = make_treeview(
            sub_ios_files,
            ["name", "type", "accessed", "path", "source"],
            [200, 160, 120, 360, 160],
        )

        # Tab: Scan Log
        self.tab_log = tk.Frame(nb, bg=BG)
        nb.add(self.tab_log, text="  Scan Log  ")
        self.log_box = scrolledtext.ScrolledText(
            self.tab_log, bg=BG, fg=FG2, font=FONT_SM,
            insertbackground=FG, state="disabled", wrap="word",
        )
        self.log_box.pack(fill="both", expand=True, padx=4, pady=4)

        # ── Status bar ───────────────────────────────────────────────────
        bar = tk.Frame(self.root, bg=HDR_BG)
        bar.pack(fill="x", side="bottom")
        self.status_var = tk.StringVar(value="Ready.")
        tk.Label(bar, textvariable=self.status_var, font=FONT_SM,
                 bg=HDR_BG, fg=FG2, anchor="w").pack(side="left", padx=8, pady=3)
        tk.Label(bar, text="EDUCATIONAL USE ONLY — always obtain proper authorisation",
                 font=FONT_SM, bg=HDR_BG, fg="#334433").pack(side="right", padx=8)

    # ------------------------------------------------------------------ #
    #  Mobile status helpers
    # ------------------------------------------------------------------ #

    def _diagnose_adb(self):
        """Show a popup with raw ADB output and fix instructions."""
        import tkinter.simpledialog as sd
        threading.Thread(target=self._diagnose_worker, daemon=True).start()

    def _diagnose_worker(self):
        from adb_setup import adb_path, adb_on_path
        lines = []
        lines.append(f"ADB binary  : {adb_path()}")
        lines.append(f"ADB on PATH : {adb_on_path()}")
        lines.append("")
        lines.append("── adb devices -l output ──")
        raw = raw_devices_output()
        lines.append(raw if raw else "(no output)")
        lines.append("")

        # Interpret state
        if "unauthorized" in raw:
            lines.append("STATUS: UNAUTHORIZED")
            lines.append("FIX:")
            lines.append("  1. Look at your phone screen — a dialog should appear:")
            lines.append('     "Allow USB debugging?" → tap ALLOW')
            lines.append("  2. Tick 'Always allow from this computer'")
            lines.append("  3. Click ↺ Refresh in the app")
        elif "offline" in raw:
            lines.append("STATUS: OFFLINE")
            lines.append("FIX:")
            lines.append("  1. Unplug and replug the USB cable")
            lines.append("  2. On phone: change USB mode to 'File Transfer (MTP)'")
            lines.append("  3. Click ↺ Refresh in the app")
        elif "List of devices attached" in raw and raw.strip().endswith("attached"):
            lines.append("STATUS: NO DEVICES DETECTED")
            lines.append("FIX:")
            lines.append("  1. Enable Developer Options on phone:")
            lines.append("     Settings → About Phone → tap Build Number 7 times")
            lines.append("  2. Enable USB Debugging:")
            lines.append("     Settings → Developer Options → USB Debugging → ON")
            lines.append("  3. Change USB mode to 'File Transfer (MTP)'")
            lines.append("  4. Plug in USB cable and click ↺ Refresh")
        elif not adb_on_path():
            lines.append("STATUS: ADB NOT INSTALLED")
            lines.append("FIX: Click ↺ Refresh — the app will offer to install ADB")
        else:
            lines.append("STATUS: DEVICE READY")

        msg = "\n".join(lines)
        self.root.after(0, lambda: messagebox.showinfo("ADB Diagnostics", msg))

    def _check_and_install_adb(self):
        """Run on startup — silently skip if ADB already present, offer install if not."""
        if adb_available():
            return
        threading.Thread(target=self._adb_install_worker, daemon=True).start()

    def _adb_install_worker(self):
        def _log(msg):
            self._log(f"[ADB Setup] {msg}")
        ok = ensure_adb(log=_log, ask_user=True)
        if ok:
            self._after(lambda: (
                self.adb_status_var.set("ADB installed — connect a device and click Refresh"),
                self._refresh_mobile_status(),
            ))

    def _refresh_mobile_status(self):
        threading.Thread(target=self._check_mobile, daemon=True).start()

    def _check_mobile(self):
        # ADB / Android
        if adb_available():
            devices = list_devices()
            ready    = [d for d in devices if d["state"] == "ready"]
            problem  = [d for d in devices if d["state"] != "ready"]

            if ready:
                opts = [f"{d['model']} ({d['serial']})" for d in ready]
                self._after(lambda: (
                    self.adb_status_var.set(f"{len(ready)} device(s) ready"),
                    self.device_menu.config(values=opts),
                    self.device_menu.current(0),
                ))
            elif problem:
                state = problem[0]["state"].upper()
                hint = ("Check phone screen — tap ALLOW on USB debugging dialog"
                        if state == "UNAUTHORIZED"
                        else "Replug USB cable and set mode to File Transfer")
                opts = [d["model"] for d in problem]
                self._after(lambda: (
                    self.adb_status_var.set(f"Device {state} — {hint}"),
                    self.device_menu.config(values=opts),
                    self.device_menu.current(0),
                ))
            else:
                self._after(lambda: (
                    self.adb_status_var.set("ADB ready — no device connected. Enable USB Debugging on phone."),
                    self.device_menu.config(values=[]),
                ))
        else:
            self._after(lambda: (
                self.adb_status_var.set("ADB not found — install Android Platform Tools"),
                self.device_menu.config(values=[]),
            ))

        # iTunes backups / iPhone
        backups = find_backups()
        if backups:
            opts = [
                f"{b.get('device_name','Unknown')} iOS {b.get('ios_version','?')} "
                f"| {b.get('backup_date','')[:10]} "
                f"{'[ENCRYPTED]' if b['encrypted'] else ''} | {b['udid'][:8]}…"
                for b in backups
            ]
            self._backup_paths = [b["path"] for b in backups]
            self._after(lambda: (
                self.backup_menu.config(values=opts),
                self.backup_menu.current(0),
                self.ios_status_var.set(f"{len(backups)} backup(s) found"),
            ))
        else:
            self._backup_paths = []
            self._after(lambda: (
                self.backup_menu.config(values=["No backups found"]),
                self.ios_status_var.set("No iTunes backups found on this machine"),
            ))

    def _after(self, fn):
        self.root.after(0, fn)

    # ------------------------------------------------------------------ #
    #  Logging
    # ------------------------------------------------------------------ #

    def _log(self, msg: str):
        def _do():
            self.log_box.config(state="normal")
            self.log_box.insert("end",
                f"[{datetime.now().strftime('%H:%M:%S')}]  {msg}\n")
            self.log_box.see("end")
            self.log_box.config(state="disabled")
            self.status_var.set(msg[:120])
        self.root.after(0, _do)

    # ------------------------------------------------------------------ #
    #  Local scan
    # ------------------------------------------------------------------ #

    def _browse_path(self):
        p = filedialog.askdirectory(title="Select forensic copy / mounted image root")
        if p:
            self.path_entry.delete(0, "end")
            self.path_entry.insert(0, p)
            self.target_var.set("custom")

    def _run_local_scan(self):
        self.scan_btn.config(state="disabled", text="…scanning…")
        if self.target_var.get() == "custom":
            cp = self.path_entry.get().strip()
            if not cp or not Path(cp).is_dir():
                messagebox.showerror("Invalid path",
                                     "Select a valid directory for the forensic copy.")
                self.scan_btn.config(state="normal", text="▶  SCAN LOCAL")
                return
            base_path = cp
            self.scan_target = cp
        else:
            base_path = None
            self.scan_target = "Local Machine"
        threading.Thread(target=self._local_worker, args=(base_path,),
                         daemon=True).start()

    def _local_worker(self, base_path):
        try:
            self._log("Locating browser databases …")
            ba = BrowserAnalyzer(base_path)
            self.browser_data = ba.analyze(callback=self._log)
            self._log(f"Browser: {len(self.browser_data)} records.")

            aa = AppAnalyzer()
            self.app_data = aa.analyze(callback=self._log)
            self._log(f"Apps: {len(self.app_data)} records.")

            fa = FileAnalyzer()
            self.file_data = fa.analyze(callback=self._log)
            self._log(f"Files: {len(self.file_data)} records.")

            da = DeletedAppAnalyzer()
            self.deleted_data = da.analyze(
                callback=self._log, existing_app_data=self.app_data)
            self._log(f"Deleted apps: {len(self.deleted_data)} records.")

            self.root.after(0, self._update_local_ui)
        except Exception as e:
            self._log(f"Local scan error: {e}")
            self.root.after(0, lambda: self.scan_btn.config(
                state="normal", text="▶  SCAN LOCAL"))

    def _update_local_ui(self):
        populate(self.browser_tv, self.browser_data,
                 ["browser", "profile", "last_visit", "url", "title", "visit_count"])
        populate(self.apps_tv, self.app_data,
                 ["name", "version", "publisher", "install_date", "status", "source"])
        populate(self.files_tv, self.file_data,
                 ["name", "type", "accessed", "path", "source"])
        populate(self.deleted_tv, self.deleted_data,
                 ["name", "version", "removed_date", "install_date",
                  "reason", "source", "platform"])
        self.browser_count.set(f"Browser History  [{len(self.browser_data)} records]")
        self.apps_count.set(f"Applications  [{len(self.app_data)} records]")
        self.files_count.set(f"File Artifacts  [{len(self.file_data)} records]")
        self.deleted_count.set(
            f"Deleted / Uninstalled Apps  [{len(self.deleted_data)} records]")
        self.scan_btn.config(state="normal", text="▶  SCAN LOCAL")
        self._log("Local scan complete.")

    # ------------------------------------------------------------------ #
    #  Android scan
    # ------------------------------------------------------------------ #

    def _run_android_scan(self):
        sel = self.device_var.get()
        # Block scan if device is unauthorized/offline
        if "UNAUTHORIZED" in sel or "OFFLINE" in sel or not sel:
            messagebox.showwarning(
                "Device not ready",
                "Device is not authorised for debugging.\n\n"
                "1. Look at your phone — tap ALLOW on the USB debugging dialog\n"
                "2. Tick 'Always allow from this computer'\n"
                "3. Click ↺ Refresh, then try again\n\n"
                "Click ⚙ Diagnose for more details."
            )
            return
        self.droid_btn.config(state="disabled", text="…scanning…")
        serial = None
        if "(" in sel and ")" in sel:
            serial = sel.split("(")[-1].rstrip(")")
        threading.Thread(target=self._android_worker, args=(serial,),
                         daemon=True).start()

    def _android_worker(self, serial):
        try:
            self._log(f"Starting Android scan (serial={serial or 'auto'}) …")
            aa = AndroidAnalyzer(serial)
            result = aa.analyze(callback=self._log)
            self.droid_data = result
            # Merge Android deleted apps into deleted tab
            droid_deleted = android_deleted_from_adb(serial)
            if droid_deleted:
                self.deleted_data.extend(droid_deleted)
                self._log(f"Android deleted apps: {len(droid_deleted)} entries.")
            self.root.after(0, self._update_android_ui)
        except Exception as e:
            self._log(f"Android scan error: {e}")
            self.root.after(0, lambda: self.droid_btn.config(
                state="normal", text="▶  SCAN ANDROID"))

    def _update_android_ui(self):
        b = self.droid_data.get("browser", [])
        a = self.droid_data.get("apps",    [])
        f = self.droid_data.get("files",   [])
        populate(self.droid_browser_tv, b,
                 ["browser", "url", "title", "visit_count", "last_visit", "source"])
        populate(self.droid_apps_tv,    a,
                 ["name", "install_date", "installer", "status", "apk_path"])
        populate(self.droid_files_tv,   f,
                 ["name", "type", "accessed", "path", "source"])
        self.droid_browser_count.set(f"[{len(b)} records]")
        self.droid_apps_count.set(f"[{len(a)} records]")
        self.droid_files_count.set(f"[{len(f)} records]")
        populate(self.deleted_tv, self.deleted_data,
                 ["name", "version", "removed_date", "install_date",
                  "reason", "source", "platform"])
        self.deleted_count.set(
            f"Deleted / Uninstalled Apps  [{len(self.deleted_data)} records]")
        self.droid_btn.config(state="normal", text="▶  SCAN ANDROID")
        dev = self.droid_data.get("device", {})
        self._log(
            f"Android scan complete — "
            f"{dev.get('manufacturer','')} {dev.get('model','')} "
            f"Android {dev.get('android_version','?')} "
            f"| Root: {'YES' if dev.get('rooted') else 'NO'}"
        )

    # ------------------------------------------------------------------ #
    #  iPhone scan
    # ------------------------------------------------------------------ #

    def _browse_backup(self):
        p = filedialog.askdirectory(title="Select iTunes backup folder (contains Manifest.db)")
        if p:
            cur_vals = list(self.backup_menu["values"])
            cur_vals.insert(0, p)
            if not hasattr(self, "_backup_paths"):
                self._backup_paths = []
            self._backup_paths.insert(0, p)
            self.backup_menu.config(values=cur_vals)
            self.backup_menu.current(0)

    def _run_ios_scan(self):
        idx = self.backup_menu.current()
        if idx < 0 or not hasattr(self, "_backup_paths") or not self._backup_paths:
            messagebox.showinfo("No backup", "No iTunes backup selected.")
            return
        backup_path = self._backup_paths[idx]
        self.ios_btn.config(state="disabled", text="…scanning…")
        threading.Thread(target=self._ios_worker, args=(backup_path,),
                         daemon=True).start()

    def _ios_worker(self, backup_path):
        try:
            self._log(f"Scanning iPhone backup: {backup_path} …")
            ia = iPhoneAnalyzer(backup_path)
            result = ia.analyze(callback=self._log)
            self.ios_data = result
            self.root.after(0, self._update_ios_ui)
        except Exception as e:
            self._log(f"iPhone scan error: {e}")
            self.root.after(0, lambda: self.ios_btn.config(
                state="normal", text="▶  SCAN iPHONE"))

    def _update_ios_ui(self):
        b = self.ios_data.get("browser", [])
        a = self.ios_data.get("apps",    [])
        f = self.ios_data.get("files",   [])
        populate(self.ios_browser_tv, b,
                 ["browser", "url", "title", "visit_count", "last_visit", "source"])
        populate(self.ios_apps_tv,    a,
                 ["name", "version", "publisher", "install_date", "status", "source"])
        populate(self.ios_files_tv,   f,
                 ["name", "type", "accessed", "path", "source"])
        self.ios_browser_count.set(f"[{len(b)} records]")
        self.ios_apps_count.set(f"[{len(a)} records]")
        self.ios_files_count.set(f"[{len(f)} records]")
        self.ios_btn.config(state="normal", text="▶  SCAN iPHONE")
        errs = self.ios_data.get("errors", [])
        if errs:
            self._log(f"iPhone warnings: {'; '.join(errs[:3])}")
        self._log(f"iPhone scan complete — "
                  f"Browser: {len(b)}, Apps: {len(a)}, Files: {len(f)}")

    # ------------------------------------------------------------------ #
    #  Export
    # ------------------------------------------------------------------ #

    def _export_report(self):
        all_browser = (self.browser_data
                       + self.droid_data.get("browser", [])
                       + self.ios_data.get("browser",   []))
        all_apps    = (self.app_data
                       + self.droid_data.get("apps",    [])
                       + self.ios_data.get("apps",      []))
        all_files   = (self.file_data
                       + self.droid_data.get("files",   [])
                       + self.ios_data.get("files",     []))

        if not (all_browser or all_apps or all_files or self.deleted_data):
            messagebox.showinfo("No data", "Run a scan first.")
            return

        ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
        out = filedialog.asksaveasfilename(
            defaultextension=".html",
            initialfile=f"forensics_report_{ts}.html",
            filetypes=[("HTML Report", "*.html"), ("All Files", "*.*")],
            title="Save Forensic Report",
        )
        if not out:
            return

        gen = ReportGenerator(all_browser, all_apps, all_files, self.scan_target,
                              deleted=self.deleted_data)
        gen.generate(out)
        self._log(f"Report saved → {out}")
        if messagebox.askyesno("Saved", f"Report saved.\n\nOpen in browser?"):
            webbrowser.open(Path(out).as_uri())


# ═══════════════════════════════════════════════════════════════════════════ #
#  Entry point
# ═══════════════════════════════════════════════════════════════════════════ #

if __name__ == "__main__":
    root = tk.Tk()
    OpenForensicsApp(root)
    root.mainloop()
