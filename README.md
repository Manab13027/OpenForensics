# OpenForensics

An **educational digital-forensics toolkit** with a dark-themed desktop GUI. It
inspects a computer or connected mobile device and surfaces forensic artifacts —
files, installed and deleted apps, and browser data — then compiles a report.
Runs on macOS, Windows and Linux, and can examine Android devices over ADB and
iPhone data from iTunes backups. Pure standard-library Python (no third-party
packages).

## Features
- Analyzers for files, apps, **deleted apps**, and browsers
- **Android** acquisition over ADB (bundled platform-tools); **iPhone** via
  iTunes backups
- One-click report generation (`report.py`)
- Cross-platform launchers (`start_mac.sh`, `start_ubuntu.sh`, `start_windows.bat`)

## Stack
Python (standard library) · Tkinter · ADB

## Getting started
```bash
python main.py
```

## Notes
> **Legal:** for forensics education and **authorised** investigations only.
> Only analyse systems you own or have written permission to examine.
