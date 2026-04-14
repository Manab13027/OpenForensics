@echo off
setlocal EnableDelayedExpansion
title OpenForensics — Educational Digital Forensics Tool

:: ============================================================
::  OpenForensics — Windows Startup Script
::  Checks / installs Python 3, then launches the app
:: ============================================================

cd /d "%~dp0"

echo.
echo   ██████  ██████  ███████ ███    ██ ███████  ██████  ██████  ███████
echo  ██    ██ ██   ██ ██      ████   ██ ██      ██    ██ ██   ██ ██
echo  ██    ██ ██████  █████   ██ ██  ██ █████   ██    ██ ██████  ███████
echo  ██    ██ ██      ██      ██  ██ ██ ██      ██    ██ ██   ██      ██
echo   ██████  ██      ███████ ██   ████ ██       ██████  ██   ██ ███████
echo.
echo   Educational Digital Forensics Tool  ^|  Windows
echo   ────────────────────────────────────────────────
echo.

:: ── 1. Find Python 3.8+ ──────────────────────────────────────────────────
set PYTHON=

:: Check common Python commands
for %%C in (python3.12 python3.11 python3.10 python3.9 python3.8 python3 python) do (
    where %%C >nul 2>&1
    if !errorlevel! == 0 (
        for /f "tokens=*" %%V in ('%%C -c "import sys; v=sys.version_info; print(v.major*100+v.minor)" 2^>nul') do (
            if %%V GEQ 308 (
                set PYTHON=%%C
                goto :found_python
            )
        )
    )
)

:: Check Windows Store / AppData installs
for %%P in (
    "%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
    "%LOCALAPPDATA%\Programs\Python\Python311\python.exe"
    "%LOCALAPPDATA%\Programs\Python\Python310\python.exe"
    "%LOCALAPPDATA%\Programs\Python\Python39\python.exe"
    "%LOCALAPPDATA%\Programs\Python\Python38\python.exe"
    "C:\Python312\python.exe"
    "C:\Python311\python.exe"
    "C:\Python310\python.exe"
    "C:\Program Files\Python312\python.exe"
    "C:\Program Files\Python311\python.exe"
) do (
    if exist %%P (
        set PYTHON=%%P
        goto :found_python
    )
)

:: Python not found — download and install
echo [WARNING] Python 3.8+ not found. Downloading installer...
echo.

set PYTHON_URL=https://www.python.org/ftp/python/3.12.8/python-3.12.8-amd64.exe
set PYTHON_INSTALLER=%TEMP%\python_installer.exe

:: Use PowerShell to download
powershell -NoProfile -Command ^
    "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; ^
     (New-Object Net.WebClient).DownloadFile('%PYTHON_URL%', '%PYTHON_INSTALLER%')"

if not exist "%PYTHON_INSTALLER%" (
    echo [ERROR] Download failed. Please install Python manually from:
    echo         https://www.python.org/downloads/windows/
    echo.
    pause
    exit /b 1
)

echo [OpenForensics] Running Python installer (select "Add to PATH" when prompted)...
"%PYTHON_INSTALLER%" /quiet InstallAllUsers=0 PrependPath=1 Include_tcltk=1
del /f /q "%PYTHON_INSTALLER%" 2>nul

:: Refresh PATH after install
for /f "tokens=*" %%P in ('powershell -NoProfile -Command ^
    "[Environment]::GetEnvironmentVariable(\"PATH\",\"User\")"') do (
    set "PATH=%%P;%PATH%"
)

:: Re-check
for %%C in (python3.12 python3 python) do (
    where %%C >nul 2>&1
    if !errorlevel! == 0 (
        set PYTHON=%%C
        goto :found_python
    )
)

echo [ERROR] Python installation may have succeeded but PATH not updated.
echo         Please restart this script, or run: python main.py
echo.
pause
exit /b 1

:found_python
for /f "tokens=*" %%V in ('!PYTHON! --version 2^>^&1') do (
    echo [OpenForensics] Found %%V
)

:: ── 2. Check tkinter ─────────────────────────────────────────────────────
!PYTHON! -c "import tkinter" >nul 2>&1
if errorlevel 1 (
    echo [WARNING] tkinter not found.
    echo           Please reinstall Python from https://www.python.org/downloads/windows/
    echo           and make sure "tcl/tk and IDLE" is checked during install.
    echo.
    pause
    exit /b 1
)
echo [OpenForensics] tkinter OK

:: ── 3. Check / install ADB ───────────────────────────────────────────────
where adb >nul 2>&1
if errorlevel 1 (
    :: Check local platform-tools folder
    if exist "%~dp0platform-tools\adb.exe" (
        set "PATH=%~dp0platform-tools;%PATH%"
        echo [OpenForensics] ADB found in local platform-tools folder
    ) else (
        echo [WARNING] ADB not found — the app will offer to install it on first launch.
    )
) else (
    for /f "tokens=*" %%A in ('adb version 2^>^&1 ^| findstr /i "version"') do (
        echo [OpenForensics] %%A
    )
)

:: ── 4. Check Windows version ──────────────────────────────────────────────
for /f "tokens=4-7 delims=[.] " %%i in ('ver') do (
    set WIN_VER=%%i.%%j
)
echo [OpenForensics] Windows %WIN_VER%

:: ── 5. Launch ─────────────────────────────────────────────────────────────
echo.
echo [OpenForensics] Launching...
echo.

!PYTHON! "%~dp0main.py"

:: If app exits with error, keep window open
if errorlevel 1 (
    echo.
    echo [ERROR] OpenForensics exited with an error (code %errorlevel%).
    echo         Check the output above for details.
    echo.
    pause
)
endlocal
