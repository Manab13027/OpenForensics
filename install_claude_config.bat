@echo off
setlocal EnableDelayedExpansion
title Claude Code Environment Installer — Windows

:: ============================================================
::  Claude Code Environment Installer (Windows)
::  Run as the target user or as Administrator for other users
:: ============================================================

echo.
echo   Claude Code Environment Installer
echo   ──────────────────────────────────
echo   User       : %USERNAME%
echo   Claude dir : %USERPROFILE%\.claude
echo.

set CLAUDE_DIR=%USERPROFILE%\.claude
set MEM_DIR=%CLAUDE_DIR%\mem
set SCRIPT_DIR=%~dp0

:: ── Create directory structure ────────────────────────────────────────────
if not exist "%CLAUDE_DIR%" mkdir "%CLAUDE_DIR%"
if not exist "%MEM_DIR%"    mkdir "%MEM_DIR%"
if not exist "%MEM_DIR%\sessions" mkdir "%MEM_DIR%\sessions"
echo [install] Directories created

:: ── Find Python ───────────────────────────────────────────────────────────
set PYTHON=
for %%C in (python3 python) do (
    where %%C >nul 2>&1 && set PYTHON=%%C && goto :python_found
)
for %%P in (
    "%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
    "%LOCALAPPDATA%\Programs\Python\Python311\python.exe"
    "C:\Python312\python.exe"
    "C:\Python311\python.exe"
) do (
    if exist %%P ( set PYTHON=%%P && goto :python_found )
)
echo [warn] Python not found — memory CLI will not be available
set PYTHON=python
:python_found

:: ── Install CLAUDE.md ─────────────────────────────────────────────────────
set SRC_MD=%USERPROFILE%\.claude\CLAUDE.md
if exist "%SRC_MD%" (
    echo [install] CLAUDE.md already in place
) else (
    :: If running from a machine where the source exists in SCRIPT_DIR parent
    if exist "%SCRIPT_DIR%..\..\.claude\CLAUDE.md" (
        copy /y "%SCRIPT_DIR%..\..\.claude\CLAUDE.md" "%CLAUDE_DIR%\CLAUDE.md" >nul
        echo [install] CLAUDE.md copied
    ) else (
        echo [warn] CLAUDE.md source not found — run start_mac.sh / start_ubuntu.sh first
    )
)

:: ── Install mem.py ────────────────────────────────────────────────────────
if exist "%USERPROFILE%\.claude\mem\mem.py" (
    if not "%MEM_DIR%\mem.py"=="%USERPROFILE%\.claude\mem\mem.py" (
        copy /y "%USERPROFILE%\.claude\mem\mem.py" "%MEM_DIR%\mem.py" >nul
    )
    echo [install] mem.py in place
) else (
    echo [warn] mem.py not found — skipping memory system install
)

:: ── Install settings.json ─────────────────────────────────────────────────
set SETTINGS=%CLAUDE_DIR%\settings.json
if not exist "%SETTINGS%" (
    (
        echo {
        echo   "extraKnownMarketplaces": {
        echo     "claude-plugins-official": {
        echo       "source": {
        echo         "source": "github",
        echo         "repo": "anthropics/claude-plugins-official"
        echo       }
        echo     }
        echo   }
        echo }
    ) > "%SETTINGS%"
    echo [install] settings.json created
) else (
    echo [install] settings.json already exists
)

:: ── Create cmem batch wrapper ─────────────────────────────────────────────
set CMEM_BAT=%CLAUDE_DIR%\cmem.bat
(
    echo @echo off
    echo !PYTHON! "%MEM_DIR%\mem.py" %%*
) > "%CMEM_BAT%"

:: Add .claude to PATH for current user (persistent)
powershell -NoProfile -Command ^
    "$p = [Environment]::GetEnvironmentVariable('PATH','User');" ^
    "if ($p -notlike '*\.claude*') {" ^
    "  [Environment]::SetEnvironmentVariable('PATH', '%CLAUDE_DIR%;' + $p, 'User')" ^
    "}"
echo [install] cmem.bat created and .claude added to PATH (restart terminal to use)

:: ── Summary ───────────────────────────────────────────────────────────────
echo.
echo   Installation complete for: %USERNAME%
echo.
echo   What was installed:
echo   +---------------------------------------------------------+
echo   ^| %%USERPROFILE%%\.claude\CLAUDE.md   Global config         ^|
echo   ^| %%USERPROFILE%%\.claude\mem\mem.py  Memory CLI (SQLite)   ^|
echo   ^| %%USERPROFILE%%\.claude\settings.json  Claude settings     ^|
echo   ^| cmem.bat   Memory CLI shortcut (after PATH reload)      ^|
echo   +---------------------------------------------------------+
echo.
echo   Memory CLI usage (after restarting terminal):
echo     cmem save "user prefers dark theme" --type feedback
echo     cmem search "theme"
echo     cmem list
echo     cmem export
echo.
pause
endlocal
