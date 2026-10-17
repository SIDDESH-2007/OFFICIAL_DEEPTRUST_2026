@echo off
setlocal enabledelayedexpansion
title DeepTrust — Build System

:: ============================================================
:: BUILD_DEEPTRUST.bat — Release Build System
::
:: Workflow:
::   1. START_DEEPTRUST.bat  (develop & test)
::   2. BUILD_DEEPTRUST.bat  (package release)
::   3. release\DeepTrust\DeepTrust.exe  (distribute)
::
:: IMPORTANT:
::   The EXE represents the source AT BUILD TIME.
::   After source changes: test with START_DEEPTRUST.bat first,
::   then run this script to produce an updated release.
:: ============================================================

set "PROJECT_ROOT=%~dp0"
if "%PROJECT_ROOT:~-1%"=="\" set "PROJECT_ROOT=%PROJECT_ROOT:~0,-1%"

echo.
echo ============================================================
echo              DEEPTRUST — RELEASE BUILD SYSTEM
echo ============================================================
echo.

:: ── Pre-flight checks ─────────────────────────────────────
echo [BUILD] Checking build dependencies...

where python >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Python is not available on PATH.
    echo [ERROR] Python is required to build DeepTrust.exe (PyInstaller).
    pause
    exit /b 1
)

where node >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Node.js is not available on PATH.
    pause
    exit /b 1
)

:: Check PyInstaller is available
python -m PyInstaller --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [BUILD] PyInstaller not found. Installing...
    pip install pyinstaller >nul 2>&1
    if %ERRORLEVEL% NEQ 0 (
        echo [ERROR] Failed to install PyInstaller.
        echo [ERROR] Run: pip install pyinstaller
        pause
        exit /b 1
    )
)

echo [BUILD] All build dependencies present.

:: ── Determine version ──────────────────────────────────────
set "VERSION=1.0.0"
for /f "tokens=*" %%a in ('python -c "import json; d=json.load(open(\"version.json\")); print(d[\"version\"])" 2^>nul') do (
    set "VERSION=%%a"
)
echo [BUILD] Building DeepTrust version: %VERSION%

:: ── Stamp build metadata into version.json ────────────────
for /f "tokens=*" %%a in ('python -c "from datetime import datetime; print(datetime.utcnow().strftime(\"%%Y%%m%%d%%H%%M%%S\"))"') do set "BUILD_ID=%%a"
for /f "tokens=*" %%a in ('python -c "from datetime import datetime; print(datetime.utcnow().isoformat()+\"Z\")"') do set "BUILD_DATE=%%a"

python -c "
import json, sys
with open('version.json','r') as f: d = json.load(f)
d['build'] = '%BUILD_ID%'
d['build_date'] = '%BUILD_DATE%'
with open('version.json','w') as f: json.dump(d, f, indent=2)
print('[BUILD] version.json updated: build=%BUILD_ID%')
"

:: ── Prepare tools and release directories ─────────────────
set "TOOLS_DIR=%PROJECT_ROOT%\tools"
set "RELEASE_DIR=%PROJECT_ROOT%\release\DeepTrust"

if not exist "%TOOLS_DIR%" mkdir "%TOOLS_DIR%"
if not exist "%RELEASE_DIR%" mkdir "%RELEASE_DIR%"

echo [BUILD] Release target: %RELEASE_DIR%

:: ── Write launcher Python script ──────────────────────────
echo [BUILD] Writing EXE launcher source...
(
echo import os, sys, subprocess, time, webbrowser, json, socket, ctypes
echo.
echo def resource_path(relative):
echo     if hasattr(sys, '_MEIPASS'^):
echo         return os.path.join(sys._MEIPASS, relative^)
echo     return os.path.join(os.path.dirname(os.path.abspath(__file__^)^), relative^)
echo.
echo def check_port(host, port, timeout=1^):
echo     try:
echo         s = socket.create_connection((host, port^), timeout^)
echo         s.close(^)
echo         return True
echo     except:
echo         return False
echo.
echo def status(msg^):
echo     print(f'[DeepTrust] {msg}', flush=True^)
echo.
echo def load_version(^):
echo     try:
echo         vf = resource_path('version.json'^)
echo         if os.path.exists(vf^):
echo             with open(vf^) as f:
echo                 return json.load(f^).get('version', '1.0.0'^)
echo     except: pass
echo     return '1.0.0'
echo.
echo def find_project_root(^):
echo     candidates = [
echo         os.path.dirname(os.path.abspath(sys.argv[0]^)^),
echo         os.path.join(os.path.dirname(os.path.abspath(sys.argv[0]^)^), '..'^),
echo     ]
echo     for c in candidates:
echo         if os.path.exists(os.path.join(c, 'server', 'server.js'^)^):
echo             return os.path.abspath(c^)
echo     return None
echo.
echo def main(^):
echo     version = load_version(^)
echo     print(^)
echo     print('============================================================'^)
echo     print(f'           DEEPTRUST SECURE ACCESS PLATFORM'^)
echo     print(f'                   Version {version}'^)
echo     print('============================================================'^)
echo     print(^)
echo.
echo     project = find_project_root(^)
echo     if not project:
echo         print('[ERROR] Cannot locate DeepTrust project directory.'^)
echo         print('[ERROR] Ensure DeepTrust.exe is in the release folder beside the project.'^)
echo         input('Press Enter to exit...'^)
echo         sys.exit(1^)
echo.
echo     launcher_js = os.path.join(project, 'server', 'scripts', 'deeptrust_launcher.js'^)
echo     if not os.path.exists(launcher_js^):
echo         print(f'[ERROR] Launcher script not found: {launcher_js}'^)
echo         input('Press Enter to exit...'^)
echo         sys.exit(1^)
echo.
echo     status(f'Project root: {project}'^)
echo     status('Starting DeepTrust services via Node.js launcher...'^)
echo     print(^)
echo.
echo     proc = subprocess.Popen(
echo         ['node', 'server/scripts/deeptrust_launcher.js', 'start'],
echo         cwd=project,
echo         shell=True
echo     ^)
echo     proc.wait(^)
echo.
echo if __name__ == '__main__':
echo     main(^)
) > "%TOOLS_DIR%\deeptrust_exe_launcher.py"

echo [BUILD] Building DeepTrust.exe with PyInstaller...

:: Run PyInstaller to produce DeepTrust.exe
python -m PyInstaller ^
    --onefile ^
    --name "DeepTrust" ^
    --distpath "%RELEASE_DIR%" ^
    --workpath "%TOOLS_DIR%\build_work" ^
    --specpath "%TOOLS_DIR%" ^
    "--add-data=%PROJECT_ROOT%\version.json;." ^
    --console ^
    --noconfirm ^
    "%TOOLS_DIR%\deeptrust_exe_launcher.py"

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [BUILD ERROR] PyInstaller failed to build DeepTrust.exe
    echo [BUILD ERROR] Check output above for details.
    pause
    exit /b 1
)

:: ── Copy required runtime config files to release ─────────
echo [BUILD] Copying runtime configuration...
copy /Y "%PROJECT_ROOT%\version.json" "%RELEASE_DIR%\version.json" >nul

:: Create a release README
(
echo DeepTrust %VERSION% — Release Build
echo Built: %BUILD_DATE%
echo.
echo USAGE:
echo   Double-click DeepTrust.exe to launch.
echo.
echo REQUIREMENTS:
echo   - Node.js must be installed (https://nodejs.org/)
echo   - Python 3.x must be installed (https://python.org/)
echo   - MongoDB must be running (service: SIDDU MongoDB or MongoDB)
echo   - DeepTrust source project must be present relative to this EXE
echo.
echo ARCHITECTURE:
echo   DeepTrust.exe starts the existing DeepTrust application by
echo   invoking the Node.js launcher (deeptrust_launcher.js).
echo   It does NOT contain or replace the FastAPI/Express backend.
echo.
echo NOTE:
echo   Source changes after this build are NOT reflected in this EXE.
echo   Run BUILD_DEEPTRUST.bat again to produce an updated release.
echo.
echo DEEPTRUST CANONICAL URL: http://localhost:5000
) > "%RELEASE_DIR%\README.txt"

:: ── Cleanup PyInstaller build artifacts ───────────────────
if exist "%TOOLS_DIR%\build_work" (
    rmdir /s /q "%TOOLS_DIR%\build_work" 2>nul
)
if exist "%TOOLS_DIR%\DeepTrust.spec" (
    del /q "%TOOLS_DIR%\DeepTrust.spec" 2>nul
)

echo.
echo ============================================================
echo              BUILD COMPLETE
echo ============================================================
echo.
echo   Version    : DeepTrust %VERSION%
echo   Build ID   : %BUILD_ID%
echo   EXE        : %RELEASE_DIR%\DeepTrust.exe
echo   README     : %RELEASE_DIR%\README.txt
echo.
echo   To launch:   Double-click %RELEASE_DIR%\DeepTrust.exe
echo.
echo ============================================================
echo.
pause
