@echo off
setlocal enabledelayedexpansion

set "SCRIPT_DIR=%~dp0"
cd /d "%SCRIPT_DIR%"

echo ==================================================
echo  DEEPTRUST RESTORE UTILITY
echo ==================================================

where python >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [X] Error: Python is required to run database restore script.
    exit /b 1
)

python server/scripts/restore_db.py %*
if %ERRORLEVEL% NEQ 0 (
    echo [X] Restore execution failed or was cancelled.
    exit /b 1
)

echo ==================================================
