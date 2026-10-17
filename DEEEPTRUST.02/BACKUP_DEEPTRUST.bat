@echo off
setlocal enabledelayedexpansion

set "SCRIPT_DIR=%~dp0"
cd /d "%SCRIPT_DIR%"

echo ==================================================
echo  DEEPTRUST BACKUP UTILITY
echo ==================================================

where python >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [X] Error: Python is required to run database backup script.
    exit /b 1
)

python server/scripts/backup_db.py
if %ERRORLEVEL% NEQ 0 (
    echo [X] Backup execution failed.
    exit /b 1
)

echo ==================================================
