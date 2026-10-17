@echo off
setlocal enabledelayedexpansion
title DeepTrust — Stopping

:: ============================================================
:: STOP_DEEPTRUST.bat — Graceful stop
:: Stops ONLY DeepTrust-owned processes (tracked by PID file).
:: Does NOT kill all Python/Node/MongoDB processes.
:: ============================================================

set "PROJECT_ROOT=%~dp0"
if "%PROJECT_ROOT:~-1%"=="\" set "PROJECT_ROOT=%PROJECT_ROOT:~0,-1%"

echo.
echo ============================================================
echo              DEEPTRUST — STOPPING
echo ============================================================
echo.

if not exist "%PROJECT_ROOT%\server\scripts\deeptrust_launcher.js" (
    echo [ERROR] Cannot find launcher script.
    pause
    exit /b 1
)

cd /d "%PROJECT_ROOT%"
node server\scripts\deeptrust_launcher.js stop

echo.
echo [DeepTrust] Services stopped. MongoDB and unrelated processes remain intact.
echo.
