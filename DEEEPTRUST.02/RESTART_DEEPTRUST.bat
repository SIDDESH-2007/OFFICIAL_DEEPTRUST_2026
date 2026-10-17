@echo off
setlocal enabledelayedexpansion
title DeepTrust — Restarting

:: ============================================================
:: RESTART_DEEPTRUST.bat — Safe restart for development
:: Stops owned processes → waits → starts fresh from source.
:: Use after Antigravity changes source code to reload.
:: ============================================================

set "PROJECT_ROOT=%~dp0"
if "%PROJECT_ROOT:~-1%"=="\" set "PROJECT_ROOT=%PROJECT_ROOT:~0,-1%"

echo.
echo ============================================================
echo              DEEPTRUST — RESTARTING
echo ============================================================
echo.

if not exist "%PROJECT_ROOT%\server\scripts\deeptrust_launcher.js" (
    echo [ERROR] Cannot find launcher script.
    pause
    exit /b 1
)

cd /d "%PROJECT_ROOT%"
node server\scripts\deeptrust_launcher.js restart

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [DeepTrust] Restart encountered an error (code %ERRORLEVEL%).
    echo [DeepTrust] Check logs\ directory for details.
    echo.
    echo Press any key to close...
    pause >nul
)
