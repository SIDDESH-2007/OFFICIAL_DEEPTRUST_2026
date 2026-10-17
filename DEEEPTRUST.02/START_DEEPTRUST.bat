@echo off
setlocal enabledelayedexpansion
title DeepTrust — Secure Platform Launcher

:: ============================================================
:: START_DEEPTRUST.bat — Development Launcher
:: Runs DeepTrust from CURRENT source code.
:: Future source changes appear after restarting with this file.
:: ============================================================

:: Resolve project root from this bat file's location
set "PROJECT_ROOT=%~dp0"
if "%PROJECT_ROOT:~-1%"=="\" set "PROJECT_ROOT=%PROJECT_ROOT:~0,-1%"

echo.
echo ============================================================
echo              DEEPTRUST — STARTING (DEV MODE)
echo ============================================================
echo.

:: Sanity check — verify this is the correct project directory
if not exist "%PROJECT_ROOT%\server\server.js" (
    echo [ERROR] Cannot find server\server.js in: %PROJECT_ROOT%
    echo [ERROR] Please ensure START_DEEPTRUST.bat is in the DeepTrust project root.
    echo.
    pause
    exit /b 1
)

if not exist "%PROJECT_ROOT%\server\scripts\deeptrust_launcher.js" (
    echo [ERROR] Cannot find server\scripts\deeptrust_launcher.js
    echo [ERROR] Launcher script is missing from the project.
    echo.
    pause
    exit /b 1
)

:: Check Node.js is available
where node >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Node.js is not installed or not on PATH.
    echo [ERROR] Please install Node.js from https://nodejs.org/
    echo.
    pause
    exit /b 1
)

:: Check Python is available
where python >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Python is not installed or not on PATH.
    echo [ERROR] Please install Python 3.x from https://python.org/
    echo.
    pause
    exit /b 1
)

echo [DeepTrust] Source directory : %PROJECT_ROOT%
echo [DeepTrust] Node.js          : OK
echo [DeepTrust] Python           : OK
echo.
echo [DeepTrust] Handing control to launcher engine...
echo.

:: Change to project root and start the launcher
cd /d "%PROJECT_ROOT%"
call node server\scripts\deeptrust_launcher.js start

:: Use labels instead of a parenthesized block: cmd parses echo brackets as syntax.
set "LAUNCH_EXIT_CODE=%ERRORLEVEL%"
if "%LAUNCH_EXIT_CODE%"=="0" goto launcher_finished
echo.
echo [DeepTrust] Launcher failed. Exit code: %LAUNCH_EXIT_CODE%
echo [DeepTrust] The startup error is shown above.
echo [DeepTrust] Check logs\fastapi.log and logs\backend.log for service details.
goto launcher_wait

:launcher_finished
echo.
echo [DeepTrust] Launcher has finished. Exit code: 0

:launcher_wait
echo.
echo Press any key to close this window...
pause >nul
exit /b %LAUNCH_EXIT_CODE%
