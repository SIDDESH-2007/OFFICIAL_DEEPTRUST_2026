@echo off
setlocal enabledelayedexpansion
title DeepTrust — Stopping

set "SCRIPT_DIR=%~dp0"
if "%SCRIPT_DIR:~-1%"=="\" set "SCRIPT_DIR=%SCRIPT_DIR:~0,-1%"

if exist "%SCRIPT_DIR%\DEEEPTRUST.02\STOP_DEEPTRUST.bat" (
    call "%SCRIPT_DIR%\DEEEPTRUST.02\STOP_DEEPTRUST.bat"
) else (
    echo [ERROR] Cannot find DEEEPTRUST.02\STOP_DEEPTRUST.bat
    pause
)
