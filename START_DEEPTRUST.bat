@echo off
setlocal enabledelayedexpansion
title DeepTrust — Launcher

:: ============================================================
:: START_DEEPTRUST.bat (Root shortcut)
:: Delegates to the project-level launcher in DEEEPTRUST.02\
:: ============================================================

set "SCRIPT_DIR=%~dp0"
if "%SCRIPT_DIR:~-1%"=="\" set "SCRIPT_DIR=%SCRIPT_DIR:~0,-1%"

if exist "%SCRIPT_DIR%\DEEEPTRUST.02\START_DEEPTRUST.bat" (
    call "%SCRIPT_DIR%\DEEEPTRUST.02\START_DEEPTRUST.bat"
) else if exist "%SCRIPT_DIR%\START_DEEPTRUST.bat" (
    echo [ERROR] This IS the root bat — cannot find DEEEPTRUST.02 subdirectory.
    pause
) else (
    echo [ERROR] Cannot find DeepTrust project directory.
    pause
)
