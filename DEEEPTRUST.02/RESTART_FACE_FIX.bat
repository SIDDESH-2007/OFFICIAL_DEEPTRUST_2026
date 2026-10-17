@echo off
setlocal
title DeepTrust Corrected Backend Restart
cd /d "%~dp0"
set "restart_log=%~dp0logs\restart_face_fix.log"
if not exist "%~dp0logs" mkdir "%~dp0logs"
echo Project: %cd% > "%restart_log%"
echo Started: %DATE% %TIME% >> "%restart_log%"
echo Stopping the old DeepTrust copy and starting this corrected project...
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\restart_face_backend.ps1" >> "%restart_log%" 2>&1
set "restart_rc=%errorlevel%"
type "%restart_log%"
if not "%restart_rc%"=="0" (
  echo Restart failed. The old process may still own port 5000 or 8000.
  pause
  exit /b 1
)
python "%~dp0scripts\verify_face_fix.py" --wait >> "%restart_log%" 2>&1
set "verify_rc=%errorlevel%"
type "%restart_log%"
if not "%verify_rc%"=="0" (
  echo DeepTrust is not corrected yet. Check this project's logs\fastapi.log and logs\backend.log.
  pause
  exit /b 1
)
echo Face correction is live on localhost:5000. Refresh Chrome with Ctrl+F5.
pause
