@echo off

setlocal

cd /d "%~dp0"

if not exist logs mkdir logs

echo Official project: %cd% > logs\restart_integration_fix.log

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\restart_face_backend.ps1" >> logs\restart_integration_fix.log 2>&1

if errorlevel 1 goto result

python "%~dp0scripts\verify_integration_fix.py" >> logs\restart_integration_fix.log 2>&1

:result

type logs\restart_integration_fix.log

pause

