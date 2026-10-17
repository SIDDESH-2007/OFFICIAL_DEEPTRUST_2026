@echo off

setlocal

cd /d "%~dp0"

if not exist logs mkdir logs

echo Official project: %cd% > logs\restart_voice_fix.log

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\restart_face_backend.ps1" >> logs\restart_voice_fix.log 2>&1

if errorlevel 1 goto failed

python "%~dp0scripts\verify_voice_fix.py" >> logs\restart_voice_fix.log 2>&1

:failed

type logs\restart_voice_fix.log

pause

