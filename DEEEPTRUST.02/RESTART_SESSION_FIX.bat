@echo off
cd /d "%~dp0"
echo Restarting DeepTrust to load dashboard and Session Control improvements...
start "" /b node server\scripts\deeptrust_launcher.js restart
python scripts/verify_session_monitor.py --wait
if errorlevel 1 (
 echo Please check the launcher output and try again.
 pause
 exit /b 1
)
echo Press Ctrl+F5 in Chrome, then sign in to create a fresh monitored session.
pause
