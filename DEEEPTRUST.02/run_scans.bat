@echo off
echo Running bandit...
bandit -r server/ai_service -f txt -o bandit_report.txt

echo Running pip-audit...
pip-audit > pip_audit_report.txt

echo Running npm audit...
cd server
cmd.exe /c "npm audit > ..\npm_audit_report.txt"
cd ..

echo Scans complete.
