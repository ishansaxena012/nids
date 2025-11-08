@echo off
echo "--- CLEARING ALERT & AUDIT LOGS ---"

REM %~dp0 is the path to this script's folder
REM %~dp0.. is the parent (root) folder
cd %~dp0..\backend

echo "Running Node.js clear script..."
node scripts/clear_alerts.js

echo "--- DONE ---"
pause