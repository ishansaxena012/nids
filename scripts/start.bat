@echo off
echo --- STARTING NIDS PLATFORM ---

pushd "%~dp0..\frontend" 2>nul
if errorlevel 1 (
  echo Frontend folder not found: "%~dp0..\frontend"
) else (
  start "Frontend" cmd /c "npx serve"
  popd
)

pushd "%~dp0..\backend" 2>nul
if errorlevel 1 (
  echo Backend folder not found: "%~dp0..\backend"
) else (
  echo Starting Backend...
  node src/index.js
  popd
)

echo --- LAUNCHER EXITING ---
exit /b 0
