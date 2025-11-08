@echo off
echo "--- CLEANING PROJECT ---"

REM Delete sensor build files
echo "Cleaning Sensor..."
del /Q ..\sensor\build\*

REM Delete backend dependencies
echo "Cleaning Backend..."
rmdir /S /Q ..\backend\node_modules

echo "--- CLEANUP COMPLETE ---"
pause