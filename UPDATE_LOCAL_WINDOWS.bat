@echo off
cd /d "%~dp0"
python -m pip install -r requirements.txt
if errorlevel 1 goto failed
python collect.py
if errorlevel 1 goto failed
echo.
echo CTI Feed updated. Open START_LOCAL_WINDOWS.bat to view.
pause
exit /b 0
:failed
echo.
echo Update failed. Previous CTI data was kept when all sources failed.
pause
exit /b 1
