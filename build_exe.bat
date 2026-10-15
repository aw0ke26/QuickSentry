@echo off
REM Builds dist\ArpWatch.exe. Run this from the arp-watch folder.
python -m pip install --upgrade -r requirements.txt || goto :err
python -m PyInstaller --onefile --windowed --clean --name ArpWatch --hidden-import pystray._win32 arp_watch_gui.py || goto :err
echo.
echo Done: dist\ArpWatch.exe
echo To use from a flash drive, copy dist\ArpWatch.exe to the drive.
pause
exit /b 0
:err
echo.
echo Build failed. Make sure Python is installed and on PATH (python.org installer, "Add to PATH" checked).
pause
exit /b 1
