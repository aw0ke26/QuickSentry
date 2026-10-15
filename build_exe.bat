@echo off
REM Builds ArpWatch.exe from arp_watch_gui.py. Run this from the folder containing the script.
python -m pip install --upgrade pyinstaller || goto :err
python -m PyInstaller --onefile --windowed --clean --name ArpWatch arp_watch_gui.py || goto :err
echo.
echo Done: dist\ArpWatch.exe
pause
exit /b 0
:err
echo.
echo Build failed. Make sure Python is installed and on PATH (python.org installer, "Add to PATH" checked).
pause
exit /b 1
