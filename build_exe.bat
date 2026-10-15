@echo off
REM Builds dist\QuickSentry.exe. Run this from the project folder.
python -m pip install --upgrade -r requirements.txt || goto :err
python -m PyInstaller --onefile --windowed --clean --name QuickSentry --icon assets\QuickSentry.ico --hidden-import pystray._win32 quicksentry_gui.py || goto :err
echo.
echo Done: dist\QuickSentry.exe
echo To use from a flash drive, copy dist\QuickSentry.exe to the drive.
pause
exit /b 0
:err
echo.
echo Build failed. Make sure Python is installed and on PATH (python.org installer, "Add to PATH" checked).
pause
exit /b 1
