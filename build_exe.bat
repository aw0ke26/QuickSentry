@echo off
REM Builds dist\QuickSentry.exe. Run this from the project folder.
REM The exe always asks for administrator rights (UAC) when started.
python -m pip install --upgrade -r requirements.txt || goto :err
python tests\test_parsers.py || goto :err
python tests\test_engine.py || goto :err
python tests\test_path.py || goto :err
python tests\test_guard.py || goto :err
python -m PyInstaller --onefile --windowed --clean --uac-admin --name QuickSentry --icon assets\QuickSentry.ico ^
  --add-data "rules;rules" quicksentry_gui.py || goto :err
echo.
echo Done: dist\QuickSentry.exe
echo Preview the interface without admin:  dist\QuickSentry.exe --demo
pause
exit /b 0
:err
echo.
echo Build failed. Make sure Python 3.10+ is installed and on PATH (python.org installer, "Add to PATH" checked).
pause
exit /b 1
