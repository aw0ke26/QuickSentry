@echo off
REM Builds dist\QuickSentry.exe. Double-click, or run from the repo folder.
REM   build_exe.bat           build and pause at the end
REM   build_exe.bat nopause   build without pausing (used by build_installer.bat)
setlocal
cd /d "%~dp0"
set "PAUSE_AT_END=1"
if /i "%~1"=="nopause" set "PAUSE_AT_END="

where python >nul 2>&1 || (echo Python 3.10+ is not on PATH. Install it from python.org with "Add to PATH" checked. & goto :fail)

echo [1/3] Installing build requirements...
python -m pip install --upgrade -r requirements.txt || goto :fail

echo [2/3] Running tests...
for %%T in (tests\test_parsers.py tests\test_engine.py tests\test_path.py tests\test_guard.py) do (
  python %%T || goto :fail
)

echo [3/3] Building dist\QuickSentry.exe...
python -m PyInstaller --noconfirm --onefile --windowed --clean --uac-admin --name QuickSentry ^
  --icon assets\QuickSentry.ico --add-data "rules;rules" quicksentry_gui.py || goto :fail

echo.
echo Done: %CD%\dist\QuickSentry.exe
if defined PAUSE_AT_END pause
exit /b 0

:fail
echo.
echo Build FAILED - see the messages above.
if defined PAUSE_AT_END pause
exit /b 1
