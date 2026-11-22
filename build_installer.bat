@echo off
REM Builds dist\QuickSentry.exe AND dist\QuickSentry-Setup-<version>.exe.
REM Needs Inno Setup 6:  winget install JRSoftware.InnoSetup
setlocal
cd /d "%~dp0"

set "ISCC="
for %%P in ("%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe" "%ProgramFiles%\Inno Setup 6\ISCC.exe" "%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe") do (
  if exist %%P set "ISCC=%%~P"
)
if not defined ISCC (
  where iscc >nul 2>&1 && set "ISCC=iscc"
)
if not defined ISCC (
  echo Inno Setup 6 was not found.
  echo Install it with:  winget install JRSoftware.InnoSetup
  echo or download it from https://jrsoftware.org/isdl.php , then run this again.
  pause
  exit /b 1
)

call build_exe.bat nopause || goto :fail

for /f "usebackq delims=" %%V in (`python -c "import quicksentry; print(quicksentry.__version__)"`) do set "VER=%%V"
if not defined VER goto :fail

echo.
echo Building installer for QuickSentry %VER%...
"%ISCC%" /Q "/DAppVersion=%VER%" installer\QuickSentry.iss || goto :fail

echo.
echo Done:
echo   %CD%\dist\QuickSentry.exe
echo   %CD%\dist\QuickSentry-Setup-%VER%.exe   ^<-- give people this one
pause
exit /b 0

:fail
echo.
echo Installer build FAILED - see the messages above.
pause
exit /b 1
