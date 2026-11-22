@echo off
REM Builds dist\QuickSentry.exe AND dist\QuickSentry-Setup-<version>.exe.
REM Needs Inno Setup 6 - if it's missing, this script offers to install it with winget.
setlocal EnableExtensions
cd /d "%~dp0"

call :find_iscc
if not defined ISCC (
  echo Inno Setup 6 ^(the installer compiler^) is not installed.
  where winget >nul 2>&1 || goto :no_winget
  choice /C YN /M "Install it now with winget"
  if errorlevel 2 goto :no_iscc
  winget install --id JRSoftware.InnoSetup -e --accept-package-agreements --accept-source-agreements
  call :find_iscc
)
if not defined ISCC goto :no_iscc
echo Using Inno Setup: %ISCC%
echo.

call build_exe.bat nopause || goto :fail

set "VER="
for /f "usebackq delims=" %%V in (`python -c "import quicksentry; print(quicksentry.__version__)"`) do set "VER=%%V"
if not defined VER goto :fail

echo.
echo Building installer for QuickSentry %VER%...
"%ISCC%" /Q "/DAppVersion=%VER%" installer\QuickSentry.iss || goto :fail

echo.
echo Done:
echo   %CD%\dist\QuickSentry.exe
echo   %CD%\dist\QuickSentry-Setup-%VER%.exe   ^<-- the installer
pause
exit /b 0

REM ---------------------------------------------------------------- helpers
:find_iscc
set "ISCC="
for %%P in ("%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe" "%ProgramFiles%\Inno Setup 6\ISCC.exe" "%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe") do (
  if exist "%%~P" set "ISCC=%%~P"
)
if defined ISCC exit /b 0
for %%K in ("HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Inno Setup 6_is1" "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Inno Setup 6_is1" "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Inno Setup 6_is1") do (
  for /f "tokens=2,*" %%A in ('reg query %%K /v InstallLocation 2^>nul ^| find "InstallLocation"') do (
    if exist "%%~BISCC.exe" set "ISCC=%%~BISCC.exe"
    if exist "%%~B\ISCC.exe" set "ISCC=%%~B\ISCC.exe"
  )
)
if defined ISCC exit /b 0
for /f "delims=" %%W in ('where iscc 2^>nul') do if not defined ISCC set "ISCC=%%W"
exit /b 0

:no_winget
echo winget isn't available on this PC.
:no_iscc
echo.
echo Install Inno Setup 6 from https://jrsoftware.org/isdl.php ^(default options^), then run this again.
pause
exit /b 1

:fail
echo.
echo Installer build FAILED - see the messages above.
pause
exit /b 1
