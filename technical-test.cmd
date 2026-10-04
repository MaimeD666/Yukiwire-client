@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"
set "YUKIWIRE_TEST_PYTHON=python"
if exist "python\python.exe" set "YUKIWIRE_TEST_PYTHON=%~dp0python\python.exe"
if "%~1"=="" (
  "%YUKIWIRE_TEST_PYTHON%" -B -u scripts\acceptance.py --exercise --capture local
) else (
  "%YUKIWIRE_TEST_PYTHON%" -B -u scripts\acceptance.py %*
)
set "YUKIWIRE_TEST_RESULT=%ERRORLEVEL%"
echo.
echo Exit code: %YUKIWIRE_TEST_RESULT%. Report: acceptance-report.json in runtime or portable folder.
pause
exit /b %YUKIWIRE_TEST_RESULT%
