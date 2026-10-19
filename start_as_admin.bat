@echo off
rem ============================================================
rem  PortGuard launcher - administrator (can write firewall).
rem  Self-elevates through UAC, then starts the app in the
rem  elevated console.
rem
rem  This file must stay pure ASCII + CRLF. See _find_python.bat
rem  header for why.
rem ============================================================

title PortGuard (admin)
cd /d "%~dp0"

rem -- need elevation? -------------------------------------------------
net session >nul 2>&1
if errorlevel 1 goto :elevate
goto :run

:elevate
echo Requesting administrator rights...
powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
if errorlevel 1 goto :elevate_failed
exit /b 0

:elevate_failed
echo.
echo [START FAILED] elevation was cancelled or refused.
echo For monitor-only mode just run start.bat instead.
echo.
chcp 65001 >nul 2>&1
if exist "%~dp0launcher_help.txt" type "%~dp0launcher_help.txt"
chcp 936 >nul 2>&1
if "%~1"=="" pause
exit /b 3

:run
call "%~dp0_find_python.bat"
if errorlevel 1 goto :nopy

echo ============================================
echo   PortGuard - administrator (blocking enabled)
echo   Python: %PY%
echo   Stack : %PY_SRC%
echo ============================================
echo.

"%PY%" main.py %*
set "CODE=%ERRORLEVEL%"
if "%CODE%"=="0" goto :end

echo.
echo [START FAILED] exit code %CODE%
echo.
echo Log file (fastest way to locate the cause):
echo   %~dp0data\logs\portguard.log
if not exist "%~dp0data\logs\portguard.log" echo   (no log yet - failure happened before logging was up)
echo.
echo Or run the built-in environment check:
echo   "%PY%" main.py --diag
goto :end

:nopy
echo.
echo [START FAILED] no usable Python runtime was found.
echo A plain Python is not enough - it must import PySide2 or PySide6.
echo.
echo Tried:
echo   %TRIED%
echo.
chcp 65001 >nul 2>&1
if exist "%~dp0launcher_help.txt" type "%~dp0launcher_help.txt"
chcp 936 >nul 2>&1
if "%~1"=="" pause
exit /b 2

:end
if "%~1"=="" pause
exit /b %CODE%
