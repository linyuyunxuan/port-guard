@echo off
rem ============================================================
rem  PortGuard launcher - monitor only (never writes firewall).
rem  Use start_as_admin.bat when you need confirm/apply/clear bans.
rem
rem  This file must stay pure ASCII + CRLF. See _find_python.bat
rem  header for why: UTF-8 text inside a .bat desyncs cmd.exe's
rem  parser and half-lines get executed as commands.
rem  Chinese user-facing text lives in launcher_help.txt and in
rem  the Python layer (main.py / --diag), never in here.
rem ============================================================

title PortGuard
cd /d "%~dp0"

call "%~dp0_find_python.bat"
if errorlevel 1 goto :nopy

echo ============================================
echo   PortGuard - monitor only (no firewall write)
echo   Python: %PY%
echo   Stack : %PY_SRC%
echo   Need blocking? run start_as_admin.bat
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
