@echo off
rem ============================================================
rem  install.bat              -> dev venv     envs\portguard    (py3.9+ / PySide6)
rem  install.bat delivery     -> delivery venv envs\portguard38 (py3.8  / PySide2)
rem  install.bat both         -> both
rem
rem  This file must stay pure ASCII + CRLF. See _find_python.bat
rem  header for why (cmd.exe parser desyncs on UTF-8 text).
rem ============================================================

title PortGuard setup
cd /d "%~dp0"

set "MODE=%~1"
if "%MODE%"=="" set "MODE=dev"
if /i "%MODE%"=="delivery" goto :delivery
if /i "%MODE%"=="both" goto :both
goto :dev

rem -- dev stack -------------------------------------------------------
:dev
set "BASE="
for /f "delims=" %%i in ('py -3 -c "import sys;print(sys.executable)" 2^>nul') do set "BASE=%%i"
if defined BASE goto :dev_have
for /f "delims=" %%i in ('python -c "import sys;print(sys.executable)" 2^>nul') do set "BASE=%%i"
if defined BASE goto :dev_have
echo [ERROR] no Python 3.9+ found for the dev stack.
echo         Install Python 3.9 or newer and make sure "py -3" or "python" works.
goto :fail

:dev_have
echo [dev] base interpreter: %BASE%
call :make_env "%BASE%" "%~dp0envs\portguard"
if errorlevel 1 goto :fail
if /i "%MODE%"=="both" goto :delivery
goto :ok

rem -- delivery stack --------------------------------------------------
:delivery
set "BASE="
for /f "delims=" %%i in ('py -3.8 -c "import sys;print(sys.executable)" 2^>nul') do set "BASE=%%i"
if defined BASE goto :delivery_have
set "BASE=%LOCALAPPDATA%\Programs\Python\Python38\python.exe"
if not exist "%BASE%" set "BASE="
if defined BASE goto :delivery_have
echo [ERROR] no Python 3.8 found. The delivery stack requires 3.8
echo         (it is the last CPython that supports Windows 7 SP1).
echo         Get it from https://www.python.org/downloads/release/python-3810/
goto :fail

:delivery_have
echo [delivery] base interpreter: %BASE%
call :make_env "%BASE%" "%~dp0envs\portguard38"
if errorlevel 1 goto :fail
goto :ok

rem -- create venv + install requirements ------------------------------
rem  %1 = base interpreter   %2 = venv folder
:make_env
if not exist "%~1" goto :bad_base
if exist "%~2\Scripts\python.exe" goto :make_deps
echo Creating venv %~2 ...
"%~1" -m venv "%~2"
if errorlevel 1 exit /b 1
:make_deps
echo Installing requirements (requirements.txt picks PySide2/PySide6 by Python version) ...
"%~2\Scripts\python.exe" -m pip install --upgrade pip
"%~2\Scripts\python.exe" -m pip install -r "%~dp0requirements.txt"
if errorlevel 1 exit /b 1
"%~2\Scripts\python.exe" -c "import PySide2" >nul 2>&1
if errorlevel 1 goto :chk_qt6
echo    OK: PySide2 available
exit /b 0
:chk_qt6
"%~2\Scripts\python.exe" -c "import PySide6" >nul 2>&1
if errorlevel 1 goto :bad_qt
echo    OK: PySide6 available
exit /b 0
:bad_base
echo [ERROR] interpreter not found: %~1
exit /b 1
:bad_qt
echo [ERROR] dependencies installed but no Qt binding importable. Check your pip source.
exit /b 1

:ok
echo.
echo Done. Double-click start.bat (monitor only) or start_as_admin.bat (blocking).
if "%~1"=="" pause
exit /b 0

:fail
echo.
echo Setup did not finish. Fix the message above and run install.bat again.
if "%~1"=="" pause
exit /b 1
