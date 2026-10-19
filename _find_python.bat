@echo off
rem ============================================================
rem  _find_python.bat - called by start.bat / start_as_admin.bat
rem
rem  Finds a Python that can actually import a Qt binding and
rem  puts its absolute path into PY.
rem    success: errorlevel 0, PY = interpreter path, PY_SRC = label
rem    failure: errorlevel 1, PY empty, TRIED = candidates tried
rem
rem  IMPORTANT - this file must stay pure ASCII and CRLF.
rem  cmd.exe parses batch files with a byte offset that desyncs on
rem  multi-byte (UTF-8) characters in the middle of the file: lines
rem  get split and half-lines are executed as commands. That is
rem  exactly what broke the previous launcher ("'08' is not
rem  recognized", garbled paths, a bare Python REPL). Keep Chinese
rem  text out of .bat files - the Python layer owns all user-facing
rem  Chinese output.
rem
rem  Also deliberately written without parenthesised blocks and
rem  without delayed expansion: plain sequential tests only.
rem ============================================================

set "PY="
set "PY_SRC="
set "TRIED="
set "C="

rem -- 1. repo venv, delivery stack (PySide2 / Qt 5.15) ----------
set "C=%~dp0envs\portguard38\Scripts\python.exe"
set "TRIED=%TRIED% %C%"
if not exist "%C%" goto :c2
"%C%" -c "import PySide2" >nul 2>&1
if errorlevel 1 goto :c2
set "PY=%C%"
set "PY_SRC=repo venv / PySide2 (delivery, Server 2008 R2+)"
goto :done

rem -- 2. repo venv, dev stack (PySide6 / Qt 6) ------------------
:c2
set "C=%~dp0envs\portguard\Scripts\python.exe"
set "TRIED=%TRIED% %C%"
if not exist "%C%" goto :c3
"%C%" -c "import PySide6" >nul 2>&1
if errorlevel 1 goto :c2b
set "PY=%C%"
set "PY_SRC=repo venv / PySide6 (dev, Win10 1703+)"
goto :done

rem same venv may only have PySide2
:c2b
"%C%" -c "import PySide2" >nul 2>&1
if errorlevel 1 goto :c3
set "PY=%C%"
set "PY_SRC=repo venv / PySide2"
goto :done

rem -- 3. managed venv in the dev box, delivery stack ------------
:c3
set "C=%USERPROFILE%\.workbuddy\binaries\python\envs\portguard38\Scripts\python.exe"
set "TRIED=%TRIED% %C%"
if not exist "%C%" goto :c4
"%C%" -c "import PySide2" >nul 2>&1
if errorlevel 1 goto :c4
set "PY=%C%"
set "PY_SRC=.workbuddy venv / PySide2 (delivery)"
goto :done

rem -- 4. managed venv in the dev box, dev stack -----------------
:c4
set "C=%USERPROFILE%\.workbuddy\binaries\python\envs\portguard\Scripts\python.exe"
set "TRIED=%TRIED% %C%"
if not exist "%C%" goto :c5
"%C%" -c "import PySide6" >nul 2>&1
if errorlevel 1 goto :c4b
set "PY=%C%"
set "PY_SRC=.workbuddy venv / PySide6 (dev)"
goto :done
:c4b
"%C%" -c "import PySide2" >nul 2>&1
if errorlevel 1 goto :c5
set "PY=%C%"
set "PY_SRC=.workbuddy venv / PySide2"
goto :done

rem -- 5. system py launcher, 3.8 (delivery stack) ---------------
:c5
set "C="
for /f "delims=" %%i in ('py -3.8 -c "import sys;print(sys.executable)" 2^>nul') do set "C=%%i"
set "TRIED=%TRIED% py -3.8"
if not defined C goto :c6
if not exist "%C%" goto :c6
"%C%" -c "import PySide2" >nul 2>&1
if errorlevel 1 goto :c6
set "PY=%C%"
set "PY_SRC=system Python 3.8 / PySide2 (delivery)"
goto :done

rem -- 6. system py launcher, default version (dev stack) --------
:c6
set "C="
for /f "delims=" %%i in ('py -3 -c "import sys;print(sys.executable)" 2^>nul') do set "C=%%i"
set "TRIED=%TRIED% py -3"
if not defined C goto :c7
if not exist "%C%" goto :c7
"%C%" -c "import PySide6" >nul 2>&1
if errorlevel 1 goto :c6b
set "PY=%C%"
set "PY_SRC=system Python / PySide6 (dev)"
goto :done
:c6b
"%C%" -c "import PySide2" >nul 2>&1
if errorlevel 1 goto :c7
set "PY=%C%"
set "PY_SRC=system Python / PySide2"
goto :done

rem -- 7. whatever "python" resolves to on PATH ------------------
:c7
set "C="
for /f "delims=" %%i in ('python -c "import sys;print(sys.executable)" 2^>nul') do set "C=%%i"
set "TRIED=%TRIED% python on PATH"
if not defined C goto :fail
if not exist "%C%" goto :fail
"%C%" -c "import PySide6" >nul 2>&1
if errorlevel 1 goto :c7b
set "PY=%C%"
set "PY_SRC=Python on PATH / PySide6"
goto :done
:c7b
"%C%" -c "import PySide2" >nul 2>&1
if errorlevel 1 goto :fail
set "PY=%C%"
set "PY_SRC=Python on PATH / PySide2"
goto :done

:done
set "C="
exit /b 0

:fail
set "PY="
set "PY_SRC="
set "C="
exit /b 1
