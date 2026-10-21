@echo off
rem ============================================================
rem  PortGuard - enable Windows Firewall safely (one click)
rem
rem  Why this exists: on this machine all three firewall profiles
rem  (Domain / Private / Public) were OFF, so every block rule was
rem  written into a firewall that does not filter anything. Bans
rem  looked successful but blocked nothing.
rem
rem  Steps performed by --enable-firewall:
rem    1) allow every port that is listening right now (skip loopback)
rem    2) turn all firewall profiles on
rem    3) re-sync bans (rebuild missing rules, drop legacy duplicates)
rem
rem  ASCII only + CRLF on purpose (cmd parses LF-only files wrongly).
rem ============================================================
setlocal
chcp 65001 >nul
cd /d "%~dp0.."

net session >nul 2>&1
if errorlevel 1 (
    echo [PortGuard] requesting administrator rights, click YES on the UAC dialog ...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b 0
)

echo [PortGuard] running with administrator rights.
echo.

if exist "dist\PortGuard\PortGuard.exe" (
    echo [PortGuard] using packaged build ...
    start /wait "" "dist\PortGuard\PortGuard.exe" --enable-firewall
) else if exist "envs\portguard38\Scripts\python.exe" (
    echo [PortGuard] using delivery venv ...
    "envs\portguard38\Scripts\python.exe" main.py --enable-firewall
) else (
    echo [PortGuard] using python from PATH ...
    python main.py --enable-firewall
)

echo.
echo ---------------- result ----------------
if exist "%TEMP%\pg_enable_fw.log" (
    type "%TEMP%\pg_enable_fw.log"
) else (
    echo log file not found: %TEMP%\pg_enable_fw.log
)
echo ----------------------------------------
echo.
echo rollback (turn firewall off again):
echo   netsh advfirewall set allprofiles state off
echo.
pause
endlocal
