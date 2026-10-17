@echo off
chcp 65001 >nul
title PortGuard 端口访问防御工具
cd /d "%~dp0"

rem 双栈运行时：交付栈（portguard38，PySide2，Server 2008 R2+）优先，
rem 找不到再退回开发栈（portguard，PySide6）。两条栈跑的是同一套源码。
set PY=C:\Users\Administrator\.workbuddy\binaries\python\envs\portguard38\Scripts\python.exe
if not exist "%PY%" set PY=C:\Users\Administrator\.workbuddy\binaries\python\envs\portguard\Scripts\python.exe
if not exist "%PY%" (
    echo [错误] 未找到虚拟环境（portguard38 / portguard）
    echo 请先执行 install.bat 创建环境
    pause
    exit /b 1
)

echo ============================================
echo   PortGuard - 普通权限启动（仅监控与建议）
echo   如需封禁功能，请使用 start_as_admin.bat
echo ============================================
echo.

"%PY%" main.py
pause
