@echo off
chcp 65001 >nul
title PortGuard 端口访问防御工具（管理员）
cd /d "%~dp0"

set PY=C:\Users\Administrator\.workbuddy\binaries\python\envs\portguard\Scripts\python.exe
if not exist "%PY%" (
    echo [错误] 未找到虚拟环境: %PY%
    pause
    exit /b 1
)

net session >nul 2>&1
if %errorLevel% neq 0 (
    echo 正在请求管理员权限...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

echo ============================================
echo   PortGuard - 管理员启动（封禁功能可用）
echo ============================================
echo.

"%PY%" main.py
pause
