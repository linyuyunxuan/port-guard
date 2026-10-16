@echo off
chcp 65001 >nul
title PortGuard 环境安装
cd /d "%~dp0"

set BASE_PY=C:\Users\Administrator\.workbuddy\binaries\python\versions\3.13.12\python.exe
set VENV=C:\Users\Administrator\.workbuddy\binaries\python\envs\portguard

if not exist "%BASE_PY%" (
    echo [错误] 未找到基础 Python: %BASE_PY%
    pause
    exit /b 1
)

if not exist "%VENV%\Scripts\python.exe" (
    echo 正在创建虚拟环境...
    "%BASE_PY%" -m venv "%VENV%"
)

echo 正在安装依赖...
"%VENV%\Scripts\python.exe" -m pip install --upgrade pip
"%VENV%\Scripts\python.exe" -m pip install -r requirements.txt

echo.
echo 安装完成。可用 start.bat 或 start_as_admin.bat 启动。
pause
