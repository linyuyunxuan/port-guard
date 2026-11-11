@echo off
rem  PortGuard - full (blocking) mode with administrator rights.
rem  PortGuard.exe itself starts with standard rights (observe mode):
rem  monitoring, risk events, history, lookup and statistics all work.
rem  Use this launcher only when you need to write Windows Firewall rules
rem  (confirm ban / unban / expired cleanup / firewall logging).
cd /d "%~dp0"
powershell -NoProfile -Command "Start-Process -FilePath (Join-Path (Get-Location).Path 'PortGuard.exe') -Verb RunAs"
if errorlevel 1 (
  echo [START FAILED] elevation was cancelled or refused.
  echo You can still run PortGuard.exe directly in observe mode.
  pause
)
