@echo off
setlocal
rem =====================================================================
rem PortGuard release verification - Windows Server 2008 R2 clean machine
rem READ ONLY: no firewall rule create/delete, no DB edit, no repack.
rem All console output and the report file are plain ASCII English.
rem This file MUST be stored with CRLF line endings and pure ASCII bytes.
rem NO version, zip filename or SHA256 is hardcoded here.
rem
rem A2 is a THREE-WAY check: certutil actual hash vs the .sha256 sidecar
rem vs verify_expect.txt (the INDEPENDENT expectation anchor). The expect
rem file MUST reach this machine through an INDEPENDENT channel (signed
rem release announcement / signature page). DO NOT generate or ship it in
rem the same batch as the zip + sidecar, or the anchor is worthless.
rem
rem SETUP: copy BOTH verify_2008r2.bat and verify_2008r2.ps1 into the
rem folder that contains ONE release zip (PortGuard-v*.zip), its matching
rem <zipname>.sha256 sidecar, and the extracted PortGuard\ folder.
rem Obtain verify_expect.txt SEPARATELY and place it next to the scripts.
rem The three values (EXPECTED_ZIP_SHA / EXPECTED_VERSION /
rem EXPECTED_SUMS_ENTRIES) must be copied BY HAND from the signed
rem release announcement body and/or the signed signature page.
rem Do NOT download it from the release, do NOT copy it from another
rem machine, and do NOT let it arrive with the zip + sidecar: the
rem anchor would then be worthless and A2 would be false-green.
rem Then double-click this .bat.
rem
rem USAGE:
rem   verify_2008r2.bat
rem       FULL evidence collection -> verify_2008r2_report.txt
rem   verify_2008r2.bat SAVEBASE
rem       Save current PortGuard rule-name set (run BEFORE E2)
rem   verify_2008r2.bat DIFF
rem       Compare current rules with the saved baseline (run AFTER E2)
rem   verify_2008r2.bat FULL "D:\fwlogs\pfirewall.log" "1.2.3.4"
rem       Also validate F2 custom log path and D3 test-IP rule name
rem   verify_2008r2.bat FULL "D:\fwlogs\pfirewall.log" "1.2.3.4" "C:\PG\PortGuard-vX.Y.Z.zip"
rem       Argument 4 = explicit zip path (use when the zip is elsewhere or
rem       when more than one PortGuard-v*.zip exists in this folder)
rem   Argument 5 (optional) = explicit verify_expect.txt path. Default is
rem       verify_expect.txt in this script's folder.
rem
rem VERDICTS: PASS / FAIL / NEEDS-VISUAL.
rem NEEDS-VISUAL means a human must judge on the 2008R2 desktop.
rem This script NEVER signs the release and NEVER replaces visual review.
rem A missing / malformed expect file is a HARD FAIL (A2_ZIP_SHA256),
rem never NEEDS-VISUAL, and can never be overridden by a human.
rem =====================================================================

set "HERE=%~dp0"
if "%HERE:~-1%"=="\" set "HERE=%HERE:~0,-1%"
set "PS1=%HERE%\verify_2008r2.ps1"
set "PSEXE=%WINDIR%\System32\WindowsPowerShell\v1.0\powershell.exe"
set "EXPECT=%HERE%\verify_expect.txt"

if not exist "%PS1%" (
  echo ERROR: verify_2008r2.ps1 is missing next to this .bat.
  echo Keep the two files in the same folder. Nothing was collected.
  goto :DONE
)
if not exist "%PSEXE%" (
  echo ERROR: Windows PowerShell was not found at the system path.
  echo Install Windows PowerShell 2.0 or run the manual checklist.
  echo Nothing was collected.
  goto :DONE
)
if "%~5"=="" (
  if not exist "%EXPECT%" (
    echo WARNING: verify_expect.txt independent expectation anchor is MISSING.
    echo A2_ZIP_SHA256 will be a HARD FAIL. Get it via an INDEPENDENT channel.
    echo Do NOT accept a human override for this.
  )
)

"%PSEXE%" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%PS1%" -Root "%HERE%" -Mode "%~1" -ExpectedLogPath "%~2" -TestIp "%~3" -ZipPath "%~4" -ExpectPath "%~5"
if errorlevel 1 (
  echo ERROR: collector returned a nonzero exit code. See the report file.
)
echo.
echo Done. Report file: verify_2008r2_report.txt (same folder as this script).
echo NEEDS-VISUAL rows still require a human on the 2008R2 machine.
:DONE
endlocal
