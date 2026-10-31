@echo off
title Minolta DiMAGE Scan Dual III - Windows 11 Installer
echo ======================================================================
echo  Starting Minolta DiMAGE Scan Dual III Windows 11 Installer...
echo  Please click "Yes" if Windows asks for Administrator permission.
echo ======================================================================
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Install-MinoltaWin11.ps1"
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [!] The installer reported an issue ^(code %ERRORLEVEL%^).
    pause
)
