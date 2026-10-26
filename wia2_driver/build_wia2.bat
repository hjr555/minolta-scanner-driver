@echo off
REM Build 64-bit WIA 2.0 Driver (MinoltaWia2Driver.dll) with Visual Studio Build Tools / Windows SDK
setlocal
where cl.exe >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [!] Run this script from an "x64 Native Tools Command Prompt for VS"
    exit /b 1
)

cl.exe /nologo /O2 /LD /DDIMAGE_NO_MAIN /D_CRT_SECURE_NO_WARNINGS ^
    MinoltaWia2Driver.cpp ..\scanner_tool\dimage_scan.c ^
    /link /DEF:MinoltaWia2Driver.def /OUT:MinoltaWia2Driver.dll ^
    wiaservc.lib sti.lib ole32.lib oleaut32.lib uuid.lib advapi32.lib

if %ERRORLEVEL% EQU 0 (
    echo [+] Built 64-bit MinoltaWia2Driver.dll successfully.
    echo [*] Registering COM server with regsvr32.exe...
    regsvr32.exe /s MinoltaWia2Driver.dll
)
endlocal
