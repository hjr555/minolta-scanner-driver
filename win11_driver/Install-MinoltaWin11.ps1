<#
.SYNOPSIS
    Automated Windows 11 Driver & Software Installer for the Minolta DiMAGE Scan Dual III
    Hardware ID: USB\VID_0686&PID_400D (Internal Model #2889 / SCSI ID "MINOLTA FS-V3           ")
.DESCRIPTION
    1. Installs DS_Dual3_Win11.inf via pnputil.exe (binds scanner to Microsoft's signed 64-bit usbscan.sys).
    2. Deploys the extracted & binary-patched Minolta DiMAGE Scan Dual III software suite to
       C:\Program Files (x86)\Minolta\DS_Dual3 (with patched MFSIFLib2889.dll fixing the Windows NT+
       handle leak at 0x10001e71 and dwShareMode=0 sharing violation at 0x100017fb / 0x100018b6).
    3. Grants Modify permissions on C:\Program Files (x86)\Minolta\DS_Dual3\Prefs so dark/white shading
       calibration files can be written under Windows 11 UAC without requiring Administrator elevation.
    4. Installs the 32-bit TWAIN DataSource (DS_Dual3.DS) to C:\Windows\twain_32\DS_Dual3 and required
       runtime DLLs (pfudsrv.dll, PQueen20.dll, MCMLDS.dll) to C:\Windows\SysWOW64.
    5. Installs the 8 Minolta ICC color profiles to C:\Windows\System32\spool\drivers\color.
    6. Registers HKLM\SOFTWARE\WOW6432Node\MINOLTA\DS_Dual3 and HKLM\SOFTWARE\MINOLTA\DS_Dual3 HomePath.
    7. Builds and installs the standalone Windows 11 CLI tool (dimage_scan.exe).
#>
[CmdletBinding()]
param(
    [string]$InstallDir = "${env:ProgramFiles(x86)}\Minolta\DS_Dual3"
)

$ErrorActionPreference = "Stop"

# 1. Self-elevate to Administrator if required
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[*] Elevating to Administrator..." -ForegroundColor Yellow
    $argList = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -InstallDir `"$InstallDir`""
    Start-Process powershell.exe -Verb RunAs -ArgumentList $argList
    exit
}

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host " Minolta DiMAGE Scan Dual III (USB\VID_0686&PID_400D) Win11 Installer " -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

$scriptDir   = $PSScriptRoot
$infPath     = Join-Path $scriptDir "DS_Dual3_Win11.inf"
$srcSoftDir  = Join-Path $scriptDir "Minolta_Software"
$scannerTool = Join-Path (Split-Path $scriptDir -Parent) "scanner_tool\Build-WindowsScanner.ps1"

# 2. Install Windows 11 INF Driver (usbscan.sys)
Write-Host "[1/7] Installing Windows 11 USB Still Image driver (DS_Dual3_Win11.inf)..." -ForegroundColor Cyan
& pnputil.exe /add-driver "$infPath" /install
if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 259 -and $LASTEXITCODE -ne 3010) {
    Write-Warning "pnputil returned exit code $LASTEXITCODE. If Memory Integrity/Driver Signature Enforcement prompts, allow the INF or right-click DS_Dual3_Win11.inf -> Show more options -> Install."
} else {
    Write-Host "      Driver registered with Windows PnP." -ForegroundColor Green
}

# 3. Copy Application Suite & Patched MFSIFLib2889.dll
Write-Host "[2/7] Deploying Minolta DiMAGE Scan Dual III software to $InstallDir..." -ForegroundColor Cyan
New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
Copy-Item -Path (Join-Path $srcSoftDir "*") -Destination $InstallDir -Recurse -Force

# 4. Set UAC-safe Modify ACLs on Prefs folder (required by MFSBaseLib2889.dll @ 0x1000cd80)
Write-Host "[3/7] Granting standard user Modify permissions on Prefs\Calibration..." -ForegroundColor Cyan
$prefsDir = Join-Path $InstallDir "Prefs"
New-Item -ItemType Directory -Path (Join-Path $prefsDir "Calibration") -Force | Out-Null
& icacls.exe "$prefsDir" /grant "*S-1-5-32-545:(OI)(CI)M" /T /Q | Out-Null

# 5. Deploy 32-bit TWAIN DataSource & SysWOW64 support DLLs
Write-Host "[4/7] Installing TWAIN DataSource (C:\Windows\twain_32\DS_Dual3) & SysWOW64 DLLs..." -ForegroundColor Cyan
$twainDir = Join-Path $env:WINDIR "twain_32\DS_Dual3"
New-Item -ItemType Directory -Path $twainDir -Force | Out-Null
$twainFiles = @(
    "DS_Dual3.DS",
    "MFSIFLib2889.dll",
    "MFSBaseLib2889.dll",
    "MFSLib2889.dll",
    "MCMLDS.dll",
    "PQueen20.dll",
    "pfudsrv.dll"
)
foreach ($f in $twainFiles) {
    $src = Join-Path $InstallDir $f
    if (Test-Path $src) {
        Copy-Item -Path $src -Destination $twainDir -Force
    }
}

$sysWow64 = Join-Path $env:WINDIR "SysWOW64"
if (Test-Path $sysWow64) {
    foreach ($f in @("pfudsrv.dll", "PQueen20.dll", "MCMLDS.dll")) {
        $src = Join-Path $InstallDir $f
        if (Test-Path $src) {
            Copy-Item -Path $src -Destination $sysWow64 -Force
        }
    }
}

# 6. Install Minolta ICC Color Profiles
Write-Host "[5/7] Installing Minolta ICC color profiles..." -ForegroundColor Cyan
$colorDir = Join-Path $env:WINDIR "System32\spool\drivers\color"
$profileDir = Join-Path $InstallDir "Profile"
if (Test-Path $profileDir) {
    Get-ChildItem -Path $profileDir -Filter "*.icc" | ForEach-Object {
        Copy-Item -Path $_.FullName -Destination $colorDir -Force
    }
}

# 7. Configure Registry Keys (32-bit WOW6432Node and 64-bit native)
Write-Host "[6/7] Writing registry keys (HKLM:\SOFTWARE\WOW6432Node\MINOLTA\DS_Dual3)..." -ForegroundColor Cyan
$regPaths = @(
    "HKLM:\SOFTWARE\WOW6432Node\MINOLTA\DS_Dual3",
    "HKLM:\SOFTWARE\MINOLTA\DS_Dual3",
    "HKCU:\Software\MINOLTA\DS_Dual3"
)
foreach ($rp in $regPaths) {
    if (-not (Test-Path $rp)) {
        New-Item -Path $rp -Force | Out-Null
    }
    Set-ItemProperty -Path $rp -Name "HomePath" -Value $InstallDir -Type String
    Set-ItemProperty -Path $rp -Name "Version"  -Value "1.0.0"     -Type String
}

# 8. Build Standalone Windows 11 CLI Utility & Create Shortcuts
Write-Host "[7/7] Building standalone Windows 11 CLI scanner utility (dimage_scan.exe)..." -ForegroundColor Cyan
if (Test-Path $scannerTool) {
    $outCli = Join-Path $InstallDir "dimage_scan.exe"
    & $scannerTool -OutputExe $outCli
}

$wsh = New-Object -ComObject WScript.Shell
$desktop = [Environment]::GetFolderPath("CommonDesktopDirectory")
$shortcut1 = $wsh.CreateShortcut((Join-Path $desktop "DiMAGE Scan Dual III.lnk"))
$shortcut1.TargetPath = Join-Path $InstallDir "DS_Dual3.exe"
$shortcut1.WorkingDirectory = $InstallDir
$shortcut1.Save()

$shortcut2 = $wsh.CreateShortcut((Join-Path $desktop "DiMAGE Scan Easy.lnk"))
$shortcut2.TargetPath = Join-Path $InstallDir "DS_Dual3Easy.exe"
$shortcut2.WorkingDirectory = $InstallDir
$shortcut2.Save()

Write-Host ""
Write-Host "[+] Installation complete!" -ForegroundColor Green
Write-Host "    - Minolta Utility    : $InstallDir\DS_Dual3.exe"
Write-Host "    - Easy Scan Utility  : $InstallDir\DS_Dual3Easy.exe"
Write-Host "    - Standalone Win11   : $InstallDir\dimage_scan.exe"
Write-Host "    - TWAIN DataSource   : $twainDir\DS_Dual3.DS"
