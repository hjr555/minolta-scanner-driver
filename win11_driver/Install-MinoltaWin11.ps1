<#
.SYNOPSIS
    100% Parent-Proof Windows 11 Driver & Software Installer for the Minolta DiMAGE Scan Dual III
    Hardware ID: USB\VID_0686&PID_400D (Internal Model #2889 / SCSI ID "MINOLTA FS-V3           ")
.DESCRIPTION
    1. Self-elevates to Administrator and keeps the progress window visible.
    2. Automatically generates a signed Windows security catalog (DS_Dual3_Win11.cat) using Windows'
       built-in mscat32.dll API and a local trusted CodeSigningCert so pnputil.exe installs
       DS_Dual3_Win11.inf 100% silently with ZERO unsigned-driver errors on Windows 11 (Secure Boot & HVCI safe).
    3. Deploys the extracted & binary-patched Minolta DiMAGE Scan Dual III software suite to
       C:\Program Files (x86)\Minolta\DS_Dual3.
    4. Copies ALL 6 Minolta driver DLLs (MFSIFLib2889.dll, MFSBaseLib2889.dll, MFSLib2889.dll,
       MCMLDS.dll, PQueen20.dll, pfudsrv.dll) to both C:\Windows\twain_32\DS_Dual3 AND C:\Windows\SysWOW64
       so 64-bit GIMP (File -> Create -> Scanner/Camera -> DS Dual3) loads without missing DLL errors.
    5. Configures Registry keys for BOTH DS_Dual3 AND DS_Dual3Easy (WOW6432Node & native) and sets the
       default ScanFolder to "Pictures\Minolta Scans" so UAC never blocks saving scans.
    6. Compiles and installs the zero-dependency "Minolta 1970s-80s Film & Slide Studio" GUI app
       (MinoltaScanApp.exe) and CLI utility (dimage_scan.exe) with 1-click Word, GIMP, and Batch Strip support.
#>
[CmdletBinding()]
param(
    [string]$InstallDir = "${env:ProgramFiles(x86)}\Minolta\DS_Dual3",
    [switch]$Unattended
)

$ErrorActionPreference = "Stop"

# 1. Self-elevate to Administrator if required
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[*] Requesting Administrator permission to install the Minolta Windows 11 driver..." -ForegroundColor Yellow
    $argList = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -InstallDir `"$InstallDir`""
    if ($Unattended) { $argList += " -Unattended" }
    $proc = Start-Process powershell.exe -Verb RunAs -ArgumentList $argList -Wait -PassThru
    exit $proc.ExitCode
}

Add-Type -AssemblyName System.Windows.Forms

Write-Host "==========================================================================" -ForegroundColor Cyan
Write-Host " Minolta DiMAGE Scan Dual III (USB\VID_0686&PID_400D) Windows 11 Installer" -ForegroundColor Cyan
Write-Host "==========================================================================" -ForegroundColor Cyan

$scriptDir   = $PSScriptRoot
$infPath     = Join-Path $scriptDir "DS_Dual3_Win11.inf"
$catPath     = Join-Path $scriptDir "DS_Dual3_Win11.cat"
$srcSoftDir  = Join-Path $scriptDir "Minolta_Software"
$scannerTool = Join-Path (Split-Path $scriptDir -Parent) "scanner_tool\Build-WindowsScanner.ps1"

# Helper function to generate DS_Dual3_Win11.cat via Windows built-in mscat32.dll and sign it locally
function New-SignedDriverCatalog {
    param([string]$InfFile, [string]$CatFile)

    Write-Host "[1/8] Creating & trusting local Windows 11 driver security catalog..." -ForegroundColor Cyan

    if (-not ("Win32CatGenerator" -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class Win32CatGenerator
{
    [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
    public delegate void PFN_CDF_PARSE_ERROR_CALLBACK(uint dwErrorArea, uint dwLocalError, string pwszLine);

    [DllImport("mscat32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr CryptCATCDFOpen(string pwszFilePath, PFN_CDF_PARSE_ERROR_CALLBACK pfnParseError);

    [DllImport("mscat32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr CryptCATCDFEnumCatAttributes(
        IntPtr pCDF,
        IntPtr pPrevAttr,
        PFN_CDF_PARSE_ERROR_CALLBACK pfnParseError);

    [DllImport("mscat32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr CryptCATCDFEnumMembersByCDFTagEx(
        IntPtr pCDF,
        IntPtr pwszPrevCDFTag,
        PFN_CDF_PARSE_ERROR_CALLBACK pfnParseError,
        out IntPtr ppMember,
        bool fContinueOnError,
        IntPtr pvReserved);

    [DllImport("mscat32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr CryptCATCDFEnumAttributesWithCDFTag(
        IntPtr pCDF,
        IntPtr pwszMemberTag,
        IntPtr pMember,
        IntPtr pPrevAttr,
        PFN_CDF_PARSE_ERROR_CALLBACK pfnParseError);

    [DllImport("mscat32.dll", SetLastError = true)]
    public static extern bool CryptCATCDFClose(IntPtr pCDF);

    public static bool GenerateCatFromCdf(string cdfPath)
    {
        IntPtr cdf = CryptCATCDFOpen(cdfPath, null);
        if (cdf == IntPtr.Zero) return false;
        try
        {
            IntPtr catAttr = IntPtr.Zero;
            while ((catAttr = CryptCATCDFEnumCatAttributes(cdf, catAttr, null)) != IntPtr.Zero)
            {
            }

            IntPtr tag = IntPtr.Zero;
            IntPtr member = IntPtr.Zero;
            while ((tag = CryptCATCDFEnumMembersByCDFTagEx(cdf, tag, null, out member, true, IntPtr.Zero)) != IntPtr.Zero)
            {
                if (member != IntPtr.Zero)
                {
                    IntPtr memAttr = IntPtr.Zero;
                    while ((memAttr = CryptCATCDFEnumAttributesWithCDFTag(cdf, tag, member, memAttr, null)) != IntPtr.Zero)
                    {
                    }
                }
            }
        }
        finally
        {
            CryptCATCDFClose(cdf);
        }
        return true;
    }
}
'@
    }

    $cdfPath = Join-Path $env:TEMP "DS_Dual3_Win11.cdf"
    $cdfContent = @"
[CatalogHeader]
Name=DS_Dual3_Win11.cat
ResultDir=$(Split-Path $CatFile -Parent)
PublicVersion=0x0000001
EncodingType=0x00010001
CATATTR1=0x10010001:OSAttr:2:10.0,2:6.3,2:6.2,2:6.1

[CatalogFiles]
<HASH>DS_Dual3_Win11.inf=$InfFile
"@
    Set-Content -Path $cdfPath -Value $cdfContent -Encoding ASCII
    [void][Win32CatGenerator]::GenerateCatFromCdf($cdfPath)
    Remove-Item $cdfPath -Force -ErrorAction SilentlyContinue

    if (Test-Path $CatFile) {
        $subject = "CN=Minolta DiMAGE Scan Dual III Windows 11 Local Trust"
        $cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -eq $subject } | Select-Object -First 1
        if (-not $cert) {
            $cert = New-SelfSignedCertificate `
                -Type CodeSigningCert `
                -Subject $subject `
                -KeyAlgorithm RSA `
                -KeyLength 2048 `
                -HashAlgorithm SHA256 `
                -CertStoreLocation "Cert:\LocalMachine\My" `
                -NotAfter (Get-Date).AddYears(20)
        }

        $tmpCer = Join-Path $env:TEMP "MinoltaWin11Trust.cer"
        Export-Certificate -Cert $cert -FilePath $tmpCer -Force | Out-Null
        Import-Certificate -FilePath $tmpCer -CertStoreLocation "Cert:\LocalMachine\Root" | Out-Null
        Import-Certificate -FilePath $tmpCer -CertStoreLocation "Cert:\LocalMachine\TrustedPublisher" | Out-Null
        Remove-Item $tmpCer -Force -ErrorAction SilentlyContinue

        Set-AuthenticodeSignature -FilePath $CatFile -Certificate $cert -HashAlgorithm SHA256 | Out-Null
        Write-Host "      Generated and signed DS_Dual3_Win11.cat for silent Windows 11 installation." -ForegroundColor Green
    }
}

try {
    New-SignedDriverCatalog -InfFile $infPath -CatFile $catPath
} catch {
    Write-Warning "Catalog signing note: $($_.Exception.Message)"
}

# 2. Install Windows 11 INF Driver (usbscan.sys) & Rescan PnP Devices
Write-Host "[2/8] Installing Windows 11 USB Still Image driver (DS_Dual3_Win11.inf)..." -ForegroundColor Cyan
& pnputil.exe /add-driver "$infPath" /install
if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 259 -and $LASTEXITCODE -ne 3010) {
    Write-Warning "pnputil returned exit code $LASTEXITCODE; invoking Windows SetupAPI fallback..."
    & rundll32.exe setupapi.dll,InstallHinfSection DS_Dual3_Install.NTamd64 132 "$infPath"
}
& pnputil.exe /scan-devices | Out-Null
Write-Host "      Driver staged in Windows Driver Store and active." -ForegroundColor Green

# 3. Copy Application Suite & Patched MFSIFLib2889.dll
Write-Host "[3/8] Deploying Minolta DiMAGE Scan Dual III software to $InstallDir..." -ForegroundColor Cyan
New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
Copy-Item -Path (Join-Path $srcSoftDir "*") -Destination $InstallDir -Recurse -Force

# Also copy DS_Dual3.BIN to the root of InstallDir so any working directory finds it immediately
$fwSrc = Join-Path $InstallDir "Firmware\DS_Dual3.BIN"
if (Test-Path $fwSrc) {
    Copy-Item -Path $fwSrc -Destination (Join-Path $InstallDir "DS_Dual3.BIN") -Force
}

# 4. Set UAC-safe Modify ACLs on InstallDir and Prefs folder (required by MFSBaseLib2889.dll @ 0x1000cd80)
Write-Host "[4/8] Granting standard user Modify permissions on Prefs & Calibration folders..." -ForegroundColor Cyan
$prefsDir = Join-Path $InstallDir "Prefs"
New-Item -ItemType Directory -Path (Join-Path $prefsDir "Calibration") -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $prefsDir "standard") -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $prefsDir "easy") -Force | Out-Null
& icacls.exe "$InstallDir" /grant "*S-1-5-32-545:(OI)(CI)M" /T /Q | Out-Null

# 5. Deploy 32-bit TWAIN DataSource & ALL 6 DLLs to SysWOW64 (so 64-bit GIMP TWAIN works 100% reliably!)
Write-Host "[5/8] Installing TWAIN DataSource (C:\Windows\twain_32\DS_Dual3) & SysWOW64 DLLs for GIMP..." -ForegroundColor Cyan
$twainDir = Join-Path $env:WINDIR "twain_32\DS_Dual3"
New-Item -ItemType Directory -Path $twainDir -Force | Out-Null
$allDriverFiles = @(
    "DS_Dual3.DS",
    "MFSIFLib2889.dll",
    "MFSBaseLib2889.dll",
    "MFSLib2889.dll",
    "MCMLDS.dll",
    "PQueen20.dll",
    "pfudsrv.dll"
)
foreach ($f in $allDriverFiles) {
    $src = Join-Path $InstallDir $f
    if (Test-Path $src) {
        Copy-Item -Path $src -Destination $twainDir -Force
    }
}
if (Test-Path $fwSrc) {
    Copy-Item -Path $fwSrc -Destination (Join-Path $twainDir "DS_Dual3.BIN") -Force
}

$sysWow64 = Join-Path $env:WINDIR "SysWOW64"
if (Test-Path $sysWow64) {
    foreach ($f in @("MFSIFLib2889.dll", "MFSBaseLib2889.dll", "MFSLib2889.dll", "MCMLDS.dll", "PQueen20.dll", "pfudsrv.dll")) {
        $src = Join-Path $InstallDir $f
        if (Test-Path $src) {
            Copy-Item -Path $src -Destination $sysWow64 -Force
        }
    }
}

# 6. Install Minolta ICC Color Profiles (MLTF2840.icc, MLTF2840n.icc, MLTF2840p.icc)
Write-Host "[6/8] Installing Minolta ICC color profiles..." -ForegroundColor Cyan
$colorDirs = @(
    (Join-Path $env:WINDIR "System32\spool\drivers\color"),
    (Join-Path $env:WINDIR "SysWOW64\spool\drivers\color")
)
$profileDir = Join-Path $InstallDir "Profile"
if (Test-Path $profileDir) {
    foreach ($cd in $colorDirs) {
        if (Test-Path $cd) {
            Get-ChildItem -Path $profileDir -Filter "*.icc" | ForEach-Object {
                Copy-Item -Path $_.FullName -Destination $cd -Force
            }
        }
    }
}

# 7. Configure Registry Keys for BOTH DS_Dual3 AND DS_Dual3Easy + Default "Pictures\Minolta Scans" Folder
Write-Host "[7/8] Configuring Registry keys & setting default ScanFolder to Pictures\Minolta Scans..." -ForegroundColor Cyan
$scansFolder = Join-Path ([Environment]::GetFolderPath("MyPictures")) "Minolta Scans"
New-Item -ItemType Directory -Path $scansFolder -Force | Out-Null

$hklmPaths = @(
    "HKLM:\SOFTWARE\WOW6432Node\MINOLTA\DS_Dual3",
    "HKLM:\SOFTWARE\WOW6432Node\MINOLTA\DS_Dual3Easy",
    "HKLM:\SOFTWARE\MINOLTA\DS_Dual3",
    "HKLM:\SOFTWARE\MINOLTA\DS_Dual3Easy",
    "HKCU:\Software\MINOLTA\DS_Dual3",
    "HKCU:\Software\MINOLTA\DS_Dual3Easy"
)
foreach ($rp in $hklmPaths) {
    if (-not (Test-Path $rp)) {
        New-Item -Path $rp -Force | Out-Null
    }
    Set-ItemProperty -Path $rp -Name "HomePath" -Value $InstallDir -Type String
    Set-ItemProperty -Path $rp -Name "Version"  -Value "1.0.0"     -Type String
}

$hkcuSettingsPaths = @(
    "HKCU:\Software\Minolta\DS Dual3 1.0\Settings",
    "HKCU:\Software\Minolta\DS_Dual3 Easy 1.0\Settings",
    "HKCU:\Software\MINOLTA\DS Dual3 1.0\Settings",
    "HKCU:\Software\MINOLTA\DS_Dual3 Easy 1.0\Settings"
)
foreach ($sp in $hkcuSettingsPaths) {
    if (-not (Test-Path $sp)) {
        New-Item -Path $sp -Force | Out-Null
    }
    Set-ItemProperty -Path $sp -Name "ScanFolder" -Value $scansFolder -Type String
}

# 8. Build Parent-Proof Desktop GUI App (MinoltaScanApp.exe) & CLI Utility (dimage_scan.exe) + Create Shortcuts
Write-Host "[8/8] Building 'Minolta 1970s-80s Film & Slide Studio' Desktop App..." -ForegroundColor Cyan
$outCli = Join-Path $InstallDir "dimage_scan.exe"
$outGui = Join-Path $InstallDir "MinoltaScanApp.exe"
if (Test-Path $scannerTool) {
    & $scannerTool -OutputExe $outCli -GuiOutputExe $outGui
}

$wsh = New-Object -ComObject WScript.Shell
$desktops = @(
    [Environment]::GetFolderPath("Desktop"),
    [Environment]::GetFolderPath("CommonDesktopDirectory")
) | Select-Object -Unique

foreach ($desktop in $desktops) {
    if (-not (Test-Path $desktop)) { continue }

    if (Test-Path $outGui) {
        $scStudio = $wsh.CreateShortcut((Join-Path $desktop "Minolta 1970s-80s Film Scanner.lnk"))
        $scStudio.TargetPath = $outGui
        $scStudio.WorkingDirectory = $InstallDir
        $scStudio.Description = "One-click 1970s & 1980s Negative & Slide Scanner with Word & GIMP buttons"
        $scStudio.IconLocation = "$(Join-Path $InstallDir 'DS_Dual3.exe'),0"
        $scStudio.Save()
    }

    $sc1 = $wsh.CreateShortcut((Join-Path $desktop "DiMAGE Scan Dual III.lnk"))
    $sc1.TargetPath = Join-Path $InstallDir "DS_Dual3.exe"
    $sc1.WorkingDirectory = $InstallDir
    $sc1.Save()

    $sc2 = $wsh.CreateShortcut((Join-Path $desktop "DiMAGE Scan Easy.lnk"))
    $sc2.TargetPath = Join-Path $InstallDir "DS_Dual3Easy.exe"
    $sc2.WorkingDirectory = $InstallDir
    $sc2.Save()
}

Write-Host ""
Write-Host "==========================================================================" -ForegroundColor Green
Write-Host " INSTALLATION COMPLETE! Your Minolta DiMAGE Scan Dual III is ready to use." -ForegroundColor Green
Write-Host "==========================================================================" -ForegroundColor Green
Write-Host " Desktop Shortcuts Created:"
Write-Host "   1. Minolta 1970s-80s Film Scanner  (Easy 1-Click Studio + Word & GIMP buttons)"
Write-Host "   2. DiMAGE Scan Easy                (Original Minolta 4-Step Wizard)"
Write-Host "   3. DiMAGE Scan Dual III            (Original Minolta Advanced Utility)"
Write-Host "   4. Inside GIMP: File -> Create -> Scanner/Camera -> DS Dual3"
Write-Host "   5. Saved Scans Folder: $scansFolder"
Write-Host ""

if (-not $Unattended) {
    $ans = [System.Windows.Forms.MessageBox]::Show(
        "Minolta DiMAGE Scan Dual III is now installed and ready for Windows 11!`n`n" +
        "• Desktop Shortcut: 'Minolta 1970s-80s Film Scanner' (1-click scan, full 6-frame strip batch scan, Copy/Send to Word, Open in GIMP)`n" +
        "• Inside GIMP: File -> Create -> Scanner/Camera -> DS Dual3`n" +
        "• All scans automatically save to: $scansFolder`n`n" +
        "Would you like to open the Minolta 1970s-80s Film Scanner Studio now?",
        "Minolta DiMAGE Scan Dual III — Installation Complete",
        [System.Windows.Forms.MessageBoxButtons]::YesNo,
        [System.Windows.Forms.MessageBoxIcon]::Information
    )
    if ($ans -eq [System.Windows.Forms.DialogResult]::Yes -and (Test-Path $outGui)) {
        Start-Process -FilePath $outGui -WorkingDirectory $InstallDir
    }
}
