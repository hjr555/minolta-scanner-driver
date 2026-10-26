# Minolta DiMAGE Scan Dual III (`AF-2840` / `#2889`) — Windows 11 Driver & Software Suite

Modern Windows 10 & Windows 11 (64-bit `x64` / `ARM64`) driver, patched software suite, 64-bit WIA 2.0 minidriver, and standalone C11/CLI scanning tool for the **Minolta DiMAGE Scan Dual III** 35mm film & slide scanner (`USB\VID_0686&PID_400D`, internal model `#2889`, SCSI ID `"MINOLTA FS-V3           "`).

---

## Features

1. **Modern Windows 11 INF Driver ([`win11_driver/DS_Dual3_Win11.inf`](win11_driver/DS_Dual3_Win11.inf))**
   - Binds `USB\VID_0686&PID_400D` to Microsoft's built-in, digitally signed 64-bit kernel driver (`usbscan.sys`) via `Include=sti.inf` and `Needs=STI.USBSection`.
   - Requires **no unsigned kernel drivers**—works out of the box with Windows 11 Secure Boot and Core Isolation / Memory Integrity (HVCI) enabled.
2. **Binary-Patched Original Minolta Software & TWAIN Driver ([`win11_driver/Minolta_Software/`](win11_driver/Minolta_Software/))**
   - Fixes a critical Windows NT+ handle leak and `ERROR_SHARING_VIOLATION` bug in `MFSIFLib2889.dll` that prevented the scanner from opening on modern Windows.
   - Configures Windows 11 `WOW6432Node` registry paths and UAC-safe folder ACLs on `Prefs\Calibration` so dark/white calibration files (`dark.bin`, `white.bin`, `_Base.dat`) can be saved without running as Administrator.
3. **One-Click Windows 11 Installer ([`win11_driver/Install-MinoltaWin11.bat`](win11_driver/Install-MinoltaWin11.bat))**
   - Automated PowerShell installer ([`Install-MinoltaWin11.ps1`](win11_driver/Install-MinoltaWin11.ps1)) that installs the INF driver via `pnputil.exe`, deploys the Minolta utility (`DS_Dual3.exe`), Easy Scan (`DS_Dual3Easy.exe`), 32-bit TWAIN DataSource (`DS_Dual3.DS`), RAM firmware (`DS_Dual3.BIN`), and 8 Minolta ICC color profiles.
4. **Native 64-bit WIA 2.0 Driver ([`wia2_driver/`](wia2_driver/))**
   - 64-bit COM `InProcServer32` implementing `IStiUSD` and `IWiaMiniDrv` (`CLSID {E4088F20-D799-11D2-BAFF-00A02491DF4E}`) so modern 64-bit Windows 11 applications (Windows Scan, Paint, 64-bit Photoshop, Affinity Photo) can scan directly.
5. **Standalone Modern C11 Library & CLI Tool ([`scanner_tool/`](scanner_tool/))**
   - Zero-dependency protocol implementation (`dimage_scan.c` / `dimage_scan.h`) and Windows 11 builder (`Build-WindowsScanner.ps1`) supporting automatic `DS_Dual3.BIN` firmware upload, holder detection, frame positioning (`1..6` strip / `1..4` slide), autofocus, multi-sampling, color negative orange-mask inversion, and 24-bit / 48-bit TIFF & BMP export.

---

## Quick Start (Windows 11 Installation)

1. Clone or download this repository to your Windows 11 PC.
2. Double-click **[`win11_driver/Install-MinoltaWin11.bat`](win11_driver/Install-MinoltaWin11.bat)** (or run [`win11_driver/Install-MinoltaWin11.ps1`](win11_driver/Install-MinoltaWin11.ps1) in PowerShell) and accept the Administrator UAC prompt.
3. Plug in and power on your **Minolta DiMAGE Scan Dual III** scanner.
4. Launch **DiMAGE Scan Dual III** (`C:\Program Files (x86)\Minolta\DS_Dual3\DS_Dual3.exe`) from your Desktop shortcut, use the 32-bit TWAIN driver (`DS Dual3`), or scan from the command line using `dimage_scan.exe`.

> **Note on Windows 11 Driver Signature Enforcement:** Because `DS_Dual3_Win11.inf` is an unsigned `.inf` wrapper around Microsoft's signed `usbscan.sys`, if `pnputil` prompts to confirm an unsigned INF package, click **Install this driver software anyway** (or right-click `DS_Dual3_Win11.inf` $\rightarrow$ **Show more options** $\rightarrow$ **Install**).

---

## Standalone CLI Usage (`dimage_scan`)

The installer automatically builds `dimage_scan.exe` into `C:\Program Files (x86)\Minolta\DS_Dual3\dimage_scan.exe`. You can also build it manually at any time:

### Windows 11 (Zero-Dependency PowerShell Build)
```powershell
cd scanner_tool
.\Build-WindowsScanner.ps1
```
*(Uses `cl.exe` or `gcc.exe` if present in `PATH`, or falls back to the built-in Windows `.NET Framework64 csc.exe` compiler with zero external dependencies.)*

### Linux / MSYS2 / MinGW Build & Protocol Verification Suite
```bash
cd scanner_tool
make all test
```

### Example Commands
```powershell
# Query scanner identity, RAM firmware state, and inserted film holder
dimage_scan.exe info

# Scan Frame 1 at full 2820 DPI optical resolution, 16-bit per channel (48-bit RGB TIFF), Color Negative
dimage_scan.exe scan --frame 1 --dpi 2820 --bits 16 --film neg --out frame01.tif

# Scan Slide 2 at 1410 DPI, 8-bit positive slide film with 4x multi-sampling
dimage_scan.exe scan --frame 2 --dpi 1410 --bits 8 --film pos --multisample 4 --out slide02.tif

# Move film carrier to frame 4, eject, or retract film holder
dimage_scan.exe frame 4
dimage_scan.exe eject
dimage_scan.exe retract
```

---

## Why the Original Driver Stopped Working After Windows XP

Reverse engineering the legacy self-extracting installer (`DD3100E.EXE`, `SHA-256: d3e7520b58e93c25ba496b627bbe8e2358c6bf0e1a29f6afc4e1236e50979104`) and its core DLLs revealed **three distinct bugs** that broke compatibility after Windows XP:

### 1. Legacy 32-Bit INF (`Inf/DS_Dual3.inf`)
- Lacked `[Models.NTamd64]` and `[Models.NTarm64]` target decorations required by 64-bit Windows PnP.
- Attempted to copy `usbscan.sys` directly from Windows 98/2000 installation media (`LayoutFile=Layout.inf, Layout1.inf, Layout2.inf`) instead of delegating to the inbox Windows Still Image driver via `Include=sti.inf` and `Needs=STI.USBSection`.

### 2. Windows NT+ Handle Leak & `ERROR_SHARING_VIOLATION` in `MFSIFLib2889.dll`
In `MFSIFLib2889.dll` (`0x10001c00`–`0x10001eb1`), when `GetVersionExA` reports `dwPlatformId == VER_PLATFORM_WIN32_NT` and `dwMajorVersion >= 5` (`0x10001d79`):
1. The device discovery loop opens `\\.\UsbScan0`..`\\.\UsbScan127` using `CreateFileA` with `dwShareMode = 0` (exclusive access) and stores the returned `HANDLE` at **`0x828(%ebx)`** (`0x10001e71`: `89 83 28 08 00 00`).
2. However, the close helper at `0x10001320` checks and closes **`0x824(%ebx)`**, leaving the probe handle in `0x828(%ebx)` **open and leaked**.
3. Immediately afterward, `OpenUsbDevice` (`0x10001870`) calls `CreateFileA` on the same `\\.\UsbScanN` device with `dwShareMode = 0` (`0x100018b6`: `6a 00`), which fails with `ERROR_SHARING_VIOLATION` (Win32 error 32) because the leaked discovery handle (or the Windows `stisvc` WIA service) already holds the device open.

#### Binary Patch Applied to [`win11_driver/Minolta_Software/MFSIFLib2889.dll`](win11_driver/Minolta_Software/MFSIFLib2889.dll)
| Virtual Address | File Offset | Original Bytes | Patched Bytes | Effect |
|---|---|---|---|---|
| `0x100017fb` | `0x17fc` | `6a 00` | `6a 03` | `push 3` (`FILE_SHARE_READ \| FILE_SHARE_WRITE`) |
| `0x100018b6` | `0x18b7` | `6a 00` | `6a 03` | `push 3` (`FILE_SHARE_READ \| FILE_SHARE_WRITE`) in `OpenUsbDevice` |
| `0x10001e71` | `0x1e73` | `89 83 28 08 00 00` | `89 83 24 08 00 00` | Store probe `HANDLE` in `0x824(%ebx)` so `0x10001320` closes it |

*(An unpatched backup of the original DLL is preserved at [`win11_driver/Minolta_Software/MFSIFLib2889.dll.orig`](win11_driver/Minolta_Software/MFSIFLib2889.dll.orig).)*

### 3. Windows Vista–11 UAC Calibration Write Failure in `MFSBaseLib2889.dll`
At `0x10003f0f` and `0x1000cd80`, `MFSBaseLib2889.dll` reads `HomePath` from `HKLM\SOFTWARE\MINOLTA\DS_Dual3` and writes dark/white calibration files (`dark.bin`, `white.bin`, `_Base.dat`) directly into `<HomePath>\Prefs\Calibration`. Under UAC, standard user processes cannot write to `C:\Program Files (x86)` unless folder ACLs grant Modify permissions (`icacls "...\Prefs" /grant *S-1-5-32-545:(OI)(CI)M /T`).

---

## Reverse-Engineered USB/SCSI Protocol (`USB\VID_0686&PID_400D`)

### 3-Phase USB Transport (`MFSIFLib2889.dll` @ `0x10002830`)
Unlike scanners that use `IOCTL_SEND_USB_REQUEST`, the DiMAGE Scan Dual III tunnels SCSI-2 CDBs over `\\.\UsbScanN` bulk pipes in three synchronous phases:
1. **Phase 1 (CDB Write)**: `WriteFile(hDevice, cdb, 6 or 10)`
2. **Phase 2 (Optional Data Phase)**: `ReadFile(hDevice, buf, len)` (Data-In) or `WriteFile(hDevice, buf, len)` (Data-Out)
3. **Phase 3 (Status Phase)**: `ReadFile(hDevice, &scsi_status, 1)` (`0x00` = Good; `0x02` = Check Condition $\rightarrow$ issue `REQUEST SENSE 0x03` for 22 bytes)

### SCSI Command & Vendor Data-Type Table (`MFSBaseLib2889.dll`)
| Opcode | Data Type (`CDB[2]`) | Qualifier (`CDB[4..5]`) | Length | Dir | Description |
|---|---|---|---|---|---|
| `0x00` | — | — | `0` | None | `TEST UNIT READY` (`0x1000c880`) |
| `0x03` | — | — | `22` | IN | `REQUEST SENSE` (`0x1000c960`, 22-byte sense buffer) |
| `0x12` | — | — | `96` | IN | `INQUIRY` (`0x1000c8e0`, returns `"MINOLTA FS-V3           "`) |
| `0x16` | — | — | `0` | None | `RESERVE UNIT` (`0x1000c9d0`) |
| `0x17` | — | — | `0` | None | `RELEASE UNIT` (`0x1000ca20`) |
| `0x1B` | — | — | `0` | None | `START/STOP SCAN` (`0x10007398`, `CDB[4]=0x01`, `CDB[5]=mode`) |
| `0x24` | — | — | `78`/`79` | OUT | `SET WINDOW` (`0x10008160`, 8B header + `0x46`/`0x47`B descriptor) |
| `0x31` | — | `CDB[9]=0x00/0x02` | `0` | None | `OBJECT POSITION` (`0x1000cad0`, `0x00`=Eject, `0x02`=Retract) |
| `0x28` | `0x00` | `0x0000` | `N` | IN | Read scanned image lines (8-bit or 12-bit big-endian RGB) |
| `0x28` | `0x60` | `0x0000` | `32` | IN | Read scanner & holder status (`raw[4]`: `1`=Strip, `2`=Slide, `0xFF`=None) |
| `0x28` | `0x61`/`0x62` | `0x0000` | `N` | IN | Read white shading calibration lines (`0x10005168`) |
| `0x28` | `0x66` | `0x0000` | `N` | IN | Read dark current calibration lines (`0x10006024`) |
| `0x28`/`0x2A` | `0x6C` | `idx` | `24` / `N` | IN/OUT | Read 24B motor ramp descriptor & upload `N`-step acceleration table (`0x100073b0`) |
| `0x2A` | `0x81` | `0..2` | `512` | OUT | Upload 256-entry 16-bit LE Gamma LUT per channel (`0x100092f0`) |
| `0x2A` | `0x82` | `0..2` | `N` | OUT | Upload per-pixel shading correction data (`0x10009098`) |
| `0x28`/`0x2A` | `0x87` | `0x0000` | `8` | IN/OUT | Get/Set film holder frame index (`1..6` strip, `1..4` slide, `0x10004ad2`) |
| `0x2A` | `0x88` | `0x0000` | `8` | OUT | Set autofocus stepper position (`0x10004b4c`) |
| `0x28` | `0x90` | `0x0022` | `8` | IN | Check RAM firmware status (`buf[4] == 0` $\rightarrow$ active, `0x1000c136`) |
| `0x2A` | `0x90` | `0x0000` | `47904` | OUT | Upload `DS_Dual3.BIN` (47,900B + 4B LE32 byte sum = `0x004A93E1`, `0x1000c3cc`) |
| `0x2A` | `0x92` | `0x0000` | `8` | OUT | Initialize scanner mode (`0x10005a40`) |
| `0x28` | `0xA0` | `0x0000` | `1` | IN | Read cold-cathode lamp warm-up status (`0x10005bc0`) |

---

## Repository Structure

```text
.
├── LICENSE                             # MIT License (+ legacy firmware/binary notice)
├── README.md                           # Documentation & reverse-engineering reference
├── win11_driver/
│   ├── DS_Dual3_Win11.inf              # Modern Windows 10/11 (amd64/arm64/x86) usbscan.sys INF driver
│   ├── Install-MinoltaWin11.bat        # One-click Windows 11 installer launcher
│   ├── Install-MinoltaWin11.ps1        # Automated PowerShell installer & UAC/WOW6432Node configurator
│   └── Minolta_Software/               # Extracted Minolta software, firmware, ICC profiles & patched DLL
├── scanner_tool/
│   ├── dimage_scan.h                   # Reverse-engineered C11 USB/SCSI protocol header
│   ├── dimage_scan.c                   # Cross-platform protocol implementation & standalone CLI tool
│   ├── Build-WindowsScanner.ps1        # Zero-dependency Windows 11 native EXE builder
│   ├── test_protocol.c                 # Stateful mock-hardware unit test suite (117 SCSI transactions)
│   └── Makefile                        # Build & test Makefile
└── wia2_driver/
    ├── MinoltaWia2Driver.cpp           # 64-bit Windows Image Acquisition (WIA 2.0 / STI) COM driver
    ├── MinoltaWia2Driver.def           # COM DLL export definitions
    ├── CMakeLists.txt                  # CMake build configuration
    └── build_wia2.bat                  # Visual Studio x64 Native Tools build & registration script
```

---

## License

All newly written source code, reverse-engineered protocol libraries (`scanner_tool/`), WIA 2.0 driver code (`wia2_driver/`), Windows 11 INF (`DS_Dual3_Win11.inf`), and installer scripts are released under the [MIT License](LICENSE). The original archive (`DD3100E.EXE`) and extracted Minolta binaries/firmware under `win11_driver/Minolta_Software/` remain copyright Minolta Co., Ltd. / Konica Minolta, Inc. and are provided for hardware interoperability and preservation.
