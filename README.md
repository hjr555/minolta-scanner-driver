# Minolta DiMAGE Scan Dual III (`AF-2840` / `#2889`) — Windows 11 Driver & 1970s/80s Film Studio

Modern Windows 10 & Windows 11 (64-bit `x64` / `ARM64`) driver, patched software suite, parent-proof **1970s & 1980s Film & Slide Desktop Studio (`MinoltaScanApp.exe`)**, 64-bit WIA 2.0 minidriver, and standalone C11/CLI scanning tool for the **Minolta DiMAGE Scan Dual III** 35mm film & slide scanner (`USB\VID_0686&PID_400D`, internal model `#2889`, SCSI ID `"MINOLTA FS-V3           "`).

---

## Highlights & Parent-Proof Reliability

1. **100% Automatic, Silent-Signed Windows 11 Driver Installation ([`win11_driver/Install-MinoltaWin11.bat`](win11_driver/Install-MinoltaWin11.bat))**
   - Automatically generates a valid Windows security catalog (`DS_Dual3_Win11.cat`) via Windows' built-in `mscat32.dll` API, signs it with a local trusted certificate (`LocalMachine\Root` & `TrustedPublisher`), and installs [`DS_Dual3_Win11.inf`](win11_driver/DS_Dual3_Win11.inf) via `pnputil.exe` with **zero unsigned-driver errors or popups**.
   - Binds `USB\VID_0686&PID_400D` to Microsoft's built-in WHQL-signed `usbscan.sys` and `sti.dll`—works out of the box with **Windows 11 Secure Boot** and **Core Isolation / Memory Integrity (HVCI)** enabled.
2. **Parent-Proof "Minolta 1970s–80s Film & Slide Studio" Desktop App (`MinoltaScanApp.exe`)**
   - Built automatically during installation using Windows 11's built-in `.NET Framework64` compiler (`csc.exe`)—**no Visual Studio or external tools required**.
   - **One-Click Single Frame & Full-Strip Batch Scanning**: Scan a single frame or click **"Scan Entire Strip (All 6 Frames / 4 Slides)"** to automatically step through the whole film holder and save numbered `.jpg`, `.png`, or `.tif` files directly to `Pictures\Minolta Scans`.
   - **1970s & 1980s Faded Film & Orange-Mask Restoration**: Uses a 4096-bin per-channel histogram over the inner 90% of the frame (ignoring the plastic holder border and sprocket holes) to compute true **0.5th–99.5th percentile auto-levels**, removing the orange mask on Color Negatives and restoring contrast on faded 1970s/80s Kodacolor, Fujicolor, Kodachrome, and Tri-X B&W negatives.
   - **One-Click Microsoft Word & GIMP Buttons**:
     - Every scan is automatically copied to the Windows Clipboard (`Ctrl+V` into Microsoft Word or email).
     - Click **"Insert Photo Directly into Microsoft Word"** to launch Word and place the scanned image directly onto a document page.
     - Click **"Open Scanned Photo in GIMP"** to open the scan directly in GIMP.
   - **One-Click "Fix Blinking Light / Reset Scanner" Recovery**: Automatically recovers the scanner if a film holder was accidentally left inside during power-on (which blocks the optical calibration sensor and causes the green LED to blink rapidly), and polls the cold-cathode fluorescent lamp warm-up (`READ(10) 0xA0`) for up to 60 seconds.
3. **Full 64-Bit GIMP TWAIN & Original Minolta Utilities (`DS_Dual3.exe` & `DS_Dual3Easy.exe`)**
   - Deploys the binary-patched [`MFSIFLib2889.dll`](win11_driver/Minolta_Software/MFSIFLib2889.dll) and all 5 companion DLLs (`MFSBaseLib2889.dll`, `MFSLib2889.dll`, `MCMLDS.dll`, `PQueen20.dll`, `pfudsrv.dll`) to **both** `C:\Windows\twain_32\DS_Dual3` **and** `C:\Windows\SysWOW64` so 64-bit GIMP's TWAIN plug-in (`File -> Create -> Scanner/Camera -> DS Dual3`) loads with zero missing-DLL errors.
   - Configures both `HKLM\SOFTWARE\WOW6432Node\MINOLTA\DS_Dual3` and `HKLM\SOFTWARE\WOW6432Node\MINOLTA\DS_Dual3Easy`, sets default `ScanFolder` to `Pictures\Minolta Scans`, and grants UAC-safe Modify permissions on `Prefs\Calibration`.

---

## Step-by-Step Windows 11 Installation (Zero Technical Knowledge Needed)

1. Download or copy this folder to the Windows 11 PC.
2. Double-click **[`win11_driver/Install-MinoltaWin11.bat`](win11_driver/Install-MinoltaWin11.bat)** and click **Yes** when Windows asks for Administrator permission.
3. When the completion message appears, click **Yes** to launch the **Minolta 1970s–80s Film Scanner** studio!
4. Turn **ON** the Minolta DiMAGE Scan Dual III (with the film slot empty so it can calibrate its lamp), wait for the green light to stop blinking, and slide in your film strip or slide holder.

### Using the Scanner from Everyday Apps on Windows 11

| Application | How to Scan |
|---|---|
| **Desktop Shortcut (`Minolta 1970s-80s Film Scanner`)** | Choose film type (`Color Negative`, `B&W Negative`, or `Color Slide`), click **Scan Selected Frame** or **Scan Entire Strip (All 6 Frames)**. |
| **Microsoft Word** | Click **Scan** in the Minolta Film Scanner app, then either click **Insert Photo Directly into Microsoft Word** or switch to Word and press **`Ctrl+V`** (Paste). |
| **GIMP (64-bit)** | In GIMP, click **`File` $\rightarrow$ `Create` $\rightarrow$ `Scanner/Camera...` $\rightarrow$ `DS Dual3`**, or click **Open Scanned Photo in GIMP** inside the Minolta Film Scanner app. |
| **Original Minolta Apps** | Use the **DiMAGE Scan Easy** (4-step wizard) or **DiMAGE Scan Dual III** (advanced controls) shortcuts on the Desktop. |

---

## Why the Original Driver Stopped Working After Windows XP

Reverse engineering the legacy self-extracting installer (`DD3100E.EXE`, `SHA-256: d3e7520b58e93c25ba496b627bbe8e2358c6bf0e1a29f6afc4e1236e50979104`) and its core DLLs revealed **four distinct bugs** that broke compatibility after Windows XP:

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
At `0x10003f0f` and `0x1000cd80`, `MFSBaseLib2889.dll` reads `HomePath` from `HKLM\SOFTWARE\MINOLTA\DS_Dual3` and writes dark/white calibration files (`dark.bin`, `white.bin`, `_Base.dat`) directly into `<HomePath>\Prefs\Calibration`. Under UAC, standard user processes cannot write to `C:\Program Files (x86)` unless folder ACLs grant Modify permissions (`icacls "...\InstallDir" /grant *S-1-5-32-545:(OI)(CI)M /T`).

### 4. `SysWOW64` DLL Search Order & `DS_Dual3Easy` Registry Key on 64-Bit Windows
- When 64-bit GIMP's TWAIN helper calls `twain_32.dll` $\rightarrow$ `LoadLibraryA("C:\\Windows\\twain_32\\DS_Dual3\\DS_Dual3.DS")`, Windows searches the host `.exe` folder and `C:\Windows\SysWOW64` (not `C:\Windows\twain_32\DS_Dual3`) for statically imported DLLs (`MFSLib2889.dll`, `MFSBaseLib2889.dll`, `MFSIFLib2889.dll`). Copying all 6 DLLs to `SysWOW64` makes TWAIN loading in GIMP work seamlessly.
- `DS_Dual3Easy.exe` reads `HomePath` from `HKLM\SOFTWARE\WOW6432Node\MINOLTA\DS_Dual3Easy` (PE string resource `0x15b53c`), whereas `DS_Dual3.exe` reads `HKLM\SOFTWARE\WOW6432Node\MINOLTA\DS_Dual3`.

---

## Standalone CLI Usage (`dimage_scan`)

```powershell
# Launch the interactive Windows GUI Studio
dimage_scan.exe

# Query scanner identity, RAM firmware state, and inserted film holder
dimage_scan.exe info

# Scan Frame 1 at 2820 DPI optical resolution, Color Negative
dimage_scan.exe scan --frame 1 --dpi 2820 --bits 16 --film neg --out frame01.tif

# Batch scan an entire 6-frame 35mm strip (or 4-slide holder)
dimage_scan.exe scan-strip --dpi 1410 --film neg --out strip1978

# Recover blinking LED if a film holder was left inside during power-on
dimage_scan.exe reset

# Move film carrier to frame 4, eject, or retract film holder
dimage_scan.exe frame 4
dimage_scan.exe eject
dimage_scan.exe retract
```

---

## Reverse-Engineered USB/SCSI Protocol (`USB\VID_0686&PID_400D`)

### 3-Phase USB Transport (`MFSIFLib2889.dll` @ `0x10002830`)
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

## License

All newly written source code, reverse-engineered protocol libraries (`scanner_tool/`), WIA 2.0 driver code (`wia2_driver/`), Windows 11 INF (`DS_Dual3_Win11.inf`), and installer scripts are released under the [MIT License](LICENSE). Extracted Minolta binaries/firmware under `win11_driver/Minolta_Software/` remain copyright Minolta Co., Ltd. / Konica Minolta, Inc. and are provided for hardware interoperability and preservation.
