<#
.SYNOPSIS
    Builds the parent-proof Minolta DiMAGE Scan Dual III Windows 11 Desktop GUI & CLI Scanner
    (MinoltaScanApp.exe and dimage_scan.exe) using Windows' built-in .NET Framework64 compiler (csc.exe).
.DESCRIPTION
    Requires ZERO external compilers (no Visual Studio or MinGW required).
    Uses C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe (built into every Windows 10/11 PC)
    to compile a self-contained 64-bit Windows application that provides:
      1. A friendly "Dad-Proof" Windows Forms GUI (when launched with no arguments / from Desktop shortcut)
         with 1-click Single Frame Scan, 1-click Full Strip Batch Scan (Frames 1-6 / Slides 1-4),
         automatic 1970s/80s Color Negative orange-mask removal & faded-film histogram restoration,
         1-click "Copy to Clipboard (Paste in Word)", "Send to Microsoft Word", "Open in GIMP",
         "Eject Film Holder", and "Fix Blinking Light / Reset Scanner" recovery.
      2. Full CLI support (info, scan, scan-strip, eject, retract, reset, frame) when run from a terminal.
#>
[CmdletBinding()]
param(
    [string]$OutputExe = (Join-Path $PSScriptRoot "dimage_scan.exe"),
    [string]$GuiOutputExe = ""
)

$ErrorActionPreference = "Stop"

$csFile = Join-Path $env:TEMP "MinoltaDimageScanFull.cs"
$csCode = @'
using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Imaging;
using System.Windows.Forms;
using System.Runtime.InteropServices;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

namespace MinoltaDimageScan
{
    internal static class NativeUsbScan
    {
        public const uint GENERIC_READ = 0x80000000;
        public const uint GENERIC_WRITE = 0x40000000;
        public const uint FILE_SHARE_READ = 0x00000001;
        public const uint FILE_SHARE_WRITE = 0x00000002;
        public const uint OPEN_EXISTING = 3;
        public const uint IOCTL_GET_DEVICE_DESCRIPTOR = 0x80002018;

        [StructLayout(LayoutKind.Sequential)]
        public struct USBSCAN_DEVICE_DESCRIPTOR
        {
            public ushort usVendorId;
            public ushort usProductId;
            public ushort usBcdDevice;
            public ushort usLanguageId;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern SafeFileHandle CreateFile(
            string lpFileName,
            uint dwDesiredAccess,
            uint dwShareMode,
            IntPtr lpSecurityAttributes,
            uint dwCreationDisposition,
            uint dwFlagsAndAttributes,
            IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool DeviceIoControl(
            SafeFileHandle hDevice,
            uint dwIoControlCode,
            IntPtr lpInBuffer,
            uint nInBufferSize,
            out USBSCAN_DEVICE_DESCRIPTOR lpOutBuffer,
            uint nOutBufferSize,
            out uint lpBytesReturned,
            IntPtr lpOverlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadFile(
            SafeFileHandle hFile,
            byte[] lpBuffer,
            uint nNumberOfBytesToRead,
            out uint lpNumberOfBytesRead,
            IntPtr lpOverlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteFile(
            SafeFileHandle hFile,
            byte[] lpBuffer,
            uint nNumberOfBytesToWrite,
            out uint lpNumberOfBytesWritten,
            IntPtr lpOverlapped);

        [DllImport("kernel32.dll")]
        public static extern IntPtr GetConsoleWindow();
    }

    public enum FilmType
    {
        ColorNegative = 1,
        BlackAndWhiteNegative = 2,
        ColorSlidePositive = 0
    }

    public sealed class DimageScanner : IDisposable
    {
        public const ushort VID_MINOLTA = 0x0686;
        public const ushort PID_DUAL_III = 0x400D;
        public const int OPTICAL_DPI = 2820;
        public const int MAX_WIDTH_PX = 2688;
        public const int MAX_HEIGHT_PX = 4032;

        private SafeFileHandle _handle;
        private Mutex _ipcMutex;
        public string DevicePath { get; private set; }
        public byte[] LastSense { get; private set; }
        public uint LastErrorCode { get; private set; }

        public DimageScanner()
        {
            LastSense = new byte[22];
            try
            {
                _ipcMutex = new Mutex(false, @"Global\MinoltaDimageScanDual3Mutex");
            }
            catch
            {
                _ipcMutex = new Mutex(false, @"Local\MinoltaDimageScanDual3Mutex");
            }
        }

        public static string FindFirmwarePath(string preferred)
        {
            if (!string.IsNullOrEmpty(preferred) && File.Exists(preferred))
                return preferred;

            string baseDir = AppDomain.CurrentDomain.BaseDirectory;
            string[] candidates = new string[]
            {
                Path.Combine(baseDir, "DS_Dual3.BIN"),
                Path.Combine(baseDir, @"Firmware\DS_Dual3.BIN"),
                @"C:\Program Files (x86)\Minolta\DS_Dual3\Firmware\DS_Dual3.BIN"
            };
            foreach (string c in candidates)
            {
                if (File.Exists(c)) return c;
            }

            string[] regPaths = new string[]
            {
                @"SOFTWARE\WOW6432Node\MINOLTA\DS_Dual3",
                @"SOFTWARE\MINOLTA\DS_Dual3",
                @"SOFTWARE\WOW6432Node\MINOLTA\DS_Dual3Easy"
            };
            foreach (string rp in regPaths)
            {
                try
                {
                    using (RegistryKey k = Registry.LocalMachine.OpenSubKey(rp))
                    {
                        if (k != null)
                        {
                            string hp = k.GetValue("HomePath") as string;
                            if (!string.IsNullOrEmpty(hp))
                            {
                                string fw = Path.Combine(hp, @"Firmware\DS_Dual3.BIN");
                                if (File.Exists(fw)) return fw;
                            }
                        }
                    }
                }
                catch { }
            }
            return null;
        }

        public bool Open(string explicitPath)
        {
            if (!string.IsNullOrEmpty(explicitPath))
            {
                _handle = NativeUsbScan.CreateFile(
                    explicitPath,
                    NativeUsbScan.GENERIC_READ | NativeUsbScan.GENERIC_WRITE,
                    NativeUsbScan.FILE_SHARE_READ | NativeUsbScan.FILE_SHARE_WRITE,
                    IntPtr.Zero,
                    NativeUsbScan.OPEN_EXISTING,
                    0,
                    IntPtr.Zero);
                if (!_handle.IsInvalid)
                {
                    DevicePath = explicitPath;
                    return true;
                }
                return false;
            }

            for (int i = 0; i < 128; i++)
            {
                string path = @"\\.\UsbScan" + i;
                SafeFileHandle h = NativeUsbScan.CreateFile(
                    path,
                    NativeUsbScan.GENERIC_READ | NativeUsbScan.GENERIC_WRITE,
                    NativeUsbScan.FILE_SHARE_READ | NativeUsbScan.FILE_SHARE_WRITE,
                    IntPtr.Zero,
                    NativeUsbScan.OPEN_EXISTING,
                    0,
                    IntPtr.Zero);
                if (h.IsInvalid)
                    continue;

                NativeUsbScan.USBSCAN_DEVICE_DESCRIPTOR desc;
                uint ret;
                bool ok = NativeUsbScan.DeviceIoControl(
                    h,
                    NativeUsbScan.IOCTL_GET_DEVICE_DESCRIPTOR,
                    IntPtr.Zero,
                    0,
                    out desc,
                    (uint)Marshal.SizeOf(typeof(NativeUsbScan.USBSCAN_DEVICE_DESCRIPTOR)),
                    out ret,
                    IntPtr.Zero);

                if (ok && desc.usVendorId == VID_MINOLTA && desc.usProductId == PID_DUAL_III)
                {
                    _handle = h;
                    DevicePath = path;
                    return true;
                }
                h.Dispose();
            }
            return false;
        }

        private byte RawTransport(byte[] cdb, int dir, byte[] data, int dataLen)
        {
            bool locked = false;
            try
            {
                if (_ipcMutex != null)
                {
                    try { locked = _ipcMutex.WaitOne(60000); }
                    catch (AbandonedMutexException) { locked = true; }
                }

                uint written;
                if (!NativeUsbScan.WriteFile(_handle, cdb, (uint)cdb.Length, out written, IntPtr.Zero) || written != cdb.Length)
                    throw new IOException("Scanner USB write failed (Win32 error " + Marshal.GetLastWin32Error() + "). Check USB cable and power.");

                if (dir == 1 && data != null && dataLen > 0)
                {
                    uint read;
                    if (!NativeUsbScan.ReadFile(_handle, data, (uint)dataLen, out read, IntPtr.Zero) || read != dataLen)
                        throw new IOException("Scanner USB data read failed (Win32 error " + Marshal.GetLastWin32Error() + ").");
                }
                else if (dir == 2 && data != null && dataLen > 0)
                {
                    if (!NativeUsbScan.WriteFile(_handle, data, (uint)dataLen, out written, IntPtr.Zero) || written != dataLen)
                        throw new IOException("Scanner USB data write failed (Win32 error " + Marshal.GetLastWin32Error() + ").");
                }

                byte[] status = new byte[1];
                uint sRead;
                if (!NativeUsbScan.ReadFile(_handle, status, 1, out sRead, IntPtr.Zero) || sRead != 1)
                    throw new IOException("Scanner USB status read failed (Win32 error " + Marshal.GetLastWin32Error() + ").");

                Thread.Sleep(1);
                return status[0];
            }
            finally
            {
                if (locked && _ipcMutex != null)
                {
                    try { _ipcMutex.ReleaseMutex(); } catch { }
                }
            }
        }

        public bool ExecScsi(byte[] cdb, int dir, byte[] data, int dataLen)
        {
            byte st = RawTransport(cdb, dir, data, dataLen);
            if (st == 0x00)
            {
                LastErrorCode = 0;
                return true;
            }
            if (st == 0x02 && cdb[0] != 0x03)
            {
                byte[] senseCdb = new byte[] { 0x03, 0, 0, 0, 22, 0 };
                if (RawTransport(senseCdb, 1, LastSense, 22) == 0x00)
                {
                    byte sk = (byte)(LastSense[2] & 0x0F);
                    byte asc = LastSense[12];
                    byte ascq = LastSense[13];
                    if (sk == 0x02 && asc == 0x04)
                        LastErrorCode = 0xA2;
                    else
                        LastErrorCode = ((uint)sk << 16) | ((uint)asc << 8) | ascq;
                }
            }
            else if (st == 0x08)
            {
                Thread.Sleep(1000);
                if (RawTransport(cdb, dir, data, dataLen) == 0x00)
                {
                    LastErrorCode = 0;
                    return true;
                }
            }
            return false;
        }

        public bool TestUnitReady()
        {
            return ExecScsi(new byte[6], 4, null, 0);
        }

        public bool WaitReady(int timeoutMs, Action<string> statusCallback = null)
        {
            int elapsed = 0;
            while (elapsed <= timeoutMs)
            {
                if (TestUnitReady()) return true;
                byte sk = (byte)((LastErrorCode >> 16) & 0x0F);
                if (LastErrorCode == 0xA2 && statusCallback != null && (elapsed % 2000 == 0))
                {
                    statusCallback("Scanner is warming up its lamp or moving the film carrier... (" + (elapsed / 1000) + "s)");
                }
                if (LastErrorCode != 0xA2 && sk != 0x06 && sk != 0x02 && elapsed > 0)
                    return false;
                Thread.Sleep(100);
                elapsed += 100;
            }
            return false;
        }

        public string Inquiry()
        {
            byte[] cdb = new byte[] { 0x12, 0, 0, 0, 96, 0 };
            byte[] buf = new byte[96];
            if (!ExecScsi(cdb, 1, buf, 96))
                throw new IOException("SCSI INQUIRY failed.");
            return Encoding.ASCII.GetString(buf, 8, 28).Trim();
        }

        public void ReserveUnit()
        {
            ExecScsi(new byte[] { 0x16, 0, 0, 0, 0, 0 }, 4, null, 0);
        }

        public void ReleaseUnit()
        {
            ExecScsi(new byte[] { 0x17, 0, 0, 0, 0, 0 }, 4, null, 0);
        }

        public void Read10(byte dataType, ushort qual, byte[] buf, int len)
        {
            byte[] cdb = new byte[10];
            cdb[0] = 0x28;
            cdb[2] = dataType;
            cdb[4] = (byte)(qual >> 8);
            cdb[5] = (byte)(qual & 0xFF);
            cdb[6] = (byte)((len >> 16) & 0xFF);
            cdb[7] = (byte)((len >> 8) & 0xFF);
            cdb[8] = (byte)(len & 0xFF);
            if (!ExecScsi(cdb, 1, buf, len))
                throw new IOException(string.Format("Scanner READ(10) command 0x{0:X2} failed (sense=0x{1:X}).", dataType, LastErrorCode));
        }

        public void Write10(byte dataType, ushort qual, byte[] buf, int len)
        {
            byte[] cdb = new byte[10];
            cdb[0] = 0x2A;
            cdb[2] = dataType;
            cdb[4] = (byte)(qual >> 8);
            cdb[5] = (byte)(qual & 0xFF);
            cdb[6] = (byte)((len >> 16) & 0xFF);
            cdb[7] = (byte)((len >> 8) & 0xFF);
            cdb[8] = (byte)(len & 0xFF);
            if (!ExecScsi(cdb, 2, buf, len))
                throw new IOException(string.Format("Scanner WRITE(10) command 0x{0:X2} failed (sense=0x{1:X}).", dataType, LastErrorCode));
        }

        public void EnsureFirmwareLoaded(string preferredBinPath, Action<string> statusCallback = null)
        {
            byte[] status = new byte[8];
            Read10(0x90, 0x0022, status, 8);
            if (status[4] == 0)
                return;

            string binPath = FindFirmwarePath(preferredBinPath);
            if (string.IsNullOrEmpty(binPath) || !File.Exists(binPath))
                throw new FileNotFoundException("Scanner firmware file DS_Dual3.BIN was not found. Re-run Install-MinoltaWin11.bat.");

            if (statusCallback != null)
                statusCallback("Uploading Minolta scanner firmware (DS_Dual3.BIN)...");

            WaitReady(15000, statusCallback);

            byte[] raw = File.ReadAllBytes(binPath);
            uint sum = 0;
            for (int i = 0; i < raw.Length; i++)
                sum += raw[i];

            byte[] payload = new byte[raw.Length + 4];
            Buffer.BlockCopy(raw, 0, payload, 0, raw.Length);
            payload[raw.Length + 0] = (byte)(sum & 0xFF);
            payload[raw.Length + 1] = (byte)((sum >> 8) & 0xFF);
            payload[raw.Length + 2] = (byte)((sum >> 16) & 0xFF);
            payload[raw.Length + 3] = (byte)((sum >> 24) & 0xFF);

            Write10(0x90, 0x0000, payload, payload.Length);
            TestUnitReady();
            Thread.Sleep(3000);
            WaitReady(30000, statusCallback);
            InitializeScanner(statusCallback);
        }

        public byte GetHolderType()
        {
            WaitReady(15000);
            byte[] st = new byte[32];
            Read10(0x60, 0, st, 32);
            return st[4];
        }

        public void ObjectPosition(byte mode, Action<string> statusCallback = null)
        {
            WaitReady(30000, statusCallback);
            byte[] cdb = new byte[] { 0x31, 0, 0, 0, 0, 0, 0, 0, 0, mode };
            ExecScsi(cdb, 4, null, 0);
            WaitReady(30000, statusCallback);
        }

        public void InitializeScanner(Action<string> statusCallback = null)
        {
            if (statusCallback != null) statusCallback("Initializing scanner optics & warming up lamp...");
            WaitReady(60000, statusCallback);
            byte[] initPayload = new byte[8];
            Write10(0x92, 0, initPayload, 8);
            WaitReady(60000, statusCallback);

            for (int i = 0; i < 120; i++)
            {
                byte[] light = new byte[1];
                Read10(0xA0, 0, light, 1);
                if (light[0] != 0) break;
                if (statusCallback != null && (i % 4 == 0))
                    statusCallback("Warming up scanner fluorescent lamp for accurate color... (" + (i / 2) + "s)");
                Thread.Sleep(500);
            }
            ObjectPosition(0x02, statusCallback);
        }

        public void RecoverJammedHolder(Action<string> statusCallback = null)
        {
            try { ReleaseUnit(); } catch { }
            WaitReady(15000, statusCallback);
            try { ObjectPosition(0x00, statusCallback); } catch { }
        }

        public void MoveToFrame(byte frameIndex, Action<string> statusCallback = null)
        {
            if (statusCallback != null) statusCallback("Positioning film carrier to Frame " + frameIndex + "...");
            WaitReady(30000, statusCallback);
            byte[] cur = new byte[8];
            Read10(0x87, 0, cur, 8);
            if (cur[0] == 0xFF)
                throw new InvalidOperationException("No film holder is inserted inside the scanner! Please slide your 35mm film strip or slide holder into the slot.");
            byte[] cmd = new byte[] { cur[0], frameIndex, 0, 0, 0, 0, 0, 0 };
            Write10(0x87, 0, cmd, 8);
            WaitReady(30000, statusCallback);
        }

        private static byte[] BuildMotorRampTable(ushort totalSteps, ushort constSteps, uint targetNum, uint targetDen, ushort startPeriod, ushort endPeriod)
        {
            byte[] table = new byte[totalSteps];
            if (totalSteps == 0) return table;

            int rampTarget = (totalSteps >= constSteps) ? (totalSteps - constSteps + 1) : 1;
            float low = 0.001f;
            float high = 1.0f;

            for (int iter = 0; iter < 30; iter++)
            {
                float mid = (low + high) * 0.5f;
                double cur = startPeriod;
                int idx = 1;
                table[0] = (byte)startPeriod;

                while (idx < 999 && idx < totalSteps)
                {
                    cur = cur - (cur - endPeriod) * mid;
                    byte val = (byte)(cur + 0.5);
                    table[idx++] = val;
                    if (val == (byte)endPeriod) break;
                }
                if (idx == rampTarget) break;
                if (idx > rampTarget) low = mid;
                else high = mid;
                if (Math.Abs(high - low) <= 1e-6f) break;
            }

            for (int i = (rampTarget > 0 ? rampTarget - 1 : 0); i < totalSteps; i++)
                table[i] = (byte)endPeriod;

            if (targetNum > 0 && targetDen > 0)
            {
                uint sum = 0;
                for (int i = 0; i < totalSteps; i++) sum += table[i];
                uint rem = (sum * targetNum) % targetDen;
                if (rem != 0)
                {
                    uint add = (targetDen - rem) / targetNum;
                    if (add > 0xFF) add = 0xFF;
                    for (int i = 0; i + 1 < totalSteps && add > 0; i++)
                    {
                        uint headroom = (uint)(0xFF - table[i]);
                        if (headroom > add)
                        {
                            table[i] = (byte)(table[i] + add);
                            add = 0;
                        }
                        else
                        {
                            table[i] = 0xFF;
                            add -= headroom;
                        }
                    }
                }
            }

            for (int i = 0; i < totalSteps; i++)
                table[i] = (byte)(table[i] - 1);

            return table;
        }

        private void SendLinearGammaLut()
        {
            byte[] lut = new byte[512];
            for (int i = 0; i < 256; i++)
            {
                ushort v = (ushort)((i << 8) | i);
                lut[i * 2 + 0] = (byte)(v & 0xFF);
                lut[i * 2 + 1] = (byte)(v >> 8);
            }
            for (ushort ch = 0; ch < 3; ch++)
                Write10(0x81, ch, lut, 512);
        }

        public Bitmap ScanFrameToBitmap(
            byte frameIndex,
            int dpi,
            FilmType filmType,
            byte multiSample,
            Action<string> statusCallback = null,
            Action<int> progressCallback = null)
        {
            if (dpi <= 0) dpi = 1410;
            int scale = OPTICAL_DPI / dpi;
            if (scale < 1) scale = 1;
            dpi = OPTICAL_DPI / scale;

            int widthPx = (MAX_WIDTH_PX / scale) & ~1;
            int heightPx = MAX_HEIGHT_PX / scale;
            int bytesPerLineCh = widthPx * 2; // Always scan in 16-bit/12-bit sensor precision for best dynamic range!
            int totalBytesPerLine = bytesPerLineCh * 3;

            MoveToFrame(frameIndex, statusCallback);

            bool hasMs = (multiSample > 1);
            ushort descLen = (ushort)(hasMs ? 0x0047 : 0x0046);
            int winLen = 8 + descLen;
            byte[] win = new byte[winLen];
            win[6] = (byte)(descLen >> 8);
            win[7] = (byte)(descLen & 0xFF);

            int d = 8;
            win[d + 0x02] = (byte)(dpi >> 8);
            win[d + 0x03] = (byte)(dpi & 0xFF);
            win[d + 0x04] = (byte)(dpi >> 8);
            win[d + 0x05] = (byte)(dpi & 0xFF);

            uint winW = (uint)(widthPx * scale * 4);
            uint winH = (uint)(heightPx * scale * 4);
            win[d + 0x0E] = (byte)((winW >> 24) & 0xFF);
            win[d + 0x0F] = (byte)((winW >> 16) & 0xFF);
            win[d + 0x10] = (byte)((winW >> 8) & 0xFF);
            win[d + 0x11] = (byte)(winW & 0xFF);
            win[d + 0x12] = (byte)((winH >> 24) & 0xFF);
            win[d + 0x13] = (byte)((winH >> 16) & 0xFF);
            win[d + 0x14] = (byte)((winH >> 8) & 0xFF);
            win[d + 0x15] = (byte)(winH & 0xFF);

            win[d + 0x16] = 0x80;
            win[d + 0x17] = 0x80;
            win[d + 0x18] = 0x80;
            win[d + 0x19] = 0x05; // RGB
            win[d + 0x1A] = 12;   // 12-bit ADC precision
            win[d + 0x1D] = 0x03;
            win[d + 0x28] = 0xFF;
            win[d + 0x29] = 0x14;
            win[d + 0x2A] = 0x60;
            win[d + 0x2B] = 0xFF;
            win[d + 0x2D] = 0x88; // 16-bit high-precision transfer
            win[d + 0x2E] = 0x64;
            win[d + 0x2F] = 0x00; win[d + 0x30] = 100; // R exp
            win[d + 0x31] = 0x00; win[d + 0x32] = 100; // B exp
            win[d + 0x33] = 0x00; win[d + 0x34] = 100; // G exp
            win[d + 0x35] = (byte)(0x10 | (hasMs ? 0x02 : 0x00));
            if (hasMs) win[d + 0x39] = multiSample;

            win[d + 0x3D] = (byte)(bytesPerLineCh >> 8);
            win[d + 0x3E] = (byte)(bytesPerLineCh & 0xFF);
            win[d + 0x43] = (byte)(heightPx >> 8);
            win[d + 0x44] = (byte)(heightPx & 0xFF);

            byte[] setWinCdb = new byte[10];
            setWinCdb[0] = 0x24;
            setWinCdb[6] = (byte)((winLen >> 16) & 0xFF);
            setWinCdb[7] = (byte)((winLen >> 8) & 0xFF);
            setWinCdb[8] = (byte)(winLen & 0xFF);
            if (!ExecScsi(setWinCdb, 2, win, winLen))
                throw new IOException("SET WINDOW (0x24) failed.");

            ReserveUnit();
            try
            {
                if (!ExecScsi(new byte[] { 0x1B, 0, 0, 0, 0x01, 0x80 }, 4, null, 0))
                    throw new IOException("START SCAN (0x1B) failed.");

                byte[] rampHdr = new byte[24];
                Read10(0x6C, 0, rampHdr, 24);
                byte numTables = rampHdr[17];
                ushort tableIdx = 0;
                while (numTables > 0 && tableIdx < numTables)
                {
                    ushort totalSteps = (ushort)((rampHdr[0] << 8) | rampHdr[1]);
                    ushort constSteps = (ushort)((rampHdr[2] << 8) | rampHdr[3]);
                    uint targetNum = ((uint)rampHdr[4] << 24) | ((uint)rampHdr[5] << 16) | ((uint)rampHdr[6] << 8) | rampHdr[7];
                    uint targetDen = ((uint)rampHdr[8] << 24) | ((uint)rampHdr[9] << 16) | ((uint)rampHdr[10] << 8) | rampHdr[11];
                    ushort startPeriod = (ushort)((rampHdr[12] << 8) | rampHdr[13]);
                    ushort endPeriod = (ushort)((rampHdr[14] << 8) | rampHdr[15]);
                    byte alreadySet = rampHdr[16];

                    if (alreadySet == 0 && totalSteps > 0 && totalSteps <= 1000)
                    {
                        byte[] rampTable = BuildMotorRampTable(totalSteps, constSteps, targetNum, targetDen, startPeriod, endPeriod);
                        Write10(0x6C, tableIdx, rampTable, totalSteps);
                    }
                    tableIdx++;
                    if (tableIdx >= numTables) break;
                    Read10(0x6C, 0, rampHdr, 24);
                    numTables = rampHdr[17];
                }

                WaitReady(60000, statusCallback);

                ushort[] raw16 = new ushort[widthPx * heightPx * 3];
                byte[] lineBuf = new byte[totalBytesPerLine];

                for (int y = 0; y < heightPx; y++)
                {
                    Read10(0x00, 0, lineBuf, totalBytesPerLine);
                    int rowBase = y * widthPx * 3;
                    for (int s = 0; s < widthPx * 3; s++)
                    {
                        ushort v = (ushort)(lineBuf[s * 2] | (lineBuf[s * 2 + 1] << 8));
                        if (v <= 0x0FFF)
                            v = (ushort)((v << 4) | (v >> 8));
                        raw16[rowBase + s] = v;
                    }
                    if (progressCallback != null && (y % 16 == 0 || y == heightPx - 1))
                    {
                        progressCallback((y + 1) * 100 / heightPx);
                    }
                    if (statusCallback != null && (y % 128 == 0))
                    {
                        statusCallback(string.Format("Scanning Frame {0} at {1} DPI... ({2}%)", frameIndex, dpi, (y + 1) * 100 / heightPx));
                    }
                }

                if (statusCallback != null)
                    statusCallback("Restoring film colors & removing orange mask...");

                return ConvertRaw16ToBitmap(raw16, widthPx, heightPx, dpi, filmType);
            }
            finally
            {
                try { ReleaseUnit(); } catch { }
            }
        }

        // Inner-90% 0.5th-to-99.5th percentile histogram auto-levels & 1970s/80s negative restoration
        private static Bitmap ConvertRaw16ToBitmap(ushort[] raw16, int width, int height, int dpi, FilmType filmType)
        {
            int x0 = width / 20;
            int x1 = width - x0;
            int y0 = height / 20;
            int y1 = height - y0;

            int[,] hist = new int[3, 4096];
            int samples = 0;

            for (int y = y0; y < y1; y++)
            {
                for (int x = x0; x < x1; x++)
                {
                    int idx = (y * width + x) * 3;
                    for (int c = 0; c < 3; c++)
                    {
                        int bin = raw16[idx + c] >> 4;
                        if (bin > 4095) bin = 4095;
                        hist[c, bin]++;
                    }
                    samples++;
                }
            }

            double[] lowVal = new double[3];
            double[] highVal = new double[3];
            int lowTarget = Math.Max(1, samples / 200);
            int highTarget = Math.Max(lowTarget + 1, samples - (samples / 200));

            for (int c = 0; c < 3; c++)
            {
                int accum = 0, lowBin = 0, highBin = 4095;
                for (int b = 0; b < 4096; b++)
                {
                    accum += hist[c, b];
                    if (accum >= lowTarget) { lowBin = b; break; }
                }
                accum = 0;
                for (int b = 0; b < 4096; b++)
                {
                    accum += hist[c, b];
                    if (accum >= highTarget) { highBin = b; break; }
                }
                if (highBin <= lowBin) { lowBin = 0; highBin = 4095; }
                lowVal[c] = lowBin * 16.0;
                highVal[c] = highBin * 16.0;
                if (highVal[c] - lowVal[c] < 16.0)
                {
                    lowVal[c] = 0.0;
                    highVal[c] = 65535.0;
                }
            }

            double invGamma = (filmType == FilmType.BlackAndWhiteNegative) ? (1.0 / 1.75) : (1.0 / 1.85);

            Bitmap bmp = new Bitmap(width, height, PixelFormat.Format24bppRgb);
            bmp.SetResolution(dpi, dpi);
            BitmapData bd = bmp.LockBits(new Rectangle(0, 0, width, height), ImageLockMode.WriteOnly, PixelFormat.Format24bppRgb);
            try
            {
                byte[] rowBytes = new byte[Math.Abs(bd.Stride)];
                for (int y = 0; y < height; y++)
                {
                    int srcRow = y * width * 3;
                    for (int x = 0; x < width; x++)
                    {
                        int idx = srcRow + x * 3;
                        byte[] rgb = new byte[3];
                        for (int c = 0; c < 3; c++)
                        {
                            double v = raw16[idx + c];
                            double norm = (v - lowVal[c]) / (highVal[c] - lowVal[c]);
                            if (norm < 0.0) norm = 0.0;
                            if (norm > 1.0) norm = 1.0;

                            double val = (filmType == FilmType.ColorSlidePositive) ? norm : (1.0 - norm);
                            if (filmType != FilmType.ColorSlidePositive)
                                val = Math.Pow(val, invGamma);

                            int b8 = (int)(val * 255.0 + 0.5);
                            if (b8 < 0) b8 = 0;
                            if (b8 > 255) b8 = 255;
                            rgb[c] = (byte)b8;
                        }
                        if (filmType == FilmType.BlackAndWhiteNegative)
                        {
                            byte lum = (byte)((rgb[0] * 30 + rgb[1] * 59 + rgb[2] * 11) / 100);
                            rgb[0] = rgb[1] = rgb[2] = lum;
                        }
                        rowBytes[x * 3 + 0] = rgb[2]; // B
                        rowBytes[x * 3 + 1] = rgb[1]; // G
                        rowBytes[x * 3 + 2] = rgb[0]; // R
                    }
                    IntPtr dstPtr = new IntPtr(bd.Scan0.ToInt64() + (long)y * bd.Stride);
                    Marshal.Copy(rowBytes, 0, dstPtr, width * 3);
                }
            }
            finally
            {
                bmp.UnlockBits(bd);
            }
            return bmp;
        }

        public void Dispose()
        {
            if (_handle != null && !_handle.IsInvalid)
                _handle.Dispose();
            if (_ipcMutex != null)
                _ipcMutex.Dispose();
        }
    }

    // =========================================================================
    // Parent-Proof Windows 11 Desktop GUI for Dad's 1970s/1980s Film Scanning
    // =========================================================================
    public sealed class MainScannerForm : Form
    {
        private Label _lblBanner;
        private ComboBox _cmbFilmType;
        private ComboBox _cmbDpi;
        private ComboBox _cmbFrame;
        private ComboBox _cmbFormat;
        private Button _btnScanOne;
        private Button _btnScanStrip;
        private Button _btnCopyWord;
        private Button _btnSendWord;
        private Button _btnOpenGimp;
        private Button _btnOpenPaint;
        private Button _btnEject;
        private Button _btnResetJam;
        private Button _btnOpenFolder;
        private PictureBox _picPreview;
        private ProgressBar _progressBar;
        private Label _lblStatus;
        private Bitmap _lastScannedBitmap;
        private string _lastSavedPath;
        private string _scansDir;

        public MainScannerForm()
        {
            Text = "Minolta DiMAGE Scan Dual III — 1970s & 1980s Film & Slide Studio";
            Size = new Size(980, 720);
            MinimumSize = new Size(880, 640);
            StartPosition = FormStartPosition.CenterScreen;
            Font = new Font("Segoe UI", 10F, FontStyle.Regular);
            BackColor = Color.FromArgb(245, 247, 250);

            _scansDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyPictures), "Minolta Scans");
            Directory.CreateDirectory(_scansDir);

            BuildUi();
            Shown += (s, e) => CheckScannerConnectionAsync();
        }

        private void BuildUi()
        {
            _lblBanner = new Label
            {
                Dock = DockStyle.Top,
                Height = 44,
                TextAlign = ContentAlignment.MiddleLeft,
                Padding = new Padding(14, 0, 0, 0),
                Font = new Font("Segoe UI", 11F, FontStyle.Bold),
                BackColor = Color.FromArgb(30, 58, 138),
                ForeColor = Color.White,
                Text = "Checking Minolta DiMAGE Scan Dual III connection..."
            };

            Panel leftPanel = new Panel
            {
                Dock = DockStyle.Left,
                Width = 370,
                Padding = new Padding(14),
                BackColor = Color.White
            };

            int y = 12;
            AddSectionHeader(leftPanel, "1. Choose Film Type & Quality", ref y);

            AddLabel(leftPanel, "Film / Slide Type:", ref y);
            _cmbFilmType = new ComboBox { Left = 14, Top = y, Width = 338, DropDownStyle = ComboBoxStyle.DropDownList };
            _cmbFilmType.Items.AddRange(new object[] {
                "1970s/80s Color Negative (Auto Orange-Mask Fix)",
                "Black & White Negative (Kodak Tri-X / Ilford)",
                "Color Slide / Positive (Kodachrome / Ektachrome)"
            });
            _cmbFilmType.SelectedIndex = 0;
            leftPanel.Controls.Add(_cmbFilmType);
            y += 36;

            AddLabel(leftPanel, "Scan Quality (Resolution):", ref y);
            _cmbDpi = new ComboBox { Left = 14, Top = y, Width = 338, DropDownStyle = ComboBoxStyle.DropDownList };
            _cmbDpi.Items.AddRange(new object[] {
                "1410 DPI — High Quality (Fast, Great for Prints & Word)",
                "2820 DPI — Maximum Archival Optical Resolution",
                "705 DPI — Quick Proof / Email"
            });
            _cmbDpi.SelectedIndex = 0;
            leftPanel.Controls.Add(_cmbDpi);
            y += 36;

            AddLabel(leftPanel, "Frame Number on Film Holder (1 to 6):", ref y);
            _cmbFrame = new ComboBox { Left = 14, Top = y, Width = 155, DropDownStyle = ComboBoxStyle.DropDownList };
            for (int f = 1; f <= 6; f++) _cmbFrame.Items.Add("Frame " + f);
            _cmbFrame.SelectedIndex = 0;
            leftPanel.Controls.Add(_cmbFrame);

            _cmbFormat = new ComboBox { Left = 185, Top = y, Width = 167, DropDownStyle = ComboBoxStyle.DropDownList };
            _cmbFormat.Items.AddRange(new object[] {
                "Save as JPEG (.jpg)",
                "Save as PNG (.png)",
                "Save as TIFF (.tif)"
            });
            _cmbFormat.SelectedIndex = 0;
            leftPanel.Controls.Add(_cmbFormat);
            y += 44;

            AddSectionHeader(leftPanel, "2. Scan Your Negatives or Slides", ref y);

            _btnScanOne = CreateButton(leftPanel, "Scan Selected Frame", ref y, Color.FromArgb(22, 101, 52), Color.White, 44, true);
            _btnScanOne.Click += (s, e) => RunScanAsync(false);

            _btnScanStrip = CreateButton(leftPanel, "Scan Entire Strip (All 6 Frames / 4 Slides)", ref y, Color.FromArgb(30, 64, 175), Color.White, 42, true);
            _btnScanStrip.Click += (s, e) => RunScanAsync(true);
            y += 8;

            AddSectionHeader(leftPanel, "3. Use Photo in Word, GIMP, Paint, or Folder", ref y);

            _btnCopyWord = CreateButton(leftPanel, "Copy Photo to Clipboard (Paste in Word)", ref y, Color.FromArgb(241, 245, 249), Color.Black, 32, false);
            _btnCopyWord.Click += (s, e) => CopyToClipboardForWord();

            _btnSendWord = CreateButton(leftPanel, "Insert Photo Directly into Microsoft Word", ref y, Color.FromArgb(241, 245, 249), Color.Black, 32, false);
            _btnSendWord.Click += (s, e) => SendToMicrosoftWord();

            _btnOpenGimp = CreateButton(leftPanel, "Open Scanned Photo in GIMP", ref y, Color.FromArgb(241, 245, 249), Color.Black, 32, false);
            _btnOpenGimp.Click += (s, e) => OpenInGimp();

            _btnOpenPaint = CreateButton(leftPanel, "Open Scanned Photo in Windows Paint", ref y, Color.FromArgb(241, 245, 249), Color.Black, 32, false);
            _btnOpenPaint.Click += (s, e) => OpenInPaint();

            _btnOpenFolder = CreateButton(leftPanel, "Open 'Pictures\\Minolta Scans' Folder", ref y, Color.FromArgb(241, 245, 249), Color.Black, 32, false);
            _btnOpenFolder.Click += (s, e) => Process.Start("explorer.exe", "\"" + _scansDir + "\"");
            y += 6;

            AddSectionHeader(leftPanel, "4. Film Holder & Troubleshooting", ref y);

            _btnEject = CreateButton(leftPanel, "Eject Film Holder", ref y, Color.FromArgb(254, 243, 199), Color.FromArgb(120, 53, 15), 34, false);
            _btnEject.Click += (s, e) => EjectHolderAsync();

            _btnResetJam = CreateButton(leftPanel, "Fix Blinking Light / Reset Scanner", ref y, Color.FromArgb(254, 226, 226), Color.FromArgb(153, 27, 27), 34, false);
            _btnResetJam.Click += (s, e) => FixBlinkingLightGuideAsync();

            Panel bottomPanel = new Panel
            {
                Dock = DockStyle.Bottom,
                Height = 56,
                Padding = new Padding(14, 8, 14, 8),
                BackColor = Color.White
            };

            _progressBar = new ProgressBar
            {
                Dock = DockStyle.Top,
                Height = 16,
                Minimum = 0,
                Maximum = 100
            };
            _lblStatus = new Label
            {
                Dock = DockStyle.Bottom,
                Height = 22,
                TextAlign = ContentAlignment.MiddleLeft,
                Text = "Ready. Scans are automatically saved to: " + _scansDir
            };
            bottomPanel.Controls.Add(_progressBar);
            bottomPanel.Controls.Add(_lblStatus);

            Panel previewContainer = new Panel
            {
                Dock = DockStyle.Fill,
                Padding = new Padding(16),
                BackColor = Color.FromArgb(30, 41, 59)
            };
            _picPreview = new PictureBox
            {
                Dock = DockStyle.Fill,
                SizeMode = PictureBoxSizeMode.Zoom,
                BackColor = Color.FromArgb(15, 23, 42)
            };
            previewContainer.Controls.Add(_picPreview);

            Controls.Add(previewContainer);
            Controls.Add(leftPanel);
            Controls.Add(bottomPanel);
            Controls.Add(_lblBanner);
        }

        private static void AddSectionHeader(Control parent, string text, ref int y)
        {
            Label lbl = new Label
            {
                Left = 14,
                Top = y,
                Width = 338,
                Height = 22,
                Font = new Font("Segoe UI", 9.5F, FontStyle.Bold),
                ForeColor = Color.FromArgb(30, 58, 138),
                Text = text
            };
            parent.Controls.Add(lbl);
            y += 24;
        }

        private static void AddLabel(Control parent, string text, ref int y)
        {
            Label lbl = new Label
            {
                Left = 14,
                Top = y,
                Width = 338,
                Height = 20,
                Text = text
            };
            parent.Controls.Add(lbl);
            y += 20;
        }

        private static Button CreateButton(Control parent, string text, ref int y, Color back, Color fore, int height, bool bold)
        {
            Button btn = new Button
            {
                Left = 14,
                Top = y,
                Width = 338,
                Height = height,
                Text = text,
                BackColor = back,
                ForeColor = fore,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Segoe UI", 9.5F, bold ? FontStyle.Bold : FontStyle.Regular),
                Cursor = Cursors.Hand
            };
            parent.Controls.Add(btn);
            y += height + 6;
            return btn;
        }

        private void SetUiBusy(bool busy, string statusText = null)
        {
            if (InvokeRequired)
            {
                BeginInvoke(new Action(() => SetUiBusy(busy, statusText)));
                return;
            }
            _btnScanOne.Enabled = !busy;
            _btnScanStrip.Enabled = !busy;
            _btnEject.Enabled = !busy;
            _btnResetJam.Enabled = !busy;
            if (!string.IsNullOrEmpty(statusText))
                _lblStatus.Text = statusText;
        }

        private void UpdateStatus(string text)
        {
            if (InvokeRequired)
            {
                BeginInvoke(new Action(() => UpdateStatus(text)));
                return;
            }
            _lblStatus.Text = text;
        }

        private void UpdateProgress(int pct)
        {
            if (InvokeRequired)
            {
                BeginInvoke(new Action(() => UpdateProgress(pct)));
                return;
            }
            _progressBar.Value = Math.Max(0, Math.Min(100, pct));
        }

        private void CheckScannerConnectionAsync()
        {
            ThreadPool.QueueUserWorkItem(_ =>
            {
                try
                {
                    using (var sc = new DimageScanner())
                    {
                        if (!sc.Open(null))
                        {
                            BeginInvoke(new Action(() =>
                            {
                                _lblBanner.BackColor = Color.FromArgb(180, 83, 9);
                                _lblBanner.Text = "Scanner Not Detected — Turn ON your Minolta scanner & plug in the USB cable (it will connect automatically).";
                            }));
                            return;
                        }
                        sc.EnsureFirmwareLoaded(null, UpdateStatus);
                        string id = sc.Inquiry();
                        byte holder = sc.GetHolderType();
                        string holderDesc = (holder == 1) ? "35mm Film Strip Holder inserted"
                                          : (holder == 2) ? "Mounted Slide Holder inserted"
                                          : "No film holder inserted yet";
                        BeginInvoke(new Action(() =>
                        {
                            _lblBanner.BackColor = Color.FromArgb(22, 101, 52);
                            _lblBanner.Text = "Ready: " + id + " (" + holderDesc + ")";
                            _lblStatus.Text = "Scanner connected and ready. Saves to: " + _scansDir;
                        }));
                    }
                }
                catch (Exception ex)
                {
                    BeginInvoke(new Action(() =>
                    {
                        _lblBanner.BackColor = Color.FromArgb(180, 83, 9);
                        _lblBanner.Text = "Scanner Needs Attention — Click 'Fix Blinking Light / Reset Scanner' if a holder was left inside.";
                        _lblStatus.Text = ex.Message;
                    }));
                }
            });
        }

        private void RunScanAsync(bool fullStrip)
        {
            int dpi = (_cmbDpi.SelectedIndex == 1) ? 2820 : (_cmbDpi.SelectedIndex == 2) ? 705 : 1410;
            FilmType film = (_cmbFilmType.SelectedIndex == 1) ? FilmType.BlackAndWhiteNegative
                          : (_cmbFilmType.SelectedIndex == 2) ? FilmType.ColorSlidePositive
                          : FilmType.ColorNegative;
            byte selectedFrame = (byte)(_cmbFrame.SelectedIndex + 1);
            int fmtIdx = _cmbFormat.SelectedIndex;

            SetUiBusy(true, "Connecting to Minolta DiMAGE Scan Dual III...");
            UpdateProgress(0);

            ThreadPool.QueueUserWorkItem(_ =>
            {
                try
                {
                    using (var sc = new DimageScanner())
                    {
                        if (!sc.Open(null))
                        {
                            throw new InvalidOperationException(
                                "Could not find the Minolta DiMAGE Scan Dual III.\n\n" +
                                "1. Make sure the power button on the front of the scanner is pushed IN (green light on).\n" +
                                "2. Make sure the USB cable is plugged into your computer.\n" +
                                "3. Wait 5 seconds and click Scan again.");
                        }

                        sc.EnsureFirmwareLoaded(null, UpdateStatus);

                        byte holder = sc.GetHolderType();
                        if (holder == 0xFF)
                        {
                            throw new InvalidOperationException(
                                "No film holder is detected inside the scanner.\n\n" +
                                "Please gently slide your 35mm film strip holder or slide holder into the scanner slot until it engages.");
                        }

                        byte startFrame = fullStrip ? (byte)1 : selectedFrame;
                        byte endFrame = fullStrip ? ((holder == 2) ? (byte)4 : (byte)6) : selectedFrame;

                        string ext = (fmtIdx == 1) ? ".png" : (fmtIdx == 2) ? ".tif" : ".jpg";
                        ImageFormat imgFmt = (fmtIdx == 1) ? ImageFormat.Png : (fmtIdx == 2) ? ImageFormat.Tiff : ImageFormat.Jpeg;
                        string timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");

                        for (byte f = startFrame; f <= endFrame; f++)
                        {
                            Bitmap bmp = sc.ScanFrameToBitmap(f, dpi, film, 1, UpdateStatus, UpdateProgress);
                            string fileName = string.Format("Minolta_{0}_Frame{1}{2}", timestamp, f, ext);
                            string fullPath = Path.Combine(_scansDir, fileName);
                            bmp.Save(fullPath, imgFmt);

                            BeginInvoke(new Action(() =>
                            {
                                if (_lastScannedBitmap != null) _lastScannedBitmap.Dispose();
                                _lastScannedBitmap = (Bitmap)bmp.Clone();
                                _picPreview.Image = _lastScannedBitmap;
                                _lastSavedPath = fullPath;
                                Clipboard.SetImage(_lastScannedBitmap);
                                _lblBanner.BackColor = Color.FromArgb(22, 101, 52);
                                _lblBanner.Text = "Scan Complete! Saved " + fileName + " (and copied to Clipboard for Word!)";
                            }));
                            bmp.Dispose();
                        }

                        UpdateProgress(100);
                        UpdateStatus("Finished! Saved to: " + _lastSavedPath + " (also copied to Clipboard—press Ctrl+V in Word!)");
                    }
                }
                catch (Exception ex)
                {
                    BeginInvoke(new Action(() =>
                    {
                        MessageBox.Show(this,
                            ex.Message + "\n\nTip: If the scanner's green light is blinking rapidly because a film holder was inside when it was turned on, click the 'Fix Blinking Light / Reset Scanner' button.",
                            "Minolta Scanner Notice",
                            MessageBoxButtons.OK,
                            MessageBoxIcon.Information);
                        UpdateStatus("Scan stopped: " + ex.Message);
                    }));
                }
                finally
                {
                    SetUiBusy(false);
                }
            });
        }

        private void CopyToClipboardForWord()
        {
            if (_lastScannedBitmap == null)
            {
                MessageBox.Show(this, "Please scan a frame first!", "No Scan Yet", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            Clipboard.SetImage(_lastScannedBitmap);
            MessageBox.Show(this,
                "The scanned photo is now copied to your Clipboard!\n\n" +
                "Switch to Microsoft Word (or your email) and press Ctrl+V (or Right-Click -> Paste).",
                "Copied for Word",
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
        }

        private void SendToMicrosoftWord()
        {
            if (string.IsNullOrEmpty(_lastSavedPath) || !File.Exists(_lastSavedPath))
            {
                MessageBox.Show(this, "Please scan a frame first!", "No Scan Yet", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            if (_lastScannedBitmap != null)
                Clipboard.SetImage(_lastScannedBitmap);

            try
            {
                Type wordType = Type.GetTypeFromProgID("Word.Application");
                if (wordType != null)
                {
                    object wordApp = Activator.CreateInstance(wordType);
                    wordType.InvokeMember("Visible", System.Reflection.BindingFlags.SetProperty, null, wordApp, new object[] { true });
                    object docs = wordType.InvokeMember("Documents", System.Reflection.BindingFlags.GetProperty, null, wordApp, null);
                    object doc = docs.GetType().InvokeMember("Add", System.Reflection.BindingFlags.InvokeMethod, null, docs, null);
                    object shapes = doc.GetType().InvokeMember("InlineShapes", System.Reflection.BindingFlags.GetProperty, null, doc, null);
                    shapes.GetType().InvokeMember("AddPicture", System.Reflection.BindingFlags.InvokeMethod, null, shapes, new object[] { _lastSavedPath });
                    UpdateStatus("Opened Microsoft Word and inserted " + Path.GetFileName(_lastSavedPath));
                    return;
                }
            }
            catch { }

            MessageBox.Show(this,
                "Your photo has been copied to the Clipboard and saved to:\n" + _lastSavedPath + "\n\n" +
                "In Microsoft Word, simply press Ctrl+V to paste it, or click Insert -> Pictures -> This Device.",
                "Ready for Microsoft Word",
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
        }

        private void OpenInPaint()
        {
            if (string.IsNullOrEmpty(_lastSavedPath) || !File.Exists(_lastSavedPath))
            {
                MessageBox.Show(this, "Please scan a frame first!", "No Scan Yet", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            try
            {
                Process.Start("mspaint.exe", "\"" + _lastSavedPath + "\"");
                UpdateStatus("Opened " + Path.GetFileName(_lastSavedPath) + " in Windows Paint.");
            }
            catch
            {
                Process.Start("explorer.exe", "/select,\"" + _lastSavedPath + "\"");
            }
        }

        private void OpenInGimp()
        {
            if (string.IsNullOrEmpty(_lastSavedPath) || !File.Exists(_lastSavedPath))
            {
                MessageBox.Show(this, "Please scan a frame first!", "No Scan Yet", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            string[] searchRoots = new string[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData) + @"\Programs"
            };
            foreach (string root in searchRoots)
            {
                if (!Directory.Exists(root)) continue;
                try
                {
                    foreach (string dir in Directory.GetDirectories(root, "GIMP*"))
                    {
                        string binDir = Path.Combine(dir, "bin");
                        if (Directory.Exists(binDir))
                        {
                            string[] exes = Directory.GetFiles(binDir, "gimp-*.exe");
                            if (exes.Length > 0)
                            {
                                Process.Start(exes[0], "\"" + _lastSavedPath + "\"");
                                return;
                            }
                        }
                    }
                }
                catch { }
            }
            Process.Start("explorer.exe", "/select,\"" + _lastSavedPath + "\"");
        }

        private void EjectHolderAsync()
        {
            SetUiBusy(true, "Ejecting film holder...");
            ThreadPool.QueueUserWorkItem(_ =>
            {
                try
                {
                    using (var sc = new DimageScanner())
                    {
                        if (sc.Open(null))
                        {
                            sc.EnsureFirmwareLoaded(null, UpdateStatus);
                            sc.ObjectPosition(0x00, UpdateStatus);
                            UpdateStatus("Film holder ejected.");
                        }
                    }
                }
                catch (Exception ex)
                {
                    UpdateStatus("Eject note: " + ex.Message);
                }
                finally
                {
                    SetUiBusy(false);
                }
            });
        }

        private void FixBlinkingLightGuideAsync()
        {
            SetUiBusy(true, "Releasing scanner lock & ejecting film holder...");
            ThreadPool.QueueUserWorkItem(_ =>
            {
                try
                {
                    using (var sc = new DimageScanner())
                    {
                        if (!sc.Open(null))
                        {
                            BeginInvoke(new Action(() =>
                            {
                                MessageBox.Show(this,
                                    "Scanner is not detected on USB.\n\n" +
                                    "1. Gently pull any film holder out of the front slot.\n" +
                                    "2. Turn the scanner OFF, wait 5 seconds, and turn it back ON with the slot empty.\n" +
                                    "3. Wait for the green light to stop blinking, then insert your film holder.",
                                    "How to Clear a Blinking Light",
                                    MessageBoxButtons.OK,
                                    MessageBoxIcon.Information);
                            }));
                            return;
                        }
                        sc.EnsureFirmwareLoaded(null, UpdateStatus);
                        sc.RecoverJammedHolder(UpdateStatus);

                        Invoke(new Action(() =>
                        {
                            MessageBox.Show(this,
                                "Step 1: Please remove the film holder completely from the scanner slot now, then click OK so the scanner can calibrate its sensor.",
                                "Remove Film Holder to Calibrate",
                                MessageBoxButtons.OK,
                                MessageBoxIcon.Information);
                        }));

                        sc.InitializeScanner(UpdateStatus);

                        BeginInvoke(new Action(() =>
                        {
                            _lblBanner.BackColor = Color.FromArgb(22, 101, 52);
                            _lblBanner.Text = "Scanner Reset & Calibrated! You may now slide your film holder back in.";
                            MessageBox.Show(this,
                                "Success! The scanner has calibrated its lamp and sensor.\n\n" +
                                "You may now gently slide your film holder back into the slot and click Scan.",
                                "Scanner Ready",
                                MessageBoxButtons.OK,
                                MessageBoxIcon.Information);
                        }));
                    }
                }
                catch (Exception ex)
                {
                    UpdateStatus("Reset note: " + ex.Message);
                }
                finally
                {
                    SetUiBusy(false);
                }
            });
        }
    }

    internal static class Program
    {
        [STAThread]
        private static int Main(string[] args)
        {
            // Launch the Dad-Proof Windows GUI when double-clicked or called with --gui!
            if (args.Length == 0 || (args.Length == 1 && args[0].Equals("--gui", StringComparison.OrdinalIgnoreCase)))
            {
                Application.EnableVisualStyles();
                Application.SetCompatibleTextRenderingDefault(false);
                Application.Run(new MainScannerForm());
                return 0;
            }

            string cmd = args[0].ToLowerInvariant();
            string devPath = null;
            string fwPath = null;
            string outPath = "scan.tif";
            int dpi = 2820;
            byte frame = 1;
            byte multiSample = 1;
            FilmType film = FilmType.ColorNegative;

            for (int i = 1; i < args.Length; i++)
            {
                if (args[i] == "--device" && i + 1 < args.Length) devPath = args[++i];
                else if (args[i] == "--firmware" && i + 1 < args.Length) fwPath = args[++i];
                else if (args[i] == "--out" && i + 1 < args.Length) outPath = args[++i];
                else if (args[i] == "--dpi" && i + 1 < args.Length) int.TryParse(args[++i], out dpi);
                else if (args[i] == "--frame" && i + 1 < args.Length) byte.TryParse(args[++i], out frame);
                else if (args[i] == "--multisample" && i + 1 < args.Length) byte.TryParse(args[++i], out multiSample);
                else if (args[i] == "--film" && i + 1 < args.Length)
                {
                    string f = args[++i].ToLowerInvariant();
                    if (f == "pos" || f == "slide") film = FilmType.ColorSlidePositive;
                    else if (f == "bw") film = FilmType.BlackAndWhiteNegative;
                    else film = FilmType.ColorNegative;
                }
                else if (cmd == "frame" && !args[i].StartsWith("-"))
                {
                    byte.TryParse(args[i], out frame);
                }
            }

            using (var scanner = new DimageScanner())
            {
                if (!scanner.Open(devPath))
                {
                    Console.Error.WriteLine("Error: Minolta DiMAGE Scan Dual III (VID_0686&PID_400D) not found on \\\\.\\UsbScan0..127.");
                    return 1;
                }

                scanner.EnsureFirmwareLoaded(fwPath, msg => Console.WriteLine(msg));

                if (cmd == "info")
                {
                    Console.WriteLine("Device Path : " + scanner.DevicePath);
                    Console.WriteLine("SCSI ID     : " + scanner.Inquiry());
                    byte ht = scanner.GetHolderType();
                    Console.WriteLine("Holder Type : 0x{0:X2} (1=35mm Strip, 2=Slide Mount, FF=None)", ht);
                }
                else if (cmd == "eject")
                {
                    scanner.ObjectPosition(0x00);
                    Console.WriteLine("Film holder ejected.");
                }
                else if (cmd == "retract")
                {
                    scanner.ObjectPosition(0x02);
                    Console.WriteLine("Film holder retracted.");
                }
                else if (cmd == "reset")
                {
                    scanner.RecoverJammedHolder();
                    Console.WriteLine("Scanner released and film holder ejected. Remove holder and run 'retract' to re-home.");
                }
                else if (cmd == "frame")
                {
                    scanner.MoveToFrame(frame);
                    Console.WriteLine("Moved film holder to frame " + frame);
                }
                else if (cmd == "scan")
                {
                    using (Bitmap bmp = scanner.ScanFrameToBitmap(frame, dpi, film, multiSample, msg => Console.WriteLine(msg), null))
                    {
                        SaveBitmapByExtension(bmp, outPath);
                        Console.WriteLine("Saved {0}x{1} scan to {2}", bmp.Width, bmp.Height, outPath);
                    }
                }
                else if (cmd == "scan-strip")
                {
                    byte ht = scanner.GetHolderType();
                    byte total = (ht == 2) ? (byte)4 : (byte)6;
                    for (byte f = 1; f <= total; f++)
                    {
                        string frameFile = string.Format("{0}_frame{1}.jpg", Path.GetFileNameWithoutExtension(outPath), f);
                        using (Bitmap bmp = scanner.ScanFrameToBitmap(f, dpi, film, multiSample, msg => Console.WriteLine(msg), null))
                        {
                            SaveBitmapByExtension(bmp, frameFile);
                            Console.WriteLine("Saved frame {0}/{1} -> {2}", f, total, frameFile);
                        }
                    }
                }
                else
                {
                    Console.WriteLine("Commands: info | scan | scan-strip | eject | retract | reset | frame <1..6>");
                    return 1;
                }
            }
            return 0;
        }

        private static void SaveBitmapByExtension(Bitmap bmp, string path)
        {
            string ext = Path.GetExtension(path).ToLowerInvariant();
            if (ext == ".jpg" || ext == ".jpeg") bmp.Save(path, ImageFormat.Jpeg);
            else if (ext == ".png") bmp.Save(path, ImageFormat.Png);
            else if (ext == ".bmp") bmp.Save(path, ImageFormat.Bmp);
            else bmp.Save(path, ImageFormat.Tiff);
        }
    }
}
'@

Set-Content -Path $csFile -Value $csCode -Encoding UTF8
$csc = Join-Path $env:WINDIR "Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if (-not (Test-Path $csc)) {
    $csc = Join-Path $env:WINDIR "Microsoft.NET\Framework\v4.0.30319\csc.exe"
}
if (-not (Test-Path $csc)) {
    throw "Could not find built-in Windows .NET compiler (csc.exe) at $csc"
}

Write-Host "[*] Compiling 64-bit Windows Scanner Studio & CLI ($OutputExe) via built-in .NET csc.exe..." -ForegroundColor Cyan
& $csc /nologo /optimize+ /r:System.Core.dll /r:Microsoft.CSharp.dll /r:System.Windows.Forms.dll /r:System.Drawing.dll /out:$OutputExe $csFile
if ($LASTEXITCODE -ne 0) {
    throw "csc.exe compilation failed with exit code $LASTEXITCODE"
}

if (-not [string]::IsNullOrEmpty($GuiOutputExe)) {
    & $csc /nologo /optimize+ /target:winexe /r:System.Core.dll /r:Microsoft.CSharp.dll /r:System.Windows.Forms.dll /r:System.Drawing.dll /out:$GuiOutputExe $csFile
    if ($LASTEXITCODE -ne 0) {
        throw "csc.exe GUI compilation failed with exit code $LASTEXITCODE"
    }
    Write-Host "[+] Built Windows Desktop GUI App: $GuiOutputExe" -ForegroundColor Green
}

Remove-Item $csFile -Force -ErrorAction SilentlyContinue
Write-Host "[+] Built Windows Scanner Utility: $OutputExe" -ForegroundColor Green
