<#
.SYNOPSIS
    Builds the standalone Minolta DiMAGE Scan Dual III (Model #2889 / FS-V3) CLI utility on Windows 11.
.DESCRIPTION
    1. If MSVC (cl.exe), GCC (gcc.exe), or Clang (clang.exe) is installed in PATH, compiles dimage_scan.c
       directly into a native 64-bit dimage_scan.exe.
    2. Otherwise, uses the built-in Windows .NET compiler (csc.exe) to compile an embedded zero-dependency
       64-bit native P/Invoke implementation speaking the exact same 3-phase \\.\UsbScanN SCSI protocol.
#>
[CmdletBinding()]
param(
    [string]$OutputExe = (Join-Path $PSScriptRoot "dimage_scan.exe")
)

$ErrorActionPreference = "Stop"
$cSource = Join-Path $PSScriptRoot "dimage_scan.c"

if (Get-Command "cl.exe" -ErrorAction SilentlyContinue) {
    Write-Host "[*] Compiling dimage_scan.c with MSVC (cl.exe)..." -ForegroundColor Cyan
    & cl.exe /nologo /O2 /W3 $cSource /Fe:$OutputExe
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[+] Built native $OutputExe via MSVC." -ForegroundColor Green
        return
    }
}

if (Get-Command "gcc.exe" -ErrorAction SilentlyContinue) {
    Write-Host "[*] Compiling dimage_scan.c with GCC..." -ForegroundColor Cyan
    & gcc.exe -std=c11 -O2 -Wall $cSource -o $OutputExe
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[+] Built native $OutputExe via GCC." -ForegroundColor Green
        return
    }
}

Write-Host "[*] No C compiler in PATH; building zero-dependency 64-bit Windows executable via built-in .NET csc.exe..." -ForegroundColor Cyan

$csFile = Join-Path $env:TEMP "MinoltaDimageScan.cs"
$csCode = @'
using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Runtime.InteropServices;
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
    }

    public sealed class DimageScanner : IDisposable
    {
        public const ushort VID_MINOLTA = 0x0686;
        public const ushort PID_DUAL_III = 0x400D;

        private SafeFileHandle _handle;
        public string DevicePath { get; private set; }

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

        // 3-phase USB/SCSI execution matching MFSIFLib2889.dll @ 0x10002830
        public byte ExecScsi(byte[] cdb, int dir, byte[] data, int dataLen)
        {
            uint written;
            if (!NativeUsbScan.WriteFile(_handle, cdb, (uint)cdb.Length, out written, IntPtr.Zero) || written != cdb.Length)
                throw new IOException("CDB WriteFile failed: Win32 error " + Marshal.GetLastWin32Error());

            if (dir == 1 && data != null && dataLen > 0)
            {
                uint read;
                if (!NativeUsbScan.ReadFile(_handle, data, (uint)dataLen, out read, IntPtr.Zero))
                    throw new IOException("Data-In ReadFile failed: Win32 error " + Marshal.GetLastWin32Error());
            }
            else if (dir == 2 && data != null && dataLen > 0)
            {
                if (!NativeUsbScan.WriteFile(_handle, data, (uint)dataLen, out written, IntPtr.Zero) || written != dataLen)
                    throw new IOException("Data-Out WriteFile failed: Win32 error " + Marshal.GetLastWin32Error());
            }

            byte[] status = new byte[1];
            uint sRead;
            if (!NativeUsbScan.ReadFile(_handle, status, 1, out sRead, IntPtr.Zero) || sRead != 1)
                throw new IOException("Status ReadFile failed: Win32 error " + Marshal.GetLastWin32Error());

            return status[0];
        }

        public bool TestUnitReady()
        {
            byte[] cdb = new byte[6];
            return ExecScsi(cdb, 4, null, 0) == 0;
        }

        public string Inquiry()
        {
            byte[] cdb = new byte[] { 0x12, 0, 0, 0, 96, 0 };
            byte[] buf = new byte[96];
            ExecScsi(cdb, 1, buf, 96);
            return Encoding.ASCII.GetString(buf, 8, 28).Trim();
        }

        public void Read10(byte dataType, ushort qual, byte[] buf)
        {
            byte[] cdb = new byte[10];
            cdb[0] = 0x28;
            cdb[2] = dataType;
            cdb[4] = (byte)(qual >> 8);
            cdb[5] = (byte)(qual & 0xFF);
            cdb[6] = (byte)((buf.Length >> 16) & 0xFF);
            cdb[7] = (byte)((buf.Length >> 8) & 0xFF);
            cdb[8] = (byte)(buf.Length & 0xFF);
            if (ExecScsi(cdb, 1, buf, buf.Length) != 0)
                throw new IOException(string.Format("READ(10) 0x{0:X2} failed", dataType));
        }

        public void Write10(byte dataType, ushort qual, byte[] buf)
        {
            byte[] cdb = new byte[10];
            cdb[0] = 0x2A;
            cdb[2] = dataType;
            cdb[4] = (byte)(qual >> 8);
            cdb[5] = (byte)(qual & 0xFF);
            cdb[6] = (byte)((buf.Length >> 16) & 0xFF);
            cdb[7] = (byte)((buf.Length >> 8) & 0xFF);
            cdb[8] = (byte)(buf.Length & 0xFF);
            if (ExecScsi(cdb, 2, buf, buf.Length) != 0)
                throw new IOException(string.Format("WRITE(10) 0x{0:X2} failed", dataType));
        }

        public void EnsureFirmwareLoaded(string binPath)
        {
            byte[] status = new byte[8];
            Read10(0x90, 0x0022, status);
            if (status[4] == 0)
                return;

            if (!File.Exists(binPath))
                throw new FileNotFoundException("Firmware file DS_Dual3.BIN not found", binPath);

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

            Console.WriteLine("Uploading {0} bytes of RAM firmware (checksum 0x{1:X8})...", payload.Length, sum);
            Write10(0x90, 0x0000, payload);
            TestUnitReady();
            Thread.Sleep(3000);
        }

        public void ObjectPosition(byte mode)
        {
            byte[] cdb = new byte[] { 0x31, 0, 0, 0, 0, 0, 0, 0, 0, mode };
            ExecScsi(cdb, 4, null, 0);
        }

        public void MoveToFrame(byte frameIndex)
        {
            byte[] cur = new byte[8];
            Read10(0x87, 0, cur);
            byte[] cmd = new byte[] { cur[0], frameIndex, 0, 0, 0, 0, 0, 0 };
            Write10(0x87, 0, cmd);
        }

        public void Dispose()
        {
            if (_handle != null && !_handle.IsInvalid)
                _handle.Dispose();
        }
    }

    internal static class Program
    {
        private static int Main(string[] args)
        {
            if (args.Length == 0)
            {
                Console.WriteLine("Minolta DiMAGE Scan Dual III (USB\\VID_0686&PID_400D) Windows 11 CLI");
                Console.WriteLine("Commands: info | eject | retract | frame <1..6>");
                return 1;
            }

            string cmd = args[0].ToLowerInvariant();
            string fwPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "DS_Dual3.BIN");
            if (!File.Exists(fwPath))
                fwPath = @"C:\Program Files (x86)\Minolta\DS_Dual3\Firmware\DS_Dual3.BIN";

            using (var scanner = new DimageScanner())
            {
                if (!scanner.Open(null))
                {
                    Console.Error.WriteLine("Error: Minolta DiMAGE Scan Dual III (VID_0686&PID_400D) not found on \\\\.\\UsbScan0..127.");
                    return 1;
                }

                scanner.EnsureFirmwareLoaded(fwPath);

                if (cmd == "info")
                {
                    Console.WriteLine("Device Path : " + scanner.DevicePath);
                    Console.WriteLine("SCSI ID     : " + scanner.Inquiry());
                    byte[] st = new byte[32];
                    scanner.Read10(0x60, 0, st);
                    Console.WriteLine("Holder Type : 0x{0:X2} (1=35mm Strip, 2=Slide Mount, FF=None)", st[4]);
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
                else if (cmd == "frame" && args.Length > 1)
                {
                    byte frame = byte.Parse(args[1]);
                    scanner.MoveToFrame(frame);
                    Console.WriteLine("Moved film holder to frame " + frame);
                }
            }
            return 0;
        }
    }
}
'@

Set-Content -Path $csFile -Value $csCode -Encoding UTF8
$csc = Join-Path $env:WINDIR "Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if (-not (Test-Path $csc)) {
    throw "Could not find csc.exe at $csc"
}
& $csc /nologo /optimize+ /out:$OutputExe $csFile
Remove-Item $csFile -Force -ErrorAction SilentlyContinue
Write-Host "[+] Built $OutputExe via .NET Framework64 csc.exe." -ForegroundColor Green
