/*
 * dimage_scan.c
 * Standalone Modern Windows 11 / Cross-Platform Driver & CLI Utility for
 * Minolta DiMAGE Scan Dual III (USB\VID_0686&PID_400D, Model #2889 "MINOLTA FS-V3")
 *
 * Implements the full reverse-engineered USB-SCSI protocol from:
 *   - MFSIFLib2889.dll   (ev_a5228e8adef7939ed59bb800a41814ce53a87e7d29fd53557ccbe7e822a4a065)
 *   - MFSBaseLib2889.dll (ev_a89b1e8479e77205639f8f9ae0b71debb09ac1523ae7266125873b7c3d26d985)
 */

#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif
#include "dimage_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <unistd.h>
#include <time.h>
#endif

/* ============================================================================
 * Endianness & Timing Helpers
 * ============================================================================ */

static inline uint16_t be16_to_cpu(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static inline uint32_t be32_to_cpu(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
}

static inline void cpu_to_be16(uint16_t v, uint8_t *p) {
    p[0] = (uint8_t)((v >> 8) & 0xFF);
    p[1] = (uint8_t)(v & 0xFF);
}

static inline void cpu_to_be24(uint32_t v, uint8_t *p) {
    p[0] = (uint8_t)((v >> 16) & 0xFF);
    p[1] = (uint8_t)((v >> 8) & 0xFF);
    p[2] = (uint8_t)(v & 0xFF);
}

static inline void cpu_to_be32(uint32_t v, uint8_t *p) {
    p[0] = (uint8_t)((v >> 24) & 0xFF);
    p[1] = (uint8_t)((v >> 16) & 0xFF);
    p[2] = (uint8_t)((v >> 8) & 0xFF);
    p[3] = (uint8_t)(v & 0xFF);
}

static inline void cpu_to_le16(uint16_t v, uint8_t *p) {
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)((v >> 8) & 0xFF);
}

static inline void cpu_to_le32(uint32_t v, uint8_t *p) {
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)((v >> 8) & 0xFF);
    p[2] = (uint8_t)((v >> 16) & 0xFF);
    p[3] = (uint8_t)((v >> 24) & 0xFF);
}

static void dimage_sleep_ms(uint32_t ms) {
#ifdef _WIN32
    Sleep(ms);
#else
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (long)(ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
#endif
}

/* ============================================================================
 * Device Discovery & Lifecycle (MFSIFLib2889.dll @ 0x100018e0)
 * ============================================================================ */

#ifdef _WIN32
#pragma pack(push, 1)
typedef struct {
    uint16_t usVendorId;
    uint16_t usProductId;
    uint16_t usBcdDevice;
    uint16_t usLanguageId;
} usbscan_device_descriptor_t;
#pragma pack(pop)
#endif

int dimage_open(dimage_scanner_t *dev, const char *explicit_path, bool verbose) {
    if (!dev) return -1;
    memset(dev, 0, sizeof(*dev));
    dev->verbose = verbose;

#ifdef _WIN32
    HANDLE hMutex = CreateMutexA(NULL, FALSE, "Global\\MinoltaDimageScanDual3Mutex");
    if (!hMutex) {
        hMutex = CreateMutexA(NULL, FALSE, "Local\\MinoltaDimageScanDual3Mutex");
    }
    dev->ipc_mutex = (void *)hMutex;

    if (explicit_path && explicit_path[0]) {
        HANDLE h = CreateFileA(
            explicit_path,
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL,
            OPEN_EXISTING,
            0,
            NULL
        );
        if (h == INVALID_HANDLE_VALUE) {
            if (verbose) {
                fprintf(stderr, "[dimage] Failed to open %s (Win32 error %lu)\n",
                        explicit_path, GetLastError());
            }
            if (dev->ipc_mutex) { CloseHandle((HANDLE)dev->ipc_mutex); dev->ipc_mutex = NULL; }
            return -1;
        }
        dev->os_handle = (void *)h;
        snprintf(dev->device_path, sizeof(dev->device_path), "%s", explicit_path);
        return 0;
    }

    /* Probe \\.\UsbScan0 .. \\.\UsbScan127 as in MFSIFLib2889.dll @ 0x10001dc7-0x10001eb1 */
    for (int i = 0; i < 128; ++i) {
        char path[64];
        snprintf(path, sizeof(path), "\\\\.\\UsbScan%d", i);
        HANDLE h = CreateFileA(
            path,
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL,
            OPEN_EXISTING,
            0,
            NULL
        );
        if (h == INVALID_HANDLE_VALUE) {
            continue;
        }

        usbscan_device_descriptor_t desc;
        memset(&desc, 0, sizeof(desc));
        DWORD bytes_ret = 0;
        BOOL ok = DeviceIoControl(
            h,
            DIMAGE_IOCTL_GET_DEVICE_DESCRIPTOR,
            NULL, 0,
            &desc, sizeof(desc),
            &bytes_ret,
            NULL
        );
        if (ok && desc.usVendorId == DIMAGE_USB_VID && desc.usProductId == DIMAGE_USB_PID) {
            dev->os_handle = (void *)h;
            snprintf(dev->device_path, sizeof(dev->device_path), "%s", path);
            if (verbose) {
                fprintf(stderr, "[dimage] Found Minolta DiMAGE Scan Dual III at %s (VID=%04X PID=%04X)\n",
                        path, desc.usVendorId, desc.usProductId);
            }
            return 0;
        }
        CloseHandle(h);
    }
    if (dev->ipc_mutex) { CloseHandle((HANDLE)dev->ipc_mutex); dev->ipc_mutex = NULL; }
    if (verbose) {
        fprintf(stderr, "[dimage] No Minolta DiMAGE Scan Dual III (VID_0686&PID_400D) found on \\\\.\\UsbScan0..127\n");
    }
    return -1;
#else
    if (explicit_path) {
        snprintf(dev->device_path, sizeof(dev->device_path), "%s", explicit_path);
    } else {
        snprintf(dev->device_path, sizeof(dev->device_path), "mock://UsbScan0");
    }
    return 0;
#endif
}

void dimage_close(dimage_scanner_t *dev) {
    if (!dev) return;
#ifdef _WIN32
    if (dev->os_handle && dev->os_handle != INVALID_HANDLE_VALUE) {
        CloseHandle((HANDLE)dev->os_handle);
        dev->os_handle = NULL;
    }
    if (dev->ipc_mutex) {
        CloseHandle((HANDLE)dev->ipc_mutex);
        dev->ipc_mutex = NULL;
    }
#else
    dev->os_handle = NULL;
    dev->ipc_mutex = NULL;
#endif
}

/* ============================================================================
 * 3-Phase USB-SCSI Execution (MFSIFLib2889.dll @ 0x10002780 & MFSBase @ 0x1000c4d0)
 *   Phase 1: WriteFile(hDevice, cdb, cdb_len)
 *   Phase 2: ReadFile/WriteFile(hDevice, data, data_len) [if dir == IN/OUT]
 *   Phase 3: ReadFile(hDevice, &status_byte, 1)
 * ============================================================================ */

static int dimage_raw_transport(
    dimage_scanner_t *dev,
    const uint8_t *cdb,
    size_t cdb_len,
    dimage_direction_t dir,
    uint8_t *data,
    size_t data_len,
    uint8_t *status_out
) {
    if (!dev || !cdb || (cdb_len != 6 && cdb_len != 10) || !status_out) {
        return -1;
    }
    *status_out = 0xFF;

    if (dev->verbose) {
        fprintf(stderr, "[SCSI CDB] ");
        for (size_t i = 0; i < cdb_len; ++i) fprintf(stderr, "%02X ", cdb[i]);
        fprintf(stderr, "(dir=%d, len=%zu)\n", (int)dir, data_len);
    }

    if (dev->custom_transport) {
        return dev->custom_transport(dev->custom_ctx, cdb, cdb_len, dir, data, data_len, status_out);
    }

#ifdef _WIN32
    HANDLE h = (HANDLE)dev->os_handle;
    if (!h || h == INVALID_HANDLE_VALUE) return -1;

    HANDLE hMtx = (HANDLE)dev->ipc_mutex;
    if (hMtx) {
        WaitForSingleObject(hMtx, 60000);
    }

    DWORD transferred = 0;
    /* Phase 1: Send CDB */
    if (!WriteFile(h, cdb, (DWORD)cdb_len, &transferred, NULL) || transferred != (DWORD)cdb_len) {
        *status_out = 0xFA; /* Bus/write error code from MFSIFLib2889.dll @ 0x10002846 */
        if (hMtx) ReleaseMutex(hMtx);
        return -1;
    }

    /* Phase 2: Data Transfer (if requested) */
    if (dir == DIMAGE_DIR_IN && data && data_len > 0) {
        transferred = 0;
        if (!ReadFile(h, data, (DWORD)data_len, &transferred, NULL) || transferred != (DWORD)data_len) {
            *status_out = 0x9F; /* Data IN error from MFSIFLib2889.dll @ 0x10002a83 */
            if (hMtx) ReleaseMutex(hMtx);
            return -1;
        }
    } else if (dir == DIMAGE_DIR_OUT && data && data_len > 0) {
        transferred = 0;
        if (!WriteFile(h, data, (DWORD)data_len, &transferred, NULL) || transferred != (DWORD)data_len) {
            *status_out = 0xA3; /* Data OUT error from MFSIFLib2889.dll @ 0x10002a69 */
            if (hMtx) ReleaseMutex(hMtx);
            return -1;
        }
    }

    /* Phase 3: Read 1-byte SCSI Status */
    uint8_t sb = 0xFF;
    transferred = 0;
    if (!ReadFile(h, &sb, 1, &transferred, NULL) || transferred != 1) {
        *status_out = 0x9D; /* Status phase error from MFSIFLib2889.dll @ 0x10002b26 */
        if (hMtx) ReleaseMutex(hMtx);
        return -1;
    }
    *status_out = sb;
    if (hMtx) ReleaseMutex(hMtx);

    /* 1ms inter-command pacing delay as in MFSBaseLib2889.dll @ 0x1000c5bc */
    dimage_sleep_ms(1);
    return (sb == 0x00) ? 0 : -1;
#else
    return -1;
#endif
}

int dimage_request_sense(dimage_scanner_t *dev, uint8_t sense_out[22]) {
    uint8_t cdb[6] = { SCSI_OP_REQUEST_SENSE, 0x00, 0x00, 0x00, 0x16, 0x00 };
    uint8_t buf[22];
    memset(buf, 0, sizeof(buf));
    uint8_t status = 0;
    int rc = dimage_raw_transport(dev, cdb, 6, DIMAGE_DIR_IN, buf, sizeof(buf), &status);
    memcpy(dev->last_sense, buf, sizeof(buf));
    if (sense_out) memcpy(sense_out, buf, sizeof(buf));
    return rc;
}

int dimage_exec_scsi(
    dimage_scanner_t *dev,
    const uint8_t *cdb,
    size_t cdb_len,
    dimage_direction_t dir,
    uint8_t *data,
    size_t data_len
) {
    uint8_t status = 0;
    int rc = dimage_raw_transport(dev, cdb, cdb_len, dir, data, data_len, &status);
    if (rc == 0 && status == 0x00) {
        dev->last_error_code = 0;
        return 0;
    }

    /* Handle CHECK CONDITION (0x02) via REQUEST SENSE (MFSBaseLib2889.dll @ 0x1000c5ef) */
    if (status == 0x02 && cdb[0] != SCSI_OP_REQUEST_SENSE) {
        uint8_t sense[22];
        if (dimage_request_sense(dev, sense) == 0) {
            uint8_t sk   = sense[2] & 0x0F;
            uint8_t asc  = sense[12];
            uint8_t ascq = sense[13];
            /* Sense Key 0x02 ASC 0x04 = Not Ready / Warming Up (0xA2 in MFSBaseLib2889) */
            if (sk == 0x02 && asc == 0x04) {
                dev->last_error_code = 0xA2;
            } else {
                dev->last_error_code = ((uint32_t)sk << 16) | ((uint32_t)asc << 8) | ascq;
            }
            if (dev->verbose) {
                fprintf(stderr, "[SCSI SENSE] SK=0x%02X ASC=0x%02X ASCQ=0x%02X (err=0x%X)\n",
                        sk, asc, ascq, dev->last_error_code);
            }
        }
    } else if (status == 0x08) {
        /* BUSY -> wait 1000ms and retry once (MFSBaseLib2889.dll @ 0x1000c640) */
        dimage_sleep_ms(1000);
        rc = dimage_raw_transport(dev, cdb, cdb_len, dir, data, data_len, &status);
        if (rc == 0 && status == 0x00) {
            dev->last_error_code = 0;
            return 0;
        }
    }
    return -1;
}

/* ============================================================================
 * Standard SCSI Commands (MFSBaseLib2889.dll @ 0x1000c880 - 0x1000cad0)
 * ============================================================================ */

int dimage_test_unit_ready(dimage_scanner_t *dev) {
    uint8_t cdb[6] = { SCSI_OP_TEST_UNIT_READY, 0, 0, 0, 0, 0 };
    return dimage_exec_scsi(dev, cdb, 6, DIMAGE_DIR_NONE, NULL, 0);
}

int dimage_wait_ready(dimage_scanner_t *dev, uint32_t timeout_ms) {
    uint32_t elapsed = 0;
    while (elapsed <= timeout_ms) {
        if (dimage_test_unit_ready(dev) == 0) {
            return 0;
        }
        /* Retry on Not Ready / Lamp Warming Up (0xA2) and Unit Attention (SK=0x06) */
        uint8_t sk = (uint8_t)((dev->last_error_code >> 16) & 0x0F);
        if (dev->last_error_code != 0xA2 && sk != 0x06 && sk != 0x02 && elapsed > 0) {
            return -1;
        }
        dimage_sleep_ms(100);
        elapsed += 100;
    }
    return -1;
}

int dimage_inquiry(dimage_scanner_t *dev, char vendor_model_out[25], char fw_rev_out[5], uint8_t raw_out[96]) {
    uint8_t cdb[6] = { SCSI_OP_INQUIRY, 0x00, 0x00, 0x00, 0x60, 0x00 };
    uint8_t buf[96];
    memset(buf, 0, sizeof(buf));
    if (dimage_exec_scsi(dev, cdb, 6, DIMAGE_DIR_IN, buf, sizeof(buf)) != 0) {
        return -1;
    }
    if (vendor_model_out) {
        memcpy(vendor_model_out, &buf[8], 24);
        vendor_model_out[24] = '\0';
    }
    if (fw_rev_out) {
        memcpy(fw_rev_out, &buf[32], 4);
        fw_rev_out[4] = '\0';
    }
    if (raw_out) {
        memcpy(raw_out, buf, sizeof(buf));
    }
    return 0;
}

int dimage_reserve_unit(dimage_scanner_t *dev) {
    uint8_t cdb[6] = { SCSI_OP_RESERVE_UNIT, 0, 0, 0, 0, 0 };
    return dimage_exec_scsi(dev, cdb, 6, DIMAGE_DIR_NONE, NULL, 0);
}

int dimage_release_unit(dimage_scanner_t *dev) {
    uint8_t cdb[6] = { SCSI_OP_RELEASE_UNIT, 0, 0, 0, 0, 0 };
    return dimage_exec_scsi(dev, cdb, 6, DIMAGE_DIR_NONE, NULL, 0);
}

int dimage_read10(dimage_scanner_t *dev, uint8_t data_type, uint16_t qual, uint8_t *buf, uint32_t len) {
    uint8_t cdb[10];
    memset(cdb, 0, sizeof(cdb));
    cdb[0] = SCSI_OP_READ_10;
    cdb[2] = data_type;
    cpu_to_be16(qual, &cdb[4]);
    cpu_to_be24(len, &cdb[6]);
    return dimage_exec_scsi(dev, cdb, 10, DIMAGE_DIR_IN, buf, len);
}

int dimage_write10(dimage_scanner_t *dev, uint8_t data_type, uint16_t qual, const uint8_t *buf, uint32_t len) {
    uint8_t cdb[10];
    memset(cdb, 0, sizeof(cdb));
    cdb[0] = SCSI_OP_WRITE_10;
    cdb[2] = data_type;
    cpu_to_be16(qual, &cdb[4]);
    cpu_to_be24(len, &cdb[6]);
    return dimage_exec_scsi(dev, cdb, 10, DIMAGE_DIR_OUT, (uint8_t *)buf, len);
}

/* ============================================================================
 * Firmware Check & Upload (MFSBaseLib2889.dll @ 0x1000c120 - 0x1000c400)
 * ============================================================================ */

uint32_t dimage_compute_firmware_checksum(const uint8_t *fw_data, size_t fw_len) {
    uint32_t sum = 0;
    for (size_t i = 0; i < fw_len; ++i) {
        sum += fw_data[i];
    }
    return sum;
}

int dimage_is_firmware_loaded(dimage_scanner_t *dev, bool *loaded_out) {
    uint8_t status_buf[8];
    memset(status_buf, 0, sizeof(status_buf));
    /* READ(10) data_type=0x90, qual=0x0022, len=8 (MFSBaseLib2889.dll @ 0x1000c136) */
    if (dimage_read10(dev, DIMAGE_DT_FIRMWARE, 0x0022, status_buf, 8) != 0) {
        return -1;
    }
    /* status_buf[4] == 0 means RAM firmware is already running */
    if (loaded_out) {
        *loaded_out = (status_buf[4] == 0);
    }
    return 0;
}

int dimage_upload_firmware_buffer(dimage_scanner_t *dev, const uint8_t *fw_data, size_t fw_len) {
    if (!dev || !fw_data || fw_len == 0) return -1;

    /* Verify scanner identity via INQUIRY before uploading (0x1000c18b) */
    char model[25];
    if (dimage_inquiry(dev, model, NULL, NULL) != 0) {
        return -1;
    }
    if (strncmp(model, "MINOLTA FS-V3", 13) != 0) {
        if (dev->verbose) {
            fprintf(stderr, "[dimage] Unexpected INQUIRY string: '%s'\n", model);
        }
        return -1;
    }

    if (dimage_wait_ready(dev, 5000) != 0) {
        return -1;
    }

    /* Allocate fw_len + 4 bytes and append 32-bit little-endian byte sum (0x1000c39f - 0x1000c3be) */
    size_t total_len = fw_len + 4;
    uint8_t *payload = (uint8_t *)malloc(total_len);
    if (!payload) return -1;

    memcpy(payload, fw_data, fw_len);
    uint32_t checksum = dimage_compute_firmware_checksum(fw_data, fw_len);
    cpu_to_le32(checksum, &payload[fw_len]);

    if (dev->verbose) {
        fprintf(stderr, "[dimage] Uploading firmware (%zu + 4 bytes, checksum=0x%08X)...\n",
                fw_len, checksum);
    }

    /* WRITE(10) data_type=0x90, qual=0x0000, len=total_len (0x1000c3cc) */
    int rc = dimage_write10(dev, DIMAGE_DT_FIRMWARE, 0x0000, payload, (uint32_t)total_len);
    free(payload);
    if (rc != 0) return -1;

    /* Post-upload TEST UNIT READY + 3000ms settle wait (0x1000c3da - 0x1000c3f8) */
    if (dimage_test_unit_ready(dev) != 0) {
        return -1;
    }
    if (dev->custom_transport == NULL) {
        dimage_sleep_ms(3000);
    }
    return 0;
}

static bool file_exists_readable(const char *path) {
    if (!path || !path[0]) return false;
    FILE *fp = fopen(path, "rb");
    if (fp) {
        fclose(fp);
        return true;
    }
    return false;
}

bool dimage_find_firmware_path(const char *preferred_path, char *out_path, size_t max_len) {
    if (!out_path || max_len == 0) return false;
    out_path[0] = '\0';

    if (preferred_path && file_exists_readable(preferred_path)) {
        snprintf(out_path, max_len, "%s", preferred_path);
        return true;
    }

    const char *rel_candidates[] = {
        "DS_Dual3.BIN",
        "Firmware/DS_Dual3.BIN",
        "Firmware\\DS_Dual3.BIN",
        "../win11_driver/Minolta_Software/Firmware/DS_Dual3.BIN",
        "..\\win11_driver\\Minolta_Software\\Firmware\\DS_Dual3.BIN"
    };
    for (size_t i = 0; i < sizeof(rel_candidates) / sizeof(rel_candidates[0]); ++i) {
        if (file_exists_readable(rel_candidates[i])) {
            snprintf(out_path, max_len, "%s", rel_candidates[i]);
            return true;
        }
    }

#ifdef _WIN32
    /* Check directory of the running executable/DLL */
    char mod_dir[MAX_PATH] = {0};
    if (GetModuleFileNameA(NULL, mod_dir, MAX_PATH) > 0) {
        char *slash = strrchr(mod_dir, '\\');
        if (slash) {
            *slash = '\0';
            char cand[MAX_PATH];
            snprintf(cand, sizeof(cand), "%s\\DS_Dual3.BIN", mod_dir);
            if (file_exists_readable(cand)) {
                snprintf(out_path, max_len, "%s", cand);
                return true;
            }
            snprintf(cand, sizeof(cand), "%s\\Firmware\\DS_Dual3.BIN", mod_dir);
            if (file_exists_readable(cand)) {
                snprintf(out_path, max_len, "%s", cand);
                return true;
            }
        }
    }

    /* Check Windows Registry HomePath (both 64-bit and WOW6432Node) */
    const char *reg_keys[] = {
        "SOFTWARE\\WOW6432Node\\MINOLTA\\DS_Dual3",
        "SOFTWARE\\MINOLTA\\DS_Dual3",
        "SOFTWARE\\WOW6432Node\\MINOLTA\\DS_Dual3Easy",
        "SOFTWARE\\MINOLTA\\DS_Dual3Easy"
    };
    for (size_t i = 0; i < sizeof(reg_keys) / sizeof(reg_keys[0]); ++i) {
        HKEY hKey = NULL;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, reg_keys[i], 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            char home[MAX_PATH] = {0};
            DWORD cb = sizeof(home) - 1;
            DWORD type = 0;
            if (RegQueryValueExA(hKey, "HomePath", NULL, &type, (LPBYTE)home, &cb) == ERROR_SUCCESS &&
                (type == REG_SZ || type == REG_EXPAND_SZ)) {
                RegCloseKey(hKey);
                char cand[MAX_PATH];
                snprintf(cand, sizeof(cand), "%s\\Firmware\\DS_Dual3.BIN", home);
                if (file_exists_readable(cand)) {
                    snprintf(out_path, max_len, "%s", cand);
                    return true;
                }
            } else {
                RegCloseKey(hKey);
            }
        }
    }

    const char *default_win_path = "C:\\Program Files (x86)\\Minolta\\DS_Dual3\\Firmware\\DS_Dual3.BIN";
    if (file_exists_readable(default_win_path)) {
        snprintf(out_path, max_len, "%s", default_win_path);
        return true;
    }
#endif
    return false;
}

int dimage_upload_firmware_file(dimage_scanner_t *dev, const char *bin_path, bool force) {
    if (!force) {
        bool already_loaded = false;
        if (dimage_is_firmware_loaded(dev, &already_loaded) == 0 && already_loaded) {
            if (dev->verbose) {
                fprintf(stderr, "[dimage] RAM firmware is already active in scanner.\n");
            }
            return 0;
        }
    }

    char resolved_path[512];
    if (!dimage_find_firmware_path(bin_path, resolved_path, sizeof(resolved_path))) {
        fprintf(stderr, "[dimage] Cannot find firmware file: %s\n", bin_path ? bin_path : "DS_Dual3.BIN");
        return -1;
    }

    FILE *fp = fopen(resolved_path, "rb");
    if (!fp) {
        fprintf(stderr, "[dimage] Cannot open firmware file: %s\n", resolved_path);
        return -1;
    }
    fseek(fp, 0, SEEK_END);
    long sz = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (sz <= 0 || sz > 1024 * 1024) {
        fclose(fp);
        return -1;
    }

    uint8_t *buf = (uint8_t *)malloc((size_t)sz);
    if (!buf) {
        fclose(fp);
        return -1;
    }
    if (fread(buf, 1, (size_t)sz, fp) != (size_t)sz) {
        free(buf);
        fclose(fp);
        return -1;
    }
    fclose(fp);

    int rc = dimage_upload_firmware_buffer(dev, buf, (size_t)sz);
    free(buf);
    return rc;
}

/* ============================================================================
 * Hardware Status, Film Holder, Focus & Initialization
 * ============================================================================ */

int dimage_get_status(dimage_scanner_t *dev, dimage_status_t *status_out) {
    if (!dev || !status_out) return -1;
    memset(status_out, 0, sizeof(*status_out));

    if (dimage_wait_ready(dev, 6000) != 0) return -1;

    uint8_t raw[32];
    memset(raw, 0, sizeof(raw));
    /* READ(10) data_type=0x60, qual=0, len=0x20 (MFSBaseLib2889.dll @ 0x10005990) */
    if (dimage_read10(dev, DIMAGE_DT_SCANNER_STATUS, 0x0000, raw, 32) != 0) {
        return -1;
    }

    memcpy(status_out->raw, raw, 32);
    status_out->flags_word0   = be16_to_cpu(&raw[0]);
    status_out->holder_type   = raw[4];
    status_out->holder_flags  = raw[5];
    status_out->r_exp_default = be16_to_cpu(&raw[9]);
    status_out->g_exp_default = be16_to_cpu(&raw[11]);
    status_out->b_exp_default = be16_to_cpu(&raw[13]);
    status_out->r_exp_current = be16_to_cpu(&raw[15]);
    status_out->g_exp_current = be16_to_cpu(&raw[17]);
    status_out->b_exp_current = be16_to_cpu(&raw[19]);
    status_out->focus_limit   = be16_to_cpu(&raw[25]);
    return 0;
}

int dimage_get_light_status(dimage_scanner_t *dev, uint8_t *light_status_out) {
    uint8_t val = 0;
    /* READ(10) data_type=0xA0, qual=0, len=1 (MFSBaseLib2889.dll @ 0x10005bc0) */
    if (dimage_read10(dev, DIMAGE_DT_LIGHT_STATUS, 0x0000, &val, 1) != 0) {
        return -1;
    }
    if (light_status_out) *light_status_out = val;
    return 0;
}

static int dimage_object_position(dimage_scanner_t *dev, uint8_t action_byte) {
    if (dimage_wait_ready(dev, 6000) != 0) return -1;
    /* OBJECT POSITION (0x31) CDB[9] = action_byte (MFSBaseLib2889.dll @ 0x1000cad0) */
    uint8_t cdb[10] = { SCSI_OP_OBJECT_POSITION, 0, 0, 0, 0, 0, 0, 0, 0, action_byte };
    return dimage_exec_scsi(dev, cdb, 10, DIMAGE_DIR_NONE, NULL, 0);
}

int dimage_eject_holder(dimage_scanner_t *dev) {
    return dimage_object_position(dev, 0x00);
}

int dimage_retract_holder(dimage_scanner_t *dev) {
    return dimage_object_position(dev, 0x02);
}

int dimage_get_holder_frame(dimage_scanner_t *dev, uint8_t *holder_id_out, uint8_t *frame_out) {
    uint8_t buf[8];
    memset(buf, 0, sizeof(buf));
    /* READ(10) data_type=0x87, qual=0, len=8 (MFSBaseLib2889.dll @ 0x100047c0) */
    if (dimage_read10(dev, DIMAGE_DT_HOLDER_POSITION, 0x0000, buf, 8) != 0) {
        return -1;
    }
    if (dimage_wait_ready(dev, 6000) != 0) return -1;
    if (holder_id_out) *holder_id_out = buf[0];
    if (frame_out)     *frame_out     = buf[2];
    return 0;
}

int dimage_move_to_frame(dimage_scanner_t *dev, uint8_t frame_index) {
    if (dimage_wait_ready(dev, 6000) != 0) return -1;
    uint8_t cur_holder = 0, max_frames = 0;
    if (dimage_get_holder_frame(dev, &cur_holder, &max_frames) != 0) {
        return -1;
    }
    if (cur_holder == 0xFF) {
        if (dev->verbose) fprintf(stderr, "[dimage] Cannot move frame: no film holder inserted.\n");
        return -1;
    }
    /* WRITE(10) data_type=0x87, qual=0, len=8 (MFSBaseLib2889.dll @ 0x10004ad2) */
    uint8_t payload[8] = { cur_holder, frame_index, 0, 0, 0, 0, 0, 0 };
    if (dimage_write10(dev, DIMAGE_DT_HOLDER_POSITION, 0x0000, payload, 8) != 0) {
        return -1;
    }
    return dimage_wait_ready(dev, 10000);
}

int dimage_set_focus_position(dimage_scanner_t *dev, int16_t focus_steps) {
    if (dimage_wait_ready(dev, 10000) != 0) return -1;
    /* MFSBaseLib2889.dll @ 0x10004b4c: positive sets 0x8000 bit on big-endian magnitude */
    uint16_t encoded = 0;
    if (focus_steps > 0) {
        encoded = (uint16_t)focus_steps | 0x8000U;
    } else if (focus_steps < 0) {
        encoded = (uint16_t)(-focus_steps) & 0x7FFFU;
    }
    uint8_t payload[8];
    memset(payload, 0, sizeof(payload));
    cpu_to_be16(encoded, &payload[0]);
    return dimage_write10(dev, DIMAGE_DT_FOCUS_POSITION, 0x0000, payload, 8);
}

int dimage_initialize_scanner(dimage_scanner_t *dev) {
    if (dimage_wait_ready(dev, 60000) != 0) return -1;

    /* WRITE(10) data_type=0x92, qual=0, len=8 (MFSBaseLib2889.dll @ 0x10004d56 -> 0x10005a40) */
    uint8_t init_payload[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };
    if (dimage_write10(dev, DIMAGE_DT_INIT_MODE, 0x0000, init_payload, 8) != 0) {
        return -1;
    }
    if (dimage_wait_ready(dev, 60000) != 0) return -1;

    /* Poll cold-cathode fluorescent lamp status (0xA0) up to 60 seconds */
    uint8_t light = 0;
    for (int attempt = 0; attempt < 120; ++attempt) {
        if (dimage_get_light_status(dev, &light) == 0 && light != 0) {
            break;
        }
        if (dev->custom_transport != NULL) {
            break;
        }
        dimage_sleep_ms(500);
    }

    /* Retract / home carrier (OBJECT POSITION 0x02 at 0x10004c88) */
    return dimage_retract_holder(dev);
}

/*
 * Recovers the scanner if a film holder was left inside during power-on
 * (which blocks the optical home/shading calibration and causes the front LED to blink).
 */
int dimage_recover_jammed_holder(dimage_scanner_t *dev) {
    if (!dev) return -1;
    dimage_release_unit(dev);
    dimage_wait_ready(dev, 15000);
    dimage_eject_holder(dev);
    dimage_wait_ready(dev, 15000);
    return 0;
}

int dimage_send_linear_gamma_lut(dimage_scanner_t *dev) {
    /* MFSBaseLib2889.dll @ 0x100092f0: WRITE(10) data_type=0x81, qual=0..2 (R,G,B), len=512 */
    uint8_t lut[512];
    for (int i = 0; i < 256; ++i) {
        uint16_t v = (uint16_t)((i << 8) | i);
        /* Stored as little-endian 16-bit entries in 0x100093a0 */
        cpu_to_le16(v, &lut[i * 2]);
    }
    for (uint16_t ch = 0; ch < 3; ++ch) {
        if (dimage_write10(dev, DIMAGE_DT_GAMMA_LUT, ch, lut, sizeof(lut)) != 0) {
            return -1;
        }
    }
    return 0;
}

/* ============================================================================
 * SET WINDOW (0x24) Builder & Motor Ramp Handshake (0x6C)
 * ============================================================================ */

void dimage_default_scan_params(dimage_scan_params_t *params) {
    if (!params) return;
    memset(params, 0, sizeof(*params));
    params->dpi          = DIMAGE_OPTICAL_DPI; /* 2820 DPI */
    params->x_offset_px  = 0;
    params->y_offset_px  = 0;
    params->width_px     = DIMAGE_MAX_WIDTH_PIXELS;  /* 2688 */
    params->height_px    = DIMAGE_MAX_HEIGHT_PIXELS; /* 4032 */
    params->bit_depth    = 16;
    params->channels     = 3;
    params->multisample  = 1;
    params->frame_index  = 1;
    params->autofocus    = false;
    params->manual_focus = 0;
    params->r_exposure   = 100;
    params->g_exposure   = 100;
    params->b_exposure   = 100;
    params->film_type    = DIMAGE_FILM_COLOR_NEG;
}

/*
 * Builds the exact SET WINDOW (0x24) payload as constructed in
 * MFSBaseLib2889.dll @ 0x10008160 - 0x10008744:
 *   Bytes 0..7:   8-byte SCSI Window Parameter Header (bytes 6..7 = BE16 descriptor len)
 *   Bytes 8..N-1: Window Descriptor (0x3B [59], 0x46 [70], or 0x47 [71] bytes)
 */
size_t dimage_build_window_descriptor(
    const dimage_scan_params_t *params,
    uint8_t out_buf[80],
    uint32_t *out_width_px,
    uint32_t *out_height_px,
    uint32_t *out_bytes_per_line
) {
    memset(out_buf, 0, 80);

    uint16_t dpi = params->dpi ? params->dpi : DIMAGE_OPTICAL_DPI;
    uint32_t scale = DIMAGE_OPTICAL_DPI / dpi;
    if (scale == 0) scale = 1;

    uint16_t width_px  = params->width_px  ? params->width_px  : (uint16_t)(DIMAGE_MAX_WIDTH_PIXELS / scale);
    uint16_t height_px = params->height_px ? params->height_px : (uint16_t)(DIMAGE_MAX_HEIGHT_PIXELS / scale);

    /* Ensure width is even as in MFSBaseLib2889.dll @ 0x10002cb4 */
    if (width_px & 1) width_px++;

    /* Coordinates in optical base units (2820 DPI * 4 = 11280 units/inch, see 0x1000840a shl 2) */
    uint32_t ul_x   = (uint32_t)params->x_offset_px * scale * 4U;
    uint32_t ul_y   = (uint32_t)params->y_offset_px * scale * 4U;
    uint32_t win_w  = (uint32_t)width_px  * scale * 4U;
    uint32_t win_h  = (uint32_t)height_px * scale * 4U;

    uint8_t bpp = (params->bit_depth >= 12) ? 16 : 8;
    uint8_t scsi_bpc = (bpp == 16) ? 12 : 8; /* 0x0C for 12/16-bit, 0x08 for 8-bit (@ 0x10008522) */
    uint8_t channels = (params->channels == 1) ? 1 : 3;
    uint32_t bytes_per_sample = (bpp == 16) ? 2U : 1U;
    uint32_t bytes_per_line_ch = (uint32_t)width_px * bytes_per_sample;
    uint32_t total_bytes_per_line = bytes_per_line_ch * channels;

    bool has_multisample = (params->multisample > 1);
    uint16_t desc_len = has_multisample ? 0x0047 : 0x0046; /* 0x10008306 - 0x10008323 */

    /* 8-byte Window Parameter Header (out_buf[0..7]) */
    cpu_to_be16(desc_len, &out_buf[6]);

    /* Window Descriptor starts at out_buf[8] (corresponds to esp+0x18 in 0x10008160) */
    uint8_t *d = &out_buf[8];
    cpu_to_be16(dpi, &d[0x02]);              /* +0x02: X Resolution (DPI) */
    cpu_to_be16(dpi, &d[0x04]);              /* +0x04: Y Resolution (DPI) */
    cpu_to_be32(ul_x, &d[0x06]);             /* +0x06: Upper-Left X */
    cpu_to_be32(ul_y, &d[0x0A]);             /* +0x0A: Upper-Left Y */
    cpu_to_be32(win_w, &d[0x0E]);            /* +0x0E: Window Width */
    cpu_to_be32(win_h, &d[0x12]);            /* +0x12: Window Length */
    d[0x16] = 0x80;                          /* +0x16: Brightness (neutral = 128) */
    d[0x17] = 0x80;                          /* +0x17: Threshold (neutral = 128) */
    d[0x18] = 0x80;                          /* +0x18: Contrast (neutral = 128) */
    d[0x19] = (channels == 3) ? 0x05 : 0x02; /* +0x19: Image Composition (5=RGB, 2=Gray) */
    d[0x1A] = scsi_bpc;                      /* +0x1A: Bits Per Channel (8 or 12) */
    d[0x1D] = 0x03;                          /* +0x1D: Riff / Padding type (0x03) */
    cpu_to_be16(0x0000, &d[0x1F]);           /* +0x1F: Halftone / bit order */
    d[0x28] = 0xFF;                          /* +0x28: Vendor header 0xFF */
    d[0x29] = 0x14;                          /* +0x29: Vendor block length (0x14) */
    d[0x2A] = (channels == 3) ? 0x60 : 0x48; /* +0x2A: Sensor channel mode */
    d[0x2B] = 0xFF;                          /* +0x2B: 0xFF */
    d[0x2C] = 0x00;                          /* +0x2C: 0x00 */

    /* +0x2D (esp+0x45): Scan flags (0x80 = 16-bit/high-bit, 0x08 = normal scan) */
    d[0x2D] = (bpp == 16) ? 0x88 : 0x08;

    /* +0x2E..0x34 (esp+0x46..0x4C): Master + R/G/B Exposure (default 100 = 0x0064) */
    uint16_t r_exp = params->r_exposure ? params->r_exposure : 100;
    uint16_t g_exp = params->g_exposure ? params->g_exposure : 100;
    uint16_t b_exp = params->b_exposure ? params->b_exposure : 100;
    d[0x2E] = 0x64;
    cpu_to_be16(r_exp, &d[0x2F]);
    cpu_to_be16(b_exp, &d[0x31]);
    cpu_to_be16(g_exp, &d[0x33]);

    /* +0x35 (esp+0x4D): Option flags (0x10 base | 0x02 if multisample) */
    d[0x35] = 0x10 | (has_multisample ? 0x02 : 0x00);
    if (has_multisample) {
        d[0x39] = params->multisample; /* esp+0x51 */
    }

    /* +0x3D (esp+0x55) & +0x43 (esp+0x5B): Bytes per channel line & total lines */
    cpu_to_be16((uint16_t)bytes_per_line_ch, &d[0x3D]);
    cpu_to_be16(height_px, &d[0x43]);

    if (out_width_px)       *out_width_px       = width_px;
    if (out_height_px)      *out_height_px      = height_px;
    if (out_bytes_per_line) *out_bytes_per_line = total_bytes_per_line;

    return (size_t)(8 + desc_len);
}

int dimage_set_window(dimage_scanner_t *dev, const uint8_t *win_buf, size_t win_len) {
    uint8_t cdb[10];
    memset(cdb, 0, sizeof(cdb));
    cdb[0] = SCSI_OP_SET_WINDOW;
    cpu_to_be24((uint32_t)win_len, &cdb[6]);
    return dimage_exec_scsi(dev, cdb, 10, DIMAGE_DIR_OUT, (uint8_t *)win_buf, win_len);
}

/*
 * Computes the stepper motor acceleration ramp table in MFSBaseLib2889.dll @ 0x100074e0 - 0x10007752
 */
static void dimage_build_motor_ramp_table(
    uint16_t total_steps,
    uint16_t const_steps,
    uint32_t target_num,
    uint32_t target_den,
    uint16_t start_period,
    uint16_t end_period,
    uint8_t *out_table
) {
    memset(out_table, 0, total_steps);
    if (total_steps == 0) return;

    uint16_t ramp_target = (total_steps >= const_steps) ? (uint16_t)(total_steps - const_steps + 1) : 1;
    float low = 0.001f;  /* 0x3a83126f @ 0x1000769d */
    float high = 1.0f;   /* 0x3f800000 @ 0x10007679 */

    for (int iter = 0; iter < 30; ++iter) {
        float mid = (low + high) * 0.5f;
        double cur = (double)start_period;
        uint16_t idx = 1;
        out_table[0] = (uint8_t)start_period;

        while (idx < 999 && idx < total_steps) {
            cur = cur - (cur - (double)end_period) * (double)mid;
            uint8_t val = (uint8_t)(cur + 0.5);
            out_table[idx++] = val;
            if (val == (uint8_t)end_period) break;
        }
        if (idx == ramp_target) break;
        if (idx > ramp_target) {
            low = mid;
        } else {
            high = mid;
        }
        if (fabs((double)(high - low)) <= 1e-6) break;
    }

    /* Fill remaining steps with end_period (@ 0x100076fa) */
    for (uint16_t i = (ramp_target > 0 ? ramp_target - 1 : 0); i < total_steps; ++i) {
        out_table[i] = (uint8_t)end_period;
    }

    /* Adjust sum to be a multiple of target_den / target_num if needed (@ 0x10007590) */
    if (target_num > 0 && target_den > 0) {
        uint32_t sum = 0;
        for (uint16_t i = 0; i < total_steps; ++i) sum += out_table[i];
        uint32_t rem = (sum * target_num) % target_den;
        if (rem != 0) {
            uint32_t add = (target_den - rem) / target_num;
            if (add > 0xFF) add = 0xFF;
            for (uint16_t i = 0; i + 1 < total_steps && add > 0; ++i) {
                uint32_t headroom = 0xFFU - out_table[i];
                if (headroom > add) {
                    out_table[i] = (uint8_t)(out_table[i] + add);
                    add = 0;
                } else {
                    out_table[i] = 0xFF;
                    add -= headroom;
                }
            }
        }
    }

    /* Decrement every entry by 1 (@ 0x1000773e) */
    for (uint16_t i = 0; i < total_steps; ++i) {
        out_table[i] = (uint8_t)(out_table[i] - 1);
    }
}

int dimage_start_scan(dimage_scanner_t *dev, uint8_t scan_mode_byte) {
    /* 1. RESERVE UNIT (0x16) (MFSBaseLib2889.dll @ 0x10007363) */
    if (dimage_reserve_unit(dev) != 0) return -1;

    /* 2. START/STOP SCAN (0x1B 00 00 00 01 <mode>) (@ 0x10007398) */
    uint8_t start_cdb[6] = { SCSI_OP_START_STOP_SCAN, 0x00, 0x00, 0x00, 0x01, scan_mode_byte };
    if (dimage_exec_scsi(dev, start_cdb, 6, DIMAGE_DIR_NONE, NULL, 0) != 0) {
        return -1;
    }

    /* 3. Query motor ramp status: READ(10) data_type=0x6C, qual=0, len=24 (@ 0x100073b0) */
    uint8_t ramp_hdr[24];
    memset(ramp_hdr, 0, sizeof(ramp_hdr));
    if (dimage_read10(dev, DIMAGE_DT_MOTOR_RAMP, 0x0000, ramp_hdr, 24) != 0) {
        return -1;
    }

    uint8_t num_tables = ramp_hdr[17];
    uint8_t table_idx = 0;
    while (num_tables > 0 && table_idx < num_tables) {
        uint16_t total_steps  = be16_to_cpu(&ramp_hdr[0]);
        uint16_t const_steps  = be16_to_cpu(&ramp_hdr[2]);
        uint32_t target_num   = be32_to_cpu(&ramp_hdr[4]);
        uint32_t target_den   = be32_to_cpu(&ramp_hdr[8]);
        uint16_t start_period = be16_to_cpu(&ramp_hdr[12]);
        uint16_t end_period   = be16_to_cpu(&ramp_hdr[14]);
        uint8_t  already_set  = ramp_hdr[16];

        if (total_steps == 0 || total_steps > 1000 || total_steps <= const_steps) {
            return -1;
        }

        if (already_set == 0) {
            uint8_t ramp_table[1000];
            dimage_build_motor_ramp_table(
                total_steps, const_steps, target_num, target_den,
                start_period, end_period, ramp_table
            );
            /* WRITE(10) data_type=0x6C, qual=table_idx, len=total_steps (@ 0x10007474) */
            if (dimage_write10(dev, DIMAGE_DT_MOTOR_RAMP, table_idx, ramp_table, total_steps) != 0) {
                return -1;
            }
        }

        table_idx++;
        if (table_idx >= num_tables) break;

        if (dimage_read10(dev, DIMAGE_DT_MOTOR_RAMP, 0x0000, ramp_hdr, 24) != 0) {
            return -1;
        }
        num_tables = ramp_hdr[17];
    }

    return 0;
}

/* ============================================================================
 * High-Level Scan Pipeline (MFSBaseLib2889.dll @ 0x10002780 - 0x100029b0, 0x1000a660)
 * ============================================================================ */

/*
 * Restores and inverts 1970s/1980s Color Negative and Black & White Negative film.
 * Uses a 4096-bin per-channel histogram sampled over the inner 90% of the frame
 * (ignoring the outer 5% plastic film holder border / sprocket edge) to find the
 * true 0.5th percentile (shadow/Dmax) and 99.5th percentile (orange mask / film base Dmin).
 * This removes the orange mask, eliminates faded-film base fog, and prevents single
 * dust specks or clear frame edges from skewing the exposure.
 */
static void dimage_invert_negative_buffer(
    uint8_t *pixels,
    uint32_t width,
    uint32_t height,
    uint8_t channels,
    uint8_t bit_depth,
    dimage_film_type_t film_type
) {
    if (film_type == DIMAGE_FILM_POSITIVE) return;
    size_t num_px = (size_t)width * height;
    if (num_px == 0) return;

    uint32_t x0 = width  / 20;
    uint32_t x1 = width  - x0;
    uint32_t y0 = height / 20;
    uint32_t y1 = height - y0;
    if (x1 <= x0) { x0 = 0; x1 = width; }
    if (y1 <= y0) { y0 = 0; y1 = height; }

    uint32_t *hist = (uint32_t *)calloc(3 * 4096, sizeof(uint32_t));
    if (!hist) return;

    size_t sample_count = 0;
    uint16_t *p16 = (uint16_t *)pixels;

    for (uint32_t y = y0; y < y1; ++y) {
        for (uint32_t x = x0; x < x1; ++x) {
            size_t idx = ((size_t)y * width + x) * channels;
            for (uint8_t c = 0; c < channels && c < 3; ++c) {
                uint32_t bin = 0;
                if (bit_depth == 16) {
                    bin = p16[idx + c] >> 4; /* 0..4095 */
                } else {
                    bin = (uint32_t)pixels[idx + c] << 4;
                }
                if (bin > 4095) bin = 4095;
                hist[c * 4096 + bin]++;
            }
            sample_count++;
        }
    }

    double low_val[3]  = { 0.0, 0.0, 0.0 };
    double high_val[3] = { (bit_depth == 16) ? 65535.0 : 255.0,
                           (bit_depth == 16) ? 65535.0 : 255.0,
                           (bit_depth == 16) ? 65535.0 : 255.0 };

    size_t low_target  = sample_count / 200; /* 0.5th percentile */
    size_t high_target = sample_count - (sample_count / 200); /* 99.5th percentile */
    if (high_target <= low_target) high_target = sample_count;

    for (uint8_t c = 0; c < channels && c < 3; ++c) {
        size_t accum = 0;
        uint32_t low_bin = 0, high_bin = 4095;
        for (uint32_t b = 0; b < 4096; ++b) {
            accum += hist[c * 4096 + b];
            if (accum >= low_target) {
                low_bin = b;
                break;
            }
        }
        accum = 0;
        for (uint32_t b = 0; b < 4096; ++b) {
            accum += hist[c * 4096 + b];
            if (accum >= high_target) {
                high_bin = b;
                break;
            }
        }
        if (high_bin <= low_bin) {
            low_bin  = 0;
            high_bin = 4095;
        }
        double scale = (bit_depth == 16) ? 16.0 : (1.0 / 16.0);
        low_val[c]  = (double)low_bin  * scale;
        high_val[c] = (double)high_bin * scale;
        if (high_val[c] - low_val[c] < 1.0) {
            low_val[c]  = 0.0;
            high_val[c] = (bit_depth == 16) ? 65535.0 : 255.0;
        }
    }
    free(hist);

    double inv_gamma = (film_type == DIMAGE_FILM_BW_NEG) ? (1.0 / 1.75) : (1.0 / 1.85);

    if (bit_depth == 16) {
        for (size_t i = 0; i < num_px; ++i) {
            for (uint8_t c = 0; c < channels && c < 3; ++c) {
                double v = (double)p16[i * channels + c];
                double norm = (v - low_val[c]) / (high_val[c] - low_val[c]);
                if (norm < 0.0) norm = 0.0;
                if (norm > 1.0) norm = 1.0;
                double pos = 1.0 - norm;
                pos = pow(pos, inv_gamma);
                p16[i * channels + c] = (uint16_t)(pos * 65535.0 + 0.5);
            }
        }
    } else {
        for (size_t i = 0; i < num_px; ++i) {
            for (uint8_t c = 0; c < channels && c < 3; ++c) {
                double v = (double)pixels[i * channels + c];
                double norm = (v - low_val[c]) / (high_val[c] - low_val[c]);
                if (norm < 0.0) norm = 0.0;
                if (norm > 1.0) norm = 1.0;
                double pos = 1.0 - norm;
                pos = pow(pos, inv_gamma);
                pixels[i * channels + c] = (uint8_t)(pos * 255.0 + 0.5);
            }
        }
    }
}

int dimage_scan_to_buffer(
    dimage_scanner_t *dev,
    const dimage_scan_params_t *params,
    uint8_t **pixels_out,
    uint32_t *width_out,
    uint32_t *height_out,
    uint32_t *bytes_per_pixel_out
) {
    if (!dev || !params || !pixels_out) return -1;
    *pixels_out = NULL;

    /* 1. Move to requested film frame if frame_index >= 1 */
    if (params->frame_index >= 1) {
        if (dimage_move_to_frame(dev, params->frame_index) != 0) {
            return -1;
        }
    }

    /* 2. Set focus position if requested */
    if (params->manual_focus != 0) {
        if (dimage_set_focus_position(dev, params->manual_focus) != 0) {
            return -1;
        }
    }

    /* 3. Build and send SET WINDOW (0x24) */
    uint8_t win_buf[80];
    uint32_t width_px = 0, height_px = 0, bytes_per_line = 0;
    size_t win_len = dimage_build_window_descriptor(params, win_buf, &width_px, &height_px, &bytes_per_line);
    if (dimage_set_window(dev, win_buf, win_len) != 0) {
        return -1;
    }

    /* 4. Upload linear gamma LUTs (0x81) for 8-bit mode (0x10002a3c) */
    uint8_t bpp = (params->bit_depth >= 12) ? 16 : 8;
    if (bpp == 8) {
        if (dimage_send_linear_gamma_lut(dev) != 0) {
            return -1;
        }
    }

    /* 5. Start scan (0x1B + 0x6C ramp table handshake) */
    /* Mode byte 0x80 = normal scan (0x1000738d when 0x1002cd7c == 1) */
    if (dimage_start_scan(dev, 0x80) != 0) {
        dimage_release_unit(dev);
        return -1;
    }

    /* 6. Wait for scanner ready before reading image lines (0x10007790) */
    if (dimage_wait_ready(dev, 6000) != 0) {
        dimage_release_unit(dev);
        return -1;
    }

    /* 7. Allocate image buffer and read scan chunks via READ(10) data_type=0x00 (0x1000a687) */
    uint8_t channels = (params->channels == 1) ? 1 : 3;
    uint32_t bytes_per_pixel = channels * ((bpp == 16) ? 2U : 1U);
    size_t total_image_bytes = (size_t)width_px * height_px * bytes_per_pixel;

    uint8_t *image_buf = (uint8_t *)calloc(1, total_image_bytes);
    uint8_t *line_buf  = (uint8_t *)malloc(bytes_per_line);
    if (!image_buf || !line_buf) {
        free(image_buf);
        free(line_buf);
        dimage_release_unit(dev);
        return -1;
    }

    for (uint32_t y = 0; y < height_px; ++y) {
        if (dimage_read10(dev, DIMAGE_DT_IMAGE_DATA, 0x0000, line_buf, bytes_per_line) != 0) {
            free(image_buf);
            free(line_buf);
            dimage_release_unit(dev);
            return -1;
        }

        uint8_t *dst_row = &image_buf[(size_t)y * bytes_per_line];
        if (bpp == 16) {
            /* Scanner returns planar or interleaved 12-bit values in 16-bit words;
             * scale 12-bit (0..4095) to full 16-bit (0..65535) as in 0x10009e7f (shl 4) */
            uint32_t samples_per_line = width_px * channels;
            uint16_t *dst16 = (uint16_t *)dst_row;
            for (uint32_t s = 0; s < samples_per_line; ++s) {
                uint16_t raw16 = (uint16_t)(line_buf[s * 2] | (line_buf[s * 2 + 1] << 8));
                if (raw16 <= 0x0FFF) {
                    raw16 = (uint16_t)((raw16 << 4) | (raw16 >> 8));
                }
                dst16[s] = raw16;
            }
        } else {
            memcpy(dst_row, line_buf, bytes_per_line);
        }
    }

    free(line_buf);

    /* 8. Release scanner unit (0x17) (MFSBaseLib2889.dll @ 0x100049f6) */
    dimage_release_unit(dev);

    /* 9. Apply negative inversion & orange-mask balance if scanning negative film */
    dimage_invert_negative_buffer(image_buf, width_px, height_px, channels, bpp, params->film_type);

    *pixels_out = image_buf;
    if (width_out)           *width_out           = width_px;
    if (height_out)          *height_out          = height_px;
    if (bytes_per_pixel_out) *bytes_per_pixel_out = bytes_per_pixel;
    return 0;
}

/* ============================================================================
 * Uncompressed TIFF (24-bit / 48-bit) & BMP (24-bit) Writers
 * ============================================================================ */

static void write_ifd_entry(uint8_t *p, uint16_t tag, uint16_t type, uint32_t count, uint32_t val_or_off) {
    cpu_to_le16(tag, &p[0]);
    cpu_to_le16(type, &p[2]);
    cpu_to_le32(count, &p[4]);
    if (type == 3 && count == 1) {
        cpu_to_le16((uint16_t)val_or_off, &p[8]);
        cpu_to_le16(0, &p[10]);
    } else {
        cpu_to_le32(val_or_off, &p[8]);
    }
}

int dimage_write_tiff(
    const char *filename,
    const uint8_t *pixels,
    uint32_t width,
    uint32_t height,
    uint8_t channels,
    uint8_t bits_per_sample,
    uint16_t dpi
) {
    if (!filename || !pixels || width == 0 || height == 0) return -1;
    FILE *fp = fopen(filename, "wb");
    if (!fp) return -1;

    uint32_t bytes_per_sample = (bits_per_sample == 16) ? 2U : 1U;
    uint32_t image_bytes = width * height * channels * bytes_per_sample;

    /* Layout:
     * 0..7:     TIFF Header (8 bytes)
     * 8..157:   IFD (2 + 12*12 + 4 = 150 bytes)
     * 158..163: BitsPerSample[3] (6 bytes)
     * 164..171: XResolution RATIONAL (8 bytes)
     * 172..179: YResolution RATIONAL (8 bytes)
     * 180..end: Pixel data
     */
    uint8_t hdr[180];
    memset(hdr, 0, sizeof(hdr));
    /* Little-endian TIFF magic ("II", 42, IFD offset = 8) */
    hdr[0] = 'I'; hdr[1] = 'I';
    cpu_to_le16(42, &hdr[2]);
    cpu_to_le32(8, &hdr[4]);

    uint16_t num_tags = 12;
    cpu_to_le16(num_tags, &hdr[8]);
    uint8_t *ifd = &hdr[10];

    uint32_t bps_offset  = 158;
    uint32_t xres_offset = 164;
    uint32_t yres_offset = 172;
    uint32_t data_offset = 180;

    write_ifd_entry(&ifd[0  * 12], 256, 4, 1, width);                               /* ImageWidth */
    write_ifd_entry(&ifd[1  * 12], 257, 4, 1, height);                              /* ImageLength */
    write_ifd_entry(&ifd[2  * 12], 258, 3, channels,
                    channels == 1 ? bits_per_sample : bps_offset);                 /* BitsPerSample */
    write_ifd_entry(&ifd[3  * 12], 259, 3, 1, 1);                                   /* Compression = None */
    write_ifd_entry(&ifd[4  * 12], 262, 3, 1, (channels == 3) ? 2 : 1);             /* Photometric = RGB(2)/BlackIsZero(1) */
    write_ifd_entry(&ifd[5  * 12], 273, 4, 1, data_offset);                         /* StripOffsets */
    write_ifd_entry(&ifd[6  * 12], 277, 3, 1, channels);                            /* SamplesPerPixel */
    write_ifd_entry(&ifd[7  * 12], 278, 4, 1, height);                              /* RowsPerStrip */
    write_ifd_entry(&ifd[8  * 12], 279, 4, 1, image_bytes);                         /* StripByteCounts */
    write_ifd_entry(&ifd[9  * 12], 282, 5, 1, xres_offset);                         /* XResolution */
    write_ifd_entry(&ifd[10 * 12], 283, 5, 1, yres_offset);                         /* YResolution */
    write_ifd_entry(&ifd[11 * 12], 296, 3, 1, 2);                                   /* ResolutionUnit = 2 (Inch) */

    /* BitsPerSample array (3 x uint16_t) */
    cpu_to_le16(bits_per_sample, &hdr[bps_offset + 0]);
    cpu_to_le16(bits_per_sample, &hdr[bps_offset + 2]);
    cpu_to_le16(bits_per_sample, &hdr[bps_offset + 4]);

    /* XResolution & YResolution RATIONAL */
    uint32_t dpi_val = dpi ? dpi : DIMAGE_OPTICAL_DPI;
    cpu_to_le32(dpi_val, &hdr[xres_offset + 0]);
    cpu_to_le32(1,       &hdr[xres_offset + 4]);
    cpu_to_le32(dpi_val, &hdr[yres_offset + 0]);
    cpu_to_le32(1,       &hdr[yres_offset + 4]);

    if (fwrite(hdr, 1, sizeof(hdr), fp) != sizeof(hdr) ||
        fwrite(pixels, 1, image_bytes, fp) != image_bytes) {
        fclose(fp);
        return -1;
    }
    fclose(fp);
    return 0;
}

int dimage_write_bmp24(
    const char *filename,
    const uint8_t *pixels,
    uint32_t width,
    uint32_t height,
    uint8_t channels,
    uint8_t bits_per_sample,
    uint16_t dpi
) {
    if (!filename || !pixels || width == 0 || height == 0) return -1;
    FILE *fp = fopen(filename, "wb");
    if (!fp) return -1;

    uint32_t row_stride = (width * 3U + 3U) & ~3U;
    uint32_t image_size = row_stride * height;
    uint32_t file_size  = 54U + image_size;
    int32_t  ppm        = (int32_t)((double)(dpi ? dpi : 2820) * 39.3700787 + 0.5);

    uint8_t hdr[54];
    memset(hdr, 0, sizeof(hdr));
    hdr[0] = 'B'; hdr[1] = 'M';
    cpu_to_le32(file_size, &hdr[2]);
    cpu_to_le32(54, &hdr[10]);
    cpu_to_le32(40, &hdr[14]);
    cpu_to_le32(width, &hdr[18]);
    cpu_to_le32((uint32_t)(-(int32_t)height), &hdr[22]); /* top-down DIB */
    cpu_to_le16(1, &hdr[26]);
    cpu_to_le16(24, &hdr[28]);
    cpu_to_le32(image_size, &hdr[34]);
    cpu_to_le32((uint32_t)ppm, &hdr[38]);
    cpu_to_le32((uint32_t)ppm, &hdr[42]);

    if (fwrite(hdr, 1, sizeof(hdr), fp) != sizeof(hdr)) {
        fclose(fp);
        return -1;
    }

    uint8_t *row_buf = (uint8_t *)calloc(1, row_stride);
    if (!row_buf) {
        fclose(fp);
        return -1;
    }

    for (uint32_t y = 0; y < height; ++y) {
        for (uint32_t x = 0; x < width; ++x) {
            uint8_t r = 0, g = 0, b = 0;
            size_t idx = ((size_t)y * width + x) * channels;
            if (bits_per_sample == 16) {
                const uint16_t *p16 = (const uint16_t *)pixels;
                r = (uint8_t)(p16[idx + 0] >> 8);
                g = (channels == 3) ? (uint8_t)(p16[idx + 1] >> 8) : r;
                b = (channels == 3) ? (uint8_t)(p16[idx + 2] >> 8) : r;
            } else {
                r = pixels[idx + 0];
                g = (channels == 3) ? pixels[idx + 1] : r;
                b = (channels == 3) ? pixels[idx + 2] : r;
            }
            row_buf[x * 3 + 0] = b;
            row_buf[x * 3 + 1] = g;
            row_buf[x * 3 + 2] = r;
        }
        if (fwrite(row_buf, 1, row_stride, fp) != row_stride) {
            free(row_buf);
            fclose(fp);
            return -1;
        }
    }

    free(row_buf);
    fclose(fp);
    return 0;
}

/* ============================================================================
 * Standalone CLI Entrypoint (compile with -DDIMAGE_NO_MAIN when embedding)
 * ============================================================================ */
#ifndef DIMAGE_NO_MAIN

static void print_usage(const char *prog) {
    printf("Minolta DiMAGE Scan Dual III (USB\\VID_0686&PID_400D) Modern Windows 11 Utility\n");
    printf("Usage:\n");
    printf("  %s info       [--device \\\\.\\UsbScan0] [--firmware DS_Dual3.BIN]\n", prog);
    printf("  %s eject      [--device \\\\.\\UsbScan0]\n", prog);
    printf("  %s retract    [--device \\\\.\\UsbScan0]\n", prog);
    printf("  %s reset      (Recovers blinking light if film holder was left in at power-on)\n", prog);
    printf("  %s frame N    [--device \\\\.\\UsbScan0]\n", prog);
    printf("  %s scan       [--frame 1..6] [--dpi 2820|1410|705|352] [--bits 8|16]\n", prog);
    printf("                [--film neg|pos|bw] [--multisample 1|2|4|8|16] [--out scan.tif]\n");
    printf("  %s scan-strip [--dpi 2820|1410|705] [--bits 8|16] [--film neg|pos|bw] [--out strip]\n", prog);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    const char *cmd = argv[1];
    const char *dev_path = NULL;
    const char *fw_path  = "DS_Dual3.BIN";
    const char *out_path = "scan.tif";
    bool verbose = false;

    dimage_scan_params_t params;
    dimage_default_scan_params(&params);

    for (int i = 2; i < argc; ++i) {
        if (strcmp(argv[i], "--device") == 0 && i + 1 < argc) {
            dev_path = argv[++i];
        } else if (strcmp(argv[i], "--firmware") == 0 && i + 1 < argc) {
            fw_path = argv[++i];
        } else if (strcmp(argv[i], "--out") == 0 && i + 1 < argc) {
            out_path = argv[++i];
        } else if (strcmp(argv[i], "--dpi") == 0 && i + 1 < argc) {
            params.dpi = (uint16_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--bits") == 0 && i + 1 < argc) {
            params.bit_depth = (uint8_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--frame") == 0 && i + 1 < argc) {
            params.frame_index = (uint8_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--multisample") == 0 && i + 1 < argc) {
            params.multisample = (uint8_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--film") == 0 && i + 1 < argc) {
            const char *f = argv[++i];
            if (strcmp(f, "pos") == 0 || strcmp(f, "slide") == 0) params.film_type = DIMAGE_FILM_POSITIVE;
            else if (strcmp(f, "bw") == 0) params.film_type = DIMAGE_FILM_BW_NEG;
            else params.film_type = DIMAGE_FILM_COLOR_NEG;
        } else if (strcmp(argv[i], "--verbose") == 0 || strcmp(argv[i], "-v") == 0) {
            verbose = true;
        } else if (strcmp(cmd, "frame") == 0 && argv[i][0] != '-') {
            params.frame_index = (uint8_t)atoi(argv[i]);
        }
    }

    dimage_scanner_t dev;
    if (dimage_open(&dev, dev_path, verbose) != 0) {
        fprintf(stderr, "Error: Could not open Minolta DiMAGE Scan Dual III.\n");
        return 1;
    }

    /* Ensure RAM firmware is uploaded */
    bool fw_loaded = false;
    if (dimage_is_firmware_loaded(&dev, &fw_loaded) == 0 && !fw_loaded) {
        printf("Uploading scanner firmware from %s...\n", fw_path);
        if (dimage_upload_firmware_file(&dev, fw_path, false) != 0) {
            fprintf(stderr, "Warning: Firmware upload failed (check path to DS_Dual3.BIN).\n");
        }
    }

    int rc = 0;
    if (strcmp(cmd, "info") == 0) {
        char model[25] = {0}, fw[5] = {0};
        if (dimage_inquiry(&dev, model, fw, NULL) == 0) {
            printf("Scanner Model : %s\n", model);
            printf("Firmware Rev  : %s\n", fw);
            printf("Device Path   : %s\n", dev.device_path);
            printf("RAM Firmware  : %s\n", fw_loaded ? "Loaded (Active)" : "Boot ROM");
        }
        dimage_status_t st;
        if (dimage_get_status(&dev, &st) == 0) {
            const char *holder_str = "Unknown";
            if (st.holder_type == DIMAGE_HOLDER_STRIP_35MM) holder_str = "FH-M10 35mm Strip Holder (6 frames)";
            else if (st.holder_type == DIMAGE_HOLDER_SLIDE_MOUNT) holder_str = "SH-M10 Slide Mount Holder (4 slides)";
            else if (st.holder_type == DIMAGE_HOLDER_NONE) holder_str = "No film holder inserted";
            printf("Film Holder   : %s (0x%02X)\n", holder_str, st.holder_type);
            printf("Default Exp   : R=%u G=%u B=%u\n", st.r_exp_default, st.g_exp_default, st.b_exp_default);
        }
    } else if (strcmp(cmd, "eject") == 0) {
        printf("Ejecting film holder...\n");
        rc = dimage_eject_holder(&dev);
    } else if (strcmp(cmd, "retract") == 0) {
        printf("Retracting film holder...\n");
        rc = dimage_retract_holder(&dev);
    } else if (strcmp(cmd, "reset") == 0) {
        printf("Recovering scanner & ejecting film holder...\n");
        rc = dimage_recover_jammed_holder(&dev);
        printf("Please remove the film holder, wait 2 seconds, and re-insert it.\n");
    } else if (strcmp(cmd, "frame") == 0) {
        printf("Moving film holder to frame %u...\n", params.frame_index);
        rc = dimage_move_to_frame(&dev, params.frame_index);
    } else if (strcmp(cmd, "scan-strip") == 0) {
        dimage_status_t st;
        uint8_t total_frames = 6;
        if (dimage_get_status(&dev, &st) == 0 && st.holder_type == DIMAGE_HOLDER_SLIDE_MOUNT) {
            total_frames = 4;
        }
        printf("Batch scanning %u frames at %u DPI (%u-bit)...\n", total_frames, params.dpi, params.bit_depth);
        for (uint8_t f = 1; f <= total_frames; ++f) {
            params.frame_index = f;
            char frame_file[512];
            snprintf(frame_file, sizeof(frame_file), "%s_frame%u.tif", out_path, f);
            printf("  [%u/%u] Scanning frame %u -> %s...\n", f, total_frames, f, frame_file);
            uint8_t *pixels = NULL;
            uint32_t w = 0, h = 0, bpp = 0;
            rc = dimage_scan_to_buffer(&dev, &params, &pixels, &w, &h, &bpp);
            if (rc == 0 && pixels) {
                rc = dimage_write_tiff(frame_file, pixels, w, h, params.channels, params.bit_depth, params.dpi);
                free(pixels);
            }
            if (rc != 0) break;
        }
    } else if (strcmp(cmd, "scan") == 0) {
        printf("Scanning Frame %u at %u DPI (%u-bit)...\n",
               params.frame_index, params.dpi, params.bit_depth);
        uint8_t *pixels = NULL;
        uint32_t w = 0, h = 0, bpp = 0;
        rc = dimage_scan_to_buffer(&dev, &params, &pixels, &w, &h, &bpp);
        if (rc == 0 && pixels) {
            size_t len = strlen(out_path);
            if (len > 4 && (strcmp(&out_path[len - 4], ".bmp") == 0 || strcmp(&out_path[len - 4], ".BMP") == 0)) {
                rc = dimage_write_bmp24(out_path, pixels, w, h, params.channels, params.bit_depth, params.dpi);
            } else {
                rc = dimage_write_tiff(out_path, pixels, w, h, params.channels, params.bit_depth, params.dpi);
            }
            if (rc == 0) {
                printf("Saved %ux%u image to %s\n", w, h, out_path);
            }
            free(pixels);
        }
    } else {
        print_usage(argv[0]);
        rc = 1;
    }

    dimage_close(&dev);
    return (rc == 0) ? 0 : 1;
}
#endif /* DIMAGE_NO_MAIN */
