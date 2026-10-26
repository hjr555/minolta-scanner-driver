/*
 * dimage_scan.h
 * Reverse-Engineered USB/SCSI Protocol Library for Minolta DiMAGE Scan Dual III
 * Hardware ID: USB\VID_0686&PID_400D (Internal Model #2889, SCSI ID "MINOLTA FS-V3           ")
 *
 * Derived from static analysis of DD3100E.EXE:
 *   - MFSIFLib2889.dll   (ev_a5228e8adef7939ed59bb800a41814ce53a87e7d29fd53557ccbe7e822a4a065)
 *   - MFSBaseLib2889.dll (ev_a89b1e8479e77205639f8f9ae0b71debb09ac1523ae7266125873b7c3d26d985)
 */

#ifndef DIMAGE_SCAN_H
#define DIMAGE_SCAN_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* USB Vendor & Product IDs (MFSIFLib2889.dll @ 0x10001e9a) */
#define DIMAGE_USB_VID              0x0686
#define DIMAGE_USB_PID              0x400D

/* Windows usbscan.sys IOCTL codes (MFSIFLib2889.dll @ 0x10001e8e) */
#define DIMAGE_IOCTL_GET_DEVICE_DESCRIPTOR 0x80002018UL

/* Optical sensor specifications (MFSBaseLib2889.dll @ 0x10004cf9, 0x10007be8) */
#define DIMAGE_OPTICAL_DPI          2820
#define DIMAGE_MAX_WIDTH_PIXELS     2688    /* 0x0A80 @ 2820 DPI */
#define DIMAGE_MAX_HEIGHT_PIXELS    4032    /* 35mm frame length @ 2820 DPI */
#define DIMAGE_FIRMWARE_RAW_SIZE    47900   /* DS_Dual3.BIN size (0xBB1C) */
#define DIMAGE_FIRMWARE_UPLOAD_SIZE 47904   /* Raw + 4B LE32 checksum (0xBB20) */

/* SCSI Data Phase Direction (MFSIFLib2889.dll @ 0x10002876) */
typedef enum {
    DIMAGE_DIR_NONE = 4,
    DIMAGE_DIR_IN   = 1,
    DIMAGE_DIR_OUT  = 2
} dimage_direction_t;

/* SCSI Opcodes (MFSBaseLib2889.dll @ 0x1000c880 - 0x1000cad0) */
#define SCSI_OP_TEST_UNIT_READY     0x00
#define SCSI_OP_REQUEST_SENSE       0x03
#define SCSI_OP_INQUIRY             0x12
#define SCSI_OP_RESERVE_UNIT        0x16
#define SCSI_OP_RELEASE_UNIT        0x17
#define SCSI_OP_START_STOP_SCAN     0x1B
#define SCSI_OP_SET_WINDOW          0x24
#define SCSI_OP_READ_10             0x28
#define SCSI_OP_WRITE_10            0x2A
#define SCSI_OP_OBJECT_POSITION     0x31

/* Minolta Vendor-Specific READ(10)/WRITE(10) Data Type Codes */
#define DIMAGE_DT_IMAGE_DATA        0x00
#define DIMAGE_DT_SCANNER_STATUS    0x60
#define DIMAGE_DT_CAL_WHITE_1       0x61
#define DIMAGE_DT_CAL_WHITE_2       0x62
#define DIMAGE_DT_CAL_DARK          0x66
#define DIMAGE_DT_MOTOR_RAMP        0x6C
#define DIMAGE_DT_WARMUP_HEADER     0x70
#define DIMAGE_DT_WARMUP_DATA       0x71
#define DIMAGE_DT_GAMMA_LUT         0x81
#define DIMAGE_DT_SHADING_DATA      0x82
#define DIMAGE_DT_HOLDER_POSITION   0x87
#define DIMAGE_DT_FOCUS_POSITION    0x88
#define DIMAGE_DT_FIRMWARE          0x90
#define DIMAGE_DT_EXPOSURE_CTRL     0x91
#define DIMAGE_DT_INIT_MODE         0x92
#define DIMAGE_DT_LIGHT_STATUS      0xA0

/* Film Holder Types (MFSBaseLib2889.dll @ 0x10001bb6) */
typedef enum {
    DIMAGE_HOLDER_NONE       = 0xFF,
    DIMAGE_HOLDER_STRIP_35MM = 0x01, /* FH-M10 35mm film strip holder (up to 6 frames) */
    DIMAGE_HOLDER_SLIDE_MOUNT= 0x02  /* SH-M10 mounted slide holder (up to 4 slides) */
} dimage_holder_type_t;

/* Film Type */
typedef enum {
    DIMAGE_FILM_POSITIVE     = 0,    /* Slide / reversal positive film */
    DIMAGE_FILM_COLOR_NEG    = 1,    /* Color negative film (inverts & removes orange mask) */
    DIMAGE_FILM_BW_NEG       = 2     /* Black & white negative film */
} dimage_film_type_t;

/* Scanner Status Structure (decoded from READ(10) 0x60, 32 bytes) */
typedef struct {
    uint16_t flags_word0;
    uint8_t  holder_type;        /* dimage_holder_type_t (1=Strip, 2=Slide, 0xFF=None) */
    uint8_t  holder_flags;       /* Bit 2 (0x04)=Dark cal needed, Bit 3 (0x08)=White cal */
    uint16_t r_exp_default;
    uint16_t g_exp_default;
    uint16_t b_exp_default;
    uint16_t r_exp_current;
    uint16_t g_exp_current;
    uint16_t b_exp_current;
    uint16_t focus_limit;
    uint8_t  raw[32];
} dimage_status_t;

/* Scan Configuration Parameters */
typedef struct {
    uint16_t dpi;                /* 352, 705, 1410, or 2820 (default: 2820) */
    uint16_t x_offset_px;        /* X offset in pixels at target DPI */
    uint16_t y_offset_px;        /* Y offset in pixels at target DPI */
    uint16_t width_px;           /* Width in pixels (0 = full frame width) */
    uint16_t height_px;          /* Height in pixels (0 = full frame height) */
    uint8_t  bit_depth;          /* 8 or 16 bits per channel (scanner native 12/16-bit) */
    uint8_t  channels;           /* 3 = RGB, 1 = Grayscale */
    uint8_t  multisample;        /* 1, 2, 4, 8, or 16 passes */
    uint8_t  frame_index;        /* 1..6 for strip holder, 1..4 for slide holder */
    bool     autofocus;          /* Perform focus step before scan */
    int16_t  manual_focus;       /* Manual focus offset (0 = default) */
    uint16_t r_exposure;         /* Red exposure % (100 = 0x64 default) */
    uint16_t g_exposure;         /* Green exposure % (100 = 0x64 default) */
    uint16_t b_exposure;         /* Blue exposure % (100 = 0x64 default) */
    dimage_film_type_t film_type;/* Positive, Color Negative, or B&W Negative */
} dimage_scan_params_t;

/* Custom transport hook for testing or non-Windows USB backends */
typedef int (*dimage_transport_fn)(
    void *user_ctx,
    const uint8_t *cdb,
    size_t cdb_len,
    dimage_direction_t dir,
    uint8_t *data,
    size_t data_len,
    uint8_t *status_out
);

/* Scanner Device Handle */
typedef struct {
    void               *os_handle;       /* Windows HANDLE to \\.\UsbScanN */
    char                device_path[64]; /* e.g. "\\\\.\\UsbScan0" */
    uint8_t             last_sense[22];  /* Last 22-byte REQUEST SENSE buffer */
    uint32_t            last_error_code; /* Decoded Minolta error code */
    dimage_transport_fn custom_transport;/* Optional custom/mock transport */
    void               *custom_ctx;      /* Context for custom_transport */
    bool                verbose;         /* Log SCSI CDBs to stderr */
} dimage_scanner_t;

/* Lifecycle & Discovery */
int  dimage_open(dimage_scanner_t *dev, const char *explicit_path, bool verbose);
void dimage_close(dimage_scanner_t *dev);

/* Low-level 3-Phase USB-SCSI Transport */
int  dimage_exec_scsi(
    dimage_scanner_t *dev,
    const uint8_t *cdb,
    size_t cdb_len,
    dimage_direction_t dir,
    uint8_t *data,
    size_t data_len
);

/* Core SCSI Commands */
int  dimage_test_unit_ready(dimage_scanner_t *dev);
int  dimage_wait_ready(dimage_scanner_t *dev, uint32_t timeout_ms);
int  dimage_request_sense(dimage_scanner_t *dev, uint8_t sense_out[22]);
int  dimage_inquiry(dimage_scanner_t *dev, char vendor_model_out[25], char fw_rev_out[5], uint8_t raw_out[96]);
int  dimage_reserve_unit(dimage_scanner_t *dev);
int  dimage_release_unit(dimage_scanner_t *dev);
int  dimage_read10(dimage_scanner_t *dev, uint8_t data_type, uint16_t qual, uint8_t *buf, uint32_t len);
int  dimage_write10(dimage_scanner_t *dev, uint8_t data_type, uint16_t qual, const uint8_t *buf, uint32_t len);

/* Firmware Management (DS_Dual3.BIN) */
uint32_t dimage_compute_firmware_checksum(const uint8_t *fw_data, size_t fw_len);
int  dimage_is_firmware_loaded(dimage_scanner_t *dev, bool *loaded_out);
int  dimage_upload_firmware_buffer(dimage_scanner_t *dev, const uint8_t *fw_data, size_t fw_len);
int  dimage_upload_firmware_file(dimage_scanner_t *dev, const char *bin_path, bool force);

/* Hardware Control, Holder, Focus & Calibration */
int  dimage_get_status(dimage_scanner_t *dev, dimage_status_t *status_out);
int  dimage_get_light_status(dimage_scanner_t *dev, uint8_t *light_status_out);
int  dimage_initialize_scanner(dimage_scanner_t *dev);
int  dimage_eject_holder(dimage_scanner_t *dev);
int  dimage_retract_holder(dimage_scanner_t *dev);
int  dimage_get_holder_frame(dimage_scanner_t *dev, uint8_t *holder_id_out, uint8_t *frame_out);
int  dimage_move_to_frame(dimage_scanner_t *dev, uint8_t frame_index);
int  dimage_set_focus_position(dimage_scanner_t *dev, int16_t focus_steps);
int  dimage_send_linear_gamma_lut(dimage_scanner_t *dev);

/* Scan Execution */
void dimage_default_scan_params(dimage_scan_params_t *params);
size_t dimage_build_window_descriptor(
    const dimage_scan_params_t *params,
    uint8_t out_buf[80],
    uint32_t *out_width_px,
    uint32_t *out_height_px,
    uint32_t *out_bytes_per_line
);
int  dimage_set_window(dimage_scanner_t *dev, const uint8_t *win_buf, size_t win_len);
int  dimage_start_scan(dimage_scanner_t *dev, uint8_t scan_mode_byte);
int  dimage_scan_to_buffer(
    dimage_scanner_t *dev,
    const dimage_scan_params_t *params,
    uint8_t **pixels_out,
    uint32_t *width_out,
    uint32_t *height_out,
    uint32_t *bytes_per_pixel_out
);

/* Image File Writers (TIFF 24/48-bit & BMP 24-bit) */
int  dimage_write_tiff(
    const char *filename,
    const uint8_t *pixels,
    uint32_t width,
    uint32_t height,
    uint8_t channels,
    uint8_t bits_per_sample,
    uint16_t dpi
);
int  dimage_write_bmp24(
    const char *filename,
    const uint8_t *pixels,
    uint32_t width,
    uint32_t height,
    uint8_t channels,
    uint8_t bits_per_sample,
    uint16_t dpi
);

#ifdef __cplusplus
}
#endif

#endif /* DIMAGE_SCAN_H */
