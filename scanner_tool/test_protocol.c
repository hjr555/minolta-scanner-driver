/*
 * test_protocol.c - Unit & Mock-Hardware Verification Suite for Minolta DiMAGE Scan Dual III
 *
 * Tests the reverse-engineered USB/SCSI protocol in dimage_scan.c against a stateful
 * mock scanner implementing the exact CDB/data-phase expectations of the Minolta
 * FS-V3 (#2889) hardware and the real extracted DS_Dual3.BIN firmware image.
 */

#include "dimage_scan.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

typedef struct {
    bool     firmware_loaded;
    uint32_t last_firmware_checksum;
    size_t   firmware_bytes_received;
    uint8_t  holder_type;
    uint8_t  current_frame;
    int16_t  current_focus;
    bool     reserved;
    bool     scanning;
    bool     ejected;
    uint16_t motor_ramp_steps;
    uint8_t  last_window_desc[80];
    size_t   last_window_len;
    uint32_t cdb_count;
} mock_scanner_state_t;

static int mock_exec_cdb(
    void              *user_ctx,
    const uint8_t     *cdb,
    size_t             cdb_len,
    dimage_direction_t direction,
    uint8_t           *data_buf,
    size_t             data_len,
    uint8_t           *out_scsi_status
) {
    mock_scanner_state_t *st = (mock_scanner_state_t *)user_ctx;
    st->cdb_count++;
    *out_scsi_status = 0x00; /* GOOD */

    uint8_t opcode = cdb[0];

    switch (opcode) {
        case SCSI_OP_TEST_UNIT_READY:
            assert(cdb_len == 6);
            assert(direction == DIMAGE_DIR_NONE);
            return 0;

        case SCSI_OP_INQUIRY: {
            assert(cdb_len == 6);
            assert(direction == DIMAGE_DIR_IN);
            memset(data_buf, 0, data_len);
            data_buf[0] = 0x06; /* Scanner device */
            data_buf[2] = 0x02; /* SCSI-2 */
            data_buf[4] = 91;
            memcpy(data_buf + 8,  "MINOLTA FS-V3           ", 24);
            memcpy(data_buf + 32, "1.00", 4);
            return 0;
        }

        case SCSI_OP_RESERVE_UNIT:
            assert(cdb_len == 6);
            st->reserved = true;
            return 0;

        case SCSI_OP_RELEASE_UNIT:
            assert(cdb_len == 6);
            st->reserved = false;
            st->scanning = false;
            return 0;

        case SCSI_OP_START_STOP_SCAN:
            assert(cdb_len == 6);
            st->scanning = true;
            return 0;

        case SCSI_OP_OBJECT_POSITION:
            assert(cdb_len == 10);
            if (cdb[9] == 0x00) {
                st->ejected = true;
            } else if (cdb[9] == 0x02) {
                st->ejected = false;
            }
            return 0;

        case SCSI_OP_SET_WINDOW:
            assert(cdb_len == 10);
            assert(direction == DIMAGE_DIR_OUT);
            if (data_len <= sizeof(st->last_window_desc)) {
                memcpy(st->last_window_desc, data_buf, data_len);
                st->last_window_len = data_len;
            }
            return 0;

        case SCSI_OP_READ_10: {
            assert(cdb_len == 10);
            assert(direction == DIMAGE_DIR_IN);
            uint8_t dtype = cdb[2];
            uint16_t qual = ((uint16_t)cdb[4] << 8) | cdb[5];
            memset(data_buf, 0, data_len);

            if (dtype == DIMAGE_DT_FIRMWARE) {
                assert(qual == 0x0022);
                assert(data_len == 8);
                /* status_buf[4] == 0 means RAM firmware is active, 1 means boot ROM */
                data_buf[4] = st->firmware_loaded ? 0x00 : 0x01;
                return 0;
            } else if (dtype == DIMAGE_DT_SCANNER_STATUS) {
                assert(data_len == 32);
                data_buf[4]  = st->holder_type;
                data_buf[5]  = 0x00;
                /* Default RGB exposures = 100 (0x0064) at raw[9..14] */
                data_buf[9]  = 0x00; data_buf[10] = 0x64;
                data_buf[11] = 0x00; data_buf[12] = 0x64;
                data_buf[13] = 0x00; data_buf[14] = 0x64;
                /* Current RGB exposures = 100 (0x0064) at raw[15..20] */
                data_buf[15] = 0x00; data_buf[16] = 0x64;
                data_buf[17] = 0x00; data_buf[18] = 0x64;
                data_buf[19] = 0x00; data_buf[20] = 0x64;
                /* Focus limit = 512 (0x0200) at raw[25..26] */
                data_buf[25] = 0x02; data_buf[26] = 0x00;
                return 0;
            } else if (dtype == DIMAGE_DT_HOLDER_POSITION) {
                assert(data_len == 8);
                data_buf[0] = st->holder_type;
                data_buf[2] = 6; /* 6 frames max */
                return 0;
            } else if (dtype == DIMAGE_DT_LIGHT_STATUS) {
                assert(data_len == 1);
                data_buf[0] = 0x01; /* Lamp warm & ready */
                return 0;
            } else if (dtype == DIMAGE_DT_MOTOR_RAMP) {
                assert(data_len == 24);
                /* Request a 64-step ramp table, 16 const steps */
                data_buf[0]  = 0x00; data_buf[1]  = 64;
                data_buf[2]  = 0x00; data_buf[3]  = 16;
                /* target_num = 1, target_den = 4 */
                data_buf[4]  = 0x00; data_buf[5]  = 0x00; data_buf[6]  = 0x00; data_buf[7]  = 1;
                data_buf[8]  = 0x00; data_buf[9]  = 0x00; data_buf[10] = 0x00; data_buf[11] = 4;
                /* start_period = 200, end_period = 50 */
                data_buf[12] = 0x00; data_buf[13] = 200;
                data_buf[14] = 0x00; data_buf[15] = 50;
                data_buf[16] = 0; /* already_set = 0 */
                data_buf[17] = 1; /* num_tables = 1 */
                return 0;
            } else if (dtype == DIMAGE_DT_IMAGE_DATA) {
                /* Generate synthetic test pattern */
                for (size_t i = 0; i < data_len; i++) {
                    data_buf[i] = (uint8_t)((i * 17 + 43) & 0x0F);
                }
                return 0;
            }
            return 0;
        }

        case SCSI_OP_WRITE_10: {
            assert(cdb_len == 10);
            assert(direction == DIMAGE_DIR_OUT);
            uint8_t dtype = cdb[2];
            uint16_t qual = ((uint16_t)cdb[4] << 8) | cdb[5];

            if (dtype == DIMAGE_DT_FIRMWARE) {
                assert(qual == 0x0000);
                assert(data_len == DIMAGE_FIRMWARE_UPLOAD_SIZE);
                uint32_t expected_sum = dimage_compute_firmware_checksum(data_buf, DIMAGE_FIRMWARE_RAW_SIZE);
                uint32_t wire_sum = (uint32_t)data_buf[DIMAGE_FIRMWARE_RAW_SIZE + 0] |
                                    ((uint32_t)data_buf[DIMAGE_FIRMWARE_RAW_SIZE + 1] << 8) |
                                    ((uint32_t)data_buf[DIMAGE_FIRMWARE_RAW_SIZE + 2] << 16) |
                                    ((uint32_t)data_buf[DIMAGE_FIRMWARE_RAW_SIZE + 3] << 24);
                assert(expected_sum == wire_sum);
                st->firmware_loaded = true;
                st->last_firmware_checksum = wire_sum;
                st->firmware_bytes_received = data_len;
                return 0;
            } else if (dtype == DIMAGE_DT_HOLDER_POSITION) {
                assert(data_len == 8);
                st->current_frame = data_buf[1];
                return 0;
            } else if (dtype == DIMAGE_DT_FOCUS_POSITION) {
                assert(data_len == 8);
                uint16_t mag = ((uint16_t)(data_buf[0] & 0x7F) << 8) | data_buf[1];
                st->current_focus = (data_buf[0] & 0x80) ? (int16_t)mag : -(int16_t)mag;
                return 0;
            } else if (dtype == DIMAGE_DT_MOTOR_RAMP) {
                st->motor_ramp_steps = (uint16_t)data_len;
                return 0;
            }
            return 0;
        }

        default:
            return -1;
    }
}

int main(void) {
    printf("=== Minolta DiMAGE Scan Dual III (#2889) Protocol Verification Suite ===\n");

    mock_scanner_state_t mock_state;
    memset(&mock_state, 0, sizeof(mock_state));
    mock_state.holder_type = DIMAGE_HOLDER_STRIP_35MM;

    dimage_scanner_t scanner;
    memset(&scanner, 0, sizeof(scanner));
    scanner.custom_transport = mock_exec_cdb;
    scanner.custom_ctx       = &mock_state;
    strcpy(scanner.device_path, "MOCK\\\\UsbScan0");

    /* 1. Test INQUIRY & model verification */
    char vendor_model[25] = {0};
    char fw_rev[5] = {0};
    int rc = dimage_inquiry(&scanner, vendor_model, fw_rev, NULL);
    assert(rc == 0);
    assert(strncmp(vendor_model, "MINOLTA FS-V3", 13) == 0);
    printf("[PASS] SCSI INQUIRY (0x12): model='%s' rev='%s'\n", vendor_model, fw_rev);

    /* 2. Test Firmware Status & Upload with real extracted DS_Dual3.BIN */
    bool fw_loaded = true;
    rc = dimage_is_firmware_loaded(&scanner, &fw_loaded);
    assert(rc == 0 && fw_loaded == false);

    const char *fw_path = "../win11_driver/Minolta_Software/Firmware/DS_Dual3.BIN";
    rc = dimage_upload_firmware_file(&scanner, fw_path, false);
    assert(rc == 0);
    assert(mock_state.firmware_loaded == true);
    assert(mock_state.firmware_bytes_received == 47904);
    printf("[PASS] Firmware Upload (0x2A, Dt=0x90): uploaded 47,904 bytes (47,900B DS_Dual3.BIN + 4B LE32 sum=0x%08X)\n",
           mock_state.last_firmware_checksum);

    /* 3. Test Scanner Status (0x28, Dt=0x60) */
    dimage_status_t status;
    rc = dimage_get_status(&scanner, &status);
    assert(rc == 0);
    assert(status.holder_type == DIMAGE_HOLDER_STRIP_35MM);
    assert(status.r_exp_default == 100);
    assert(status.focus_limit == 512);
    printf("[PASS] Scanner Status (0x28, Dt=0x60): holder=35mm Strip (0x%02X), exp=%u/%u/%u, focus_limit=%u\n",
           status.holder_type, status.r_exp_default, status.g_exp_default, status.b_exp_default, status.focus_limit);

    /* 4. Test Initialization, Frame Positioning (0x87), Focus (0x88), Eject/Retract (0x31) */
    rc = dimage_initialize_scanner(&scanner);
    assert(rc == 0);

    rc = dimage_move_to_frame(&scanner, 4);
    assert(rc == 0 && mock_state.current_frame == 4);

    rc = dimage_set_focus_position(&scanner, 120);
    assert(rc == 0 && mock_state.current_focus == 120);

    rc = dimage_eject_holder(&scanner);
    assert(rc == 0 && mock_state.ejected == true);
    rc = dimage_retract_holder(&scanner);
    assert(rc == 0 && mock_state.ejected == false);
    printf("[PASS] Mechanics & Optics: Init (0x92/0xA0), Frame=4 (0x87), Focus=120 (0x88), Eject/Retract (0x31)\n");

    /* 5. Test Full Scan Sequence (SET WINDOW 0x24, Motor Ramp 0x6C, Scan 0x00, TIFF/BMP export) */
    dimage_scan_params_t params;
    dimage_default_scan_params(&params);
    params.dpi        = 1410;
    params.bit_depth  = 16;
    params.width_px   = 64;
    params.height_px  = 32;
    params.film_type  = DIMAGE_FILM_COLOR_NEG;

    uint8_t *rgb_buf = NULL;
    uint32_t out_w = 0, out_h = 0, out_bpp = 0;
    rc = dimage_scan_to_buffer(&scanner, &params, &rgb_buf, &out_w, &out_h, &out_bpp);
    assert(rc == 0 && rgb_buf != NULL);
    assert(out_w == 64 && out_h == 32 && out_bpp == 6);
    assert(mock_state.last_window_len == 78); /* 8B header + 0x46 (70B) descriptor */
    assert(mock_state.motor_ramp_steps == 64);

    rc = dimage_write_tiff("/tmp/test_scan_48bit.tif", rgb_buf, out_w, out_h, 3, 16, 1410);
    assert(rc == 0);
    free(rgb_buf);

    /* Also test 8-bit BMP24 & TIFF24 */
    params.bit_depth = 8;
    rc = dimage_scan_to_buffer(&scanner, &params, &rgb_buf, &out_w, &out_h, &out_bpp);
    assert(rc == 0 && rgb_buf != NULL);
    assert(out_w == 64 && out_h == 32 && out_bpp == 3);
    rc = dimage_write_bmp24("/tmp/test_scan_24bit.bmp", rgb_buf, out_w, out_h, 3, 8, 1410);
    assert(rc == 0);
    free(rgb_buf);

    remove("/tmp/test_scan_48bit.tif");
    remove("/tmp/test_scan_24bit.bmp");
    dimage_close(&scanner);

    printf("[PASS] Scan Sequence (SET WINDOW 78B, Motor Ramp 64 steps, 48-bit TIFF & 24-bit BMP export)\n");
    printf("=== ALL %u SCSI CDB TRANSACTIONS VERIFIED SUCCESSFULLY ===\n", mock_state.cdb_count);
    return 0;
}
