/*
 * MinoltaWia2Driver.cpp
 * 64-bit Windows Image Acquisition (WIA 2.0) & Still Image (STI) Minidriver
 * for the Minolta DiMAGE Scan Dual III (USB\VID_0686&PID_400D, Model #2889 / FS-V3)
 *
 * Exposes CLSID {E4088F20-D799-11D2-BAFF-00A02491DF4E} (matching DS_Dual3_Win11.inf)
 * so 64-bit Windows 11 applications (Windows Scan, Paint, Photoshop x64, Affinity Photo)
 * can acquire scans directly via the WIA service (stisvc / wiaacmgr).
 *
 * Uses the reverse-engineered USB/SCSI protocol in ../scanner_tool/dimage_scan.c.
 */

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <objbase.h>
#include <sti.h>
#include <stiusd.h>
#include <wia.h>
#include <wiamindr.h>
#include <strsafe.h>
#include <stdlib.h>
#include <stdio.h>
#include "../scanner_tool/dimage_scan.h"

/* {E4088F20-D799-11D2-BAFF-00A02491DF4E} - Minolta USDClass from DS_Dual3.inf */
static const CLSID CLSID_MinoltaDual3WiaDriver = {
    0xe4088f20, 0xd799, 0x11d2, { 0xba, 0xff, 0x00, 0xa0, 0x24, 0x91, 0xdf, 0x4e }
};

static HINSTANCE g_hInst = NULL;
static LONG      g_cLocks = 0;

/* Helper to locate DS_Dual3.BIN via HKLM\SOFTWARE\MINOLTA\DS_Dual3\HomePath */
static void GetFirmwarePath(char *outPath, size_t maxLen) {
    HKEY hKey = NULL;
    const char *subkeys[] = {
        "SOFTWARE\\MINOLTA\\DS_Dual3",
        "SOFTWARE\\WOW6432Node\\MINOLTA\\DS_Dual3"
    };
    for (int i = 0; i < 2; ++i) {
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, subkeys[i], 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            char home[MAX_PATH] = {0};
            DWORD cb = sizeof(home) - 1;
            DWORD type = 0;
            if (RegQueryValueExA(hKey, "HomePath", NULL, &type, (LPBYTE)home, &cb) == ERROR_SUCCESS &&
                (type == REG_SZ || type == REG_EXPAND_SZ)) {
                RegCloseKey(hKey);
                snprintf(outPath, maxLen, "%s\\Firmware\\DS_Dual3.BIN", home);
                return;
            }
            RegCloseKey(hKey);
        }
    }
    snprintf(outPath, maxLen, "C:\\Program Files (x86)\\Minolta\\DS_Dual3\\Firmware\\DS_Dual3.BIN");
}

class MinoltaWia2Driver : public IStiUSD, public IWiaMiniDrv {
private:
    LONG             m_cRef;
    dimage_scanner_t m_scanner;
    bool             m_scannerOpen;
    WCHAR            m_wszDevicePath[MAX_PATH];
    IWiaDrvItem     *m_pRootItem;
    BSTR             m_bstrRootFullItemName;
    dimage_scan_params_t m_params;

public:
    MinoltaWia2Driver()
        : m_cRef(1),
          m_scannerOpen(false),
          m_pRootItem(NULL),
          m_bstrRootFullItemName(NULL)
    {
        InterlockedIncrement(&g_cLocks);
        memset(&m_scanner, 0, sizeof(m_scanner));
        memset(m_wszDevicePath, 0, sizeof(m_wszDevicePath));
        dimage_default_scan_params(&m_params);
        m_params.dpi       = 1410;
        m_params.bit_depth = 8;
        m_params.film_type = DIMAGE_FILM_COLOR_NEG;
    }

    virtual ~MinoltaWia2Driver() {
        if (m_scannerOpen) {
            dimage_close(&m_scanner);
            m_scannerOpen = false;
        }
        if (m_pRootItem) {
            m_pRootItem->Release();
            m_pRootItem = NULL;
        }
        if (m_bstrRootFullItemName) {
            SysFreeString(m_bstrRootFullItemName);
            m_bstrRootFullItemName = NULL;
        }
        InterlockedDecrement(&g_cLocks);
    }

    /* IUnknown */
    STDMETHODIMP QueryInterface(REFIID riid, void **ppv) override {
        if (!ppv) return E_POINTER;
        *ppv = NULL;
        if (riid == IID_IUnknown || riid == IID_IStiUSD) {
            *ppv = static_cast<IStiUSD *>(this);
        } else if (riid == IID_IWiaMiniDrv) {
            *ppv = static_cast<IWiaMiniDrv *>(this);
        } else {
            return E_NOINTERFACE;
        }
        AddRef();
        return S_OK;
    }

    STDMETHODIMP_(ULONG) AddRef() override {
        return (ULONG)InterlockedIncrement(&m_cRef);
    }

    STDMETHODIMP_(ULONG) Release() override {
        LONG c = InterlockedDecrement(&m_cRef);
        if (c == 0) {
            delete this;
        }
        return (ULONG)c;
    }

    /* Ensure the scanner is open and DS_Dual3.BIN RAM firmware is loaded */
    bool EnsureHardwareReady() {
        if (!m_scannerOpen) {
            char ansiPath[MAX_PATH] = {0};
            if (m_wszDevicePath[0] != L'\0') {
                WideCharToMultiByte(CP_ACP, 0, m_wszDevicePath, -1, ansiPath, sizeof(ansiPath), NULL, NULL);
            }
            if (dimage_open(&m_scanner, ansiPath[0] ? ansiPath : NULL, false) != 0) {
                return false;
            }
            m_scannerOpen = true;
        }

        bool fwLoaded = false;
        if (dimage_is_firmware_loaded(&m_scanner, &fwLoaded) == 0 && !fwLoaded) {
            char fwPath[MAX_PATH] = {0};
            GetFirmwarePath(fwPath, sizeof(fwPath));
            dimage_upload_firmware_file(&m_scanner, fwPath, false);
        }
        return true;
    }

    /* ========================================================================
     * IStiUSD Implementation
     * ======================================================================== */
    STDMETHODIMP Initialize(PSTIDEVICECONTROL pHelDcb, DWORD dwStiVersion, HKEY hParametersKey) override {
        (void)dwStiVersion;
        (void)hParametersKey;
        if (!pHelDcb) return E_INVALIDARG;
        pHelDcb->GetMyDevicePortName(m_wszDevicePath, sizeof(m_wszDevicePath) / sizeof(WCHAR));
        EnsureHardwareReady();
        return S_OK;
    }

    STDMETHODIMP GetCapabilities(PSTI_USD_CAPS pDevCaps) override {
        if (!pDevCaps) return E_INVALIDARG;
        memset(pDevCaps, 0, sizeof(*pDevCaps));
        pDevCaps->dwVersion     = STI_VERSION;
        pDevCaps->dwGenericCaps = STI_GENCAP_DO_NOT_POLL;
        return S_OK;
    }

    STDMETHODIMP GetStatus(PSTI_DEVICE_STATUS pDevStatus) override {
        if (!pDevStatus) return E_INVALIDARG;
        pDevStatus->dwOnlineState = 0;
        if (EnsureHardwareReady() && dimage_test_unit_ready(&m_scanner) == 0) {
            pDevStatus->dwOnlineState |= STI_ONLINESTATE_OPERATIONAL;
        }
        return S_OK;
    }

    STDMETHODIMP DeviceReset() override {
        if (EnsureHardwareReady()) {
            dimage_initialize_scanner(&m_scanner);
        }
        return S_OK;
    }

    STDMETHODIMP Diagnostic(LPSTI_DIAG pBuffer) override {
        if (!pBuffer) return E_INVALIDARG;
        pBuffer->dwStatusMask = 0;
        pBuffer->sErrorInfo.dwGenericError = NOERROR;
        return S_OK;
    }

    STDMETHODIMP Escape(STI_RAW_CONTROL_CODE EscapeFunction, LPVOID lpInData, DWORD cbInDataSize,
                        LPVOID pOutData, DWORD dwOutDataSize, LPDWORD pdwActualData) override {
        (void)EscapeFunction; (void)lpInData; (void)cbInDataSize;
        (void)pOutData; (void)dwOutDataSize;
        if (pdwActualData) *pdwActualData = 0;
        return E_NOTIMPL;
    }

    STDMETHODIMP GetLastError(LPDWORD pdwLastDeviceError) override {
        if (!pdwLastDeviceError) return E_INVALIDARG;
        *pdwLastDeviceError = m_scanner.last_error_code;
        return S_OK;
    }

    STDMETHODIMP LockDevice() override { return S_OK; }
    STDMETHODIMP UnLockDevice() override { return S_OK; }

    STDMETHODIMP RawReadData(LPVOID lpBuffer, LPDWORD lpdwNumberOfBytes, LPOVERLAPPED lpOverlapped) override {
        (void)lpBuffer; (void)lpdwNumberOfBytes; (void)lpOverlapped;
        return E_NOTIMPL;
    }

    STDMETHODIMP RawWriteData(LPVOID lpBuffer, DWORD nNumberOfBytes, LPOVERLAPPED lpOverlapped) override {
        (void)lpBuffer; (void)nNumberOfBytes; (void)lpOverlapped;
        return E_NOTIMPL;
    }

    STDMETHODIMP RawReadCommand(LPVOID lpBuffer, LPDWORD lpdwNumberOfBytes, LPOVERLAPPED lpOverlapped) override {
        (void)lpBuffer; (void)lpdwNumberOfBytes; (void)lpOverlapped;
        return E_NOTIMPL;
    }

    STDMETHODIMP RawWriteCommand(LPVOID lpBuffer, DWORD nNumberOfBytes, LPOVERLAPPED lpOverlapped) override {
        (void)lpBuffer; (void)nNumberOfBytes; (void)lpOverlapped;
        return E_NOTIMPL;
    }

    STDMETHODIMP SetNotificationHandle(HANDLE hEvent) override {
        (void)hEvent;
        return S_OK;
    }

    STDMETHODIMP GetNotificationData(LPSTINOTIFY lpNotify) override {
        (void)lpNotify;
        return STIERR_NOEVENTS;
    }

    STDMETHODIMP GetLastErrorInfo(STI_ERROR_INFO *pLastErrorInfo) override {
        if (!pLastErrorInfo) return E_INVALIDARG;
        memset(pLastErrorInfo, 0, sizeof(*pLastErrorInfo));
        return S_OK;
    }

    /* ========================================================================
     * IWiaMiniDrv Implementation
     * ======================================================================== */
    STDMETHODIMP drvInitializeWia(
        BYTE *pWiasContext,
        LONG lFlags,
        BSTR bstrDeviceID,
        BSTR bstrRootFullItemName,
        IUnknown *pStiDevice,
        IUnknown *pIUnknownOuter,
        IWiaDrvItem **ppIDrvItemRoot,
        IUnknown **ppIUnknownInner,
        LONG *plDevErrVal
    ) override {
        (void)pWiasContext; (void)lFlags; (void)bstrDeviceID;
        (void)pStiDevice; (void)pIUnknownOuter;
        if (plDevErrVal) *plDevErrVal = 0;
        if (ppIUnknownInner) *ppIUnknownInner = NULL;
        if (!ppIDrvItemRoot) return E_INVALIDARG;

        EnsureHardwareReady();

        if (!m_bstrRootFullItemName && bstrRootFullItemName) {
            m_bstrRootFullItemName = SysAllocString(bstrRootFullItemName);
        }

        if (!m_pRootItem) {
            LONG lFlagsRoot = WiaItemTypeFolder | WiaItemTypeDevice | WiaItemTypeRoot;
            BSTR bstrRootName = SysAllocString(L"Root");
            HRESULT hr = wiasCreateDrvItem(
                lFlagsRoot,
                bstrRootName,
                m_bstrRootFullItemName,
                static_cast<IWiaMiniDrv *>(this),
                0,
                NULL,
                &m_pRootItem
            );
            SysFreeString(bstrRootName);
            if (FAILED(hr)) return hr;

            /* Create child Film Scanner item */
            BSTR bstrFilmName = SysAllocString(L"Film");
            WCHAR wszFullFilm[256] = {0};
            StringCchPrintfW(wszFullFilm, 256, L"%s\\Film", m_bstrRootFullItemName ? m_bstrRootFullItemName : L"0000\\Root");
            BSTR bstrFullFilm = SysAllocString(wszFullFilm);

            IWiaDrvItem *pFilmItem = NULL;
            hr = wiasCreateDrvItem(
                WiaItemTypeFile | WiaItemTypeImage | WiaItemTypeTransfer,
                bstrFilmName,
                bstrFullFilm,
                static_cast<IWiaMiniDrv *>(this),
                0,
                NULL,
                &pFilmItem
            );
            SysFreeString(bstrFilmName);
            SysFreeString(bstrFullFilm);

            if (SUCCEEDED(hr) && pFilmItem) {
                pFilmItem->AddItemToFolder(m_pRootItem);
                pFilmItem->Release();
            }
        }

        m_pRootItem->AddRef();
        *ppIDrvItemRoot = m_pRootItem;
        return S_OK;
    }

    STDMETHODIMP drvAcquireItemData(
        BYTE *pWiasContext,
        LONG lFlags,
        PMINIDRV_TRANSFER_CONTEXT pmdtc,
        LONG *plDevErrVal
    ) override {
        (void)lFlags;
        if (plDevErrVal) *plDevErrVal = 0;
        if (!pmdtc) return E_INVALIDARG;

        if (!EnsureHardwareReady()) {
            return E_FAIL;
        }

        /* Read any resolution/datatype overrides from WIA item properties */
        if (pWiasContext) {
            LONG xres = 0, datatype = 0;
            if (SUCCEEDED(wiasReadPropLong(pWiasContext, WIA_IPS_XRES, &xres, NULL, FALSE)) && xres > 0) {
                m_params.dpi = (uint16_t)xres;
            }
            if (SUCCEEDED(wiasReadPropLong(pWiasContext, WIA_IPA_DATATYPE, &datatype, NULL, FALSE))) {
                m_params.channels = (datatype == WIA_DATA_GRAYSCALE) ? 1 : 3;
            }
        }

        uint8_t *pixels = NULL;
        uint32_t width = 0, height = 0, bpp = 0;
        if (dimage_scan_to_buffer(&m_scanner, &m_params, &pixels, &width, &height, &bpp) != 0 || !pixels) {
            return E_FAIL;
        }

        /* Write to temporary BMP and stream to WIA callback or memory buffer */
        char tmpPath[MAX_PATH] = {0};
        GetTempPathA(MAX_PATH, tmpPath);
        strcat_s(tmpPath, MAX_PATH, "minolta_wia_scan.bmp");

        int rc = dimage_write_bmp24(
            tmpPath,
            pixels,
            width,
            height,
            m_params.channels,
            m_params.bit_depth,
            m_params.dpi
        );
        free(pixels);
        if (rc != 0) return E_FAIL;

        FILE *fp = fopen(tmpPath, "rb");
        if (!fp) return E_FAIL;
        fseek(fp, 0, SEEK_END);
        long fileSize = ftell(fp);
        fseek(fp, 0, SEEK_SET);

        HRESULT hr = S_OK;
        BYTE *buf = (BYTE *)malloc((size_t)fileSize);
        if (buf && fread(buf, 1, (size_t)fileSize, fp) == (size_t)fileSize) {
            /* WiaImgFmt_MEMORYBMP expects raw DIB starting at BITMAPINFOHEADER (skipping 14-byte "BM" header) */
            bool isMemoryBmp = (IsEqualGUID(pmdtc->guidFormatID, WiaImgFmt_MEMORYBMP) != 0);
            BYTE *payloadPtr = (isMemoryBmp && fileSize > 14) ? (buf + 14) : buf;
            LONG  payloadLen = (isMemoryBmp && fileSize > 14) ? (fileSize - 14) : fileSize;

            if (pmdtc->bTransferDataCB && pmdtc->pIWiaMiniDrvCallBack) {
                WIA_DATA_CALLBACK_HEADER hdr;
                memset(&hdr, 0, sizeof(hdr));
                hdr.lSize        = sizeof(hdr);
                hdr.guidFormatID = pmdtc->guidFormatID;
                hdr.lBufferSize  = payloadLen;
                hdr.lPageCount   = 1;

                hr = pmdtc->pIWiaMiniDrvCallBack->MiniDrvCallback(
                    IT_MSG_DATA_HEADER, IT_STATUS_TRANSFER_TO_CLIENT,
                    0, 0, sizeof(hdr), &pmdtc->guidFormatID, (BYTE *)&hdr
                );
                if (SUCCEEDED(hr)) {
                    hr = pmdtc->pIWiaMiniDrvCallBack->MiniDrvCallback(
                        IT_MSG_DATA, IT_STATUS_TRANSFER_TO_CLIENT,
                        100, 0, payloadLen, &pmdtc->guidFormatID, payloadPtr
                    );
                }
            } else if (pmdtc->pTransferBuffer && pmdtc->lBufferSize >= payloadLen) {
                memcpy(pmdtc->pTransferBuffer, payloadPtr, (size_t)payloadLen);
            }
        }
        free(buf);

        fclose(fp);
        DeleteFileA(tmpPath);
        return hr;
    }

    STDMETHODIMP drvInitItemProperties(BYTE *pWiasContext, LONG lFlags, LONG *plDevErrVal) override {
        (void)lFlags;
        if (plDevErrVal) *plDevErrVal = 0;
        if (!pWiasContext) return E_INVALIDARG;

        LONG itemType = 0;
        wiasGetItemType(pWiasContext, &itemType);

        if (itemType & WiaItemTypeRoot) {
            wiasWritePropLong(pWiasContext, WIA_DPS_OPTICAL_XRES, DIMAGE_OPTICAL_DPI);
            wiasWritePropLong(pWiasContext, WIA_DPS_OPTICAL_YRES, DIMAGE_OPTICAL_DPI);
            wiasWritePropLong(pWiasContext, WIA_DPS_DOCUMENT_HANDLING_CAPABILITIES, FILM_TPA);
            wiasWritePropLong(pWiasContext, WIA_DPS_DOCUMENT_HANDLING_STATUS, TPA_READY);
            return S_OK;
        }

        /* Child Film Item Properties */
        LONG dpi    = m_params.dpi ? m_params.dpi : 1410;
        LONG scale  = DIMAGE_OPTICAL_DPI / dpi;
        if (scale < 1) scale = 1;
        LONG width  = DIMAGE_MAX_WIDTH_PIXELS / scale;
        LONG height = DIMAGE_MAX_HEIGHT_PIXELS / scale;
        LONG stride = (width * 3 + 3) & ~3;

        wiasWritePropLong(pWiasContext, WIA_IPA_DATATYPE, WIA_DATA_COLOR);
        wiasWritePropLong(pWiasContext, WIA_IPA_DEPTH, 24);
        wiasWritePropLong(pWiasContext, WIA_IPA_CHANNELS_PER_PIXEL, 3);
        wiasWritePropLong(pWiasContext, WIA_IPA_BITS_PER_CHANNEL, 8);
        wiasWritePropGuid(pWiasContext, WIA_IPA_FORMAT, WiaImgFmt_BMP);
        wiasWritePropLong(pWiasContext, WIA_IPA_TYMED, TYMED_FILE);
        wiasWritePropLong(pWiasContext, WIA_IPS_XRES, dpi);
        wiasWritePropLong(pWiasContext, WIA_IPS_YRES, dpi);
        wiasWritePropLong(pWiasContext, WIA_IPS_XPOS, 0);
        wiasWritePropLong(pWiasContext, WIA_IPS_YPOS, 0);
        wiasWritePropLong(pWiasContext, WIA_IPS_XEXTENT, width);
        wiasWritePropLong(pWiasContext, WIA_IPS_YEXTENT, height);
        wiasWritePropLong(pWiasContext, WIA_IPA_PIXELS_PER_LINE, width);
        wiasWritePropLong(pWiasContext, WIA_IPA_NUMBER_OF_LINES, height);
        wiasWritePropLong(pWiasContext, WIA_IPA_BYTES_PER_LINE, stride);
        wiasWritePropLong(pWiasContext, WIA_IPA_BUFFER_SIZE, 65536);
        return S_OK;
    }

    STDMETHODIMP drvValidateItemProperties(BYTE *pWiasContext, LONG lFlags, ULONG nPropSpec,
                                           const PROPSPEC *pPropSpec, LONG *plDevErrVal) override {
        (void)lFlags; (void)nPropSpec; (void)pPropSpec;
        if (plDevErrVal) *plDevErrVal = 0;
        if (!pWiasContext) return S_OK;

        LONG itemType = 0;
        wiasGetItemType(pWiasContext, &itemType);
        if (!(itemType & WiaItemTypeRoot)) {
            LONG xres = 1410;
            wiasReadPropLong(pWiasContext, WIA_IPS_XRES, &xres, NULL, FALSE);
            if (xres <= 0) xres = 1410;
            LONG scale  = DIMAGE_OPTICAL_DPI / xres;
            if (scale < 1) scale = 1;
            LONG width  = DIMAGE_MAX_WIDTH_PIXELS / scale;
            LONG height = DIMAGE_MAX_HEIGHT_PIXELS / scale;
            LONG stride = (width * 3 + 3) & ~3;

            wiasWritePropLong(pWiasContext, WIA_IPS_XEXTENT, width);
            wiasWritePropLong(pWiasContext, WIA_IPS_YEXTENT, height);
            wiasWritePropLong(pWiasContext, WIA_IPA_PIXELS_PER_LINE, width);
            wiasWritePropLong(pWiasContext, WIA_IPA_NUMBER_OF_LINES, height);
            wiasWritePropLong(pWiasContext, WIA_IPA_BYTES_PER_LINE, stride);
        }
        return S_OK;
    }

    STDMETHODIMP drvWriteItemProperties(BYTE *pWiasContext, LONG lFlags, PMINIDRV_TRANSFER_CONTEXT pmdtc,
                                        LONG *plDevErrVal) override {
        (void)pWiasContext; (void)lFlags; (void)pmdtc;
        if (plDevErrVal) *plDevErrVal = 0;
        return S_OK;
    }

    STDMETHODIMP drvReadItemProperties(BYTE *pWiasContext, LONG lFlags, ULONG nPropSpec,
                                       const PROPSPEC *pPropSpec, LONG *plDevErrVal) override {
        return drvValidateItemProperties(pWiasContext, lFlags, nPropSpec, pPropSpec, plDevErrVal);
    }

    STDMETHODIMP drvLockWiaDevice(BYTE *pWiasContext, LONG lFlags, LONG *plDevErrVal) override {
        (void)pWiasContext; (void)lFlags;
        if (plDevErrVal) *plDevErrVal = 0;
        return S_OK;
    }

    STDMETHODIMP drvUnLockWiaDevice(BYTE *pWiasContext, LONG lFlags, LONG *plDevErrVal) override {
        (void)pWiasContext; (void)lFlags;
        if (plDevErrVal) *plDevErrVal = 0;
        return S_OK;
    }

    STDMETHODIMP drvAnalyzeItem(BYTE *pWiasContext, LONG lFlags, LONG *plDevErrVal) override {
        (void)pWiasContext; (void)lFlags;
        if (plDevErrVal) *plDevErrVal = 0;
        return S_OK;
    }

    STDMETHODIMP drvGetDeviceErrorStr(LONG lFlags, LONG lDevErrVal, LPOLESTR *ppszDevErrStr, LONG *plDevErr) override {
        (void)lFlags; (void)lDevErrVal;
        if (plDevErr) *plDevErr = 0;
        if (!ppszDevErrStr) return E_INVALIDARG;
        const WCHAR msg[] = L"Minolta DiMAGE Scan Dual III Error";
        size_t cb = sizeof(msg);
        LPOLESTR psz = (LPOLESTR)CoTaskMemAlloc(cb);
        if (!psz) return E_OUTOFMEMORY;
        memcpy(psz, msg, cb);
        *ppszDevErrStr = psz;
        return S_OK;
    }

    STDMETHODIMP drvDeviceCommand(BYTE *pWiasContext, LONG lFlags, const GUID *plCommand,
                                  IWiaDrvItem **ppWiaDrvItem, LONG *plDevErrVal) override {
        (void)pWiasContext; (void)lFlags; (void)plCommand; (void)ppWiaDrvItem;
        if (plDevErrVal) *plDevErrVal = 0;
        return S_OK;
    }

    STDMETHODIMP drvGetCapabilities(BYTE *pWiasContext, LONG ulFlags, LONG *pcelt,
                                    WIA_DEV_CAP_DRV **ppCapabilities, LONG *plDevErrVal) override {
        (void)pWiasContext; (void)ulFlags;
        if (plDevErrVal) *plDevErrVal = 0;
        if (pcelt) *pcelt = 0;
        if (ppCapabilities) *ppCapabilities = NULL;
        return S_OK;
    }

    STDMETHODIMP drvDeleteItem(BYTE *pWiasContext, LONG lFlags, LONG *plDevErrVal) override {
        (void)pWiasContext; (void)lFlags;
        if (plDevErrVal) *plDevErrVal = 0;
        return E_NOTIMPL;
    }

    STDMETHODIMP drvFreeDrvItemContext(LONG lFlags, BYTE *pSpecContext, LONG *plDevErrVal) override {
        (void)lFlags; (void)pSpecContext;
        if (plDevErrVal) *plDevErrVal = 0;
        return S_OK;
    }

    STDMETHODIMP drvGetWiaFormatInfo(BYTE *pWiasContext, LONG lFlags, LONG *pcelt,
                                     WIA_FORMAT_INFO **ppwfi, LONG *plDevErrVal) override {
        (void)pWiasContext; (void)lFlags;
        if (plDevErrVal) *plDevErrVal = 0;
        static WIA_FORMAT_INFO s_formats[2] = {
            { WiaImgFmt_BMP,       TYMED_FILE },
            { WiaImgFmt_MEMORYBMP, TYMED_CALLBACK }
        };
        if (pcelt) *pcelt = 2;
        if (ppwfi) *ppwfi = s_formats;
        return S_OK;
    }

    STDMETHODIMP drvNotifyPnpEvent(const GUID *pEventGUID, BSTR bstrDeviceID, ULONG ulReserved) override {
        (void)pEventGUID; (void)bstrDeviceID; (void)ulReserved;
        return S_OK;
    }

    STDMETHODIMP drvUnInitializeWia(BYTE *pWiasContext) override {
        (void)pWiasContext;
        return S_OK;
    }
};

/* ============================================================================
 * COM Class Factory & DLL Exports
 * ============================================================================ */

class MinoltaClassFactory : public IClassFactory {
private:
    LONG m_cRef;
public:
    MinoltaClassFactory() : m_cRef(1) {}
    virtual ~MinoltaClassFactory() {}

    STDMETHODIMP QueryInterface(REFIID riid, void **ppv) override {
        if (!ppv) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IClassFactory) {
            *ppv = static_cast<IClassFactory *>(this);
            AddRef();
            return S_OK;
        }
        *ppv = NULL;
        return E_NOINTERFACE;
    }

    STDMETHODIMP_(ULONG) AddRef() override {
        return (ULONG)InterlockedIncrement(&m_cRef);
    }

    STDMETHODIMP_(ULONG) Release() override {
        LONG c = InterlockedDecrement(&m_cRef);
        if (c == 0) delete this;
        return (ULONG)c;
    }

    STDMETHODIMP CreateInstance(IUnknown *pUnkOuter, REFIID riid, void **ppv) override {
        if (pUnkOuter) return CLASS_E_NOAGGREGATION;
        MinoltaWia2Driver *pDrv = new MinoltaWia2Driver();
        if (!pDrv) return E_OUTOFMEMORY;
        HRESULT hr = pDrv->QueryInterface(riid, ppv);
        pDrv->Release();
        return hr;
    }

    STDMETHODIMP LockServer(BOOL fLock) override {
        if (fLock) InterlockedIncrement(&g_cLocks);
        else InterlockedDecrement(&g_cLocks);
        return S_OK;
    }
};

extern "C" BOOL WINAPI DllMain(HINSTANCE hInstance, DWORD dwReason, LPVOID lpReserved) {
    (void)lpReserved;
    if (dwReason == DLL_PROCESS_ATTACH) {
        g_hInst = hInstance;
        DisableThreadLibraryCalls(hInstance);
    }
    return TRUE;
}

extern "C" STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, LPVOID *ppv) {
    if (!ppv) return E_POINTER;
    *ppv = NULL;
    if (rclsid != CLSID_MinoltaDual3WiaDriver) {
        return CLASS_E_CLASSNOTAVAILABLE;
    }
    MinoltaClassFactory *pFactory = new MinoltaClassFactory();
    if (!pFactory) return E_OUTOFMEMORY;
    HRESULT hr = pFactory->QueryInterface(riid, ppv);
    pFactory->Release();
    return hr;
}

extern "C" STDAPI DllCanUnloadNow(void) {
    return (g_cLocks == 0) ? S_OK : S_FALSE;
}

extern "C" STDAPI DllRegisterServer(void) {
    WCHAR wszModule[MAX_PATH] = {0};
    GetModuleFileNameW(g_hInst, wszModule, MAX_PATH);

    HKEY hKey = NULL;
    const WCHAR *keyPath = L"CLSID\\{E4088F20-D799-11D2-BAFF-00A02491DF4E}\\InProcServer32";
    if (RegCreateKeyExW(HKEY_CLASSES_ROOT, keyPath, 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) != ERROR_SUCCESS) {
        return SELFREG_E_CLASS;
    }
    RegSetValueExW(hKey, NULL, 0, REG_SZ, (const BYTE *)wszModule,
                   (DWORD)((wcslen(wszModule) + 1) * sizeof(WCHAR)));
    const WCHAR *threading = L"Both";
    RegSetValueExW(hKey, L"ThreadingModel", 0, REG_SZ, (const BYTE *)threading,
                   (DWORD)((wcslen(threading) + 1) * sizeof(WCHAR)));
    RegCloseKey(hKey);
    return S_OK;
}

extern "C" STDAPI DllUnregisterServer(void) {
    RegDeleteTreeW(HKEY_CLASSES_ROOT, L"CLSID\\{E4088F20-D799-11D2-BAFF-00A02491DF4E}");
    return S_OK;
}
#endif /* _WIN32 */
