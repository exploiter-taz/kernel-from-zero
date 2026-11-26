/*
 * User-mode → kernel-mode communication: device handles and IOCTLs.
 *
 * Build:  cl talk.c /link advapi32.lib
 *         gcc talk.c -o talk -ladvapi32
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
/* Stubs for compiling the IOCTL decoder on Linux/macOS */
typedef unsigned long DWORD;
typedef unsigned long long ULONG64;
#define CTL_CODE(DeviceType, Function, Method, Access) \
    (((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method))
#endif

/*
 *   31          16 15  14 13         2 1    0
 *  ┌──────────────┬─────┬────────────┬──────┐
 *  │  DeviceType  │ Acc │  Function  │Method│
 *  │   (16 bits)  │(2b) │  (12 bits) │ (2b) │
 *  └──────────────┴─────┴────────────┴──────┘
 */

#define METHOD_BUFFERED   0
#define METHOD_IN_DIRECT  1
#define METHOD_OUT_DIRECT 2
#define METHOD_NEITHER    3

#define FILE_ANY_ACCESS   0
#define FILE_READ_ACCESS  1
#define FILE_WRITE_ACCESS 2

void DecodeIoctl(DWORD code)
{
    DWORD deviceType = (code >> 16) & 0xFFFF;
    DWORD access     = (code >> 14) & 0x3;
    DWORD function   = (code >> 2)  & 0xFFF;
    DWORD method     = code & 0x3;

    const char *methodStr[] = {
        "METHOD_BUFFERED", "METHOD_IN_DIRECT",
        "METHOD_OUT_DIRECT", "METHOD_NEITHER"
    };
    const char *accessStr[] = {
        "FILE_ANY_ACCESS", "FILE_READ_ACCESS",
        "FILE_WRITE_ACCESS", "READ+WRITE"
    };

    printf("IOCTL 0x%08lX\n", (unsigned long)code);
    printf("  DeviceType : 0x%04lX  (%s)\n", (unsigned long)deviceType,
           deviceType >= 0x8000 ? "third-party" : "Microsoft");
    printf("  Function   : 0x%03lX  (%s range)\n", (unsigned long)function,
           function >= 0x800 ? "third-party" : "Microsoft-reserved");
    printf("  Method     : %s (%lu)\n", methodStr[method], (unsigned long)method);
    printf("  Access     : %s (%lu)\n", accessStr[access], (unsigned long)access);
    printf("  Reconstruct: CTL_CODE(0x%04lX, 0x%03lX, %s, %s)\n",
           (unsigned long)deviceType, (unsigned long)function,
           methodStr[method], accessStr[access]);
}

#ifdef _WIN32

HANDLE OpenDevice(const wchar_t *devicePath)
{
    HANDLE hDevice = CreateFileW(
        devicePath,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hDevice == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        wprintf(L"[-] CreateFile(\"%s\") failed: error %lu", devicePath, err);
        switch (err) {
        case 2:  wprintf(L" (FILE_NOT_FOUND — driver not loaded or no symlink)\n"); break;
        case 5:  wprintf(L" (ACCESS_DENIED — need admin or DACL blocks you)\n"); break;
        case 32: wprintf(L" (SHARING_VIOLATION — device opened exclusively)\n"); break;
        default: wprintf(L"\n"); break;
        }
        return INVALID_HANDLE_VALUE;
    }

    wprintf(L"[+] Handle to \"%s\" opened: 0x%p\n", devicePath, hDevice);
    return hDevice;
}

int SendIoctl(HANDLE hDevice, DWORD ioctlCode,
              void *inBuf, DWORD inSize,
              void *outBuf, DWORD outSize)
{
    DWORD bytesReturned = 0;

    BOOL ok = DeviceIoControl(
        hDevice,
        ioctlCode,
        inBuf, inSize,
        outBuf, outSize,
        &bytesReturned,
        NULL
    );

    if (!ok) {
        printf("[-] DeviceIoControl(0x%08lX) failed: error %lu\n",
               (unsigned long)ioctlCode, GetLastError());
        return 0;
    }

    printf("[+] DeviceIoControl(0x%08lX) succeeded, %lu bytes returned\n",
           (unsigned long)ioctlCode, bytesReturned);
    return 1;
}

void ScanDevices(void)
{
    const wchar_t *targets[] = {
        L"\\\\.\\RTCore64",
        L"\\\\.\\DBUtil_2_3",
        L"\\\\.\\AsIO3",
        L"\\\\.\\WinRing0_1_2_0",
        L"\\\\.\\Htsysm72FB",           /* Capcom.sys */
        L"\\\\.\\GIO",                   /* Gigabyte */
        L"\\\\.\\Nal",                   /* Intel diag */
        L"\\\\.\\HWiNFO64A",
        L"\\\\.\\KProcessHacker3",
        L"\\\\.\\procexp152",            /* Process Explorer */
        NULL
    };

    printf("[*] Scanning for loaded BYOVD drivers...\n\n");

    for (int i = 0; targets[i]; i++) {
        HANDLE h = CreateFileW(targets[i],
                               GENERIC_READ | GENERIC_WRITE,
                               0, NULL, OPEN_EXISTING, 0, NULL);
        if (h != INVALID_HANDLE_VALUE) {
            wprintf(L"  [!] FOUND: %s\n", targets[i]);
            CloseHandle(h);
        } else {
            DWORD err = GetLastError();
            wprintf(L"  [ ] %-30s  (error %lu)\n", targets[i], err);
        }
    }
}

#endif /* _WIN32 */

int main(int argc, char *argv[])
{
    if (argc < 2) {
        printf("Usage:\n");
        printf("  talk decode <ioctl_hex>          Decode an IOCTL code\n");
        printf("  talk encode <dev> <func> <meth>  Encode a CTL_CODE (hex)\n");
#ifdef _WIN32
        printf("  talk open <device_path>          Open a device handle\n");
        printf("  talk scan                        Scan for known BYOVD drivers\n");
        printf("  talk send <device> <ioctl_hex>   Send an IOCTL (empty buffer)\n");
#endif
        printf("\nExamples:\n");
        printf("  talk decode 0x80002048\n");
        printf("  talk encode 0x8000 0x812 0\n");
#ifdef _WIN32
        printf("  talk open \\\\.\\RTCore64\n");
        printf("  talk scan\n");
#endif
        return 1;
    }

    if (strcmp(argv[1], "decode") == 0 && argc >= 3) {
        DWORD code = (DWORD)strtoul(argv[2], NULL, 16);
        DecodeIoctl(code);

        printf("\nWell-known BYOVD IOCTLs:\n");
        printf("  RTCore64  read:  0x80002048  write: 0x8000204C  MSR: 0x80002058\n");
        printf("  DBUtil    read:  0x9B0C1EC8  write: 0x9B0C1ED0\n");
        printf("  Capcom    exec:  0xAA013044\n");
    }
    else if (strcmp(argv[1], "encode") == 0 && argc >= 5) {
        DWORD dev  = (DWORD)strtoul(argv[2], NULL, 16);
        DWORD func = (DWORD)strtoul(argv[3], NULL, 16);
        DWORD meth = (DWORD)strtoul(argv[4], NULL, 16);
        DWORD code = CTL_CODE(dev, func, meth, FILE_ANY_ACCESS);
        printf("CTL_CODE(0x%04lX, 0x%03lX, %lu, 0) = 0x%08lX\n",
               (unsigned long)dev, (unsigned long)func,
               (unsigned long)meth, (unsigned long)code);
        DecodeIoctl(code);
    }
#ifdef _WIN32
    else if (strcmp(argv[1], "open") == 0 && argc >= 3) {
        wchar_t wpath[256];
        MultiByteToWideChar(CP_UTF8, 0, argv[2], -1, wpath, 256);
        HANDLE h = OpenDevice(wpath);
        if (h != INVALID_HANDLE_VALUE)
            CloseHandle(h);
    }
    else if (strcmp(argv[1], "scan") == 0) {
        ScanDevices();
    }
    else if (strcmp(argv[1], "send") == 0 && argc >= 4) {
        wchar_t wpath[256];
        MultiByteToWideChar(CP_UTF8, 0, argv[2], -1, wpath, 256);
        DWORD ioctl = (DWORD)strtoul(argv[3], NULL, 16);

        HANDLE h = OpenDevice(wpath);
        if (h != INVALID_HANDLE_VALUE) {
            unsigned char inBuf[64]  = {0};
            unsigned char outBuf[64] = {0};
            SendIoctl(h, ioctl, inBuf, sizeof(inBuf), outBuf, sizeof(outBuf));
            CloseHandle(h);
        }
    }
#endif
    else {
        printf("Unknown command. Run with no arguments for usage.\n");
        return 1;
    }

    return 0;
}
