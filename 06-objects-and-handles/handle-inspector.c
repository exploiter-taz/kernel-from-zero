/*
 * Handle inspector: handle lifecycle, duplication, _EX_FAST_REF decoding,
 * Object Manager namespace, and system-wide handle enumeration.
 *
 * Compile:  cl /W4 /O2 handle-inspector.c ntdll.lib
 */

#include <windows.h>
#include <winternl.h>
#include <stdio.h>

#pragma comment(lib, "ntdll.lib")

#define SystemExtendedHandleInformation_ 64

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
    PVOID      Object;
    ULONG_PTR  UniqueProcessId;
    ULONG_PTR  HandleValue;
    ULONG      GrantedAccess;
    USHORT     CreatorBackTraceIndex;
    USHORT     ObjectTypeIndex;
    ULONG      HandleAttributes;
    ULONG      Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX;

void EnumerateOurHandles(void)
{
    DWORD myPid = GetCurrentProcessId();
    printf("--- Handles in PID %u ---\n\n", myPid);

    ULONG bufSize = 1024 * 1024;
    BYTE *buf = NULL;
    NTSTATUS status;

    for (;;) {
        buf = (BYTE *)malloc(bufSize);
        if (!buf) return;

        ULONG needed = 0;
        status = NtQuerySystemInformation(
            SystemExtendedHandleInformation_, buf, bufSize, &needed);

        if (status == (NTSTATUS)0xC0000004) {
            free(buf);
            bufSize = needed + 65536;
            continue;
        }
        break;
    }

    if (status != 0) {
        printf("[-] NtQuerySystemInformation failed: 0x%08X\n", (unsigned)status);
        free(buf);
        return;
    }

    SYSTEM_HANDLE_INFORMATION_EX *info = (SYSTEM_HANDLE_INFORMATION_EX *)buf;

    printf("Total handles in system: %Iu\n\n", info->NumberOfHandles);
    printf("%-8s  %-8s  %-10s  %-6s  %s\n",
           "Handle", "Type", "Access", "Attrs", "Object");
    printf("%-8s  %-8s  %-10s  %-6s  %s\n",
           "------", "----", "------", "-----", "------");

    int ourCount = 0;
    for (ULONG_PTR i = 0; i < info->NumberOfHandles && ourCount < 50; i++) {
        SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX *h = &info->Handles[i];
        if (h->UniqueProcessId == myPid) {
            printf("0x%-6X  %-8u  0x%08X  0x%04X  %p\n",
                   (unsigned)h->HandleValue,
                   h->ObjectTypeIndex,
                   h->GrantedAccess,
                   h->HandleAttributes,
                   h->Object);
            ourCount++;
        }
    }

    printf("\nShowing first %d handles of PID %u\n\n", ourCount, myPid);
    free(buf);
}

void DemoHandleLifecycle(void)
{
    printf("--- Handle lifecycle ---\n\n");

    printf("Step 1: Create an Event\n");
    HANDLE hEvent = CreateEventW(NULL, TRUE, FALSE, L"KernelFromZero06Demo");
    printf("  Handle = 0x%p\n", (void *)hEvent);

    printf("\nStep 2: Duplicate (same object, two handles)\n");
    HANDLE hEvent2;
    DuplicateHandle(GetCurrentProcess(), hEvent,
                    GetCurrentProcess(), &hEvent2,
                    0, FALSE, DUPLICATE_SAME_ACCESS);
    printf("  Second handle = 0x%p\n", (void *)hEvent2);

    printf("\nStep 3: Close first handle\n");
    CloseHandle(hEvent);
    printf("  Object survives — second handle still valid.\n");

    printf("\nStep 4: Signal through second handle\n");
    SetEvent(hEvent2);
    printf("  Works. Object alive.\n");

    printf("\nStep 5: Close second handle\n");
    CloseHandle(hEvent2);
    printf("  Both closed. Destroyed if PointerCount is also 0.\n\n");
}

void DemoHandleDuplication(void)
{
    printf("--- Handle duplication ---\n\n");

    HANDLE hFile = CreateFileW(L"C:\\Windows\\notepad.exe",
        GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] CreateFile failed\n\n");
        return;
    }

    printf("Original:   0x%p\n", (void *)hFile);

    HANDLE hDup;
    DuplicateHandle(GetCurrentProcess(), hFile,
                    GetCurrentProcess(), &hDup,
                    0, FALSE, DUPLICATE_SAME_ACCESS);

    printf("Duplicate:  0x%p\n", (void *)hDup);

    LARGE_INTEGER size1, size2;
    GetFileSizeEx(hFile, &size1);
    GetFileSizeEx(hDup, &size2);
    printf("Size via original:   %lld bytes\n", size1.QuadPart);
    printf("Size via duplicate:  %lld bytes\n\n", size2.QuadPart);

    CloseHandle(hFile);
    CloseHandle(hDup);
}

void ExplainExFastRef(void)
{
    printf("--- _EX_FAST_REF ---\n\n");

    ULONG_PTR val = 0xFFFF9A8012345678ULL | 0x7;

    printf("  Raw value:   0x%016llX\n\n", (unsigned long long)val);

    printf("  x64 mask (~0xF):\n");
    printf("    Pointer:  0x%016llX\n", (unsigned long long)(val & ~(ULONG_PTR)0xF));
    printf("    Refcount: %llu\n\n", (unsigned long long)(val & 0xF));

    printf("  Wrong mask (~0x7, x86 on x64):\n");
    printf("    Pointer:  0x%016llX  <- bit 3 leaked\n",
           (unsigned long long)(val & ~(ULONG_PTR)0x7));
    printf("    Off by 8 -> PAGE_FAULT_IN_NONPAGED_AREA\n\n");
}

void PrintObjectManager(void)
{
    printf("--- Object Manager namespace ---\n\n");
    printf("  \\                     Root\n");
    printf("  \\Device               Device objects\n");
    printf("  \\Driver               Driver objects\n");
    printf("  \\??                   Symbolic links\n");
    printf("  \\BaseNamedObjects     Named events, mutexes, sections\n");
    printf("  \\KernelObjects        Kernel-internal named objects\n");
    printf("  \\ObjectTypes          Type objects\n\n");
}

int main(void)
{
    printf("=== 06: Objects and Handles ===\n\n");

    DemoHandleLifecycle();
    DemoHandleDuplication();
    ExplainExFastRef();
    PrintObjectManager();
    EnumerateOurHandles();

    printf("=== done ===\n");
    return 0;
}
