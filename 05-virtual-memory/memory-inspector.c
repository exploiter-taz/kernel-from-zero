/*
 * Virtual memory inspector: page protections, committed vs reserved,
 * working sets, and the Native API underneath.
 *
 * Compile:  cl /W4 /O2 memory-inspector.c ntdll.lib
 */

#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <psapi.h>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "psapi.lib")

static const char *ProtectStr(DWORD prot)
{
    switch (prot & 0xFF) {
    case PAGE_NOACCESS:          return "---";
    case PAGE_READONLY:          return "R--";
    case PAGE_READWRITE:         return "RW-";
    case PAGE_WRITECOPY:         return "RWC";
    case PAGE_EXECUTE:           return "--X";
    case PAGE_EXECUTE_READ:      return "R-X";
    case PAGE_EXECUTE_READWRITE: return "RWX";
    case PAGE_EXECUTE_WRITECOPY: return "RWXC";
    default:                     return "???";
    }
}

static const char *StateStr(DWORD state)
{
    switch (state) {
    case MEM_COMMIT:  return "Commit ";
    case MEM_RESERVE: return "Reserve";
    case MEM_FREE:    return "Free   ";
    default:          return "???    ";
    }
}

static const char *TypeStr(DWORD type)
{
    switch (type) {
    case MEM_IMAGE:   return "Image ";
    case MEM_MAPPED:  return "Mapped";
    case MEM_PRIVATE: return "Private";
    default:          return "      ";
    }
}

void MapOurMemory(void)
{
    printf("--- Virtual memory regions ---\n\n");
    printf("%-18s  %-10s  %-7s  %-4s  %-7s  %s\n",
           "BaseAddress", "Size", "State", "Prot", "Type", "Notes");
    printf("%-18s  %-10s  %-7s  %-4s  %-7s  %s\n",
           "-----------", "----", "-----", "----", "----", "-----");

    MEMORY_BASIC_INFORMATION mbi;
    BYTE *addr = NULL;
    int count = 0;
    int rwxCount = 0;

    while (VirtualQuery(addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.State != MEM_FREE) {
            const char *notes = "";
            if ((mbi.Protect & 0xFF) == PAGE_EXECUTE_READWRITE)
                notes = "!! RWX";
            if (mbi.Type == MEM_IMAGE && (mbi.Protect & 0xFF) == PAGE_EXECUTE_READ)
                notes = "code section";

            printf("%p  %-10zu  %s  %-4s  %s  %s\n",
                   mbi.BaseAddress, mbi.RegionSize,
                   StateStr(mbi.State), ProtectStr(mbi.Protect),
                   TypeStr(mbi.Type), notes);

            count++;
            if ((mbi.Protect & 0xFF) == PAGE_EXECUTE_READWRITE)
                rwxCount++;
        }

        addr = (BYTE *)mbi.BaseAddress + mbi.RegionSize;
        if (addr < (BYTE *)mbi.BaseAddress) break;
    }

    printf("\nTotal regions: %d", count);
    if (rwxCount > 0)
        printf("  (!! %d RWX regions)", rwxCount);
    printf("\n\n");
}

void DemoAllocationLifecycle(void)
{
    printf("--- Allocation lifecycle ---\n\n");

    printf("Step 1: Reserve 1 MB\n");
    void *base = VirtualAlloc(NULL, 1024 * 1024, MEM_RESERVE, PAGE_NOACCESS);
    printf("  Reserved at %p\n", base);

    MEMORY_BASIC_INFORMATION mbi;
    VirtualQuery(base, &mbi, sizeof(mbi));
    printf("  State: %s  Protect: %s\n\n",
           StateStr(mbi.State), ProtectStr(mbi.Protect));

    printf("Step 2: Commit first 4 KB\n");
    void *page = VirtualAlloc(base, 4096, MEM_COMMIT, PAGE_READWRITE);
    printf("  Committed at %p\n", page);

    VirtualQuery(base, &mbi, sizeof(mbi));
    printf("  State: %s  Protect: %s\n\n",
           StateStr(mbi.State), ProtectStr(mbi.Protect));

    printf("Step 3: Write\n");
    memcpy(page, "Hello from committed memory", 28);
    printf("  Wrote: \"%s\"\n\n", (char *)page);

    printf("Step 4: RW -> RX\n");
    DWORD oldProt;
    VirtualProtect(page, 4096, PAGE_EXECUTE_READ, &oldProt);
    VirtualQuery(base, &mbi, sizeof(mbi));
    printf("  Protect: %s -> %s\n\n",
           ProtectStr(oldProt), ProtectStr(mbi.Protect));

    printf("Step 5: Decommit\n");
    VirtualFree(base, 4096, MEM_DECOMMIT);
    VirtualQuery(base, &mbi, sizeof(mbi));
    printf("  State: %s\n\n", StateStr(mbi.State));

    printf("Step 6: Release\n");
    VirtualFree(base, 0, MEM_RELEASE);
    printf("  Released.\n\n");
}

void ShowWorkingSet(void)
{
    printf("--- Working set ---\n\n");

    PROCESS_MEMORY_COUNTERS pmc;
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
        printf("Working set size:  %zu KB\n", pmc.WorkingSetSize / 1024);
        printf("Peak working set:  %zu KB\n", pmc.PeakWorkingSetSize / 1024);
        printf("Pagefile usage:    %zu KB\n", pmc.PagefileUsage / 1024);
        printf("Peak pagefile:     %zu KB\n", pmc.PeakPagefileUsage / 1024);
        printf("Page fault count:  %u\n", pmc.PageFaultCount);
    }
    printf("\n");
}

typedef NTSTATUS (NTAPI *PFN_NtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

void DemoNativeAlloc(void)
{
    printf("--- NtAllocateVirtualMemory ---\n\n");

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    PFN_NtAllocateVirtualMemory pNtAlloc =
        (PFN_NtAllocateVirtualMemory)GetProcAddress(ntdll, "NtAllocateVirtualMemory");

    if (!pNtAlloc) {
        printf("[-] Could not resolve NtAllocateVirtualMemory\n\n");
        return;
    }

    PVOID base = NULL;
    SIZE_T size = 4096;

    NTSTATUS status = pNtAlloc(
        GetCurrentProcess(), &base, 0, &size,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (status == 0) {
        printf("[+] Succeeded: base = %p, size = %zu\n", base, size);
        memcpy(base, "Allocated via Native API", 25);
        printf("    Wrote: \"%s\"\n", (char *)base);

        SIZE_T freeSize = 0;
        pNtAlloc(GetCurrentProcess(), &base, 0, &freeSize, MEM_RELEASE, 0);
        printf("    Released.\n");
    } else {
        printf("[-] Failed: 0x%08X\n", (unsigned)status);
    }
    printf("\n");
}

int main(void)
{
    printf("=== 05: Virtual Memory ===\n\n");

    ShowWorkingSet();
    DemoAllocationLifecycle();
    DemoNativeAlloc();
    MapOurMemory();

    printf("=== done ===\n");
    return 0;
}
