/*
 * Thread inspector: enumerate threads, read the TEB, demonstrate
 * priority scheduling, and fire a user-mode APC.
 *
 * Compile:  cl /W4 /O2 thread-irql-inspector.c ntdll.lib
 */

#include <windows.h>
#include <winternl.h>
#include <stdio.h>

#pragma comment(lib, "ntdll.lib")

#define SystemProcessInformation_ 5

typedef struct _MY_SYSTEM_THREAD_INFO {
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG         WaitTime;
    PVOID         StartAddress;
    CLIENT_ID     ClientId;
    LONG          Priority;
    LONG          BasePriority;
    ULONG         ContextSwitches;
    ULONG         ThreadState;
    ULONG         WaitReason;
} MY_SYSTEM_THREAD_INFO;

typedef struct _MY_SYSTEM_PROCESS_INFO {
    ULONG  NextEntryOffset;
    ULONG  NumberOfThreads;
    BYTE   Reserved1[48];
    UNICODE_STRING ImageName;
    LONG   BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG  HandleCount;
    ULONG  SessionId;
    PVOID  Reserved2;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG  Reserved3;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    PVOID  Reserved4;
    SIZE_T QuotaPagedPoolUsage;
    PVOID  Reserved5;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
    MY_SYSTEM_THREAD_INFO Threads[1];
} MY_SYSTEM_PROCESS_INFO;

static const char *ThreadStateNames[] = {
    "Initialized", "Ready", "Running", "Standby",
    "Terminated", "Waiting", "Transition", "DeferredReady"
};

void EnumerateOurThreads(void)
{
    DWORD myPid = GetCurrentProcessId();
    printf("--- Threads in PID %u ---\n\n", myPid);

    ULONG needed = 0;
    NtQuerySystemInformation(SystemProcessInformation_, NULL, 0, &needed);
    ULONG bufSize = needed + 65536;
    BYTE *buf = (BYTE *)malloc(bufSize);
    if (!buf) return;

    NTSTATUS status = NtQuerySystemInformation(
        SystemProcessInformation_, buf, bufSize, &needed);
    if (status != 0) { free(buf); return; }

    MY_SYSTEM_PROCESS_INFO *entry = (MY_SYSTEM_PROCESS_INFO *)buf;
    for (;;) {
        if ((ULONG_PTR)entry->UniqueProcessId == myPid) {
            printf("%-8s %-10s %-12s %-8s %-10s  %s\n",
                   "TID", "State", "CtxSwitches", "Priority", "WaitTime", "StartAddr");
            printf("%-8s %-10s %-12s %-8s %-10s  %s\n",
                   "---", "-----", "-----------", "--------", "--------", "---------");

            for (ULONG i = 0; i < entry->NumberOfThreads; i++) {
                MY_SYSTEM_THREAD_INFO *t = &entry->Threads[i];
                ULONG tid = (ULONG)(ULONG_PTR)t->ClientId.UniqueThread;
                const char *state = t->ThreadState < 8
                    ? ThreadStateNames[t->ThreadState] : "Unknown";

                printf("%-8u %-10s %-12u %-8d %-10u  %p\n",
                       tid, state, t->ContextSwitches,
                       t->Priority, t->WaitTime, t->StartAddress);
            }
            printf("\nTotal threads: %u\n", entry->NumberOfThreads);
            break;
        }
        if (entry->NextEntryOffset == 0) break;
        entry = (MY_SYSTEM_PROCESS_INFO *)((BYTE *)entry + entry->NextEntryOffset);
    }
    printf("\n");
    free(buf);
}

void InspectTeb(void)
{
    printf("--- TEB (Thread Environment Block) ---\n\n");

    PTEB teb = NtCurrentTeb();
    PPEB peb = teb->ProcessEnvironmentBlock;

    printf("TEB address:               %p\n", (void *)teb);
    printf("PEB address (from TEB):    %p\n", (void *)peb);
    printf("Current TID:               %u\n", GetCurrentThreadId());
    printf("Current PID:               %u\n", GetCurrentProcessId());
    printf("Stack base  (high):        %p\n", teb->NtTib.StackBase);
    printf("Stack limit (low):         %p\n", teb->NtTib.StackLimit);

    SIZE_T stackSize = (SIZE_T)((char *)teb->NtTib.StackBase -
                                (char *)teb->NtTib.StackLimit);
    printf("Current stack committed:   %zu KB\n", stackSize / 1024);
    printf("\n");
}

volatile LONG g_WorkDone = 0;

DWORD WINAPI WorkerThread(LPVOID param)
{
    int id = (int)(INT_PTR)param;
    DWORD tid = GetCurrentThreadId();

    printf("  [Thread %d] TID=%u, priority %d\n",
           id, tid, GetThreadPriority(GetCurrentThread()));

    for (volatile int i = 0; i < 5000000; i++) {}

    InterlockedIncrement(&g_WorkDone);
    printf("  [Thread %d] done (total done: %d)\n", id, g_WorkDone);
    return 0;
}

void DemoThreadPriority(void)
{
    printf("--- Thread priority demo ---\n\n");
    printf("Creating 3 threads at different priorities:\n");
    printf("  Thread 0: BELOW_NORMAL (-1)\n");
    printf("  Thread 1: NORMAL (0)\n");
    printf("  Thread 2: ABOVE_NORMAL (+1)\n\n");

    HANDLE threads[3];
    g_WorkDone = 0;

    for (int i = 0; i < 3; i++) {
        threads[i] = CreateThread(NULL, 0, WorkerThread,
                                  (LPVOID)(INT_PTR)i, CREATE_SUSPENDED, NULL);
    }

    SetThreadPriority(threads[0], THREAD_PRIORITY_BELOW_NORMAL);
    SetThreadPriority(threads[1], THREAD_PRIORITY_NORMAL);
    SetThreadPriority(threads[2], THREAD_PRIORITY_ABOVE_NORMAL);

    for (int i = 0; i < 3; i++)
        ResumeThread(threads[i]);

    WaitForMultipleObjects(3, threads, TRUE, INFINITE);

    for (int i = 0; i < 3; i++)
        CloseHandle(threads[i]);

    printf("\nAll threads finished.\n\n");
}

void CALLBACK ApcCallback(ULONG_PTR param)
{
    printf("  [APC] Executed in thread %u! param = %Iu\n",
           GetCurrentThreadId(), param);
}

DWORD WINAPI AlertableThread(LPVOID param)
{
    (void)param;
    printf("  [AlertableThread] TID=%u, entering alertable wait...\n",
           GetCurrentThreadId());
    SleepEx(5000, TRUE);
    printf("  [AlertableThread] woke up, exiting.\n");
    return 0;
}

void DemoApcInjection(void)
{
    printf("--- APC demo ---\n\n");

    HANDLE hThread = CreateThread(NULL, 0, AlertableThread, NULL, 0, NULL);
    Sleep(100);

    printf("  Queuing APC to the alertable thread...\n");
    QueueUserAPC(ApcCallback, hThread, 42);

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    printf("\n");
}

void PrintIrqlRules(void)
{
    printf("--- IRQL levels ---\n\n");
    printf("  Level  Name              Rules\n");
    printf("  -----  ----              -----\n");
    printf("  0      PASSIVE_LEVEL     Everything works. Driver code runs here.\n");
    printf("  1      APC_LEVEL         APCs blocked. Rarely used directly.\n");
    printf("  2      DISPATCH_LEVEL    No page faults, no waits, no paged pool.\n");
    printf("                           DPCs and SpinLocks run here.\n");
    printf("  3-11   Device IRQLs      ISRs. Keep it short, queue a DPC.\n");
    printf("  15     HIGH_LEVEL        NMI, KeBugCheck. Nothing preempts this.\n\n");
    printf("  BSOD 0xA (IRQL_NOT_LESS_OR_EQUAL):\n");
    printf("    Code at DISPATCH_LEVEL touched paged memory.\n\n");
}

void PrintDpcExplanation(void)
{
    printf("--- DPCs ---\n\n");
    printf("  ISR ──short──> DPC ──medium──> Work item ──long──>\n");
    printf("  IRQL 6+        IRQL 2          IRQL 0\n");
    printf("  microseconds   < 100 us        milliseconds+\n\n");
    printf("  ISR acknowledges the interrupt, queues a DPC.\n");
    printf("  DPC processes the data, completes the IRP if possible.\n");
    printf("  Work item handles anything that needs paged memory or waits.\n\n");
}

int main(void)
{
    printf("=== 04: Threads, Scheduling, and IRQL ===\n\n");

    InspectTeb();
    EnumerateOurThreads();
    DemoThreadPriority();
    DemoApcInjection();
    PrintIrqlRules();
    PrintDpcExplanation();

    printf("=== done ===\n");
    return 0;
}
