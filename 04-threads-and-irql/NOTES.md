# 04 — Threads, Scheduling, and IRQL

The CPU doesn't run processes — it runs threads. A process is a container
(address space, handles, token). Threads are what the scheduler actually
picks up and puts on a core.

```
Process (EPROCESS) ──── address space, token, handles
  │
  ├── Thread 1 (ETHREAD) ── own stack, own TEB, own priority
  ├── Thread 2 (ETHREAD) ── own stack, own TEB, own priority
  └── Thread 3 (ETHREAD) ── own stack, own TEB, own priority
        │
        └── This is what the CPU runs.
            One thread per core at any instant.
```

## Kernel structures

| Structure | Where | What |
|-----------|-------|------|
| ETHREAD | Kernel memory | Full thread object — everything the kernel knows |
| KTHREAD | Inside ETHREAD (offset 0) | Scheduler-visible part: priority, state, stack, affinity |
| TEB | User-mode memory | Per-thread user data: stack limits, TLS, PEB pointer, last error |

EPROCESS has `ThreadListHead` — a LIST_ENTRY (step 01) that chains
all the threads belonging to that process. The scheduler doesn't use
this list — it has its own ready queues per priority level.

## The TEB

The TEB is to a thread what the PEB is to a process. It lives in
user-mode address space. On x64, the CPU's GS register points to it.

Key fields:
- `NtTib.StackBase` / `NtTib.StackLimit` — stack boundaries
- `ClientId` — {PID, TID}
- `ProcessEnvironmentBlock` — pointer to the PEB
- `LastErrorValue` — what GetLastError() reads
- `ThreadLocalStoragePointer` — TLS data

Shellcode finds the PEB through the TEB: `GS:[0x60]` on x64 →
PEB → Ldr → kernel32.dll base → GetProcAddress → any API.

## Thread injection techniques

| Technique | How | Detection |
|-----------|-----|-----------|
| **CreateRemoteThread** | Create a thread at a known address (usually shellcode or LoadLibrary) in another process | EDR hooks NtCreateThreadEx. Cross-process thread creation is very high signal. |
| **APC injection** | Queue a user APC to a thread in an alertable wait → code runs in target's context | EDR monitors QueueUserAPC / NtQueueApcThreadEx. Early bird (APC + CREATE_SUSPENDED) is a known signature. |
| **Thread hijacking** | SuspendThread → GetThreadContext → change RIP → SetThreadContext → ResumeThread | No new thread created (harder to detect), but suspending/resuming + context change is flagged by advanced EDR. |
| **Thread pool abuse** | Use TpAllocWork/TpPostWork to queue work in the target's thread pool | Legitimate API, but the callback address can be inspected. |
| **NtCreateThreadEx flags** | `THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER` hides the thread from debugger thread lists | Thread still visible in NtQuerySystemInformation. Flag itself is a signal. |

## Scheduling

The Windows scheduler is priority-based, preemptive, and round-robin
within the same priority level.

```
Priority levels: 0 (lowest) to 31 (highest)
  0       = Idle (only the zero page thread)
  1-15    = Dynamic range (normal applications)
  16-31   = Real-time range (needs special privilege)

Each level has a ready queue (linked list of KTHREAD objects).
The scheduler picks the highest non-empty queue and runs the
first thread from it.
```

Each core looks at its own ready queues. It picks the highest-priority
ready thread, gives it a quantum (~15ms on client, ~30ms on server),
and when the quantum expires, the timer interrupt fires and the scheduler
runs again. If a higher-priority thread becomes ready mid-quantum, it
preempts immediately.

The kernel temporarily boosts thread priority after I/O completion
(~+2), GUI input (foreground boost), and starvation (a thread that
hasn't run for 4 seconds gets boosted to 15 for one quantum). The boost
decays by 1 each quantum until it hits the base priority.

## IRQL — Interrupt Request Level

This is a per-CPU priority system that sits above thread scheduling.
Thread priority decides which thread runs. IRQL decides whether the
scheduler itself can run.

```
  IRQL 15  HIGH_LEVEL        NMI, machine check, KeBugCheck
  IRQL 3+  Device IRQLs      Hardware interrupt handlers (ISRs)
  ─────────────────────────── everything above here blocks scheduling
  IRQL 2   DISPATCH_LEVEL    DPCs, SpinLocks, scheduler
  ─────────────────────────── page faults blocked above here
  IRQL 1   APC_LEVEL         APCs blocked
  IRQL 0   PASSIVE_LEVEL     Normal execution, everything works
```

| At this IRQL | You CAN | You CANNOT |
|---|---|---|
| PASSIVE (0) | Everything: paged memory, waiting, I/O, syscalls | — |
| APC (1) | Page faults, paged memory | Deliver APCs to this thread |
| DISPATCH (2) | Non-paged pool, stack, SpinLock | Page faults, waits, paged memory, Zw* calls |
| Device (3+) | Acknowledge hardware, queue DPC | Almost everything else |

DISPATCH_LEVEL is the danger zone. If the memory you touch is paged out,
the page fault handler needs to do I/O and wait — but waiting requires
the scheduler, which is blocked at DISPATCH_LEVEL. Result:
`IRQL_NOT_LESS_OR_EQUAL (0x0000000A)`. If you spin-loop at DISPATCH,
that core freezes — no context switch until IRQL drops.

## ISR → DPC → Work Item

```
Hardware interrupt fires
    ↓
ISR runs at device IRQL (3+)
    - Acknowledge the interrupt
    - Read status register
    - Queue a DPC
    - Return (< 25 μs)
    ↓
DPC runs at DISPATCH_LEVEL (2)
    - Process the data the ISR read
    - Complete the IRP if possible
    - Queue a work item if more complex work needed
    - Return (< 100 μs recommended)
    ↓
Work item runs at PASSIVE_LEVEL (0)
    - Full access to everything
    - Can wait, do I/O, touch paged memory
    - Takes as long as it needs
```

Red team angle: a DPC timer callback runs periodically at DISPATCH_LEVEL
and is harder to remove than a user-mode timer. Rootkits use this for
persistent callbacks. And understanding that EDR kernel components use
SpinLocks (which raise to DISPATCH) means they can't do complex checks
inside a SpinLock-protected region — heavy analysis gets deferred to a
work item at PASSIVE, creating a window between detection and blocking.

## The code

`thread-irql-inspector.c` demonstrates:

1. **TEB inspection** — reads the TEB (stack base/limit, PEB pointer)
2. **Thread enumeration** — lists all threads via NtQuerySystemInformation,
   showing state, priority, context switches
3. **Priority demo** — 3 threads at different priorities, shows scheduling
4. **APC injection** — queues a user APC to an alertable thread
5. **IRQL rules** — prints the level table (can't change IRQL from user mode)
6. **DPC chain** — the ISR → DPC → work item chain

## WinDbg

```
; Check current IRQL
0: kd> !irql

; Look at a thread
0: kd> !thread

; Set a breakpoint on a DPC-related function
0: kd> bp nt!KiRetireDpcList

; Watch context switches
0: kd> !ready

; SpinLock: before and after
0: kd> bp nt!KeAcquireSpinLockRaiseToDpc
; Before: PASSIVE_LEVEL. After: DISPATCH_LEVEL.

; APC queue
0: kd> dt nt!_KAPC

; Per-CPU DPC queue
0: kd> dt nt!_KPRCB DpcData <Prcb address>
```
