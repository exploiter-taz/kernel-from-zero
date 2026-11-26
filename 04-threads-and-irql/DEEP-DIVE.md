# 04 — Deep dive: threads, IRQL, and the bugs they cause

---

## Thread priority vs IRQL

Two separate ranking systems at different layers.

**Thread priority** (0-31) decides which thread the scheduler picks.
**IRQL** (0-15) decides whether the CPU responds to an interrupt — it
operates below the scheduler and decides whether the scheduler *itself*
can run.

IRQL outranks priority. A priority-31 thread can't run if the CPU is
at DISPATCH_LEVEL, because the scheduler is blocked.

```
IRQL 2 (DISPATCH)  → scheduler blocked → no context switch possible
    │                 regardless of thread priority
    ▼
IRQL 0 (PASSIVE)   → scheduler runs → picks highest-priority thread
                      thread priority matters HERE
```

A DPC (IRQL 2) can starve all threads: nothing runs until all pending
DPCs finish. A buggy DPC that loops forever freezes the core.

Red team angle: if you get code running in a DPC context (via a
vulnerable driver), you have a window where the EDR's user-mode
threads can't preempt you. The EDR's kernel components (minifilter
callbacks) still run at their own IRQL, but user-mode detection is
frozen until your DPC returns.

## Why SpinLocks raise IRQL to DISPATCH_LEVEL

A SpinLock protects a data structure by ensuring only one core accesses
it at a time. The acquiring core spin-waits (busy loop) until the lock
is free.

If the thread holding the SpinLock gets preempted, another thread runs,
tries to acquire the same lock, spins... and the first thread can't
release it because it's not running. On a single-core machine (or same
core due to affinity), that's a deadlock.

Raising IRQL to DISPATCH solves it: the scheduler can't preempt you,
so no context switch happens on this core while you hold the lock.
Other cores can still run and spin-wait — the holding core will
release quickly.

Rules for SpinLock-protected code:
- Keep it short — you're blocking the scheduler on this core
- No page faults — you're at DISPATCH
- No waits — no mutex, event, or dispatcher object
- Allocate from non-paged pool only

Violate these: IRQL_NOT_LESS_OR_EQUAL (0xA) or SPIN_LOCK_ALREADY_OWNED
(0xF).

EDR kernel components protect their callback lists and detection data
with SpinLocks. Inside the lock, they can't do complex operations —
no memory allocation, no file I/O, no network. Heavy analysis gets
deferred to a work item at PASSIVE_LEVEL, creating a window between
detection and blocking.

## APC injection across processes

User-mode demo in the code: `QueueUserAPC` queues a function to our
own alertable thread. The kernel side is more interesting.

Each KTHREAD has two APC queues:
- **Kernel APC queue** — always processed (can't be blocked by user mode)
- **User APC queue** — processed only during alertable waits

When you call `QueueUserAPC(func, hThread, param)`:
1. Calls `NtQueueApcThread`
2. Kernel allocates a KAPC structure
3. Inserts it into the target thread's user APC queue
4. If the thread is in an alertable wait, it's woken up
5. When APCs are processed, `KiDeliverApc` calls the routine in the
   thread's context

**Cross-process (red team):**

```
1. OpenThread(THREAD_SET_CONTEXT, FALSE, targetTid)
2. VirtualAllocEx in the target process (shellcode)
3. WriteProcessMemory (write shellcode)
4. QueueUserAPC(shellcodeAddr, hThread, 0)
   OR
   NtQueueApcThreadEx(hThread, 1, shellcodeAddr, ...) ← "special user APC"
```

The special user APC doesn't need an alertable wait — it fires at the
next kernel-to-user transition. This is what early bird injection uses:

```
1. CreateProcess(..., CREATE_SUSPENDED, ...)
2. Write shellcode into the new process
3. NtQueueApcThreadEx on the suspended initial thread
4. ResumeThread → thread starts → APC fires before main()
```

Kernel APC injection from a driver:

```c
KAPC *apc = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(KAPC), 'cpAK');
KeInitializeApc(apc, targetThread, OriginalApcEnvironment,
                KernelApcRoutine, NULL, UserApcRoutine,
                UserMode, context);
KeInsertQueueApc(apc, sysarg1, sysarg2, 0);
```

Detection: ETW logs APC operations (requires PPL), EDR hooks on
NtQueueApcThread, stack analysis (APC callback in a RWX allocation),
and cross-process APC from an unexpected source.

## DPCs and I/O completion

When you call `ReadFile` on a disk file:

```
1. ReadFile → NtReadFile → I/O Manager creates IRP_MJ_READ
2. IRP goes down the driver stack → reaches disk driver
3. Disk driver programs the hardware, returns STATUS_PENDING
4. The calling thread waits (or uses IOCP for async)
5.
   ... time passes, disk DMA completes ...

6. Hardware fires interrupt → ISR at device IRQL
7. ISR acknowledges interrupt, queues a DPC
8. DPC at DISPATCH_LEVEL:
   - Marks the IRP as complete (IoCompleteRequest)
   - Walks the IRP stack calling completion routines
   - If synchronous: signals the event the thread is waiting on
   - If IOCP: queues the completion to the IOCP port
9. IRQL drops to PASSIVE → thread runs → sees the completed I/O
```

Most I/O completions go through a DPC. The DPC bridges "hardware
finished" (device IRQL) and "tell the application" (PASSIVE_LEVEL).

IOCP uses LIFO: the kernel wakes the thread that most recently called
`GetQueuedCompletionStatus`. That thread's cache is still warm. This
is why IOCP servers scale to thousands of connections.

This path explains why minifilters intercept IRPs, not DPCs — the IRP
carries the structured data. The DPC is just the mechanism that
processes it. If you want to intercept file I/O, hook the IRP path.
If you need to understand *when* processing happens (timing attacks,
race conditions), understand the DPC path.

---

A BSOD from a bad pointer at PASSIVE_LEVEL gives you
PAGE_FAULT_IN_NONPAGED_AREA. The same bad pointer at DISPATCH_LEVEL
gives IRQL_NOT_LESS_OR_EQUAL (0xA) — the page fault handler itself
can't run at that IRQL. Same root cause, different bugcheck code.
That's why `!analyze -v` always shows the IRQL at the time of the crash.
