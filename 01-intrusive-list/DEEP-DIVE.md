# Deep Dive — LIST_ENTRY in the Windows Kernel

This is where the code from `list.c` connects to the actual kernel.

## ActiveProcessLinks: the process chain

Every process on a Windows system has an `EPROCESS` structure in kernel memory. Inside it:

```
+0x000  Pcb                : _KPROCESS
...
+0x448  ActiveProcessLinks : _LIST_ENTRY    ← this field
...
+0x5a8  ImageFileName      : [15] UChar
```

The offsets above are for Windows 10 x64 22H2. They shift between builds — always verify with `dt nt!_EPROCESS` in WinDbg.

`ActiveProcessLinks` is a `LIST_ENTRY`. It works exactly like the `Link` field in our `EMPLOYEE` struct. The global list head is `nt!PsActiveProcessHead`, a kernel variable that plays the same role as our `Head`.

### WinDbg: walk the process list yourself

Attach a kernel debugger to your test VM and run:

```
kd> dt nt!_EPROCESS ActiveProcessLinks ImageFileName
   +0x448 ActiveProcessLinks : _LIST_ENTRY
   +0x5a8 ImageFileName      : [15] UChar
```

This confirms the offsets. Now get the list head:

```
kd> ? nt!PsActiveProcessHead
Evaluate expression: -8773698655024 = fffff805`1dc47550
```

Walk the list manually:

```
kd> dl fffff805`1dc47550
fffff805`1dc47550  ffff9a0a`12345448  ffff9a0a`56789448
ffff9a0a`12345448  ffff9a0a`abcde448  fffff805`1dc47550
...
```

Each address is a `LIST_ENTRY` at offset `+0x448` inside an `EPROCESS`. To get the `EPROCESS` base, subtract the offset:

```
kd> dt nt!_EPROCESS ImageFileName (ffff9a0a`12345448 - 0x448)
   +0x5a8 ImageFileName : [15] "System"
```

That subtraction is exactly `CONTAINING_RECORD(Current, EPROCESS, ActiveProcessLinks)`.

Or use the shortcut:

```
kd> !list -t _LIST_ENTRY.Flink -x "dt nt!_EPROCESS ImageFileName @$extret-0x448" nt!PsActiveProcessHead
```

## DKOM: what happens when you unlink a node

Direct Kernel Object Manipulation removes an `EPROCESS` from the `ActiveProcessLinks` chain:

```c
// Conceptual — this runs in a kernel driver
LIST_ENTRY *Current = PsActiveProcessHead.Flink;
while (Current != &PsActiveProcessHead) {
    EPROCESS *Process = CONTAINING_RECORD(Current, EPROCESS, ActiveProcessLinks);
    if (Process->UniqueProcessId == TargetPid) {
        RemoveEntryList(Current);
        break;
    }
    Current = Current->Flink;
}
```

After this, `NtQuerySystemInformation(SystemProcessInformation, ...)` — which Task Manager, Process Explorer, and most user-mode tools call — will not see the target process. The process is still running (the scheduler uses a different structure), but it is invisible to anything that walks `ActiveProcessLinks`.

This is the foundation of kernel-level process hiding. Steps 11 (callbacks) and 14 (BYOVD + DKOM) build on it.

## What goes wrong: a real crash

Walking `ActiveProcessLinks` is dangerous because the list changes while you read it. A process can terminate between the time you read `Current->Flink` and the time you dereference the `EPROCESS`. When that happens:

1. The terminated process's `EPROCESS` may have been partially torn down
2. Fields like `UniqueProcessId` may read as NULL
3. Following a pointer from a torn-down `EPROCESS` (e.g., `ThreadListHead.Flink`) can hit a page that has been freed

The result is a bugcheck:

```
SYSTEM_SERVICE_EXCEPTION (3b)
...
READ_ADDRESS: ffffffffffffffff
```

An address of `0xFFFFFFFFFFFFFFFF` means someone read a field that was set to `-1` as a teardown marker, then tried to use it as a pointer.

The fix in real driver code: acquire `PsLookupProcessByProcessId` or hold the appropriate lock (`PspActiveProcessLock`, which is not exported — one reason DKOM is fragile). Or reference the `EPROCESS` before using it and check that the reference count did not hit zero.

## CONTAINING_RECORD under the hood

The macro:

```c
#define CONTAINING_RECORD(address, type, field) \
    ((type *)((char *)(address) - offsetof(type, field)))
```

This is pointer arithmetic. If `EMPLOYEE.Link` is at offset 16, and you have a pointer to a `LIST_ENTRY` at address `0x1050`, then:

```
EMPLOYEE base = 0x1050 - 16 = 0x1040
```

The cast to `(char *)` ensures the subtraction is in bytes, not in units of `sizeof(LIST_ENTRY)`.

In the kernel, `CONTAINING_RECORD` runs with no safety check. If the `LIST_ENTRY*` does not actually point to a `Link` field inside a valid `type`, the resulting pointer is garbage, and you corrupt or crash whatever you touch next.

## _EX_FAST_REF: a trap in pointer fields

Some kernel fields that look like plain pointers are actually `_EX_FAST_REF` — the low bits encode a reference count:

```
kd> dt nt!_EX_FAST_REF
   +0x000 Object    : Ptr64 Void
   +0x000 RefCnt    : Pos 0, 4 Bits   ← x64: 4 bits (mask 0xF)
   +0x000 Value     : Uint8B
```

To get the real pointer, mask off the low bits: `Value & ~0xF` on x64 (not `~0x7` — that is the x86 mask). Using the wrong mask gives you a pointer that is off by up to 8 bytes, which may appear to work until it does not.

`EPROCESS.Token` is `_EX_FAST_REF`. If you walk `ActiveProcessLinks` and read `Token.Value` without masking, your pointer is wrong.

## Exercises

1. Add an `InsertAfter(LIST_ENTRY *After, LIST_ENTRY *Entry)` function that inserts a node after a specific existing node (not the head).

2. Write a `CountList(LIST_ENTRY *Head)` function. Think about what happens if the list is corrupted (a node's `Flink` points to itself instead of to the next node or the head).

3. The poison values after `RemoveEntryList` in our code are NULL. The Windows checked build uses `0xDEAD00000000DEAD`. Why would a non-zero poison value be more useful for debugging than NULL? (Hint: think about what happens when you try to read offset `+0x5a8` from address 0 versus from `0xDEAD00000000DEAD`.)

4. If `EPROCESS.ActiveProcessLinks` is at offset `+0x448` and you have an `EPROCESS*` at `0xFFFF9A0A12345000`, what is the address of that process's `LIST_ENTRY`? If you then read `Flink` and get `0xFFFF9A0A56789448`, what is the `EPROCESS*` of the next process?
