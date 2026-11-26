# 06 — Objects and Handles

Every kernel resource — files, processes, threads, tokens, events,
mutexes — is tracked through a unified object system. User-mode code
references these objects through handles. `CloseHandle` doesn't mean
"destroy", `_EX_FAST_REF` will crash your driver if you mask wrong,
and handle duplication is one way to bypass EDR.

## The object model

Every kernel resource is an object: a chunk of kernel memory with a
common header and a type-specific body.

```
┌────────────────────────────────┐
│ OBJECT_HEADER                  │  ← same for all objects
│   PointerCount (kernel refs)   │
│   HandleCount (user refs)      │
│   TypeIndex → OBJECT_TYPE      │
│   SecurityDescriptor           │
│   ObjectName (optional)        │
├────────────────────────────────┤
│ OBJECT BODY                    │  ← type-specific
│   (FILE_OBJECT, EPROCESS,      │
│    ETHREAD, EVENT, TOKEN, etc.)│
└────────────────────────────────┘
```

One system for everything. The Object Manager (`Ob` prefix) handles
create, reference, dereference, name, secure, destroy — same logic
for every type.

## Handles

A handle is a small integer (4, 8, 12, 16, ...) that indexes into the
process's handle table — a per-process kernel structure.

```
Process A's handle table:                   Kernel memory:
┌─────────┬──────────────┬────────────┐
│ Handle  │ Object ptr   │ Access     │    ┌──────────────┐
├─────────┼──────────────┼────────────┤    │ FILE_OBJECT  │
│  0x04   │ ──────────────────────────────→│ (notepad.exe)│
├─────────┼──────────────┼────────────┤    └──────────────┘
│  0x08   │ ──────────────────────────────→┌──────────────┐
├─────────┼──────────────┼────────────┤    │ EPROCESS     │
│  0x0C   │ ──────────────────────────────→│ (child proc) │
└─────────┴──────────────┴────────────┘    └──────────────┘
```

User code never touches kernel pointers. The kernel validates
handle + access mask on every call. Handle 4 in process A is a
different object than handle 4 in process B.

## The two refcounts

| Count | Incremented by | Decremented by | Meaning |
|-------|---------------|----------------|---------|
| **HandleCount** | Opening/creating a handle | CloseHandle | Handles across all processes |
| **PointerCount** | ObReferenceObject (kernel code) | ObDereferenceObject | Kernel references (always >= HandleCount) |

Both must reach 0 for the object to be destroyed:

```
                    HandleCount  PointerCount  Alive?
OpenProcess:            1            2          yes
Kernel ref:             1            3          yes
CloseHandle:            0            2          yes  (kernel still refs it)
ObDereferenceObject:    0            1          yes
ObDereferenceObject:    0            0          DESTROYED
```

## Handle-based attacks

| Technique | Detail |
|-----------|--------|
| **OpenProcess to LSASS** | `OpenProcess(PROCESS_VM_READ)` → `ReadProcessMemory` → dump credentials. EDR's #1 detection: who opens a handle to LSASS? |
| **Handle duplication** | If process A has a handle to LSASS, and you have `PROCESS_DUP_HANDLE` on A, you can `DuplicateHandle` it into your process — without ever calling OpenProcess on LSASS. Bypasses ObRegisterCallbacks. |
| **Handle inheritance** | Child inherits parent's handles if `bInheritHandles = TRUE`. Malware passes sensitive handles to children. |
| **NtQuerySystemInformation class 64** | Enumerate ALL handles in the system. Find who has an interesting handle and duplicate it. |
| **Handle stripping** | EDR uses ObRegisterCallbacks to strip access bits. Your OpenProcess "succeeds" but the handle can't do VM read/write. |

Handles are per-process. Protected Process Light (PPL) blocks
OpenProcess even from admin. The handle table is in kernel memory and
can't be tampered with from user mode. Max handles per process: ~16M.

## _EX_FAST_REF

A 64-bit value that packs a pointer and a reference count into one word.
Used for frequently-accessed pointers like EPROCESS.Token.

```
x64 layout:
┌──────────────────────────────────────────────┬──────┐
│         Pointer (bits 63-4)                  │RefCnt│
│                                              │(0-15)│
└──────────────────────────────────────────────┴──────┘

To get the pointer:  value & ~0xF   (mask off low 4 bits)
To get the refcount: value & 0xF
```

One `cmpxchg` can update both — no separate lock needed. The
CallbackRemoval driver used `~0x7` (the x86 mask) instead of `~0xF`
(x64). Bit 3 of the refcount leaked into the pointer → address off by
8 → `PAGE_FAULT_IN_NONPAGED_AREA`.

```
Value:   0xFFFF9A80123456F7
Correct: & ~0xF = 0xFFFF9A80123456F0  ← valid token pointer
Wrong:   & ~0x7 = 0xFFFF9A80123456F8  ← if refcount bit 3 = 1 → BAD
```

## Object Manager namespace

```
\                         Root
├── Device\               Device objects
│   ├── HarddiskVolume1
│   └── Tcp
├── Driver\               Driver objects
├── ??\                   Symbolic links (C: → \Device\HarddiskVolume3)
├── BaseNamedObjects\     Named events, mutexes, sections
├── KernelObjects\        Kernel-internal named objects
└── ObjectTypes\          Type objects (Process, Thread, File, ...)
```

Malware creates named mutexes to prevent double execution. Blue team:
scan `\BaseNamedObjects` for known mutex names. Device namespace is how
drivers become reachable: `\Device\MyDriver` + `\??\MyDriver` →
user code opens `\\.\MyDriver`.

## The code

`handle-inspector.c` demonstrates:

1. **Handle lifecycle** — create an event → duplicate → close first
   (object survives) → close second (destroyed)
2. **Handle duplication** — duplicate a file handle, prove both point
   to the same file object
3. **_EX_FAST_REF** — the x86 vs x64 mask difference
4. **Object Manager namespace** — the tree and common directories
5. **Handle enumeration** — NtQuerySystemInformation class 64

## WinDbg

```
; Handle table
0: kd> !process 0 0 notepad.exe
0: kd> !handle 0 7 <process address>

; Object header
0: kd> !object <object address>
0: kd> dt nt!_OBJECT_HEADER <address - sizeof(OBJECT_HEADER)>

; Namespace
0: kd> !object \
0: kd> !object \Device
0: kd> !object \BaseNamedObjects

; _EX_FAST_REF on a process token
0: kd> dt nt!_EPROCESS Token <eprocess_addr>
0: kd> ? <value> & ~0xf
0: kd> dt nt!_TOKEN <masked pointer>

; ObRegisterCallbacks (EDR hook point)
0: kd> !obcallbacks
```
