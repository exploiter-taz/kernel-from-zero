# 05 — Deep dive: virtual memory, page faults, and what EDR sees

---

## The page fault

When code accesses a virtual address that isn't present in physical RAM:

```
1. CPU walks the page tables → PTE says "not present"
2. CPU raises exception #14 (Page Fault)
3. KiPageFault runs (kernel trap handler)
4. Checks CR2 (the faulting address) and the error code (read/write/exec)
5. Calls MmAccessFault → the Memory Manager takes over
```

MmAccessFault decides what kind of fault this is:

**Demand-zero:** page committed (VAD says so) but never touched.
Allocate a physical page, zero it, map it in the PTE, return. CPU
retries the instruction.

**Pagefile:** page was in RAM, got paged out to disk. Schedule a read,
thread waits on STATUS_PENDING, I/O completes, page is back in RAM,
update PTE, resume.

**Mapped file:** page is part of a file mapping (DLL code, data file).
Same flow: read from the file, map, resume.

**Guard page:** page has PAGE_GUARD protection. Raise
STATUS_GUARD_PAGE_VIOLATION, remove the guard flag, next access works.
Used by: stack growth (auto-commit), VEH-based shellcode.

**Access violation:** address is not committed (VAD says Free/Reserved)
or protection doesn't allow this access (write to read-only, exec on
NX). STATUS_ACCESS_VIOLATION → crash (or SEH/VEH handler).

**IRQL too high:** fault at DISPATCH_LEVEL or above. Can't page in
(needs I/O, needs waiting, needs the scheduler).
KeBugCheck(IRQL_NOT_LESS_OR_EQUAL) — 0x0000000A.

Red team connections: guard page shellcode allocates PAGE_GUARD,
registers a VEH, triggers the exception, decrypts and executes the
payload — the EDR's VirtualAlloc hook saw a guard page, not shellcode.
Pagefile forensics: if your shellcode gets paged out before you zero
and free it, it's in the pagefile on disk. Module stomping: when you
overwrite a DLL's pages, Windows marks them as "modified" and they
become pagefile-backed instead of file-backed — some forensic tools
detect this transition.

## The RW→RX two-step and what catches it

Classic injection:
```
VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
WriteProcessMemory(hProcess, addr, shellcode, size, NULL)
CreateRemoteThread(hProcess, NULL, 0, addr, NULL, 0, NULL)
```

The RWX allocation is the loudest signal. PAGE_EXECUTE_READWRITE in a
VirtualAlloc is logged by most EDRs.

Two-step evasion:
```
VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
WriteProcessMemory(hProcess, addr, shellcode, size, NULL)
VirtualProtectEx(hProcess, addr, size, PAGE_EXECUTE_READ, &oldProt)
CreateRemoteThread(hProcess, NULL, 0, addr, NULL, 0, NULL)
```

No RWX page ever exists. Starts RW (write shellcode), becomes RX
(execute shellcode).

What catches it:
1. **VirtualProtect monitoring** — EDR watches NtProtectVirtualMemory.
   RW → RX (gaining execute) is flagged, especially cross-process.
2. **VAD analysis** — the VAD records original and current protection.
   Private region that started RW and is now RX is suspicious.
3. **Page content inspection** — EDR reads page contents at
   protection-change time. Known shellcode patterns get matched.
4. **Timing correlation** — VirtualAllocEx + WriteProcessMemory +
   VirtualProtectEx + CreateRemoteThread in sequence, targeting a
   remote process, is the injection pattern regardless of protections.

More advanced evasion: module stomping (pages already RX, no protection
change), NtCreateSection + NtMapViewOfSection (mimics a DLL load),
atom bombing, process hollowing, early bird.

## Kernel pool exploitation

Both paged and non-paged pool are kernel heap regions.

**Non-paged pool** — always in RAM, deterministic access. Used for
objects at DISPATCH_LEVEL (IRPs, MDLs). Pool headers and free lists
can be corrupted via overflow. Pool feng shui: manipulate
allocation/free patterns to place a specific object adjacent to your
overflow buffer, then corrupt its fields (Token, function pointer).
Mitigations: pool header cookies (Win8), NonPagedPoolNx (NX on pool,
can't execute from it directly).

**Paged pool** — can be paged out. Same overflow/feng shui applies but
different objects (registry data, security descriptors, object names).
Less targeted because the interesting objects tend to be non-paged.

| Version | What changed |
|---------|-------------|
| Win 7   | Pool headers, free lists, no pool NX |
| Win 8   | Pool header cookies (canary), pool quota enforcement |
| Win 8.1 | NonPagedPoolNx — most allocations are NX by default |
| Win 10  | Segment heap for pool, guard pages on some pools |
| Win 11  | kCFG + XFG in pool function pointers |

Modern pool exploitation is hard. The easy corruption techniques are
blocked by NX pool + kCFG. Current techniques focus on data-only
attacks: corrupt a pointer or size field to get arbitrary read/write,
then use that for token manipulation (step 08) or page table corruption.

## ASLR and what breaks it

On process creation, the kernel randomizes image base, stack, heap,
and PEB/TEB. DLLs with `/DYNAMICBASE` support relocation. Kernel ASLR
randomizes ntoskrnl.exe and driver bases at boot.

ASLR is useless if the attacker can read a pointer:

| Leak source | What it reveals |
|-------------|----------------|
| **Format string bug** | Stack contents → return addresses → module bases |
| **Out-of-bounds read** | Adjacent memory → pointers to heap/stack/modules |
| **NtQuerySystemInformation class 11** | Kernel module base addresses — from user mode |
| **Timing side channels** | Cache timing can distinguish mapped vs. unmapped |
| **Partial overwrite** | Only overwrite 2 bytes of a pointer → limited brute-force |

Class 11 is the big one for kernel ASLR. Any user-mode process can call
`NtQuerySystemInformation(SystemModuleInformation)` and get every kernel
module's base address. This completely defeats kernel ASLR for a local
attacker. Microsoft added restrictions in some builds (requiring medium
integrity), but it's still accessible in many configurations. This is
why kernel exploits often start with that call: "where is ntoskrnl?" →
compute ROP gadget addresses → exploit.
