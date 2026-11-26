# Page Table Entry (PTE)

> Reference card — the 8-byte structure that controls every memory
> protection in the system.

---

An 8-byte (64-bit) entry in the Page Table (Level 1 of the page walk).
Every 4 KB page has exactly one PTE. It holds the PFN (which physical
page this virtual page maps to) and permission bits (what the CPU
allows). The CPU reads the PTE before every memory access — if the
bits say no, the instruction doesn't happen.

```
Bit layout (x64):

  63    62:52    51:12              11:9   8  7  6  5  4   3   2   1  0
 ┌───┬────────┬──────────────────┬──────┬──┬──┬──┬──┬───┬───┬───┬───┬──┐
 │NX │  Avail │  PFN (40 bits)   │ Avail│ G│PAT│ D│ A│PCD│PWT│U/S│R/W│ P│
 └───┴────────┴──────────────────┴──────┴──┴──┴──┴──┴───┴───┴───┴───┴──┘
```

All hardware memory protection lives here — DEP/NX (bit 63), read-only
code (bit 1), user vs. kernel isolation (bit 2), page presence (bit 0).
Without the PTE, there's no isolation between processes, no DEP, no
SMEP, no W^X.

---

## The critical bits

### Bit 0: Present (P)

| Value | Meaning |
|-------|---------|
| 1 | Page is in RAM. CPU proceeds with the access. |
| 0 | Page is NOT in RAM. CPU raises #PF (Page Fault). |

**What happens on P = 0:**
- If the page is in the pagefile → OS loads it back to RAM (demand paging)
- If the page was never committed → ACCESS_VIOLATION
- If it's a guard page → STATUS_GUARD_PAGE_VIOLATION
- If IRQL ≥ DISPATCH_LEVEL → IRQL_NOT_LESS_OR_EQUAL (BSOD 0xA)

**Red team:** Guard pages (P = 0 with special marking) are honeypot
traps between the stack and other regions. Stack-based shellcode that
overruns hits the guard page and crashes. Some exploits use guard page
exceptions deliberately to redirect execution through VEH/SEH.

---

### Bit 1: Read/Write (R/W)

| Value | Meaning |
|-------|---------|
| 0 | Read-only. Write attempt → #PF. |
| 1 | Read and write allowed. |

**Where you see R/W = 0:**
- `.text` section (code) — read-only, so you can't patch instructions
- Copy-on-Write pages — shared between processes until one writes,
  then the OS makes a private copy (COW fault)
- Read-only data sections

**Red team:** Flipping R/W from 0 to 1 on a code page = you can patch
any instruction in memory. Kernel exploits that achieve arbitrary PTE
write use this to disable W^X: make a data page writable AND executable
by also clearing NX.

**Blue team:** Code Integrity checks (HVCI) prevent unsigned modification
of kernel code pages. Even if you flip R/W, the hypervisor catches it.

---

### Bit 2: User/Supervisor (U/S)

| Value | Meaning |
|-------|---------|
| 0 | Supervisor (Ring 0 only). User-mode access → #PF. |
| 1 | User mode (Ring 3) can access. |

**This is THE boundary between user mode and kernel mode in hardware.**

Every kernel page has U/S = 0. Every user page has U/S = 1. When your
code runs at Ring 3 and touches an address where U/S = 0, the CPU
doesn't even ask the OS — it faults immediately.

**Red team:** Kernel exploit goal: flip U/S on a kernel page from 0 to 1
→ user-mode code can now read kernel memory (tokens, EPROCESS, driver
data). This is what SMEP and SMAP were invented to prevent:

| Protection | What it blocks |
|-----------|---------------|
| **SMEP** (Supervisor Mode Execution Prevention) | Kernel can't **execute** pages where U/S = 1 (user pages) |
| **SMAP** (Supervisor Mode Access Prevention) | Kernel can't **read/write** pages where U/S = 1 |

Before SMEP: allocate RWX in user space, trigger kernel vuln to jump
there → shellcode runs at Ring 0. After SMEP: that jump faults.

---

### Bit 5: Accessed (A)

| Value | Meaning |
|-------|---------|
| 0 | Page has not been read since last clear. |
| 1 | CPU has read this page (set by hardware). |

The OS uses this for working set management: pages that haven't been
accessed recently are candidates for paging out.

**Red team (side channels):** Flush+Reload and Prime+Probe attacks
check the Accessed bit (indirectly, through timing) to detect whether
a specific page was accessed. This is the basis of Meltdown/Spectre
variants.

---

### Bit 6: Dirty (D)

| Value | Meaning |
|-------|---------|
| 0 | Page has not been written to. |
| 1 | Page has been modified (set by hardware). |

The OS uses this to decide whether a page needs to be written back to
disk when paged out. If D = 0, the page can be discarded (the copy on
disk is still valid).

**Forensics:** A page with D = 1 that's backed by a DLL file means the
page was modified in memory (module stomping, IAT hooking, code
patching). Forensic tools flag Image-backed pages with D = 1 as
potentially tampered.

---

### Bit 8: Global (G)

| Value | Meaning |
|-------|---------|
| 0 | Normal — flushed from TLB on CR3 change. |
| 1 | Stays in TLB across CR3 changes (context switches). |

Used for kernel pages that are the same in every process. Keeps them
cached for performance.

**Red team (Meltdown):** Meltdown worked because speculative execution
accessed kernel pages through the TLB before the permission check
completed. The CPU speculatively used the cached translation (G = 1,
still in TLB) and read kernel data into a cache line. Then it faulted —
but the cache line remained, and a timing attack could extract the data.

**KPTI** (Kernel Page Table Isolation) was the fix: separate page tables
for user and kernel, so kernel pages aren't even mapped when in user
mode. This forced full TLB flushes on every kernel entry/exit, which
hurt performance. **PCID** (Process Context Identifiers) partially
recovered that performance by tagging TLB entries per-process.

---

### Bit 63: No Execute (NX / XD)

| Value | Meaning |
|-------|---------|
| 0 | Execution allowed. |
| 1 | Execution forbidden. Attempt → #PF with error code bit 4 = 1. |

**This is DEP in hardware.** Before NX: the stack was RWX, shellcode
ran directly. After NX: the stack is RW + NX, and jumping to shellcode
on the stack faults.

**Red team response:** ROP (Return-Oriented Programming). Instead of
injecting new code, chain existing executable code snippets (gadgets)
that end with `ret`. Each gadget does one small thing, and the chain
accomplishes the payload. The gadgets are in .text sections where NX = 0.

**Modern evasion:** The two-step pattern (step 05 code):
1. Allocate RW (NX = 1 in PTE) → write shellcode
2. VirtualProtect to RX (NX = 0, R/W = 0) → execute

No page is ever RWX. Some EDRs now monitor the NX bit flip.

---

## PFN — Page Frame Number (bits 51:12)

The 40-bit physical page address. This is what the CPU uses to find
the actual data in RAM.

```
Physical Address = (PTE.PFN << 12) | Offset
```

Shift left by 12 because pages are 4096 bytes (2^12). The PFN is the
page number, not the byte address.

### PFN Swapping (exploit primitive)

If you can write to a PTE, replace its PFN with a different page's PFN.
Now the virtual address maps to a different physical page.

**Use case:** Map a kernel page into user space by writing a kernel
PFN into a user-accessible PTE. User-mode code can now read/write
kernel memory through that virtual address.

**Detection:** PatchGuard (KPP) periodically checks critical page table
entries. HVCI validates page table modifications through the hypervisor.

---

## The page walk (from my WinDbg session)

```
VA 00007ff735a20000  (cmd.exe base address)

Level 4: PML4E @ 351d87f8  → PFN 38364  flags: P|RW|U|A|NX
Level 3: PDPE  @ 38364ee0  → PFN 37c65  flags: P|RW|U|A|NX
Level 2: PDE   @ 37c65d68  → PFN 1e5e6  flags: P|RW|U|A|NX
Level 1: PTE   @ 1e5e6100  → PFN 70005  flags: P|R|U|A|NX
                                           (R/W = 0: read-only code)

Physical Address = 70005000
```

Every level confirmed manually. PFN at each level matches the address
of the next table. Theory meets reality.

See [WALKTHROUGH.md](WALKTHROUGH.md) for the full step-by-step session.

---

## Related

- Full article: [Virtual Memory & Paging for Exploit Developers](https://medium.com/@exploiter-taz/virtual-memory-paging-for-exploit-devlprs-5f74d0f8d4d0)
- Step 02 — syscall crosses the U/S boundary (Ring 3 → Ring 0)
- Step 04 — CR3 changes on context switch, TLB flush, IRQL and page faults
- Step 05 — memory-inspector.c and DEEP-DIVE Q1 (page fault types)
- Step 13 — HEVD exploitation needs ROP (NX bypass) and pool corruption
- Step 14 — PFN swap and DKOM-level memory attacks
