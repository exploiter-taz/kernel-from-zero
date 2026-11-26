# 05 — Virtual Memory

## The address space

Every process gets its own virtual address space. On x64:

```
0x0000'00000000 ──────── 0x7FFF'FFFFFFFF     User space (128 TB)
   │  Your code, DLLs, heap, stack, mapped files
   │  Each process has its own mapping (different CR3)
   │
0x8000'00000000 ──────── 0xFFFF'7FFFFFFF     Non-canonical hole
   │  CPU faults if you access this range
   │
0xFFFF'80000000 ──────── 0xFFFF'FFFFFFFF     Kernel space (128 TB)
   │  ntoskrnl, drivers, kernel pool, EPROCESS, page tables
   │  SAME mapping in every process (shared page table entries)
```

Process A's virtual address `0x7FF600000000` maps to one physical page;
process B's same address maps to a different one. The CPU enforces this
through page tables — the kernel switches CR3 (page table base register)
on every context switch.

## Page tables (x64, 4-level)

```
Virtual address (48 bits used):
┌────────┬────────┬────────┬────────┬──────────┐
│ PML4   │ PDPT   │ PD     │ PT     │ Offset   │
│ 9 bits │ 9 bits │ 9 bits │ 9 bits │ 12 bits  │
└────────┴────────┴────────┴────────┴──────────┘

CR3 → PML4 table → PML4 entry[index] → PDPT table →
PDPT entry[index] → PD table → PD entry[index] → PT table →
PT entry[index] → Physical page + Offset = Physical address
```

Each level: 512 entries (9 bits), 8 bytes each. The final entry points
to a 4 KB physical page and carries permission bits (Read/Write,
Execute Disable, User/Supervisor, Present).

The NX bit (Execute Disable) in the PTE is what DEP enforces. If a
page is marked NX and code tries to execute from it →
STATUS_ACCESS_VIOLATION.

## Red team and memory

| Technique | Memory detail |
|-----------|--------------|
| **Shellcode injection** | VirtualAllocEx(RWX) + WriteProcessMemory + CreateRemoteThread. The RWX allocation creates a VAD entry in the target process. |
| **RW→RX two-step** | Allocate RW, write shellcode, VirtualProtect to RX. Avoids the RWX signal. Some EDRs now watch the protect-change pattern too. |
| **Module stomping** | Load a legitimate DLL, overwrite its .text section. Memory type stays MEM_IMAGE, section was already RX. |
| **Pagefile forensics** | Committed pages can be paged out. Memory forensics tools scan the pagefile for shellcode patterns. VirtualLock prevents paging but requires quota. |
| **Guard page shellcode** | Allocate with PAGE_GUARD, trigger exception on access, handle it in a VEH — exception-based execution flow. |

Mitigations:
- ASLR randomizes image base, stack, heap, PEB/TEB on each process start
- CFG restricts indirect call targets
- CET adds a hardware shadow stack
- HVCI prevents kernel-mode RWX and unsigned code

## VADs — Virtual Address Descriptors

The kernel tracks every allocated region in a balanced binary tree (AVL)
stored in the EPROCESS. Each VAD node describes one region: start,
end, protection, type (private / mapped / image), and backing
(pagefile, file, or nothing).

Page tables tell the CPU how to translate addresses. The VAD tree tells
the kernel *why* a region exists — "this was allocated by VirtualAlloc
with RW protection" or "this is a mapped view of kernel32.dll."

```
VirtualAlloc(NULL, 64KB, MEM_RESERVE, PAGE_READWRITE)
    → NtAllocateVirtualMemory
        → MmCreateVad
            1. Find a free range in the VAD tree (64KB aligned)
            2. Create a VAD node: start, end, protection, type=Private
            3. Insert into the AVL tree
            4. For MEM_RESERVE: no page table entries yet
            5. For MEM_COMMIT: also create PTEs (demand-zero)
```

Forensics angle: Volatility's `vadinfo` plugin dumps the entire VAD
tree. Even hidden shellcode has a VAD entry. A region with VAD type
Private + protection RWX + no associated image is almost certainly
injected code. Advanced rootkits unlink VAD entries (like DKOM for
processes), but this risks instability — the Memory Manager expects the
tree to be consistent.

## Kernel pool

The kernel's `malloc`. Drivers and kernel code allocate from two pools:

| Pool | IRQL limit | Pageable? | Use case |
|------|-----------|-----------|----------|
| **Non-paged pool** | Any IRQL | No (always in RAM) | DPC/ISR data, SpinLock-protected structures, MDLs |
| **Paged pool** | PASSIVE or APC only | Yes | Most kernel allocations, object bodies, registry data |

Code at DISPATCH_LEVEL (step 04) can't handle page faults, so any data
accessed there must be in non-paged pool.

```c
// Old API (before Windows 10 2004):
PVOID p = ExAllocatePoolWithTag(NonPagedPool, 256, 'tseT');

// New API:
PVOID p = ExAllocatePool2(POOL_FLAG_NON_PAGED, 256, 'tseT');

// The 4-byte tag helps debugging:
// !poolfind tseT → finds all allocations with that tag
```

Pool overflow is a classic kernel exploit primitive. Pool feng shui
arranges allocations so a specific object is adjacent to your overflow
buffer. When you overflow, you corrupt the adjacent object's fields.
Modern mitigations: pool header cookies (Win8), NonPagedPoolNx (Win8.1),
segment heap (Win10), kCFG/XFG (Win11).

## The code

`memory-inspector.c` demonstrates:

1. **Working set** — physical RAM footprint, page faults, pagefile usage
2. **Allocation lifecycle** — Reserve → Commit → Write → VirtualProtect
   (RW→RX two-step) → Decommit → Release
3. **NtAllocateVirtualMemory** — the Native API behind VirtualAlloc,
   called directly through NTDLL
4. **Memory map** — walks every region with VirtualQuery, shows state,
   protection, type, flags RWX regions

## WinDbg

```
; VAD tree for a process
0: kd> !process 0 0 notepad.exe
0: kd> !vad <VadRoot address from EPROCESS>

; Page table walk for a virtual address
0: kd> !pte <virtual address>

; Kernel pool usage
0: kd> !poolused 2

; Find a specific pool allocation
0: kd> !poolfind Proc

; Working set info
0: kd> !process <address> 1

; Physical memory mapping
0: kd> !pfn <page frame number>
```
