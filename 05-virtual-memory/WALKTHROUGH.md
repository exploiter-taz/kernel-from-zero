# 05 — Walkthrough: manual page walk in WinDbg

> This is a real page table walk I did on my lab VM, following a virtual
> address through all four translation levels exactly as the CPU does it
> internally. Full article:
> [Virtual Memory & Paging for Exploit Developers](https://medium.com/@exploiter-taz/virtual-memory-paging-for-exploit-devlprs-5f74d0f8d4d0)

---

## Setup

Target process: `cmd.exe` running on the debuggee (Test VM).

```
kd> !process 0 0 cmd.exe
PROCESS ffffd187abc7a080
DirBase: 351d8002
```

`DirBase` = the CR3 register value. CR3 is the CPU's map pointer — it
holds the **physical address** of the PML4 table (the top of the page
table hierarchy). Without CR3, the CPU can't translate a single address.

Strip the flags (low 12 bits) to get the PFN:

```
PFN = DirBase & 0xFFFFFFFFFFFFF000 = 351d8000
```

The last nibble `2` = flags: Present (bit 0 = 1), R/W (bit 1 = 1).

## Context switch into cmd.exe

```
kd> .process /i ffffd187abc7a080
```

Then `g` (Go) — the invasive switch needs the OS to actually run for a
moment to load cmd.exe's CR3 into the CPU. When it breaks back:

```
.reload
```

This rebuilds the symbol/module map for cmd.exe's address space.

```
1: kd> lm m cmd
start             end                 module name
00007ff7`35a20000 00007ff7`35a87000   cmd        (deferred)
```

**Target VA: `00007ff735a20000`** (base of cmd.exe)

## The full walk: VA → PA

Quick verification first — `!vtop` does the entire walk in one shot:

```
1: kd> !vtop 351d8000 00007ff735a20000
Amd64VtoP: Virt 00007ff735a20000, pagedir 00000000351d8000
Amd64VtoP: PML4E 00000000351d87f8
Amd64VtoP: PDPE  0000000038364ee0
Amd64VtoP: PDE   0000000037c65d68
Amd64VtoP: PTE   000000001e5e6100
Amd64VtoP: Mapped phys 0000000070005000
Virtual address 7ff735a20000 translates to physical address 70005000
```

Now we do it by hand, level by level.

---

## Level 4: PML4E

The CPU takes the VA and splits it:

```
VA: 00007ff735a20000

Binary (48 bits used):
0000 0000 0000 0000 0111 1111 1111 0111 0011 0101 1010 0010 0000 0000 0000 0000

Split:
  PML4 index  (bits 47-39):  0 1111 1111  = 0xFF  (255)
  PDPT index  (bits 38-30):  0 1110 1110  = 0xEE  (238)
  PD index    (bits 29-21):  1 1010 1101  = 0x1AD (429)
  PT index    (bits 20-12):  0 0010 0000  = 0x20  (32)
  Offset      (bits 11-0):   0000 0000 0000 = 0x000
```

PML4 table starts at PFN `351d8000`. Each entry is 8 bytes.
PML4E address = `351d8000 + (0xFF * 8)` = `351d87f8`

```
1: kd> !dq 351d87f8
#351d87f8 8a000000`38364867
```

### Decoding the PML4E: `8a00000038364867`

```
PFN   = 38364000  (bits 51:12 → physical address of the PDPT)
Flags = 867

867 in binary = 1000 0110 0111
  Bit 0  P     = 1  → Present (page is in RAM)
  Bit 1  R/W   = 1  → Writable
  Bit 2  U/S   = 1  → User mode accessible
  Bit 5  A     = 1  → Accessed (CPU has used this entry)
  Bit 6  (ign) = 1
  Bit 63 NX    = 1  → No Execute at this level
```

**Confirmation:** PFN `38364` matches the PDPE address `0000000038364ee0` ✓

**Exploit relevance:** U/S = 1 means this is user-mode memory. If this
bit were 0, user-mode code couldn't touch it — that's the hardware
boundary between Ring 3 and Ring 0. Kernel exploits that flip this bit
gain access to supervisor pages.

---

## Level 3: PDPE

PDPT table at physical `38364000`. Entry index = `0xEE`.
PDPE address = `38364000 + (0xEE * 8)` = `38364ee0`

```
1: kd> !dq 38364ee0
#38364ee0 0a000000`37c65867
```

### Decoding: `0a00000037c65867`

```
PFN   = 37c65000
Flags = 867  (same as PML4E: Present, R/W, User, Accessed)
```

**Confirmation:** PFN `37c65` matches PDE address `0000000037c65d68` ✓

---

## Level 2: PDE

Page Directory at physical `37c65000`. Entry index = `0x1AD`.
PDE address = `37c65000 + (0x1AD * 8)` = `37c65d68`

```
1: kd> !dq 37c65d68
#37c65d68 0a000000`1e5e6867
```

### Decoding: `0a0000001e5e6867`

```
PFN   = 1e5e6000
Flags = 867  (Present, R/W, User, Accessed)
```

**Confirmation:** PFN `1e5e6` matches PTE address `000000001e5e6100` ✓

---

## Level 1: PTE — the final level

Page Table at physical `1e5e6000`. Entry index = `0x20`.
PTE address = `1e5e6000 + (0x20 * 8)` = `1e5e6100`

```
1: kd> !dq 1e5e6100
#1e5e6100 81000000`70005025
```

### Decoding: `8100000070005025`

```
PFN   = 70005000  → THE PHYSICAL ADDRESS OF THE PAGE
Flags = 025

025 in binary = 0000 0010 0101
  Bit 0  P     = 1  → Present
  Bit 1  R/W   = 0  → READ-ONLY
  Bit 2  U/S   = 1  → User mode
  Bit 5  A     = 1  → Accessed
  Bit 63 NX    = 1  → No Execute
```

**This is cmd.exe's code page. The flags make perfect sense:**
- Read-only (R/W = 0): you can't patch code by writing to it
- No Execute... wait. NX = 1 on a code page? That's the PTE-level NX.
  The `.text` section's execution permission comes from the combination
  of all levels — if **any** level sets NX, execution is blocked. The
  actual execute permission for `.text` is set through the section's
  VAD entry and reflected in the final effective permission. The `!pte`
  command shows the effective result.

**Confirmation:** PFN `70005000` matches the `!vtop` result ✓

---

## The complete translation

```
VA 00007ff735a20000  (cmd.exe base)

   PML4E @ 351d87f8  → PFN 38364000  flags: P|RW|U|A|NX
   PDPE  @ 38364ee0  → PFN 37c65000  flags: P|RW|U|A|NX
   PDE   @ 37c65d68  → PFN 1e5e6000  flags: P|RW|U|A|NX
   PTE   @ 1e5e6100  → PFN 70005000  flags: P|R|U|A|NX

PA = 70005000 + offset 000 = 70005000

4 tables, 4 lookups, 1 physical address.
The CPU does this millions of times per second.
I did it once, by hand.
That's the difference between knowing paging and understanding it.
```

---

## What this proves for exploit development

| What I touched | Why it matters |
|----------------|---------------|
| **CR3 → PML4** | If you control CR3, you control the entire address translation. Kernel exploit primitive: write your own PML4 → read/write anything. |
| **PFN at each level** | PFN Swapping: replace a PFN in a PTE to point at a different physical page. Map kernel memory into user space. |
| **R/W bit** | Flipping R/W on a code page = write to .text = patch any instruction. Kernel exploits that flip this bit bypass W^X. |
| **U/S bit** | Flipping U/S on a kernel page = user-mode code can read kernel data. This is what SMEP/SMAP protect against. |
| **NX bit** | Clearing NX on a data page = execute shellcode there. This is what DEP prevents and ROP bypasses. |
| **Present bit** | Clearing P = page becomes "not present" = next access triggers #PF. Guard pages use this for honeypot traps. |

Every modern kernel exploit — from pool overflow to arbitrary write to
PFN swap — eventually touches one of these bits. The page table isn't
just a translation mechanism. It's the enforcement layer for every
memory protection that exists.

---

## Connection to other steps

- CR3 switch on context switch → step 04 (scheduler changes CR3)
- U/S bit = Ring 3 vs Ring 0 boundary → step 02 (syscall crosses this)
- NX bit = DEP enforcement → step 13 (HEVD bypass needs ROP)
- PFN manipulation → step 14 (DKOM-level memory attacks)
- Guard pages → step 05 DEEP-DIVE Q1 (page fault types)
- TLB flush on CR3 change → step 04 (why KPCR uses `swapgs` not CR3)
