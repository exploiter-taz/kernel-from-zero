# 03 - Model-Specific Registers

MSRs are CPU registers you can't see in a normal register dump. They
control how the processor handles syscalls, memory protection, paging
features, and virtualization. The instructions to access them (rdmsr /
wrmsr) are Ring 0 only. User-mode code can't touch them directly, but
understanding them is mandatory because they define the boundary
between user mode and kernel mode at the hardware level.

Every BYOVD driver that exposes rdmsr/wrmsr gives an attacker control
over these. That's not just a kernel read/write primitive. It's control
over how the CPU itself behaves.

## The syscall path

When user-mode code executes the `syscall` instruction, the CPU doesn't
look at any interrupt table. It reads three MSRs:

| MSR | Address | What it holds |
|-----|---------|---------------|
| IA32_STAR | 0xC0000081 | CS/SS selectors for kernel and user mode |
| IA32_LSTAR | 0xC0000082 | The RIP the CPU jumps to on syscall |
| IA32_FMASK | 0xC0000084 | RFLAGS bits to clear on syscall entry |

IA32_LSTAR is the big one. On a standard Windows install, it points to
`nt!KiSystemCall64`. Every syscall in the system lands there.

```
User mode:                           Kernel mode:
  mov r10, rcx                       KiSystemCall64:
  mov eax, <syscall number>            swapgs
  syscall ──────────────────────────→  mov gs:[...], rsp
     CPU reads IA32_LSTAR               mov rsp, gs:[...]  (kernel stack)
     CPU reads IA32_STAR (CS/SS)        ... look up syscall table ...
     CPU reads IA32_FMASK (clear IF)
```

IA32_STAR packs two pairs of selectors into one 64-bit register:

```
Bits 63:48  →  user CS/SS base    (on sysret)
Bits 47:32  →  kernel CS/SS base  (on syscall)
Bits 31:0   →  (legacy, unused on x64)
```

The kernel sets `STAR[47:32] = 0x0010` (kernel CS = 0x10, SS = 0x18).
On `sysret`, the CPU uses `STAR[63:48] + 16` for CS and `STAR[63:48] + 8`
for SS.

IA32_FMASK controls which RFLAGS bits get cleared on syscall. Windows
sets it to 0x4700, which clears:
- IF (bit 9): interrupts disabled during the first instructions
- DF (bit 10): direction flag cleared for safety
- TF (bit 8): single-step trap disabled
- AC (bit 18): alignment check disabled

## IA32_EFER (Extended Feature Enable Register)

Address: 0xC0000080

| Bit | Name | What it does |
|-----|------|-------------|
| 0 | SCE | Syscall Enable. Without this, the syscall instruction #UDs. |
| 8 | LME | Long Mode Enable. Set during boot to enter 64-bit mode. |
| 10 | LMA | Long Mode Active. Read-only, confirms the CPU is in 64-bit mode. |
| 11 | NXE | No-Execute Enable. Without this, the NX bit in page tables is ignored. |

NXE is the hardware switch for DEP. If you can clear bit 11 through a
wrmsr primitive, every NX page becomes executable. The page tables
still have the NX bit set, but the CPU ignores it. DEP is gone
system-wide.

## swapgs and IA32_KERNEL_GS_BASE

Address: 0xC0000102

On x64 Windows, the GS register in user mode points to the TEB (step 04).
The kernel needs GS to point to the KPCR (Kernel Processor Control Region)
instead. The `swapgs` instruction swaps the current GS base with the
value stored in IA32_KERNEL_GS_BASE.

```
User mode:   GS → TEB             IA32_KERNEL_GS_BASE = KPCR address
                   swapgs
Kernel mode: GS → KPCR            IA32_KERNEL_GS_BASE = TEB address
```

This is why KiSystemCall64 starts with `swapgs` before doing anything
else. Without it, any `gs:[offset]` reference would hit the user's TEB
instead of the KPCR, and the kernel would use a user-controlled stack
pointer.

The KPCR holds per-processor data: the current thread (KPRCB.CurrentThread),
the IDT, the GDT, the IRQL, the DPC queue. Everything the kernel needs
to know about which core it's running on.

```
KPCR (gs:0)
  ├── +0x000  GdtBase
  ├── +0x008  TssBase
  ├── +0x018  IdtBase (Interrupt Descriptor Table)
  ├── +0x180  Prcb (KPRCB starts here)
  │     ├── +0x008  CurrentThread → KTHREAD
  │     ├── +0x010  NextThread
  │     ├── +0x018  IdleThread
  │     ├── +0x004  Number (processor index)
  │     └── ...DpcData, ReadySummary, etc.
```

## CR4 (not an MSR, but the same story)

CR4 is a control register, not an MSR (read with `mov rax, cr4`, not
rdmsr). But BYOVD drivers that expose rdmsr/wrmsr often expose CR4
access too, and it controls two critical protections:

| Bit | Name | What it blocks |
|-----|------|---------------|
| 20 | SMEP | Kernel executing user-mode pages (U/S=1) |
| 21 | SMAP | Kernel reading/writing user-mode pages (U/S=1) |

Before SMEP: allocate RWX in user space, trigger a kernel bug to jump
there, shellcode runs at Ring 0. SMEP made that fault. Before SMAP:
kernel code could freely read user buffers without ProbeForRead, making
double-fetch bugs trivial to exploit.

## Other MSRs

| MSR | Address | Use |
|-----|---------|-----|
| IA32_APIC_BASE | 0x1B | Local APIC base address. Remapping APIC = interrupt control. |
| IA32_FEATURE_CONTROL | 0x3A | VMX enable bit. Must be set before VMXON. |
| IA32_VMX_BASIC | 0x480 | VMX capabilities. Read to understand hypervisor constraints. |
| IA32_DEBUGCTL | 0x1D9 | Branch tracing, last branch records (LBR). |
| IA32_SYSENTER_EIP | 0x176 | 32-bit syscall entry (legacy, still set on x64 for WoW64). |
| IA32_TSC_AUX | 0xC0000103 | RDTSCP reads this alongside the timestamp. OS stores CPU index here. |

## WinDbg

```
; Read IA32_LSTAR (where does syscall land?)
0: kd> rdmsr 0xC0000082
; Should show nt!KiSystemCall64

; Read IA32_EFER (is NX enabled?)
0: kd> rdmsr 0xC0000080
; Bit 11 (NXE) should be 1

; Read IA32_KERNEL_GS_BASE (the KPCR address stored for swapgs)
0: kd> rdmsr 0xC0000102

; Read IA32_STAR (syscall CS/SS selectors)
0: kd> rdmsr 0xC0000081

; Check CR4 for SMEP and SMAP
0: kd> r cr4
; Bit 20 = SMEP, bit 21 = SMAP

; The KPCR itself
0: kd> !pcr
0: kd> dt nt!_KPCR @$pcr

; Current thread from the KPCR
0: kd> dt nt!_KPRCB @$prcb CurrentThread
```
