# 03 - Deep dive: MSRs, syscall interception, and SMEP bypass

---

## LSTAR hooking

IA32_LSTAR holds the address of KiSystemCall64. Every syscall in the
entire system passes through that single address. If you can wrmsr
0xC0000082, you can redirect every syscall to your own handler.

The classic rootkit approach:

```
1. rdmsr 0xC0000082 → save original KiSystemCall64 address
2. Write a trampoline in non-paged kernel memory:
     - Check syscall number in EAX
     - If it's the one you want (NtOpenProcess, NtReadVirtualMemory...),
       log it, modify arguments, or return fake results
     - Otherwise, jump to the saved KiSystemCall64
3. wrmsr 0xC0000082, trampoline address
4. Every syscall now hits your code first
```

This is system-wide. Not per-process, not per-thread. Every core uses
the same LSTAR value (Windows writes the same address to all cores
during boot). To hook all cores, you need to run wrmsr on each one
(via DPC or KeIpiGenericCall).

Detection: PatchGuard (KPP) periodically reads IA32_LSTAR and compares
it against the expected KiSystemCall64. If it doesn't match, bugcheck
0x109 (CRITICAL_STRUCTURE_CORRUPTION). PatchGuard's check interval is
randomized (5-10 minutes). There's a window between the hook and the
check.

Hypervisor-based detection (Credential Guard, HVCI) can trap wrmsr
through VMCS MSR bitmaps. The hypervisor intercepts the write before
it reaches the actual MSR. This is significantly harder to bypass than
PatchGuard.

## SMEP/SMAP bypass through CR4

SMEP (bit 20) and SMAP (bit 21) in CR4 are the hardware barriers
between kernel and user memory.

```
SMEP on:  kernel tries to execute user-mode page → #PF
SMEP off: kernel executes user-mode page → works

SMAP on:  kernel tries to read/write user-mode page → #PF
SMAP off: kernel reads/writes user-mode page → works
```

If you have an arbitrary write to CR4 (or wrmsr on a register that
controls these bits), clearing bit 20 brings back the pre-SMEP world.
Allocate RWX in user space, write shellcode, trigger a kernel bug to
call your user-mode address. Without SMEP, the CPU doesn't care.

The practical chain:

```
1. BYOVD driver gives you wrmsr or CR4 write
2. Read current CR4 → 0x...B50EF8 (SMEP and SMAP set)
3. Clear bits 20-21 → 0x...950EF8
4. Write new CR4
5. Now: allocate user-mode RWX page
6. Write kernel shellcode (token theft, callback removal)
7. Trigger kernel code path that jumps to user address
8. Shellcode runs at Ring 0 from user pages
9. Restore CR4 (put SMEP/SMAP back)
```

PatchGuard also monitors CR4. Same window problem as LSTAR hooking.
HVCI traps CR4 writes through the hypervisor (VM exits on CR access).
With HVCI enabled, this technique is dead.

Modern exploits skip SMEP bypass entirely. Instead of executing from
user pages, they use data-only attacks: overwrite a token pointer or a
function pointer in kernel memory. No code execution from user space
needed, so SMEP and SMAP don't matter.

## swapgs and the KPCR attack surface

The first instruction in KiSystemCall64 is `swapgs`. It trades the
user GS base (TEB) for the kernel GS base (KPCR) stored in
IA32_KERNEL_GS_BASE (0xC0000102).

If you wrmsr 0xC0000102 with a pointer to memory you control, then
trigger a syscall, the kernel's `swapgs` loads YOUR address as the GS
base. Every `gs:[offset]` reference after that reads your controlled
memory.

The kernel immediately does:
```asm
swapgs
mov  gs:[0x6000], rsp      ; save user RSP
mov  rsp, gs:[0x6008]      ; load kernel RSP
```

If GS points to your buffer, the kernel saves RSP to your buffer and
loads a new RSP from your buffer. You control the kernel stack pointer.
That's arbitrary code execution (ROP from your controlled stack).

This is why IA32_KERNEL_GS_BASE is guarded as heavily as LSTAR.
PatchGuard checks it. HVCI traps wrmsr on it.

In practice, you're more likely to read the KPCR through it than to
attack it. If you have rdmsr on 0xC0000102, you get the KPCR address
for the current processor. From the KPCR:

```
KPCR.Prcb.CurrentThread → KTHREAD → EPROCESS → Token
```

That's a full chain from one MSR read to the token address. You still
need a kernel read primitive to follow the pointers, but you have your
starting point without any NtQuerySystemInformation call, which EDR
monitors.

## rdmsr/wrmsr as BYOVD primitives

Step 02 covered how BYOVD drivers expose arbitrary kernel read/write
through IOCTLs. Some drivers go further and expose rdmsr/wrmsr directly.

From the step 02 IOCTL table:

```
AsrDrv101.sys:  IOCTL 0x222808  → arbitrary read (virtual + physical + MSR)
WinRing0x64.sys: IOCTL 0x9C402084 → MSR read
```

The driver's IOCTL handler looks like this:

```c
case IOCTL_READ_MSR:
{
    PMSR_REQUEST req = (PMSR_REQUEST)Irp->AssociatedIrp.SystemBuffer;
    req->Value = __readmsr(req->Register);
    // ...
}

case IOCTL_WRITE_MSR:
{
    PMSR_REQUEST req = (PMSR_REQUEST)Irp->AssociatedIrp.SystemBuffer;
    __writemsr(req->Register, req->Value);
    // ...
}
```

No validation on which MSR you're reading or writing. The driver trusts
the register number from user mode. Same pattern as the arbitrary
read/write vulnerability in step 02, but instead of memory addresses
it's MSR addresses.

What you get from MSR access alone (no memory read/write needed):

| MSR | What you can do |
|-----|----------------|
| IA32_LSTAR | Redirect all syscalls to your handler |
| IA32_KERNEL_GS_BASE | Find the KPCR, derive EPROCESS chain |
| IA32_EFER | Disable NX system-wide (clear bit 11) |
| IA32_DEBUGCTL | Enable LBR to trace kernel execution without breakpoints |
| IA32_APIC_BASE | Remap the APIC for interrupt manipulation |

MSR access + memory read/write together is full system control. But
MSR access alone, without memory primitives, is already enough for
syscall hooking and NX bypass.

## The IA32_EFER NX kill

This is the simplest system-wide protection bypass through a single
wrmsr:

```
1. rdmsr 0xC0000080 → current EFER value (e.g. 0xD01)
2. Clear bit 11:  0xD01 & ~(1 << 11) = 0x101
3. wrmsr 0xC0000080, 0x101
4. NX is now ignored by the CPU on all page table walks
5. Every page in the system is executable
6. Write shellcode anywhere writable, jump to it
```

The page tables still have NX set. `!pte` in WinDbg still shows NX.
But the CPU skips the check because NXE in EFER is 0. No page fault
happens on execute.

This is rarely used in practice because it's loud (PatchGuard, HVCI)
and unnecessary when you have other primitives. But it shows how a
single bit in one register dismantles an entire protection layer.
