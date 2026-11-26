# Kernel From Zero

From a doubly linked list to BYOVD exploitation.

A hands-on path through the Windows kernel, built from the ground up. Each step starts with a concept the kernel depends on, implements it in C, then connects it to where the kernel actually uses it. Verified in WinDbg on a live debuggee.

## Why this exists

Most kernel resources explain theory without touching code, or dump driver samples with no context. This does neither.

The first step is a doubly linked list. Not because lists are interesting, but because `LIST_ENTRY` is the backbone of nearly every kernel structure. `EPROCESS.ActiveProcessLinks` chains all processes. `EPROCESS.ThreadListHead` chains their threads. `PsLoadedModuleList` chains loaded drivers. Without understanding intrusive linked lists, nothing else in the kernel makes sense.

That pattern (build it, then find it in the kernel) runs through the entire repository.

## Steps

| Step | What it covers | Code |
|------|---------------|------|
| [01](01-intrusive-list/) | `LIST_ENTRY`, `CONTAINING_RECORD`, intrusive linked lists. The data structure behind every kernel chain | `list.c` |
| [02](02-talking-to-drivers/) | Device handles, `DeviceIoControl`, `CTL_CODE` layout, BYOVD driver scanning. The bridge between user mode and kernel mode | `talk.c` |
| [04](04-threads-and-irql/) | Threads, the TEB, scheduling, IRQL levels, DPCs, APC injection. What the CPU actually runs and why touching paged memory in a DPC blue-screens | `thread-irql-inspector.c` |
| [05](05-virtual-memory/) | Virtual address spaces, 4-level page tables, VADs, kernel pool, the allocation lifecycle, `NtAllocateVirtualMemory` | `memory-inspector.c` |
| [06](06-objects-and-handles/) | The object model, handle tables, dual refcounting, `_EX_FAST_REF`, the Object Manager namespace, system-wide handle enumeration | `handle-inspector.c` |
| [08](08-security-tokens/) | `_TOKEN`, `_SEP_TOKEN_PRIVILEGES`, integrity levels, impersonation, token theft, privilege escalation paths | `token-inspector.c` |

Step 05 includes a [manual page table walk](05-virtual-memory/WALKTHROUGH.md) done by hand in WinDbg. Four levels, every PFN confirmed, CR3 to physical address.

## Structure

Each step has:

```
04-threads-and-irql/
├── thread-irql-inspector.c   # Compiles and runs, demonstrates the concept
├── NOTES.md                  # Build instructions, key structures, WinDbg commands
└── DEEP-DIVE.md              # Kernel internals, exploitation relevance, attack chains
```

Code runs on its own. NOTES explain the implementation and what to look at in a debugger. DEEP-DIVE connects the code to real attack and defense scenarios.

## The endpoint

The goal is BYOVD: loading a legitimately signed but vulnerable driver and using it to read and write arbitrary kernel memory. That technique is behind real attacks (Lazarus, BlackByte, Cuba ransomware). Getting there requires every step before it. Driver loading, IOCTLs, memory layout, tokens, object manipulation. Each step here is a prerequisite for the next.

## Lab

All code runs inside isolated VMs with kernel debugging enabled over a serial pipe. Nothing is tested on production machines. Exploitation steps run against intentionally vulnerable targets only.

## License

Educational and defensive security research only. Do not use any code or technique from this repository against systems you do not own or have written authorization to test.
