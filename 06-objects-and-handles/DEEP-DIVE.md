# 06 — Deep dive: handles, the object lifecycle, and EDR bypass

---

## ObRegisterCallbacks — the EDR's strongest weapon

A kernel API that lets a driver register callbacks that fire every time
a handle to a process or thread is created, duplicated, or opened. The
callback runs before the handle is returned to the caller.

```c
// EDR driver code (simplified)
OB_CALLBACK_REGISTRATION reg = { ... };
OB_OPERATION_REGISTRATION ops[] = {
    { PsProcessType, OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE,
      PreOperationCallback, NULL }
};
ObRegisterCallbacks(&reg, &handle);
```

When you call `OpenProcess(PROCESS_ALL_ACCESS, FALSE, lsassPid)`:

```
1. NtOpenProcess → ObOpenObjectByPointer
2. Object Manager is about to create a handle with PROCESS_ALL_ACCESS
3. BEFORE creating the handle, it calls every registered callback
4. EDR's callback:
   - If target is LSASS and caller is untrusted:
     DesiredAccess &= ~(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD)
   - Modifies DesiredAccess in PRE_OPERATION_INFORMATION
5. Handle is created with the REDUCED access mask
6. Your OpenProcess "succeeds" but the handle can't do VM read/write
7. ReadProcessMemory fails with ACCESS_DENIED
```

It's strong because it runs in kernel mode, fires on every handle
operation, can strip access bits (not just block/allow), supports
multiple callbacks, and requires a signed driver to register.

### How to get around it

| Method | How | Difficulty |
|--------|-----|-----------|
| **Handle duplication** | Find a process with a good handle to LSASS (csrss.exe, etc.). DuplicateHandle it into your process. Some EDRs now hook this too. | Medium |
| **Direct syscall** | NtOpenProcess via direct syscall. Avoids user-mode hooks but the kernel callback still fires. | Low (doesn't bypass) |
| **BYOVD** | Load a signed vuln driver. Use it to find the callback registration in kernel memory and unlink it. | High |
| **Callback removal** | From your own kernel driver, call ObUnRegisterCallbacks with the EDR's handle. Requires knowing the registration handle. | High |
| **PPL abuse** | If your process is signed as PPL, ObRegisterCallbacks can't strip your access. | Very high |

The CallbackRemoval driver (step 01) was doing option 4 — walking
kernel data structures to find and remove callbacks. The crash happened
while traversing those structures (stale pointer in the callback list).

## Handle inheritance

When a process creates a child with `bInheritHandles = TRUE`, the child
gets copies of all the parent's inheritable handles. Same kernel objects
— HandleCount goes up.

```
Parent's handle table:
  Handle 0x04 → FILE_OBJECT (notepad.exe)     [inheritable = YES]
  Handle 0x08 → EVENT_OBJECT                  [inheritable = NO]
  Handle 0x0C → PROCESS_OBJECT (LSASS)        [inheritable = YES]

CreateProcess(..., bInheritHandles = TRUE, ...)

Child's handle table:
  Handle 0x04 → FILE_OBJECT (notepad.exe)     [same object]
  Handle 0x0C → PROCESS_OBJECT (LSASS)        [same object]
  (0x08 not inherited)
```

The child gets handle 0x0C to LSASS without ever calling OpenProcess.
ObRegisterCallbacks doesn't fire because no new handle is "opened" —
it's copied.

Handle laundering: malware opens sensitive handles, then spawns a child
that inherits them. The child does the malicious work. The parent's
OpenProcess is logged, but the child's use of the inherited handle
isn't.

## The handle table in kernel memory

A 3-level tree (like page tables):

```
Level 0:  HANDLE_TABLE (pointed to by EPROCESS.ObjectTable)
Level 1:  Array of pointers to Level 2 tables
Level 2:  Array of HANDLE_TABLE_ENTRY structures

Each HANDLE_TABLE_ENTRY:
  - ObjectPointerBits (encoded pointer to the object)
  - GrantedAccessBits (what you can do with this handle)
  - Lock bit, audit flag, inheritable flag
```

Handles are multiples of 4 (0x04, 0x08, 0x0C, ...) because the low 2
bits are flags. Handle 0 is always invalid.

If you have arbitrary kernel write:
1. Find the target process's EPROCESS
2. Follow EPROCESS.ObjectTable to the HANDLE_TABLE
3. Walk to the HANDLE_TABLE_ENTRY for the handle you want
4. Change GrantedAccessBits to PROCESS_ALL_ACCESS

A handle with limited access becomes all-powerful. No new handle is
created (no ObRegisterCallbacks trigger), no audit event generated.
This is a data-only attack — no code execution, no ROP, no shellcode.
Just changing one integer in kernel memory.

## Two refcounts: HandleCount and PointerCount

Process A has a handle to file X. Driver B also holds a kernel pointer
to X (it called `ObReferenceObjectByHandle`).

```
File X: HandleCount = 1, PointerCount = 2
```

Process A calls CloseHandle:
```
File X: HandleCount = 0, PointerCount = 1
```

If the kernel only had HandleCount, it would destroy the object here.
But driver B still holds a pointer. If the object is freed, B's pointer
becomes dangling → use-after-free → BSOD or worse.

PointerCount prevents this. Object isn't freed until both reach 0.
Driver B calls ObDereferenceObject when done:

```
File X: HandleCount = 0, PointerCount = 0 → DESTROYED
```

Kernel UAF happens when a driver forgets ObDereferenceObject (leak) or
calls it too many times (premature free). If it races with another
thread: the object gets freed while someone still uses it → classic
UAF → exploitable via pool feng shui (step 05).

The _EX_FAST_REF on EPROCESS.Token packs a mini-refcount (4 bits)
into the pointer for fast access. The 3-bit vs 4-bit masking bug didn't
just give a bad pointer — it also broke the fast-ref refcounting, which
could have caused a ref leak even if the pointer happened to be valid.
