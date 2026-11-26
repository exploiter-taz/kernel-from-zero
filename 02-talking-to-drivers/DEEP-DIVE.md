# Deep Dive — Device Handles, IOCTLs, and the BYOVD Attack Surface

This is where `talk.c` connects to real BYOVD exploitation.

## The Object Namespace

The Windows kernel organizes all named objects in a tree rooted at `\`. Device objects, driver objects, symbolic links, and everything else reachable by name lives here.

```
\
├── Device\                      ← all device objects
│   ├── RTCore64                 ← DEVICE_OBJECT created by RTCore64.sys
│   ├── DBUtil_2_3               ← Dell BYOVD device
│   ├── PhysicalMemory           ← maps physical RAM
│   ├── Null
│   └── ...
│
├── Driver\                      ← all driver objects
│   ├── RTCore64                 ← DRIVER_OBJECT for RTCore64.sys
│   └── ...
│
├── GLOBAL??\                    ← global DosDevices (Win32 namespace root)
│   ├── RTCore64 → \Device\RTCore64    ← symbolic link
│   ├── C: → \Device\HarddiskVolume3
│   └── ...
│
└── ??\                          ← per-session DosDevices
    └── RTCore64 → \Device\RTCore64
```

When you call `CreateFile(L"\\\\.\\RTCore64")`:

1. Win32 translates `\\.\RTCore64` to `\??\RTCore64`
2. Object Manager finds `\??\RTCore64` — it's a symbolic link
3. The link points to `\Device\RTCore64`
4. Object Manager finds the `DEVICE_OBJECT` at that name
5. `NtCreateFile` creates a `FILE_OBJECT` and returns a `HANDLE`

If the driver did not create a symbolic link in `\DosDevices\` or `\GLOBAL??\`, `CreateFile` returns `ERROR_FILE_NOT_FOUND` even if `\Device\DriverName` exists. The only alternative is `NtOpenFile` with the full NT path `\Device\DriverName`.

### WinDbg: explore the namespace yourself

```
kd> !object \Device
kd> !object \Device\RTCore64
kd> !object \GLOBAL??\RTCore64
```

## How the driver creates its device

In `DriverEntry`, the driver does two things to become reachable:

```c
// 1. Create a named device object in \Device\
UNICODE_STRING devName = RTL_CONSTANT_STRING(L"\\Device\\RTCore64");
IoCreateDevice(DriverObject, 0, &devName,
               FILE_DEVICE_UNKNOWN, 0, FALSE, &deviceObject);

// 2. Create a symbolic link so user mode can reach it
UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\DosDevices\\RTCore64");
IoCreateSymbolicLink(&symLink, &devName);
```

Then it registers its IOCTL handler:

```c
DriverObject->MajorFunction[IRP_MJ_CREATE]         = DispatchCreate;
DriverObject->MajorFunction[IRP_MJ_CLOSE]          = DispatchClose;
DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoControl;  // ← this is where BYOVD lives
```

`MajorFunction[IRP_MJ_DEVICE_CONTROL]` is index 14 (0x0E) in the dispatch table. The function pointer lives at offset `0x70 + 14*8 = 0xE0` in the `DRIVER_OBJECT`.

## The IRP flow in detail

When `DeviceIoControl` crosses into the kernel:

```
User mode                          Kernel mode
─────────                          ───────────
DeviceIoControl(hDev, IOCTL, ...)
  │
  └─→ ntdll!NtDeviceIoControlFile
        │
        └─→ syscall instruction
              │
              └─→ KiSystemCall64 → nt!NtDeviceIoControlFile
                    │
                    ├─ IoAllocateIrp(deviceObject->StackSize)
                    │
                    ├─ For METHOD_BUFFERED:
                    │    Allocate SystemBuffer = max(inSize, outSize)
                    │    Copy input → SystemBuffer
                    │
                    ├─ Set up IO_STACK_LOCATION:
                    │    MajorFunction = IRP_MJ_DEVICE_CONTROL
                    │    Parameters.DeviceIoControl.IoControlCode = IOCTL
                    │    Parameters.DeviceIoControl.InputBufferLength = inSize
                    │    Parameters.DeviceIoControl.OutputBufferLength = outSize
                    │
                    └─ IoCallDriver(topOfDeviceStack, Irp)
                          │
                          └─→ Driver's DispatchIoControl(DeviceObject, Irp)
                                │
                                ├─ stack = IoGetCurrentIrpStackLocation(Irp)
                                ├─ ioctl = stack->Parameters.DeviceIoControl.IoControlCode
                                ├─ buf   = Irp->AssociatedIrp.SystemBuffer
                                │
                                ├─ switch (ioctl) { ... }   ← the vulnerable code
                                │
                                ├─ Irp->IoStatus.Status = STATUS_SUCCESS
                                ├─ Irp->IoStatus.Information = bytesWritten
                                └─ IoCompleteRequest(Irp, IO_NO_INCREMENT)
                                      │
                                      ├─ Copy SystemBuffer → user output buffer
                                      └─ Signal waiting thread
                                            │
DeviceIoControl returns ←─────────────────┘
```

## The vulnerability pattern

A typical BYOVD arbitrary-read handler looks like this:

```c
case IOCTL_READ_KERNEL_MEMORY:
{
    PREAD_REQUEST req = (PREAD_REQUEST)Irp->AssociatedIrp.SystemBuffer;

    // No validation of req->Address — user controls the target
    req->Value = *(PULONG64)(req->Address);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = sizeof(READ_REQUEST);
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}
```

The driver trusts the `Address` field from the user's buffer. The user sends a kernel address, the driver reads it and returns the value. That is an arbitrary kernel read primitive.

The write primitive is the same pattern:

```c
case IOCTL_WRITE_KERNEL_MEMORY:
{
    PWRITE_REQUEST req = (PWRITE_REQUEST)Irp->AssociatedIrp.SystemBuffer;

    // User controls both the address and the value
    *(PULONG)(req->Address) = req->Value;
    // ...
}
```

With arbitrary read and write, you can do anything: steal tokens, remove callbacks, hide processes, disable DSE.

## Device security: who can open the handle?

The `DEVICE_OBJECT` has a `SecurityDescriptor` field. If the driver called `IoCreateDevice` without setting it (and most BYOVD drivers don't), the default DACL allows any user to open the device.

```
kd> !devobj \Device\RTCore64
  SecurityDescriptor: 0x0000000000000000    ← NULL = anyone can open
```

A properly secured driver would use `IoCreateDeviceSecure` with an SDDL string:

```c
// Allow only SYSTEM and Administrators:
IoCreateDeviceSecure(DriverObject, 0, &devName,
    FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE,
    L"D:P(A;;GA;;;SY)(A;;GA;;;BA)",    // SDDL: SYSTEM + BuiltinAdmin only
    NULL, &deviceObject);
```

Most hardware utility drivers skip this, which is why BYOVD works from a standard admin account — and sometimes from a non-admin user.

## Device stacks and filter drivers

A device stack is a vertical chain of `DEVICE_OBJECT`s. IRPs enter at the top and travel down:

```
┌───────────────────────────┐  ← top of stack (IRPs arrive here first)
│  EDR filter device        │    WdFilter.sys, CrowdStrike, etc.
│  (attached with IoAttach) │
├───────────────────────────┤
│  RTCore64 device          │  ← the vulnerable driver
│  \Device\RTCore64         │
└───────────────────────────┘
```

If an EDR attaches a filter above the target device, the filter sees every IOCTL before the vulnerable driver does. It can inspect, modify, or block the IRP.

In practice, most EDRs do not filter individual device IOCTLs. They focus on:
- File system operations (minifilters on FltMgr)
- Process/thread creation (PsSetCreateProcessNotifyRoutineEx)
- Handle operations (ObRegisterCallbacks)

This is why BYOVD works: the IOCTL path to the vulnerable driver is usually unmonitored.

## IOCTL discovery through reverse engineering

When you have a driver binary, the IOCTL dispatch handler is the first target:

1. **Find DriverEntry** — the PE entry point
2. **Find MajorFunction[14] assignment** — `DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = SomeFunction`
3. **Read the switch statement** in that function — each `case` is an IOCTL code
4. **For each IOCTL**: what structure does it cast the buffer to? What does it do with the fields?

In IDA Pro, the switch cases show up as a series of `cmp eax, 0x8000XXXX` / `jz` instructions. Each comparison is an IOCTL code, and the jump target is the handler.

Automated approach: fuzz all possible IOCTL codes for a device type:

```c
for (ULONG func = 0; func <= 0xFFF; func++) {
    for (ULONG method = 0; method <= 3; method++) {
        DWORD ioctl = CTL_CODE(deviceType, func, method, 0);
        if (DeviceIoControl(hDev, ioctl, buf, 64, buf, 64, &ret, NULL)
            || GetLastError() != ERROR_INVALID_FUNCTION) {
            // This IOCTL is recognized by the driver
        }
    }
}
```

`ERROR_INVALID_FUNCTION` means the driver's switch statement hit the `default` case. Any other result means the IOCTL matched a `case` — even if it returned an error, it was recognized.

## Exercises

1. Decode these IOCTL codes by hand (without the tool), then verify with `talk decode`:
   - `0x9B0C1EC8` (DBUtil read)
   - `0xAA013044` (Capcom execute)
   - `0x9C402084` (WinRing0 MSR read)

2. A driver uses `IoCreateDevice` with device name `\Device\MyDriver` but does NOT call `IoCreateSymbolicLink`. Can user-mode code reach this driver? How?

3. A driver's IOCTL handler has this code:
   ```c
   PVOID userPtr = req->BufferPointer;
   ULONG val = *(PULONG)userPtr;
   ```
   The IOCTL uses `METHOD_BUFFERED`. Is `userPtr` safe to dereference? Why or why not?

4. If `DEVICE_OBJECT.SecurityDescriptor` is NULL and the device has no filter drivers attached, what stops a non-admin user from opening the device? What if the user needs admin to load the driver (via `sc create`) but not to use it afterwards?
