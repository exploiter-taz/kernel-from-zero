# Talking to Drivers

## What this is

The user-mode side of kernel driver communication. How you open a handle to a driver's device object and send it IOCTL (I/O Control) requests. This is the entry point for every BYOVD attack: without a device handle, you have no way to reach the vulnerable driver's code

## Why this comes second

Step 01 gave us intrusive linked lists the data structure the kernel uses internally. This step gives us the bridge between user mode and kernel mode: the mechanism that lets a user-mode program talk to a kernel driver. Everything from here forward (reading kernel memory, manipulating tokens, removing callbacks) depends on being able to open a device and send IOCTLs through it

## Build

**MSVC (Developer Command Prompt):**
```
cl talk.c /link advapi32.lib
```

**GCC / MinGW:**
```
gcc talk.c -o talk -ladvapi32
```

The IOCTL decoder compiles on Linux/macOS too (the Windows-specific parts are behind `#ifdef _WIN32`)

## Usage

### Decode an IOCTL code

```
talk decode 0x80002048
```

Output:
```
IOCTL 0x80002048
  DeviceType : 0x8000  (third-party)
  Function   : 0x812  (third-party range)
  Method     : METHOD_BUFFERED (0)
  Access     : FILE_ANY_ACCESS (0)
  Reconstruct: CTL_CODE(0x8000, 0x812, METHOD_BUFFERED, FILE_ANY_ACCESS)
```

### Encode an IOCTL code

```
talk encode 0x8000 0x812 0
```

Builds `CTL_CODE(0x8000, 0x812, METHOD_BUFFERED, FILE_ANY_ACCESS)` and prints the result.

### Open a device (Windows only)

```
talk open \\.\RTCore64
```

Tries `CreateFile` on the device path. Reports success (handle opened) or the specific error (not found, access denied, sharing violation).

### Scan for loaded BYOVD drivers (Windows only)

```
talk scan
```

Tries to open 10 well-known BYOVD driver device paths and reports which are accessible.

### Send an IOCTL (Windows only)

```
talk send \\.\RTCore64 0x80002048
```

Opens the device and sends the IOCTL with an empty 64-byte buffer. Reports success or failure. For real exploitation you would fill the buffer with the target address — this is just the communication test.

## Key concepts

### The path from user mode to kernel mode

```
CreateFile(L"\\\\.\\RTCore64")
  → \??\RTCore64              (Win32 to NT namespace)
  → \Device\RTCore64          (symbolic link target)
  → DEVICE_OBJECT             (kernel device object)
  → FILE_OBJECT + HANDLE      (returned to user mode)
```

Without both a `DEVICE_OBJECT` (created by `IoCreateDevice`) and a symbolic link (created by `IoCreateSymbolicLink`), user mode cannot reach the driver at all.

### DeviceIoControl flow

```
DeviceIoControl(hDevice, IOCTL_CODE, inBuf, inSize, outBuf, outSize, ...)
  → ntdll!NtDeviceIoControlFile (syscall)
  → I/O Manager creates IRP, copies input to SystemBuffer
  → IRP dispatched to driver's MajorFunction[IRP_MJ_DEVICE_CONTROL]
  → Driver processes the IOCTL (this is where the vulnerability is)
  → IoCompleteRequest
  → SystemBuffer copied back to outBuf
  → DeviceIoControl returns
```

### CTL_CODE layout

| Bits | Field | Purpose |
|------|-------|---------|
| 31:16 | DeviceType | Device category. 0x8000+ = third-party. |
| 15:14 | Access | Required access rights. 0 = any. |
| 13:2 | Function | Operation ID. 0x800+ = third-party. |
| 1:0 | Method | Buffer transfer method. 0 = buffered. |

### Why METHOD_BUFFERED matters

With `METHOD_BUFFERED`, the I/O Manager allocates a kernel buffer, copies your input into it, and passes that safe copy to the driver. The driver reads from `Irp->AssociatedIrp.SystemBuffer` — a kernel-controlled pointer.

With `METHOD_NEITHER`, the driver gets your raw user-mode pointer. If it dereferences without `ProbeForRead`, you can pass a kernel address and trick the driver into reading kernel memory for you. This is a separate class of vulnerability, but most common BYOVD drivers use `METHOD_BUFFERED` with an address field inside the buffer structure.

## Known BYOVD IOCTL codes

| Driver | Device path | Read IOCTL | Write IOCTL | Notes |
|--------|------------|------------|-------------|-------|
| RTCore64.sys | `\\.\RTCore64` | 0x80002048 | 0x8000204C | 4-byte kernel R/W, MSI Afterburner |
| DBUtil_2_3.sys | `\\.\DBUtil_2_3` | 0x9B0C1EC8 | 0x9B0C1ED0 | Large-block R/W via MmCopyMemory, Dell |
| AsrDrv101.sys | `\\.\AsrDrv101` | 0x222808 | 0x22280C | Virtual + physical + MSR, ASRock |
| Capcom.sys | `\\.\Htsysm72FB` | — | — | 0xAA013044 = ring-0 code execution |
| WinRing0x64.sys | `\\.\WinRing0_1_2_0` | 0x9C402080 | — | Physical memory read, monitoring tools |
