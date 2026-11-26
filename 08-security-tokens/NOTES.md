# 08 — Security: Tokens, Privileges, and Impersonation

This is where steps 01–06 converge. LIST_ENTRY links processes,
EPROCESS holds the token pointer via _EX_FAST_REF, the Object Manager
checks token SIDs against ACLs, and a BYOVD IOCTL gives you the
kernel R/W to rewrite the token.

## _TOKEN

A kernel object attached to every process and (optionally) every thread.
Every access check in the kernel reads it.

| Field | What it holds |
|-------|--------------|
| `UserAndGroups` | Array of SID_AND_ATTRIBUTES — your user SID + every group |
| `Privileges` (_SEP_TOKEN_PRIVILEGES) | 3 bitmasks: Present, Enabled, EnabledByDefault |
| `IntegrityLevelIndex` | Index into UserAndGroups pointing to the IL SID |
| `TokenType` | Primary (process) or Impersonation (thread) |
| `ImpersonationLevel` | 0–3: Anonymous, Identification, Impersonation, Delegation |

Every kernel access check follows the same pattern: read the caller's
token, compare SIDs against the object's security descriptor (ACL),
check privileges for special operations, check integrity level, then
grant or deny.

```
EPROCESS
  +0x4B8  Token : _EX_FAST_REF    ← & ~0xF on x64 (step 06)

_TOKEN
  +0x040  Privileges : _SEP_TOKEN_PRIVILEGES
    +0x000  Present          : Uint8B
    +0x008  Enabled          : Uint8B
    +0x010  EnabledByDefault : Uint8B

  +0x098  UserAndGroups : Ptr64 _SID_AND_ATTRIBUTES
    [0] = user SID (S-1-5-21-...-1001)
    [1] = Everyone (S-1-1-0)
    [2] = BUILTIN\Users (S-1-5-32-545)
    ...
    [n] = Mandatory Label\Medium (S-1-16-8192)
```

Offsets vary per Windows build. Use `dt nt!_TOKEN` in WinDbg.

## Token manipulation

| Technique | Target | Result |
|-----------|--------|--------|
| **Token theft** | EPROCESS.Token | Copy SYSTEM's token to your process → you ARE System |
| **Privilege enable** | Privileges.Present + Enabled | Set to 0xFFFFFFFFFFFFFFFF → all 64 privileges ON |
| **Integrity DKOM** | The SID at IntegrityLevelIndex | Change 0x2000 (Medium) to 0x5000 (System) |
| **Token swap** | EPROCESS.Token | Point to a hand-crafted _TOKEN with custom SIDs |

Token theft from user mode requires SeDebugPrivilege (admin + elevated).
Kernel-mode manipulation requires a driver or exploit. PPL processes
can't be opened even with SeDebugPrivilege. Credential Guard virtualizes
LSASS, so token theft doesn't get you cached creds.

## _SEP_TOKEN_PRIVILEGES

Three 64-bit bitmasks. Each bit position maps to a privilege LUID:

```
Bit 0  = SeCreateTokenPrivilege       (LUID 2)
Bit 1  = SeAssignPrimaryTokenPrivilege (LUID 3)
...
Bit 18 = SeDebugPrivilege             (LUID 20)
Bit 27 = SeImpersonatePrivilege       (LUID 29)
Bit 33 = SeLoadDriverPrivilege        (LUID 35)
```

**Present** = the token knows this privilege exists. If the bit is 0,
it can't be enabled. **Enabled** = currently active, access checks
test this. **EnabledByDefault** = which bits were on at logon.

The exploit shortcut: find your _TOKEN, write `0xFFFFFFFFFFFFFFFF` to
both Present and Enabled. Done — your process now has every privilege.

| Privilege | Why you want it |
|-----------|----------------|
| SeDebugPrivilege | OpenProcess(LSASS) → dump credentials |
| SeImpersonatePrivilege | Named pipe impersonation → Potato attacks → SYSTEM |
| SeLoadDriverPrivilege | Load a vulnerable driver → BYOVD |
| SeBackupPrivilege | Read any file, bypass all ACLs |
| SeRestorePrivilege | Write any file, bypass all ACLs |
| SeTakeOwnershipPrivilege | Take ownership of any object |
| SeCreateTokenPrivilege | Create arbitrary tokens |

AdjustTokenPrivileges from user mode can only enable bits already in
Present — it can't add new privileges.

## Integrity levels

A mandatory access control layer on top of the discretionary ACL system.

| Level | Value | SID | Who has it |
|-------|-------|-----|-----------|
| Untrusted | 0x0000 | S-1-16-0 | Sandboxed processes |
| Low | 0x1000 | S-1-16-4096 | Browser tabs, downloads |
| Medium | 0x2000 | S-1-16-8192 | Standard user processes |
| High | 0x4000 | S-1-16-16384 | Elevated admin processes |
| System | 0x5000 | S-1-16-20480 | SYSTEM account services |
| Protected | 0x7000 | S-1-16-28672 | WinTcb, anti-malware |

A Medium-IL process can't write to a High-IL file, can't send messages
to a High-IL window, can't inject into a High-IL process — even if the
ACL would allow it. UAC is an IL check.

You can lower your own IL (irreversible) but can't raise it without
kernel access.

## Impersonation

A thread can temporarily use a different user's token. Servers need
this — when a client connects, the server does work "as the client."

```
Primary token: EPROCESS.Token → "SYSTEM" (the service's identity)
Impersonation: ETHREAD.ClientSecurity → _TOKEN for "DomainUser\Bob"

Access check: kernel checks ETHREAD first. If impersonation token
exists, uses it. Otherwise falls back to EPROCESS.Token.
```

| Level | Name | What the server can do |
|-------|------|----------------------|
| 0 | SecurityAnonymous | Nothing |
| 1 | SecurityIdentification | Can read the client's SIDs but can't act as them |
| 2 | SecurityImpersonation | Can act as the client on THIS machine |
| 3 | SecurityDelegation | Can act as the client on REMOTE machines |

## Named pipe impersonation (Potato attacks)

Every Potato variant follows the same chain: coerce a SYSTEM service
into connecting to your named pipe, capture its token, spawn a process.

```
1. Create named pipe
2. Trick SYSTEM service into connecting (the coercion)
3. ConnectNamedPipe → pipe connected
4. ImpersonateNamedPipeClient → thread gets SYSTEM token
5. OpenThreadToken → get handle to impersonation token
6. DuplicateTokenEx → make a primary token from it
7. CreateProcessWithTokenW → spawn cmd.exe as SYSTEM
```

| Potato | Year | Coercion method |
|--------|------|----------------|
| Hot Potato | 2016 | WPAD + NBNS poisoning |
| Juicy Potato | 2018 | DCOM CLSID abuse |
| PrintSpoofer | 2020 | Print Spooler RPC |
| GodPotato | 2023 | DCOM OXID |
| CoercedPotato | 2024 | Multiple RPC interfaces |

Requirements: SeImpersonatePrivilege (service accounts have it by
default; standard user accounts don't) and a way to make SYSTEM connect.

## The code

`token-inspector.c` demonstrates:

1. **DumpIntegrityLevel** — reads the process integrity level
2. **DumpPrivileges** — enumerates all privileges with their state,
   checks for SeDebugPrivilege
3. **DumpGroups** — lists all SIDs in the token with attributes

## WinDbg

```
; Get our process's token
0: kd> !process 0 1 token-inspector.exe

; Decode the _EX_FAST_REF (mask off low 4 bits)
0: kd> ? <Token value> & fffffffffff`fffffff0

; Dump the _TOKEN
0: kd> dt nt!_TOKEN <address>

; Look at _SEP_TOKEN_PRIVILEGES
0: kd> dt nt!_SEP_TOKEN_PRIVILEGES <token+Privileges offset>

; Full token dump
0: kd> !token <token address>

; Compare with SYSTEM's token
0: kd> !process 0 1 System
0: kd> !token <system token address>

; Integrity level SID
0: kd> dt nt!_TOKEN <address> IntegrityLevelIndex
```
