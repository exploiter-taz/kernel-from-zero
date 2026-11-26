# 08 — Deep dive: tokens, privilege escalation, and impersonation attacks

---

## Token theft in kernel memory

Every process's identity lives in one pointer:

```
EPROCESS.Token = _EX_FAST_REF → _TOKEN
```

The _EX_FAST_REF (step 06) packs a mini-refcount into the low 4 bits.
The actual _TOKEN address = `EPROCESS.Token & ~0xF`.

SYSTEM (PID 4) always runs. Its _TOKEN has all privileges Present and
Enabled, SID = S-1-5-18, Integrity = 0x5000. Your process's _TOKEN
has ~20 privileges Present with ~5 Enabled, your user SID, Integrity =
0x2000.

The attack:

```
1. Get kernel R/W (BYOVD or your own driver)
2. Find your EPROCESS — NtQuerySystemInformation class 5 → your PID,
   then walk ActiveProcessLinks from PsInitialSystemProcess
3. Find SYSTEM's EPROCESS — PsInitialSystemProcess IS PID 4
4. Read SYSTEM's token: systemToken = ReadKernel(systemEprocess + TOKEN_OFFSET)
5. Write it to yours: WriteKernel(yourEprocess + TOKEN_OFFSET, systemToken)
6. Increment the _TOKEN's PointerCount (the _EX_FAST_REF mini-refcount
   is now wrong — some exploits skip this, it works but risks a UAF)
7. Your process is SYSTEM.
```

One write changes your entire security context. No new process, no new
handle (no ObRegisterCallbacks trigger), no token creation audit.
EDR that monitors token changes via ETW may still catch it.

| Detection method | How |
|-----------------|-----|
| ETW token change events | Some EDR hooks token assignment |
| Token integrity checking | Periodically compare EPROCESS.Token against expected values |
| PID-to-token mapping | Detect when a user process suddenly has SYSTEM's token |
| Kernel page monitoring | HVCI detects writes to EPROCESS pages |
| Refcount anomaly | _TOKEN's PointerCount doesn't match the number of users |

## Token theft vs privilege enable

**Token theft** copies SYSTEM's token pointer to your EPROCESS. You
change identity — `whoami` returns `NT AUTHORITY\SYSTEM`. You have
SYSTEM's SIDs, groups, integrity level.

**Privilege enable** writes `0xFFFFFFFFFFFFFFFF` to your _TOKEN's
Privileges.Present and Privileges.Enabled. You keep your identity but
gain all 64 capabilities. `whoami` still returns your username.

| Scenario | Best approach | Why |
|----------|--------------|-----|
| You want SYSTEM shell | Token theft | Complete identity change |
| You want to dump LSASS | Privilege enable | Just need SeDebugPrivilege |
| You want to load a driver | Privilege enable | Just need SeLoadDriverPrivilege |
| You want to bypass mandatory IL | Token theft or IL DKOM | Token theft changes everything; IL DKOM is surgical |
| EDR monitors token assignment | Privilege enable | Modifying Privileges is less monitored |
| EDR monitors privilege changes | Token theft | Token swap bypasses privilege monitoring |
| You want stealth | Privilege enable | Smaller change, same identity |
| You want reliability | Token theft | One write, guaranteed |

**Integrity Level DKOM** is the third option — the most surgical. Change
the SID at IntegrityLevelIndex from S-1-16-8192 (Medium) to S-1-16-20480
(System). Your token pointer didn't change, privilege bitmasks didn't
change, only a 4-byte SID sub-authority value changed inside the token.
Very few detection tools monitor SID values inside tokens. This bypasses
UAC without elevation (UAC is an integrity check).

## Potato attacks: impersonation to SYSTEM

Every Potato variant follows the same chain:

```
Phase 1: COERCE
  Make a SYSTEM service connect to something you control

Phase 2: CAPTURE
  Grab SYSTEM's token from the connection

Phase 3: CREATE
  Use the captured token to spawn a SYSTEM process
```

The variants differ only in Phase 1.

| Potato | Year | Coercion method |
|--------|------|----------------|
| Hot Potato | 2016 | WPAD + NBNS poisoning → local MITM |
| Rotten Potato | 2016 | DCOM activation → OXID resolver |
| Juicy Potato | 2018 | DCOM CLSID abuse |
| Rouge Potato | 2020 | Fake OXID resolver |
| PrintSpoofer | 2020 | SpoolService → named pipe via RPC |
| EfsPotato | 2021 | EfsRpcOpenFileRaw |
| GodPotato | 2023 | DCOM OXID, Win8-11 |
| CoercedPotato | 2024 | Tries 10+ coercion methods |

Detailed chain (PrintSpoofer):

```
1. Running as a service account (has SeImpersonatePrivilege)
2. hPipe = CreateNamedPipe("\\\\.\\pipe\\test\\pipe\\spoolss")
3. Call RpcOpenPrinter("\\\\localhost/pipe/test")
   SpoolService (SYSTEM) connects to your pipe
4. ConnectNamedPipe(hPipe)
5. ImpersonateNamedPipeClient(hPipe) → thread impersonates SYSTEM
6. OpenThreadToken → handle to SYSTEM impersonation token
7. DuplicateTokenEx → convert to primary token
8. CreateProcessWithTokenW → cmd.exe as SYSTEM
```

SeImpersonatePrivilege is required. Without it, the kernel downgrades
the impersonation to SecurityIdentification (level 1) — you can see
who the client is but can't act as them. CreateProcessWithTokenW
requires at least level 2. Standard user accounts don't have
SeImpersonatePrivilege. Service accounts do. That's why Potato attacks
are "service account → SYSTEM", not "user → SYSTEM".

Patches close individual coercion methods, but new ones keep appearing.
EDR detects the pipe creation + impersonation + token duplication
sequence.

## The full exploit chain

This is the payload of the entire journey so far:

```
PHASE 1: Get kernel R/W
  Option A: BYOVD — load a signed vulnerable driver, use IOCTL
  Option B: Kernel exploit — pool overflow, UAF, type confusion
  Option C: Your own driver — if you can load one (SeLoadDriverPrivilege)

PHASE 2: Find the target (steps 01, 03)
  1. Read PsInitialSystemProcess → SYSTEM's EPROCESS
  2. Walk ActiveProcessLinks (LIST_ENTRY)
  3. Match UniqueProcessId to find your process

PHASE 3: Modify the token
  Option A: Token theft — copy SYSTEM's token to your EPROCESS
  Option B: Privilege enable — set Present + Enabled = 0xFFFF...
  Option C: Integrity DKOM — modify the SID value

PHASE 4: Post-exploitation
  Option A: Spawn SYSTEM shell
  Option B: Dump LSASS
  Option C: Load another driver
  Option D: Disable EDR (remove callbacks)
```

Each step in this repo feeds into the chain. LIST_ENTRY → navigate
kernel structures. EPROCESS → find the target. Memory → understand
pool allocations where _TOKEN lives. Objects → understand handles,
refcounts, _EX_FAST_REF. I/O → the IOCTL that gives you kernel R/W.
Tokens → the target. Modify the security context.

The token is always the destination. Everything else is the road.
