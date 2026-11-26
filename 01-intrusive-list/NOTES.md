# Intrusive Doubly Linked List

## What this is

A circular doubly linked list where the link node (`LIST_ENTRY`) lives inside the data structure, not the other way around. The list does not allocate or own the nodes. Each structure owns its own `LIST_ENTRY` field, and the `CONTAINING_RECORD` macro recovers the outer structure from a pointer to that field.

This is the design the Windows kernel uses for almost every linked structure.

## Why this comes first

`LIST_ENTRY` is not a data structures exercise. It is the mechanism behind:

- **`EPROCESS.ActiveProcessLinks :`**
   every running process is on this list. Walk it and you can enumerate all processes. Remove a node and the process disappears from tools that use this list (DKOM).
- **`EPROCESS.ThreadListHead :`** 
  every thread of a process, same pattern.
- **`PsLoadedModuleList :`**  
  every loaded kernel module (drivers included).
- **Scheduler ready queues, timer lists, IRP queues :** all `LIST_ENTRY`.

If you cannot read and manipulate this list, you cannot read or manipulate anything in the kernel.

## Build

**MSVC (Developer Command Prompt):**
```
cl list.c
list.exe
```

**GCC / MinGW:**
```
gcc list.c -o list
./list
```

No dependencies, no Windows headers needed. The types and macros are defined in the source to match `ntddk.h` exactly.

## What the code does

### Types

| Type | Fields | Purpose |
|------|--------|---------|
| `LIST_ENTRY` | `Flink`, `Blink` | Forward and backward pointers. Identical to `ntddk.h`. |
| `EMPLOYEE` | `Id`, `Name`, `Link` | A sample structure with an embedded `LIST_ENTRY`. |

### Operations

| Function | What it does |
|----------|-------------|
| `InitializeListHead` | Points both `Flink` and `Blink` at the head. An empty list is a head pointing to itself. |
| `IsListEmpty` | Returns 1 if `Head->Flink == Head`. |
| `InsertTailList` | Appends a node before the head (end of list). Updates four pointers. |
| `InsertHeadList` | Prepends a node after the head (start of list). |
| `RemoveEntryList` | Unlinks a node. Poisons its `Flink`/`Blink` with NULL. Returns 1 if the list is now empty. |
| `CONTAINING_RECORD` | Subtracts the field offset from a `LIST_ENTRY*` to get the outer struct pointer. |

### Expected output

```
Empty? 1

After InsertTail(a, b, c):
  Forward:  [1 Alice] -> [2 Bob] -> [3 Carol] -> (head)
  Backward: [3 Carol] -> [2 Bob] -> [1 Alice] -> (head)
  Empty? 0

After InsertHead(d):
  Forward:  [4 Dave] -> [1 Alice] -> [2 Bob] -> [3 Carol] -> (head)
  Backward: [3 Carol] -> [2 Bob] -> [1 Alice] -> [4 Dave] -> (head)

Removing Bob...
  List now empty? 0
  Forward:  [4 Dave] -> [1 Alice] -> [3 Carol] -> (head)

Removing all...
  RemoveEntryList returned: 1  (1 = list is now empty)
  Empty? 1

--- CONTAINING_RECORD demo ---
  Link is at:     <address>
  EMPLOYEE is at: <address>
  Offset of Link in EMPLOYEE: 16 bytes
  Recovered: Id=5, Name=Eve
```

## Key details

**Why circular?** The head is a sentinel it is a `LIST_ENTRY` that is not inside any data structure. Walking forward from the head reaches every node and returns to the head. No NULL checks needed. The kernel relies on this: the walk termination condition is always `Current != Head`, never `Current != NULL`.

**Why intrusive?** A node can be on multiple lists at once (different `LIST_ENTRY` fields for each). `EPROCESS` has `ActiveProcessLinks`, `ThreadListHead`, `SessionProcessLinks`, and more each is a separate `LIST_ENTRY` linking the same `EPROCESS` into a different list.

**Why poison after remove?** A double-remove on a live list silently corrupts two other nodes' pointers. Poisoning with NULL makes the second remove crash immediately instead of corrupting data you will not notice until much later (or until the kernel bugchecks with 0x139).

**InsertTailList needs exactly four pointer writes.** Getting one wrong means the forward and backward walks disagree. Windows validates this: at DISPATCH_LEVEL and above, the kernel checks that `Entry->Flink->Blink == Entry` before every list operation. A mismatch is bugcheck 0x139 `KERNEL_DATA_INPAGE_ERROR`.
