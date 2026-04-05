# Vuln_driver — Windows Kernel Exploitation 

> **For educational purposes only.**  
> Developed for the talk *"From a missing LOCK to NT AUTHORITY\SYSTEM"*

---

## Overview

This repository contains a deliberately vulnerable Windows kernel driver (`vuln_driver.sys`) and a usermode exploit (`poc.exe`) that chains multiple vulnerabilities to achieve Local Privilege Escalation (LPE) from a standard user to `NT AUTHORITY\SYSTEM`.

The entire chain starts from a single missing `LOCK` prefix on an increment instruction.

```
RefCount++ without LOCK
  → Race Condition (TOCTOU)
    → Use-After-Free
      → Heap Spray
        → Write Primitive
          → Read + Write Absolute
            → Token Stealing
              → NT AUTHORITY\SYSTEM
```

**Similar real-world CVEs:** CVE-2022-21882, CVE-2021-1732, CVE-2023-21768, CVE-2024-30088

---

## Vulnerability Analysis

### Root Cause — Non-Atomic Reference Count

The driver maintains a global object `g_VulnObject` with a reference count field:

```c
typedef struct _VULN_OBJECT {
    LONG    RefCount;   // [VULN] not protected atomically
    PVOID   Buffer;     // 256-byte PagedPool allocation
    ULONG   BufferSize;
    BOOLEAN Active;
} VULN_OBJECT, *PVULN_OBJECT;
```

The `AcquireObject()` function increments `RefCount` without atomicity:

```c
NTSTATUS AcquireObject(VOID) {
    if (g_VulnObject->RefCount > 0) {         // [1] CHECK
        //
        // ← TOCTOU WINDOW
        // Thread 2 can execute ReleaseObject() here:
        //   RefCount-- → 0
        //   ExFreePool(Buffer)  ← FREE
        //
        g_VulnObject->RefCount++;              // [2] USE — no LOCK
        DoWorkWithBuffer(g_VulnObject->Buffer);// [3] UAF if window was hit
    }
}
```

The compiler translates `RefCount++` into three separate instructions:

```asm
MOV EAX, [RefCount]   ; read
INC EAX               ; modify
MOV [RefCount], EAX   ; write
; ← another CPU can execute between any of these
```

**Fix — one line closes the entire chain:**

```c
InterlockedIncrement(&g_VulnObject->RefCount);
// emits: LOCK XADD [RefCount], EAX
// atomic + full memory barrier across all CPUs
```

---

### Exploitation Chain

#### Step 1 — Race Condition (TOCTOU)

Two threads are created and pinned to different CPUs:

- **Thread 1 (CPU 0):** calls `IOCTL_ACQUIRE` in a loop → `AcquireObject()`
- **Thread 2 (CPU 1):** calls `IOCTL_RELEASE` in a loop → `ReleaseObject()`

`SetThreadAffinityMask` is critical: without it, the scheduler alternates threads on the same CPU (time-slicing, not true parallelism). With affinity masks `0x1` and `0x2`, both threads run simultaneously on different CPUs, reliably hitting the TOCTOU window.

The dispatch signal uses `InterlockedExchange` instead of `volatile bool` because `volatile` alone does not emit a memory barrier between CPUs. Without it, a thread may spin on a stale cache value indefinitely. `InterlockedExchange` emits `LOCK` — a full memory barrier visible to all CPUs immediately.

> Ironic: the fix for the race condition uses the same LOCK the driver forgot.

#### Step 2 — Use-After-Free

When the race is won, Thread 2 calls `ExFreePool(Buffer)` between Thread 1's CHECK and USE. Thread 1 holds a dangling pointer — `g_VulnObject->Buffer` still points to the freed 256-byte slot in PagedPool. The freed slot is not zeroed or unmapped. The data remains physically in memory until the allocator reuses it.

**Key distinction:**
- **Buffer** — the pointer stored in `g_VulnObject->Buffer`
- **Slot** — the 256 bytes of physical memory that pointer addresses

`ExFreePool` frees the slot. It does not touch the pointer. The dangling pointer persists.

#### Step 3 — Heap Spray

5000 anonymous pipes are created, each with a buffer of exactly 256 bytes (`nSize = 256` in `CreatePipe`). Their content is injected via `WriteFile` with a controlled `FAKE_BUFFER` structure.

Why pipes:
- Allocate in **PagedPool** — same pool type as the freed Buffer, competing for the same slot
- Size precisely controllable via `nSize` — 256 bytes matches the freed slot exactly  
- Content is 100% attacker-controlled via `WriteFile`
- Thousands can be created from usermode with no special privilege

One of the 5000 pipes lands in the freed slot. The dangling pointer now addresses attacker-controlled memory.

#### Step 4 — Write Primitive

`IOCTL_WRITE_BUFFER` calls `WriteToBuffer()` without bounds checking:

```c
NTSTATUS WriteToBuffer(ULONG Offset, PVOID Data, ULONG Size) {
    // [VULN] Offset not validated against BufferSize
    RtlCopyMemory(
        (PUCHAR)g_VulnObject->Buffer + Offset,
        Data,
        Size
    );
}
```

Since `g_VulnObject->Buffer` now points to the spray-controlled slot, this call writes directly into attacker-controlled kernel memory — **write primitive established**.

#### Step 5 — EPROCESS Leak

`NtQuerySystemInformation(SystemHandleInformation)` returns the system-wide handle table. Each entry exposes:

- `ProcessId` — PID of the owning process
- `Handle` — the handle value
- `Object` — the kernel virtual address of the underlying object

Opening `OpenProcess(pid)` produces a handle whose `Object` field points to the target `_EPROCESS`. Filtering the returned table by our PID and handle value leaks the kernel address of any process's `_EPROCESS` — no vulnerability required, this is intentionally exposed by Windows for debugging purposes.

#### Step 6 — Token Stealing

`_EPROCESS.Token` at offset `+0x4B8` is an `EX_FAST_REF`:

```
Bits [63:4] — pointer to the _TOKEN object in NonPagedPool
Bits  [3:0] — inline reference count (kernel optimization)
```

The exploit:
1. Reads 8 bytes from `EPROCESS[SYSTEM] + 0x4B8` using `IOCTL_READ_ABSOLUTE` (kernel read primitive)
2. Writes those 8 bytes to `EPROCESS[poc.exe] + 0x4B8` using `IOCTL_WRITE_ABSOLUTE` (kernel write primitive)

After the write, `poc.exe`'s token field points to `_TOKEN{SYSTEM}`. Any process spawned from this point inherits `NT AUTHORITY\SYSTEM` privileges.

```
Before: EPROCESS[poc.exe].Token → _TOKEN{ User=<user>, Groups=[Users] }
After:  EPROCESS[poc.exe].Token → _TOKEN{ User=SYSTEM, SeDebugPrivilege, ... }
```

---


## Lab Setup

### Requirements

- Windows 10 x64 (VM strongly recommended — bugs cause BSOD)
- Visual Studio 2019/2022 + WDK
- WinDbg
- Test signing enabled

### 1. Enable test signing

```cmd
bcdedit /set testsigning on
bcdedit /set nointegritychecks on
shutdown /r /t 0
```

### 2. Build the driver

Create a WDM project in Visual Studio, add `vuln_driver.c`, build for x64 Debug. The runtime library must be set to **Multi-threaded (/MT)**.

### 3. Install the driver

```cmd
copy x64\Debug\vuln_driver.sys C:\Windows\System32\drivers\
sc create VulnDriver type= kernel start= demand binPath= C:\Windows\System32\drivers\vuln_driver.sys
sc start VulnDriver
```

### 4. Verify TOKEN_OFFSET

```windbg
dt nt!_EPROCESS
```

Update `TOKEN_OFFSET` in `poc.c` if it differs from `0x4B8`.

| Windows Build | TOKEN_OFFSET |
|---------------|--------------|
| 17763 (1809)  | 0x358        |
| 19041 (2004)  | 0x4b8        |
| 19044 (21H2)  | 0x4b8        |
| 19045 (22H2)  | 0x4b8        |
| 22000 (11 21H2)| 0x4b8       |
| 22621 (11 22H2)| 0x4b8       |

### 5. Build the PoC

```cmd
cl.exe poc.c /O2 /TC /MT ^
    /link ntdll.lib kernel32.lib advapi32.lib ^
    /out:poc.exe
```

### 6. Run as Administrator

```cmd
poc.exe
```

---

## WinDbg — Live Debugging

### Kernel debug setup

```cmd
bcdedit /debug on
bcdedit /dbgsettings net hostip:<host_ip> port:50000 key:1.2.3.4
```

### Breakpoints

```windbg
.sympath+ C:\path\to\vuln_driver\x64\Debug
.reload /f vuln_driver.sys

; [1] CHECK — RefCount read, window not yet open
bp vuln_driver!AcquireObject+0x1f ".printf \"[1] CHECK RefCount=%d\n\", dwo(poi(vuln_driver!g_VulnObject)); g"

; [2] TOCTOU WINDOW — past CHECK, not yet incremented
bp vuln_driver!AcquireObject+0x24 ".printf \"[2] WINDOW OPEN RefCount=%d\n\", dwo(poi(vuln_driver!g_VulnObject)); g"

; [3] WATCHPOINT — fires when ExFreePool writes to the slot
ba w8 <BufferAddr> ".printf \"[3] ExFreePool — dangling pointer active!\n\"; k; g"

; [4] UAF CONFIRMED — stops at RefCount<=0, disables all breakpoints
bp vuln_driver!ReleaseObject "r $t0=poi(vuln_driver!g_VulnObject); .if(@$t0==0){g} .else{ r $t1=dwo(@$t0); .if(@$t1<=0){ .printf \"UAF CONFIRMED!\n\"; dq <g_VulnObject_addr> L4; bd 0 1 2 3 4; } .else{g} }"
```

### After UAF confirmation

```windbg
; Freed slot — expect (Free) *Vuln
!pool <BufferAddr>

; Dangling pointer still present
dq <g_VulnObject_addr> L4

; Compare tokens before and after exploit
dq <eprocess_system>+4b8 L1
dq <eprocess_poc>+4b8    L1
; After exploit: both values should match
```

---

## Mitigations

| Mitigation | Impact |
|---|---|
| **Interlocked APIs** | Closes the TOCTOU window entirely. One-line fix. |
| **Pool Randomization** (Win10 1909+) | Heap spray less reliable — requires surgical pool grooming |
| **KPTI** | No impact — data-only attack, no cross-ring shellcode |
| **SMEP** | No impact — no userspace code executed in kernel mode |
| **HVCI / VBS** | Blocks unsigned kernel shellcode — but token steal via write primitive still works since it modifies data, not code |

---

## Disclaimer

This project is provided strictly for educational and research purposes in controlled lab environments. Running this against any system you do not own and have explicit written permission to test is illegal.
