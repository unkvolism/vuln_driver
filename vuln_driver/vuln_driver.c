/*
 * vuln_driver.c
 * Vulnerable driver for PoC of Race Condition -> UAF -> LPE
 *
 * Build with WDK:
 *   - Open project in Visual Studio with WDK installed
 *   - Set as "Kernel Mode Driver" (KMDF or WDM)
 *   - Build -> x64 Debug
 *
 * Install (as admin, with test signing enabled):
 *   sc create VulnDriver type= kernel binPath= C:\path\to\vuln_driver.sys
 *   sc start VulnDriver
 *
 * Enable test signing (requires reboot):
 *   bcdedit /set testsigning on
 *
 * INTENTIONAL VULNERABILITIES:
 *   [1] RefCount not atomically protected -> Race Condition (TOCTOU)
 *   [2] Use-After-Free when race is exploited
 *   [3] No offset validation in IOCTL_WRITE_BUFFER -> OOB write
 */

#include <ntddk.h>
#include <wdm.h>


#define DEVICE_NAME     L"\\Device\\VulnDriver"
#define SYMLINK_NAME    L"\\DosDevices\\VulnDriver"
#define POOL_TAG        'nluV'
#define BUFFER_SIZE     256

 // IOCTLs 
#define IOCTL_ACQUIRE       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_RELEASE       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WRITE_BUFFER  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_READ_BUFFER   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_REINIT            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_LEAK_BUFFER_ADDR  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WRITE_ABSOLUTE    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_READ_ABSOLUTE     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS)


/*
 * Main structure of the shared object.
 *
 * VULNERABILITY [1]: RefCount is a simple LONG.
 * The correct approach would be to use Interlocked* operations on all accesses.
 * As it is, two threads can pass the check simultaneously.
 */
typedef struct _VULN_OBJECT {
    LONG    RefCount;       // [VULN] no atomic protection
    PVOID   Buffer;         // data buffer allocated in PagedPool
    ULONG   BufferSize;     // buffer size
    BOOLEAN Active;         // is the object active?
} VULN_OBJECT, * PVULN_OBJECT;

/*
 * Input for IOCTL_WRITE_BUFFER
 *
 * VULNERABILITY [3]: Offset is not validated against BufferSize.
 * Allows arbitrary write in kernel pool beyond the buffer.
 */

typedef struct _WRITE_INPUT {
    ULONG  Offset;          // [VULN] offset without validation
    ULONG  Size;            // data size
    UCHAR  Data[1];         // data to write (flexible array)
    // BYTE does not exist in kernel use UCHAR
} WRITE_INPUT, * PWRITE_INPUT;

/*
 * Input for IOCTL_WRITE_ABSOLUTE
 * Writes Size bytes of Data to the absolute address KernelAddr.
 * This is the direct write primitive, without relying on OOB.
 */
typedef struct _WRITE_ABSOLUTE_INPUT {
    ULONG64 KernelAddr;   // absolute kernel address to write to
    ULONG   Size;         // bytes to write (max 8)
    UCHAR   Data[8];      // data
} WRITE_ABSOLUTE_INPUT, * PWRITE_ABSOLUTE_INPUT;



PDEVICE_OBJECT  g_DeviceObject = NULL;
PVULN_OBJECT    g_VulnObject = NULL;


DRIVER_UNLOAD       DriverUnload;
DRIVER_DISPATCH     DispatchCreate;
DRIVER_DISPATCH     DispatchClose;
DRIVER_DISPATCH     DispatchDeviceControl;



/*
 * AcquireObject
 *
 * Attempts to acquire a reference to the global object.
 * If RefCount > 0, increments and allows usage.
 * If RefCount == 0, frees the object from memory.
 *
 * VULNERABILITY [1] + [2]:
 *
 *   CHECK:  if (g_VulnObject->RefCount > 0)   <- reads RefCount
 *           ...
 *   USE:    g_VulnObject->RefCount++           <- modifies RefCount
 *
 *   Window between CHECK and USE:
 *   Another thread may call ReleaseObject() and make RefCount reach 0,
 *   which triggers ExFreePool(Buffer). When the first thread returns
 *   from CHECK and executes USE, the Buffer has already been freed -> UAF.
 */

NTSTATUS AcquireObject(VOID)
{
    if (g_VulnObject == NULL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    // ─── VULNERABILITY: CHECK without lock ──────────────────────────────────
    //
    // Correct approach would be:
    //   LONG prev = InterlockedCompareExchange(&g_VulnObject->RefCount, 
    //                                          g_VulnObject->RefCount + 1,
    //                                          g_VulnObject->RefCount);
    //   if (prev <= 0) return STATUS_INVALID_DEVICE_STATE;
    //
    if (g_VulnObject->RefCount > 0) {               // CHECK <- point 1

        // ── ATTACK WINDOW ─────────────────────────────────────────────────
        // Another CPU may execute ReleaseObject() here,
        // setting RefCount to zero and calling ExFreePool(Buffer).
        // This thread is unaware, it will continue as if the object still exists.
        // ──────────────────────────────────────────────────────────────────

        g_VulnObject->RefCount++;                    // USE  <- use 2 (no LOCK)

        DbgPrint("[VulnDriver] AcquireObject: RefCount = %d\n",
            g_VulnObject->RefCount);

        return STATUS_SUCCESS;

    }
    else {
        // RefCount == 0 -> no one is using it anymore, free the object
        DbgPrint("[VulnDriver] AcquireObject: RefCount == 0, freeing object\n");

        if (g_VulnObject->Buffer != NULL) {
            ExFreePoolWithTag(g_VulnObject->Buffer, POOL_TAG);
            g_VulnObject->Buffer = NULL;
        }

        ExFreePoolWithTag(g_VulnObject, POOL_TAG);
        g_VulnObject = NULL;

        return STATUS_INVALID_DEVICE_STATE;
    }
}

/*
 * ReleaseObject
 *
 * Decrements the object's RefCount.
 * If it reaches 0, frees the buffer.
 *
 * VULNERABILITY: no InterlockedDecrement.
 * Two threads may decrement simultaneously and both see
 * the value reaching 0, causing double-free.
 */

NTSTATUS ReleaseObject(VOID)
{
    if (g_VulnObject == NULL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    // [VULN] should be: InterlockedDecrement(&g_VulnObject->RefCount)
    g_VulnObject->RefCount--;

    DbgPrint("[VulnDriver] ReleaseObject: RefCount = %d\n",
        g_VulnObject->RefCount);

    if (g_VulnObject->RefCount <= 0) {
        DbgPrint("[VulnDriver] ReleaseObject: freeing buffer\n");

        if (g_VulnObject->Buffer != NULL) {
            ExFreePoolWithTag(g_VulnObject->Buffer, POOL_TAG);  // <- FREE
            g_VulnObject->Buffer = NULL;
        }
    }

    return STATUS_SUCCESS;
}

/*
 * WriteToBuffer
 *
 * Writes data to the object's buffer at the specified offset.
 *
 * VULNERABILITY [3]: Offset + Size are not validated against BufferSize.
 * Allows out-of-bounds write (OOB write in kernel pool).
 *
 * Additionally, if AcquireObject() suffered UAF, the Buffer may point
 * to freed memory   this write goes wherever the heap spray placed.
 */

NTSTATUS WriteToBuffer(ULONG Offset, PVOID Data, ULONG Size)
{
    if (g_VulnObject == NULL || g_VulnObject->Buffer == NULL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    // [VULN] no validation: Offset + Size may exceed BufferSize
    // Correct approach would be:
    //   if (Offset + Size > g_VulnObject->BufferSize) return STATUS_INVALID_PARAMETER;

    DbgPrint("[VulnDriver] WriteToBuffer: offset=0x%x size=0x%x\n", Offset, Size);

    RtlCopyMemory(
        (PUCHAR)g_VulnObject->Buffer + Offset,  // <- destination without validation
        Data,
        Size
    );

    return STATUS_SUCCESS;
}


NTSTATUS InitObject(VOID)
{
    // ExAllocatePool2 replaces ExAllocatePoolWithTag (deprecated in WDK 2004+)
    // POOL_FLAG_NON_PAGED = NonPagedPool | automatically zeroes memory (no RtlZeroMemory needed)
    g_VulnObject = (PVULN_OBJECT)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(VULN_OBJECT),
        POOL_TAG
    );

    if (g_VulnObject == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // ExAllocatePool2 already zeroes memory automatically
    // RtlZeroMemory would be redundant here

    g_VulnObject->Buffer = ExAllocatePool2(
        POOL_FLAG_PAGED,     // PagedPool for the data buffer
        BUFFER_SIZE,
        POOL_TAG
    );

    if (g_VulnObject->Buffer == NULL) {
        ExFreePoolWithTag(g_VulnObject, POOL_TAG);
        g_VulnObject = NULL;
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(g_VulnObject->Buffer, BUFFER_SIZE);
    g_VulnObject->BufferSize = BUFFER_SIZE;
    g_VulnObject->RefCount = 1;   // starts with 1 reference
    g_VulnObject->Active = TRUE;

    DbgPrint("[VulnDriver] Object initialized at: %p, Buffer at: %p\n",
        g_VulnObject, g_VulnObject->Buffer);

    return STATUS_SUCCESS;
}


NTSTATUS DispatchCreate(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    DbgPrint("[VulnDriver] IRP_MJ_CREATE\n");
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS DispatchClose(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    DbgPrint("[VulnDriver] IRP_MJ_CLOSE\n");
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS DispatchDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP           Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION  stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG               ioctl = stack->Parameters.DeviceIoControl.IoControlCode;
    PVOID               inputBuf = Irp->AssociatedIrp.SystemBuffer;
    ULONG               inputLen = stack->Parameters.DeviceIoControl.InputBufferLength;
    NTSTATUS            status = STATUS_SUCCESS;
    ULONG_PTR           information = 0;

    switch (ioctl)
    {
        // ── IOCTL_ACQUIRE ────────────────────────────────────────────────────────
    case IOCTL_ACQUIRE:
        DbgPrint("[VulnDriver] IOCTL_ACQUIRE\n");
        status = AcquireObject();
        break;

        // ── IOCTL_RELEASE ────────────────────────────────────────────────────────
    case IOCTL_RELEASE:
        DbgPrint("[VulnDriver] IOCTL_RELEASE\n");
        status = ReleaseObject();
        break;

        // ── IOCTL_WRITE_BUFFER ───────────────────────────────────────────────────
    case IOCTL_WRITE_BUFFER:
    {
        if (inputLen < sizeof(WRITE_INPUT)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        PWRITE_INPUT writeInput = (PWRITE_INPUT)inputBuf;
        ULONG dataSize = inputLen - FIELD_OFFSET(WRITE_INPUT, Data);

        status = WriteToBuffer(writeInput->Offset, writeInput->Data, dataSize);
        break;
    }

    // ── IOCTL_READ_BUFFER ────────────────────────────────────────────────────
    case IOCTL_READ_BUFFER:
    {
        PVOID outputBuf = Irp->AssociatedIrp.SystemBuffer;
        ULONG outputLen = stack->Parameters.DeviceIoControl.OutputBufferLength;

        if (g_VulnObject == NULL || g_VulnObject->Buffer == NULL) {
            status = STATUS_INVALID_DEVICE_STATE;
            break;
        }

        ULONG copySize = min(outputLen, g_VulnObject->BufferSize);
        RtlCopyMemory(outputBuf, g_VulnObject->Buffer, copySize);
        information = copySize;
        break;
    }

    // ── IOCTL_WRITE_ABSOLUTE ─────────────────────────────────────────────────
    // Writes directly to an arbitrary kernel address.
    // Intentional vulnerability   demonstrates the full write primitive.
    // In real drivers, this manifests as lack of validation on pointers
    // received from usermode.
    case IOCTL_WRITE_ABSOLUTE:
    {
        if (inputLen < sizeof(WRITE_ABSOLUTE_INPUT)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        PWRITE_ABSOLUTE_INPUT wa = (PWRITE_ABSOLUTE_INPUT)inputBuf;

        if (wa->KernelAddr == 0 || wa->Size == 0 || wa->Size > 8) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        DbgPrint("[VulnDriver] IOCTL_WRITE_ABSOLUTE: addr=%llx size=%d\n",
            wa->KernelAddr, wa->Size);

        // Direct write to the kernel address passed from usermode
        // [VULN] no validation whether the address is mapped or valid
        RtlCopyMemory((PVOID)wa->KernelAddr, wa->Data, wa->Size);

        break;
    }

    // ── IOCTL_READ_ABSOLUTE ──────────────────────────────────────────────────
    // Reads Size bytes from the absolute kernel address KernelAddr.
    // Symmetric to WRITE_ABSOLUTE completes the read/write primitive.
    case IOCTL_READ_ABSOLUTE:
    {
        PVOID  outputBuf = Irp->AssociatedIrp.SystemBuffer;
        ULONG  outputLen = stack->Parameters.DeviceIoControl.OutputBufferLength;

        if (inputLen < sizeof(ULONG64) + sizeof(ULONG)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        ULONG64 kernelAddr = *(ULONG64*)inputBuf;
        ULONG   readSize = *(ULONG*)((PUCHAR)inputBuf + sizeof(ULONG64));

        if (readSize == 0 || readSize > 8 || outputLen < readSize) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        DbgPrint("[VulnDriver] IOCTL_READ_ABSOLUTE: addr=%llx size=%d\n",
            kernelAddr, readSize);

        // [VULN] no address validation   direct read primitive
        RtlCopyMemory(outputBuf, (PVOID)kernelAddr, readSize);
        information = readSize;
        break;
    }

    // ── IOCTL_LEAK_BUFFER_ADDR ───────────────────────────────────────────────
    // Returns the virtual address of the Buffer in kernel memory.
    // Simulates an info leak (thats all we have for today ¯\_(ツ)_/¯), in real CVEs this would come from an OOB read
    // or a field improperly exposed by a diagnostic IOCTL.
    case IOCTL_LEAK_BUFFER_ADDR:
    {
        PVOID  outputBuf = Irp->AssociatedIrp.SystemBuffer;
        ULONG  outputLen = stack->Parameters.DeviceIoControl.OutputBufferLength;

        if (outputLen < sizeof(PVOID)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        if (g_VulnObject == NULL) {
            status = STATUS_INVALID_DEVICE_STATE;
            break;
        }

        // "Leak" the Buffer address, intentional info leak
        *(PVOID*)outputBuf = g_VulnObject->Buffer;
        information = sizeof(PVOID);
        DbgPrint("[VulnDriver] IOCTL_LEAK_BUFFER_ADDR: Buffer = %p\n",
            g_VulnObject->Buffer);
        break;
    }

    // ── IOCTL_REINIT ─────────────────────────────────────────────────────────
    // Reinitializes g_VulnObject to allow new operations after the race.
    // Used by the PoC to restore state and exercise the write primitive.
    case IOCTL_REINIT:
        DbgPrint("[VulnDriver] IOCTL_REINIT\n");
        if (g_VulnObject == NULL) {
            status = InitObject();
        }
        else {
            status = STATUS_ALREADY_COMPLETE;
        }
        break;

    default:
        DbgPrint("[VulnDriver] Unknown IOCTL: 0x%x\n", ioctl);
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}


VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    UNICODE_STRING symlink = RTL_CONSTANT_STRING(SYMLINK_NAME);
    IoDeleteSymbolicLink(&symlink);

    if (g_DeviceObject) {
        IoDeleteDevice(g_DeviceObject);
    }

    if (g_VulnObject) {
        if (g_VulnObject->Buffer) {
            ExFreePoolWithTag(g_VulnObject->Buffer, POOL_TAG);
        }
        ExFreePoolWithTag(g_VulnObject, POOL_TAG);
    }

    DbgPrint("[VulnDriver] Driver unloaded\n");
}

NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS       status;
    UNICODE_STRING deviceName = RTL_CONSTANT_STRING(DEVICE_NAME);
    UNICODE_STRING symlink = RTL_CONSTANT_STRING(SYMLINK_NAME);

    DbgPrint("[VulnDriver] DriverEntry\n");

    // Register callbacks
    DriverObject->DriverUnload = DriverUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;

    // Create device object
    status = IoCreateDevice(
        DriverObject,
        0,
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &g_DeviceObject
    );

    if (!NT_SUCCESS(status)) {
        DbgPrint("[VulnDriver] IoCreateDevice failed: 0x%x\n", status);
        return status;
    }

    // Create symbolic link for usermode access via \\.\VulnDriver
    status = IoCreateSymbolicLink(&symlink, &deviceName);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[VulnDriver] IoCreateSymbolicLink failed: 0x%x\n", status);
        IoDeleteDevice(g_DeviceObject);
        return status;
    }

    // Initialize the vulnerable object
    status = InitObject();
    if (!NT_SUCCESS(status)) {
        DbgPrint("[VulnDriver] InitObject failed: 0x%x\n", status);
        IoDeleteSymbolicLink(&symlink);
        IoDeleteDevice(g_DeviceObject);
        return status;
    }

    DbgPrint("[VulnDriver] Driver loaded successfully\n");
    DbgPrint("[VulnDriver] g_VulnObject = %p\n", g_VulnObject);
    DbgPrint("[VulnDriver] Buffer       = %p\n", g_VulnObject->Buffer);

    return STATUS_SUCCESS;
}