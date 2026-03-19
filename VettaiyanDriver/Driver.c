#include "DriverMeta.h"
#include "DriverHeader.h"
#include "DeviceHandler.h"
#include "CallBackAll.h"
#include "EventBuffer.h"


VOID DriverUnload(
    _In_ PDRIVER_OBJECT DriverObject
)
{
    
    UNREFERENCED_PARAMETER(DriverObject);

    NTSTATUS status;

    status = UnregisterImageNotifyRoutine();
    if (!NT_SUCCESS(status)) {
       DbgPrint("[ VettaiyanDriver ] Failed to unregister EdrLoadImageNotifyRoutine : %08X\n", status);
    }
    status = UnregisterProcessNotifyRoutine();
    if (!NT_SUCCESS(status)) {
       DbgPrint("[ VettaiyanDriver ] Failed to unregister EdrCreateProcessNotifyRoutine : %08X\n", status);
    }
    status = UnregisterThreadNotifyRoutine();
    if (!NT_SUCCESS(status)) {
       DbgPrint("[ VettaiyanDriver ] Failed to unregister EdrCreateThreadNotifyRoutine : %08X\n", status);
    }

    UnregisterRegistryCallbacks();
    UnregisterObjectCallbacks();

    /* Cleanup event buffer before removing device */
    CleanupEventBuffer();

    UNICODE_STRING symbolicLinkName;
    RtlInitUnicodeString(&symbolicLinkName, EDR_SYMLINK_NAME);
    IoDeleteSymbolicLink(&symbolicLinkName);
    IoDeleteDevice(DriverObject->DeviceObject);

    DbgPrint("[ VettaiyanDriver ] Driver Unloaded\n");

}


NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS status;
    UNICODE_STRING deviceName;
    UNICODE_STRING symbolicLinkName;
    PDEVICE_OBJECT deviceObject = NULL;

    // Initialise Driver Device -- SYSTEM and Administrators only
    RtlInitUnicodeString(&deviceName, EDR_DEVICE_NAME);
    UNICODE_STRING sddl;
    RtlInitUnicodeString(&sddl, L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
    status = IoCreateDeviceSecure(
        DriverObject,
        0,
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        0,
        FALSE,
        &sddl,
        NULL,
        &deviceObject
    );
    if (!NT_SUCCESS(status)) {
        DbgPrint("[ VettaiyanDriver ] Failed to create device: 0x%X\n", status);
        return status;
    }

    // Initialise Driver Symlink
    RtlInitUnicodeString(&symbolicLinkName, EDR_SYMLINK_NAME);
    status = IoCreateSymbolicLink(&symbolicLinkName, &deviceName);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[ VettaiyanDriver ] Failed to create symbolic link: 0x%X\n", status);
        IoDeleteDevice(deviceObject);
        return status;
    }

    // Initialise Driver Major Functions
    DbgPrint("[ VettaiyanDriver ] Loading Driver\n");
    DriverObject->DriverUnload = DriverUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DriverCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverDeviceControl;

    // Initialize event buffer (must be before registering callbacks)
    status = InitializeEventBuffer();
    if (!NT_SUCCESS(status)) {
        DbgPrint("[ VettaiyanDriver ] Failed to initialize event buffer: 0x%X\n", status);
        IoDeleteSymbolicLink(&symbolicLinkName);
        IoDeleteDevice(deviceObject);
        return status;
    }
    DbgPrint("[ VettaiyanDriver ] Event buffer initialized\n");

    // Register Image Notification Routine
    status = RegisterImageNotifyRoutine();
    if (!NT_SUCCESS(status)) {
       DbgPrint("[ VettaiyanDriver ] Failed to register EdrLoadImageNotifyRoutine : %08X\n", status);
       return status;
    }
    DbgPrint("[ VettaiyanDriver ] Loaded Image Notify Routine\n");

    // Register Process Notification Routine
    status = RegisterProcessNotifyRoutine();
    if (!NT_SUCCESS(status)) {
       DbgPrint("[ VettaiyanDriver ] Failed to register EdrCreateProcessNotifyRoutine : %08X\n", status);
       return status;
    }
    DbgPrint("[ VettaiyanDriver ] Loaded Process Notify Routine\n");

    // Register Thread Notification Routine
    status = RegisterThreadNotifyRoutine();
    if (!NT_SUCCESS(status)) {
       DbgPrint("[ VettaiyanDriver ] Failed to register EdrCreateThreadNotifyRoutine : %08X\n", status);
       return status;
    }
    DbgPrint("[ VettaiyanDriver ] Loaded Thread Notify Routine\n");

    // Register Registry Callbacks
    status = RegisterRegistryCallbacks(DriverObject);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[ VettaiyanDriver ] Failed to register Registry Callbacks: %08X\n", status);
        /* Non-fatal - continue without registry monitoring */
    } else {
        DbgPrint("[ VettaiyanDriver ] Loaded Registry Callbacks\n");
    }

    // Register Object Callbacks
    status = RegisterObjectCallbacks();
    if (!NT_SUCCESS(status)) {
        DbgPrint("[ VettaiyanDriver ] Failed to register Object Callbacks: %08X\n", status);
        /* Non-fatal - continue without object monitoring */
    } else {
        DbgPrint("[ VettaiyanDriver ] Loaded Object Callbacks\n");
    }

    DbgPrint("[ VettaiyanDriver ] Driver Loaded Successfully - All Sensors Active\n");
    return STATUS_SUCCESS;

}

