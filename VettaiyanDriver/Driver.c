#include "DriverMeta.h"
#include "DriverHeader.h"
#include "DeviceHandler.h"
#include "CallBackAll.h"


VOID DriverUnload(
    _In_ PDRIVER_OBJECT DriverObject
)
{
    
    UNREFERENCED_PARAMETER(DriverObject);

    NTSTATUS status;

    //status = UnregisterImageNotifyRoutine();
    //if (!NT_SUCCESS(status)) {
    //    DbgPrint("[-] Failed to unregister EdrLoadImageNotifyRoutine : %08X\n", status);
    //}
    //status = UnregisterProcessNotifyRoutine();
    //if (!NT_SUCCESS(status)) {
    //    DbgPrint("[-] Failed to unregister EdrCreateProcessNotifyRoutine : %08X\n", status);
    //}
    //status = UnregisterThreadNotifyRoutine();
    //if (!NT_SUCCESS(status)) {
    //    DbgPrint("[-] Failed to unregister EdrCreateThreadNotifyRoutine : %08X\n", status);
    //}
    status = UnregisterRegistryCallbacks();
    if (!NT_SUCCESS(status)) {
        DbgPrint("[-] Failed to unregister EdrCreateThreadNotifyRoutine : %08X\n", status);
    }

    UnregisterObjectCallbacks();


    UNICODE_STRING symbolicLinkName;
    RtlInitUnicodeString(&symbolicLinkName, EDR_SYMLINK_NAME);
    IoDeleteSymbolicLink(&symbolicLinkName);
    IoDeleteDevice(DriverObject->DeviceObject);

    DbgPrint("[+] Driver Unloaded\n");

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

    // Initialise Driver Device
    RtlInitUnicodeString(&deviceName, EDR_DEVICE_NAME);
    status = IoCreateDevice(
        DriverObject,
        0,
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        0,
        FALSE,
        &deviceObject
    );
    if (!NT_SUCCESS(status)) {
        DbgPrint("[-] Failed to create device: 0x%X\n", status);
        return status;
    }

    // Initialise Driver Symlink
    RtlInitUnicodeString(&symbolicLinkName, EDR_SYMLINK_NAME);
    status = IoCreateSymbolicLink(&symbolicLinkName, &deviceName);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[-] Failed to create symbolic link: 0x%X\n", status);
        IoDeleteDevice(deviceObject);
        return status;
    }

    // Initialise Driver Major Functions
    DbgPrint("[+] Loading Driver\n");
    DriverObject->DriverUnload = DriverUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DriverCreateClose;

    // Register Image Notification Routine
    //status = RegisterImageNotifyRoutine();
    //if (!NT_SUCCESS(status)) {
    //    DbgPrint("[-] Failed to register EdrLoadImageNotifyRoutine : %08X\n", status);
    //    return status;
    //}
    //DbgPrint("[+] Loaded Image Notify Routine\n");

    //// Register Process Notification Routine
    //status = RegisterProcessNotifyRoutine();
    //if (!NT_SUCCESS(status)) {
    //    DbgPrint("[-] Failed to register EdrCreateProcessNotifyRoutine : %08X\n", status);
    //    return status;
    //}
    //DbgPrint("[+] Loaded Process Notify Routine\n");

    //// Register Thread Notification Routine
    //status = RegisterThreadNotifyRoutine();
    //if (!NT_SUCCESS(status)) {
    //    DbgPrint("[-] Failed to register EdrCreateThreadNotifyRoutine : %08X\n", status);
    //    return status;
    //}
    //DbgPrint("[+] Loaded Thread Notify Routine\n");

    //Register Registry Callbacks
    status = RegisterRegistryCallbacks(DriverObject);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[-] Failed to register Registry callbacks : %08X\n", status);
        return status;
    }
    DbgPrint("[+] Registry callback registration succeeded\n");

    // Register Object Callbacks
    status = RegisterObjectCallbacks();
    if (!NT_SUCCESS(status)) {
        DbgPrint("[-] Failed to register Object callbacks : %08X\n", status);
        return status;
    }
    DbgPrint("[+] Object callback registration succeeded\n");

    DbgPrint("[+] Driver Loaded Successfully\n");
    return STATUS_SUCCESS;

}

