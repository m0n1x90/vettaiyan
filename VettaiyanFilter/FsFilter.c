#include "FsFilter.h"

PFLT_FILTER FSFilterHandle = NULL;

const FLT_OPERATION_REGISTRATION FSFilterCallbacks[] = {
    { IRP_MJ_CREATE,0,FSCreatePreCallback,FSCreatePostCallback },
    //{ IRP_MJ_WRITE, 0, FSWritePreCallback, NULL },
    //{ IRP_MJ_SET_INFORMATION, 0, FSSetInfoPreCallback, NULL },
    { IRP_MJ_OPERATION_END }
};

const FLT_REGISTRATION FSFilterRegistration = {
    sizeof(FLT_REGISTRATION),      // Size
    FLT_REGISTRATION_VERSION,      // Version
    0,                             // Flags
    NULL,                          // Contexts
    FSFilterCallbacks,             // Operation callbacks
    UnloadFSFilter,                // FilterUnloadCallback
    NULL,                          // InstanceSetup
    NULL,                          // InstanceQueryTeardown
    NULL,                          // InstanceTeardownStart
    NULL,                          // InstanceTeardownComplete
    NULL,                          // GenerateFileName
    NULL,                          // GenerateDestinationFileName
    NULL,                          // NormalizeNameComponent
    NULL                           // NormalizeContextCleanup
};


NTSTATUS RegisterFSFilter(_In_ PDRIVER_OBJECT DriverObject) 
{

    NTSTATUS status;

    KdPrint(("[ VettaiyanFilter ] Registering Vettaiyan Filter"));
    status = FltRegisterFilter(DriverObject, &FSFilterRegistration, &FSFilterHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    KdPrint(("[ VettaiyanFilter ] Starting Vettaiyan Filter"));
    status = FltStartFiltering(FSFilterHandle);
    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(FSFilterHandle);
    }

    return status;

}


NTSTATUS UnloadFSFilter(_In_ FLT_FILTER_UNLOAD_FLAGS Flags) 
{

    UNREFERENCED_PARAMETER(Flags);

    KdPrint(("[ VettaiyanFilter ] Unloading Vettaiyan Filter"));
    FltUnregisterFilter(FSFilterHandle);
    return STATUS_SUCCESS;

}

NTSTATUS UnregisterFSFilter() 
{
    KdPrint(("[ VettaiyanFilter ] Unregistering Vettaiyan Filter"));
    FltUnregisterFilter(FSFilterHandle);
    return STATUS_SUCCESS;

}