/*
 * FsFilter.c -- filter registration, startup, and teardown.
 *
 * This is where everything hooks together. We tell the filter manager
 * which IRPs we care about (create, write, set-info, close), wire up
 * the comm port so the agent can talk to us, and start filtering.
 */

#include "FsFilter.h"

PFLT_FILTER FSFilterHandle = NULL;

/* The IRPs we intercept and which callbacks handle them. */
const FLT_OPERATION_REGISTRATION FSFilterCallbacks[] = {
    { IRP_MJ_CREATE,          0, FSCreatePreCallback, FSCreatePostCallback },
    { IRP_MJ_WRITE,           0, FSWritePreCallback,  NULL },
    { IRP_MJ_SET_INFORMATION, 0, FSSetInfoPreCallback, NULL },
    { IRP_MJ_CLOSE,           0, FSClosePreCallback,  NULL },
    { IRP_MJ_OPERATION_END }
};

/* Tells the filter manager who we are and what we do. */
const FLT_REGISTRATION FSFilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,                             /* No special flags */
    NULL,                          /* No contexts */
    FSFilterCallbacks,             /* Operation callbacks */
    UnloadFSFilter,                /* FilterUnloadCallback */
    NULL,                          /* InstanceSetup */
    NULL,                          /* InstanceQueryTeardown */
    NULL,                          /* InstanceTeardownStart */
    NULL,                          /* InstanceTeardownComplete */
    NULL,                          /* GenerateFileName */
    NULL,                          /* GenerateDestinationFileName */
    NULL,                          /* NormalizeNameComponent */
    NULL                           /* NormalizeContextCleanup */
};


PFLT_FILTER GetFilterHandle(VOID)
{
    return FSFilterHandle;
}


/*
 * Register with the filter manager, open the comm port, start filtering.
 * If the comm port fails we keep going -- the filter still works,
 * it just can't talk to the agent until it reconnects.
 */
NTSTATUS RegisterFSFilter(_In_ PDRIVER_OBJECT DriverObject) 
{
    NTSTATUS status;

    KdPrint(("[ VettaiyanFilter ] Registering filter\n"));
    status = FltRegisterFilter(DriverObject, &FSFilterRegistration, &FSFilterHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    /* Open the comm port so the agent can connect */
    status = InitializeFilterCommPort(FSFilterHandle);
    if (!NT_SUCCESS(status)) {
        KdPrint(("[ VettaiyanFilter ] Comm port failed (non-fatal): 0x%X\n", status));
    }

    KdPrint(("[ VettaiyanFilter ] Starting filter\n"));
    status = FltStartFiltering(FSFilterHandle);
    if (!NT_SUCCESS(status)) {
        CleanupFilterCommPort();
        FltUnregisterFilter(FSFilterHandle);
    }

    return status;
}


/* Called when the filter is asked to unload (fltmc unload, etc.) */
NTSTATUS UnloadFSFilter(_In_ FLT_FILTER_UNLOAD_FLAGS Flags) 
{
    UNREFERENCED_PARAMETER(Flags);

    KdPrint(("[ VettaiyanFilter ] Unloading filter\n"));
    CleanupFilterCommPort();
    FltUnregisterFilter(FSFilterHandle);
    return STATUS_SUCCESS;
}

/* Manual unregister path -- same cleanup, different entry point. */
NTSTATUS UnregisterFSFilter() 
{
    KdPrint(("[ VettaiyanFilter ] Unregistering filter\n"));
    CleanupFilterCommPort();
    FltUnregisterFilter(FSFilterHandle);
    return STATUS_SUCCESS;
}