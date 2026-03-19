/*
 * CallBackObject.c -- monitors process and thread handle operations.
 *
 * Uses ObRegisterCallbacks to watch every time a process or thread
 * handle is created or duplicated. This catches things like:
 *   - OpenProcess with PROCESS_VM_WRITE (remote injection setup)
 *   - OpenThread with THREAD_SET_CONTEXT (APC injection)
 *   - OpenThread with THREAD_SUSPEND_RESUME (process hollowing)
 *   - Handle duplication to escalate access rights
 *   - Attempts to open lsass, csrss, or our own agent
 *
 * We log the source PID, target PID/TID, and what access was requested
 * vs what was originally asked for. The agent uses this to detect
 * suspicious cross-process access patterns.
 */

#include "CallBackObject.h"
#include "DriverMeta.h"
#include "EventBuffer.h"
#include "../EdrCommon/EdrEvents.h"

/* Registration state -- kept around so we can unregister on unload */
UNICODE_STRING altitude;
PVOID OBJECT_CALLBACK_HANDLE = NULL;
OB_CALLBACK_REGISTRATION OBJECT_CALLBACK_REGISTRATION;
OB_OPERATION_REGISTRATION OBJECT_OPERATION_REGISTRATION[2];  /* [0]=process, [1]=thread */

/*
 * PreOperationCallback -- fires before a process or thread handle is granted.
 *
 * We get the operation type (create vs duplicate), the target object,
 * and the access rights being requested. Works for both PsProcessType
 * and PsThreadType -- we check ObjectType to tell them apart.
 */
OB_PREOP_CALLBACK_STATUS PreOperationCallback(
    _In_ PVOID RegContext,
    _In_ POB_PRE_OPERATION_INFORMATION OpInfo
){

    UNREFERENCED_PARAMETER(RegContext);
    
    if (OpInfo == NULL) return OB_PREOP_SUCCESS;

    EDR_HANDLE_EVENT event = { 0 };

    /* Figure out what kind of handle operation this is */
    switch (OpInfo->Operation) {
    case OB_OPERATION_HANDLE_CREATE:
        event.Header.EventType = EdrEventHandleCreate;
        break;
    case OB_OPERATION_HANDLE_DUPLICATE:
        event.Header.EventType = EdrEventHandleDuplicate;
        break;
    default:
        return OB_PREOP_SUCCESS;
    }

    /* Fill in the common header fields */
    KeQuerySystemTimePrecise(&event.Header.Timestamp);
    event.Header.ProcessId = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    event.Header.ThreadId = (ULONG)(ULONG_PTR)PsGetCurrentThreadId();
    event.Header.EventSize = sizeof(EDR_HANDLE_EVENT);
    event.Header.SequenceNumber = GetNextSequenceNumber();

    /* Process handle -- grab the target PID */
    if (OpInfo->ObjectType == *PsProcessType) {
        if (OpInfo->Object) {
            PEPROCESS targetProcess = (PEPROCESS)OpInfo->Object;
            event.TargetProcessId = (ULONG)(ULONG_PTR)PsGetProcessId(targetProcess);
        }
    }
    /* Thread handle -- grab both the target TID and its owning PID */
    else if (OpInfo->ObjectType == *PsThreadType) {
        if (OpInfo->Object) {
            PETHREAD targetThread = (PETHREAD)OpInfo->Object;
            event.TargetThreadId = (ULONG)(ULONG_PTR)PsGetThreadId(targetThread);
            event.TargetProcessId = (ULONG)(ULONG_PTR)PsGetThreadProcessId(targetThread);
        }
    }

    /* Capture the access rights -- both what was requested and what
       the caller originally asked for (before any stripping) */
    if (OpInfo->Operation == OB_OPERATION_HANDLE_CREATE) {
        event.DesiredAccess = OpInfo->Parameters->CreateHandleInformation.DesiredAccess;
        event.OriginalAccess = OpInfo->Parameters->CreateHandleInformation.OriginalDesiredAccess;
    } else {
        event.DesiredAccess = OpInfo->Parameters->DuplicateHandleInformation.DesiredAccess;
        event.OriginalAccess = OpInfo->Parameters->DuplicateHandleInformation.OriginalDesiredAccess;
    }

    /* Queue for the agent to pick up */
    PushEvent(&event, sizeof(event));

    return OB_PREOP_SUCCESS;

}

/* Register object callbacks for both process and thread handles */
NTSTATUS RegisterObjectCallbacks() {

    RtlInitUnicodeString(&altitude, DRIVER_ALTITUDE);

    /* [0] Watch process handle create and duplicate */
    OBJECT_OPERATION_REGISTRATION[0].ObjectType = PsProcessType;
    OBJECT_OPERATION_REGISTRATION[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    OBJECT_OPERATION_REGISTRATION[0].PreOperation = PreOperationCallback;
    OBJECT_OPERATION_REGISTRATION[0].PostOperation = NULL;

    /* [1] Watch thread handle create and duplicate -- catches APC injection,
       SetThreadContext, and suspend/resume used in process hollowing */
    OBJECT_OPERATION_REGISTRATION[1].ObjectType = PsThreadType;
    OBJECT_OPERATION_REGISTRATION[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    OBJECT_OPERATION_REGISTRATION[1].PreOperation = PreOperationCallback;
    OBJECT_OPERATION_REGISTRATION[1].PostOperation = NULL;

    OBJECT_CALLBACK_REGISTRATION.Version = OB_FLT_REGISTRATION_VERSION;
    OBJECT_CALLBACK_REGISTRATION.OperationRegistrationCount = 2;
    OBJECT_CALLBACK_REGISTRATION.Altitude = altitude;
    OBJECT_CALLBACK_REGISTRATION.RegistrationContext = NULL;
    OBJECT_CALLBACK_REGISTRATION.OperationRegistration = OBJECT_OPERATION_REGISTRATION;

    return  ObRegisterCallbacks(&OBJECT_CALLBACK_REGISTRATION, &OBJECT_CALLBACK_HANDLE);

}

/* Tear down -- called during driver unload */
VOID UnregisterObjectCallbacks() {

    if (OBJECT_CALLBACK_HANDLE) {
        ObUnRegisterCallbacks(OBJECT_CALLBACK_HANDLE);
        OBJECT_CALLBACK_HANDLE = NULL;
        DbgPrint("[ VettaiyanDriver ] Object callback unregister succeeded\n");
    }

}