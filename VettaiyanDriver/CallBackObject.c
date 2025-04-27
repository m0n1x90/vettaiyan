#include "DriverMeta.h"
#include "DriverHeader.h"

UNICODE_STRING altitude;
PVOID OBJECT_CALLBACK_HANDLE = NULL;
OB_CALLBACK_REGISTRATION OBJECT_CALLBACK_REGISTRATION;
OB_OPERATION_REGISTRATION OBJECT_OPERATION_REGISTRATION;

OB_PREOP_CALLBACK_STATUS PreOperationCallback(
    _In_ PVOID RegContext,
    _In_ POB_PRE_OPERATION_INFORMATION OpInfo
){

    UNREFERENCED_PARAMETER(RegContext);
    
    if (OpInfo == NULL) {
        DbgPrint("[+] PreOperationCallback: OpInfo is NULL\n");
        return OB_PREOP_SUCCESS;
    }

    switch (OpInfo->Operation) {
    case OB_OPERATION_HANDLE_CREATE:
        DbgPrint("[+] PreOperationCallback: Handle Create operation\n");
        break;
    case OB_OPERATION_HANDLE_DUPLICATE:
        DbgPrint("[+] PreOperationCallback: Handle Duplicate operation\n");
        break;
    default:
        DbgPrint("[+] PreOperationCallback: Unknown operation type: %d\n", OpInfo->Operation);
        break;
    }

    if (OpInfo->Object) {
        PEPROCESS targetProcess = (PEPROCESS)OpInfo->Object;
        HANDLE targetProcessId = PsGetProcessId(targetProcess);
        DbgPrint("[+] PreOperationCallback: Target Process ID: %d\n", targetProcessId);
    }
    else {
        DbgPrint("[+] PreOperationCallback: Object is NULL\n");
    }

    return OB_PREOP_SUCCESS;

}

NTSTATUS RegisterObjectCallbacks() {

    RtlInitUnicodeString(&altitude, DRIVER_ALTITUDE);

    OBJECT_OPERATION_REGISTRATION.ObjectType = PsProcessType;
    OBJECT_OPERATION_REGISTRATION.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;;
    OBJECT_OPERATION_REGISTRATION.PreOperation = PreOperationCallback;
    OBJECT_OPERATION_REGISTRATION.PostOperation = NULL;

    OBJECT_CALLBACK_REGISTRATION.Version = OB_FLT_REGISTRATION_VERSION;
    OBJECT_CALLBACK_REGISTRATION.OperationRegistrationCount = 1;
    OBJECT_CALLBACK_REGISTRATION.Altitude = altitude;
    OBJECT_CALLBACK_REGISTRATION.RegistrationContext = NULL;
    OBJECT_CALLBACK_REGISTRATION.OperationRegistration = &OBJECT_OPERATION_REGISTRATION;

    return  ObRegisterCallbacks(&OBJECT_CALLBACK_REGISTRATION, &OBJECT_CALLBACK_HANDLE);

}

VOID UnregisterObjectCallbacks() {

    if (OBJECT_CALLBACK_HANDLE) {
        ObUnRegisterCallbacks(OBJECT_CALLBACK_HANDLE);
        OBJECT_CALLBACK_HANDLE = NULL;
        DbgPrint("[+] Object callback unregister succeeded\n");
    }

}