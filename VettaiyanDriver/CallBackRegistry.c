#include "DriverMeta.h"
#include "CallBackRegistry.h"

LARGE_INTEGER REGISTRY_CALLBACK_COOKIE = { 0 };

NTSTATUS EdrRegistryNotifyCallback(
    _In_ PVOID CallbackContext,
    _In_ PVOID Argument1,
    _In_ PVOID Argument2
) {

    UNREFERENCED_PARAMETER(CallbackContext);

    NTSTATUS status;
    PCUNICODE_STRING RegistryPath = NULL;
    REG_NOTIFY_CLASS notifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;
    PREG_POST_OPERATION_INFORMATION RegPostOperationInfo = (PREG_POST_OPERATION_INFORMATION)Argument2;

    if (RegPostOperationInfo && MmIsAddressValid(RegPostOperationInfo->Object)) {
        
        switch (notifyClass) {
            case RegNtDeleteValueKey:
                DbgPrint("[+] Registry operation: Delete Value Key\n");
                break;
            case RegNtDeleteKey:
                DbgPrint("[+] Registry operation: Delete Key\n");
                break;
            case RegNtSetValueKey:
                DbgPrint("[+] Registry operation: Set Value Key\n");
                break;
            case RegNtSetInformationKey:
                DbgPrint("[+] Registry operation: Set Information Key\n");
                break;
            case RegNtQueryKey:
                DbgPrint("[+] Registry operation: Query Key\n");
                break;
            case RegNtQueryValueKey:
                DbgPrint("[+] Registry operation: Query Value Key\n");
                break;
            case RegNtEnumerateKey:
                DbgPrint("[+] Registry operation: Enumerate Key\n");
                break;
            case RegNtEnumerateValueKey:
                DbgPrint("[+] Registry operation: Enumerate Value Key\n");
                break;
            case RegNtRenameKey:
                DbgPrint("[+] Registry operation: Rename Key\n");
                break;
            default:
                DbgPrint("[+] Registry operation: Unknown operation type: %d\n", notifyClass);
                break;
        };

        status = CmCallbackGetKeyObjectIDEx(
            &REGISTRY_CALLBACK_COOKIE,
            RegPostOperationInfo->Object,
            NULL,
            &RegistryPath,
            0
        );

        if (!NT_SUCCESS(status) || RegistryPath == NULL || RegistryPath->Length == 0 || !MmIsAddressValid(RegistryPath->Buffer)) {
            return STATUS_SUCCESS;
        }
        else {
            DbgPrint("[+] Registry Path: %wZ\n", RegistryPath);
            return STATUS_SUCCESS;
        }
    }

    return STATUS_SUCCESS;

};

NTSTATUS RegisterRegistryCallbacks(
	_In_ PVOID DriverObject
){

	UNICODE_STRING altitude;
	RtlInitUnicodeString(&altitude, DRIVER_ALTITUDE);

	return CmRegisterCallbackEx(
		EdrRegistryNotifyCallback,
		&altitude,
		DriverObject,
		NULL,
		&REGISTRY_CALLBACK_COOKIE,
		NULL
	);

}

NTSTATUS UnregisterRegistryCallbacks() {

	return CmUnRegisterCallback(REGISTRY_CALLBACK_COOKIE);

}