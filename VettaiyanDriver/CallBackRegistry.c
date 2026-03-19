/*
 * CallBackRegistry.c -- monitors registry mutations in real time.
 *
 * Uses CmRegisterCallbackEx to watch registry operations system-wide.
 * We only care about mutations (create, delete, rename, set value) -- 
 * read-only operations are ignored to keep the event stream manageable.
 *
 * Registry is a prime target for persistence (Run keys, services,
 * scheduled tasks), defense evasion (disabling Defender, firewall rules),
 * and credential access (SAM hive manipulation). Watching mutations
 * lets the agent flag suspicious writes like:
 *   - HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\*
 *   - HKLM\SYSTEM\CurrentControlSet\Services\*
 *   - HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\*
 */

#include "DriverMeta.h"
#include "CallBackRegistry.h"
#include "EventBuffer.h"

/* Cookie from CmRegisterCallbackEx -- needed to unregister and to
   resolve key objects back to their full registry paths */
LARGE_INTEGER REGISTRY_CALLBACK_COOKIE = { 0 };

/*
 * EdrRegistryNotifyCallback -- called by the config manager on every
 * registry operation. Argument1 is the REG_NOTIFY_CLASS telling us
 * what kind of operation it is. Argument2 is operation-specific context.
 *
 * We treat Argument2 as a REG_POST_OPERATION_INFORMATION to get the
 * key object, then switch on the notify class to decide if we care.
 */
NTSTATUS EdrRegistryNotifyCallback(
    _In_ PVOID CallbackContext,
    _In_ PVOID Argument1,
    _In_ PVOID Argument2
) {

    UNREFERENCED_PARAMETER(CallbackContext);

    NTSTATUS status;
    PCUNICODE_STRING RegistryPath = NULL;

    /* Argument1 = what kind of registry operation (create, delete, set, etc.)
       Argument2 = pointer to operation-specific struct with the key object */
    REG_NOTIFY_CLASS notifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;
    PREG_POST_OPERATION_INFORMATION RegPostOperationInfo = (PREG_POST_OPERATION_INFORMATION)Argument2;

    /* Validate the key object pointer before touching it */
    if (RegPostOperationInfo && MmIsAddressValid(RegPostOperationInfo->Object)) {
        
        EDR_REGISTRY_EVENT event = { 0 };
        EDR_EVENT_TYPE eventType = EdrEventNone;

        /* Only report mutations -- reads are too noisy and not
           interesting from a detection standpoint */
        switch (notifyClass) {
            case RegNtDeleteValueKey:
                eventType = EdrEventRegistryDeleteValue;
                break;
            case RegNtDeleteKey:
                eventType = EdrEventRegistryDeleteKey;
                break;
            case RegNtSetValueKey:
                eventType = EdrEventRegistrySetValue;
                break;
            case RegNtRenameKey:
                eventType = EdrEventRegistryRenameKey;
                break;
            case RegNtPreCreateKeyEx:
                eventType = EdrEventRegistryCreateKey;
                break;
            default:
                /* Reads, enumerations, flushes -- not worth reporting */
                return STATUS_SUCCESS;
        };

        /* Resolve the key object to its full registry path string.
           We need our callback cookie to do this lookup. */
        status = CmCallbackGetKeyObjectIDEx(
            &REGISTRY_CALLBACK_COOKIE,
            RegPostOperationInfo->Object,
            NULL,
            &RegistryPath,
            0
        );

        /* If we can't get the path, skip silently -- don't block the operation */
        if (!NT_SUCCESS(status) || RegistryPath == NULL || RegistryPath->Length == 0 || !MmIsAddressValid(RegistryPath->Buffer)) {
            return STATUS_SUCCESS;
        }

        /* Build the event -- who did it, when, and to which key */
        event.Header.EventType = eventType;
        KeQuerySystemTimePrecise(&event.Header.Timestamp);
        event.Header.ProcessId = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
        event.Header.ThreadId = (ULONG)(ULONG_PTR)PsGetCurrentThreadId();
        event.Header.EventSize = sizeof(EDR_REGISTRY_EVENT);
        event.Header.SequenceNumber = GetNextSequenceNumber();

        /* Copy the full registry path into the event buffer */
        RtlStringCbCopyUnicodeString(event.KeyPath, sizeof(event.KeyPath), RegistryPath);

        /* For SetValue, grab the value name too -- knowing which specific
           value was written matters (e.g. Run key "malware" vs "OneDrive") */
        if (notifyClass == RegNtSetValueKey) {
            PREG_SET_VALUE_KEY_INFORMATION setInfo = (PREG_SET_VALUE_KEY_INFORMATION)Argument2;
            if (setInfo && setInfo->ValueName && setInfo->ValueName->Buffer) {
                RtlStringCbCopyUnicodeString(event.ValueName, sizeof(event.ValueName), setInfo->ValueName);
            }
        }

        /* Send to the agent */
        PushEvent(&event, sizeof(event));

        /* Release the path string allocated by CmCallbackGetKeyObjectIDEx */
        CmCallbackReleaseKeyObjectIDEx(RegistryPath);
    }

    return STATUS_SUCCESS;

};

/* Register our registry callback at our driver altitude.
   DriverObject is passed as the callback context owner. */
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

/* Unregister -- called during driver unload. Uses the cookie
   we got back from CmRegisterCallbackEx. */
NTSTATUS UnregisterRegistryCallbacks() {

	return CmUnRegisterCallback(REGISTRY_CALLBACK_COOKIE);

}