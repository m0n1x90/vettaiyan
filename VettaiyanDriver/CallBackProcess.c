/*
 * CallBackProcess.c -- watches every process create and terminate.
 *
 * The kernel calls us whenever a process starts or exits. We capture
 * the PID, parent PID, session ID, image path for both the process
 * and its parent, then queue the event for the agent.
 *
 * This is foundational telemetry -- the agent uses it to build
 * a process tree and detect things like unusual parent-child
 * relationships (e.g. Word spawning PowerShell).
 */

#include "CallBackProcess.h"
#include "EventBuffer.h"

/* PsGetProcessSessionId may not be declared in all WDK header versions */
NTKERNELAPI ULONG PsGetProcessSessionId(_In_ PEPROCESS Process);

/*
 * EdrCreateProcessNotifyRoutine -- fires on every process create/terminate.
 *
 * For creates: we resolve both the new process and its parent image paths.
 * For terminates: just log that the PID is gone.
 */
VOID EdrCreateProcessNotifyRoutine(
    _In_ HANDLE ParentProcessId,
    _In_ HANDLE ProcessId,
    _In_ BOOLEAN Create
) {

    EDR_PROCESS_EVENT event = { 0 };
    PEPROCESS process = NULL;
    PUNICODE_STRING processName = NULL;
    PUNICODE_STRING parentProcessName = NULL;

    /* Create or terminate? */
    event.Header.EventType = Create ? EdrEventProcessCreate : EdrEventProcessTerminate;
    KeQuerySystemTimePrecise(&event.Header.Timestamp);
    event.Header.ProcessId = (ULONG)(ULONG_PTR)ProcessId;
    event.Header.ThreadId = (ULONG)(ULONG_PTR)PsGetCurrentThreadId();
    event.Header.EventSize = sizeof(EDR_PROCESS_EVENT);
    event.Header.SequenceNumber = GetNextSequenceNumber();
    event.ParentProcessId = (ULONG)(ULONG_PTR)ParentProcessId;

    /* Look up the new process -- get its image path, session, and logon ID */
    if (NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &process))) {
        if (NT_SUCCESS(SeLocateProcessImageName(process, &processName)) && processName) {
            RtlStringCbCopyUnicodeString(event.ImagePath, sizeof(event.ImagePath), processName);
        }
        event.SessionId = (ULONG)(ULONG_PTR)PsGetProcessSessionId(process);

        /* Grab the logon session LUID from the process token.
           The agent maps this to a LogonType via LsaGetLogonSessionData:
           type 3 = network (PsExec/WMI), type 10 = RDP, etc. */
        {
            PACCESS_TOKEN token = PsReferencePrimaryToken(process);
            if (token) {
                LUID authId = { 0 };
                if (NT_SUCCESS(SeQueryAuthenticationIdToken(token, &authId))) {
                    event.AuthenticationId = authId;
                }
                PsDereferencePrimaryToken(token);
            }
        }

        ObDereferenceObject(process);
    }

    /* Look up the parent -- agent uses this to build the process tree */
    if (NT_SUCCESS(PsLookupProcessByProcessId(ParentProcessId, &process))) {
        if (NT_SUCCESS(SeLocateProcessImageName(process, &parentProcessName)) && parentProcessName) {
            RtlStringCbCopyUnicodeString(event.ParentImagePath, sizeof(event.ParentImagePath), parentProcessName);
        }
        ObDereferenceObject(process);
    }

    /* Queue for the agent to pick up */
    PushEvent(&event, sizeof(event));

}

/* Register our callback with the kernel */
NTSTATUS RegisterProcessNotifyRoutine() {
    return PsSetCreateProcessNotifyRoutine(EdrCreateProcessNotifyRoutine, FALSE);
}

/* Unregister -- called during driver unload */
NTSTATUS UnregisterProcessNotifyRoutine() {
    return PsSetCreateProcessNotifyRoutine(EdrCreateProcessNotifyRoutine, TRUE);
}