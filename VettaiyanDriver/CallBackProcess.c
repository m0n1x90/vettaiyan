/*
 * CallBackProcess.c -- watches every process create and terminate.
 *
 * Uses PsSetCreateProcessNotifyRoutineEx to get the full
 * PS_CREATE_NOTIFY_INFO on create, which includes CommandLine.
 * The kernel calls us whenever a process starts or exits. We capture
 * the PID, parent PID, session ID, image path, and command line,
 * then queue the event for the agent.
 *
 * This is foundational telemetry -- the agent uses it to build
 * a process tree and detect things like unusual parent-child
 * relationships (e.g. Word spawning PowerShell).
 */

#include "CallBackProcess.h"
#include "EventBuffer.h"

/* PsGetProcessSessionId may not be declared in all WDK header versions */
NTKERNELAPI ULONG PsGetProcessSessionId(_In_ PEPROCESS Process);
NTKERNELAPI HANDLE PsGetProcessInheritedFromUniqueProcessId(_In_ PEPROCESS Process);

/*
 * EdrCreateProcessNotifyRoutine -- fires on every process create/terminate.
 *
 * CreateInfo non-NULL = create. CreateInfo NULL = terminate.
 * For creates: we get image path from CreateInfo->ImageFileName,
 *   command line from CreateInfo->CommandLine, and parent PID from
 *   CreateInfo->ParentProcessId.
 * For terminates: just log that the PID is gone.
 */
VOID EdrCreateProcessNotifyRoutine(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
) {

    EDR_PROCESS_EVENT event = { 0 };
    PEPROCESS parentProcess = NULL;

    /* Create or terminate? CreateInfo is non-NULL for creates. */
    event.Header.EventType = CreateInfo ? EdrEventProcessCreate : EdrEventProcessTerminate;
    KeQuerySystemTimePrecise(&event.Header.Timestamp);
    event.Header.ProcessId = (ULONG)(ULONG_PTR)ProcessId;
    event.Header.ThreadId = (ULONG)(ULONG_PTR)PsGetCurrentThreadId();
    event.Header.EventSize = sizeof(EDR_PROCESS_EVENT);
    event.Header.SequenceNumber = GetNextSequenceNumber();

    if (CreateInfo) {
        /* ---- Process Create ---- */
        event.ParentProcessId = (ULONG)(ULONG_PTR)CreateInfo->ParentProcessId;

        /* Image path from CreateInfo (more reliable than SeLocateProcessImageName
           at this point because the process is still being set up) */
        if (CreateInfo->ImageFileName) {
            RtlStringCbCopyUnicodeString(event.ImagePath, sizeof(event.ImagePath),
                CreateInfo->ImageFileName);
        }

        /* Command line -- the key field we upgraded to Ex for */
        if (CreateInfo->CommandLine) {
            RtlStringCbCopyUnicodeString(event.CommandLine, sizeof(event.CommandLine),
                CreateInfo->CommandLine);
        }

        /* Session ID and logon session from the process object */
        event.SessionId = (ULONG)(ULONG_PTR)PsGetProcessSessionId(Process);

        /* Grab the logon session LUID from the process token.
           The agent maps this to a LogonType via LsaGetLogonSessionData:
           type 3 = network (PsExec/WMI), type 10 = RDP, etc. */
        {
            PACCESS_TOKEN token = PsReferencePrimaryToken(Process);
            if (token) {
                LUID authId = { 0 };
                if (NT_SUCCESS(SeQueryAuthenticationIdToken(token, &authId))) {
                    event.AuthenticationId = authId;
                }
                PsDereferencePrimaryToken(token);
            }
        }

        /* Look up the parent -- agent uses this to build the process tree */
        if (NT_SUCCESS(PsLookupProcessByProcessId(CreateInfo->ParentProcessId, &parentProcess))) {
            PUNICODE_STRING parentProcessName = NULL;
            if (NT_SUCCESS(SeLocateProcessImageName(parentProcess, &parentProcessName)) && parentProcessName) {
                RtlStringCbCopyUnicodeString(event.ParentImagePath, sizeof(event.ParentImagePath),
                    parentProcessName);
            }
            ObDereferenceObject(parentProcess);
        }
    } else {
        /* ---- Process Terminate ---- */
        /* CreateInfo is NULL at termination, but the Process object is
           still valid so we can pull the interesting fields from it. */
        PUNICODE_STRING processName = NULL;
        if (NT_SUCCESS(SeLocateProcessImageName(Process, &processName)) && processName) {
            RtlStringCbCopyUnicodeString(event.ImagePath, sizeof(event.ImagePath), processName);
        }

        event.SessionId = (ULONG)(ULONG_PTR)PsGetProcessSessionId(Process);

        /* InheritedFromUniqueProcessId = parent PID stored in EPROCESS */
        event.ParentProcessId = (ULONG)(ULONG_PTR)PsGetProcessInheritedFromUniqueProcessId(Process);
    }

    /* Queue for the agent to pick up */
    PushEvent(&event, sizeof(event));

}

/* Register our callback with the kernel.
   Ex version gives us PS_CREATE_NOTIFY_INFO with CommandLine. */
NTSTATUS RegisterProcessNotifyRoutine() {
    return PsSetCreateProcessNotifyRoutineEx(EdrCreateProcessNotifyRoutine, FALSE);
}

/* Unregister -- called during driver unload */
NTSTATUS UnregisterProcessNotifyRoutine() {
    return PsSetCreateProcessNotifyRoutineEx(EdrCreateProcessNotifyRoutine, TRUE);
}