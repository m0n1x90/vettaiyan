/*
 * FsClose.c -- tells the agent when a file handle is released.
 *
 * Every file close on the system comes through here. We send all
 * of them to the agent — no extension filtering in kernel. The agent
 * decides what to YARA-scan using the priority list in EdrEvents.h
 * and magic-byte inspection. This way nothing slips through just
 * because an attacker used a weird extension.
 */

#include "FsFilter.h"

/*
 * FSClosePreCallback — Pre-operation callback for IRP_MJ_CLOSE.
 *
 * Observe-only — closes always succeed, so we report in pre-op
 * and skip the post-op entirely.
 */
FLT_PREOP_CALLBACK_STATUS FSClosePreCallback(
    PFLT_CALLBACK_DATA CallbackData,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID* CompletionContext
) {

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION fileNameInfo;

    /* Early exit if the agent isn't connected — no point processing */
    if (!IsAgentConnected()) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    /* Retrieve the normalized file path */
    status = FltGetFileNameInformation(
        CallbackData,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &fileNameInfo
    );

    if (NT_SUCCESS(status)) {
        /* Parse name into components (volume, dir, filename, extension) */
        FltParseFileNameInformation(fileNameInfo);

        /* Check PID-based exclusion — skip our own agent's I/O */
        if (ShouldExcludePath(fileNameInfo)) {
            FltReleaseFileNameInformation(fileNameInfo);
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }

        /* Build the close event — agent will triage and possibly YARA-scan */
        EDR_FILE_EVENT event = { 0 };
        event.Header.EventType = EdrEventFileClose;
        event.Header.SequenceNumber = (ULONG)InterlockedIncrement(&g_FilterSequence);
        KeQuerySystemTimePrecise(&event.Header.Timestamp);
        event.Header.ProcessId = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
        event.Header.ThreadId = (ULONG)(ULONG_PTR)PsGetCurrentThreadId();
        event.Header.EventSize = sizeof(EDR_FILE_EVENT);

        /* Copy the normalized file path into the event */
        RtlStringCbCopyUnicodeString(event.FilePath, sizeof(event.FilePath), &fileNameInfo->Name);

        /* Send to agent via filter comm port (with FS_SEND_TIMEOUT_100NS timeout) */
        SendFileEventToAgent(&event);

        /* Always release the name info when done */
        FltReleaseFileNameInformation(fileNameInfo);
    }
    /* If FltGetFileNameInformation fails (paging I/O, etc.)
       we silently let the close through — observe-only, never block. */

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}
