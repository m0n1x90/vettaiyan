#include "FsFilter.h"

/*
 * FSWritePreCallback — Pre-operation callback for IRP_MJ_WRITE.
 *
 * Monitors file write operations and forwards qualifying events
 * to the user-mode agent via the filter communication port.
 * This is observe-only — writes are never blocked or modified.
 */
FLT_PREOP_CALLBACK_STATUS FSWritePreCallback(
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

    /* Skip sub-threshold writes (OS metadata/journal noise).
       See FS_MIN_WRITE_SIZE in FsCommon.h to adjust. */
    if (CallbackData->Iopb->Parameters.Write.Length < FS_MIN_WRITE_SIZE)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    /* Retrieve the normalized file path for this write operation */
    status = FltGetFileNameInformation(
        CallbackData, 
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, 
        &fileNameInfo
    );

    if (NT_SUCCESS(status)) {

        /* Parse name into components (volume, dir, filename, extension) */
        FltParseFileNameInformation(fileNameInfo);

        /* Check against exclusion list (system dirs, browser caches, our own files) */
        if (ShouldExcludePath(fileNameInfo)) {
            FltReleaseFileNameInformation(fileNameInfo);
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }

        /* Build the event struct to send to the agent */
        EDR_FILE_EVENT event = { 0 };
        event.Header.EventType = EdrEventFileWrite;
        event.Header.SequenceNumber = (ULONG)InterlockedIncrement(&g_FilterSequence);
        KeQuerySystemTimePrecise(&event.Header.Timestamp);
        event.Header.ProcessId = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
        event.Header.ThreadId = (ULONG)(ULONG_PTR)PsGetCurrentThreadId();
        event.Header.EventSize = sizeof(EDR_FILE_EVENT);

        /* Copy the normalized file path into the event */
        if (fileNameInfo->Name.Length > 0 && fileNameInfo->Name.Buffer) {
            RtlStringCbCopyUnicodeString(event.FilePath, sizeof(event.FilePath), &fileNameInfo->Name);
        }

        /* Store the write length (not total file size) for analysis */
        event.FileSize.QuadPart = (LONGLONG)CallbackData->Iopb->Parameters.Write.Length;

        /* Send to agent via filter comm port (with FS_SEND_TIMEOUT_100NS timeout) */
        SendFileEventToAgent(&event);

        /* Always release the name info when done */
        FltReleaseFileNameInformation(fileNameInfo);
    }
    /* If FltGetFileNameInformation fails (paging I/O, file deletion, etc.)
       we silently let the write through — observe-only, never block. */

    return FLT_PREOP_SUCCESS_NO_CALLBACK;

}
