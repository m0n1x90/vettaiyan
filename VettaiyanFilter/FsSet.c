/*
 * FsSet.c -- catches file renames and deletes.
 *
 * The file system uses IRP_MJ_SET_INFORMATION for a bunch of things,
 * but we only care about two: delete (FileDispositionInformation) and
 * rename (FileRenameInformation). Everything else passes through
 * untouched.
 *
 * For renames we grab the new name too, so the agent can see
 * "old.exe was renamed to svchost.exe" -- classic evasion trick.
 */

#include "FsFilter.h"

/*
 * FSSetInfoPreCallback — Pre-operation callback for IRP_MJ_SET_INFORMATION.
 *
 * Watches for delete and rename operations. Observe-only — we never
 * block or modify the request, just report it to the agent.
 */
FLT_PREOP_CALLBACK_STATUS FSSetInfoPreCallback(
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

    if (!NT_SUCCESS(status)) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    /* Parse name into components (volume, dir, filename, extension) */
    FltParseFileNameInformation(fileNameInfo);

    /* Check PID-based exclusion — skip our own agent's I/O */
    if (ShouldExcludePath(fileNameInfo)) {
        FltReleaseFileNameInformation(fileNameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* Figure out what kind of set-info this is */
    FILE_INFORMATION_CLASS infoClass = CallbackData->Iopb->Parameters.SetFileInformation.FileInformationClass;

    EDR_FILE_EVENT event = { 0 };
    BOOLEAN shouldSend = FALSE;

    /* Delete — someone's marking a file for removal */
    if (infoClass == FileDispositionInformation || infoClass == FileDispositionInformationEx) {
        event.Header.EventType = EdrEventFileDelete;
        shouldSend = TRUE;
    }
    /* Rename — grab the new name so the agent sees both old and new paths */
    else if (infoClass == FileRenameInformation || infoClass == FileRenameInformationEx) {
        event.Header.EventType = EdrEventFileRename;
        shouldSend = TRUE;

        /* Pull the destination path from the rename buffer */
        PFILE_RENAME_INFORMATION renameInfo = 
            (PFILE_RENAME_INFORMATION)CallbackData->Iopb->Parameters.SetFileInformation.InfoBuffer;
        if (renameInfo && renameInfo->FileNameLength > 0) {
            ULONG copyLen = min(renameInfo->FileNameLength, sizeof(event.NewFilePath) - sizeof(WCHAR));
            RtlCopyMemory(event.NewFilePath, renameInfo->FileName, copyLen);
        }
    }

    /* Only send if we matched delete or rename — ignore everything else */
    if (shouldSend) {
        event.Header.SequenceNumber = (ULONG)InterlockedIncrement(&g_FilterSequence);
        KeQuerySystemTimePrecise(&event.Header.Timestamp);
        event.Header.ProcessId = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
        event.Header.ThreadId = (ULONG)(ULONG_PTR)PsGetCurrentThreadId();
        event.Header.EventSize = sizeof(EDR_FILE_EVENT);

        /* Copy the original file path into the event */
        if (fileNameInfo->Name.Length > 0 && fileNameInfo->Name.Buffer) {
            RtlStringCbCopyUnicodeString(event.FilePath, sizeof(event.FilePath), &fileNameInfo->Name);
        }

        /* Send to agent via filter comm port */
        SendFileEventToAgent(&event);
    }

    /* Always release the name info when done */
    FltReleaseFileNameInformation(fileNameInfo);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;

}
