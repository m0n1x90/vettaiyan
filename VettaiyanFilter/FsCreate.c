/*
 * FsCreate.c -- handles every file open/create on the system.
 *
 * Split into two stages:
 *   Pre-op  - quick check: is the agent online? is this our own PID?
 *             If it looks worth tracking, grab the file name and hand
 *             it off to post-op.
 *   Post-op - runs after the file system finishes the open. We only
 *             care if it actually succeeded. Tells the agent what
 *             happened: new file dropped, existing file opened, etc.
 */

#include "FsFilter.h"

/*
 * Pre-op: decide if this create is worth watching.
 *
 * If yes, hold onto the file name info and ask the filter manager
 * to call our post-op when the I/O completes. If no, bail early.
 */
FLT_PREOP_CALLBACK_STATUS FSCreatePreCallback(
    PFLT_CALLBACK_DATA CallbackData,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID* CompletionContext
) {

    UNREFERENCED_PARAMETER(FltObjects);

    *CompletionContext = NULL;

    /* Nobody listening -- don't bother */
    if (!IsAgentConnected()) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    PFLT_FILE_NAME_INFORMATION fileNameInfo;
    NTSTATUS status = FltGetFileNameInformation(
        CallbackData,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &fileNameInfo
    );

    if (NT_SUCCESS(status)) {
        status = FltParseFileNameInformation(fileNameInfo);

        if (NT_SUCCESS(status) && !ShouldExcludePath(fileNameInfo)) {
            /* Bump the ref count so it survives until post-op */
            FltReferenceFileNameInformation(fileNameInfo);
            *CompletionContext = fileNameInfo;
        }

        FltReleaseFileNameInformation(fileNameInfo);
    }

    /* Only ask for post-op if we have something to report */
    return (*CompletionContext != NULL)
        ? FLT_PREOP_SUCCESS_WITH_CALLBACK
        : FLT_PREOP_SUCCESS_NO_CALLBACK;
}

/*
 * Post-op: the file system finished the open -- did it work?
 *
 * If the open failed (access denied, not found, etc.) we drop it.
 * If it succeeded, we send the event with the disposition:
 *   0 = file was replaced  (FILE_SUPERSEDED)
 *   1 = existing file opened  (FILE_OPENED)
 *   2 = brand new file created  (FILE_CREATED)
 *   3 = existing file overwritten  (FILE_OVERWRITTEN)
 */
FLT_POSTOP_CALLBACK_STATUS FSCreatePostCallback(
    PFLT_CALLBACK_DATA CallbackData,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID CompletionContext,
    FLT_POST_OPERATION_FLAGS PostOpFlags
)
{
    UNREFERENCED_PARAMETER(FltObjects);

    PFLT_FILE_NAME_INFORMATION fileNameInfo = (PFLT_FILE_NAME_INFORMATION)CompletionContext;

    /* Filter is shutting down -- just free and get out */
    if (PostOpFlags & FLTFL_POST_OPERATION_DRAINING) {
        if (fileNameInfo) FltReleaseFileNameInformation(fileNameInfo);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    /* Only report opens that actually succeeded */
    if (fileNameInfo && NT_SUCCESS(CallbackData->IoStatus.Status)) {

        EDR_FILE_EVENT event = { 0 };
        event.Header.EventType = EdrEventFileCreate;
        event.Header.SequenceNumber = (ULONG)InterlockedIncrement(&g_FilterSequence);
        KeQuerySystemTimePrecise(&event.Header.Timestamp);
        event.Header.ProcessId = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
        event.Header.ThreadId = (ULONG)(ULONG_PTR)PsGetCurrentThreadId();
        event.Header.EventSize = sizeof(EDR_FILE_EVENT);

        if (fileNameInfo->Name.Length > 0 && fileNameInfo->Name.Buffer) {
            RtlStringCbCopyUnicodeString(event.FilePath, sizeof(event.FilePath), &fileNameInfo->Name);
        }

        event.FileAttributes = CallbackData->Iopb->Parameters.Create.FileAttributes;
        event.CreateDisposition = (ULONG)CallbackData->IoStatus.Information;

        SendFileEventToAgent(&event);
    }

    if (fileNameInfo) FltReleaseFileNameInformation(fileNameInfo);

    return FLT_POSTOP_FINISHED_PROCESSING;
}