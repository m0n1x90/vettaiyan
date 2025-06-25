#include "FsFilter.h"

FLT_PREOP_CALLBACK_STATUS FSSetInfoPreCallback(
    PFLT_CALLBACK_DATA CallbackData,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID* CompletionContext
) {

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION fileNameInfo;

    status = FltGetFileNameInformation(
        CallbackData,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &fileNameInfo
    );

    if (!NT_SUCCESS(status)) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    FltParseFileNameInformation(fileNameInfo);

    FILE_INFORMATION_CLASS infoClass = CallbackData->Iopb->Parameters.SetFileInformation.FileInformationClass;

    if (infoClass == FileDispositionInformation || infoClass == FileDispositionInformationEx) {
        KdPrint(("[VettaiyanFilter] File marked for deletion: %wZ\n", &fileNameInfo->Name));
    }
    else if (infoClass == FileRenameInformation || infoClass == FileRenameInformationEx) {
        KdPrint(("[VettaiyanFilter] File rename detected: %wZ\n", &fileNameInfo->Name));
    }

    FltReleaseFileNameInformation(fileNameInfo);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;

}
