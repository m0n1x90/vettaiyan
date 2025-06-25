#include "FsFilter.h"

FLT_PREOP_CALLBACK_STATUS FSWritePreCallback(
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

    if (NT_SUCCESS(status)) {

        FltParseFileNameInformation(fileNameInfo);

        KdPrint(("[VettaiyanFilter] File written: %wZ", &fileNameInfo->Name));

        FltReleaseFileNameInformation(fileNameInfo);
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;

}
