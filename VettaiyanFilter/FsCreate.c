#include "FsFilter.h"

FLT_PREOP_CALLBACK_STATUS FSCreatePreCallback(
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

        status = FltParseFileNameInformation(fileNameInfo);
        
        KdPrint(("[ VettaiyanFilter ] File being opened/created: %wZ\n", &fileNameInfo->Name));

        FltReleaseFileNameInformation(fileNameInfo);

        return FLT_PREOP_SUCCESS_WITH_CALLBACK;

    }
    FltReleaseFileNameInformation(fileNameInfo);

    return FLT_PREOP_SUCCESS_NO_CALLBACK;

}

FLT_POSTOP_CALLBACK_STATUS FSCreatePostCallback(
    PFLT_CALLBACK_DATA CallbackData, 
    PCFLT_RELATED_OBJECTS FltObjects, 
    PVOID* CompletionContext, 
    FLT_POST_OPERATION_FLAGS PostOpFlags
)
{

    UNREFERENCED_PARAMETER(CallbackData);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(PostOpFlags);

    return FLT_POSTOP_FINISHED_PROCESSING;

}