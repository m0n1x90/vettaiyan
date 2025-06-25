#ifndef FS_FILTER_H
#define FS_FILTER_H

#include "DriverHeader.h"

NTSTATUS RegisterFSFilter(_In_ PDRIVER_OBJECT DriverObject);

NTSTATUS UnloadFSFilter(_In_ FLT_FILTER_UNLOAD_FLAGS Flags);

NTSTATUS UnregisterFSFilter();

FLT_PREOP_CALLBACK_STATUS FSCreatePreCallback(
    PFLT_CALLBACK_DATA CallbackData, 
    PCFLT_RELATED_OBJECTS FltObjects, 
    PVOID* CompletionContext
);

FLT_POSTOP_CALLBACK_STATUS FSCreatePostCallback(
    PFLT_CALLBACK_DATA CallbackData, 
    PCFLT_RELATED_OBJECTS FltObjects, 
    PVOID* CompletionContext, 
    FLT_POST_OPERATION_FLAGS PostOpFlags
);

FLT_PREOP_CALLBACK_STATUS FSWritePreCallback(
    PFLT_CALLBACK_DATA CallbackData,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID* CompletionContext
);

FLT_PREOP_CALLBACK_STATUS FSSetInfoPreCallback(
    PFLT_CALLBACK_DATA CallbackData,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID* CompletionContext
);

#endif