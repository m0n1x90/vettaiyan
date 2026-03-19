#ifndef FS_FILTER_H
#define FS_FILTER_H

/*
 * FsFilter.h -- the one header every filter source file includes.
 * Brings in the kernel stuff, our config, the comm port API,
 * and declares all the IRP callbacks so they can find each other.
 */

#include "DriverHeader.h"
#include "FsCommon.h"
#include "FilterCommPort.h"

/* Shared counter -- each callback bumps this so events stay ordered. */
extern volatile LONG g_FilterSequence;

/* Bring the filter up and tear it down. */
NTSTATUS RegisterFSFilter(_In_ PDRIVER_OBJECT DriverObject);
NTSTATUS UnloadFSFilter(_In_ FLT_FILTER_UNLOAD_FLAGS Flags);
NTSTATUS UnregisterFSFilter();
PFLT_FILTER GetFilterHandle(VOID);

/* File open/create -- pre-op gates, post-op reports successful opens. */
FLT_PREOP_CALLBACK_STATUS FSCreatePreCallback(
    PFLT_CALLBACK_DATA CallbackData, 
    PCFLT_RELATED_OBJECTS FltObjects, 
    PVOID* CompletionContext
);
FLT_POSTOP_CALLBACK_STATUS FSCreatePostCallback(
    PFLT_CALLBACK_DATA CallbackData, 
    PCFLT_RELATED_OBJECTS FltObjects, 
    PVOID CompletionContext, 
    FLT_POST_OPERATION_FLAGS PostOpFlags
);

/* File write -- fires when data is actually written to disk. */
FLT_PREOP_CALLBACK_STATUS FSWritePreCallback(
    PFLT_CALLBACK_DATA CallbackData,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID* CompletionContext
);

/* Rename, delete, and other metadata changes. */
FLT_PREOP_CALLBACK_STATUS FSSetInfoPreCallback(
    PFLT_CALLBACK_DATA CallbackData,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID* CompletionContext
);

/* File close -- tells the agent a file handle was released. */
FLT_PREOP_CALLBACK_STATUS FSClosePreCallback(
    PFLT_CALLBACK_DATA CallbackData,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID* CompletionContext
);

#endif