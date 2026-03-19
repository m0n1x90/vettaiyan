#ifndef CALLBACK_OBJECT_H
#define CALLBACK_OBJECT_H

/*
 * CallBackObject.h -- process and thread handle monitoring.
 * Catches handle create/duplicate on both processes and threads
 * so we can spot injection, hollowing, credential dumping, etc.
 */

#include "DriverHeader.h"

/* The callback -- fires before a process handle is granted */
OB_PREOP_CALLBACK_STATUS PreOperationCallback(
    _In_ PVOID RegContext,
    _In_ POB_PRE_OPERATION_INFORMATION OpInfo
);

/* Wire up / tear down the object callback */
NTSTATUS RegisterObjectCallbacks();
VOID UnregisterObjectCallbacks();

#endif
