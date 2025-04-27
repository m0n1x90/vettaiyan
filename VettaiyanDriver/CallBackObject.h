#ifndef CALLBACK_OBJECT_H
#define CALLBACK_OBJECT_H

#include "DriverHeader.h"

OB_PREOP_CALLBACK_STATUS PreOperationCallback(
    _In_ PVOID RegContext,
    _In_ POB_PRE_OPERATION_INFORMATION OpInfo
);

NTSTATUS RegisterObjectCallbacks();

VOID UnregisterObjectCallbacks();

#endif
