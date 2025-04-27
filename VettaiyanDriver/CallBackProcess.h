#ifndef CALLBACK_PROCESS_H
#define CALLBACK_PROCESS_H

#include "DriverHeader.h"

VOID EdrCreateProcessNotifyRoutine(
    _In_ HANDLE ParentProcessId,
    _In_ HANDLE ProcessId,
    _In_ BOOLEAN Create
);

NTSTATUS RegisterProcessNotifyRoutine();

NTSTATUS UnregisterProcessNotifyRoutine();

#endif