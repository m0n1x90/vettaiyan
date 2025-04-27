#ifndef CALLBACK_THREAD_H
#define CALLBACK_THREAD_H

#include "DriverHeader.h"

VOID EdrCreateThreadNotifyRoutine(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ BOOLEAN Create
);

NTSTATUS RegisterThreadNotifyRoutine();

NTSTATUS UnregisterThreadNotifyRoutine();

#endif