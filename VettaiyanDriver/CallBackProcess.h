#ifndef CALLBACK_PROCESS_H
#define CALLBACK_PROCESS_H

/*
 * CallBackProcess.h -- process create/terminate monitoring.
 * Fires on every process start and exit. The agent builds its
 * process tree from these events.
 */

#include "DriverHeader.h"

/* The callback -- registered via PsSetCreateProcessNotifyRoutine */
VOID EdrCreateProcessNotifyRoutine(
    _In_ HANDLE ParentProcessId,
    _In_ HANDLE ProcessId,
    _In_ BOOLEAN Create
);

/* Wire up / tear down the callback */
NTSTATUS RegisterProcessNotifyRoutine();
NTSTATUS UnregisterProcessNotifyRoutine();

#endif