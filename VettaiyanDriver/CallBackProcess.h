#ifndef CALLBACK_PROCESS_H
#define CALLBACK_PROCESS_H

/*
 * CallBackProcess.h -- process create/terminate monitoring.
 * Uses PsSetCreateProcessNotifyRoutineEx for command line capture.
 * Fires on every process start and exit. The agent builds its
 * process tree from these events.
 */

#include "DriverHeader.h"

/* The callback -- registered via PsSetCreateProcessNotifyRoutineEx.
   CreateInfo is non-NULL for creates, NULL for terminates. */
VOID EdrCreateProcessNotifyRoutine(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
);

/* Wire up / tear down the callback */
NTSTATUS RegisterProcessNotifyRoutine();
NTSTATUS UnregisterProcessNotifyRoutine();

#endif