#ifndef CALLBACK_THREAD_H
#define CALLBACK_THREAD_H

/*
 * CallBackThread.h -- thread creation/termination monitoring.
 *
 * Detects remote thread injection by comparing the caller PID
 * against the target PID. Remote threads are the primary mechanism
 * for DLL injection, APC injection, and process hollowing.
 */

#include "DriverHeader.h"

/* The callback -- fires on every thread create and terminate system-wide */
VOID EdrCreateThreadNotifyRoutine(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ BOOLEAN Create
);

/* Wire up / tear down the thread notify routine */
NTSTATUS RegisterThreadNotifyRoutine();
NTSTATUS UnregisterThreadNotifyRoutine();

#endif