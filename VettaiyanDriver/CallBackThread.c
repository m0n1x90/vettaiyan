/*
 * CallBackThread.c -- monitors thread creation and termination.
 *
 * Uses PsSetCreateThreadNotifyRoutine to get called every time a
 * thread starts or stops anywhere on the system. The key detection
 * here is remote thread creation -- when process A creates a thread
 * inside process B. That's the bread and butter of:
 *   - CreateRemoteThread injection (classic DLL injection)
 *   - NtCreateThreadEx with a remote start address
 *   - APC-based injection (thread starts in target after APC queued)
 *   - Process hollowing (resume thread in hollowed-out process)
 *
 * We flag remote threads by comparing the caller's PID against the
 * target PID. If they differ, something is reaching into another
 * process -- the agent decides whether it's benign (debugger, etc.)
 * or malicious.
 */

#include "CallBackThread.h"
#include "EventBuffer.h"

/*
 * EdrCreateThreadNotifyRoutine -- fires on every thread create/terminate.
 *
 * ProcessId/ThreadId = the target (where the thread lives).
 * PsGetCurrentProcessId() = the caller (who created the thread).
 * When these differ on a Create, it's a remote thread.
 */
VOID EdrCreateThreadNotifyRoutine(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ BOOLEAN Create
) {
    
    EDR_THREAD_EVENT event = { 0 };

    /* Tag as create or terminate */
    event.Header.EventType = Create ? EdrEventThreadCreate : EdrEventThreadTerminate;
    KeQuerySystemTimePrecise(&event.Header.Timestamp);

    /* Header gets the caller's PID/TID (who initiated the operation) */
    event.Header.ProcessId = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    event.Header.ThreadId = (ULONG)(ULONG_PTR)PsGetCurrentThreadId();
    event.Header.EventSize = sizeof(EDR_THREAD_EVENT);
    event.Header.SequenceNumber = GetNextSequenceNumber();

    /* Target fields = where the new thread actually lives */
    event.TargetProcessId = (ULONG)(ULONG_PTR)ProcessId;
    event.TargetThreadId = (ULONG)(ULONG_PTR)ThreadId;

    /* Remote thread check: caller PID != target PID means cross-process
       thread creation -- the #1 signal for injection techniques */
    event.IsRemoteThread = (PsGetCurrentProcessId() != ProcessId) ? TRUE : FALSE;

    PushEvent(&event, sizeof(event));

}

/* Register the thread notify callback with the kernel */
NTSTATUS RegisterThreadNotifyRoutine() {

    return PsSetCreateThreadNotifyRoutine(EdrCreateThreadNotifyRoutine);

}

/* Unregister -- called during driver unload */
NTSTATUS UnregisterThreadNotifyRoutine() {

    return PsRemoveCreateThreadNotifyRoutine(EdrCreateThreadNotifyRoutine);

}