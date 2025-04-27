#include "CallBackThread.h"

VOID EdrCreateThreadNotifyRoutine(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ BOOLEAN Create
) {
    
    if (Create) {
        DbgPrint(
            "[+] Thread Created: ID = %d, ProcessID = %d\n",
            ThreadId,
            ProcessId
        );
    }
    else {
        DbgPrint(
            "[+] Thread Terminated: ID = %d, ProcessID = %d\n",
            ThreadId,
            ProcessId
        );
    }

}

NTSTATUS RegisterThreadNotifyRoutine() {

    return PsSetCreateThreadNotifyRoutine(EdrCreateThreadNotifyRoutine);

}

NTSTATUS UnregisterThreadNotifyRoutine() {

    return PsRemoveCreateThreadNotifyRoutine(EdrCreateThreadNotifyRoutine);

}