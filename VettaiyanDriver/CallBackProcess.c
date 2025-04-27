#include "CallBackProcess.h"

VOID EdrCreateProcessNotifyRoutine(
    _In_ HANDLE ParentProcessId,
    _In_ HANDLE ProcessId,
    _In_ BOOLEAN Create
) {

    if (Create) {

        PEPROCESS process = NULL;
        PUNICODE_STRING parentProcessName = NULL, processName = NULL;

        PsLookupProcessByProcessId(ParentProcessId, &process);
        SeLocateProcessImageName(process, &parentProcessName);

        PsLookupProcessByProcessId(ProcessId, &process);
        SeLocateProcessImageName(process, &processName);

        DbgPrint(
            "[+] Process spawned : PPID = %d, Parent Process Name = %wZ\n\t\tChild Process : PIDD = %d, Process Name = %wZ",
            ParentProcessId,
            parentProcessName,
            ProcessId,
            processName
        );

    }
    else {

        DbgPrint(
            "[+] Process Deleted: PPID = %d, PID = %d\n",
            ParentProcessId,
            ProcessId
        );

    }

}

NTSTATUS RegisterProcessNotifyRoutine() {

    return PsSetCreateProcessNotifyRoutine(EdrCreateProcessNotifyRoutine, FALSE);

}

NTSTATUS UnregisterProcessNotifyRoutine() {

    return PsSetCreateProcessNotifyRoutine(EdrCreateProcessNotifyRoutine, TRUE);

}