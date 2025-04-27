#include "CallBackImage.h"

VOID EdrLoadImageNotifyRoutine(
    _In_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo
) {

    UNREFERENCED_PARAMETER(ImageInfo);

    PEPROCESS Process = NULL;
    PUNICODE_STRING ProcessName = NULL;

    PsLookupProcessByProcessId(ProcessId, &Process);
    SeLocateProcessImageName(Process, &ProcessName);

    DbgPrint(
        "[+] Image Loaded: ProcessName = %wZ, ProcessID = %d, ImageName = %wZ\n",
        ProcessName,
        (ULONG)(ULONG_PTR)ProcessId,
        FullImageName
    );

}

NTSTATUS RegisterImageNotifyRoutine() {

    return PsSetLoadImageNotifyRoutine(EdrLoadImageNotifyRoutine);

}

NTSTATUS UnregisterImageNotifyRoutine() {

    return PsRemoveLoadImageNotifyRoutine(EdrLoadImageNotifyRoutine);

}