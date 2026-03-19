/*
 * CallBackImage.c -- watches every DLL/image load on the system.
 *
 * The kernel calls us whenever a process maps an image into memory.
 * We skip kernel-mode images and system process loads, but report
 * everything else -- including System32/SysWOW64 DLLs, because
 * DLL hijacking and side-loading happen in those exact directories.
 * The agent handles triage and volume.
 */

#include "CallBackImage.h"
#include "EventBuffer.h"

/*
 * EdrLoadImageNotifyRoutine -- the kernel calls this for every image load.
 * We get the image path, base address, size, and which process loaded it.
 */
VOID EdrLoadImageNotifyRoutine(
    _In_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo
) {

    EDR_IMAGE_EVENT event = { 0 };
    PEPROCESS process = NULL;
    PUNICODE_STRING processName = NULL;

    /* PID 0/4 are System Idle and System -- not needed */
    if (ProcessId == NULL || (ULONG)(ULONG_PTR)ProcessId <= 4) return;

    /* Kernel-mode driver loads -- not user-initiated */
    /* But once attack comes into kernel mode, its in more privileged context */
    if (ImageInfo && ImageInfo->SystemModeImage) return;

    /* Build the image load event */
    event.Header.EventType = EdrEventImageLoad;
    KeQuerySystemTimePrecise(&event.Header.Timestamp);
    event.Header.ProcessId = (ULONG)(ULONG_PTR)ProcessId;
    event.Header.ThreadId = (ULONG)(ULONG_PTR)PsGetCurrentThreadId();
    event.Header.EventSize = sizeof(EDR_IMAGE_EVENT);
    event.Header.SequenceNumber = GetNextSequenceNumber();

    /* Grab the base address and size from IMAGE_INFO */
    if (ImageInfo) {
        event.ImageBase = (ULONG_PTR)ImageInfo->ImageBase;
        event.ImageSize = ImageInfo->ImageSize;
    }

    /* Copy the loaded image path */
    if (FullImageName && FullImageName->Length > 0 && FullImageName->Buffer) {
        RtlStringCbCopyUnicodeString(event.ImagePath, sizeof(event.ImagePath), FullImageName);
    }

    /* Look up the process that loaded this image */
    if (NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &process))) {
        if (NT_SUCCESS(SeLocateProcessImageName(process, &processName)) && processName) {
            RtlStringCbCopyUnicodeString(event.ProcessImagePath, sizeof(event.ProcessImagePath), processName);
        }
        ObDereferenceObject(process);
    }

    /* Queue for the agent to pick up */
    PushEvent(&event, sizeof(event));
}

/* Register our callback with the kernel */
NTSTATUS RegisterImageNotifyRoutine() {
    return PsSetLoadImageNotifyRoutine(EdrLoadImageNotifyRoutine);
}

/* Unregister -- called during driver unload */
NTSTATUS UnregisterImageNotifyRoutine() {
    return PsRemoveLoadImageNotifyRoutine(EdrLoadImageNotifyRoutine);
}