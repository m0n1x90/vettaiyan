#ifndef CALLBACK_IMAGE_H
#define CALLBACK_IMAGE_H

/*
 * CallBackImage.h -- DLL/image load monitoring.
 * Fires every time a process maps an executable image into memory.
 */

#include "DriverHeader.h"

/* The callback itself -- registered via PsSetLoadImageNotifyRoutine */
VOID EdrLoadImageNotifyRoutine(
    _In_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo
);

/* Wire up / tear down the callback */
NTSTATUS RegisterImageNotifyRoutine();
NTSTATUS UnregisterImageNotifyRoutine();

#endif