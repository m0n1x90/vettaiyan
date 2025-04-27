#ifndef CALLBACK_IMAGE_H
#define CALLBACK_IMAGE_H

#include "DriverHeader.h"

VOID EdrLoadImageNotifyRoutine(
    _In_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo
);

NTSTATUS RegisterImageNotifyRoutine();

NTSTATUS UnregisterImageNotifyRoutine();

#endif