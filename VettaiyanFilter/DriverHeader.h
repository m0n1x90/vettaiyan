#ifndef FILTER_DRIVER_HEADER_H
#define FILTER_DRIVER_HEADER_H

/*
 * DriverHeader.h -- the kitchen-sink kernel include.
 * Every .c in the filter ends up pulling this in through FsFilter.h.
 * Keeps the individual source files clean.
 */

#include <ntifs.h>
#include <ntddk.h>
#include <ntdef.h>
#include <ntstrsafe.h>

#include <wdm.h>
#include <fltKernel.h>

#pragma comment (lib,"FltMgr.lib")

/* Shared event structs used by both kernel and user mode. */
#include "../EdrCommon/EdrEvents.h"

#endif