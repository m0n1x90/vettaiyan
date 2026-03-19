#ifndef DRIVER_HEADER_H
#define DRIVER_HEADER_H

/*
 * DriverHeader.h -- common kernel-mode includes for VettaiyanDriver.
 *
 * Every driver source file pulls this in. Order matters:
 * ntifs.h before ntddk.h to avoid redefinition conflicts.
 */

#include <ntifs.h>       /* NT filesystem + security APIs (SeLocateProcessImageName, etc.) */
#include <ntddk.h>       /* Core kernel APIs (PsSetCreateProcessNotifyRoutine, etc.) */
#include <wdm.h>         /* WDM base (IoCreateDevice, ObRegisterCallbacks, etc.) */
#include <wdmsec.h>      /* IoCreateDeviceSecure -- SDDL-based device ACLs */
#include <ntstrsafe.h>   /* Safe string functions (RtlStringCbCopyUnicodeString, etc.) */

#endif