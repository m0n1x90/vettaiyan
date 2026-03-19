#ifndef DEVICE_HANDLER_H
#define DEVICE_HANDLER_H

/*
 * DeviceHandler.h -- IOCTL dispatch for agent-to-driver communication.
 *
 * The agent sends IOCTLs to read events, get stats, and kill processes.
 * All use METHOD_BUFFERED through \Device\VettaiyanEDR.
 */

#include "DriverHeader.h"
#include "../EdrCommon/EdrEvents.h"

/* IRP_MJ_CREATE / IRP_MJ_CLOSE -- just completes successfully */
NTSTATUS DriverCreateClose(
	_In_ PDEVICE_OBJECT DeviceObject,
	_In_ PIRP Irp
);

/* IRP_MJ_DEVICE_CONTROL -- routes IOCTLs to the right handler */
NTSTATUS DriverDeviceControl(
	_In_ PDEVICE_OBJECT DeviceObject,
	_In_ PIRP Irp
);

#endif