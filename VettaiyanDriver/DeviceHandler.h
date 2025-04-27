#ifndef DEVICE_HANDLER_H
#define DEVICE_HANDLER_H

#include "DriverHeader.h"

NTSTATUS DriverCreateClose(
	_In_ PDEVICE_OBJECT DeviceObject,
	_In_ PIRP Irp
);

#endif