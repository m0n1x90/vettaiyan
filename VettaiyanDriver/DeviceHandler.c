#include "DeviceHandler.h"

NTSTATUS DriverCreateClose(
    _In_ PDEVICE_OBJECT DeviceObject, 
    _In_ PIRP Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}