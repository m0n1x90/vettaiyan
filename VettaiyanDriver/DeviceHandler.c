/*
 * DeviceHandler.c -- handles IOCTLs from the agent to the driver.
 *
 * The agent talks to us through a device object (\Device\VettaiyanEDR).
 * This file processes three IOCTLs:
 *
 *   IOCTL_EDR_READ_EVENTS  -- agent polls for queued events (process,
 *                             thread, image, registry, handle events)
 *   IOCTL_EDR_GET_STATS    -- agent requests event buffer statistics
 *                             (total pushed, dropped, current fill level)
 *   IOCTL_EDR_KILL_PROCESS -- agent tells us to terminate a malicious
 *                             process by PID (kernel-level kill, can't
 *                             be blocked by the target process)
 *
 * All IOCTLs use METHOD_BUFFERED, so input/output share SystemBuffer.
 */

#include "DeviceHandler.h"
#include "EventBuffer.h"
/*
 * DriverCreateClose -- handles IRP_MJ_CREATE and IRP_MJ_CLOSE.
 *
 * Called when the agent opens or closes a handle to our device.
 * Nothing to do here -- just complete the IRP successfully.
 */
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


/*
 * DriverDeviceControl -- the main IOCTL dispatcher.
 *
 * Parses the control code from the IRP stack location and routes
 * to the appropriate handler. Uses METHOD_BUFFERED, so both input
 * and output go through Irp->AssociatedIrp.SystemBuffer.
 */
NTSTATUS DriverDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_SUCCESS;
    ULONG bytesReturned = 0;
    ULONG ioControlCode = irpSp->Parameters.DeviceIoControl.IoControlCode;
    PVOID inputBuffer = Irp->AssociatedIrp.SystemBuffer;
    PVOID outputBuffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG inputLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outputLength = irpSp->Parameters.DeviceIoControl.OutputBufferLength;

    UNREFERENCED_PARAMETER(inputBuffer);
    UNREFERENCED_PARAMETER(inputLength);

    switch (ioControlCode) {

    /* READ_EVENTS -- drain the ring buffer into the agent's output buffer.
       Returns as many events as fit, agent calls again for more. */
    case IOCTL_EDR_READ_EVENTS:
        {
            if (outputBuffer == NULL || outputLength == 0) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }

            bytesReturned = DrainEvents(outputBuffer, outputLength);
            status = STATUS_SUCCESS;
        }
        break;

    /* GET_STATS -- return event buffer statistics (pushed, dropped, etc.) */
    case IOCTL_EDR_GET_STATS:
        {
            if (outputBuffer == NULL || outputLength < sizeof(EDR_STATISTICS)) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }

            GetEventStatistics((EDR_STATISTICS*)outputBuffer);
            bytesReturned = sizeof(EDR_STATISTICS);
            status = STATUS_SUCCESS;
        }
        break;

    /* KILL_PROCESS -- terminate a process from kernel mode.
       The agent sends us a PID and a reason code. We open the process
       with PROCESS_TERMINATE and call ZwTerminateProcess. This is a
       kernel-level kill -- the target can't intercept or block it. */
    case IOCTL_EDR_KILL_PROCESS:
        {
            if (inputBuffer == NULL || inputLength < sizeof(EDR_KILL_PROCESS_REQUEST)) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }

            EDR_KILL_PROCESS_REQUEST* request = (EDR_KILL_PROCESS_REQUEST*)inputBuffer;
            HANDLE processHandle = NULL;
            CLIENT_ID clientId = { 0 };
            OBJECT_ATTRIBUTES objAttr = { 0 };

            clientId.UniqueProcess = ULongToHandle(request->ProcessId);
            InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);

            status = ZwOpenProcess(&processHandle, 0x0001 /* PROCESS_TERMINATE */, &objAttr, &clientId);
            if (NT_SUCCESS(status)) {
                status = ZwTerminateProcess(processHandle, STATUS_SUCCESS);
                ZwClose(processHandle);
                DbgPrint("[ VettaiyanDriver ] Killed process PID=%d reason=%d\n",
                    request->ProcessId, request->Reason);
            } else {
                DbgPrint("[ VettaiyanDriver ] Failed to kill PID=%d status=0x%X\n",
                    request->ProcessId, status);
            }
        }
        break;

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    /* Complete the IRP with our status and byte count */
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = bytesReturned;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}