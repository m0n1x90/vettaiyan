/*
 * Filter.c — VettaiyanFilter minifilter driver entry point.
 *
 * This is the main module for the filesystem minifilter.
 * It registers the filter with the Filter Manager on load
 * and unregisters it on unload. All callback registration
 * and communication port setup happens inside RegisterFSFilter().
 */

#include "DriverHeader.h"
#include "FsFilter.h"

/*
 * DriverUnload — Called by the Filter Manager when the driver is being unloaded.
 *
 * Tears down the minifilter registration (callbacks, comm port, etc.)
 * via UnregisterFSFilter().
 */
VOID DriverUnload(
    _In_ PDRIVER_OBJECT DriverObject
)
{

    UNREFERENCED_PARAMETER(DriverObject);

    NTSTATUS status;

    /* Unregister the filter — detaches from volumes and closes the comm port */
    status = UnregisterFSFilter();

    KdPrint(("[ VettaiyanFilter ] Filter Unloaded\n"));

}

/*
 * DriverEntry — Minifilter driver entry point, called by the OS at load time.
 *
 * Registers the minifilter with the Filter Manager, which:
 *   1. Attaches to volumes
 *   2. Installs pre/post operation callbacks (create, write, set-info, close)
 *   3. Creates the communication port for agent connectivity
 */
NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS status;

    /* Register the minifilter — sets up callbacks and comm port */
    status = RegisterFSFilter(DriverObject);
    KdPrint(("[ VettaiyanFilter ] Filter Loaded\n"));

    return status;
}
