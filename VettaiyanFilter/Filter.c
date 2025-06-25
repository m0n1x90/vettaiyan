#include "DriverHeader.h"
#include "FsFilter.h"

VOID DriverUnload(
    _In_ PDRIVER_OBJECT DriverObject
)
{

    UNREFERENCED_PARAMETER(DriverObject);

    NTSTATUS status;
    status = UnregisterFSFilter();

    KdPrint(("[ VettaiyanFilter ] Filter Unloaded\n"));

}

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS status;

    status = RegisterFSFilter(DriverObject);
    KdPrint(("[ VettaiyanFilter ] Filter Loaded\n"));

    return status;
}
