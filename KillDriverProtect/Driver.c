#include "KillFsFilter.h"
#include "KillRegFilter.h"

VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	KillFsFilter();

	KillRegFilter();

	DriverObject->DriverUnload = DriverUnload;

	return STATUS_SUCCESS;
}