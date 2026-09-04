#include "../DbgHook/dbg.h"

SYMBOLS_DATA g_SymbolsData = { 0 };

#define IOCTL_PTEDBG_LOAD_SYMBOLS    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PTEDBG_ADD_DEBUGGER    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PTEDBG_REMOVE_DEBUGGER CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PTEDBG_ADD_DEBUGGEE    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PTEDBG_REMOVE_DEBUGGEE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)

static VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
	UnHookFuncs();

	if (DriverObject->DeviceObject)
	{
		UNICODE_STRING DosDeviceName;
		RtlInitUnicodeString(&DosDeviceName, L"\\DosDevices\\PteDbg");
		IoDeleteSymbolicLink(&DosDeviceName);
		IoDeleteDevice(DriverObject->DeviceObject);
	}
}

static NTSTATUS DrvComm(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

static NTSTATUS DrvIOCTLDispatcher(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
	NTSTATUS Status = STATUS_SUCCESS;
	ULONG Ioctl = Stack->Parameters.DeviceIoControl.IoControlCode;
	PVOID Buf = Irp->AssociatedIrp.SystemBuffer;
	ULONG Len = Stack->Parameters.DeviceIoControl.InputBufferLength;

	switch (Ioctl)
	{
		case IOCTL_PTEDBG_LOAD_SYMBOLS:
		{
			if (Len < sizeof(SYMBOLS_DATA))
			{
				Status = STATUS_BUFFER_TOO_SMALL;
				break;
			}
			memcpy(&g_SymbolsData, Buf, sizeof(SYMBOLS_DATA));
			if (!DbgInit())
			{
				DbgPrintEx(77, 0, "[PteDbg] DbgInit failed\n");
				Status = STATUS_UNSUCCESSFUL;
			}
			break;
		}
		case IOCTL_PTEDBG_ADD_DEBUGGER:
		case IOCTL_PTEDBG_REMOVE_DEBUGGER:
		case IOCTL_PTEDBG_ADD_DEBUGGEE:
		case IOCTL_PTEDBG_REMOVE_DEBUGGEE:
		{
			if (Len < sizeof(ULONG64))
			{
				Status = STATUS_BUFFER_TOO_SMALL;
				break;
			}
			ULONG64 pid = *(ULONG64*)Buf;
			BOOLEAN ok = FALSE;
			if (Ioctl == IOCTL_PTEDBG_ADD_DEBUGGER)        ok = DbgAddDebugger(pid);
			else if (Ioctl == IOCTL_PTEDBG_REMOVE_DEBUGGER) ok = DbgRemoveDebugger(pid);
			else if (Ioctl == IOCTL_PTEDBG_ADD_DEBUGGEE)    ok = DbgAddDebuggee(pid);
			else                                            ok = DbgRemoveDebuggee(pid);
			Status = ok ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
			break;
		}
		default:
			Status = STATUS_INVALID_DEVICE_REQUEST;
			break;
	}

	Irp->IoStatus.Status = Status;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Status;
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT Driver, PUNICODE_STRING Reg)
{
	UNREFERENCED_PARAMETER(Reg);
	Driver->DriverUnload = DriverUnload;

	PDEVICE_OBJECT DeviceObject = NULL;
	UNICODE_STRING DriverName, DosDeviceName;
	RtlInitUnicodeString(&DriverName, L"\\Device\\PteDbg");
	RtlInitUnicodeString(&DosDeviceName, L"\\DosDevices\\PteDbg");

	NTSTATUS status = IoCreateDevice(Driver, 0, &DriverName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &DeviceObject);
	if (!NT_SUCCESS(status))
		return status;

	Driver->MajorFunction[IRP_MJ_CLOSE] = DrvComm;
	Driver->MajorFunction[IRP_MJ_CREATE] = DrvComm;
	Driver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DrvIOCTLDispatcher;
	Driver->Flags |= DO_BUFFERED_IO;

	status = IoCreateSymbolicLink(&DosDeviceName, &DriverName);
	if (!NT_SUCCESS(status))
	{
		IoDeleteDevice(DeviceObject);
		return status;
	}

	DbgPrintEx(77, 0, "[PteDbg] driver loaded, waiting for symbols (device: \\\\.\\PteDbg)\n");
	return STATUS_SUCCESS;
}
