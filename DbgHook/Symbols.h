#pragma once
#include <ntddk.h>

//
// Addresses and struct offsets resolved in R3 via dbghelp + symsrv, sent to
// R0 with a single IOCTL. Field order must match the R3 Symbols.h exactly.
//
typedef struct _SYMBOLS_DATA {
	// ---- function addresses ----
	PVOID NtCreateDebugObject;
	PVOID PsGetNextProcessThread;
	PVOID DbgkpPostFakeThreadMessages;
	PVOID DbgkpWakeTarget;
	PVOID DbgkpSetProcessDebugObject;
	PVOID DbgkCreateThread;
	PVOID DbgkpQueueMessage;
	PVOID PsCaptureExceptionPort;
	PVOID DbgkpSendApiMessage;
	PVOID DbgkpSendApiMessageLpc;
	PVOID DbgkpSendErrorMessage;
	PVOID DbgkForwardException;
	PVOID DbgkpSuppressDbgMsg;
	PVOID DbgkpSectionToFileHandle;
	PVOID DbgkUnMapViewOfSection;
	PVOID DbgkpPostFakeProcessCreateMessages;
	PVOID NtDebugActiveProcess;
	PVOID DbgkpMarkProcessPeb;
	PVOID KiDispatchException;
	PVOID NtCreateUserProcess;
	PVOID DbgkDebugObjectType;
	PVOID ObTypeIndexTable;
	PVOID NtTerminateProcess;
	PVOID DbgkMapViewOfSection;
	PVOID DbgkSendSystemDllMessages;
	PVOID DbgkpProcessDebugPortMutex;

	// ---- struct member offsets (resolved from the PDB, never hardcoded) ----
	ULONG64 Process_DebugPort;                       // _EPROCESS.DebugPort
	ULONG64 Process_RundownProtect;                  // _EPROCESS.RundownProtect
	ULONG64 Process_Flags;                           // _EPROCESS.Flags
	ULONG64 Process_SectionObject;                   // _EPROCESS.SectionObject
	ULONG64 Process_SectionBaseAddress;              // _EPROCESS.SectionBaseAddress
	ULONG64 Thread_CrossThreadFlags;                 // _ETHREAD.CrossThreadFlags
	ULONG64 Thread_RundownProtect;                   // _ETHREAD.RundownProtect
	ULONG64 Thread_Win32StartAddress;                // _ETHREAD.Win32StartAddress
	ULONG64 ObjectTypeInit_GenericMapping;           // _OBJECT_TYPE_INITIALIZER.GenericMapping
	ULONG64 ObjectTypeInit_ValidAccessMask;          // _OBJECT_TYPE_INITIALIZER.ValidAccessMask
	ULONG64 ObjectTypeInit_CloseProcedure;           // _OBJECT_TYPE_INITIALIZER.CloseProcedure
	ULONG64 ObjectTypeInit_DeleteProcedure;          // _OBJECT_TYPE_INITIALIZER.DeleteProcedure

	// reserved control bits, must be 0
	ULONG Flags;
} SYMBOLS_DATA, *PSYMBOLS_DATA;

// 26 PVOID + 12 ULONG64 = 304 bytes (portion before Flags)
#define SYMBOLS_DATA_BASE_SIZE    (26 * sizeof(PVOID) + 12 * sizeof(ULONG64))

#define DBG_FLAG_REBUILD_CREATE_DEBUG 0x00000001
