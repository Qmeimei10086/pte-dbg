#include "dbg.h"
#include "../PteHook/hook_manager.h"

extern SYMBOLS_DATA g_SymbolsData;
extern __DbgkpWakeTarget DbgkpWakeTarget;
extern __DbgkpSuppressDbgMsg DbgkpSuppressDbgMsg;
extern __DbgkpMarkProcessPeb DbgkpMarkProcessPeb;
extern __DbgkpSendApiMessage DbgkpSendApiMessage;
extern __DbgkCreateThread OriginalDbgkCreateThread;
extern __DbgkpSendErrorMessage DbgkpSendErrorMessage;
extern __NtTerminateProcess OrignalNtTerminateProcess;
extern __DbgkpSendApiMessageLpc DbgkpSendApiMessageLpc;
extern __PsCaptureExceptionPort PsCaptureExceptionPort;
extern __PsGetNextProcessThread PsGetNextProcessThread;
extern __KiDispatchException OrignalKiDispatchException;
extern __NtCreateUserProcess OrignalNtCreateUserProcess;
extern __DbgkpSectionToFileHandle DbgkpSectionToFileHandle;
extern __DbgkSendSystemDllMessages DbgkSendSystemDllMessages;
extern __DbgkpPostFakeThreadMessages DbgkpPostFakeThreadMessages;
extern __DbgkpPostFakeThreadMessages OriginalDbgkpPostFakeThreadMessages;
extern __DbgkpPostFakeProcessCreateMessages DbgkpPostFakeProcessCreateMessages;
extern KSPIN_LOCK g_DebugLock;
extern DebugInfomation g_Debuginfo;
extern PFAST_MUTEX DbgkpProcessDebugPortMutex;

__DbgkpQueueMessage OriginalDbgkpQueueMessage = NULL;
__NtCreateDebugObject OriginalNtCreateDebugObject = NULL;
__DbgkForwardException OriginalDbgkForwardException = NULL;
__NtDebugActiveProcess OriginalNtDebugActiveProcess = NULL;
__DbgkMapViewOfSection OriginalDbgkMapViewOfSection = NULL;
__DbgkUnMapViewOfSection OriginalDbgkUnMapViewOfSection = NULL;
__DbgkpSetProcessDebugObject OriginalDbgkpSetProcessDebugObject = NULL;

POBJECT_TYPE* g_DbgkDebugObjectType = NULL;

static HOOK_MANAGER g_HookManager = { 0 };
static BOOLEAN g_EngineReady = FALSE;
static LIST_ENTRY g_Sessions;

// Trampolines are content-identical for every hooked process (they hold the
// original kernel prologue), so a single global pointer per function is safe.
typedef struct _HOOK_DEF {
	PVOID* Source;    // &g_SymbolsData.<func>
	PVOID Hook;       // replacement function
	PVOID* Original;  // receives the trampoline
} HOOK_DEF;

static HOOK_DEF g_DebuggerHooks[] = {
	{ &g_SymbolsData.NtCreateUserProcess,        NtCreateUserProcess,             (PVOID*)&OrignalNtCreateUserProcess },
	{ &g_SymbolsData.DbgkCreateThread,           DbgkCreateThread,                (PVOID*)&OriginalDbgkCreateThread },
	{ &g_SymbolsData.DbgkMapViewOfSection,       DbgkMapViewOfSection,            (PVOID*)&OriginalDbgkMapViewOfSection },
	{ &g_SymbolsData.DbgkUnMapViewOfSection,     DbgkUnMapViewOfSection,          (PVOID*)&OriginalDbgkUnMapViewOfSection },
	{ &g_SymbolsData.DbgkpQueueMessage,          DbgkpQueueMessage,               (PVOID*)&OriginalDbgkpQueueMessage },
	{ &g_SymbolsData.DbgkpPostFakeThreadMessages,DbgkpPostFakeThreadMessagesHook, (PVOID*)&OriginalDbgkpPostFakeThreadMessages },
	{ &g_SymbolsData.NtTerminateProcess,         NtTerminateProcess,              (PVOID*)&OrignalNtTerminateProcess },
	{ &g_SymbolsData.KiDispatchException,        KiDispatchException,             (PVOID*)&OrignalKiDispatchException },
	{ &g_SymbolsData.NtCreateDebugObject,        NtCreateDebugObject,             (PVOID*)&OriginalNtCreateDebugObject },
	{ &g_SymbolsData.NtDebugActiveProcess,       NtDebugActiveProcess,            (PVOID*)&OriginalNtDebugActiveProcess },
	{ &g_SymbolsData.DbgkForwardException,       DbgkForwardException,            (PVOID*)&OriginalDbgkForwardException },
	{ &g_SymbolsData.DbgkpSetProcessDebugObject, DbgkpSetProcessDebugObject,      (PVOID*)&OriginalDbgkpSetProcessDebugObject },
};

static HOOK_DEF g_DebuggeeHooks[] = {
	{ &g_SymbolsData.DbgkCreateThread,       DbgkCreateThread,       (PVOID*)&OriginalDbgkCreateThread },
	{ &g_SymbolsData.DbgkMapViewOfSection,   DbgkMapViewOfSection,   (PVOID*)&OriginalDbgkMapViewOfSection },
	{ &g_SymbolsData.DbgkUnMapViewOfSection, DbgkUnMapViewOfSection, (PVOID*)&OriginalDbgkUnMapViewOfSection },
	{ &g_SymbolsData.KiDispatchException,    KiDispatchException,    (PVOID*)&OrignalKiDispatchException },
	{ &g_SymbolsData.DbgkForwardException,   DbgkForwardException,   (PVOID*)&OriginalDbgkForwardException },
	{ &g_SymbolsData.DbgkpQueueMessage,      DbgkpQueueMessage,      (PVOID*)&OriginalDbgkpQueueMessage },
	{ &g_SymbolsData.NtTerminateProcess,     NtTerminateProcess,     (PVOID*)&OrignalNtTerminateProcess },
};

// Install one PTE hook for a process. On input pFunc is the real function
// address, on success *outAddress receives the trampoline.
static BOOLEAN HookFunction(ULONG64 pid, PVOID pFunc, PVOID hookAddress, PVOID* outAddress)
{
	if (!pFunc)
		return FALSE;

	void* isolatedPage = NULL;
	void* original = pFunc;

	if (!hook_manager_install_hook(&g_HookManager,
		(HANDLE)pid,
		&original,
		hookAddress,
		&isolatedPage))
	{
		DbgPrintEx(77, 0, "[DbgHook] PTE hook failed for %p (pid %llu)\n", pFunc, (unsigned long long)pid);
		return FALSE;
	}

	*outAddress = original;
	return TRUE;
}

static BOOLEAN InstallHookSet(ULONG64 pid, const HOOK_DEF* set, ULONG count)
{
	for (ULONG i = 0; i < count; i++)
	{
		if (!HookFunction(pid, *set[i].Source, set[i].Hook, set[i].Original))
		{
			hook_manager_uninstall_pid(&g_HookManager, (HANDLE)pid);
			return FALSE;
		}
	}
	return TRUE;
}

// Replace the global DbgkDebugObjectType with a fake type ("PteDbg"), so
// anti-debug checks (NtQueryObject ObjectTypeInformation) cannot see the real
// "DebugObject" type.
static BOOLEAN HookDbgkDebugObjectType()
{
	UNICODE_STRING ObjectTypeName;

	g_DbgkDebugObjectType = (POBJECT_TYPE*)g_SymbolsData.DbgkDebugObjectType;
	if (g_DbgkDebugObjectType == 0)
		return FALSE;

	RtlInitUnicodeString(&ObjectTypeName, L"PteDbg");
	PUCHAR pTypeInfo = (PUCHAR)&(*g_DbgkDebugObjectType)->TypeInfo;
	USHORT Length = *(PUSHORT)pTypeInfo;
	if (Length == 0 || Length > PAGE_SIZE)
		return FALSE;
	PUCHAR pInit = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, Length, 'Dbg');
	if (!pInit)
		return FALSE;
	RtlCopyMemory(pInit, pTypeInfo, Length);
	*(PVOID*)(pInit + g_SymbolsData.ObjectTypeInit_DeleteProcedure) = NULL;
	*(PVOID*)(pInit + g_SymbolsData.ObjectTypeInit_CloseProcedure) = NULL;
	*(PULONG)(pInit + g_SymbolsData.ObjectTypeInit_GenericMapping + 0x00) = 0x00020001;
	*(PULONG)(pInit + g_SymbolsData.ObjectTypeInit_GenericMapping + 0x04) = 0x00020002;
	*(PULONG)(pInit + g_SymbolsData.ObjectTypeInit_GenericMapping + 0x08) = 0x00120000;
	*(PULONG)(pInit + g_SymbolsData.ObjectTypeInit_GenericMapping + 0x0c) = 0x001f000f;
	*(PULONG)(pInit + g_SymbolsData.ObjectTypeInit_ValidAccessMask) = 0x001f000f;

	NTSTATUS status = ObCreateObjectType(&ObjectTypeName, pInit, NULL, (PVOID*)g_DbgkDebugObjectType);
	ExFreePoolWithTag(pInit, 'Dbg');
	if (!NT_SUCCESS(status))
	{
		if (status == STATUS_OBJECT_NAME_COLLISION)
		{
			POBJECT_TYPE* ObTypeIndexTable = (POBJECT_TYPE*)g_SymbolsData.ObTypeIndexTable;
			if (!ObTypeIndexTable)
				return FALSE;
			ULONG Index = 2;
			while (ObTypeIndexTable[Index])
			{
				if (&ObTypeIndexTable[Index]->Name && ObTypeIndexTable[Index]->Name.Buffer &&
					RtlCompareUnicodeString(&ObTypeIndexTable[Index]->Name, &ObjectTypeName, FALSE) == 0)
				{
					*g_DbgkDebugObjectType = ObTypeIndexTable[Index];
					return TRUE;
				}
				Index++;
			}
		}
	}
	return TRUE;
}

// ---- PID sessions ----

typedef struct _PID_SESSION {
	LIST_ENTRY List;
	ULONG64 Pid;
	BOOLEAN IsDebugger;
} PID_SESSION, *PPID_SESSION;

static BOOLEAN SessionExists(ULONG64 pid)
{
	BOOLEAN found = FALSE;
	KIRQL OldIrql = { 0 };
	KeAcquireSpinLock(&g_DebugLock, &OldIrql);
	for (PLIST_ENTRY e = g_Sessions.Flink; e != &g_Sessions; e = e->Flink)
	{
		if (CONTAINING_RECORD(e, PID_SESSION, List)->Pid == pid)
		{
			found = TRUE;
			break;
		}
	}
	KeReleaseSpinLock(&g_DebugLock, OldIrql);
	return found;
}

static BOOLEAN SessionAdd(ULONG64 pid, BOOLEAN isDebugger)
{
	PPID_SESSION s = (PPID_SESSION)ExAllocatePoolWithTag(NonPagedPool, sizeof(PID_SESSION), 'SeS');
	if (!s)
		return FALSE;
	s->Pid = pid;
	s->IsDebugger = isDebugger;
	KIRQL OldIrql = { 0 };
	KeAcquireSpinLock(&g_DebugLock, &OldIrql);
	InsertTailList(&g_Sessions, &s->List);
	KeReleaseSpinLock(&g_DebugLock, OldIrql);
	return TRUE;
}

static void SessionRemove(ULONG64 pid)
{
	KIRQL OldIrql = { 0 };
	KeAcquireSpinLock(&g_DebugLock, &OldIrql);
	for (PLIST_ENTRY e = g_Sessions.Flink; e != &g_Sessions; )
	{
		PLIST_ENTRY next = e->Flink;
		PPID_SESSION s = CONTAINING_RECORD(e, PID_SESSION, List);
		if (s->Pid == pid)
		{
			RemoveEntryList(e);
			ExFreePoolWithTag(s, 'SeS');
		}
		e = next;
	}
	KeReleaseSpinLock(&g_DebugLock, OldIrql);
}

// ---- PID map (debugger <-> debuggee <-> fake debug object) ----

static BOOLEAN HasTargetEntry(ULONG64 pid)
{
	for (PLIST_ENTRY e = g_Debuginfo.List.Flink; e != &g_Debuginfo.List; e = e->Flink)
	{
		if (CONTAINING_RECORD(e, DebugInfomation, List)->TargetProcessId == (HANDLE)pid)
			return TRUE;
	}
	return FALSE;
}

static void RemoveListBy(BOOLEAN bySource, ULONG64 pid)
{
	KIRQL OldIrql = { 0 };
	KeAcquireSpinLock(&g_DebugLock, &OldIrql);
	for (PLIST_ENTRY e = g_Debuginfo.List.Flink; e != &g_Debuginfo.List; )
	{
		PLIST_ENTRY next = e->Flink;
		PDebugInfomation p = CONTAINING_RECORD(e, DebugInfomation, List);
		HANDLE key = bySource ? p->SourceProcessId : p->TargetProcessId;
		if (key == (HANDLE)pid)
		{
			RemoveEntryList(e);
			ExFreePoolWithTag(p, 'YC');
		}
		e = next;
	}
	KeReleaseSpinLock(&g_DebugLock, OldIrql);
}

// ---- public API ----

BOOLEAN DbgInit(VOID)
{
	if (g_EngineReady)
		return TRUE;

	DbgkpWakeTarget = (__DbgkpWakeTarget)g_SymbolsData.DbgkpWakeTarget;
	DbgkpSuppressDbgMsg = (__DbgkpSuppressDbgMsg)g_SymbolsData.DbgkpSuppressDbgMsg;
	DbgkpSendApiMessage = (__DbgkpSendApiMessage)g_SymbolsData.DbgkpSendApiMessage;
	DbgkpMarkProcessPeb = (__DbgkpMarkProcessPeb)g_SymbolsData.DbgkpMarkProcessPeb;
	DbgkpSendErrorMessage = (__DbgkpSendErrorMessage)g_SymbolsData.DbgkpSendErrorMessage;
	PsGetNextProcessThread = (__PsGetNextProcessThread)g_SymbolsData.PsGetNextProcessThread;
	DbgkpSendApiMessageLpc = (__DbgkpSendApiMessageLpc)g_SymbolsData.DbgkpSendApiMessageLpc;
	PsCaptureExceptionPort = (__PsCaptureExceptionPort)g_SymbolsData.PsCaptureExceptionPort;
	DbgkpSectionToFileHandle = (__DbgkpSectionToFileHandle)g_SymbolsData.DbgkpSectionToFileHandle;
	DbgkSendSystemDllMessages = (__DbgkSendSystemDllMessages)g_SymbolsData.DbgkSendSystemDllMessages;
	DbgkpPostFakeThreadMessages = (__DbgkpPostFakeThreadMessages)g_SymbolsData.DbgkpPostFakeThreadMessages;
	DbgkpPostFakeProcessCreateMessages = (__DbgkpPostFakeProcessCreateMessages)g_SymbolsData.DbgkpPostFakeProcessCreateMessages;
	DbgkpProcessDebugPortMutex = (PFAST_MUTEX)g_SymbolsData.DbgkpProcessDebugPortMutex;

	BOOLEAN ok = TRUE;
	for (ULONG i = 0; i < sizeof(g_DebuggerHooks) / sizeof(g_DebuggerHooks[0]); i++)
		if (!*g_DebuggerHooks[i].Source) ok = FALSE;
	if (!ok || !DbgkpWakeTarget || !DbgkpSendApiMessage || !DbgkpMarkProcessPeb ||
		!DbgkpPostFakeThreadMessages || !DbgkpPostFakeProcessCreateMessages ||
		!DbgkpSectionToFileHandle || !DbgkSendSystemDllMessages ||
		!DbgkpProcessDebugPortMutex || !g_SymbolsData.DbgkDebugObjectType ||
		!g_SymbolsData.ObTypeIndexTable)
	{
		DbgPrintEx(77, 0, "[DbgHook] required debug symbol is missing\n");
		return FALSE;
	}

	InitializeListHead(&g_Debuginfo.List);
	InitializeListHead(&g_Sessions);
	KeInitializeSpinLock(&g_DebugLock);

	NTSTATUS status = hook_manager_init(&g_HookManager);
	if (!NT_SUCCESS(status))
	{
		DbgPrintEx(77, 0, "[DbgHook] hook_manager_init failed: 0x%08X\n", status);
		return FALSE;
	}
	g_EngineReady = TRUE;

	if (!HookDbgkDebugObjectType())
		DbgPrintEx(77, 0, "[DbgHook] HookDbgkDebugObjectType failed\n");

	DbgPrintEx(77, 0, "[DbgHook] engine ready\n");
	return TRUE;
}

BOOLEAN DbgAddDebugger(ULONG64 pid)
{
	if (!g_EngineReady || !pid || SessionExists(pid))
		return FALSE;

	if (!InstallHookSet(pid, g_DebuggerHooks, sizeof(g_DebuggerHooks) / sizeof(g_DebuggerHooks[0])))
		return FALSE;

	if (!SessionAdd(pid, TRUE))
	{
		// Session bookkeeping is what prevents a second hook of the same
		// function in the same process (which would corrupt the trampoline),
		// so a failed add must roll the hooks back.
		hook_manager_uninstall_pid(&g_HookManager, (HANDLE)pid);
		return FALSE;
	}

	DbgPrintEx(77, 0, "[DbgHook] debugger %llu hooked (full set)\n", (unsigned long long)pid);
	return TRUE;
}

BOOLEAN DbgRemoveDebugger(ULONG64 pid)
{
	if (!g_EngineReady || !SessionExists(pid))
		return FALSE;

	hook_manager_uninstall_pid(&g_HookManager, (HANDLE)pid);
	SessionRemove(pid);
	RemoveListBy(TRUE, pid);
	DbgPrintEx(77, 0, "[DbgHook] debugger %llu unhooked\n", (unsigned long long)pid);
	return TRUE;
}

BOOLEAN DbgAddDebuggee(ULONG64 pid)
{
	if (!g_EngineReady || !pid || SessionExists(pid))
		return FALSE;

	if (!InstallHookSet(pid, g_DebuggeeHooks, sizeof(g_DebuggeeHooks) / sizeof(g_DebuggeeHooks[0])))
		return FALSE;

	if (!SessionAdd(pid, FALSE))
	{
		hook_manager_uninstall_pid(&g_HookManager, (HANDLE)pid);
		return FALSE;
	}

	DbgPrintEx(77, 0, "[DbgHook] debuggee %llu hooked (event set)\n", (unsigned long long)pid);
	return TRUE;
}

BOOLEAN DbgRemoveDebuggee(ULONG64 pid)
{
	if (!g_EngineReady || !SessionExists(pid))
		return FALSE;

	hook_manager_uninstall_pid(&g_HookManager, (HANDLE)pid);
	SessionRemove(pid);
	RemoveListBy(FALSE, pid);
	DbgPrintEx(77, 0, "[DbgHook] debuggee %llu unhooked\n", (unsigned long long)pid);
	return TRUE;
}

BOOLEAN UnHookFuncs(VOID)
{
	if (g_EngineReady)
	{
		hook_manager_uninstall_all(&g_HookManager);
		hook_manager_destroy(&g_HookManager);

		// Clear the PID map and session table under the same lock the hook
		// functions use, so nothing can observe the lists mid-teardown.
		KIRQL OldIrql = { 0 };
		KeAcquireSpinLock(&g_DebugLock, &OldIrql);
		while (!IsListEmpty(&g_Debuginfo.List))
		{
			PDebugInfomation p = (PDebugInfomation)RemoveHeadList(&g_Debuginfo.List);
			ExFreePoolWithTag(p, 'YC');
		}
		while (!IsListEmpty(&g_Sessions))
		{
			PPID_SESSION s = (PPID_SESSION)RemoveHeadList(&g_Sessions);
			ExFreePoolWithTag(s, 'SeS');
		}
		KeReleaseSpinLock(&g_DebugLock, OldIrql);

		g_EngineReady = FALSE;
	}

	// The fake debug object type cannot be unregistered safely, it is simply
	// left in place (it has no Close/Delete procedures).

	DbgPrintEx(77, 0, "[DbgHook] hooks removed, driver unloaded.\n");
	return TRUE;
}
