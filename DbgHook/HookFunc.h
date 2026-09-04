#pragma once
#include <ntifs.h>
#include <ntimage.h>
#include "KernelDbgStruct.h"
#include "Symbols.h"

#define KGDT64_R3_CMCODE (2 * 16)       // user mode 32-bit code

#define DBGKP_FIELD_FROM_IMAGE_OPTIONAL_HEADER(hdrs, field) \
            ((hdrs)->OptionalHeader.field)

// unexported kernel function declarations
extern "C" PVOID PsGetThreadTeb(PETHREAD Thread);
extern "C" LONG NTAPI ExSystemExceptionFilter(VOID);
extern "C" PVOID PsGetProcessWow64Process(PEPROCESS eprocess);
extern "C" PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(PVOID Base);
extern "C" NTKERNELAPI NTSTATUS ObCreateObjectType(PUNICODE_STRING TypeName, PVOID ObjectTypeInitializer, PSECURITY_DESCRIPTOR SecurityDescriptor, PVOID* ObjectType);
extern "C" NTSTATUS ObCreateObject(KPROCESSOR_MODE ProbeMode, POBJECT_TYPE ObjectType, POBJECT_ATTRIBUTES ObjectAttributes, KPROCESSOR_MODE OwnershipMode, PVOID ParseContext, ULONG ObjectBodySize, ULONG PagedPoolCharge, ULONG NonPagedPoolCharge, PVOID* Object);

// debugger to debuggee binding, kept in the driver private list (core of the debug channel transfer)
typedef struct _DebugInfomation {
	LIST_ENTRY List;
	HANDLE SourceProcessId;      // debugger process pid
	HANDLE TargetProcessId;      // debuggee process pid
	DEBUG_OBJECT* DebugObject;   // fake debug object
} DebugInfomation, *PDebugInfomation;

// This global is a FAST_MUTEX in the target ntoskrnl build. Its type must
// match the acquire/release instructions used by the kernel helpers.
extern PFAST_MUTEX DbgkpProcessDebugPortMutex;

// original function pointer types used by the hooks
typedef VOID(*__DbgkCreateThread)(PETHREAD Thread);
typedef VOID(*__DbgkpWakeTarget)(PDEBUG_EVENT DebugEvent);
typedef PVOID(*__PsCaptureExceptionPort)(PEPROCESS Process);
typedef PETHREAD(*__PsGetNextProcessThread)(PEPROCESS Process, PETHREAD Thread);
typedef NTSTATUS(*__DbgkpPostFakeThreadMessages)(PEPROCESS Process, PDEBUG_OBJECT DebugObject, PETHREAD StartThread, PETHREAD* pFirstThread, PETHREAD* pLastThread);
NTSTATUS DbgkpPostFakeThreadMessagesHook(PEPROCESS Process, PDEBUG_OBJECT DebugObject, PETHREAD StartThread, PETHREAD* pFirstThread, PETHREAD* pLastThread);

#ifdef WIN7
typedef NTSTATUS(*__DbgkpSendApiMessage)(BOOLEAN SuspendProcess, PDBGKM_APIMSG ApiMsg);
#else
typedef NTSTATUS(*__DbgkpSendApiMessage)(PEPROCESS Process, BOOLEAN SuspendProcess, PDBGKM_APIMSG ApiMsg);
#endif

typedef BOOLEAN(*__DbgkpSuppressDbgMsg)(PVOID teb);
typedef VOID(*__DbgkpMarkProcessPeb)(PEPROCESS Process);
typedef HANDLE(*__DbgkpSectionToFileHandle)(PVOID SectionObject);
typedef NTSTATUS(*__NtTerminateProcess)(HANDLE ProcessHandle, NTSTATUS ExitStatus);
typedef NTSTATUS(*__DbgkpSendApiMessageLpc)(PDBGKM_APIMSG ApiMsg, PVOID Port, BOOLEAN SuspendProcess);
typedef VOID(*__DbgkSendSystemDllMessages)(PETHREAD Thread, PKEVENT EventsPresent, PDBGKM_APIMSG ApiMsg);
typedef NTSTATUS(*__DbgkpSendErrorMessage)(PEXCEPTION_RECORD ExceptionRecord, ULONG Falge, PDBGKM_APIMSG DbgApiMsg);
typedef NTSTATUS(*__DbgkpPostFakeProcessCreateMessages)(PEPROCESS Process, PDEBUG_OBJECT DebugObject, PETHREAD* pLastThread);
typedef VOID(*__KiDispatchException)(PEXCEPTION_RECORD ExceptionRecord, void* ExceptionFrame, void* TrapFrame, KPROCESSOR_MODE PreviousMode, BOOLEAN FirstChance);
typedef NTSTATUS(*__NtCreateUserProcess)(PHANDLE ProcessHandle, PHANDLE ThreadHandle, ACCESS_MASK ProcessDesiredAccess, ACCESS_MASK ThreadDesiredAccess, PVOID ProcessObjectAttributes, PVOID ThreadObjectAttributes, ULONG ProcessFlags, ULONG ThreadFlags, PVOID ProcessParameters, void* CreateInfo, void* AttributeList);

// reimplemented functions (hook targets, signatures must match the originals)
VOID DbgkCreateThread(PETHREAD Thread);
VOID DbgkUnMapViewOfSection(PEPROCESS Process, PVOID BaseAddress);
NTSTATUS NtTerminateProcess(HANDLE ProcessHandle, NTSTATUS ExitStatus);
NTSTATUS NtDebugActiveProcess(HANDLE ProcessHandle, HANDLE DebugObjectHandle);
VOID DbgkMapViewOfSection(PEPROCESS Process, PVOID SectionObject, PVOID BaseAddress);
BOOLEAN DbgkForwardException(PEXCEPTION_RECORD ExceptionRecord, BOOLEAN DebugException, BOOLEAN SecondChance);
NTSTATUS DbgkpSetProcessDebugObject(PEPROCESS Process, PDEBUG_OBJECT DebugObject, NTSTATUS MsgStatus, PETHREAD LastThread);
NTSTATUS DbgkpQueueMessage(PEPROCESS Process, PETHREAD Thread, PDBGKM_APIMSG ApiMsg, ULONG Flags, PDEBUG_OBJECT TargetDebugObject);
NTSTATUS NtCreateDebugObject(PHANDLE DebugObjectHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, ULONG Flags);
VOID KiDispatchException(PEXCEPTION_RECORD ExceptionRecord, void* ExceptionFrame, PKTRAP_FRAME TrapFrame, KPROCESSOR_MODE PreviousMode, BOOLEAN FirstChance);
NTSTATUS NtCreateUserProcess(PHANDLE ProcessHandle, PHANDLE ThreadHandle, ACCESS_MASK ProcessDesiredAccess, ACCESS_MASK ThreadDesiredAccess, PVOID ProcessObjectAttributes, PVOID ThreadObjectAttributes, ULONG ProcessFlags, ULONG ThreadFlags, PVOID ProcessParameters, void* CreateInfo, void* AttributeList);

// ---- missing function pointer types (for calling the original functions) ----
typedef NTSTATUS(*__DbgkpQueueMessage)(PEPROCESS Process, PETHREAD Thread, PDBGKM_APIMSG ApiMsg, ULONG Flags, PDEBUG_OBJECT TargetDebugObject);
typedef BOOLEAN(*__DbgkForwardException)(PEXCEPTION_RECORD ExceptionRecord, BOOLEAN DebugException, BOOLEAN SecondChance);
typedef VOID(*__DbgkMapViewOfSection)(PEPROCESS Process, PVOID SectionObject, PVOID BaseAddress);
typedef VOID(*__DbgkUnMapViewOfSection)(PEPROCESS Process, PVOID BaseAddress);
typedef NTSTATUS(*__DbgkpSetProcessDebugObject)(PEPROCESS Process, PDEBUG_OBJECT DebugObject, NTSTATUS MsgStatus, PETHREAD LastThread);
typedef NTSTATUS(*__NtCreateDebugObject)(PHANDLE DebugObjectHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, ULONG Flags);
typedef NTSTATUS(*__NtDebugActiveProcess)(HANDLE ProcessHandle, HANDLE DebugObjectHandle);

// ---- original function trampolines (filled by hook_manager, used to call the original functions) ----
extern __DbgkCreateThread OriginalDbgkCreateThread;
extern __DbgkpQueueMessage OriginalDbgkpQueueMessage;
extern __DbgkpPostFakeThreadMessages OriginalDbgkpPostFakeThreadMessages;
extern __DbgkForwardException OriginalDbgkForwardException;
extern __DbgkMapViewOfSection OriginalDbgkMapViewOfSection;
extern __DbgkUnMapViewOfSection OriginalDbgkUnMapViewOfSection;
extern __DbgkpSetProcessDebugObject OriginalDbgkpSetProcessDebugObject;
extern __NtCreateDebugObject OriginalNtCreateDebugObject;
extern __NtDebugActiveProcess OriginalNtDebugActiveProcess;
extern __KiDispatchException OrignalKiDispatchException;
extern __NtCreateUserProcess OrignalNtCreateUserProcess;
extern __NtTerminateProcess OrignalNtTerminateProcess;
