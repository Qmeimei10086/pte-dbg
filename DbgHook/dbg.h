#pragma once
#include <ntifs.h>
#include "HookFunc.h"
#include "Symbols.h"

// Engine init: resolves helper pointers from g_SymbolsData, prepares the PID
// map and the PTE hook manager, creates the fake debug object type. Idempotent.
BOOLEAN DbgInit(VOID);

// Per-process hook management. Debuggers get the full hook set (create/attach
// flows), debuggees get the event set only.
BOOLEAN DbgAddDebugger(ULONG64 pid);
BOOLEAN DbgRemoveDebugger(ULONG64 pid);
BOOLEAN DbgAddDebuggee(ULONG64 pid);
BOOLEAN DbgRemoveDebuggee(ULONG64 pid);

// Full teardown: unhook everything.
BOOLEAN UnHookFuncs(VOID);
