#pragma once

#include <windows.h>

#define DRV_SERVICE_NAME  L"PteDbg"
#define DRV_SYS_FILENAME  L"pte-dbg.sys"
#define DRV_DEVICE_NAME   L"\\\\.\\PteDbg"

typedef void(__cdecl* SVC_LOG_CB)(const wchar_t* line);

BOOL DriverLoad(SVC_LOG_CB log);
BOOL DriverUnload(SVC_LOG_CB log);
