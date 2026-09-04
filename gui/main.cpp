#include "../Common/SymbolLoader.h"
#include "DriverService.h"

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <wchar.h>

#pragma comment(lib, "advapi32.lib")

#define IOCTL_PTEDBG_LOAD_SYMBOLS    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PTEDBG_ADD_DEBUGGER    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PTEDBG_REMOVE_DEBUGGER CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PTEDBG_ADD_DEBUGGEE    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PTEDBG_REMOVE_DEBUGGEE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IDC_LOG        1001
#define IDB_LOAD       1002
#define IDB_UNLOAD     1003
#define GRB_DBG        1004
#define LBC_DBG        1005
#define IDB_DBG_ADD    1006
#define IDB_DBG_DEL    1007
#define GRB_TGT        1008
#define LBC_TGT        1009
#define IDB_TGT_ADD    1010
#define IDB_TGT_DEL    1011

#define IDC_DLG_PID    2001
#define IDC_DLG_ADD    2002
#define IDC_DLG_CANCEL 2003

#define WM_APP_SYMBOLS_DONE (WM_APP + 1)

#define MAX_PIDS 64

static SYMBOLS_DATA g_SymbolsData = { 0 };
static BOOL g_symbolsOk = FALSE;
static BOOL g_loaded = FALSE;
static HANDLE g_hDevice = INVALID_HANDLE_VALUE;
static HINSTANCE g_hInst = NULL;
static HFONT g_font = NULL;
static volatile LONG g_closing = 0;

static HWND g_hMainWnd, g_hLog, g_hBtnLoad, g_hBtnUnload;
static HWND g_hGrpDbg, g_hLbDbg, g_hBtnDbgAdd, g_hBtnDbgDel;
static HWND g_hGrpTgt, g_hLbTgt, g_hBtnTgtAdd, g_hBtnTgtDel;
static HANDLE g_hSymbolThread = NULL;

static ULONG64 g_dbgPids[MAX_PIDS]; static int g_dbgCount = 0;
static ULONG64 g_tgtPids[MAX_PIDS]; static int g_tgtCount = 0;

static void LogLineW(const wchar_t* line)
{
    if (InterlockedCompareExchange(&g_closing, 0, 0) != 0)
        return;

    if (g_hLog && IsWindow(g_hLog)) {
        wchar_t tmp[512];
        swprintf_s(tmp, _countof(tmp), L"%s\r\n", line);
        int len = GetWindowTextLengthW(g_hLog);
        SendMessageW(g_hLog, EM_SETSEL, (WPARAM)len, (LPARAM)len);
        SendMessageW(g_hLog, EM_REPLACESEL, FALSE, (LPARAM)tmp);
        UpdateWindow(g_hLog);
    }
}

static void LogW(const wchar_t* fmt, ...)
{
    wchar_t buf[512];
    va_list ap;
    va_start(ap, fmt);
    _vsnwprintf_s(buf, _countof(buf), _TRUNCATE, fmt, ap);
    va_end(ap);
    LogLineW(buf);
}

static void __cdecl LogLineCB(const wchar_t* line) { LogLineW(line); }

static void __cdecl SymbolLog(const char* fmt, ...)
{
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    _vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, ap);
    va_end(ap);
    wchar_t wbuf[512];
    MultiByteToWideChar(CP_ACP, 0, buf, -1, wbuf, _countof(wbuf));
    LogLineW(wbuf);
}

static void UpdateControls()
{
    EnableWindow(g_hBtnLoad, g_symbolsOk && !g_loaded);
    EnableWindow(g_hBtnUnload, g_loaded);
    EnableWindow(g_hLbDbg, g_loaded);
    EnableWindow(g_hLbTgt, g_loaded);
    EnableWindow(g_hBtnDbgAdd, g_loaded);
    EnableWindow(g_hBtnTgtAdd, g_loaded);
    EnableWindow(g_hBtnDbgDel, g_loaded &&
        SendMessageW(g_hLbDbg, LB_GETCURSEL, 0, 0) != LB_ERR);
    EnableWindow(g_hBtnTgtDel, g_loaded &&
        SendMessageW(g_hLbTgt, LB_GETCURSEL, 0, 0) != LB_ERR);
}

static BOOL SendPidIoctl(DWORD code, ULONG64 pid)
{
    DWORD bytes = 0;
    return DeviceIoControl(g_hDevice, code, &pid, sizeof(pid), NULL, 0, &bytes, NULL);
}

static void AddPid(HWND lb, ULONG64* arr, int* cnt, ULONG64 pid)
{
    if (*cnt >= MAX_PIDS)
        return;
    wchar_t t[32];
    swprintf_s(t, _countof(t), L"%llu", (unsigned long long)pid);
    SendMessageW(lb, LB_ADDSTRING, 0, (LPARAM)t);
    arr[(*cnt)++] = pid;
}

static void RemovePidAt(HWND lb, ULONG64* arr, int* cnt, int idx)
{
    if (idx < 0 || idx >= *cnt)
        return;
    SendMessageW(lb, LB_DELETESTRING, (WPARAM)idx, 0);
    for (int i = idx; i < *cnt - 1; i++)
        arr[i] = arr[i + 1];
    (*cnt)--;
}

static void ClearPids(HWND lb, int* cnt)
{
    SendMessageW(lb, LB_RESETCONTENT, 0, 0);
    *cnt = 0;
}

// ---- modal pid input dialog ----

static BOOL g_dlgOk = FALSE;
static ULONG64 g_dlgPid = 0;

static LRESULT CALLBACK PidDlgProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_CREATE: {
        HINSTANCE hi = GetModuleHandleW(NULL);
        CreateWindowW(L"STATIC", L"PID:", WS_CHILD | WS_VISIBLE,
            16, 18, 36, 20, hwnd, NULL, hi, NULL);
        CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL | ES_NUMBER,
            56, 14, 160, 24, hwnd, (HMENU)IDC_DLG_PID, hi, NULL);
        CreateWindowW(L"BUTTON", L"Add",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
            56, 52, 76, 28, hwnd, (HMENU)IDC_DLG_ADD, hi, NULL);
        CreateWindowW(L"BUTTON", L"Cancel",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            140, 52, 76, 28, hwnd, (HMENU)IDC_DLG_CANCEL, hi, NULL);
        return 0;
    }
    case WM_COMMAND: {
        int id = LOWORD(wp);
        if (id == IDC_DLG_ADD) {
            wchar_t t[32] = { 0 };
            GetDlgItemTextW(hwnd, IDC_DLG_PID, t, _countof(t));
            ULONG64 pid = wcstoull(t, NULL, 0);
            if (pid == 0) {
                MessageBoxW(hwnd, L"Please enter a valid pid.", L"PteDbg", MB_ICONWARNING);
                return 0;
            }
            HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)pid);
            if (!h) {
                MessageBoxW(hwnd, L"Process not found.", L"PteDbg", MB_ICONWARNING);
                return 0;
            }
            CloseHandle(h);
            g_dlgPid = pid;
            g_dlgOk = TRUE;
            DestroyWindow(hwnd);
            return 0;
        }
        if (id == IDC_DLG_CANCEL || id == IDCANCEL) {
            DestroyWindow(hwnd);
            return 0;
        }
        break;
    }
    case WM_CLOSE:
        DestroyWindow(hwnd);
        return 0;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

static BOOL PidDialog(HWND parent, const wchar_t* title, ULONG64* outPid)
{
    g_dlgOk = FALSE;
    g_dlgPid = 0;

    WNDCLASSW wc = { 0 };
    wc.lpfnWndProc = PidDlgProc;
    wc.hInstance = g_hInst;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"PteDbgPidDlg";
    RegisterClassW(&wc);

    EnableWindow(parent, FALSE);
    HWND dlg = CreateWindowExW(WS_EX_DLGMODALFRAME, L"PteDbgPidDlg", title,
        WS_POPUP | WS_CAPTION | WS_SYSMENU,
        CW_USEDEFAULT, CW_USEDEFAULT, 250, 128,
        parent, NULL, g_hInst, NULL);
    if (!dlg) {
        EnableWindow(parent, TRUE);
        return FALSE;
    }
    RECT r, rp;
    GetWindowRect(dlg, &r);
    GetWindowRect(parent, &rp);
    SetWindowPos(dlg, NULL,
        rp.left + ((rp.right - rp.left) - (r.right - r.left)) / 2,
        rp.top + ((rp.bottom - rp.top) - (r.bottom - r.top)) / 2,
        0, 0, SWP_NOSIZE | SWP_NOZORDER);
    {
        // apply font to children
        HWND c = GetWindow(dlg, GW_CHILD);
        while (c) { SendMessageW(c, WM_SETFONT, (WPARAM)g_font, TRUE); c = GetWindow(c, GW_HWNDNEXT); }
    }
    ShowWindow(dlg, SW_SHOW);
    SetFocus(GetDlgItem(dlg, IDC_DLG_PID));

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0)) {
        if (IsDialogMessage(dlg, &msg))
            continue;
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    EnableWindow(parent, TRUE);
    SetForegroundWindow(parent);
    *outPid = g_dlgPid;
    return g_dlgOk;
}

// ---- actions ----

static void OnLoadDriver()
{
    LogW(L"[*] Loading driver ...");
    if (!DriverLoad(LogLineCB)) {
        LogW(L"[!] Load driver failed");
        return;
    }

    g_hDevice = CreateFileW(DRV_DEVICE_NAME, GENERIC_READ | GENERIC_WRITE, 0,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (g_hDevice == INVALID_HANDLE_VALUE) {
        LogW(L"[!] Open %s failed: %lu", DRV_DEVICE_NAME, GetLastError());
        DriverUnload(LogLineCB);
        return;
    }

    DWORD bytes = 0;
    if (!DeviceIoControl(g_hDevice, IOCTL_PTEDBG_LOAD_SYMBOLS,
        &g_SymbolsData, sizeof(g_SymbolsData), NULL, 0, &bytes, NULL)) {
        LogW(L"[!] Send symbols failed: %lu", GetLastError());
        CloseHandle(g_hDevice);
        g_hDevice = INVALID_HANDLE_VALUE;
        DriverUnload(LogLineCB);
        return;
    }

    g_loaded = TRUE;
    UpdateControls();
    LogW(L"[+] Driver loaded. Add a debugger pid, then debuggee pids.");
}

static void OnUnloadDriver()
{
    LogW(L"[*] Unloading driver ...");
    if (g_hDevice != INVALID_HANDLE_VALUE) {
        CloseHandle(g_hDevice);
        g_hDevice = INVALID_HANDLE_VALUE;
    }
    if (DriverUnload(LogLineCB)) {
        g_loaded = FALSE;
        ClearPids(g_hLbDbg, &g_dbgCount);
        ClearPids(g_hLbTgt, &g_tgtCount);
        LogW(L"[+] Driver unloaded, all hooks removed");
    }
    UpdateControls();
}

static void OnAddDebugger()
{
    ULONG64 pid;
    if (!PidDialog(g_hMainWnd, L"Add Debugger", &pid))
        return;
    if (SendPidIoctl(IOCTL_PTEDBG_ADD_DEBUGGER, pid)) {
        AddPid(g_hLbDbg, g_dbgPids, &g_dbgCount, pid);
        LogW(L"[+] Debugger %llu hooked (full set)", pid);
    } else {
        LogW(L"[!] Add debugger %llu failed: %lu (already hooked? dead pid?)", pid, GetLastError());
    }
}

static void OnDelDebugger()
{
    int idx = (int)SendMessageW(g_hLbDbg, LB_GETCURSEL, 0, 0);
    if (idx == LB_ERR)
        return;
    ULONG64 pid = g_dbgPids[idx];
    if (SendPidIoctl(IOCTL_PTEDBG_REMOVE_DEBUGGER, pid)) {
        RemovePidAt(g_hLbDbg, g_dbgPids, &g_dbgCount, idx);
        LogW(L"[+] Debugger %llu unhooked", pid);
    } else {
        LogW(L"[!] Remove debugger %llu failed: %lu", pid, GetLastError());
    }
    UpdateControls();
}

static void OnAddDebuggee()
{
    ULONG64 pid;
    if (!PidDialog(g_hMainWnd, L"Add Debuggee", &pid))
        return;
    if (SendPidIoctl(IOCTL_PTEDBG_ADD_DEBUGGEE, pid)) {
        AddPid(g_hLbTgt, g_tgtPids, &g_tgtCount, pid);
        LogW(L"[+] Debuggee %llu hooked (event set)", pid);
    } else {
        LogW(L"[!] Add debuggee %llu failed: %lu (already hooked?)", pid, GetLastError());
    }
}

static void OnDelDebuggee()
{
    int idx = (int)SendMessageW(g_hLbTgt, LB_GETCURSEL, 0, 0);
    if (idx == LB_ERR)
        return;
    ULONG64 pid = g_tgtPids[idx];
    if (SendPidIoctl(IOCTL_PTEDBG_REMOVE_DEBUGGEE, pid)) {
        RemovePidAt(g_hLbTgt, g_tgtPids, &g_tgtCount, idx);
        LogW(L"[+] Debuggee %llu unhooked", pid);
    } else {
        LogW(L"[!] Remove debuggee %llu failed: %lu", pid, GetLastError());
    }
    UpdateControls();
}

static void Layout(int w, int h)
{
    if (w < 420 || h < 360)
        return;
    MoveWindow(g_hLog, 12, 12, w - 24, 168, TRUE);
    MoveWindow(g_hBtnLoad, 12, 190, 150, 30, TRUE);
    MoveWindow(g_hBtnUnload, 172, 190, 150, 30, TRUE);

    int gw = (w - 36) / 2;
    int gy = 232;
    int gh = h - gy - 12;
    MoveWindow(g_hGrpDbg, 12, gy, gw, gh, TRUE);
    MoveWindow(g_hLbDbg, 24, gy + 20, gw - 24, gh - 76, TRUE);
    MoveWindow(g_hBtnDbgAdd, 24, gy + gh - 44, (gw - 34) / 2, 30, TRUE);
    MoveWindow(g_hBtnDbgDel, 34 + (gw - 34) / 2, gy + gh - 44, (gw - 34) / 2, 30, TRUE);

    MoveWindow(g_hGrpTgt, 24 + gw, gy, gw, gh, TRUE);
    MoveWindow(g_hLbTgt, 36 + gw, gy + 20, gw - 24, gh - 76, TRUE);
    MoveWindow(g_hBtnTgtAdd, 36 + gw, gy + gh - 44, (gw - 34) / 2, 30, TRUE);
    MoveWindow(g_hBtnTgtDel, 46 + gw + (gw - 34) / 2, gy + gh - 44, (gw - 34) / 2, 30, TRUE);
}

static DWORD WINAPI SymbolThread(LPVOID param)
{
    UNREFERENCED_PARAMETER(param);
    BOOL ok = SymbolLoadAndResolve(&g_SymbolsData, SymbolLog);
    SymbolCleanup();
    if (InterlockedCompareExchange(&g_closing, 0, 0) == 0)
        PostMessageW(g_hMainWnd, WM_APP_SYMBOLS_DONE, (WPARAM)ok, 0);
    return 0;
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
    case WM_CREATE: {
        g_hMainWnd = hwnd;
        HINSTANCE hi = GetModuleHandleW(NULL);

        g_hLog = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY | WS_VSCROLL,
            12, 12, 736, 168, hwnd, (HMENU)IDC_LOG, hi, NULL);
        g_hBtnLoad = CreateWindowW(L"BUTTON", L"Load Driver",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON | WS_DISABLED,
            12, 190, 150, 30, hwnd, (HMENU)IDB_LOAD, hi, NULL);
        g_hBtnUnload = CreateWindowW(L"BUTTON", L"Unload Driver",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON | WS_DISABLED,
            172, 190, 150, 30, hwnd, (HMENU)IDB_UNLOAD, hi, NULL);

        g_hGrpDbg = CreateWindowW(L"BUTTON", L"Debuggers",
            WS_CHILD | WS_VISIBLE | BS_GROUPBOX,
            12, 232, 364, 216, hwnd, (HMENU)GRB_DBG, hi, NULL);
        g_hLbDbg = CreateWindowExW(WS_EX_CLIENTEDGE, L"LISTBOX", L"",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | LBS_NOTIFY | WS_VSCROLL | WS_DISABLED,
            24, 252, 340, 128, hwnd, (HMENU)LBC_DBG, hi, NULL);
        g_hBtnDbgAdd = CreateWindowW(L"BUTTON", L"Add",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON | WS_DISABLED,
            24, 404, 165, 30, hwnd, (HMENU)IDB_DBG_ADD, hi, NULL);
        g_hBtnDbgDel = CreateWindowW(L"BUTTON", L"Delete",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON | WS_DISABLED,
            199, 404, 165, 30, hwnd, (HMENU)IDB_DBG_DEL, hi, NULL);

        g_hGrpTgt = CreateWindowW(L"BUTTON", L"Debuggees",
            WS_CHILD | WS_VISIBLE | BS_GROUPBOX,
            384, 232, 364, 216, hwnd, (HMENU)GRB_TGT, hi, NULL);
        g_hLbTgt = CreateWindowExW(WS_EX_CLIENTEDGE, L"LISTBOX", L"",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | LBS_NOTIFY | WS_VSCROLL | WS_DISABLED,
            396, 252, 340, 128, hwnd, (HMENU)LBC_TGT, hi, NULL);
        g_hBtnTgtAdd = CreateWindowW(L"BUTTON", L"Add",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON | WS_DISABLED,
            396, 404, 165, 30, hwnd, (HMENU)IDB_TGT_ADD, hi, NULL);
        g_hBtnTgtDel = CreateWindowW(L"BUTTON", L"Delete",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON | WS_DISABLED,
            571, 404, 165, 30, hwnd, (HMENU)IDB_TGT_DEL, hi, NULL);

        g_font = CreateFontW(-14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            DEFAULT_QUALITY, DEFAULT_PITCH, L"Segoe UI");
        HWND ctrls[] = { g_hLog, g_hBtnLoad, g_hBtnUnload, g_hGrpDbg, g_hLbDbg,
            g_hBtnDbgAdd, g_hBtnDbgDel, g_hGrpTgt, g_hLbTgt, g_hBtnTgtAdd, g_hBtnTgtDel };
        for (int i = 0; i < _countof(ctrls); i++)
            SendMessageW(ctrls[i], WM_SETFONT, (WPARAM)g_font, TRUE);

        UpdateControls();

        LogW(L"[*] Loading kernel symbols, please wait ...");
        g_hSymbolThread = CreateThread(NULL, 0, SymbolThread, NULL, 0, NULL);
        if (!g_hSymbolThread) {
            LogW(L"[!] Failed to create symbol loading thread: %lu", GetLastError());
            MessageBoxW(hwnd, L"Failed to create the symbol loading thread.",
                L"Startup failed", MB_ICONERROR);
            PostMessageW(hwnd, WM_CLOSE, 0, 0);
        }
        return 0;
    }
    case WM_APP_SYMBOLS_DONE: {
        if ((BOOL)wParam) {
            g_symbolsOk = TRUE;
            LogW(L"[+] Kernel symbols and offsets loaded");
        } else {
            LogW(L"[!] Kernel symbol/offset resolution failed");
            MessageBoxW(hwnd, L"Kernel symbol/offset resolution failed, see the log window for details.",
                L"PteDbg", MB_ICONERROR);
            PostMessageW(hwnd, WM_CLOSE, 0, 0);
        }
        UpdateControls();
        return 0;
    }
    case WM_COMMAND: {
        int id = LOWORD(wParam);
        switch (id) {
        case IDB_LOAD:    OnLoadDriver();  return 0;
        case IDB_UNLOAD:  OnUnloadDriver(); return 0;
        case IDB_DBG_ADD: OnAddDebugger();  return 0;
        case IDB_DBG_DEL: OnDelDebugger();  return 0;
        case IDB_TGT_ADD: OnAddDebuggee();  return 0;
        case IDB_TGT_DEL: OnDelDebuggee();  return 0;
        case LBC_DBG:
        case LBC_TGT:
            if (HIWORD(wParam) == LBN_SELCHANGE)
                UpdateControls();
            return 0;
        }
        break;
    }
    case WM_SIZE:
        Layout(LOWORD(lParam), HIWORD(lParam));
        return 0;
    case WM_GETMINMAXINFO: {
        MINMAXINFO* mmi = (MINMAXINFO*)lParam;
        mmi->ptMinTrackSize.x = 640;
        mmi->ptMinTrackSize.y = 480;
        return 0;
    }
    case WM_DESTROY:
        if (g_hSymbolThread) {
            InterlockedExchange(&g_closing, 1);
            CloseHandle(g_hSymbolThread);
            g_hSymbolThread = NULL;
        }
        if (g_loaded) {
            if (g_hDevice != INVALID_HANDLE_VALUE) {
                CloseHandle(g_hDevice);
                g_hDevice = INVALID_HANDLE_VALUE;
            }
            DriverUnload(LogLineCB);
            g_loaded = FALSE;
        }
        if (g_font) DeleteObject(g_font);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrev, PWSTR cmdline, int show)
{
    UNREFERENCED_PARAMETER(hPrev);
    UNREFERENCED_PARAMETER(cmdline);
    UNREFERENCED_PARAMETER(show);

    g_hInst = hInstance;

    WNDCLASSW wc = { 0 };
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"PteDbgMain";
    wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    RegisterClassW(&wc);

    HWND hwnd = CreateWindowExW(0, L"PteDbgMain", L"PTE ReloadDbg",
        WS_OVERLAPPEDWINDOW | WS_VISIBLE,
        CW_USEDEFAULT, CW_USEDEFAULT, 790, 560,
        NULL, NULL, hInstance, NULL);
    if (!hwnd)
        return 1;

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return (int)msg.wParam;
}
