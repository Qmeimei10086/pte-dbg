#pragma once
#include <ntifs.h>
#include <ntddk.h>

#define MAX_HOOK_COUNT 128

typedef struct _HOOK_ENTRY {
    HANDLE pid;
    void* original_func_ptr;        // real kernel address of the hooked function
    void* target_func_ptr;          // replacement function
    void* trampoline_ptr;           // saved original bytes + jump back
    void* isolated_page_va;         // system-wide VA of the private copy of the page
    ULONG page_offset;              // offset of original_func_ptr inside the page
    unsigned char original_bytes[32];
    size_t original_bytes_len;
    bool in_use;
} HOOK_ENTRY;

typedef struct _HOOK_MANAGER {
    HOOK_ENTRY hooks[MAX_HOOK_COUNT];
    unsigned char* trampoline_pool;
    size_t trampoline_used;
    KSPIN_LOCK lock;
} HOOK_MANAGER;

NTSTATUS hook_manager_init(HOOK_MANAGER* manager);
void hook_manager_destroy(HOOK_MANAGER* manager);

// original_func is in/out: input = real function address, output = trampoline.
// isolated_page_va (optional) receives the system-wide VA of the private page
// that now backs the function, see isolation_pages().
bool hook_manager_install_hook(
    HOOK_MANAGER* manager,
    HANDLE pid,
    void** original_func,
    void* target_func,
    void** isolated_page_va
);

// Restores the original bytes of a single hook (the private hierarchy stays
// active until hook_manager_uninstall_all / hook_manager_destroy).
bool hook_manager_uninstall_hook(
    HOOK_MANAGER* manager,
    HANDLE pid,
    void* original_func
);

// Restores the original bytes of every hook installed for one pid.
void hook_manager_uninstall_pid(HOOK_MANAGER* manager, HANDLE pid);

// Restores the original bytes of every hook and frees the manager.
void hook_manager_uninstall_all(HOOK_MANAGER* manager);
