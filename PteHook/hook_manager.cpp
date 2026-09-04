#include "hook_manager.h"
#include "inline_hook.h"
#include "hde64.h"
#include "ptehook.h"

#define TRAMPOLINE_POOL_SIZE (PAGE_SIZE * 4)

NTSTATUS hook_manager_init(HOOK_MANAGER* manager) {
    if (!manager) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(manager, sizeof(HOOK_MANAGER));
    KeInitializeSpinLock(&manager->lock);

    manager->trampoline_pool = (unsigned char*)ExAllocatePoolWithTag(
        NonPagedPoolExecute,
        TRAMPOLINE_POOL_SIZE,
        'pmrT'
    );

    if (!manager->trampoline_pool) {
        DbgPrintEx(77, 0, "[HookManager] Failed to allocate trampoline pool\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    manager->trampoline_used = 0;

    for (int i = 0; i < MAX_HOOK_COUNT; i++) {
        manager->hooks[i].in_use = false;
    }

    DbgPrintEx(77, 0, "[HookManager] Initialized successfully\n");
    return STATUS_SUCCESS;
}

void hook_manager_destroy(HOOK_MANAGER* manager) {
    if (!manager) {
        return;
    }

    hook_manager_uninstall_all(manager);

    if (manager->trampoline_pool) {
        ExFreePoolWithTag(manager->trampoline_pool, 'pmrT');
        manager->trampoline_pool = NULL;
    }

    DbgPrintEx(77, 0, "[HookManager] Destroyed\n");
}

bool hook_manager_install_hook(
    HOOK_MANAGER* manager,
    HANDLE pid,
    void** original_func,
    void* target_func,
    void** isolated_page_va
) {
    KIRQL old_irql;
    int free_slot;
    unsigned char* trampoline;
    PEPROCESS target_process;
    KAPC_STATE apc;
    NTSTATUS lookup_status;
    char* func_start;
    const uint32_t min_bytes = 14;
    uint32_t total_bytes;
    hde64s hde;
    unsigned char saved_bytes[32];
    unsigned char trampoline_tail[20];
    uint64_t return_addr;
    unsigned char absolute_jmp[14];
    KIRQL wp_irql;
    const unsigned char trampoline_template[20] = {
        0x6A, 0x00, 0x3E, 0xC7, 0x04, 0x24, 0x00, 0x00, 0x00, 0x00,
        0x3E, 0xC7, 0x44, 0x24, 0x04, 0x00, 0x00, 0x00, 0x00, 0xC3
    };
    const unsigned char jump_template[14] = {
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    if (isolated_page_va)
        *isolated_page_va = NULL;

    RtlZeroMemory(saved_bytes, sizeof(saved_bytes));
    RtlZeroMemory(trampoline_tail, sizeof(trampoline_tail));
    RtlZeroMemory(absolute_jmp, sizeof(absolute_jmp));
    free_slot = -1;
    trampoline = NULL;
    target_process = NULL;
    total_bytes = 0;

    if (!manager || !original_func || !*original_func || !target_func) {
        DbgPrintEx(77, 0, "[HookManager] Invalid parameters\n");
        return false;
    }

    KeAcquireSpinLock(&manager->lock, &old_irql);

    // Defense in depth: never hook the same function twice in one process. A
    // second hook would save the jump patch as "original bytes", making the
    // trampoline re-enter the replacement function forever.
    for (int i = 0; i < MAX_HOOK_COUNT; i++) {
        if (manager->hooks[i].in_use &&
            manager->hooks[i].pid == pid &&
            manager->hooks[i].original_func_ptr == *original_func) {
            KeReleaseSpinLock(&manager->lock, old_irql);
            DbgPrintEx(77, 0, "[HookManager] Function already hooked for this pid\n");
            return false;
        }
    }

    for (int i = 0; i < MAX_HOOK_COUNT; i++) {
        if (!manager->hooks[i].in_use) {
            free_slot = i;
            break;
        }
    }

    if (free_slot == -1) {
        KeReleaseSpinLock(&manager->lock, old_irql);
        DbgPrintEx(77, 0, "[HookManager] No free hook slots\n");
        return false;
    }

    if (manager->trampoline_used + 64 > TRAMPOLINE_POOL_SIZE) {
        KeReleaseSpinLock(&manager->lock, old_irql);
        DbgPrintEx(77, 0, "[HookManager] Trampoline pool exhausted\n");
        return false;
    }

    manager->hooks[free_slot].in_use = true;
    trampoline = manager->trampoline_pool + manager->trampoline_used;

    KeReleaseSpinLock(&manager->lock, old_irql);

    lookup_status = PsLookupProcessByProcessId(pid, &target_process);
    if (!NT_SUCCESS(lookup_status)) {
        DbgPrintEx(77, 0, "[HookManager] Failed to lookup process: 0x%X\n", lookup_status);

        KeAcquireSpinLock(&manager->lock, &old_irql);
        manager->hooks[free_slot].in_use = false;
        KeReleaseSpinLock(&manager->lock, old_irql);
        return false;
    }

    // All further work happens in the target process context so the private
    // page hierarchy is built inside the page tables of that process.
    KeStackAttachProcess(target_process, &apc);

    func_start = (char*)*original_func;

    // Disassemble the prologue until it can be overwritten by the 14-byte
    // absolute jump without cutting an instruction in half.
    while (total_bytes < min_bytes && total_bytes < sizeof(saved_bytes)) {
        uint32_t len = hde64_disasm(func_start + total_bytes, &hde);
        if (len == 0) {
            KeUnstackDetachProcess(&apc);
            ObDereferenceObject(target_process);

            KeAcquireSpinLock(&manager->lock, &old_irql);
            manager->hooks[free_slot].in_use = false;
            KeReleaseSpinLock(&manager->lock, old_irql);

            DbgPrintEx(77, 0, "[HookManager] Disassembly failed\n");
            return false;
        }
        total_bytes += len;
    }

    RtlCopyMemory(saved_bytes, func_start, total_bytes);

    if (!::isolation_pages(pid, *original_func, isolated_page_va)) {
        KeUnstackDetachProcess(&apc);
        ObDereferenceObject(target_process);

        KeAcquireSpinLock(&manager->lock, &old_irql);
        manager->hooks[free_slot].in_use = false;
        KeReleaseSpinLock(&manager->lock, old_irql);

        DbgPrintEx(77, 0, "[HookManager] Page isolation failed\n");
        return false;
    }

    // Trampoline: original prologue bytes + stack marker + jump back to
    // func_start + total_bytes (inside the isolated page).
    RtlCopyMemory(trampoline_tail, trampoline_template, sizeof(trampoline_tail));

    return_addr = (uint64_t)func_start + total_bytes;
    *(uint32_t*)(&trampoline_tail[6]) = (uint32_t)(return_addr & 0xFFFFFFFF);
    *(uint32_t*)(&trampoline_tail[15]) = (uint32_t)(return_addr >> 32);

    RtlCopyMemory(trampoline, saved_bytes, total_bytes);
    RtlCopyMemory(trampoline + total_bytes, trampoline_tail, sizeof(trampoline_tail));

    // Build the absolute jump to the replacement function. After isolation the
    // write through func_start lands in the private page copy, the real kernel
    // page stays untouched.
    RtlCopyMemory(absolute_jmp, jump_template, sizeof(absolute_jmp));
    *(uint64_t*)(&absolute_jmp[6]) = (uint64_t)target_func;

    wp_irql = wp_bit_off();
    RtlCopyMemory(func_start, absolute_jmp, 14);
    wp_bit_on(wp_irql);

    // Record the hook entry.
    KeAcquireSpinLock(&manager->lock, &old_irql);

    manager->hooks[free_slot].pid = pid;
    manager->hooks[free_slot].original_func_ptr = func_start;
    manager->hooks[free_slot].target_func_ptr = target_func;
    manager->hooks[free_slot].trampoline_ptr = trampoline;
    manager->hooks[free_slot].isolated_page_va = isolated_page_va ? *isolated_page_va : NULL;
    manager->hooks[free_slot].page_offset = (ULONG)((uint64_t)func_start & 0xFFF);
    manager->hooks[free_slot].original_bytes_len = total_bytes;
    RtlCopyMemory(manager->hooks[free_slot].original_bytes, saved_bytes, total_bytes);

    manager->trampoline_used += total_bytes + sizeof(trampoline_tail);

    KeReleaseSpinLock(&manager->lock, old_irql);

    *original_func = trampoline;

    KeUnstackDetachProcess(&apc);
    ObDereferenceObject(target_process);

    DbgPrintEx(77, 0, "[HookManager] Hook installed: PID=%llu, Orig=%p, Target=%p, Trampoline=%p\n",
        (uint64_t)pid, func_start, target_func, trampoline);

    return true;
}

bool hook_manager_uninstall_hook(
    HOOK_MANAGER* manager,
    HANDLE pid,
    void* original_func
) {
    if (!manager || !original_func) {
        return false;
    }

    KIRQL old_irql;
    KeAcquireSpinLock(&manager->lock, &old_irql);

    int hook_index = -1;
    for (int i = 0; i < MAX_HOOK_COUNT; i++) {
        if (manager->hooks[i].in_use &&
            manager->hooks[i].pid == pid &&
            manager->hooks[i].original_func_ptr == original_func) {
            hook_index = i;
            break;
        }
    }

    if (hook_index == -1) {
        KeReleaseSpinLock(&manager->lock, old_irql);
        DbgPrintEx(77, 0, "[HookManager] Hook not found for unhook\n");
        return false;
    }

    HOOK_ENTRY entry_copy = manager->hooks[hook_index];

    KeReleaseSpinLock(&manager->lock, old_irql);

    // Restore the original bytes inside the private page copy. This is safe
    // from any process context because the private pages are contiguous
    // allocations with a system-wide virtual address.
    if (entry_copy.isolated_page_va && entry_copy.original_bytes_len) {
        KIRQL wp_irql = wp_bit_off();
        RtlCopyMemory(
            (unsigned char*)entry_copy.isolated_page_va + entry_copy.page_offset,
            entry_copy.original_bytes,
            entry_copy.original_bytes_len
        );
        wp_bit_on(wp_irql);
    }

    KeAcquireSpinLock(&manager->lock, &old_irql);
    RtlZeroMemory(&manager->hooks[hook_index], sizeof(HOOK_ENTRY));
    manager->hooks[hook_index].in_use = false;
    KeReleaseSpinLock(&manager->lock, old_irql);

    DbgPrintEx(77, 0, "[HookManager] Hook uninstalled: PID=%llu, Orig=%p\n",
        (uint64_t)entry_copy.pid, entry_copy.original_func_ptr);

    return true;
}

void hook_manager_uninstall_pid(HOOK_MANAGER* manager, HANDLE pid) {
    if (!manager) {
        return;
    }

    DbgPrintEx(77, 0, "[HookManager] Uninstalling hooks for pid %llu...\n", (uint64_t)pid);

    // Restore the original bytes inside every isolated page of this pid. The
    // real kernel pages were never modified, so this alone deactivates the
    // hooks. The isolated pages are contiguous allocations with a system-wide
    // virtual address, so no KeStackAttachProcess is needed and the restore
    // also works when the process is already gone.
    //
    // Like the original ptehook, the isolated pages and the rewired PML4E are
    // kept as-is: processes that inherited the private hierarchy keep a valid
    // mapping, and the restored bytes make it functionally identical to the
    // original mapping.
    for (int i = 0; i < MAX_HOOK_COUNT; i++) {
        KIRQL old_irql;
        KeAcquireSpinLock(&manager->lock, &old_irql);

        if (!manager->hooks[i].in_use || manager->hooks[i].pid != pid) {
            KeReleaseSpinLock(&manager->lock, old_irql);
            continue;
        }

        HOOK_ENTRY entry_copy = manager->hooks[i];
        KeReleaseSpinLock(&manager->lock, old_irql);

        if (entry_copy.isolated_page_va && entry_copy.original_bytes_len) {
            KIRQL wp_irql = wp_bit_off();
            RtlCopyMemory(
                (unsigned char*)entry_copy.isolated_page_va + entry_copy.page_offset,
                entry_copy.original_bytes,
                entry_copy.original_bytes_len
            );
            wp_bit_on(wp_irql);

            DbgPrintEx(77, 0, "[HookManager] Unhooked: PID=%llu, Orig=%p\n",
                (uint64_t)entry_copy.pid, entry_copy.original_func_ptr);
        }

        KeAcquireSpinLock(&manager->lock, &old_irql);
        RtlZeroMemory(&manager->hooks[i], sizeof(HOOK_ENTRY));
        manager->hooks[i].in_use = false;
        KeReleaseSpinLock(&manager->lock, old_irql);
    }
}

void hook_manager_uninstall_all(HOOK_MANAGER* manager) {
    if (!manager) {
        return;
    }

    DbgPrintEx(77, 0, "[HookManager] Uninstalling all hooks...\n");

    // Restore the original bytes inside every isolated page. The real kernel
    // pages were never modified, so this alone deactivates all hooks.
    for (int i = 0; i < MAX_HOOK_COUNT; i++) {
        KIRQL old_irql;
        KeAcquireSpinLock(&manager->lock, &old_irql);

        if (!manager->hooks[i].in_use) {
            KeReleaseSpinLock(&manager->lock, old_irql);
            continue;
        }

        HOOK_ENTRY entry_copy = manager->hooks[i];
        KeReleaseSpinLock(&manager->lock, old_irql);

        if (entry_copy.isolated_page_va && entry_copy.original_bytes_len) {
            KIRQL wp_irql = wp_bit_off();
            RtlCopyMemory(
                (unsigned char*)entry_copy.isolated_page_va + entry_copy.page_offset,
                entry_copy.original_bytes,
                entry_copy.original_bytes_len
            );
            wp_bit_on(wp_irql);

            DbgPrintEx(77, 0, "[HookManager] Unhooked: PID=%llu, Orig=%p\n",
                (uint64_t)entry_copy.pid, entry_copy.original_func_ptr);
        }

        KeAcquireSpinLock(&manager->lock, &old_irql);
        RtlZeroMemory(&manager->hooks[i], sizeof(HOOK_ENTRY));
        manager->hooks[i].in_use = false;
        KeReleaseSpinLock(&manager->lock, old_irql);
    }

    DbgPrintEx(77, 0, "[HookManager] All hooks uninstalled\n");
}
