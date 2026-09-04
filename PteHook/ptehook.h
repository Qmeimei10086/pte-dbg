#pragma once
#include "pageUtils.h"

void logger(const char* info, bool is_err, LONG err_code);

// CRITICAL: the caller must already be attached to the target process
// (hook_manager does KeStackAttachProcess). isolation_pages only performs the
// page table isolation, the hook patching is done by the caller.
//
// isolated_page_va (optional) receives the system-wide virtual address of the
// isolated copy of the page, so the original bytes can be restored later
// without attaching (fulfills the TODO of the original ptehook code).
bool isolation_pages(HANDLE process_id, void* va, void** isolated_page_va);
