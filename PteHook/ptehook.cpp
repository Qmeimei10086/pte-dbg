#include "ptehook.h"
#include "inline_hook.h"

void logger(const char* info, bool is_err, LONG err_code) {
	if (is_err) {
		DbgPrintEx(77, 0, "[PteHook] Error: %s, Code: %d\n", info, err_code);
	}
	else {
		DbgPrintEx(77, 0, "[PteHook] Info: %s\n", info);
	}
}

// CRITICAL FIX: isolation_pages now assumes the caller has already attached to
// the target process. It is only responsible for the page table isolation,
// not for the hook installation.
bool isolation_pages(HANDLE process_id, void* va, void** isolated_page_va) {
	UNREFERENCED_PARAMETER(process_id);

	NTSTATUS status = STATUS_SUCCESS;
	PHYSICAL_ADDRESS LowAddrPa{ 0 }, MaxAddrPa{ 0 };
	MaxAddrPa.QuadPart = MAXULONG64;
	void* replaceAlignAddr = PAGE_ALIGN(va);

	pdpte_64* fake_pdpt = nullptr;
	pde_64* fake_pdt = nullptr;
	pte_64* fake_pt = nullptr;
	unsigned char* fake_4kb_memory = nullptr;

	uint64_t pml4e_index, pdpte_index, pde_index, pte_index;
	PAGE_TABLE Table{ 0 };

	Table.LineAddress = (uint64_t)replaceAlignAddr;

	// FIX: no longer looks up and attaches the process, the caller did it.
	if (!getPagesTable(&Table)) {
		logger("Failed to get Page Table addresses! GetPml4Base likely returned -1.", true, 0);
		return false;
	}

	pml4e_index = ((uint64_t)replaceAlignAddr & 0x0000FF8000000000) >> 39;
	pdpte_index = ((uint64_t)replaceAlignAddr & 0x0000007FC0000000) >> 30;
	pde_index = ((uint64_t)replaceAlignAddr & 0x000000003FE00000) >> 21;
	pte_index = ((uint64_t)replaceAlignAddr & 0x00000000001FF000) >> 12;

	// allocate the page table memory
	fake_4kb_memory = (unsigned char*)MmAllocateContiguousMemorySpecifyCache(PAGE_SIZE, LowAddrPa, MaxAddrPa, LowAddrPa, MmCached);
	fake_pdt = (pde_64*)MmAllocateContiguousMemorySpecifyCache(PAGE_SIZE, LowAddrPa, MaxAddrPa, LowAddrPa, MmCached);
	fake_pdpt = (pdpte_64*)MmAllocateContiguousMemorySpecifyCache(PAGE_SIZE, LowAddrPa, MaxAddrPa, LowAddrPa, MmCached);

	if (!fake_4kb_memory || !fake_pdt || !fake_pdpt) {
		logger("Failed to allocate memory for fake page tables", true, STATUS_INSUFFICIENT_RESOURCES);
		if (fake_4kb_memory) MmFreeContiguousMemory(fake_4kb_memory);
		if (fake_pdt) MmFreeContiguousMemory(fake_pdt);
		if (fake_pdpt) MmFreeContiguousMemory(fake_pdpt);
		return false;
	}

	RtlZeroMemory(fake_4kb_memory, PAGE_SIZE);
	RtlZeroMemory(fake_pdt, PAGE_SIZE);
	RtlZeroMemory(fake_pdpt, PAGE_SIZE);

	// handle large page splitting
	pde_64 fake_pde_split_info = { 0 };

	if (Table.PdeAddress->large_page) {
		logger("Meet large page, splitting...", false, 0);
		if (!split_large_pages(Table.PdeAddress, &fake_pde_split_info)) {
			logger("Failed to split large page", true, 0);
			MmFreeContiguousMemory(fake_4kb_memory);
			MmFreeContiguousMemory(fake_pdt);
			MmFreeContiguousMemory(fake_pdpt);
			return false;
		}

		if (Table.PdeAddress->flags & 0x100) {
			Table.PdeAddress->flags &= ~0x100;
		}
		fake_pt = (pte_64*)pa_to_va((uint64_t)fake_pde_split_info.page_frame_number * PAGE_SIZE);
	}
	else {
		// small page: allocate and copy the existing PT
		fake_pt = (pte_64*)MmAllocateContiguousMemorySpecifyCache(PAGE_SIZE, LowAddrPa, MaxAddrPa, LowAddrPa, MmCached);
		if (!fake_pt) {
			logger("Failed to allocate PT", true, STATUS_INSUFFICIENT_RESOURCES);
			MmFreeContiguousMemory(fake_4kb_memory);
			MmFreeContiguousMemory(fake_pdt);
			MmFreeContiguousMemory(fake_pdpt);
			return false;
		}
		memcpy(fake_pt, Table.PteAddress - pte_index, PAGE_SIZE);
	}

	logger("Page table splitting/copying success", false, 0);

	// copy the data into the isolated memory pages
	memcpy(fake_4kb_memory, replaceAlignAddr, PAGE_SIZE);
	memcpy(fake_pdt, Table.PdeAddress - pde_index, PAGE_SIZE);
	memcpy(fake_pdpt, Table.PdpteAddress - pdpte_index, PAGE_SIZE);

	// make the target memory point to the isolated page
	fake_pt[pte_index].page_frame_number = va_to_pa((uint64_t)fake_4kb_memory) / PAGE_SIZE;

	// rebuild the chain
	fake_pdt[pde_index].page_frame_number = va_to_pa((uint64_t)fake_pt) / PAGE_SIZE;
	fake_pdt[pde_index].large_page = 0;
	fake_pdt[pde_index].ignored_1 = 0;
	fake_pdt[pde_index].page_level_cache_disable = 1;

	fake_pdpt[pdpte_index].page_frame_number = va_to_pa((uint64_t)fake_pdt) / PAGE_SIZE;

	// disable interrupts and modify CR3
	_disable();

	uint64_t cr3_pa = __readcr3() & 0xFFFFFFFFFFFFF000;
	pml4e_64* cr3_va = (pml4e_64*)pa_to_va(cr3_pa);
	cr3_va[pml4e_index].page_frame_number = va_to_pa((uint64_t)fake_pdpt) / PAGE_SIZE;

	DbgPrintEx(77, 0, "[PteHook] Page isolation complete for VA: %p\n", va);

	__writecr3(__readcr3());
	__invlpg(replaceAlignAddr);

	_enable();

	// FIX: does not call install_hook, the caller is responsible for it.
	// FIX: does not call KeUnstackDetachProcess, the caller is responsible.
	// FIX: does not call ObDereferenceObject, the caller is responsible.

	if (isolated_page_va)
		*isolated_page_va = fake_4kb_memory;

	// the fake pages stay allocated on purpose, see the original TODO:
	// fake_4kb_memory, fake_pdt, fake_pdpt, fake_pt
	return true;
}
