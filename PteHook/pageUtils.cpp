#include "pageUtils.h"

uint64_t va_to_pa(uint64_t va) {

	return MmGetPhysicalAddress((PVOID)va).QuadPart;
}

uint64_t pa_to_va(uint64_t pa) {
	PHYSICAL_ADDRESS phyAddr;
	phyAddr.QuadPart = pa;
	return (uint64_t)MmGetVirtualForPhysical(phyAddr);
}

// Locate the self-referencing PML4 entry in the current CR3 and derive the
// recursive mapping base (0xFFFF000000000000 | index << 39).
ULONG64 GetPml4Base()
{
    cr3 cr3_pa{ 0 };
    cr3_pa.flags = __readcr3();
    pml4e_64* cr3_va = nullptr;

    cr3_va = (pml4e_64*)pa_to_va(cr3_pa.address_of_page_directory * PAGE_SIZE);

    if (!cr3_va) {
        DbgPrintEx(77, 0, "[PteHook] GetPml4Base Error: Failed to get valid CR3 VA.\n");
        return -1;
    }

    for (uint64_t i = 0; i < 512; i++) {
        // Self-reference entry: the PML4E whose PFN maps the page directory itself.
        if (cr3_va[i].page_frame_number == cr3_pa.address_of_page_directory) {
            // Recover the real recursive mapping base from the entry index.
            ULONG64 pml4_base = (0xFFFF000000000000ull | (i << 39));
            DbgPrintEx(77, 0, "[PteHook] GetPml4Base Success: Found self-reference at index %llu, PML4_BASE=0x%llx\n",
                i, pml4_base);
            return pml4_base;
        }
    }

    DbgPrintEx(77, 0, "[PteHook] GetPml4Base Error: Failed to find self-reference entry (checked 512 items).\n");
    return -1;
}

// Return the PTE virtual address for a given VA via the recursive mapping.
uint64_t get_pte_address_by_va(uint64_t va) {
    ULONG64 PML4_VirtualBase = GetPml4Base();
    if (PML4_VirtualBase == (ULONG64)-1) {
        return 0; // failed
    }

    // Extract the self-reference index from PML4_VirtualBase.
    uint64_t i = (PML4_VirtualBase >> 39) & 0x1FF;

    // Derive PTE_BASE from the self-reference index.
    uint64_t PTE_BASE = 0xFFFF000000000000ull | (i << 39);

    // Keep the low 36 bits of the page number, multiply by the entry size.
    uint64_t offset = ((va >> 12) & 0xFFFFFFFFF) * 8;
    return PTE_BASE + offset;
}

// Fill the PAGE_TABLE structure with all paging-structure addresses of the current process.
bool getPagesTable(PAGE_TABLE* table) {
    if (!table || !table->LineAddress) return false;

    uint64_t va = table->LineAddress;
    DbgPrintEx(77, 0, "[PteHook] getPagesTable: Parsing for target VA=0x%llx\n", va);

    // 1. Get the recursive mapping base.
    ULONG64 PML4_VirtualBase = GetPml4Base();
    if (PML4_VirtualBase == (ULONG64)-1) {
        return false;
    }

    // 2. Extract the self-reference index `i`
    //    since PML4_VirtualBase = 0xFFFF000000000000 | (i << 39).
    uint64_t i = (PML4_VirtualBase >> 39) & 0x1FF;

    // 3. Build every level base with the recursive mapping formula.
    uint64_t PTE_BASE = PML4_VirtualBase;                  // i << 39
    uint64_t PDE_BASE = PTE_BASE | (i << 30);              // i << 39 | i << 30
    uint64_t PDPTE_BASE = PDE_BASE | (i << 21);            // i << 39 | i << 30 | i << 21
    uint64_t PML4_BASE = PDPTE_BASE | (i << 12);           // i << 39 | i << 30 | i << 21 | i << 12

    DbgPrintEx(77, 0, "[PteHook] Bases: \n -> PTE_BASE=0x%llx\n -> PDE_BASE=0x%llx\n -> PDPTE_BASE=0x%llx\n -> PML4_BASE=0x%llx\n",
        PTE_BASE, PDE_BASE, PDPTE_BASE, PML4_BASE);

    // 4. Compute per-level entries (mask the low 36 bits, multiply by entry size).
    table->PteAddress = (pte_64*)(PTE_BASE + ((va >> 12) & 0xFFFFFFFFF) * 8);
    table->PdeAddress = (pde_64*)(PDE_BASE + ((va >> 21) & 0x7FFFFFF) * 8);
    table->PdpteAddress = (pdpte_64*)(PDPTE_BASE + ((va >> 30) & 0x3FFFF) * 8);
    table->Pml4eAddress = (pml4e_64*)(PML4_BASE + ((va >> 39) & 0x1FF) * 8);

    DbgPrintEx(77, 0, "[PteHook] getPagesTable Result:\n --> PTE_Addr=0x%p\n --> PDE_Addr=0x%p\n --> PDPTE_Addr=0x%p\n --> PML4E_Addr=0x%p\n",
        table->PteAddress, table->PdeAddress, table->PdpteAddress, table->Pml4eAddress);

    return true;
}

// Split a 2MB large page into a 4KB page table that preserves the original mapping.
bool split_large_pages(pde_64* in_pde, pde_64* out_pde) {

    PHYSICAL_ADDRESS MaxADDRPa{ 0 }, LowADDRPa{ 0 };
    MaxADDRPa.QuadPart = MAXULONG64;
    LowADDRPa.QuadPart = 0;
    pt_entry_64* Pt;

    // Clear the low 9 bits (PAT + reserved) of the 2MB PFN before using it as
    // the base frame, otherwise a misaligned start address is produced.
    auto start_pfn = in_pde->page_frame_number & ~0x1FFull;

    Pt = (pt_entry_64*)MmAllocateContiguousMemorySpecifyCache(PAGE_SIZE, LowADDRPa, MaxADDRPa, LowADDRPa, MmCached);

    if (!Pt) {
        DbgPrintEx(77, 0, "[PteHook] split_large_pages Error: Failed to allocate memory for new PT.\n");
        return false;
    }

    for (int i = 0; i < 512; i++) {
        // Inherit all flags from the large page PDE.
        Pt[i].flags = in_pde->flags;
        // Clear the global bit.
        Pt[i].global = 0;
        // Clear the large-page bit (this becomes a plain 4KB PTE; the bit also
        // acts as the PAT bit on PTE level, forcing 0 keeps standard WriteBack).
        Pt[i].large_page = 0;

        // Each 4KB page in sequence covers the original 2MB range.
        Pt[i].page_frame_number = start_pfn + i;
    }

    out_pde->flags = in_pde->flags;
    out_pde->large_page = 0;
    out_pde->page_frame_number = va_to_pa((uint64_t)Pt) / PAGE_SIZE;

    return true;
}
