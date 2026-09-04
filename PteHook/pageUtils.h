#pragma once
#include <stdint.h>
#include <intrin.h>
#include <ntifs.h>
#include "ia32.hpp"

typedef struct _PAGE_TABLE {
    uint64_t LineAddress;
    pte_64* PteAddress;
    pde_64* PdeAddress;
    pdpte_64* PdpteAddress;
    pml4e_64* Pml4eAddress;
} PAGE_TABLE;

uint64_t va_to_pa(uint64_t va);
uint64_t pa_to_va(uint64_t pa);
bool split_large_pages(pde_64* in_pde, pde_64* out_pde);

ULONG64 GetPml4Base();

// Walk the current page tables and fill in the PTE/PDE/PDPTE/PML4E addresses for table->LineAddress.
bool getPagesTable(PAGE_TABLE* table);

uint64_t get_pte_address_by_va(uint64_t va);
