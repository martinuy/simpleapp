/*
 *   Martin Balao (martin.uy) - Copyright 2020, 2023
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/mm_types.h>
#include <linux/rmap.h>
#include <linux/syscalls.h>

#include "simplemodule_kernel_lib.h"

noinline void pre_syscall_trampoline_hook(unsigned long syscall_number,
        unsigned long syscall_args[]) {
    if (syscall_number == __NR_mmap) {
        //BREAKPOINT(1);
    }
}

noinline void post_syscall_trampoline_hook(unsigned long syscall_number,
        unsigned long syscall_args[], unsigned long return_value) {
    if (syscall_number == __NR_mmap) {
        //BREAKPOINT(2);
    }
}

unsigned long get_struct_page(unsigned long vaddr);
static void print_mem_zone(struct zone* zone);
static void print_node_zonelists(pg_data_t* pglist_data_ptr);

// References to headers
// struct page --> mm_types.h
// struct pglist_data -> mmzone.h
// Buddy allocator -> page_alloc.c
unsigned long show_memory_structures(void) {
    pgd_t* current_pgd_address;
    unsigned long cr3_value;
    unsigned int cpu = get_cpu();
    pg_data_t* pglist_data_ptr = NODE_DATA(cpu_to_node(cpu));
    // NODE_DATA is an access to the global pg_data_t* node_data[] array
    struct zone* zone_dma = &(pglist_data_ptr->node_zones[ZONE_DMA]);
    struct zone* zone_dma32 = &(pglist_data_ptr->node_zones[ZONE_DMA32]);
    struct zone* zone_normal = &(pglist_data_ptr->node_zones[ZONE_NORMAL]);
    struct zone* zone_movable = &(pglist_data_ptr->node_zones[ZONE_MOVABLE]);
    struct zone* zone_device = &(pglist_data_ptr->node_zones[ZONE_DEVICE]);
    struct page* p0 = pfn_to_page(0);
    struct page* p1 = pfn_to_page(1);
    struct page* pn = NULL;
    struct page* plast_m_1 = pfn_to_page(node_end_pfn(cpu_to_node(cpu))-2);
    struct page* plast = pfn_to_page(node_end_pfn(cpu_to_node(cpu))-1);
    char* m_kmalloc = NULL;
    GDB("print *(pg_data_t*)0x%px", pglist_data_ptr);
    pn = alloc_pages(GFP_KERNEL | __GFP_ZERO, 1); // Page allocation occurs in rmqueue (page_alloc.c)
    m_kmalloc = (char*)kmalloc(sizeof(char)*4, GFP_KERNEL);
    SM_PRINTF("\n");
    SM_PRINTF("===== MEMORY MAPPING =====\n");
    SM_PRINTF("Current CPU: %u\n", cpu);
    SM_PRINTF("PAGE_SIZE: %lu\n", PAGE_SIZE);
    SM_PRINTF("PAGE_OFFSET (mapped to phy 0x0): 0x%lx\n", PAGE_OFFSET);
    SM_PRINTF("TASK_SIZE: 0x%lx\n", TASK_SIZE);
    SM_PRINTF("node_end_pfn(node = 0): %lu\n", node_end_pfn(cpu_to_node(cpu)));
    SM_PRINTF("pglist_data_ptr (node %d): 0x%px\n", cpu_to_node(cpu), pglist_data_ptr);
    SM_PRINTF("pglist_data_ptr MAX_NR_ZONES %d\n", MAX_NR_ZONES);
    SM_PRINTF("pglist_data_ptr->nr_zones: %d\n", pglist_data_ptr->nr_zones);
    SM_PRINTF("pglist_data_ptr->node_start_pfn: 0x%lx\n", pglist_data_ptr->node_start_pfn);
    SM_PRINTF("pglist_data_ptr->node_present_pages: %lu\n", pglist_data_ptr->node_present_pages);
    SM_PRINTF("pglist_data_ptr->node_spanned_pages: %lu\n", pglist_data_ptr->node_spanned_pages);
    SM_PRINTF("pglist_data_ptr->totalreserve_pages: %lu\n", pglist_data_ptr->totalreserve_pages);
    SM_PRINTF("sizeof(struct page): 0x%lx\n", sizeof(struct page));
    SM_PRINTF("&vmemmap[0]: 0x%px\n", &vmemmap[0]);
    SM_PRINTF("&vmemmap[1]: 0x%px\n", &vmemmap[1]);
    if (pn) {
        SM_PRINTF("&vmemmap[n]: 0x%px\n", &vmemmap[page_to_pfn(pn)]);
    } else {
        SM_PRINTF("&vmemmap[n]: NULL\n");
    }
    SM_PRINTF("&vmemmap[last-1]: 0x%px\n", &vmemmap[node_end_pfn(cpu_to_node(cpu))-2]);
    SM_PRINTF("&vmemmap[last]: 0x%px\n", &vmemmap[node_end_pfn(cpu_to_node(cpu))-1]);
    SM_PRINTF("NR_SECTION_ROOTS: %lu\n", NR_SECTION_ROOTS);
    SM_PRINTF("SECTIONS_PER_ROOT: %lu\n", SECTIONS_PER_ROOT);
    SM_PRINTF("NR_MEM_SECTIONS (NR_SECTION_ROOTS * SECTIONS_PER_ROOT): %lu\n", NR_MEM_SECTIONS);
    SM_PRINTF("mem_section* &mem_section[0][0]: 0x%px\n", *mem_section);
    SM_PRINTF("__pfn_to_section(0): 0x%px\n", __pfn_to_section(0));
    SM_PRINTF("__pfn_to_section(0).section_mem_map: 0x%px\n", __section_mem_map_addr(__pfn_to_section(0)));
    SM_PRINTF("__pfn_to_section(1): 0x%px\n", __pfn_to_section(1));
    SM_PRINTF("__pfn_to_section(1).section_mem_map: 0x%px\n", __section_mem_map_addr(__pfn_to_section(1)));
    if (pn) {
        SM_PRINTF("__pfn_to_section(n): 0x%px\n", __pfn_to_section(page_to_pfn(pn)));
        SM_PRINTF("__pfn_to_section(n).section_mem_map: 0x%px\n", __section_mem_map_addr(__pfn_to_section(page_to_pfn(pn))));
    } else {
        SM_PRINTF("__pfn_to_section(n) = NULL\n");
    }
    SM_PRINTF("__pfn_to_section(last - 1): 0x%px\n", __pfn_to_section(node_end_pfn(cpu_to_node(cpu))-2));
    SM_PRINTF("__pfn_to_section(last - 1).section_mem_map: 0x%px\n", __section_mem_map_addr(__pfn_to_section(node_end_pfn(cpu_to_node(cpu))-2)));
    SM_PRINTF("__pfn_to_section(last): 0x%px\n", __pfn_to_section(node_end_pfn(cpu_to_node(cpu))-1));
    SM_PRINTF("__pfn_to_section(last).section_mem_map: 0x%px\n", __section_mem_map_addr(__pfn_to_section(node_end_pfn(cpu_to_node(cpu))-1)));
    SM_PRINTF("PAGE 0 -> struct page*: 0x%px\n", p0);
    SM_PRINTF("PAGE 0 -> virtual address: 0x%px\n", page_to_virt(p0));
    SM_PRINTF("PAGE 0 -> phys address: 0x%lx\n", __pa(page_to_virt(p0)));
    SM_PRINTF("PAGE 0 -> mem_section: 0x%px\n", __pfn_to_section(page_to_pfn(p0)));
    sm_print_memory("PAGE 0 (first bytes)", (char*)page_to_virt(p0), 16);
    SM_PRINTF("PAGE 1 -> struct page*: 0x%px\n", p1);
    SM_PRINTF("PAGE 1 -> virtual address: 0x%px\n", page_to_virt(p1));
    SM_PRINTF("PAGE 1 -> phys address: 0x%lx\n", __pa(page_to_virt(p1)));
    SM_PRINTF("PAGE 1 -> mem_section: 0x%px\n", __pfn_to_section(page_to_pfn(p1)));
    if (pn) {
        SM_PRINTF("PAGE N -> struct page*: 0x%px\n", pn);
        SM_PRINTF("PAGE N -> virtual address: 0x%px\n", page_to_virt(pn));
        SM_PRINTF("PAGE N -> phys address: 0x%lx\n", __pa(page_to_virt(pn)));
        SM_PRINTF("PAGE N -> mem_section: 0x%px\n", __pfn_to_section(page_to_pfn(pn)));
        SM_PRINTF("PAGE N -> mem_section[...][...].section_mem_map: 0x%px\n", __section_mem_map_addr(__pfn_to_section(page_to_pfn(pn))));
        SM_PRINTF("PAGE N -> mapping: 0x%px\n", pn->mapping);

    } else {
        SM_PRINTF("PAGE N = NULL\n");
    }
    SM_PRINTF("PAGE LAST - 1 -> struct page*: 0x%px\n", plast_m_1);
    SM_PRINTF("PAGE LAST - 1 -> virtual address: 0x%px\n", page_to_virt(plast_m_1));
    SM_PRINTF("PAGE LAST - 1 -> phys address: 0x%lx\n", __pa(page_to_virt(plast_m_1)));
    SM_PRINTF("PAGE LAST - 1 -> mem_section: 0x%px\n", __pfn_to_section(page_to_pfn(plast_m_1)));
    SM_PRINTF("PAGE LAST -> struct page*: 0x%px\n", plast);
    SM_PRINTF("PAGE LAST -> virtual address: 0x%px\n", page_to_virt(plast));
    SM_PRINTF("PAGE LAST -> phys address: 0x%lx\n", __pa(page_to_virt(plast)));
    SM_PRINTF("PAGE LAST -> mem_section: 0x%px\n", __pfn_to_section(page_to_pfn(plast)));
    SM_PRINTF("m_kmalloc: 0x%px\n", m_kmalloc);
    print_mem_zone(zone_dma);
    print_mem_zone(zone_dma32);
    print_mem_zone(zone_normal);
    print_mem_zone(zone_movable);
    print_mem_zone(zone_device);
    print_node_zonelists(pglist_data_ptr);

    current_pgd_address = current->mm->pgd;
    SM_PRINTF("current_pgd_address: 0x%px\n", current_pgd_address);
    cr3_value = read_cr3_pa();
    SM_PRINTF("%%cr3: 0x%px\n", (void*)cr3_value);
    //BREAKPOINT(1);
    //pgtable.h
    SM_PRINTF("pfn_pte(0): 0x%lx\n", pfn_pte(0, PAGE_READONLY).pte);
    SM_PRINTF("pte_page(pfn_pte(0)): 0x%px\n", pte_page(pfn_pte(0, PAGE_READONLY)));
    get_struct_page((unsigned long)(&vmemmap[0]));
    get_struct_page((unsigned long)(page_to_virt(p0)));

    //BREAKPOINT_SET("__alloc_pages_nodemask");
    //BREAKPOINT_SET("get_page_from_freelist");
    //BREAKPOINT_SET("__zone_watermark_ok");
    //GDB("break *(get_page_from_freelist+3195)"); // --> in rbp there is the struct page* page from page_alloc.c#L2193
    pn = alloc_pages(GFP_USER, 1);
    sm_print_memory("GFP_USER page", page_to_virt(pn), 32);
    //BREAKPOINT_UNSET("__zone_watermark_ok");
    //BREAKPOINT_UNSET("get_page_from_freelist");
    //BREAKPOINT_UNSET("__alloc_pages_nodemask");

    {
        struct vm_area_struct* vma_p = current->mm->mmap;
        while (vma_p != NULL) {
            SM_PRINTF("-----------------\n");
            SM_PRINTF("vma_p->vm_start: 0x%lx\n", vma_p->vm_start);
            if (vma_p->vm_file != NULL) {
                if (vma_p->vm_file->f_path.dentry != NULL) {
                    if (vma_p->vm_file->f_path.dentry->d_name.name != NULL) {
                        SM_PRINTF("File name: %s\n", vma_p->vm_file->f_path.dentry->d_name.name);
                    }
                }
                SM_PRINTF("vma_p->vm_pgoff: %lu\n", vma_p->vm_pgoff);
            }
            if (vma_p->anon_vma != NULL) {
                SM_PRINTF("vma_p->anon_vma->refcount: %d\n", vma_p->anon_vma->refcount.counter);
            }
            vma_p = vma_p->vm_next;
        }
    }
    SM_PRINTF("\n");

    if (pn) {
        __free_page(pn);
    }
    if (m_kmalloc) {
        kfree(m_kmalloc);
    }
    put_cpu();
    SM_LOG(MIN_VERBOSITY, "show_memory_structures - end\n");
    return 0x0UL;
}

unsigned long get_struct_page(unsigned long vaddr) {
    struct page* page;
    pgd_t* pgd;
    pud_t* pud;
    pmd_t* pmd;
    pte_t* pte;

    SM_PRINTF("------------------------------------------------------------------------------\n");
    SM_PRINTF("--- Mapping of a virtual address to a struct page* through the Page Tables ---\n");
    SM_PRINTF("------------------------------------------------------------------------------\n");
    SM_PRINTF("Virtual address: 0x%lx\n", vaddr);

    if (pgtable_l5_enabled()) {
        SM_PRINTF("Cannot handle 5 levels at the moment.\n");
        return 0UL;
    }

    pgd = pgd_offset(current->mm, vaddr);
    SM_PRINTF("PGD start (current->mm->pgd): 0x%px\n", current->mm->pgd);
    SM_PRINTF("PGD offset: 0x%lx\n", ((char*)pgd - (char*)current->mm->pgd));
    SM_PRINTF("PGD (entry's addr): 0x%px\n", pgd);
    SM_PRINTF("*PGD (entry's value): 0x%lx\n", pgd_val(*pgd));
    SM_PRINTF("*PGD (entry's next table value): 0x%lx\n", pgd_page_vaddr(*pgd));

    pud = pud_offset((p4d_t*)pgd, vaddr);
    SM_PRINTF("PUD start: 0x%lx\n", pgd_page_vaddr(*pgd));
    SM_PRINTF("PUD offset: 0x%px\n", ((char*)pud - pgd_page_vaddr(*pgd)));
    SM_PRINTF("PUD (entry's addr): 0x%px\n", pud);
    SM_PRINTF("*PUD (entry's value): 0x%lx\n", pud_val(*pud));
    SM_PRINTF("*PUD (entry's next table value): 0x%lx\n", pud_page_vaddr(*pud));

    if (pud_trans_huge(*pud)) {
        SM_PRINTF("PUD page IS transparent huge\n");
        page = pud_page(*pud);
    } else {
        SM_PRINTF("PUD page IS NOT transparent huge\n");
        pmd = pmd_offset(pud, vaddr);
        SM_PRINTF("PMD start: 0x%lx\n", pud_page_vaddr(*pud));
        SM_PRINTF("PMD offset: 0x%px\n", ((char*)pmd - pud_page_vaddr(*pud)));
        SM_PRINTF("PMD (entry's addr): 0x%px\n", pmd);
        SM_PRINTF("*PMD (entry's value): 0x%lx\n", pmd_val(*pmd));
        SM_PRINTF("*PMD (entry's next table value): 0x%lx\n", pmd_page_vaddr(*pmd));
        if (pmd_large(*pmd)) {
            SM_PRINTF("pmd_large: true\n");
        } else {
            SM_PRINTF("pmd_large: false\n");
        }
        if (pmd_trans_huge(*pmd)) {
            SM_PRINTF("PMD page IS transparent huge\n");
            page = pmd_page(*pmd);
        } else {
            SM_PRINTF("PMD page IS NOT transparent huge\n");
            pte = pte_offset_map(pmd, vaddr);
            SM_PRINTF("PTE start: 0x%lx\n", pmd_page_vaddr(*pmd));
            SM_PRINTF("PTE offset: 0x%px\n", ((char*)pte - pmd_page_vaddr(*pmd)));
            SM_PRINTF("PTE (entry's addr): 0x%px\n", pte);
            SM_PRINTF("*PTE (entry's value): 0x%lx\n", pte_val(*pte));
            if (pte_huge(*pte)) {
                SM_PRINTF("pte_huge: true\n");
            } else {
                SM_PRINTF("pte_huge: false\n");
            }
            if (pte_global(*pte)) {
                SM_PRINTF("pte_global: true\n");
            } else {
                SM_PRINTF("pte_global: false\n");
            }
            page = pte_page(*pte);
        }
    }

    SM_PRINTF("Page's virtual address (direct mapping): 0x%px\n", page_to_virt(page));
    SM_PRINTF("Page's physical address: 0x%lx\n", __pa(page_to_virt(page)));
    SM_PRINTF("Page's frame number (PFN): %lu\n", page_to_pfn(page));
    SM_PRINTF("Page's mem_section: 0x%px\n", __pfn_to_section(page_to_pfn(page)));
    GDB("print \"Virt1\"");
    GDB("print 0x%px", (void*)page_to_virt(page));
    GDB("print \"Virt2\"");
    GDB("print 0x%px", (void*)vaddr);
    if (PageTransHuge(page)) {
        SM_PRINTF("Page IS transparent huge\n");
    } else {
        SM_PRINTF("Page IS NOT transparent huge\n");
    }
    return (unsigned long)page;
}

static void print_mem_zone(struct zone* zone) {
    // mmzone.h
    SM_PRINTF("--- ZONE %s ---\n", zone->name);
    SM_PRINTF("zone: 0x%px\n", zone);
    SM_PRINTF("node: %d\n", zone->node);
    SM_PRINTF("zone_start_pfn: %lu\n", zone->zone_start_pfn);
    SM_PRINTF("spanned_pages: %lu\n", zone->spanned_pages);
    SM_PRINTF("present_pages: %lu\n", zone->present_pages);
    SM_PRINTF("---\n");
}

static void print_node_zonelists(pg_data_t* pglist_data_ptr) {
    // mmzone.h
    int i;
    struct zonelist* zl;
    SM_PRINTF("---  ZONELIST ZONELIST_FALLBACK for node %d ---\n", pglist_data_ptr->node_id);
    zl = &(pglist_data_ptr->node_zonelists[ZONELIST_FALLBACK]);
    for (i = 0; i <= MAX_ZONES_PER_ZONELIST; i++) {
        struct zoneref* zr = &(zl->_zonerefs[i]);
        struct zone* z = zr->zone;
        if (z != NULL) {
            SM_PRINTF("zone: %s\n", z->name);
            SM_PRINTF("zone's node: %d\n", z->node);
            SM_PRINTF("zone_idx: %d\n", zr->zone_idx);
            SM_PRINTF("...\n");
        }
    }
    SM_PRINTF("---\n");
}
