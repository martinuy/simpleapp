/*
 *   Martin Balao (martin.uy) - Copyright 2020, 2022
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

#include <asm/syscall.h>

#include <linux/cdev.h>
#include <linux/err.h>
#include <linux/kprobes.h>
#include <linux/mm_types.h>
#include <linux/mutex.h>
#include <linux/rmap.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/unistd.h>
#include <linux/version.h>

#include "simplemodule.h"

#include "__priv_simplemodule.h"

/////////////////////
//     Defines     //
/////////////////////
#define SM_PRINTF(fmt,...) __SM_PRINTF("SimpleModule (PID: %d): " fmt, \
        current->pid __VA_OPT__(,) __VA_ARGS__)
#define __SM_PRINTF(fmt,...) \
 do { \
     int bytes_required = 0; \
     output_t* out = NULL,* out_it = NULL; \
     bytes_required = snprintf(NULL, 0, fmt __VA_OPT__(,) __VA_ARGS__); \
     mutex_lock(&outputs_lock); \
     list_for_each_entry(out_it, &outputs, list) { \
         if (out_it->pid == current->pid) { \
             out = out_it; \
             break; \
         } \
     } \
     if (out == NULL) { \
         out = (output_t*)kmalloc(sizeof(output_t), GFP_KERNEL); \
         out->pid = current->pid; \
         out->output_buffer_size = sizeof(char) * (bytes_required + 1); \
         out->output_buffer = kmalloc(out->output_buffer_size, GFP_KERNEL); \
         snprintf(out->output_buffer, out->output_buffer_size, fmt __VA_OPT__(,) __VA_ARGS__); \
         GDB("echo %s", out->output_buffer); \
         INIT_LIST_HEAD(&out->list); \
         list_add(&out->list, &outputs); \
     } else { \
         out->output_buffer = krealloc(out->output_buffer, \
                 out->output_buffer_size + (sizeof(char) * bytes_required), GFP_KERNEL); \
         snprintf(out->output_buffer + (out->output_buffer_size - 1), \
                 sizeof(char) * (bytes_required + 1), fmt __VA_OPT__(,) __VA_ARGS__); \
         GDB("echo %s", (out->output_buffer + out->output_buffer_size - 1)); \
         out->output_buffer_size += (sizeof(char) * bytes_required); \
     } \
     mutex_unlock(&outputs_lock); \
 } while(0)

#define SM_LOG(level, args...) \
 do { \
     if (LOG_VERBOSITY >= level) \
         SM_PRINTF(args); \
 } while(0)

#define BREAKPOINT(NUM) sm_debug(NUM)

#define BREAKPOINT_SET(SYM) sm_breakpoint_set(SYM)

#define BREAKPOINT_UNSET(SYM) sm_breakpoint_unset(SYM)

#define GDB(cmd, ...) \
 do { \
    char* gdb_cmd = NULL; \
    int bytes_required = 0; \
    bytes_required = snprintf(NULL, 0, cmd __VA_OPT__(,) __VA_ARGS__) + 1; \
    gdb_cmd = kmalloc(bytes_required, GFP_KERNEL); \
    if (gdb_cmd != NULL) { \
        snprintf(gdb_cmd, bytes_required, cmd __VA_OPT__(,) __VA_ARGS__); \
        sm_gdb(gdb_cmd); \
        kfree(gdb_cmd); \
    } \
 } while(0)

typedef struct output {
     pid_t pid;
     char* output_buffer;
     unsigned long output_buffer_size;
     struct list_head list;
} output_t;

/////////////////////////
// Function prototypes //
/////////////////////////
extern long run_module_asm(void);
static long run_module_code(void);
static void navigate_page_tables(unsigned long vaddr);
static void print_mem_zone(struct zone* zone);
static void print_node_zonelists(pg_data_t* pglist_data_ptr);
extern void sm_debug(int num);
extern void sm_breakpoint_set(const char* sym);
extern void sm_breakpoint_unset(const char* sym);
extern void sm_gdb(const char* cmd);

static unsigned long sm_lookup_name(const char* sym);
static long unlocked_ioctl(struct file* f, unsigned int cmd, unsigned long arg);
static long run_module_test(unsigned long arg);
static const char* get_syscall_name(unsigned long sys_code);

///////////////////////
// Global variables  //
///////////////////////
static dev_t simplemodule_devt = (dev_t)-1;
static struct cdev simplemodule_cdev;
static struct class* simplemodule_class = NULL;
static struct device* simplemodule_device = NULL;
static const struct file_operations fops = {
    .unlocked_ioctl = unlocked_ioctl,
    .owner = THIS_MODULE,
};
static sys_call_ptr_t* sys_call_table_ptr;

// Output
static DEFINE_MUTEX(outputs_lock);
static struct list_head outputs = LIST_HEAD_INIT(outputs);

/////////////////////
//    Functions    //
/////////////////////
__attribute__((used, optimize("O0")))
noinline void sm_debug(int num) {
}

__attribute__((used, optimize("O0")))
noinline void sm_breakpoint_set(const char* sym) {
}

__attribute__((used, optimize("O0")))
noinline void sm_breakpoint_unset(const char* sym) {
}

__attribute__((used, optimize("O0")))
noinline void sm_gdb(const char* cmd) {
}

static long unlocked_ioctl(struct file* f, unsigned int cmd, unsigned long arg) {
    long ret_val = SAMODULE_ERROR;
    switch(cmd) {
    case SAMODULE_IOCTL_TEST:
        if ((ret_val = run_module_test(arg)) == SAMODULE_ERROR)
            goto cleanup;
        break;
    case SAMODULE_IOCTL_OUTPUT_SIZE:
        {
            output_t* out = NULL,* out_it = NULL;
            mutex_lock(&outputs_lock);
            list_for_each_entry(out_it, &outputs, list) {
                if (out_it->pid == current->pid) {
                    out = out_it;
                    break;
                }
            }
            if (out == NULL)
                ret_val = 0L;
            else
                ret_val = (long)out->output_buffer_size;

            mutex_unlock(&outputs_lock);
        }
        break;
    case SAMODULE_IOCTL_OUTPUT_FLUSH:
        {
            output_t* out = NULL,* out_it = NULL;
            mutex_lock(&outputs_lock);
            list_for_each_entry(out_it, &outputs, list) {
                if (out_it->pid == current->pid) {
                    out = out_it;
                    break;
                }
            }
            if (out != NULL) {
                if (copy_to_user((void*)arg, out->output_buffer,
                        out->output_buffer_size) == 0) {
                    ret_val = SAMODULE_SUCCESS;
                    kfree(out->output_buffer);
                    list_del_init(&out->list);
                    kfree(out);
                }
            }
            mutex_unlock(&outputs_lock);
        }
        break;
    }

cleanup:
    return ret_val;
}

__attribute__((used))
static void print_mem_area(const char* name, void* s, size_t l) {
    size_t i = 0;
    SM_PRINTF("%s:\n", name);
    for (; i < l; i++) {
        if (i % 8 == 0 && i % 16 != 0)
            __SM_PRINTF("  ");

        if (i > 0 && i % 16 == 0)
            __SM_PRINTF("\n");

        if (i == 0 || (i % 16 == 0 && i + 1 < l))
            SM_PRINTF("");

        __SM_PRINTF("%02x ", (*((unsigned char*)s + i)) & 0xFF);
    }
    __SM_PRINTF("\n");
}

static long run_module_test(unsigned long arg) {
    long ret_val = SAMODULE_ERROR;
    module_test_data_t d;
    void* d_data_usr = NULL;
    void* d_data_krn = NULL;
    if (copy_from_user(&d, (void*)arg, sizeof(module_test_data_t)) != 0)
        goto error;
    if (d.data_length != 0x0UL) {
        d_data_usr = d.data;
        d_data_krn = kmalloc(d.data_length, GFP_KERNEL);
        d.data = d_data_krn;
        if (copy_from_user(d_data_krn, (void*)d_data_usr, d.data_length) != 0)
            goto error;
    }

    if (d.test_number == TEST_SYSCALLS_TRAMPOLINE) {
        {
            unsigned long* data_ptr = (unsigned long*)d.data;
            unsigned long syscall_number = *(data_ptr++);
            unsigned long args_count = *(data_ptr++), args_i = 0x0UL;
            struct pt_regs regs = {0x0};
            unsigned long syscall_args[6] = {0x0};
            SM_LOG(MIN_VERBOSITY, "%s\n", get_syscall_name(syscall_number));
            while (args_i < args_count)
                syscall_args[args_i++] = *(data_ptr++);
            args_i = 0x0UL;
            while (args_i < args_count) {
                #if LINUX_VERSION_CODE <= KERNEL_VERSION(5,0,0)
                syscall_set_arguments(current, &regs, (unsigned int)args_i++,
                        (unsigned int)args_count, syscall_args);
                #else // LINUX_VERSION_CODE
                memcpy(&(regs.bx) + (unsigned int)args_i++, syscall_args,
                        (unsigned int)args_count * sizeof(syscall_args[0]));
                #endif // LINUX_VERSION_CODE
            }
            preempt_disable();
            if (syscall_number == __NR_getuid) {
                GDB("print ((struct task_struct*)(0x%px))->pid", current);
                BREAKPOINT(1);
                BREAKPOINT_SET("from_kuid");
            }
            d.return_value = sys_call_table_ptr[syscall_number](&regs);
            if (syscall_number == __NR_getuid) {
                BREAKPOINT_UNSET("from_kuid");
            }
            preempt_enable();
        }
    } else if (d.test_number == TEST_MODULE_ASM) {
        d.return_value = (unsigned long) run_module_asm();
        print_mem_area("run_module_asm 'RET' opcode", (void*)d.return_value, 1);
    } else if (d.test_number == TEST_MODULE_CODE) {
        d.return_value = (unsigned long) run_module_code();
    }

    if (d.data_length != 0x0UL) {
        if (copy_to_user((void*)d_data_usr, d_data_krn, d.data_length) != 0)
            goto error;
        d.data = d_data_usr;
    }
    if (copy_to_user((void*)arg, &d, sizeof(module_test_data_t)) != 0)
        goto error;

    goto success;

error:
    ret_val = SAMODULE_ERROR;
    goto cleanup;
success:
    ret_val = SAMODULE_SUCCESS;
cleanup:
    if (d_data_krn != NULL)
        kfree(d_data_krn);
    return ret_val;
}

// References to headers
// struct page --> mm_types.h
// struct pglist_data -> mmzone.h
static long run_module_code(void) {
    unsigned int cpu = get_cpu();
    pgd_t* current_pgd_address;
    unsigned long cr3_value;
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
    pn = alloc_page(GFP_KERNEL | __GFP_ZERO); // Page allocation occurs in rmqueue (page_alloc.c)
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
    print_mem_area("PAGE 0 (first bytes)", (char*)page_to_virt(p0), 16);
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
    navigate_page_tables((unsigned long)(&vmemmap[0]));
    navigate_page_tables((unsigned long)(page_to_virt(p0)));
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
    SM_LOG(MIN_VERBOSITY, "run_module_code - end\n");
    return 0x0L;
}

static void navigate_page_tables(unsigned long vaddr) {
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
        return;
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

static unsigned long sm_lookup_name(const char* sym) {
    int ret;
    struct kprobe kp = { 0x0 };
    kp.symbol_name = sym;
    ret = register_kprobe(&kp);
    if (ret == 0)
        unregister_kprobe(&kp);
    // Even if register_kprobe returned an error, it may have
    // resolved the symbol. In example, this happens when trying
    // to set a kprobe out of the Kernel's .text section.
    return (unsigned long)kp.addr;
}

static void __exit simplemodule_cleanup(void) {
    if (simplemodule_cdev.ops != NULL)
        cdev_del(&simplemodule_cdev);

    if (simplemodule_device != NULL && simplemodule_class != NULL &&
            simplemodule_devt != -1)
        device_destroy(simplemodule_class, simplemodule_devt);

    if (simplemodule_class != NULL)
        class_destroy(simplemodule_class);

    if (simplemodule_devt != -1)
        unregister_chrdev_region(simplemodule_devt, 1);

    {
        output_t* out = NULL,* tmp_node = NULL;
        list_for_each_entry_safe(out, tmp_node, &outputs, list) {
            kfree(out->output_buffer);
            list_del_init(&out->list);
            kfree(out);
        }
    }
}

static int __init simplemodule_init(void) {
    SM_LOG(MAX_VERBOSITY, "simplemodule_init - begin\n");

    if (alloc_chrdev_region(&simplemodule_devt, 0, 1, SAMODULE_NAME "_proc") != 0)
        goto error;
    SM_LOG(MAX_VERBOSITY, "Device major: %d\n", MAJOR(simplemodule_devt));
    SM_LOG(MAX_VERBOSITY, "Device minor: %d\n", MINOR(simplemodule_devt));

    if ((simplemodule_class = class_create(THIS_MODULE, SAMODULE_NAME "_sys")) == NULL)
        goto error;

    if ((simplemodule_device = device_create(simplemodule_class, NULL,
            simplemodule_devt, NULL, SAMODULE_NAME "_dev")) == NULL)
        goto error;

    cdev_init(&simplemodule_cdev, &fops);

    if (cdev_add(&simplemodule_cdev, simplemodule_devt, 1) == -1)
        goto error;

    // How to get the address of a function whose symbol was not exported:
    //      void(*int3_ptr)(void) = (void(*)(void))sm_lookup_name("int3");
    // Invoke: int3_ptr();

    sys_call_table_ptr = (sys_call_ptr_t*)sm_lookup_name("sys_call_table");
    if (sys_call_table_ptr == NULL)
        goto error;

    goto success;

error:
    SM_LOG(MAX_VERBOSITY, "simplemodule_init - end error\n");
    return SAMODULE_ERROR;

success:
    SM_LOG(MAX_VERBOSITY, "simplemodule_init - end success\n");
    return SAMODULE_SUCCESS;
}

module_init(simplemodule_init);
module_exit(simplemodule_cleanup);
MODULE_LICENSE("GPL");
