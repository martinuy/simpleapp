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
#define _GNU_SOURCE

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "simplelib.h"
#include "simplemodule.h"

#define TEST_ERROR -1
#define TEST_SUCCESS 0

#define EXECUTE_TEST(test) \
  if (test() == TEST_ERROR) \
      goto error;

static int merge_vma_area_structs_test(void);
static int dump_memory_structures_test(void);
static int fork_copy_on_write_test(void);

static long page_size;

int main(void) {
    int ret;
    SA_LOG(MIN_VERBOSITY, "main - begin\n");

    ////////////////////
    // Initialization //
    ////////////////////

    page_size = sysconf(_SC_PAGE_SIZE);

    ///////////////
    //   Tests   //
    ///////////////

    EXECUTE_TEST(merge_vma_area_structs_test);

    EXECUTE_TEST(dump_memory_structures_test);

    EXECUTE_TEST(fork_copy_on_write_test);

    goto success;
error:
    ret = TEST_ERROR;
    SA_LOG(MIN_VERBOSITY, "main - end error\n");
    goto cleanup;
success:
    ret = TEST_SUCCESS;
    SA_LOG(MIN_VERBOSITY, "main - end success\n");
cleanup:
    return ret;
}

static int fork_copy_on_write_test(void) {
    int ret = TEST_ERROR;
    void* mmaped_page = MAP_FAILED;
    long mmap_allocation_chunk = page_size * 2;
    void* mmaped_struct_page = NULL;
    int i = 0;
    long child = 0L;
    int status_code = 0;
    mmaped_page = (void*)SM_SYS(mmap, NULL, mmap_allocation_chunk, PROT_READ |
            PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
    if (mmaped_page == MAP_FAILED) {
        goto error;
    }
    SA_LOG(MIN_VERBOSITY, "mmaped area: 0x%p\n", mmaped_page);
    // Generate the actual memory allocation
    KERNEL_GDB("stopi on");
    KERNEL_BREAKPOINT_SET("handle_mm_fault");
    KERNEL_BREAKPOINT_SET("__alloc_pages_nodemask");
    *((char*)mmaped_page) = 1;
    KERNEL_BREAKPOINT_UNSET("__alloc_pages_nodemask");
    KERNEL_BREAKPOINT_UNSET("handle_mm_fault");
    KERNEL_GDB("stopi off");
    *((char*)mmaped_page + page_size) = 2;
    child = fork();
    if (child == 0) {
        mmaped_struct_page = (void*)(SM_CALL(get_struct_page, (unsigned long)mmaped_page));
        KERNEL_GDB("print *(struct page*)%p", mmaped_struct_page);
        KERNEL_BREAKPOINT(1);
        KERNEL_GDB("stopi on");
        KERNEL_BREAKPOINT_SET("handle_mm_fault");
        KERNEL_BREAKPOINT_SET("__alloc_pages_nodemask");
        // Force a copy-on-write of the 1st page in the child process.
        ((char*)mmaped_page)[0] = 3;
        KERNEL_BREAKPOINT_UNSET("__alloc_pages_nodemask");
        KERNEL_BREAKPOINT_UNSET("handle_mm_fault");
        KERNEL_GDB("stopi off");
        mmaped_struct_page = (void*)(SM_CALL(get_struct_page, (unsigned long)mmaped_page));
        KERNEL_GDB("print *(struct page*)%p", mmaped_struct_page);
        KERNEL_BREAKPOINT(2);
    } else {
        SA_LOG(MIN_VERBOSITY, "child (fork): %ld\n", child);
        if (waitpid(-1, &status_code, 0) == -1) {
            SA_LOG(MIN_VERBOSITY, "Waitpid failed\n");
        }
    }
    goto success;
error:
    ret = TEST_ERROR;
    goto cleanup;
success:
    ret = TEST_SUCCESS;
cleanup:
    if (mmaped_page != MAP_FAILED) {
        SM_SYS(munmap, mmaped_page, mmap_allocation_chunk);
    }
    if (child == 0) {
        exit(0);
    }
    return ret;
}

static int merge_vma_area_structs_test(void) {
    int ret = TEST_ERROR;
    void* mmaped_page = MAP_FAILED, *new_mmaped_page = MAP_FAILED,
            *req_new_mmaped_page = MAP_FAILED;
    long mmap_allocation_chunk = page_size * 3;
    mmaped_page = (void*)SM_SYS(mmap, NULL, mmap_allocation_chunk, PROT_READ |
            PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
    if (mmaped_page == MAP_FAILED) {
        goto error;
    }
    // Free 1 page counting from the end, so there is space for the new
    // allocation that will generate the vm_area_struct merge.
    mmap_allocation_chunk -= page_size;
    SM_SYS(munmap, ((char*)mmaped_page) + mmap_allocation_chunk,
            page_size);
    SA_LOG(MIN_VERBOSITY, "mmaped_page: %p\n", mmaped_page);
    KERNEL_GDB("stopi off");
    KERNEL_BREAKPOINT_SET("vma_merge");
    KERNEL_BREAKPOINT_SET("is_mergeable_anon_vma");
    KERNEL_BREAKPOINT_SET("__vma_adjust");
    req_new_mmaped_page = (void*)(((char*)mmaped_page) + mmap_allocation_chunk);
    new_mmaped_page = (void*)SM_SYS(mmap, req_new_mmaped_page,
                page_size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS |
                MAP_PRIVATE | MAP_FIXED_NOREPLACE, 0, 0);
    if (new_mmaped_page != req_new_mmaped_page) {
        new_mmaped_page = MAP_FAILED;
    }
    KERNEL_BREAKPOINT_UNSET("__vma_adjust");
    KERNEL_BREAKPOINT_UNSET("is_mergeable_anon_vma");
    KERNEL_BREAKPOINT_UNSET("vma_merge");
    KERNEL_GDB("stopi on");
    if (new_mmaped_page == MAP_FAILED) {
        goto error;
    }
    SA_LOG(MIN_VERBOSITY, "new_mmaped_page: %p\n", new_mmaped_page);
    goto success;
error:
    ret = TEST_ERROR;
    goto cleanup;
success:
    ret = TEST_SUCCESS;
cleanup:
    if (mmaped_page != MAP_FAILED) {
        SM_SYS(munmap, mmaped_page, mmap_allocation_chunk);
    }
    if (new_mmaped_page != MAP_FAILED) {
        SM_SYS(munmap, new_mmaped_page, page_size);
    }
    return ret;
}

static int dump_memory_structures_test(void) {
    SM_CALL(show_memory_structures);
    return TEST_SUCCESS;
}
