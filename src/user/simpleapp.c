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

int main(void) {
    int ret;
    SA_LOG(MAX_VERBOSITY, "main - begin\n");

    //SM_CALL(show_memory_structures);

    void* new_mmaped_page = MAP_FAILED;
    void* mmaped_page = MAP_FAILED;
    void* mmaped_struct_page = NULL;
    int i = 0;
    long child = 0L;
    int status_code = 0;
    long mmap_allocation_chunk = sysconf(_SC_PAGE_SIZE)*2;
    mmaped_page = (void*)SM_SYS(mmap, NULL, mmap_allocation_chunk, PROT_READ | PROT_WRITE,
            MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
    if (mmaped_page == MAP_FAILED) {
        goto error;
    }
    SA_LOG(MIN_VERBOSITY, "mmaped area: %p\n", mmaped_page);
    for (i = 0; i < mmap_allocation_chunk / sizeof(int); i++) {
        ((int*)mmaped_page)[i] = 0;
    }
    child = fork();
    if (child == 0) {
        //KERNEL_GDB("stopi on");
        mmaped_struct_page = (void*)(SM_CALL(get_struct_page, (unsigned long)mmaped_page));
        //KERNEL_GDB("print *(struct page*)%p", mmaped_struct_page);
        //KERNEL_BREAKPOINT(1);
        //KERNEL_BREAKPOINT_SET("handle_mm_fault");
        // Force a copy-on-write of the 1st page in the child process.
        ((int*)mmaped_page)[0] = 1;
        //KERNEL_BREAKPOINT_UNSET("handle_mm_fault");
        mmaped_struct_page = (void*)(SM_CALL(get_struct_page, (unsigned long)mmaped_page));
        //KERNEL_GDB("print *(struct page*)%p", mmaped_struct_page);
        //KERNEL_BREAKPOINT(2);
        // Append new pages to the mmaped area in the child process.
        void* new_mmaped_page = (void*)SM_SYS(mmap, ((char*)mmaped_page) + mmap_allocation_chunk,
                mmap_allocation_chunk, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, 0, 0);
        if (new_mmaped_page == MAP_FAILED) {
            goto error;
        }
        SA_LOG(MIN_VERBOSITY, "New mmaped area: %p\n", new_mmaped_page);
        for (i = 0; i < mmap_allocation_chunk / sizeof(int); i++) {
            ((int*)new_mmaped_page)[i] = 0;
        }
    } else {
        SA_LOG(MIN_VERBOSITY, "child (fork): %ld\n", child);
        if (waitpid(-1, &status_code, 0) == -1) {
            SA_LOG(MIN_VERBOSITY, "Waitpid failed\n");
        }
    }
    goto success;
error:
    ret = -1;
    SA_LOG(MIN_VERBOSITY, "main - end error\n");
    goto cleanup;
success:
    ret = 0;
    SA_LOG(MAX_VERBOSITY, "main - end success\n");
cleanup:
    if (mmaped_page != MAP_FAILED) {
        SM_SYS(munmap, mmaped_page, mmap_allocation_chunk);
    }
    if (new_mmaped_page != MAP_FAILED) {
        SM_SYS(munmap, new_mmaped_page, mmap_allocation_chunk);
    }
    return ret;
}
