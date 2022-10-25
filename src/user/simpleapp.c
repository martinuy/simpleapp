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
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "simpleapp_syscalls.h"
#include "simplelib.h"
#include "simplemodule.h"

static void execute_module_asm_hook(void);
static void execute_module_code_hook(void);
static void execute_proxied_syscalls_hook(void);
static void execute_direct_syscalls_hook(void);
static void execute_direct_asm_hook(void);

int main(void) {
    int ret = -1;
    SA_LOG(MAX_VERBOSITY, "main - begin\n");

    if (load_module() == SLIB_ERROR)
        goto error;

    BREAKPOINT(1);

    execute_proxied_syscalls_hook();

    execute_module_asm_hook();

    execute_module_code_hook();

    execute_direct_asm_hook();

    execute_direct_syscalls_hook();

    goto success;
error:
    SA_LOG(MIN_VERBOSITY, "main - end error\n");
    ret = -1;
    goto cleanup;
success:
    SA_LOG(MAX_VERBOSITY, "main - end success\n");
    ret = 0;
cleanup:
    unload_module();
    return ret;
}

__attribute__((noinline))
void execute_module_asm_hook(void) {
}

__attribute__((noinline))
void execute_module_code_hook(void) {
    module_test_data_t module_test_data = {0x0};
    module_test_data.test_number = TEST_MODULE_CODE;
    if (run_module_test(&module_test_data) == SLIB_ERROR)
        goto error;
    print_module_output();
    SA_LOG(MIN_VERBOSITY, "TEST_MODULE_CODE return: 0x%lx\n", module_test_data.return_value);
    return;
error:
    SA_LOG(MIN_VERBOSITY, "TEST_MODULE_CODE error\n");
}

#include <sys/mman.h>

__attribute__((noinline))
void execute_proxied_syscalls_hook(void) {
    int i = 0;
    void* mmaped_page = (void*)SM_SYS(mmap, NULL, sysconf(_SC_PAGE_SIZE)*10, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
    if (mmaped_page != MAP_FAILED) {
        for (i = 0; i < (sysconf(_SC_PAGE_SIZE)*10) / sizeof(int); i++) {
            if (((int*)mmaped_page)[i] != 0) {
                SA_LOG(MIN_VERBOSITY, "BYTE != 0x0\n");
            }
            ((int*)mmaped_page)[i] = 0;
        }
        SA_LOG(MIN_VERBOSITY, "Zero-check finished\n");
        SM_SYS(munmap, mmaped_page, sysconf(_SC_PAGE_SIZE)*10);
    } else {
        SA_LOG(MIN_VERBOSITY, "mmap failed\n");
    }
}

__attribute__((noinline))
void execute_direct_syscalls_hook(void) {
}

__attribute__((noinline))
void execute_direct_asm_hook(void) {
}
