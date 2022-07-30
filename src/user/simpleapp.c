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

static void execute_module_asm(void);
static void execute_module_code(void);
static void execute_proxied_syscalls(void);
static void execute_direct_syscalls(void);
static void execute_direct_asm(void);

int main(void) {
    int ret = -1;
    SA_LOG(MAX_VERBOSITY, "main - begin\n");

    if (load_module() == SLIB_ERROR)
        goto error;

    BREAKPOINT(1);

    execute_proxied_syscalls();

    execute_module_asm();

    execute_module_code();

    execute_direct_asm();

    execute_direct_syscalls();

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
void execute_module_asm(void) {
    module_test_data_t module_test_data = {0x0};
    module_test_data.test_number = TEST_MODULE_ASM;
    if (run_module_test(&module_test_data) == SLIB_ERROR)
        goto error;
    print_module_output();
    SA_LOG(MIN_VERBOSITY, "TEST_MODULE_ASM return: 0x%lx\n", module_test_data.return_value);
    return;
error:
    SA_LOG(MIN_VERBOSITY, "TEST_MODULE_ASM error\n");
}

__attribute__((noinline))
void execute_module_code(void) {
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

__attribute__((noinline))
void execute_proxied_syscalls(void) {
    uid_t u = SM_SYS(getuid);
    SA_LOG(MIN_VERBOSITY, "uid: %d\n", u);
}

__attribute__((noinline))
void execute_direct_syscalls(void) {
    int sys_open_fd = -1;

    sys_open_fd = _sys_open("/proc/self/exe", O_RDONLY, 0);
    if (sys_open_fd < 0)
        goto cleanup;
    else
        SA_LOG(MIN_VERBOSITY, "sys_open_fd: %d\n", sys_open_fd);

cleanup:
    if (sys_open_fd != -1)
        close(sys_open_fd);
}

__attribute__((noinline))
void execute_direct_asm(void) {
    __asm__ __volatile__ ("cpuid\n\t" \
           : : : "rax", "rbx", "rcx", "rdx");
}
