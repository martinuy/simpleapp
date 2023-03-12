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

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "simplelib.h"
#include "simplemodule.h"

static void execute_module_asm_function(void);
static void execute_module_c_function(void);
static void execute_proxied_syscall(void);
static void execute_direct_syscall(void);
static void execute_direct_asm(void);

int main(void) {
    int ret = -1;
    SA_LOG(MAX_VERBOSITY, "main - begin\n");

    BREAKPOINT(1);

    execute_proxied_syscall();

    execute_module_asm_function();

    execute_module_c_function();

    execute_direct_asm();

    execute_direct_syscall();

    goto success;
error:
    SA_LOG(MIN_VERBOSITY, "main - end error\n");
    ret = -1;
    goto cleanup;
success:
    SA_LOG(MAX_VERBOSITY, "main - end success\n");
    ret = 0;
cleanup:
    return ret;
}

__attribute__((noinline))
void execute_module_asm_function(void) {
    unsigned long ret = SM_CALL(sm_asm_function_hook);
    SA_LOG(MIN_VERBOSITY, "execute_module_asm_function ret: 0x%lx\n", ret);
}

__attribute__((noinline))
void execute_module_c_function(void) {
    unsigned long ret = SM_CALL(sm_c_function_hook, -1);
    SA_LOG(MIN_VERBOSITY, "execute_module_c_function ret: 0x%lx\n", ret);
}

__attribute__((noinline))
void execute_proxied_syscall(void) {
    uid_t u = SM_SYS(getuid);
    SA_LOG(MIN_VERBOSITY, "uid: %d\n", u);
}

__attribute__((noinline))
void execute_direct_syscall(void) {
    int sys_open_fd = -1;
    KERNEL_GDB("echo \"Setting a breakpoint in do_sys_open.\"");
    KERNEL_GDB("stopi on");
    KERNEL_BREAKPOINT_SET("do_sys_open");
    sys_open_fd = _sys_open("/proc/self/exe", O_RDONLY, 0);
    if (sys_open_fd < 0)
        goto cleanup;
    else
        SA_LOG(MIN_VERBOSITY, "sys_open_fd: %d\n", sys_open_fd);
cleanup:
    KERNEL_BREAKPOINT_UNSET("do_sys_open");
    if (sys_open_fd != -1)
        close(sys_open_fd);
}

__attribute__((noinline))
void execute_direct_asm(void) {
    __asm__ __volatile__ ("cpuid\n\t" \
           : : : "rax", "rbx", "rcx", "rdx");
}
