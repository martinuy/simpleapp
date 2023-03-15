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
#include <sys/types.h>

#include "simplelib.h"
#include "simplemodule.h"

#define LOG_END_SEPARATOR SA_LOG(MIN_VERBOSITY, "-------------------------------\n")

static void kernel_asm_function(void);
static void kernel_c_function(void);
static void proxied_syscall(void);
static void direct_syscall(void);
static void direct_asm(void);

int main(void) {
    int ret;
    SA_LOG(MAX_VERBOSITY, "main - begin\n");

    BREAKPOINT(1);

    kernel_asm_function();

    kernel_c_function();

    proxied_syscall();

    direct_syscall();

    direct_asm();

    goto success;
error:
    ret = -1;
    SA_LOG(MIN_VERBOSITY, "main - end error\n");
    goto cleanup;
success:
    ret = 0;
    SA_LOG(MAX_VERBOSITY, "main - end success\n");
cleanup:
    return ret;
}

__attribute__((noinline))
void kernel_asm_function(void) {
    SA_LOG(MIN_VERBOSITY, "===== kernel_asm_function =====\n");
    unsigned long ret = SM_CALL(sm_asm_function_hook);
    SA_LOG(MIN_VERBOSITY, "Returned value: 0x%lx\n", ret);
    LOG_END_SEPARATOR;
}

__attribute__((noinline))
void kernel_c_function(void) {
    SA_LOG(MIN_VERBOSITY, "====== kernel_c_function ======\n");
    unsigned long ret = SM_CALL(sm_c_function_hook, -1);
    SA_LOG(MIN_VERBOSITY, "Returned value: 0x%lx\n", ret);
    LOG_END_SEPARATOR;
}

__attribute__((noinline))
void proxied_syscall(void) {
    SA_LOG(MIN_VERBOSITY, "======= proxied_syscall =======\n");
    uid_t u = SM_SYS(getuid);
    SA_LOG(MIN_VERBOSITY, "Returned value (UID): %d\n", u);
    LOG_END_SEPARATOR;
}

__attribute__((noinline))
void direct_syscall(void) {
    SA_LOG(MIN_VERBOSITY, "======== direct_syscall =======\n");
    int sys_open_fd;
    KERNEL_GDB("echo \"Setting a breakpoint in do_sys_open.\"");
    KERNEL_GDB("stopi on");
    KERNEL_BREAKPOINT_SET("do_sys_open");
    KERNEL_BREAKPOINT(2);
    sys_open_fd = _sys_open("/proc/self/exe", O_RDONLY, 0);
    if (sys_open_fd < 0)
        goto cleanup;
    else
        SA_LOG(MIN_VERBOSITY, "Returned value (open FD): %d\n", sys_open_fd);
cleanup:
    KERNEL_BREAKPOINT_UNSET("do_sys_open");
    if (sys_open_fd != -1)
        close(sys_open_fd);
    LOG_END_SEPARATOR;
}

__attribute__((noinline))
void direct_asm(void) {
    SA_LOG(MIN_VERBOSITY, "========== direct_asm =========\n");
    __asm__ __volatile__ ("cpuid\n\t" \
           : : : "rax", "rbx", "rcx", "rdx");
    LOG_END_SEPARATOR;
}
