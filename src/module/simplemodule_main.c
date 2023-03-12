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

#include <linux/syscalls.h>

#include "simplemodule_kernel_lib.h"

void pre_syscall_trampoline_hook(unsigned long syscall_number,
        unsigned long syscall_args[]) {
    if (syscall_number == __NR_getuid) {
        GDB("print ((struct task_struct*)(0x%px))->pid", current);
        BREAKPOINT(1);
        BREAKPOINT_SET("from_kuid");
    }
}

void post_syscall_trampoline_hook(unsigned long syscall_number,
        unsigned long syscall_args[], unsigned long return_value) {
    if (syscall_number == __NR_getuid) {
        BREAKPOINT_UNSET("from_kuid");
    }
}

unsigned long sm_c_function_hook(unsigned long arg_1) {
    SM_LOG(MIN_VERBOSITY, "sm_c_function_hook called with arg_1 = 0x%lx\n", arg_1);
    return arg_1;
}
