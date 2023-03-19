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

#include <linux/kprobes.h>

#include "__simplemodule_kernel_lib_syscalls.h"

#include "simplemodule_kernel_lib.h"

// Output
DEFINE_MUTEX(outputs_lock);
struct list_head outputs = LIST_HEAD_INIT(outputs);

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

void sm_print_memory(const char* name, void* s, size_t l) {
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

unsigned long sm_lookup_name(const char* sym) {
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
