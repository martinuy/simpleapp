/*
 *   Martin Balao (martin.uy) - Copyright 2020, 2024
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

noinline void pre_syscall_trampoline_hook(unsigned long syscall_number,
        unsigned long syscall_args[]) {
    if (syscall_number == __NR_mq_open) {
        GDB("print *(struct vfsmount *)(((struct task_struct*)(0x%px))->nsproxy->ipc_ns->mq_mnt)", current);
        // Functions to watch once the queue is opened:
        //BREAKPOINT_SET("mqueue_create");
        //BREAKPOINT_SET("mqueue_unlink");
        //BREAKPOINT_SET("mqueue_flush_file");
        //BREAKPOINT_SET("mqueue_poll_file");
        //BREAKPOINT_SET("mqueue_read_file");
        //BREAKPOINT_SET("mqueue_alloc_inode");
        //BREAKPOINT_SET("mqueue_free_inode");
        //BREAKPOINT_SET("mqueue_evict_inode");
        //BREAKPOINT_SET("mqueue_fs_context_free");
        //BREAKPOINT_SET("mqueue_get_tree");
        //BREAKPOINT_SET("mqueue_init_fs_context");
    }
}

noinline void post_syscall_trampoline_hook(unsigned long syscall_number,
        unsigned long syscall_args[], unsigned long return_value) {
    if (syscall_number == __NR_mq_open) {
        SM_PRINTF("mq_open finished, going back to user-space\n");
    }
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-prototypes"

#pragma GCC diagnostic pop
