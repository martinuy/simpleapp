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

#include <asm/syscall.h>

#include <linux/cdev.h>
#include <linux/err.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/unistd.h>
#include <linux/version.h>

#include "simplemodule_kernel_lib.h"

/////////////////////////
// Function prototypes //
/////////////////////////
extern void pre_syscall_trampoline_hook(unsigned long syscall_number,
        unsigned long syscall_args[]);
extern void post_syscall_trampoline_hook(unsigned long syscall_number,
        unsigned long syscall_args[], unsigned long return_value);

static long unlocked_ioctl(struct file* f, unsigned int cmd, unsigned long arg);
static long sm_call(unsigned long arg);

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

/////////////////////
//    Functions    //
/////////////////////

static long unlocked_ioctl(struct file* f, unsigned int cmd, unsigned long arg) {
    long ret_val = SAMODULE_ERROR;
    switch(cmd) {
    case SM_IOCTL_CALL:
        if ((ret_val = sm_call(arg)) == SAMODULE_ERROR)
            goto cleanup;
        break;
    case SM_IOCTL_OUTPUT_SIZE:
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
    case SM_IOCTL_OUTPUT_FLUSH:
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

static long sm_call(unsigned long arg) {
    long ret_val = SAMODULE_ERROR;
    sm_call_data_t d;
    void* d_data_usr = NULL;
    void* d_data_krn = NULL;
    if (copy_from_user(&d, (void*)arg, sizeof(sm_call_data_t)) != 0)
        goto error;
    if (d.data_length != 0x0UL) {
        d_data_usr = d.data;
        d_data_krn = kmalloc(d.data_length, GFP_KERNEL);
        d.data = d_data_krn;
        if (copy_from_user(d_data_krn, (void*)d_data_usr, d.data_length) != 0)
            goto error;
    }

    if (d.call_number == SM_CALL_SYSCALLS_TRAMPOLINE) {
        {
            unsigned long* data_ptr = (unsigned long*)d.data;
            unsigned long syscall_number = *(data_ptr++);
            unsigned long args_count = *(data_ptr++), args_i = 0x0UL;
            struct pt_regs regs = {0x0};
            unsigned long syscall_args[6] = {0x0};
            SM_LOG(MIN_VERBOSITY, "%s\n", get_syscall_name(syscall_number));
            while (args_i < args_count)
                syscall_args[args_i++] = *(data_ptr++);
            preempt_disable();
            pre_syscall_trampoline_hook(syscall_number, syscall_args);
            args_i = 0x0UL;
            #if LINUX_VERSION_CODE <= KERNEL_VERSION(5,0,0)
            while (args_i < args_count) {
                syscall_set_arguments(current, &regs, (unsigned int)args_i++,
                        (unsigned int)args_count, syscall_args);
            }
            #else // LINUX_VERSION_CODE
            {
                regs.di = syscall_args[args_i++];
                regs.si = syscall_args[args_i++];
                regs.dx = syscall_args[args_i++];
                regs.r10 = syscall_args[args_i++];
                regs.r8 = syscall_args[args_i++];
                regs.r9 = syscall_args[args_i];
            }
            #endif // LINUX_VERSION_CODE
            d.return_value = sys_call_table_ptr[syscall_number](&regs);
            post_syscall_trampoline_hook(syscall_number, syscall_args, d.return_value);
            preempt_enable();
        }
    } else if (d.call_number == SM_CALL_FUNCTION) {
        void* function_ptr;
        unsigned int args_count;
        void* data_ptr = (void*)d.data;
        const char* function_name = (const char*)data_ptr;
        size_t function_name_length = strlen(function_name);
        data_ptr = (char*)data_ptr + function_name_length + 1;
        args_count = *(unsigned int*)data_ptr;
        data_ptr = (char*)data_ptr + sizeof(unsigned int);
        function_ptr = (void*)sm_lookup_name(function_name);
        if (args_count == 0) {
            d.return_value = ((unsigned long (*)(void))function_ptr)();
        } else if (args_count == 1) {
            d.return_value = ((unsigned long (*)(unsigned long))function_ptr)(*(unsigned long*)data_ptr);
        }
        // TODO: extend to more parameters. Use a macro possibly.
    } else if (d.call_number == SM_CALL_GDB) {
        unsigned int gdb_mode = *((unsigned int*)d.data);
        const char* gdb_data = ((const char*)d.data + sizeof(unsigned int));
        d.return_value = GDB_SUCCESS;
        if (gdb_mode == GDB_MODE_BREAKPOINT_GDB) {
            sm_gdb(gdb_data);
        } else if (gdb_mode == GDB_MODE_BREAKPOINT_SET) {
            sm_breakpoint_set(gdb_data);
        } else if (gdb_mode == GDB_MODE_BREAKPOINT_UNSET) {
            sm_breakpoint_unset(gdb_data);
        } else {
            d.return_value = GDB_ERROR;
        }
    }

    if (d.data_length != 0x0UL) {
        if (copy_to_user((void*)d_data_usr, d_data_krn, d.data_length) != 0)
            goto error;
        d.data = d_data_usr;
    }
    if (copy_to_user((void*)arg, &d, sizeof(sm_call_data_t)) != 0)
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
