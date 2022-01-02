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

#include <asm/syscall.h>

#include <linux/cdev.h>
#include <linux/err.h>
#include <linux/kprobes.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/unistd.h>

#include "simplemodule.h"

#include "__priv_simplemodule.h"

/////////////////////
//     Defines     //
/////////////////////
#define SM_PRINTF(fmt,...) __SM_PRINTF("SimpleModule (PID: %d): " fmt, \
        current->pid __VA_OPT__(,) __VA_ARGS__)
#define __SM_PRINTF(fmt,...) \
 do { \
     int bytes_required = 0; \
     output_t* out = NULL,* out_it = NULL; \
     bytes_required = snprintf(NULL, 0, fmt __VA_OPT__(,) __VA_ARGS__); \
     mutex_lock(&outputs_lock); \
     list_for_each_entry(out_it, &outputs, list) { \
         if (out_it->pid == current->pid) { \
             out = out_it; \
             break; \
         } \
     } \
     if (out == NULL) { \
         out = (output_t*)kmalloc(sizeof(output_t), GFP_KERNEL); \
         out->pid = current->pid; \
         out->output_buffer_size = sizeof(char) * (bytes_required + 1); \
         out->output_buffer = kmalloc(out->output_buffer_size, GFP_KERNEL); \
         snprintf(out->output_buffer, out->output_buffer_size, fmt __VA_OPT__(,) __VA_ARGS__); \
         INIT_LIST_HEAD(&out->list); \
         list_add(&out->list, &outputs); \
     } else { \
         out->output_buffer = krealloc(out->output_buffer, \
                 out->output_buffer_size + (sizeof(char) * bytes_required), GFP_KERNEL); \
         snprintf(out->output_buffer + (out->output_buffer_size - 1), \
                 sizeof(char) * (bytes_required + 1), fmt __VA_OPT__(,) __VA_ARGS__); \
         out->output_buffer_size += (sizeof(char) * bytes_required); \
     } \
     mutex_unlock(&outputs_lock); \
 } while(0)

#define SM_LOG(level, args...) \
 do { \
     if (LOG_VERBOSITY >= level) \
         SM_PRINTF(args); \
 } while(0)

#define BREAKPOINT(NUM) sm_debug(NUM)

#define BREAKPOINT_SET(SYM) sm_breakpoint_set(SYM)

#define BREAKPOINT_UNSET(SYM) sm_breakpoint_unset(SYM)

#define GDB(cmd, ...) \
 do { \
    char* gdb_cmd = NULL; \
    int bytes_required = 0; \
    bytes_required = snprintf(NULL, 0, cmd __VA_OPT__(,) __VA_ARGS__) + 1; \
    gdb_cmd = kmalloc(bytes_required, GFP_KERNEL); \
    if (gdb_cmd != NULL) { \
        snprintf(gdb_cmd, bytes_required, cmd __VA_OPT__(,) __VA_ARGS__); \
        sm_gdb(gdb_cmd); \
        kfree(gdb_cmd); \
    } \
 } while(0)

typedef struct output {
     pid_t pid;
     char* output_buffer;
     unsigned long output_buffer_size;
     struct list_head list;
} output_t;

/////////////////////////
// Function prototypes //
/////////////////////////
extern long asm_test_function(void);
extern void sm_debug(int num);
extern void sm_breakpoint_set(const char* sym);
extern void sm_breakpoint_unset(const char* sym);
extern void sm_gdb(const char* cmd);

static unsigned long sm_lookup_name(const char* sym);
static long unlocked_ioctl(struct file* f, unsigned int cmd, unsigned long arg);
static long run_module_test(unsigned long arg);
static const char* get_syscall_name(unsigned long sys_code);

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

// Output
static DEFINE_MUTEX(outputs_lock);
static struct list_head outputs = LIST_HEAD_INIT(outputs);

/////////////////////
//    Functions    //
/////////////////////
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

static long unlocked_ioctl(struct file* f, unsigned int cmd, unsigned long arg) {
    long ret_val = SAMODULE_ERROR;
    switch(cmd) {
    case SAMODULE_IOCTL_TEST:
        if ((ret_val = run_module_test(arg)) == SAMODULE_ERROR)
            goto cleanup;
        break;
    case SAMODULE_IOCTL_OUTPUT_SIZE:
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
    case SAMODULE_IOCTL_OUTPUT_FLUSH:
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

__attribute__((used))
static void print_mem_area(const char* name, void* s, size_t l) {
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

static long run_module_test(unsigned long arg) {
    long ret_val = SAMODULE_ERROR;
    module_test_data_t d;
    void* d_data_usr = NULL;
    void* d_data_krn = NULL;
    if (copy_from_user(&d, (void*)arg, sizeof(module_test_data_t)) != 0)
        goto error;
    if (d.data_length != 0x0UL) {
        d_data_usr = d.data;
        d_data_krn = kmalloc(d.data_length, GFP_KERNEL);
        d.data = d_data_krn;
        if (copy_from_user(d_data_krn, (void*)d_data_usr, d.data_length) != 0)
            goto error;
    }

    if (d.test_number == TEST_SYSCALLS_TRAMPOLINE) {
        {
            unsigned long* data_ptr = (unsigned long*)d.data;
            unsigned long syscall_number = *(data_ptr++);
            unsigned long args_count = *(data_ptr++), args_i = 0x0UL;
            struct pt_regs regs = {0x0};
            unsigned long syscall_args[6] = {0x0};
            SM_LOG(MIN_VERBOSITY, "%s\n", get_syscall_name(syscall_number));
            while (args_i < args_count)
                syscall_args[args_i++] = *(data_ptr++);
            syscall_set_arguments(current, &regs, syscall_args);
            preempt_disable();
            if (syscall_number == __NR_getuid) {
                GDB("print ((struct task_struct*)(0x%px))->pid", current);
                BREAKPOINT(1);
                BREAKPOINT_SET("from_kuid");
            }
            d.return_value = sys_call_table_ptr[syscall_number](&regs);
            if (syscall_number == __NR_getuid) {
                BREAKPOINT_UNSET("from_kuid");
            }
            preempt_enable();
        }
    } else if (d.test_number == TEST_ASM) {
        d.return_value = (unsigned long) asm_test_function();
        print_mem_area("asm_test_function 'RET' opcode", (void*)d.return_value, 1);
    }

    if (d.data_length != 0x0UL) {
        if (copy_to_user((void*)d_data_usr, d_data_krn, d.data_length) != 0)
            goto error;
        d.data = d_data_usr;
    }
    if (copy_to_user((void*)arg, &d, sizeof(module_test_data_t)) != 0)
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

static unsigned long sm_lookup_name(const char* sym) {
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
