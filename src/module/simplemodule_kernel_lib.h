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

#ifndef SIMPLEMODULE_KERNEL_LIB_H
#define SIMPLEMODULE_KERNEL_LIB_H

#include <linux/mutex.h>
#include <linux/types.h>

#include "simplemodule.h"

/////////////////////
//     Defines     //
/////////////////////
#define SM_PRINTF(fmt,...) __SM_PRINTF("SimpleModule (PID: %d): " fmt, \
        current->pid __VA_OPT__(,) __VA_ARGS__)
#define __SM_PRINTF(fmt,...) \
 do { \
     int bytes_required = 0; \
     sm_output_t* out = NULL,* out_it = NULL; \
     bytes_required = snprintf(NULL, 0, fmt __VA_OPT__(,) __VA_ARGS__); \
     mutex_lock(&outputs_lock); \
     list_for_each_entry(out_it, &outputs, list) { \
         if (out_it->pid == current->pid) { \
             out = out_it; \
             break; \
         } \
     } \
     if (out == NULL) { \
         out = (sm_output_t*)kmalloc(sizeof(sm_output_t), GFP_KERNEL); \
         out->pid = current->pid; \
         out->output_buffer_size = sizeof(char) * (bytes_required + 1); \
         out->output_buffer = kmalloc(out->output_buffer_size, GFP_KERNEL); \
         snprintf(out->output_buffer, out->output_buffer_size, fmt __VA_OPT__(,) __VA_ARGS__); \
         GDB("echo %s", out->output_buffer); \
         INIT_LIST_HEAD(&out->list); \
         list_add(&out->list, &outputs); \
     } else { \
         out->output_buffer = krealloc(out->output_buffer, \
                 out->output_buffer_size + (sizeof(char) * bytes_required), GFP_KERNEL); \
         snprintf(out->output_buffer + (out->output_buffer_size - 1), \
                 sizeof(char) * (bytes_required + 1), fmt __VA_OPT__(,) __VA_ARGS__); \
         GDB("echo %s", (out->output_buffer + out->output_buffer_size - 1)); \
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

typedef struct sm_output {
     pid_t pid;
     char* output_buffer;
     unsigned long output_buffer_size;
     struct list_head list;
} sm_output_t;

extern struct list_head outputs;
extern struct mutex outputs_lock;

extern void sm_debug(int num);
extern void sm_breakpoint_set(const char* sym);
extern void sm_breakpoint_unset(const char* sym);
extern void sm_gdb(const char* cmd);

extern const char* sm_get_syscall_name(unsigned long sys_code);
extern unsigned long sm_lookup_name(const char* sym);
extern void sm_print_memory(const char* name, void* s, size_t l);

#endif // SIMPLEMODULE_KERNEL_LIB_H
