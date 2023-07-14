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

#ifndef SIMPLELIB_H
#define SIMPLELIB_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "simplemodule.h"

#define SLIB_ERROR -1L
#define SLIB_SUCCESS 0L

#define MOVE_PARAM_PTR(X)                              \
        *(unsigned long*)param_ptr = (unsigned long)X;  \
        param_ptr += 1;

#define SA_PRINTF(fmt,...) __SA_PRINTF("SimpleApp (PID: %d): " fmt, \
        getpid() __VA_OPT__(,) __VA_ARGS__)
#define __SA_PRINTF(fmt,...) \
    printf(fmt __VA_OPT__(,) __VA_ARGS__); \
    fflush(stdout);

#define SA_LOG(level, args...) \
 do { \
     if (LOG_VERBOSITY >= level) \
         SA_PRINTF(args); \
 } while(0)

#define BREAKPOINT(MSG) \
 do { \
     if (is_debugger_attached) \
         __asm__ __volatile__ ("int3":::); \
 } while(0)

extern long sm_call_gdb(unsigned int gdb_call,
        unsigned int declared_args_count, unsigned int args_count, ...);

#define KERNEL_BREAKPOINT_SET(...) \
({ \
    sm_call_gdb(GDB_MODE_BREAKPOINT_SET, 2, SM_COUNT_ARGS(__VA_ARGS__), __VA_ARGS__); \
})

#define KERNEL_BREAKPOINT_UNSET(function_name) \
({ \
    sm_call_gdb(GDB_MODE_BREAKPOINT_UNSET, 1, 1, function_name); \
})

#define KERNEL_BREAKPOINT(msg) \
({ \
    sm_call_gdb(GDB_MODE_BREAKPOINT, 1, 1, msg); \
})

#define KERNEL_GDB(gdb_cmd, ...) \
 do { \
     char* gdb_cmd_final = NULL; \
     int bytes_required = 0; \
     bytes_required = snprintf(NULL, 0, gdb_cmd __VA_OPT__(,) __VA_ARGS__) + 1; \
     gdb_cmd_final = malloc(bytes_required); \
     if (gdb_cmd_final != NULL) { \
         snprintf(gdb_cmd_final, bytes_required, gdb_cmd __VA_OPT__(,) __VA_ARGS__); \
         sm_call_gdb(GDB_MODE_BREAKPOINT_GDB, 1, 1, gdb_cmd_final); \
         free(gdb_cmd_final); \
     } \
 } while(0)

extern unsigned long sm_call_function(const char* function_name, unsigned int args_count, ...);

#define SM_CALL(name, ...) \
({ \
    unsigned int args_count = SM_COUNT_ARGS(__VA_ARGS__); \
    sm_call_function(#name, args_count __VA_OPT__(,) __VA_ARGS__); \
})

extern int is_debugger_attached;
extern int simplemodule_fd;

extern long sm_call(sm_call_data_t* d);
extern void print_module_output(void);
extern const char* get_module_output(void); // Caller must free memory

#include "simpleapp_syscalls.h"

#endif // SIMPLELIB_H
