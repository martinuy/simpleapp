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

#include <stdlib.h>
#include <string.h>

#include "simplemodule.h"

#define SLIB_ERROR -1L
#define SLIB_SUCCESS 0L

// FOREACH macro based on https://stackoverflow.com/a/11994395
#define FE_0(WHAT, X) WHAT(X)
#define FE_1(WHAT, ...) __VA_OPT__(FE_0(WHAT, __VA_ARGS__))
#define FE_2(WHAT, X, ...) WHAT(X)FE_1(WHAT, __VA_ARGS__)
#define FE_3(WHAT, X, ...) WHAT(X)FE_2(WHAT, __VA_ARGS__)
#define FE_4(WHAT, X, ...) WHAT(X)FE_3(WHAT, __VA_ARGS__)
#define FE_5(WHAT, X, ...) WHAT(X)FE_4(WHAT, __VA_ARGS__)
#define FE_6(WHAT, X, ...) WHAT(X)FE_5(WHAT, __VA_ARGS__)
#define GET_MACRO(_0,_1,_2,_3,_4,_5,_6,NAME,...) NAME
#define FOR_EACH(action,...) \
  GET_MACRO(_0,__VA_ARGS__,FE_6,FE_5,FE_4,FE_3,FE_2,FE_1,)(action,__VA_ARGS__)

# undef MOVE_PARAM_PTR
# define MOVE_PARAM_PTR(X)                              \
        *(unsigned long*)param_ptr = (unsigned long)X;  \
        param_ptr += 1;

# undef _COUNT_ARGS
# define _COUNT_ARGS(X)                                 \
    + 1

# undef COUNT_ARGS
# define COUNT_ARGS(...)                                \
    0 FOR_EACH(_COUNT_ARGS,__VA_ARGS__)

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

#define BREAKPOINT(nr) \
 do { \
     if (is_debugger_attached) \
         __asm__ __volatile__ ("int3":::); \
 } while(0)

#define __KERNEL_GDB_CMD(gdb_mode, gdb_data) \
 do { \
     sm_call_data_t sm_call_data = {0x0}; \
     size_t data_length = strlen(gdb_data); \
     size_t final_data_length = data_length + (size_t)(sizeof(unsigned int) + 1); \
     if (final_data_length < data_length || final_data_length > (unsigned long)-1 \
             || data_length == 0x0) { \
         SA_LOG(MIN_VERBOSITY, "SM_CALL_GDB gdb_data length error\n"); \
         break; \
     } \
     sm_call_data.data_length = (unsigned long)final_data_length; \
     sm_call_data.data = (void*)malloc(final_data_length); \
     if (!sm_call_data.data) { \
         SA_LOG(MIN_VERBOSITY, "SM_CALL_GDB malloc error\n"); \
         break; \
     } \
     *((char*)(sm_call_data.data) + sm_call_data.data_length - 1) = '\0'; \
     *((unsigned int*)sm_call_data.data) = (unsigned int)gdb_mode; \
     strcpy((void*)((char*)sm_call_data.data + sizeof(unsigned int)), gdb_data); \
     sm_call_data.call_number = SM_CALL_GDB; \
     if (sm_call(&sm_call_data) != SLIB_ERROR && \
             sm_call_data.return_value != GDB_ERROR) \
         print_module_output(); \
     else \
         SA_LOG(MIN_VERBOSITY, "SM_CALL_GDB error in module\n"); \
     free(sm_call_data.data); \
 } while(0)

#define KERNEL_BREAKPOINT_SET(function_name) \
 do { \
     __KERNEL_GDB_CMD(GDB_MODE_BREAKPOINT_SET, function_name); \
 } while(0)

#define KERNEL_BREAKPOINT_UNSET(function_name) \
 do { \
     __KERNEL_GDB_CMD(GDB_MODE_BREAKPOINT_UNSET, function_name); \
 } while(0)

#define KERNEL_GDB(gdb_cmd, ...) \
 do { \
     char* gdb_cmd_final = NULL; \
     int bytes_required = 0; \
     bytes_required = snprintf(NULL, 0, gdb_cmd __VA_OPT__(,) __VA_ARGS__) + 1; \
     gdb_cmd_final = malloc(bytes_required); \
     if (gdb_cmd_final != NULL) { \
         snprintf(gdb_cmd_final, bytes_required, gdb_cmd __VA_OPT__(,) __VA_ARGS__); \
         __KERNEL_GDB_CMD(GDB_MODE_BREAKPOINT_GDB, gdb_cmd_final); \
         free(gdb_cmd_final); \
     } \
 } while(0)

extern unsigned long sm_call_function(const char* function_name, unsigned int args_count, ...);

#define SMF_CALL(name, ...) \
({ \
    unsigned int args_count = COUNT_ARGS(__VA_ARGS__); \
    sm_call_function(#name, args_count __VA_OPT__(,) __VA_ARGS__); \
})

extern int is_debugger_attached;
extern int simplemodule_fd;

extern long load_module(void);
extern long unload_module(void);
extern long sm_call(sm_call_data_t* d);
extern void print_module_output(void);
extern const char* get_module_output(void); // Caller must free memory

#include "simpleapp_syscalls.h"

#endif // SIMPLELIB_H
