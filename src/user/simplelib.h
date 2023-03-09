/*
 *   Martin Balao (martin.uy) - Copyright 2020
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
     module_test_data_t module_test_data = {0x0}; \
     size_t data_length = strlen(gdb_data); \
     size_t final_data_length = data_length + (size_t)(sizeof(unsigned int) + 1); \
     if (final_data_length < data_length || final_data_length > (unsigned long)-1 \
             || data_length == 0x0) { \
         SA_LOG(MIN_VERBOSITY, "TEST_MODULE_GDB gdb_data length error\n"); \
         break; \
     } \
     module_test_data.data_length = (unsigned long)final_data_length; \
     module_test_data.data = (void*)malloc(final_data_length); \
     if (!final_data_length) { \
         SA_LOG(MIN_VERBOSITY, "TEST_MODULE_GDB malloc error\n"); \
         break; \
     } \
     *((char*)(module_test_data.data) + module_test_data.data_length - 1) = '\0'; \
     *((unsigned int*)module_test_data.data) = (unsigned int)gdb_mode; \
     strcpy((void*)((char*)module_test_data.data + sizeof(unsigned int)), gdb_data); \
     module_test_data.test_number = TEST_MODULE_GDB; \
     if (run_module_test(&module_test_data) != SLIB_ERROR && \
             module_test_data.return_value != GDB_ERROR) \
         print_module_output(); \
     else \
         SA_LOG(MIN_VERBOSITY, "TEST_MODULE_GDB error in module\n"); \
     free(module_test_data.data); \
 } while(0)

#define KERNEL_BREAKPOINT_SET(function_name) \
 do { \
     __KERNEL_GDB_CMD(GDB_MODE_BREAKPOINT_SET, function_name); \
 } while(0)

#define KERNEL_BREAKPOINT_UNSET(function_name) \
 do { \
     __KERNEL_GDB_CMD(GDB_MODE_BREAKPOINT_UNSET, function_name); \
 } while(0)

#define KERNEL_GDB(gdb_cmd) \
 do { \
     __KERNEL_GDB_CMD(GDB_MODE_BREAKPOINT_GDB, gdb_cmd); \
 } while(0)

extern int is_debugger_attached;
extern int simplemodule_fd;

extern long load_module(void);
extern long unload_module(void);
extern long run_module_test(module_test_data_t* d);
extern void print_module_output(void);
extern const char* get_module_output(void); // Caller must free memory

#endif // SIMPLELIB_H
