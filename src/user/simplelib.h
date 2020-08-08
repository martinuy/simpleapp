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

extern int is_debugger_attached;
extern int simplemodule_fd;

extern long load_module(void);
extern long unload_module(void);
extern long run_module_test(module_test_data_t* d);
extern void print_module_output(void);
extern const char* get_module_output(void); // Caller must free memory

#endif // SIMPLELIB_H
