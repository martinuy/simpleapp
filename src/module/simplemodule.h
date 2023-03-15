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

#ifndef SIMPLEMODULE_H
#define SIMPLEMODULE_H

#include <linux/ioctl.h>

#ifdef SAMODULE_FROM_USER
#include <unistd.h>
#else
#include <linux/unistd.h>
#endif // SAMODULE_FROM_USER

#define SAMODULE_NAME "simplemodule"
#define SAMODULE_IMAGE SAMODULE_NAME".ko"
#define SAMODULE_DEVICE_PATH "/dev/"SAMODULE_NAME"_dev"

#define SAMODULE_SUCCESS 0L
#define SAMODULE_ERROR -1L

// Log verbosity
#define MIN_VERBOSITY 0
#define MEDIUM_VERBOSITY 1
#define MAX_VERBOSITY 2
#define LOG_VERBOSITY MEDIUM_VERBOSITY

//
// SM_CALL
//
#define SM_CALL_SYSCALLS_TRAMPOLINE 0x0U
typedef struct sm_call_data {
    unsigned int call_number;   // read-only (in kernel)
    void* data;                 // in/out buffer to kernel
    unsigned long data_length;  // read-only (in kernel)
    long return_value;          // write-only (in kernel)
} sm_call_data_t;
#define SM_CALL_FUNCTION 0x1U
#define SM_CALL_GDB 0x2U
#define SM_CALL_OUTPUT 0x3U

// SM_CALL_GDB
#define GDB_MODE_BREAKPOINT 0x1U
#define GDB_MODE_BREAKPOINT_SET 0x2U
#define GDB_MODE_BREAKPOINT_UNSET 0x3U
#define GDB_MODE_BREAKPOINT_GDB 0x4U
#define GDB_SUCCESS 0x0L
#define GDB_ERROR 0x1L

// IOCTLs
#define SM_IOCTL_TYPE 0xA4
#define SM_IOCTL_CALL _IOW(SM_IOCTL_TYPE, 0x00, sm_call_data_t)

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

#define SM__COUNT_ARGS(X)                                 \
    + 1

#define SM_COUNT_ARGS(...)                                \
    0 FOR_EACH(SM__COUNT_ARGS,__VA_ARGS__)

#endif // SIMPLEMODULE_H
