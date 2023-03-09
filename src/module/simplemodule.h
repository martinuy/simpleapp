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
// Tests
//
#define TEST_SYSCALLS_TRAMPOLINE 0x0U
typedef struct module_test_data {
    unsigned int test_number;   // read-only (in kernel)
    void* data;                 // in/out buffer to kernel
    unsigned long data_length;  // read-only (in kernel)
    long return_value;          // write-only (in kernel)
} module_test_data_t;

#define TEST_MODULE_ASM 0x1U
#define TEST_MODULE_CODE 0x2U
#define TEST_MODULE_GDB 0x3U

// TEST_MODULE_GDB modes
#define GDB_MODE_BREAKPOINT_SET 0x1U
#define GDB_MODE_BREAKPOINT_UNSET 0x2U
#define GDB_MODE_BREAKPOINT_GDB 0x3U

#define GDB_SUCCESS 0x0L
#define GDB_ERROR 0x1L

// IOCTLs
#define SAMODULE_IOCTL_TYPE 0xA4
#define SAMODULE_IOCTL_TEST _IOW(SAMODULE_IOCTL_TYPE, 0x00, module_test_data_t)
#define SAMODULE_IOCTL_OUTPUT_SIZE _IO(SAMODULE_IOCTL_TYPE, 0x01)
#define SAMODULE_IOCTL_OUTPUT_FLUSH _IOR(SAMODULE_IOCTL_TYPE, 0x02, char)

#endif // SIMPLEMODULE_H
