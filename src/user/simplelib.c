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

#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "simplelib.h"

#define _GNU_SOURCE

#define TRACER_PID "TracerPid:"

extern int init_module(void* module_image, unsigned long len,
        const char* param_values);
extern int delete_module(const char* name, int flags);

int is_debugger_attached = 0;
int simplemodule_fd = -1;

typedef enum module_state_t { UNLOADED = 0, LOADED } module_state_t;

static const char* get_path_to_file_with_base(const char* file);
static const char* get_path_to_library_directory(void);

static module_state_t module_loaded = UNLOADED;
static const char* path_to_library_directory = NULL;

// This is not Thread-Safe
__attribute__((constructor))
static void initialize_once(void) {

    path_to_library_directory = get_path_to_library_directory();
    if (path_to_library_directory == NULL)
        goto error;

    {
        // Set debugger status
        FILE* fp;
        char* line = NULL;
        size_t len = 0U;
        ssize_t read;
        size_t tracer_pid_length = strlen(TRACER_PID);
        fp = fopen("/proc/self/status", "r");
        if (fp == NULL)
            goto error;
        while ((read = getline(&line, &len, fp)) != -1) {
            if ((size_t)read > tracer_pid_length + 1) {
                if (strncmp(line, TRACER_PID, tracer_pid_length) == 0) {
                    if (line[tracer_pid_length + 1] != '0')
                        is_debugger_attached = 1;
                    break;
                }
            }
        }
        free(line);
    }

    goto success;
error:
    SA_LOG(MIN_VERBOSITY, "Error initializing simplelib\n");
    exit(-1);
    return;
success:
    return;
}

long load_module(void) {
    long ret = SLIB_ERROR;
    int cret = -1;
    int simplemodule_image_fd = -1;
    const char* path_to_simplemodule_image = NULL;
    void* simplemodule_image_buf = NULL;
    struct stat simplemodule_image_sb = {0x0};

    if (module_loaded == LOADED)
        goto success;

    path_to_simplemodule_image = get_path_to_file_with_base(SAMODULE_IMAGE);
    if (path_to_simplemodule_image == NULL)
        goto error;

    while((simplemodule_image_fd = open(path_to_simplemodule_image, 0, O_RDONLY)) == -1
            && errno == EINTR);
    if (simplemodule_image_fd < 0)
        goto error;

    if (fstat(simplemodule_image_fd, &simplemodule_image_sb) == -1)
        goto error;

    simplemodule_image_buf = mmap(0, simplemodule_image_sb.st_size,
            PROT_READ|PROT_EXEC, MAP_PRIVATE, simplemodule_image_fd, 0);
    if (simplemodule_image_buf == NULL)
        goto error;

    if (init_module(simplemodule_image_buf, simplemodule_image_sb.st_size, "") != 0
            && errno != EEXIST)
        goto error;

    while((simplemodule_fd = open(SAMODULE_DEVICE_PATH, O_RDWR)) == -1
            && errno == EINTR);
    if (simplemodule_fd < 0)
        goto error;

    goto success;

error:
    ret = SLIB_ERROR;
    goto cleanup;
success:
    module_loaded = LOADED;
    ret = SLIB_SUCCESS;
cleanup:

    if (simplemodule_image_buf != NULL)
        munmap(simplemodule_image_buf, simplemodule_image_sb.st_size);

    if (simplemodule_image_fd >= 0)
        while((cret = close(simplemodule_image_fd)) == -1 && errno == EINTR);

    if (path_to_simplemodule_image != NULL)
        free((void*)path_to_simplemodule_image);

    return ret;
}

long unload_module(void) {
    long ret = SLIB_ERROR;
    int cret = -1;

    if (module_loaded == UNLOADED)
        goto success;

    if (simplemodule_fd >= 0) {
        close(simplemodule_fd);
        simplemodule_fd = -1;
    }

    {
        unsigned int remaining_tries = 5U;
        while ((cret = delete_module(SAMODULE_NAME, O_NONBLOCK)) != 0 &&
                (errno == EAGAIN || errno == EBUSY) &&
                remaining_tries-- != 0U)
            sleep(1);
        if (cret != 0 && errno != EWOULDBLOCK)
            goto error;
    }

    goto success;

error:
    ret = SLIB_ERROR;
    goto cleanup;
success:
    module_loaded = UNLOADED;
    ret = SLIB_SUCCESS;
cleanup:
    return ret;
}

void print_module_output(void) {
    const char* out = get_module_output();
    if (out != NULL) {
        printf("%s", out);
        fflush(stdout);
        free((void*)out);
    }
}

const char* get_module_output(void) {
    unsigned long output_size = 0UL;
    const char* output_buffer = NULL;
    if (module_loaded != LOADED)
        goto error;
    output_size = (unsigned long)ioctl(simplemodule_fd,
            SM_IOCTL_OUTPUT_SIZE, 0UL);
    if (output_size == 0UL)
        goto success;
    output_buffer = (const char*)malloc(output_size);
    if (output_buffer == NULL)
        goto error;
    if (ioctl(simplemodule_fd, SM_IOCTL_OUTPUT_FLUSH,
            (void*)output_buffer) != SAMODULE_SUCCESS)
        goto error;
    goto success;
error:
    if (output_buffer != NULL)
        free((void*)output_buffer);
    output_buffer = NULL;
    goto cleanup;
success:
cleanup:
    return output_buffer;
}

long sm_call(sm_call_data_t* d) {
    long ret = SLIB_ERROR;

    if (module_loaded != LOADED)
        goto error;

    if (ioctl(simplemodule_fd, SM_IOCTL_CALL, (void*)d) != SAMODULE_SUCCESS)
        goto error;
    goto success;

error:
    ret = SLIB_ERROR;
    goto cleanup;
success:
    ret = SLIB_SUCCESS;
    goto cleanup;
cleanup:
    return ret;
}

unsigned long sm_call_function(const char* function_name, unsigned int args_count, ...) {
    void* data_ptr;
    unsigned int args_i;
    va_list args;
    sm_call_data_t sm_call_data = {0x0};
    sm_call_data.call_number = SM_CALL_FUNCTION;
    size_t function_name_length = strlen(function_name);
    if (args_count > 6U) {
        SA_LOG(MIN_VERBOSITY, "Number of arguments %u not supported.", args_count);
        goto error;
    }
    size_t final_data_length = function_name_length + (size_t)(sizeof(unsigned int) + 1
            + sizeof(unsigned long)*args_count);
    if (final_data_length < function_name_length || final_data_length > (unsigned long)-1
            || function_name_length == 0x0) {
        SA_LOG(MIN_VERBOSITY, "SM_CALL_FUNCTION data length error\n");
        goto error;
    }
    sm_call_data.data_length = (unsigned long)final_data_length;
    sm_call_data.data = (void*)malloc(final_data_length);
    if (!sm_call_data.data) {
        SA_LOG(MIN_VERBOSITY, "SM_CALL_FUNCTION malloc error\n");
        goto error;
    }
    data_ptr = sm_call_data.data;
    strcpy((void*)((char*)data_ptr), function_name);
    data_ptr = (char*)data_ptr + function_name_length;
    *((char*)data_ptr) = '\0';
    data_ptr = (char*)data_ptr + sizeof(char);
    *((unsigned int*)data_ptr) = args_count;
    data_ptr = (char*)data_ptr + sizeof(unsigned int);
    va_start(args, args_count);
    args_i = args_count;
    while (args_i-- > 0) {
        *((unsigned long*)data_ptr) = va_arg(args, unsigned long);
        data_ptr = (char*)data_ptr + sizeof(unsigned long);
    }
    if (sm_call(&sm_call_data) == SLIB_ERROR) {
        goto error;
    }
    print_module_output();
    goto cleanup;
error:
    SA_LOG(MIN_VERBOSITY, "SM_CALL_FUNCTION error\n");
cleanup:
    if (sm_call_data.data) {
        free(sm_call_data.data);
    }
    return (unsigned long)sm_call_data.return_value;
}

const char* get_path_to_file_with_base(const char* file) {
    const size_t path_to_file_with_base_length = strlen(path_to_library_directory)
            + 1 + strlen(file) + 1;
    char* path_to_file_with_base = (char*)malloc(path_to_file_with_base_length);
    if (path_to_file_with_base == NULL)
        goto end;
    path_to_file_with_base[0] = 0;
    strcat(path_to_file_with_base, path_to_library_directory);
    strcat(path_to_file_with_base, "/");
    strcat(path_to_file_with_base, file);
    path_to_file_with_base[path_to_file_with_base_length-1] = 0;
end:
    return path_to_file_with_base;
}

const char* get_path_to_library_directory(void) {
    char* ret = NULL;
    char* executable_full_path_ptr = NULL;
    unsigned int executable_directory_length = 0;
    ssize_t count = -1;
    char* executable_full_path = (char*)malloc(PATH_MAX);
    if (executable_full_path == NULL)
        goto cleanup;
    count = readlink("/proc/self/exe", executable_full_path, PATH_MAX);
    // Fail if we cannot read the link or if the name is too long
    // and it was truncated by readlink
    if (count == -1 || count == PATH_MAX)
        goto cleanup;
    // man page readlink(2) says
    //  "readlink() does not append a null byte to buf"
    // So we put an explict 0 here to be sure that we will not
    // overrun the buffer later
    //
    executable_full_path[count] = 0;

    executable_full_path_ptr = dirname(executable_full_path);
    executable_directory_length = strlen(executable_full_path_ptr);
    ret = (char*)malloc(executable_directory_length + 1);
    if (ret == NULL)
        goto cleanup;
    memcpy(ret, executable_full_path_ptr, executable_directory_length);
    ret[executable_directory_length] = 0;
cleanup:
    if (executable_full_path != NULL) {
        free(executable_full_path);
        executable_full_path = NULL;
    }
    return ret;
}
