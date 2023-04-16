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
#define _GNU_SOURCE

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "simplelib.h"
#include "simplemodule.h"

#define TEST_ERROR -1
#define TEST_SUCCESS 0

#define EXECUTE_TEST(test) \
  if (test() == TEST_ERROR) \
      goto error;

static int merge_vma_area_structs_test(void);
static int dump_memory_structures_test(void);
static int fork_copy_on_write_test(void);
static int file_backed_memory_allocation_test(void);

static long page_size;

int main(void) {
    int ret;
    SA_LOG(MIN_VERBOSITY, "main - begin\n");

    ////////////////////
    // Initialization //
    ////////////////////

    page_size = sysconf(_SC_PAGE_SIZE);

    ///////////////
    //   Tests   //
    ///////////////

    EXECUTE_TEST(merge_vma_area_structs_test);

    EXECUTE_TEST(dump_memory_structures_test);

    EXECUTE_TEST(fork_copy_on_write_test);

    EXECUTE_TEST(file_backed_memory_allocation_test);

    goto success;
error:
    ret = TEST_ERROR;
    SA_LOG(MIN_VERBOSITY, "main - end error\n");
    goto cleanup;
success:
    ret = TEST_SUCCESS;
    SA_LOG(MIN_VERBOSITY, "main - end success\n");
cleanup:
    return ret;
}

static int fork_copy_on_write_test(void) {
    int ret = TEST_ERROR;
    void* mmaped_page = MAP_FAILED;
    long mmap_allocation_chunk = page_size * 2;
    void* mmapped_struct_page = NULL;
    int i = 0;
    long child = 0L;
    int status_code = 0;
    mmaped_page = (void*)SM_SYS(mmap, NULL, mmap_allocation_chunk, PROT_READ |
            PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
    if (mmaped_page == MAP_FAILED) {
        goto error;
    }
    SA_LOG(MIN_VERBOSITY, "mmaped area: 0x%p\n", mmaped_page);
    // Generate the actual memory allocation
    KERNEL_BREAKPOINT_SET("handle_mm_fault");
    KERNEL_BREAKPOINT_SET("__alloc_pages_nodemask");
    KERNEL_GDB("stopi on");
    *((char*)mmaped_page) = 1;
    KERNEL_GDB("stopi off");
    KERNEL_BREAKPOINT_UNSET("__alloc_pages_nodemask");
    KERNEL_BREAKPOINT_UNSET("handle_mm_fault");
    *((char*)mmaped_page + page_size) = 2;
    child = fork();
    if (child == 0) {
        mmapped_struct_page = (void*)(SM_CALL(get_struct_page, (unsigned long)mmaped_page));
        KERNEL_GDB("print *(struct page*)%p", mmapped_struct_page);
        KERNEL_BREAKPOINT(1);
        KERNEL_BREAKPOINT_SET("handle_mm_fault");
        KERNEL_BREAKPOINT_SET("__alloc_pages_nodemask");
        KERNEL_GDB("stopi on");
        // Force a copy-on-write of the 1st page in the child process.
        ((char*)mmaped_page)[0] = 3;
        KERNEL_GDB("stopi off");
        KERNEL_BREAKPOINT_UNSET("__alloc_pages_nodemask");
        KERNEL_BREAKPOINT_UNSET("handle_mm_fault");
        mmapped_struct_page = (void*)(SM_CALL(get_struct_page, (unsigned long)mmaped_page));
        KERNEL_GDB("print *(struct page*)%p", mmapped_struct_page);
        KERNEL_BREAKPOINT(2);
    } else {
        SA_LOG(MIN_VERBOSITY, "child (fork): %ld\n", child);
        if (waitpid(-1, &status_code, 0) == -1) {
            SA_LOG(MIN_VERBOSITY, "Waitpid failed\n");
        }
    }
    goto success;
error:
    ret = TEST_ERROR;
    goto cleanup;
success:
    ret = TEST_SUCCESS;
cleanup:
    if (mmaped_page != MAP_FAILED) {
        SM_SYS(munmap, mmaped_page, mmap_allocation_chunk);
    }
    if (child == 0) {
        exit(0);
    }
    return ret;
}

static int merge_vma_area_structs_test(void) {
    int ret = TEST_ERROR;
    void* mmaped_page = MAP_FAILED, *new_mmaped_page = MAP_FAILED,
            *req_new_mmaped_page = MAP_FAILED;
    long mmap_allocation_chunk = page_size * 3;
    mmaped_page = (void*)SM_SYS(mmap, NULL, mmap_allocation_chunk, PROT_READ |
            PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
    if (mmaped_page == MAP_FAILED) {
        goto error;
    }
    // Free 1 page counting from the end, so there is space for the new
    // allocation that will generate the vm_area_struct merge.
    mmap_allocation_chunk -= page_size;
    SM_SYS(munmap, ((char*)mmaped_page) + mmap_allocation_chunk,
            page_size);
    SA_LOG(MIN_VERBOSITY, "mmaped_page: %p\n", mmaped_page);
    req_new_mmaped_page = (void*)(((char*)mmaped_page) + mmap_allocation_chunk);
    KERNEL_BREAKPOINT_SET("vma_merge");
    KERNEL_BREAKPOINT_SET("is_mergeable_anon_vma");
    KERNEL_BREAKPOINT_SET("__vma_adjust");
    new_mmaped_page = (void*)SM_SYS(mmap, req_new_mmaped_page,
                page_size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS |
                MAP_PRIVATE | MAP_FIXED_NOREPLACE, 0, 0);
    KERNEL_BREAKPOINT_UNSET("__vma_adjust");
    KERNEL_BREAKPOINT_UNSET("is_mergeable_anon_vma");
    KERNEL_BREAKPOINT_UNSET("vma_merge");
    if (new_mmaped_page != req_new_mmaped_page || new_mmaped_page == MAP_FAILED) {
        new_mmaped_page = MAP_FAILED;
        goto error;
    }
    SA_LOG(MIN_VERBOSITY, "new_mmaped_page: %p\n", new_mmaped_page);
    goto success;
error:
    ret = TEST_ERROR;
    goto cleanup;
success:
    ret = TEST_SUCCESS;
cleanup:
    if (mmaped_page != MAP_FAILED) {
        SM_SYS(munmap, mmaped_page, mmap_allocation_chunk);
    }
    if (new_mmaped_page != MAP_FAILED) {
        SM_SYS(munmap, new_mmaped_page, page_size);
    }
    return ret;
}

static int dump_memory_structures_test(void) {
    SM_CALL(show_memory_structures);
    return TEST_SUCCESS;
}

static int file_backed_memory_allocation_test(void) {
    #define TEST_FILE_DIR_PATH "/tmp/"
    //#define TEST_FILE_DIR_PATH "/home/test/tmp/"
    #define TEST_FILE_NAME "mapped_reading_test_file"
    #define TEST_FILE_CONTENT "abc"
    int ret = TEST_ERROR;
    char buff[4096];
    void* test_file_mmapped_addr = MAP_FAILED;
    void* mmapped_struct_page = NULL;
    int bytes_read;
    char byte_read_from_memory;

    // Create file, write some content, read to check and reset cursor.
    int test_file_fd = SM_SYS(open, TEST_FILE_DIR_PATH TEST_FILE_NAME,
            O_CREAT | O_TRUNC | O_RDWR | O_SYNC, 0);
    SA_LOG(MIN_VERBOSITY, "test_file_fd: %d\n", test_file_fd);
    if (test_file_fd == -1) {
        SA_LOG(MIN_VERBOSITY, "Error creating the test file\n");
        goto error;
    }
    if (SM_SYS(ftruncate, test_file_fd, page_size) == -1) {
        SA_LOG(MIN_VERBOSITY, "Error truncating the test file to %d\n", page_size);
        goto error;
    }
    memset(buff, 0, sizeof(buff));
    if (SM_SYS(lseek, test_file_fd, 0, SEEK_SET) == (off_t) -1) {
        SA_LOG(MIN_VERBOSITY, "Error lseeking the test file.\n");
        goto error;
    }
    KERNEL_BREAKPOINT_SET("__alloc_pages_nodemask");
    // See if the read generates a struct page allocation
    bytes_read = SM_SYS(read, test_file_fd, buff, 1);
    KERNEL_BREAKPOINT_UNSET("__alloc_pages_nodemask");
    if (bytes_read != 1) {
        SA_LOG(MIN_VERBOSITY, "Bytes read different than expected.\n");
        goto error;
    }
    SA_LOG(MIN_VERBOSITY, "Char read from memory: 0x%x\n", ((int)buff[0]) & 0xFF);
    if (SM_SYS(lseek, test_file_fd, 0, SEEK_SET) == (off_t) -1) {
        SA_LOG(MIN_VERBOSITY, "Error lseeking the test file.\n");
        goto error;
    }
    memset(buff, 0, sizeof(buff));
    strcpy(buff, TEST_FILE_CONTENT);
    int bytes_to_be_written = strlen(buff);
    KERNEL_BREAKPOINT_SET("__alloc_pages_nodemask");
    int bytes_written = SM_SYS(write, test_file_fd, buff, bytes_to_be_written);
    KERNEL_BREAKPOINT_UNSET("__alloc_pages_nodemask");
    if (bytes_written != bytes_to_be_written) {
        SA_LOG(MIN_VERBOSITY, "Error writing test file. Expected to be written: %d," \
                " Actually written: %d\n", bytes_to_be_written, bytes_written);
        goto error;
    }
    memset(buff, 0, sizeof(buff));
    if (SM_SYS(lseek, test_file_fd, 0, SEEK_SET) == (off_t) -1) {
        SA_LOG(MIN_VERBOSITY, "Error lseeking the test file.\n");
        goto error;
    }
    bytes_read = SM_SYS(read, test_file_fd, buff, bytes_to_be_written);
    if (bytes_read != bytes_to_be_written) {
        SA_LOG(MIN_VERBOSITY, "Error reading the test file. Expected to be read: %d," \
                " Actually read: %d\n", bytes_to_be_written, bytes_read);
        goto error;
    }
    SA_LOG(MIN_VERBOSITY, "Test file read content: %s\n", buff);
    if (strcmp(buff, TEST_FILE_CONTENT) != 0) {
        SA_LOG(MIN_VERBOSITY, "Test file content read is different than expected\n");
        goto error;
    }

    // Create file mappings
    KERNEL_BREAKPOINT_SET("do_mmap");
    KERNEL_BREAKPOINT_SET("mmap_region");
    test_file_mmapped_addr = (void*)SM_SYS(mmap, NULL, page_size, PROT_READ, MAP_SHARED, test_file_fd, 0);
    KERNEL_BREAKPOINT_UNSET("mmap_region");
    KERNEL_BREAKPOINT_UNSET("do_mmap");
    if (test_file_mmapped_addr == MAP_FAILED) {
        SA_LOG(MIN_VERBOSITY, "Test file mapping failed\n");
        goto error;
    } else {
        SA_LOG(MIN_VERBOSITY, "test_file_mmapped_addr: %p\n", test_file_mmapped_addr);
    }

    // Read from memory and from file
    byte_read_from_memory = *((const char*)test_file_mmapped_addr);
    SA_LOG(MIN_VERBOSITY, "Char read from memory: %c\n", byte_read_from_memory);
    memset(buff, 0, sizeof(buff));
    if (SM_SYS(lseek, test_file_fd, 0, SEEK_SET) == (off_t) -1) {
        SA_LOG(MIN_VERBOSITY, "Error lseeking the test file.\n");
        goto error;
    }
    bytes_read = SM_SYS(read, test_file_fd, buff, 1);
    if (bytes_read != 1) {
        SA_LOG(MIN_VERBOSITY, "Error reading the test file. Expected to be read: %d," \
                " Actually read: %d\n", bytes_to_be_written, bytes_read);
        goto error;
    }
    SA_LOG(MIN_VERBOSITY, "Test file read content: %s\n", buff);
    if (byte_read_from_memory != buff[0]) {
        SA_LOG(MIN_VERBOSITY, "Error reading the test file. Byte read from memory is " \
                "different than from file\n");
        goto error;
    }
    mmapped_struct_page = (void*)(SM_CALL(get_struct_page, (unsigned long)test_file_mmapped_addr));
    KERNEL_GDB("print *(struct page*)%p", mmapped_struct_page);
    KERNEL_BREAKPOINT(3);
    goto success;
error:
    ret = TEST_ERROR;
    goto cleanup;
success:
    ret = TEST_SUCCESS;
cleanup:
    if (test_file_mmapped_addr != MAP_FAILED)
        SM_SYS(munmap, test_file_mmapped_addr, page_size);
    if (test_file_fd != -1)
        close(test_file_fd);
    SM_SYS(unlink, TEST_FILE_DIR_PATH TEST_FILE_NAME);
    return ret;
}
