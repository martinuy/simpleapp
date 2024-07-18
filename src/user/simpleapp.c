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
#include <semaphore.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "simplelib.h"
#include "simplemodule.h"

#define TEST_ERROR -1
#define TEST_SUCCESS 0

#define EXECUTE_TEST(test) \
  if (test() == TEST_ERROR) \
      goto error;

typedef enum fs_type {TMPFS, EXT4} fs_type_t;

static int initialize_globals(void);
static int create_blank_file_helper(fs_type_t fs_type,
        const char* fs_dir, int* fd_ptr, int flags);

static long page_size;
static const char* user_home_dir;

static int initialize_globals(void) {
    int ret = TEST_ERROR;
    page_size = sysconf(_SC_PAGE_SIZE);
    user_home_dir = getenv("HOME");
    if (user_home_dir == NULL) {
        goto error;
    }
    goto success;
error:
    ret = TEST_ERROR;
    goto cleanup;
success:
    ret = TEST_SUCCESS;
cleanup:
    return ret;
}

static int submit_bio_test(void) {
    int ret = TEST_ERROR;
    long sys_ret;
    char buff[256];
    int test_file_fd = -1;
    if (create_blank_file_helper(EXT4, user_home_dir, &test_file_fd, 0) == TEST_ERROR) {
        goto error;
    }
    memset(buff, 'a', sizeof(buff));
    if (SM_SYS(write, test_file_fd, buff, sizeof(buff)) < 0) {
        goto error;
    }
    KERNEL_BREAKPOINT_SET("mpage_prepare_extent_to_map");
    KERNEL_BREAKPOINT_SET("bio_add_page");
    KERNEL_BREAKPOINT_SET("submit_bio");
    sys_ret = SM_SYS(fsync, test_file_fd);
    KERNEL_BREAKPOINT_UNSET("submit_bio");
    KERNEL_BREAKPOINT_UNSET("bio_add_page");
    KERNEL_BREAKPOINT_UNSET("mpage_prepare_extent_to_map");
    if (sys_ret != 0) {
        goto error;
    }
    goto success;
error:
    ret = TEST_ERROR;
    goto cleanup;
success:
    ret = TEST_SUCCESS;
cleanup:
    if (test_file_fd != -1) {
        close(test_file_fd);
    }
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
    KERNEL_GDB("break *(handle_mm_fault+3952)");
    KERNEL_BREAKPOINT_SET("__alloc_pages_nodemask");
    KERNEL_GDB("stopi on");
    *((char*)mmaped_page) = 1;
    KERNEL_GDB("stopi off");
    KERNEL_BREAKPOINT_UNSET("__alloc_pages_nodemask");
    KERNEL_GDB("delete breakpoint *(handle_mm_fault+3952)");
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

static int create_blank_file_helper(fs_type_t fs_type,
        const char* fs_dir, int* fd_ptr, int flags) {
    #define TEST_FILE_NAME "test_file"
    int ret = TEST_ERROR;
    int test_file_fd = -1;
    long sys_ret;
    char* file_path = (char*)malloc(strlen(fs_dir) + 1 + sizeof(TEST_FILE_NAME));
    if (file_path == NULL) {
        goto error;
    }
    *file_path = '\0';
    strcat(file_path, fs_dir);
    strcat(file_path, "/");
    strcat(file_path, TEST_FILE_NAME);
    SA_LOG(MIN_VERBOSITY, "Opening file: %s\n", file_path);
    test_file_fd = SM_SYS(open, file_path,
            O_CREAT | O_TRUNC | O_RDWR | flags, 0);
    SA_LOG(MIN_VERBOSITY, "test_file_fd: %d\n", test_file_fd);
    if (test_file_fd < 0) {
        SA_LOG(MIN_VERBOSITY, "Error creating the test file\n");
        goto error;
    }
    sys_ret = SM_SYS(ftruncate, test_file_fd, page_size);
    if (sys_ret == -1) {
        SA_LOG(MIN_VERBOSITY, "Error truncating the test file to %d\n", page_size);
        goto error;
    }
    if (SM_SYS(lseek, test_file_fd, 0, SEEK_SET) == (off_t) -1) {
        SA_LOG(MIN_VERBOSITY, "Error lseeking the test file.\n");
        goto error;
    }
    *fd_ptr = dup(test_file_fd);
    goto success;
error:
    ret = TEST_ERROR;
    goto cleanup;
success:
    ret = TEST_SUCCESS;
cleanup:
    if (test_file_fd >= 0) {
        close(test_file_fd);
    }
    if (file_path != NULL) {
        SM_SYS(unlink, file_path);
        free(file_path);
    }
    return ret;
}

static int file_backed_memory_allocation_test(fs_type_t fs_type,
        const char* fs_dir) {
    #define TEST_FILE_CONTENT "abc"
    int ret = TEST_ERROR;
    char buff[4096];
    void* test_file_mmapped_addr = MAP_FAILED;
    void* mmapped_struct_page = NULL;
    int bytes_read;
    char byte_read_from_memory;
    int test_file_fd = -1;
    if (create_blank_file_helper(fs_type, fs_dir, &test_file_fd, O_SYNC)
            == TEST_ERROR) {
        goto error;
    }
    memset(buff, 0, sizeof(buff));
    KERNEL_BREAKPOINT_SET("new_sync_read");
    KERNEL_BREAKPOINT_SET("copy_page_to_iter");
    if (fs_type == TMPFS) {
        KERNEL_BREAKPOINT_SET("shmem_file_read_iter");
        KERNEL_BREAKPOINT_SET("shmem_getpage_gfp");
    } else if (fs_type == EXT4) {
        KERNEL_BREAKPOINT_SET("ext4_file_read_iter");
        KERNEL_BREAKPOINT_SET("generic_file_buffered_read");
        KERNEL_BREAKPOINT_SET("ext4_mpage_readpages");
        KERNEL_BREAKPOINT_SET("ext4_map_blocks");
        KERNEL_BREAKPOINT_SET("ext4_find_extent");
        KERNEL_BREAKPOINT_SET("ext4_ext_put_gap_in_cache");
    }
    // See if the read generates a struct page allocation
    bytes_read = SM_SYS(read, test_file_fd, buff, 1);
    if (fs_type == TMPFS) {
        KERNEL_BREAKPOINT_UNSET("shmem_getpage_gfp");
        KERNEL_BREAKPOINT_UNSET("shmem_file_read_iter");
    } else if (fs_type == EXT4) {
        KERNEL_BREAKPOINT_UNSET("ext4_ext_put_gap_in_cache");
        KERNEL_BREAKPOINT_UNSET("ext4_find_extent");
        KERNEL_BREAKPOINT_UNSET("ext4_map_blocks");
        KERNEL_BREAKPOINT_UNSET("ext4_mpage_readpages");
        KERNEL_BREAKPOINT_UNSET("generic_file_buffered_read");
        KERNEL_BREAKPOINT_UNSET("ext4_file_read_iter");
    }
    KERNEL_BREAKPOINT_UNSET("copy_page_to_iter");
    KERNEL_BREAKPOINT_UNSET("new_sync_read");
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
    if (fs_type != EXT4) {
        KERNEL_BREAKPOINT_SET("__alloc_pages_nodemask");
    }
    int bytes_written = SM_SYS(write, test_file_fd, buff, bytes_to_be_written);
    if (fs_type != EXT4) {
        KERNEL_BREAKPOINT_UNSET("__alloc_pages_nodemask");
    }
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
    if (fs_type == TMPFS) {
        KERNEL_BREAKPOINT_SET("shmem_fault");
    } else if (fs_type == EXT4) {
        KERNEL_BREAKPOINT_SET("ext4_filemap_fault");
    }
    KERNEL_BREAKPOINT_SET("filemap_map_pages");
    KERNEL_BREAKPOINT_SET("alloc_set_pte");
    KERNEL_GDB("stopi on");
    byte_read_from_memory = *((const char*)test_file_mmapped_addr);
    KERNEL_GDB("stopi off");
    KERNEL_BREAKPOINT_UNSET("alloc_set_pte");
    KERNEL_BREAKPOINT_UNSET("filemap_map_pages");
    if (fs_type == TMPFS) {
        KERNEL_BREAKPOINT_UNSET("shmem_fault");
    } else if (fs_type == EXT4) {
        KERNEL_BREAKPOINT_UNSET("ext4_filemap_fault");
    }
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
    if (fs_type == EXT4) {
        KERNEL_GDB("print *(struct buffer_head*)(((struct page*)%p)->private)", mmapped_struct_page);
        system("lsblk -a");
        KERNEL_GDB("x/s ((struct buffer_head*)(((struct page*)%p)->private))->b_bdev->bd_bdi->dev_name", mmapped_struct_page);
    }
    KERNEL_BREAKPOINT(3);
    goto success;
error:
    ret = TEST_ERROR;
    goto cleanup;
success:
    ret = TEST_SUCCESS;
cleanup:
    if (test_file_mmapped_addr != MAP_FAILED) {
        SM_SYS(munmap, test_file_mmapped_addr, page_size);
    }
    if (test_file_fd >= 0) {
        close(test_file_fd);
    }
    return ret;
}

static int file_backed_memory_allocation_ext4_test(void) {
    return file_backed_memory_allocation_test(EXT4, user_home_dir);
}

static int file_backed_memory_allocation_tmpfs_test(void) {
    return file_backed_memory_allocation_test(TMPFS, P_tmpdir);
}

static int pte_entry_states_transition_test(void) {
    int ret = TEST_ERROR;
    long sys_ret;
    int child = -1;
    int test_file_fd = -1;
    void* shared_page = MAP_FAILED;
    sem_t* shared_sem_child = NULL;
    sem_t* shared_sem_parent = NULL;
    int sem_ret;
    int* shared_parent_wrote = NULL;
    int status_code = 0;
    void* test_file_mmapped_addr = MAP_FAILED;
    unsigned long page_table_entries[5];
    if (create_blank_file_helper(EXT4, user_home_dir, &test_file_fd, 0) == TEST_ERROR) {
        goto error;
    }
    test_file_mmapped_addr = (void*)SM_SYS(mmap, NULL, page_size * 2, PROT_READ | PROT_WRITE, MAP_SHARED, test_file_fd, 0);
    if ((long)test_file_mmapped_addr < 0L) {
        SA_LOG(MIN_VERBOSITY, "Test file mapping failed\n");
        test_file_mmapped_addr = MAP_FAILED;
        goto error;
    } else {
        SA_LOG(MIN_VERBOSITY, "test_file_mmapped_addr: %p\n", test_file_mmapped_addr);
    }
    // At this point, the pte entry is 0x0 (no mapping).

    // How to check the pte entry value in a native_set_pte_at breakpoint?
    // The pte entry is in $rcx. Thus, (gdb) print (($rcx & (1 << BIT_TO_CHECK)) != 0)
    // See BIT_TO_CHECK values in pgtable_types.h.

    if (SM_CALL(get_page_tables_entry, (unsigned long)test_file_mmapped_addr,
            0UL, (unsigned long)page_table_entries) == SAMODULE_ERROR) {
        goto error;
    }
    SA_LOG(MIN_VERBOSITY, "Parent pre-write page tables entry: 0x%016lx\n",
            page_table_entries[page_table_entries[4]]);
    SA_LOG(MIN_VERBOSITY, "Parent writing test_file_mmapped_addr[0]\n");
    //KERNEL_BREAKPOINT_SET("native_set_pte_at");
    KERNEL_BREAKPOINT_SET("ext4_da_get_block_prep");
    KERNEL_BREAKPOINT_SET("set_page_dirty");
    KERNEL_BREAKPOINT_SET("__set_page_dirty_buffers");
    KERNEL_GDB("stopi on");
    *((char*)test_file_mmapped_addr) = 'a';
    KERNEL_GDB("stopi off");
    KERNEL_BREAKPOINT_UNSET("__set_page_dirty_buffers");
    KERNEL_BREAKPOINT_UNSET("set_page_dirty");
    KERNEL_BREAKPOINT_SET("ext4_da_get_block_prep");
    //KERNEL_BREAKPOINT_UNSET("native_set_pte_at");
    SA_LOG(MIN_VERBOSITY, "Parent wrote test_file_mmapped_addr[0] = %c\n", *(char*)test_file_mmapped_addr);
    if (SM_CALL(get_page_tables_entry, (unsigned long)test_file_mmapped_addr,
            0UL, (unsigned long)page_table_entries) == SAMODULE_ERROR) {
        goto error;
    }
    SA_LOG(MIN_VERBOSITY, "Parent post-write page tables entry: 0x%016lx\n",
            page_table_entries[page_table_entries[4]]);
    // At this point, a page fault occurred and the pte entry points to the page cache's page.
    // The pte entry has the _PAGE_BIT_DIRTY (bit 6) and _PAGE_BIT_RW (bit 1) bits set.

    //KERNEL_BREAKPOINT("fsync coming...");
    //KERNEL_BREAKPOINT_SET("native_set_pte_at");
    sys_ret = SM_SYS(fsync, test_file_fd);
    //KERNEL_BREAKPOINT_UNSET("native_set_pte_at");
    if (sys_ret != 0) {
        goto error;
    }
    if (SM_CALL(get_page_tables_entry, (unsigned long)test_file_mmapped_addr,
            0UL, (unsigned long)page_table_entries) == SAMODULE_ERROR) {
        goto error;
    }
    SA_LOG(MIN_VERBOSITY, "Parent post-fsync page tables entry: 0x%016lx\n",
            page_table_entries[page_table_entries[4]]);
    // The pte entry is similar to the previous value but has the _PAGE_BIT_DIRTY (bit 6) and _PAGE_BIT_RW bits (bit 1) unset.

    shared_page = (void*)SM_SYS(mmap, NULL, page_size, PROT_READ |
            PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, 0, 0);
    if ((long)shared_page < 0L) {
        shared_page = MAP_FAILED;
        goto error;
    }
    shared_sem_child = (sem_t*)shared_page;
    shared_sem_parent = (sem_t*)((char*)shared_page + sizeof(sem_t));
    if (sem_init(shared_sem_child, 1, 0) != 0) {
        SA_LOG(MIN_VERBOSITY, "Sem initialization failed\n");
        shared_sem_child = NULL;
        goto error;
    }
    if (sem_init(shared_sem_parent, 1, 0) != 0) {
        SA_LOG(MIN_VERBOSITY, "Sem initialization failed\n");
        shared_sem_parent = NULL;
        goto error;
    }

    SA_LOG(MIN_VERBOSITY, "Forking process...\n");
    child = fork();
    if (child == 0) {
        if (SM_CALL(get_page_tables_entry, (unsigned long)test_file_mmapped_addr,
                0UL, (unsigned long)page_table_entries) == SAMODULE_ERROR) {
            goto error;
        }
        SA_LOG(MIN_VERBOSITY, "Child pre-read page tables entry: 0x%016lx\n",
                page_table_entries[page_table_entries[4]]);
        SA_LOG(MIN_VERBOSITY, "Child read test_file_mmapped_addr[0] = %c\n", *(char*)test_file_mmapped_addr);
        if (SM_CALL(get_page_tables_entry, (unsigned long)test_file_mmapped_addr,
                0UL, (unsigned long)page_table_entries) == SAMODULE_ERROR) {
            goto error;
        }
        SA_LOG(MIN_VERBOSITY, "Child post-read page tables entry: 0x%016lx\n",
                page_table_entries[page_table_entries[4]]);

        if (sem_post(shared_sem_parent) != 0) {
            SA_LOG(MIN_VERBOSITY, "sem_post failed\n");
            goto error;
        }

        SA_LOG(MIN_VERBOSITY, "Child waiting for parent to write: started\n");
        while ((sem_ret = sem_wait(shared_sem_child)) == -1 && errno == EINTR) {
            SA_LOG(MIN_VERBOSITY, "sem_wait retry\n");
            continue;
        }
        if (sem_ret != 0) {
            SA_LOG(MIN_VERBOSITY, "sem_wait failed\n");
            goto error;
        }
        SA_LOG(MIN_VERBOSITY, "Child waiting for parent to write: finished\n");

        if (SM_CALL(get_page_tables_entry, (unsigned long)test_file_mmapped_addr,
                0UL, (unsigned long)page_table_entries) == SAMODULE_ERROR) {
            goto error;
        }
        SA_LOG(MIN_VERBOSITY, "Child post-parent-write page tables entry: 0x%016lx\n",
                page_table_entries[page_table_entries[4]]);
        SA_LOG(MIN_VERBOSITY, "Child post-parent-write read test_file_mmapped_addr[0] = %c\n", *(char*)test_file_mmapped_addr);
    } else if (child != -1) {
        SA_LOG(MIN_VERBOSITY, "Parent waiting for child to read: started\n");
        while ((sem_ret = sem_wait(shared_sem_parent)) == -1 && errno == EINTR) {
            SA_LOG(MIN_VERBOSITY, "sem_wait retry\n");
            continue;
        }
        if (sem_ret != 0) {
            SA_LOG(MIN_VERBOSITY, "sem_wait failed\n");
            goto error;
        }
        SA_LOG(MIN_VERBOSITY, "Parent waiting for child to read: finished\n");

        // Dirty the page one more time!
        SA_LOG(MIN_VERBOSITY, "Parent writing test_file_mmapped_addr[0]\n");
        //KERNEL_BREAKPOINT_SET("native_set_pte");
        //KERNEL_GDB("stopi on");
        *(char*)test_file_mmapped_addr = 'b';
        //KERNEL_GDB("stopi off");
        //KERNEL_BREAKPOINT_SET("native_set_pte");
        SA_LOG(MIN_VERBOSITY, "Parent wrote test_file_mmapped_addr[0] = %c\n", *(char*)test_file_mmapped_addr);
        if (SM_CALL(get_page_tables_entry, (unsigned long)test_file_mmapped_addr,
                0UL, (unsigned long)page_table_entries) == SAMODULE_ERROR) {
            goto error;
        }
        SA_LOG(MIN_VERBOSITY, "Parent post-write page tables entry: 0x%016lx\n",
                page_table_entries[page_table_entries[4]]);
        if (sem_post(shared_sem_child) != 0) {
            SA_LOG(MIN_VERBOSITY, "sem_post failed\n");
            goto error;
        }
        SA_LOG(MIN_VERBOSITY, "Parent waiting for child to finish: started\n");
        if (waitpid(child, &status_code, 0) == -1) {
            SA_LOG(MIN_VERBOSITY, "Parent waiting for child to finish: failed\n");
        }
        SA_LOG(MIN_VERBOSITY, "Parent waiting for child to finish: finished\n");
    }
    goto success;
error:
    ret = TEST_ERROR;
    goto cleanup;
success:
    ret = TEST_SUCCESS;
cleanup:
    if (test_file_mmapped_addr != MAP_FAILED) {
        SM_SYS(munmap, test_file_mmapped_addr, page_size);
    }
    if (test_file_fd >= 0) {
        close(test_file_fd);
    }
    if (child == 0) {
        if (shared_page != MAP_FAILED) {
            SM_SYS(munmap, shared_page, page_size);
        }
        exit(0);
    } else if (child != -1) {
        if (shared_sem_child != NULL) {
            sem_destroy(shared_sem_child);
        }
        if (shared_sem_parent != NULL) {
            sem_destroy(shared_sem_parent);
        }
        if (shared_page != MAP_FAILED) {
            SM_SYS(munmap, shared_page, page_size);
        }
    }
    return ret;
}

int main(void) {
    int ret;
    SA_LOG(MIN_VERBOSITY, "main - begin\n");

    if (initialize_globals() == TEST_ERROR) {
        goto error;
    }

    ///////////////
    //   Tests   //
    ///////////////

    //EXECUTE_TEST(merge_vma_area_structs_test);

    EXECUTE_TEST(dump_memory_structures_test);

    //EXECUTE_TEST(fork_copy_on_write_test);

    //EXECUTE_TEST(file_backed_memory_allocation_tmpfs_test);

    //EXECUTE_TEST(file_backed_memory_allocation_ext4_test);

    //EXECUTE_TEST(pte_entry_states_transition_test);

    //EXECUTE_TEST(submit_bio_test);

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
