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
#define _GNU_SOURCE

#include <asm/types.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/mqueue.h>
#include <linux/netlink.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "simpleapp_syscalls.h"
#include "simplelib.h"
#include "simplemodule.h"

static void execute_module_asm_hook(void);
static void execute_module_code_hook(void);
static void execute_proxied_syscalls_hook(void);
static void execute_direct_syscalls_hook(void);
static void execute_direct_asm_hook(void);

int main(void) {
    int ret = -1;
    SA_LOG(MAX_VERBOSITY, "main - begin\n");

    if (load_module() == SLIB_ERROR)
        goto error;

    BREAKPOINT(1);

    execute_proxied_syscalls_hook();

    execute_module_asm_hook();

    execute_module_code_hook();

    execute_direct_asm_hook();

    execute_direct_syscalls_hook();

    goto success;
error:
    SA_LOG(MIN_VERBOSITY, "main - end error\n");
    ret = -1;
    goto cleanup;
success:
    SA_LOG(MAX_VERBOSITY, "main - end success\n");
    ret = 0;
cleanup:
    unload_module();
    return ret;
}

__attribute__((noinline))
void execute_module_asm_hook(void) {
    module_test_data_t module_test_data = {0x0};
    module_test_data.test_number = TEST_MODULE_ASM;
    if (run_module_test(&module_test_data) == SLIB_ERROR)
        goto error;
    print_module_output();
    SA_LOG(MIN_VERBOSITY, "TEST_MODULE_ASM return: 0x%lx\n", module_test_data.return_value);
    return;
error:
    SA_LOG(MIN_VERBOSITY, "TEST_MODULE_ASM error\n");
}

__attribute__((noinline))
void execute_module_code_hook(void) {
    module_test_data_t module_test_data = {0x0};
    module_test_data.test_number = TEST_MODULE_CODE;
    if (run_module_test(&module_test_data) == SLIB_ERROR)
        goto error;
    print_module_output();
    SA_LOG(MIN_VERBOSITY, "TEST_MODULE_CODE return: 0x%lx\n", module_test_data.return_value);
    return;
error:
    SA_LOG(MIN_VERBOSITY, "TEST_MODULE_CODE error\n");
}

char* read_buff = NULL;
char* read_buff_ptr = NULL;
#define READ_BUFF_INC_SIZE 1024UL
unsigned long read_buff_size = 0UL;
unsigned long read_buff_used = 0UL;

typedef int mqd_t;
#define MQ_MSG_SIZE 16L
static char mq_send_receive_buffer[MQ_MSG_SIZE];
static unsigned int mq_msg_prio;
static ssize_t mq_bytes_received;
static mqd_t mq1 = (mqd_t)-1;
static const char* mq1_name = "mq1";
static struct mq_attr mq1_attr = {
        .mq_flags = 0L, .mq_maxmsg = 20L, .mq_msgsize = MQ_MSG_SIZE, .mq_curmsgs = 0L
};
static struct mq_attr mq1_attr_2;
static const char* mq1_message_1 = "mq-1 message 1";
static struct timespec mq1_time = {.tv_sec = 0L, .tv_nsec = 0L};
static int mq1_notification_socket = -1;
static char mq1_notification_cookie[NOTIFY_COOKIE_LEN] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
};
static struct sigevent mq1_sevp = {
        .sigev_value.sival_ptr = &mq1_notification_cookie,
        .sigev_signo = 0,
        .sigev_notify = SIGEV_THREAD,
        .sigev_notify_function = NULL,
        .sigev_notify_attributes = NULL
};

__attribute__((noinline))
void execute_proxied_syscalls_hook(void) {
    read_buff_size = READ_BUFF_INC_SIZE;
    if ((read_buff = (char*)malloc(READ_BUFF_INC_SIZE)) == NULL)
        goto error;
    read_buff_ptr = read_buff;

    mq1 = SM_SYS(mq_open, mq1_name, O_RDWR | O_CREAT, S_IRWXU, &mq1_attr);
    if (mq1 == (mqd_t)-1)
        goto error;
    SA_PRINTF("mq1: mq_open %ld\n", (long)mq1);

    if ((mq1_notification_socket = (int)SM_SYS(socket, AF_NETLINK, SOCK_RAW, NETLINK_GENERIC)) == -1)
        goto error;
    SA_PRINTF("mq1: mq1_notification_socket %d\n", mq1_notification_socket);

    mq1_sevp.sigev_signo = mq1_notification_socket;
    if (SM_SYS(mq_notify, mq1, &mq1_sevp) != 0L)
        goto error;

    if (SM_SYS(mq_timedsend, mq1, mq1_message_1, strlen(mq1_message_1) + 1, 0U, &mq1_time) != 0L)
        goto error;
    SA_PRINTF("mq1: mq_timedsend OK\n");

    {
        char notify_status;
        ssize_t bytes_read;
        size_t bytes_expected = NOTIFY_COOKIE_LEN;
        int selected_fds;
        fd_set readfds, writefds, exceptfds;
        if (mq1_notification_socket >= FD_SETSIZE)
            goto error;
        if (read_buff_size < bytes_expected) {
            read_buff_size = bytes_expected;
            read_buff = (char*)realloc(read_buff, read_buff_size);
            if (read_buff == NULL)
                goto error;
            read_buff_ptr = read_buff;
        }
        while (bytes_expected > 0) {
            FD_ZERO(&readfds);
            FD_ZERO(&writefds);
            FD_ZERO(&exceptfds);
            FD_SET(mq1_notification_socket, &readfds);
            while ((selected_fds = (int)SM_SYS(select, mq1_notification_socket + 1, &readfds, &writefds, &exceptfds, NULL)) == -EINTR);
            if (selected_fds <= 0)
                goto error;
            if (FD_ISSET(mq1_notification_socket, &readfds)) {
                while ((bytes_read = SM_SYS(read, mq1_notification_socket, read_buff_ptr, bytes_expected)) == -EINTR);
                if (bytes_read < 0)
                    goto error;
                bytes_expected -= bytes_read;
                read_buff_ptr += bytes_read;
            }
        }
        if (memcmp(read_buff, mq1_notification_cookie, NOTIFY_COOKIE_LEN-1) != 0)
            goto error;
        notify_status = read_buff[NOTIFY_COOKIE_LEN-1];
        if (notify_status == NOTIFY_WOKENUP) {
            SA_PRINTF("mq1_notification NOTIFY_WOKENUP\n");
        } else if (notify_status == NOTIFY_REMOVED) {
            SA_PRINTF("mq1_notification NOTIFY_REMOVED\n");
        } else if (notify_status == NOTIFY_NONE) {
            SA_PRINTF("mq1_notification NOTIFY_NONE\n");
        } else {
            goto error;
        }
    }

    if (SM_SYS(mq_getsetattr, mq1, &mq1_attr, &mq1_attr_2) != 0L)
        goto error;
    SA_PRINTF("mq1: mq_getsetattr GET (mq_flags = %ld, mq_maxmsg = %ld, mq_msgsize = %ld, mq_curmsgs = %ld)\n",
            mq1_attr_2.mq_flags, mq1_attr_2.mq_maxmsg, mq1_attr_2.mq_msgsize, mq1_attr_2.mq_curmsgs);

    if ((mq_bytes_received = SM_SYS(mq_timedreceive, mq1, (char*)mq_send_receive_buffer,
            MQ_MSG_SIZE, &mq_msg_prio, &mq1_time)) < 0L)
        goto error;
    SA_PRINTF("mq1: mq_timedreceive msg bytes: %d\n", mq_bytes_received);
    SA_PRINTF("mq1: mq_timedreceive msg priority: %u\n", mq_msg_prio);
    SA_PRINTF("mq1: mq_timedreceive msg: %s\n", mq_send_receive_buffer);

    /*
    long child_tid = SM_SYS(clone, CLONE_NEWIPC, (void*)0x0, (void*)0x0,
            (void*)0x0, (void*)0x0);
    if (child_tid == -1)
        goto error;
    SA_PRINTF("child_tid: %ld\n", child_tid);
    */
    goto success;

error:
    SA_LOG(MIN_VERBOSITY, "error\n");
    goto cleanup;
success:
    SA_LOG(MAX_VERBOSITY, "success\n");
cleanup:
    if (mq1_notification_socket != -1)
        SM_SYS(close, mq1_notification_socket);
    if (mq1 != (mqd_t)-1) {
        SM_SYS(close, mq1);
        SM_SYS(mq_unlink, mq1_name);
    }
    if (read_buff != NULL)
        free(read_buff);
}

__attribute__((noinline))
void execute_direct_syscalls_hook(void) {
}

__attribute__((noinline))
void execute_direct_asm_hook(void) {
}
