/*
 *   Martin Balao (martin.uy) - Copyright 2020, 2024
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

#include "simplelib.h"
#include "simplemodule.h"

static int count_network_packets(void);

int main(void) {
    int ret;
    SA_LOG(MAX_VERBOSITY, "main - begin\n");

    count_network_packets();

    goto success;
error:
    ret = -1;
    SA_LOG(MIN_VERBOSITY, "main - end error\n");
    goto cleanup;
success:
    ret = 0;
    SA_LOG(MAX_VERBOSITY, "main - end success\n");
cleanup:
    return ret;
}

/* The code below is based on the Kernel's samples/sock_example.c. */

/* eBPF example program:
 * - creates arraymap in kernel with key 4 bytes and value 8 bytes
 *
 * - loads eBPF program:
 *   r0 = skb->data[ETH_HLEN + offsetof(struct iphdr, protocol)];
 *   *(u32*)(fp - 4) = r0;
 *   // assuming packet is IPv4, lookup ip->proto in a map
 *   value = bpf_map_lookup_elem(map_fd, fp - 4);
 *   if (value)
 *        (*(u64*)value) += 1;
 *
 * - attaches this program to loopback interface "lo" raw socket
 *
 * - every second user space reads map[tcp], map[udp], map[icmp] to see
 *   how many packets of given protocol were seen on "lo"
 */
#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <linux/bpf.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <stddef.h>
#include <bpf/bpf.h>
#include "bpf_insn.h"
#include "sock_example.h"
#include "bpf_util.h"

char bpf_log_buf[BPF_LOG_BUF_SIZE];

static int test_sock(void)
{
    int sock = -1, map_fd, prog_fd, i, key;
    long long value = 0, tcp_cnt, udp_cnt, icmp_cnt;

    map_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, NULL, sizeof(key), sizeof(value),
                256, NULL);
    if (map_fd < 0) {
        printf("failed to create map '%s'\n", strerror(errno));
        goto cleanup;
    }

    struct bpf_insn prog[] = {
        BPF_MOV64_REG(BPF_REG_6, BPF_REG_1),
        BPF_LD_ABS(BPF_B, ETH_HLEN + offsetof(struct iphdr, protocol) /* R0 = ip->proto */),
        BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_0, -4), /* *(u32 *)(fp - 4) = r0 */
        BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4), /* r2 = fp - 4 */
        BPF_LD_MAP_FD(BPF_REG_1, map_fd),
        BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
        BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 2),
        BPF_MOV64_IMM(BPF_REG_1, 1), /* r1 = 1 */
        BPF_ATOMIC_OP(BPF_DW, BPF_ADD, BPF_REG_0, BPF_REG_1, 0),
        BPF_MOV64_IMM(BPF_REG_0, 0), /* r0 = 0 */
        BPF_EXIT_INSN(),
    };
    size_t insns_cnt = ARRAY_SIZE(prog);
    LIBBPF_OPTS(bpf_prog_load_opts, opts,
        .log_buf = bpf_log_buf,
        .log_size = BPF_LOG_BUF_SIZE,
    );

    //KERNEL_BREAKPOINT_SET("__sys_bpf");
    KERNEL_BREAKPOINT_SET("bpf_check");
    KERNEL_BREAKPOINT_SET("bpf_int_jit_compile");
    KERNEL_GDB("stopi on");
    prog_fd = bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER, NULL, "GPL",
                prog, insns_cnt, &opts);
    KERNEL_GDB("stopi off");
    KERNEL_BREAKPOINT_UNSET("bpf_int_jit_compile");
    KERNEL_BREAKPOINT_UNSET("bpf_check");
    //KERNEL_BREAKPOINT_UNSET("__sys_bpf");
    if (prog_fd < 0) {
        printf("failed to load prog '%s'\n", strerror(errno));
        goto cleanup;
    }

    sock = open_raw_sock("lo");

    if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd,
               sizeof(prog_fd)) < 0) {
        printf("setsockopt %s\n", strerror(errno));
        goto cleanup;
    }

    for (i = 0; i < 10; i++) {
        key = IPPROTO_TCP;
        assert(bpf_map_lookup_elem(map_fd, &key, &tcp_cnt) == 0);

        key = IPPROTO_UDP;
        assert(bpf_map_lookup_elem(map_fd, &key, &udp_cnt) == 0);

        key = IPPROTO_ICMP;
        assert(bpf_map_lookup_elem(map_fd, &key, &icmp_cnt) == 0);

        printf("TCP %lld UDP %lld ICMP %lld packets\n",
               tcp_cnt, udp_cnt, icmp_cnt);
        sleep(1);
    }

cleanup:
    /* maps, programs, raw sockets will auto cleanup on process exit */
    return 0;
}

static const char bpf_jit_option_enable[] = "1";
static int bpf_jit_enable(void) {
    int ret;
    FILE* fp = NULL;
    size_t fp_written;
    fp = fopen("/proc/sys/net/core/bpf_jit_enable", "w");
    if (fp == NULL) {
        goto error;
    }
    fp_written = fwrite(bpf_jit_option_enable, sizeof(bpf_jit_option_enable[0]), strlen(bpf_jit_option_enable), fp);
    if (fp_written != strlen(bpf_jit_option_enable)) {
        goto error;
    }
    goto success;
error:
    ret = -1;
    SA_LOG(MIN_VERBOSITY, "bpf_jit_enable - end error\n");
    goto cleanup;
success:
    ret = 0;
    SA_LOG(MAX_VERBOSITY, "bpf_jit_enable - end success\n");
cleanup:
    if (fp != NULL) {
        fclose(fp);
    }
    return ret;
}

__attribute__((noinline))
static int count_network_packets() {
    FILE *f;

    // Not needed if CONFIG_BPF_JIT_ALWAYS_ON=y
    bpf_jit_enable();

    f = popen("ping -4 -c5 localhost", "r");
    (void)f;

    return test_sock();
}
