/*
 *   Martin Balao (martin.uy) - Copyright 2022, 2023
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

#ifndef __SIMPLEMODULE_KERNEL_LIB_SYSCALLS_H
#define __SIMPLEMODULE_KERNEL_LIB_SYSCALLS_H

#include <linux/syscalls.h>

#include "simplemodule_kernel_lib.h"

const char* sm_get_syscall_name(unsigned long sys_code) {
    switch(sys_code) {
    #define syscode_case(x) case __NR_##x: return "SYS_"#x;
        // From Linux 4.14.0 headers (x86_64)
        syscode_case(read);
        syscode_case(write);
        syscode_case(open);
        syscode_case(close);
        syscode_case(stat);
        syscode_case(fstat);
        syscode_case(lstat);
        syscode_case(poll);
        syscode_case(lseek);
        syscode_case(mmap);
        syscode_case(mprotect);
        syscode_case(munmap);
        syscode_case(brk);
        syscode_case(rt_sigaction);
        syscode_case(rt_sigprocmask);
        syscode_case(rt_sigreturn);
        syscode_case(ioctl);
        syscode_case(pread64);
        syscode_case(pwrite64);
        syscode_case(readv);
        syscode_case(writev);
        syscode_case(access);
        syscode_case(pipe);
        syscode_case(select);
        syscode_case(sched_yield);
        syscode_case(mremap);
        syscode_case(msync);
        syscode_case(mincore);
        syscode_case(madvise);
        syscode_case(shmget);
        syscode_case(shmat);
        syscode_case(shmctl);
        syscode_case(dup);
        syscode_case(dup2);
        syscode_case(pause);
        syscode_case(nanosleep);
        syscode_case(getitimer);
        syscode_case(alarm);
        syscode_case(setitimer);
        syscode_case(getpid);
        syscode_case(sendfile);
        syscode_case(socket);
        syscode_case(connect);
        syscode_case(accept);
        syscode_case(sendto);
        syscode_case(recvfrom);
        syscode_case(sendmsg);
        syscode_case(recvmsg);
        syscode_case(shutdown);
        syscode_case(bind);
        syscode_case(listen);
        syscode_case(getsockname);
        syscode_case(getpeername);
        syscode_case(socketpair);
        syscode_case(setsockopt);
        syscode_case(getsockopt);
        syscode_case(clone);
        syscode_case(fork);
        syscode_case(vfork);
        syscode_case(execve);
        syscode_case(exit);
        syscode_case(wait4);
        syscode_case(kill);
        syscode_case(uname);
        syscode_case(semget);
        syscode_case(semop);
        syscode_case(semctl);
        syscode_case(shmdt);
        syscode_case(msgget);
        syscode_case(msgsnd);
        syscode_case(msgrcv);
        syscode_case(msgctl);
        syscode_case(fcntl);
        syscode_case(flock);
        syscode_case(fsync);
        syscode_case(fdatasync);
        syscode_case(truncate);
        syscode_case(ftruncate);
        syscode_case(getdents);
        syscode_case(getcwd);
        syscode_case(chdir);
        syscode_case(fchdir);
        syscode_case(rename);
        syscode_case(mkdir);
        syscode_case(rmdir);
        syscode_case(creat);
        syscode_case(link);
        syscode_case(unlink);
        syscode_case(symlink);
        syscode_case(readlink);
        syscode_case(chmod);
        syscode_case(fchmod);
        syscode_case(chown);
        syscode_case(fchown);
        syscode_case(lchown);
        syscode_case(umask);
        syscode_case(gettimeofday);
        syscode_case(getrlimit);
        syscode_case(getrusage);
        syscode_case(sysinfo);
        syscode_case(times);
        syscode_case(ptrace);
        syscode_case(getuid);
        syscode_case(syslog);
        syscode_case(getgid);
        syscode_case(setuid);
        syscode_case(setgid);
        syscode_case(geteuid);
        syscode_case(getegid);
        syscode_case(setpgid);
        syscode_case(getppid);
        syscode_case(getpgrp);
        syscode_case(setsid);
        syscode_case(setreuid);
        syscode_case(setregid);
        syscode_case(getgroups);
        syscode_case(setgroups);
        syscode_case(setresuid);
        syscode_case(getresuid);
        syscode_case(setresgid);
        syscode_case(getresgid);
        syscode_case(getpgid);
        syscode_case(setfsuid);
        syscode_case(setfsgid);
        syscode_case(getsid);
        syscode_case(capget);
        syscode_case(capset);
        syscode_case(rt_sigpending);
        syscode_case(rt_sigtimedwait);
        syscode_case(rt_sigqueueinfo);
        syscode_case(rt_sigsuspend);
        syscode_case(sigaltstack);
        syscode_case(utime);
        syscode_case(mknod);
        syscode_case(uselib);
        syscode_case(personality);
        syscode_case(ustat);
        syscode_case(statfs);
        syscode_case(fstatfs);
        syscode_case(sysfs);
        syscode_case(getpriority);
        syscode_case(setpriority);
        syscode_case(sched_setparam);
        syscode_case(sched_getparam);
        syscode_case(sched_setscheduler);
        syscode_case(sched_getscheduler);
        syscode_case(sched_get_priority_max);
        syscode_case(sched_get_priority_min);
        syscode_case(sched_rr_get_interval);
        syscode_case(mlock);
        syscode_case(munlock);
        syscode_case(mlockall);
        syscode_case(munlockall);
        syscode_case(vhangup);
        syscode_case(modify_ldt);
        syscode_case(pivot_root);
        syscode_case(_sysctl);
        syscode_case(prctl);
        syscode_case(arch_prctl);
        syscode_case(adjtimex);
        syscode_case(setrlimit);
        syscode_case(chroot);
        syscode_case(sync);
        syscode_case(acct);
        syscode_case(settimeofday);
        syscode_case(mount);
        syscode_case(umount2);
        syscode_case(swapon);
        syscode_case(swapoff);
        syscode_case(reboot);
        syscode_case(sethostname);
        syscode_case(setdomainname);
        syscode_case(iopl);
        syscode_case(ioperm);
        syscode_case(create_module);
        syscode_case(init_module);
        syscode_case(delete_module);
        syscode_case(get_kernel_syms);
        syscode_case(query_module);
        syscode_case(quotactl);
        syscode_case(nfsservctl);
        syscode_case(getpmsg);
        syscode_case(putpmsg);
        syscode_case(afs_syscall);
        syscode_case(tuxcall);
        syscode_case(security);
        syscode_case(gettid);
        syscode_case(readahead);
        syscode_case(setxattr);
        syscode_case(lsetxattr);
        syscode_case(fsetxattr);
        syscode_case(getxattr);
        syscode_case(lgetxattr);
        syscode_case(fgetxattr);
        syscode_case(listxattr);
        syscode_case(llistxattr);
        syscode_case(flistxattr);
        syscode_case(removexattr);
        syscode_case(lremovexattr);
        syscode_case(fremovexattr);
        syscode_case(tkill);
        syscode_case(time);
        syscode_case(futex);
        syscode_case(sched_setaffinity);
        syscode_case(sched_getaffinity);
        syscode_case(set_thread_area);
        syscode_case(io_setup);
        syscode_case(io_destroy);
        syscode_case(io_getevents);
        syscode_case(io_submit);
        syscode_case(io_cancel);
        syscode_case(get_thread_area);
        syscode_case(lookup_dcookie);
        syscode_case(epoll_create);
        syscode_case(epoll_ctl_old);
        syscode_case(epoll_wait_old);
        syscode_case(remap_file_pages);
        syscode_case(getdents64);
        syscode_case(set_tid_address);
        syscode_case(restart_syscall);
        syscode_case(semtimedop);
        syscode_case(fadvise64);
        syscode_case(timer_create);
        syscode_case(timer_settime);
        syscode_case(timer_gettime);
        syscode_case(timer_getoverrun);
        syscode_case(timer_delete);
        syscode_case(clock_settime);
        syscode_case(clock_gettime);
        syscode_case(clock_getres);
        syscode_case(clock_nanosleep);
        syscode_case(exit_group);
        syscode_case(epoll_wait);
        syscode_case(epoll_ctl);
        syscode_case(tgkill);
        syscode_case(utimes);
        syscode_case(vserver);
        syscode_case(mbind);
        syscode_case(set_mempolicy);
        syscode_case(get_mempolicy);
        syscode_case(mq_open);
        syscode_case(mq_unlink);
        syscode_case(mq_timedsend);
        syscode_case(mq_timedreceive);
        syscode_case(mq_notify);
        syscode_case(mq_getsetattr);
        syscode_case(kexec_load);
        syscode_case(waitid);
        syscode_case(add_key);
        syscode_case(request_key);
        syscode_case(keyctl);
        syscode_case(ioprio_set);
        syscode_case(ioprio_get);
        syscode_case(inotify_init);
        syscode_case(inotify_add_watch);
        syscode_case(inotify_rm_watch);
        syscode_case(migrate_pages);
        syscode_case(openat);
        syscode_case(mkdirat);
        syscode_case(mknodat);
        syscode_case(fchownat);
        syscode_case(futimesat);
        syscode_case(newfstatat);
        syscode_case(unlinkat);
        syscode_case(renameat);
        syscode_case(linkat);
        syscode_case(symlinkat);
        syscode_case(readlinkat);
        syscode_case(fchmodat);
        syscode_case(faccessat);
        syscode_case(pselect6);
        syscode_case(ppoll);
        syscode_case(unshare);
        syscode_case(set_robust_list);
        syscode_case(get_robust_list);
        syscode_case(splice);
        syscode_case(tee);
        syscode_case(sync_file_range);
        syscode_case(vmsplice);
        syscode_case(move_pages);
        syscode_case(utimensat);
        syscode_case(epoll_pwait);
        syscode_case(signalfd);
        syscode_case(timerfd_create);
        syscode_case(eventfd);
        syscode_case(fallocate);
        syscode_case(timerfd_settime);
        syscode_case(timerfd_gettime);
        syscode_case(accept4);
        syscode_case(signalfd4);
        syscode_case(eventfd2);
        syscode_case(epoll_create1);
        syscode_case(dup3);
        syscode_case(pipe2);
        syscode_case(inotify_init1);
        syscode_case(preadv);
        syscode_case(pwritev);
        syscode_case(rt_tgsigqueueinfo);
        syscode_case(perf_event_open);
        syscode_case(recvmmsg);
        syscode_case(fanotify_init);
        syscode_case(fanotify_mark);
        syscode_case(prlimit64);
        syscode_case(name_to_handle_at);
        syscode_case(open_by_handle_at);
        syscode_case(clock_adjtime);
        syscode_case(syncfs);
        syscode_case(sendmmsg);
        syscode_case(setns);
        syscode_case(getcpu);
        syscode_case(process_vm_readv);
        syscode_case(process_vm_writev);
        syscode_case(kcmp);
        syscode_case(finit_module);
        syscode_case(sched_setattr);
        syscode_case(sched_getattr);
        syscode_case(renameat2);
        syscode_case(seccomp);
        syscode_case(getrandom);
        syscode_case(memfd_create);
        syscode_case(kexec_file_load);
        syscode_case(bpf);
        syscode_case(execveat);
        syscode_case(userfaultfd);
        syscode_case(membarrier);
        syscode_case(mlock2);
        syscode_case(copy_file_range);
        syscode_case(preadv2);
        syscode_case(pwritev2);
        syscode_case(pkey_mprotect);
        syscode_case(pkey_alloc);
        syscode_case(pkey_free);
        syscode_case(statx);
    }
    return "SYS_undef";
}

#endif // __SIMPLEMODULE_KERNEL_LIB_SYSCALLS_H
