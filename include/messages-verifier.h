#ifndef _HQ_VERIFIER_MESSAGES_H_
#define _HQ_VERIFIER_MESSAGES_H_

#include "config.h"

#ifdef __KERNEL__
#include <linux/ioctl.h>
#include <linux/types.h>
#else
#include <linux/ioctl.h>
#endif

enum hq_verifier_msg_op {
    // Create policy context from a cloned/forked process
    // .value = { child_tgid }
    HQ_VERIFIER_MSG_CLONE,
    // Create policy context and monitor an existing process
    // .value = { buffer_fd }, .comm = { process name }
    HQ_VERIFIER_MSG_MONITOR,
    // Delete policy context for a terminated process
    // .value = { is_execve }
    HQ_VERIFIER_MSG_TERMINATE,
    // Enqueue possibly-missing signals to the child verifier process
    // .value = {}
    HQ_VERIFIER_MSG_ENQUEUE_SIGNAL,
};

struct hq_verifier_msg {
    pid_t pid, tid;
    enum hq_verifier_msg_op op;
    uintptr_t value;
    char comm[16];
} __attribute__((__aligned__(8)));

// SIGRTMIN + 8 for queuing signals
#define VERIFIER_MESSAGE_SIGNAL 40

#define IOCTL_KILL_TGID _IO('h', 0)

#ifdef HQ_CHECK_SYSCALL
struct hq_syscall {
    int32_t ok;
};

// Must round to page size in order to remap to userspace
#define SYSCALL_MAP_SIZE                                                       \
    ((sizeof(struct hq_syscall) + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1))
#endif /* HQ_CHECK_SYSCALL */

#endif /* _HQ_VERIFIER_MESSAGES_H_ */
