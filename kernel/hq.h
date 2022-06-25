#ifndef _HQ_H_
#define _HQ_H_

#include <linux/atomic.h>
#include <linux/rhashtable.h>

#include "config.h"
#include "interfaces.h"
#include "messages-verifier.h"
#include "messages.h"
#include "stats.h"

#define HQ_CLASS_NAME "hq"

#ifdef pr_fmt
#undef pr_fmt
#endif
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

enum hq_status {
    // Indicates that tgid has died
    DEAD,
    // Indicates that tgid is unmonitored (from execve or just initialized)
    INACTIVE,
    // Indicates that tgid is monitored and running normally
    ACTIVE,
    // Indicates that tgid is monitored (from fork) and must reinitialize
    ACTIVE_FORK,
};

/* Hashtable entry for tracking per-thread state */
struct hq_ctx {
    pid_t pid, vpid;
    struct rhash_head node;
    struct rcu_head rcu;

    // Thread status
    enum hq_status status;
    // Thread name
    char name[TASK_COMM_LEN];

#ifdef HQ_CHECK_SYSCALL
    // Pointer to system call identifier
    struct hq_syscall *syscall;
#endif /* HQ_CHECK_SYSCALL */

    pid_t verifier_pid;

    // Statistics
    atomic_t stats[HQ_NUM_STATS];
};

#endif /* _HQ_H_ */
