#include <linux/delay.h>
#include <linux/fdtable.h>
#include <linux/fs.h>
#include <linux/jiffies.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/ptrace.h>
#include <linux/rhashtable.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/tracepoint.h>
#include <linux/uprobes.h>
#include <linux/version.h>

#include <asm/byteorder.h>
#include <asm/io.h>
#include <asm/prctl.h>
#include <asm/ptrace.h>
#include <asm/syscall.h>

#include "config.h"
#include "fpga.h"
#include "hooks.h"
#include "hq-interface.h"
#include "hq.h"
#include "interface-ipc.h"
#include "interface.h"
#include "verifier.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
static unsigned long dummy_lookup_name(const char *name) {
    pr_err("Cannot lookup symbol '%s' by name!", name);
    return 0;
}

unsigned long (*lookup_name)(const char *name) = &dummy_lookup_name;
#else
unsigned long (*lookup_name)(const char *name) = &kallsyms_lookup_name;
#endif

#if INTERFACE_TYPE == INTERFACE_TYPE_OPAE
// Either use the upstream kernel driver (dfl-afu, etc) or the old Intel driver
// from the opae-intel-fpga-driver package (intel-fpga-afu, etc)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
#include "dfl.h"
typedef struct dfl_feature_platform_data fpga_t;
#define FPGA_ID_AFU PORT_FEATURE_ID_AFU
#define FPGA_PORT_DRIVER DFL_FPGA_FEATURE_DEV_PORT
#define fpga_is_disabled(pdata) pdata->disable_count
#define fpga_get_feature_ioaddr(dev, id) dfl_get_feature_ioaddr_by_id(dev, id)
#else
#include "feature-dev.h"
typedef struct feature_platform_data fpga_t;
#define FPGA_ID_AFU FEATURE_ID_AFU
#define FPGA_PORT_DRIVER FPGA_FEATURE_DEV_PORT
#define fpga_is_disabled(pdata) 0
#define fpga_get_feature_ioaddr(dev, id) get_feature_ioaddr_by_id(dev, id)
#endif /* LINUX_VERSION_CODE */

fpga_t *fpga = NULL;
struct file *fpga_file = NULL;
void __iomem *fpga_mmio = NULL;
#endif /* INTERFACE_TYPE == INTERFACE_TYPE_OPAE */

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 20, 0)
static inline unsigned long regs_get_kernel_argument(struct pt_regs *regs,
                                                     unsigned int n) {
    static const unsigned int argument_offs[] = {
#ifdef __i386__
        offsetof(struct pt_regs, ax),
        offsetof(struct pt_regs, cx),
        offsetof(struct pt_regs, dx),
#define NR_REG_ARGUMENTS 3
#else
        offsetof(struct pt_regs, di), offsetof(struct pt_regs, si),
        offsetof(struct pt_regs, dx), offsetof(struct pt_regs, cx),
        offsetof(struct pt_regs, r8), offsetof(struct pt_regs, r9),
#define NR_REG_ARGUMENTS 6
#endif
    };

    if (n >= NR_REG_ARGUMENTS) {
        n -= NR_REG_ARGUMENTS - 1;
        return regs_get_kernel_stack_nth(regs, n);
    } else
        return regs_get_register(regs, argument_offs[n]);
}
#endif /* LINUX_VERSION_CODE */

// Enables HerQules for a process
static int notify_prctl(uintptr_t __user *addr, int fork) {
    const pid_t tgid = task_tgid_nr(current), pid = task_pid_nr(current);
    struct hq_ctx *app;
    struct file *f;
    int fd, insert = 0, tmp;
    long ret = 0;

    if (!verifier_is_connected()) {
        pr_err("Cannot enable HQ for pid %d (%s), missing verifier!\n", pid,
               current->comm);
        return -ENODEV;
    }

    if (!thread_group_empty(current)) {
        pr_err("Cannot enable HQ for pid %d (%s), has multiple threads!\n", pid,
               current->comm);
        return -EINVAL;
    }

    rcu_read_lock();
    // Ensure no context exists for this process, unless forked
    app = rhashtable_lookup(&hq_table, &pid, hq_params);
    if (fork) {
        // Fork must have copied context that is not dead
        if (!app || app->status != ACTIVE_FORK) {
            pr_err(
                "Cannot enable HQ for pid %d (%s), missing copied context!\n",
                pid, current->comm);
            app = NULL;
            ret = -EINVAL;
            goto err;
        }
    } else if (app) {
        if (app->status == DEAD || app->status == INACTIVE) {
            pr_debug("Overwriting stale context for pid %d (%s)!\n", pid,
                     app->name);

            // Initialize the context
            tmp = app->verifier_pid;
            init_hq_context(app, current);
            app->verifier_pid = tmp;
        } else {
            pr_err("Context already exists for pid %d (%s)!\n", pid, app->name);
            ret = -EEXIST;
            app = NULL;
            goto err;
        }
    } else {
        // Allocate the per-process context
        if (!(app = kzalloc(sizeof(*app), GFP_KERNEL))) {
            pr_err("Cannot allocate context for pid %d!\n", pid);
            ret = -ENOMEM;
            goto err;
        }

        // Initialize the context
        init_hq_context(app, current);

        insert = 1;
    }
err:
    rcu_read_unlock();
    if (!app)
        return ret;

#if INTERFACE_TYPE == INTERFACE_TYPE_OPAE
    if (fpga) {
        pr_debug("Updating PID for context tgid %d\n", tgid);
        // Update PID register on FPGA
        iowrite64(tgid, fpga_mmio + REG_PID);
#ifdef HQ_INTERFACE_OPAE_WC
        clwb(fpga_mmio + REG_PID);
#endif /* HQ_INTERFACE_OPAE_WC */
    }
#endif /* INTERFACE_TYPE == INTERFACE_TYPE_OPAE */

    // Allocate fd for the file
    if ((fd = get_unused_fd_flags(O_CLOEXEC)) < 0) {
        ret = fd;
        pr_err("Cannot allocate fd for pid %d: %ld!\n", pid, ret);
        goto err_file;
    }

    // Create the file for the memory buffer; f->f_count = 1
    if (IS_ERR(f = ipc_create_file())) {
        ret = PTR_ERR(f);
        pr_err("Cannot create message buffer for pid %d: %ld!\n", pid, ret);
        goto err_fd;
    }
    // fd is not returned, but needs to be installed as reference for cleanup
    fd_install(fd, f);

    // Map the memory buffer; f->f_count += 1
    if (IS_ERR((void *)(ret = ipc_map_file(f)))) {
        pr_err("Cannot map message buffer for pid %d: %ld!\n", pid, ret);
        goto err_file;
    }

    // Write the mapped address
    if ((ret = put_user(ret, addr))) {
        pr_err("Cannot write address to userspace for pid %d: %ld!\n", pid,
               ret);
        goto err_file;
    }

    // Insert the context into the hashtable
    if (insert) {
        rcu_read_lock();
        if (rhashtable_lookup_insert_fast(&hq_table, &app->node, hq_params)) {
            pr_err("Cannot insert context for pid %d!\n", pid);
            rcu_read_unlock();
            goto err_file;
        }
        rcu_read_unlock();

        insert = 0;
    }

    app->status = ACTIVE;
    // Use virtual PID from within the current namespace
    // Send the syscall buffer to userspace verifier; f->f_count += 1
    if ((ret = verifier_interface_monitor(tgid, app, f))) {
        pr_err("Cannot notify context for tgid %d: %ld!\n", tgid, ret);
        goto err_file;
    }

err_file:
    if (insert)
        free_hq_context(app, (void *)1);
    return ret;
err_fd:
    put_unused_fd(fd);
    goto err_file;
}

/* Tracepoints */
// FIXME: For HQ_INTERFACE_UNSAFE_PID_CONCURRENT, need to update PID when about
// to be scheduled (e.g. signals) for FPGA
static struct tracepoint *tp_sched_exec = NULL, *tp_sched_free = NULL,
#ifdef HQ_CHECK_SYSCALL
                         *tp_sys_enter = NULL,
#endif /* HQ_CHECK_SYSCALL */
                         *tp_sys_exit = NULL, *tp_task_newtask = NULL;

#ifdef HQ_CHECK_SYSCALL
// Hooks system calls to synchronize with verifier state
static void tracepoint_sys_enter(void *data, struct pt_regs *regs, long id) {
    const pid_t tgid = task_tgid_nr(current), pid = task_pid_nr(current);
    struct hq_ctx *app;

    rcu_read_lock();
    app = rhashtable_lookup(&hq_table, &pid, hq_params);
    if (app && app->status >= ACTIVE) {
        bool after = 0;
        unsigned long jiffies_start, sleep = 1;

        // Allow forked processes to re-enable without a message buffer
        if (unlikely(app->status == ACTIVE_FORK &&
                     ((id == __NR_gettid) ||
                      (id == __NR_prctl &&
                       regs_get_kernel_argument(regs, 0) == PR_HQ)))) {
            pr_debug_ratelimited(
                "Allowing post-copy system call %ld in context pid %d (%s)!\n",
                id, pid, app->name);
            goto out;
        }

        if (
        // Allow vDSO system calls, which lack compile-time instrumentation.
        // vDSO uses kernel-loaded binary in process memory.
#ifdef CONFIG_X86_64
            id == __NR_clock_getres || id == __NR_clock_gettime ||
            id == __NR_gettimeofday ||
#endif
            // Whitelist certain system calls
            id == __NR_futex
#ifdef __NR_futex_time64
            || id == __NR_futex_time64
#endif
        ) {
            pr_debug_ratelimited(
                "Allowing system call %ld in context pid %d (%s)!\n", id, pid,
                app->name);
            goto out;
        }

#ifdef HQ_UNSAFE_COMPAT_RR
        // When running under rr, it may inject psuedo-syscalls with number
        // greater than or equal to RR_CALL_BASE (1000).
        if (unlikely(id >= 1000)) {
            pr_debug_ratelimited(
                "Allowing rr system call %ld in context pid %d (%s)!\n", id,
                pid, app->name);
            goto out;
        }
#endif /* HQ_UNSAFE_COMPAT_RR */

        // Ensure system call is in range
        if (unlikely(id >= NR_syscalls)) {
            pr_warn("Unrecognized system call %ld in contxt pid %d (%s)!\n", id,
                    pid, app->name);
            goto die;
        }

#if INTERFACE_TYPE == INTERFACE_TYPE_POSIX_FIFO ||                             \
    INTERFACE_TYPE == INTERFACE_TYPE_POSIX_MQ
        // Skip check on write if interacting with the interface
        if (
#if INTERFACE_TYPE == INTERFACE_TYPE_POSIX_FIFO
            id == __NR_write
#elif INTERFACE_TYPE == INTERFACE_TYPE_POSIX_MQ
            id == __NR_mq_timedsend
#endif /* INTERFACE_TYPE */
        ) {
            bool skip = false;
            struct file *f = fget(regs_get_kernel_argument(regs, 0));
            if (f &&
#if INTERFACE_TYPE == INTERFACE_TYPE_POSIX_FIFO
                S_ISFIFO(file_inode(f)->i_mode)
#elif INTERFACE_TYPE == INTERFACE_TYPE_POSIX_MQ
                // from MQUEUE_MAGIC in ipc/mqueue.c
                file_inode(f)->i_sb->s_magic == 0x19800202
#endif /* INTERFACE_TYPE */
            )
                skip = true;

            fput(f);
            if (skip)
                goto out;
        }
#endif /* INTERFACE_TYPE */

        jiffies_start = jiffies;
        // Block system call until verifier has caught up
        while (1) {
            long val;
            barrier();

            if (unlikely(!pid_alive(current) || fatal_signal_pending(current)))
                goto dead;

            if (unlikely(!app->syscall)) {
                pr_err("Missing system call buffer in pid %d!\n", pid);
                goto die;
            }

            if ((val = atomic_read_acquire((atomic_t *)&app->syscall->ok))) {
                atomic_set_release((atomic_t *)&app->syscall->ok, 0);
                // System call allowed, continue execution
                atomic_inc(&app->stats[after ? HQ_STAT_NUM_SYSCALLS_ABOVE
                                             : HQ_STAT_NUM_SYSCALLS_BELOW]);
                goto out;
            }

            if (id == __NR_exit || id == __NR_exit_group) {
                // Allow potentially-uninstrumented exit, which may be called
                // from the C runtime after unmapping all memory regions
                goto out;
            }

#ifdef HQ_ENFORCE_SYSCALL_HARD
            // Kill if hard threshold exceeded
            if (time_is_before_jiffies(
                    jiffies_start +
                    msecs_to_jiffies(HQ_ENFORCE_SYSCALL_HARD))) {
                pr_err("Reached hard threshold of %d ms on syscall %ld in tgid "
                       "%d, pid %d!\n",
                       HQ_ENFORCE_SYSCALL_HARD, id, tgid, pid);
                goto die;
            }
#endif /* HQ_ENFORCE_SYSCALL_HARD */

            // Sleep if threshold exceeded to avoid blocking kernel thread
            if (time_is_before_jiffies(
                    jiffies_start + msecs_to_jiffies(HQ_SYSCALL_THRESHOLD))) {
                after = 1;

                if (sleep < HQ_SYSCALL_SLEEP_MAX) {
                    rcu_read_unlock_sched_notrace();
                    rcu_read_unlock();
                    usleep_range(sleep * 500, sleep * 1000);
                    rcu_read_lock();
                    rcu_read_lock_sched_notrace();
                    sleep *= HQ_SYSCALL_SLEEP_MULTIPLIER;
                } else {
                    pr_debug_ratelimited(
                        "Waiting on syscall %ld for %d ms in "
                        "context tgid %d (%s, pid %d)!\n",
                        id, jiffies_to_msecs(jiffies - jiffies_start), tgid,
                        app->name, pid);

                    rcu_read_unlock_sched_notrace();
                    rcu_read_unlock();
                    msleep_interruptible(HQ_SYSCALL_SLEEP_MAX);
                    rcu_read_lock();
                    rcu_read_lock_sched_notrace();
                }
            }
        }

    die:
#ifdef HQ_ENFORCE_CHECKS
        pr_warn("Killing tgid %d (%s, pid %d): system call timeout!\n", tgid,
                app->name, pid);
        send_sig(HQ_KILL_SIGNAL, current, 1);
#endif /* HQ_ENFORCE_CHECKS */
    dead:
        atomic_inc(&app->stats[HQ_STAT_NUM_FAILS]);
    }

out:
    rcu_read_unlock();
}
#endif /* HQ_CHECK_SYSCALL */

// Hooks return, enable HerQules from prctl, or adjust counter from signal
static void tracepoint_sys_exit(void *data, struct pt_regs *regs, long ret) {
    const long id = syscall_get_nr(current, regs);

    if (id == __NR_prctl && regs_get_kernel_argument(regs, 0) == PR_HQ &&
        ret == -EINVAL) {
        syscall_set_return_value(
            current, regs,
            notify_prctl((uintptr_t *)regs_get_kernel_argument(regs, 1),
                         regs_get_kernel_argument(regs, 2)),
            0);
    }
#ifdef HQ_CHECK_SYSCALL
    else if (signal_pending(current) && !fatal_signal_pending(current) &&
             id >= 0) {
        const long errno = syscall_get_error(current, regs);
        // Pending non-fatal signal(s) during a restartable system call
        // FIXME: Fetch signal(s), inspect action, check for signal handler
        if (errno == -ERESTARTSYS || errno == -ERESTARTNOHAND ||
            errno == -ERESTARTNOINTR || errno == -ERESTART_RESTARTBLOCK) {
            // Increment the counter to allow the restarted system call
            struct hq_ctx *app;
            const pid_t pid = task_pid_nr(current);

            rcu_read_lock();
            app = rhashtable_lookup(&hq_table, &pid, hq_params);
            if (app && app->status == ACTIVE && app->syscall) {
                pr_debug_ratelimited(
                    "Syscall %ld may restart after signal in context pid "
                    "%d (%s)!\n",
                    id, pid, app->name);
                atomic_set_release((atomic_t *)&app->syscall->ok, 1);
            }
            rcu_read_unlock();
        }
    }
#endif
}

// Handles thread termination by deleting context and notifying verifier
static void tracepoint_sched_free(void *data, struct task_struct *task) {
    const pid_t pid = task_pid_nr(task);
    struct hq_ctx *app;

    rcu_read_lock();

    app = rhashtable_lookup(&hq_table, &pid, hq_params);
    if (app && app->status != DEAD) {
        int ret;

        pr_debug("Notifying exit for context pid %d...\n", pid);

        // Notify process has exited
        // Use virtual PID from within the current namespace
        if ((ret =
                 verifier_interface_on_exit(task_tgid_nr(task), app->vpid, 0)))
            pr_err("Cannot notify exit for pid %d: %d!\n", pid, ret);

        free_hq_context(app, NULL);
    }

    rcu_read_unlock();
}

// Handles execve by deleting context and notifying verifier
static void tracepoint_sched_exec(void *data, struct task_struct *task,
                                  pid_t old_pid, struct linux_binprm *bprm) {
    const pid_t pid = task_pid_nr(task);
    struct hq_ctx *app;

    rcu_read_lock();

    app = rhashtable_lookup(&hq_table, &pid, hq_params);
    if (app && app->status == ACTIVE) {
        int ret;

        pr_debug("Notifying execve for context pid %d...\n", pid);
        // Mark process unmonitored after execve, but do not free here because
        // this can race with tracepoint_sched_free
        app->status = INACTIVE;

        // Notify process has exited on execve
        // Use virtual PID from within the current namespace
        if ((ret =
                 verifier_interface_on_exit(task_tgid_nr(task), app->vpid, 1)))
            pr_err("Cannot notify execve for pid %d: %d!\n", pid, ret);
    }

    rcu_read_unlock();
}

// Handles clone/fork by copying context and notifying verifier
static void tracepoint_task_newtask(void *data, struct task_struct *task,
                                    unsigned long clone_flags) {
    const pid_t tgid = task_tgid_nr(current), pid = task_pid_nr(current);
    const bool is_thread = clone_flags & CLONE_THREAD;
    struct hq_ctx *app, *app_clone;
    int ret;

    rcu_read_lock();

    // Check if the process is under HQ and copy entry if it is
    app = rhashtable_lookup(&hq_table, &pid, hq_params);
    if (!app || app->status != ACTIVE)
        goto out;

    atomic_inc(&app->stats[HQ_STAT_NUM_FORKS]);

    if (!is_thread && (clone_flags & CLONE_VM))
        pr_warn("Unsupported cloned memory space in context pid %d for "
                "process '%s'...\n",
                pid, app->name);

    if (!(app_clone = kzalloc(sizeof(*app_clone), GFP_KERNEL))) {
        pr_err("Cannot allocate context for pid %d!\n", pid);
        goto out;
    }

    // Kernel tracks actual PID, but userspace needs to know the virtual PID
    // from within the child namespace (if applicable)
    if (is_thread)
        init_hq_context(app_clone, task);
    else
        copy_hq_context(app_clone, app, task_pid_nr(task),
                        task_pid_nr_ns(task, task_active_pid_ns(task)));

    if (rhashtable_insert_fast(&hq_table, &app_clone->node, hq_params)) {
        pr_err("Cannot insert context for pid %d!\n", pid);
        free_hq_context(app_clone, (void *)1);
        goto out;
    }

    // Threads do not need to reinitialize
    if (is_thread) {
        app_clone->status = ACTIVE;
        app_clone->verifier_pid = app->verifier_pid;
    }

    if (is_thread ? (ret = verifier_interface_monitor(tgid, app_clone, NULL))
                  : (ret = verifier_interface_on_clone(tgid, task_tgid_nr(task),
                                                       app_clone))) {
        pr_err("Cannot notify for tgid %d: %d!\n", tgid, ret);
        goto out;
    }

out:
    rcu_read_unlock();
}

// Tracepoints are not exported, must search through list
static void lookup_tracepoints(struct tracepoint *tp, void *ignore) {
    if (!tp_sched_exec && !strcmp("sched_process_exec", tp->name))
        tp_sched_exec = tp;
    else if (!tp_sched_free && !strcmp("sched_process_free", tp->name))
        tp_sched_free = tp;
#ifdef HQ_CHECK_SYSCALL
    else if (!tp_sys_enter && !strcmp("sys_enter", tp->name))
        tp_sys_enter = tp;
#endif /* HQ_CHECK_SYSCALL */
    else if (!tp_sys_exit && !strcmp("sys_exit", tp->name))
        tp_sys_exit = tp;
    else if (!tp_task_newtask && !strcmp("task_newtask", tp->name))
        tp_task_newtask = tp;
}

int tracepoints_insert(void) {
    int ret;

    if (!tp_sched_exec || !tp_sched_free
#ifdef HQ_CHECK_SYSCALL
        || !tp_sys_enter
#endif /* HQ_CHECK_SYSCALL */
        || !tp_sys_exit || !tp_task_newtask)
        for_each_kernel_tracepoint(lookup_tracepoints, NULL);

    if (!tp_sched_exec) {
        pr_err("Could not find tracepoint 'sched_process_exec'!\n");
        return -ENODEV;
    }

    if (!tp_sched_free) {
        pr_err("Could not find tracepoint 'sched_process_free'!\n");
        return -ENODEV;
    }

#ifdef HQ_CHECK_SYSCALL
    if (!tp_sys_enter) {
        pr_err("Could not find tracepoint 'sys_enter'!\n");
        return -ENODEV;
    }
#endif /* HQ_CHECK_SYSCALL */

    if (!tp_task_newtask) {
        pr_err("Could not find tracepoint 'task_newtask'\n");
        return -ENODEV;
    }

    if (!tp_sys_exit) {
        pr_err("Could not find tracepoint 'sys_exit'\n");
        return -ENODEV;
    }

    if ((ret = tracepoint_probe_register(tp_sched_exec, tracepoint_sched_exec,
                                         NULL))) {
        pr_err("Could not register tracepoint 'sched_process_exec'!\n");
        tp_sched_exec = NULL;
        return ret;
    }

    if ((ret = tracepoint_probe_register(tp_sched_free, tracepoint_sched_free,
                                         NULL))) {
        pr_err("Could not register tracepoint 'sched_process_free'!\n");
        tp_sched_free = NULL;
        return ret;
    }

#ifdef HQ_CHECK_SYSCALL
    if ((ret = tracepoint_probe_register(tp_sys_enter, tracepoint_sys_enter,
                                         NULL))) {
        pr_err("Could not register tracepoint 'sys_enter'!\n");
        tp_sys_enter = NULL;
        return ret;
    }
#endif /* HQ_CHECK_SYSCALL */

    if (tp_sys_exit && (ret = tracepoint_probe_register(
                            tp_sys_exit, tracepoint_sys_exit, NULL))) {
        pr_err("Could not register tracepoint 'sys_exit'!\n");
        tp_sys_exit = NULL;
        return ret;
    }

    if ((ret = tracepoint_probe_register(tp_task_newtask,
                                         tracepoint_task_newtask, NULL))) {
        pr_err("Could not register tracepoint 'task_newtask'!\n");
        tp_task_newtask = NULL;
        return ret;
    }

    return 0;
}

void tracepoints_remove(void) {
    if (tp_task_newtask &&
        tracepoint_probe_unregister(tp_task_newtask, tracepoint_task_newtask,
                                    NULL)) {
        pr_err("Could not unregister tracepoint 'task_newtask'!\n");
        return;
    }

    if (tp_sys_exit &&
        tracepoint_probe_unregister(tp_sys_exit, tracepoint_sys_exit, NULL)) {
        pr_err("Could not unregister tracepoint 'sys_exit'!\n");
        return;
    }

#ifdef HQ_CHECK_SYSCALL
    if (tp_sys_enter &&
        tracepoint_probe_unregister(tp_sys_enter, tracepoint_sys_enter, NULL)) {
        pr_err("Could not unregister tracepoint 'sys_enter'!\n");
        return;
    }
#endif /* HQ_CHECK_SYSCALL */

    if (tp_sched_free && tracepoint_probe_unregister(
                             tp_sched_free, tracepoint_sched_free, NULL)) {
        pr_err("Could not unregister tracepoint 'sched_process_free'!\n");
        return;
    }

    if (tp_sched_exec && tracepoint_probe_unregister(
                             tp_sched_exec, tracepoint_sched_exec, NULL)) {
        pr_err("Could not unregister tracepoint 'sched_process_exec'!\n");
        return;
    }

    tracepoint_synchronize_unregister();
}

/* kprobes */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
static int dummy_probe(struct kprobe *kp, struct pt_regs *regs) { return 0; }

static struct kprobe kallsyms_find = {
    .symbol_name = "kallsyms_lookup_name",
    .pre_handler = dummy_probe,
};
#endif

int kprobes_insert(void) {
    int ret = 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
    if ((ret = register_kprobe(&kallsyms_find))) {
        pr_err("Could not find kprobe symbol '%s'!\n",
               kallsyms_find.symbol_name);
        return ret;
    }
    lookup_name = (void *)kallsyms_find.addr;
    unregister_kprobe(&kallsyms_find);
#endif

    return ret;
}

void kprobes_remove(void) {}

/* FPGA */
#if INTERFACE_TYPE == INTERFACE_TYPE_OPAE
static int match_fpga_port(struct device *dev, const void *data) {
    int ret = 0;
    fpga_t *pdata = dev_get_platdata(dev);

    if (pdata) {
        mutex_lock(&pdata->lock);
        if (!fpga_is_disabled(pdata)) {
            const u8 guid[] = {AFU_UUID};
            void __iomem *base = fpga_get_feature_ioaddr(dev, FPGA_ID_AFU);
            const u64 afuh = ioread64(base + REG_AFU_ID_H),
                      aful = ioread64(base + REG_AFU_ID_L);

            // Check the AFU has a matching GUID
            if (((u64 *)guid)[1] == be64_to_cpu(aful) &&
                ((u64 *)guid)[0] == be64_to_cpu(afuh))
                ret = 1;
            else
                pr_warn("Found FPGA AFU with different GUID %llx%llx!\n", afuh,
                        aful);
        }
        mutex_unlock(&pdata->lock);
    }

    return ret;
}
#endif /* INTERFACE_TYPE == INTERFACE_TYPE_OPAE */

int fpga_init(void) {
#if INTERFACE_TYPE == INTERFACE_TYPE_OPAE
    struct device_driver *drv =
        driver_find(FPGA_PORT_DRIVER, &platform_bus_type);
    struct device *dev = driver_find_device(drv, NULL, NULL, match_fpga_port);

    if (!dev)
        return -ENODEV;

    fpga = dev_get_platdata(dev);
    // Open the file so that the driver can reset the port on close
    fpga_file = filp_open(FPGA_PATH, O_RDWR, 0);
    // Fetch the physical address of the fpga_mmio region
    fpga_mmio = fpga_get_feature_ioaddr(dev, FPGA_ID_AFU);
    return fpga && fpga_file && fpga_mmio ? 0 : -EINVAL;
#else
    return 0;
#endif /* INTERFACE_TYPE == INTERFACE_TYPE_OPAE */
}

void fpga_finish(void) {
#if INTERFACE_TYPE == INTERFACE_TYPE_OPAE
    if (fpga) {
        fpga_mmio = NULL;
        fput(fpga_file);
        fpga_file = NULL;
        fpga = NULL;
    }
#endif /* INTERFACE_TYPE == INTERFACE_TYPE_OPAE */
}
