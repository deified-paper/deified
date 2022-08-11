#include <linux/delay.h>
#include <linux/kfifo.h>
#include <linux/mm.h>
#include <linux/pid_namespace.h>
#include <linux/printk.h>
#include <linux/ratelimit.h>
#include <linux/rhashtable.h>
#include <linux/sched/signal.h>
#include <linux/signal.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/wait.h>

#include <asm/pgtable.h>

#include "hooks.h"
#include "hq-interface.h"
#include "hq.h"
#include "verifier.h"

#include "config.h"
#include "interfaces.h"
#include "messages-verifier.h"

/* Unexported kernel functions that must be looked up */
static int (*__receive_fd_fp)(int fd, struct file *, int __user *,
                              unsigned int);

/* Function declarations */
static ssize_t interface_verifier_read(struct file *fp, char *buf, size_t len,
                                       loff_t *off);
static long interface_verifier_ioctl(struct file *fp, unsigned int cmd,
                                     unsigned long arg);
static int interface_verifier_mmap(struct file *fp, struct vm_area_struct *vma);
static int interface_verifier_open(struct inode *ip, struct file *fp);
static int interface_verifier_release(struct inode *ip, struct file *fp);

/* Internal variables */
const struct file_operations verifier_interface_fops = {
    .owner = THIS_MODULE,
    .read = interface_verifier_read,
    .unlocked_ioctl = interface_verifier_ioctl,
    .mmap = interface_verifier_mmap,
    .open = interface_verifier_open,
    .release = interface_verifier_release,
};

// Notify page for the verifier
static struct task_struct *verifier = NULL;

// Tracks pointer and size for each mappable region
struct hq_verifier_map {
    void *ptr;
    size_t sz;
};

// Message buffer queue for the verifier
DEFINE_KFIFO(msg_fifo, struct hq_verifier_msg, VERIFIER_MSG_FIFO_SIZE);
DECLARE_WAIT_QUEUE_HEAD(msg_wq);
// Memory mapping queue for the verifier
DEFINE_KFIFO(map_fifo, struct hq_verifier_map, VERIFIER_MSG_FIFO_SIZE);

// Lock on message queues to ensure single-producer, and to prevent reordering
// between both queues
DEFINE_SPINLOCK(fifo_lock);

static int send_message_inner(const struct hq_verifier_msg *msg,
                              const struct hq_verifier_map *map) {
    unsigned long flags;
    int ret = 0;

    spin_lock_irqsave(&fifo_lock, flags);
    if (!verifier) {
        ret = -ENODEV;
        goto out;
    }

    // char signal_sent = 0;

    // Check both FIFOs are not full
    if (kfifo_is_full(&msg_fifo) || (map && kfifo_is_full(&map_fifo))) {
        ret = -ENOSPC;
        goto out;
    }

    // Check either both insertions succeeded or failed
    if (kfifo_put(&msg_fifo, *msg) != (map ? kfifo_put(&map_fifo, *map) : 1)) {
        ret = -ENOSPC;
        goto out;
    }

    wake_up_interruptible(&msg_wq);
out:
    spin_unlock_irqrestore(&fifo_lock, flags);
    return 0;
}

static int send_message(const struct hq_verifier_msg *msg,
                        const struct hq_verifier_map *map) {
    struct hq_ctx *app;
    pid_t pid_from = msg->pid, child_verifier_pid = -1;
    int ret = 0;

    // Check signals to child verifier if exists
    rcu_read_lock();
    app = rhashtable_lookup(&hq_table, &pid_from, hq_params);
    rcu_read_unlock();
    if (app && app->verifier_pid) {
        child_verifier_pid = app->verifier_pid;
    } else {
        struct hq_verifier_msg temp_msg = {
            .pid = msg->pid,
            .tid = msg->tid,
            .op = HQ_VERIFIER_MSG_ENQUEUE_SIGNAL,
            .value = 0,
        };

        pr_warn("No entry for pid %d, ver: %p :: %d %d\n", pid_from, app,
                app ? app->verifier_pid : -1, app ? app->status : -1);
        // Two cases here; Initial one, or
        // cloned-but-not-registered-yet. Either case, send; initial
        // one: no enqueued message(ACTIVE), no: (FORKED)
        ret = send_message_inner(&temp_msg, NULL);
    }

    if (ret == 0) {
        ret = send_message_inner(msg, map);
    }

    if (ret == 0 && child_verifier_pid != -1) {
        struct pid_namespace *pid_ns = task_active_pid_ns(verifier);
        if (pid_ns == NULL) {
            pr_warn("Verifier namespace is NULL!\n");
        } else {
            struct pid *pid = find_pid_ns(child_verifier_pid, pid_ns);
            struct task_struct *task = get_pid_task(pid, PIDTYPE_PID);

            if (!task) {
                pr_warn("Error notifying child verifier of new message(s) "
                        "- NULL(op: %d from: %d pid: %d pid?: %p)!\n",
                        msg->op, pid_from, child_verifier_pid, pid);
            } else if ((ret = send_sig(VERIFIER_MESSAGE_SIGNAL, task, 1)))
                pr_warn("Error notifying child verifier of new "
                        "message(s)!\n");
            else {
                // signal_sent = 1;
            }
        }
    }

    return ret;
}

/* Function implementations */
int verifier_is_connected(void) { return !!verifier; }

int verifier_interface_on_clone(pid_t ptgid, pid_t tgid, struct hq_ctx *ctx) {
    int ret = 0;
    struct hq_verifier_msg msg = {
        .pid = ptgid,
        .tid = 0,
        .op = HQ_VERIFIER_MSG_CLONE,
        .value = tgid,
        .comm = {0},
    };

    if ((ret = send_message(&msg, NULL)))
        pr_warn("Error while appending CLONE, dropping verifier message!\n");

    return ret;
}

int verifier_interface_on_exit(pid_t tgid, pid_t pid, int execve) {
    int ret = 0;
    struct hq_verifier_msg msg = {
        .pid = tgid,
        .tid = pid,
        .op = HQ_VERIFIER_MSG_TERMINATE,
        .value = execve,
        .comm = {0},
    };

    if ((ret = send_message(&msg, NULL)))
        pr_warn(
            "Error while appending TERMINATE, dropping verifier message!\n");

    return ret;
}

int verifier_interface_monitor(pid_t tgid, struct hq_ctx *ctx, struct file *f) {
    int ret = 0;
#ifdef HQ_CHECK_SYSCALL
    struct hq_verifier_map map = {
        .ptr = ctx->syscall,
        .sz = SYSCALL_MAP_SIZE,
    };
    const struct hq_verifier_map *map_ptr = &map;
#else
    const struct hq_verifier_map *map_ptr = NULL;
#endif /* HQ_CHECK_SYSCALL */
    struct hq_verifier_msg msg = {
        .pid = tgid,
        .tid = ctx->vpid,
        .op = HQ_VERIFIER_MSG_MONITOR,
        .value = (uintptr_t)f,
    };
    strncpy(msg.comm, ctx->name, sizeof(msg.comm));

    if (f) {
        // Increment f->f_count in case the original process is killed
        get_file(f);
    }

    if ((ret = send_message(&msg, map_ptr)))
        pr_warn("Error while appending MONITOR, dropping verifier message!\n");

    return ret;
}

/* Filesystem operations */

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0)
// FIXME: receive_fd_user -> __receive_fd is not available
static int fd_receive(int fd, struct file *file, int __user *ufd,
                      unsigned int o_flags) {
    int new_fd;
    int error;

    // error = security_file_receive(file);
    // if (error)
    //     return error;

    new_fd = get_unused_fd_flags(o_flags);
    if (new_fd < 0)
        return new_fd;

    if (ufd) {
        error = put_user(new_fd, ufd);
        if (error) {
            put_unused_fd(new_fd);
            return error;
        }
    }

    fd_install(new_fd, get_file(file));

    /* Bump the sock usage counts, if any. */
    // __receive_sock(file);
    return new_fd;
}
#endif

static ssize_t interface_verifier_read(struct file *fp, char *buf, size_t len,
                                       loff_t *off) {
    struct hq_verifier_msg msg;
    ssize_t written = 0;

    if (!verifier)
        return -ENXIO;

    // Wait until waitqueue to reduce signals
    wait_event_interruptible(msg_wq, !kfifo_is_empty(&msg_fifo));

    while (written + sizeof(msg) < len && !kfifo_is_empty(&msg_fifo)) {
        if (!kfifo_get(&msg_fifo, &msg))
            break;

        // Open the corresponding file to obtain the fd
        if (msg.op == HQ_VERIFIER_MSG_MONITOR && msg.value) {
            int fd;

            if (!__receive_fd_fp) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
                __receive_fd_fp = (void *)(*lookup_name)("__receive_fd");
#else
                __receive_fd_fp = &fd_receive;
#endif
                if (!__receive_fd_fp) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
                    pr_err("Cannot lookup '__receive_fd'!\n");
#endif
                    break;
                }
            }

            fd = (*__receive_fd_fp)(-1, (struct file *)msg.value, NULL,
                                    O_CLOEXEC);
            // Always decrement f_count; either 1->0 or 2->1 depending on
            // whether __receive_fd succeeded
            fput((struct file *)msg.value);
            msg.value = fd;
        }

        if (copy_to_user(buf + written, &msg, sizeof(msg))) {
            written = -EFAULT;
            break;
        }

        written += sizeof(msg);
    }

    return written;
}

static int interface_verifier_mmap(struct file *fp,
                                   struct vm_area_struct *vma) {
    struct hq_verifier_map map;
    size_t len = vma->vm_end - vma->vm_start;

    // Check the mapping arguments are valid
    if (vma->vm_end <= vma->vm_start ||
        (vma->vm_flags & (VM_READ | VM_WRITE | VM_EXEC)) != VM_WRITE ||
        vma->vm_pgoff)
        return -EINVAL;

    // Get the next mapping
    if (!kfifo_get(&map_fifo, &map) || len != map.sz)
        return -EINVAL;

    // Ensure the mapping flags are correct
    vma->vm_flags = (vma->vm_flags &
                     ~(VM_MERGEABLE | VM_HUGEPAGE | VM_HUGETLB | VM_MAYEXEC)) |
                    VM_DONTCOPY | VM_DONTEXPAND | VM_SHARED;

    // Map the physical page(s)
    return remap_pfn_range(vma, vma->vm_start,
                           virt_to_phys(map.ptr) >> PAGE_SHIFT, len,
                           vma->vm_page_prot);
}

static long interface_verifier_ioctl(struct file *fp, unsigned int cmd,
                                     unsigned long arg) {
    switch (cmd) {
    case IOCTL_KILL_TGID: {
        struct pid *pid = find_get_pid(arg);
        struct task_struct *tsk = pid ? get_pid_task(pid, PIDTYPE_TGID) : NULL;
        if (!tsk) {
            pr_err("Cannot kill tgid %lu: Unknown!\n", arg);
            return -ESRCH;
        }

#ifdef HQ_ENFORCE_CHECKS
        pr_warn("Killing tgid %lu (%s): verifier request!\n", arg, tsk->comm);
        send_sig(HQ_KILL_SIGNAL, tsk, 1);
#endif /* HQ_ENFORCE_CHECKS */
        return 0;
    } break;

    // Register child verifier process
    case _IO('h', 1): {
        pid_t pid_from = arg & 0xFFFFFFFF;
        pid_t pid_to = (arg >> 32);
        struct hq_ctx *app;

        rcu_read_lock();
        app = rhashtable_lookup(&hq_table, &pid_from, hq_params);
        if (app) {
            app->verifier_pid = pid_to;
        }
        rcu_read_unlock();
        return 0;
    }

    // Unregister child verifier process
    case _IO('h', 2): {
        pid_t pid_from = arg & 0xFFFFFFFF;
        pid_t pid_to = (arg >> 32);
        struct hq_ctx *app;
        int res = -ENOENT;

        rcu_read_lock();
        app = rhashtable_lookup(&hq_table, &pid_from, hq_params);
        if (app) {
            if (app->verifier_pid == pid_to) {
                if (rhashtable_remove_fast(&hq_table, &app->node, hq_params))
                    pr_warn("Cannot remove context for pid %d!\n", pid_from);
                free_hq_context(app, (void *)1);
                res = 0;
            } else {
                res = -ESRCH;
            }
        }
        rcu_read_unlock();
        return res;
    }

    default:
        break;
    }

    return -EINVAL;
}

static int interface_verifier_open(struct inode *ip, struct file *fp) {
    if (verifier)
        return -EBUSY;

    verifier = current;
    return nonseekable_open(ip, fp);
}

static int interface_verifier_release(struct inode *ip, struct file *fp) {
    struct rhashtable_iter iter;
    struct hq_ctx *app;
    unsigned long flags;

    spin_lock_irqsave(&fifo_lock, flags);
    verifier = NULL;

    // Clear the FIFOs
    while (!kfifo_is_empty(&msg_fifo)) {
        struct hq_verifier_msg msg;
        if (!kfifo_get(&msg_fifo, &msg))
            break;
        if (msg.op == HQ_VERIFIER_MSG_MONITOR && msg.value)
            fput((struct file *)msg.value);
    }
    kfifo_reset(&msg_fifo);
    kfifo_reset(&map_fifo);
    spin_unlock_irqrestore(&fifo_lock, flags);

    // Clear the rhashtable
    rhashtable_walk_enter(&hq_table, &iter);
    rhashtable_walk_start(&iter);
    while ((app = rhashtable_walk_next(&iter))) {
        if (IS_ERR(app)) {
            if (PTR_ERR(app) == -EAGAIN)
                continue;
            pr_warn("Cannot access context entry %p while walking hashtable!\n",
                    app);
            break;
        }

#ifdef HQ_PRESERVE_STATS
        free_hq_context(app, NULL);
#else
        if (rhashtable_remove_fast(&hq_table, &app->node, hq_params))
            pr_warn("Cannot remove context for pid %d!\n", app->pid);
        free_hq_context(app, (void *)1);
#endif /* HQ_PRESERVE_STATS */
    }
    rhashtable_walk_stop(&iter);
    rhashtable_walk_exit(&iter);
    return 0;
}

