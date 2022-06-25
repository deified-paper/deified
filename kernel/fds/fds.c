#include <asm/syscall.h>
#include <linux/fs.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/rcupdate.h>
#include <linux/tracepoint.h>

#include "compat.h"
#include "fds.h"

MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("Support passing file descriptors without UNIX sockets");
MODULE_VERSION("0.1");

/* Hashtable from filp to hq_ctx */
const struct rhashtable_params map_params = {
    .key_len = sizeof(((struct hq_ctx *)NULL)->inode),
    .key_offset = offsetof(struct hq_ctx, inode),
    .head_offset = offsetof(struct hq_ctx, node),
};
struct rhashtable fifo_table;

static void ctx_free(void *ptr, void *arg) {
    struct hq_ctx *ctx = ptr;
    while (!kfifo_is_empty(&ctx->fifo)) {
        struct file *pop;
        if (kfifo_out_spinlocked(&ctx->fifo, &pop, 1, &ctx->lock)) {
            fput(pop);
        }
    }

    // pr_info("Cleared context for inode %p\n", ctx->inode);
    kfree_rcu(ctx, head);
}

// FIXME: receive_fd_user -> __receive_fd is not exported
static int fd_receive(struct file *file, int __user *ufd,
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

static int do_pushfd(const struct inode *inode, unsigned long arg) {
    const int fd = arg;
    struct file *push = fget_raw(fd);
    struct hq_ctx *ctx;
    int ret = 0;

    if (!push) {
        pr_warn("Invalid file descriptor to push: %d!\n", fd);
        return -EBADF;
    }

    rcu_read_lock();
    ctx = rhashtable_lookup(&fifo_table, &inode, map_params);
    if (!ctx) {
        ctx = kmalloc(sizeof(*ctx), GFP_USER);
        ctx->inode = inode;
        INIT_KFIFO(ctx->fifo);

        if (rhashtable_insert_fast(&fifo_table, &ctx->node, map_params)) {
            pr_warn("Cannot insert context for inode %p!\n", inode);
            kfree(ctx);
            ret = -EAGAIN;
            goto out1;
        }
    }

    if (!kfifo_in_spinlocked(&ctx->fifo, &push, 1, &ctx->lock)) {
        pr_warn("Cannot push to FIFO for inode %p!\n", inode);
        ret = -ENOSPC;
        goto out1;
    }

    pr_debug("Pushed fd %d (%p) to inode %p\n", fd, push, inode);
out1:
    rcu_read_unlock();
    return ret;
}

static int do_popfd(const struct inode *inode, void *addr, bool cloexec) {
    int ret = 0;
    struct hq_ctx *ctx;
    struct file *pop;

    rcu_read_lock();
    ctx = rhashtable_lookup(&fifo_table, &inode, map_params);
    if (!ctx) {
        pr_warn("Cannot find context for inode %p!\n", inode);
        ret = -EBADF;
        goto out2;
    }

    if (!kfifo_out_spinlocked(&ctx->fifo, &pop, 1, &ctx->lock)) {
        pr_warn("Cannot pop from FIFO for inode %p!\n", inode);
        ret = -ENOENT;
        goto out2;
    }

    if ((ret = fd_receive(pop, addr, cloexec ? O_CLOEXEC : 0)) < 0) {
        pr_warn("Cannot duplicate popped fd for inode %p: %d!\n", inode, ret);
        goto out2;
    }

    fput(pop);
    // pr_info("Popped fd %d (%p) from inode %p\n", ret, pop, inode);
    ret = 0;
out2:
    rcu_read_unlock();

    return ret;
}

static int do_popfd_nocloexec(const struct inode *inode, unsigned long arg) {
    return do_popfd(inode, (void *)arg, false);
}

static int do_popfd_cloexec(const struct inode *inode, unsigned long arg) {
    return do_popfd(inode, (void *)arg, true);
}

static int do_fdv(const struct inode *inode,
                  int (*fp)(const struct inode *inode, unsigned long arg),
                  const struct fdvec __user *arg) {
    int ret;
    size_t i;
    struct fdvec vec;

    if (copy_from_user(&vec, arg, sizeof(*arg)))
        return -EFAULT;

    for (i = 0; i < vec.sz; ++i) {
        unsigned long val = (unsigned long)(vec.addr + i);
        if (fp == do_pushfd) {
            // Must copy fd from userspace
            if (get_user(val, vec.addr + i))
                return -EFAULT;
        }
        if ((ret = (*fp)(inode, val)))
            return ret;
    }

    return 0;
}

static int notify_fcntl(const struct inode *inode, const unsigned int cmd,
                        unsigned long arg) {
    switch (cmd) {
    case F_PUSHFD:
        return do_pushfd(inode, arg);
    case F_POPFD:
        return do_popfd_nocloexec(inode, arg);
    case F_POPFD_CLOEXEC:
        return do_popfd_cloexec(inode, arg);
    case F_PUSHFDV:
        return do_fdv(inode, do_pushfd, (struct fdvec __user *)arg);
    case F_POPFDV:
        return do_fdv(inode, do_popfd_nocloexec, (struct fdvec __user *)arg);
    case F_POPFDV_CLOEXEC:
        return do_fdv(inode, do_popfd_cloexec, (struct fdvec __user *)arg);
    default:
        return -EINVAL;
    }

    return -EINVAL;
}

static struct tracepoint *tp_sys_exit = NULL;

static void tracepoint_sys_exit(void *data, struct pt_regs *regs, long ret) {
    if (syscall_get_nr(current, regs) == __NR_fcntl) {
        unsigned int cmd = regs_get_kernel_argument(regs, 1);
        if (cmd >= F_PUSHFD && cmd <= F_POPFDV_CLOEXEC && ret == -EINVAL) {
            struct file *f = fget(regs_get_kernel_argument(regs, 0));
            regs_set_return_value(
                regs, notify_fcntl(f->f_inode, cmd,
                                   regs_get_kernel_argument(regs, 2)));
            fput(f);
        }
    }
}

static void lookup_tracepoints(struct tracepoint *tp, void *ignore) {
    if (!tp_sys_exit && !strcmp("sys_exit", tp->name))
        tp_sys_exit = tp;
}

static int notify_close_pre(struct kprobe *kp, struct pt_regs *regs) {
    struct file *filp = (void *)regs_get_kernel_argument(regs, 0);
    // FIXME: Detect cycles involving unread messages
    if (file_count(filp) == 1) {
        struct hq_ctx *ctx;

        rcu_read_lock();
        ctx = rhashtable_lookup(&fifo_table, &filp->f_inode, map_params);
        if (ctx) {
            rhashtable_remove_fast(&fifo_table, &ctx->node, map_params);
            ctx_free(ctx, NULL);
        }
        rcu_read_unlock();
    }

    return 0;
}

static struct kprobe kp_close = {
    .symbol_name = "filp_close",
    .pre_handler = notify_close_pre,
};

static int __init mod_init(void) {
    int ret;

    if ((ret = rhashtable_init(&fifo_table, &map_params))) {
        pr_warn("Failed to initialize hashtable!\n");
        goto out;
    }

    if (!tp_sys_exit)
        for_each_kernel_tracepoint(lookup_tracepoints, NULL);

    if (!tp_sys_exit) {
        pr_err("Could not find tracepoint 'sys_exit'\n");
        ret = -ENODEV;
        goto out_rhash;
    }

    if ((ret = tracepoint_probe_register(tp_sys_exit, tracepoint_sys_exit,
                                         NULL))) {
        pr_err("Could not register tracepoint 'sys_exit'!\n");
        goto out_rhash;
    }

    if ((ret = register_kprobe(&kp_close))) {
        pr_warn("Could not find kprobe symbol '%s'!\n", kp_close.symbol_name);
        goto out_tp;
    }

    goto out;
out_tp:
    tracepoint_probe_unregister(tp_sys_exit, tracepoint_sys_exit, NULL);
    tracepoint_synchronize_unregister();
out_rhash:
    rhashtable_free_and_destroy(&fifo_table, ctx_free, NULL);
out:
    return ret;
}

static void __exit mod_exit(void) {
    if (kp_close.nmissed)
        pr_warn("Missed calls to 'close' detected: %ld!\n", kp_close.nmissed);

    unregister_kprobe(&kp_close);
    tracepoint_probe_unregister(tp_sys_exit, tracepoint_sys_exit, NULL);
    tracepoint_synchronize_unregister();
    rhashtable_free_and_destroy(&fifo_table, ctx_free, NULL);
}

module_init(mod_init);
module_exit(mod_exit);
