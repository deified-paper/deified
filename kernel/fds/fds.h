#ifndef _HQ_FDS_
#define _HQ_FDS_

#include <linux/file.h>
#include <linux/fs.h>
#include <linux/kfifo.h>
#include <linux/rhashtable.h>
#include <linux/spinlock.h>

#ifdef pr_fmt
#undef pr_fmt
#endif
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#define HQ_FIFO_SIZE 128

struct hq_ctx {
    const struct inode *inode;
    struct rhash_head node;
    spinlock_t lock;
    DECLARE_KFIFO(fifo, struct file *, HQ_FIFO_SIZE);
    struct rcu_head head;
};

#endif
