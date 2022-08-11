#include <linux/debugfs.h>
#include <linux/gfp.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/rhashtable.h>
#include <linux/sched/signal.h>

#include <asm/pgtable.h>

#include "config.h"
#include "hooks.h"
#include "hq.h"
#include "interface.h"
#include "messages-verifier.h"

MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("Generic interface for HQ");
MODULE_VERSION("0.1");

/* Per-pid hashtable */
const struct rhashtable_params hq_params = {
    .key_len = sizeof(((struct hq_ctx *)NULL)->pid),
    .key_offset = offsetof(struct hq_ctx, pid),
    .head_offset = offsetof(struct hq_ctx, node),
};
struct rhashtable hq_table;

/* Debugfs directory */
struct dentry *debugfs;

/* Exported interface for getting this module */
struct module *hq_get_module(void) {
    return THIS_MODULE;
}
EXPORT_SYMBOL(hq_get_module);

/* Implementation of per-application context functions */
void init_hq_context(struct hq_ctx *ctx, struct task_struct *task) {
    ctx->pid = task_pid_nr(task);
    ctx->vpid = task_pid_vnr(task);
    ctx->status = INACTIVE;
    ctx->verifier_pid = 0;
    get_task_comm(ctx->name, current);

    pr_debug("Creating context pid %d for process '%s'...\n", ctx->pid,
             ctx->name);

#ifdef HQ_CHECK_SYSCALL
    // Allocate aligned page(s), or re-use existing page(s)
    if (!ctx->syscall)
        ctx->syscall = (struct hq_syscall *)__get_free_pages(
            GFP_USER | __GFP_ZERO, get_order(SYSCALL_MAP_SIZE));
#endif /* HQ_CHECK_SYSCALL */

    memset(ctx->stats, 0, sizeof(*ctx->stats));
}

void copy_hq_context(struct hq_ctx *new, struct hq_ctx *old, pid_t pid,
                     pid_t vpid) {
    int max;

    new->pid = pid;
    new->vpid = vpid;
    new->status = ACTIVE_FORK;
    new->verifier_pid = 0;
    strncpy(new->name, old->name, sizeof(new->name));

    pr_debug("Copying context from %d to %d for process '%s'...\n", old->pid,
             pid, old->name);

#ifdef HQ_CHECK_SYSCALL
    // Allocate aligned page(s), or re-use existing page(s)
    if (!new->syscall)
        new->syscall = (struct hq_syscall *)__get_free_pages(
            GFP_USER | __GFP_ZERO, get_order(SYSCALL_MAP_SIZE));
#endif /* HQ_CHECK_SYSCALL */

    max = atomic_read(&old->stats[HQ_STAT_MAX_ENTRIES]);
    atomic_set(&new->stats[HQ_STAT_MAX_ENTRIES], max);
}

void free_hq_context(void *pctx, void *erase) {
    struct hq_ctx *ctx = pctx;
#ifdef HQ_CHECK_SYSCALL
    struct hq_syscall *syscall = ctx->syscall;
#endif /* HQ_CHECK_SYSCALL */

    ctx->status = DEAD;
#ifdef HQ_CHECK_SYSCALL
    // Free the pages
    if (syscall) {
        ctx->syscall = NULL;
        free_pages((unsigned long)syscall, get_order(SYSCALL_MAP_SIZE));
    }
#endif /* HQ_CHECK_SYSCALL */

    // To preserve statistics, delete context only if module is being unloaded
    if (erase) {
        pr_debug("Destroying context pid %d for process '%s'...\n", ctx->pid,
                 ctx->name);
        kfree_rcu(ctx, rcu);
    }
}

/* Implementation of module init/exit functions */
static int __init hq_mod_init(void) {
    int ret;

    // Create per-pid hashtable
    if ((ret = rhashtable_init(&hq_table, &hq_params))) {
        pr_warn("Unable to create hashtable!\n");
        return ret;
    }

    // Initialize FPGA
    if ((ret = fpga_init())) {
        pr_warn("Unable to find FPGA device!\n");
        goto err_hashtable;
    }

    // Insert tracepoints
    if ((ret = tracepoints_insert())) {
        pr_warn("Unable to insert tracepoints!\n");
        goto err_fpga;
    }

    // Insert kprobes
    if ((ret = kprobes_insert())) {
        pr_warn("Unable to insert kprobes!\n");
        goto err_tracepoints;
    }

    // Create debugfs directory
    debugfs = debugfs_create_dir(HQ_CLASS_NAME, NULL);
    if (IS_ERR(debugfs)) {
        pr_warn("Creation of debugfs directory " HQ_CLASS_NAME " failed!\n");
        ret = PTR_ERR(debugfs);
        goto err_kprobes;
    }

    // Register interface
    if ((ret = interface_register())) {
        pr_warn("Unable to register interface!\n");
        goto err_debugfs;
    }

    return ret;

err_debugfs:
    debugfs_remove_recursive(debugfs);
err_kprobes:
    kprobes_remove();
err_tracepoints:
    tracepoints_remove();
err_hashtable:
    fpga_finish();
err_fpga:
    rhashtable_destroy(&hq_table);
    return ret;
}

static void __exit hq_mod_exit(void) {
    // Unregister the interface
    interface_unregister();

    // Remove the debugfs directory
    debugfs_remove_recursive(debugfs);

    // Remove kprobes
    kprobes_remove();

    // Remove syscall hooks
    tracepoints_remove();

    // Cleanup FPGA
    fpga_finish();

    // Delete all contexts
    rhashtable_free_and_destroy(&hq_table, free_hq_context, (void *)1);
}

module_init(hq_mod_init);
module_exit(hq_mod_exit);
