#ifndef _HQ_VERIFIER_
#define _HQ_VERIFIER_

#include "interfaces.h"

#include <linux/file.h>
#include <linux/fs.h>

#define VERIFIER_MSG_FIFO_SIZE 128
#define INTERFACE_DEVICE_NAME "hq-verifier"

/* Declared definitions */
extern const struct file_operations verifier_interface_fops;

int verifier_is_connected(void);
int verifier_interface_on_clone(pid_t ptgid, pid_t tgid, struct hq_ctx *ctx);
int verifier_interface_on_exit(pid_t tgid, pid_t pid, int execve);
int verifier_interface_monitor(pid_t tgid, struct hq_ctx *ctx, struct file *);

#endif /* _HQ_VERIFIER */
