#ifndef _HQ_FDS_COMPAT_
#define _HQ_FDS_COMPAT_

#include <linux/security.h>
#include <linux/version.h>
#include <net/sock.h>

#define F_PUSHFD 100
#define F_POPFD 101
#define F_POPFD_CLOEXEC 102
#define F_PUSHFDV 103
#define F_POPFDV 104
#define F_POPFDV_CLOEXEC 105

struct fdvec {
   int64_t *addr;
   size_t sz;
};

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

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 16, 0)
static inline void regs_set_return_value(struct pt_regs *regs,
                                         unsigned long rc) {
    regs->ax = rc;
}
#endif /* LINUX_VERSION_CODE */

#endif
