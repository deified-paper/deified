#ifndef _HQ_COMPAT_H_
#define _HQ_COMPAT_H_

#include "config.h"

#include <time.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef HQ_INTERFACE_FUTEX_WAITV
#include <linux/futex.h>
#include <sys/syscall.h>

#ifdef FUTEX_WAIT_MULTIPLE
typedef struct futex_wait_block futex_waitv_t;
#define futex_waitv_init(a, v, x)                                              \
    futex_waitv_t { .uaddr = a, .val = v, .bitset = FUTEX_BITSET_MATCH_ANY }
#define futex_wait_multiple(waiters, nr_futexes, flags, timespec)              \
    syscall(SYS_futex, waiters, FUTEX_WAIT_MULTIPLE | flags, nr_futexes,       \
            timespec, NULL, 0)
#else
struct futex_waitv {
      __u64 uaddr;
      __u32 val;
      __u32 flags;
};

typedef struct futex_waitv futex_waitv_t;
#define futex_waitv_init(a, v, x)                                              \
    futex_waitv_t { .uaddr = (__u64)(void *)a, .val = v, .flags = x }
#define futex_wait_multiple(waiters, nr_futexes, flags, timespec)              \
    syscall(SYS_futex, ((futex_waitv_t *)waiters)->uaddr, FUTEX_WAIT | flags, ((futex_waitv_t *)waiters)->val, timespec)
#endif
#endif

// not defined until glibc >= 2.28
#ifndef MAP_SHARED_VALIDATE
#define MAP_SHARED_VALIDATE (MAP_SHARED | MAP_PRIVATE)
#endif /* MAP_SHARED_VALIDATE */

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif /* MAP_FIXED_NOREPLACE */

// from kernel include/linux/err.h
#define MAX_ERRNO 4095

#ifndef MAP_HUGE_SHIFT
#define MAP_HUGE_SHIFT 26
#endif /* MAP_HUGE_SHIFT */

#ifndef MAP_HUGE_1GB
#define MAP_HUGE_1GB (30 << MAP_HUGE_SHIFT)
#endif /* MAP_HUGE_1GB */

#ifndef MAP_HUGE_2MB
#define MAP_HUGE_2MB (21 << MAP_HUGE_SHIFT)
#endif /* MAP_HUGE_2MB */

#endif /* _HQ_COMPAT_H_ */
