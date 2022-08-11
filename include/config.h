#ifndef _HQ_CONFIG_H_
#define _HQ_CONFIG_H_

/* Cacheline size (bytes) */
#define CACHELINE_BYTES 64

/* Default buffer size (bytes) for application messages.
 * Must be aligned to page size.  */
#define HQ_INTERFACE_APPLICATION_SIZE (256UL * 1024UL * 1024UL)

/* Default buffer size (bytes) for kernel messages */
#define HQ_INTERFACE_KERNEL_SIZE (32UL * 1024UL)

/* Default address for memory-mapped interfaces */
#define HQ_INTERFACE_MAP_ADDRESS 0x80000000ULL

/* Whether to enable waiting on multiple futexes at the same time. Requires
 * a kernel with FUTEX_WAIT_MULTIPLE or futex_waitv (futex2) support. */
// #define HQ_INTERFACE_FUTEX_WAITV

/* Whether to enable emulation of append-only page permissions using Memory
 * Protection Keys for Userspace. */
// #define HQ_INTERFACE_MPK

/* Whether to enable write-combining for OPAE interface. Will need to build
 * applications and libraries with `-mclflushopt` */
// #define HQ_INTERFACE_OPAE_WC

/* Whether to enable concurrent-safe messaging. This is needed if threads may
 * execute concurrently. */
// #define HQ_INTERFACE_UNSAFE_PID_CONCURRENT

/* Whether the verifier should preserve statistics after instrumented processes
 * have exited */
// #define HQ_PRESERVE_STATS

/* Whether to perform system call checking */
#define HQ_CHECK_SYSCALL

/* Whether to allow certain system calls for compatibility with rr */
// #define HQ_UNSAFE_COMPAT_RR

/* Whether to kill the application when a check fails */
#define HQ_ENFORCE_CHECKS

/* Signal to send when killing an application */
#define HQ_KILL_SIGNAL SIGKILL

/* Whether to kill the application when the system call wait has exceeded a hard
 * threshold, and if so, the threshold in milliseconds */
#define HQ_ENFORCE_SYSCALL_HARD 2000

/* Threshold at which internal globals are initialized in verifier */
#define HQ_GLOBALS_INTERNAL_THRESHOLD 500

/* Threshold (ms) before sleeping while waiting on a system call */
#define HQ_SYSCALL_THRESHOLD 1

/* Sleep duration exponential backoff multiplier after exceeding threshold */
#define HQ_SYSCALL_SLEEP_MULTIPLIER 3

/* Maximum sleep interval (ms) while waiting on a system call */
#define HQ_SYSCALL_SLEEP_MAX 1000

/* For configuration affecting the LLVM instrumentation, refer to the
 * command-line options embedded within the LLVM plugin. */

#endif /* _HQ_CONFIG_H_ */
