#include <cstdint>
#include <cstdlib>
#include <new>
#include <type_traits>

#include <pthread.h>
#include <signal.h>
#include <unistd.h>

#include "config.h"
#include "interfaces-tx.h"
#include "rtlib.h"
#include "runtime.h"
#include "syscalls.h"

/* Internal variables */

// Use a statically allocated buffer with placement new to prevent destructor
// from automatically being called. Otherwise, internal libc cleanup functions
// will not be able to make system calls, because the interface will have been
// automatically destroyed.
static std::aligned_storage<sizeof(tx_interface), alignof(tx_interface)>::type
    buffer;
tx_interface &interface = *reinterpret_cast<tx_interface *>(&buffer);

extern "C" {

/* Function implementations */
// These functions cannot be inlined because they are called directly by musl
// while loading the program, so put them here.

void INIT_FUNCTION(int fork) {
    uintptr_t addr;

    // Skip duplicate initializations
    if (interface && !fork)
        return;

    // Enable HQ
    if (RAW_SYSCALL(5, SYS_prctl, PR_HQ, (uintptr_t)&addr, fork, 0, 0)) {
        constexpr static char err[] = "Error enabling HQ!\n";
        RAW_SYSCALL(3, SYS_write, STDERR_FILENO,
                    reinterpret_cast<uintptr_t>(err), sizeof(err));
        RAW_SYSCALL(1, SYS_exit_group, -1);
    }

    // Normal library functions are now available since the interface is up

    // Initialize via placement new
    new (&buffer) tx_interface();
    if (!interface.initialize(reinterpret_cast<void *>(addr))) {
        constexpr static char err[] = "Error opening interface!\n";
        RAW_SYSCALL(3, SYS_write, STDERR_FILENO,
                    reinterpret_cast<uintptr_t>(err), sizeof(err));
        RAW_SYSCALL(1, SYS_exit_group, -1);
    }

    // Define the TID variable since it is checked in system calls
    const int *tid = reinterpret_cast<int *>(pthread_self() + 0x30);
    __hq_pointer_define((const void **)tid, (void *)(intptr_t)*tid, false);

    // Normal library functions are now available since the interface is up
    // Block on dummy syscall until verifier catches up
    getuid();
}
}
