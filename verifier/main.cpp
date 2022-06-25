#include <csignal>
#include <iostream>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unordered_map>

#include "compat.h"
#include "config.h"
#include "interfaces-rx.h"
#include "interfaces-verifier.h"
#include "messages.h"
#include "process.h"
#include "verifier.h"

volatile sig_atomic_t execute = true, main_kernel_msg = false;
HQ::Verifier<verifier_interface> verifier;

static void signal_handler(int sig, siginfo_t *info, void *ucontext) {
    if (sig == SIGINT) {
        execute = false;
        verifier.kill_all();
        exit(0);
    } else if (sig == VERIFIER_MESSAGE_SIGNAL) {
    } else if (sig == SIGUSR2) {
        // Errors from child processes
        execute = false;
    }
}

void waiter(int signo) { wait(NULL); }

int main(int argc, char **argv) {
    int ret = 0;

    // Register signal handler
    struct sigaction sa;
    sa.sa_sigaction = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_SIGINFO | SA_RESTART;
    for (const auto &s : {SIGINT, VERIFIER_MESSAGE_SIGNAL, SIGUSR2}) {
        if (sigaction(s, &sa, nullptr) == -1) {
            std::cerr << "Error registering signal handler!" << std::endl;
            return -1;
        }
    }

    signal(SIGCHLD, waiter);

    std::cout << "Awaiting messages..." << std::endl;
    // Read and loop on messages
    while (execute) {
        // handle_verifier_msgs moved to signal handler
        if (!verifier.handle_verifier_msgs()) {
            execute = false;
        }
    }

    // Kill all remaining processes
    verifier.kill_all();
    return ret;
}
