#include <csignal>
#include <iostream>
#include <sched.h>
#include <signal.h>
#include <sys/socket.h>
#include <unordered_map>

#include "compat.h"
#include "config.h"
#include "interfaces-rx.h"
#include "interfaces-verifier.h"
#include "messages-verifier.h"
#include "messages.h"
#include "process.h"
#include "verifier.h"

volatile sig_atomic_t kernel_msg;
using namespace HQ;

int create_socket_pair(int *pair) {
    if (socketpair(AF_LOCAL, SOCK_SEQPACKET, 0, pair) < 0)
        return -1;
    for (int i = 0; i < 2; i++) {
        struct timeval timeout = {std::numeric_limits<time_t>::max()};
        if (setsockopt(pair[i], SOL_SOCKET, SO_RCVTIMEO, &timeout,
                       sizeof(timeout)) < 0)
            return -1;
    }
    return 0;
}

// Futex waiter optimization
int waiton(const std::vector<futex_waitv_t> &waitv) {
    const futex_waitv_t *ptr = &waitv[0];
    // if (!ptr || !ptr->uaddr || ptr->val != *(int *)ptr->uaddr) {
    //     errno = EAGAIN;
    //     return -1;
    // }
    return futex_wait_multiple(ptr, waitv.size(), 0, nullptr);
}

template <typename V, typename RX> class ChildVerifierTy {
    V *kernel;
    bool execute;
    pid_t pid;
    int verifier_fd_;
    struct hq_verifier_msg kmsg_buf;

#ifdef HQ_INTERFACE_FUTEX_WAITV
    std::vector<futex_waitv_t> waitv;
#endif

#if INTERFACE_TYPE == INTERFACE_TYPE_OPAE
    // FPGA only supports one buffer, each message labeled with PID
    RX interface;
    using ProcessT = Process<std::nullopt_t>;
#else
    using ProcessT = HQ::Process<RX>;
#endif
    absl::flat_hash_map<pid_t, std::unique_ptr<ProcessT>> processes;

    using KernelMessageIt = typename V::const_iterator;
    using MessageIt = typename RX::const_iterator;

    using ProcessIt = typename decltype(processes)::iterator;

    pid_t get_pid() { return pid; }

  public:
    ChildVerifierTy(V *kernel_ptr, int verifier_fd)
        : kernel(kernel_ptr), execute(true), pid(getpid()),
          verifier_fd_(verifier_fd) {}

    bool handle_verifier_msgs() {
        int outfd = -1;
        while (1) {
            if (read_fd_from_socket(verifier_fd_, &kmsg_buf, sizeof(kmsg_buf),
                                    &outfd) < 0) {
                if (errno == EINTR) {
                    if (!execute) {
                        return false;
                    }
                    continue;
                }
                perror("Child process: recv");
                return false;
            }
            break;
        }

        kernel_msg--;
        auto res = parse_verifier_msgs(&kmsg_buf, outfd);
        int res_value = res.second;

        // clone special case
        bool clone = kmsg_buf.op == HQ_VERIFIER_MSG_CLONE;
        if (clone && res_value != 0) {
            // clone && child process
            int pair[2];
            if (create_socket_pair(pair) < 0) {
                perror("socketpair");
                res.first = false;
            } else {
                int send_fd = pair[0];
                send_fd_to_socket(verifier_fd_, &res_value, sizeof(res_value),
                                  send_fd);
                verifier_fd_ = pair[1];
            }
        }

        if (!clone) {
            send_fd_to_socket(verifier_fd_, &res_value, sizeof(res_value), -1);
        }

        if (!res.first)
            return false;

        return true;
    }

    void notify_parent() {
        // Notify parent process about the failure
        kill(getppid(), SIGUSR2);
    }

    void loop() {
        while (execute) {
            while (kernel_msg) {
                if (!handle_verifier_msgs()) {
                    kill_all();
                    return;
                }
            }

            if (!execute) {
                return;
            }

            if (!handle_app_msgs()) {
                notify_parent();
                return;
            }

#ifdef HQ_INTERFACE_FUTEX_WAITV
            if (waitv.size()) {
                long int ret;

                // Ignore errors from changed values, signal interruptions, and
                // invalid addresses due to process termination
                if (!kernel_msg && (ret = waiton(waitv)) < 0 &&
                    errno != EAGAIN && errno != EINTR && errno != EFAULT) {
                    std::cerr << "Failed to wait on futexes!" << std::endl;
                    break;
                }
                waitv.clear();
            } else
                pause();
#else
            sched_yield();
#endif
        }

        // Normal exit (all process terminated)
        kill_all();
    }

    std::pair<bool, int> parse_verifier_msgs(struct hq_verifier_msg *begin,
                                             int new_fd) {
        const auto pid = begin->pid, tid = begin->tid;
        auto it = processes.find(pid);

#ifndef NDEBUG
        std::cout << *begin << std::endl;
        printf("Verifier (Child) message: op:%d pid:%d tid:%d\n", begin->op,
               begin->pid, begin->tid);
#endif /* NDEBUG */

        switch (begin->op) {
        case HQ_VERIFIER_MSG_CLONE: {
            if (it == processes.end()) {
                std::cerr << "PID: " << std::dec << pid << " Unknown!"
                          << std::endl;
                return {false, 0};
            }

            auto &process = *it->second;
#ifndef HQ_CHECK_SYSCALL
            // Must ensure no pending messages remain, since system call
            // synchronization does not occur
            auto range = get_app_msgs(&process);
            if (!process_app_msgs(it->first, &process, range))
                return {false, 0};
#endif

            assert(begin->value > 0);
	    auto new_process = std::make_unique<ProcessT>(process);
            int verifier_pid = fork();
            if (verifier_pid < 0) {
                perror("Child process: fork");
                return {false, 0};
            }
            if (verifier_pid != 0) {
                // Nothing to do; the child process will take care of the
                // request
                return {true, 0};
            }

            verifier_pid = getpid();
            this->pid = verifier_pid;
            kernel->register_child_verifier(begin->value, verifier_pid);

            // Duplicate the existing process with new PID
            auto res = processes.try_emplace(
                begin->value, std::move(new_process));
            if (!res.second) {
                if (res.first->second->is_alive()) {
                    std::cerr << "PID: " << std::dec << pid
                              << " Clone already exists!" << std::endl;
                    return {false, 0};
                } else {
                    std::cout << "PID: " << std::dec << pid
                              << " Replacing dead process!" << std::endl;
                    processes[begin->value] =
                        std::make_unique<ProcessT>(process);
                }
            } else
                process.inc_stat(HQ_STAT_NUM_FORKS);

            std::cout << "PID: " << std::dec << pid << " ("
                      << process.get_name() << ") cloned to " << begin->value
                      << "!" << std::endl;

            it = processes.end();
            processes.erase(pid);

            return {true, verifier_pid};
        } break;

        case HQ_VERIFIER_MSG_MONITOR: {
            bool insert;

            // Create new process
            // TODO: receive fd on fork
            assert(pid > 0 && tid > 0);
            std::tie(it, insert) = processes.try_emplace(
                pid, std::make_unique<ProcessT>(begin->comm));
            auto &process = *it->second;
            if (insert || !process.is_alive()) {
                if (!insert) {
                    // Forked
                    begin->value = new_fd;
                }
#if INTERFACE_TYPE != INTERFACE_TYPE_OPAE
                if (!process.get_rx().open(begin->value)) {
                    std::cerr << "PID: " << std::dec << pid
                              << " Error opening application interface!"
                              << std::endl;
                    close(begin->value);
                    kill_process(pid, process);
                    return {false, 0};
                }
                close(begin->value);

                process.set_alive();
#endif
            }

            struct hq_syscall *page = nullptr;
#ifdef HQ_CHECK_SYSCALL
            // Set the system call buffer
            if (!(page = reinterpret_cast<struct hq_syscall *>(
                      kernel->map(SYSCALL_MAP_SIZE)))) {
                std::cerr << "PID: " << std::dec << pid << " TID: " << tid
                          << " Failed to map syscall page(s)!" << std::endl;
                kill_process(pid, process);
                return {false, 0};
            }
#endif /* HQ_CHECK_SYSCALL */
            process.add_thread(tid, page);

            std::cout << "PID: " << std::dec << pid << " ("
                      << process.get_name() << ") TID: " << tid << " connected!"
                      << std::endl;
        } break;

        case HQ_VERIFIER_MSG_TERMINATE: {
            if (it == processes.end()) {
                std::cerr << "PID: " << std::dec << pid << " Unknown!"
                          << std::endl;
                return {false, 0};
            }

            auto &process = *it->second;

            // Thread death, not on execve
            if (!begin->value) {
                if (!process.del_thread(tid)) {
                    std::cerr << "TID: " << std::dec << tid << " Unknown!"
                              << std::endl;
                    return {false, 0};
                }
            }

            // Cleanup on execve or death of all threads
            if (begin->value || !process.has_thread())
                process.cleanup();

            std::cout << "PID: " << std::dec << pid << " ("
                      << process.get_name() << ") TID: " << tid << " exited"
                      << (begin->value ? " on execve" : "") << "!" << std::endl;

#ifndef HQ_PRESERVE_STATS
            // Erase only on death of all threads
            if (!begin->value && !process.has_thread()) {
                std::cout << pid << "," << process << std::endl;
                processes.erase(it);
            }

            if (processes.empty()) {
                // Cleanup verifier process
                execute = false;
                return {true, 0};
            }

#endif /* HQ_PRESERVE_STATS */
        } break;

        default:
            std::cerr << "PID: " << std::dec << pid << " Unrecognized message "
                      << std::hex << begin->op << " " << begin->value << "!"
                      << std::endl;
            return {false, 0};
        }

        return {true, 0};
    }
    bool parse_app_msgs(pid_t pid, ProcessT *process,
                        std::pair<MessageIt, MessageIt> &range) {
        auto &begin = range.first;
        auto &end = range.second;

        // Process application messages
        while (begin != end) {
#if INTERFACE_TYPE == INTERFACE_TYPE_OPAE
            // Stop if next message has been overwritten
            if (!begin.is_valid())
                break;

            // Cache the last process to avoid redundant lookups
            if (!process || pid != begin->pid) {
                auto it = processes.find(static_cast<const pid_t>(begin->pid));
                if (it == processes.end()) {
                    std::cout << "PID: " << std::dec << pid << " Unrecognized!"
                              << std::endl;
                    return false;
                }

                process = it->second.get();
                pid = it->first;

                if (!process->is_alive())
                    return true;
            }
#endif
            // Stop processing application messages if kernel message pending
            if (kernel_msg)
                return true;

            assert(pid > 0);
            // Dispatch the message for processing
#ifndef NDEBUG
            std::cout << "PID: " << std::dec << pid << ", message " << *begin
                      << std::endl;
#endif /* NDEBUG */
            if (!process->parse_msg(pid, *begin)) {
                std::cerr << "begin: " << &*begin << ", end: " << &*end
                          << std::endl;
                // uint8_t *ptr = (uint8_t *)&*begin;
                // for(int i = -0x100; i < 0x100; i+=0x10) {
                //     printf("0x%02x: ", i + 0x100);
                //     for(int j = 0; j < 0x10; j++) {
                //         printf("%02hhx ", ptr[i + j]);
                //     }
                //     puts("");
                // }
                if (!kill_process(pid, *process)) {
                    std::cerr << "PID: " << std::dec << pid
                              << " Unable to kill!" << std::endl;
                    return false;
                }

                break;
            }

            ++begin;
        }

        return true;
    }

    bool process_app_msgs(pid_t pid, ProcessT *process,
                          std::pair<MessageIt, MessageIt> &range) {
#if INTERFACE_TYPE == INTERFACE_TYPE_OPAE
        while (!range.second) {
            std::cerr << "Error receiving application messages, resetting!"
                      << std::endl;

            kill_all();
            if (!interface.reset())
                return false;

            range.second = interface.get_msgs();
        }
#else
        if (!range.second) {
            std::cerr << "Error receiving application messages, destroying!"
                      << std::endl;

            process->get_rx().destroy();
            if (!kill_process(pid, *process))
                return false;
        }
#endif

        if (!parse_app_msgs(pid, process, range)) {
            std::cerr << "Error parsing application messages!" << std::endl;
            return false;
        }

        return true;
    }

    std::pair<MessageIt, MessageIt> get_app_msgs(ProcessT *process) {
#if INTERFACE_TYPE != INTERFACE_TYPE_OPAE
        auto &interface = process->get_rx();
#endif
        MessageIt &&end = interface.get_msgs(); // Must be called before begin()
        return std::make_pair(interface.begin(), (MessageIt &&) end);
    }

    bool handle_app_msgs() {
        std::pair<MessageIt, MessageIt> range;

        for (auto &p :
#if INTERFACE_TYPE == INTERFACE_TYPE_OPAE
             { -1, nullptr }
#else
             processes
#endif
        ) {
#if INTERFACE_TYPE == INTERFACE_TYPE_OPAE
            ProcessT *process = p.second;
#else
            ProcessT *process = &*p.second;
            if (!process->is_alive())
                continue;
#endif

            range = get_app_msgs(process);
            if (!process_app_msgs(p.first, process, range))
                return false;

#ifdef HQ_INTERFACE_FUTEX_WAITV
            waitv.emplace_back(process->get_rx().get_futex_waitv());
#endif
        }

        return true;
    }

    bool kill_process(pid_t pid, ProcessT &process) {
        process.cleanup();

#ifdef HQ_ENFORCE_CHECKS
        std::cout << "PID: " << std::dec << pid << " (" << process.get_name()
                  << ") killing..." << std::endl;
        if (!kernel->kill(pid) && errno != ESRCH)
            return false;
#endif /* HQ_ENFORCE_CHECKS */
        return true;
    }

    void kill_all() {
        for (auto &p : processes)
            kill_process(p.first, *p.second);

        // Print stats before exit
        print_apps(std::cout);
    }

    void print_apps(std::ostream &os) {
        os << "pid,name," << std::dec;
#define HQ_STAT(x) os << #x ",";
        HQ_STATS_LIST
#undef HQ_STAT
        os << std::endl;

        for (auto it = processes.begin(), ie = processes.end(); it != ie;
             ++it) {
            std::cout << std::dec << it->first << "," << *it->second
                      << std::endl;
        }
#if INTERFACE_TYPE == INTERFACE_TYPE_OPAE
        std::cout << interface << std::endl;
#endif
    }

    bool assign_cpus() {
// Maximum cores assigned to all verifiers
#define MAXCPU 2

        cpu_set_t mask;
        CPU_ZERO(&mask);
        for (int i = 0; i < MAXCPU; i++)
            CPU_SET(i, &mask);

        return sched_setaffinity(getpid(), sizeof(mask), &mask);
    }
};

using ChildVerifier = ChildVerifierTy<verifier_interface, rx_interface>;
ChildVerifier *g_child_verifier = NULL;

void process_kernel_msg(int signo) { kernel_msg++; }

void cleanup_child_verifier(int signo) {
    if (g_child_verifier) {
        g_child_verifier->kill_all();
    }
    exit(0);
}

#if 0
#define DEBUG puts
#else
#define DEBUG                                                                  \
    if (0)                                                                     \
    puts
#endif

void nop(int) {
    // If SIGINT is passed to all processes, the main process will forward
    // SIGUSR2 again To handle verifier error at once, I'm skipping the SIGINT
    // handler
}

std::pair<pid_t, int> get_child_verifier_instance(verifier_interface *v,
                                                  pid_t pid_from) {
    int pair[2];
    if (create_socket_pair(pair) < 0) {
        perror("socketpair");
        return {-1, -1};
    }
    DEBUG("spawning child");

    int pid = fork();
    if (pid < 0) {
        perror("fork");
        return {-1, -1};
    } else if (pid == 0) {
        struct sigaction sa = {}, oldsa = {};
        sa.sa_handler = process_kernel_msg;
        sa.sa_flags =
#ifdef FUTEX_WAIT_MULTIPLE
            0
#else
            0
#endif
            ;
        sigaction(VERIFIER_MESSAGE_SIGNAL, &sa, &oldsa);
        sa.sa_handler = cleanup_child_verifier;
        sigaction(SIGUSR2, &sa, &oldsa);
        signal(SIGINT, nop);

        auto *verifier = new ChildVerifier(v, pair[1]);
        g_child_verifier = verifier;
        verifier->assign_cpus();

        if (send(pair[1], "", 1, 0) < 0) {
            perror("send");
            exit(1);
        }

        // Refactored: VERIFIER_MESSAGE_SIGNAL is not sent for initial message
        kernel_msg = 1;
        v->register_child_verifier(pid_from, getpid());
        verifier->loop();
        exit(0);
    } else {
        char tmp[1];
        if (recv(pair[0], tmp, 1, 0) <= 0) {
            perror("recv");
            return {-1, -1};
        }
        DEBUG("child init complete!");
        return {pid, pair[0]};
    }
}
