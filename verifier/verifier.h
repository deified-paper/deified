#ifndef _HQ_VERIFIER_H_
#define _HQ_VERIFIER_H_

#include <cassert>
#include <iostream>
#include <string>
#include <sys/wait.h>
#include <tuple>
#include <type_traits>
#include <vector>

#include <signal.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/user.h>

#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "absl/container/node_hash_map.h"

#include "compat.h"
#include "config.h"
#include "interfaces.h"
#include "messages-verifier.h"
#include "messages.h"
#include "stats.h"

#include "process.h"

std::pair<pid_t, int> get_child_verifier_instance(verifier_interface *v,
                                                  pid_t pid_from);

static int read_fd_from_socket(int socket, void *outbuf, size_t size,
                               int *outfd) // receive fd from socket
{
    while (1) {
        struct msghdr msg = {0};

        char cbuf[CMSG_SPACE(sizeof(int))];
        msg.msg_control = cbuf;
        msg.msg_controllen = CMSG_SPACE(sizeof(int));

        struct iovec io = {.iov_base = outbuf, .iov_len = size};
        msg.msg_iov = &io;
        msg.msg_iovlen = 1;

        if (recvmsg(socket, &msg, 0) < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("Manager: recvmsg");
            return -1;
        }

        struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
        *outfd = msg.msg_controllen == 0 ? 0 : *(int *)CMSG_DATA(cmsg);
        return 0;
    }
}

// https://stackoverflow.com/questions/28003921/sending-file-descriptor-by-linux-socket
static bool send_fd_to_socket(int socket, const void *payload, size_t size,
                              int fd) {
    struct msghdr msg = {0};
    char cbuf[CMSG_SPACE(sizeof(fd))];
    memset(cbuf, '\0', sizeof(cbuf));
    struct iovec io = {.iov_base = (void *)payload, .iov_len = size};

    msg.msg_iov = &io;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf;
    msg.msg_controllen = fd == -1 ? 0 : CMSG_SPACE(sizeof(fd));

    if (fd != -1) {
        struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = CMSG_LEN(sizeof(fd));

        *((int *)CMSG_DATA(cmsg)) = fd;
    }

    while (1) {
        if (sendmsg(socket, &msg, 0) < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("Child process: sendmsg");
            return false;
        }
        break;
    }
    return true;
}

namespace HQ {

class TinyProcess {
    pid_t pid_;
    int fd_;
    std::set<int> threads;
    enum { ALIVE, FORKED, DEAD } status_;

  public:
    TinyProcess(pid_t pid, int fd) : pid_(pid), fd_(fd), status_(ALIVE) {}
    TinyProcess(const TinyProcess &other)
        : pid_(other.pid_), fd_(other.fd_), threads(other.threads),
          status_(other.status_) {}
    void add_thread(int tid) { threads.insert(tid); }
    void remove_thread(int tid) { threads.erase(tid); }
    void clear_threads() { threads.clear(); }
    void cleanup() {
        threads.clear();
        set_dead();
    }
    bool has_threads() { return !threads.empty(); }

    pid_t pid() const { return pid_; }
    int fd() const { return fd_; }

    bool is_alive() { return status_ == ALIVE; }

    void set_alive() { status_ = ALIVE; }
    void set_forked() { status_ = FORKED; }
    void set_dead() { status_ = DEAD; }
    void set_fd(int fd) { fd_ = fd; }
    void set_pid(pid_t pid) { pid_ = pid; }
};

template <typename V> class Verifier {
    V kernel;

    using KernelMessageIt = typename V::const_iterator;
    // app pid -> child verifier pid
    absl::flat_hash_map<pid_t, TinyProcess> child_verifiers;
    // received between fork and register_child_verifier
    absl::flat_hash_map<pid_t, int> enqueued_signals;
    std::atomic<unsigned int> max_processes;

  public:
    Verifier() {
        if (!kernel.open()) {
            std::cerr << "Error opening verifier interface!" << std::endl;
            exit(1);
        }

#if INTERFACE_TYPE == INTERFACE_TYPE_OPAE
        if (!interface.open(-1)) {
            std::cerr << "Error opening OPAE interface!" << std::endl;
        }
#endif
    }

    ~Verifier() {
        std::cout << "Max Processes: " << max_processes << std::endl;
    }

    void kill_all() {
        for (auto &p : child_verifiers) {
            std::cerr << "Terminating verifier pid: " << p.second.pid()
                      << std::endl;
            kill_child_verifier(p.second.pid());
        }
    }

    std::tuple<bool, int, int> forward(const TinyProcess &child_verifier,
                                       KernelMessageIt &msg, int send_fd = -1) {
        int result = 0;
        if (!send_fd_to_socket(child_verifier.fd(), msg,
                               sizeof(struct hq_verifier_msg), send_fd)) {
            return {false, -1, -1};
        }

        // Refactored: child verifier now receives SIGUSR1 from kernel as well,
        // so no need to send this
        // kill(child_verifier_pid, SIGUSR1);
        int recv_fd = -1;
        if (read_fd_from_socket(child_verifier.fd(), &result, sizeof(result),
                                &recv_fd) < 0) {
            return {false, -1, -1};
        }
        return {true, result, recv_fd};
    }

    bool handle_verifier_msgs() {
        auto range = get_verifier_msgs();
        return process_verifier_msgs(range);
    }

    std::pair<KernelMessageIt, KernelMessageIt> get_verifier_msgs() {
        return std::make_pair(kernel.begin(), kernel.get_msgs());
    }

    void update_max_processes() {
        auto old_sz = max_processes.load();
        auto new_sz = child_verifiers.size();
        while (old_sz < new_sz &&
               !max_processes.compare_exchange_weak(old_sz, new_sz)) {
        }
    }

    bool
    parse_verifier_msgs(std::pair<KernelMessageIt, KernelMessageIt> &range) {
        auto &begin = range.first;
        auto &end = range.second;
        int res = 0, new_pid = 0, new_fd = -1;

        while (begin != end) {
            const auto pid = begin->pid, tid = begin->tid;
            auto it = child_verifiers.find(pid);

            printf("Verifier message (%p): op:%d pid:%d tid:%d\n", &*begin,
                   begin->op, begin->pid, begin->tid);

            switch (begin->op) {
            case HQ_VERIFIER_MSG_MONITOR: {
                bool insert;

                if (it != child_verifiers.end()) {
                    int send_fd = -1;
                    if (!it->second.is_alive()) {
                        // Verifier <-> forked/execed child verifier is not
                        // connected, so need to duplicate fd
                        send_fd = begin->value;
                        it->second.set_alive();
                    }
                    it->second.add_thread(tid);
                    {
                        auto enqueue_it = enqueued_signals.find(pid);
                        if (enqueue_it != enqueued_signals.end()) {
                            auto child_verifier_pid = it->second.pid();
                            auto count = enqueue_it->second;
                            std::cout << "Sending " << count
                                      << " pending signals to "
                                      << child_verifier_pid;
                            while (count--) {
                                kill(child_verifier_pid,
                                     VERIFIER_MESSAGE_SIGNAL);
                            }
                            enqueue_it = enqueued_signals.end();
                            enqueued_signals.erase(pid);
                        }
                    }
                    std::tie(res, new_pid, std::ignore) =
                        forward(it->second, begin, send_fd);
                    if (send_fd != -1) {
                        close(send_fd);
                    }
                } else {
                    // Create new process
                    assert(pid > 0 && tid > 0);
                    pid_t verifier_pid, verifier_fd;
                    std::tie(verifier_pid, verifier_fd) =
                        get_child_verifier_instance(&kernel, pid);

                    close(begin->value);
                    if (verifier_pid == -1) {
                        std::cerr
                            << "PID: " << std::dec << pid
                            << " Error spawning a child verifier! (Manager)"
                            << std::endl;
                        return false;
                    }

                    // TODO: check insert == true
                    std::tie(it, insert) = child_verifiers.try_emplace(
                        pid, verifier_pid, verifier_fd);
                    update_max_processes();

                    it->second.add_thread(tid);
                    std::tie(res, new_pid, std::ignore) =
                        forward(it->second, begin);
                }
                if (!res)
                    return false;
            } break;

            case HQ_VERIFIER_MSG_CLONE: {
                if (it == child_verifiers.end()) {
                    std::cerr << "PID: " << std::dec << pid
                              << " Unknown! (Manager)" << std::endl;
                    return false;
                }
                std::tie(res, new_pid, new_fd) = forward(it->second, begin);
                if (!res)
                    return false;
                // printf("Manager: received %d -> %d\n", it->first, new_pid);
                TinyProcess new_process(it->second);
                new_process.set_fd(new_fd);
                new_process.set_pid(new_pid);
                new_process.set_forked();
                new_process.clear_threads();

                child_verifiers.try_emplace(begin->value, new_process);
            } break;

            case HQ_VERIFIER_MSG_TERMINATE: {
                if (it == child_verifiers.end()) {
                    std::cerr << "PID: " << std::dec << pid
                              << " Unknown! (Manager)" << std::endl;
                    return false;
                }
                std::tie(res, std::ignore, std::ignore) =
                    forward(it->second, begin);

                it->second.remove_thread(tid);
                if (begin->value || !it->second.has_threads()) {
                    it->second.cleanup();
                }

                if (!begin->value && !it->second.has_threads()) {
                    if (!kernel.unregister_child_verifier(pid,
                                                          it->second.pid())) {
                        return false;
                    }
                    child_verifiers.erase(pid);
                }
                if (!res)
                    return false;
            } break;
            case HQ_VERIFIER_MSG_ENQUEUE_SIGNAL: {
                if (it != child_verifiers.end()) {
                    // if this does not hold, Initial message; nothing to do
                    // Also is_alive() == true if initial message
                    if (!it->second.is_alive())
                        enqueued_signals[pid]++;
                }
            } break;
            default:
                std::cerr << "PID: " << std::dec << pid
                          << " Unrecognized message " << std::hex << begin->op
                          << " " << begin->value << "!" << std::endl;
                return false;
            }

            ++begin;
        }

        return true;
    }

    bool
    process_verifier_msgs(std::pair<KernelMessageIt, KernelMessageIt> &range) {
        if (!range.second) {
            std::cerr << "Error receiving verifier messages!" << std::endl;
            return false;
        }

        if (!parse_verifier_msgs(range)) {
            std::cerr << "Error parsing verifier messages!" << std::endl;
            return false;
        }

        return true;
    }

    bool kill_child_verifier(pid_t pid) {
        // TODO: SIGUSR2
        if (kill(pid, SIGKILL))
            return true;
        waitpid(pid, NULL, 0);
        return false;
    }
};

} // namespace HQ

#endif /* _HQ_VERIFIER_H_ */

