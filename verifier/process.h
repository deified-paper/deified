#ifndef _HQ_VERIFIER_PROCESS_H_
#define _HQ_VERIFIER_PROCESS_H_

#include <array>
#include <atomic>
#include <ostream>
#include <string>

#include <sys/mman.h>
#include <sys/user.h>

#include "absl/container/btree_map.h"

#include "config.h"
#include "interfaces-verifier.h"
#include "interfaces.h"
#include "messages-verifier.h"
#include "messages.h"
#include "stats.h"
#include "verifier-elf.h"

namespace HQ {
std::ostream &operator<<(std::ostream &os, const hq_msg &msg);
std::ostream &operator<<(std::ostream &os, const hq_verifier_msg &msg);

template <typename RX> class Process {
    // Process status
    enum { ALIVE, FORKED, DEAD } status;
    // Process name
    std::string name;
    // Interface buffer for receiving messages
    RX rx;
    // Program data entries
    absl::btree_map<uintptr_t, uintptr_t> entries;
    // Shared kernel buffer for controlling system calls
    absl::btree_map<pid_t, struct hq_syscall *> syscalls;
    // Statistics
    std::array<std::atomic<unsigned int>, HQ_NUM_STATS> stats = {
        ATOMIC_VAR_INIT(0)};

    void define_pointer(uintptr_t ptr, uintptr_t val) {
        stats[HQ_STAT_NUM_DEFINES]++;

        entries[ptr] = val;

        auto old_sz = stats[HQ_STAT_MAX_ENTRIES].load();
        auto new_sz = entries.size();
        while (
            old_sz < new_sz &&
            !stats[HQ_STAT_MAX_ENTRIES].compare_exchange_weak(old_sz, new_sz)) {
        }
    }

    bool check_pointer(uintptr_t ptr, uintptr_t val, bool erase) {
        stats[erase ? HQ_STAT_NUM_CHECK_INVALIDATES : HQ_STAT_NUM_CHECKS]++;

        const auto it = entries.find(ptr);
        if (__builtin_expect(it != entries.end(), 1)) {
            const auto last = it->second;
            if (erase)
                entries.erase(ptr);

            if (__builtin_expect(last == val, 1))
                return true;

            std::cerr << (erase ? "Check-invalidate" : "Check")
                      << " failed on pointer " << std::hex << ptr << ", values "
                      << val << " != " << last << std::endl;
        } else {
            std::cerr << (erase ? "Check-invalidate" : "Check")
                      << " failed on missing pointer " << std::hex << ptr
                      << ", values " << val << std::endl;
        }

        stats[HQ_STAT_NUM_FAILS]++;
        return false;
    }

  public:
    Process(std::string &&s) : status(ALIVE), name(s), rx({}) {}

    Process(const Process &other)
        : status(FORKED), name(other.name), rx({}), entries(other.entries) {}

    Process(Process &&old) { *this = std::move(old); }

    ~Process() { cleanup(); }

    Process &operator=(Process &&old) {
        if (this != &old) {
            status = old.status;
            name = std::move(old.name);
            rx = std::move(old.rx);
            entries = std::move(old.entries);
            syscalls = std::move(old.syscalls);
            for (unsigned i = 0; i < old.stats.size(); ++i)
                stats[i] = old.stats[i].load();
        }

        return *this;
    }

    void cleanup() {
        set_dead();
#if INTERFACE_TYPE != INTERFACE_TYPE_OPAE
        rx.destroy();
#endif
#ifdef HQ_PRESERVE_STATS
        clear_entries();
#endif /* HQ_PRESERVE_STATS */
#ifdef HQ_CHECK_SYSCALL
        for (auto &p : syscalls) {
            verifier_interface::unmap(p.second);
            p.second = nullptr;
        }
#endif
    }

    bool is_alive() const { return status == ALIVE; }
    bool is_dead() const { return status == DEAD; }
    bool is_forked() const { return status == FORKED; }
    void set_alive() { status = ALIVE; }
    void set_dead() { status = DEAD; }

    void clear_entries() { entries.clear(); }

    void add_thread(pid_t tid, struct hq_syscall *s) {
        syscalls[tid] = s;

        auto old_sz = stats[HQ_STAT_MAX_THREADS].load();
        auto new_sz = syscalls.size();
        while (
            old_sz < new_sz &&
            !stats[HQ_STAT_MAX_THREADS].compare_exchange_weak(old_sz, new_sz)) {
        }
    }
    bool del_thread(pid_t tid) { return syscalls.erase(tid); }
    bool has_thread() const { return syscalls.size(); }

    RX &get_rx() { return rx; }

    const std::string &get_name() const { return name; }
    unsigned get_stat(enum hq_stats stat) const { return stats.at(stat); }
    void inc_stat(enum hq_stats stat) { stats[stat]++; }

    bool parse_msg(const pid_t pid, const struct hq_msg &msg) {
        switch (msg.op) {
        case HQ_MSG_DEFINE_PRIVATE:
        case HQ_MSG_DEFINE: {
            const uintptr_t ptr = msg.values[0], val = msg.values[1];

            // Check for pointer alignment
            if (__builtin_expect(POINTER_IS_MISALIGNED(ptr), 0)) {
                std::cerr << "Define failed on unaligned pointer " << std::hex
                          << ptr << std::endl;
                stats[HQ_STAT_NUM_FAILS]++;
                return false;
            }

            define_pointer(ptr, val);
            return true;
        }

        case HQ_MSG_DEFINE_BLOCK_PRIVATE:
        case HQ_MSG_DEFINE_BLOCK: {
            const uintptr_t ptr = msg.values[0], sz = msg.values[1];

            // Check for overflow
            if (__builtin_expect(ptr + sz < ptr, 0)) {
                std::cerr << "Define-block failed on range " << std::hex << ptr
                          << ",sz=" << sz << " due to overflow!" << std::endl;
                stats[HQ_STAT_NUM_FAILS]++;
                return false;
            }

            // Check for pointer alignment
            if (__builtin_expect(
                    POINTER_IS_MISALIGNED(ptr) || SIZE_IS_MISALIGNED(sz), 0)) {
                std::cerr << "Define-block failed on unaligned pointer "
                          << std::hex << ptr << " or size " << sz << std::endl;
                stats[HQ_STAT_NUM_FAILS]++;
                return false;
            }

            for (uintptr_t i = 0; i < sz; i += POINTER_VALUE_SIZE)
                define_pointer(ptr + i, *reinterpret_cast<const uintptr_t *>(
                                            &msg.contents[i]));

            return true;
        }

        case HQ_MSG_CHECK: {
            const uintptr_t ptr = msg.values[0], val = msg.values[1];

            // Check for pointer alignment
            if (__builtin_expect(POINTER_IS_MISALIGNED(ptr), 0)) {
                std::cerr << "Check failed on unaligned pointer " << std::hex
                          << ptr << std::endl;
                stats[HQ_STAT_NUM_FAILS]++;
                return false;
            }

            return check_pointer(ptr, val, false);
        }

        case HQ_MSG_CHECK_BLOCK: {
            const uintptr_t ptr = msg.values[0], sz = msg.values[1];

            // Check for overflow
            if (__builtin_expect(ptr + sz < ptr, 0)) {
                std::cerr << "Check-block failed on range " << std::hex << ptr
                          << ",sz=" << sz << " due to overflow!" << std::endl;
                stats[HQ_STAT_NUM_FAILS]++;
                return false;
            }

            // Check for pointer alignment
            if (__builtin_expect(
                    POINTER_IS_MISALIGNED(ptr) || SIZE_IS_MISALIGNED(sz), 0)) {
                std::cerr << "Check-block failed on unaligned pointer "
                          << std::hex << ptr << " or size " << sz << std::endl;
                stats[HQ_STAT_NUM_FAILS]++;
                return false;
            }

            for (uintptr_t i = 0; i < sz; i += POINTER_VALUE_SIZE)
                if (!check_pointer(
                        ptr + i,
                        *reinterpret_cast<const uintptr_t *>(&msg.contents[i]),
                        false))
                    return false;

            return true;
        }

        case HQ_MSG_INVALIDATE: {
            const uintptr_t ptr = msg.values[1];

            stats[HQ_STAT_NUM_INVALIDATES]++;

            entries.erase(ptr);
            return true;
        }

        case HQ_MSG_CHECK_INVALIDATE: {
            const uintptr_t ptr = msg.values[0], val = msg.values[1];

            // Check for pointer alignment
            if (__builtin_expect(POINTER_IS_MISALIGNED(ptr), 0)) {
                std::cerr << "Check-invalidate failed on unaligned pointer "
                          << std::hex << ptr << std::endl;
                stats[HQ_STAT_NUM_FAILS]++;
                return false;
            }

            return check_pointer(ptr, val, true);
        }

        case HQ_MSG_COPY_BLOCK: {
            std::vector<typename decltype(entries)::value_type> copy;
            const uintptr_t dst = ADDRESS_FROM_EMBED(msg.values[0]),
                            src = ADDRESS_FROM_EMBED(msg.values[1]),
                            sz = SIZE_FROM_EMBED(msg.values[0], msg.values[1]);

            stats[HQ_STAT_NUM_COPIES]++;

            // Check for same offset or empty size
            if (__builtin_expect(dst == src || !sz, 0))
                return true;

            // Check for overflow
            if (__builtin_expect(dst + sz < dst || src + sz < src, 0)) {
                std::cerr << "Copy failed on range " << std::hex << std::hex
                          << src << ",sz=" << sz << " to " << dst
                          << " due to overflow!" << std::endl;
                stats[HQ_STAT_NUM_FAILS]++;
                return false;
            }

            // Check for pointer alignment
            if (__builtin_expect(POINTER_IS_MISALIGNED(dst) ||
                                     POINTER_IS_MISALIGNED(src) ||
                                     SIZE_IS_MISALIGNED(sz),
                                 0)) {
                std::cerr << "Copy failed on unaligned pointers " << std::hex
                          << dst << ", " << src << ", or size " << sz
                          << std::endl;
                stats[HQ_STAT_NUM_FAILS]++;
                return false;
            }

            // Copy existing entries in old region - may overlap
            const auto ub = entries.lower_bound(src + sz);
            for (auto it = entries.lower_bound(src); it != ub; ++it) {
                assert(it->first >= src && it->first < src + sz);
                copy.emplace_back((it->first - src) + dst, it->second);
            }

            // Delete matching entries in new region
            entries.erase(entries.lower_bound(dst),
                          entries.lower_bound(dst + sz));

            // Insert entries into new region
            entries.insert(copy.begin(), copy.end());

            auto old_sz = stats[HQ_STAT_MAX_ENTRIES].load();
            auto new_sz = entries.size();
            while (old_sz < new_sz &&
                   !stats[HQ_STAT_MAX_ENTRIES].compare_exchange_weak(old_sz,
                                                                     new_sz)) {
            }

            return true;
        }

        case HQ_MSG_INVALIDATE_BLOCK: {
            const uintptr_t ptr = msg.values[0], sz = msg.values[1];

            stats[HQ_STAT_NUM_FREES]++;

            // Check for null pointer or empty size
            if (__builtin_expect(!ptr || !sz, 0))
                return true;

            // Check for overflow
            if (__builtin_expect(ptr + sz < ptr, 0)) {
                std::cerr << "Invalidate failed on range " << std::hex << ptr
                          << ",sz=" << sz << " due to overflow!" << std::endl;
                stats[HQ_STAT_NUM_FAILS]++;
                return false;
            }

            // Check for pointer alignment
            if (__builtin_expect(
                    POINTER_IS_MISALIGNED(ptr) || SIZE_IS_MISALIGNED(sz), 0)) {
                std::cerr << "Copy failed on unaligned pointer " << std::hex
                          << ptr << ", " << ptr << ", or size " << sz
                          << std::endl;
                stats[HQ_STAT_NUM_FAILS]++;
                return false;
            }

            // Delete matching entries in new region
            entries.erase(entries.lower_bound(ptr),
                          entries.lower_bound(ptr + sz));

            return true;
        }

        case HQ_MSG_MOVE_BLOCK: {
            const uintptr_t dst = ADDRESS_FROM_EMBED(msg.values[0]),
                            src = ADDRESS_FROM_EMBED(msg.values[1]),
                            sz = SIZE_FROM_EMBED(msg.values[0], msg.values[1]);

            stats[HQ_STAT_NUM_MOVES]++;

            // Check for null destination, same offset, or empty size
            if (__builtin_expect(!dst || dst == src || !sz, 0))
                return true;

            // Check for range overlap or overflow
            if (__builtin_expect((src < dst + sz && src + sz > dst) ||
                                     dst + sz < dst || src + sz < src,
                                 0)) {
                std::cerr << "Relocate failed on range " << std::hex << src
                          << ",sz=" << sz << " to " << dst
                          << " due to overflow!" << std::endl;
                stats[HQ_STAT_NUM_FAILS]++;
                return false;
            }

            // Check for pointer alignment
            if (__builtin_expect(POINTER_IS_MISALIGNED(dst) ||
                                     POINTER_IS_MISALIGNED(src) ||
                                     SIZE_IS_MISALIGNED(sz),
                                 0)) {
                std::cerr << "Relocate failed on unaligned pointers "
                          << std::hex << dst << ", " << src << ", or size "
                          << sz << std::endl;
                stats[HQ_STAT_NUM_FAILS]++;
                return false;
            }

            // Delete matching entries in new region
            entries.erase(entries.lower_bound(dst),
                          entries.lower_bound(dst + sz));

            // Move existing entries in old region
            const uintptr_t ub = src + sz;
            for (const auto it = entries.lower_bound(src);
                 it != entries.lower_bound(ub);) {
                assert(it->first >= src && it->first < src + sz);
                auto entry = entries.extract(it);
                entry.key() = (entry.key() - src) + dst;

                // Insert the new entry
                auto ins = entries.insert(std::move(entry));
                assert(ins.inserted);
            }

            auto old_sz = stats[HQ_STAT_MAX_ENTRIES].load();
            auto new_sz = entries.size();
            while (old_sz < new_sz &&
                   !stats[HQ_STAT_MAX_ENTRIES].compare_exchange_weak(old_sz,
                                                                     new_sz)) {
            }

            return true;
        }

        case HQ_MSG_SYSCALL: {
            stats[HQ_STAT_NUM_SYSCALLS]++;

#ifdef HQ_CHECK_SYSCALL
            const pid_t tid = msg.values[1];

            const auto it = syscalls.find(tid);
            if (__builtin_expect(it == syscalls.end(), 0)) {
                std::cerr << "TID: " << std::dec << tid
                          << " Missing syscall buffer!" << std::endl;
                stats[HQ_STAT_NUM_FAILS]++;
                return false;
            }

            __atomic_store_n(&it->second->ok, 1, __ATOMIC_RELEASE);
#endif /* HQ_CHECK_SYSCALL */
            return true;
        } break;

        case HQ_MSG_INIT_GLOBALS: {
            const uintptr_t base = msg.values[1];
            ELF elf(pid);

            if (__builtin_expect(entries.size(), 0)) {
                std::cerr << "Pointers are already defined!" << std::endl;
                return false;
            }

            if (__builtin_expect(!elf.load(), 0)) {
                std::cerr << "Failed to read ELF header!" << std::endl;
                return false;
            }

            ELF::iterator it, ie;
            auto hint = entries.begin();
            for (std::tie(it, ie) = elf.get_globals(); it != ie; ++it) {
                hint =
                    entries.emplace_hint(hint, base + it->ptr, base + it->val);
                stats[HQ_STAT_NUM_INIT_GLOBALS]++;
            }

            auto old_sz = stats[HQ_STAT_MAX_ENTRIES].load();
            auto new_sz = entries.size();
            while (old_sz < new_sz &&
                   !stats[HQ_STAT_MAX_ENTRIES].compare_exchange_weak(old_sz,
                                                                     new_sz)) {
            }

            return true;
        } break;

        default:
            std::cerr << "Unrecognized message " << std::hex << msg.op << " "
                      << msg.values[0] << " " << msg.values[1] << "!"
                      << std::endl;
            stats[HQ_STAT_NUM_FAILS]++;
            break;
        }

        return false;
    }

    friend std::ostream &operator<<(std::ostream &os, const Process<RX> &p) {
        os << std::dec << p.name << ",";
#define HQ_STAT(x) os << p.stats.at(HQ_STAT_##x).load() << ",";
        HQ_STATS_LIST
#undef HQ_STAT
        os << "\n" << p.rx << std::endl;

        return os;
    }
};

} // namespace HQ

#endif /* _HQ_VERIFIER_PROCESS_H_ */
