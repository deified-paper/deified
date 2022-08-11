#ifndef _HQ_INTERFACES_MODEL_H_
#define _HQ_INTERFACES_MODEL_H_

#include <array>
#include <cassert>
#include <climits>
#include <cstdint>
#include <cstring>
#include <iterator>
#include <ostream>

#include <fcntl.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "compat.h"
#include "config.h"
#include "interfaces.h"
#include "messages.h"
#include "syscalls.h"

namespace HQ::MODEL {

// Must ensure final data structure is multiple of hugepage size
using msg_type = uint8_t;

static constexpr size_t BUFFER_SIZE =
    ((HQ_INTERFACE_APPLICATION_SIZE - CACHELINE_BYTES) / sizeof(msg_type));
static constexpr char MFD_NAME[] = "HQ";

using status_t = uint32_t;
static constexpr status_t FULL_FLAG = 1U << 31;

struct ring_buffer {
    struct alignas(CACHELINE_BYTES) {
        // Prevents concurrent writers, and reader-writer races
        bool lock;
        // Indicates full (1U << 31) and write offset
        status_t status;
    };
    alignas(CACHELINE_BYTES) msg_type msgs[BUFFER_SIZE];
};

static_assert(sizeof(struct ring_buffer) <= HQ_INTERFACE_APPLICATION_SIZE,
              "Ring buffer must be smaller than memory buffer size!");

static constexpr unsigned get_hugetlb_flags(size_t sz, bool mmap) {
    if (!(sz % 1073741824))
        return (mmap ? MAP_HUGETLB : MFD_HUGETLB) | MAP_HUGE_1GB;
    else if (!(sz % 2097152))
        return (mmap ? MAP_HUGETLB : MFD_HUGETLB) | MAP_HUGE_2MB;
    return 0;
}

class RX {
    struct ring_buffer *map = nullptr;
    status_t read = 0;
    unsigned resets = 0;

  public:
    // Must use custom iterator for read tracking
    template <typename T> class iterator {
        using internal_pointer = msg_type *;

      public:
        using difference_type = std::ptrdiff_t;
        using pointer = T *;
        using reference = T &;
        using value_type = T;
        using iterator_category = std::forward_iterator_tag;

        iterator() = default;
        iterator(internal_pointer _ptr, internal_pointer _base, status_t *_read)
            : ptr(_ptr), base(_base), read(_read) {}
        iterator(const iterator &other) = delete;
        iterator(iterator &&old) { *this = std::move(old); }

        iterator &operator=(const iterator &old) = delete;
        iterator &operator=(iterator &&old) {
            if (this != &old) {
                ptr = old.ptr;
                base = old.base;
                read = old.read;

                old.ptr = nullptr;
                old.base = nullptr;
                old.read = nullptr;
            }

            return *this;
        }

        iterator &operator++() {
            ptr = &base[((*read) += sizeof(T) + MSG_BODY_SIZE(**this))];
            return *this;
        }

        reference operator*() const { return *reinterpret_cast<pointer>(ptr); }
        pointer operator->() const { return reinterpret_cast<pointer>(ptr); }

        operator bool() const { return ptr; }
        bool operator==(const iterator &other) const {
            return ptr == other.ptr && base == other.base && read == other.read;
        }
        bool operator!=(const iterator &other) const {
            return !(*this == other);
        }
        bool operator>(const iterator &other) const { return ptr > other.ptr; }
        bool operator<(const iterator &other) const { return ptr < other.ptr; }

      private:
        internal_pointer ptr = nullptr;
        internal_pointer base = nullptr;
        status_t *read = nullptr;
    };

    using const_iterator = iterator<const struct hq_msg>;

    RX() = default;

    RX(const RX &other) = delete;

    RX(RX &&old) { *this = std::move(old); }

    void destroy() {
        if (*this) {
            munmap(const_cast<struct ring_buffer *>(map), sizeof(*map));
            map = nullptr;
            read = 0;
        }
    }

    RX &operator=(RX &&old) {
        if (this != &old) {
            destroy();

            map = old.map;

            old.map = nullptr;
        }

        return *this;
    }

    ~RX() { destroy(); }

    bool open(int fd) {
        if (*this)
            destroy();

        map = reinterpret_cast<struct ring_buffer *>(
            mmap(NULL, sizeof(*map), PROT_READ | PROT_WRITE,
                 MAP_SHARED_VALIDATE | MAP_POPULATE |
                     get_hugetlb_flags(sizeof(*map), true),
                 fd, 0));
        return *this;
    }
    const_iterator begin() {
        return const_iterator(&map->msgs[read], map->msgs, &read);
    }
    const_iterator get_msgs();

    bool reset() {
        read = 0;
        ++resets;
        __atomic_store_n(&map->status, 0, __ATOMIC_RELEASE);

        return true;
    }

#ifdef HQ_INTERFACE_FUTEX_WAITV
    futex_waitv_t get_futex_waitv() {
        return futex_waitv_init(&map->status, read, 0);
    }
#endif

    operator bool() const { return map && map != MAP_FAILED; }

    friend std::ostream &operator<<(std::ostream &os, const RX &rx);
};

class TX {
    void *map = nullptr;
#ifdef HQ_INTERFACE_MPK
    int pkey = -1;
#endif

    // Must be hugepage aligned
#define MAP reinterpret_cast<struct ring_buffer *>(HQ_INTERFACE_MAP_ADDRESS)

    inline status_t do_lock(const uintptr_t size) {
        status_t status;

#ifndef NDEBUG
        if (__builtin_expect(!*this, 0))
            return false;
#endif /* !NDEBUG */

        // Spin while another thread is writing
        while (__atomic_test_and_set(&MAP->lock, __ATOMIC_ACQ_REL))
            ;

#ifdef HQ_INTERFACE_MPK
        RAW_SYSCALL(4, SYS_pkey_mprotect, &MAP, sizeof(MAP),
                    PROT_READ | PROT_WRITE, pkey);
#endif

    retry:
        // Spin while buffer is full
        while ((status = __atomic_load_n(&MAP->status, __ATOMIC_ACQUIRE)) &
               FULL_FLAG)
            ;

        if (__builtin_expect(status + size >= BUFFER_SIZE, 0)) {
            __atomic_store_n(&MAP->status, status | FULL_FLAG,
                             __ATOMIC_RELEASE);
            goto retry;
        }

        return status;
    }

    inline void do_unlock(const uintptr_t size) {
        // Increment the write offset
        __atomic_add_fetch(&MAP->status, size, __ATOMIC_ACQ_REL);
        // Unlock for other writers
        __atomic_clear(&MAP->lock, __ATOMIC_RELEASE);

#ifdef HQ_INTERFACE_MPK
        RAW_SYSCALL(4, SYS_pkey_mprotect, &MAP, sizeof(MAP),
                    PROT_READ | PROT_WRITE, 0);
#endif
#ifdef HQ_INTERFACE_FUTEX_WAITV
        futex(&MAP->status, FUTEX_WAKE, INT_MAX, nullptr, nullptr, 0);
#endif
    }

  public:
    static int create() {
        int fd;

        if ((fd = RAW_SYSCALL(
                 2, SYS_memfd_create, reinterpret_cast<uintptr_t>(&MFD_NAME),
                 MFD_CLOEXEC | MFD_ALLOW_SEALING |
                     get_hugetlb_flags(sizeof(struct ring_buffer), false))) < 0)
            return fd;

        if (RAW_SYSCALL(2, SYS_ftruncate, fd, sizeof(struct ring_buffer)) ||
            RAW_SYSCALL(3, SYS_fcntl, fd, F_ADD_SEALS,
                        F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW))
            goto err;

        return fd;
    err:
        RAW_SYSCALL(1, SYS_close, fd);
        return -1;
    }

    TX() = default;

    TX(const TX &other) = delete;

    TX(TX &&old) { *this = std::move(old); }

    TX &operator=(TX &&old) {
        if (this != &old) {
            map = old.map;

            old.map = nullptr;
        }

        return *this;
    }

    ~TX() {
        if (*this)
            RAW_SYSCALL(2, SYS_munmap, HQ_INTERFACE_MAP_ADDRESS, sizeof(*MAP));
#ifdef HQ_INTERFACE_MPK
        if (pkey > 0)
            RAW_SYSCALL(1, SYS_pkey_free, pkey);
#endif
    }

    bool open(int fd) {
        map = reinterpret_cast<struct ring_buffer *>(
            RAW_SYSCALL(6, SYS_mmap, HQ_INTERFACE_MAP_ADDRESS, sizeof(*MAP),
                        PROT_READ | PROT_WRITE,
                        MAP_FIXED | MAP_SHARED_VALIDATE | MAP_POPULATE |
                            get_hugetlb_flags(sizeof(*MAP), true),
                        fd, 0));

        RAW_SYSCALL(1, SYS_close, fd);

#ifdef HQ_INTERFACE_MPK
        pkey = RAW_SYSCALL(2, SYS_pkey_alloc, 0, PKEY_DISABLE_WRITE);
#endif
        return *this;
    }

    bool initialize(void *addr) {
        map = addr;
        return *this;
    }

    inline bool send_msgn(const enum hq_msg_op op, const void *pointer,
                          const uintptr_t size) {
        const auto msg_size = sizeof(struct hq_msg) + size;
        auto write = do_lock(msg_size);

        auto *msg = reinterpret_cast<struct hq_msg *>(&MAP->msgs[write]);
        msg->op = op;
        msg->values[0] = reinterpret_cast<uintptr_t>(pointer);
        msg->values[1] = size;
        memcpy(const_cast<uint8_t *>(msg->contents), pointer, size);

        do_unlock(msg_size);
        return true;
    }

    inline bool send_msg2(const enum hq_msg_op op, const uintptr_t pointer,
                          const uintptr_t value) {
        constexpr auto msg_size = sizeof(struct hq_msg);
        auto write = do_lock(msg_size);

        auto *msg = reinterpret_cast<struct hq_msg *>(&MAP->msgs[write]);
        msg->op = op;
        msg->values[0] = pointer;
        msg->values[1] = value;

        do_unlock(msg_size);
        return true;
    }

    inline bool send_msg1(const enum hq_msg_op op, const uintptr_t value) {
        return send_msg2(op, 0, value);
    }

    operator bool() const { return map == MAP; }
};

} // namespace HQ::MODEL

#endif /* _HQ_INTERFACES_MODEL_H_ */
