#include <unistd.h>

#include "model.h"

namespace HQ::MODEL {

// bool full = false;

RX::const_iterator RX::get_msgs() {
#ifndef NDEBUG
    if (__builtin_expect(!*this, 0))
        return nullptr;
#endif /* !NDEBUG */

    status_t status = __atomic_load_n(&map->status, __ATOMIC_ACQUIRE);
    if (__builtin_expect(status & FULL_FLAG, 0)) {
        status &= ~FULL_FLAG;

        // Only reset if up-to-date
        if (read != status)
            goto out;

        // Does not need lock because it is held by the busy-waiting writer
        reset();
    }

    // Current message may not be fully written yet, so skip if locked
    if (__atomic_load_n(&map->lock, __ATOMIC_ACQUIRE))
        status = read;

out:
    return const_iterator(&map->msgs[status], map->msgs, &read);
}

std::ostream &operator<<(std::ostream &os, const RX &rx) {
    return os << "MODEL::RX = Map: "
              << static_cast<const void *>(
                     const_cast<struct ring_buffer *>(rx.map))
              << ", Read: " << rx.read << ", Resets: " << rx.resets;
}

} // namespace HQ::MODEL
