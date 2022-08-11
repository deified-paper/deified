#include <iostream>

#include "config.h"
#include "interfaces.h"
#include "messages-verifier.h"
#include "messages.h"

namespace HQ {
std::ostream &operator<<(std::ostream &os, const hq_msg &msg) {
#if INTERFACE_TYPE == INTERFACE_TYPE_OPAE
    os << std::dec << "PID: " << msg.pid << " ";
#endif

    switch (msg.op) {
    case HQ_MSG_EMPTY:
        os << "EMPTY (" << msg.op << ")";
        break;
    case HQ_MSG_SYSCALL:
        os << "SYSCALL (" << msg.op << ") " << msg.values[1];
        break;
    case HQ_MSG_INVALIDATE:
        os << "INVALIDATE (" << msg.op << ") " << std::hex << msg.values[1];
        break;
    case HQ_MSG_COPY_BLOCK: {
        const uintptr_t dst = ADDRESS_FROM_EMBED(msg.values[0]),
                        src = ADDRESS_FROM_EMBED(msg.values[1]),
                        sz = SIZE_FROM_EMBED(msg.values[0], msg.values[1]);
        os << "COPY-BLOCK (" << msg.op << ") [" << std::hex << src << ", "
           << src + sz << ") -> [" << dst << ", " << dst + sz << ")";
        break;
    }
    case HQ_MSG_INVALIDATE_BLOCK: {
        const uintptr_t ptr = msg.values[0], sz = msg.values[1];
        os << "INVALIDATE-BLOCK (" << msg.op << ") [" << std::hex << ptr << ", "
           << ptr + sz << ")";
        break;
    }
    case HQ_MSG_MOVE_BLOCK: {
        const uintptr_t dst = ADDRESS_FROM_EMBED(msg.values[0]),
                        src = ADDRESS_FROM_EMBED(msg.values[1]),
                        sz = SIZE_FROM_EMBED(msg.values[0], msg.values[1]);
        os << "MOVE-BLOCK (" << msg.op << ") [" << std::hex << src << ", "
           << src + sz << ") -> [" << dst << ", " << dst + sz << ")";
        break;
    }
    case HQ_MSG_DEFINE: {
        const uintptr_t ptr = msg.values[0], val = msg.values[1];
        os << "DEFINE (" << msg.op << ") *" << std::hex << ptr << " = " << val;
        break;
    }
    case HQ_MSG_DEFINE_PRIVATE: {
        const uintptr_t ptr = msg.values[0], val = msg.values[1];
        os << "DEFINE-PRIVATE (" << msg.op << ") *" << std::hex << ptr << " = "
           << val;
        break;
    }
    case HQ_MSG_DEFINE_BLOCK: {
        const uintptr_t ptr = msg.values[0], sz = msg.values[1];
        os << "DEFINE-BLOCK (" << msg.op << ") [" << std::hex << ptr << ", "
           << ptr + sz << ") = { ";
        for (uintptr_t i = 0; i < sz; i += 8)
            os << std::hex
               << *reinterpret_cast<const uintptr_t *>(&msg.contents[i])
               << ", ";
        os << "}";
        break;
    }
    case HQ_MSG_DEFINE_BLOCK_PRIVATE: {
        const uintptr_t ptr = msg.values[0], sz = msg.values[1];
        os << "DEFINE-BLOCK-PRIVATE (" << msg.op << ") [" << std::hex << ptr
           << ", " << ptr + sz << ") = { ";
        for (uintptr_t i = 0; i < sz; i += 8)
            os << std::hex
               << *reinterpret_cast<const uintptr_t *>(&msg.contents[i])
               << ", ";
        os << "}";
        break;
    }
    case HQ_MSG_CHECK: {
        const uintptr_t ptr = msg.values[0], val = msg.values[1];
        os << "CHECK (" << msg.op << ") *" << std::hex << ptr << " == " << val;
        break;
    }
    case HQ_MSG_CHECK_BLOCK: {
        const uintptr_t ptr = msg.values[0], sz = msg.values[1];
        os << "CHECK-BLOCK (" << msg.op << ") [" << std::hex << ptr << ", "
           << ptr + sz << ") = { ";
        for (uintptr_t i = 0; i < sz; i += 8)
            os << std::hex
               << *reinterpret_cast<const uintptr_t *>(&msg.contents[i])
               << ", ";
        os << "}";
        break;
    }
    case HQ_MSG_CHECK_INVALIDATE: {
        const uintptr_t ptr = msg.values[0], val = msg.values[1];
        os << "CHECK-INVALIDATE (" << msg.op << ") " << std::hex << ptr
           << " == " << val;
        break;
    }
    case HQ_MSG_INIT_GLOBALS:
        os << "INIT-GLOBALS (" << msg.op << ") " << std::hex << msg.values[1];
        break;
    default:
        os << "UNKNOWN (" << msg.op << ") " << std::hex << msg.values[0] << " "
           << msg.values[1];
        break;
    }

    return os;
}

std::ostream &operator<<(std::ostream &os, const hq_verifier_msg &msg) {
    os << std::dec << "PID: " << msg.pid << " TID: " << msg.tid << " ";

    switch (msg.op) {
    case HQ_VERIFIER_MSG_CLONE:
        os << "CLONE (" << msg.op << ") " << msg.value;
        break;

    case HQ_VERIFIER_MSG_MONITOR:
        os << "MONITOR (" << msg.op << ") " << msg.comm << ", " << msg.value;
        break;

    case HQ_VERIFIER_MSG_TERMINATE:
        os << "TERMINATE (" << msg.op << ") " << msg.value;
        break;

    default:
        os << "UNKNOWN (" << msg.op << ")";
        break;
    }

    return os;
}

} // namespace HQ
