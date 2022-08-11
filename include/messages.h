#ifndef _HQ_MESSAGES_H_
#define _HQ_MESSAGES_H_

#include "config.h"
#include "interfaces.h"

// Must keep in sync with 'hq_fifo_csr.vh'
enum hq_msg_op {
    // .values = {0}, .contents = {}
    HQ_MSG_EMPTY,
    // .values = {tid}, .contents = {}
    HQ_MSG_SYSCALL,
    // .values = {0, ptr}, .contents = {}
    HQ_MSG_INVALIDATE,
    // .values = {ptr, body_sz}, .contents = {body}
    HQ_MSG_DEFINE_BLOCK,
    // .values = {ptr, body_sz}, .contents = {body}
    HQ_MSG_DEFINE_BLOCK_PRIVATE,
    // .values = {ptr, body_sz}, .contents = {}
    HQ_MSG_CHECK_BLOCK,
    // .values = {EMBED_ADDRESS_SIZE_HIGH(dst, sz),
    //            EMBED_ADDRESS_SIZE_LOW(src, sz)}, .contents = {}
    HQ_MSG_COPY_BLOCK,
    // .values = {ptr, sz}, .contents = {}
    HQ_MSG_INVALIDATE_BLOCK,
    // .values = {EMBED_ADDRESS_SIZE_HIGH(dst, sz),
    //            EMBED_ADDRESS_SIZE_LOW(src, sz)}, .contents = {}
    HQ_MSG_MOVE_BLOCK,
    // .values = {ptr, val}, .contents = {}
    HQ_MSG_DEFINE,
    // .values = {ptr, val}, .contents = {}
    HQ_MSG_DEFINE_PRIVATE,
    // .values = {ptr, val}, .contents = {}
    HQ_MSG_CHECK,
    // .values = {ptr, val}, .contents = {}
    HQ_MSG_CHECK_INVALIDATE,
    // .values = {0, base}, .contents = {}
    HQ_MSG_INIT_GLOBALS,
};

struct hq_msg {
#if INTERFACE_TYPE == INTERFACE_TYPE_OPAE
    pid_t pid __attribute__((__aligned__(8)));
#endif
    enum hq_msg_op op __attribute__((__aligned__(8)));

    uintptr_t values[2];
    uint8_t contents[];
} __attribute__((__aligned__(8)));

// With four-level paging, 48th bit is used to denote kernel space, and
// remaining 47 bits denote user-space virtual addresses. Since all address
// must be in virtual space, we can store the size in the upper 17 bits.
#define EMBED_ADDRESS_SIZE_HIGH(ptr, sz)                                       \
    (((uint64_t)ptr & ((1ULL << 47) - 1ULL)) |                                 \
     ((uint64_t)(sz & ~((1ULL << 17) - 1ULL)) << 30))
#define EMBED_ADDRESS_SIZE_LOW(ptr, sz)                                        \
    (((uint64_t)ptr & ((1ULL << 47) - 1ULL)) | ((uint64_t)sz << 47))
#define ADDRESS_FROM_EMBED(e) (e & ((1ULL << 47) - 1ULL))
#define SIZE_FROM_EMBED(eh, el)                                                \
    (((eh & ~((1ULL << 47) - 1ULL)) >> 30) |                                   \
     ((el & ~((1ULL << 47) - 1ULL)) >> 47))

// Option for prctl() to enable HQ
#define PR_HQ 100

#endif /* _HQ_MESSAGES_H_ */
