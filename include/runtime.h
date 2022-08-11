#ifndef _HQ_RUNTIME_H_
#define _HQ_RUNTIME_H_

#include "config.h"

#define __STR(x) (#x)
#define STR(x) __STR(x)

// Initialize underlying interface. Automatically called by C runtime library
// during initialization.
#define INIT_FUNCTION __hq_init
// Called to define all global pointers at program startup
#define INIT_GLOBALS_FUNCTION __hq_init_globals

#define INIT_ARRAY_INTERNAL __hq_init_array_internal
#define INIT_ARRAY_EXTERNAL __hq_init_array_external
#define INIT_SECTION_INTERNAL .hq_init
#define INIT_FUNCTION_EXTERNAL __hq_init_module

#define OBJECT_CHECK_FUNCTION __hq_object_check
#define OBJECT_DEFINE_FUNCTION __hq_object_define
#define OBJECT_REALLOC_FUNCTION __hq_object_realloc
#define OBJECT_INVALIDATE_FUNCTION __hq_object_invalidate

#define POINTER_CHECK_FUNCTION __hq_pointer_check
#define POINTER_CHECK_INVALIDATE_FUNCTION __hq_pointer_check_invalidate
#define POINTER_DEFINE_FUNCTION __hq_pointer_define
#define POINTER_INVALIDATE_FUNCTION __hq_pointer_invalidate

#define POINTER_COPY_FUNCTION __hq_pointer_copy

#define POINTER_FREE_FUNCTION __hq_pointer_free
#define POINTER_REALLOC_FUNCTION __hq_pointer_realloc

#define SYSCALL_FUNCTION __hq_syscall

typedef struct {
    const uintptr_t ptr;
    const uintptr_t val;
} hq_init_t;

#define MSG_BODY_SIZE(msg)                                                     \
    (((msg).op == HQ_MSG_DEFINE_BLOCK ||                                       \
      (msg).op == HQ_MSG_DEFINE_BLOCK_PRIVATE ||                               \
      (msg).op == HQ_MSG_CHECK_BLOCK)                                          \
         ? (msg).values[1]                                                     \
         : 0)

#define POINTER_VALUE_SIZE 8UL
#define POINTER_ALIGNED_MASK (POINTER_VALUE_SIZE - 1UL)
#define POINTER_IS_MISALIGNED(x) ((x)&POINTER_ALIGNED_MASK)
#define SIZE_IS_MISALIGNED(x) ((x)&POINTER_ALIGNED_MASK)

#endif /* _HQ_RUNTIME_H_ */
