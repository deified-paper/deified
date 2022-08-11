#ifndef _HQ_RTLIB_H_
#define _HQ_RTLIB_H_

#include <cstdint>

#include "messages.h"

#include "config.h"
#include "runtime.h"

/* Switch for whether to generate inlinable messaging component */
#ifdef INLINE
#define INLINABLE __attribute__((always_inline))
#else
#define INLINABLE /* nothing */
#endif            /* INLINE */

extern "C" {

INLINABLE void OBJECT_CHECK_FUNCTION(const void *p, uint64_t sz);
INLINABLE void OBJECT_DEFINE_FUNCTION(const void *p, uint64_t sz, bool priv);
INLINABLE void OBJECT_REALLOC_FUNCTION(const void *dst, const void *src,
                                       uint64_t sz);
INLINABLE void OBJECT_INVALIDATE_FUNCTION(const void *p, uint64_t sz);

INLINABLE void POINTER_CHECK_FUNCTION(const void **pp, const void *p);
INLINABLE void POINTER_CHECK_INVALIDATE_FUNCTION(const void **pp,
                                                 const void *p);
INLINABLE void POINTER_DEFINE_FUNCTION(const void **pp, const void *p,
                                       bool priv);
INLINABLE void POINTER_INVALIDATE_FUNCTION(const void **pp);

INLINABLE void POINTER_COPY_FUNCTION(void *dst, const void *src, uint64_t sz);

INLINABLE void POINTER_FREE_FUNCTION(void *ptr);
INLINABLE void *POINTER_REALLOC_FUNCTION(void *src, uint64_t new_sz);

INLINABLE void SYSCALL_FUNCTION(uint64_t num);

INLINABLE void INIT_GLOBALS_FUNCTION(const hq_init_t *init_int,
                                     const size_t int_sz,
                                     const hq_init_t *init_ext,
                                     const size_t ext_sz);
}

#endif /* _HQ_RTLIB_H_ */
