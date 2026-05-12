#ifndef VE_TLS_MSVC_COMPAT_H
#define VE_TLS_MSVC_COMPAT_H

#if defined(_MSC_VER)

#include <string.h>

#ifndef strdup
#define strdup _strdup
#endif

#if !defined(__clang__)

#include <stdint.h>
#include <intrin.h>

#ifndef __thread
#define __thread _Thread_local
#endif

#ifndef __ATOMIC_RELAXED
#define __ATOMIC_RELAXED 0
#define __ATOMIC_CONSUME 1
#define __ATOMIC_ACQUIRE 2
#define __ATOMIC_RELEASE 3
#define __ATOMIC_ACQ_REL 4
#define __ATOMIC_SEQ_CST 5
#endif

static inline void ve_tls_msvc_atomic_fence(int order) {
    (void)order;
    _ReadWriteBarrier();
}

static inline long ve_tls_msvc_fetch_add_32(volatile long * p, long v) {
    return _InterlockedExchangeAdd(p, v);
}

static inline long long ve_tls_msvc_fetch_add_64(volatile long long * p, long long v) {
    return _InterlockedExchangeAdd64(p, v);
}

static inline long ve_tls_msvc_exchange_32(volatile long * p, long v) {
    return _InterlockedExchange(p, v);
}

static inline long long ve_tls_msvc_exchange_64(volatile long long * p, long long v) {
    return _InterlockedExchange64(p, v);
}

static inline int ve_tls_msvc_compare_exchange_32(volatile long * p, long * expected, long desired) {
    long old = _InterlockedCompareExchange(p, desired, *expected);
    if (old == *expected) {
        return 1;
    }
    *expected = old;
    return 0;
}

static inline int ve_tls_msvc_compare_exchange_64(volatile long long * p, long long * expected, long long desired) {
    long long old = _InterlockedCompareExchange64(p, desired, *expected);
    if (old == *expected) {
        return 1;
    }
    *expected = old;
    return 0;
}

#define __atomic_load_n(ptr, order) \
    (ve_tls_msvc_atomic_fence(order), *(ptr))

#define __atomic_store_n(ptr, value, order) \
    do { \
        *(ptr) = (value); \
        ve_tls_msvc_atomic_fence(order); \
    } while (0)

#define __atomic_fetch_add(ptr, value, order) \
    (sizeof(*(ptr)) == 8 ? \
        ve_tls_msvc_fetch_add_64((volatile long long *)(ptr), (long long)(value)) : \
        (long long)ve_tls_msvc_fetch_add_32((volatile long *)(ptr), (long)(value)))

#define __atomic_fetch_sub(ptr, value, order) \
    __atomic_fetch_add((ptr), -(value), (order))

#define __atomic_add_fetch(ptr, value, order) \
    (__atomic_fetch_add((ptr), (value), (order)) + (value))

#define __atomic_sub_fetch(ptr, value, order) \
    (__atomic_fetch_sub((ptr), (value), (order)) - (value))

#define __atomic_exchange_n(ptr, value, order) \
    (sizeof(*(ptr)) == 8 ? \
        ve_tls_msvc_exchange_64((volatile long long *)(ptr), (long long)(value)) : \
        (long long)ve_tls_msvc_exchange_32((volatile long *)(ptr), (long)(value)))

#define __atomic_compare_exchange_n(ptr, expected, desired, weak, success_order, failure_order) \
    (sizeof(*(ptr)) == 8 ? \
        ve_tls_msvc_compare_exchange_64((volatile long long *)(ptr), (long long *)(expected), (long long)(desired)) : \
        ve_tls_msvc_compare_exchange_32((volatile long *)(ptr), (long *)(expected), (long)(desired)))

#endif

#endif

#endif
