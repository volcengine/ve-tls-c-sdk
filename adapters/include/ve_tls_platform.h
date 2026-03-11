#ifndef VE_TLS_PLATFORM_H
#define VE_TLS_PLATFORM_H

#include <stdint.h>
#include <stddef.h>

typedef struct ve_tls_mutex ve_tls_mutex;
typedef struct ve_tls_cond ve_tls_cond;
typedef struct ve_tls_thread ve_tls_thread;

typedef void * (*ve_tls_thread_fn)(void * arg);

typedef struct {
    int64_t (*time_ms)(void);
    void (*sleep_ms)(int64_t ms);
    ve_tls_mutex * (*mutex_create)(void);
    void (*mutex_destroy)(ve_tls_mutex * m);
    void (*mutex_lock)(ve_tls_mutex * m);
    void (*mutex_unlock)(ve_tls_mutex * m);
    ve_tls_cond * (*cond_create)(void);
    void (*cond_destroy)(ve_tls_cond * c);
    void (*cond_wait)(ve_tls_cond * c, ve_tls_mutex * m);
    int (*cond_timedwait_ms)(ve_tls_cond * c, ve_tls_mutex * m, int64_t timeout_ms);
    void (*cond_signal)(ve_tls_cond * c);
    void (*cond_broadcast)(ve_tls_cond * c);
    ve_tls_thread * (*thread_create)(ve_tls_thread_fn fn, void * arg);
    void (*thread_join)(ve_tls_thread * t);
} ve_tls_platform;

void ve_tls_platform_init_default(ve_tls_platform * platform);

#endif
