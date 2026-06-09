#include "ve_tls_alloc.h"

#include <stdlib.h>
#include <string.h>

#if defined(VE_TLS_ENABLE_PTHREAD)
#include <pthread.h>
#endif

/* 前向声明默认 hook，便于 g_hooks 静态聚合初始化。 */
static void * ve_tls_default_malloc(size_t n, void * user_data);
static void * ve_tls_default_calloc(size_t n, size_t size, void * user_data);
static void * ve_tls_default_realloc(void * p, size_t n, void * user_data);
static void ve_tls_default_free(void * p, void * user_data);
static char * ve_tls_default_strdup(const char * s, void * user_data);

/* g_hooks 在编译期即填好默认 fn，热路径无需任何 once/atomic-load 兜底。
 * 仅 set_hooks/get_hooks 走 mutex 保护 struct 一致性；
 * 这与 set_hooks 之前的旧语义完全等价（旧实现首次 alloc 也只是把同样的 fn 注入进去）。 */
static ve_tls_alloc_hooks g_hooks = {
    ve_tls_default_malloc,
    ve_tls_default_calloc,
    ve_tls_default_realloc,
    ve_tls_default_free,
    ve_tls_default_strdup,
    NULL,
};
#if defined(VE_TLS_ENABLE_PTHREAD)
static pthread_mutex_t g_alloc_mu = PTHREAD_MUTEX_INITIALIZER;
#endif

/* Fault injection 仅在 VE_TLS_ENABLE_ALLOC_FAULT_INJECT 下编译进二进制；
 * 生产构建为 no-op，热路径不引入任何 TLS load/branch 开销。 */
#if defined(VE_TLS_ENABLE_ALLOC_FAULT_INJECT)

/* TLS 关键字 feature-detect：优先 C11 _Thread_local，再 fallback 到 GNU/Clang __thread。
 * 与 core/src/ve_tls_sign.c 保持同一套宏模式。 */
#if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 201112L)
#define VE_TLS_ALLOC_TLS _Thread_local
#elif defined(__GNUC__) || defined(__clang__)
#define VE_TLS_ALLOC_TLS __thread
#else
#define VE_TLS_ALLOC_TLS
#endif

/* Per-thread fault injection state. */
static VE_TLS_ALLOC_TLS const char * g_site = NULL;
static VE_TLS_ALLOC_TLS const char * g_fault_tag = NULL;
static VE_TLS_ALLOC_TLS int g_fault_after = 0;
static VE_TLS_ALLOC_TLS int g_fault_count = 0;
static VE_TLS_ALLOC_TLS int g_fault_seen = 0;

static int ve_tls_alloc_fault_should_fail(void) {
    if (g_fault_tag == NULL) {
        return 0;
    }
    if (g_site == NULL || strcmp(g_site, g_fault_tag) != 0) {
        return 0;
    }
    g_fault_seen++;
    if (g_fault_seen > g_fault_after && g_fault_count > 0) {
        g_fault_count--;
        return 1;
    }
    return 0;
}

void ve_tls_alloc_fault_inject(const char * tag, int fail_after, int fail_count) {
    g_fault_tag = tag;
    g_fault_after = fail_after < 0 ? 0 : fail_after;
    g_fault_count = fail_count <= 0 ? 1 : fail_count;
    g_fault_seen = 0;
}

const char * ve_tls_alloc_set_site(const char * site) {
    const char * prev = g_site;
    g_site = site;
    return prev;
}

#else /* !VE_TLS_ENABLE_ALLOC_FAULT_INJECT */

static inline int ve_tls_alloc_fault_should_fail(void) {
    return 0;
}

void ve_tls_alloc_fault_inject(const char * tag, int fail_after, int fail_count) {
    (void)tag;
    (void)fail_after;
    (void)fail_count;
}

const char * ve_tls_alloc_set_site(const char * site) {
    (void)site;
    return NULL;
}

#endif /* VE_TLS_ENABLE_ALLOC_FAULT_INJECT */

static void * ve_tls_default_malloc(size_t n, void * user_data) {
    (void)user_data;
    return malloc(n);
}

static void * ve_tls_default_calloc(size_t n, size_t size, void * user_data) {
    (void)user_data;
    return calloc(n, size);
}

static void * ve_tls_default_realloc(void * p, size_t n, void * user_data) {
    (void)user_data;
    return realloc(p, n);
}

static void ve_tls_default_free(void * p, void * user_data) {
    (void)user_data;
    free(p);
}

static char * ve_tls_default_strdup(const char * s, void * user_data) {
    (void)user_data;
    if (!s) {
        return NULL;
    }
    size_t n = strlen(s);
    char * p = (char *)g_hooks.malloc_fn(n + 1, g_hooks.user_data);
    if (!p) {
        return NULL;
    }
    memcpy(p, s, n);
    p[n] = 0;
    return p;
}

static void ve_tls_alloc_assign_defaults(void) {
    if (!g_hooks.malloc_fn) g_hooks.malloc_fn = ve_tls_default_malloc;
    if (!g_hooks.calloc_fn) g_hooks.calloc_fn = ve_tls_default_calloc;
    if (!g_hooks.realloc_fn) g_hooks.realloc_fn = ve_tls_default_realloc;
    if (!g_hooks.free_fn) g_hooks.free_fn = ve_tls_default_free;
    if (!g_hooks.strdup_fn) g_hooks.strdup_fn = ve_tls_default_strdup;
}

void ve_tls_alloc_set_hooks(const ve_tls_alloc_hooks * hooks) {
#if defined(VE_TLS_ENABLE_PTHREAD)
    pthread_mutex_lock(&g_alloc_mu);
#endif
    if (!hooks) {
        memset(&g_hooks, 0, sizeof(g_hooks));
        ve_tls_alloc_assign_defaults();
    } else {
        g_hooks = *hooks;
        ve_tls_alloc_assign_defaults();
    }
#if defined(VE_TLS_ENABLE_PTHREAD)
    pthread_mutex_unlock(&g_alloc_mu);
#endif
}

void ve_tls_alloc_get_hooks(ve_tls_alloc_hooks * out_hooks) {
    if (!out_hooks) {
        return;
    }
#if defined(VE_TLS_ENABLE_PTHREAD)
    pthread_mutex_lock(&g_alloc_mu);
    *out_hooks = g_hooks;
    pthread_mutex_unlock(&g_alloc_mu);
#else
    *out_hooks = g_hooks;
#endif
}

void * ve_tls_malloc(size_t n) {
    if (ve_tls_alloc_fault_should_fail()) {
        return NULL;
    }
    return g_hooks.malloc_fn(n, g_hooks.user_data);
}

void * ve_tls_calloc(size_t n, size_t size) {
    if (ve_tls_alloc_fault_should_fail()) {
        return NULL;
    }
    return g_hooks.calloc_fn(n, size, g_hooks.user_data);
}

void * ve_tls_realloc(void * p, size_t n) {
    if (ve_tls_alloc_fault_should_fail()) {
        return NULL;
    }
    return g_hooks.realloc_fn(p, n, g_hooks.user_data);
}

void ve_tls_free(void * p) {
    g_hooks.free_fn(p, g_hooks.user_data);
}

char * ve_tls_strdup(const char * s) {
    if (ve_tls_alloc_fault_should_fail()) {
        return NULL;
    }
    return g_hooks.strdup_fn(s, g_hooks.user_data);
}

void ve_tls_secure_zero(void * p, size_t n) {
    if (!p || n == 0) {
        return;
    }
    memset(p, 0, n);
#if defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("" : : "r"(p) : "memory");
#else
    volatile unsigned char * vp = (volatile unsigned char *)p;
    while (n--) {
        *vp++ = 0;
    }
#endif
}

void ve_tls_secure_free_str(char ** ps) {
    if (!ps || !*ps) {
        return;
    }
    size_t n = strlen(*ps);
    ve_tls_secure_zero(*ps, n);
    ve_tls_free(*ps);
    *ps = NULL;
}
