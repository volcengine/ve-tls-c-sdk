#include "ve_tls_alloc.h"

#include <stdlib.h>
#include <string.h>

#if defined(VE_TLS_ENABLE_PTHREAD)
#include <pthread.h>
#endif

static ve_tls_alloc_hooks g_hooks;
#if defined(VE_TLS_ENABLE_PTHREAD)
/* g_hooks 是全局可变状态：默认初始化路径与 set_hooks/get_hooks 必须串行化，
 * 否则多线程首次 ve_tls_malloc 同时进入会观测到部分字段为 NULL 的撕裂状态。 */
static pthread_once_t g_alloc_once = PTHREAD_ONCE_INIT;
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

#if defined(VE_TLS_ENABLE_PTHREAD)
static void ve_tls_alloc_once_init(void) {
    /* pthread_once 仅串行化 default hooks 注入；之后所有读路径都看到稳定快照。 */
    ve_tls_alloc_assign_defaults();
}
#endif

static void ve_tls_alloc_init_defaults_if_needed(void) {
#if defined(VE_TLS_ENABLE_PTHREAD)
    pthread_once(&g_alloc_once, ve_tls_alloc_once_init);
#else
    ve_tls_alloc_assign_defaults();
#endif
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
    /* 保证 set_hooks 完成后，后续读到的 g_hooks 至少是 default + 自定义 fields 的完整快照。 */
    pthread_once(&g_alloc_once, ve_tls_alloc_once_init);
    pthread_mutex_unlock(&g_alloc_mu);
#endif
}

void ve_tls_alloc_get_hooks(ve_tls_alloc_hooks * out_hooks) {
    if (!out_hooks) {
        return;
    }
    ve_tls_alloc_init_defaults_if_needed();
#if defined(VE_TLS_ENABLE_PTHREAD)
    pthread_mutex_lock(&g_alloc_mu);
    *out_hooks = g_hooks;
    pthread_mutex_unlock(&g_alloc_mu);
#else
    *out_hooks = g_hooks;
#endif
}

void * ve_tls_malloc(size_t n) {
    ve_tls_alloc_init_defaults_if_needed();
    if (ve_tls_alloc_fault_should_fail()) {
        return NULL;
    }
    return g_hooks.malloc_fn(n, g_hooks.user_data);
}

void * ve_tls_calloc(size_t n, size_t size) {
    ve_tls_alloc_init_defaults_if_needed();
    if (ve_tls_alloc_fault_should_fail()) {
        return NULL;
    }
    return g_hooks.calloc_fn(n, size, g_hooks.user_data);
}

void * ve_tls_realloc(void * p, size_t n) {
    ve_tls_alloc_init_defaults_if_needed();
    if (ve_tls_alloc_fault_should_fail()) {
        return NULL;
    }
    return g_hooks.realloc_fn(p, n, g_hooks.user_data);
}

void ve_tls_free(void * p) {
    ve_tls_alloc_init_defaults_if_needed();
    g_hooks.free_fn(p, g_hooks.user_data);
}

char * ve_tls_strdup(const char * s) {
    ve_tls_alloc_init_defaults_if_needed();
    if (ve_tls_alloc_fault_should_fail()) {
        return NULL;
    }
    return g_hooks.strdup_fn(s, g_hooks.user_data);
}
