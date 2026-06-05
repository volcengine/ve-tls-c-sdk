#ifndef VE_TLS_ALLOC_H
#define VE_TLS_ALLOC_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void * (*ve_tls_malloc_fn)(size_t n, void * user_data);
typedef void * (*ve_tls_calloc_fn)(size_t n, size_t size, void * user_data);
typedef void * (*ve_tls_realloc_fn)(void * p, size_t n, void * user_data);
typedef void (*ve_tls_free_fn)(void * p, void * user_data);
typedef char * (*ve_tls_strdup_fn)(const char * s, void * user_data);

typedef struct {
    ve_tls_malloc_fn malloc_fn;
    ve_tls_calloc_fn calloc_fn;
    ve_tls_realloc_fn realloc_fn;
    ve_tls_free_fn free_fn;
    ve_tls_strdup_fn strdup_fn;
    void * user_data;
} ve_tls_alloc_hooks;

void ve_tls_alloc_set_hooks(const ve_tls_alloc_hooks * hooks);
void ve_tls_alloc_get_hooks(ve_tls_alloc_hooks * out_hooks);

void * ve_tls_malloc(size_t n);
void * ve_tls_calloc(size_t n, size_t size);
void * ve_tls_realloc(void * p, size_t n);
void ve_tls_free(void * p);
char * ve_tls_strdup(const char * s);

/* === Fault injection (test-only, no-op in production) ===
 * Default state: tag == NULL, costs at most one branch in alloc paths.
 * tag == NULL clears injection. fail_after >= 0; fail_count <= 0 treated as 1. */
void ve_tls_alloc_fault_inject(const char * tag, int fail_after, int fail_count);

/* Set per-thread call-site tag for subsequent ve_tls_malloc/calloc/realloc/strdup.
 * Returns previous site (may be NULL). NULL site disables matching. */
const char * ve_tls_alloc_set_site(const char * site);

static inline void ve_tls__site_cleanup(const char ** prev) {
    ve_tls_alloc_set_site(*prev);
}
#define VE_TLS_ALLOC_SITE_CONCAT_(a, b) a##b
#define VE_TLS_ALLOC_SITE_CONCAT(a, b) VE_TLS_ALLOC_SITE_CONCAT_(a, b)
#define VE_TLS_ALLOC_SITE(name) \
    const char * __attribute__((cleanup(ve_tls__site_cleanup))) \
        VE_TLS_ALLOC_SITE_CONCAT(_ve_tls_prev_site_, __LINE__) = ve_tls_alloc_set_site(name)

#ifdef __cplusplus
}
#endif

#endif

