#ifndef VE_TLS_ALLOC_H
#define VE_TLS_ALLOC_H

#include <stddef.h>

#include "ve_tls_export.h"

VE_TLS_BEGIN_DECLS

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

VE_TLS_API void ve_tls_alloc_set_hooks(const ve_tls_alloc_hooks * hooks);
VE_TLS_API void ve_tls_alloc_get_hooks(ve_tls_alloc_hooks * out_hooks);

VE_TLS_API void * ve_tls_malloc(size_t n);
VE_TLS_API void * ve_tls_calloc(size_t n, size_t size);
VE_TLS_API void * ve_tls_realloc(void * p, size_t n);
VE_TLS_API void ve_tls_free(void * p);
VE_TLS_API char * ve_tls_strdup(const char * s);

/* Best-effort sensitive data cleanup helpers shared by producer/signing code. */
VE_TLS_API void ve_tls_secure_zero(void * p, size_t n);
VE_TLS_API void ve_tls_secure_free_str(char ** ps);

#if defined(VE_TLS_ENABLE_ALLOC_FAULT_INJECT)
/* Fault injection is a test-only interface and is not part of the public ABI. */
void ve_tls_alloc_fault_inject(const char * tag, int fail_after, int fail_count);

/* Set per-thread call-site tag for subsequent ve_tls_malloc/calloc/realloc/strdup.
 * Returns previous site (may be NULL). NULL site disables matching. */
const char * ve_tls_alloc_set_site(const char * site);
#endif

/* VE_TLS_ALLOC_SITE 自动恢复宏（仅用于测试/调试）：
 * - 默认完全 no-op，不引入任何运行时开销，也不依赖编译器扩展，保持纯 C11 兼容；
 * - 仅当显式开启 VE_TLS_ENABLE_ALLOC_FAULT_INJECT 且编译器支持
 *   __attribute__((cleanup)) 时，才展开为基于 cleanup 的自动恢复实现。
 * 不支持 cleanup 的编译器需要显式调用 ve_tls_alloc_set_site() 配对管理。 */
#if defined(VE_TLS_ENABLE_ALLOC_FAULT_INJECT)
#  if defined(__GNUC__) || defined(__clang__)
#    define VE_TLS_HAS_CLEANUP_ATTR 1
#  endif
#endif

#if defined(VE_TLS_HAS_CLEANUP_ATTR)
static inline void ve_tls__site_cleanup(const char ** prev) {
    ve_tls_alloc_set_site(*prev);
}
#  define VE_TLS_ALLOC_SITE_CONCAT_(a, b) a##b
#  define VE_TLS_ALLOC_SITE_CONCAT(a, b) VE_TLS_ALLOC_SITE_CONCAT_(a, b)
#  define VE_TLS_ALLOC_SITE(name) \
    const char * __attribute__((cleanup(ve_tls__site_cleanup))) \
        VE_TLS_ALLOC_SITE_CONCAT(_ve_tls_prev_site_, __LINE__) = ve_tls_alloc_set_site(name)
#else
/* no-op：不修改 site，避免在公共头里引入编译器扩展。
 * 测试若需要 site 标记，请显式调用 ve_tls_alloc_set_site/恢复。 */
#  define VE_TLS_ALLOC_SITE(name) ((void)0)
#endif

VE_TLS_END_DECLS

#endif
