#include "ve_tls_alloc.h"

#include <stdlib.h>
#include <string.h>

static ve_tls_alloc_hooks g_hooks;

/* Per-thread fault injection state. */
static __thread const char * g_site = NULL;
static __thread const char * g_fault_tag = NULL;
static __thread int g_fault_after = 0;
static __thread int g_fault_count = 0;
static __thread int g_fault_seen = 0;

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

static void ve_tls_alloc_init_defaults_if_needed(void) {
    if (!g_hooks.malloc_fn) g_hooks.malloc_fn = ve_tls_default_malloc;
    if (!g_hooks.calloc_fn) g_hooks.calloc_fn = ve_tls_default_calloc;
    if (!g_hooks.realloc_fn) g_hooks.realloc_fn = ve_tls_default_realloc;
    if (!g_hooks.free_fn) g_hooks.free_fn = ve_tls_default_free;
    if (!g_hooks.strdup_fn) g_hooks.strdup_fn = ve_tls_default_strdup;
}

void ve_tls_alloc_set_hooks(const ve_tls_alloc_hooks * hooks) {
    if (!hooks) {
        memset(&g_hooks, 0, sizeof(g_hooks));
        ve_tls_alloc_init_defaults_if_needed();
        return;
    }
    g_hooks = *hooks;
    ve_tls_alloc_init_defaults_if_needed();
}

void ve_tls_alloc_get_hooks(ve_tls_alloc_hooks * out_hooks) {
    if (!out_hooks) {
        return;
    }
    ve_tls_alloc_init_defaults_if_needed();
    *out_hooks = g_hooks;
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
