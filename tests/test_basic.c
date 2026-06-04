#include "ve_tls_hash.h"
#include "ve_tls_compress.h"
#include "ve_tls_proto.h"
#include "ve_tls_sign.h"
#include "ve_tls_producer.h"
#include "ve_tls_env.h"
#include "ve_tls_alloc.h"
#include "ve_tls_error.h"
#include "ve_tls_http.h"
#include "ve_tls_version.h"
#include "producer/ve_tls_producer_internal.h"
#include "producer/ve_tls_snapshot.h"
#include "producer/ve_tls_pool.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <limits.h>

#if defined(VE_TLS_HAVE_ZLIB)
#include <zlib.h>
#endif

#if defined(VE_TLS_HAVE_LZ4)
#include "lz4.h"
#endif

static int test_http_ok_do(ve_tls_http_client * client, const ve_tls_http_request * req, ve_tls_http_response * resp);
static void test_http_ok_free(ve_tls_http_client * client, ve_tls_http_response * resp);
static double fixed_rand01(void * p);

static int g_http_done = 0;
static int g_http_ok = 0;

static int g_cred_done = 0;
static int g_cred_cb = 0;
static int g_cred_req = 0;
static int g_cred_provider_calls = 0;
static char g_cred_seen_1[64];
static char g_cred_seen_2[64];

typedef struct {
    ve_tls_platform * platform;
    int fail_after;
} cred_state;

static cred_state g_cred_state;

typedef struct {
    int fail_after;
    int calls;
} alloc_fail_state;

static void * alloc_fail_malloc(size_t n, void * user_data) {
    alloc_fail_state * st = (alloc_fail_state *)user_data;
    if (!st) return malloc(n);
    st->calls++;
    if (st->fail_after > 0 && st->calls >= st->fail_after) return NULL;
    return malloc(n);
}

static void * alloc_fail_calloc(size_t n, size_t size, void * user_data) {
    alloc_fail_state * st = (alloc_fail_state *)user_data;
    if (!st) return calloc(n, size);
    st->calls++;
    if (st->fail_after > 0 && st->calls >= st->fail_after) return NULL;
    return calloc(n, size);
}

static void * alloc_fail_realloc(void * p, size_t n, void * user_data) {
    alloc_fail_state * st = (alloc_fail_state *)user_data;
    if (!st) return realloc(p, n);
    st->calls++;
    if (st->fail_after > 0 && st->calls >= st->fail_after) return NULL;
    return realloc(p, n);
}

static void alloc_fail_free(void * p, void * user_data) {
    (void)user_data;
    free(p);
}

static char * alloc_fail_strdup(const char * s, void * user_data) {
    if (!s) return NULL;
    size_t n = strlen(s);
    char * p = (char *)alloc_fail_malloc(n + 1, user_data);
    if (!p) return NULL;
    memcpy(p, s, n);
    p[n] = 0;
    return p;
}

static void set_alloc_fail_after(alloc_fail_state * st, int fail_after) {
    ve_tls_alloc_hooks hooks;
    memset(&hooks, 0, sizeof(hooks));
    st->fail_after = fail_after;
    st->calls = 0;
    hooks.malloc_fn = alloc_fail_malloc;
    hooks.calloc_fn = alloc_fail_calloc;
    hooks.realloc_fn = alloc_fail_realloc;
    hooks.free_fn = alloc_fail_free;
    hooks.strdup_fn = alloc_fail_strdup;
    hooks.user_data = st;
    ve_tls_alloc_set_hooks(&hooks);
}

typedef struct {
    int fail_malloc_call;
    int fail_calloc_call;
    int fail_realloc_call;
    int fail_strdup_call;
    int malloc_calls;
    int calloc_calls;
    int realloc_calls;
    int strdup_calls;
    size_t fail_calloc_n_match;
    size_t fail_calloc_size_match;
    size_t fail_realloc_size_match;
    int fail_realloc_null_match;
    int realloc_null_size_calls;
    int fail_realloc_null_size_call;
} alloc_select_fail_state;

static void * alloc_select_malloc(size_t n, void * user_data) {
    alloc_select_fail_state * st = (alloc_select_fail_state *)user_data;
    if (st) {
        st->malloc_calls++;
        if (st->fail_malloc_call > 0 && st->malloc_calls == st->fail_malloc_call) return NULL;
    }
    return malloc(n);
}

static void * alloc_select_calloc(size_t n, size_t size, void * user_data) {
    alloc_select_fail_state * st = (alloc_select_fail_state *)user_data;
    if (st) {
        st->calloc_calls++;
        if (st->fail_calloc_n_match > 0 && st->fail_calloc_size_match > 0 && st->fail_calloc_n_match == n && st->fail_calloc_size_match == size) return NULL;
        if (st->fail_calloc_call > 0 && st->calloc_calls == st->fail_calloc_call) return NULL;
    }
    return calloc(n, size);
}

static void * alloc_select_realloc(void * p, size_t n, void * user_data) {
    alloc_select_fail_state * st = (alloc_select_fail_state *)user_data;
    if (st) {
        st->realloc_calls++;
        if (st->fail_realloc_null_match && !p && st->fail_realloc_size_match > 0 && st->fail_realloc_size_match == n) {
            st->realloc_null_size_calls++;
            if (st->fail_realloc_null_size_call > 0 && st->realloc_null_size_calls == st->fail_realloc_null_size_call) return NULL;
        }
        if (st->fail_realloc_call > 0 && st->realloc_calls == st->fail_realloc_call) return NULL;
    }
    return realloc(p, n);
}

static void alloc_select_free(void * p, void * user_data) {
    (void)user_data;
    free(p);
}

static char * alloc_select_strdup(const char * s, void * user_data) {
    alloc_select_fail_state * st = (alloc_select_fail_state *)user_data;
    if (st) {
        st->strdup_calls++;
        if (st->fail_strdup_call > 0 && st->strdup_calls == st->fail_strdup_call) return NULL;
    }
    if (!s) return NULL;
    size_t n = strlen(s);
    char * p = (char *)malloc(n + 1);
    if (!p) return NULL;
    memcpy(p, s, n);
    p[n] = 0;
    return p;
}

static void set_alloc_select_fail(alloc_select_fail_state * st, int fail_malloc_call, int fail_calloc_call, int fail_realloc_call, int fail_strdup_call) {
    ve_tls_alloc_hooks hooks;
    memset(&hooks, 0, sizeof(hooks));
    st->fail_malloc_call = fail_malloc_call;
    st->fail_calloc_call = fail_calloc_call;
    st->fail_realloc_call = fail_realloc_call;
    st->fail_strdup_call = fail_strdup_call;
    st->malloc_calls = 0;
    st->calloc_calls = 0;
    st->realloc_calls = 0;
    st->strdup_calls = 0;
    st->realloc_null_size_calls = 0;
    hooks.malloc_fn = alloc_select_malloc;
    hooks.calloc_fn = alloc_select_calloc;
    hooks.realloc_fn = alloc_select_realloc;
    hooks.free_fn = alloc_select_free;
    hooks.strdup_fn = alloc_select_strdup;
    hooks.user_data = st;
    ve_tls_alloc_set_hooks(&hooks);
}

typedef struct {
    int64_t live;
} alloc_track_state;

static void * alloc_track_malloc(size_t n, void * user_data) {
    alloc_track_state * st = (alloc_track_state *)user_data;
    void * p = malloc(n);
    if (p && st) {
        (void)__atomic_fetch_add(&st->live, 1, __ATOMIC_RELAXED);
    }
    return p;
}

static void * alloc_track_calloc(size_t n, size_t size, void * user_data) {
    alloc_track_state * st = (alloc_track_state *)user_data;
    void * p = calloc(n, size);
    if (p && st) {
        (void)__atomic_fetch_add(&st->live, 1, __ATOMIC_RELAXED);
    }
    return p;
}

static void * alloc_track_realloc(void * p, size_t n, void * user_data) {
    alloc_track_state * st = (alloc_track_state *)user_data;
    if (!p) {
        void * np = realloc(NULL, n);
        if (np && st) {
            (void)__atomic_fetch_add(&st->live, 1, __ATOMIC_RELAXED);
        }
        return np;
    }
    return realloc(p, n);
}

static void alloc_track_free(void * p, void * user_data) {
    alloc_track_state * st = (alloc_track_state *)user_data;
    if (p && st) {
        (void)__atomic_fetch_sub(&st->live, 1, __ATOMIC_RELAXED);
    }
    free(p);
}

static char * alloc_track_strdup(const char * s, void * user_data) {
    if (!s) return NULL;
    size_t n = strlen(s);
    char * p = (char *)alloc_track_malloc(n + 1, user_data);
    if (!p) return NULL;
    memcpy(p, s, n);
    p[n] = 0;
    return p;
}

static void enable_alloc_tracking(alloc_track_state * st) {
    ve_tls_alloc_hooks hooks;
    memset(&hooks, 0, sizeof(hooks));
    hooks.malloc_fn = alloc_track_malloc;
    hooks.calloc_fn = alloc_track_calloc;
    hooks.realloc_fn = alloc_track_realloc;
    hooks.free_fn = alloc_track_free;
    hooks.strdup_fn = alloc_track_strdup;
    hooks.user_data = st;
    ve_tls_alloc_set_hooks(&hooks);
}

typedef struct {
    int fail_after;
    int calls;
    int64_t live;
} alloc_failtrack_state;

static void * alloc_failtrack_malloc(size_t n, void * user_data) {
    alloc_failtrack_state * st = (alloc_failtrack_state *)user_data;
    if (st) {
        st->calls++;
        if (st->fail_after > 0 && st->calls >= st->fail_after) return NULL;
    }
    void * p = malloc(n);
    if (p && st) {
        (void)__atomic_fetch_add(&st->live, 1, __ATOMIC_RELAXED);
    }
    return p;
}

static void * alloc_failtrack_calloc(size_t n, size_t size, void * user_data) {
    alloc_failtrack_state * st = (alloc_failtrack_state *)user_data;
    if (st) {
        st->calls++;
        if (st->fail_after > 0 && st->calls >= st->fail_after) return NULL;
    }
    void * p = calloc(n, size);
    if (p && st) {
        (void)__atomic_fetch_add(&st->live, 1, __ATOMIC_RELAXED);
    }
    return p;
}

static void * alloc_failtrack_realloc(void * p, size_t n, void * user_data) {
    alloc_failtrack_state * st = (alloc_failtrack_state *)user_data;
    if (st) {
        st->calls++;
        if (st->fail_after > 0 && st->calls >= st->fail_after) return NULL;
    }
    void * np = realloc(p, n);
    if (!p && np && st) {
        (void)__atomic_fetch_add(&st->live, 1, __ATOMIC_RELAXED);
    }
    return np;
}

static void alloc_failtrack_free(void * p, void * user_data) {
    alloc_failtrack_state * st = (alloc_failtrack_state *)user_data;
    if (p && st) {
        (void)__atomic_fetch_sub(&st->live, 1, __ATOMIC_RELAXED);
    }
    free(p);
}

static char * alloc_failtrack_strdup(const char * s, void * user_data) {
    alloc_failtrack_state * st = (alloc_failtrack_state *)user_data;
    if (st) {
        st->calls++;
        if (st->fail_after > 0 && st->calls >= st->fail_after) return NULL;
    }
    if (!s) return NULL;
    size_t n = strlen(s);
    char * p = (char *)malloc(n + 1);
    if (!p) return NULL;
    memcpy(p, s, n);
    p[n] = 0;
    if (st) {
        (void)__atomic_fetch_add(&st->live, 1, __ATOMIC_RELAXED);
    }
    return p;
}

static void set_alloc_failtrack(alloc_failtrack_state * st, int fail_after) {
    ve_tls_alloc_hooks hooks;
    memset(&hooks, 0, sizeof(hooks));
    st->fail_after = fail_after;
    st->calls = 0;
    __atomic_store_n(&st->live, 0, __ATOMIC_RELAXED);
    hooks.malloc_fn = alloc_failtrack_malloc;
    hooks.calloc_fn = alloc_failtrack_calloc;
    hooks.realloc_fn = alloc_failtrack_realloc;
    hooks.free_fn = alloc_failtrack_free;
    hooks.strdup_fn = alloc_failtrack_strdup;
    hooks.user_data = st;
    ve_tls_alloc_set_hooks(&hooks);
}

static ve_tls_platform g_real_platform;
static int64_t g_fake_time = 0;

static int64_t test_fake_time_ms(void) {
    return g_fake_time;
}

static void test_fake_sleep_ms(int64_t ms) {
    if (ms > 0) {
        g_fake_time += ms;
    }
}

static int test_fake_cond_timedwait_ms(ve_tls_cond * c, ve_tls_mutex * m, int64_t timeout_ms) {
    (void)c;
    if (g_real_platform.mutex_unlock) {
        g_real_platform.mutex_unlock(m);
    }
    if (timeout_ms > 0) {
        g_fake_time += timeout_ms;
    }
    if (g_real_platform.mutex_lock) {
        g_real_platform.mutex_lock(m);
    }
    return 0;
}

static int test_http_do(ve_tls_http_client * client, const ve_tls_http_request * req, ve_tls_http_response * resp) {
    (void)client;
    (void)req;
    if (!resp) {
        return -1;
    }
    resp->status_code = 500;
    resp->request_id = strdup("hdr-rid");
    const char * body = "{\"errorCode\":\"LimitExceeded\",\"errorMessage\":\"too many\",\"requestID\":\"body-rid\"}";
    resp->body = (unsigned char *)strdup(body);
    resp->body_size = strlen(body);
    return 0;
}

static void test_http_free(ve_tls_http_client * client, ve_tls_http_response * resp) {
    (void)client;
    if (!resp) {
        return;
    }
    free(resp->body);
    free(resp->request_id);
    free(resp->error_code);
    free(resp->error_message);
    resp->body = NULL;
    resp->request_id = NULL;
    resp->error_code = NULL;
    resp->error_message = NULL;
}

static void on_send_done_v2(
    ve_tls_result result,
    size_t log_bytes,
    size_t compressed_bytes,
    const ve_tls_error * error,
    const unsigned char * raw_buffer,
    void * user_param,
    int64_t start_id,
    int64_t end_id
) {
    (void)log_bytes;
    (void)compressed_bytes;
    (void)user_param;
    (void)start_id;
    (void)end_id;
    g_http_done = 1;
    if (raw_buffer != NULL) {
        g_http_ok = 0;
        return;
    }
    if (result != VE_TLS_DROP_ERROR || !error) {
        g_http_ok = 0;
        return;
    }
    if (error->http_code != 500) {
        g_http_ok = 0;
        return;
    }
    if (!error->error_code || strcmp(error->error_code, "LimitExceeded") != 0) {
        g_http_ok = 0;
        return;
    }
    if (!error->error_message || strcmp(error->error_message, "too many") != 0) {
        g_http_ok = 0;
        return;
    }
    if (!error->request_id || strcmp(error->request_id, "hdr-rid") != 0) {
        g_http_ok = 0;
        return;
    }
    if (error->retryable != 1) {
        g_http_ok = 0;
        return;
    }
    g_http_ok = 1;
}

static int test_structured_error_and_retryable(void) {
    g_http_done = 0;
    g_http_ok = 0;

    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.retry_policy.max_attempts = 1;

    cfg.http_client.do_request = test_http_do;
    cfg.http_client.free_response = test_http_free;
    cfg.http_client.user_data = NULL;

    ve_tls_producer * p = ve_tls_producer_create(&cfg);
    if (!p) {
        return -1;
    }
    ve_tls_producer_set_send_done_v2(p, on_send_done_v2, NULL);

    ve_tls_kv kvs[1];
    kvs[0].key = "k1";
    kvs[0].value = "v1";
    if (ve_tls_producer_add_log_kv(p, 0, kvs, 1, 1) != VE_TLS_OK) {
        ve_tls_producer_destroy(p);
        return -1;
    }

    for (int i = 0; i < 200 && !g_http_done; i++) {
        cfg.platform.sleep_ms(10);
    }
    ve_tls_producer_destroy(p);
    return g_http_ok ? 0 : -1;
}

typedef struct {
    int done;
    int ok;
    int calls;
} http_seq_state;

static http_seq_state g_seq_state;

static int test_http_429_then_ok_do(ve_tls_http_client * client, const ve_tls_http_request * req, ve_tls_http_response * resp) {
    (void)client;
    (void)req;
    if (!resp) {
        return -1;
    }
    g_seq_state.calls++;
    if (g_seq_state.calls <= 2) {
        resp->status_code = 429;
        resp->request_id = strdup("rid-429");
        const char * body = "{\"errorCode\":\"RateLimited\",\"errorMessage\":\"slow down\",\"requestID\":\"body-rid\"}";
        resp->body = (unsigned char *)strdup(body);
        resp->body_size = strlen(body);
        return 0;
    }
    resp->status_code = 200;
    resp->request_id = strdup("rid-ok-429");
    resp->body = NULL;
    resp->body_size = 0;
    return 0;
}

static int test_http_400_do(ve_tls_http_client * client, const ve_tls_http_request * req, ve_tls_http_response * resp) {
    (void)client;
    (void)req;
    if (!resp) {
        return -1;
    }
    g_seq_state.calls++;
    resp->status_code = 400;
    resp->request_id = strdup("rid-400");
    const char * body = "{\"errorCode\":\"BadRequest\",\"errorMessage\":\"bad\",\"requestID\":\"body-rid\"}";
    resp->body = (unsigned char *)strdup(body);
    resp->body_size = strlen(body);
    return 0;
}

static int test_http_transport_retryable_then_ok_do(ve_tls_http_client * client, const ve_tls_http_request * req, ve_tls_http_response * resp) {
    (void)client;
    (void)req;
    if (!resp) {
        return -1;
    }
    g_seq_state.calls++;
    if (g_seq_state.calls <= 2) {
        resp->transport_kind = VE_TLS_TRANSPORT_GENERIC;
        resp->transport_code = 111;
        resp->transport_retryable = 1;
        resp->error_message = strdup("network error");
        return -1;
    }
    resp->status_code = 200;
    resp->request_id = strdup("rid-ok-net");
    resp->body = NULL;
    resp->body_size = 0;
    return 0;
}

static void on_send_done_seq_v2(
    ve_tls_result result,
    size_t log_bytes,
    size_t compressed_bytes,
    const ve_tls_error * error,
    const unsigned char * raw_buffer,
    void * user_param,
    int64_t start_id,
    int64_t end_id
) {
    (void)log_bytes;
    (void)compressed_bytes;
    (void)raw_buffer;
    (void)user_param;
    (void)start_id;
    (void)end_id;
    g_seq_state.done = 1;
    if (result == VE_TLS_OK && error && error->request_id && (strcmp(error->request_id, "rid-ok-429") == 0 || strcmp(error->request_id, "rid-ok-net") == 0)) {
        g_seq_state.ok = 1;
        return;
    }
    if (result == VE_TLS_DROP_ERROR && error && error->request_id && strcmp(error->request_id, "rid-400") == 0 && error->retryable == 0) {
        g_seq_state.ok = 1;
        return;
    }
    g_seq_state.ok = 0;
}

static int test_sender_retries_429_then_ok(void) {
    memset(&g_seq_state, 0, sizeof(g_seq_state));
    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.flush_interval_ms = 0;
    cfg.retry_policy.max_attempts = 5;
    cfg.retry_policy.initial_interval_ms = 1;
    cfg.retry_policy.max_interval_ms = 1;
    cfg.http_client.do_request = test_http_429_then_ok_do;
    cfg.http_client.free_response = test_http_free;
    ve_tls_producer * p = ve_tls_producer_create(&cfg);
    if (!p) return -1;
    ve_tls_producer_set_send_done_v2(p, on_send_done_seq_v2, NULL);
    ve_tls_kv kvs[1];
    kvs[0].key = "k1";
    kvs[0].value = "v1";
    if (ve_tls_producer_add_log_kv(p, 0, kvs, 1, 1) != VE_TLS_OK) {
        ve_tls_producer_destroy(p);
        return -1;
    }
    for (int i = 0; i < 400 && !g_seq_state.done; i++) cfg.platform.sleep_ms(10);
    ve_tls_producer_destroy(p);
    return (g_seq_state.ok && g_seq_state.calls == 3) ? 0 : -1;
}

static int test_sender_http_400_no_retry(void) {
    memset(&g_seq_state, 0, sizeof(g_seq_state));
    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.flush_interval_ms = 0;
    cfg.retry_policy.max_attempts = 5;
    cfg.retry_policy.initial_interval_ms = 1;
    cfg.retry_policy.max_interval_ms = 1;
    cfg.http_client.do_request = test_http_400_do;
    cfg.http_client.free_response = test_http_free;
    ve_tls_producer * p = ve_tls_producer_create(&cfg);
    if (!p) return -1;
    ve_tls_producer_set_send_done_v2(p, on_send_done_seq_v2, NULL);
    ve_tls_kv kvs[1];
    kvs[0].key = "k1";
    kvs[0].value = "v1";
    if (ve_tls_producer_add_log_kv(p, 0, kvs, 1, 1) != VE_TLS_OK) {
        ve_tls_producer_destroy(p);
        return -1;
    }
    for (int i = 0; i < 200 && !g_seq_state.done; i++) cfg.platform.sleep_ms(10);
    ve_tls_producer_destroy(p);
    return (g_seq_state.ok && g_seq_state.calls == 1) ? 0 : -1;
}

static int test_sender_transport_retryable_then_ok(void) {
    memset(&g_seq_state, 0, sizeof(g_seq_state));
    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.flush_interval_ms = 0;
    cfg.retry_policy.max_attempts = 5;
    cfg.retry_policy.initial_interval_ms = 1;
    cfg.retry_policy.max_interval_ms = 1;
    cfg.http_client.do_request = test_http_transport_retryable_then_ok_do;
    cfg.http_client.free_response = test_http_free;
    ve_tls_producer * p = ve_tls_producer_create(&cfg);
    if (!p) return -1;
    ve_tls_producer_set_send_done_v2(p, on_send_done_seq_v2, NULL);
    ve_tls_kv kvs[1];
    kvs[0].key = "k1";
    kvs[0].value = "v1";
    if (ve_tls_producer_add_log_kv(p, 0, kvs, 1, 1) != VE_TLS_OK) {
        ve_tls_producer_destroy(p);
        return -1;
    }
    for (int i = 0; i < 400 && !g_seq_state.done; i++) cfg.platform.sleep_ms(10);
    ve_tls_producer_destroy(p);
    return (g_seq_state.ok && g_seq_state.calls == 3) ? 0 : -1;
}

typedef struct {
    int done;
    int ok;
    int calls;
    int retryable;
    char code[64];
    char msg[256];
    char rid[64];
} sender_err_state;

static sender_err_state g_serr;

static int test_http_rc_minus1_no_fields_do(ve_tls_http_client * client, const ve_tls_http_request * req, ve_tls_http_response * resp) {
    (void)client;
    (void)req;
    if (!resp) return -1;
    g_serr.calls++;
    resp->transport_kind = VE_TLS_TRANSPORT_GENERIC;
    resp->transport_code = 7;
    resp->transport_retryable = 0;
    resp->request_id = strdup("rid-rc1");
    return -1;
}

static int test_http_status_500_no_body_do(ve_tls_http_client * client, const ve_tls_http_request * req, ve_tls_http_response * resp) {
    (void)client;
    (void)req;
    if (!resp) return -1;
    g_serr.calls++;
    resp->status_code = 500;
    resp->request_id = strdup("rid-500");
    resp->body = NULL;
    resp->body_size = 0;
    return 0;
}

static int g_http_called_unexpected = 0;
static int test_http_should_not_call_do(ve_tls_http_client * client, const ve_tls_http_request * req, ve_tls_http_response * resp) {
    (void)client;
    (void)req;
    (void)resp;
    g_http_called_unexpected = 1;
    return -1;
}

static void on_send_done_err_v2(
    ve_tls_result result,
    size_t log_bytes,
    size_t compressed_bytes,
    const ve_tls_error * error,
    const unsigned char * raw_buffer,
    void * user_param,
    int64_t start_id,
    int64_t end_id
) {
    (void)log_bytes;
    (void)compressed_bytes;
    (void)raw_buffer;
    (void)user_param;
    (void)start_id;
    (void)end_id;
    g_serr.done = 1;
    if (result != VE_TLS_DROP_ERROR || !error) {
        g_serr.ok = 0;
        return;
    }
    g_serr.retryable = error->retryable;
    if (error->error_code) snprintf(g_serr.code, sizeof(g_serr.code), "%s", error->error_code);
    if (error->error_message) snprintf(g_serr.msg, sizeof(g_serr.msg), "%s", error->error_message);
    if (error->request_id) snprintf(g_serr.rid, sizeof(g_serr.rid), "%s", error->request_id);
    g_serr.ok = 1;
}

static int test_sender_http_rc_minus1_defaults_error(void) {
    memset(&g_serr, 0, sizeof(g_serr));
    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.flush_interval_ms = 0;
    cfg.retry_policy.max_attempts = 1;
    cfg.http_client.do_request = test_http_rc_minus1_no_fields_do;
    cfg.http_client.free_response = test_http_free;
    ve_tls_producer * p = ve_tls_producer_create(&cfg);
    if (!p) return -1;
    ve_tls_producer_set_send_done_v2(p, on_send_done_err_v2, NULL);
    ve_tls_kv kvs[1];
    kvs[0].key = "k1";
    kvs[0].value = "v1";
    if (ve_tls_producer_add_log_kv(p, 0, kvs, 1, 1) != VE_TLS_OK) {
        ve_tls_producer_destroy(p);
        return -1;
    }
    for (int i = 0; i < 300 && !g_serr.done; i++) cfg.platform.sleep_ms(10);
    ve_tls_producer_destroy(p);
    if (!g_serr.ok) return -1;
    if (strcmp(g_serr.code, "ClientError") != 0) return -1;
    if (strcmp(g_serr.msg, "http request failed") != 0) return -1;
    if (strcmp(g_serr.rid, "rid-rc1") != 0) return -1;
    return 0;
}

static int test_sender_http_500_sets_badresponse(void) {
    memset(&g_serr, 0, sizeof(g_serr));
    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.flush_interval_ms = 0;
    cfg.retry_policy.max_attempts = 1;
    cfg.http_client.do_request = test_http_status_500_no_body_do;
    cfg.http_client.free_response = test_http_free;
    ve_tls_producer * p = ve_tls_producer_create(&cfg);
    if (!p) return -1;
    ve_tls_producer_set_send_done_v2(p, on_send_done_err_v2, NULL);
    ve_tls_kv kvs[1];
    kvs[0].key = "k1";
    kvs[0].value = "v1";
    if (ve_tls_producer_add_log_kv(p, 0, kvs, 1, 1) != VE_TLS_OK) {
        ve_tls_producer_destroy(p);
        return -1;
    }
    for (int i = 0; i < 300 && !g_serr.done; i++) cfg.platform.sleep_ms(10);
    ve_tls_producer_destroy(p);
    if (!g_serr.ok) return -1;
    if (strcmp(g_serr.code, "BadResponse") != 0) return -1;
    if (strcmp(g_serr.msg, "non-200 response") != 0) return -1;
    if (strcmp(g_serr.rid, "rid-500") != 0) return -1;
    return 0;
}

static int test_sender_unsupported_compress_type_drops_before_http(void) {
    memset(&g_serr, 0, sizeof(g_serr));
    g_http_called_unexpected = 0;
    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.flush_interval_ms = 0;
    cfg.retry_policy.max_attempts = 1;
    cfg.compress_type = "bad";
    cfg.http_client.do_request = test_http_should_not_call_do;
    cfg.http_client.free_response = test_http_free;
    ve_tls_producer * p = ve_tls_producer_create(&cfg);
    if (!p) return -1;
    ve_tls_producer_set_send_done_v2(p, on_send_done_err_v2, NULL);
    ve_tls_kv kvs[1];
    kvs[0].key = "k1";
    kvs[0].value = "v1";
    if (ve_tls_producer_add_log_kv(p, 0, kvs, 1, 1) != VE_TLS_OK) {
        ve_tls_producer_destroy(p);
        return -1;
    }
    for (int i = 0; i < 300 && !g_serr.done; i++) cfg.platform.sleep_ms(10);
    ve_tls_producer_destroy(p);
    if (g_http_called_unexpected) return -1;
    if (!g_serr.ok) return -1;
    if (strcmp(g_serr.code, "ClientError") != 0) return -1;
    if (strcmp(g_serr.msg, "unsupported compress_type") != 0) return -1;
    return 0;
}

static int test_sender_build_url_calloc_fail_drops_without_http(void) {
    memset(&g_serr, 0, sizeof(g_serr));
    g_http_called_unexpected = 0;

    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.flush_interval_ms = 100000;
    cfg.retry_policy.max_attempts = 1;
    cfg.ordered_send = 1;
    cfg.http_client.do_request = test_http_should_not_call_do;
    cfg.http_client.free_response = test_http_free;
    ve_tls_producer * p = ve_tls_producer_create(&cfg);
    if (!p) return -1;
    ve_tls_producer_set_send_done_v2(p, on_send_done_err_v2, NULL);

    ve_tls_kv kvs[1];
    kvs[0].key = "k1";
    kvs[0].value = "v1";
    if (ve_tls_producer_add_log_kv(p, 0, kvs, 1, 0) != VE_TLS_OK) {
        ve_tls_producer_destroy(p);
        return -1;
    }

    ve_tls_alloc_hooks saved;
    memset(&saved, 0, sizeof(saved));
    ve_tls_alloc_get_hooks(&saved);
    alloc_select_fail_state st;
    memset(&st, 0, sizeof(st));
    set_alloc_select_fail(&st, 0, 0, 0, 0);
    st.fail_calloc_n_match = 1;
    st.fail_calloc_size_match = strlen(cfg.endpoint) + strlen("/PutLogs?TopicId=") + strlen(cfg.topic_id) + 1;

    if (ve_tls_producer_flush(p) != VE_TLS_OK) {
        ve_tls_alloc_set_hooks(&saved);
        ve_tls_producer_destroy(p);
        return -1;
    }
    for (int i = 0; i < 300 && !g_serr.done; i++) cfg.platform.sleep_ms(10);

    ve_tls_alloc_set_hooks(&saved);
    ve_tls_producer_destroy(p);

    if (g_http_called_unexpected) return -1;
    if (!g_serr.ok) return -1;
    if (strcmp(g_serr.code, "ClientError") != 0) return -1;
    if (strcmp(g_serr.msg, "build url failed") != 0) return -1;
    return 0;
}

static int test_sender_build_headers_realloc_fail_drops_without_http(void) {
    memset(&g_serr, 0, sizeof(g_serr));
    g_http_called_unexpected = 0;

    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.flush_interval_ms = 100000;
    cfg.retry_policy.max_attempts = 1;
    cfg.ordered_send = 1;
    cfg.http_client.do_request = test_http_should_not_call_do;
    cfg.http_client.free_response = test_http_free;
    ve_tls_producer * p = ve_tls_producer_create(&cfg);
    if (!p) return -1;
    ve_tls_producer_set_send_done_v2(p, on_send_done_err_v2, NULL);

    ve_tls_kv kvs[1];
    kvs[0].key = "k1";
    kvs[0].value = "v1";
    if (ve_tls_producer_add_log_kv(p, 0, kvs, 1, 0) != VE_TLS_OK) {
        ve_tls_producer_destroy(p);
        return -1;
    }

    ve_tls_alloc_hooks saved;
    memset(&saved, 0, sizeof(saved));
    ve_tls_alloc_get_hooks(&saved);
    alloc_select_fail_state st;
    memset(&st, 0, sizeof(st));
    set_alloc_select_fail(&st, 0, 0, 0, 0);
    st.fail_realloc_null_match = 1;
    st.fail_realloc_size_match = 256;
    st.fail_realloc_null_size_call = 1;

    if (ve_tls_producer_flush(p) != VE_TLS_OK) {
        ve_tls_alloc_set_hooks(&saved);
        ve_tls_producer_destroy(p);
        return -1;
    }
    for (int i = 0; i < 300 && !g_serr.done; i++) cfg.platform.sleep_ms(10);

    ve_tls_alloc_set_hooks(&saved);
    ve_tls_producer_destroy(p);

    if (g_http_called_unexpected) return -1;
    if (!g_serr.ok) return -1;
    if (strcmp(g_serr.code, "ClientError") != 0) return -1;
    if (strcmp(g_serr.msg, "build headers failed") != 0) return -1;
    return 0;
}

static int test_sender_sign_realloc_fail_drops_without_http(void) {
    memset(&g_serr, 0, sizeof(g_serr));
    g_http_called_unexpected = 0;

    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.flush_interval_ms = 100000;
    cfg.retry_policy.max_attempts = 1;
    cfg.ordered_send = 1;
    cfg.http_client.do_request = test_http_should_not_call_do;
    cfg.http_client.free_response = test_http_free;
    ve_tls_producer * p = ve_tls_producer_create(&cfg);
    if (!p) return -1;
    ve_tls_producer_set_send_done_v2(p, on_send_done_err_v2, NULL);

    ve_tls_kv kvs[1];
    kvs[0].key = "k1";
    kvs[0].value = "v1";
    if (ve_tls_producer_add_log_kv(p, 0, kvs, 1, 0) != VE_TLS_OK) {
        ve_tls_producer_destroy(p);
        return -1;
    }

    ve_tls_alloc_hooks saved;
    memset(&saved, 0, sizeof(saved));
    ve_tls_alloc_get_hooks(&saved);
    alloc_select_fail_state st;
    memset(&st, 0, sizeof(st));
    set_alloc_select_fail(&st, 0, 0, 0, 0);
    st.fail_realloc_null_match = 1;
    st.fail_realloc_size_match = 256;
    st.fail_realloc_null_size_call = 2;

    if (ve_tls_producer_flush(p) != VE_TLS_OK) {
        ve_tls_alloc_set_hooks(&saved);
        ve_tls_producer_destroy(p);
        return -1;
    }
    for (int i = 0; i < 300 && !g_serr.done; i++) cfg.platform.sleep_ms(10);

    ve_tls_alloc_set_hooks(&saved);
    ve_tls_producer_destroy(p);

    if (g_http_called_unexpected) return -1;
    if (!g_serr.ok) return -1;
    if (strcmp(g_serr.code, "ClientError") != 0) return -1;
    if (strcmp(g_serr.msg, "sign request failed") != 0) return -1;
    return 0;
}

static int64_t g_sender_time_t[8] = {0};
static int g_sender_time_n = 0;
static int g_sender_provider_calls = 0;

static int test_http_sender_time_ok_do(ve_tls_http_client * client, const ve_tls_http_request * req, ve_tls_http_response * resp) {
    (void)client;
    (void)req;
    if (!resp) return -1;
    if (g_sender_time_n < (int)(sizeof(g_sender_time_t) / sizeof(g_sender_time_t[0]))) {
        g_sender_time_t[g_sender_time_n++] = test_fake_time_ms();
    }
    resp->status_code = 200;
    resp->request_id = strdup("rid-ok");
    return 0;
}

static int test_http_sender_time_500_do(ve_tls_http_client * client, const ve_tls_http_request * req, ve_tls_http_response * resp) {
    (void)client;
    (void)req;
    if (!resp) return -1;
    if (g_sender_time_n < (int)(sizeof(g_sender_time_t) / sizeof(g_sender_time_t[0]))) {
        g_sender_time_t[g_sender_time_n++] = test_fake_time_ms();
    }
    resp->status_code = 500;
    resp->request_id = strdup("rid-500");
    resp->body = (unsigned char *)strdup("{\"errorCode\":\"E\",\"errorMessage\":\"m\",\"requestId\":\"rid-body\"}");
    resp->body_size = strlen((const char *)resp->body);
    return 0;
}

static int sender_creds_provider_ok_short_expire(ve_tls_credentials * out, void * user_param) {
    (void)user_param;
    if (!out) return -1;
    g_sender_provider_calls++;
    out->access_key_id = "ak1";
    out->access_key_secret = "sk1";
    out->security_token = "tok1";
    out->expire_time_ms = test_fake_time_ms() + 1;
    return 0;
}

static int sender_creds_provider_always_fail(ve_tls_credentials * out, void * user_param) {
    (void)out;
    (void)user_param;
    g_sender_provider_calls++;
    return -1;
}

static int g_sender_ok_v1 = 0;
static int g_sender_drop_v1 = 0;
static char g_sender_msg_v1[256];

static void on_sender_done_v1(
    ve_tls_result result,
    size_t log_bytes,
    size_t compressed_bytes,
    const char * req_id,
    const char * error_message,
    const unsigned char * raw_buffer,
    void * user_param,
    int64_t start_id,
    int64_t end_id
) {
    (void)log_bytes;
    (void)compressed_bytes;
    (void)req_id;
    (void)raw_buffer;
    (void)user_param;
    (void)start_id;
    (void)end_id;
    if (result == VE_TLS_OK) {
        g_sender_ok_v1++;
    } else if (result == VE_TLS_DROP_ERROR) {
        g_sender_drop_v1++;
        if (error_message) {
            snprintf(g_sender_msg_v1, sizeof(g_sender_msg_v1), "%s", error_message);
        }
    }
}

static int test_sender_key_rate_limit_delays_same_key(void) {
    memset(g_sender_time_t, 0, sizeof(g_sender_time_t));
    g_sender_time_n = 0;
    g_sender_ok_v1 = 0;

    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    g_real_platform = cfg.platform;
    g_fake_time = 1000;
    cfg.platform.time_ms = test_fake_time_ms;
    cfg.platform.sleep_ms = test_fake_sleep_ms;
    cfg.platform.cond_timedwait_ms = test_fake_cond_timedwait_ms;

    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.compress_type = "none";
    cfg.flush_interval_ms = 10;
    cfg.send_thread_count = 1;
    cfg.log_count_per_package = 1;
    cfg.key_queue_idle_ttl_ms = 100000;
    cfg.key_rate_limit_rps = 1;
    cfg.retry_policy.max_attempts = 1;
    cfg.http_client.do_request = test_http_sender_time_ok_do;
    cfg.http_client.free_response = test_http_ok_free;

    ve_tls_producer * p = ve_tls_producer_create(&cfg);
    if (!p) return -1;
    ve_tls_producer_set_send_done(p, on_sender_done_v1, NULL);

    ve_tls_kv kvs[1];
    kvs[0].key = "k";
    kvs[0].value = "v";
    if (ve_tls_producer_add_log_kv_hashkey(p, 0, "hk", kvs, 1, 1) != VE_TLS_OK) {
        ve_tls_producer_destroy(p);
        return -1;
    }
    if (ve_tls_producer_add_log_kv_hashkey(p, 0, "hk", kvs, 1, 1) != VE_TLS_OK) {
        ve_tls_producer_destroy(p);
        return -1;
    }
    for (int i = 0; i < 5000; i++) {
        g_real_platform.sleep_ms(1);
        if (g_sender_time_n >= 2) break;
    }
    ve_tls_producer_destroy(p);
    if (g_sender_time_n < 2) {
        fprintf(stderr, "test_sender_key_rate_limit_delays_same_key: calls=%d ok=%d t0=%lld t1=%lld now=%lld\n",
            g_sender_time_n, g_sender_ok_v1, (long long)g_sender_time_t[0], (long long)g_sender_time_t[1], (long long)g_fake_time);
        return -1;
    }
    if (g_sender_time_t[1] - g_sender_time_t[0] < 1000) {
        fprintf(stderr, "test_sender_key_rate_limit_delays_same_key: delta=%lld calls=%d ok=%d t0=%lld t1=%lld now=%lld\n",
            (long long)(g_sender_time_t[1] - g_sender_time_t[0]), g_sender_time_n, g_sender_ok_v1, (long long)g_sender_time_t[0], (long long)g_sender_time_t[1], (long long)g_fake_time);
        return -1;
    }
    if (g_sender_ok_v1 < 2) {
        fprintf(stderr, "test_sender_key_rate_limit_delays_same_key: ok=%d calls=%d t0=%lld t1=%lld now=%lld\n",
            g_sender_ok_v1, g_sender_time_n, (long long)g_sender_time_t[0], (long long)g_sender_time_t[1], (long long)g_fake_time);
        return -1;
    }
    return 0;
}

static int test_sender_key_breaker_delays_same_key(void) {
    memset(g_sender_time_t, 0, sizeof(g_sender_time_t));
    g_sender_time_n = 0;

    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    g_real_platform = cfg.platform;
    g_fake_time = 2000;
    cfg.platform.time_ms = test_fake_time_ms;
    cfg.platform.sleep_ms = test_fake_sleep_ms;
    cfg.platform.cond_timedwait_ms = test_fake_cond_timedwait_ms;

    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.compress_type = "none";
    cfg.flush_interval_ms = 10;
    cfg.send_thread_count = 1;
    cfg.log_count_per_package = 1;
    cfg.key_queue_idle_ttl_ms = 100000;
    cfg.key_breaker_fail_threshold = 1;
    cfg.key_breaker_open_ms = 5000;
    cfg.retry_policy.max_attempts = 1;
    cfg.http_client.do_request = test_http_sender_time_500_do;
    cfg.http_client.free_response = test_http_ok_free;

    ve_tls_producer * p = ve_tls_producer_create(&cfg);
    if (!p) return -1;
    g_real_platform.sleep_ms(20);

    ve_tls_kv kvs[1];
    kvs[0].key = "k";
    kvs[0].value = "v";
    if (ve_tls_producer_add_log_kv_hashkey(p, 0, "hk", kvs, 1, 1) != VE_TLS_OK) {
        ve_tls_producer_destroy(p);
        return -1;
    }
    if (ve_tls_producer_add_log_kv_hashkey(p, 0, "hk", kvs, 1, 1) != VE_TLS_OK) {
        ve_tls_producer_destroy(p);
        return -1;
    }
    for (int i = 0; i < 8000; i++) {
        g_real_platform.sleep_ms(1);
        if (g_sender_time_n >= 2) break;
    }
    ve_tls_producer_destroy(p);
    if (g_sender_time_n < 2) {
        fprintf(stderr, "test_sender_key_breaker_delays_same_key: calls=%d t0=%lld t1=%lld now=%lld\n",
            g_sender_time_n, (long long)g_sender_time_t[0], (long long)g_sender_time_t[1], (long long)g_fake_time);
        return -1;
    }
    if (g_sender_time_t[1] - g_sender_time_t[0] < 5000) {
        fprintf(stderr, "test_sender_key_breaker_delays_same_key: delta=%lld calls=%d t0=%lld t1=%lld now=%lld\n",
            (long long)(g_sender_time_t[1] - g_sender_time_t[0]), g_sender_time_n, (long long)g_sender_time_t[0], (long long)g_sender_time_t[1], (long long)g_fake_time);
        return -1;
    }
    return 0;
}

static int test_sender_credentials_min_interval_returns_cached(void) {
    g_sender_provider_calls = 0;
    memset(g_sender_time_t, 0, sizeof(g_sender_time_t));
    g_sender_time_n = 0;

    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    g_real_platform = cfg.platform;
    g_fake_time = 3000;
    cfg.platform.time_ms = test_fake_time_ms;
    cfg.platform.sleep_ms = test_fake_sleep_ms;
    cfg.platform.cond_timedwait_ms = test_fake_cond_timedwait_ms;

    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.compress_type = "none";
    cfg.flush_interval_ms = 10;
    cfg.send_thread_count = 1;
    cfg.log_count_per_package = 1;
    cfg.credentials_provider = sender_creds_provider_ok_short_expire;
    cfg.credentials_refresh_min_interval_ms = 100000;
    cfg.retry_policy.max_attempts = 1;
    cfg.http_client.do_request = test_http_sender_time_ok_do;
    cfg.http_client.free_response = test_http_ok_free;

    ve_tls_producer * p = ve_tls_producer_create(&cfg);
    if (!p) return -1;

    ve_tls_kv kvs[1];
    kvs[0].key = "k";
    kvs[0].value = "v";
    if (ve_tls_producer_add_log_kv(p, 0, kvs, 1, 1) != VE_TLS_OK) {
        ve_tls_producer_destroy(p);
        return -1;
    }
    cfg.platform.sleep_ms(2);
    if (ve_tls_producer_add_log_kv(p, 0, kvs, 1, 1) != VE_TLS_OK) {
        ve_tls_producer_destroy(p);
        return -1;
    }
    for (int i = 0; i < 5000; i++) {
        g_real_platform.sleep_ms(1);
        if (g_sender_time_n >= 2) break;
    }
    ve_tls_producer_destroy(p);
    if (g_sender_time_n < 2) return -1;
    if (g_sender_provider_calls != 1) return -1;
    return 0;
}

static int test_sender_credentials_min_interval_fail_without_cached(void) {
    g_sender_provider_calls = 0;
    g_sender_drop_v1 = 0;
    memset(g_sender_msg_v1, 0, sizeof(g_sender_msg_v1));

    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    g_real_platform = cfg.platform;
    g_fake_time = 4000;
    cfg.platform.time_ms = test_fake_time_ms;
    cfg.platform.sleep_ms = test_fake_sleep_ms;
    cfg.platform.cond_timedwait_ms = test_fake_cond_timedwait_ms;

    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.compress_type = "none";
    cfg.flush_interval_ms = 10;
    cfg.send_thread_count = 1;
    cfg.log_count_per_package = 1;
    cfg.credentials_provider = sender_creds_provider_always_fail;
    cfg.credentials_refresh_min_interval_ms = 100000;
    cfg.retry_policy.max_attempts = 1;
    cfg.http_client.do_request = test_http_sender_time_ok_do;
    cfg.http_client.free_response = test_http_ok_free;

    ve_tls_producer * p = ve_tls_producer_create(&cfg);
    if (!p) return -1;
    ve_tls_producer_set_send_done(p, on_sender_done_v1, NULL);

    ve_tls_kv kvs[1];
    kvs[0].key = "k";
    kvs[0].value = "v";
    if (ve_tls_producer_add_log_kv(p, 0, kvs, 1, 1) != VE_TLS_OK) {
        ve_tls_producer_destroy(p);
        return -1;
    }
    cfg.platform.sleep_ms(1);
    if (ve_tls_producer_add_log_kv(p, 0, kvs, 1, 1) != VE_TLS_OK) {
        ve_tls_producer_destroy(p);
        return -1;
    }
    for (int i = 0; i < 2000; i++) {
        g_real_platform.sleep_ms(1);
        if (g_sender_drop_v1 >= 2) break;
    }
    ve_tls_producer_destroy(p);
    if (g_sender_drop_v1 < 2) {
        fprintf(stderr, "creds_min_int_fail_no_cached: drops=%d calls=%d msg='%s'\n", g_sender_drop_v1, g_sender_provider_calls, g_sender_msg_v1);
        return -1;
    }
    if (strcmp(g_sender_msg_v1, "credentials refresh failed") != 0) {
        fprintf(stderr, "creds_min_int_fail_no_cached: msg='%s'\n", g_sender_msg_v1);
        return -1;
    }
    if (g_sender_provider_calls != 1) {
        fprintf(stderr, "creds_min_int_fail_no_cached: provider_calls=%d\n", g_sender_provider_calls);
        return -1;
    }
    return 0;
}

static int test_builder_flush_interval_respects_configured_deadline(void) {
    memset(g_sender_time_t, 0, sizeof(g_sender_time_t));
    g_sender_time_n = 0;

    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    g_real_platform = cfg.platform;
    g_fake_time = 5000;
    cfg.platform.time_ms = test_fake_time_ms;
    cfg.platform.sleep_ms = test_fake_sleep_ms;
    cfg.platform.cond_timedwait_ms = test_fake_cond_timedwait_ms;

    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.compress_type = "none";
    cfg.flush_interval_ms = 10;
    cfg.send_thread_count = 1;
    cfg.ordered_send = 1;
    cfg.log_count_per_package = 2;
    cfg.retry_policy.max_attempts = 1;
    cfg.http_client.do_request = test_http_sender_time_ok_do;
    cfg.http_client.free_response = test_http_ok_free;

    ve_tls_producer * p = ve_tls_producer_create(&cfg);
    if (!p) return -1;

    ve_tls_kv kvs[1];
    kvs[0].key = "k";
    kvs[0].value = "v";
    if (ve_tls_producer_add_log_kv(p, 0, kvs, 1, 0) != VE_TLS_OK) {
        ve_tls_producer_destroy(p);
        return -1;
    }
    cfg.platform.mutex_lock(p->mutex);
    cfg.platform.cond_signal(p->cond);
    cfg.platform.mutex_unlock(p->mutex);
    for (int i = 0; i < 2000; i++) {
        g_real_platform.sleep_ms(1);
        if (g_sender_time_n >= 1) break;
    }
    ve_tls_producer_destroy(p);
    if (g_sender_time_n < 1) {
        fprintf(stderr, "builder_flush_deadline: no send fake_now=%lld\n", (long long)g_fake_time);
        return -1;
    }
    if (g_sender_time_t[0] - 5000 < 10 || g_sender_time_t[0] - 5000 > 20) {
        fprintf(stderr, "builder_flush_deadline: send_at=%lld fake_now=%lld\n",
            (long long)g_sender_time_t[0], (long long)g_fake_time);
        return -1;
    }
    return 0;
}

static int test_sender_idle_wait_without_delayed_does_not_spin_timedwait(void) {
    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    g_real_platform = cfg.platform;
    g_fake_time = 7000;
    cfg.platform.time_ms = test_fake_time_ms;
    cfg.platform.sleep_ms = test_fake_sleep_ms;
    cfg.platform.cond_timedwait_ms = test_fake_cond_timedwait_ms;

    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.compress_type = "none";
    cfg.flush_interval_ms = 10;
    cfg.send_thread_count = 1;
    cfg.ordered_send = 1;
    cfg.retry_policy.max_attempts = 1;
    cfg.http_client.do_request = test_http_sender_time_ok_do;
    cfg.http_client.free_response = test_http_ok_free;

    ve_tls_producer * p = ve_tls_producer_create(&cfg);
    if (!p) return -1;
    g_real_platform.sleep_ms(20);
    int64_t after_wait = g_fake_time;
    ve_tls_producer_destroy(p);
    if (after_wait - 7000 > 20) {
        fprintf(stderr, "sender_idle_wait_spun: fake_now=%lld\n", (long long)after_wait);
        return -1;
    }
    return 0;
}

static int g_sender_hdr_ok = 0;
static int g_sender_seen_retryable = 0;
static int g_sender_seen_transport_curl = 0;
static char g_sender_seen_url[256];
static int g_func_matrix_req_count = 0;
static int g_func_matrix_seen_old_url = 0;
static int g_func_matrix_seen_new_url = 0;
static int g_func_matrix_seen_old_ak = 0;
static int g_func_matrix_seen_new_ak = 0;

static int test_http_sender_check_default_hashkey_do(ve_tls_http_client * client, const ve_tls_http_request * req, ve_tls_http_response * resp) {
    (void)client;
    if (!req || !resp) return -1;
    if (req->headers && strstr(req->headers, "x-tls-hashkey: def-hk")) {
        g_sender_hdr_ok = 1;
    }
    resp->status_code = 200;
    resp->request_id = strdup("rid-ok");
    return 0;
}

static int test_http_sender_transport_curl_retryable_do(ve_tls_http_client * client, const ve_tls_http_request * req, ve_tls_http_response * resp) {
    (void)client;
    (void)req;
    if (!resp) return -1;
    resp->transport_kind = VE_TLS_TRANSPORT_CURL;
    resp->transport_code = 28;
    resp->transport_retryable = 1;
    resp->request_id = strdup("rid-curl");
    return -1;
}

static void on_sender_done_capture_v2(
    ve_tls_result result,
    size_t log_bytes,
    size_t compressed_bytes,
    const ve_tls_error * error,
    const unsigned char * raw_buffer,
    void * user_param,
    int64_t start_id,
    int64_t end_id
) {
    (void)log_bytes;
    (void)compressed_bytes;
    (void)raw_buffer;
    (void)user_param;
    (void)start_id;
    (void)end_id;
    if (result == VE_TLS_DROP_ERROR && error) {
        g_sender_seen_retryable = error->retryable;
        g_sender_seen_transport_curl = (error->transport_kind == VE_TLS_TRANSPORT_CURL) ? 1 : 0;
    }
}

static int test_http_sender_capture_url_and_auth_do(ve_tls_http_client * client, const ve_tls_http_request * req, ve_tls_http_response * resp) {
    (void)client;
    if (!req || !resp) return -1;
    if (req->url) {
        snprintf(g_sender_seen_url, sizeof(g_sender_seen_url), "%s", req->url);
    }
    if (req->headers && strstr(req->headers, "Authorization: HMAC-SHA256 Credential=ak2/")) {
        g_sender_hdr_ok = 1;
    }
    resp->status_code = 200;
    resp->request_id = strdup("rid-ok");
    return 0;
}

static int test_http_functional_matrix_capture_do(ve_tls_http_client * client, const ve_tls_http_request * req, ve_tls_http_response * resp) {
    (void)client;
    if (!req || !resp) return -1;
    if (req->url && strstr(req->url, "https://example.com/PutLogs?TopicId=t1")) {
        __atomic_store_n(&g_func_matrix_seen_old_url, 1, __ATOMIC_RELAXED);
    }
    if (req->url && strstr(req->url, "https://new.example.com/PutLogs?TopicId=t2")) {
        __atomic_store_n(&g_func_matrix_seen_new_url, 1, __ATOMIC_RELAXED);
    }
    if (req->headers && strstr(req->headers, "Authorization: HMAC-SHA256 Credential=ak/")) {
        __atomic_store_n(&g_func_matrix_seen_old_ak, 1, __ATOMIC_RELAXED);
    }
    if (req->headers && strstr(req->headers, "Authorization: HMAC-SHA256 Credential=ak2/")) {
        __atomic_store_n(&g_func_matrix_seen_new_ak, 1, __ATOMIC_RELAXED);
    }
    (void)__atomic_fetch_add(&g_func_matrix_req_count, 1, __ATOMIC_RELAXED);
    resp->status_code = 200;
    resp->request_id = strdup("rid-func");
    return 0;
}

static int test_pipeline_v2_functional_matrix_raw_kv_template_and_runtime_updates(void) {
    __atomic_store_n(&g_func_matrix_req_count, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&g_func_matrix_seen_old_url, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&g_func_matrix_seen_new_url, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&g_func_matrix_seen_old_ak, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&g_func_matrix_seen_new_ak, 0, __ATOMIC_RELAXED);

    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t1";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.compress_type = "none";
    cfg.send_thread_count = 1;
    cfg.log_count_per_package = 1;
    cfg.flush_interval_ms = 10;
    cfg.retry_policy.max_attempts = 1;
    cfg.http_client.do_request = test_http_functional_matrix_capture_do;
    cfg.http_client.free_response = test_http_ok_free;

    ve_tls_producer * p = ve_tls_producer_create(&cfg);
    if (!p) return -1;

    const char * tpl_keys[1];
    size_t tpl_key_lens[1];
    tpl_keys[0] = "message";
    tpl_key_lens[0] = 7;
    ve_tls_log_template * tpl = ve_tls_template_create(p, tpl_keys, tpl_key_lens, 1, NULL);
    if (!tpl) {
        ve_tls_producer_destroy(p);
        return -1;
    }

    const char * raw1 = "{\"m\":\"raw1\"}";
    ve_tls_kv kvs[1];
    kvs[0].key = "message";
    kvs[0].value = "kv1";
    const char * values1[1];
    size_t value_lens1[1];
    values1[0] = "tpl1";
    value_lens1[0] = 4;

    if (ve_tls_producer_add_log_raw(p, raw1, strlen(raw1), 1) != VE_TLS_OK) {
        ve_tls_template_destroy(tpl);
        ve_tls_producer_destroy(p);
        return -1;
    }
    if (ve_tls_producer_add_log_kv(p, 0, kvs, 1, 1) != VE_TLS_OK) {
        ve_tls_template_destroy(tpl);
        ve_tls_producer_destroy(p);
        return -1;
    }
    if (ve_tls_template_add_values(tpl, 0, 0, 0, values1, value_lens1, 1, 1) != VE_TLS_OK) {
        ve_tls_template_destroy(tpl);
        ve_tls_producer_destroy(p);
        return -1;
    }

    for (int i = 0; i < 2000; i++) {
        if (__atomic_load_n(&g_func_matrix_req_count, __ATOMIC_RELAXED) >= 1) {
            break;
        }
        cfg.platform.sleep_ms(1);
    }

    if (ve_tls_producer_update_endpoint(p, "https://new.example.com", "cn-beijing", "t2") != VE_TLS_OK) {
        ve_tls_template_destroy(tpl);
        ve_tls_producer_destroy(p);
        return -1;
    }
    if (ve_tls_producer_update_static_credentials(p, "ak2", "sk2", NULL) != VE_TLS_OK) {
        ve_tls_template_destroy(tpl);
        ve_tls_producer_destroy(p);
        return -1;
    }

    const char * raw2 = "{\"m\":\"raw2\"}";
    kvs[0].value = "kv2";
    const char * values2[1];
    size_t value_lens2[1];
    values2[0] = "tpl2";
    value_lens2[0] = 4;

    if (ve_tls_producer_add_log_raw(p, raw2, strlen(raw2), 1) != VE_TLS_OK) {
        ve_tls_template_destroy(tpl);
        ve_tls_producer_destroy(p);
        return -1;
    }
    if (ve_tls_producer_add_log_kv(p, 0, kvs, 1, 1) != VE_TLS_OK) {
        ve_tls_template_destroy(tpl);
        ve_tls_producer_destroy(p);
        return -1;
    }
    if (ve_tls_template_add_values(tpl, 0, 0, 0, values2, value_lens2, 1, 1) != VE_TLS_OK) {
        ve_tls_template_destroy(tpl);
        ve_tls_producer_destroy(p);
        return -1;
    }

    ve_tls_result close_rc = ve_tls_producer_close(p, 5000);
    ve_tls_template_destroy(tpl);
    ve_tls_producer_destroy(p);
    if (close_rc != VE_TLS_OK) return -1;

    if (!__atomic_load_n(&g_func_matrix_seen_old_url, __ATOMIC_RELAXED)) return -1;
    if (!__atomic_load_n(&g_func_matrix_seen_new_url, __ATOMIC_RELAXED)) return -1;
    if (!__atomic_load_n(&g_func_matrix_seen_old_ak, __ATOMIC_RELAXED)) return -1;
    if (!__atomic_load_n(&g_func_matrix_seen_new_ak, __ATOMIC_RELAXED)) return -1;
    if (__atomic_load_n(&g_func_matrix_req_count, __ATOMIC_RELAXED) < 2) return -1;
    return 0;
}

static int test_sender_default_hash_key_header_set(void) {
    g_sender_hdr_ok = 0;
    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.hash_key = "def-hk";
    cfg.log_count_per_package = 1;
    cfg.flush_interval_ms = 10;
    cfg.retry_policy.max_attempts = 1;
    cfg.http_client.do_request = test_http_sender_check_default_hashkey_do;
    cfg.http_client.free_response = test_http_ok_free;
    ve_tls_producer * p = ve_tls_producer_create(&cfg);
    if (!p) return -1;
    ve_tls_kv kvs[1];
    kvs[0].key = "k";
    kvs[0].value = "v";
    if (ve_tls_producer_add_log_kv(p, 0, kvs, 1, 1) != VE_TLS_OK) {
        ve_tls_producer_destroy(p);
        return -1;
    }
    for (int i = 0; i < 2000 && !g_sender_hdr_ok; i++) cfg.platform.sleep_ms(1);
    ve_tls_producer_destroy(p);
    return g_sender_hdr_ok ? 0 : -1;
}

static int test_sender_transport_curl_retryable_flag(void) {
    g_sender_seen_retryable = 0;
    g_sender_seen_transport_curl = 0;
    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.log_count_per_package = 1;
    cfg.flush_interval_ms = 10;
    cfg.retry_policy.max_attempts = 1;
    cfg.http_client.do_request = test_http_sender_transport_curl_retryable_do;
    cfg.http_client.free_response = test_http_ok_free;
    ve_tls_producer * p = ve_tls_producer_create(&cfg);
    if (!p) return -1;
    ve_tls_producer_set_send_done_v2(p, on_sender_done_capture_v2, NULL);
    ve_tls_kv kvs[1];
    kvs[0].key = "k";
    kvs[0].value = "v";
    if (ve_tls_producer_add_log_kv(p, 0, kvs, 1, 1) != VE_TLS_OK) {
        ve_tls_producer_destroy(p);
        return -1;
    }
    for (int i = 0; i < 2000 && !g_sender_seen_transport_curl; i++) cfg.platform.sleep_ms(1);
    ve_tls_producer_destroy(p);
    return (g_sender_seen_transport_curl && g_sender_seen_retryable) ? 0 : -1;
}

static int test_producer_update_endpoint_affects_url(void) {
    memset(g_sender_seen_url, 0, sizeof(g_sender_seen_url));
    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.log_count_per_package = 1;
    cfg.flush_interval_ms = 10;
    cfg.retry_policy.max_attempts = 1;
    cfg.http_client.do_request = test_http_sender_capture_url_and_auth_do;
    cfg.http_client.free_response = test_http_ok_free;
    ve_tls_producer * p = ve_tls_producer_create(&cfg);
    if (!p) return -1;
    if (ve_tls_producer_update_endpoint(p, "https://new.example.com", "cn-beijing", "t2") != VE_TLS_OK) {
        ve_tls_producer_destroy(p);
        return -1;
    }
    ve_tls_kv kvs[1];
    kvs[0].key = "k";
    kvs[0].value = "v";
    if (ve_tls_producer_add_log_kv(p, 0, kvs, 1, 1) != VE_TLS_OK) {
        ve_tls_producer_destroy(p);
        return -1;
    }
    for (int i = 0; i < 2000 && g_sender_seen_url[0] == 0; i++) cfg.platform.sleep_ms(1);
    ve_tls_producer_destroy(p);
    if (strstr(g_sender_seen_url, "https://new.example.com/PutLogs?TopicId=t2") == NULL) return -1;
    return 0;
}

static int test_producer_update_static_credentials_affects_auth_header(void) {
    g_sender_hdr_ok = 0;
    memset(g_sender_seen_url, 0, sizeof(g_sender_seen_url));
    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.log_count_per_package = 1;
    cfg.flush_interval_ms = 10;
    cfg.retry_policy.max_attempts = 1;
    cfg.http_client.do_request = test_http_sender_capture_url_and_auth_do;
    cfg.http_client.free_response = test_http_ok_free;
    ve_tls_producer * p = ve_tls_producer_create(&cfg);
    if (!p) return -1;
    if (ve_tls_producer_update_static_credentials(p, "ak2", "sk2", NULL) != VE_TLS_OK) {
        ve_tls_producer_destroy(p);
        return -1;
    }
    ve_tls_kv kvs[1];
    kvs[0].key = "k";
    kvs[0].value = "v";
    if (ve_tls_producer_add_log_kv(p, 0, kvs, 1, 1) != VE_TLS_OK) {
        ve_tls_producer_destroy(p);
        return -1;
    }
    for (int i = 0; i < 2000 && !g_sender_hdr_ok; i++) cfg.platform.sleep_ms(1);
    ve_tls_producer_destroy(p);
    return g_sender_hdr_ok ? 0 : -1;
}

static int test_producer_common_rate_limit_and_breaker_paths(void) {
    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    ve_tls_platform plat = cfg.platform;
    g_real_platform = plat;
    g_fake_time = 1000;
    plat.time_ms = test_fake_time_ms;
    plat.sleep_ms = test_fake_sleep_ms;

    ve_tls_producer p;
    memset(&p, 0, sizeof(p));
    p.config = cfg;
    p.config.platform = plat;
    p.mutex = plat.mutex_create();
    if (!p.mutex) return -1;

    if (ve_tls_latency_bucket_index(10) != 1) return -1;
    if (ve_tls_latency_bucket_index(50) != 2) return -1;
    if (ve_tls_latency_bucket_index(3000) != 6) return -1;
    if (ve_tls_latency_bucket_index(5000) != 7) return -1;

    ve_tls_rate_limit_wait(NULL, 0);

    p.config.rate_limit_rps = 1;
    p.config.rate_limit_bps = 0;
    p.config.platform.time_ms = NULL;
    ve_tls_rate_limit_wait(&p, 0);
    p.config.platform.time_ms = test_fake_time_ms;

    p.config.rate_limit_rps = 0;
    p.config.rate_limit_bps = 100;
    p.rl_last_ms = 0;
    p.rl_byte_tokens = 0;
    ve_tls_rate_limit_wait(&p, 1);

    p.config.rate_limit_rps = 0;
    p.config.rate_limit_bps = 1000;
    p.rl_last_ms = 1000;
    p.rl_byte_tokens = 0;
    g_fake_time = 1000;
    ve_tls_rate_limit_wait(&p, 1);

    p.config.rate_limit_rps = 0;
    p.config.rate_limit_bps = 1;
    p.rl_last_ms = 1000;
    p.rl_byte_tokens = 100;
    g_fake_time = 1001;
    ve_tls_rate_limit_wait(&p, 0);

    p.config.rate_limit_rps = 100;
    p.rl_last_ms = 1000;
    p.rl_req_tokens = 0;
    ve_tls_rate_limit_wait(&p, 0);

    p.stop = 1;
    ve_tls_rate_limit_wait(&p, 0);
    p.stop = 0;

    p.config.breaker_fail_threshold = 1;
    p.config.breaker_open_ms = 5;
    p.breaker_open_until_ms = test_fake_time_ms() + 5;
    ve_tls_breaker_wait_open(&p);

    p.config.platform.time_ms = NULL;
    ve_tls_breaker_wait_open(&p);
    p.config.platform.time_ms = test_fake_time_ms;

    p.stop = 1;
    p.breaker_open_until_ms = test_fake_time_ms() + 10;
    ve_tls_breaker_wait_open(&p);
    p.stop = 0;

    p.config.breaker_half_open_max_inflight = 1;
    p.breaker_half_open_inflight = 0;
    p.breaker_open_until_ms = 0;
    if (ve_tls_breaker_try_enter_half_open(&p) != 2) return -1;
    if (ve_tls_breaker_try_enter_half_open(&p) != 0) return -1;
    p.breaker_open_until_ms = test_fake_time_ms() + 10;
    if (ve_tls_breaker_try_enter_half_open(&p) != 0) return -1;

    p.config.platform.time_ms = NULL;
    if (ve_tls_breaker_try_enter_half_open(&p) != 1) return -1;
    p.config.platform.time_ms = test_fake_time_ms;

    p.breaker_half_open_inflight = 1;
    ve_tls_breaker_leave_half_open(&p, 1);
    ve_tls_breaker_leave_half_open(&p, 0);
    ve_tls_breaker_on_final_result(&p, 0);
    ve_tls_breaker_on_final_result(&p, 1);

    p.config.breaker_fail_threshold = 0;
    ve_tls_breaker_leave_half_open(&p, 1);
    p.config.breaker_fail_threshold = 1;

    p.config.platform.time_ms = NULL;
    ve_tls_breaker_leave_half_open(&p, 1);
    ve_tls_breaker_on_final_result(&p, 0);
    p.config.platform.time_ms = test_fake_time_ms;

    p.config.breaker_open_ms = 0;
    p.breaker_half_open_inflight = 1;
    p.breaker_consecutive_failures = 0;
    p.breaker_open_until_ms = 0;
    ve_tls_breaker_leave_half_open(&p, 0);
    if (p.breaker_open_until_ms == 0) return -1;

    p.breaker_consecutive_failures = 0;
    p.breaker_open_until_ms = 0;
    ve_tls_breaker_on_final_result(&p, 0);
    if (p.breaker_open_until_ms == 0) return -1;

    plat.mutex_destroy(p.mutex);
    return 0;
}

static int init_fake_sender_producer(ve_tls_producer * p, ve_tls_config * cfg) {
    if (!p || !cfg) return -1;
    memset(p, 0, sizeof(*p));
    p->config = *cfg;
    p->mutex = p->config.platform.mutex_create();
    p->cond = p->config.platform.cond_create();
    p->send_cond = p->config.platform.cond_create();
    if (!p->mutex || !p->cond || !p->send_cond) return -1;
    p->accepting = 1;
    p->use_global_env = 0;
    p->key_bucket_count = 8;
    p->key_buckets = (ve_tls_key_queue **)ve_tls_calloc(p->key_bucket_count, sizeof(ve_tls_key_queue *));
    if (!p->key_buckets) return -1;
    size_t sq = (cfg->send_queue_size > 0) ? (size_t)cfg->send_queue_size : 16;
    if (sq == 0) sq = 16;
    if (ve_tls_send_queue_init(&p->send_queue, &p->config.platform, sq, NULL) != 0) return -1;
    if (ve_tls_runtime_snapshot_refresh(p) != 0) return -1;
    return 0;
}

static void destroy_fake_sender_producer(ve_tls_producer * p) {
    if (!p) return;
    ve_tls_runtime_snapshot_clear(p);
    ve_tls_send_queue_stop(&p->send_queue);
    ve_tls_send_queue_destroy(&p->send_queue);
    ve_tls_key_map_free_all(p);
    if (p->send_cond) p->config.platform.cond_destroy(p->send_cond);
    if (p->cond) p->config.platform.cond_destroy(p->cond);
    if (p->mutex) p->config.platform.mutex_destroy(p->mutex);
    memset(p, 0, sizeof(*p));
}

static int g_step_http_calls = 0;
static int g_step_ok_calls = 0;
static int g_step_drop_calls = 0;
static char g_step_drop_code[64];

static int test_http_step_ok_do(ve_tls_http_client * client, const ve_tls_http_request * req, ve_tls_http_response * resp) {
    (void)client;
    (void)req;
    if (!resp) return -1;
    g_step_http_calls++;
    resp->status_code = 200;
    resp->request_id = strdup("rid-ok");
    return 0;
}

static int test_http_step_retry_then_ok_do(ve_tls_http_client * client, const ve_tls_http_request * req, ve_tls_http_response * resp) {
    (void)client;
    (void)req;
    if (!resp) return -1;
    g_step_http_calls++;
    if (g_step_http_calls == 1) {
        resp->transport_kind = VE_TLS_TRANSPORT_GENERIC;
        resp->transport_code = 7;
        resp->transport_retryable = 1;
        return -1;
    }
    resp->status_code = 200;
    resp->request_id = strdup("rid-ok");
    return 0;
}

static void on_step_done_v2(
    ve_tls_result result,
    size_t log_bytes,
    size_t compressed_bytes,
    const ve_tls_error * error,
    const unsigned char * raw_buffer,
    void * user_param,
    int64_t start_id,
    int64_t end_id
) {
    (void)log_bytes;
    (void)compressed_bytes;
    (void)raw_buffer;
    (void)user_param;
    (void)start_id;
    (void)end_id;
    if (result == VE_TLS_OK) {
        g_step_ok_calls++;
    } else if (result == VE_TLS_DROP_ERROR) {
        g_step_drop_calls++;
        if (error && error->error_code) snprintf(g_step_drop_code, sizeof(g_step_drop_code), "%s", error->error_code);
    }
}

static void on_step_done_v1(
    ve_tls_result result,
    size_t log_bytes,
    size_t compressed_bytes,
    const char * req_id,
    const char * error_message,
    const unsigned char * raw_buffer,
    void * user_param,
    int64_t start_id,
    int64_t end_id
) {
    (void)log_bytes;
    (void)compressed_bytes;
    (void)req_id;
    (void)error_message;
    (void)raw_buffer;
    (void)user_param;
    (void)start_id;
    (void)end_id;
    if (result == VE_TLS_OK) {
        g_step_ok_calls++;
    } else if (result == VE_TLS_DROP_ERROR) {
        g_step_drop_calls++;
    }
}

static ve_tls_key_queue * find_key_queue(ve_tls_producer * p, const char * key) {
    if (!p || !p->key_buckets || p->key_bucket_count == 0 || !key) return NULL;
    for (size_t i = 0; i < p->key_bucket_count; i++) {
        for (ve_tls_key_queue * q = p->key_buckets[i]; q; q = q->hnext) {
            if (q->key && strcmp(q->key, key) == 0) return q;
        }
    }
    return NULL;
}

static int test_sender_step_key_rate_limit_delays_then_sends(void) {
    g_step_http_calls = 0;
    g_step_ok_calls = 0;
    g_step_drop_calls = 0;
    memset(g_step_drop_code, 0, sizeof(g_step_drop_code));

    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    g_real_platform = cfg.platform;
    g_fake_time = 1000;
    cfg.platform.time_ms = test_fake_time_ms;
    cfg.platform.sleep_ms = test_fake_sleep_ms;
    cfg.platform.cond_timedwait_ms = test_fake_cond_timedwait_ms;
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.compress_type = "none";
    cfg.key_rate_limit_rps = 1;
    cfg.retry_policy.max_attempts = 1;
    cfg.http_client.do_request = test_http_step_ok_do;
    cfg.http_client.free_response = test_http_free;

    ve_tls_producer p;
    if (init_fake_sender_producer(&p, &cfg) != 0) return -1;
    p.send_done_v2 = on_step_done_v2;
    p.send_done_v2_param = NULL;

    unsigned char * body = (unsigned char *)ve_tls_malloc(16);
    if (!body) {
        destroy_fake_sender_producer(&p);
        return -1;
    }
    memset(body, 'A', 16);
    ve_tls_send_task t;
    memset(&t, 0, sizeof(t));
    t.body = body;
    t.body_size = 16;
    t.raw_body_size = 16;
    t.log_count = 1;
    t.hash_key = ve_tls_strdup("k1");
    t.start_id = 1;
    t.end_id = 1;
    t.batch_bytes = 16;
    if (!t.hash_key) {
        ve_tls_free(body);
        destroy_fake_sender_producer(&p);
        return -1;
    }
    if (ve_tls_key_queue_push_task(&p, "k1", &t) != 0) {
        ve_tls_send_task_free(&t);
        destroy_fake_sender_producer(&p);
        return -1;
    }
    memset(&t, 0, sizeof(t));

    ve_tls_key_queue * kq = find_key_queue(&p, "k1");
    if (!kq) {
        destroy_fake_sender_producer(&p);
        return -1;
    }
    kq->rl_last_ms = g_fake_time;
    kq->rl_req_tokens = 0.0;

    if (ve_tls_sender_step(&p) != 1) {
        destroy_fake_sender_producer(&p);
        return -1;
    }
    if (!p.delayed_head) {
        destroy_fake_sender_producer(&p);
        return -1;
    }

    p.config.key_rate_limit_rps = 0;
    g_fake_time += 2000;
    if (ve_tls_sender_step(&p) != 1) {
        destroy_fake_sender_producer(&p);
        return -1;
    }
    destroy_fake_sender_producer(&p);
    return (g_step_ok_calls >= 1) ? 0 : -1;
}

static int test_sender_step_credentials_provider_failure_drops(void) {
    g_step_drop_calls = 0;
    memset(g_step_drop_code, 0, sizeof(g_step_drop_code));

    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    g_real_platform = cfg.platform;
    g_fake_time = 2000;
    cfg.platform.time_ms = test_fake_time_ms;
    cfg.platform.sleep_ms = test_fake_sleep_ms;
    cfg.platform.cond_timedwait_ms = test_fake_cond_timedwait_ms;
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.compress_type = "none";
    cfg.credentials_provider = sender_creds_provider_always_fail;
    cfg.credentials_refresh_min_interval_ms = 0;
    cfg.retry_policy.max_attempts = 1;
    cfg.http_client.do_request = test_http_should_not_call_do;
    cfg.http_client.free_response = test_http_free;

    ve_tls_producer p;
    if (init_fake_sender_producer(&p, &cfg) != 0) return -1;
    p.send_done_v2 = on_step_done_v2;
    p.send_done_v2_param = NULL;

    unsigned char * body = (unsigned char *)ve_tls_malloc(8);
    if (!body) {
        destroy_fake_sender_producer(&p);
        return -1;
    }
    memset(body, 'B', 8);
    ve_tls_send_task t;
    memset(&t, 0, sizeof(t));
    t.body = body;
    t.body_size = 8;
    t.raw_body_size = 8;
    t.log_count = 1;
    t.hash_key = ve_tls_strdup("k1");
    t.start_id = 1;
    t.end_id = 1;
    t.batch_bytes = 8;
    if (!t.hash_key) {
        ve_tls_free(body);
        destroy_fake_sender_producer(&p);
        return -1;
    }
    if (ve_tls_key_queue_push_task(&p, "k1", &t) != 0) {
        ve_tls_send_task_free(&t);
        destroy_fake_sender_producer(&p);
        return -1;
    }
    memset(&t, 0, sizeof(t));

    if (ve_tls_sender_step(&p) != 1) {
        destroy_fake_sender_producer(&p);
        return -1;
    }
    destroy_fake_sender_producer(&p);
    if (g_step_drop_calls < 1) return -1;
    if (strcmp(g_step_drop_code, "CredentialsRefreshFailed") != 0) return -1;
    return 0;
}

static int test_sender_step_retries_transport_then_ok(void) {
    g_step_http_calls = 0;
    g_step_ok_calls = 0;
    g_step_drop_calls = 0;
    memset(g_step_drop_code, 0, sizeof(g_step_drop_code));

    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    g_real_platform = cfg.platform;
    g_fake_time = 3000;
    cfg.platform.time_ms = test_fake_time_ms;
    cfg.platform.sleep_ms = test_fake_sleep_ms;
    cfg.platform.cond_timedwait_ms = test_fake_cond_timedwait_ms;
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.compress_type = "none";
    cfg.retry_policy.max_attempts = 2;
    cfg.retry_policy.initial_interval_ms = 1;
    cfg.retry_policy.max_interval_ms = 1;
    cfg.retry_policy.total_timeout_ms = 0;
    cfg.http_client.do_request = test_http_step_retry_then_ok_do;
    cfg.http_client.free_response = test_http_free;

    ve_tls_producer p;
    if (init_fake_sender_producer(&p, &cfg) != 0) return -1;
    p.send_done = on_step_done_v1;
    p.send_done_param = NULL;
    p.send_done_v2 = on_step_done_v2;
    p.send_done_v2_param = NULL;

    unsigned char * body = (unsigned char *)ve_tls_malloc(8);
    if (!body) {
        destroy_fake_sender_producer(&p);
        return -1;
    }
    memset(body, 'C', 8);
    ve_tls_send_task t;
    memset(&t, 0, sizeof(t));
    t.body = body;
    t.body_size = 8;
    t.raw_body_size = 8;
    t.log_count = 1;
    t.hash_key = ve_tls_strdup("k1");
    t.start_id = 1;
    t.end_id = 1;
    t.batch_bytes = 8;
    if (!t.hash_key) {
        ve_tls_free(body);
        destroy_fake_sender_producer(&p);
        return -1;
    }
    if (ve_tls_key_queue_push_task(&p, "k1", &t) != 0) {
        ve_tls_send_task_free(&t);
        destroy_fake_sender_producer(&p);
        return -1;
    }
    memset(&t, 0, sizeof(t));

    if (ve_tls_sender_step(&p) != 1) {
        destroy_fake_sender_producer(&p);
        return -1;
    }
    destroy_fake_sender_producer(&p);
    if (g_step_http_calls != 2) return -1;
    if (g_step_ok_calls < 1) return -1;
    return 0;
}

static int test_http_step_always_transport_retry_do(ve_tls_http_client * client, const ve_tls_http_request * req, ve_tls_http_response * resp) {
    (void)client;
    (void)req;
    if (!resp) return -1;
    g_step_http_calls++;
    resp->transport_kind = VE_TLS_TRANSPORT_GENERIC;
    resp->transport_code = 7;
    resp->transport_retryable = 1;
    return -1;
}

static int test_sender_step_retry_total_timeout_caps_delay(void) {
    g_step_http_calls = 0;
    g_step_ok_calls = 0;
    g_step_drop_calls = 0;
    memset(g_step_drop_code, 0, sizeof(g_step_drop_code));

    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    g_real_platform = cfg.platform;
    g_fake_time = 11000;
    cfg.platform.time_ms = test_fake_time_ms;
    cfg.platform.sleep_ms = test_fake_sleep_ms;
    cfg.platform.cond_timedwait_ms = test_fake_cond_timedwait_ms;
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.compress_type = "none";
    cfg.retry_policy.max_attempts = 0;
    cfg.retry_policy.total_timeout_ms = 5;
    cfg.retry_policy.initial_interval_ms = 10;
    cfg.retry_policy.max_interval_ms = 10;
    cfg.http_client.do_request = test_http_step_always_transport_retry_do;
    cfg.http_client.free_response = test_http_free;

    ve_tls_producer p;
    if (init_fake_sender_producer(&p, &cfg) != 0) return -1;
    p.send_done = on_step_done_v1;
    p.send_done_param = NULL;
    p.send_done_v2 = on_step_done_v2;
    p.send_done_v2_param = NULL;

    unsigned char * body = (unsigned char *)ve_tls_malloc(8);
    if (!body) {
        destroy_fake_sender_producer(&p);
        return -1;
    }
    memset(body, 'I', 8);
    ve_tls_send_task t;
    memset(&t, 0, sizeof(t));
    t.body = body;
    t.body_size = 8;
    t.raw_body_size = 8;
    t.log_count = 1;
    t.hash_key = ve_tls_strdup("k1");
    t.start_id = 1;
    t.end_id = 1;
    t.batch_bytes = 8;
    if (!t.hash_key) {
        ve_tls_free(body);
        destroy_fake_sender_producer(&p);
        return -1;
    }
    if (ve_tls_key_queue_push_task(&p, "k1", &t) != 0) {
        ve_tls_send_task_free(&t);
        destroy_fake_sender_producer(&p);
        return -1;
    }
    memset(&t, 0, sizeof(t));

    if (ve_tls_sender_step(&p) != 1) {
        destroy_fake_sender_producer(&p);
        return -1;
    }
    destroy_fake_sender_producer(&p);
    if (g_step_http_calls < 1) return -1;
    if (g_step_ok_calls != 0) return -1;
    if (g_step_drop_calls < 1) return -1;
    return 0;
}

static int test_http_step_curl_nonretry_do(ve_tls_http_client * client, const ve_tls_http_request * req, ve_tls_http_response * resp) {
    (void)client;
    (void)req;
    if (!resp) return -1;
    g_step_http_calls++;
    resp->transport_kind = VE_TLS_TRANSPORT_CURL;
    resp->transport_code = 28;
    resp->transport_retryable = 0;
    resp->request_id = strdup("rid-curl");
    resp->error_message = strdup("curl failed");
    return -1;
}

static int test_http_step_status_403_plain_do(ve_tls_http_client * client, const ve_tls_http_request * req, ve_tls_http_response * resp) {
    (void)client;
    (void)req;
    if (!resp) return -1;
    g_step_http_calls++;
    resp->status_code = 403;
    resp->request_id = strdup("rid-403");
    resp->body = (unsigned char *)strdup("plain");
    resp->body_size = strlen((const char *)resp->body);
    return 0;
}

static int test_sender_step_compress_unsupported_drops(void) {
    g_step_http_calls = 0;
    g_step_ok_calls = 0;
    g_step_drop_calls = 0;
    memset(g_step_drop_code, 0, sizeof(g_step_drop_code));

    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    g_real_platform = cfg.platform;
    g_fake_time = 4000;
    cfg.platform.time_ms = test_fake_time_ms;
    cfg.platform.sleep_ms = test_fake_sleep_ms;
    cfg.platform.cond_timedwait_ms = test_fake_cond_timedwait_ms;
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.compress_type = "bad";
    cfg.retry_policy.max_attempts = 1;
    cfg.http_client.do_request = test_http_step_ok_do;
    cfg.http_client.free_response = test_http_free;

    ve_tls_producer p;
    if (init_fake_sender_producer(&p, &cfg) != 0) return -1;
    p.send_done_v2 = on_step_done_v2;

    unsigned char * body = (unsigned char *)ve_tls_malloc(8);
    if (!body) {
        destroy_fake_sender_producer(&p);
        return -1;
    }
    memset(body, 'D', 8);
    ve_tls_send_task t;
    memset(&t, 0, sizeof(t));
    t.body = body;
    t.body_size = 8;
    t.raw_body_size = 8;
    t.log_count = 1;
    t.hash_key = ve_tls_strdup("k1");
    t.start_id = 1;
    t.end_id = 1;
    t.batch_bytes = 8;
    if (!t.hash_key) {
        ve_tls_free(body);
        destroy_fake_sender_producer(&p);
        return -1;
    }
    if (ve_tls_key_queue_push_task(&p, "k1", &t) != 0) {
        ve_tls_send_task_free(&t);
        destroy_fake_sender_producer(&p);
        return -1;
    }
    memset(&t, 0, sizeof(t));

    if (ve_tls_sender_step(&p) != 1) {
        destroy_fake_sender_producer(&p);
        return -1;
    }
    destroy_fake_sender_producer(&p);
    if (g_step_drop_calls != 0) return -1;
    if (g_step_ok_calls < 1) return -1;
    return g_step_http_calls == 1 ? 0 : -1;
}

static int test_sender_step_breaker_half_open_curl_nonretry_drops(void) {
    g_step_http_calls = 0;
    g_step_ok_calls = 0;
    g_step_drop_calls = 0;
    memset(g_step_drop_code, 0, sizeof(g_step_drop_code));

    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    g_real_platform = cfg.platform;
    g_fake_time = 5000;
    cfg.platform.time_ms = test_fake_time_ms;
    cfg.platform.sleep_ms = test_fake_sleep_ms;
    cfg.platform.cond_timedwait_ms = test_fake_cond_timedwait_ms;
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.compress_type = "none";
    cfg.breaker_fail_threshold = 1;
    cfg.breaker_open_ms = 10;
    cfg.breaker_half_open_max_inflight = 1;
    cfg.retry_policy.max_attempts = 2;
    cfg.http_client.do_request = test_http_step_curl_nonretry_do;
    cfg.http_client.free_response = test_http_free;

    ve_tls_producer p;
    if (init_fake_sender_producer(&p, &cfg) != 0) return -1;
    p.send_done_v2 = on_step_done_v2;

    unsigned char * body = (unsigned char *)ve_tls_malloc(8);
    if (!body) {
        destroy_fake_sender_producer(&p);
        return -1;
    }
    memset(body, 'E', 8);
    ve_tls_send_task t;
    memset(&t, 0, sizeof(t));
    t.body = body;
    t.body_size = 8;
    t.raw_body_size = 8;
    t.log_count = 1;
    t.hash_key = ve_tls_strdup("k1");
    t.start_id = 1;
    t.end_id = 1;
    t.batch_bytes = 8;
    if (!t.hash_key) {
        ve_tls_free(body);
        destroy_fake_sender_producer(&p);
        return -1;
    }
    if (ve_tls_key_queue_push_task(&p, "k1", &t) != 0) {
        ve_tls_send_task_free(&t);
        destroy_fake_sender_producer(&p);
        return -1;
    }
    memset(&t, 0, sizeof(t));

    if (ve_tls_sender_step(&p) != 1) {
        destroy_fake_sender_producer(&p);
        return -1;
    }
    destroy_fake_sender_producer(&p);
    if (g_step_http_calls != 1) return -1;
    if (g_step_drop_calls < 1) return -1;
    if (strcmp(g_step_drop_code, "ClientError") != 0) return -1;
    return 0;
}

static int test_sender_step_http_non200_plain_message(void) {
    g_step_http_calls = 0;
    g_step_ok_calls = 0;
    g_step_drop_calls = 0;
    memset(g_step_drop_code, 0, sizeof(g_step_drop_code));

    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    g_real_platform = cfg.platform;
    g_fake_time = 6000;
    cfg.platform.time_ms = test_fake_time_ms;
    cfg.platform.sleep_ms = test_fake_sleep_ms;
    cfg.platform.cond_timedwait_ms = test_fake_cond_timedwait_ms;
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.compress_type = "none";
    cfg.retry_policy.max_attempts = 1;
    cfg.http_client.do_request = test_http_step_status_403_plain_do;
    cfg.http_client.free_response = test_http_free;

    ve_tls_producer p;
    if (init_fake_sender_producer(&p, &cfg) != 0) return -1;
    p.send_done_v2 = on_step_done_v2;

    unsigned char * body = (unsigned char *)ve_tls_malloc(8);
    if (!body) {
        destroy_fake_sender_producer(&p);
        return -1;
    }
    memset(body, 'F', 8);
    ve_tls_send_task t;
    memset(&t, 0, sizeof(t));
    t.body = body;
    t.body_size = 8;
    t.raw_body_size = 8;
    t.log_count = 1;
    t.hash_key = ve_tls_strdup("k1");
    t.start_id = 1;
    t.end_id = 1;
    t.batch_bytes = 8;
    if (!t.hash_key) {
        ve_tls_free(body);
        destroy_fake_sender_producer(&p);
        return -1;
    }
    if (ve_tls_key_queue_push_task(&p, "k1", &t) != 0) {
        ve_tls_send_task_free(&t);
        destroy_fake_sender_producer(&p);
        return -1;
    }
    memset(&t, 0, sizeof(t));

    if (ve_tls_sender_step(&p) != 1) {
        destroy_fake_sender_producer(&p);
        return -1;
    }
    destroy_fake_sender_producer(&p);
    if (g_step_http_calls != 1) return -1;
    if (g_step_drop_calls < 1) return -1;
    if (strcmp(g_step_drop_code, "BadResponse") != 0) return -1;
    return 0;
}

static int test_sender_step_global_breaker_wait_open_then_ok(void) {
    g_step_http_calls = 0;
    g_step_ok_calls = 0;
    g_step_drop_calls = 0;
    memset(g_step_drop_code, 0, sizeof(g_step_drop_code));

    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    g_real_platform = cfg.platform;
    g_fake_time = 7000;
    cfg.platform.time_ms = test_fake_time_ms;
    cfg.platform.sleep_ms = test_fake_sleep_ms;
    cfg.platform.cond_timedwait_ms = test_fake_cond_timedwait_ms;
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.compress_type = "none";
    cfg.breaker_fail_threshold = 1;
    cfg.breaker_open_ms = 10;
    cfg.breaker_half_open_max_inflight = 1;
    cfg.retry_policy.max_attempts = 1;
    cfg.http_client.do_request = test_http_step_ok_do;
    cfg.http_client.free_response = test_http_free;

    ve_tls_producer p;
    if (init_fake_sender_producer(&p, &cfg) != 0) return -1;
    p.send_done_v2 = on_step_done_v2;
    p.breaker_open_until_ms = g_fake_time + 10;

    unsigned char * body = (unsigned char *)ve_tls_malloc(8);
    if (!body) {
        destroy_fake_sender_producer(&p);
        return -1;
    }
    memset(body, 'G', 8);
    ve_tls_send_task t;
    memset(&t, 0, sizeof(t));
    t.body = body;
    t.body_size = 8;
    t.raw_body_size = 8;
    t.log_count = 1;
    t.hash_key = ve_tls_strdup("k1");
    t.start_id = 1;
    t.end_id = 1;
    t.batch_bytes = 8;
    if (!t.hash_key) {
        ve_tls_free(body);
        destroy_fake_sender_producer(&p);
        return -1;
    }
    if (ve_tls_key_queue_push_task(&p, "k1", &t) != 0) {
        ve_tls_send_task_free(&t);
        destroy_fake_sender_producer(&p);
        return -1;
    }
    memset(&t, 0, sizeof(t));

    if (ve_tls_sender_step(&p) != 1) {
        destroy_fake_sender_producer(&p);
        return -1;
    }
    int64_t now_after = g_fake_time;
    destroy_fake_sender_producer(&p);
    if (now_after < 7010) return -1;
    if (g_step_ok_calls < 1) return -1;
    return 0;
}

static int test_sender_step_precompressed_sends_ok(void) {
    g_step_http_calls = 0;
    g_step_ok_calls = 0;
    g_step_drop_calls = 0;
    memset(g_step_drop_code, 0, sizeof(g_step_drop_code));

    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    g_real_platform = cfg.platform;
    g_fake_time = 8000;
    cfg.platform.time_ms = test_fake_time_ms;
    cfg.platform.sleep_ms = test_fake_sleep_ms;
    cfg.platform.cond_timedwait_ms = test_fake_cond_timedwait_ms;
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.compress_type = "gzip";
    cfg.retry_policy.max_attempts = 1;
    cfg.http_client.do_request = test_http_step_ok_do;
    cfg.http_client.free_response = test_http_free;

    ve_tls_producer p;
    if (init_fake_sender_producer(&p, &cfg) != 0) return -1;
    p.send_done_v2 = on_step_done_v2;

    unsigned char * pre = (unsigned char *)ve_tls_malloc(4);
    if (!pre) {
        destroy_fake_sender_producer(&p);
        return -1;
    }
    memcpy(pre, "PBUF", 4);
    ve_tls_send_task t;
    memset(&t, 0, sizeof(t));
    t.precompressed = pre;
    t.precompressed_size = 4;
    t.body = (unsigned char *)ve_tls_malloc(1);
    if (t.body) t.body[0] = 0;
    t.body_size = 1;
    t.raw_body_size = 1;
    t.log_count = 1;
    t.hash_key = ve_tls_strdup("k1");
    t.start_id = 1;
    t.end_id = 1;
    t.batch_bytes = 1;
    if (!t.hash_key || !t.body) {
        ve_tls_send_task_free(&t);
        destroy_fake_sender_producer(&p);
        return -1;
    }
    if (ve_tls_key_queue_push_task(&p, "k1", &t) != 0) {
        ve_tls_send_task_free(&t);
        destroy_fake_sender_producer(&p);
        return -1;
    }
    memset(&t, 0, sizeof(t));

    if (ve_tls_sender_step(&p) != 1) {
        destroy_fake_sender_producer(&p);
        return -1;
    }
    destroy_fake_sender_producer(&p);
    if (g_step_ok_calls < 1) return -1;
    if (g_step_http_calls < 1) return -1;
    return 0;
}

static int test_sender_main_stop_empty_returns(void) {
    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    g_real_platform = cfg.platform;
    g_fake_time = 9000;
    cfg.platform.time_ms = test_fake_time_ms;
    cfg.platform.sleep_ms = test_fake_sleep_ms;
    cfg.platform.cond_timedwait_ms = test_fake_cond_timedwait_ms;
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.compress_type = "none";
    cfg.retry_policy.max_attempts = 1;
    cfg.http_client.do_request = test_http_step_ok_do;
    cfg.http_client.free_response = test_http_free;

    ve_tls_producer p;
    if (init_fake_sender_producer(&p, &cfg) != 0) return -1;
    p.stop = 1;
    void * ret = ve_tls_sender_main(&p);
    destroy_fake_sender_producer(&p);
    return ret == NULL ? 0 : -1;
}

static int test_sender_main_stop_drains_send_queue_and_sends(void) {
    g_step_http_calls = 0;
    g_step_ok_calls = 0;
    g_step_drop_calls = 0;
    memset(g_step_drop_code, 0, sizeof(g_step_drop_code));

    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    g_real_platform = cfg.platform;
    g_fake_time = 10000;
    cfg.platform.time_ms = test_fake_time_ms;
    cfg.platform.sleep_ms = test_fake_sleep_ms;
    cfg.platform.cond_timedwait_ms = test_fake_cond_timedwait_ms;
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.compress_type = "none";
    cfg.retry_policy.max_attempts = 1;
    cfg.http_client.do_request = test_http_step_ok_do;
    cfg.http_client.free_response = test_http_free;

    ve_tls_producer p;
    if (init_fake_sender_producer(&p, &cfg) != 0) return -1;
    p.send_done_v2 = on_step_done_v2;
    p.stop = 1;

    unsigned char * body = (unsigned char *)ve_tls_malloc(8);
    if (!body) {
        destroy_fake_sender_producer(&p);
        return -1;
    }
    memset(body, 'H', 8);
    ve_tls_send_task t;
    memset(&t, 0, sizeof(t));
    t.body = body;
    t.body_size = 8;
    t.raw_body_size = 8;
    t.log_count = 1;
    t.hash_key = ve_tls_strdup("k1");
    t.start_id = 1;
    t.end_id = 1;
    t.batch_bytes = 8;
    if (!t.hash_key) {
        ve_tls_send_task_free(&t);
        destroy_fake_sender_producer(&p);
        return -1;
    }
    if (ve_tls_send_queue_push(&p.send_queue, &t, 0) != 0) {
        ve_tls_send_task_free(&t);
        destroy_fake_sender_producer(&p);
        return -1;
    }
    memset(&t, 0, sizeof(t));

    void * ret = ve_tls_sender_main(&p);
    destroy_fake_sender_producer(&p);
    if (ret != NULL) return -1;
    if (g_step_ok_calls < 1) return -1;
    if (g_step_http_calls < 1) return -1;
    return 0;
}

static int test_queue_push_front_pop_order(void) {
    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    cfg.key_queue_idle_ttl_ms = 0;
    ve_tls_producer p;
    if (init_fake_sender_producer(&p, &cfg) != 0) return -1;

    ve_tls_send_task t1;
    ve_tls_send_task t2;
    ve_tls_send_task t0;
    memset(&t1, 0, sizeof(t1));
    memset(&t2, 0, sizeof(t2));
    memset(&t0, 0, sizeof(t0));
    t1.hash_key = ve_tls_strdup("k1");
    t2.hash_key = ve_tls_strdup("k1");
    t0.hash_key = ve_tls_strdup("k1");
    if (!t1.hash_key || !t2.hash_key || !t0.hash_key) {
        ve_tls_send_task_free(&t1);
        ve_tls_send_task_free(&t2);
        ve_tls_send_task_free(&t0);
        destroy_fake_sender_producer(&p);
        return -1;
    }
    t1.start_id = 1;
    t2.start_id = 2;
    t0.start_id = 0;

    if (ve_tls_key_queue_push_task(&p, "k1", &t1) != 0 ||
        ve_tls_key_queue_push_task(&p, "k1", &t2) != 0) {
        ve_tls_send_task_free(&t1);
        ve_tls_send_task_free(&t2);
        ve_tls_send_task_free(&t0);
        destroy_fake_sender_producer(&p);
        return -1;
    }
    memset(&t1, 0, sizeof(t1));
    memset(&t2, 0, sizeof(t2));
    ve_tls_key_queue * q = find_key_queue(&p, "k1");
    if (!q) {
        ve_tls_send_task_free(&t0);
        destroy_fake_sender_producer(&p);
        return -1;
    }
    if (ve_tls_key_queue_push_front_task(q, &t0) != 0) {
        ve_tls_send_task_free(&t0);
        destroy_fake_sender_producer(&p);
        return -1;
    }
    memset(&t0, 0, sizeof(t0));

    ve_tls_send_task out;
    memset(&out, 0, sizeof(out));
    if (ve_tls_key_queue_pop_task(q, &out) != 0) {
        destroy_fake_sender_producer(&p);
        return -1;
    }
    int64_t id0 = out.start_id;
    ve_tls_send_task_free(&out);

    memset(&out, 0, sizeof(out));
    if (ve_tls_key_queue_pop_task(q, &out) != 0) {
        destroy_fake_sender_producer(&p);
        return -1;
    }
    int64_t id1 = out.start_id;
    ve_tls_send_task_free(&out);

    memset(&out, 0, sizeof(out));
    if (ve_tls_key_queue_pop_task(q, &out) != 0) {
        destroy_fake_sender_producer(&p);
        return -1;
    }
    int64_t id2 = out.start_id;
    ve_tls_send_task_free(&out);

    destroy_fake_sender_producer(&p);
    return (id0 == 0 && id1 == 1 && id2 == 2) ? 0 : -1;
}

static int test_queue_idle_cleanup_removes_expired(void) {
    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    g_real_platform = cfg.platform;
    g_fake_time = 1000;
    cfg.platform.time_ms = test_fake_time_ms;
    cfg.key_queue_idle_ttl_ms = 10;
    ve_tls_producer p;
    if (init_fake_sender_producer(&p, &cfg) != 0) return -1;

    ve_tls_send_task t;
    memset(&t, 0, sizeof(t));
    t.hash_key = ve_tls_strdup("k1");
    if (!t.hash_key) {
        destroy_fake_sender_producer(&p);
        return -1;
    }
    if (ve_tls_key_queue_push_task(&p, "k1", &t) != 0) {
        ve_tls_send_task_free(&t);
        destroy_fake_sender_producer(&p);
        return -1;
    }
    memset(&t, 0, sizeof(t));
    ve_tls_key_queue * q = find_key_queue(&p, "k1");
    if (!q) {
        destroy_fake_sender_producer(&p);
        return -1;
    }
    ve_tls_send_task out;
    memset(&out, 0, sizeof(out));
    if (ve_tls_key_queue_pop_task(q, &out) != 0) {
        destroy_fake_sender_producer(&p);
        return -1;
    }
    ve_tls_send_task_free(&out);

    ve_tls_key_queue_finish(&p, q);
    if (!p.idle_head) {
        destroy_fake_sender_producer(&p);
        return -1;
    }
    g_fake_time += 20;
    ve_tls_idle_cleanup(&p);
    ve_tls_key_queue * q2 = find_key_queue(&p, "k1");
    destroy_fake_sender_producer(&p);
    return q2 == NULL ? 0 : -1;
}

static int test_queue_delayed_promote_due_moves_to_ready(void) {
    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    g_real_platform = cfg.platform;
    g_fake_time = 1000;
    cfg.platform.time_ms = test_fake_time_ms;
    cfg.key_queue_idle_ttl_ms = 0;
    ve_tls_producer p;
    if (init_fake_sender_producer(&p, &cfg) != 0) return -1;

    ve_tls_send_task t;
    memset(&t, 0, sizeof(t));
    t.hash_key = ve_tls_strdup("k1");
    if (!t.hash_key) {
        destroy_fake_sender_producer(&p);
        return -1;
    }
    if (ve_tls_key_queue_push_task(&p, "k1", &t) != 0) {
        ve_tls_send_task_free(&t);
        destroy_fake_sender_producer(&p);
        return -1;
    }
    memset(&t, 0, sizeof(t));
    ve_tls_key_queue * q = find_key_queue(&p, "k1");
    if (!q) {
        destroy_fake_sender_producer(&p);
        return -1;
    }
    q->inflight = 0;
    ve_tls_delayed_add_sorted(&p, q, g_fake_time + 10);
    if (!p.delayed_head) {
        destroy_fake_sender_producer(&p);
        return -1;
    }
    ve_tls_delayed_promote_due(&p, g_fake_time + 20);
    int ok = (p.ready_head != NULL);
    destroy_fake_sender_producer(&p);
    return ok ? 0 : -1;
}

static int test_ingress_queue_push_pop_order_and_drain_state(void) {
    ve_tls_config cfg;
    ve_tls_config_init(&cfg);

    ve_tls_producer p;
    memset(&p, 0, sizeof(p));
    p.config = cfg;
    p.accepting = 1;
    p.mutex = p.config.platform.mutex_create();
    p.cond = p.config.platform.cond_create();
    if (!p.mutex || !p.cond) {
        if (p.cond) p.config.platform.cond_destroy(p.cond);
        if (p.mutex) p.config.platform.mutex_destroy(p.mutex);
        return -1;
    }

    if (ve_tls_ingress_queue_init(&p, 2) != 0) {
        p.config.platform.cond_destroy(p.cond);
        p.config.platform.mutex_destroy(p.mutex);
        return -1;
    }

    ve_tls_log_group_builder * b1 = ve_tls_log_builder_create("");
    ve_tls_log_group_builder * b2 = ve_tls_log_builder_create("");
    ve_tls_log_group_builder * b3 = ve_tls_log_builder_create("");
    if (!b1 || !b2 || !b3) {
        ve_tls_log_builder_free(b1);
        ve_tls_log_builder_free(b2);
        ve_tls_log_builder_free(b3);
        ve_tls_ingress_queue_destroy(&p);
        p.config.platform.cond_destroy(p.cond);
        p.config.platform.mutex_destroy(p.mutex);
        return -1;
    }
    b1->log_count = 1;
    b2->log_count = 2;
    b3->log_count = 3;

    p.config.platform.mutex_lock(p.mutex);
    int rc1 = ve_tls_ingress_queue_push_locked(&p, "", b1, 0, 0);
    int rc2 = ve_tls_ingress_queue_push_locked(&p, "", b2, 1, 0);
    int rc3 = ve_tls_ingress_queue_push_locked(&p, "", b3, 0, 0);
    int drained_when_nonempty = ve_tls_producer_is_drained_locked(&p);
    p.config.platform.mutex_unlock(p.mutex);
    if (rc1 != 0 || rc2 != 0 || rc3 != -1 || drained_when_nonempty != 0) {
        ve_tls_log_builder_free(b3);
        ve_tls_ingress_queue_destroy(&p);
        p.config.platform.cond_destroy(p.cond);
        p.config.platform.mutex_destroy(p.mutex);
        return -1;
    }
    ve_tls_log_builder_free(b3);

    ve_tls_ingress_task t;
    memset(&t, 0, sizeof(t));
    p.config.platform.mutex_lock(p.mutex);
    int pop1 = ve_tls_ingress_queue_pop_locked(&p, &t);
    p.config.platform.mutex_unlock(p.mutex);
    if (pop1 != 0 || t.batch != b1 || t.force_flush != 0) {
        ve_tls_ingress_queue_destroy(&p);
        p.config.platform.cond_destroy(p.cond);
        p.config.platform.mutex_destroy(p.mutex);
        return -1;
    }
    ve_tls_log_builder_free(t.batch);

    memset(&t, 0, sizeof(t));
    p.config.platform.mutex_lock(p.mutex);
    int pop2 = ve_tls_ingress_queue_pop_locked(&p, &t);
    int drained_after_pop = ve_tls_producer_is_drained_locked(&p);
    p.config.platform.mutex_unlock(p.mutex);
    if (pop2 != 0 || t.batch != b2 || t.force_flush != 1 || drained_after_pop != 1) {
        ve_tls_ingress_queue_destroy(&p);
        p.config.platform.cond_destroy(p.cond);
        p.config.platform.mutex_destroy(p.mutex);
        return -1;
    }
    ve_tls_log_builder_free(t.batch);

    ve_tls_ingress_queue_destroy(&p);
    p.config.platform.cond_destroy(p.cond);
    p.config.platform.mutex_destroy(p.mutex);
    return 0;
}

static int g_worker_drop_full = 0;
static int g_worker_drop_timeout = 0;
static int g_worker_pack_drop = 0;
static char g_worker_pack_drop_msg[96];

static void on_worker_done_v2(
    ve_tls_result result,
    size_t log_bytes,
    size_t compressed_bytes,
    const ve_tls_error * error,
    const unsigned char * raw_buffer,
    void * user_param,
    int64_t start_id,
    int64_t end_id
) {
    (void)log_bytes;
    (void)compressed_bytes;
    (void)raw_buffer;
    (void)user_param;
    (void)start_id;
    (void)end_id;
    if (result != VE_TLS_DROP_ERROR || !error || !error->error_code) return;
    if (strcmp(error->error_code, "SendQueueFull") == 0) g_worker_drop_full++;
    if (strcmp(error->error_code, "SendQueueTimeout") == 0) g_worker_drop_timeout++;
}

static void on_worker_pack_done_v2(
    ve_tls_result result,
    size_t log_bytes,
    size_t compressed_bytes,
    const ve_tls_error * error,
    const unsigned char * raw_buffer,
    void * user_param,
    int64_t start_id,
    int64_t end_id
) {
    (void)log_bytes;
    (void)compressed_bytes;
    (void)raw_buffer;
    (void)user_param;
    (void)start_id;
    (void)end_id;
    if (result != VE_TLS_DROP_ERROR || !error || !error->error_message) return;
    g_worker_pack_drop++;
    snprintf(g_worker_pack_drop_msg, sizeof(g_worker_pack_drop_msg), "%s", error->error_message);
}

static int test_worker_send_queue_full_drop_sampled_paths(void) {
    g_worker_drop_full = 0;
    g_worker_drop_timeout = 0;

    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    g_real_platform = cfg.platform;
    g_fake_time = 1000;
    cfg.platform.time_ms = test_fake_time_ms;
    cfg.platform.sleep_ms = test_fake_sleep_ms;
    cfg.platform.cond_timedwait_ms = test_fake_cond_timedwait_ms;
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.compress_type = "none";
    cfg.agg_strategy = 0;
    cfg.log_count_per_package = 1;
    cfg.flush_interval_ms = 0;
    cfg.send_queue_size = 1;
    cfg.send_queue_full_policy = VE_TLS_SEND_QUEUE_FULL_DROP_SAMPLED;
    cfg.send_queue_sample_every_n = 2;
    cfg.send_queue_block_timeout_ms = 5;
    cfg.key_queue_idle_ttl_ms = 100000;

    ve_tls_producer p;
    if (init_fake_sender_producer(&p, &cfg) != 0) return -1;
    p.send_done_v2 = on_worker_done_v2;

    ve_tls_kv kvs[1];
    kvs[0].key = "k";
    kvs[0].value = "v";
    for (int64_t id = 1; id <= 3; id++) {
        ve_tls_bytes log;
        memset(&log, 0, sizeof(log));
        if (ve_tls_proto_encode_log_ex(1710000000000LL + id, 0, 0, kvs, 1, &log) != 0) {
            destroy_fake_sender_producer(&p);
            return -1;
        }
        int rc = ve_tls_queue_push(&p, log.data, log.size, id, 1710000000000LL + id, 0, 0, "hk");
        ve_tls_bytes_free(&log);
        if (rc != 0) {
            destroy_fake_sender_producer(&p);
            return -1;
        }
    }

    p.stop = 1;
    p.flush_requested = 1;
    void * ret = ve_tls_worker_main(&p);
    destroy_fake_sender_producer(&p);
    if (ret != NULL) return -1;
    if (g_worker_drop_timeout < 1) return -1;
    if (g_worker_drop_full < 1) return -1;
    return 0;
}

static int test_worker_send_queue_block_timeout_path(void) {
    g_worker_drop_full = 0;
    g_worker_drop_timeout = 0;

    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    g_real_platform = cfg.platform;
    g_fake_time = 2000;
    cfg.platform.time_ms = test_fake_time_ms;
    cfg.platform.sleep_ms = test_fake_sleep_ms;
    cfg.platform.cond_timedwait_ms = test_fake_cond_timedwait_ms;
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.compress_type = "none";
    cfg.agg_strategy = 0;
    cfg.log_count_per_package = 1;
    cfg.flush_interval_ms = 0;
    cfg.send_queue_size = 1;
    cfg.send_queue_full_policy = VE_TLS_SEND_QUEUE_FULL_BLOCK;
    cfg.send_queue_block_timeout_ms = 5;
    cfg.key_queue_idle_ttl_ms = 100000;

    ve_tls_producer p;
    if (init_fake_sender_producer(&p, &cfg) != 0) return -1;
    p.send_done_v2 = on_worker_done_v2;

    ve_tls_kv kvs[1];
    kvs[0].key = "k";
    kvs[0].value = "v";
    for (int64_t id = 1; id <= 2; id++) {
        ve_tls_bytes log;
        memset(&log, 0, sizeof(log));
        if (ve_tls_proto_encode_log_ex(1710000000000LL + id, 0, 0, kvs, 1, &log) != 0) {
            destroy_fake_sender_producer(&p);
            return -1;
        }
        int rc = ve_tls_queue_push(&p, log.data, log.size, id, 1710000000000LL + id, 0, 0, "hk");
        ve_tls_bytes_free(&log);
        if (rc != 0) {
            destroy_fake_sender_producer(&p);
            return -1;
        }
    }

    p.stop = 1;
    p.flush_requested = 1;
    void * ret = ve_tls_worker_main(&p);
    destroy_fake_sender_producer(&p);
    if (ret != NULL) return -1;
    if (g_worker_drop_timeout < 1) return -1;
    return 0;
}

static int test_send_queue_bytes_count_against_max_buffer_budget(void) {
    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.flush_interval_ms = 0;
    cfg.ordered_send = 1;
    cfg.max_buffer_bytes = 64;
    cfg.buffer_full_policy = VE_TLS_BUFFER_FULL_DROP;
    cfg.send_queue_size = 4;

    ve_tls_producer p;
    if (init_fake_sender_producer(&p, &cfg) != 0) return -1;

    ve_tls_send_task task;
    memset(&task, 0, sizeof(task));
    task.body = (unsigned char *)ve_tls_malloc(40);
    if (!task.body) {
        destroy_fake_sender_producer(&p);
        return -1;
    }
    memset(task.body, 'x', 40);
    task.body_size = 40;
    task.raw_body_size = 40;
    task.batch_bytes = 40;
    task.start_id = 1;
    task.end_id = 1;
    if (ve_tls_send_queue_push(&p.send_queue, &task, 0) != 0) {
        ve_tls_send_task_free(&task);
        destroy_fake_sender_producer(&p);
        return -1;
    }
    p.send_queue_bytes = ve_tls_send_task_memory_bytes(&task);

    ve_tls_send_task extra;
    memset(&extra, 0, sizeof(extra));
    extra.body = (unsigned char *)ve_tls_malloc(32);
    if (!extra.body) {
        destroy_fake_sender_producer(&p);
        return -1;
    }
    memset(extra.body, 'y', 32);
    extra.body_size = 32;
    extra.raw_body_size = 32;
    extra.batch_bytes = 32;
    extra.start_id = 2;
    extra.end_id = 2;
    int rc = ve_tls_producer_reserve_send_task_bytes(&p, &extra);
    ve_tls_send_task_free(&extra);

    destroy_fake_sender_producer(&p);
    return rc != 0 ? 0 : -1;
}

static int test_ingress_budget_blocks_before_send_budget_is_exhausted(void) {
    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.flush_interval_ms = 0;
    cfg.ordered_send = 1;
    cfg.max_buffer_bytes = 128;
    cfg.buffer_full_policy = VE_TLS_BUFFER_FULL_DROP;
    cfg.send_queue_size = 4;

    ve_tls_producer p;
    if (init_fake_sender_producer(&p, &cfg) != 0) return -1;
    p.send_reserved_bytes = 64;
    p.queue_bytes = 65;

    ve_tls_kv kvs[1];
    kvs[0].key = "k";
    kvs[0].value = "v";
    ve_tls_result rc = ve_tls_producer_add_log_kv(&p, 1710000000000LL, kvs, 1, 0);
    if (rc != VE_TLS_DROP_ERROR) {
        destroy_fake_sender_producer(&p);
        return -1;
    }

    ve_tls_send_task task;
    memset(&task, 0, sizeof(task));
    task.body = (unsigned char *)ve_tls_malloc(32);
    if (!task.body) {
        destroy_fake_sender_producer(&p);
        return -1;
    }
    memset(task.body, 'x', 32);
    task.body_size = 32;
    task.raw_body_size = 32;
    task.batch_bytes = 32;
    task.start_id = 1;
    task.end_id = 1;
    int reserve_rc = ve_tls_producer_reserve_send_task_bytes(&p, &task);
    ve_tls_send_task_free(&task);
    destroy_fake_sender_producer(&p);
    return reserve_rc == 0 ? 0 : -1;
}

static int test_raw_add_log_budget_full_drops_before_copy_alloc(void) {
    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.flush_interval_ms = 0;
    cfg.ordered_send = 1;
    cfg.max_buffer_bytes = 8;
    cfg.buffer_full_policy = VE_TLS_BUFFER_FULL_DROP;
    cfg.send_queue_size = 4;

    ve_tls_producer p;
    if (init_fake_sender_producer(&p, &cfg) != 0) return -1;
    p.queue_bytes = 8;

    ve_tls_alloc_hooks saved;
    memset(&saved, 0, sizeof(saved));
    ve_tls_alloc_get_hooks(&saved);
    alloc_fail_state st;
    memset(&st, 0, sizeof(st));
    set_alloc_fail_after(&st, 1000);

    ve_tls_result rc = ve_tls_producer_add_log_raw(&p, "0123456789", 10, 0);

    ve_tls_alloc_set_hooks(&saved);
    int ok = (rc == VE_TLS_DROP_ERROR && st.calls == 0 && p.queue_bytes == 8);
    destroy_fake_sender_producer(&p);
    return ok ? 0 : -1;
}

static int test_kv_add_log_budget_full_drops_before_builder_grow(void) {
    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.flush_interval_ms = 0;
    cfg.ordered_send = 1;
    cfg.max_buffer_bytes = 128;
    cfg.buffer_full_policy = VE_TLS_BUFFER_FULL_DROP;
    cfg.send_queue_size = 4;

    ve_tls_producer p;
    if (init_fake_sender_producer(&p, &cfg) != 0) return -1;
    p.send_reserved_bytes = 64;
    p.queue_bytes = 60;

    ve_tls_kv kvs[1];
    kvs[0].key = "k";
    kvs[0].value = "value-that-needs-more-than-four-bytes";
    ve_tls_result rc = ve_tls_producer_add_log_kv(&p, 1710000000000LL, kvs, 1, 0);
    int ok = (rc == VE_TLS_DROP_ERROR && p.queue_bytes == 60 && p.key_queue_count == 0);
    destroy_fake_sender_producer(&p);
    return ok ? 0 : -1;
}

static int test_breaker_ingress_fail_fast_rejects_before_queue(void) {
    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.flush_interval_ms = 0;
    cfg.ordered_send = 1;
    cfg.breaker_fail_threshold = 1;
    cfg.breaker_ingress_policy = VE_TLS_BREAKER_INGRESS_FAIL_FAST;

    ve_tls_producer p;
    if (init_fake_sender_producer(&p, &cfg) != 0) return -1;
    p.breaker_open_until_ms = (cfg.platform.time_ms ? cfg.platform.time_ms() : 0) + 30000;

    ve_tls_result rc = ve_tls_producer_add_log_raw(&p, "abc", 3, 0);
    int ok = (rc == VE_TLS_DROP_ERROR && p.queue_count == 0 && p.queue_bytes == 0);
    destroy_fake_sender_producer(&p);
    return ok ? 0 : -1;
}

static int g_breaker_ingress_drop_cb = 0;
static char g_breaker_ingress_drop_code[64];

static void on_breaker_ingress_drop_v2(
    ve_tls_result result,
    size_t log_bytes,
    size_t compressed_bytes,
    const ve_tls_error * error,
    const unsigned char * raw_buffer,
    void * user_param,
    int64_t start_id,
    int64_t end_id) {
    (void)compressed_bytes;
    (void)raw_buffer;
    (void)user_param;
    if (result == VE_TLS_DROP_ERROR && log_bytes > 0 && start_id == end_id) {
        g_breaker_ingress_drop_cb++;
        if (error && error->error_code) {
            snprintf(g_breaker_ingress_drop_code, sizeof(g_breaker_ingress_drop_code), "%s", error->error_code);
        }
    }
}

static int test_breaker_ingress_drop_with_callback_reports_drop_without_queue(void) {
    g_breaker_ingress_drop_cb = 0;
    memset(g_breaker_ingress_drop_code, 0, sizeof(g_breaker_ingress_drop_code));

    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.flush_interval_ms = 0;
    cfg.ordered_send = 1;
    cfg.breaker_fail_threshold = 1;
    cfg.breaker_ingress_policy = VE_TLS_BREAKER_INGRESS_DROP_WITH_CALLBACK;

    ve_tls_producer p;
    if (init_fake_sender_producer(&p, &cfg) != 0) return -1;
    p.send_done_v2 = on_breaker_ingress_drop_v2;
    p.breaker_open_until_ms = (cfg.platform.time_ms ? cfg.platform.time_ms() : 0) + 30000;

    ve_tls_kv kvs[1];
    kvs[0].key = "k";
    kvs[0].value = "v";
    ve_tls_result rc = ve_tls_producer_add_log_kv(&p, 1710000000000LL, kvs, 1, 0);
    int ok = (rc == VE_TLS_DROP_ERROR &&
              p.queue_count == 0 &&
              p.queue_bytes == 0 &&
              g_breaker_ingress_drop_cb == 1 &&
              strcmp(g_breaker_ingress_drop_code, "CircuitOpen") == 0);
    destroy_fake_sender_producer(&p);
    return ok ? 0 : -1;
}

static int test_scratch_budget_is_counted_against_max_buffer_bytes(void) {
    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.max_buffer_bytes = 64;
    cfg.buffer_full_policy = VE_TLS_BUFFER_FULL_DROP;

    ve_tls_producer p;
    if (init_fake_sender_producer(&p, &cfg) != 0) return -1;
    p.queue_bytes = 60;

    int fail_rc = ve_tls_producer_reserve_scratch_bytes(&p, 8);
    if (fail_rc == 0 || p.scratch_bytes != 0) {
        destroy_fake_sender_producer(&p);
        return -1;
    }
    int huge_rc = ve_tls_producer_reserve_scratch_bytes(&p, (size_t)-1);
    if (huge_rc == 0 || p.scratch_bytes != 0) {
        p.scratch_bytes = 0;
        destroy_fake_sender_producer(&p);
        return -1;
    }
    int ok_rc = ve_tls_producer_reserve_scratch_bytes(&p, 4);
    size_t buffered = ve_tls_producer_get_buffered_bytes(&p);
    ve_tls_producer_release_scratch_bytes(&p, 4);
    int ok = (ok_rc == 0 && buffered == 64 && p.scratch_bytes == 0);
    destroy_fake_sender_producer(&p);
    return ok ? 0 : -1;
}

static int test_worker_pack_stage_unsupported_compress_drops_before_enqueue(void) {
    g_worker_pack_drop = 0;
    memset(g_worker_pack_drop_msg, 0, sizeof(g_worker_pack_drop_msg));

    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    g_real_platform = cfg.platform;
    g_fake_time = 3000;
    cfg.platform.time_ms = test_fake_time_ms;
    cfg.platform.sleep_ms = test_fake_sleep_ms;
    cfg.platform.cond_timedwait_ms = test_fake_cond_timedwait_ms;
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.compress_type = "bad";
    cfg.agg_strategy = 1;
    cfg.log_count_per_package = 1;
    cfg.flush_interval_ms = 0;
    cfg.send_queue_size = 8;
    cfg.key_queue_idle_ttl_ms = 100000;

    ve_tls_producer p;
    if (init_fake_sender_producer(&p, &cfg) != 0) return -1;
    p.send_done_v2 = on_worker_pack_done_v2;

    ve_tls_kv kvs[1];
    kvs[0].key = "k";
    kvs[0].value = "v";
    ve_tls_bytes log;
    memset(&log, 0, sizeof(log));
    if (ve_tls_proto_encode_log_ex(1710000000001LL, 0, 0, kvs, 1, &log) != 0) {
        destroy_fake_sender_producer(&p);
        return -1;
    }
    int rc = ve_tls_queue_push(&p, log.data, log.size, 1, 1710000000001LL, 0, 0, "hk");
    ve_tls_bytes_free(&log);
    if (rc != 0) {
        destroy_fake_sender_producer(&p);
        return -1;
    }

    p.stop = 1;
    p.flush_requested = 1;
    (void)ve_tls_worker_main(&p);

    size_t send_count = 0;
    if (p.send_queue.mutex && p.send_queue.platform) {
        p.send_queue.platform->mutex_lock(p.send_queue.mutex);
        send_count = p.send_queue.count;
        p.send_queue.platform->mutex_unlock(p.send_queue.mutex);
    }
    destroy_fake_sender_producer(&p);

    if (send_count != 0) return -1;
    if (g_worker_pack_drop < 1) return -1;
    return strcmp(g_worker_pack_drop_msg, "unsupported compress_type") == 0 ? 0 : -1;
}

static int g_mgr_done = 0;
static int g_mgr_ok = 0;

static void on_send_done_mgr_v2(
    ve_tls_result result,
    size_t log_bytes,
    size_t compressed_bytes,
    const ve_tls_error * error,
    const unsigned char * raw_buffer,
    void * user_param,
    int64_t start_id,
    int64_t end_id
) {
    (void)log_bytes;
    (void)compressed_bytes;
    (void)user_param;
    (void)start_id;
    (void)end_id;
    g_mgr_done = 1;
    if (raw_buffer != NULL) {
        g_mgr_ok = 0;
        return;
    }
    if (result != VE_TLS_DROP_ERROR || !error) {
        g_mgr_ok = 0;
        return;
    }
    if (!error->error_code || strcmp(error->error_code, "ClientError") != 0) {
        g_mgr_ok = 0;
        return;
    }
    if (!error->error_message || strcmp(error->error_message, "unsupported compress_type") != 0) {
        g_mgr_ok = 0;
        return;
    }
    g_mgr_ok = 1;
}

static int test_manager_callback_no_raw_buffer_on_compress_error(void) {
    g_mgr_done = 0;
    g_mgr_ok = 0;

    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.retry_policy.max_attempts = 1;
    cfg.flush_interval_ms = 0;

    cfg.agg_strategy = 1;
    cfg.agg_max_compressed_bytes_per_request = 1;
    cfg.compress_type = "bad";

    ve_tls_producer * p = ve_tls_producer_create(&cfg);
    if (!p) {
        return -1;
    }
    ve_tls_producer_set_send_done_v2(p, on_send_done_mgr_v2, NULL);

    ve_tls_kv kvs[1];
    kvs[0].key = "k1";
    kvs[0].value = "v1";
    if (ve_tls_producer_add_log_kv(p, 0, kvs, 1, 1) != VE_TLS_OK) {
        ve_tls_producer_destroy(p);
        return -1;
    }
    for (int i = 0; i < 200 && !g_mgr_done; i++) {
        cfg.platform.sleep_ms(10);
    }
    ve_tls_producer_destroy(p);
    return g_mgr_ok ? 0 : -1;
}

static int g_mgr_p2l_done = 0;
static int g_mgr_p2l_ok = 0;
static int g_mgr_p2l_http_calls = 0;
static char g_mgr_p2l_code[64];
static char g_mgr_p2l_msg[128];

static void on_send_done_mgr_p2l_v2(
    ve_tls_result result,
    size_t log_bytes,
    size_t compressed_bytes,
    const ve_tls_error * error,
    const unsigned char * raw_buffer,
    void * user_param,
    int64_t start_id,
    int64_t end_id
) {
    (void)log_bytes;
    (void)compressed_bytes;
    (void)raw_buffer;
    (void)user_param;
    (void)start_id;
    (void)end_id;
    g_mgr_p2l_done = 1;
    if (result != VE_TLS_DROP_ERROR || !error || !error->error_code || !error->error_message) {
        g_mgr_p2l_ok = 0;
        return;
    }
    snprintf(g_mgr_p2l_code, sizeof(g_mgr_p2l_code), "%s", error->error_code);
    snprintf(g_mgr_p2l_msg, sizeof(g_mgr_p2l_msg), "%s", error->error_message);
    g_mgr_p2l_ok = 1;
}

static int test_http_mgr_count_ok_do(ve_tls_http_client * client, const ve_tls_http_request * req, ve_tls_http_response * resp) {
    (void)client;
    (void)req;
    if (!resp) return -1;
    g_mgr_p2l_http_calls++;
    resp->status_code = 200;
    resp->request_id = strdup("rid-ok");
    return 0;
}

static int test_manager_payload_too_large_after_comp_single(void) {
    g_mgr_p2l_done = 0;
    g_mgr_p2l_ok = 0;
    g_http_called_unexpected = 0;
    memset(g_mgr_p2l_code, 0, sizeof(g_mgr_p2l_code));
    memset(g_mgr_p2l_msg, 0, sizeof(g_mgr_p2l_msg));

    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.retry_policy.max_attempts = 1;
    cfg.flush_interval_ms = 0;
    cfg.log_count_per_package = 1;
    cfg.agg_strategy = 1;
    cfg.agg_max_compressed_bytes_per_request = 1;
    cfg.compress_type = "none";
    cfg.http_client.do_request = test_http_should_not_call_do;
    cfg.http_client.free_response = test_http_free;

    ve_tls_producer * p = ve_tls_producer_create(&cfg);
    if (!p) return -1;
    ve_tls_producer_set_send_done_v2(p, on_send_done_mgr_p2l_v2, NULL);

    ve_tls_kv kvs[1];
    kvs[0].key = "k1";
    kvs[0].value = "v1";
    if (ve_tls_producer_add_log_kv(p, 0, kvs, 1, 1) != VE_TLS_OK) {
        ve_tls_producer_destroy(p);
        return -1;
    }
    for (int i = 0; i < 200 && !g_mgr_p2l_done; i++) cfg.platform.sleep_ms(10);
    ve_tls_producer_destroy(p);
    if (g_http_called_unexpected) return -1;
    if (!g_mgr_p2l_ok) return -1;
    if (strcmp(g_mgr_p2l_code, "PayloadTooLarge") != 0) return -1;
    if (strcmp(g_mgr_p2l_msg, "payload too large after compression") != 0) return -1;
    return 0;
}

static int test_manager_payload_too_large_split_into_two_requests(void) {
    g_mgr_p2l_http_calls = 0;

    ve_tls_kv kvs[1];
    kvs[0].key = "k1";
    kvs[0].value = "v1";
    ve_tls_bytes l1;
    ve_tls_bytes l2;
    memset(&l1, 0, sizeof(l1));
    memset(&l2, 0, sizeof(l2));
    if (ve_tls_proto_encode_log_ex(1710000000000LL, 0, 0, kvs, 1, &l1) != 0) return -1;
    kvs[0].value = "v2";
    if (ve_tls_proto_encode_log_ex(1710000000001LL, 0, 0, kvs, 1, &l2) != 0) {
        ve_tls_bytes_free(&l1);
        return -1;
    }
    ve_tls_bytes b1;
    ve_tls_bytes b2;
    memset(&b1, 0, sizeof(b1));
    memset(&b2, 0, sizeof(b2));
    ve_tls_bytes logs1[1] = {l1};
    ve_tls_bytes logs2[2] = {l1, l2};
    if (ve_tls_proto_encode_log_group_list_ex2(logs1, 1, NULL, NULL, NULL, 0, NULL, 10000, &b1) != 0) {
        ve_tls_bytes_free(&l1);
        ve_tls_bytes_free(&l2);
        return -1;
    }
    if (ve_tls_proto_encode_log_group_list_ex2(logs2, 2, NULL, NULL, NULL, 0, NULL, 10000, &b2) != 0) {
        ve_tls_bytes_free(&b1);
        ve_tls_bytes_free(&l1);
        ve_tls_bytes_free(&l2);
        return -1;
    }
    if (b2.size <= b1.size) {
        ve_tls_bytes_free(&b2);
        ve_tls_bytes_free(&b1);
        ve_tls_bytes_free(&l1);
        ve_tls_bytes_free(&l2);
        return -1;
    }
    size_t max_comp = b1.size;
    ve_tls_bytes_free(&b2);
    ve_tls_bytes_free(&b1);
    ve_tls_bytes_free(&l1);
    ve_tls_bytes_free(&l2);

    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.retry_policy.max_attempts = 1;
    cfg.flush_interval_ms = 0;
    cfg.log_count_per_package = 1;
    cfg.agg_strategy = 1;
    cfg.agg_max_compressed_bytes_per_request = (int32_t)max_comp;
    cfg.compress_type = "none";
    cfg.send_queue_size = 16;
    cfg.key_queue_idle_ttl_ms = 100000;
    cfg.http_client.do_request = test_http_mgr_count_ok_do;
    cfg.http_client.free_response = test_http_free;

    ve_tls_producer * p = ve_tls_producer_create(&cfg);
    if (!p) return -1;
    ve_tls_kv kvs2[1];
    kvs2[0].key = "k1";
    kvs2[0].value = "v1";
    if (ve_tls_producer_add_log_kv(p, 1710000000000LL, kvs2, 1, 0) != VE_TLS_OK) {
        ve_tls_producer_destroy(p);
        return -1;
    }
    kvs2[0].value = "v2";
    if (ve_tls_producer_add_log_kv(p, 1710000000001LL, kvs2, 1, 1) != VE_TLS_OK) {
        ve_tls_producer_destroy(p);
        return -1;
    }
    for (int i = 0; i < 4000 && g_mgr_p2l_http_calls < 2; i++) cfg.platform.sleep_ms(1);
    ve_tls_producer_destroy(p);
    if (g_mgr_p2l_http_calls >= 2) {
        return 0;
    }
    return -1;
}

static int test_manager_key_queue_limit_exceeded_drops(void) {
    g_mgr_p2l_done = 0;
    g_mgr_p2l_ok = 0;
    g_mgr_p2l_http_calls = 0;
    g_http_called_unexpected = 0;
    memset(g_mgr_p2l_code, 0, sizeof(g_mgr_p2l_code));
    memset(g_mgr_p2l_msg, 0, sizeof(g_mgr_p2l_msg));

    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.retry_policy.max_attempts = 1;
    cfg.flush_interval_ms = 0;
    cfg.log_count_per_package = 1;
    cfg.key_queue_max_active = 1;
    cfg.key_queue_idle_ttl_ms = 100000;
    cfg.send_queue_size = 16;
    cfg.compress_type = "none";
    cfg.http_client.do_request = test_http_mgr_count_ok_do;
    cfg.http_client.free_response = test_http_free;

    ve_tls_producer * p = ve_tls_producer_create(&cfg);
    if (!p) return -1;

    ve_tls_kv kvs[1];
    kvs[0].key = "k1";
    kvs[0].value = "v1";
    if (ve_tls_producer_add_log_kv_hashkey(p, 0, "hk1", kvs, 1, 1) != VE_TLS_OK) {
        ve_tls_producer_destroy(p);
        return -1;
    }
    for (int i = 0; i < 2000 && g_mgr_p2l_http_calls < 1; i++) cfg.platform.sleep_ms(1);
    if (g_mgr_p2l_http_calls < 1) {
        ve_tls_producer_destroy(p);
        return -1;
    }

    g_mgr_p2l_done = 0;
    g_mgr_p2l_ok = 0;
    ve_tls_producer_set_send_done_v2(p, on_send_done_mgr_p2l_v2, NULL);
    if (ve_tls_producer_add_log_kv_hashkey(p, 0, "hk2", kvs, 1, 1) != VE_TLS_OK) {
        ve_tls_producer_destroy(p);
        return -1;
    }
    for (int i = 0; i < 200 && !g_mgr_p2l_done; i++) cfg.platform.sleep_ms(10);
    ve_tls_producer_destroy(p);
    if (!g_mgr_p2l_ok) return -1;
    if (strcmp(g_mgr_p2l_code, "KeyQueueLimitExceeded") != 0) return -1;
    if (strcmp(g_mgr_p2l_msg, "key queue limit exceeded") != 0) return -1;
    return 0;
}

static int g_hdr_done = 0;
static int g_hdr_ok = 0;
static int g_hdr_small_done = 0;
static int g_hdr_small_ok = 0;
static int g_hdr_order_done = 0;
static int g_hdr_order_ok = 0;
static int g_hdr_md5_done = 0;
static int g_hdr_md5_ok = 0;
static int g_hdr_empty_hash_done = 0;
static int g_hdr_empty_hash_ok = 0;

static int test_http_assert_headers_do(ve_tls_http_client * client, const ve_tls_http_request * req, ve_tls_http_response * resp) {
    (void)client;
    if (!req || !resp) {
        return -1;
    }
    g_hdr_done = 1;
    if (!req->headers) {
        g_hdr_ok = 0;
        return -1;
    }
    const char * h = req->headers;
    if (!strstr(h, "Content-Type: application/x-protobuf\n")) {
        g_hdr_ok = 0;
    } else if (!strstr(h, "x-tls-apiversion:")) {
        g_hdr_ok = 0;
    } else if (!strstr(h, "x-tls-compresstype:")) {
        g_hdr_ok = 0;
    } else if (!strstr(h, "log-count:")) {
        g_hdr_ok = 0;
    } else if (strstr(h, "\n\n") != NULL) {
        g_hdr_ok = 0;
    } else if (req->tcp_keepalive != 1 || req->tcp_keepidle != 11 || req->tcp_keepintvl != 7) {
        g_hdr_ok = 0;
    } else {
        g_hdr_ok = 1;
    }
    resp->status_code = 200;
    resp->request_id = strdup("rid-hdr");
    resp->body = NULL;
    resp->body_size = 0;
    return 0;
}

static void on_send_done_hdr_v2(
    ve_tls_result result,
    size_t log_bytes,
    size_t compressed_bytes,
    const ve_tls_error * error,
    const unsigned char * raw_buffer,
    void * user_param,
    int64_t start_id,
    int64_t end_id
) {
    (void)log_bytes;
    (void)compressed_bytes;
    (void)error;
    (void)raw_buffer;
    (void)user_param;
    (void)start_id;
    (void)end_id;
    if (result == VE_TLS_OK) {
        g_hdr_done = 1;
    }
}

static int test_sender_builds_headers_and_http_options(void) {
    g_hdr_done = 0;
    g_hdr_ok = 0;

    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.retry_policy.max_attempts = 1;
    cfg.flush_interval_ms = 0;

    cfg.tcp_keepalive = 1;
    cfg.tcp_keepidle = 11;
    cfg.tcp_keepintvl = 7;
    cfg.compress_type = "none";

    cfg.http_client.do_request = test_http_assert_headers_do;
    cfg.http_client.free_response = test_http_free;
    cfg.http_client.user_data = NULL;

    ve_tls_producer * p = ve_tls_producer_create(&cfg);
    if (!p) {
        return -1;
    }
    ve_tls_producer_set_send_done_v2(p, on_send_done_hdr_v2, NULL);

    ve_tls_kv kvs[1];
    kvs[0].key = "k1";
    kvs[0].value = "v1";
    if (ve_tls_producer_add_log_kv(p, 0, kvs, 1, 1) != VE_TLS_OK) {
        ve_tls_producer_destroy(p);
        return -1;
    }
    for (int i = 0; i < 200 && !g_hdr_done; i++) {
        cfg.platform.sleep_ms(10);
    }
    ve_tls_producer_destroy(p);
    return g_hdr_ok ? 0 : -1;
}

static int test_http_assert_small_comp_none_do(ve_tls_http_client * client, const ve_tls_http_request * req, ve_tls_http_response * resp) {
    (void)client;
    if (!req || !req->headers || !resp) {
        g_hdr_small_done = 1;
        g_hdr_small_ok = 0;
        return -1;
    }
    g_hdr_small_done = 1;
    if (strstr(req->headers, "x-tls-compresstype: none\n")) {
        g_hdr_small_ok = 1;
    } else {
        g_hdr_small_ok = 0;
    }
    resp->status_code = 200;
    resp->request_id = strdup("rid-small");
    resp->body = NULL;
    resp->body_size = 0;
    return 0;
}

static int test_sender_small_payload_uses_none_compresstype(void) {
    g_hdr_small_done = 0;
    g_hdr_small_ok = 0;

    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.retry_policy.max_attempts = 1;
    cfg.flush_interval_ms = 0;
    cfg.log_count_per_package = 1;
    cfg.compress_type = "lz4";
    cfg.http_client.do_request = test_http_assert_small_comp_none_do;
    cfg.http_client.free_response = test_http_free;

    ve_tls_producer * p = ve_tls_producer_create(&cfg);
    if (!p) return -1;

    ve_tls_kv kvs[1];
    kvs[0].key = "k";
    kvs[0].value = "v";
    if (ve_tls_producer_add_log_kv(p, 0, kvs, 1, 1) != VE_TLS_OK) {
        ve_tls_producer_destroy(p);
        return -1;
    }

    for (int i = 0; i < 200 && !g_hdr_small_done; i++) {
        cfg.platform.sleep_ms(10);
    }
    ve_tls_producer_destroy(p);
    return g_hdr_small_ok ? 0 : -1;
}

static int test_sender_small_payload_with_agg_strategy_uses_none_compresstype(void) {
    g_hdr_small_done = 0;
    g_hdr_small_ok = 0;

    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.retry_policy.max_attempts = 1;
    cfg.flush_interval_ms = 0;
    cfg.log_count_per_package = 1;
    cfg.compress_type = "lz4";
    cfg.agg_strategy = 1;
    cfg.agg_max_compressed_bytes_per_request = 1024;
    cfg.http_client.do_request = test_http_assert_small_comp_none_do;
    cfg.http_client.free_response = test_http_free;

    ve_tls_producer * p = ve_tls_producer_create(&cfg);
    if (!p) return -1;

    ve_tls_kv kvs[1];
    kvs[0].key = "k";
    kvs[0].value = "v";
    if (ve_tls_producer_add_log_kv(p, 0, kvs, 1, 1) != VE_TLS_OK) {
        ve_tls_producer_destroy(p);
        return -1;
    }

    for (int i = 0; i < 200 && !g_hdr_small_done; i++) {
        cfg.platform.sleep_ms(10);
    }
    ve_tls_producer_destroy(p);
    return g_hdr_small_ok ? 0 : -1;
}

static int test_http_assert_unsigned_headers_after_auth_do(ve_tls_http_client * client, const ve_tls_http_request * req, ve_tls_http_response * resp) {
    (void)client;
    g_hdr_order_done = 1;
    g_hdr_order_ok = 0;
    if (!req || !req->headers || !resp) {
        return -1;
    }
    const char * h = req->headers;
    const char * p_auth = strstr(h, "\nAuthorization: ");
    if (!p_auth && strstr(h, "Authorization: ") == h) {
        p_auth = h;
    }
    const char * p_count = strstr(h, "\nlog-count:");
    const char * p_earliest = strstr(h, "\nearliest-log-time:");
    const char * p_latest = strstr(h, "\nlatest-log-time:");
    if (p_auth && p_count && p_earliest && p_latest && p_auth < p_count && p_count < p_earliest && p_earliest < p_latest) {
        g_hdr_order_ok = 1;
    }
    resp->status_code = 200;
    resp->request_id = strdup("rid-order");
    resp->body = NULL;
    resp->body_size = 0;
    return 0;
}

static int test_sender_unsigned_headers_appended_after_authorization(void) {
    g_hdr_order_done = 0;
    g_hdr_order_ok = 0;

    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.retry_policy.max_attempts = 1;
    cfg.flush_interval_ms = 0;
    cfg.log_count_per_package = 1;
    cfg.compress_type = "none";
    cfg.http_client.do_request = test_http_assert_unsigned_headers_after_auth_do;
    cfg.http_client.free_response = test_http_free;

    ve_tls_producer * p = ve_tls_producer_create(&cfg);
    if (!p) return -1;
    ve_tls_kv kvs[1];
    kvs[0].key = "k";
    kvs[0].value = "v";
    if (ve_tls_producer_add_log_kv(p, 0, kvs, 1, 1) != VE_TLS_OK) {
        ve_tls_producer_destroy(p);
        return -1;
    }
    for (int i = 0; i < 200 && !g_hdr_order_done; i++) {
        cfg.platform.sleep_ms(10);
    }
    ve_tls_producer_destroy(p);
    return g_hdr_order_ok ? 0 : -1;
}

static int test_http_assert_content_md5_signed_do(ve_tls_http_client * client, const ve_tls_http_request * req, ve_tls_http_response * resp) {
    (void)client;
    g_hdr_md5_done = 1;
    g_hdr_md5_ok = 0;
    if (!req || !req->headers || !resp) {
        return -1;
    }
    if (strstr(req->headers, "Content-MD5: ") &&
        strstr(req->headers, "Authorization: HMAC-SHA256 Credential=") &&
        strstr(req->headers, "SignedHeaders=content-md5;")) {
        g_hdr_md5_ok = 1;
    }
    resp->status_code = 200;
    resp->request_id = strdup("rid-md5");
    resp->body = NULL;
    resp->body_size = 0;
    return 0;
}

static int test_sender_putlogs_includes_content_md5_header(void) {
    g_hdr_md5_done = 0;
    g_hdr_md5_ok = 0;

    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.retry_policy.max_attempts = 1;
    cfg.flush_interval_ms = 0;
    cfg.log_count_per_package = 1;
    cfg.compress_type = "none";
    cfg.http_client.do_request = test_http_assert_content_md5_signed_do;
    cfg.http_client.free_response = test_http_free;

    ve_tls_producer * p = ve_tls_producer_create(&cfg);
    if (!p) return -1;

    ve_tls_kv kvs[1];
    kvs[0].key = "k";
    kvs[0].value = "v";
    if (ve_tls_producer_add_log_kv(p, 0, kvs, 1, 1) != VE_TLS_OK) {
        ve_tls_producer_destroy(p);
        return -1;
    }
    for (int i = 0; i < 200 && !g_hdr_md5_done; i++) {
        cfg.platform.sleep_ms(10);
    }
    ve_tls_producer_destroy(p);
    return g_hdr_md5_ok ? 0 : -1;
}

static int test_http_assert_empty_hashkey_signed_do(ve_tls_http_client * client, const ve_tls_http_request * req, ve_tls_http_response * resp) {
    (void)client;
    g_hdr_empty_hash_done = 1;
    g_hdr_empty_hash_ok = 0;
    if (!req || !req->headers || !resp) {
        return -1;
    }
    if (strstr(req->headers, "x-tls-hashkey: \n") &&
        strstr(req->headers, "SignedHeaders=") &&
        strstr(req->headers, "x-tls-hashkey")) {
        g_hdr_empty_hash_ok = 1;
    }
    resp->status_code = 200;
    resp->request_id = strdup("rid-empty-hash");
    resp->body = NULL;
    resp->body_size = 0;
    return 0;
}

static int test_sender_putlogs_includes_empty_hashkey_header(void) {
    g_hdr_empty_hash_done = 0;
    g_hdr_empty_hash_ok = 0;

    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.retry_policy.max_attempts = 1;
    cfg.flush_interval_ms = 0;
    cfg.log_count_per_package = 1;
    cfg.compress_type = "none";
    cfg.http_client.do_request = test_http_assert_empty_hashkey_signed_do;
    cfg.http_client.free_response = test_http_free;

    ve_tls_producer * p = ve_tls_producer_create(&cfg);
    if (!p) return -1;

    ve_tls_kv kvs[1];
    kvs[0].key = "k";
    kvs[0].value = "v";
    if (ve_tls_producer_add_log_kv(p, 0, kvs, 1, 1) != VE_TLS_OK) {
        ve_tls_producer_destroy(p);
        return -1;
    }
    for (int i = 0; i < 200 && !g_hdr_empty_hash_done; i++) {
        cfg.platform.sleep_ms(10);
    }
    ve_tls_producer_destroy(p);
    return g_hdr_empty_hash_ok ? 0 : -1;
}

static int g_raw_done = 0;
static int g_raw_ok = 0;
static int g_raw_ok_count = 0;

static void on_send_done_raw_v2(
    ve_tls_result result,
    size_t log_bytes,
    size_t compressed_bytes,
    const ve_tls_error * error,
    const unsigned char * raw_buffer,
    void * user_param,
    int64_t start_id,
    int64_t end_id
) {
    (void)log_bytes;
    (void)compressed_bytes;
    (void)raw_buffer;
    (void)user_param;
    (void)start_id;
    (void)end_id;
    if (result == VE_TLS_OK && error && error->request_id && strcmp(error->request_id, "rid-ok") == 0) {
        g_raw_ok_count++;
        g_raw_ok = 1;
    }
    if (g_raw_ok_count >= 2) {
        g_raw_done = 1;
    }
}

static int test_raw_add_log_paths_ok(void) {
    g_raw_done = 0;
    g_raw_ok = 0;
    g_raw_ok_count = 0;

    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.retry_policy.max_attempts = 1;
    cfg.flush_interval_ms = 0;
    cfg.agg_strategy = 0;
    cfg.compress_type = "none";
    cfg.http_client.do_request = test_http_ok_do;
    cfg.http_client.free_response = test_http_free;

    ve_tls_producer * p = ve_tls_producer_create(&cfg);
    if (!p) {
        return -1;
    }
    ve_tls_producer_set_send_done_v2(p, on_send_done_raw_v2, NULL);

    const char * raw = "{\"k\":\"v\"}";
    if (ve_tls_producer_add_log_raw(p, raw, strlen(raw), 1) != VE_TLS_OK) {
        ve_tls_producer_destroy(p);
        return -1;
    }
    if (ve_tls_producer_add_log_raw_time_parts(p, 1710000000000LL, 1, 123, raw, strlen(raw), 1) != VE_TLS_OK) {
        ve_tls_producer_destroy(p);
        return -1;
    }

    for (int i = 0; i < 300 && !g_raw_done; i++) {
        cfg.platform.sleep_ms(10);
    }
    ve_tls_producer_destroy(p);
    return g_raw_ok ? 0 : -1;
}

static int test_add_log_with_id_returns_monotonic_ids(void) {
    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.retry_policy.max_attempts = 1;
    cfg.flush_interval_ms = 0;
    cfg.agg_strategy = 0;
    cfg.compress_type = "none";
    cfg.http_client.do_request = test_http_ok_do;
    cfg.http_client.free_response = test_http_free;

    ve_tls_producer * p = ve_tls_producer_create(&cfg);
    if (!p) {
        return -1;
    }

    const char * raw = "{\"k\":\"v\"}";
    int64_t raw_id = 0;
    int64_t kv_id = 0;
    ve_tls_kv kvs[1];
    kvs[0].key = "k";
    kvs[0].value = "v";
    if (ve_tls_producer_add_log_raw_with_id(p, raw, strlen(raw), 1, &raw_id) != VE_TLS_OK || raw_id <= 0) {
        ve_tls_producer_destroy(p);
        return -1;
    }
    if (ve_tls_producer_add_log_kv_hashkey_with_id(p, 0, "hk", kvs, 1, 1, &kv_id) != VE_TLS_OK || kv_id <= raw_id) {
        ve_tls_producer_destroy(p);
        return -1;
    }

    ve_tls_producer_destroy(p);
    return 0;
}

static int g_sq_drop_done = 0;
static int g_sq_drop_ok = 0;

static int test_http_slow_ok_do(ve_tls_http_client * client, const ve_tls_http_request * req, ve_tls_http_response * resp) {
    (void)req;
    if (!client || !resp) {
        return -1;
    }
    ve_tls_platform * platform = (ve_tls_platform *)client->user_data;
    if (platform && platform->sleep_ms) {
        platform->sleep_ms(50);
    }
    resp->status_code = 200;
    resp->request_id = strdup("rid-slow");
    resp->body = NULL;
    resp->body_size = 0;
    return 0;
}

static void on_send_done_sq_drop_v2(
    ve_tls_result result,
    size_t log_bytes,
    size_t compressed_bytes,
    const ve_tls_error * error,
    const unsigned char * raw_buffer,
    void * user_param,
    int64_t start_id,
    int64_t end_id
) {
    (void)log_bytes;
    (void)compressed_bytes;
    (void)raw_buffer;
    (void)user_param;
    (void)start_id;
    (void)end_id;
    if (result != VE_TLS_DROP_ERROR || !error || !error->error_code) {
        return;
    }
    if (strcmp(error->error_code, "SendQueueTimeout") == 0 || strcmp(error->error_code, "SendQueueFull") == 0) {
        g_sq_drop_ok = 1;
        g_sq_drop_done = 1;
    }
}

static int test_send_queue_full_paths_drop_and_timeout(void) {
    g_sq_drop_done = 0;
    g_sq_drop_ok = 0;

    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.retry_policy.max_attempts = 1;
    cfg.flush_interval_ms = 0;
    cfg.agg_strategy = 0;
    cfg.log_count_per_package = 1;
    cfg.log_bytes_per_package = 128;
    cfg.compress_type = "none";

    cfg.send_queue_size = 1;
    cfg.send_queue_full_policy = VE_TLS_SEND_QUEUE_FULL_BLOCK;
    cfg.send_queue_block_timeout_ms = 1;

    cfg.http_client.do_request = test_http_slow_ok_do;
    cfg.http_client.free_response = test_http_free;
    cfg.http_client.user_data = &cfg.platform;

    ve_tls_producer * p = ve_tls_producer_create(&cfg);
    if (!p) {
        return -1;
    }
    ve_tls_producer_set_send_done_v2(p, on_send_done_sq_drop_v2, NULL);

    ve_tls_kv kvs[1];
    kvs[0].key = "k1";
    kvs[0].value = "v1";
    for (int i = 0; i < 200 && !g_sq_drop_done; i++) {
        (void)ve_tls_producer_add_log_kv(p, 0, kvs, 1, 1);
        cfg.platform.sleep_ms(1);
    }

    for (int i = 0; i < 200 && !g_sq_drop_done; i++) {
        cfg.platform.sleep_ms(10);
    }
    ve_tls_producer_destroy(p);
    return g_sq_drop_ok ? 0 : -1;
}

typedef struct {
    int done;
    int ok;
} env_send_state;

static void on_send_done_env_v2(
    ve_tls_result result,
    size_t log_bytes,
    size_t compressed_bytes,
    const ve_tls_error * error,
    const unsigned char * raw_buffer,
    void * user_param,
    int64_t start_id,
    int64_t end_id
) {
    (void)log_bytes;
    (void)compressed_bytes;
    (void)start_id;
    (void)end_id;
    env_send_state * st = (env_send_state *)user_param;
    if (!st) {
        return;
    }
    st->done = 1;
    if (raw_buffer != NULL) {
        st->ok = 0;
        return;
    }
    if (result != VE_TLS_DROP_ERROR || !error) {
        st->ok = 0;
        return;
    }
    if (!error->request_id || strcmp(error->request_id, "hdr-rid") != 0) {
        st->ok = 0;
        return;
    }
    st->ok = 1;
}

static int test_env_shared_senders_multi_producer(void) {
    if (ve_tls_env_init(2) != VE_TLS_OK) {
        return -1;
    }

    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.retry_policy.max_attempts = 1;
    cfg.http_client.do_request = test_http_do;
    cfg.http_client.free_response = test_http_free;
    cfg.use_global_env = 1;
    cfg.send_thread_count = 8;

    env_send_state s1;
    env_send_state s2;
    memset(&s1, 0, sizeof(s1));
    memset(&s2, 0, sizeof(s2));

    ve_tls_producer * p1 = ve_tls_producer_create(&cfg);
    ve_tls_producer * p2 = ve_tls_producer_create(&cfg);
    if (!p1 || !p2) {
        if (p1) ve_tls_producer_destroy(p1);
        if (p2) ve_tls_producer_destroy(p2);
        (void)ve_tls_env_destroy(1000);
        return -1;
    }
    if (((ve_tls_producer *)p1)->sender_count != 0) {
        ve_tls_producer_destroy(p1);
        ve_tls_producer_destroy(p2);
        (void)ve_tls_env_destroy(1000);
        return -1;
    }
    if (((ve_tls_producer *)p2)->sender_count != 0) {
        ve_tls_producer_destroy(p1);
        ve_tls_producer_destroy(p2);
        (void)ve_tls_env_destroy(1000);
        return -1;
    }

    ve_tls_producer_set_send_done_v2(p1, on_send_done_env_v2, &s1);
    ve_tls_producer_set_send_done_v2(p2, on_send_done_env_v2, &s2);

    ve_tls_kv kvs[1];
    kvs[0].key = "k1";
    kvs[0].value = "v1";
    if (ve_tls_producer_add_log_kv(p1, 0, kvs, 1, 1) != VE_TLS_OK) {
        ve_tls_producer_destroy(p1);
        ve_tls_producer_destroy(p2);
        (void)ve_tls_env_destroy(1000);
        return -1;
    }
    if (ve_tls_producer_add_log_kv(p2, 0, kvs, 1, 1) != VE_TLS_OK) {
        ve_tls_producer_destroy(p1);
        ve_tls_producer_destroy(p2);
        (void)ve_tls_env_destroy(1000);
        return -1;
    }

    for (int i = 0; i < 400 && (!s1.done || !s2.done); i++) {
        cfg.platform.sleep_ms(10);
    }

    (void)ve_tls_producer_close(p1, 5000);
    (void)ve_tls_producer_close(p2, 5000);
    ve_tls_producer_destroy(p1);
    ve_tls_producer_destroy(p2);
    ve_tls_result erc = ve_tls_env_destroy(5000);
    if (erc != VE_TLS_OK) {
        return -1;
    }
    return (s1.ok && s2.ok) ? 0 : -1;
}

static int test_env_create_without_init_fails(void) {
    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.use_global_env = 1;
    ve_tls_producer * p = ve_tls_producer_create(&cfg);
    if (p) {
        ve_tls_producer_destroy(p);
        return -1;
    }
    return 0;
}

static int test_env_destroy_timeout_then_recover(void) {
    if (ve_tls_env_init(1) != VE_TLS_OK) {
        return -1;
    }

    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.retry_policy.max_attempts = 1;
    cfg.http_client.do_request = test_http_do;
    cfg.http_client.free_response = test_http_free;
    cfg.use_global_env = 1;

    ve_tls_producer * p = ve_tls_producer_create(&cfg);
    if (!p) {
        (void)ve_tls_env_destroy(1000);
        return -1;
    }

    ve_tls_kv kvs[1];
    kvs[0].key = "k1";
    kvs[0].value = "v1";
    if (ve_tls_producer_add_log_kv(p, 0, kvs, 1, 1) != VE_TLS_OK) {
        ve_tls_producer_destroy(p);
        (void)ve_tls_env_destroy(1000);
        return -1;
    }

    ve_tls_result trc = ve_tls_env_destroy(0);
    if (trc != VE_TLS_TIMEOUT) {
        ve_tls_producer_destroy(p);
        (void)ve_tls_env_destroy(1000);
        return -1;
    }

    (void)ve_tls_producer_close(p, 5000);
    ve_tls_producer_destroy(p);
    ve_tls_result rc = ve_tls_env_destroy(5000);
    return rc == VE_TLS_OK ? 0 : -1;
}

static int test_env_init_idempotent(void) {
    if (ve_tls_env_init(1) != VE_TLS_OK) {
        return -1;
    }
    if (ve_tls_env_init(2) != VE_TLS_OK) {
        (void)ve_tls_env_destroy(1000);
        return -1;
    }
    ve_tls_result rc = ve_tls_env_destroy(5000);
    return rc == VE_TLS_OK ? 0 : -1;
}

static int test_alloc_fail_add_log_raw_drops(void) {
    alloc_fail_state st;
    memset(&st, 0, sizeof(st));
    ve_tls_alloc_hooks saved;
    memset(&saved, 0, sizeof(saved));

    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.retry_policy.max_attempts = 1;
    cfg.flush_interval_ms = 0;
    cfg.http_client.do_request = test_http_ok_do;
    cfg.http_client.free_response = test_http_ok_free;

    ve_tls_producer * p = ve_tls_producer_create(&cfg);
    if (!p) {
        return -1;
    }
    ve_tls_alloc_get_hooks(&saved);
    set_alloc_fail_after(&st, 1);
    const char * raw = "{\"k\":\"v\"}";
    ve_tls_result rc = ve_tls_producer_add_log_raw(p, raw, strlen(raw), 0);
    ve_tls_alloc_set_hooks(&saved);
    ve_tls_producer_destroy(p);
    return rc == VE_TLS_DROP_ERROR ? 0 : -1;
}

static int test_alloc_fail_add_log_kv_drops(void) {
    alloc_fail_state st;
    memset(&st, 0, sizeof(st));
    ve_tls_alloc_hooks saved;
    memset(&saved, 0, sizeof(saved));

    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.retry_policy.max_attempts = 1;
    cfg.flush_interval_ms = 0;
    cfg.http_client.do_request = test_http_ok_do;
    cfg.http_client.free_response = test_http_ok_free;

    ve_tls_producer * p = ve_tls_producer_create(&cfg);
    if (!p) {
        return -1;
    }
    ve_tls_alloc_get_hooks(&saved);
    set_alloc_fail_after(&st, 1);
    ve_tls_kv kvs[1];
    kvs[0].key = "k1";
    kvs[0].value = "v1";
    ve_tls_result rc = ve_tls_producer_add_log_kv(p, 0, kvs, 1, 0);
    ve_tls_alloc_set_hooks(&saved);
    ve_tls_producer_destroy(p);
    return rc == VE_TLS_DROP_ERROR ? 0 : -1;
}

static int test_alloc_fail_env_init_fails(void) {
    alloc_fail_state st;
    memset(&st, 0, sizeof(st));
    ve_tls_alloc_hooks saved;
    memset(&saved, 0, sizeof(saved));
    ve_tls_alloc_get_hooks(&saved);
    set_alloc_fail_after(&st, 1);
    ve_tls_result rc = ve_tls_env_init(1);
    ve_tls_alloc_set_hooks(&saved);
    if (rc != VE_TLS_DROP_ERROR) {
        (void)ve_tls_env_destroy(1000);
        return -1;
    }
    if (ve_tls_env_init(1) != VE_TLS_OK) {
        return -1;
    }
    return ve_tls_env_destroy(1000) == VE_TLS_OK ? 0 : -1;
}

static int test_alloc_failtrack_producer_create_no_leak(void) {
    ve_tls_alloc_hooks saved;
    memset(&saved, 0, sizeof(saved));
    ve_tls_alloc_get_hooks(&saved);

    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.send_thread_count = 1;
    cfg.flush_interval_ms = 100000;
    cfg.retry_policy.max_attempts = 1;
    cfg.http_client.do_request = test_http_ok_do;
    cfg.http_client.free_response = test_http_ok_free;

    for (int i = 1; i <= 220; i++) {
        alloc_failtrack_state st;
        memset(&st, 0, sizeof(st));
        set_alloc_failtrack(&st, i);

        ve_tls_producer * p = ve_tls_producer_create(&cfg);
        if (p) {
            st.fail_after = 0;
            (void)ve_tls_producer_close(p, 5000);
            ve_tls_producer_destroy(p);
        }

        ve_tls_alloc_set_hooks(&saved);
        int64_t live = __atomic_load_n(&st.live, __ATOMIC_RELAXED);
        if (live != 0) {
            return -1;
        }
    }
    return 0;
}

static int test_alloc_tracking_env_lifecycle_no_leak(void) {
    ve_tls_alloc_hooks saved;
    memset(&saved, 0, sizeof(saved));
    ve_tls_alloc_get_hooks(&saved);

    alloc_track_state tr;
    memset(&tr, 0, sizeof(tr));
    enable_alloc_tracking(&tr);

    ve_tls_result rc = ve_tls_env_init(1);
    ve_tls_result drc = ve_tls_env_destroy(1000);

    ve_tls_alloc_set_hooks(&saved);
    if (rc != VE_TLS_OK || drc != VE_TLS_OK) {
        return -1;
    }
    int64_t live = __atomic_load_n(&tr.live, __ATOMIC_RELAXED);
    return live == 0 ? 0 : -1;
}

static int test_alloc_tracking_sign_success_no_leak(void) {
    ve_tls_alloc_hooks saved;
    memset(&saved, 0, sizeof(saved));
    ve_tls_alloc_get_hooks(&saved);

    alloc_track_state tr;
    memset(&tr, 0, sizeof(tr));
    enable_alloc_tracking(&tr);

    char * out = NULL;
    int rc = ve_tls_sign_v4_append(
        "ak",
        "sk",
        "tok",
        "cn-beijing",
        "TLS",
        "POST",
        "example.com",
        "/PutLogs",
        "TopicId=t",
        (const unsigned char *)"abc",
        3,
        "Content-Type: application/x-protobuf\n",
        &out
    );

    int ok = 0;
    if (rc == 0 && out && strstr(out, "Authorization: ") && strstr(out, "X-Date: ") && strstr(out, "Host: ")) {
        ok = 1;
    }
    ve_tls_free(out);
    ve_tls_alloc_set_hooks(&saved);
    int64_t live = __atomic_load_n(&tr.live, __ATOMIC_RELAXED);
    return (ok && live == 0) ? 0 : -1;
}

static int test_sign_allocation_budget(void) {
    ve_tls_alloc_hooks saved;
    memset(&saved, 0, sizeof(saved));
    ve_tls_alloc_get_hooks(&saved);

    alloc_select_fail_state st;
    memset(&st, 0, sizeof(st));
    set_alloc_select_fail(&st, 0, 0, 0, 0);

    char * out = NULL;
    int rc = ve_tls_sign_v4_append(
        "ak",
        "sk",
        "tok",
        "cn-beijing",
        "TLS",
        "POST",
        "example.com",
        "/PutLogs",
        "TopicId=t&aa=1&bb=2",
        (const unsigned char *)"abc",
        3,
        "Content-Type: application/x-protobuf\nx-tls-apiversion: " VE_TLS_C_SDK_API_VERSION "\n",
        &out
    );

    ve_tls_alloc_set_hooks(&saved);
    int ok = 0;
    if (rc == 0 && out && strstr(out, "Authorization: ") && strstr(out, "X-Date: ")) {
        ok = 1;
    }
    ve_tls_free(out);

    int total_calls = st.malloc_calls + st.calloc_calls + st.realloc_calls + st.strdup_calls;
    return (ok && total_calls <= 22) ? 0 : -1;
}

static int test_alloc_tracking_producer_lifecycle_no_leak(void) {
    ve_tls_alloc_hooks saved;
    memset(&saved, 0, sizeof(saved));
    ve_tls_alloc_get_hooks(&saved);

    alloc_track_state tr;
    memset(&tr, 0, sizeof(tr));
    enable_alloc_tracking(&tr);

    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.retry_policy.max_attempts = 1;
    cfg.flush_interval_ms = 0;
    cfg.http_client.do_request = test_http_ok_do;
    cfg.http_client.free_response = test_http_ok_free;

    ve_tls_producer * p = ve_tls_producer_create(&cfg);
    if (!p) {
        ve_tls_alloc_set_hooks(&saved);
        return -1;
    }
    ve_tls_kv kvs[1];
    kvs[0].key = "k1";
    kvs[0].value = "v1";
    (void)ve_tls_producer_add_log_kv(p, 0, kvs, 1, 1);
    (void)ve_tls_producer_close(p, 5000);
    ve_tls_producer_destroy(p);

    ve_tls_alloc_set_hooks(&saved);
    int64_t live = __atomic_load_n(&tr.live, __ATOMIC_RELAXED);
    return live == 0 ? 0 : -1;
}

static int test_alloc_fail_fuzz_sign_does_not_crash(void) {
    ve_tls_alloc_hooks saved;
    memset(&saved, 0, sizeof(saved));
    ve_tls_alloc_get_hooks(&saved);

    alloc_fail_state st;
    memset(&st, 0, sizeof(st));

    for (int i = 1; i <= 80; i++) {
        set_alloc_fail_after(&st, i);
        char * out = NULL;
        (void)ve_tls_sign_v4_append(
            "ak",
            "sk",
            "tok",
            "cn-beijing",
            "TLS",
            "POST",
            "example.com",
            "/PutLogs",
            "TopicId=t",
            (const unsigned char *)"abc",
            3,
            "Content-Type: application/x-protobuf\n",
            &out
        );
        ve_tls_free(out);
    }

    ve_tls_alloc_set_hooks(&saved);
    return 0;
}

static int test_alloc_fail_fuzz_proto_does_not_crash(void) {
    ve_tls_alloc_hooks saved;
    memset(&saved, 0, sizeof(saved));
    ve_tls_alloc_get_hooks(&saved);

    alloc_fail_state st;
    memset(&st, 0, sizeof(st));

    ve_tls_kv kvs[1];
    kvs[0].key = "k1";
    kvs[0].value = "v1";

    for (int i = 1; i <= 120; i++) {
        set_alloc_fail_after(&st, i);
        ve_tls_bytes out;
        memset(&out, 0, sizeof(out));
        int rc = ve_tls_proto_encode_log_ex(1710000000000LL, 123, 1, kvs, 1, &out);
        if (rc == 0) {
            ve_tls_bytes_free(&out);
        }
    }

    ve_tls_alloc_set_hooks(&saved);
    return 0;
}

static int test_alloc_fail_fuzz_proto_group_list_does_not_crash(void) {
    ve_tls_alloc_hooks saved;
    memset(&saved, 0, sizeof(saved));
    ve_tls_alloc_get_hooks(&saved);

    alloc_fail_state st;
    memset(&st, 0, sizeof(st));

    unsigned char dummy[8] = {0, 1, 2, 3, 4, 5, 6, 7};
    ve_tls_bytes logs[3];
    for (size_t i = 0; i < 3; i++) {
        logs[i].data = dummy;
        logs[i].size = sizeof(dummy);
    }
    ve_tls_kv tags[1];
    tags[0].key = "tk";
    tags[0].value = "tv";

    for (int i = 1; i <= 200; i++) {
        set_alloc_fail_after(&st, i);
        ve_tls_bytes out;
        memset(&out, 0, sizeof(out));
        int rc = ve_tls_proto_encode_log_group_list_ex2(logs, 3, "src", "fn", tags, 1, "cf", 0, &out);
        if (rc == 0) {
            ve_tls_bytes_free(&out);
        }
    }

    ve_tls_alloc_set_hooks(&saved);
    return 0;
}

static int test_proto_group_list_edge_cases(void) {
    ve_tls_bytes out;
    memset(&out, 0, sizeof(out));
    if (ve_tls_proto_encode_log_group_list_ex2(NULL, 0, NULL, NULL, NULL, 0, NULL, 0, &out) != 0) return -1;
    if (out.data != NULL || out.size != 0) return -1;
    if (ve_tls_proto_encode_log_group_list_ex2(NULL, 0, NULL, NULL, NULL, 0, NULL, 0, NULL) != -1) return -1;

    unsigned char dummy[1] = {0};
    ve_tls_bytes logs[1];
    logs[0].data = dummy;
    logs[0].size = sizeof(dummy);
    memset(&out, 0, sizeof(out));
    if (ve_tls_proto_encode_log_group_list_ex2(logs, 1, NULL, NULL, NULL, 0, NULL, 0, &out) != 0) return -1;
    ve_tls_bytes_free(&out);
    memset(&out, 0, sizeof(out));
    if (ve_tls_proto_encode_log_group_list_ex2(logs, 1, NULL, NULL, NULL, 0, NULL, 10001, &out) != 0) return -1;
    ve_tls_bytes_free(&out);
    return 0;
}

static int test_compress_apply_edge_cases(void) {
    unsigned char in[1] = {0};
    ve_tls_bytes out;
    memset(&out, 0, sizeof(out));

    if (ve_tls_compress_apply("lz4", in, sizeof(in), NULL) != -1) return -1;
    if (ve_tls_compress_apply(NULL, in, sizeof(in), &out) != -2) return -1;
    if (ve_tls_compress_apply("none", in, sizeof(in), &out) != -2) return -1;
    if (ve_tls_compress_apply("zlib", NULL, 0, &out) != -1) return -1;
    if (ve_tls_compress_apply("bad", in, sizeof(in), &out) != -3) return -1;

#if defined(VE_TLS_HAVE_ZLIB)
    if (ve_tls_compress_apply("zlib", in, (size_t)UINT_MAX + 1, &out) != -1) return -1;
    memset(&out, 0, sizeof(out));
    if (ve_tls_compress_apply("ZLIB", in, sizeof(in), &out) != 0 || !out.data || out.size == 0) return -1;
    ve_tls_bytes_free(&out);
#endif

#if defined(VE_TLS_HAVE_LZ4)
    if (ve_tls_compress_apply("lz4", in, (size_t)INT_MAX + 1, &out) != -1) return -1;
    memset(&out, 0, sizeof(out));
    if (ve_tls_compress_apply("LZ4", in, sizeof(in), &out) != 0 || !out.data || out.size == 0) return -1;
    ve_tls_bytes_free(&out);
#endif

    ve_tls_alloc_hooks saved;
    memset(&saved, 0, sizeof(saved));
    ve_tls_alloc_get_hooks(&saved);

    alloc_select_fail_state st;
    memset(&st, 0, sizeof(st));

#if defined(VE_TLS_HAVE_ZLIB)
    set_alloc_select_fail(&st, 0, 1, 0, 0);
    memset(&out, 0, sizeof(out));
    if (ve_tls_compress_apply("zlib", in, sizeof(in), &out) != -1) {
        ve_tls_alloc_set_hooks(&saved);
        return -1;
    }
    if (out.data != NULL || out.size != 0) {
        ve_tls_alloc_set_hooks(&saved);
        return -1;
    }
    memset(&st, 0, sizeof(st));
    set_alloc_select_fail(&st, 1, 0, 0, 0);
    memset(&out, 0, sizeof(out));
    if (ve_tls_compress_apply("zlib", in, sizeof(in), &out) != -1) {
        ve_tls_alloc_set_hooks(&saved);
        return -1;
    }
    if (out.data != NULL || out.size != 0) {
        ve_tls_alloc_set_hooks(&saved);
        return -1;
    }
#endif

#if defined(VE_TLS_HAVE_LZ4)
    memset(&st, 0, sizeof(st));
    set_alloc_select_fail(&st, 1, 0, 0, 0);
    memset(&out, 0, sizeof(out));
    if (ve_tls_compress_apply("lz4", in, sizeof(in), &out) != -1) {
        ve_tls_alloc_set_hooks(&saved);
        return -1;
    }
    if (out.data != NULL || out.size != 0) {
        ve_tls_alloc_set_hooks(&saved);
        return -1;
    }
#endif

    ve_tls_alloc_set_hooks(&saved);
    return 0;
}

static void * test_null_malloc(size_t n, void * user_data) {
    (void)n;
    (void)user_data;
    return NULL;
}

static double test_neg_rand01(void * p) {
    (void)p;
    return -0.5;
}

static double test_big_rand01(void * p) {
    (void)p;
    return 1.5;
}

static int test_alloc_hooks_and_small_edge_cases(void) {
    ve_tls_config_init(NULL);
    ve_tls_http_response_init(NULL);
    ve_tls_error_free_fields(NULL);
    ve_tls_retry_policy_init(NULL);

    ve_tls_http_response resp;
    memset(&resp, 0xAB, sizeof(resp));
    ve_tls_http_response_init(&resp);
    if (resp.status_code != 0 || resp.body != NULL || resp.body_size != 0) return -1;

    ve_tls_error err;
    memset(&err, 0, sizeof(err));
    err.error_code = ve_tls_strdup("E");
    err.error_message = ve_tls_strdup("M");
    err.request_id = ve_tls_strdup("R");
    err.http_code = 123;
    err.transport_kind = VE_TLS_TRANSPORT_GENERIC;
    err.transport_code = 7;
    err.retryable = 1;
    ve_tls_error_free_fields(&err);
    if (err.error_code != NULL || err.error_message != NULL || err.request_id != NULL) return -1;
    if (err.http_code != 0 || err.transport_kind != VE_TLS_TRANSPORT_NONE || err.transport_code != 0 || err.retryable != 0) return -1;

    ve_tls_alloc_hooks saved;
    memset(&saved, 0, sizeof(saved));
    ve_tls_alloc_get_hooks(&saved);

    ve_tls_alloc_hooks hooks;
    memset(&hooks, 0, sizeof(hooks));
    hooks.malloc_fn = test_null_malloc;
    ve_tls_alloc_set_hooks(&hooks);

    char * s1 = ve_tls_strdup("x");
    if (s1 != NULL) {
        ve_tls_free(s1);
        ve_tls_alloc_set_hooks(&saved);
        return -1;
    }
    if (ve_tls_strdup(NULL) != NULL) {
        ve_tls_alloc_set_hooks(&saved);
        return -1;
    }
    ve_tls_alloc_get_hooks(NULL);
    ve_tls_alloc_set_hooks(NULL);

    char * s2 = ve_tls_strdup("y");
    if (!s2) {
        ve_tls_alloc_set_hooks(&saved);
        return -1;
    }
    ve_tls_free(s2);
    ve_tls_alloc_set_hooks(&saved);

    ve_tls_retry_policy rp;
    ve_tls_retry_policy_init(&rp);
    if (ve_tls_retry_next_interval_ms(NULL, 1) != 0) return -1;
    if (ve_tls_retry_next_interval_ms(&rp, 0) != 0) return -1;

    rp.initial_interval_ms = 1000;
    rp.max_interval_ms = 1000;
    rp.multiplier = 1.0;
    rp.randomization_factor = 0.2;
    rp.rand01 = test_neg_rand01;
    if (ve_tls_retry_next_interval_ms(&rp, 1) != 800) return -1;
    rp.rand01 = test_big_rand01;
    if (ve_tls_retry_next_interval_ms(&rp, 1) != 1200) return -1;
    rp.randomization_factor = 2.0;
    rp.rand01 = fixed_rand01;
    if (ve_tls_retry_next_interval_ms(&rp, 1) != 0) return -1;

    return 0;
}

static int test_config_init_request_timeout_default_is_50s(void) {
    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    return (cfg.request_timeout_ms == 50000 &&
            cfg.connect_timeout_ms == 10000 &&
            cfg.breaker_ingress_policy == VE_TLS_BREAKER_INGRESS_ALLOW) ? 0 : -1;
}

static int test_producer_derived_defaults_follow_memory_budget(void) {
    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.max_buffer_bytes = 64 * 1024 * 1024;

    ve_tls_producer * p = ve_tls_producer_create(&cfg);
    if (!p) return -1;
    int ok64 = (p->config.log_bytes_per_package == 2 * 1024 * 1024 &&
                p->config.log_count_per_package == 4096 &&
                p->config.send_thread_count == 2 &&
                p->config.pack_thread_count == 2 &&
                p->config.send_queue_size == 40);
    ve_tls_producer_destroy(p);
    if (!ok64) return -1;

    ve_tls_config_init(&cfg);
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.max_buffer_bytes = 256 * 1024 * 1024;

    p = ve_tls_producer_create(&cfg);
    if (!p) return -1;
    int ok256 = (p->config.log_bytes_per_package == 4 * 1024 * 1024 &&
                 p->config.log_count_per_package == 4096 &&
                 p->config.send_thread_count == 4 &&
                 p->config.pack_thread_count == 4 &&
                 p->config.send_queue_size == 72);
    ve_tls_producer_destroy(p);
    return ok256 ? 0 : -1;
}

static int test_producer_derived_defaults_preserve_explicit_overrides(void) {
    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.max_buffer_bytes = 64 * 1024 * 1024;
    cfg.log_bytes_per_package = 3 * 1024 * 1024;
    cfg.log_count_per_package = 3000;
    cfg.send_thread_count = 7;
    cfg.pack_thread_count = 5;
    cfg.send_queue_size = 33;

    ve_tls_producer * p = ve_tls_producer_create(&cfg);
    if (!p) return -1;
    int ok = (p->config.log_bytes_per_package == 3 * 1024 * 1024 &&
              p->config.log_count_per_package == 3000 &&
              p->config.send_thread_count == 7 &&
              p->config.pack_thread_count == 5 &&
              p->config.send_queue_size == 33);
    ve_tls_producer_destroy(p);
    return ok ? 0 : -1;
}

static int test_producer_create_rejects_block_without_timeout(void) {
    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.buffer_full_policy = VE_TLS_BUFFER_FULL_BLOCK;
    cfg.buffer_full_block_timeout_ms = 0;
    cfg.max_buffer_bytes = 64 * 1024 * 1024;

    ve_tls_producer * p = ve_tls_producer_create(&cfg);
    if (p) {
        ve_tls_producer_destroy(p);
        return -1;
    }
    return 0;
}

static int test_producer_create_rejects_block_when_buffer_smaller_than_two_packages(void) {
    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.buffer_full_policy = VE_TLS_BUFFER_FULL_BLOCK;
    cfg.buffer_full_block_timeout_ms = 100;
    cfg.max_buffer_bytes = 7 * 1024 * 1024;
    cfg.log_bytes_per_package = 4 * 1024 * 1024;

    ve_tls_producer * p = ve_tls_producer_create(&cfg);
    if (p) {
        ve_tls_producer_destroy(p);
        return -1;
    }
    return 0;
}

static int test_producer_create_allows_low_resource_block_config_and_derives_send_reserve(void) {
    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.buffer_full_policy = VE_TLS_BUFFER_FULL_BLOCK;
    cfg.buffer_full_block_timeout_ms = 100;
    cfg.max_buffer_bytes = 10 * 1024 * 1024;
    cfg.log_bytes_per_package = 1 * 1024 * 1024;
    cfg.log_count_per_package = 1000;
    cfg.send_thread_count = 4;
    cfg.pack_thread_count = 4;

    ve_tls_producer * p = ve_tls_producer_create(&cfg);
    if (!p) return -1;
    int ok = (p->send_reserved_bytes == 4 * 1024 * 1024);
    ve_tls_producer_destroy(p);
    return ok ? 0 : -1;
}

static int test_send_queue_push_timeout_returns_minus2(void) {
    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    g_real_platform = cfg.platform;
    g_fake_time = 1000;
    ve_tls_platform plat = cfg.platform;
    plat.time_ms = test_fake_time_ms;
    plat.cond_timedwait_ms = test_fake_cond_timedwait_ms;

    ve_tls_send_queue q;
    memset(&q, 0, sizeof(q));
    if (ve_tls_send_queue_init(&q, &plat, 1, NULL) != 0) return -1;

    ve_tls_send_task t1;
    memset(&t1, 0, sizeof(t1));
    t1.hash_key = ve_tls_strdup("k1");
    t1.body = (unsigned char *)ve_tls_malloc(1);
    if (!t1.hash_key || !t1.body) {
        ve_tls_send_task_free(&t1);
        ve_tls_send_queue_destroy(&q);
        return -1;
    }
    t1.body_size = 1;
    t1.raw_body_size = 1;
    if (ve_tls_send_queue_push(&q, &t1, 0) != 0) {
        ve_tls_send_task_free(&t1);
        ve_tls_send_queue_destroy(&q);
        return -1;
    }
    memset(&t1, 0, sizeof(t1));

    ve_tls_send_task t2;
    memset(&t2, 0, sizeof(t2));
    t2.hash_key = ve_tls_strdup("k2");
    t2.body = (unsigned char *)ve_tls_malloc(1);
    if (!t2.hash_key || !t2.body) {
        ve_tls_send_task_free(&t2);
        ve_tls_send_queue_destroy(&q);
        return -1;
    }
    t2.body_size = 1;
    t2.raw_body_size = 1;
    int rc = ve_tls_send_queue_push(&q, &t2, 5);
    ve_tls_send_task_free(&t2);
    ve_tls_send_queue_destroy(&q);
    return rc == -2 ? 0 : -1;
}

static int test_send_queue_stop_causes_push_pop_fail(void) {
    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    ve_tls_platform plat = cfg.platform;
    ve_tls_send_queue q;
    memset(&q, 0, sizeof(q));
    if (ve_tls_send_queue_init(&q, &plat, 1, NULL) != 0) return -1;
    ve_tls_send_queue_stop(&q);

    ve_tls_send_task t;
    memset(&t, 0, sizeof(t));
    t.hash_key = ve_tls_strdup("k1");
    if (!t.hash_key) {
        ve_tls_send_task_free(&t);
        ve_tls_send_queue_destroy(&q);
        return -1;
    }
    int rc_push = ve_tls_send_queue_push(&q, &t, 0);
    ve_tls_send_task_free(&t);

    ve_tls_send_task out;
    memset(&out, 0, sizeof(out));
    int rc_pop = ve_tls_send_queue_pop(&q, &out, 0);
    ve_tls_send_task_free(&out);
    ve_tls_send_queue_destroy(&q);
    return (rc_push == -1 && rc_pop == -1) ? 0 : -1;
}

static int g_deepcopy_done = 0;
static int g_deepcopy_ok = 0;

static int test_http_assert_proxy_ua_do(ve_tls_http_client * client, const ve_tls_http_request * req, ve_tls_http_response * resp) {
    (void)client;
    if (!req || !resp) {
        return -1;
    }
    g_deepcopy_done = 1;
    if (!req->proxy || strcmp(req->proxy, "http://proxy.example") != 0) {
        g_deepcopy_ok = 0;
    } else if (!req->user_agent || strcmp(req->user_agent, "ua-test") != 0) {
        g_deepcopy_ok = 0;
    } else {
        g_deepcopy_ok = 1;
    }
    resp->status_code = 200;
    resp->request_id = strdup("rid-deepcopy");
    resp->body = NULL;
    resp->body_size = 0;
    return 0;
}

static int test_create_deep_copies_string_fields(void) {
    g_deepcopy_done = 0;
    g_deepcopy_ok = 0;

    ve_tls_config cfg;
    ve_tls_config_init(&cfg);

    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.retry_policy.max_attempts = 1;
    cfg.flush_interval_ms = 0;

    char proxy_buf[64];
    snprintf(proxy_buf, sizeof(proxy_buf), "%s", "http://proxy.example");
    cfg.proxy = proxy_buf;

    char ua_buf[32];
    snprintf(ua_buf, sizeof(ua_buf), "%s", "ua-test");
    cfg.user_agent = ua_buf;

    cfg.http_client.do_request = test_http_assert_proxy_ua_do;
    cfg.http_client.free_response = test_http_free;
    cfg.http_client.user_data = NULL;

    ve_tls_producer * p = ve_tls_producer_create(&cfg);
    if (!p) {
        return -1;
    }

    memset(proxy_buf, 'X', sizeof(proxy_buf));
    memset(ua_buf, 'Y', sizeof(ua_buf));

    ve_tls_kv kvs[1];
    kvs[0].key = "k1";
    kvs[0].value = "v1";
    if (ve_tls_producer_add_log_kv(p, 0, kvs, 1, 1) != VE_TLS_OK) {
        ve_tls_producer_destroy(p);
        return -1;
    }
    for (int i = 0; i < 200 && !g_deepcopy_done; i++) {
        cfg.platform.sleep_ms(10);
    }
    ve_tls_producer_destroy(p);
    return g_deepcopy_ok ? 0 : -1;
}

static int test_export_import_raw_buffer(void) {
    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.retry_policy.max_attempts = 1;
    cfg.flush_interval_ms = 0;

    ve_tls_producer * p = ve_tls_producer_create(&cfg);
    if (!p) {
        return -1;
    }
    ve_tls_kv kvs[1];
    kvs[0].key = "k1";
    kvs[0].value = "v1";
    if (ve_tls_producer_add_log_kv(p, 1710000000000LL, kvs, 1, 0) != VE_TLS_OK) {
        ve_tls_producer_destroy(p);
        return -1;
    }
    if (ve_tls_producer_add_log_kv(p, 1710000000001LL, kvs, 1, 0) != VE_TLS_OK) {
        ve_tls_producer_destroy(p);
        return -1;
    }

    unsigned char * b1 = NULL;
    size_t n1 = 0;
    if (ve_tls_producer_export_raw_buffer(p, &b1, &n1) != VE_TLS_OK || !b1 || n1 == 0) {
        ve_tls_producer_destroy(p);
        return -1;
    }
    ve_tls_producer_destroy(p);

    ve_tls_producer * p2 = ve_tls_producer_create(&cfg);
    if (!p2) {
        ve_tls_producer_free_raw_buffer(b1);
        return -1;
    }
    if (ve_tls_producer_import_raw_buffer(p2, b1, n1) != VE_TLS_OK) {
        ve_tls_producer_free_raw_buffer(b1);
        ve_tls_producer_destroy(p2);
        return -1;
    }
    unsigned char * b2 = NULL;
    size_t n2 = 0;
    if (ve_tls_producer_export_raw_buffer(p2, &b2, &n2) != VE_TLS_OK || !b2 || n2 == 0) {
        ve_tls_producer_free_raw_buffer(b1);
        ve_tls_producer_destroy(p2);
        return -1;
    }
    int ok = (n1 == n2 && memcmp(b1, b2, n1) == 0) ? 0 : -1;
    ve_tls_producer_free_raw_buffer(b1);
    ve_tls_producer_free_raw_buffer(b2);
    ve_tls_producer_destroy(p2);
    return ok;
}

static uint32_t read_u32_le(const unsigned char * p) {
    return (uint32_t)p[0] |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static int mem_has(const unsigned char * hay, size_t hay_len, const unsigned char * needle, size_t needle_len) {
    if (!hay || !needle || needle_len == 0 || hay_len < needle_len) {
        return 0;
    }
    for (size_t i = 0; i + needle_len <= hay_len; i++) {
        if (memcmp(hay + i, needle, needle_len) == 0) {
            return 1;
        }
    }
    return 0;
}

static int test_add_log_with_len_exports_one_record(void) {
    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.retry_policy.max_attempts = 1;
    cfg.flush_interval_ms = 100000;
    cfg.log_count_per_package = 1000000;
    cfg.log_bytes_per_package = 100000000;

    ve_tls_producer * p = ve_tls_producer_create(&cfg);
    if (!p) return -1;

    const unsigned char k_raw[6] = {'K','E','Y','X','X','X'};
    const unsigned char v_raw[7] = {'V','A','L','U','E','Y','Y'};
    const char * keys[1] = {(const char *)k_raw};
    const char * values[1] = {(const char *)v_raw};
    size_t k_lens[1] = {3};
    size_t v_lens[1] = {5};
    if (ve_tls_producer_add_log_with_len(p, 1710000000000LL, keys, k_lens, values, v_lens, 1, 0) != VE_TLS_OK) {
        ve_tls_producer_destroy(p);
        return -1;
    }

    unsigned char * b = NULL;
    size_t n = 0;
    if (ve_tls_producer_export_raw_buffer(p, &b, &n) != VE_TLS_OK || !b || n < 4 + 4 + 4 + 8) {
        ve_tls_producer_destroy(p);
        return -1;
    }
    uint32_t count = read_u32_le(b + 8);
    if (count != 1) {
        ve_tls_producer_free_raw_buffer(b);
        ve_tls_producer_destroy(p);
        return -1;
    }

    size_t off = 4 + 4 + 4 + 8;
    if (n < off + 8 + 8 + 1 + 4 + 4 + 4) {
        ve_tls_producer_free_raw_buffer(b);
        ve_tls_producer_destroy(p);
        return -1;
    }
    off += 8 + 8 + 1 + 4;
    uint32_t hk_len = read_u32_le(b + off);
    off += 4;
    uint32_t data_size = read_u32_le(b + off);
    off += 4;
    if (n < off + (size_t)hk_len + (size_t)data_size) {
        ve_tls_producer_free_raw_buffer(b);
        ve_tls_producer_destroy(p);
        return -1;
    }
    off += (size_t)hk_len;
    const unsigned char * body = b + off;
    size_t body_len = (size_t)data_size;
    const unsigned char k_expect[3] = {'K','E','Y'};
    const unsigned char v_expect[5] = {'V','A','L','U','E'};
    const unsigned char k_full[6] = {'K','E','Y','X','X','X'};
    const unsigned char v_full[7] = {'V','A','L','U','E','Y','Y'};
    int ok = mem_has(body, body_len, k_expect, sizeof(k_expect)) &&
             mem_has(body, body_len, v_expect, sizeof(v_expect)) &&
             !mem_has(body, body_len, k_full, sizeof(k_full)) &&
             !mem_has(body, body_len, v_full, sizeof(v_full));

    ve_tls_producer_free_raw_buffer(b);
    ve_tls_producer_destroy(p);
    return ok ? 0 : -1;
}

static int test_export_raw_buffer_includes_tls_batch_with_len(void) {
    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.retry_policy.max_attempts = 1;
    cfg.flush_interval_ms = 100000;
    cfg.log_count_per_package = 1000000;
    cfg.log_bytes_per_package = 100000000;
    cfg.ordered_send = 0;

    ve_tls_producer * p = ve_tls_producer_create(&cfg);
    if (!p) return -1;

    const unsigned char k_raw[3] = {'a','b','c'};
    const unsigned char v_raw[3] = {'1','2','3'};
    const char * keys[1] = {(const char *)k_raw};
    const char * values[1] = {(const char *)v_raw};
    size_t k_lens[1] = {3};
    size_t v_lens[1] = {3};
    if (ve_tls_producer_add_log_with_len(p, 1710000000000LL, keys, k_lens, values, v_lens, 1, 0) != VE_TLS_OK) {
        ve_tls_producer_destroy(p);
        return -1;
    }

    unsigned char * b = NULL;
    size_t n = 0;
    if (ve_tls_producer_export_raw_buffer(p, &b, &n) != VE_TLS_OK || !b || n < 4 + 4 + 4 + 8) {
        ve_tls_producer_destroy(p);
        return -1;
    }
    uint32_t count = read_u32_le(b + 8);
    ve_tls_producer_free_raw_buffer(b);
    ve_tls_producer_destroy(p);
    return count == 1 ? 0 : -1;
}

static int test_template_lifecycle_and_add_values_exports_one_record(void) {
    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.retry_policy.max_attempts = 1;
    cfg.flush_interval_ms = 100000;
    cfg.log_count_per_package = 1000000;
    cfg.log_bytes_per_package = 100000000;

    ve_tls_producer * p = ve_tls_producer_create(&cfg);
    if (!p) return -1;

    const unsigned char k_raw[6] = {'K','E','Y','X','X','X'};
    const char * keys[1] = {(const char *)k_raw};
    size_t key_lens[1] = {3};
    ve_tls_log_template * tpl = ve_tls_template_create(p, keys, key_lens, 1, NULL);
    if (!tpl) {
        ve_tls_producer_destroy(p);
        return -1;
    }

    const unsigned char v_raw[7] = {'V','A','L','U','E','Y','Y'};
    const char * values[1] = {(const char *)v_raw};
    size_t value_lens[1] = {5};
    if (ve_tls_template_add_values(tpl, 1710000000000LL, 0, 0, values, value_lens, 1, 0) != VE_TLS_OK) {
        ve_tls_template_destroy(tpl);
        ve_tls_producer_destroy(p);
        return -1;
    }

    unsigned char * b = NULL;
    size_t n = 0;
    if (ve_tls_producer_export_raw_buffer(p, &b, &n) != VE_TLS_OK || !b || n < 4 + 4 + 4 + 8) {
        ve_tls_template_destroy(tpl);
        ve_tls_producer_destroy(p);
        return -1;
    }
    uint32_t count = read_u32_le(b + 8);
    if (count != 1) {
        ve_tls_producer_free_raw_buffer(b);
        ve_tls_template_destroy(tpl);
        ve_tls_producer_destroy(p);
        return -1;
    }

    size_t off = 4 + 4 + 4 + 8;
    if (n < off + 8 + 8 + 1 + 4 + 4 + 4) {
        ve_tls_producer_free_raw_buffer(b);
        ve_tls_template_destroy(tpl);
        ve_tls_producer_destroy(p);
        return -1;
    }
    off += 8 + 8 + 1 + 4;
    uint32_t hk_len = read_u32_le(b + off);
    off += 4;
    uint32_t data_size = read_u32_le(b + off);
    off += 4;
    if (n < off + (size_t)hk_len + (size_t)data_size) {
        ve_tls_producer_free_raw_buffer(b);
        ve_tls_template_destroy(tpl);
        ve_tls_producer_destroy(p);
        return -1;
    }
    off += (size_t)hk_len;
    const unsigned char * body = b + off;
    size_t body_len = (size_t)data_size;
    const unsigned char k_expect[3] = {'K','E','Y'};
    const unsigned char v_expect[5] = {'V','A','L','U','E'};
    const unsigned char k_full[6] = {'K','E','Y','X','X','X'};
    const unsigned char v_full[7] = {'V','A','L','U','E','Y','Y'};
    int ok = mem_has(body, body_len, k_expect, sizeof(k_expect)) &&
             mem_has(body, body_len, v_expect, sizeof(v_expect)) &&
             !mem_has(body, body_len, k_full, sizeof(k_full)) &&
             !mem_has(body, body_len, v_full, sizeof(v_full));

    ve_tls_producer_free_raw_buffer(b);
    ve_tls_template_destroy(tpl);
    ve_tls_producer_destroy(p);
    return ok ? 0 : -1;
}

static int test_template_add_values_value_count_mismatch_invalid(void) {
    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.retry_policy.max_attempts = 1;
    cfg.flush_interval_ms = 0;

    ve_tls_producer * p = ve_tls_producer_create(&cfg);
    if (!p) return -1;

    const char * keys[2] = {"k1", "k2"};
    size_t key_lens[2] = {2, 2};
    ve_tls_log_template * tpl = ve_tls_template_create(p, keys, key_lens, 2, NULL);
    if (!tpl) {
        ve_tls_producer_destroy(p);
        return -1;
    }

    const char * values[1] = {"v1"};
    size_t value_lens[1] = {2};
    ve_tls_result rc = ve_tls_template_add_values(tpl, 1710000000000LL, 0, 0, values, value_lens, 1, 0);
    ve_tls_template_destroy(tpl);
    ve_tls_producer_destroy(p);
    return rc == VE_TLS_INVALID ? 0 : -1;
}

static int test_template_high_rate_submit_metrics(void) {
    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.retry_policy.max_attempts = 1;
    cfg.flush_interval_ms = 100000;
    cfg.log_count_per_package = 1000000;
    cfg.log_bytes_per_package = 100000000;

    ve_tls_producer * p = ve_tls_producer_create(&cfg);
    if (!p) return -1;
    const char * keys[2] = {"k1", "k2"};
    size_t key_lens[2] = {2, 2};
    ve_tls_log_template * tpl = ve_tls_template_create(p, keys, key_lens, 2, "hk_tpl");
    if (!tpl) {
        ve_tls_producer_destroy(p);
        return -1;
    }

    for (int i = 0; i < 64; i++) {
        const char * values[2] = {"v1", "v2"};
        size_t value_lens[2] = {2, 2};
        if (ve_tls_template_add_values(tpl, 1710000000000LL + i, 0, 0, values, value_lens, 2, 0) != VE_TLS_OK) {
            ve_tls_template_destroy(tpl);
            ve_tls_producer_destroy(p);
            return -1;
        }
    }

    ve_tls_metrics m;
    ve_tls_producer_get_metrics(p, &m);
    ve_tls_template_destroy(tpl);
    ve_tls_producer_destroy(p);
    return (m.logs_enqueued_total >= 64 && m.logs_dropped_total == 0) ? 0 : -1;
}

static int test_import_raw_buffer_invalid_magic(void) {
    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.retry_policy.max_attempts = 1;
    cfg.flush_interval_ms = 0;
    ve_tls_producer * p = ve_tls_producer_create(&cfg);
    if (!p) return -1;
    const unsigned char bad[4 + 4 + 4 + 8] = {'B','A','D','!', 0,0,0,0, 0,0,0,0, 0,0,0,0,0,0,0,0};
    ve_tls_result rc = ve_tls_producer_import_raw_buffer(p, bad, sizeof(bad));
    ve_tls_producer_destroy(p);
    return rc == VE_TLS_INVALID ? 0 : -1;
}

static int test_import_raw_buffer_truncated_invalid(void) {
    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.retry_policy.max_attempts = 1;
    cfg.flush_interval_ms = 0;
    ve_tls_producer * p = ve_tls_producer_create(&cfg);
    if (!p) return -1;
    ve_tls_kv kvs[1];
    kvs[0].key = "k1";
    kvs[0].value = "v1";
    if (ve_tls_producer_add_log_kv(p, 1710000000000LL, kvs, 1, 0) != VE_TLS_OK) {
        ve_tls_producer_destroy(p);
        return -1;
    }
    unsigned char * b = NULL;
    size_t n = 0;
    if (ve_tls_producer_export_raw_buffer(p, &b, &n) != VE_TLS_OK || !b || n < 4 + 4 + 4 + 8 + 8) {
        ve_tls_producer_destroy(p);
        return -1;
    }
    ve_tls_producer_destroy(p);

    ve_tls_producer * p2 = ve_tls_producer_create(&cfg);
    if (!p2) {
        ve_tls_producer_free_raw_buffer(b);
        return -1;
    }
    ve_tls_result rc = ve_tls_producer_import_raw_buffer(p2, b, n - 1);
    ve_tls_producer_free_raw_buffer(b);
    ve_tls_producer_destroy(p2);
    return rc == VE_TLS_INVALID ? 0 : -1;
}

static int test_import_raw_buffer_exceeds_max_buffer_bytes_drop(void) {
    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.retry_policy.max_attempts = 1;
    cfg.flush_interval_ms = 0;
    ve_tls_producer * p = ve_tls_producer_create(&cfg);
    if (!p) return -1;
    char bigv[256];
    memset(bigv, 'A', sizeof(bigv) - 1);
    bigv[sizeof(bigv) - 1] = 0;
    ve_tls_kv kvs[1];
    kvs[0].key = "k1";
    kvs[0].value = bigv;
    if (ve_tls_producer_add_log_kv(p, 1710000000000LL, kvs, 1, 0) != VE_TLS_OK) {
        ve_tls_producer_destroy(p);
        return -1;
    }
    unsigned char * b = NULL;
    size_t n = 0;
    if (ve_tls_producer_export_raw_buffer(p, &b, &n) != VE_TLS_OK || !b || n == 0) {
        ve_tls_producer_destroy(p);
        return -1;
    }
    ve_tls_producer_destroy(p);

    ve_tls_config cfg2 = cfg;
    cfg2.max_buffer_bytes = 1;
    ve_tls_producer * p2 = ve_tls_producer_create(&cfg2);
    if (!p2) {
        ve_tls_producer_free_raw_buffer(b);
        return -1;
    }
    ve_tls_result rc = ve_tls_producer_import_raw_buffer(p2, b, n);
    ve_tls_producer_free_raw_buffer(b);
    ve_tls_producer_destroy(p2);
    return rc == VE_TLS_DROP_ERROR ? 0 : -1;
}

static int test_import_raw_buffer_hash_key_ok(void) {
    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.retry_policy.max_attempts = 1;
    cfg.flush_interval_ms = 0;
    ve_tls_producer * p = ve_tls_producer_create(&cfg);
    if (!p) return -1;
    ve_tls_kv kvs[1];
    kvs[0].key = "k1";
    kvs[0].value = "v1";
    if (ve_tls_producer_add_log_kv_hashkey(p, 1710000000000LL, "hk1", kvs, 1, 0) != VE_TLS_OK) {
        ve_tls_producer_destroy(p);
        return -1;
    }
    unsigned char * b = NULL;
    size_t n = 0;
    if (ve_tls_producer_export_raw_buffer(p, &b, &n) != VE_TLS_OK || !b || n == 0) {
        ve_tls_producer_destroy(p);
        return -1;
    }
    ve_tls_producer_destroy(p);

    ve_tls_producer * p2 = ve_tls_producer_create(&cfg);
    if (!p2) {
        ve_tls_producer_free_raw_buffer(b);
        return -1;
    }
    ve_tls_result rc = ve_tls_producer_import_raw_buffer(p2, b, n);
    ve_tls_producer_free_raw_buffer(b);
    ve_tls_producer_destroy(p2);
    return rc == VE_TLS_OK ? 0 : -1;
}

static int test_producer_close_timeout_zero_returns_timeout(void) {
    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.retry_policy.max_attempts = 1;
    cfg.flush_interval_ms = 0;
    cfg.log_count_per_package = 1;
    cfg.send_queue_size = 1;
    cfg.send_queue_full_policy = VE_TLS_SEND_QUEUE_FULL_BLOCK;
    cfg.send_queue_block_timeout_ms = 1;
    cfg.http_client.do_request = test_http_slow_ok_do;
    cfg.http_client.free_response = test_http_free;
    cfg.http_client.user_data = &cfg.platform;

    ve_tls_producer * p = ve_tls_producer_create(&cfg);
    if (!p) return -1;
    ve_tls_kv kvs[1];
    kvs[0].key = "k1";
    kvs[0].value = "v1";
    if (ve_tls_producer_add_log_kv(p, 0, kvs, 1, 1) != VE_TLS_OK) {
        ve_tls_producer_destroy(p);
        return -1;
    }
    ve_tls_result rc = ve_tls_producer_close(p, 0);
    ve_tls_producer_destroy(p);
    return rc == VE_TLS_TIMEOUT ? 0 : -1;
}

static int test_producer_update_invalid_and_closed(void) {
    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.retry_policy.max_attempts = 1;
    cfg.flush_interval_ms = 0;
    ve_tls_producer * p = ve_tls_producer_create(&cfg);
    if (!p) return -1;

    if (ve_tls_producer_update_endpoint(p, "ftp://bad", "cn-beijing", "t") != VE_TLS_INVALID) {
        ve_tls_producer_destroy(p);
        return -1;
    }
    if (ve_tls_producer_update_static_credentials(p, "ak2", NULL, NULL) != VE_TLS_INVALID) {
        ve_tls_producer_destroy(p);
        return -1;
    }

    (void)ve_tls_producer_close(p, 0);
    if (ve_tls_producer_update_endpoint(p, "https://new.example.com", "cn-beijing", "t2") != VE_TLS_CLOSED) {
        ve_tls_producer_destroy(p);
        return -1;
    }
    if (ve_tls_producer_update_static_credentials(p, "ak2", "sk2", NULL) != VE_TLS_CLOSED) {
        ve_tls_producer_destroy(p);
        return -1;
    }
    ve_tls_producer_destroy(p);
    return 0;
}

static int test_time_parts_roundtrip_in_raw_buffer(void) {
    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.retry_policy.max_attempts = 1;
    cfg.flush_interval_ms = 0;
    cfg.enable_time_ns = 1;
    cfg.platform.time_ms = NULL;
    cfg.platform.time_unix_ns = NULL;

    ve_tls_producer * p = ve_tls_producer_create(&cfg);
    if (!p) {
        return -1;
    }
    ve_tls_kv kvs[1];
    kvs[0].key = "k1";
    kvs[0].value = "v1";
    if (ve_tls_producer_add_log_kv_time_parts(p, 1710000000000LL, 1, 123456, kvs, 1, 0) != VE_TLS_OK) {
        ve_tls_producer_destroy(p);
        return -1;
    }
    unsigned char * b = NULL;
    size_t n = 0;
    if (ve_tls_producer_export_raw_buffer(p, &b, &n) != VE_TLS_OK || !b || n == 0) {
        ve_tls_producer_destroy(p);
        return -1;
    }
    int ok = 0;
    size_t off = 0;
    if (n >= 4 + 4 + 4 + 8) {
        off = 4 + 4 + 4 + 8;
        if (off + 8 + 8 + 1 + 4 <= n) {
            off += 8;
            uint64_t tm = 0;
            for (int i = 0; i < 8; i++) {
                tm |= ((uint64_t)b[off + i]) << (8 * i);
            }
            off += 8;
            unsigned char has = b[off++];
            uint32_t ns = 0;
            for (int i = 0; i < 4; i++) {
                ns |= ((uint32_t)b[off + i]) << (8 * i);
            }
            ok = (tm == (uint64_t)1710000000000LL && has == 1 && ns == 123456) ? 1 : 0;
        }
    }
    ve_tls_producer_free_raw_buffer(b);
    ve_tls_producer_destroy(p);
    return ok ? 0 : -1;
}

static int64_t stub_time_ms(void) { return 0; }
static int64_t stub_time_unix_ns(void) { return 1710000000000LL * 1000000LL + 654321; }

static double fixed_rand01(void * p) {
    (void)p;
    return 0.0;
}

static int test_auto_time_ns_when_time_missing(void) {
    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.retry_policy.max_attempts = 1;
    cfg.flush_interval_ms = 0;
    cfg.enable_time_ns = 1;
    cfg.platform.time_ms = stub_time_ms;
    cfg.platform.time_unix_ns = stub_time_unix_ns;

    ve_tls_producer * p = ve_tls_producer_create(&cfg);
    if (!p) {
        return -1;
    }
    ve_tls_kv kvs[1];
    kvs[0].key = "k1";
    kvs[0].value = "v1";
    if (ve_tls_producer_add_log_kv_time_parts(p, 0, 0, 0, kvs, 1, 0) != VE_TLS_OK) {
        ve_tls_producer_destroy(p);
        return -1;
    }
    unsigned char * b = NULL;
    size_t n = 0;
    if (ve_tls_producer_export_raw_buffer(p, &b, &n) != VE_TLS_OK || !b || n == 0) {
        ve_tls_producer_destroy(p);
        return -1;
    }
    int ok = 0;
    size_t off = 4 + 4 + 4 + 8 + 8;
    if (n >= off + 8 + 1 + 4) {
        uint64_t tm = 0;
        for (int i = 0; i < 8; i++) {
            tm |= ((uint64_t)b[off + i]) << (8 * i);
        }
        off += 8;
        unsigned char has = b[off++];
        uint32_t ns = 0;
        for (int i = 0; i < 4; i++) {
            ns |= ((uint32_t)b[off + i]) << (8 * i);
        }
        ok = (tm == (uint64_t)1710000000000LL && has == 1 && ns == 654321) ? 1 : 0;
    }
    ve_tls_producer_free_raw_buffer(b);
    ve_tls_producer_destroy(p);
    return ok ? 0 : -1;
}

static int test_retry_jitter_rand01_injectable(void) {
    ve_tls_retry_policy rp;
    ve_tls_retry_policy_init(&rp);
    rp.initial_interval_ms = 1000;
    rp.max_interval_ms = 1000;
    rp.randomization_factor = 0.2;
    rp.rand01 = fixed_rand01;
    rp.rand01_param = NULL;
    int64_t v = ve_tls_retry_next_interval_ms(&rp, 1);
    return v == 800 ? 0 : -1;
}

static int g_metrics_done = 0;
static int g_metrics_ok = 0;
static int g_metrics_latency_events = 0;

static void metrics_sink_emit(const char * name, int64_t v1, int64_t v2, void * user_param) {
    (void)v1;
    (void)v2;
    if (!name || !user_param) {
        return;
    }
    int * p = (int *)user_param;
    if (strcmp(name, "request_latency_ms") == 0) {
        (*p)++;
    }
}

static int test_http_ok_do(ve_tls_http_client * client, const ve_tls_http_request * req, ve_tls_http_response * resp) {
    (void)client;
    (void)req;
    if (!resp) {
        return -1;
    }
    resp->status_code = 200;
    resp->request_id = strdup("rid-ok");
    resp->body = NULL;
    resp->body_size = 0;
    return 0;
}

static void test_http_ok_free(ve_tls_http_client * client, ve_tls_http_response * resp) {
    (void)client;
    if (!resp) {
        return;
    }
    free(resp->body);
    free(resp->request_id);
    free(resp->error_code);
    free(resp->error_message);
    resp->body = NULL;
    resp->request_id = NULL;
    resp->error_code = NULL;
    resp->error_message = NULL;
}

typedef struct {
    ve_tls_platform * platform;
    int32_t sleep_ms;
} close_http_state;

static int test_http_sleep_ok_do(ve_tls_http_client * client, const ve_tls_http_request * req, ve_tls_http_response * resp) {
    (void)req;
    if (!client || !resp) {
        return -1;
    }
    close_http_state * s = (close_http_state *)client->user_data;
    if (s && s->platform && s->sleep_ms > 0) {
        s->platform->sleep_ms(s->sleep_ms);
    }
    resp->status_code = 200;
    resp->request_id = strdup("rid-sleep-ok");
    resp->body = NULL;
    resp->body_size = 0;
    return 0;
}

static int cred_provider(ve_tls_credentials * out, void * user_param) {
    (void)user_param;
    if (!out || !g_cred_state.platform) {
        return -1;
    }
    g_cred_provider_calls++;
    if (g_cred_state.fail_after > 0 && g_cred_provider_calls > g_cred_state.fail_after) {
        return -1;
    }
    out->access_key_id = "ak";
    out->access_key_secret = "sk";
    if (g_cred_provider_calls == 1) {
        out->security_token = "tok1";
    } else {
        out->security_token = "tok2";
    }
    out->expire_time_ms = g_cred_state.platform->time_ms() + 10;
    return 0;
}

typedef struct {
    ve_tls_producer * p;
    int32_t timeout_ms;
    ve_tls_result rc;
} close_arg;

static void * close_thread(void * arg) {
    close_arg * a = (close_arg *)arg;
    a->rc = ve_tls_producer_close(a->p, a->timeout_ms);
    return NULL;
}

static int test_graceful_close_ok(void) {
    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.retry_policy.max_attempts = 1;
    cfg.flush_interval_ms = 0;
    cfg.send_queue_full_policy = VE_TLS_SEND_QUEUE_FULL_BLOCK;
    cfg.send_queue_block_timeout_ms = 1000;
    cfg.http_client.do_request = test_http_ok_do;
    cfg.http_client.free_response = test_http_ok_free;

    ve_tls_producer * p = ve_tls_producer_create(&cfg);
    if (!p) {
        return -1;
    }
    ve_tls_kv kvs[1];
    kvs[0].key = "k1";
    kvs[0].value = "v1";
    if (ve_tls_producer_add_log_kv(p, 0, kvs, 1, 1) != VE_TLS_OK) {
        ve_tls_producer_destroy(p);
        return -1;
    }
    ve_tls_result rc = ve_tls_producer_close(p, 2000);
    ve_tls_producer_destroy(p);
    return rc == VE_TLS_OK ? 0 : -1;
}

static int test_graceful_close_timeout(void) {
    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.retry_policy.max_attempts = 1;
    cfg.flush_interval_ms = 0;
    cfg.send_queue_full_policy = VE_TLS_SEND_QUEUE_FULL_BLOCK;
    cfg.send_queue_block_timeout_ms = 0;

    close_http_state s;
    memset(&s, 0, sizeof(s));
    s.platform = &cfg.platform;
    s.sleep_ms = 200;
    cfg.http_client.do_request = test_http_sleep_ok_do;
    cfg.http_client.free_response = test_http_ok_free;
    cfg.http_client.user_data = &s;

    ve_tls_producer * p = ve_tls_producer_create(&cfg);
    if (!p) {
        return -1;
    }
    ve_tls_kv kvs[1];
    kvs[0].key = "k1";
    kvs[0].value = "v1";
    if (ve_tls_producer_add_log_kv(p, 0, kvs, 1, 1) != VE_TLS_OK) {
        ve_tls_producer_destroy(p);
        return -1;
    }
    cfg.platform.sleep_ms(10);
    ve_tls_result rc = ve_tls_producer_close(p, 1);
    ve_tls_producer_destroy(p);
    return rc == VE_TLS_TIMEOUT ? 0 : -1;
}

static int test_close_rejects_new_writes(void) {
    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.retry_policy.max_attempts = 1;
    cfg.flush_interval_ms = 0;
    cfg.send_queue_full_policy = VE_TLS_SEND_QUEUE_FULL_BLOCK;
    cfg.send_queue_block_timeout_ms = 0;

    close_http_state s;
    memset(&s, 0, sizeof(s));
    s.platform = &cfg.platform;
    s.sleep_ms = 300;
    cfg.http_client.do_request = test_http_sleep_ok_do;
    cfg.http_client.free_response = test_http_ok_free;
    cfg.http_client.user_data = &s;

    ve_tls_producer * p = ve_tls_producer_create(&cfg);
    if (!p) {
        return -1;
    }
    ve_tls_kv kvs[1];
    kvs[0].key = "k1";
    kvs[0].value = "v1";
    if (ve_tls_producer_add_log_kv(p, 0, kvs, 1, 1) != VE_TLS_OK) {
        ve_tls_producer_destroy(p);
        return -1;
    }

    close_arg a;
    memset(&a, 0, sizeof(a));
    a.p = p;
    a.timeout_ms = 2000;
    ve_tls_thread * th = cfg.platform.thread_create(close_thread, &a);
    if (!th) {
        ve_tls_producer_destroy(p);
        return -1;
    }

    cfg.platform.sleep_ms(10);
    ve_tls_result add_rc = ve_tls_producer_add_log_kv(p, 0, kvs, 1, 0);
    cfg.platform.thread_join(th);
    if (add_rc != VE_TLS_CLOSED) {
        ve_tls_producer_destroy(p);
        return -1;
    }
    ve_tls_producer_destroy(p);
    return a.rc == VE_TLS_OK ? 0 : -1;
}

static int g_update_called = 0;
static char g_update_seen_url[256];
static char g_update_seen_ak[128];

static int test_http_capture_url_and_ak_do(ve_tls_http_client * client, const ve_tls_http_request * req, ve_tls_http_response * resp) {
    (void)client;
    if (!req || !resp) {
        return -1;
    }
    g_update_called++;
    if (req->url) {
        snprintf(g_update_seen_url, sizeof(g_update_seen_url), "%s", req->url);
    } else {
        g_update_seen_url[0] = 0;
    }
    g_update_seen_ak[0] = 0;
    if (req->headers) {
        const char * p = strstr(req->headers, "Credential=");
        if (p) {
            p += strlen("Credential=");
            const char * end = strchr(p, '/');
            size_t n = end ? (size_t)(end - p) : strlen(p);
            if (n >= sizeof(g_update_seen_ak)) n = sizeof(g_update_seen_ak) - 1;
            memcpy(g_update_seen_ak, p, n);
            g_update_seen_ak[n] = 0;
        }
    }
    resp->status_code = 200;
    resp->request_id = strdup("rid-update");
    resp->body = NULL;
    resp->body_size = 0;
    return 0;
}

static int test_create_fail_fast_missing_required(void) {
    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    cfg.endpoint = NULL;
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    ve_tls_producer * p = ve_tls_producer_create(&cfg);
    if (p) {
        ve_tls_producer_destroy(p);
        return -1;
    }
    return 0;
}

static int test_runtime_config_update_effective_for_new_requests(void) {
    g_update_called = 0;
    g_update_seen_url[0] = 0;
    g_update_seen_ak[0] = 0;

    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    cfg.endpoint = "https://old.example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "old-topic";
    cfg.access_key_id = "ak1";
    cfg.access_key_secret = "sk1";
    cfg.retry_policy.max_attempts = 1;
    cfg.flush_interval_ms = 0;
    cfg.http_client.do_request = test_http_capture_url_and_ak_do;
    cfg.http_client.free_response = test_http_ok_free;
    cfg.http_client.user_data = NULL;

    ve_tls_producer * p = ve_tls_producer_create(&cfg);
    if (!p) {
        return -1;
    }
    if (ve_tls_producer_update_endpoint(p, "https://new.example.com", "cn-beijing", "new-topic") != VE_TLS_OK) {
        ve_tls_producer_destroy(p);
        return -1;
    }
    if (ve_tls_producer_update_static_credentials(p, "ak2", "sk2", "") != VE_TLS_OK) {
        ve_tls_producer_destroy(p);
        return -1;
    }

    ve_tls_kv kvs[1];
    kvs[0].key = "k";
    kvs[0].value = "v";
    if (ve_tls_producer_add_log_kv(p, 0, kvs, 1, 1) != VE_TLS_OK) {
        ve_tls_producer_destroy(p);
        return -1;
    }
    for (int i = 0; i < 200 && g_update_called == 0; i++) {
        cfg.platform.sleep_ms(10);
    }
    int ok = 0;
    if (g_update_called > 0 && strstr(g_update_seen_url, "https://new.example.com") != NULL && strcmp(g_update_seen_ak, "ak2") == 0) {
        ok = 1;
    }
    ve_tls_producer_destroy(p);
    return ok ? 0 : -1;
}

static int test_runtime_snapshot_reflects_runtime_updates(void) {
    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    cfg.endpoint = "https://old.example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "old-topic";
    cfg.access_key_id = "ak1";
    cfg.access_key_secret = "sk1";
    cfg.retry_policy.max_attempts = 1;
    cfg.flush_interval_ms = 0;
    cfg.http_client.do_request = test_http_capture_url_and_ak_do;
    cfg.http_client.free_response = test_http_ok_free;

    ve_tls_producer * p = ve_tls_producer_create(&cfg);
    if (!p) {
        return -1;
    }
    if (ve_tls_runtime_snapshot_refresh(p) != 0) {
        ve_tls_producer_destroy(p);
        return -1;
    }

    const ve_tls_runtime_snapshot * s1 = ve_tls_runtime_snapshot_acquire(p);
    if (!s1) {
        ve_tls_producer_destroy(p);
        return -1;
    }
    if (!s1->endpoint || strcmp(s1->endpoint, "https://old.example.com") != 0) {
        ve_tls_runtime_snapshot_release(s1);
        ve_tls_producer_destroy(p);
        return -1;
    }
    if (!s1->access_key_id || strcmp(s1->access_key_id, "ak1") != 0) {
        ve_tls_runtime_snapshot_release(s1);
        ve_tls_producer_destroy(p);
        return -1;
    }
    ve_tls_runtime_snapshot_release(s1);

    if (ve_tls_producer_update_endpoint(p, "https://new.example.com", "cn-beijing", "new-topic") != VE_TLS_OK) {
        ve_tls_producer_destroy(p);
        return -1;
    }
    if (ve_tls_producer_update_static_credentials(p, "ak2", "sk2", NULL) != VE_TLS_OK) {
        ve_tls_producer_destroy(p);
        return -1;
    }

    const ve_tls_runtime_snapshot * s2 = ve_tls_runtime_snapshot_acquire(p);
    if (!s2) {
        ve_tls_producer_destroy(p);
        return -1;
    }
    int ok = (s2->endpoint && strcmp(s2->endpoint, "https://new.example.com") == 0 &&
              s2->topic_id && strcmp(s2->topic_id, "new-topic") == 0 &&
              s2->access_key_id && strcmp(s2->access_key_id, "ak2") == 0);
    ve_tls_runtime_snapshot_release(s2);
    ve_tls_producer_destroy(p);
    return ok ? 0 : -1;
}

static int test_obj_pool_reuses_recent_item(void) {
    ve_tls_obj_pool pool;
    if (ve_tls_obj_pool_init(&pool, 64, 8) != 0) {
        return -1;
    }
    void * p1 = ve_tls_obj_pool_get(&pool);
    if (!p1) {
        ve_tls_obj_pool_destroy(&pool);
        return -1;
    }
    memset(p1, 0xAB, 64);
    ve_tls_obj_pool_put(&pool, p1);
    if (ve_tls_obj_pool_cached(&pool) != 1) {
        ve_tls_obj_pool_destroy(&pool);
        return -1;
    }
    void * p2 = ve_tls_obj_pool_get(&pool);
    if (!p2) {
        ve_tls_obj_pool_destroy(&pool);
        return -1;
    }
    int ok = (p2 == p1);
    ve_tls_obj_pool_put(&pool, p2);
    ve_tls_obj_pool_destroy(&pool);
    return ok ? 0 : -1;
}

static int test_runtime_update_rejected_during_close(void) {
    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.retry_policy.max_attempts = 1;
    cfg.flush_interval_ms = 0;

    close_http_state s;
    memset(&s, 0, sizeof(s));
    s.platform = &cfg.platform;
    s.sleep_ms = 300;
    cfg.http_client.do_request = test_http_sleep_ok_do;
    cfg.http_client.free_response = test_http_ok_free;
    cfg.http_client.user_data = &s;

    ve_tls_producer * p = ve_tls_producer_create(&cfg);
    if (!p) {
        return -1;
    }
    ve_tls_kv kvs[1];
    kvs[0].key = "k";
    kvs[0].value = "v";
    if (ve_tls_producer_add_log_kv(p, 0, kvs, 1, 1) != VE_TLS_OK) {
        ve_tls_producer_destroy(p);
        return -1;
    }

    close_arg a;
    memset(&a, 0, sizeof(a));
    a.p = p;
    a.timeout_ms = 2000;
    ve_tls_thread * th = cfg.platform.thread_create(close_thread, &a);
    if (!th) {
        ve_tls_producer_destroy(p);
        return -1;
    }
    cfg.platform.sleep_ms(10);
    ve_tls_result rc = ve_tls_producer_update_endpoint(p, "https://new.example.com", NULL, NULL);
    cfg.platform.thread_join(th);
    ve_tls_producer_destroy(p);
    return rc == VE_TLS_CLOSED ? 0 : -1;
}

static int test_http_capture_token_do(ve_tls_http_client * client, const ve_tls_http_request * req, ve_tls_http_response * resp) {
    (void)client;
    if (!req || !resp || !req->headers) {
        return -1;
    }
    int idx = g_cred_req++;
    const char * p = strstr(req->headers, "X-Security-Token:");
    if (!p) {
        p = strstr(req->headers, "x-security-token:");
    }
    if (!p) {
        fprintf(stderr, "missing security token header in request %d:\n%s\n", idx, req->headers);
    }
    if (p) {
        if (p[0] == 'X') {
            p += strlen("X-Security-Token:");
        } else {
            p += strlen("x-security-token:");
        }
        while (*p == ' ') {
            p++;
        }
        const char * end = strchr(p, '\n');
        size_t n = end ? (size_t)(end - p) : strlen(p);
        while (n > 0 && (p[n - 1] == '\r' || p[n - 1] == ' ')) {
            n--;
        }
        if (idx == 0) {
            size_t m = n < sizeof(g_cred_seen_1) - 1 ? n : (sizeof(g_cred_seen_1) - 1);
            memcpy(g_cred_seen_1, p, m);
            g_cred_seen_1[m] = 0;
        } else if (idx == 1) {
            size_t m = n < sizeof(g_cred_seen_2) - 1 ? n : (sizeof(g_cred_seen_2) - 1);
            memcpy(g_cred_seen_2, p, m);
            g_cred_seen_2[m] = 0;
        }
    }
    resp->status_code = 200;
    resp->request_id = strdup("rid-cred");
    resp->body = NULL;
    resp->body_size = 0;
    return 0;
}

static void on_send_done_cred(
    ve_tls_result result,
    size_t log_bytes,
    size_t compressed_bytes,
    const ve_tls_error * error,
    const unsigned char * raw_buffer,
    void * user_param,
    int64_t start_id,
    int64_t end_id
) {
    (void)result;
    (void)log_bytes;
    (void)compressed_bytes;
    (void)error;
    (void)raw_buffer;
    (void)user_param;
    (void)start_id;
    (void)end_id;
    g_cred_cb++;
    g_cred_done = 1;
}

static void on_send_done_metrics(
    ve_tls_result result,
    size_t log_bytes,
    size_t compressed_bytes,
    const ve_tls_error * error,
    const unsigned char * raw_buffer,
    void * user_param,
    int64_t start_id,
    int64_t end_id
) {
    (void)log_bytes;
    (void)compressed_bytes;
    (void)raw_buffer;
    (void)user_param;
    (void)start_id;
    (void)end_id;
    g_metrics_done = 1;
    if (result != VE_TLS_OK || !error) {
        g_metrics_ok = 0;
        return;
    }
    g_metrics_ok = 1;
}

static int test_metrics_basic(void) {
    g_metrics_done = 0;
    g_metrics_ok = 0;
    g_metrics_latency_events = 0;

    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.compress_type = "none";
    cfg.flush_interval_ms = 10;
    cfg.send_thread_count = 2;
    cfg.retry_policy.max_attempts = 1;
    cfg.metrics_sink.emit = metrics_sink_emit;
    cfg.metrics_sink.user_param = &g_metrics_latency_events;
    cfg.http_client.do_request = test_http_ok_do;
    cfg.http_client.free_response = test_http_ok_free;
    cfg.http_client.user_data = NULL;

    ve_tls_producer * p = ve_tls_producer_create(&cfg);
    if (!p) {
        return -1;
    }
    ve_tls_producer_set_send_done_v2(p, on_send_done_metrics, NULL);

    ve_tls_kv kvs[1];
    kvs[0].key = "k1";
    kvs[0].value = "v1";
    if (ve_tls_producer_add_log_kv(p, 0, kvs, 1, 1) != VE_TLS_OK) {
        ve_tls_producer_destroy(p);
        return -1;
    }

    for (int i = 0; i < 200 && !g_metrics_done; i++) {
        cfg.platform.sleep_ms(10);
    }
    if (!g_metrics_ok) {
        ve_tls_producer_destroy(p);
        return -1;
    }
    ve_tls_metrics m;
    ve_tls_producer_get_metrics(p, &m);
    ve_tls_producer_destroy(p);
    if (m.logs_enqueued_total < 1 || m.batches_built_total < 1 || m.requests_total < 1) {
        return -1;
    }
    if (m.bytes_sent_total == 0) {
        return -1;
    }
    if (g_metrics_latency_events <= 0) {
        return -1;
    }
    return 0;
}

static int g_order_done = 0;
static int g_order_cb = 0;
static int g_order_cur = 0;
static int g_order_max = 0;

typedef struct {
    ve_tls_platform * platform;
    int count;
    int64_t t[2];
} rl_state;

static rl_state g_rl_state;

static int test_rl_do(ve_tls_http_client * client, const ve_tls_http_request * req, ve_tls_http_response * resp) {
    (void)req;
    if (!client || !resp) {
        return -1;
    }
    rl_state * s = (rl_state *)client->user_data;
    if (s && s->platform && s->count < 2) {
        s->t[s->count] = s->platform->time_ms();
    }
    if (s) {
        s->count++;
    }
    resp->status_code = 200;
    resp->request_id = strdup("rid-ok");
    return 0;
}

static void test_rl_free(ve_tls_http_client * client, ve_tls_http_response * resp) {
    (void)client;
    if (!resp) {
        return;
    }
    free(resp->body);
    free(resp->request_id);
    free(resp->error_code);
    free(resp->error_message);
    resp->body = NULL;
    resp->request_id = NULL;
    resp->error_code = NULL;
    resp->error_message = NULL;
}

typedef struct {
    ve_tls_send_queue * q;
    ve_tls_platform * platform;
} pop_arg;

static void * pop_after_sleep(void * arg) {
    pop_arg * a = (pop_arg *)arg;
    a->platform->sleep_ms(50);
    ve_tls_send_task out;
    memset(&out, 0, sizeof(out));
    (void)ve_tls_send_queue_pop(a->q, &out, -1);
    ve_tls_send_task_free(&out);
    return NULL;
}

static int test_send_queue_blocking_push(void) {
    ve_tls_platform platform;
    ve_tls_platform_init_default(&platform);

    ve_tls_send_queue q;
    if (ve_tls_send_queue_init(&q, &platform, 1, NULL) != 0) {
        return -1;
    }

    ve_tls_send_task t1;
    memset(&t1, 0, sizeof(t1));
    t1.body = (unsigned char *)strdup("a");
    t1.body_size = 1;
    t1.raw_body_size = 1;
    t1.batch_bytes = 1;
    t1.start_id = 1;
    t1.end_id = 1;
    if (ve_tls_send_queue_push(&q, &t1, 0) != 0) {
        ve_tls_send_task_free(&t1);
        ve_tls_send_queue_destroy(&q);
        return -1;
    }

    pop_arg a;
    a.q = &q;
    a.platform = &platform;
    ve_tls_thread * th = platform.thread_create(pop_after_sleep, &a);
    if (!th) {
        ve_tls_send_queue_destroy(&q);
        return -1;
    }

    ve_tls_send_task t2;
    memset(&t2, 0, sizeof(t2));
    t2.body = (unsigned char *)strdup("b");
    t2.body_size = 1;
    t2.raw_body_size = 1;
    t2.batch_bytes = 1;
    t2.start_id = 2;
    t2.end_id = 2;
    int rc = ve_tls_send_queue_push(&q, &t2, 200);
    if (rc != 0) {
        ve_tls_send_task_free(&t2);
        platform.thread_join(th);
        ve_tls_send_queue_destroy(&q);
        return -1;
    }

    platform.thread_join(th);

    ve_tls_send_task out2;
    memset(&out2, 0, sizeof(out2));
    if (ve_tls_send_queue_pop(&q, &out2, 0) != 0) {
        ve_tls_send_queue_destroy(&q);
        return -1;
    }
    ve_tls_send_task_free(&out2);

    ve_tls_send_task t3;
    memset(&t3, 0, sizeof(t3));
    t3.body = (unsigned char *)strdup("c");
    t3.body_size = 1;
    t3.raw_body_size = 1;
    t3.batch_bytes = 1;
    t3.start_id = 3;
    t3.end_id = 3;
    if (ve_tls_send_queue_push(&q, &t3, 0) != 0) {
        ve_tls_send_task_free(&t3);
        ve_tls_send_queue_destroy(&q);
        return -1;
    }

    ve_tls_send_task t4;
    memset(&t4, 0, sizeof(t4));
    t4.body = (unsigned char *)strdup("d");
    t4.body_size = 1;
    t4.raw_body_size = 1;
    t4.batch_bytes = 1;
    t4.start_id = 4;
    t4.end_id = 4;
    int rc2 = ve_tls_send_queue_push(&q, &t4, 30);
    if (rc2 != -2) {
        if (rc2 == 0) {
            ve_tls_send_task out4;
            memset(&out4, 0, sizeof(out4));
            (void)ve_tls_send_queue_pop(&q, &out4, 0);
            ve_tls_send_task_free(&out4);
        } else {
            ve_tls_send_task_free(&t4);
        }
        ve_tls_send_queue_destroy(&q);
        return -1;
    }
    ve_tls_send_task_free(&t4);

    ve_tls_send_queue_destroy(&q);
    return 0;
}

static int test_dynamic_credentials_refreshes_token(void) {
    g_cred_done = 0;
    g_cred_cb = 0;
    g_cred_req = 0;
    g_cred_provider_calls = 0;
    memset(g_cred_seen_1, 0, sizeof(g_cred_seen_1));
    memset(g_cred_seen_2, 0, sizeof(g_cred_seen_2));

    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    cfg.endpoint = "https://tls.example.com";
    cfg.region = "cn-test";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak0";
    cfg.access_key_secret = "sk0";
    cfg.security_token = NULL;
    cfg.credentials_provider = cred_provider;
    cfg.credentials_provider_param = NULL;
    cfg.credentials_expire_advance_ms = 0;
    cfg.credentials_refresh_min_interval_ms = 0;
    cfg.send_thread_count = 1;
    cfg.send_queue_size = 8;
    cfg.flush_interval_ms = 0;
    cfg.http_client.do_request = test_http_capture_token_do;
    cfg.http_client.free_response = test_http_ok_free;
    cfg.metrics_sink.emit = NULL;

    g_cred_state.platform = &cfg.platform;
    g_cred_state.fail_after = 0;

    ve_tls_producer * p = ve_tls_producer_create(&cfg);
    if (!p) {
        return 1;
    }
    ve_tls_producer_set_send_done_v2(p, on_send_done_cred, NULL);

    ve_tls_kv kv;
    kv.key = "k";
    kv.value = "v";
    if (ve_tls_producer_add_log_kv(p, 0, &kv, 1, 1) != VE_TLS_OK) {
        ve_tls_producer_destroy(p);
        return 2;
    }
    for (int i = 0; i < 200 && g_cred_cb < 1; i++) {
        cfg.platform.sleep_ms(10);
    }
    if (g_cred_cb < 1) {
        ve_tls_producer_destroy(p);
        return 3;
    }
    cfg.platform.sleep_ms(20);

    if (ve_tls_producer_add_log_kv(p, 0, &kv, 1, 1) != VE_TLS_OK) {
        ve_tls_producer_destroy(p);
        return 4;
    }
    for (int i = 0; i < 200 && g_cred_cb < 2; i++) {
        cfg.platform.sleep_ms(10);
    }
    ve_tls_producer_destroy(p);

    if (g_cred_cb < 2) {
        return 5;
    }
    if (g_cred_seen_1[0] == 0) {
        return 6;
    }
    if (g_cred_seen_2[0] == 0) {
        return 7;
    }
    if (strcmp(g_cred_seen_1, g_cred_seen_2) == 0) {
        return 8;
    }
    if (g_cred_provider_calls < 2) {
        return 9;
    }
    return 0;
}

static int test_dynamic_credentials_failure_does_not_deadlock(void) {
    g_cred_done = 0;
    g_cred_cb = 0;
    g_cred_req = 0;
    g_cred_provider_calls = 0;
    memset(g_cred_seen_1, 0, sizeof(g_cred_seen_1));
    memset(g_cred_seen_2, 0, sizeof(g_cred_seen_2));

    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    cfg.endpoint = "https://tls.example.com";
    cfg.region = "cn-test";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak0";
    cfg.access_key_secret = "sk0";
    cfg.security_token = NULL;
    cfg.credentials_provider = cred_provider;
    cfg.credentials_provider_param = NULL;
    cfg.credentials_expire_advance_ms = 0;
    cfg.credentials_refresh_min_interval_ms = 0;
    cfg.send_thread_count = 1;
    cfg.send_queue_size = 8;
    cfg.flush_interval_ms = 0;
    cfg.http_client.do_request = test_http_capture_token_do;
    cfg.http_client.free_response = test_http_ok_free;
    cfg.metrics_sink.emit = NULL;

    g_cred_state.platform = &cfg.platform;
    g_cred_state.fail_after = 1;

    ve_tls_producer * p = ve_tls_producer_create(&cfg);
    if (!p) {
        return -1;
    }
    ve_tls_producer_set_send_done_v2(p, on_send_done_cred, NULL);

    ve_tls_kv kv;
    kv.key = "k";
    kv.value = "v";
    if (ve_tls_producer_add_log_kv(p, 0, &kv, 1, 1) != VE_TLS_OK) {
        ve_tls_producer_destroy(p);
        return -1;
    }
    for (int i = 0; i < 200 && g_cred_cb < 1; i++) {
        cfg.platform.sleep_ms(10);
    }
    if (g_cred_cb < 1) {
        ve_tls_producer_destroy(p);
        return -1;
    }
    cfg.platform.sleep_ms(20);

    if (ve_tls_producer_add_log_kv(p, 0, &kv, 1, 1) != VE_TLS_OK) {
        ve_tls_producer_destroy(p);
        return -1;
    }
    for (int i = 0; i < 200 && g_cred_cb < 2; i++) {
        cfg.platform.sleep_ms(10);
    }
    ve_tls_producer_destroy(p);

    if (g_cred_cb < 2) {
        return -1;
    }
    if (g_cred_provider_calls < 2) {
        return -1;
    }
    return 0;
}

typedef struct {
    ve_tls_platform * platform;
    int count;
    int64_t t[2];
} cb_state;

static cb_state g_cb_state;

static int test_cb_do(ve_tls_http_client * client, const ve_tls_http_request * req, ve_tls_http_response * resp) {
    (void)req;
    if (!client || !resp) {
        return -1;
    }
    cb_state * s = (cb_state *)client->user_data;
    if (s && s->platform && s->count < 2) {
        s->t[s->count] = s->platform->time_ms();
    }
    if (s) {
        s->count++;
    }
    resp->status_code = 500;
    resp->request_id = strdup("hdr-rid");
    const char * body = "{\"errorCode\":\"LimitExceeded\",\"errorMessage\":\"too many\",\"requestID\":\"body-rid\"}";
    resp->body = (unsigned char *)strdup(body);
    resp->body_size = strlen(body);
    return 0;
}

static void test_cb_free(ve_tls_http_client * client, ve_tls_http_response * resp) {
    test_http_free(client, resp);
}

static int test_http_sleep_do(ve_tls_http_client * client, const ve_tls_http_request * req, ve_tls_http_response * resp) {
    (void)client;
    (void)req;
    if (!resp) {
        return -1;
    }
    int cur = __atomic_add_fetch(&g_order_cur, 1, __ATOMIC_RELAXED);
    int maxv = __atomic_load_n(&g_order_max, __ATOMIC_RELAXED);
    while (cur > maxv && !__atomic_compare_exchange_n(&g_order_max, &maxv, cur, 0, __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
    }
    usleep(50 * 1000);
    resp->status_code = 200;
    resp->request_id = strdup("rid-ok");
    __atomic_sub_fetch(&g_order_cur, 1, __ATOMIC_RELAXED);
    return 0;
}

static void test_http_sleep_free(ve_tls_http_client * client, ve_tls_http_response * resp) {
    (void)client;
    if (!resp) {
        return;
    }
    free(resp->body);
    free(resp->request_id);
    free(resp->error_code);
    free(resp->error_message);
    resp->body = NULL;
    resp->request_id = NULL;
    resp->error_code = NULL;
    resp->error_message = NULL;
}

static void on_send_done_ordered(
    ve_tls_result result,
    size_t log_bytes,
    size_t compressed_bytes,
    const ve_tls_error * error,
    const unsigned char * raw_buffer,
    void * user_param,
    int64_t start_id,
    int64_t end_id
) {
    (void)log_bytes;
    (void)compressed_bytes;
    (void)error;
    (void)raw_buffer;
    (void)user_param;
    (void)start_id;
    (void)end_id;
    if (result == VE_TLS_OK) {
        int n = __atomic_add_fetch(&g_order_cb, 1, __ATOMIC_RELAXED);
        if (n >= 2) {
            g_order_done = 1;
        }
    } else {
        g_order_done = 1;
    }
}

static int test_ordered_send_max_concurrency_one(void) {
    g_order_done = 0;
    g_order_cb = 0;
    g_order_cur = 0;
    g_order_max = 0;

    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.compress_type = "none";
    cfg.flush_interval_ms = 10;
    cfg.log_count_per_package = 1;
    cfg.send_thread_count = 2;
    cfg.ordered_send = 1;
    cfg.retry_policy.max_attempts = 1;
    cfg.http_client.do_request = test_http_sleep_do;
    cfg.http_client.free_response = test_http_sleep_free;

    ve_tls_producer * p = ve_tls_producer_create(&cfg);
    if (!p) {
        return -1;
    }
    ve_tls_producer_set_send_done_v2(p, on_send_done_ordered, NULL);

    ve_tls_kv kvs[1];
    kvs[0].key = "k";
    kvs[0].value = "v";
    if (ve_tls_producer_add_log_kv(p, 0, kvs, 1, 1) != VE_TLS_OK) {
        ve_tls_producer_destroy(p);
        return -1;
    }
    if (ve_tls_producer_add_log_kv(p, 0, kvs, 1, 1) != VE_TLS_OK) {
        ve_tls_producer_destroy(p);
        return -1;
    }

    for (int i = 0; i < 400 && !g_order_done; i++) {
        cfg.platform.sleep_ms(10);
    }
    ve_tls_producer_destroy(p);
    if (!g_order_done) {
        return -1;
    }
    return g_order_max == 1 ? 0 : -1;
}

static const char * g_hk_keys[4] = {"key_a", "key_b", "key_c", "key_d"};
static int g_hk_cur[4] = {0};
static int g_hk_max[4] = {0};
static int g_hk_total_cur = 0;
static int g_hk_total_max = 0;
static int g_hk_cb = 0;
static int g_hk_done = 0;

static int test_hashkey_do(ve_tls_http_client * client, const ve_tls_http_request * req, ve_tls_http_response * resp) {
    (void)client;
    if (!req || !resp || !req->headers) {
        return -1;
    }
    const char * p = strstr(req->headers, "x-tls-hashkey:");
    int idx = -1;
    if (p) {
        p += strlen("x-tls-hashkey:");
        while (*p == ' ') p++;
        char key[64];
        size_t k = 0;
        while (*p && *p != '\n' && *p != '\r' && k + 1 < sizeof(key)) {
            key[k++] = *p++;
        }
        key[k] = 0;
        for (int i = 0; i < 4; i++) {
            if (strcmp(key, g_hk_keys[i]) == 0) {
                idx = i;
                break;
            }
        }
    }
    if (idx < 0) {
        return -1;
    }
    int cur = __atomic_add_fetch(&g_hk_cur[idx], 1, __ATOMIC_RELAXED);
    int maxv = __atomic_load_n(&g_hk_max[idx], __ATOMIC_RELAXED);
    while (cur > maxv && !__atomic_compare_exchange_n(&g_hk_max[idx], &maxv, cur, 0, __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
    }
    int total_cur = __atomic_add_fetch(&g_hk_total_cur, 1, __ATOMIC_RELAXED);
    int tmax = __atomic_load_n(&g_hk_total_max, __ATOMIC_RELAXED);
    while (total_cur > tmax && !__atomic_compare_exchange_n(&g_hk_total_max, &tmax, total_cur, 0, __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
    }
    usleep(50 * 1000);
    __atomic_sub_fetch(&g_hk_total_cur, 1, __ATOMIC_RELAXED);
    __atomic_sub_fetch(&g_hk_cur[idx], 1, __ATOMIC_RELAXED);
    resp->status_code = 200;
    resp->request_id = strdup("rid-ok");
    return 0;
}

static void test_hashkey_free(ve_tls_http_client * client, ve_tls_http_response * resp) {
    (void)client;
    if (!resp) {
        return;
    }
    free(resp->body);
    free(resp->request_id);
    free(resp->error_code);
    free(resp->error_message);
    resp->body = NULL;
    resp->request_id = NULL;
    resp->error_code = NULL;
    resp->error_message = NULL;
}

static void on_send_done_hashkey(
    ve_tls_result result,
    size_t log_bytes,
    size_t compressed_bytes,
    const ve_tls_error * error,
    const unsigned char * raw_buffer,
    void * user_param,
    int64_t start_id,
    int64_t end_id
) {
    (void)log_bytes;
    (void)compressed_bytes;
    (void)error;
    (void)raw_buffer;
    (void)user_param;
    (void)start_id;
    (void)end_id;
    if (result != VE_TLS_OK) {
        g_hk_done = 1;
        return;
    }
    int n = __atomic_add_fetch(&g_hk_cb, 1, __ATOMIC_RELAXED);
    if (n >= 4) {
        g_hk_done = 1;
    }
}

static int test_hashkey_partition_parallelism(void) {
    memset(g_hk_cur, 0, sizeof(g_hk_cur));
    memset(g_hk_max, 0, sizeof(g_hk_max));
    g_hk_total_cur = 0;
    g_hk_total_max = 0;
    g_hk_cb = 0;
    g_hk_done = 0;

    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.compress_type = "none";
    cfg.flush_interval_ms = 10;
    cfg.log_count_per_package = 1;
    cfg.send_thread_count = 4;
    cfg.ordered_send = 0;
    cfg.retry_policy.max_attempts = 1;
    cfg.http_client.do_request = test_hashkey_do;
    cfg.http_client.free_response = test_hashkey_free;

    ve_tls_producer * p = ve_tls_producer_create(&cfg);
    if (!p) {
        return -1;
    }
    ve_tls_producer_set_send_done_v2(p, on_send_done_hashkey, NULL);

    ve_tls_kv kvs[1];
    kvs[0].key = "k";
    kvs[0].value = "v";
    for (int i = 0; i < 4; i++) {
        if (ve_tls_producer_add_log_kv_hashkey(p, 0, g_hk_keys[i], kvs, 1, 1) != VE_TLS_OK) {
            ve_tls_producer_destroy(p);
            return -1;
        }
    }

    for (int i = 0; i < 500 && !g_hk_done; i++) {
        cfg.platform.sleep_ms(10);
    }
    ve_tls_producer_destroy(p);
    if (!g_hk_done || g_hk_cb < 4) {
        return -1;
    }
    for (int i = 0; i < 4; i++) {
        if (g_hk_max[i] != 1) {
            return -1;
        }
    }
    return g_hk_total_max >= 2 ? 0 : -1;
}

static int g_split_req_count = 0;
static int g_split_ok = 1;

static int test_split_do(ve_tls_http_client * client, const ve_tls_http_request * req, ve_tls_http_response * resp) {
    (void)client;
    if (!req || !resp) {
        return -1;
    }
    if (req->body_size > (size_t)(50 * 1024)) {
        g_split_ok = 0;
    }
    __atomic_add_fetch(&g_split_req_count, 1, __ATOMIC_RELAXED);
    resp->status_code = 200;
    resp->request_id = strdup("rid-ok");
    return 0;
}

static void test_split_free(ve_tls_http_client * client, ve_tls_http_response * resp) {
    test_http_ok_free(client, resp);
}

static int test_agg_strategy_split_by_compressed_limit(void) {
    g_split_req_count = 0;
    g_split_ok = 1;

    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.compress_type = "none";
    cfg.flush_interval_ms = 10;
    cfg.send_thread_count = 1;
    cfg.ordered_send = 1;
    cfg.log_count_per_package = 100000;
    cfg.log_bytes_per_package = 32 * 1024;
    cfg.agg_strategy = 1;
    cfg.agg_max_compressed_bytes_per_request = 50 * 1024;
    cfg.retry_policy.max_attempts = 1;
    cfg.http_client.do_request = test_split_do;
    cfg.http_client.free_response = test_split_free;

    ve_tls_producer * p = ve_tls_producer_create(&cfg);
    if (!p) {
        return -1;
    }
    char big[2048];
    memset(big, 'a', sizeof(big) - 1);
    big[sizeof(big) - 1] = 0;
    ve_tls_kv kvs[1];
    kvs[0].key = "k";
    kvs[0].value = big;
    for (int i = 0; i < 80; i++) {
        int flush = (i == 79) ? 1 : 0;
        if (ve_tls_producer_add_log_kv_hashkey(p, 0, "key_a", kvs, 1, flush) != VE_TLS_OK) {
            ve_tls_producer_destroy(p);
            return -1;
        }
    }
    for (int i = 0; i < 500; i++) {
        cfg.platform.sleep_ms(10);
        int n = __atomic_load_n(&g_split_req_count, __ATOMIC_RELAXED);
        if (n >= 2) {
            break;
        }
    }
    ve_tls_producer_destroy(p);
    int n = __atomic_load_n(&g_split_req_count, __ATOMIC_RELAXED);
    return (g_split_ok && n >= 2) ? 0 : -1;
}

static int g_keylimit_drop = 0;

static void on_send_done_keylimit(
    ve_tls_result result,
    size_t log_bytes,
    size_t compressed_bytes,
    const ve_tls_error * error,
    const unsigned char * raw_buffer,
    void * user_param,
    int64_t start_id,
    int64_t end_id
) {
    (void)log_bytes;
    (void)compressed_bytes;
    (void)raw_buffer;
    (void)user_param;
    (void)start_id;
    (void)end_id;
    if (result == VE_TLS_DROP_ERROR && error && error->error_code && strcmp(error->error_code, "KeyQueueLimitExceeded") == 0) {
        __atomic_add_fetch(&g_keylimit_drop, 1, __ATOMIC_RELAXED);
    }
}

static int test_key_queue_max_active_drops(void) {
    g_keylimit_drop = 0;

    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.compress_type = "none";
    cfg.flush_interval_ms = 10;
    cfg.send_thread_count = 1;
    cfg.ordered_send = 1;
    cfg.key_queue_max_active = 1;
    cfg.log_count_per_package = 1;
    cfg.retry_policy.max_attempts = 1;
    cfg.http_client.do_request = test_http_sleep_do;
    cfg.http_client.free_response = test_http_sleep_free;

    ve_tls_producer * p = ve_tls_producer_create(&cfg);
    if (!p) {
        return -1;
    }
    ve_tls_producer_set_send_done_v2(p, on_send_done_keylimit, NULL);
    ve_tls_kv kvs[1];
    kvs[0].key = "k";
    kvs[0].value = "v";
    if (ve_tls_producer_add_log_kv_hashkey(p, 0, "k1", kvs, 1, 1) != VE_TLS_OK) {
        ve_tls_producer_destroy(p);
        return -1;
    }
    if (ve_tls_producer_add_log_kv_hashkey(p, 0, "k2", kvs, 1, 1) != VE_TLS_OK) {
        ve_tls_producer_destroy(p);
        return -1;
    }
    for (int i = 0; i < 400; i++) {
        cfg.platform.sleep_ms(10);
        if (__atomic_load_n(&g_keylimit_drop, __ATOMIC_RELAXED) > 0) {
            break;
        }
    }
    ve_tls_producer_destroy(p);
    return __atomic_load_n(&g_keylimit_drop, __ATOMIC_RELAXED) > 0 ? 0 : -1;
}

static int64_t g_keyrl_t[4] = {0};
static int g_keyrl_n[2] = {0};
static int64_t g_keyrl_start = 0;

static int test_key_rate_limit_do(ve_tls_http_client * client, const ve_tls_http_request * req, ve_tls_http_response * resp) {
    if (!req || !req->headers || !resp) {
        return -1;
    }
    if (!client || !client->user_data) {
        return -1;
    }
    const char * p = strstr(req->headers, "x-tls-hashkey:");
    int idx = -1;
    if (p) {
        p += strlen("x-tls-hashkey:");
        while (*p == ' ') p++;
        if (strncmp(p, "k1", 2) == 0) idx = 0;
        if (strncmp(p, "k2", 2) == 0) idx = 1;
    }
    if (idx < 0) {
        return -1;
    }
    int n = __atomic_add_fetch(&g_keyrl_n[idx], 1, __ATOMIC_RELAXED);
    if (n <= 2) {
        int64_t now = ((ve_tls_platform *)client->user_data)->time_ms();
        if (g_keyrl_start == 0) {
            g_keyrl_start = now;
        }
        g_keyrl_t[idx * 2 + (n - 1)] = now;
    }
    resp->status_code = 200;
    resp->request_id = strdup("rid-ok");
    return 0;
}

static void test_key_rate_limit_free(ve_tls_http_client * client, ve_tls_http_response * resp) {
    test_http_ok_free(client, resp);
}

static int test_key_rate_limit_is_per_key(void) {
    memset(g_keyrl_t, 0, sizeof(g_keyrl_t));
    g_keyrl_n[0] = 0;
    g_keyrl_n[1] = 0;
    g_keyrl_start = 0;

    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.compress_type = "none";
    cfg.flush_interval_ms = 10;
    cfg.send_thread_count = 2;
    cfg.ordered_send = 0;
    cfg.log_count_per_package = 1;
    cfg.retry_policy.max_attempts = 1;
    cfg.key_queue_idle_ttl_ms = 2000;
    cfg.key_rate_limit_rps = 1;
    cfg.http_client.do_request = test_key_rate_limit_do;
    cfg.http_client.free_response = test_key_rate_limit_free;
    cfg.http_client.user_data = &cfg.platform;

    ve_tls_producer * p = ve_tls_producer_create(&cfg);
    if (!p) {
        return -1;
    }
    ve_tls_kv kvs[1];
    kvs[0].key = "k";
    kvs[0].value = "v";
    if (ve_tls_producer_add_log_kv_hashkey(p, 0, "k1", kvs, 1, 1) != VE_TLS_OK) {
        ve_tls_producer_destroy(p);
        return -1;
    }
    if (ve_tls_producer_add_log_kv_hashkey(p, 0, "k2", kvs, 1, 1) != VE_TLS_OK) {
        ve_tls_producer_destroy(p);
        return -1;
    }
    if (ve_tls_producer_add_log_kv_hashkey(p, 0, "k1", kvs, 1, 1) != VE_TLS_OK) {
        ve_tls_producer_destroy(p);
        return -1;
    }
    if (ve_tls_producer_add_log_kv_hashkey(p, 0, "k2", kvs, 1, 1) != VE_TLS_OK) {
        ve_tls_producer_destroy(p);
        return -1;
    }
    for (int i = 0; i < 400 && (g_keyrl_n[0] < 2 || g_keyrl_n[1] < 2); i++) {
        cfg.platform.sleep_ms(10);
    }
    ve_tls_producer_destroy(p);
    if (g_keyrl_n[0] < 2 || g_keyrl_n[1] < 2) {
        return -1;
    }
    int64_t dt1 = g_keyrl_t[1] - g_keyrl_t[0];
    int64_t dt2 = g_keyrl_t[3] - g_keyrl_t[2];
    if (dt1 < 900 || dt2 < 900) {
        return -1;
    }
    int64_t first_min = g_keyrl_t[0] < g_keyrl_t[2] ? g_keyrl_t[0] : g_keyrl_t[2];
    int64_t second_max = g_keyrl_t[1] > g_keyrl_t[3] ? g_keyrl_t[1] : g_keyrl_t[3];
    int64_t span = second_max - first_min;
    return span <= 1700 ? 0 : -1;
}

static int test_rate_limit_rps_throttles(void) {
    memset(&g_rl_state, 0, sizeof(g_rl_state));

    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.compress_type = "none";
    cfg.flush_interval_ms = 10;
    cfg.log_count_per_package = 1;
    cfg.send_thread_count = 1;
    cfg.rate_limit_rps = 1;
    cfg.retry_policy.max_attempts = 1;
    g_rl_state.platform = &cfg.platform;
    cfg.http_client.do_request = test_rl_do;
    cfg.http_client.free_response = test_rl_free;
    cfg.http_client.user_data = &g_rl_state;

    ve_tls_producer * p = ve_tls_producer_create(&cfg);
    if (!p) {
        return -1;
    }
    ve_tls_kv kvs[1];
    kvs[0].key = "k";
    kvs[0].value = "v";
    int64_t t0 = cfg.platform.time_ms();
    if (ve_tls_producer_add_log_kv(p, 0, kvs, 1, 1) != VE_TLS_OK) {
        ve_tls_producer_destroy(p);
        return -1;
    }
    if (ve_tls_producer_add_log_kv(p, 0, kvs, 1, 1) != VE_TLS_OK) {
        ve_tls_producer_destroy(p);
        return -1;
    }
    for (int i = 0; i < 200 && g_rl_state.count < 2; i++) {
        cfg.platform.sleep_ms(10);
    }
    ve_tls_producer_destroy(p);
    if (g_rl_state.count < 2 || g_rl_state.t[0] == 0 || g_rl_state.t[1] == 0) {
        return -1;
    }
    int64_t dt = g_rl_state.t[1] - g_rl_state.t[0];
    return dt >= 900 ? 0 : -1;
}

static int test_circuit_breaker_delays_second_send(void) {
    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.compress_type = "none";
    cfg.flush_interval_ms = 10;
    cfg.log_count_per_package = 1;
    cfg.send_thread_count = 1;
    cfg.retry_policy.max_attempts = 1;
    cfg.breaker_fail_threshold = 1;
    cfg.breaker_open_ms = 300;
    cfg.breaker_half_open_max_inflight = 1;
    memset(&g_cb_state, 0, sizeof(g_cb_state));
    g_cb_state.platform = &cfg.platform;
    cfg.http_client.do_request = test_cb_do;
    cfg.http_client.free_response = test_cb_free;
    cfg.http_client.user_data = &g_cb_state;

    ve_tls_producer * p = ve_tls_producer_create(&cfg);
    if (!p) {
        return -1;
    }
    ve_tls_kv kvs[1];
    kvs[0].key = "k";
    kvs[0].value = "v";
    if (ve_tls_producer_add_log_kv(p, 0, kvs, 1, 1) != VE_TLS_OK) {
        ve_tls_producer_destroy(p);
        return -1;
    }
    if (ve_tls_producer_add_log_kv(p, 0, kvs, 1, 1) != VE_TLS_OK) {
        ve_tls_producer_destroy(p);
        return -1;
    }

    for (int i = 0; i < 200 && g_cb_state.count < 2; i++) {
        cfg.platform.sleep_ms(10);
    }
    ve_tls_producer_destroy(p);
    if (g_cb_state.count < 2 || g_cb_state.t[0] == 0 || g_cb_state.t[1] == 0) {
        return -1;
    }
    int64_t dt = g_cb_state.t[1] - g_cb_state.t[0];
    return dt >= 250 ? 0 : -1;
}

static int test_sha256(void) {
    unsigned char out[32];
    ve_tls_sha256((const unsigned char *)"abc", 3, out);
    char hex[65];
    ve_tls_hex_lower(out, 32, hex, sizeof(hex));
    return strcmp(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == 0 ? 0 : -1;
}

static int test_proto(void) {
    ve_tls_kv kvs[1];
    kvs[0].key = "k";
    kvs[0].value = "v";
    ve_tls_bytes log;
    if (ve_tls_proto_encode_log(1, kvs, 1, &log) != 0 || !log.data || log.size == 0) {
        ve_tls_bytes_free(&log);
        return -1;
    }
    ve_tls_bytes out;
    if (ve_tls_proto_encode_log_group_list(&log, 1, "s", "f", &out) != 0 || !out.data || out.size == 0) {
        ve_tls_bytes_free(&log);
        ve_tls_bytes_free(&out);
        return -1;
    }
    ve_tls_bytes_free(&log);
    ve_tls_bytes_free(&out);
    return 0;
}

static int test_proto_log_group_list_multi_groups(void) {
    const size_t n = 10001;
    ve_tls_bytes * logs = (ve_tls_bytes *)calloc(n, sizeof(ve_tls_bytes));
    if (!logs) {
        return -1;
    }
    ve_tls_kv kvs[1];
    kvs[0].key = "k";
    kvs[0].value = "v";
    for (size_t i = 0; i < n; i++) {
        if (ve_tls_proto_encode_log_ex(1, 0, 0, kvs, 1, &logs[i]) != 0 || !logs[i].data || logs[i].size == 0) {
            for (size_t j = 0; j <= i; j++) {
                ve_tls_bytes_free(&logs[j]);
            }
            free(logs);
            return -1;
        }
    }
    ve_tls_bytes out;
    int rc = ve_tls_proto_encode_log_group_list_ex(logs, n, "s", "f", NULL, 0, NULL, &out);
    for (size_t i = 0; i < n; i++) {
        ve_tls_bytes_free(&logs[i]);
    }
    free(logs);
    if (rc != 0 || !out.data || out.size == 0) {
        ve_tls_bytes_free(&out);
        return -1;
    }
    ve_tls_bytes_free(&out);
    return 0;
}

static int test_proto_time_ns(void) {
    ve_tls_kv kvs[1];
    kvs[0].key = "k";
    kvs[0].value = "v";
    ve_tls_bytes log;
    if (ve_tls_proto_encode_log_ex(1710000000000LL, 123456, 1, kvs, 1, &log) != 0 || !log.data || log.size == 0) {
        ve_tls_bytes_free(&log);
        return -1;
    }
    int ok = 0;
    for (size_t i = 0; i + 5 <= log.size; i++) {
        if (log.data[i] == 0x1d) {
            uint32_t v = (uint32_t)log.data[i + 1] |
                         ((uint32_t)log.data[i + 2] << 8) |
                         ((uint32_t)log.data[i + 3] << 16) |
                         ((uint32_t)log.data[i + 4] << 24);
            if (v == 123456) {
                ok = 1;
                break;
            }
        }
    }
    ve_tls_bytes_free(&log);
    return ok ? 0 : -1;
}

static int test_proto_log_tags_and_context_flow(void) {
    ve_tls_kv kvs[1];
    kvs[0].key = "k";
    kvs[0].value = "v";
    ve_tls_bytes log;
    if (ve_tls_proto_encode_log(1710000000000LL, kvs, 1, &log) != 0 || !log.data || log.size == 0) {
        ve_tls_bytes_free(&log);
        return -1;
    }
    ve_tls_kv tags[2];
    tags[0].key = "tag_key_a";
    tags[0].value = "tag_val_a";
    tags[1].key = "tag_key_b";
    tags[1].value = "tag_val_b";

    ve_tls_bytes out;
    if (ve_tls_proto_encode_log_group_list_ex(&log, 1, "src", "file", tags, 2, "ctx_flow", &out) != 0 || !out.data || out.size == 0) {
        ve_tls_bytes_free(&log);
        ve_tls_bytes_free(&out);
        return -1;
    }
    int ok = 0;
    for (size_t i = 0; i + strlen("ctx_flow") <= out.size; i++) {
        if (memcmp(out.data + i, "ctx_flow", strlen("ctx_flow")) == 0) {
            ok = 1;
            break;
        }
    }
    int ok2 = 0;
    for (size_t i = 0; i + strlen("tag_key_a") <= out.size; i++) {
        if (memcmp(out.data + i, "tag_key_a", strlen("tag_key_a")) == 0) {
            ok2 = 1;
            break;
        }
    }
    int ok3 = 0;
    for (size_t i = 0; i + strlen("tag_val_b") <= out.size; i++) {
        if (memcmp(out.data + i, "tag_val_b", strlen("tag_val_b")) == 0) {
            ok3 = 1;
            break;
        }
    }
    ve_tls_bytes_free(&log);
    ve_tls_bytes_free(&out);
    return (ok && ok2 && ok3) ? 0 : -1;
}

static int test_sign(void) {
    const char * headers = "Content-Type: application/x-protobuf\nx-tls-apiversion: " VE_TLS_C_SDK_API_VERSION "\n";
    unsigned char body[3] = {1,2,3};
    char * out = NULL;
    int rc = ve_tls_sign_v4_append("ak", "sk", "", "cn-beijing", "TLS", "POST", "tls-cn-beijing.volces.com", "/PutLogs", "TopicId=t", body, sizeof(body), headers, &out);
    if (rc != 0 || !out) {
        free(out);
        return -1;
    }
    int ok = strstr(out, "Authorization: HMAC-SHA256 Credential=ak/") != NULL && strstr(out, "X-Date: ") != NULL && strstr(out, "X-Content-Sha256: ") != NULL;
    free(out);
    return ok ? 0 : -1;
}

static int test_sign_matches_go_reference_with_fixed_xdate(void) {
    const char * headers =
        "Content-Type: application/x-protobuf\n"
        "Content-MD5: EC292B5AF5705CA644BEB1BAE239DBD9\n"
        "x-tls-apiversion: 0.3.0\n"
        "x-tls-bodyrawsize: 79\n"
        "x-tls-compresstype: lz4\n"
        "x-tls-hashkey: \n";
    const unsigned char body[5] = {1, 2, 3, 4, 5};
    char * out = NULL;
    int rc = ve_tls_sign_v4_append_at(
        "test-access-key-id",
        "test-secret-access-key",
        "",
        "cn-test",
        "TLS",
        "POST",
        "tls-cn-test.example.com",
        "/PutLogs",
        "TopicId=test-topic-id",
        body,
        sizeof(body),
        "20260410T032329Z",
        headers,
        &out
    );
    if (rc != 0 || !out) {
        free(out);
        return -1;
    }
    if (!strstr(out, "X-Date: 20260410T032329Z\n") ||
        !strstr(out, "Signature=1494950acdb923bc992de590605245a18da9ce6a4eee42cb232a8c2db8b90095")) {
        free(out);
        return -1;
    }
    free(out);
    return 0;
}

static int test_sign_cache_secret_change_same_pointer_effective(void) {
    const char * headers = "Content-Type: application/x-protobuf\nx-tls-apiversion: " VE_TLS_C_SDK_API_VERSION "\n";
    unsigned char body[3] = {1,2,3};
    char sk_buf[32];
    char * out1 = NULL;
    char * out2 = NULL;
    int saw_same_xdate = 0;
    for (int i = 0; i < 5; i++) {
        snprintf(sk_buf, sizeof(sk_buf), "sk-one");
        if (ve_tls_sign_v4_append("ak", sk_buf, "", "cn-beijing", "TLS", "POST", "tls-cn-beijing.volces.com", "/PutLogs", "TopicId=t", body, sizeof(body), headers, &out1) != 0 || !out1) {
            free(out1);
            free(out2);
            return -1;
        }
        snprintf(sk_buf, sizeof(sk_buf), "sk-two");
        if (ve_tls_sign_v4_append("ak", sk_buf, "", "cn-beijing", "TLS", "POST", "tls-cn-beijing.volces.com", "/PutLogs", "TopicId=t", body, sizeof(body), headers, &out2) != 0 || !out2) {
            free(out1);
            free(out2);
            return -1;
        }
        const char * d1 = strstr(out1, "X-Date: ");
        const char * d2 = strstr(out2, "X-Date: ");
        if (d1 && d2 && strncmp(d1, d2, strlen("X-Date: YYYYMMDDThhmmssZ")) == 0) {
            saw_same_xdate = 1;
            break;
        }
        free(out1);
        free(out2);
        out1 = NULL;
        out2 = NULL;
    }
    if (!saw_same_xdate) {
        free(out1);
        free(out2);
        return -1;
    }
    const char * a1 = strstr(out1, "Authorization: ");
    const char * a2 = strstr(out2, "Authorization: ");
    int ok = (a1 && a2 && strcmp(a1, a2) != 0);
    free(out1);
    free(out2);
    return ok ? 0 : -1;
}

static int test_sign_repeated_call_allocation_reduced(void) {
    ve_tls_alloc_hooks saved;
    memset(&saved, 0, sizeof(saved));
    ve_tls_alloc_get_hooks(&saved);

    alloc_select_fail_state st;
    memset(&st, 0, sizeof(st));
    set_alloc_select_fail(&st, 0, 0, 0, 0);

    const char * headers = "Content-Type: application/x-protobuf\nx-tls-apiversion: " VE_TLS_C_SDK_API_VERSION "\n";
    const unsigned char body[3] = {1, 2, 3};
    char * out1 = NULL;
    char * out2 = NULL;
    int rc1 = ve_tls_sign_v4_append("ak", "sk", "tok", "cn-beijing", "TLS", "POST", "example.com", "/PutLogs", "TopicId=t&aa=1&bb=2", body, sizeof(body), headers, &out1);
    int calls_after_first = st.malloc_calls + st.calloc_calls + st.realloc_calls + st.strdup_calls;
    int rc2 = ve_tls_sign_v4_append("ak", "sk", "tok", "cn-beijing", "TLS", "POST", "example.com", "/PutLogs", "TopicId=t&aa=1&bb=2", body, sizeof(body), headers, &out2);
    int calls_after_second = st.malloc_calls + st.calloc_calls + st.realloc_calls + st.strdup_calls;

    ve_tls_alloc_set_hooks(&saved);
    int ok = (rc1 == 0 && rc2 == 0 &&
              out1 && out2 &&
              strstr(out1, "Authorization: ") &&
              strstr(out2, "Authorization: "));
    int first_calls = calls_after_first;
    int second_calls = calls_after_second - calls_after_first;
    ve_tls_free(out1);
    ve_tls_free(out2);
    return (ok && first_calls > 0 && second_calls <= first_calls - 2) ? 0 : -1;
}

static int test_sign_allocation_budget_tight(void) {
    ve_tls_alloc_hooks saved;
    memset(&saved, 0, sizeof(saved));
    ve_tls_alloc_get_hooks(&saved);

    alloc_select_fail_state st;
    memset(&st, 0, sizeof(st));
    set_alloc_select_fail(&st, 0, 0, 0, 0);

    char * out = NULL;
    int rc = ve_tls_sign_v4_append(
        "ak",
        "sk",
        "tok",
        "cn-beijing",
        "TLS",
        "POST",
        "example.com",
        "/PutLogs",
        "TopicId=tight_budget_probe_key_1",
        (const unsigned char *)"abc",
        3,
        "Content-Type: application/x-protobuf\nx-tls-apiversion: " VE_TLS_C_SDK_API_VERSION "\n",
        &out
    );

    ve_tls_alloc_set_hooks(&saved);
    int ok = 0;
    if (rc == 0 && out && strstr(out, "Authorization: ") && strstr(out, "X-Date: ")) {
        ok = 1;
    }
    ve_tls_free(out);

    int total_calls = st.malloc_calls + st.calloc_calls + st.realloc_calls + st.strdup_calls;
    return (ok && total_calls <= 14) ? 0 : -1;
}

static int test_sign_allocation_budget_multi_query_tight(void) {
    ve_tls_alloc_hooks saved;
    memset(&saved, 0, sizeof(saved));
    ve_tls_alloc_get_hooks(&saved);

    alloc_select_fail_state st;
    memset(&st, 0, sizeof(st));
    set_alloc_select_fail(&st, 0, 0, 0, 0);

    char * out = NULL;
    int rc = ve_tls_sign_v4_append(
        "ak",
        "sk",
        "tok",
        "cn-beijing",
        "TLS",
        "POST",
        "example.com",
        "/PutLogs",
        "TopicId=t&aa=1&bb=2",
        (const unsigned char *)"abc",
        3,
        "Content-Type: application/x-protobuf\nx-tls-apiversion: " VE_TLS_C_SDK_API_VERSION "\n",
        &out
    );

    ve_tls_alloc_set_hooks(&saved);
    int ok = 0;
    if (rc == 0 && out && strstr(out, "Authorization: ") && strstr(out, "X-Date: ")) {
        ok = 1;
    }
    ve_tls_free(out);

    int total_calls = st.malloc_calls + st.calloc_calls + st.realloc_calls + st.strdup_calls;
    return (ok && total_calls <= 14) ? 0 : -1;
}

static int test_sign_repeated_call_allocation_reduced_tight(void) {
    ve_tls_alloc_hooks saved;
    memset(&saved, 0, sizeof(saved));
    ve_tls_alloc_get_hooks(&saved);

    alloc_select_fail_state st;
    memset(&st, 0, sizeof(st));
    set_alloc_select_fail(&st, 0, 0, 0, 0);

    const char * headers = "Content-Type: application/x-protobuf\nx-tls-apiversion: " VE_TLS_C_SDK_API_VERSION "\n";
    const unsigned char body[3] = {1, 2, 3};
    char * out1 = NULL;
    char * out2 = NULL;
    int rc1 = ve_tls_sign_v4_append("ak", "sk", "tok", "cn-beijing", "TLS", "POST", "example.com", "/PutLogs", "TopicId=t&aa=1&bb=2", body, sizeof(body), headers, &out1);
    int calls_after_first = st.malloc_calls + st.calloc_calls + st.realloc_calls + st.strdup_calls;
    int rc2 = ve_tls_sign_v4_append("ak", "sk", "tok", "cn-beijing", "TLS", "POST", "example.com", "/PutLogs", "TopicId=t&aa=1&bb=2", body, sizeof(body), headers, &out2);
    int calls_after_second = st.malloc_calls + st.calloc_calls + st.realloc_calls + st.strdup_calls;

    ve_tls_alloc_set_hooks(&saved);
    int ok = (rc1 == 0 && rc2 == 0 &&
              out1 && out2 &&
              strstr(out1, "Authorization: ") &&
              strstr(out2, "Authorization: "));
    int second_calls = calls_after_second - calls_after_first;
    ve_tls_free(out1);
    ve_tls_free(out2);
    return (ok && second_calls <= 4) ? 0 : -1;
}

#if defined(VE_TLS_HAVE_ZLIB)
static int test_zlib_compress_roundtrip(void) {
    unsigned char in[8] = {0,1,2,3,4,5,6,7};
    ve_tls_bytes enc;
    if (ve_tls_compress_apply("zlib", in, sizeof(in), &enc) != 0 || !enc.data || enc.size == 0) {
        ve_tls_bytes_free(&enc);
        return -1;
    }

    unsigned char dec[8] = {0};
    z_stream s;
    memset(&s, 0, sizeof(s));
    if (inflateInit(&s) != Z_OK) {
        ve_tls_bytes_free(&enc);
        return -1;
    }
    s.next_in = enc.data;
    s.avail_in = (uInt)enc.size;
    s.next_out = dec;
    s.avail_out = (uInt)sizeof(dec);
    int rc = inflate(&s, Z_FINISH);
    inflateEnd(&s);
    ve_tls_bytes_free(&enc);
    if (rc != Z_STREAM_END) {
        return -1;
    }
    if (s.total_out != sizeof(dec)) {
        return -1;
    }
    return memcmp(dec, in, sizeof(in)) == 0 ? 0 : -1;
}
#endif

#if defined(VE_TLS_HAVE_LZ4)
static int test_lz4_compress_roundtrip(void) {
    unsigned char in[64];
    for (int i = 0; i < (int)sizeof(in); i++) {
        in[i] = (unsigned char)(i * 3);
    }
    ve_tls_bytes enc;
    if (ve_tls_compress_apply("lz4", in, sizeof(in), &enc) != 0 || !enc.data || enc.size == 0) {
        ve_tls_bytes_free(&enc);
        return -1;
    }
    unsigned char dec[64] = {0};
    int n = LZ4_decompress_safe((const char *)enc.data, (char *)dec, (int)enc.size, (int)sizeof(dec));
    ve_tls_bytes_free(&enc);
    if (n != (int)sizeof(dec)) {
        return -1;
    }
    return memcmp(dec, in, sizeof(in)) == 0 ? 0 : -1;
}
#endif

int main(void) {
    int rc = 0;
#define RUN(code, fn) do { if ((fn) != 0) { rc = (code); goto end; } } while (0)

    RUN(1, test_sha256());
    RUN(2, test_proto());
    RUN(3, test_proto_log_group_list_multi_groups());
    RUN(4, test_proto_time_ns());
    RUN(5, test_proto_log_tags_and_context_flow());
    RUN(6, test_structured_error_and_retryable());
    RUN(60, test_sender_retries_429_then_ok());
    RUN(61, test_sender_http_400_no_retry());
    RUN(62, test_sender_transport_retryable_then_ok());
    RUN(66, test_sender_http_rc_minus1_defaults_error());
    RUN(67, test_sender_http_500_sets_badresponse());
    RUN(68, test_sender_unsupported_compress_type_drops_before_http());
    RUN(39, test_sender_small_payload_uses_none_compresstype());
    RUN(40, test_sender_small_payload_with_agg_strategy_uses_none_compresstype());
    RUN(41, test_sender_unsigned_headers_appended_after_authorization());
    RUN(125, test_sender_putlogs_includes_content_md5_header());
    RUN(126, test_sender_putlogs_includes_empty_hashkey_header());
    RUN(42, test_sign_repeated_call_allocation_reduced());
    RUN(43, test_sign_allocation_budget_tight());
    RUN(44, test_sign_allocation_budget_multi_query_tight());
    RUN(45, test_sign_repeated_call_allocation_reduced_tight());
    RUN(71, test_sender_build_url_calloc_fail_drops_without_http());
    RUN(72, test_sender_build_headers_realloc_fail_drops_without_http());
    RUN(73, test_sender_sign_realloc_fail_drops_without_http());
    RUN(75, test_sender_key_rate_limit_delays_same_key());
    RUN(76, test_sender_key_breaker_delays_same_key());
    RUN(77, test_sender_credentials_min_interval_returns_cached());
    RUN(78, test_sender_credentials_min_interval_fail_without_cached());
    RUN(79, test_sender_default_hash_key_header_set());
    RUN(80, test_sender_transport_curl_retryable_flag());
    RUN(81, test_producer_update_endpoint_affects_url());
    RUN(82, test_producer_update_static_credentials_affects_auth_header());
    RUN(83, test_producer_common_rate_limit_and_breaker_paths());
    RUN(84, test_manager_payload_too_large_after_comp_single());
    RUN(85, test_manager_payload_too_large_split_into_two_requests());
    RUN(86, test_manager_key_queue_limit_exceeded_drops());
    RUN(7, test_export_import_raw_buffer());
    RUN(87, test_import_raw_buffer_invalid_magic());
    RUN(88, test_import_raw_buffer_truncated_invalid());
    RUN(89, test_import_raw_buffer_exceeds_max_buffer_bytes_drop());
    RUN(90, test_import_raw_buffer_hash_key_ok());
    RUN(91, test_producer_close_timeout_zero_returns_timeout());
    RUN(92, test_producer_update_invalid_and_closed());
    RUN(93, test_sender_step_key_rate_limit_delays_then_sends());
    RUN(94, test_sender_step_credentials_provider_failure_drops());
    RUN(95, test_sender_step_retries_transport_then_ok());
    RUN(103, test_sender_step_retry_total_timeout_caps_delay());
    RUN(96, test_sender_step_compress_unsupported_drops());
    RUN(97, test_sender_step_breaker_half_open_curl_nonretry_drops());
    RUN(98, test_sender_step_http_non200_plain_message());
    RUN(99, test_sender_step_global_breaker_wait_open_then_ok());
    RUN(100, test_sender_step_precompressed_sends_ok());
    RUN(101, test_sender_main_stop_empty_returns());
    RUN(102, test_sender_main_stop_drains_send_queue_and_sends());
    RUN(104, test_queue_push_front_pop_order());
    RUN(105, test_queue_idle_cleanup_removes_expired());
    RUN(106, test_queue_delayed_promote_due_moves_to_ready());
    RUN(119, test_ingress_queue_push_pop_order_and_drain_state());
    RUN(107, test_worker_send_queue_full_drop_sampled_paths());
    RUN(108, test_worker_send_queue_block_timeout_path());
    RUN(130, test_send_queue_bytes_count_against_max_buffer_budget());
    RUN(131, test_ingress_budget_blocks_before_send_budget_is_exhausted());
    RUN(139, test_raw_add_log_budget_full_drops_before_copy_alloc());
    RUN(140, test_kv_add_log_budget_full_drops_before_builder_grow());
    RUN(141, test_breaker_ingress_fail_fast_rejects_before_queue());
    RUN(142, test_breaker_ingress_drop_with_callback_reports_drop_without_queue());
    RUN(143, test_scratch_budget_is_counted_against_max_buffer_bytes());
    RUN(120, test_worker_pack_stage_unsupported_compress_drops_before_enqueue());
    RUN(8, test_manager_callback_no_raw_buffer_on_compress_error());
    RUN(9, test_time_parts_roundtrip_in_raw_buffer());
    RUN(10, test_auto_time_ns_when_time_missing());
    RUN(11, test_retry_jitter_rand01_injectable());
    RUN(12, test_metrics_basic());
    RUN(9, test_ordered_send_max_concurrency_one());
    RUN(10, test_hashkey_partition_parallelism());
    RUN(11, test_agg_strategy_split_by_compressed_limit());
    RUN(12, test_key_queue_max_active_drops());
    RUN(13, test_key_rate_limit_is_per_key());
    RUN(14, test_rate_limit_rps_throttles());
    RUN(15, test_circuit_breaker_delays_second_send());
    RUN(16, test_sign());
    RUN(127, test_sign_matches_go_reference_with_fixed_xdate());
    RUN(128, test_builder_flush_interval_respects_configured_deadline());
    RUN(129, test_sender_idle_wait_without_delayed_does_not_spin_timedwait());
    RUN(118, test_sign_cache_secret_change_same_pointer_effective());
    RUN(17, test_send_queue_blocking_push());
    {
        int x = test_dynamic_credentials_refreshes_token();
        if (x != 0) {
            fprintf(stderr,
                "test_dynamic_credentials_refreshes_token failed: %d (req=%d provider_calls=%d seen1='%s' seen2='%s')\n",
                x, g_cred_req, g_cred_provider_calls, g_cred_seen_1, g_cred_seen_2);
            rc = 18;
            goto end;
        }
    }
    {
        int x = test_dynamic_credentials_failure_does_not_deadlock();
        if (x != 0) {
            fprintf(stderr, "test_dynamic_credentials_failure_does_not_deadlock failed: %d\n", x);
            rc = 19;
            goto end;
        }
    }
    RUN(20, test_graceful_close_ok());
    RUN(21, test_graceful_close_timeout());
    RUN(22, test_close_rejects_new_writes());
    RUN(23, test_create_fail_fast_missing_required());
    RUN(24, test_create_deep_copies_string_fields());
    RUN(25, test_runtime_config_update_effective_for_new_requests());
    RUN(109, test_runtime_snapshot_reflects_runtime_updates());
    RUN(110, test_obj_pool_reuses_recent_item());
    RUN(26, test_runtime_update_rejected_during_close());
    RUN(27, test_sender_builds_headers_and_http_options());
    RUN(28, test_raw_add_log_paths_ok());
    RUN(132, test_add_log_with_id_returns_monotonic_ids());
    RUN(29, test_send_queue_full_paths_drop_and_timeout());
    RUN(30, test_env_shared_senders_multi_producer());
    RUN(31, test_env_create_without_init_fails());
    RUN(32, test_env_destroy_timeout_then_recover());
    RUN(33, test_env_init_idempotent());
    RUN(34, test_alloc_fail_add_log_raw_drops());
    RUN(35, test_alloc_fail_add_log_kv_drops());
    RUN(36, test_alloc_fail_env_init_fails());
    RUN(74, test_alloc_failtrack_producer_create_no_leak());
    RUN(63, test_alloc_tracking_env_lifecycle_no_leak());
    RUN(64, test_alloc_tracking_sign_success_no_leak());
    RUN(117, test_sign_allocation_budget());
    RUN(65, test_alloc_tracking_producer_lifecycle_no_leak());
    RUN(69, test_alloc_fail_fuzz_sign_does_not_crash());
    RUN(70, test_alloc_fail_fuzz_proto_does_not_crash());
    RUN(109, test_alloc_fail_fuzz_proto_group_list_does_not_crash());
    RUN(110, test_proto_group_list_edge_cases());
    RUN(111, test_compress_apply_edge_cases());
    RUN(114, test_alloc_hooks_and_small_edge_cases());
    RUN(138, test_config_init_request_timeout_default_is_50s());
    RUN(133, test_producer_derived_defaults_follow_memory_budget());
    RUN(134, test_producer_derived_defaults_preserve_explicit_overrides());
    RUN(135, test_producer_create_rejects_block_without_timeout());
    RUN(136, test_producer_create_rejects_block_when_buffer_smaller_than_two_packages());
    RUN(137, test_producer_create_allows_low_resource_block_config_and_derives_send_reserve());
    RUN(112, test_send_queue_push_timeout_returns_minus2());
    RUN(113, test_send_queue_stop_causes_push_pop_fail());
    RUN(115, test_add_log_with_len_exports_one_record());
    RUN(116, test_export_raw_buffer_includes_tls_batch_with_len());
    RUN(121, test_template_lifecycle_and_add_values_exports_one_record());
    RUN(122, test_template_add_values_value_count_mismatch_invalid());
    RUN(123, test_template_high_rate_submit_metrics());
    RUN(124, test_pipeline_v2_functional_matrix_raw_kv_template_and_runtime_updates());
#if defined(VE_TLS_HAVE_ZLIB)
    RUN(37, test_zlib_compress_roundtrip());
#endif
#if defined(VE_TLS_HAVE_LZ4)
    RUN(38, test_lz4_compress_roundtrip());
#endif

end:
#undef RUN
    return rc;
}
