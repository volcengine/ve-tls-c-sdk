#include "ve_tls_hash.h"
#include "ve_tls_compress.h"
#include "ve_tls_proto.h"
#include "ve_tls_sign.h"
#include "ve_tls_producer.h"
#include "ve_tls_version.h"
#include "producer/ve_tls_producer_internal.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#if defined(VE_TLS_HAVE_ZLIB)
#include <zlib.h>
#endif

#if defined(VE_TLS_HAVE_LZ4)
#include "lz4.h"
#endif

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
    if (ve_tls_send_queue_init(&q, &platform, 1) != 0) {
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
    cfg.log_bytes_per_package = 1024 * 1024;
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
    if (test_sha256() != 0) return 1;
    if (test_proto() != 0) return 2;
    if (test_proto_log_group_list_multi_groups() != 0) return 3;
    if (test_proto_time_ns() != 0) return 4;
    if (test_proto_log_tags_and_context_flow() != 0) return 5;
    if (test_structured_error_and_retryable() != 0) return 6;
    if (test_export_import_raw_buffer() != 0) return 7;
    if (test_manager_callback_no_raw_buffer_on_compress_error() != 0) return 8;
    if (test_time_parts_roundtrip_in_raw_buffer() != 0) return 9;
    if (test_auto_time_ns_when_time_missing() != 0) return 10;
    if (test_metrics_basic() != 0) return 11;
    if (test_ordered_send_max_concurrency_one() != 0) return 9;
    if (test_hashkey_partition_parallelism() != 0) return 10;
    if (test_agg_strategy_split_by_compressed_limit() != 0) return 11;
    if (test_key_queue_max_active_drops() != 0) return 12;
    if (test_key_rate_limit_is_per_key() != 0) return 13;
    if (test_rate_limit_rps_throttles() != 0) return 14;
    if (test_circuit_breaker_delays_second_send() != 0) return 15;
    if (test_sign() != 0) return 16;
    if (test_send_queue_blocking_push() != 0) return 17;
    {
        int rc = test_dynamic_credentials_refreshes_token();
        if (rc != 0) {
            fprintf(stderr,
                "test_dynamic_credentials_refreshes_token failed: %d (req=%d provider_calls=%d seen1='%s' seen2='%s')\n",
                rc, g_cred_req, g_cred_provider_calls, g_cred_seen_1, g_cred_seen_2);
            return 18;
        }
    }
    {
        int rc = test_dynamic_credentials_failure_does_not_deadlock();
        if (rc != 0) {
            fprintf(stderr, "test_dynamic_credentials_failure_does_not_deadlock failed: %d\n", rc);
            return 19;
        }
    }
    if (test_graceful_close_ok() != 0) return 20;
    if (test_graceful_close_timeout() != 0) return 21;
    if (test_close_rejects_new_writes() != 0) return 22;
    if (test_create_fail_fast_missing_required() != 0) return 23;
    if (test_create_deep_copies_string_fields() != 0) return 24;
    if (test_runtime_config_update_effective_for_new_requests() != 0) return 25;
    if (test_runtime_update_rejected_during_close() != 0) return 26;
#if defined(VE_TLS_HAVE_ZLIB)
    if (test_zlib_compress_roundtrip() != 0) return 27;
#endif
#if defined(VE_TLS_HAVE_LZ4)
    if (test_lz4_compress_roundtrip() != 0) return 28;
#endif
    return 0;
}
