#include "ve_tls_producer.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

/*
 * 0: local demo path. It injects a mock HTTP client, so no network or real
 *    credentials are required.
 * 1: real TLS sending path. Build the SDK with VE_TLS_ENABLE_CURL=ON and pass
 *    -DVE_TLS_CAMERA_DEMO_SEND_TO_TLS=1 when compiling this demo.
 */
#ifndef VE_TLS_CAMERA_DEMO_SEND_TO_TLS
#define VE_TLS_CAMERA_DEMO_SEND_TO_TLS 0
#endif

#if VE_TLS_CAMERA_DEMO_SEND_TO_TLS && !defined(VE_TLS_HAVE_CURL)
#error "VE_TLS_CAMERA_DEMO_SEND_TO_TLS requires SDK build with VE_TLS_ENABLE_CURL=ON"
#endif

typedef struct {
    const char * credential_url;
    const char * device_id;
    const char * device_secret;

    char endpoint[256];
    char region[64];
    char topic_id[128];
    char access_key_id[256];
    char access_key_secret[256];
    char session_token[2048];
    int64_t expire_time_ms;
    int64_t refresh_advance_ms;
    int64_t credential_ttl_ms;
    int credential_version;
    int refresh_inflight;
    int mock_request_count;
} camera_tls_ctx;

static int64_t now_ms(void) {
    struct timeval tv;
    if (gettimeofday(&tv, NULL) != 0) {
        return (int64_t)time(NULL) * 1000;
    }
    return (int64_t)tv.tv_sec * 1000 + (int64_t)tv.tv_usec / 1000;
}

static int copy_cstr(char * dst, size_t dst_size, const char * src) {
    if (!dst || dst_size == 0 || !src) return -1;
    int n = snprintf(dst, dst_size, "%s", src);
    return (n < 0 || (size_t)n >= dst_size) ? -1 : 0;
}

static int fetch_credentials_from_server(camera_tls_ctx * ctx) {
    if (!ctx) return -1;

    /*
     * Replace this block with a business-server request, for example:
     *
     *   POST /api/v1/cameras/{deviceId}/tls-credential
     *   Authorization: device signature or mTLS
     *
     * Parse response fields:
     *   endpoint, region, topicId,
     *   accessKeyId, secretAccessKey, sessionToken, expireTimeMs
     *
     * The SDK credentials_provider only refreshes AK/SK/token. If endpoint,
     * region, or topic changes after producer creation, call
     * ve_tls_producer_update_endpoint() explicitly.
     */
    ctx->credential_version++;
    if (copy_cstr(ctx->endpoint, sizeof(ctx->endpoint), "https://tls-cn-beijing.volces.com") != 0 ||
        copy_cstr(ctx->region, sizeof(ctx->region), "cn-beijing") != 0 ||
        copy_cstr(ctx->topic_id, sizeof(ctx->topic_id), "your-topic-id") != 0) {
        return -1;
    }

    int n1 = snprintf(ctx->access_key_id, sizeof(ctx->access_key_id), "temp-access-key-id-v%d", ctx->credential_version);
    int n2 = snprintf(ctx->access_key_secret, sizeof(ctx->access_key_secret), "temp-secret-access-key-v%d", ctx->credential_version);
    int n3 = snprintf(ctx->session_token, sizeof(ctx->session_token), "temp-session-token-v%d", ctx->credential_version);
    if (n1 < 0 || n2 < 0 || n3 < 0 ||
        (size_t)n1 >= sizeof(ctx->access_key_id) ||
        (size_t)n2 >= sizeof(ctx->access_key_secret) ||
        (size_t)n3 >= sizeof(ctx->session_token)) {
        return -1;
    }

    /* Demo uses a short TTL to show refresh. Production should use expireTimeMs from the server. */
    ctx->expire_time_ms = now_ms() + ctx->credential_ttl_ms;
    printf("fetched temp credentials version=%d\n", ctx->credential_version);
    return 0;
}

static int credentials_hard_valid(const camera_tls_ctx * ctx) {
    if (!ctx || ctx->access_key_id[0] == 0 || ctx->access_key_secret[0] == 0) {
        return 0;
    }
    return now_ms() < ctx->expire_time_ms;
}

static int credentials_need_soft_refresh(const camera_tls_ctx * ctx) {
    if (!ctx || ctx->refresh_inflight || !credentials_hard_valid(ctx)) {
        return 0;
    }
    return now_ms() + ctx->refresh_advance_ms >= ctx->expire_time_ms;
}

static void business_maybe_start_background_refresh(camera_tls_ctx * ctx) {
    if (!credentials_need_soft_refresh(ctx)) {
        return;
    }
    ctx->refresh_inflight = 1;
    printf("business soft refresh started; continuing to serve old token version=%d until hard expire\n",
        ctx->credential_version);
}

static int business_finish_background_refresh(camera_tls_ctx * ctx) {
    if (!ctx || !ctx->refresh_inflight) {
        return 0;
    }
    if (fetch_credentials_from_server(ctx) != 0) {
        return -1;
    }
    ctx->refresh_inflight = 0;
    printf("business background refresh finished; new token version=%d\n", ctx->credential_version);
    return 0;
}

static int tls_credentials_provider(ve_tls_credentials * out, void * user_param) {
    camera_tls_ctx * ctx = (camera_tls_ctx *)user_param;
    if (!out || !ctx) return -1;

    if (!credentials_hard_valid(ctx)) {
        fprintf(stderr, "cached temp credentials expired before business refresh completed\n");
        return -1;
    }

    printf("provider using cached temp credentials version=%d\n", ctx->credential_version);
    out->access_key_id = ctx->access_key_id;
    out->access_key_secret = ctx->access_key_secret;
    out->security_token = ctx->session_token;
    out->expire_time_ms = ctx->expire_time_ms;
    return 0;
}

#if !VE_TLS_CAMERA_DEMO_SEND_TO_TLS
static int demo_http_ok(ve_tls_http_client * client, const ve_tls_http_request * req, ve_tls_http_response * resp) {
    camera_tls_ctx * ctx = client ? (camera_tls_ctx *)client->user_data : NULL;
    if (!req || !resp) return -1;
    int token_version = 0;
    if (ctx && req->headers) {
        for (int i = 1; i <= ctx->credential_version; i++) {
            char token[64];
            int n = snprintf(token, sizeof(token), "temp-session-token-v%d", i);
            if (n > 0 && (size_t)n < sizeof(token) && strstr(req->headers, token)) {
                token_version = i;
            }
        }
        ctx->mock_request_count++;
    }
    printf("mock send request=%d token_version=%d url=%s body_size=%zu\n",
        ctx ? ctx->mock_request_count : 0,
        token_version,
        req->url ? req->url : "",
        req->body_size);
    resp->status_code = 200;
    return 0;
}

static void demo_http_free(ve_tls_http_client * client, ve_tls_http_response * resp) {
    (void)client;
    (void)resp;
}
#endif

static void on_send_done(
    ve_tls_result result,
    size_t log_bytes,
    size_t compressed_bytes,
    const ve_tls_error * error,
    const unsigned char * raw_buffer,
    void * user_param,
    int64_t start_id,
    int64_t end_id
) {
    (void)raw_buffer;
    (void)user_param;
    printf("send_done result=%d log_bytes=%zu compressed_bytes=%zu request_id=%s error=%s start=%lld end=%lld\n",
        (int)result,
        log_bytes,
        compressed_bytes,
        error && error->request_id ? error->request_id : "",
        error && error->error_message ? error->error_message : "",
        (long long)start_id,
        (long long)end_id);
}

static ve_tls_result send_camera_heartbeat(ve_tls_producer * producer, const camera_tls_ctx * ctx) {
    ve_tls_kv kvs[4];
    kvs[0] = (ve_tls_kv){"device_id", ctx->device_id};
    kvs[1] = (ve_tls_kv){"event_type", "heartbeat"};
    kvs[2] = (ve_tls_kv){"status", "online"};
    kvs[3] = (ve_tls_kv){"message", "camera heartbeat"};
    return ve_tls_producer_add_log_kv_hashkey(producer, 0, ctx->device_id, kvs, 4, 1);
}

int main(void) {
    camera_tls_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.credential_url = "https://api.example.com/api/v1/cameras/cam-001/tls-credential";
    ctx.device_id = "cam-001";
    ctx.device_secret = "device-secret";
    ctx.credential_ttl_ms = 1500;
    ctx.refresh_advance_ms = 1000;

    if (fetch_credentials_from_server(&ctx) != 0) {
        fprintf(stderr, "fetch initial tls credentials failed\n");
        return 1;
    }

    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    cfg.endpoint = ctx.endpoint;
    cfg.region = ctx.region;
    cfg.topic_id = ctx.topic_id;
    cfg.source = ctx.device_id;
    cfg.file_name = "camera-runtime";
    cfg.flush_interval_ms = 1000;
    cfg.log_count_per_package = 256;
    cfg.max_buffer_bytes = 8 * 1024 * 1024;
    cfg.buffer_full_policy = VE_TLS_BUFFER_FULL_DROP;
    cfg.send_queue_full_policy = VE_TLS_SEND_QUEUE_FULL_DROP;
    cfg.credentials_provider = tls_credentials_provider;
    cfg.credentials_provider_param = &ctx;
    /* Business code owns soft refresh. Let SDK call provider only at hard-expire time. */
    cfg.credentials_expire_advance_ms = 0;
    cfg.credentials_refresh_min_interval_ms = 0;
    cfg.connect_timeout_ms = 3000;
    cfg.request_timeout_ms = 5000;
    cfg.retry_policy.max_attempts = 2;
    cfg.retry_policy.total_timeout_ms = 10000;

#if VE_TLS_CAMERA_DEMO_SEND_TO_TLS
    /*
     * Real sending path:
     *   - build SDK with VE_TLS_ENABLE_CURL=ON
     *   - compile this file with -DVE_TLS_CAMERA_DEMO_SEND_TO_TLS=1
     *   - replace fetch_credentials_from_server() with your real API call
     *
     * Do not override cfg.http_client here. ve_tls_config_init() has already
     * installed the SDK curl adapter when VE_TLS_HAVE_CURL is enabled.
     */
#else
    cfg.http_client.do_request = demo_http_ok;
    cfg.http_client.free_response = demo_http_free;
    cfg.http_client.user_data = &ctx;
#endif

    ve_tls_producer * producer = ve_tls_producer_create(&cfg);
    if (!producer) {
        fprintf(stderr, "create tls producer failed\n");
        return 2;
    }
    ve_tls_producer_set_send_done_v2(producer, on_send_done, NULL);

    ve_tls_result rc = send_camera_heartbeat(producer, &ctx);
    if (rc != VE_TLS_OK) {
        fprintf(stderr, "enqueue tls log failed rc=%d\n", (int)rc);
        ve_tls_producer_destroy(producer);
        return 3;
    }

    /*
     * Demo only: enter the soft refresh window, but do not replace the cached
     * credentials yet. Production would start an async request here.
     */
    if (cfg.platform.sleep_ms) {
        cfg.platform.sleep_ms(700);
    }
    business_maybe_start_background_refresh(&ctx);

    rc = send_camera_heartbeat(producer, &ctx);
    if (rc != VE_TLS_OK) {
        fprintf(stderr, "enqueue tls log during refresh failed rc=%d\n", (int)rc);
        ve_tls_producer_destroy(producer);
        return 4;
    }

#if !VE_TLS_CAMERA_DEMO_SEND_TO_TLS
    for (int i = 0; i < 100 && ctx.mock_request_count < 2; i++) {
        if (cfg.platform.sleep_ms) {
            cfg.platform.sleep_ms(10);
        }
    }
#endif

    if (business_finish_background_refresh(&ctx) != 0) {
        fprintf(stderr, "finish background credentials refresh failed\n");
        ve_tls_producer_destroy(producer);
        return 5;
    }

    if (cfg.platform.sleep_ms) {
        cfg.platform.sleep_ms(1200);
    }

    rc = send_camera_heartbeat(producer, &ctx);
    if (rc != VE_TLS_OK) {
        fprintf(stderr, "enqueue tls log after refresh failed rc=%d\n", (int)rc);
        ve_tls_producer_destroy(producer);
        return 6;
    }

    (void)ve_tls_producer_flush(producer);
    rc = ve_tls_producer_close(producer, 10000);
    ve_tls_producer_destroy(producer);
    return rc == VE_TLS_OK ? 0 : 7;
}
