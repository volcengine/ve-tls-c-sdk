#include "ve_tls_producer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static const char * env_str(const char * key, const char * defv) {
    const char * v = getenv(key);
    return (v && v[0] != 0) ? v : defv;
}

static int32_t env_i32(const char * key, int32_t defv) {
    const char * s = getenv(key);
    if (!s || s[0] == 0) return defv;
    char * end = NULL;
    long v = strtol(s, &end, 10);
    if (!end || end == s) return defv;
    return (int32_t)v;
}

static void usage(const char * argv0) {
    fprintf(stderr, "usage: %s [--help]\n", argv0 ? argv0 : "ve_tls_demo");
    fprintf(stderr, "required env: VE_TLS_ENDPOINT VE_TLS_REGION VE_TLS_TOPIC_ID VE_TLS_ACCESS_KEY_ID VE_TLS_ACCESS_KEY_SECRET\n");
    fprintf(stderr, "optional env: VE_TLS_SECURITY_TOKEN VE_TLS_HASH_KEY VE_TLS_DEMO_MESSAGE VE_TLS_COMPRESS_TYPE VE_TLS_FLUSH_INTERVAL_MS VE_TLS_SEND_THREAD_COUNT VE_TLS_CLOSE_TIMEOUT_MS VE_TLS_HTTP_DEBUG\n");
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
    (void)raw_buffer;
    (void)user_param;
    printf("PRODUCER_DEMO_CALLBACK result=%d log_bytes=%zu compressed_bytes=%zu request_id=%s error=%s start=%lld end=%lld\n",
        (int)result,
        log_bytes,
        compressed_bytes,
        (error && error->request_id) ? error->request_id : "",
        (error && error->error_message) ? error->error_message : "",
        (long long)start_id,
        (long long)end_id);
}

int main(int argc, char ** argv) {
    if (argc > 1 && strcmp(argv[1], "--help") == 0) {
        usage(argv[0]);
        return 0;
    }

#if !defined(VE_TLS_HAVE_CURL)
    fprintf(stderr, "ve_tls_demo requires VE_TLS_ENABLE_CURL=ON at build time\n");
    return 2;
#else
    ve_tls_config cfg;
    ve_tls_producer * producer;
    ve_tls_metrics metrics;
    ve_tls_kv kvs[4];
    const char * endpoint = env_str("VE_TLS_ENDPOINT", NULL);
    const char * region = env_str("VE_TLS_REGION", NULL);
    const char * topic_id = env_str("VE_TLS_TOPIC_ID", NULL);
    const char * access_key_id = env_str("VE_TLS_ACCESS_KEY_ID", NULL);
    const char * access_key_secret = env_str("VE_TLS_ACCESS_KEY_SECRET", NULL);
    const char * security_token = env_str("VE_TLS_SECURITY_TOKEN", "");
    const char * hash_key = env_str("VE_TLS_HASH_KEY", NULL);
    const char * message = env_str("VE_TLS_DEMO_MESSAGE", "hello from producer demo");
    const char * compress_type = env_str("VE_TLS_COMPRESS_TYPE", NULL);
    int32_t flush_interval_ms = env_i32("VE_TLS_FLUSH_INTERVAL_MS", 1000);
    int32_t send_thread_count = env_i32("VE_TLS_SEND_THREAD_COUNT", 1);
    int32_t close_timeout_ms = env_i32("VE_TLS_CLOSE_TIMEOUT_MS", 5000);
    int32_t http_debug = env_i32("VE_TLS_HTTP_DEBUG", 0);
    ve_tls_result add_rc;
    ve_tls_result close_rc;

    if (!endpoint || !region || !topic_id || !access_key_id || !access_key_secret) {
        usage(argv[0]);
        return 2;
    }

    ve_tls_config_init(&cfg);
    cfg.endpoint = endpoint;
    cfg.region = region;
    cfg.topic_id = topic_id;
    cfg.access_key_id = access_key_id;
    cfg.access_key_secret = access_key_secret;
    cfg.security_token = security_token;
    cfg.hash_key = hash_key;
    cfg.flush_interval_ms = flush_interval_ms;
    cfg.send_thread_count = send_thread_count > 0 ? send_thread_count : 1;
    cfg.http_debug = http_debug;
    if (compress_type && compress_type[0] != 0) {
        cfg.compress_type = compress_type;
    }

    producer = ve_tls_producer_create(&cfg);
    if (!producer) {
        fprintf(stderr, "ve_tls_producer_create failed\n");
        return 3;
    }
    ve_tls_producer_set_send_done_v2(producer, on_send_done_v2, NULL);

    kvs[0].key = "message";
    kvs[0].value = message;
    kvs[1].key = "demo";
    kvs[1].value = "producer";
    kvs[2].key = "sdk";
    kvs[2].value = "ve-tls-c";
    kvs[3].key = "mode";
    kvs[3].value = "async";

    add_rc = ve_tls_producer_add_log_kv_hashkey(producer, 0, hash_key, kvs, 4, 1);
    if (add_rc != VE_TLS_OK) {
        fprintf(stderr, "ve_tls_producer_add_log_kv_hashkey failed rc=%d\n", (int)add_rc);
        ve_tls_producer_destroy(producer);
        return 4;
    }

    (void)ve_tls_producer_flush(producer);
    close_rc = ve_tls_producer_close(producer, close_timeout_ms);
    memset(&metrics, 0, sizeof(metrics));
    ve_tls_producer_get_metrics(producer, &metrics);
    printf("PRODUCER_DEMO close_rc=%d logs_enqueued=%llu logs_dropped=%llu requests=%llu requests_failed=%llu retries=%llu bytes_sent=%llu\n",
        (int)close_rc,
        (unsigned long long)metrics.logs_enqueued_total,
        (unsigned long long)metrics.logs_dropped_total,
        (unsigned long long)metrics.requests_total,
        (unsigned long long)metrics.requests_failed_total,
        (unsigned long long)metrics.retries_total,
        (unsigned long long)metrics.bytes_sent_total);
    ve_tls_producer_destroy(producer);
    return close_rc == VE_TLS_OK ? 0 : 1;
#endif
}
