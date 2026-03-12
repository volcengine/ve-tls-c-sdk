#include "ve_tls_producer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static int http_ok_do(ve_tls_http_client * client, const ve_tls_http_request * req, ve_tls_http_response * resp) {
    (void)client;
    (void)req;
    if (!resp) return -1;
    resp->status_code = 200;
    resp->request_id = strdup("rid-bench");
    resp->body = NULL;
    resp->body_size = 0;
    return 0;
}

static void http_ok_free(ve_tls_http_client * client, ve_tls_http_response * resp) {
    (void)client;
    if (!resp) return;
    free(resp->request_id);
    free(resp->error_code);
    free(resp->error_message);
    free(resp->body);
    resp->request_id = NULL;
    resp->error_code = NULL;
    resp->error_message = NULL;
    resp->body = NULL;
    resp->body_size = 0;
}

static int parse_i32(const char * s, int32_t * out) {
    if (!s || !out) return -1;
    char * end = NULL;
    long v = strtol(s, &end, 10);
    if (end == s || *end != 0) return -1;
    if (v < INT32_MIN || v > INT32_MAX) return -1;
    *out = (int32_t)v;
    return 0;
}

static void usage(const char * argv0) {
    fprintf(stderr, "usage: %s [--duration-s S] [--rate-lps N] [--message-bytes N] [--flush-every-n N] [--close-timeout-ms N]\n", argv0 ? argv0 : "ve_tls_bench");
    fprintf(stderr, "optional: [--max-buffer-bytes N] [--send-queue-size N] [--flush-interval-ms N] [--log-count-per-package N]\n");
}

int main(int argc, char ** argv) {
    int32_t duration_s = 10;
    int32_t rate_lps = 5000;
    int32_t message_bytes = 256;
    int32_t flush_every_n = 0;
    int32_t close_timeout_ms = 60000;
    int32_t max_buffer_bytes = 0;
    int32_t send_queue_size = 0;
    int32_t flush_interval_ms = 0;
    int32_t log_count_per_package = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        }
        if (i + 1 >= argc) {
            usage(argv[0]);
            return 2;
        }
        const char * k = argv[i];
        const char * v = argv[++i];
        if (strcmp(k, "--duration-s") == 0) {
            if (parse_i32(v, &duration_s) != 0 || duration_s <= 0) return 2;
        } else if (strcmp(k, "--rate-lps") == 0) {
            if (parse_i32(v, &rate_lps) != 0 || rate_lps < 0) return 2;
        } else if (strcmp(k, "--message-bytes") == 0) {
            if (parse_i32(v, &message_bytes) != 0 || message_bytes < 1) return 2;
        } else if (strcmp(k, "--flush-every-n") == 0) {
            if (parse_i32(v, &flush_every_n) != 0 || flush_every_n < 0) return 2;
        } else if (strcmp(k, "--close-timeout-ms") == 0) {
            if (parse_i32(v, &close_timeout_ms) != 0) return 2;
        } else if (strcmp(k, "--max-buffer-bytes") == 0) {
            if (parse_i32(v, &max_buffer_bytes) != 0 || max_buffer_bytes < 0) return 2;
        } else if (strcmp(k, "--send-queue-size") == 0) {
            if (parse_i32(v, &send_queue_size) != 0 || send_queue_size < 0) return 2;
        } else if (strcmp(k, "--flush-interval-ms") == 0) {
            if (parse_i32(v, &flush_interval_ms) != 0 || flush_interval_ms < 0) return 2;
        } else if (strcmp(k, "--log-count-per-package") == 0) {
            if (parse_i32(v, &log_count_per_package) != 0 || log_count_per_package < 0) return 2;
        } else {
            usage(argv[0]);
            return 2;
        }
    }

    char * msg = (char *)malloc((size_t)message_bytes + 1);
    if (!msg) return 3;
    memset(msg, 'a', (size_t)message_bytes);
    msg[message_bytes] = 0;

    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "bench-topic";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.retry_policy.max_attempts = 1;
    cfg.send_thread_count = 4;
    cfg.send_queue_full_policy = VE_TLS_SEND_QUEUE_FULL_BLOCK;
    cfg.send_queue_block_timeout_ms = 5000;
    cfg.send_queue_size = 4096;
    cfg.flush_interval_ms = 100;
    cfg.log_count_per_package = 512;
    cfg.max_buffer_bytes = 16 * 1024 * 1024;
    cfg.http_client.do_request = http_ok_do;
    cfg.http_client.free_response = http_ok_free;
    if (max_buffer_bytes > 0) cfg.max_buffer_bytes = max_buffer_bytes;
    if (send_queue_size > 0) cfg.send_queue_size = send_queue_size;
    if (flush_interval_ms > 0) cfg.flush_interval_ms = flush_interval_ms;
    if (log_count_per_package > 0) cfg.log_count_per_package = log_count_per_package;

    ve_tls_producer * p = ve_tls_producer_create(&cfg);
    if (!p) {
        free(msg);
        return 4;
    }

    ve_tls_kv kvs[1];
    kvs[0].key = "message";
    kvs[0].value = msg;

    int64_t start_ms = cfg.platform.time_ms();
    int64_t end_ms = start_ms + (int64_t)duration_s * 1000;
    int64_t next_tick = start_ms;
    int64_t sent = 0;
    int64_t seq = 0;

    while (cfg.platform.time_ms() < end_ms) {
        if (rate_lps > 0) {
            int64_t now = cfg.platform.time_ms();
            if (now < next_tick) {
                int32_t sleep_ms = (int32_t)(next_tick - now);
                if (sleep_ms > 0) cfg.platform.sleep_ms(sleep_ms);
            }
            next_tick += 1000 / rate_lps;
            if (next_tick < cfg.platform.time_ms()) next_tick = cfg.platform.time_ms();
        }

        int flush = (flush_every_n > 0 && (seq % flush_every_n) == 0) ? 1 : 0;
        ve_tls_result rc = ve_tls_producer_add_log_kv(p, 0, kvs, 1, flush);
        if (rc != VE_TLS_OK) {
            break;
        }
        sent++;
        seq++;
    }

    ve_tls_result close_rc = ve_tls_producer_close(p, close_timeout_ms);
    ve_tls_metrics m;
    memset(&m, 0, sizeof(m));
    ve_tls_producer_get_metrics(p, &m);
    ve_tls_producer_destroy(p);
    free(msg);

    int64_t dur_ms = cfg.platform.time_ms() - start_ms;
    double dur_s = dur_ms > 0 ? (double)dur_ms / 1000.0 : 0.001;
    fprintf(stderr, "bench close_rc=%d duration_ms=%lld\n", (int)close_rc, (long long)dur_ms);
    fprintf(stderr, "bench loops=%lld loops_per_s=%.2f\n", (long long)sent, dur_s > 0 ? (double)sent / dur_s : 0.0);
    fprintf(stderr, "metrics logs_enqueued_total=%llu logs_dropped_total=%llu bytes_enqueued_total=%llu bytes_dropped_total=%llu\n",
        (unsigned long long)m.logs_enqueued_total,
        (unsigned long long)m.logs_dropped_total,
        (unsigned long long)m.bytes_enqueued_total,
        (unsigned long long)m.bytes_dropped_total
    );
    fprintf(stderr, "metrics requests_total=%llu requests_failed_total=%llu retries_total=%llu bytes_sent_total=%llu\n",
        (unsigned long long)m.requests_total,
        (unsigned long long)m.requests_failed_total,
        (unsigned long long)m.retries_total,
        (unsigned long long)m.bytes_sent_total
    );
    if (dur_s > 0) {
        fprintf(stderr, "throughput logs_per_s=%.2f bytes_per_s=%.2f\n",
            (double)m.logs_enqueued_total / dur_s,
            (double)m.bytes_sent_total / dur_s
        );
    }
    return 0;
}
