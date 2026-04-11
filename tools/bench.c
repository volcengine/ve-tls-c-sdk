#include "ve_tls_producer.h"
#include "ve_tls_env.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdint.h>
#include <limits.h>
#include <unistd.h>

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

static int parse_i64(const char * s, int64_t * out) {
    if (!s || !out) return -1;
    char * end = NULL;
    long long v = strtoll(s, &end, 10);
    if (end == s || *end != 0) return -1;
    *out = (int64_t)v;
    return 0;
}

typedef enum {
    WRITE_MODE_KV = 0,
    WRITE_MODE_RAW = 1,
    WRITE_MODE_TEMPLATE = 2
} write_mode_t;

static int parse_write_mode(const char * s, write_mode_t * out) {
    if (!s || !out) return -1;
    if (strcmp(s, "kv") == 0) {
        *out = WRITE_MODE_KV;
        return 0;
    }
    if (strcmp(s, "raw") == 0) {
        *out = WRITE_MODE_RAW;
        return 0;
    }
    if (strcmp(s, "template") == 0) {
        *out = WRITE_MODE_TEMPLATE;
        return 0;
    }
    return -1;
}

static const char * write_mode_str(write_mode_t mode) {
    if (mode == WRITE_MODE_RAW) return "raw";
    if (mode == WRITE_MODE_TEMPLATE) return "template";
    return "kv";
}

static int parse_queue_full_policy(const char * s, ve_tls_send_queue_full_policy * out) {
    if (!s || !out) return -1;
    if (strcasecmp(s, "block") == 0) {
        *out = VE_TLS_SEND_QUEUE_FULL_BLOCK;
        return 0;
    }
    if (strcasecmp(s, "drop") == 0) {
        *out = VE_TLS_SEND_QUEUE_FULL_DROP;
        return 0;
    }
    if (strcasecmp(s, "drop_sampled") == 0 || strcasecmp(s, "drop-sampled") == 0) {
        *out = VE_TLS_SEND_QUEUE_FULL_DROP_SAMPLED;
        return 0;
    }
    return -1;
}

static const char * queue_full_policy_str(ve_tls_send_queue_full_policy p) {
    if (p == VE_TLS_SEND_QUEUE_FULL_DROP) return "drop";
    if (p == VE_TLS_SEND_QUEUE_FULL_DROP_SAMPLED) return "drop_sampled";
    return "block";
}

static int parse_profile(const char * s, int32_t * message_bytes) {
    if (!s || !message_bytes) return -1;
    if (strcasecmp(s, "sls200") == 0) {
        *message_bytes = 200;
        return 0;
    }
    if (strcasecmp(s, "sls700") == 0) {
        *message_bytes = 700;
        return 0;
    }
    if (strcasecmp(s, "sls5120") == 0) {
        *message_bytes = 5120;
        return 0;
    }
    return -1;
}

static int32_t estimate_p99_upper_ms(const ve_tls_metrics * m) {
    if (!m) return 0;
    uint64_t total = 0;
    for (size_t i = 0; i < 8; i++) {
        total += m->request_latency_buckets[i];
    }
    if (total == 0) return 0;
    uint64_t target = (total * 99 + 99) / 100;
    uint64_t cum = 0;
    static const int32_t upper[8] = {5, 10, 50, 100, 300, 1000, 3000, 3001};
    for (size_t i = 0; i < 8; i++) {
        cum += m->request_latency_buckets[i];
        if (cum >= target) {
            return upper[i];
        }
    }
    return 3001;
}

static void usage(const char * argv0) {
    fprintf(stderr, "usage: %s [--duration-s S] [--rate-lps N] [--message-bytes N] [--writer-threads N] [--flush-every-n N] [--close-timeout-ms N] [--use-global-env 0|1] [--global-senders N]\n", argv0 ? argv0 : "ve_tls_bench");
    fprintf(stderr, "optional: [--write-mode raw|kv|template] [--template-mode on|off] [--send-thread-count N] [--compress-type none|lz4|zlib]\n");
    fprintf(stderr, "optional: [--queue-full-policy block|drop|drop_sampled] [--send-queue-block-timeout-ms N] [--max-buffer-bytes N] [--send-queue-size N] [--flush-interval-ms N] [--log-count-per-package N]\n");
    fprintf(stderr, "optional: [--use-persistent 0|1] [--persistent-dir PATH] [--profile sls200|sls700|sls5120]\n");
}

static uint64_t g_sent = 0;
static uint64_t g_seq = 0;

typedef struct {
    ve_tls_producer * producer;
    ve_tls_log_template * tpl;
    ve_tls_platform * platform;
    int32_t rate_lps;
    int32_t flush_every_n;
    write_mode_t write_mode;
    const char * value;
    size_t value_len;
    const char * raw;
    size_t raw_len;
    ve_tls_kv * kvs;
    int64_t end_ms;
} writer_ctx;

static void * writer_main(void * arg) {
    writer_ctx * c = (writer_ctx *)arg;
    int64_t next_tick = c->platform->time_ms();
    for (;;) {
        int64_t now0 = c->platform->time_ms();
        if (now0 >= c->end_ms) {
            break;
        }
        if (c->rate_lps > 0) {
            if (now0 < next_tick) {
                int32_t sleep_ms = (int32_t)(next_tick - now0);
                if (sleep_ms > 0) c->platform->sleep_ms(sleep_ms);
            }
            next_tick += 1000 / c->rate_lps;
            int64_t now1 = c->platform->time_ms();
            if (next_tick < now1) next_tick = now1;
        }
        uint64_t seq = __atomic_fetch_add(&g_seq, 1, __ATOMIC_RELAXED);
        int flush = (c->flush_every_n > 0 && (seq % (uint64_t)c->flush_every_n) == 0) ? 1 : 0;
        ve_tls_result rc;
        if (c->write_mode == WRITE_MODE_TEMPLATE) {
            const char * values[1];
            size_t value_lens[1];
            values[0] = c->value;
            value_lens[0] = c->value_len;
            rc = ve_tls_template_add_values(c->tpl, 0, 0, 0, values, value_lens, 1, flush);
        } else if (c->write_mode == WRITE_MODE_RAW) {
            rc = ve_tls_producer_add_log_raw(c->producer, c->raw, c->raw_len, flush);
        } else {
            rc = ve_tls_producer_add_log_kv(c->producer, 0, c->kvs, 1, flush);
        }
        if (rc == VE_TLS_OK) {
            __atomic_fetch_add(&g_sent, 1, __ATOMIC_RELAXED);
            continue;
        }
        if (rc == VE_TLS_DROP_ERROR) {
            continue;
        }
        break;
    }
    (void)ve_tls_producer_flush(c->producer);
    return NULL;
}

int main(int argc, char ** argv) {
    int32_t duration_s = 10;
    int32_t rate_lps = 5000;
    int32_t message_bytes = 256;
    int32_t writer_threads = 1;
    int32_t use_global_env = 0;
    int32_t global_senders = 1;
    int32_t flush_every_n = 0;
    int32_t close_timeout_ms = 60000;
    int32_t max_buffer_bytes = 0;
    int32_t send_queue_size = 0;
    int32_t flush_interval_ms = 0;
    int32_t log_count_per_package = 0;
    int32_t send_thread_count = 0;
    int32_t send_queue_block_timeout_ms = 5000;
    int32_t use_persistent = 0;
    const char * persistent_dir_arg = NULL;
    char persistent_dir_buf[PATH_MAX];
    const char * profile = "custom";
    write_mode_t write_mode = WRITE_MODE_KV;
    ve_tls_send_queue_full_policy queue_full_policy = VE_TLS_SEND_QUEUE_FULL_BLOCK;
    const char * compress_type = NULL;

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
            profile = "custom";
        } else if (strcmp(k, "--writer-threads") == 0) {
            if (parse_i32(v, &writer_threads) != 0 || writer_threads < 1) return 2;
        } else if (strcmp(k, "--use-global-env") == 0) {
            if (parse_i32(v, &use_global_env) != 0) return 2;
        } else if (strcmp(k, "--global-senders") == 0) {
            if (parse_i32(v, &global_senders) != 0 || global_senders < 1) return 2;
        } else if (strcmp(k, "--flush-every-n") == 0) {
            if (parse_i32(v, &flush_every_n) != 0 || flush_every_n < 0) return 2;
        } else if (strcmp(k, "--close-timeout-ms") == 0) {
            if (parse_i32(v, &close_timeout_ms) != 0) return 2;
        } else if (strcmp(k, "--send-thread-count") == 0) {
            if (parse_i32(v, &send_thread_count) != 0 || send_thread_count < 1) return 2;
        } else if (strcmp(k, "--compress-type") == 0) {
            compress_type = v;
        } else if (strcmp(k, "--write-mode") == 0) {
            if (parse_write_mode(v, &write_mode) != 0) return 2;
        } else if (strcmp(k, "--queue-full-policy") == 0) {
            if (parse_queue_full_policy(v, &queue_full_policy) != 0) return 2;
        } else if (strcmp(k, "--send-queue-block-timeout-ms") == 0) {
            if (parse_i32(v, &send_queue_block_timeout_ms) != 0 || send_queue_block_timeout_ms < 0) return 2;
        } else if (strcmp(k, "--max-buffer-bytes") == 0) {
            int64_t x = 0;
            if (parse_i64(v, &x) != 0 || x < 0) {
                usage(argv[0]);
                return 2;
            }
            if (x > (int64_t)INT32_MAX) {
                fprintf(stderr, "max-buffer-bytes capped to %d (int32 max)\n", (int)INT32_MAX);
                x = (int64_t)INT32_MAX;
            }
            max_buffer_bytes = (int32_t)x;
        } else if (strcmp(k, "--send-queue-size") == 0) {
            if (parse_i32(v, &send_queue_size) != 0 || send_queue_size < 0) return 2;
        } else if (strcmp(k, "--flush-interval-ms") == 0) {
            if (parse_i32(v, &flush_interval_ms) != 0 || flush_interval_ms < 0) return 2;
        } else if (strcmp(k, "--log-count-per-package") == 0) {
            if (parse_i32(v, &log_count_per_package) != 0 || log_count_per_package < 0) return 2;
        } else if (strcmp(k, "--use-persistent") == 0) {
            if (parse_i32(v, &use_persistent) != 0) return 2;
        } else if (strcmp(k, "--persistent-dir") == 0) {
            persistent_dir_arg = v;
        } else if (strcmp(k, "--profile") == 0) {
            if (parse_profile(v, &message_bytes) != 0) return 2;
            profile = v;
        } else if (strcmp(k, "--template-mode") == 0) {
            if (strcmp(v, "on") == 0) {
                write_mode = WRITE_MODE_TEMPLATE;
            } else if (strcmp(v, "off") == 0) {
                write_mode = WRITE_MODE_KV;
            } else {
                return 2;
            }
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
    cfg.send_queue_full_policy = queue_full_policy;
    cfg.send_queue_block_timeout_ms = send_queue_block_timeout_ms;
    cfg.send_queue_size = 4096;
    cfg.flush_interval_ms = 100;
    cfg.log_count_per_package = 512;
    cfg.max_buffer_bytes = 16 * 1024 * 1024;
    if (send_thread_count > 0) cfg.send_thread_count = send_thread_count;
    if (compress_type && compress_type[0] != 0) cfg.compress_type = compress_type;
    cfg.http_client.do_request = http_ok_do;
    cfg.http_client.free_response = http_ok_free;
    if (max_buffer_bytes > 0) cfg.max_buffer_bytes = max_buffer_bytes;
    if (send_queue_size > 0) cfg.send_queue_size = send_queue_size;
    if (flush_interval_ms > 0) cfg.flush_interval_ms = flush_interval_ms;
    if (log_count_per_package > 0) cfg.log_count_per_package = log_count_per_package;
    if (use_persistent) {
        if (!persistent_dir_arg || persistent_dir_arg[0] == 0) {
            snprintf(persistent_dir_buf, sizeof(persistent_dir_buf), "/tmp/ve_tls_bench_persistent_%ld", (long)getpid());
            persistent_dir_arg = persistent_dir_buf;
        }
        cfg.use_persistent = 1;
        cfg.persistent_file_path = persistent_dir_arg;
        cfg.max_persistent_file_size = 8 * 1024 * 1024;
        cfg.max_persistent_file_count = 64;
        cfg.max_persistent_log_count = 10000000;
        cfg.persistent_max_bytes = 512 * 1024 * 1024;
        cfg.persistent_max_records = 10000000;
        cfg.persistent_max_segments = 64;
        cfg.send_thread_count = 1;
    }

    if (use_global_env) {
        if (ve_tls_env_init(global_senders) != VE_TLS_OK) {
            free(msg);
            return 4;
        }
        cfg.use_global_env = 1;
    }

    ve_tls_producer * p = ve_tls_producer_create(&cfg);
    if (!p) {
        if (use_global_env) {
            (void)ve_tls_env_destroy(close_timeout_ms);
        }
        free(msg);
        return 4;
    }

    ve_tls_kv kvs[1];
    kvs[0].key = "message";
    kvs[0].value = msg;
    ve_tls_log_template * tpl = NULL;
    if (write_mode == WRITE_MODE_TEMPLATE) {
        const char * tkeys[1];
        size_t tkey_lens[1];
        tkeys[0] = "message";
        tkey_lens[0] = 7;
        tpl = ve_tls_template_create(p, tkeys, tkey_lens, 1, NULL);
        if (!tpl) {
            ve_tls_producer_destroy(p);
            free(msg);
            if (use_global_env) {
                (void)ve_tls_env_destroy(close_timeout_ms);
            }
            return 4;
        }
    }

    int64_t start_ms = cfg.platform.time_ms();
    int64_t end_ms = start_ms + (int64_t)duration_s * 1000;
    g_sent = 0;
    g_seq = 0;
    ve_tls_thread ** threads = (ve_tls_thread **)calloc((size_t)writer_threads, sizeof(ve_tls_thread *));
    writer_ctx * ctxs = (writer_ctx *)calloc((size_t)writer_threads, sizeof(writer_ctx));
    if (!threads || !ctxs) {
        free(threads);
        free(ctxs);
        ve_tls_producer_destroy(p);
        free(msg);
        return 5;
    }
    for (int32_t i = 0; i < writer_threads; i++) {
        ctxs[i].producer = p;
        ctxs[i].platform = &cfg.platform;
        ctxs[i].rate_lps = rate_lps;
        ctxs[i].flush_every_n = flush_every_n;
        ctxs[i].write_mode = write_mode;
        ctxs[i].tpl = tpl;
        ctxs[i].value = msg;
        ctxs[i].value_len = (size_t)message_bytes;
        ctxs[i].raw = msg;
        ctxs[i].raw_len = (size_t)message_bytes;
        ctxs[i].kvs = kvs;
        ctxs[i].end_ms = end_ms;
        threads[i] = cfg.platform.thread_create(writer_main, &ctxs[i]);
        if (!threads[i]) {
            writer_threads = i;
            break;
        }
    }
    for (int32_t i = 0; i < writer_threads; i++) {
        cfg.platform.thread_join(threads[i]);
    }
    int64_t produce_end_ms = cfg.platform.time_ms();
    uint64_t produced_sent = __atomic_load_n(&g_sent, __ATOMIC_RELAXED);
    free(threads);
    free(ctxs);

    int64_t close_start_ms = cfg.platform.time_ms();
    ve_tls_result close_rc = ve_tls_producer_close(p, close_timeout_ms);
    int64_t close_end_ms = cfg.platform.time_ms();
    ve_tls_metrics m;
    memset(&m, 0, sizeof(m));
    ve_tls_producer_get_metrics(p, &m);
    ve_tls_template_destroy(tpl);
    ve_tls_producer_destroy(p);
    free(msg);
    if (use_global_env) {
        (void)ve_tls_env_destroy(close_timeout_ms);
    }

    int64_t dur_ms = close_end_ms - start_ms;
    double dur_s = dur_ms > 0 ? (double)dur_ms / 1000.0 : 0.001;
    int64_t produce_ms = produce_end_ms - start_ms;
    int64_t close_ms = close_end_ms - close_start_ms;
    if (produce_ms < 0) produce_ms = 0;
    if (close_ms < 0) close_ms = 0;
    double produce_s = produce_ms > 0 ? (double)produce_ms / 1000.0 : 0.001;
    double close_s = close_ms > 0 ? (double)close_ms / 1000.0 : 0.001;
    uint64_t drained_logs = m.logs_enqueued_total > produced_sent ? (m.logs_enqueued_total - produced_sent) : 0;
    fprintf(stderr, "bench config write_mode=%s persistent=%d profile=%s target_payload_bytes=%d queue_full_policy=%s compress_type=%s writers=%d senders=%d\n",
        write_mode_str(write_mode),
        use_persistent ? 1 : 0,
        profile,
        (int)message_bytes,
        queue_full_policy_str(queue_full_policy),
        (compress_type && compress_type[0] != 0) ? compress_type : (cfg.compress_type ? cfg.compress_type : "none"),
        (int)writer_threads,
        (int)cfg.send_thread_count
    );
    fprintf(stderr, "bench close_rc=%d duration_ms=%lld\n", (int)close_rc, (long long)dur_ms);
    fprintf(stderr, "bench phases produce_ms=%lld close_ms=%lld total_ms=%lld produce_lps=%.2f close_drain_lps=%.2f total_lps=%.2f\n",
        (long long)produce_ms,
        (long long)close_ms,
        (long long)dur_ms,
        (double)produced_sent / produce_s,
        (double)drained_logs / close_s,
        dur_s > 0 ? (double)m.logs_enqueued_total / dur_s : 0.0
    );
    uint64_t sent = __atomic_load_n(&g_sent, __ATOMIC_RELAXED);
    fprintf(stderr, "bench loops=%llu loops_per_s=%.2f\n", (unsigned long long)sent, dur_s > 0 ? (double)sent / dur_s : 0.0);
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
    fprintf(stderr, "metrics latency_buckets=%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu p99_ms_upper=%d\n",
        (unsigned long long)m.request_latency_buckets[0],
        (unsigned long long)m.request_latency_buckets[1],
        (unsigned long long)m.request_latency_buckets[2],
        (unsigned long long)m.request_latency_buckets[3],
        (unsigned long long)m.request_latency_buckets[4],
        (unsigned long long)m.request_latency_buckets[5],
        (unsigned long long)m.request_latency_buckets[6],
        (unsigned long long)m.request_latency_buckets[7],
        (int)estimate_p99_upper_ms(&m)
    );
    if (dur_s > 0) {
        fprintf(stderr, "throughput logs_per_s=%.2f bytes_per_s=%.2f\n",
            (double)m.logs_enqueued_total / dur_s,
            (double)m.bytes_sent_total / dur_s
        );
    }
    return 0;
}
