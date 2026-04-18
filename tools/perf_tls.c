#include "ve_tls_producer.h"
#include "ve_tls_env.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <time.h>
#include <sys/resource.h>
#include <unistd.h>

typedef struct {
    char * kv[256][2];
    int kv_len;
    char * allocs[512];
    int alloc_len;
} conf_kv;

static void conf_free(conf_kv * c) {
    if (!c) return;
    for (int i = 0; i < c->alloc_len; i++) {
        free(c->allocs[i]);
    }
    c->alloc_len = 0;
    c->kv_len = 0;
}

static char * conf_strdup(conf_kv * c, const char * s) {
    if (!c || !s) return NULL;
    char * p = strdup(s);
    if (!p) return NULL;
    if (c->alloc_len < (int)(sizeof(c->allocs) / sizeof(c->allocs[0]))) {
        c->allocs[c->alloc_len++] = p;
        return p;
    }
    free(p);
    return NULL;
}

static char * trim_inplace(char * s) {
    while (s && *s && isspace((unsigned char)*s)) s++;
    if (!s || *s == 0) return s;
    char * end = s + strlen(s);
    while (end > s && isspace((unsigned char)end[-1])) end--;
    *end = 0;
    return s;
}

static int conf_put(conf_kv * c, const char * k, const char * v) {
    if (!c || !k || !v) return -1;
    if (c->kv_len >= (int)(sizeof(c->kv) / sizeof(c->kv[0]))) return -1;
    char * kk = conf_strdup(c, k);
    char * vv = conf_strdup(c, v);
    if (!kk || !vv) return -1;
    c->kv[c->kv_len][0] = kk;
    c->kv[c->kv_len][1] = vv;
    c->kv_len++;
    return 0;
}

static int conf_load_file(conf_kv * c, const char * path) {
    if (!c || !path) return -1;
    FILE * f = fopen(path, "rb");
    if (!f) return -1;
    char line[4096];
    while (fgets(line, (int)sizeof(line), f)) {
        char * s = trim_inplace(line);
        if (!s || s[0] == 0) continue;
        if (s[0] == '#') continue;
        char * eq = strchr(s, '=');
        if (!eq) continue;
        *eq = 0;
        char * k = trim_inplace(s);
        char * v = trim_inplace(eq + 1);
        if (!k || k[0] == 0) continue;
        if (!v) v = "";
        if (conf_put(c, k, v) != 0) {
            fclose(f);
            return -1;
        }
    }
    fclose(f);
    return 0;
}

static const char * conf_get_str(conf_kv * c, const char * key, const char * defv) {
    if (!key) return defv;
    for (int i = 0; c && i < c->kv_len; i++) {
        if (strcmp(c->kv[i][0], key) == 0) {
            const char * v = c->kv[i][1];
            return (v && v[0] != 0) ? v : defv;
        }
    }
    const char * e = getenv(key);
    return (e && e[0] != 0) ? e : defv;
}

static int32_t conf_get_i32(conf_kv * c, const char * key, int32_t defv) {
    const char * s = conf_get_str(c, key, NULL);
    if (!s || s[0] == 0) return defv;
    char * end = NULL;
    long v = strtol(s, &end, 10);
    if (!end || end == s) return defv;
    if (v < INT32_MIN || v > INT32_MAX) return defv;
    return (int32_t)v;
}

static int conf_has_key(conf_kv * c, const char * key) {
    if (!key) return 0;
    for (int i = 0; c && i < c->kv_len; i++) {
        if (strcmp(c->kv[i][0], key) == 0) {
            return 1;
        }
    }
    {
        const char * e = getenv(key);
        return (e && e[0] != 0) ? 1 : 0;
    }
}

static uint64_t now_ns(void) {
    struct timespec ts;
    memset(&ts, 0, sizeof(ts));
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void sleep_until_ns(uint64_t deadline_ns) {
    for (;;) {
        uint64_t now = now_ns();
        if (now >= deadline_ns) return;
        uint64_t diff = deadline_ns - now;
        struct timespec ts;
        ts.tv_sec = (time_t)(diff / 1000000000ULL);
        ts.tv_nsec = (long)(diff % 1000000000ULL);
        nanosleep(&ts, NULL);
    }
}

static int http_ok_do(ve_tls_http_client * client, const ve_tls_http_request * req, ve_tls_http_response * resp) {
    (void)client;
    (void)req;
    if (!resp) return -1;
    resp->status_code = 200;
    resp->request_id = strdup("rid-tls-mock");
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

typedef struct {
    ve_tls_platform * platform;
    ve_tls_mutex * mu;
    ve_tls_cond * cv;
    int started;
    uint64_t start_ns;
    uint64_t end_ns;
} start_gate;

typedef struct {
    ve_tls_producer * producer;
    const ve_tls_kv * kvs;
    size_t kv_count;
    start_gate * gate;
    int64_t rate_total_lps;
    int32_t writers;
    int32_t writer_idx;
    uint64_t ok;
    uint64_t drop;
    uint64_t other;
} writer_ctx;

static void * writer_main(void * arg) {
    writer_ctx * c = (writer_ctx *)arg;
    uint64_t start_ns = 0;
    uint64_t end_ns = 0;
    if (c->gate && c->gate->platform && c->gate->mu && c->gate->cv) {
        c->gate->platform->mutex_lock(c->gate->mu);
        while (!c->gate->started) {
            c->gate->platform->cond_wait(c->gate->cv, c->gate->mu);
        }
        start_ns = c->gate->start_ns;
        end_ns = c->gate->end_ns;
        c->gate->platform->mutex_unlock(c->gate->mu);
    }
    uint64_t interval_ns = 0;
    if (c->rate_total_lps > 0) {
        interval_ns = 1000000000ULL / (uint64_t)c->rate_total_lps;
        if (interval_ns == 0) interval_ns = 1;
    }
    uint64_t next_deadline = start_ns + (uint64_t)c->writer_idx * interval_ns;
    uint64_t stride = interval_ns * (uint64_t)c->writers;
    for (;;) {
        uint64_t t = now_ns();
        if (t >= end_ns) break;
        if (c->rate_total_lps > 0) {
            if (t < next_deadline) {
                sleep_until_ns(next_deadline);
            }
            next_deadline += stride;
        }
        ve_tls_result rc = ve_tls_producer_add_log_kv(c->producer, 0, c->kvs, c->kv_count, 0);
        if (rc == VE_TLS_OK) {
            c->ok++;
        } else if (rc == VE_TLS_DROP_ERROR) {
            c->drop++;
        } else {
            c->other++;
            break;
        }
    }
    return NULL;
}

static const ve_tls_kv k_tls_200_kvs[] = {
    {"Interconnection", "Grafana and JDBC/SQL92"},
    {"LogHub", "Real-time log collection and consumption"},
    {"Search/Analytics", "Query and real-time analysis"},
    {"Visualized", "dashboard and report functions"}
};

static const ve_tls_kv k_tls_700_kvs[] = {
    {"content_key_1", "1abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+"},
    {"content_key_2", "2abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+"},
    {"content_key_3", "3abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+"},
    {"content_key_4", "4abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+"},
    {"content_key_5", "5abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+"},
    {"content_key_6", "6abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+"},
    {"content_key_7", "7abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+"},
    {"content_key_8", "8abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+"},
    {"content_key_9", "9abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+"},
    {"index", "0"}
};

static const ve_tls_kv k_tls_tags[] = {
    {"tag_1", "val_1"},
    {"tag_2", "val_2"},
    {"tag_3", "val_3"},
    {"tag_4", "val_4"},
    {"tag_5", "val_5"}
};

static double tv_to_s(struct timeval tv) {
    return (double)tv.tv_sec + (double)tv.tv_usec / 1000000.0;
}

static void usage(const char * argv0) {
    fprintf(stderr, "usage: %s [--mode mock|curl] [--config path] [--duration-s S] [--rate-lps N] [--writers N] [--profile tls200|tls700] [--close-timeout-ms M]\n", argv0 ? argv0 : "ve_tls_perf_tls");
}

int main(int argc, char ** argv) {
    const char * mode = "mock";
    const char * config_path = NULL;
    int32_t duration_s = 60;
    int64_t rate_lps = 100000;
    int32_t writers = 1;
    const char * profile = "tls700";
    int32_t close_timeout_ms = 60000;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--mode") == 0 && i + 1 < argc) {
            mode = argv[++i];
            continue;
        }
        if (strcmp(argv[i], "--config") == 0 && i + 1 < argc) {
            config_path = argv[++i];
            continue;
        }
        if (strcmp(argv[i], "--duration-s") == 0 && i + 1 < argc) {
            duration_s = (int32_t)atoi(argv[++i]);
            continue;
        }
        if (strcmp(argv[i], "--rate-lps") == 0 && i + 1 < argc) {
            rate_lps = (int64_t)atoll(argv[++i]);
            continue;
        }
        if (strcmp(argv[i], "--writers") == 0 && i + 1 < argc) {
            writers = (int32_t)atoi(argv[++i]);
            continue;
        }
        if (strcmp(argv[i], "--profile") == 0 && i + 1 < argc) {
            profile = argv[++i];
            continue;
        }
        if (strcmp(argv[i], "--close-timeout-ms") == 0 && i + 1 < argc) {
            close_timeout_ms = (int32_t)atoi(argv[++i]);
            continue;
        }
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        }
        usage(argv[0]);
        return 2;
    }

    if (duration_s <= 0 || writers < 1) return 2;
    if (!mode || (strcmp(mode, "mock") != 0 && strcmp(mode, "curl") != 0)) return 2;
    if (rate_lps < 0) return 2;

    conf_kv conf;
    memset(&conf, 0, sizeof(conf));
    if (config_path && config_path[0] != 0) {
        if (conf_load_file(&conf, config_path) != 0) {
            fprintf(stderr, "failed to load config: %s\n", config_path);
            conf_free(&conf);
            return 3;
        }
    }

    const ve_tls_kv * kvs = NULL;
    size_t kv_count = 0;
    if (!profile || strcmp(profile, "tls700") == 0) {
        kvs = k_tls_700_kvs;
        kv_count = sizeof(k_tls_700_kvs) / sizeof(k_tls_700_kvs[0]);
    } else if (strcmp(profile, "tls200") == 0) {
        kvs = k_tls_200_kvs;
        kv_count = sizeof(k_tls_200_kvs) / sizeof(k_tls_200_kvs[0]);
    } else {
        fprintf(stderr, "invalid profile: %s\n", profile);
        conf_free(&conf);
        return 3;
    }
    const ve_tls_kv * tags = k_tls_tags;
    size_t tag_count = sizeof(k_tls_tags) / sizeof(k_tls_tags[0]);

    ve_tls_config cfg;
    ve_tls_config_init(&cfg);

    if (strcmp(mode, "curl") == 0) {
        cfg.endpoint = conf_get_str(&conf, "VE_TLS_ENDPOINT", NULL);
        cfg.region = conf_get_str(&conf, "VE_TLS_REGION", NULL);
        cfg.topic_id = conf_get_str(&conf, "VE_TLS_TOPIC_ID", NULL);
        cfg.access_key_id = conf_get_str(&conf, "VE_TLS_ACCESS_KEY_ID", NULL);
        cfg.access_key_secret = conf_get_str(&conf, "VE_TLS_ACCESS_KEY_SECRET", NULL);
        cfg.security_token = conf_get_str(&conf, "VE_TLS_SECURITY_TOKEN", NULL);
        if (!cfg.endpoint || !cfg.region || !cfg.topic_id || !cfg.access_key_id || !cfg.access_key_secret) {
            fprintf(stderr, "missing required config for curl mode\n");
            conf_free(&conf);
            return 3;
        }
    } else {
        cfg.endpoint = "https://example.com";
        cfg.region = "cn-beijing";
        cfg.topic_id = "mock-topic";
        cfg.access_key_id = "ak";
        cfg.access_key_secret = "sk";
        cfg.http_client.do_request = http_ok_do;
        cfg.http_client.free_response = http_ok_free;
    }

    cfg.max_buffer_bytes = conf_get_i32(&conf, "VE_TLS_MAX_BUFFER_BYTES", 64 * 1024 * 1024);
    cfg.buffer_full_policy = VE_TLS_BUFFER_FULL_BLOCK;
    cfg.buffer_full_block_timeout_ms = close_timeout_ms;
    if (conf_has_key(&conf, "VE_TLS_FLUSH_INTERVAL_MS")) {
        cfg.flush_interval_ms = conf_get_i32(&conf, "VE_TLS_FLUSH_INTERVAL_MS", cfg.flush_interval_ms);
    }
    if (conf_has_key(&conf, "VE_TLS_LOG_BYTES_PER_PACKAGE")) {
        cfg.log_bytes_per_package = conf_get_i32(&conf, "VE_TLS_LOG_BYTES_PER_PACKAGE", cfg.log_bytes_per_package);
    }
    if (conf_has_key(&conf, "VE_TLS_LOG_COUNT_PER_PACKAGE")) {
        cfg.log_count_per_package = conf_get_i32(&conf, "VE_TLS_LOG_COUNT_PER_PACKAGE", cfg.log_count_per_package);
    }
    if (conf_has_key(&conf, "VE_TLS_SEND_THREAD_COUNT")) {
        cfg.send_thread_count = conf_get_i32(&conf, "VE_TLS_SEND_THREAD_COUNT", cfg.send_thread_count);
    }
    if (conf_has_key(&conf, "VE_TLS_PACK_THREAD_COUNT")) {
        cfg.pack_thread_count = conf_get_i32(&conf, "VE_TLS_PACK_THREAD_COUNT", cfg.pack_thread_count);
    }
    if (conf_has_key(&conf, "VE_TLS_COMPRESS_TYPE")) {
        cfg.compress_type = conf_get_str(&conf, "VE_TLS_COMPRESS_TYPE", cfg.compress_type);
    }
    cfg.retry_policy.max_attempts = 1;
    cfg.log_tags = tags;
    cfg.log_tag_count = tag_count;

    ve_tls_producer * p = ve_tls_producer_create(&cfg);
    if (!p) {
        conf_free(&conf);
        return 4;
    }

    start_gate gate;
    memset(&gate, 0, sizeof(gate));
    gate.platform = &cfg.platform;
    gate.mu = cfg.platform.mutex_create();
    gate.cv = cfg.platform.cond_create();
    if (!gate.mu || !gate.cv) {
        if (gate.mu) cfg.platform.mutex_destroy(gate.mu);
        if (gate.cv) cfg.platform.cond_destroy(gate.cv);
        ve_tls_producer_destroy(p);
        conf_free(&conf);
        return 4;
    }

    ve_tls_thread ** th = (ve_tls_thread **)calloc((size_t)writers, sizeof(ve_tls_thread *));
    writer_ctx * ctx = (writer_ctx *)calloc((size_t)writers, sizeof(writer_ctx));
    if (!th || !ctx) {
        free(th);
        free(ctx);
        cfg.platform.mutex_destroy(gate.mu);
        cfg.platform.cond_destroy(gate.cv);
        ve_tls_producer_destroy(p);
        conf_free(&conf);
        return 4;
    }

    for (int32_t i = 0; i < writers; i++) {
        ctx[i].producer = p;
        ctx[i].kvs = kvs;
        ctx[i].kv_count = kv_count;
        ctx[i].gate = &gate;
        ctx[i].rate_total_lps = rate_lps;
        ctx[i].writers = writers;
        ctx[i].writer_idx = i;
        th[i] = cfg.platform.thread_create(writer_main, &ctx[i]);
        if (!th[i]) {
            writers = i;
            break;
        }
    }
    struct rusage ru0;
    memset(&ru0, 0, sizeof(ru0));
    getrusage(RUSAGE_SELF, &ru0);
    size_t sdk_buffered_bytes_peak = ve_tls_producer_get_buffered_bytes(p);
    size_t sdk_buffered_bytes_final = sdk_buffered_bytes_peak;

    cfg.platform.mutex_lock(gate.mu);
    gate.start_ns = now_ns();
    gate.end_ns = gate.start_ns + (uint64_t)duration_s * 1000000000ULL;
    gate.started = 1;
    cfg.platform.cond_broadcast(gate.cv);
    cfg.platform.mutex_unlock(gate.mu);

    while (now_ns() < gate.end_ns) {
        size_t buffered_bytes = ve_tls_producer_get_buffered_bytes(p);
        if (buffered_bytes > sdk_buffered_bytes_peak) {
            sdk_buffered_bytes_peak = buffered_bytes;
        }
        usleep(10000);
    }

    for (int32_t i = 0; i < writers; i++) {
        cfg.platform.thread_join(th[i]);
    }

    uint64_t send_end_ns = now_ns();

    struct rusage ru1;
    memset(&ru1, 0, sizeof(ru1));
    getrusage(RUSAGE_SELF, &ru1);

    uint64_t ok = 0;
    uint64_t drop = 0;
    uint64_t other = 0;
    for (int32_t i = 0; i < writers; i++) {
        ok += ctx[i].ok;
        drop += ctx[i].drop;
        other += ctx[i].other;
    }
    free(th);
    free(ctx);

    ve_tls_metrics m0;
    memset(&m0, 0, sizeof(m0));
    ve_tls_producer_get_metrics(p, &m0);
    sdk_buffered_bytes_final = ve_tls_producer_get_buffered_bytes(p);
    if (sdk_buffered_bytes_final > sdk_buffered_bytes_peak) {
        sdk_buffered_bytes_peak = sdk_buffered_bytes_final;
    }

    (void)ve_tls_producer_flush(p);
    ve_tls_result close_rc = ve_tls_producer_close(p, close_timeout_ms);
    sdk_buffered_bytes_final = ve_tls_producer_get_buffered_bytes(p);
    if (sdk_buffered_bytes_final > sdk_buffered_bytes_peak) {
        sdk_buffered_bytes_peak = sdk_buffered_bytes_final;
    }

    ve_tls_metrics m;
    memset(&m, 0, sizeof(m));
    ve_tls_producer_get_metrics(p, &m);
    ve_tls_producer_destroy(p);

    cfg.platform.mutex_destroy(gate.mu);
    cfg.platform.cond_destroy(gate.cv);

    double wall_s = (double)(send_end_ns - gate.start_ns) / 1000000000.0;
    double run_s = (double)duration_s;
    double user_s = tv_to_s(ru1.ru_utime) - tv_to_s(ru0.ru_utime);
    double sys_s = tv_to_s(ru1.ru_stime) - tv_to_s(ru0.ru_stime);
    double cpu_s = user_s + sys_s;
    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpu < 1) ncpu = 1;
    double cpu_cores = (wall_s > 0) ? (cpu_s / wall_s) : 0.0;
    double cpu_pct_1 = cpu_cores * 100.0;
    double cpu_pct_total = (wall_s > 0) ? (cpu_s / (wall_s * (double)ncpu)) * 100.0 : 0.0;

#if defined(__APPLE__)
    double rss_mb = (double)ru1.ru_maxrss / 1024.0 / 1024.0;
#else
    double rss_mb = (double)ru1.ru_maxrss / 1024.0;
#endif

    double enq_lps = (run_s > 0) ? ((double)m0.logs_enqueued_total / run_s) : 0.0;
    double us_per_log = (m0.logs_enqueued_total > 0) ? (run_s * 1000000.0 / (double)m0.logs_enqueued_total) : 0.0;
    double raw_kb_s = (run_s > 0) ? ((double)m0.bytes_enqueued_total / 1024.0 / run_s) : 0.0;

    printf(
        "tlsperf mode=%s profile=%s target_lps=%lld writers=%d run_s=%.3f wall_s=%.3f close_rc=%d "
        "ok=%llu drop=%llu other=%llu logs_enq=%llu logs_drop=%llu bytes_enq=%llu bytes_drop=%llu req=%llu failed=%llu "
        "enq_lps=%.2f us_per_log=%.2f raw_kb_s=%.2f user_s=%.3f sys_s=%.3f cpu_cores=%.2f cpu_pct_1=%.2f cpu_pct_total=%.2f rss_mb=%.2f "
        "sdk_buffered_bytes_peak=%llu sdk_buffered_bytes_final=%llu\n",
        mode,
        profile ? profile : "",
        (long long)rate_lps,
        (int)writers,
        run_s,
        wall_s,
        (int)close_rc,
        (unsigned long long)ok,
        (unsigned long long)drop,
        (unsigned long long)other,
        (unsigned long long)m0.logs_enqueued_total,
        (unsigned long long)m0.logs_dropped_total,
        (unsigned long long)m0.bytes_enqueued_total,
        (unsigned long long)m0.bytes_dropped_total,
        (unsigned long long)m.requests_total,
        (unsigned long long)m.requests_failed_total,
        enq_lps,
        us_per_log,
        raw_kb_s,
        user_s,
        sys_s,
        cpu_cores,
        cpu_pct_1,
        cpu_pct_total,
        rss_mb,
        (unsigned long long)sdk_buffered_bytes_peak,
        (unsigned long long)sdk_buffered_bytes_final
    );

    conf_free(&conf);
    return 0;
}
