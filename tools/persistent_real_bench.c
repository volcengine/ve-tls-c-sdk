#include "ve_tls_producer.h"
#include "producer/ve_tls_producer_internal.h"
#include "producer/ve_tls_persistent.h"

#include <ctype.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char * kv[128][2];
    int kv_len;
    char * allocs[256];
    int alloc_len;
} bench_conf;

typedef struct {
    volatile int success_logs;
    volatile int failed_logs;
    volatile int failed_callbacks_logged;
    volatile uint64_t success_raw_bytes;
    volatile uint64_t success_comp_bytes;
} bench_state;

typedef enum {
    BENCH_MODE_STEADY = 0,
    BENCH_MODE_RECOVER = 1
} bench_mode;

typedef enum {
    BENCH_WRITE_MODE_KV = 0,
    BENCH_WRITE_MODE_RAW = 1
} bench_write_mode;

typedef enum {
    BENCH_PROFILE_CUSTOM = 0,
    BENCH_PROFILE_SLS200 = 1,
    BENCH_PROFILE_SLS700 = 2,
    BENCH_PROFILE_SLS5120 = 3
} bench_profile;

static bench_state g_state;

typedef struct {
    int64_t sample_ms;
    ve_tls_metrics metrics;
    int add_ok;
    int add_fail;
    int success;
    int fail;
    uint64_t raw_ok;
    uint64_t comp_ok;
} progress_sample;

typedef struct {
    ve_tls_producer * producer;
    int32_t timeout_ms;
    ve_tls_result rc;
    volatile int done;
} close_thread_ctx;

static const char * k_sls_700_vals[] = {
    "1abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+",
    "2abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+",
    "3abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+",
    "4abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+",
    "5abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+",
    "6abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+",
    "7abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+",
    "8abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+",
    "9abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+",
    "0"
};

static const ve_tls_kv k_sls_200_base[] = {
    {"LogHub", "Real-time log collection and consumption"},
    {"Search/Analytics", "Query and real-time analysis"},
    {"Visualized", "dashboard and report functions"},
    {"Interconnection", "Grafana and JDBC/SQL92"},
};

static void conf_free(bench_conf * c) {
    int i;
    if (!c) return;
    for (i = 0; i < c->alloc_len; i++) {
        free(c->allocs[i]);
    }
    c->alloc_len = 0;
    c->kv_len = 0;
}

static char * conf_strdup(bench_conf * c, const char * s) {
    char * p;
    if (!c || !s) return NULL;
    p = strdup(s);
    if (!p) return NULL;
    if (c->alloc_len >= (int)(sizeof(c->allocs) / sizeof(c->allocs[0]))) {
        free(p);
        return NULL;
    }
    c->allocs[c->alloc_len++] = p;
    return p;
}

static char * trim_inplace(char * s) {
    char * end;
    while (s && *s && isspace((unsigned char)*s)) s++;
    if (!s || *s == 0) return s;
    end = s + strlen(s);
    while (end > s && isspace((unsigned char)end[-1])) end--;
    *end = 0;
    return s;
}

static int conf_set(bench_conf * c, const char * k, const char * v) {
    if (!c || !k || !v) return -1;
    if (c->kv_len >= (int)(sizeof(c->kv) / sizeof(c->kv[0]))) return -1;
    c->kv[c->kv_len][0] = conf_strdup(c, k);
    c->kv[c->kv_len][1] = conf_strdup(c, v);
    if (!c->kv[c->kv_len][0] || !c->kv[c->kv_len][1]) return -1;
    c->kv_len++;
    return 0;
}

static const char * conf_get(bench_conf * c, const char * k) {
    int i;
    if (!c || !k) return NULL;
    for (i = 0; i < c->kv_len; i++) {
        if (c->kv[i][0] && strcmp(c->kv[i][0], k) == 0) {
            return c->kv[i][1];
        }
    }
    return NULL;
}

static int conf_load_file(bench_conf * c, const char * path) {
    FILE * f;
    char line[4096];
    if (!c || !path) return -1;
    f = fopen(path, "r");
    if (!f) return -1;
    while (fgets(line, (int)sizeof(line), f)) {
        char * s = trim_inplace(line);
        char * eq;
        if (!s || s[0] == 0 || s[0] == '#') continue;
        eq = strchr(s, '=');
        if (!eq) continue;
        *eq = 0;
        s = trim_inplace(s);
        eq = trim_inplace(eq + 1);
        if (!s || !eq || s[0] == 0) continue;
        (void)conf_set(c, s, eq);
    }
    fclose(f);
    return 0;
}

static const char * get_str(bench_conf * c, const char * key, const char * defv) {
    const char * env = getenv(key);
    const char * fv;
    if (env && env[0] != 0) return env;
    fv = conf_get(c, key);
    if (fv && fv[0] != 0) return fv;
    return defv;
}

static int32_t get_i32(bench_conf * c, const char * key, int32_t defv) {
    const char * s = get_str(c, key, NULL);
    char * end = NULL;
    long v;
    if (!s || s[0] == 0) return defv;
    v = strtol(s, &end, 10);
    if (!end || end == s) return defv;
    return (int32_t)v;
}

static int str_ieq(const char * a, const char * b) {
    while (a && b && *a && *b) {
        char ca = (char)tolower((unsigned char)*a);
        char cb = (char)tolower((unsigned char)*b);
        if (ca != cb) return 0;
        a++;
        b++;
    }
    return a && b && *a == 0 && *b == 0;
}

static bench_mode parse_mode(const char * s) {
    if (s && str_ieq(s, "recover")) return BENCH_MODE_RECOVER;
    return BENCH_MODE_STEADY;
}

static bench_write_mode parse_write_mode(const char * s) {
    if (s && str_ieq(s, "raw")) return BENCH_WRITE_MODE_RAW;
    return BENCH_WRITE_MODE_KV;
}

static const char * write_mode_str(bench_write_mode mode) {
    return mode == BENCH_WRITE_MODE_RAW ? "raw" : "kv";
}

static bench_profile parse_profile(const char * s) {
    if (!s || s[0] == 0 || str_ieq(s, "custom")) return BENCH_PROFILE_CUSTOM;
    if (str_ieq(s, "sls200")) return BENCH_PROFILE_SLS200;
    if (str_ieq(s, "sls700")) return BENCH_PROFILE_SLS700;
    if (str_ieq(s, "sls5120")) return BENCH_PROFILE_SLS5120;
    return BENCH_PROFILE_CUSTOM;
}

static const char * profile_str(bench_profile profile) {
    if (profile == BENCH_PROFILE_SLS200) return "sls200";
    if (profile == BENCH_PROFILE_SLS700) return "sls700";
    if (profile == BENCH_PROFILE_SLS5120) return "sls5120";
    return "custom";
}

static void * close_thread_main(void * arg) {
    close_thread_ctx * ctx = (close_thread_ctx *)arg;
    if (!ctx || !ctx->producer) {
        return NULL;
    }
    ctx->rc = ve_tls_producer_close(ctx->producer, ctx->timeout_ms);
    __atomic_store_n(&ctx->done, 1, __ATOMIC_RELEASE);
    return NULL;
}

static int32_t target_profile_bytes(bench_profile profile, int32_t custom_bytes) {
    if (profile == BENCH_PROFILE_SLS200) return 200;
    if (profile == BENCH_PROFILE_SLS700) return 700;
    if (profile == BENCH_PROFILE_SLS5120) return 5120;
    return custom_bytes > 0 ? custom_bytes : 256;
}

static char * alloc_fill_bytes(size_t size, char seed) {
    char * p = (char *)malloc(size + 1);
    size_t i;
    if (!p) return NULL;
    for (i = 0; i < size; i++) {
        p[i] = (char)(seed + (char)(i % 23));
        if (p[i] < '0' || p[i] > 'z') {
            p[i] = (char)('a' + (i % 26));
        }
    }
    p[size] = 0;
    return p;
}

static void build_sls700_kvs(ve_tls_kv * out, int * out_count, const char * run_id, const char * seq_str) {
    int i;
    for (i = 0; i < 9; i++) {
        out[i].key = (i == 0) ? "content_key_1"
            : (i == 1) ? "content_key_2"
            : (i == 2) ? "content_key_3"
            : (i == 3) ? "content_key_4"
            : (i == 4) ? "content_key_5"
            : (i == 5) ? "content_key_6"
            : (i == 6) ? "content_key_7"
            : (i == 7) ? "content_key_8"
            : "content_key_9";
        out[i].value = k_sls_700_vals[i];
    }
    out[9].key = "index";
    out[9].value = seq_str;
    out[10].key = "run_id";
    out[10].value = run_id;
    out[11].key = "seq";
    out[11].value = seq_str;
    *out_count = 12;
}

static void build_sls200_kvs(ve_tls_kv * out, int * out_count, const char * run_id, const char * seq_str) {
    int i;
    for (i = 0; i < 4; i++) {
        out[i] = k_sls_200_base[i];
    }
    out[4].key = "run_id";
    out[4].value = run_id;
    out[5].key = "seq";
    out[5].value = seq_str;
    *out_count = 6;
}

static void build_custom_kvs(ve_tls_kv * out, int * out_count, const char * message, const char * run_id, const char * seq_str) {
    out[0].key = "message";
    out[0].value = message;
    out[1].key = "run_id";
    out[1].value = run_id;
    out[2].key = "seq";
    out[2].value = seq_str;
    *out_count = 3;
}

static void build_sls5120_kvs(ve_tls_kv * out, int * out_count, const char * large_value, const char * run_id, const char * seq_str) {
    out[0].key = "app";
    out[0].value = "ve-tls-persistent-bench";
    out[1].key = "level";
    out[1].value = "INFO";
    out[2].key = "content";
    out[2].value = large_value;
    out[3].key = "run_id";
    out[3].value = run_id;
    out[4].key = "seq";
    out[4].value = seq_str;
    *out_count = 5;
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
    int logs = 1;
    (void)error;
    (void)raw_buffer;
    (void)user_param;
    if (start_id > 0 && end_id >= start_id) {
        logs = (int)(end_id - start_id + 1);
    }
    if (result == VE_TLS_OK) {
        (void)__atomic_add_fetch(&g_state.success_logs, logs, __ATOMIC_RELAXED);
        (void)__atomic_add_fetch(&g_state.success_raw_bytes, (uint64_t)log_bytes, __ATOMIC_RELAXED);
        (void)__atomic_add_fetch(&g_state.success_comp_bytes, (uint64_t)compressed_bytes, __ATOMIC_RELAXED);
        return;
    }
    (void)__atomic_add_fetch(&g_state.failed_logs, logs, __ATOMIC_RELAXED);
    if (__atomic_add_fetch(&g_state.failed_callbacks_logged, 1, __ATOMIC_RELAXED) <= 3) {
        fprintf(stderr,
            "callback fail result=%d logs=%d http=%d code=%s msg=%s start=%lld end=%lld\n",
            (int)result,
            logs,
            error ? (int)error->http_code : 0,
            (error && error->error_code) ? error->error_code : "",
            (error && error->error_message) ? error->error_message : "",
            (long long)start_id,
            (long long)end_id);
    }
}

static void usage(const char * argv0) {
    fprintf(stderr,
        "usage: %s [--config FILE] [--mode steady|recover] [--write-mode kv|raw] [--profile custom|sls200|sls700|sls5120]\n",
        argv0 ? argv0 : "ve_tls_persistent_real_bench");
    fprintf(stderr,
        "       [--duration-s N] [--count N] [--rate-lps N] [--wait-ms N] [--close-timeout-ms N] [--message-bytes N]\n");
    fprintf(stderr,
        "       [--persistent-dir DIR] [--run-id ID] [--recover-expect N] [--report-interval-s N]\n");
    fprintf(stderr,
        "env fallback uses VE_TLS_ENDPOINT/REGION/TOPIC_ID/ACCESS_KEY_ID/ACCESS_KEY_SECRET and persistent settings\n");
}

static void print_progress(
    const char * phase,
    bench_write_mode write_mode,
    bench_profile profile,
    int64_t elapsed_ms,
    int add_ok,
    int add_fail,
    ve_tls_producer * producer,
    progress_sample * prev
) {
    ve_tls_metrics metrics;
    progress_sample cur;
    int64_t delta_ms;
    double total_sec;
    double window_sec;
    size_t buffered;
    uint64_t acked_log_id = 0;
    uint64_t replay_begin_log_id = 0;
    uint32_t active_segment_id = 0;
    uint32_t current_segments = 0;
    uint64_t current_records = 0;
    uint64_t current_bytes = 0;

    memset(&metrics, 0, sizeof(metrics));
    ve_tls_producer_get_metrics(producer, &metrics);
    memset(&cur, 0, sizeof(cur));
    cur.sample_ms = elapsed_ms;
    cur.metrics = metrics;
    cur.add_ok = add_ok;
    cur.add_fail = add_fail;
    cur.success = __atomic_load_n(&g_state.success_logs, __ATOMIC_RELAXED);
    cur.fail = __atomic_load_n(&g_state.failed_logs, __ATOMIC_RELAXED);
    cur.raw_ok = __atomic_load_n(&g_state.success_raw_bytes, __ATOMIC_RELAXED);
    cur.comp_ok = __atomic_load_n(&g_state.success_comp_bytes, __ATOMIC_RELAXED);
    buffered = ve_tls_producer_get_buffered_bytes(producer);
    if (producer && producer->persistent) {
        acked_log_id = (uint64_t)(producer->persistent->checkpoint.acked_log_id > 0 ? producer->persistent->checkpoint.acked_log_id : 0);
        replay_begin_log_id = (uint64_t)(producer->persistent->checkpoint.replay_begin_log_id > 0 ? producer->persistent->checkpoint.replay_begin_log_id : 0);
        active_segment_id = producer->persistent->store.active_segment_id;
        current_segments = producer->persistent->current_segments;
        current_records = producer->persistent->current_records;
        current_bytes = producer->persistent->current_bytes;
    }

    delta_ms = cur.sample_ms - prev->sample_ms;
    if (delta_ms <= 0) {
        delta_ms = 1;
    }
    total_sec = elapsed_ms > 0 ? (double)elapsed_ms / 1000.0 : 0.0;
    window_sec = (double)delta_ms / 1000.0;

    printf(
        "PERSISTENT_REAL_PROGRESS phase=%s write_mode=%s profile=%s elapsed_ms=%lld add_ok=%d add_fail=%d success=%d fail=%d enqueue_lps=%.2f enqueue_lps_avg=%.2f success_lps=%.2f success_lps_avg=%.2f enqueue_bytes_ps=%.2f raw_ok_bytes_ps=%.2f comp_ok_bytes_ps=%.2f send_bytes_ps=%.2f buffered_bytes=%llu acked_log_id=%llu replay_begin_log_id=%llu active_segment_id=%u current_segments=%u current_records=%llu current_bytes=%llu requests=%llu requests_failed=%llu retries=%llu\n",
        phase,
        write_mode_str(write_mode),
        profile_str(profile),
        (long long)elapsed_ms,
        add_ok,
        add_fail,
        cur.success,
        cur.fail,
        (double)(cur.add_ok - prev->add_ok) / window_sec,
        total_sec > 0.0 ? (double)cur.add_ok / total_sec : 0.0,
        (double)(cur.success - prev->success) / window_sec,
        total_sec > 0.0 ? (double)cur.success / total_sec : 0.0,
        (double)(cur.metrics.bytes_enqueued_total - prev->metrics.bytes_enqueued_total) / window_sec,
        (double)(cur.raw_ok - prev->raw_ok) / window_sec,
        (double)(cur.comp_ok - prev->comp_ok) / window_sec,
        (double)(cur.metrics.bytes_sent_total - prev->metrics.bytes_sent_total) / window_sec,
        (unsigned long long)buffered,
        (unsigned long long)acked_log_id,
        (unsigned long long)replay_begin_log_id,
        active_segment_id,
        current_segments,
        (unsigned long long)current_records,
        (unsigned long long)current_bytes,
        (unsigned long long)(cur.metrics.requests_total - prev->metrics.requests_total),
        (unsigned long long)(cur.metrics.requests_failed_total - prev->metrics.requests_failed_total),
        (unsigned long long)(cur.metrics.retries_total - prev->metrics.retries_total)
    );

    *prev = cur;
}

int main(int argc, char ** argv) {
    bench_conf conf;
    ve_tls_config cfg;
    ve_tls_producer * producer = NULL;
    ve_tls_metrics metrics;
    progress_sample progress_prev;
    ve_tls_kv kvs[16];
    char * message = NULL;
    ve_tls_log_template * raw_tpl = NULL;
    char * sls5120_value = NULL;
    char seq_buf[32];
    int32_t duration_s = 10;
    int32_t count = 0;
    int32_t rate_lps = 0;
    int32_t wait_ms = 30000;
    int32_t close_timeout_ms = 30000;
    int32_t message_bytes = 256;
    int32_t recover_expect = 0;
    int32_t add_ok = 0;
    int32_t add_fail = 0;
    int32_t seq = 0;
    int32_t sleep_ms = 0;
    int32_t kv_count = 0;
    int32_t flush_interval_ms = 1000;
    int32_t log_count_per_package = 1024;
    int32_t send_thread_count = 1;
    int32_t report_interval_s = 1;
    int64_t begin_ms = 0;
    int64_t deadline_ms = 0;
    int64_t end_ms = 0;
    int64_t elapsed_ms = 0;
    int64_t close_begin_ms = 0;
    int64_t close_end_ms = 0;
    int64_t next_report_ms = 0;
    int i;
    bench_mode mode = BENCH_MODE_STEADY;
    bench_write_mode write_mode = BENCH_WRITE_MODE_KV;
    bench_profile profile = BENCH_PROFILE_CUSTOM;
    const char * config_path = NULL;
    const char * run_id = NULL;
    const char * persistent_dir = NULL;
    const char * hash_key = NULL;
    const char * mode_str = NULL;
    const char * write_mode_cfg = NULL;
    const char * profile_cfg = NULL;
    ve_tls_result rc;

    memset(&conf, 0, sizeof(conf));
    memset(&cfg, 0, sizeof(cfg));
    memset(&metrics, 0, sizeof(metrics));
    memset(&progress_prev, 0, sizeof(progress_prev));
    memset(&g_state, 0, sizeof(g_state));

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        }
        if (i + 1 >= argc) {
            usage(argv[0]);
            conf_free(&conf);
            return 2;
        }
        if (strcmp(argv[i], "--config") == 0) {
            config_path = argv[++i];
        } else if (strcmp(argv[i], "--mode") == 0) {
            mode_str = argv[++i];
        } else if (strcmp(argv[i], "--write-mode") == 0) {
            write_mode_cfg = argv[++i];
        } else if (strcmp(argv[i], "--profile") == 0) {
            profile_cfg = argv[++i];
        } else if (strcmp(argv[i], "--duration-s") == 0) {
            duration_s = (int32_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--count") == 0) {
            count = (int32_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--rate-lps") == 0) {
            rate_lps = (int32_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--wait-ms") == 0) {
            wait_ms = (int32_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--close-timeout-ms") == 0) {
            close_timeout_ms = (int32_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--message-bytes") == 0) {
            message_bytes = (int32_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--persistent-dir") == 0) {
            persistent_dir = argv[++i];
        } else if (strcmp(argv[i], "--run-id") == 0) {
            run_id = argv[++i];
        } else if (strcmp(argv[i], "--recover-expect") == 0) {
            recover_expect = (int32_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--report-interval-s") == 0) {
            report_interval_s = (int32_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--send-thread-count") == 0) {
            send_thread_count = (int32_t)atoi(argv[++i]);
        } else {
            usage(argv[0]);
            conf_free(&conf);
            return 2;
        }
    }

    if (config_path && conf_load_file(&conf, config_path) != 0) {
        fprintf(stderr, "failed to load config: %s\n", config_path);
        conf_free(&conf);
        return 2;
    }

    mode = parse_mode(mode_str ? mode_str : get_str(&conf, "VE_TLS_BENCH_MODE", "steady"));
    write_mode = parse_write_mode(write_mode_cfg ? write_mode_cfg : get_str(&conf, "VE_TLS_BENCH_WRITE_MODE", "kv"));
    profile = parse_profile(profile_cfg ? profile_cfg : get_str(&conf, "VE_TLS_BENCH_PROFILE", "custom"));
    flush_interval_ms = get_i32(&conf, "VE_TLS_FLUSH_INTERVAL_MS", flush_interval_ms);
    log_count_per_package = get_i32(&conf, "VE_TLS_LOG_COUNT_PER_PACKAGE", log_count_per_package);
    send_thread_count = get_i32(&conf, "VE_TLS_SEND_THREAD_COUNT", send_thread_count);
    report_interval_s = get_i32(&conf, "VE_TLS_BENCH_REPORT_INTERVAL_S", report_interval_s);
    if (!persistent_dir) persistent_dir = get_str(&conf, "VE_TLS_PERSISTENT_FILE_PATH", "/tmp/ve-tls-persistent-real-bench");
    if (!run_id) run_id = get_str(&conf, "VE_TLS_DEMO_RUN_ID", "persistent-real-bench");
    hash_key = get_str(&conf, "VE_TLS_HASH_KEY", NULL);
    message_bytes = target_profile_bytes(profile, message_bytes);

    ve_tls_config_init(&cfg);
    cfg.endpoint = get_str(&conf, "VE_TLS_ENDPOINT", NULL);
    cfg.region = get_str(&conf, "VE_TLS_REGION", NULL);
    cfg.topic_id = get_str(&conf, "VE_TLS_TOPIC_ID", NULL);
    cfg.access_key_id = get_str(&conf, "VE_TLS_ACCESS_KEY_ID", NULL);
    cfg.access_key_secret = get_str(&conf, "VE_TLS_ACCESS_KEY_SECRET", NULL);
    cfg.security_token = get_str(&conf, "VE_TLS_SECURITY_TOKEN", NULL);
    cfg.compress_type = get_str(&conf, "VE_TLS_COMPRESS_TYPE", "lz4");
    cfg.hash_key = hash_key;
    cfg.send_thread_count = send_thread_count > 0 ? send_thread_count : 1;
    cfg.flush_interval_ms = flush_interval_ms;
    cfg.log_count_per_package = log_count_per_package;
    cfg.request_timeout_ms = get_i32(&conf, "VE_TLS_REQUEST_TIMEOUT_MS", 10000);
    cfg.connect_timeout_ms = get_i32(&conf, "VE_TLS_CONNECT_TIMEOUT_MS", 10000);
    cfg.send_queue_size = get_i32(&conf, "VE_TLS_SEND_QUEUE_SIZE", 4096);
    cfg.send_queue_block_timeout_ms = get_i32(&conf, "VE_TLS_SEND_QUEUE_BLOCK_TIMEOUT_MS", 100);
    cfg.send_queue_sample_every_n = get_i32(&conf, "VE_TLS_SEND_QUEUE_SAMPLE_EVERY_N", 10);
    cfg.max_persistent_log_count = get_i32(&conf, "VE_TLS_MAX_PERSISTENT_LOG_COUNT", 200000);
    cfg.max_persistent_file_size = get_i32(&conf, "VE_TLS_MAX_PERSISTENT_FILE_SIZE", 8 * 1024 * 1024);
    cfg.max_persistent_file_count = get_i32(&conf, "VE_TLS_MAX_PERSISTENT_FILE_COUNT", 32);
    cfg.persistent_max_records = get_i32(&conf, "VE_TLS_PERSISTENT_MAX_RECORDS", cfg.persistent_max_records);
    cfg.persistent_max_segments = get_i32(&conf, "VE_TLS_PERSISTENT_MAX_SEGMENTS", cfg.persistent_max_segments);
    cfg.persistent_lease_timeout_ms = get_i32(&conf, "VE_TLS_PERSISTENT_LEASE_TIMEOUT_MS", cfg.persistent_lease_timeout_ms);
    cfg.persistent_heartbeat_interval_ms = get_i32(&conf, "VE_TLS_PERSISTENT_HEARTBEAT_INTERVAL_MS", cfg.persistent_heartbeat_interval_ms);
    cfg.use_persistent = 1;
    cfg.persistent_file_path = persistent_dir;

    if (!cfg.endpoint || !cfg.region || !cfg.topic_id || !cfg.access_key_id || !cfg.access_key_secret) {
        fprintf(stderr, "missing required config: endpoint/region/topic_id/access_key_id/access_key_secret\n");
        conf_free(&conf);
        return 2;
    }
    if (mode == BENCH_MODE_STEADY && count <= 0 && duration_s <= 0) {
        fprintf(stderr, "steady mode requires --count > 0 or --duration-s > 0\n");
        conf_free(&conf);
        return 2;
    }
    if (mode == BENCH_MODE_RECOVER && recover_expect <= 0) {
        fprintf(stderr, "recover mode requires --recover-expect > 0\n");
        conf_free(&conf);
        return 2;
    }

    message = alloc_fill_bytes((size_t)message_bytes, 'x');
    sls5120_value = alloc_fill_bytes((size_t)(message_bytes > 64 ? message_bytes - 64 : message_bytes), 's');
    if (!message || !sls5120_value) {
        free(message);
        free(sls5120_value);
        conf_free(&conf);
        return 3;
    }

    producer = ve_tls_producer_create(&cfg);
    if (!producer) {
        fprintf(stderr, "ve_tls_producer_create failed\n");
        free(message);
        free(sls5120_value);
        conf_free(&conf);
        return 4;
    }
    ve_tls_producer_set_send_done_v2(producer, on_send_done_v2, NULL);
    if (write_mode == BENCH_WRITE_MODE_RAW) {
        const char * raw_keys[1] = {"message"};
        const size_t raw_key_lens[1] = {7};
        raw_tpl = ve_tls_template_create(producer, raw_keys, raw_key_lens, 1, cfg.hash_key);
        if (!raw_tpl) {
            fprintf(stderr, "ve_tls_template_create failed for raw mode\n");
            ve_tls_producer_destroy(producer);
            free(message);
            free(sls5120_value);
            conf_free(&conf);
            return 4;
        }
    }

    begin_ms = cfg.platform.time_ms ? cfg.platform.time_ms() : 0;
    progress_prev.sample_ms = 0;
    next_report_ms = begin_ms + (report_interval_s > 0 ? (int64_t)report_interval_s * 1000 : 0);

    if (mode == BENCH_MODE_RECOVER) {
        rc = ve_tls_producer_recover(producer);
        if (rc != VE_TLS_OK) {
            fprintf(stderr, "recover failed rc=%d\n", (int)rc);
            if (raw_tpl) ve_tls_template_destroy(raw_tpl);
            ve_tls_producer_destroy(producer);
            free(message);
            free(sls5120_value);
            conf_free(&conf);
            return 5;
        }
        deadline_ms = begin_ms + wait_ms;
        while ((cfg.platform.time_ms ? cfg.platform.time_ms() : 0) < deadline_ms) {
            int64_t now_ms = cfg.platform.time_ms ? cfg.platform.time_ms() : 0;
            int ok = __atomic_load_n(&g_state.success_logs, __ATOMIC_RELAXED);
            int fail = __atomic_load_n(&g_state.failed_logs, __ATOMIC_RELAXED);
            if (report_interval_s > 0 && now_ms >= next_report_ms) {
                print_progress("recover", write_mode, profile, now_ms - begin_ms, add_ok, add_fail, producer, &progress_prev);
                next_report_ms += (int64_t)report_interval_s * 1000;
            }
            if (ok + fail >= recover_expect) break;
            if (cfg.platform.sleep_ms) cfg.platform.sleep_ms(50);
        }
    } else {
        if (rate_lps > 0 && rate_lps <= 1000) {
            sleep_ms = 1000 / rate_lps;
        }
        end_ms = duration_s > 0 ? begin_ms + (int64_t)duration_s * 1000 : 0;
        for (;;) {
            int64_t now_ms = cfg.platform.time_ms ? cfg.platform.time_ms() : 0;
            if (count > 0 && seq >= count) break;
            if (end_ms > 0 && now_ms >= end_ms) break;

            snprintf(seq_buf, sizeof(seq_buf), "%d", seq);
            if (write_mode == BENCH_WRITE_MODE_RAW) {
                const char * raw_values[1];
                const size_t raw_value_lens[1] = {(size_t)message_bytes};
                raw_values[0] = message;
                rc = ve_tls_template_add_values(raw_tpl, 0, 0, 0, raw_values, raw_value_lens, 1, 0);
            } else {
                if (profile == BENCH_PROFILE_SLS200) {
                    build_sls200_kvs(kvs, &kv_count, run_id, seq_buf);
                } else if (profile == BENCH_PROFILE_SLS700) {
                    build_sls700_kvs(kvs, &kv_count, run_id, seq_buf);
                } else if (profile == BENCH_PROFILE_SLS5120) {
                    build_sls5120_kvs(kvs, &kv_count, sls5120_value, run_id, seq_buf);
                } else {
                    build_custom_kvs(kvs, &kv_count, message, run_id, seq_buf);
                }
                rc = ve_tls_producer_add_log_kv_hashkey(producer, 0, cfg.hash_key, kvs, (size_t)kv_count, 0);
            }

            if (rc == VE_TLS_OK) {
                add_ok++;
            } else {
                add_fail++;
            }
            seq++;

            if (report_interval_s > 0 && now_ms >= next_report_ms) {
                print_progress("steady", write_mode, profile, now_ms - begin_ms, add_ok, add_fail, producer, &progress_prev);
                next_report_ms += (int64_t)report_interval_s * 1000;
            }
            if (sleep_ms > 0 && cfg.platform.sleep_ms) {
                cfg.platform.sleep_ms(sleep_ms);
            }
        }
        (void)ve_tls_producer_flush(producer);
    }

    close_begin_ms = cfg.platform.time_ms ? cfg.platform.time_ms() : 0;
    {
        close_thread_ctx close_ctx;
        pthread_t close_tid;
        int close_thread_started = 0;
        memset(&close_ctx, 0, sizeof(close_ctx));
        close_ctx.producer = producer;
        close_ctx.timeout_ms = close_timeout_ms;
        if (pthread_create(&close_tid, NULL, close_thread_main, &close_ctx) == 0) {
            close_thread_started = 1;
            while (!__atomic_load_n(&close_ctx.done, __ATOMIC_ACQUIRE)) {
                int64_t now_ms = cfg.platform.time_ms ? cfg.platform.time_ms() : 0;
                if (report_interval_s > 0 && now_ms >= next_report_ms) {
                    print_progress("drain", write_mode, profile, now_ms - begin_ms, add_ok, add_fail, producer, &progress_prev);
                    next_report_ms += (int64_t)report_interval_s * 1000;
                }
                if (cfg.platform.sleep_ms) {
                    cfg.platform.sleep_ms(50);
                }
            }
            (void)pthread_join(close_tid, NULL);
            rc = close_ctx.rc;
        }
        if (!close_thread_started) {
            rc = ve_tls_producer_close(producer, close_timeout_ms);
        }
    }
    close_end_ms = cfg.platform.time_ms ? cfg.platform.time_ms() : 0;
    ve_tls_producer_get_metrics(producer, &metrics);
    ve_tls_producer_destroy(producer);

    elapsed_ms = close_end_ms - begin_ms;
    printf(
        "PERSISTENT_REAL_BENCH mode=%s write_mode=%s profile=%s target_payload_bytes=%d run_id=%s persistent_dir=%s add_ok=%d add_fail=%d success=%d fail=%d close_rc=%d elapsed_ms=%lld close_wait_ms=%lld logs_enqueued=%llu bytes_enqueued=%llu requests=%llu requests_failed=%llu retries=%llu bytes_sent=%llu success_raw_bytes=%llu success_comp_bytes=%llu\n",
        mode == BENCH_MODE_RECOVER ? "recover" : "steady",
        write_mode_str(write_mode),
        profile_str(profile),
        (int)message_bytes,
        run_id,
        persistent_dir,
        add_ok,
        add_fail,
        __atomic_load_n(&g_state.success_logs, __ATOMIC_RELAXED),
        __atomic_load_n(&g_state.failed_logs, __ATOMIC_RELAXED),
        (int)rc,
        (long long)elapsed_ms,
        (long long)(close_end_ms - close_begin_ms),
        (unsigned long long)metrics.logs_enqueued_total,
        (unsigned long long)metrics.bytes_enqueued_total,
        (unsigned long long)metrics.requests_total,
        (unsigned long long)metrics.requests_failed_total,
        (unsigned long long)metrics.retries_total,
        (unsigned long long)metrics.bytes_sent_total,
        (unsigned long long)__atomic_load_n(&g_state.success_raw_bytes, __ATOMIC_RELAXED),
        (unsigned long long)__atomic_load_n(&g_state.success_comp_bytes, __ATOMIC_RELAXED)
    );

    if (raw_tpl) {
        ve_tls_template_destroy(raw_tpl);
    }
    free(message);
    free(sls5120_value);
    conf_free(&conf);
    return rc == VE_TLS_OK ? 0 : 6;
}
