#include "ve_tls_producer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>

typedef struct {
    char * kv[128][2];
    int kv_len;
    char * allocs[256];
    int alloc_len;
} demo_conf;

typedef struct {
    volatile int success_logs;
    volatile int failed_logs;
    int exit_after_success;
    int print_success_callbacks;
} demo_run_state;

static demo_run_state g_demo_state;

static int64_t monotonic_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

static void pace_rate_lps(int32_t rate_lps, int64_t * next_emit_ns) {
    int64_t step_ns;
    int64_t sleep_ns;
    struct timespec req;
    if (rate_lps <= 0 || !next_emit_ns) return;
    step_ns = 1000000000LL / rate_lps;
    if (step_ns <= 0) step_ns = 1;
    if (*next_emit_ns == 0) {
        *next_emit_ns = monotonic_ns();
    }
    *next_emit_ns += step_ns;
    sleep_ns = *next_emit_ns - monotonic_ns();
    if (sleep_ns <= 0) return;
    req.tv_sec = sleep_ns / 1000000000LL;
    req.tv_nsec = sleep_ns % 1000000000LL;
    while (nanosleep(&req, &req) != 0 && errno == EINTR) {
    }
}

static void conf_free(demo_conf * c) {
    if (!c) return;
    for (int i = 0; i < c->alloc_len; i++) {
        free(c->allocs[i]);
    }
    c->alloc_len = 0;
    c->kv_len = 0;
}

static char * conf_strdup(demo_conf * c, const char * s) {
    if (!c || !s) return NULL;
    char * p = strdup(s);
    if (!p) return NULL;
    if (c->alloc_len < (int)(sizeof(c->allocs) / sizeof(c->allocs[0]))) {
        c->allocs[c->alloc_len++] = p;
    } else {
        free(p);
        return NULL;
    }
    return p;
}

static char * trim_inplace(char * s) {
    while (s && *s && isspace((unsigned char)*s)) s++;
    if (!s || *s == 0) return s;
    char * end = s + strlen(s);
    while (end > s && isspace((unsigned char)end[-1])) end--;
    *end = 0;
    return s;
}

static int conf_set(demo_conf * c, const char * k, const char * v) {
    if (!c || !k || !v) return -1;
    if (c->kv_len >= (int)(sizeof(c->kv) / sizeof(c->kv[0]))) return -1;
    c->kv[c->kv_len][0] = conf_strdup(c, k);
    c->kv[c->kv_len][1] = conf_strdup(c, v);
    if (!c->kv[c->kv_len][0] || !c->kv[c->kv_len][1]) return -1;
    c->kv_len++;
    return 0;
}

static const char * conf_get(demo_conf * c, const char * k) {
    if (!c || !k) return NULL;
    for (int i = 0; i < c->kv_len; i++) {
        if (c->kv[i][0] && strcmp(c->kv[i][0], k) == 0) {
            return c->kv[i][1];
        }
    }
    return NULL;
}

static int conf_load_file(demo_conf * c, const char * path) {
    if (!c || !path) return -1;
    FILE * f = fopen(path, "r");
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
        if (!k || !v || k[0] == 0) continue;
        (void)conf_set(c, k, v);
    }
    fclose(f);
    return 0;
}

static const char * get_str(demo_conf * c, const char * key, const char * defv) {
    const char * env = getenv(key);
    if (env && env[0] != 0) return env;
    const char * fv = conf_get(c, key);
    if (fv && fv[0] != 0) return fv;
    return defv;
}

static int32_t get_i32(demo_conf * c, const char * key, int32_t defv) {
    const char * s = get_str(c, key, NULL);
    if (!s || s[0] == 0) return defv;
    char * end = NULL;
    long v = strtol(s, &end, 10);
    if (!end || end == s) return defv;
    return (int32_t)v;
}

static int str_ieq(const char * a, const char * b) {
    if (!a || !b) return 0;
    while (*a && *b) {
        char ca = (char)tolower((unsigned char)*a);
        char cb = (char)tolower((unsigned char)*b);
        if (ca != cb) return 0;
        a++;
        b++;
    }
    return *a == 0 && *b == 0;
}

static ve_tls_send_queue_full_policy parse_send_queue_full_policy(demo_conf * c, const char * key, ve_tls_send_queue_full_policy defv) {
    const char * s = get_str(c, key, NULL);
    if (!s || s[0] == 0) return defv;
    if (str_ieq(s, "block")) return VE_TLS_SEND_QUEUE_FULL_BLOCK;
    if (str_ieq(s, "drop")) return VE_TLS_SEND_QUEUE_FULL_DROP;
    if (str_ieq(s, "drop_sampled")) return VE_TLS_SEND_QUEUE_FULL_DROP_SAMPLED;
    if (str_ieq(s, "drop-sampled")) return VE_TLS_SEND_QUEUE_FULL_DROP_SAMPLED;
    return defv;
}

static ve_tls_persistent_overflow_policy parse_persistent_overflow_policy(demo_conf * c, const char * key, ve_tls_persistent_overflow_policy defv) {
    const char * s = get_str(c, key, NULL);
    if (!s || s[0] == 0) return defv;
    if (str_ieq(s, "reject_new")) return VE_TLS_POVERFLOW_REJECT_NEW;
    if (str_ieq(s, "reject-new")) return VE_TLS_POVERFLOW_REJECT_NEW;
    if (str_ieq(s, "block")) return VE_TLS_POVERFLOW_BLOCK;
    if (str_ieq(s, "drop_oldest_unacked")) return VE_TLS_POVERFLOW_DROP_OLDEST_UNACKED;
    if (str_ieq(s, "drop-oldest-unacked")) return VE_TLS_POVERFLOW_DROP_OLDEST_UNACKED;
    if (str_ieq(s, "drop_newest_sample")) return VE_TLS_POVERFLOW_DROP_NEWEST_SAMPLE;
    if (str_ieq(s, "drop-newest-sample")) return VE_TLS_POVERFLOW_DROP_NEWEST_SAMPLE;
    return (ve_tls_persistent_overflow_policy)get_i32(c, key, (int32_t)defv);
}

static ve_tls_persistent_open_mode parse_persistent_open_mode(demo_conf * c, const char * key, ve_tls_persistent_open_mode defv) {
    const char * s = get_str(c, key, NULL);
    if (!s || s[0] == 0) return defv;
    if (str_ieq(s, "fail_if_owned")) return VE_TLS_POPEN_FAIL_IF_OWNED;
    if (str_ieq(s, "fail-if-owned")) return VE_TLS_POPEN_FAIL_IF_OWNED;
    if (str_ieq(s, "takeover_if_stale")) return VE_TLS_POPEN_TAKEOVER_IF_STALE;
    if (str_ieq(s, "takeover-if-stale")) return VE_TLS_POPEN_TAKEOVER_IF_STALE;
    return (ve_tls_persistent_open_mode)get_i32(c, key, (int32_t)defv);
}

static int parse_log_tags(demo_conf * conf, const char * s, ve_tls_kv ** out_kvs, int32_t * out_n) {
    if (!out_kvs || !out_n) return -1;
    *out_kvs = NULL;
    *out_n = 0;
    if (!conf || !s || s[0] == 0) return 0;

    char * buf = conf_strdup(conf, s);
    if (!buf) return -1;

    int32_t cap = 32;
    ve_tls_kv * kvs = (ve_tls_kv *)malloc(sizeof(ve_tls_kv) * (size_t)cap);
    if (!kvs) return -1;
    memset(kvs, 0, sizeof(ve_tls_kv) * (size_t)cap);
    if (conf->alloc_len < (int)(sizeof(conf->allocs) / sizeof(conf->allocs[0]))) {
        conf->allocs[conf->alloc_len++] = (char *)kvs;
    } else {
        free(kvs);
        return -1;
    }

    int32_t n = 0;
    char * p = buf;
    while (p && *p) {
        char * token = p;
        char * comma = strchr(p, ',');
        if (comma) {
            *comma = 0;
            p = comma + 1;
        } else {
            p = NULL;
        }

        token = trim_inplace(token);
        if (!token || token[0] == 0) continue;
        char * eq = strchr(token, '=');
        if (!eq) continue;
        *eq = 0;
        char * k = trim_inplace(token);
        char * v = trim_inplace(eq + 1);
        if (!k || k[0] == 0) continue;
        if (!v) v = "";
        if (n >= cap) break;
        kvs[n].key = conf_strdup(conf, k);
        kvs[n].value = conf_strdup(conf, v);
        if (!kvs[n].key || !kvs[n].value) return -1;
        n++;
    }

    *out_kvs = kvs;
    *out_n = n;
    return 0;
}

static int load_file_bytes(const char * path, unsigned char ** out, size_t * out_size) {
    if (!path || !out || !out_size) return -1;
    *out = NULL;
    *out_size = 0;
    FILE * f = fopen(path, "rb");
    if (!f) return -1;
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return -1;
    }
    long n = ftell(f);
    if (n <= 0) {
        fclose(f);
        return -1;
    }
    if ((size_t)n > (size_t)(64 * 1024 * 1024)) {
        fclose(f);
        return -1;
    }
    if (fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return -1;
    }
    unsigned char * p = (unsigned char *)malloc((size_t)n);
    if (!p) {
        fclose(f);
        return -1;
    }
    size_t r = fread(p, 1, (size_t)n, f);
    fclose(f);
    if (r != (size_t)n) {
        free(p);
        return -1;
    }
    *out = p;
    *out_size = (size_t)n;
    return 0;
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
    int logs = 1;
    int total = 0;
    if (start_id > 0 && end_id >= start_id) {
        logs = (int)(end_id - start_id + 1);
    }
    const char * req_id = (error && error->request_id) ? error->request_id : "";
    const char * err_code = (error && error->error_code) ? error->error_code : "";
    const char * err_msg = (error && error->error_message) ? error->error_message : "";
    int http_code = error ? error->http_code : 0;
    int retryable = error ? error->retryable : 0;
    if (result == VE_TLS_OK) {
        total = __atomic_add_fetch(&g_demo_state.success_logs, logs, __ATOMIC_RELAXED);
        if (g_demo_state.print_success_callbacks) {
            printf("callback ok logs=%d total_ok=%d bytes=%zu compressed=%zu req_id=%s start=%lld end=%lld\n",
                logs,
                total,
                log_bytes,
                compressed_bytes,
                req_id,
                (long long)start_id,
                (long long)end_id
            );
        }
        if (g_demo_state.exit_after_success > 0 && total >= g_demo_state.exit_after_success) {
            fprintf(stderr, "abrupt exit after success threshold=%d\n", g_demo_state.exit_after_success);
            fflush(stderr);
            _exit(91);
        }
        return;
    }
    total = __atomic_add_fetch(&g_demo_state.failed_logs, logs, __ATOMIC_RELAXED);
    printf("callback fail result=%d logs=%d total_fail=%d bytes=%zu http=%d retryable=%d req_id=%s code=%s msg=%s start=%lld end=%lld\n",
        (int)result,
        logs,
        total,
        log_bytes,
        http_code,
        retryable,
        req_id,
        err_code,
        err_msg,
        (long long)start_id,
        (long long)end_id
    );
}

static void metrics_emit(const char * name, int64_t v1, int64_t v2, void * user_param) {
    (void)user_param;
    if (!name) return;
    fprintf(stderr, "metric name=%s v1=%lld v2=%lld\n", name, (long long)v1, (long long)v2);
}

static void print_cfg(const ve_tls_config * cfg, int demo_count, int interval_ms, int wait_ms, int debug, int metrics, int http_debug) {
    if (!cfg) return;
    int ak_set = cfg->access_key_id && cfg->access_key_id[0] != 0;
    int sk_set = cfg->access_key_secret && cfg->access_key_secret[0] != 0;
    int token_set = cfg->security_token && cfg->security_token[0] != 0;
    fprintf(stderr,
        "config endpoint=%s region=%s topic_id=%s api_version=%s compress=%s threads=%d flush_interval_ms=%d\n",
        cfg->endpoint ? cfg->endpoint : "",
        cfg->region ? cfg->region : "",
        cfg->topic_id ? cfg->topic_id : "",
        cfg->api_version ? cfg->api_version : "",
        cfg->compress_type ? cfg->compress_type : "",
        (int)cfg->send_thread_count,
        (int)cfg->flush_interval_ms
    );
    fprintf(stderr,
        "config timeouts connect_ms=%d request_ms=%d tls_verify_peer=%d tls_verify_host=%d ca_cert_path=%s proxy=%s user_agent=%s hash_key=%s\n",
        (int)cfg->connect_timeout_ms,
        (int)cfg->request_timeout_ms,
        (int)cfg->tls_verify_peer,
        (int)cfg->tls_verify_host,
        cfg->ca_cert_path ? cfg->ca_cert_path : "",
        cfg->proxy ? cfg->proxy : "",
        cfg->user_agent ? cfg->user_agent : "",
        cfg->hash_key ? cfg->hash_key : ""
    );
    fprintf(stderr,
        "send-queue size=%d full_policy=%d block_timeout_ms=%d sample_every_n=%d\n",
        (int)cfg->send_queue_size,
        (int)cfg->send_queue_full_policy,
        (int)cfg->send_queue_block_timeout_ms,
        (int)cfg->send_queue_sample_every_n
    );
    fprintf(stderr,
        "io-stats headers x-tls-bodyrawsize x-tls-compresstype log-count earliest-log-time latest-log-time\n"
    );
    fprintf(stderr,
        "auth ak_set=%d sk_set=%d token_set=%d demo count=%d interval_ms=%d wait_ms=%d debug=%d metrics=%d http_debug=%d\n",
        ak_set, sk_set, token_set, demo_count, interval_ms, wait_ms, debug, metrics, http_debug
    );
    if (cfg->use_persistent) {
        fprintf(stderr,
            "persistent enabled=1 path=%s open_mode=%d lease_timeout_ms=%d heartbeat_interval_ms=%d overflow_policy=%d\n",
            cfg->persistent_file_path ? cfg->persistent_file_path : "",
            (int)cfg->persistent_open_mode,
            (int)cfg->persistent_lease_timeout_ms,
            (int)cfg->persistent_heartbeat_interval_ms,
            (int)cfg->persistent_overflow_policy
        );
        fprintf(stderr,
            "persistent quota bytes=%d records=%d segments=%d hwm=%d lwm=%d sample_every_n=%d block_timeout_ms=%d\n",
            (int)cfg->persistent_max_bytes,
            (int)cfg->persistent_max_records,
            (int)cfg->persistent_max_segments,
            (int)cfg->persistent_high_watermark_pct,
            (int)cfg->persistent_low_watermark_pct,
            (int)cfg->persistent_sample_every_n,
            (int)cfg->persistent_block_timeout_ms
        );
    }
}

static void usage(const char * argv0) {
    fprintf(stderr, "usage: %s [--config path] [--count N] [--interval-ms M] [--wait-ms M] [--duration-s S]\n", argv0 ? argv0 : "ve_tls_demo_real");
    fprintf(stderr, "required env/config keys: VE_TLS_ENDPOINT VE_TLS_REGION VE_TLS_TOPIC_ID VE_TLS_ACCESS_KEY_ID VE_TLS_ACCESS_KEY_SECRET\n");
    fprintf(stderr, "optional keys: VE_TLS_SECURITY_TOKEN VE_TLS_COMPRESS_TYPE VE_TLS_SEND_THREAD_COUNT VE_TLS_MAX_BUFFER_BYTES VE_TLS_LOG_BYTES_PER_PACKAGE VE_TLS_LOG_COUNT_PER_PACKAGE VE_TLS_AGG_MAX_RAW_BYTES_PER_REQUEST VE_TLS_AGG_MAX_COMPRESSED_BYTES_PER_REQUEST VE_TLS_LOG_TAGS VE_TLS_FLUSH_INTERVAL_MS VE_TLS_REQUEST_TIMEOUT_MS VE_TLS_CONNECT_TIMEOUT_MS VE_TLS_CA_CERT_PATH VE_TLS_PROXY VE_TLS_TLS_VERIFY_PEER VE_TLS_TLS_VERIFY_HOST VE_TLS_USER_AGENT VE_TLS_HASH_KEY VE_TLS_HTTP_DEBUG VE_TLS_SEND_QUEUE_SIZE VE_TLS_SEND_QUEUE_FULL_POLICY VE_TLS_SEND_QUEUE_BLOCK_TIMEOUT_MS VE_TLS_SEND_QUEUE_SAMPLE_EVERY_N\n");
    fprintf(stderr, "persistent keys: VE_TLS_USE_PERSISTENT VE_TLS_PERSISTENT_FILE_PATH VE_TLS_MAX_PERSISTENT_LOG_COUNT VE_TLS_MAX_PERSISTENT_FILE_SIZE VE_TLS_MAX_PERSISTENT_FILE_COUNT VE_TLS_FORCE_FLUSH_DISK VE_TLS_PERSISTENT_MAX_BYTES VE_TLS_PERSISTENT_MAX_RECORDS VE_TLS_PERSISTENT_MAX_SEGMENTS VE_TLS_PERSISTENT_HIGH_WATERMARK_PCT VE_TLS_PERSISTENT_LOW_WATERMARK_PCT VE_TLS_PERSISTENT_OVERFLOW_POLICY VE_TLS_PERSISTENT_SAMPLE_EVERY_N VE_TLS_PERSISTENT_BLOCK_TIMEOUT_MS VE_TLS_PERSISTENT_LEASE_TIMEOUT_MS VE_TLS_PERSISTENT_HEARTBEAT_INTERVAL_MS VE_TLS_PERSISTENT_OPEN_MODE\n");
    fprintf(stderr, "demo keys: VE_TLS_DEMO_MESSAGE VE_TLS_DEMO_LOG_RAW_FILE VE_TLS_DEMO_DEBUG VE_TLS_DEMO_METRICS VE_TLS_DEMO_RATE_LPS VE_TLS_DEMO_DURATION_S VE_TLS_DEMO_FLUSH_EVERY_N VE_TLS_DEMO_RUN_ID VE_TLS_DEMO_SCENARIO VE_TLS_DEMO_START_SEQ VE_TLS_DEMO_RECOVER VE_TLS_DEMO_EXPECT_SUCCESS VE_TLS_DEMO_EXIT_AFTER_ENQUEUE VE_TLS_DEMO_EXIT_AFTER_SUCCESS VE_TLS_DEMO_EXIT_DELAY_MS VE_TLS_DEMO_CLOSE_TIMEOUT_MS\n");
}

int main(int argc, char ** argv) {
#if !defined(VE_TLS_HAVE_CURL)
    fprintf(stderr, "ve_tls_demo_real requires VE_TLS_ENABLE_CURL=ON at build time\n");
    return 2;
#endif
    demo_conf conf;
    memset(&conf, 0, sizeof(conf));

    const char * cfg_path = NULL;
    int32_t count = 1;
    int32_t interval_ms = 0;
    int32_t wait_ms = 2000;
    int32_t duration_s = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--config") == 0 && i + 1 < argc) {
            cfg_path = argv[++i];
            continue;
        }
        if (strcmp(argv[i], "--count") == 0 && i + 1 < argc) {
            count = (int32_t)atoi(argv[++i]);
            continue;
        }
        if (strcmp(argv[i], "--interval-ms") == 0 && i + 1 < argc) {
            interval_ms = (int32_t)atoi(argv[++i]);
            continue;
        }
        if (strcmp(argv[i], "--wait-ms") == 0 && i + 1 < argc) {
            wait_ms = (int32_t)atoi(argv[++i]);
            continue;
        }
        if (strcmp(argv[i], "--duration-s") == 0 && i + 1 < argc) {
            duration_s = (int32_t)atoi(argv[++i]);
            continue;
        }
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            conf_free(&conf);
            return 0;
        }
        usage(argv[0]);
        conf_free(&conf);
        return 1;
    }

    if (cfg_path && cfg_path[0] != 0) {
        if (conf_load_file(&conf, cfg_path) != 0) {
            fprintf(stderr, "failed to load config file: %s\n", cfg_path);
            conf_free(&conf);
            return 1;
        }
    }

    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    cfg.endpoint = get_str(&conf, "VE_TLS_ENDPOINT", NULL);
    cfg.region = get_str(&conf, "VE_TLS_REGION", NULL);
    cfg.topic_id = get_str(&conf, "VE_TLS_TOPIC_ID", NULL);
    cfg.access_key_id = get_str(&conf, "VE_TLS_ACCESS_KEY_ID", NULL);
    cfg.access_key_secret = get_str(&conf, "VE_TLS_ACCESS_KEY_SECRET", NULL);
    cfg.security_token = get_str(&conf, "VE_TLS_SECURITY_TOKEN", NULL);

    cfg.compress_type = get_str(&conf, "VE_TLS_COMPRESS_TYPE", cfg.compress_type);
    cfg.send_thread_count = get_i32(&conf, "VE_TLS_SEND_THREAD_COUNT", cfg.send_thread_count);
    cfg.max_buffer_bytes = get_i32(&conf, "VE_TLS_MAX_BUFFER_BYTES", cfg.max_buffer_bytes);
    cfg.log_bytes_per_package = get_i32(&conf, "VE_TLS_LOG_BYTES_PER_PACKAGE", cfg.log_bytes_per_package);
    cfg.log_count_per_package = get_i32(&conf, "VE_TLS_LOG_COUNT_PER_PACKAGE", cfg.log_count_per_package);
    cfg.agg_max_raw_bytes_per_request = get_i32(&conf, "VE_TLS_AGG_MAX_RAW_BYTES_PER_REQUEST", cfg.agg_max_raw_bytes_per_request);
    cfg.agg_max_compressed_bytes_per_request = get_i32(&conf, "VE_TLS_AGG_MAX_COMPRESSED_BYTES_PER_REQUEST", cfg.agg_max_compressed_bytes_per_request);
    ve_tls_kv * log_tags = NULL;
    int32_t log_tag_count = 0;
    if (parse_log_tags(&conf, get_str(&conf, "VE_TLS_LOG_TAGS", NULL), &log_tags, &log_tag_count) != 0) {
        fprintf(stderr, "failed to parse VE_TLS_LOG_TAGS\n");
        conf_free(&conf);
        return 1;
    }
    cfg.log_tags = log_tags;
    cfg.log_tag_count = (size_t)log_tag_count;
    cfg.flush_interval_ms = get_i32(&conf, "VE_TLS_FLUSH_INTERVAL_MS", cfg.flush_interval_ms);
    cfg.send_queue_size = get_i32(&conf, "VE_TLS_SEND_QUEUE_SIZE", cfg.send_queue_size);
    cfg.send_queue_full_policy = parse_send_queue_full_policy(&conf, "VE_TLS_SEND_QUEUE_FULL_POLICY", cfg.send_queue_full_policy);
    cfg.send_queue_block_timeout_ms = get_i32(&conf, "VE_TLS_SEND_QUEUE_BLOCK_TIMEOUT_MS", cfg.send_queue_block_timeout_ms);
    cfg.send_queue_sample_every_n = get_i32(&conf, "VE_TLS_SEND_QUEUE_SAMPLE_EVERY_N", cfg.send_queue_sample_every_n);
    cfg.request_timeout_ms = get_i32(&conf, "VE_TLS_REQUEST_TIMEOUT_MS", cfg.request_timeout_ms);
    cfg.connect_timeout_ms = get_i32(&conf, "VE_TLS_CONNECT_TIMEOUT_MS", cfg.connect_timeout_ms);
    cfg.tls_verify_peer = get_i32(&conf, "VE_TLS_TLS_VERIFY_PEER", cfg.tls_verify_peer);
    cfg.tls_verify_host = get_i32(&conf, "VE_TLS_TLS_VERIFY_HOST", cfg.tls_verify_host);
    cfg.ca_cert_path = get_str(&conf, "VE_TLS_CA_CERT_PATH", cfg.ca_cert_path);
    cfg.proxy = get_str(&conf, "VE_TLS_PROXY", cfg.proxy);
    cfg.user_agent = get_str(&conf, "VE_TLS_USER_AGENT", cfg.user_agent);
    cfg.hash_key = get_str(&conf, "VE_TLS_HASH_KEY", cfg.hash_key);
    cfg.http_debug = get_i32(&conf, "VE_TLS_HTTP_DEBUG", cfg.http_debug);
    cfg.use_persistent = get_i32(&conf, "VE_TLS_USE_PERSISTENT", cfg.use_persistent);
    cfg.persistent_file_path = get_str(&conf, "VE_TLS_PERSISTENT_FILE_PATH", cfg.persistent_file_path);
    cfg.max_persistent_log_count = get_i32(&conf, "VE_TLS_MAX_PERSISTENT_LOG_COUNT", cfg.max_persistent_log_count);
    cfg.max_persistent_file_size = get_i32(&conf, "VE_TLS_MAX_PERSISTENT_FILE_SIZE", cfg.max_persistent_file_size);
    cfg.max_persistent_file_count = get_i32(&conf, "VE_TLS_MAX_PERSISTENT_FILE_COUNT", cfg.max_persistent_file_count);
    cfg.force_flush_disk = get_i32(&conf, "VE_TLS_FORCE_FLUSH_DISK", cfg.force_flush_disk);
    cfg.persistent_max_bytes = get_i32(&conf, "VE_TLS_PERSISTENT_MAX_BYTES", cfg.persistent_max_bytes);
    cfg.persistent_max_records = get_i32(&conf, "VE_TLS_PERSISTENT_MAX_RECORDS", cfg.persistent_max_records);
    cfg.persistent_max_segments = get_i32(&conf, "VE_TLS_PERSISTENT_MAX_SEGMENTS", cfg.persistent_max_segments);
    cfg.persistent_high_watermark_pct = get_i32(&conf, "VE_TLS_PERSISTENT_HIGH_WATERMARK_PCT", cfg.persistent_high_watermark_pct);
    cfg.persistent_low_watermark_pct = get_i32(&conf, "VE_TLS_PERSISTENT_LOW_WATERMARK_PCT", cfg.persistent_low_watermark_pct);
    cfg.persistent_overflow_policy = parse_persistent_overflow_policy(&conf, "VE_TLS_PERSISTENT_OVERFLOW_POLICY", (ve_tls_persistent_overflow_policy)cfg.persistent_overflow_policy);
    cfg.persistent_sample_every_n = get_i32(&conf, "VE_TLS_PERSISTENT_SAMPLE_EVERY_N", cfg.persistent_sample_every_n);
    cfg.persistent_block_timeout_ms = get_i32(&conf, "VE_TLS_PERSISTENT_BLOCK_TIMEOUT_MS", cfg.persistent_block_timeout_ms);
    cfg.persistent_lease_timeout_ms = get_i32(&conf, "VE_TLS_PERSISTENT_LEASE_TIMEOUT_MS", cfg.persistent_lease_timeout_ms);
    cfg.persistent_heartbeat_interval_ms = get_i32(&conf, "VE_TLS_PERSISTENT_HEARTBEAT_INTERVAL_MS", cfg.persistent_heartbeat_interval_ms);
    cfg.persistent_open_mode = parse_persistent_open_mode(&conf, "VE_TLS_PERSISTENT_OPEN_MODE", (ve_tls_persistent_open_mode)cfg.persistent_open_mode);

    int demo_debug = get_i32(&conf, "VE_TLS_DEMO_DEBUG", 0);
    int demo_metrics = get_i32(&conf, "VE_TLS_DEMO_METRICS", 0);
    int32_t demo_rate_lps = get_i32(&conf, "VE_TLS_DEMO_RATE_LPS", 0);
    int32_t demo_duration_s = get_i32(&conf, "VE_TLS_DEMO_DURATION_S", 0);
    int32_t demo_flush_every_n = get_i32(&conf, "VE_TLS_DEMO_FLUSH_EVERY_N", 0);
    int32_t demo_start_seq = get_i32(&conf, "VE_TLS_DEMO_START_SEQ", 0);
    int32_t demo_recover = get_i32(&conf, "VE_TLS_DEMO_RECOVER", 0);
    int32_t demo_expect_success = get_i32(&conf, "VE_TLS_DEMO_EXPECT_SUCCESS", count);
    int32_t demo_exit_after_enqueue = get_i32(&conf, "VE_TLS_DEMO_EXIT_AFTER_ENQUEUE", 0);
    int32_t demo_exit_after_success = get_i32(&conf, "VE_TLS_DEMO_EXIT_AFTER_SUCCESS", 0);
    int32_t demo_exit_delay_ms = get_i32(&conf, "VE_TLS_DEMO_EXIT_DELAY_MS", 0);
    int32_t demo_close_timeout_ms = get_i32(&conf, "VE_TLS_DEMO_CLOSE_TIMEOUT_MS", wait_ms);
    int32_t demo_print_success_callbacks = get_i32(&conf, "VE_TLS_DEMO_PRINT_SUCCESS_CALLBACKS", 1);
    const char * demo_run_id = get_str(&conf, "VE_TLS_DEMO_RUN_ID", NULL);
    const char * demo_scenario = get_str(&conf, "VE_TLS_DEMO_SCENARIO", NULL);
    if (demo_rate_lps < 0) demo_rate_lps = 0;
    if (demo_duration_s < 0) demo_duration_s = 0;
    if (demo_flush_every_n < 0) demo_flush_every_n = 0;
    if (demo_metrics) {
        cfg.metrics_sink.emit = metrics_emit;
        cfg.metrics_sink.user_param = NULL;
    }

    if (!cfg.endpoint || !cfg.region || !cfg.topic_id || !cfg.access_key_id || !cfg.access_key_secret) {
        fprintf(stderr, "missing required config: endpoint/region/topic_id/access_key_id/access_key_secret\n");
        usage(argv[0]);
        conf_free(&conf);
        return 1;
    }

    const char * msg = get_str(&conf, "VE_TLS_DEMO_MESSAGE", "hello");
    const char * raw_file = get_str(&conf, "VE_TLS_DEMO_LOG_RAW_FILE", NULL);
    unsigned char * raw_log = NULL;
    size_t raw_log_size = 0;
    int use_raw_log = 0;
    if (raw_file && raw_file[0] != 0) {
        if (load_file_bytes(raw_file, &raw_log, &raw_log_size) != 0) {
            fprintf(stderr, "failed to load raw log file: %s\n", raw_file);
            conf_free(&conf);
            return 1;
        }
        use_raw_log = 1;
    }
    print_cfg(&cfg, (int)count, (int)interval_ms, (int)wait_ms, demo_debug, demo_metrics, cfg.http_debug);

    ve_tls_producer * p = ve_tls_producer_create(&cfg);
    if (!p) {
        fprintf(stderr, "ve_tls_producer_create failed\n");
        free(raw_log);
        conf_free(&conf);
        return 1;
    }
    memset(&g_demo_state, 0, sizeof(g_demo_state));
    g_demo_state.exit_after_success = demo_exit_after_success;
    g_demo_state.print_success_callbacks = demo_print_success_callbacks != 0;
    ve_tls_producer_set_send_done_v2(p, on_send_done_v2, NULL);

    int recover_rc = -1;
    if (demo_recover) {
        ve_tls_result recover = ve_tls_producer_recover(p);
        recover_rc = (int)recover;
        fprintf(stderr, "recover rc=%d\n", (int)recover);
        if (recover != VE_TLS_OK) {
            ve_tls_producer_destroy(p);
            free(raw_log);
            conf_free(&conf);
            return 1;
        }
    }

    if (count < 0) count = 0;
    if (interval_ms < 0) interval_ms = 0;
    if (wait_ms < 0) wait_ms = 0;
    if (duration_s < 0) duration_s = 0;
    if (duration_s == 0 && demo_duration_s > 0) duration_s = demo_duration_s;

    int64_t start_ms = cfg.platform.time_ms();
    int64_t end_ms = 0;
    if (duration_s > 0) {
        end_ms = start_ms + (int64_t)duration_s * 1000;
    }
    int32_t attempted = 0;
    int32_t add_ok = 0;
    int32_t add_fail = 0;
    int32_t seq_i = 0;
    int64_t next_emit_ns = 0;
    for (;;) {
        if (duration_s > 0) {
            int64_t now = cfg.platform.time_ms();
            if (now >= end_ms) break;
        } else {
            if (attempted >= count) break;
        }
        int32_t seq_n = seq_i++;
        ve_tls_result rc;
        if (use_raw_log) {
            rc = ve_tls_producer_add_log_raw(p, (const char *)raw_log, raw_log_size, 0);
        } else {
            char seq[32];
            char pid_buf[32];
            ve_tls_kv kvs[5];
            size_t kv_count = 0;
            snprintf(seq, sizeof(seq), "%d", (int)(demo_start_seq + seq_n));
            snprintf(pid_buf, sizeof(pid_buf), "%d", (int)getpid());
            kvs[kv_count].key = "message";
            kvs[kv_count++].value = msg;
            kvs[kv_count].key = "seq";
            kvs[kv_count++].value = seq;
            kvs[kv_count].key = "pid";
            kvs[kv_count++].value = pid_buf;
            if (demo_run_id && demo_run_id[0] != 0) {
                kvs[kv_count].key = "run_id";
                kvs[kv_count++].value = demo_run_id;
            }
            if (demo_scenario && demo_scenario[0] != 0) {
                kvs[kv_count].key = "scenario";
                kvs[kv_count++].value = demo_scenario;
            }
            rc = ve_tls_producer_add_log_kv_hashkey(p, 0, cfg.hash_key, kvs, kv_count, 0);
        }
        if (rc != VE_TLS_OK) {
            fprintf(stderr, "add_log failed: %d\n", (int)rc);
            add_fail++;
        } else if (demo_debug) {
            fprintf(stderr, "add_log ok seq=%d\n", (int)seq_n);
            add_ok++;
        } else {
            add_ok++;
        }
        attempted++;
        if (demo_flush_every_n > 0 && (attempted % demo_flush_every_n) == 0) {
            (void)ve_tls_producer_flush(p);
            if (demo_debug) {
                fprintf(stderr, "flush requested n=%d\n", (int)attempted);
            }
        }
        if (interval_ms > 0) {
            cfg.platform.sleep_ms(interval_ms);
        } else if (demo_rate_lps > 0) {
            pace_rate_lps(demo_rate_lps, &next_emit_ns);
        }
    }

    if (demo_exit_after_enqueue) {
        if (demo_exit_delay_ms > 0 && cfg.platform.sleep_ms) {
            cfg.platform.sleep_ms(demo_exit_delay_ms);
        }
        fprintf(stderr, "abrupt exit after enqueue add_ok=%d add_fail=%d attempted=%d\n", (int)add_ok, (int)add_fail, (int)attempted);
        fflush(stderr);
        _exit(90);
    }

    if (demo_expect_success > 0) {
        int64_t begin_ms = cfg.platform.time_ms ? cfg.platform.time_ms() : 0;
        int64_t deadline_ms = begin_ms + wait_ms;
        while ((cfg.platform.time_ms ? cfg.platform.time_ms() : 0) < deadline_ms) {
            int ok = __atomic_load_n(&g_demo_state.success_logs, __ATOMIC_RELAXED);
            int fail = __atomic_load_n(&g_demo_state.failed_logs, __ATOMIC_RELAXED);
            if (ok + fail >= demo_expect_success) {
                break;
            }
            if (cfg.platform.sleep_ms) {
                cfg.platform.sleep_ms(50);
            }
        }
    }

    (void)ve_tls_producer_flush(p);
    if (demo_debug) {
        fprintf(stderr, "flush requested\n");
    }
    ve_tls_result close_rc = ve_tls_producer_close(p, demo_close_timeout_ms);
    if (demo_debug || close_rc != VE_TLS_OK) {
        fprintf(stderr, "close rc=%d\n", (int)close_rc);
    }
    ve_tls_metrics m;
    ve_tls_producer_get_metrics(p, &m);
    fprintf(stderr,
        "metrics logs_enqueued=%llu logs_dropped=%llu bytes_enqueued=%llu bytes_dropped=%llu batches=%llu requests=%llu failed=%llu retries=%llu bytes_sent=%llu\n",
        (unsigned long long)m.logs_enqueued_total,
        (unsigned long long)m.logs_dropped_total,
        (unsigned long long)m.bytes_enqueued_total,
        (unsigned long long)m.bytes_dropped_total,
        (unsigned long long)m.batches_built_total,
        (unsigned long long)m.requests_total,
        (unsigned long long)m.requests_failed_total,
        (unsigned long long)m.retries_total,
        (unsigned long long)m.bytes_sent_total
    );
    fprintf(stdout,
        "RUN_RESULT run_id=%s add_ok=%d recover_rc=%d success=%d fail=%d close_rc=%d\n",
        demo_run_id ? demo_run_id : "",
        (int)add_ok,
        recover_rc,
        __atomic_load_n(&g_demo_state.success_logs, __ATOMIC_RELAXED),
        __atomic_load_n(&g_demo_state.failed_logs, __ATOMIC_RELAXED),
        (int)close_rc
    );
    ve_tls_producer_destroy(p);
    free(raw_log);
    conf_free(&conf);
    return 0;
}
