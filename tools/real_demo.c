#include "ve_tls_producer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

typedef struct {
    char * kv[128][2];
    int kv_len;
    char * allocs[256];
    int alloc_len;
} demo_conf;

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
    (void)compressed_bytes;
    (void)raw_buffer;
    (void)user_param;
    const char * req_id = (error && error->request_id) ? error->request_id : "";
    const char * err_code = (error && error->error_code) ? error->error_code : "";
    const char * err_msg = (error && error->error_message) ? error->error_message : "";
    int http_code = error ? error->http_code : 0;
    int retryable = error ? error->retryable : 0;
    printf("result=%d bytes=%zu http=%d retryable=%d req_id=%s code=%s msg=%s start=%lld end=%lld\n",
        (int)result,
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
}

static void usage(const char * argv0) {
    fprintf(stderr, "usage: %s [--config path] [--count N] [--interval-ms M] [--wait-ms M] [--duration-s S]\n", argv0 ? argv0 : "ve_tls_demo_real");
    fprintf(stderr, "required env/config keys: VE_TLS_ENDPOINT VE_TLS_REGION VE_TLS_TOPIC_ID VE_TLS_ACCESS_KEY_ID VE_TLS_ACCESS_KEY_SECRET\n");
    fprintf(stderr, "optional keys: VE_TLS_SECURITY_TOKEN VE_TLS_COMPRESS_TYPE VE_TLS_SEND_THREAD_COUNT VE_TLS_MAX_BUFFER_BYTES VE_TLS_LOG_BYTES_PER_PACKAGE VE_TLS_LOG_COUNT_PER_PACKAGE VE_TLS_AGG_MAX_RAW_BYTES_PER_REQUEST VE_TLS_AGG_MAX_COMPRESSED_BYTES_PER_REQUEST VE_TLS_LOG_TAGS VE_TLS_FLUSH_INTERVAL_MS VE_TLS_REQUEST_TIMEOUT_MS VE_TLS_CONNECT_TIMEOUT_MS VE_TLS_CA_CERT_PATH VE_TLS_PROXY VE_TLS_TLS_VERIFY_PEER VE_TLS_TLS_VERIFY_HOST VE_TLS_USER_AGENT VE_TLS_HASH_KEY VE_TLS_HTTP_DEBUG VE_TLS_SEND_QUEUE_SIZE VE_TLS_SEND_QUEUE_FULL_POLICY VE_TLS_SEND_QUEUE_BLOCK_TIMEOUT_MS VE_TLS_SEND_QUEUE_SAMPLE_EVERY_N\n");
    fprintf(stderr, "demo keys: VE_TLS_DEMO_MESSAGE VE_TLS_DEMO_LOG_RAW_FILE VE_TLS_DEMO_DEBUG VE_TLS_DEMO_METRICS VE_TLS_DEMO_RATE_LPS VE_TLS_DEMO_DURATION_S VE_TLS_DEMO_FLUSH_EVERY_N\n");
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

    int demo_debug = get_i32(&conf, "VE_TLS_DEMO_DEBUG", 0);
    int demo_metrics = get_i32(&conf, "VE_TLS_DEMO_METRICS", 0);
    int32_t demo_rate_lps = get_i32(&conf, "VE_TLS_DEMO_RATE_LPS", 0);
    int32_t demo_duration_s = get_i32(&conf, "VE_TLS_DEMO_DURATION_S", 0);
    int32_t demo_flush_every_n = get_i32(&conf, "VE_TLS_DEMO_FLUSH_EVERY_N", 0);
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
    ve_tls_producer_set_send_done_v2(p, on_send_done_v2, NULL);

    if (count < 1) count = 1;
    if (interval_ms < 0) interval_ms = 0;
    if (wait_ms < 0) wait_ms = 0;
    if (duration_s < 0) duration_s = 0;
    if (duration_s == 0 && demo_duration_s > 0) duration_s = demo_duration_s;

    int64_t start_ms = cfg.platform.time_ms();
    int64_t end_ms = 0;
    if (duration_s > 0) {
        end_ms = start_ms + (int64_t)duration_s * 1000;
    }
    int32_t sent = 0;
    int32_t seq_i = 0;
    int32_t per_log_sleep_ms = 0;
    if (demo_rate_lps > 0) {
        per_log_sleep_ms = 1000 / demo_rate_lps;
        if (per_log_sleep_ms < 0) per_log_sleep_ms = 0;
    }
    for (;;) {
        if (duration_s > 0) {
            int64_t now = cfg.platform.time_ms();
            if (now >= end_ms) break;
        } else {
            if (sent >= count) break;
        }
        int32_t seq_n = seq_i++;
        ve_tls_result rc;
        if (use_raw_log) {
            rc = ve_tls_producer_add_log_raw(p, (const char *)raw_log, raw_log_size, 0);
        } else {
            char seq[32];
            snprintf(seq, sizeof(seq), "%d", (int)seq_n);
            ve_tls_kv kvs[3];
            kvs[0].key = "message";
            kvs[0].value = msg;
            kvs[1].key = "seq";
            kvs[1].value = seq;
            kvs[2].key = "pid";
            kvs[2].value = "demo";
            rc = ve_tls_producer_add_log_kv_hashkey(p, 0, cfg.hash_key, kvs, 3, 0);
        }
        if (rc != VE_TLS_OK) {
            fprintf(stderr, "add_log failed: %d\n", (int)rc);
        } else if (demo_debug) {
            fprintf(stderr, "add_log ok seq=%d\n", (int)seq_n);
        }
        sent++;
        if (demo_flush_every_n > 0 && (sent % demo_flush_every_n) == 0) {
            (void)ve_tls_producer_flush(p);
            if (demo_debug) {
                fprintf(stderr, "flush requested n=%d\n", (int)sent);
            }
        }
        if (interval_ms > 0) {
            cfg.platform.sleep_ms(interval_ms);
        } else if (per_log_sleep_ms > 0) {
            cfg.platform.sleep_ms(per_log_sleep_ms);
        }
    }

    (void)ve_tls_producer_flush(p);
    if (demo_debug) {
        fprintf(stderr, "flush requested\n");
    }
    ve_tls_result close_rc = ve_tls_producer_close(p, wait_ms);
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
    ve_tls_producer_destroy(p);
    free(raw_log);
    conf_free(&conf);
    return 0;
}
