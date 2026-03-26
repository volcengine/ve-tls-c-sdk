#include "ve_tls_producer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <sys/resource.h>

#if defined(__APPLE__)
#include <sys/time.h>
#endif

static uint64_t g_send_ok = 0;
static uint64_t g_send_fail = 0;
static uint64_t g_send_bytes_raw = 0;
static uint64_t g_send_bytes_comp = 0;

static int64_t now_us(void) {
#if defined(__APPLE__)
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (int64_t)tv.tv_sec * 1000000LL + (int64_t)tv.tv_usec;
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000000LL + (int64_t)(ts.tv_nsec / 1000);
#endif
}

static double tv_to_s(struct timeval tv) {
    return (double)tv.tv_sec + (double)tv.tv_usec / 1000000.0;
}

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
    if (v < INT32_MIN || v > INT32_MAX) return defv;
    return (int32_t)v;
}

static int http_ok_do(ve_tls_http_client * client, const ve_tls_http_request * req, ve_tls_http_response * resp) {
    (void)client;
    (void)req;
    if (!resp) return -1;
    resp->status_code = 200;
    resp->request_id = strdup("rid-sls-mock");
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
    (void)error;
    (void)raw_buffer;
    (void)user_param;
    (void)start_id;
    (void)end_id;
    if (result == VE_TLS_OK) {
        (void)__atomic_fetch_add(&g_send_ok, 1, __ATOMIC_RELAXED);
        (void)__atomic_fetch_add(&g_send_bytes_raw, (uint64_t)log_bytes, __ATOMIC_RELAXED);
        (void)__atomic_fetch_add(&g_send_bytes_comp, (uint64_t)compressed_bytes, __ATOMIC_RELAXED);
    } else {
        (void)__atomic_fetch_add(&g_send_fail, 1, __ATOMIC_RELAXED);
    }
}

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

static void fill_sls700_kvs(ve_tls_kv * out, const char * index_str) {
    out[0].key = "content_key_1"; out[0].value = k_sls_700_vals[0];
    out[1].key = "content_key_2"; out[1].value = k_sls_700_vals[1];
    out[2].key = "content_key_3"; out[2].value = k_sls_700_vals[2];
    out[3].key = "content_key_4"; out[3].value = k_sls_700_vals[3];
    out[4].key = "content_key_5"; out[4].value = k_sls_700_vals[4];
    out[5].key = "content_key_6"; out[5].value = k_sls_700_vals[5];
    out[6].key = "content_key_7"; out[6].value = k_sls_700_vals[6];
    out[7].key = "content_key_8"; out[7].value = k_sls_700_vals[7];
    out[8].key = "content_key_9"; out[8].value = k_sls_700_vals[8];
    out[9].key = "index"; out[9].value = index_str ? index_str : k_sls_700_vals[9];
}

static void fill_sls200_kvs(ve_tls_kv * out) {
    out[0].key = "LogHub"; out[0].value = "Real-time log collection and consumption";
    out[1].key = "Search/Analytics"; out[1].value = "Query and real-time analysis";
    out[2].key = "Visualized"; out[2].value = "dashboard and report functions";
    out[3].key = "Interconnection"; out[3].value = "Grafana and JDBC/SQL92";
}

int main(int argc, char ** argv) {
    int logs_per_sec = 100;
    int send_sec = 180;
    if (argc >= 3) {
        logs_per_sec = atoi(argv[1]);
        send_sec = atoi(argv[2]);
    }
    const char * profile = NULL;
    if (argc >= 4) {
        profile = argv[3];
    } else {
        profile = env_str("SLS_BENCH_PROFILE", "both");
    }
    const char * mode = env_str("SLS_BENCH_MODE", "mock");
    fprintf(stderr, "ve_tls_benchmark_sls build=%s %s profile=%s mode=%s\n", __DATE__, __TIME__, profile ? profile : "(null)", mode ? mode : "(null)");

    ve_tls_config cfg;
    ve_tls_config_init(&cfg);

    if (strcmp(mode, "curl") == 0) {
        cfg.endpoint = env_str("VE_TLS_ENDPOINT", NULL);
        cfg.region = env_str("VE_TLS_REGION", NULL);
        cfg.topic_id = env_str("VE_TLS_TOPIC_ID", NULL);
        cfg.access_key_id = env_str("VE_TLS_ACCESS_KEY_ID", NULL);
        cfg.access_key_secret = env_str("VE_TLS_ACCESS_KEY_SECRET", NULL);
        cfg.security_token = env_str("VE_TLS_SECURITY_TOKEN", NULL);
        if (!cfg.endpoint || !cfg.region || !cfg.topic_id || !cfg.access_key_id || !cfg.access_key_secret) {
            fprintf(stderr, "missing VE_TLS_ENDPOINT/REGION/TOPIC_ID/ACCESS_KEY_ID/ACCESS_KEY_SECRET for curl mode\n");
            return 2;
        }
    } else if (strcmp(mode, "mock") == 0) {
        cfg.endpoint = "https://example.com";
        cfg.region = "cn-beijing";
        cfg.topic_id = "mock-topic";
        cfg.access_key_id = "ak";
        cfg.access_key_secret = "sk";
        cfg.http_client.do_request = http_ok_do;
        cfg.http_client.free_response = http_ok_free;
    } else {
        fprintf(stderr, "invalid mode: %s\n", mode);
        return 2;
    }

    cfg.max_buffer_bytes = env_i32("SLS_MAX_BUFFER_BYTES", 64 * 1024 * 1024);
    cfg.log_bytes_per_package = env_i32("SLS_PACKET_LOG_BYTES", 4 * 1024 * 1024);
    cfg.log_count_per_package = env_i32("SLS_PACKET_LOG_COUNT", 4096);
    cfg.flush_interval_ms = env_i32("SLS_PACKET_TIMEOUT_MS", 3000);
    cfg.send_thread_count = env_i32("SLS_SEND_THREADS", 16);
    cfg.pack_thread_count = env_i32("SLS_PACK_THREADS", cfg.send_thread_count);
    cfg.buffer_full_policy = VE_TLS_BUFFER_FULL_DROP;

    int use_lz4 = env_i32("SLS_COMPRESS_LZ4", 1);
    cfg.compress_type = use_lz4 ? "lz4" : "none";
    fprintf(stderr, "ve_tls_benchmark_sls cfg: lps=%d send_s=%d send_threads=%d pack_threads=%d compress=%s ordered_send=%d\n",
            logs_per_sec, send_sec, (int)cfg.send_thread_count, (int)cfg.pack_thread_count, cfg.compress_type ? cfg.compress_type : "(null)", (int)cfg.ordered_send);

    int32_t est_q = 0;
    if (cfg.max_buffer_bytes > 0 && cfg.log_bytes_per_package > 0) {
        est_q = cfg.max_buffer_bytes / (cfg.log_bytes_per_package + 1) + 10;
    } else {
        est_q = 1024;
    }
    if (est_q < 64) est_q = 64;
    if (est_q > 100000) est_q = 100000;
    cfg.send_queue_size = est_q * 2;
    cfg.retry_policy.max_attempts = 1;

    ve_tls_producer * p = ve_tls_producer_create(&cfg);
    if (!p) {
        fprintf(stderr, "create producer failed\n");
        return 3;
    }
    ve_tls_producer_set_send_done_v2(p, on_send_done, NULL);

    int64_t total_time_us = 0;
    uint64_t last_send_ok = 0;
    uint64_t last_send_fail = 0;
    uint64_t last_send_raw = 0;
    uint64_t last_send_comp = 0;

    struct rusage ru0;
    memset(&ru0, 0, sizeof(ru0));
    getrusage(RUSAGE_SELF, &ru0);
    int64_t wall_start_us = now_us();

    for (int i = 0; i < send_sec; i++) {
        int64_t start_us = now_us();
        int64_t ok = 0;
        int64_t drop = 0;
        int64_t other = 0;
        int per_iter = (!profile || strcmp(profile, "both") == 0) ? 2 : 1;
        for (int j = 0; j < logs_per_sec; j++) {
            char index_str[32];
            snprintf(index_str, sizeof(index_str), "%d", i * logs_per_sec + j);
            if (!profile || strcmp(profile, "both") == 0 || strcmp(profile, "sls700") == 0) {
                ve_tls_kv kvs[10];
                fill_sls700_kvs(kvs, index_str);
                ve_tls_result r = ve_tls_producer_add_log_kv(p, 0, kvs, 10, 0);
                if (r == VE_TLS_OK) ok++; else if (r == VE_TLS_DROP_ERROR) drop++; else other++;
            }
            if (!profile || strcmp(profile, "both") == 0 || strcmp(profile, "sls200") == 0) {
                ve_tls_kv kvs[4];
                fill_sls200_kvs(kvs);
                ve_tls_result r = ve_tls_producer_add_log_kv(p, 0, kvs, 4, 0);
                if (r == VE_TLS_OK) ok++; else if (r == VE_TLS_DROP_ERROR) drop++; else other++;
            }
        }
        int64_t end_us = now_us();
        int64_t calls = (int64_t)logs_per_sec * (int64_t)per_iter;
        double us_per_log = calls > 0 ? (double)(end_us - start_us) / (double)calls : 0.0;

        uint64_t so = __atomic_load_n(&g_send_ok, __ATOMIC_RELAXED);
        uint64_t sf = __atomic_load_n(&g_send_fail, __ATOMIC_RELAXED);
        uint64_t sr = __atomic_load_n(&g_send_bytes_raw, __ATOMIC_RELAXED);
        uint64_t sc = __atomic_load_n(&g_send_bytes_comp, __ATOMIC_RELAXED);
        uint64_t dso = so - last_send_ok;
        uint64_t dsf = sf - last_send_fail;
        uint64_t dsr = sr - last_send_raw;
        uint64_t dsc = sc - last_send_comp;
        last_send_ok = so;
        last_send_fail = sf;
        last_send_raw = sr;
        last_send_comp = sc;

        size_t buf_bytes = ve_tls_producer_get_buffered_bytes(p);
        fprintf(stderr, "Done : %d target_iter=%d per_iter=%d calls=%lld ok=%lld drop=%lld other=%lld us_per_log=%0.2f\n",
            i, logs_per_sec, per_iter, (long long)calls, (long long)ok, (long long)drop, (long long)other, us_per_log);
        fprintf(stderr, "Send : %d send_ok=%llu send_fail=%llu raw_mb=%0.2f comp_mb=%0.2f buffer_mb=%0.2f\n",
            i,
            (unsigned long long)dso,
            (unsigned long long)dsf,
            (double)dsr / 1024.0 / 1024.0,
            (double)dsc / 1024.0 / 1024.0,
            (double)buf_bytes / 1024.0 / 1024.0
        );

        total_time_us += end_us - start_us;
        int64_t spend = end_us - start_us;
        if (spend < 1000000) {
            usleep((useconds_t)(1000000 - spend));
        }
    }

    int per_iter = (!profile || strcmp(profile, "both") == 0) ? 2 : 1;
    double avg_us = (send_sec > 0 && logs_per_sec > 0) ? (double)total_time_us / ((double)send_sec * (double)logs_per_sec * (double)per_iter) : 0.0;
    fprintf(stderr, "Total done : total_us=%lld avg_us_per_log=%0.2f\n", (long long)total_time_us, avg_us);

    struct rusage ru1;
    memset(&ru1, 0, sizeof(ru1));
    getrusage(RUSAGE_SELF, &ru1);
    int64_t wall_end_us = now_us();
    double wall_s = (double)(wall_end_us - wall_start_us) / 1000000.0;
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
    fprintf(stderr, "Stats : user_s=%.3f sys_s=%.3f cpu_cores=%.2f cpu_pct_1=%.2f cpu_pct_total=%.2f rss_mb=%.2f\n",
        user_s, sys_s, cpu_cores, cpu_pct_1, cpu_pct_total, rss_mb);

    ve_tls_producer_destroy(p);
    return 0;
}
