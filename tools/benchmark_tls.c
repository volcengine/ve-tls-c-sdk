#include "ve_tls_producer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdint.h>
#include <time.h>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <psapi.h>
#else
#include <unistd.h>
#include <sys/resource.h>
#if defined(__APPLE__)
#include <sys/time.h>
#endif
#endif

static uint64_t g_send_ok = 0;
static uint64_t g_send_fail = 0;
static uint64_t g_send_bytes_raw = 0;
static uint64_t g_send_bytes_comp = 0;
static uint64_t g_fail_key_queue = 0;
static uint64_t g_fail_payload_too_large = 0;
static uint64_t g_fail_other = 0;

static int64_t now_us(void) {
#if defined(_WIN32)
    static LARGE_INTEGER freq;
    static int freq_ready = 0;
    LARGE_INTEGER now;
    if (!freq_ready) {
        QueryPerformanceFrequency(&freq);
        freq_ready = 1;
    }
    QueryPerformanceCounter(&now);
    return (int64_t)((now.QuadPart * 1000000LL) / freq.QuadPart);
#elif defined(__APPLE__)
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (int64_t)tv.tv_sec * 1000000LL + (int64_t)tv.tv_usec;
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000000LL + (int64_t)(ts.tv_nsec / 1000);
#endif
}

#if !defined(_WIN32)
static double tv_to_s(struct timeval tv) {
    return (double)tv.tv_sec + (double)tv.tv_usec / 1000000.0;
}
#endif

typedef struct {
    double user_s;
    double sys_s;
    double rss_mb;
    long cpu_count;
} usage_snapshot;

#if defined(_WIN32)
static double filetime_to_s(FILETIME ft) {
    ULARGE_INTEGER u;
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    return (double)u.QuadPart / 10000000.0;
}
#endif

static void usage_snapshot_now(usage_snapshot * out) {
    memset(out, 0, sizeof(*out));
#if defined(_WIN32)
    FILETIME create_time;
    FILETIME exit_time;
    FILETIME kernel_time;
    FILETIME user_time;
    SYSTEM_INFO si;
    PROCESS_MEMORY_COUNTERS pmc;
    if (GetProcessTimes(GetCurrentProcess(), &create_time, &exit_time, &kernel_time, &user_time)) {
        out->user_s = filetime_to_s(user_time);
        out->sys_s = filetime_to_s(kernel_time);
    }
    GetSystemInfo(&si);
    out->cpu_count = si.dwNumberOfProcessors > 0 ? (long)si.dwNumberOfProcessors : 1;
    memset(&pmc, 0, sizeof(pmc));
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
        out->rss_mb = (double)pmc.PeakWorkingSetSize / 1024.0 / 1024.0;
    }
#else
    struct rusage ru;
    memset(&ru, 0, sizeof(ru));
    getrusage(RUSAGE_SELF, &ru);
    out->user_s = tv_to_s(ru.ru_utime);
    out->sys_s = tv_to_s(ru.ru_stime);
    out->cpu_count = sysconf(_SC_NPROCESSORS_ONLN);
    if (out->cpu_count < 1) out->cpu_count = 1;
#if defined(__APPLE__)
    out->rss_mb = (double)ru.ru_maxrss / 1024.0 / 1024.0;
#else
    out->rss_mb = (double)ru.ru_maxrss / 1024.0;
#endif
#endif
    if (out->cpu_count < 1) out->cpu_count = 1;
}

static void sleep_us(int64_t us) {
    if (us <= 0) {
        return;
    }
#if defined(_WIN32)
    Sleep((DWORD)((us + 999) / 1000));
#else
    usleep((useconds_t)us);
#endif
}

static const char * env_str(const char * key, const char * defv) {
    const char * v = getenv(key);
    return (v && v[0] != 0) ? v : defv;
}

static const char * env_str2(const char * key1, const char * key2, const char * defv) {
    const char * v = env_str(key1, NULL);
    if (v) return v;
    return env_str(key2, defv);
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

static int32_t env_i32_2(const char * key1, const char * key2, int32_t defv) {
    const char * s = getenv(key1);
    if (s && s[0] != 0) return env_i32(key1, defv);
    return env_i32(key2, defv);
}

static int http_ok_do(ve_tls_http_client * client, const ve_tls_http_request * req, ve_tls_http_response * resp) {
    (void)client;
    (void)req;
    if (!resp) return -1;
    resp->status_code = 200;
    resp->request_id = strdup("rid-benchmark-tls");
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
        const char * code = (error && error->error_code) ? error->error_code : "";
        if (strcmp(code, "KeyQueueLimitExceeded") == 0) {
            (void)__atomic_fetch_add(&g_fail_key_queue, 1, __ATOMIC_RELAXED);
        } else if (strcmp(code, "PayloadTooLarge") == 0) {
            (void)__atomic_fetch_add(&g_fail_payload_too_large, 1, __ATOMIC_RELAXED);
        } else {
            (void)__atomic_fetch_add(&g_fail_other, 1, __ATOMIC_RELAXED);
        }
    }
}

static const char * k_tls700_vals[] = {
    "1abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+",
    "2abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+",
    "3abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+",
    "4abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+",
    "5abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+",
    "6abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+",
    "7abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+",
    "8abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+",
    "9abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+"
};

static void fill_tls700_kvs(ve_tls_kv * out, const char * index_str) {
    out[0].key = "content_key_1"; out[0].value = k_tls700_vals[0];
    out[1].key = "content_key_2"; out[1].value = k_tls700_vals[1];
    out[2].key = "content_key_3"; out[2].value = k_tls700_vals[2];
    out[3].key = "content_key_4"; out[3].value = k_tls700_vals[3];
    out[4].key = "content_key_5"; out[4].value = k_tls700_vals[4];
    out[5].key = "content_key_6"; out[5].value = k_tls700_vals[5];
    out[6].key = "content_key_7"; out[6].value = k_tls700_vals[6];
    out[7].key = "content_key_8"; out[7].value = k_tls700_vals[7];
    out[8].key = "content_key_9"; out[8].value = k_tls700_vals[8];
    out[9].key = "index"; out[9].value = index_str ? index_str : "0";
}

static void fill_tls200_kvs(ve_tls_kv * out, const char * index_str) {
    out[0].key = "LogHub"; out[0].value = "Real-time log collection and consumption";
    out[1].key = "SearchAnalytics"; out[1].value = "Query and real-time analysis";
    out[2].key = "Visualized"; out[2].value = "dashboard and report functions";
    out[3].key = "index"; out[3].value = index_str ? index_str : "0";
}

static char * make_payload(size_t n) {
    if (n == 0) n = 1;
    char * s = (char *)malloc(n + 1);
    if (!s) return NULL;
    static const char alphabet[] = "abcdefghijklmnopqrstuvwxyz0123456789";
    for (size_t i = 0; i < n; i++) {
        s[i] = alphabet[i % (sizeof(alphabet) - 1)];
    }
    s[n] = 0;
    return s;
}

static int profile_enabled(const char * profile, const char * name) {
    if (!profile || strcmp(profile, "both") == 0) {
        return strcmp(name, "tls200") == 0 || strcmp(name, "tls700") == 0;
    }
    return strcasecmp(profile, name) == 0;
}

static int per_iter_for_profile(const char * profile) {
    if (!profile || strcmp(profile, "both") == 0) return 2;
    return 1;
}

static void usage(const char * argv0) {
    fprintf(stderr, "usage: %s <logs_per_sec> <seconds> [tls200|tls700|tls5120|both]\n", argv0 ? argv0 : "ve_tls_benchmark_tls");
    fprintf(stderr, "env: TLS_BENCH_MODE=mock|curl, VE_TLS_ENDPOINT, VE_TLS_REGION, VE_TLS_TOPIC_ID, VE_TLS_ACCESS_KEY_ID, VE_TLS_ACCESS_KEY_SECRET\n");
}

int main(int argc, char ** argv) {
    int logs_per_sec = 100;
    int send_sec = 60;
    const char * profile = env_str("TLS_BENCH_PROFILE", "both");
    if (argc >= 3) {
        logs_per_sec = atoi(argv[1]);
        send_sec = atoi(argv[2]);
    }
    if (argc >= 4) {
        profile = argv[3];
    }
    if (logs_per_sec <= 0 || send_sec <= 0) {
        usage(argv[0]);
        return 2;
    }
    if (!profile_enabled(profile, "tls200") && !profile_enabled(profile, "tls700") && !profile_enabled(profile, "tls5120")) {
        usage(argv[0]);
        return 2;
    }

    const char * mode = env_str("TLS_BENCH_MODE", "mock");
    fprintf(stderr, "ve_tls_benchmark_tls profile=%s mode=%s lps=%d seconds=%d\n", profile, mode, logs_per_sec, send_sec);

    ve_tls_config cfg;
    ve_tls_config_init(&cfg);

    if (strcmp(mode, "curl") == 0) {
#if !defined(VE_TLS_HAVE_CURL)
        fprintf(stderr, "curl mode requires VE_TLS_ENABLE_CURL=ON\n");
        return 2;
#endif
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
        fprintf(stderr, "invalid TLS_BENCH_MODE: %s\n", mode);
        return 2;
    }

    cfg.max_buffer_bytes = env_i32_2("TLS_MAX_BUFFER_BYTES", "VE_TLS_MAX_BUFFER_BYTES", 64 * 1024 * 1024);
    cfg.log_bytes_per_package = env_i32_2("TLS_PACKET_LOG_BYTES", "VE_TLS_LOG_BYTES_PER_PACKAGE", 4 * 1024 * 1024);
    cfg.log_count_per_package = env_i32_2("TLS_PACKET_LOG_COUNT", "VE_TLS_LOG_COUNT_PER_PACKAGE", 4096);
    cfg.flush_interval_ms = env_i32_2("TLS_PACKET_TIMEOUT_MS", "VE_TLS_FLUSH_INTERVAL_MS", 3000);
    cfg.send_thread_count = env_i32_2("TLS_SEND_THREADS", "VE_TLS_SEND_THREAD_COUNT", 16);
    cfg.pack_thread_count = env_i32("TLS_PACK_THREADS", cfg.send_thread_count);
    cfg.send_queue_size = env_i32_2("TLS_SEND_QUEUE_SIZE", "VE_TLS_SEND_QUEUE_SIZE", 0);
    cfg.send_queue_block_timeout_ms = env_i32_2("TLS_SEND_QUEUE_BLOCK_TIMEOUT_MS", "VE_TLS_SEND_QUEUE_BLOCK_TIMEOUT_MS", 30000);
    cfg.request_timeout_ms = env_i32_2("TLS_REQUEST_TIMEOUT_MS", "VE_TLS_REQUEST_TIMEOUT_MS", cfg.request_timeout_ms);
    cfg.connect_timeout_ms = env_i32_2("TLS_CONNECT_TIMEOUT_MS", "VE_TLS_CONNECT_TIMEOUT_MS", cfg.connect_timeout_ms);
    cfg.tls_verify_peer = env_i32("VE_TLS_TLS_VERIFY_PEER", cfg.tls_verify_peer);
    cfg.tls_verify_host = env_i32("VE_TLS_TLS_VERIFY_HOST", cfg.tls_verify_host);
    cfg.ca_cert_path = env_str("VE_TLS_CA_CERT_PATH", cfg.ca_cert_path);
    cfg.proxy = env_str("VE_TLS_PROXY", cfg.proxy);
    cfg.user_agent = env_str("VE_TLS_USER_AGENT", cfg.user_agent);
    cfg.compress_type = env_str2("TLS_COMPRESS_TYPE", "VE_TLS_COMPRESS_TYPE", "lz4");
    cfg.buffer_full_policy = VE_TLS_BUFFER_FULL_DROP;
    cfg.retry_policy.max_attempts = env_i32("TLS_MAX_ATTEMPTS", 1);

    if (cfg.send_queue_size <= 0) {
        int32_t est_q = 1024;
        if (cfg.max_buffer_bytes > 0 && cfg.log_bytes_per_package > 0) {
            est_q = cfg.max_buffer_bytes / (cfg.log_bytes_per_package + 1) + 10;
        }
        if (est_q < 64) est_q = 64;
        if (est_q > 100000) est_q = 100000;
        cfg.send_queue_size = est_q * 2;
    }

    fprintf(stderr,
        "bench_config profile=%s mode=%s send_threads=%d pack_threads=%d queue=%d compress=%s flush_ms=%d packet_bytes=%d packet_count=%d request_timeout_ms=%d\n",
        profile,
        mode,
        (int)cfg.send_thread_count,
        (int)cfg.pack_thread_count,
        (int)cfg.send_queue_size,
        cfg.compress_type ? cfg.compress_type : "",
        (int)cfg.flush_interval_ms,
        (int)cfg.log_bytes_per_package,
        (int)cfg.log_count_per_package,
        (int)cfg.request_timeout_ms
    );

    char * tls5120_payload = make_payload(5120);
    if (!tls5120_payload) return 3;

    ve_tls_producer * p = ve_tls_producer_create(&cfg);
    if (!p) {
        fprintf(stderr, "create producer failed\n");
        free(tls5120_payload);
        return 3;
    }
    ve_tls_producer_set_send_done_v2(p, on_send_done, NULL);

    int64_t total_enqueue_us = 0;
    uint64_t enqueue_ok_total = 0;
    uint64_t enqueue_drop_total = 0;
    uint64_t enqueue_other_total = 0;
    uint64_t last_send_ok = 0;
    uint64_t last_send_fail = 0;
    uint64_t last_send_raw = 0;
    uint64_t last_send_comp = 0;

    usage_snapshot usage0;
    usage_snapshot_now(&usage0);
    int64_t wall_start_us = now_us();

    for (int i = 0; i < send_sec; i++) {
        int64_t start_us = now_us();
        int64_t ok = 0;
        int64_t drop = 0;
        int64_t other = 0;
        for (int j = 0; j < logs_per_sec; j++) {
            char index_str[32];
            snprintf(index_str, sizeof(index_str), "%d", i * logs_per_sec + j);
            if (profile_enabled(profile, "tls700")) {
                ve_tls_kv kvs[10];
                fill_tls700_kvs(kvs, index_str);
                ve_tls_result r = ve_tls_producer_add_log_kv(p, 0, kvs, 10, 0);
                if (r == VE_TLS_OK) ok++; else if (r == VE_TLS_DROP_ERROR) drop++; else other++;
            }
            if (profile_enabled(profile, "tls200")) {
                ve_tls_kv kvs[4];
                fill_tls200_kvs(kvs, index_str);
                ve_tls_result r = ve_tls_producer_add_log_kv(p, 0, kvs, 4, 0);
                if (r == VE_TLS_OK) ok++; else if (r == VE_TLS_DROP_ERROR) drop++; else other++;
            }
            if (profile_enabled(profile, "tls5120")) {
                ve_tls_kv kvs[2];
                kvs[0].key = "message";
                kvs[0].value = tls5120_payload;
                kvs[1].key = "index";
                kvs[1].value = index_str;
                ve_tls_result r = ve_tls_producer_add_log_kv(p, 0, kvs, 2, 0);
                if (r == VE_TLS_OK) ok++; else if (r == VE_TLS_DROP_ERROR) drop++; else other++;
            }
        }
        int64_t end_us = now_us();
        int per_iter = per_iter_for_profile(profile);
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
        fprintf(stderr,
            "second=%d calls=%lld enqueue_ok=%lld enqueue_drop=%lld enqueue_other=%lld us_per_log=%.2f send_ok=%llu send_fail=%llu raw_mb=%.2f comp_mb=%.2f buffer_mb=%.2f\n",
            i,
            (long long)calls,
            (long long)ok,
            (long long)drop,
            (long long)other,
            us_per_log,
            (unsigned long long)dso,
            (unsigned long long)dsf,
            (double)dsr / 1024.0 / 1024.0,
            (double)dsc / 1024.0 / 1024.0,
            (double)buf_bytes / 1024.0 / 1024.0
        );

        enqueue_ok_total += (uint64_t)ok;
        enqueue_drop_total += (uint64_t)drop;
        enqueue_other_total += (uint64_t)other;
        total_enqueue_us += end_us - start_us;
        int64_t spend = end_us - start_us;
        if (spend < 1000000) {
            sleep_us(1000000 - spend);
        }
    }

    int64_t close_start_us = now_us();
    int32_t close_timeout_ms = env_i32("TLS_CLOSE_TIMEOUT_MS", 300000);
    ve_tls_result close_rc = ve_tls_producer_close(p, close_timeout_ms);
    int64_t close_us = now_us() - close_start_us;

    ve_tls_metrics m;
    memset(&m, 0, sizeof(m));
    ve_tls_producer_get_metrics(p, &m);

    int per_iter = per_iter_for_profile(profile);
    double avg_us = (send_sec > 0 && logs_per_sec > 0) ? (double)total_enqueue_us / ((double)send_sec * (double)logs_per_sec * (double)per_iter) : 0.0;
    int64_t wall_end_us = now_us();
    double wall_s = (double)(wall_end_us - wall_start_us) / 1000000.0;

    usage_snapshot usage1;
    usage_snapshot_now(&usage1);
    double user_s = usage1.user_s - usage0.user_s;
    double sys_s = usage1.sys_s - usage0.sys_s;
    double cpu_s = user_s + sys_s;
    long ncpu = usage1.cpu_count;
    double cpu_cores = wall_s > 0 ? cpu_s / wall_s : 0.0;
    double cpu_pct_total = wall_s > 0 ? (cpu_s / (wall_s * (double)ncpu)) * 100.0 : 0.0;
    double rss_mb = usage1.rss_mb;

    fprintf(stderr, "summary profile=%s target_rate=%d logs_per_s seconds=%d enqueue_ok=%llu enqueue_drop=%llu enqueue_other=%llu avg_enqueue_us=%.2f\n",
        profile,
        logs_per_sec * per_iter,
        send_sec,
        (unsigned long long)enqueue_ok_total,
        (unsigned long long)enqueue_drop_total,
        (unsigned long long)enqueue_other_total,
        avg_us
    );
    fprintf(stderr, "summary close_rc=%d close_ms=%.2f wall_s=%.3f logs=%llu dropped=%llu batches=%llu requests=%llu failed=%llu retries=%llu bytes_sent=%llu\n",
        (int)close_rc,
        (double)close_us / 1000.0,
        wall_s,
        (unsigned long long)m.logs_enqueued_total,
        (unsigned long long)m.logs_dropped_total,
        (unsigned long long)m.batches_built_total,
        (unsigned long long)m.requests_total,
        (unsigned long long)m.requests_failed_total,
        (unsigned long long)m.retries_total,
        (unsigned long long)m.bytes_sent_total
    );
    fprintf(stderr, "summary send_callback_ok=%llu send_callback_non_ok=%llu fail_key_queue=%llu fail_payload_too_large=%llu fail_other=%llu\n",
        (unsigned long long)__atomic_load_n(&g_send_ok, __ATOMIC_RELAXED),
        (unsigned long long)__atomic_load_n(&g_send_fail, __ATOMIC_RELAXED),
        (unsigned long long)__atomic_load_n(&g_fail_key_queue, __ATOMIC_RELAXED),
        (unsigned long long)__atomic_load_n(&g_fail_payload_too_large, __ATOMIC_RELAXED),
        (unsigned long long)__atomic_load_n(&g_fail_other, __ATOMIC_RELAXED)
    );
    fprintf(stderr, "summary user_s=%.3f sys_s=%.3f cpu_cores=%.2f cpu_pct_total=%.2f rss_mb=%.2f\n",
        user_s,
        sys_s,
        cpu_cores,
        cpu_pct_total,
        rss_mb
    );

    ve_tls_producer_destroy(p);
    free(tls5120_payload);
    return close_rc == VE_TLS_OK ? 0 : 1;
}
