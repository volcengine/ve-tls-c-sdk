#include "ve_tls_bricks.h"
#include "ve_tls_proto.h"

#include <curl/curl.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

typedef struct {
    char * data;
    size_t size;
} mem_buf;

typedef struct {
    int attempts;
    int success;
    int failed;
    size_t request_bytes;
    size_t response_bytes;
    int64_t total_us;
    int64_t min_us;
    int64_t max_us;
} bench_stats;

static int64_t now_us(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (int64_t)tv.tv_sec * 1000000LL + (int64_t)tv.tv_usec;
}

static void stats_record(bench_stats * stats, int ok, size_t request_bytes, size_t response_bytes, int64_t elapsed_us) {
    if (!stats) return;
    stats->attempts++;
    if (ok) {
        stats->success++;
    } else {
        stats->failed++;
    }
    stats->request_bytes += request_bytes;
    stats->response_bytes += response_bytes;
    stats->total_us += elapsed_us;
    if (stats->min_us == 0 || elapsed_us < stats->min_us) {
        stats->min_us = elapsed_us;
    }
    if (elapsed_us > stats->max_us) {
        stats->max_us = elapsed_us;
    }
}

static const char * env_str(const char * key, const char * defv) {
    const char * v = getenv(key);
    return (v && v[0] != 0) ? v : defv;
}

static int env_i32(const char * key, int defv) {
    const char * s = env_str(key, NULL);
    if (!s) return defv;
    char * end = NULL;
    long v = strtol(s, &end, 10);
    if (!end || end == s) return defv;
    return (int)v;
}

static size_t write_cb(char * ptr, size_t size, size_t nmemb, void * userdata) {
    size_t n = size * nmemb;
    mem_buf * b = (mem_buf *)userdata;
    if (!b || n == 0) return n;
    if (b->size > (size_t)-1 - n - 1) return 0;
    char * next = (char *)realloc(b->data, b->size + n + 1);
    if (!next) return 0;
    b->data = next;
    memcpy(b->data + b->size, ptr, n);
    b->size += n;
    b->data[b->size] = 0;
    return n;
}

static struct curl_slist * headers_to_curl_list(const char * headers) {
    if (!headers) return NULL;
    char * copy = strdup(headers);
    if (!copy) return NULL;
    struct curl_slist * list = NULL;
    char * line = copy;
    while (line && *line) {
        char * nl = strchr(line, '\n');
        if (nl) *nl = 0;
        if (line[0] != 0) {
            const char * header_line = line;
            char * empty_header = NULL;
            char * colon = strchr(line, ':');
            if (colon) {
                const char * value = colon + 1;
                while (*value == ' ' || *value == '\t') value++;
                if (*value == 0) {
                    size_t key_len = (size_t)(colon - line);
                    empty_header = (char *)malloc(key_len + 2);
                    if (!empty_header) {
                        curl_slist_free_all(list);
                        free(copy);
                        return NULL;
                    }
                    memcpy(empty_header, line, key_len);
                    empty_header[key_len] = ';';
                    empty_header[key_len + 1] = 0;
                    header_line = empty_header;
                }
            }
            struct curl_slist * next = curl_slist_append(list, header_line);
            free(empty_header);
            if (!next) {
                curl_slist_free_all(list);
                free(copy);
                return NULL;
            }
            list = next;
        }
        line = nl ? (nl + 1) : NULL;
    }
    free(copy);
    return list;
}

static void usage(const char * argv0) {
    fprintf(stderr, "usage: %s [--count N] [--timeout-ms N] [--quiet]\n", argv0 ? argv0 : "ve_tls_bricks_demo_real");
    fprintf(stderr, "required env: VE_TLS_ENDPOINT VE_TLS_REGION VE_TLS_TOPIC_ID VE_TLS_ACCESS_KEY_ID VE_TLS_ACCESS_KEY_SECRET\n");
    fprintf(stderr, "optional env: VE_TLS_SECURITY_TOKEN VE_TLS_COMPRESS_TYPE VE_TLS_HASH_KEY VE_TLS_HTTP_DEBUG\n");
}

static int send_one(CURL * curl, int index, int timeout_ms, int quiet, bench_stats * stats) {
    int64_t start_us = now_us();
    int64_t elapsed_us;
    char msg[128];
    snprintf(msg, sizeof(msg), "ve-tls-bricks-real-%lld-%d", (long long)time(NULL), index);
    ve_tls_kv kvs[1];
    kvs[0].key = "message";
    kvs[0].value = msg;

    int64_t now_ms = (int64_t)time(NULL) * 1000LL;
    ve_tls_bytes log;
    ve_tls_bytes group;
    ve_tls_bricks_request req;
    ve_tls_bricks_config cfg;
    memset(&log, 0, sizeof(log));
    memset(&group, 0, sizeof(group));
    memset(&req, 0, sizeof(req));
    memset(&cfg, 0, sizeof(cfg));

    int rc = ve_tls_proto_encode_log(now_ms, kvs, 1, &log);
    if (rc == 0) {
        rc = ve_tls_proto_encode_log_group_list_ex(&log, 1, "bricks-real", "bricks_real_demo", NULL, 0, NULL,
                                                   &group);
    }
    if (rc != 0) {
        elapsed_us = now_us() - start_us;
        stats_record(stats, 0, 0, 0, elapsed_us);
        fprintf(stderr, "encode failed rc=%d\n", rc);
        ve_tls_bytes_free(&log);
        ve_tls_bytes_free(&group);
        return 1;
    }

    cfg.endpoint = env_str("VE_TLS_ENDPOINT", NULL);
    cfg.region = env_str("VE_TLS_REGION", NULL);
    cfg.topic_id = env_str("VE_TLS_TOPIC_ID", NULL);
    cfg.api_version = "0.3.0";
    cfg.access_key_id = env_str("VE_TLS_ACCESS_KEY_ID", NULL);
    cfg.access_key_secret = env_str("VE_TLS_ACCESS_KEY_SECRET", NULL);
    cfg.security_token = env_str("VE_TLS_SECURITY_TOKEN", NULL);
    cfg.compress_type = env_str("VE_TLS_COMPRESS_TYPE", "none");
    cfg.hash_key = env_str("VE_TLS_HASH_KEY", "");
    cfg.body_no_copy = 1;

    if (!cfg.endpoint || !cfg.region || !cfg.topic_id || !cfg.access_key_id || !cfg.access_key_secret) {
        elapsed_us = now_us() - start_us;
        stats_record(stats, 0, 0, 0, elapsed_us);
        usage("ve_tls_bricks_demo_real");
        ve_tls_bytes_free(&log);
        ve_tls_bytes_free(&group);
        return 1;
    }

    rc = ve_tls_bricks_pack_request(&cfg, group.data, group.size, 1, now_ms, now_ms, &req);
    if (rc != 0) {
        elapsed_us = now_us() - start_us;
        stats_record(stats, 0, 0, 0, elapsed_us);
        fprintf(stderr, "pack failed rc=%d\n", rc);
        ve_tls_bytes_free(&log);
        ve_tls_bytes_free(&group);
        return 1;
    }

    struct curl_slist * headers = headers_to_curl_list(req.headers);
    mem_buf body;
    mem_buf resp_headers;
    memset(&body, 0, sizeof(body));
    memset(&resp_headers, 0, sizeof(resp_headers));

    curl_easy_reset(curl);
    curl_easy_setopt(curl, CURLOPT_URL, req.url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, (const char *)req.body);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)req.body_size);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, (long)timeout_ms);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, (long)timeout_ms);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_TCP_NODELAY, 1L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "ve-tls-bricks-real/0.1");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &body);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &resp_headers);
    if (env_i32("VE_TLS_HTTP_DEBUG", 0)) {
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    }

    CURLcode cr = curl_easy_perform(curl);
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    elapsed_us = now_us() - start_us;
    int ok = (cr == CURLE_OK && http_code / 100 == 2);
    stats_record(stats, ok, req.body_size, body.size, elapsed_us);
    if (!quiet) {
        printf("attempt=%d curl=%d http=%ld request_bytes=%zu response_bytes=%zu latency_ms=%.3f\n",
               index, (int)cr, http_code, req.body_size, body.size, (double)elapsed_us / 1000.0);
    }
    if (cr != CURLE_OK) {
        fprintf(stderr, "curl_error=%s\n", curl_easy_strerror(cr));
    }
    if (http_code / 100 != 2 && body.data) {
        fprintf(stderr, "response_body=%s\n", body.data);
    }

    free(body.data);
    free(resp_headers.data);
    curl_slist_free_all(headers);
    ve_tls_bricks_request_free(&req);
    ve_tls_bytes_free(&log);
    ve_tls_bytes_free(&group);
    return ok ? 0 : 1;
}

int main(int argc, char ** argv) {
    int count = 1;
    int timeout_ms = 15000;
    int quiet = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--count") == 0 && i + 1 < argc) {
            count = atoi(argv[++i]);
            continue;
        }
        if (strcmp(argv[i], "--timeout-ms") == 0 && i + 1 < argc) {
            timeout_ms = atoi(argv[++i]);
            continue;
        }
        if (strcmp(argv[i], "--quiet") == 0) {
            quiet = 1;
            continue;
        }
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        }
        usage(argv[0]);
        return 1;
    }
    if (count <= 0) count = 1;
    if (timeout_ms <= 0) timeout_ms = 15000;

    CURLcode global = curl_global_init(CURL_GLOBAL_NOTHING);
    if (global != CURLE_OK) {
        fprintf(stderr, "curl_global_init failed: %d\n", (int)global);
        return 1;
    }
    CURL * curl = curl_easy_init();
    if (!curl) {
        curl_global_cleanup();
        return 1;
    }

    int failed = 0;
    bench_stats stats;
    memset(&stats, 0, sizeof(stats));
    int64_t bench_start_us = now_us();
    for (int i = 0; i < count; i++) {
        failed += send_one(curl, i + 1, timeout_ms, quiet, &stats);
    }
    int64_t bench_elapsed_us = now_us() - bench_start_us;
    double elapsed_s = (double)bench_elapsed_us / 1000000.0;
    double avg_ms = stats.attempts > 0 ? (double)stats.total_us / (double)stats.attempts / 1000.0 : 0.0;
    double rps = elapsed_s > 0.0 ? (double)stats.success / elapsed_s : 0.0;
    printf("benchmark attempts=%d success=%d failed=%d elapsed_ms=%.3f req_per_sec=%.2f avg_ms=%.3f min_ms=%.3f max_ms=%.3f request_bytes=%zu response_bytes=%zu\n",
           stats.attempts,
           stats.success,
           stats.failed,
           (double)bench_elapsed_us / 1000.0,
           rps,
           avg_ms,
           (double)stats.min_us / 1000.0,
           (double)stats.max_us / 1000.0,
           stats.request_bytes,
           stats.response_bytes);
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    return failed == 0 ? 0 : 1;
}
