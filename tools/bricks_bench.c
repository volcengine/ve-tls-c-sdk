#include "ve_tls_bricks.h"
#include "ve_tls_alloc.h"
#include "ve_tls_proto.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

typedef struct {
    size_t current_bytes;
    size_t peak_bytes;
    size_t total_bytes;
    size_t alloc_calls;
    size_t active_allocs;
} bench_alloc_stats;

static void bench_alloc_add(bench_alloc_stats * stats, size_t n) {
    stats->current_bytes += n;
    stats->total_bytes += n;
    stats->alloc_calls++;
    stats->active_allocs++;
    if (stats->current_bytes > stats->peak_bytes) {
        stats->peak_bytes = stats->current_bytes;
    }
}

static void bench_alloc_remove(bench_alloc_stats * stats, size_t n) {
    if (stats->current_bytes >= n) {
        stats->current_bytes -= n;
    } else {
        stats->current_bytes = 0;
    }
    if (stats->active_allocs > 0) {
        stats->active_allocs--;
    }
}

static void * bench_malloc(size_t n, void * user_data) {
    bench_alloc_stats * stats = (bench_alloc_stats *)user_data;
    size_t actual = n ? n : 1;
    size_t * p = (size_t *)malloc(sizeof(size_t) + actual);
    if (!p) return NULL;
    *p = n;
    bench_alloc_add(stats, n);
    return p + 1;
}

static void * bench_calloc(size_t n, size_t size, void * user_data) {
    if (size != 0 && n > (size_t)-1 / size) return NULL;
    size_t bytes = n * size;
    void * p = bench_malloc(bytes, user_data);
    if (p) memset(p, 0, bytes);
    return p;
}

static void * bench_realloc(void * ptr, size_t n, void * user_data) {
    bench_alloc_stats * stats = (bench_alloc_stats *)user_data;
    if (!ptr) return bench_malloc(n, user_data);
    if (n == 0) {
        size_t * old = ((size_t *)ptr) - 1;
        bench_alloc_remove(stats, *old);
        free(old);
        return NULL;
    }
    size_t * old = ((size_t *)ptr) - 1;
    size_t old_n = *old;
    size_t actual = n ? n : 1;
    size_t * next = (size_t *)realloc(old, sizeof(size_t) + actual);
    if (!next) return NULL;
    *next = n;
    if (stats->current_bytes >= old_n) {
        stats->current_bytes = stats->current_bytes - old_n + n;
    } else {
        stats->current_bytes = n;
    }
    stats->total_bytes += n;
    stats->alloc_calls++;
    if (stats->current_bytes > stats->peak_bytes) {
        stats->peak_bytes = stats->current_bytes;
    }
    return next + 1;
}

static void bench_free(void * ptr, void * user_data) {
    bench_alloc_stats * stats = (bench_alloc_stats *)user_data;
    if (!ptr) return;
    size_t * p = ((size_t *)ptr) - 1;
    bench_alloc_remove(stats, *p);
    free(p);
}

static char * bench_strdup(const char * s, void * user_data) {
    if (!s) return NULL;
    size_t n = strlen(s);
    char * p = (char *)bench_malloc(n + 1, user_data);
    if (!p) return NULL;
    memcpy(p, s, n + 1);
    return p;
}

static int64_t now_us(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (int64_t)tv.tv_sec * 1000000LL + (int64_t)tv.tv_usec;
}

static int parse_int_arg(const char * s, int * out) {
    char * end = NULL;
    long v;
    if (!s || !out) return -1;
    v = strtol(s, &end, 10);
    if (!end || *end != '\0' || v <= 0 || v > 100000000L) return -1;
    *out = (int)v;
    return 0;
}

static int parse_bool_arg(const char * s, int * out) {
    char * end = NULL;
    long v;
    if (!s || !out) return -1;
    v = strtol(s, &end, 10);
    if (!end || *end != '\0' || (v != 0 && v != 1)) return -1;
    *out = (int)v;
    return 0;
}

static int read_arg_value(int argc, char ** argv, int * i, const char * name, const char ** value) {
    size_t n = strlen(name);
    const char * arg = argv[*i];
    if (strcmp(arg, name) == 0) {
        if (*i + 1 >= argc) return -1;
        *value = argv[++(*i)];
        return 1;
    }
    if (strncmp(arg, name, n) == 0 && arg[n] == '=') {
        *value = arg + n + 1;
        return 1;
    }
    return 0;
}

static void usage(const char * argv0) {
    fprintf(stderr,
            "usage: %s [--iterations N] [--logs N] [--message-bytes N] [--compress-type none|lz4|zlib] [--copy-body 0|1] [--track-alloc 0|1]\n",
            argv0);
}

int main(int argc, char ** argv) {
    int iterations = 10000;
    int logs = 10;
    int message_bytes = 128;
    int copy_body = 0;
    int track_alloc = 1;
    const char * compress_type = "none";
    char * message = NULL;
    ve_tls_kv kv;
    ve_tls_bricks_config cfg;
    bench_alloc_stats alloc_stats;
    ve_tls_alloc_hooks alloc_hooks;
    size_t total_raw = 0;
    size_t total_out = 0;
    int64_t start_us;
    int64_t end_us;
    int i;

    for (i = 1; i < argc; i++) {
        const char * value = NULL;
        int matched = read_arg_value(argc, argv, &i, "--iterations", &value);
        if (matched < 0) {
            usage(argv[0]);
            return 2;
        }
        if (matched) {
            if (parse_int_arg(value, &iterations) != 0) return 2;
            continue;
        }
        matched = read_arg_value(argc, argv, &i, "--logs", &value);
        if (matched < 0) {
            usage(argv[0]);
            return 2;
        }
        if (matched) {
            if (parse_int_arg(value, &logs) != 0) return 2;
            continue;
        }
        matched = read_arg_value(argc, argv, &i, "--message-bytes", &value);
        if (matched < 0) {
            usage(argv[0]);
            return 2;
        }
        if (matched) {
            if (parse_int_arg(value, &message_bytes) != 0) return 2;
            continue;
        }
        matched = read_arg_value(argc, argv, &i, "--compress-type", &value);
        if (matched < 0) {
            usage(argv[0]);
            return 2;
        }
        if (matched) {
            compress_type = value;
            continue;
        }
        matched = read_arg_value(argc, argv, &i, "--copy-body", &value);
        if (matched < 0) {
            usage(argv[0]);
            return 2;
        }
        if (matched) {
            if (parse_bool_arg(value, &copy_body) != 0) return 2;
            continue;
        }
        matched = read_arg_value(argc, argv, &i, "--track-alloc", &value);
        if (matched < 0) {
            usage(argv[0]);
            return 2;
        }
        if (matched) {
            if (parse_bool_arg(value, &track_alloc) != 0) return 2;
            continue;
        }
        usage(argv[0]);
        return 2;
    }

    message = (char *)malloc((size_t)message_bytes + 1);
    if (!message) return 1;
    memset(message, 'x', (size_t)message_bytes);
    message[message_bytes] = '\0';
    kv.key = "message";
    kv.value = message;

    memset(&alloc_stats, 0, sizeof(alloc_stats));
    memset(&alloc_hooks, 0, sizeof(alloc_hooks));
    alloc_hooks.malloc_fn = bench_malloc;
    alloc_hooks.calloc_fn = bench_calloc;
    alloc_hooks.realloc_fn = bench_realloc;
    alloc_hooks.free_fn = bench_free;
    alloc_hooks.strdup_fn = bench_strdup;
    alloc_hooks.user_data = &alloc_stats;
    if (track_alloc) {
        ve_tls_alloc_set_hooks(&alloc_hooks);
    }

    memset(&cfg, 0, sizeof(cfg));
    cfg.endpoint = "https://tls-cn-test.example.com";
    cfg.region = "cn-test";
    cfg.topic_id = "test-topic-id";
    cfg.api_version = "0.3.0";
    cfg.access_key_id = "test-access-key-id";
    cfg.access_key_secret = "test-secret-access-key";
    cfg.security_token = "";
    cfg.compress_type = compress_type;
    cfg.hash_key = "";
    cfg.xdate = "20260410T032329Z";
    cfg.body_no_copy = copy_body ? 0 : 1;

    start_us = now_us();
    for (i = 0; i < iterations; i++) {
        ve_tls_bytes * encoded_logs = (ve_tls_bytes *)calloc((size_t)logs, sizeof(*encoded_logs));
        ve_tls_bytes group;
        ve_tls_bricks_request req;
        int j;
        int rc = 0;

        memset(&group, 0, sizeof(group));
        memset(&req, 0, sizeof(req));
        if (!encoded_logs) {
            free(message);
            return 1;
        }
        for (j = 0; j < logs; j++) {
            rc = ve_tls_proto_encode_log(1710000000000LL + j, &kv, 1, &encoded_logs[j]);
            if (rc != 0) break;
        }
        if (rc == 0) {
            rc = ve_tls_proto_encode_log_group_list_ex(encoded_logs, (size_t)logs, "src", "file", NULL, 0, NULL,
                                                       &group);
        }
        if (rc == 0) {
            rc = ve_tls_bricks_pack_request(&cfg, group.data, group.size, logs, 1710000000000LL,
                                            1710000000000LL + logs - 1, &req);
        }
        if (rc != 0) {
            for (j = 0; j < logs; j++) ve_tls_bytes_free(&encoded_logs[j]);
            ve_tls_bytes_free(&group);
            ve_tls_bricks_request_free(&req);
            free(encoded_logs);
            free(message);
            fprintf(stderr, "benchmark encode/pack failed: %d\n", rc);
            return 1;
        }
        total_raw += group.size;
        total_out += req.body_size;
        for (j = 0; j < logs; j++) ve_tls_bytes_free(&encoded_logs[j]);
        ve_tls_bytes_free(&group);
        ve_tls_bricks_request_free(&req);
        free(encoded_logs);
    }
    end_us = now_us();

    {
        double elapsed_s = (double)(end_us - start_us) / 1000000.0;
        double req_per_s = elapsed_s > 0.0 ? (double)iterations / elapsed_s : 0.0;
        double avg_us = iterations > 0 ? (double)(end_us - start_us) / (double)iterations : 0.0;
        double raw_mib_s = elapsed_s > 0.0 ? ((double)total_raw / (1024.0 * 1024.0)) / elapsed_s : 0.0;
        double out_mib_s = elapsed_s > 0.0 ? ((double)total_out / (1024.0 * 1024.0)) / elapsed_s : 0.0;

        printf("iterations=%d logs=%d message_bytes=%d compress_type=%s copy_body=%d track_alloc=%d\n",
               iterations, logs, message_bytes, compress_type, copy_body, track_alloc);
        printf("elapsed_ms=%.3f avg_us=%.3f req_per_sec=%.2f\n", elapsed_s * 1000.0, avg_us, req_per_s);
        printf("raw_bytes=%zu out_bytes=%zu raw_mib_per_sec=%.2f out_mib_per_sec=%.2f\n", total_raw, total_out,
               raw_mib_s, out_mib_s);
        if (track_alloc) {
            printf("sdk_heap_peak_bytes=%zu sdk_heap_current_bytes=%zu sdk_heap_total_alloc_bytes=%zu sdk_heap_alloc_calls=%zu sdk_heap_active_allocs=%zu\n",
                   alloc_stats.peak_bytes, alloc_stats.current_bytes, alloc_stats.total_bytes,
                   alloc_stats.alloc_calls, alloc_stats.active_allocs);
        } else {
            printf("sdk_heap_tracking=off\n");
        }
    }

    if (track_alloc) {
        ve_tls_alloc_set_hooks(NULL);
    }
    free(message);
    return 0;
}
