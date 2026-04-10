#include "ve_tls_producer.h"
#include "producer/ve_tls_persistent.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>
#include <unistd.h>

typedef struct {
    uint64_t count;
} recover_ctx;

static int64_t now_ms(ve_tls_platform * platform) {
    return platform && platform->time_ms ? platform->time_ms() : 0;
}

static int on_recover_record(int64_t log_id, const char * hash_key, const unsigned char * payload, size_t payload_size, void * user) {
    recover_ctx * ctx = (recover_ctx *)user;
    (void)log_id;
    (void)hash_key;
    (void)payload;
    (void)payload_size;
    if (ctx) {
        ctx->count++;
    }
    return 0;
}

static void usage(const char * argv0) {
    fprintf(stderr, "usage: %s [--records N] [--payload-bytes N] [--dir PATH] [--hash-key HK]\n", argv0 ? argv0 : "ve_tls_persistent_bench");
}

static int parse_i32(const char * s, int32_t * out) {
    char * end = NULL;
    long v;
    if (!s || !out) return -1;
    v = strtol(s, &end, 10);
    if (end == s || *end != 0) return -1;
    if (v < 1 || v > INT32_MAX) return -1;
    *out = (int32_t)v;
    return 0;
}

int main(int argc, char ** argv) {
    char dir_buf[PATH_MAX];
    char * payload = NULL;
    ve_tls_config cfg;
    ve_tls_persistent persistent;
    ve_tls_persistent_options opt;
    ve_tls_path_info info;
    ve_tls_file * file = NULL;
    recover_ctx recover;
    const char * dir_arg = NULL;
    const char * hash_key = NULL;
    int32_t records = 100000;
    int32_t payload_bytes = 256;
    int i;
    uint64_t dir_bytes = 0;
    int64_t append_start;
    int64_t append_end;
    int64_t recover_start;
    int64_t recover_end;
    int64_t ack_start;
    int64_t ack_end;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        }
        if (i + 1 >= argc) {
            usage(argv[0]);
            return 2;
        }
        if (strcmp(argv[i], "--records") == 0) {
            if (parse_i32(argv[++i], &records) != 0) return 2;
        } else if (strcmp(argv[i], "--payload-bytes") == 0) {
            if (parse_i32(argv[++i], &payload_bytes) != 0) return 2;
        } else if (strcmp(argv[i], "--dir") == 0) {
            dir_arg = argv[++i];
        } else if (strcmp(argv[i], "--hash-key") == 0) {
            hash_key = argv[++i];
        } else {
            usage(argv[0]);
            return 2;
        }
    }

    ve_tls_config_init(&cfg);
    memset(&persistent, 0, sizeof(persistent));
    memset(&opt, 0, sizeof(opt));
    memset(&recover, 0, sizeof(recover));

    if (dir_arg && dir_arg[0] != 0) {
        snprintf(dir_buf, sizeof(dir_buf), "%s", dir_arg);
    } else {
        snprintf(dir_buf, sizeof(dir_buf), "/tmp/ve_tls_persistent_bench_%d", (int)getpid());
    }
    if (cfg.platform.path_remove) {
        cfg.platform.path_remove(dir_buf);
    }
    if (cfg.platform.path_mkdirs(dir_buf, 0755) != 0) {
        fprintf(stderr, "mkdirs failed: %s\n", dir_buf);
        return 3;
    }

    payload = (char *)malloc((size_t)payload_bytes + 1);
    if (!payload) {
        return 4;
    }
    memset(payload, 'x', (size_t)payload_bytes);
    payload[payload_bytes] = 0;

    opt.platform = &cfg.platform;
    opt.dir_path = dir_buf;
    opt.instance_id = "persistent-bench";
    opt.owner_id = "bench-owner";
    opt.owner_process_name = "bench";
    opt.owner_pid = (int32_t)getpid();
    opt.segment_max_bytes = 8 * 1024 * 1024;
    opt.segment_max_records = 0;
    opt.max_bytes = 512ULL * 1024ULL * 1024ULL;
    opt.max_records = (uint64_t)records + 16ULL;
    opt.max_segments = 1024;
    opt.high_watermark_pct = 85;
    opt.low_watermark_pct = 70;
    opt.overflow_policy = VE_TLS_POVERFLOW_REJECT_NEW;
    opt.sample_every_n = 10;
    opt.block_timeout_ms = 1000;
    opt.now_ms = now_ms(&cfg.platform);
    opt.lease_timeout_ms = 60000;
    opt.heartbeat_interval_ms = 10000;
    opt.open_mode = VE_TLS_POPEN_TAKEOVER_IF_STALE;

    if (ve_tls_persistent_open(&persistent, &opt) != 0) {
        fprintf(stderr, "persistent_open failed\n");
        free(payload);
        return 5;
    }

    append_start = now_ms(&cfg.platform);
    for (i = 0; i < records; i++) {
        if (ve_tls_persistent_append(&persistent, (int64_t)(i + 1), hash_key, (const unsigned char *)payload, (size_t)payload_bytes) != 0) {
            fprintf(stderr, "persistent_append failed at %d\n", i);
            ve_tls_persistent_close(&persistent);
            free(payload);
            return 6;
        }
    }
    append_end = now_ms(&cfg.platform);

    recover_start = now_ms(&cfg.platform);
    if (ve_tls_persistent_recover(&persistent, on_recover_record, &recover) != 0) {
        fprintf(stderr, "persistent_recover failed\n");
        ve_tls_persistent_close(&persistent);
        free(payload);
        return 7;
    }
    recover_end = now_ms(&cfg.platform);

    ack_start = now_ms(&cfg.platform);
    if (ve_tls_persistent_ack_range(&persistent, 1, records) != 0) {
        fprintf(stderr, "persistent_ack_range failed\n");
        ve_tls_persistent_close(&persistent);
        free(payload);
        return 8;
    }
    ack_end = now_ms(&cfg.platform);

    if (cfg.platform.path_stat(dir_buf, &info) == 0 && info.exists && info.is_dir) {
        char path[PATH_MAX];
        uint32_t seg;
        for (seg = 1; seg <= persistent.store.active_segment_id + 1; seg++) {
            if (ve_tls_segment_store_get_segment_path(&persistent.store, seg, path, sizeof(path)) == 0 &&
                cfg.platform.path_stat(path, &info) == 0 && info.exists) {
                dir_bytes += info.size;
            }
        }
    }
    printf("persistent_bench records=%d payload_bytes=%d hash_key=%s\n",
        records, payload_bytes, hash_key ? hash_key : "(null)");
    printf("append ms=%lld logs_per_s=%.2f\n",
        (long long)(append_end - append_start),
        (append_end > append_start) ? ((double)records * 1000.0 / (double)(append_end - append_start)) : 0.0);
    printf("recover ms=%lld records=%llu logs_per_s=%.2f\n",
        (long long)(recover_end - recover_start),
        (unsigned long long)recover.count,
        (recover_end > recover_start) ? ((double)recover.count * 1000.0 / (double)(recover_end - recover_start)) : 0.0);
    printf("ack ms=%lld acked=%d residual_bytes=%llu current_records=%llu current_segments=%u\n",
        (long long)(ack_end - ack_start),
        records,
        (unsigned long long)dir_bytes,
        (unsigned long long)persistent.current_records,
        persistent.current_segments);

    ve_tls_persistent_close(&persistent);
    free(payload);
    file = NULL;
    (void)file;
    return 0;
}
