#include "ve_tls_proto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static void usage(const char * argv0) {
    fprintf(stderr, "usage: %s --out path [--message-bytes N] [--kvs k1=v1,k2=v2] [--time-ms N]\n", argv0 ? argv0 : "ve_tls_gen_raw_log");
}

static int write_file(const char * path, const unsigned char * data, size_t n) {
    if (!path || !data || n == 0) return -1;
    FILE * f = fopen(path, "wb");
    if (!f) return -1;
    size_t w = fwrite(data, 1, n, f);
    fclose(f);
    return (w == n) ? 0 : -1;
}

static char * build_message(size_t n) {
    if (n == 0) n = 1;
    char * s = (char *)malloc(n + 1);
    if (!s) return NULL;
    memset(s, 'x', n);
    s[n] = 0;
    return s;
}

static int parse_kvs(char * buf, ve_tls_kv * kvs, size_t cap, size_t * out_n) {
    if (!buf || !kvs || cap == 0 || !out_n) return -1;
    size_t n = 0;
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
        if (!token || token[0] == 0) continue;
        char * eq = strchr(token, '=');
        if (!eq) continue;
        *eq = 0;
        char * k = token;
        char * v = eq + 1;
        if (!k || k[0] == 0) continue;
        if (n >= cap) return -1;
        kvs[n].key = k;
        kvs[n].value = v;
        n++;
    }
    *out_n = n;
    return 0;
}

int main(int argc, char ** argv) {
    const char * out_path = NULL;
    int64_t time_ms = 0;
    size_t message_bytes = 0;
    const char * kvs_str = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--out") == 0 && i + 1 < argc) {
            out_path = argv[++i];
            continue;
        }
        if (strcmp(argv[i], "--message-bytes") == 0 && i + 1 < argc) {
            long v = atol(argv[++i]);
            if (v < 0) v = 0;
            message_bytes = (size_t)v;
            continue;
        }
        if (strcmp(argv[i], "--kvs") == 0 && i + 1 < argc) {
            kvs_str = argv[++i];
            continue;
        }
        if (strcmp(argv[i], "--time-ms") == 0 && i + 1 < argc) {
            time_ms = (int64_t)atoll(argv[++i]);
            continue;
        }
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        }
        usage(argv[0]);
        return 2;
    }

    if (!out_path || out_path[0] == 0) {
        usage(argv[0]);
        return 2;
    }

    ve_tls_kv kvs[64];
    size_t kv_count = 0;
    char * kvs_buf = NULL;
    char * msg = NULL;

    if (kvs_str && kvs_str[0] != 0) {
        kvs_buf = strdup(kvs_str);
        if (!kvs_buf) return 1;
        if (parse_kvs(kvs_buf, kvs, sizeof(kvs) / sizeof(kvs[0]), &kv_count) != 0) {
            free(kvs_buf);
            return 1;
        }
    }

    if (message_bytes > 0) {
        msg = build_message(message_bytes);
        if (!msg) {
            free(kvs_buf);
            return 1;
        }
        if (kv_count + 1 > (sizeof(kvs) / sizeof(kvs[0]))) {
            free(msg);
            free(kvs_buf);
            return 1;
        }
        kvs[kv_count].key = "message";
        kvs[kv_count].value = msg;
        kv_count++;
    }

    if (kv_count == 0) {
        kvs[0].key = "message";
        kvs[0].value = "hello";
        kv_count = 1;
    }

    ve_tls_bytes out;
    memset(&out, 0, sizeof(out));
    int rc = ve_tls_proto_encode_log(time_ms, kvs, kv_count, &out);
    if (rc != 0 || !out.data || out.size == 0) {
        ve_tls_bytes_free(&out);
        free(msg);
        free(kvs_buf);
        return 1;
    }

    if (write_file(out_path, out.data, out.size) != 0) {
        ve_tls_bytes_free(&out);
        free(msg);
        free(kvs_buf);
        return 1;
    }

    fprintf(stderr, "raw_log bytes=%zu out=%s\n", out.size, out_path);
    ve_tls_bytes_free(&out);
    free(msg);
    free(kvs_buf);
    return 0;
}

