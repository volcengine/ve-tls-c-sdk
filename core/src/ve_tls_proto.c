#include "ve_tls_proto.h"
#include "ve_tls_alloc.h"

#include <stdlib.h>
#include <string.h>

typedef struct {
    unsigned char * data;
    size_t len;
    size_t cap;
} ve_tls_buf;

static int ve_tls_buf_reserve(ve_tls_buf * b, size_t n) {
    if (n > (size_t)-1 - b->len) {
        return -1;
    }
    size_t target = b->len + n;
    if (target <= b->cap) {
        return 0;
    }
    size_t next = b->cap ? b->cap : 128;
    while (next < target) {
        if (next > (size_t)-1 / 2) {
            next = target;
            break;
        }
        next *= 2;
    }
    unsigned char * p = (unsigned char *)ve_tls_realloc(b->data, next);
    if (!p) {
        return -1;
    }
    b->data = p;
    b->cap = next;
    return 0;
}

#if defined(VE_TLS_ENABLE_ALLOC_FAULT_INJECT)
int ve_tls_proto_test_reserve(size_t len, size_t cap, size_t append_size) {
    ve_tls_buf b;
    int rc;
    unsigned char sentinel = 0;
    memset(&b, 0, sizeof(b));
    b.len = len;
    b.cap = cap;
    /* Do not materialize a synthetic capacity when the request is already
     * known to overflow; use a non-null sentinel so even this synthetic
     * buffer has a valid data/capacity pairing. */
    if (append_size > (size_t)-1 - len) {
        b.data = &sentinel;
        return ve_tls_buf_reserve(&b, append_size);
    }
    if (len > cap) {
        return -1;
    }
    if (cap > 0) {
        b.data = (unsigned char *)ve_tls_malloc(cap);
        if (!b.data) {
            return -1;
        }
    }
    rc = ve_tls_buf_reserve(&b, append_size);
    ve_tls_free(b.data);
    return rc;
}
#endif

static int ve_tls_buf_put(ve_tls_buf * b, const void * p, size_t n) {
    if (ve_tls_buf_reserve(b, n) != 0) {
        return -1;
    }
    memcpy(b->data + b->len, p, n);
    b->len += n;
    return 0;
}

static int ve_tls_buf_put_u8(ve_tls_buf * b, unsigned char v) {
    return ve_tls_buf_put(b, &v, 1);
}

static int ve_tls_put_varint_u64(ve_tls_buf * b, uint64_t v) {
    while (v >= 0x80) {
        unsigned char c = (unsigned char)((v & 0x7F) | 0x80);
        if (ve_tls_buf_put_u8(b, c) != 0) {
            return -1;
        }
        v >>= 7;
    }
    return ve_tls_buf_put_u8(b, (unsigned char)v);
}

static int ve_tls_put_key(ve_tls_buf * b, uint32_t field_number, uint32_t wire_type) {
    uint64_t key = ((uint64_t)field_number << 3) | (uint64_t)wire_type;
    return ve_tls_put_varint_u64(b, key);
}

static int ve_tls_put_len_delimited(ve_tls_buf * b, const void * data, size_t n) {
    if (ve_tls_put_varint_u64(b, (uint64_t)n) != 0) {
        return -1;
    }
    return ve_tls_buf_put(b, data, n);
}

static int ve_tls_put_string(ve_tls_buf * b, uint32_t field_number, const char * s) {
    if (!s) {
        s = "";
    }
    if (ve_tls_put_key(b, field_number, 2) != 0) {
        return -1;
    }
    return ve_tls_put_len_delimited(b, s, strlen(s));
}

static int ve_tls_put_int64(ve_tls_buf * b, uint32_t field_number, int64_t v) {
    if (ve_tls_put_key(b, field_number, 0) != 0) {
        return -1;
    }
    return ve_tls_put_varint_u64(b, (uint64_t)v);
}

static int ve_tls_put_fixed32(ve_tls_buf * b, uint32_t field_number, uint32_t v) {
    if (ve_tls_put_key(b, field_number, 5) != 0) {
        return -1;
    }
    unsigned char le[4];
    le[0] = (unsigned char)(v & 0xFF);
    le[1] = (unsigned char)((v >> 8) & 0xFF);
    le[2] = (unsigned char)((v >> 16) & 0xFF);
    le[3] = (unsigned char)((v >> 24) & 0xFF);
    return ve_tls_buf_put(b, le, sizeof(le));
}

static int ve_tls_encode_log_content(const ve_tls_kv * kv, ve_tls_buf * out) {
    ve_tls_buf tmp = {0};
    if (ve_tls_put_string(&tmp, 1, kv->key) != 0) {
        ve_tls_free(tmp.data);
        return -1;
    }
    if (ve_tls_put_string(&tmp, 2, kv->value) != 0) {
        ve_tls_free(tmp.data);
        return -1;
    }
    if (ve_tls_put_key(out, 2, 2) != 0) {
        ve_tls_free(tmp.data);
        return -1;
    }
    if (ve_tls_put_len_delimited(out, tmp.data, tmp.len) != 0) {
        ve_tls_free(tmp.data);
        return -1;
    }
    ve_tls_free(tmp.data);
    return 0;
}

static int ve_tls_encode_log_tag(const ve_tls_kv * kv, ve_tls_buf * out) {
    ve_tls_buf tmp = {0};
    if (ve_tls_put_string(&tmp, 1, kv->key) != 0) {
        ve_tls_free(tmp.data);
        return -1;
    }
    if (ve_tls_put_string(&tmp, 2, kv->value) != 0) {
        ve_tls_free(tmp.data);
        return -1;
    }
    if (ve_tls_put_key(out, 3, 2) != 0) {
        ve_tls_free(tmp.data);
        return -1;
    }
    if (ve_tls_put_len_delimited(out, tmp.data, tmp.len) != 0) {
        ve_tls_free(tmp.data);
        return -1;
    }
    ve_tls_free(tmp.data);
    return 0;
}

int ve_tls_proto_encode_log(int64_t time_ms, const ve_tls_kv * kvs, size_t kv_count, ve_tls_bytes * out) {
    return ve_tls_proto_encode_log_ex(time_ms, 0, 0, kvs, kv_count, out);
}

int ve_tls_proto_encode_log_ex(int64_t time_ms, uint32_t time_ns, int32_t has_time_ns, const ve_tls_kv * kvs, size_t kv_count, ve_tls_bytes * out) {
    if (!out) {
        return -1;
    }
    if (has_time_ns && time_ns >= 1000000U) {
        return -1;
    }
    memset(out, 0, sizeof(ve_tls_bytes));
    ve_tls_buf b = {0};
    if (time_ms <= 0) {
        time_ms = 0;
        has_time_ns = 0;
        time_ns = 0;
    }
    if (ve_tls_put_int64(&b, 1, time_ms) != 0) {
        ve_tls_free(b.data);
        return -1;
    }
    for (size_t i = 0; i < kv_count; i++) {
        if (ve_tls_encode_log_content(&kvs[i], &b) != 0) {
            ve_tls_free(b.data);
            return -1;
        }
    }
    if (has_time_ns) {
        if (ve_tls_put_fixed32(&b, 3, time_ns) != 0) {
            ve_tls_free(b.data);
            return -1;
        }
    }
    out->data = b.data;
    out->size = b.len;
    return 0;
}

static int ve_tls_encode_log_group(const ve_tls_bytes * logs, size_t log_count, const char * source, const char * file_name, const ve_tls_kv * log_tags, size_t log_tag_count, const char * context_flow, ve_tls_buf * out) {
    ve_tls_buf tmp = {0};
    for (size_t i = 0; i < log_count; i++) {
        if (ve_tls_put_key(&tmp, 1, 2) != 0) {
            ve_tls_free(tmp.data);
            return -1;
        }
        if (ve_tls_put_len_delimited(&tmp, logs[i].data, logs[i].size) != 0) {
            ve_tls_free(tmp.data);
            return -1;
        }
    }
    if (source && source[0] != 0) {
        if (ve_tls_put_string(&tmp, 2, source) != 0) {
            ve_tls_free(tmp.data);
            return -1;
        }
    }
    if (file_name && file_name[0] != 0) {
        if (ve_tls_put_string(&tmp, 4, file_name) != 0) {
            ve_tls_free(tmp.data);
            return -1;
        }
    }
    if (log_tags && log_tag_count > 0) {
        for (size_t i = 0; i < log_tag_count; i++) {
            if (ve_tls_encode_log_tag(&log_tags[i], &tmp) != 0) {
                ve_tls_free(tmp.data);
                return -1;
            }
        }
    }
    if (context_flow && context_flow[0] != 0) {
        if (ve_tls_put_string(&tmp, 5, context_flow) != 0) {
            ve_tls_free(tmp.data);
            return -1;
        }
    }
    if (ve_tls_put_key(out, 1, 2) != 0) {
        ve_tls_free(tmp.data);
        return -1;
    }
    if (ve_tls_put_len_delimited(out, tmp.data, tmp.len) != 0) {
        ve_tls_free(tmp.data);
        return -1;
    }
    ve_tls_free(tmp.data);
    return 0;
}

int ve_tls_proto_encode_log_group_list(const ve_tls_bytes * logs, size_t log_count, const char * source, const char * file_name, ve_tls_bytes * out) {
    return ve_tls_proto_encode_log_group_list_ex(logs, log_count, source, file_name, NULL, 0, NULL, out);
}

int ve_tls_proto_encode_log_group_list_ex(const ve_tls_bytes * logs, size_t log_count, const char * source, const char * file_name, const ve_tls_kv * log_tags, size_t log_tag_count, const char * context_flow, ve_tls_bytes * out) {
    return ve_tls_proto_encode_log_group_list_ex2(logs, log_count, source, file_name, log_tags, log_tag_count, context_flow, 10000, out);
}

int ve_tls_proto_encode_log_group_list_ex2(const ve_tls_bytes * logs, size_t log_count, const char * source, const char * file_name, const ve_tls_kv * log_tags, size_t log_tag_count, const char * context_flow, size_t max_log_group_logs, ve_tls_bytes * out) {
    if (!out) {
        return -1;
    }
    memset(out, 0, sizeof(ve_tls_bytes));
    if (!logs || log_count == 0) {
        return 0;
    }
    ve_tls_buf b = {0};
    size_t per_group = max_log_group_logs;
    if (per_group == 0 || per_group > 10000) {
        per_group = 10000;
    }
    for (size_t off = 0; off < log_count; off += per_group) {
        size_t n = log_count - off;
        if (n > per_group) {
            n = per_group;
        }
        if (ve_tls_encode_log_group(logs + off, n, source, file_name, log_tags, log_tag_count, context_flow, &b) != 0) {
            ve_tls_free(b.data);
            return -1;
        }
    }
    out->data = b.data;
    out->size = b.len;
    return 0;
}

void ve_tls_bytes_free(ve_tls_bytes * b) {
    if (!b) {
        return;
    }
    ve_tls_free(b->data);
    b->data = NULL;
    b->size = 0;
}
