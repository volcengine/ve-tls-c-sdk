#include "ve_tls_producer_internal.h"
#include "ve_tls_alloc.h"

#include <string.h>

typedef struct {
    unsigned char * data;
    size_t len;
    size_t cap;
} ve_tls_wire_buf;

static size_t ve_tls_varint_u64_size(uint64_t v) {
    size_t n = 1;
    while (v >= 0x80) {
        n++;
        v >>= 7;
    }
    return n;
}

static size_t ve_tls_varint_u32_size(uint32_t v) {
    if (v < (1u << 7)) return 1;
    if (v < (1u << 14)) return 2;
    if (v < (1u << 21)) return 3;
    if (v < (1u << 28)) return 4;
    return 5;
}

static unsigned char * ve_tls_varint_u32_pack(uint32_t v, unsigned char * out) {
    if (v >= 0x80) {
        *out++ = (unsigned char)(v | 0x80);
        v >>= 7;
        if (v >= 0x80) {
            *out++ = (unsigned char)(v | 0x80);
            v >>= 7;
            if (v >= 0x80) {
                *out++ = (unsigned char)(v | 0x80);
                v >>= 7;
                if (v >= 0x80) {
                    *out++ = (unsigned char)(v | 0x80);
                    v >>= 7;
                }
            }
        }
    }
    *out++ = (unsigned char)v;
    return out;
}

static unsigned char * ve_tls_varint_u64_pack(uint64_t v, unsigned char * out) {
    while (v >= 0x80) {
        *out++ = (unsigned char)((v & 0x7F) | 0x80);
        v >>= 7;
    }
    *out++ = (unsigned char)v;
    return out;
}

static int ve_tls_bytes_reserve(unsigned char ** p, size_t * cap, size_t need) {
    if (*cap >= need) {
        return 0;
    }
    size_t next = *cap ? *cap : 256;
    while (next < need) {
        if (next > (size_t)-1 / 2) {
            next = need;
            break;
        }
        next *= 2;
    }
    unsigned char * np = (unsigned char *)ve_tls_realloc(*p, next);
    if (!np) {
        return -1;
    }
    *p = np;
    *cap = next;
    return 0;
}

static size_t ve_tls_key_u32_size(uint32_t field_number, uint32_t wire_type) {
    uint64_t key = ((uint64_t)field_number << 3) | (uint64_t)wire_type;
    return ve_tls_varint_u64_size(key);
}

/* 防溢出加法：a + b 若回绕则返回 (size_t)-1（哨兵）。
 * 上层拿到 -1 必须直接拒绝该 log，避免基于回绕值做预算/编码。 */
static size_t ve_tls_size_add_safe(size_t a, size_t b) {
    if (a == (size_t)-1 || b == (size_t)-1) return (size_t)-1;
    if (a > (size_t)-1 - b) return (size_t)-1;
    return a + b;
}

static size_t ve_tls_bytes_field_size(uint32_t field_number, size_t n) {
    size_t k = ve_tls_key_u32_size(field_number, 2);
    size_t l = ve_tls_varint_u64_size((uint64_t)n);
    return ve_tls_size_add_safe(ve_tls_size_add_safe(k, l), n);
}

static int ve_tls_wire_reserve(ve_tls_wire_buf * b, size_t n) {
    if (b->len + n <= b->cap) {
        return 0;
    }
    if (b->len > (size_t)-1 - n) {
        return -1;
    }
    size_t target = b->len + n;
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

static int ve_tls_wire_put_u8(ve_tls_wire_buf * b, unsigned char v) {
    if (ve_tls_wire_reserve(b, 1) != 0) {
        return -1;
    }
    b->data[b->len++] = v;
    return 0;
}

static int ve_tls_wire_put_bytes(ve_tls_wire_buf * b, const void * p, size_t n) {
    if (n == 0) {
        return 0;
    }
    if (ve_tls_wire_reserve(b, n) != 0) {
        return -1;
    }
    memcpy(b->data + b->len, p, n);
    b->len += n;
    return 0;
}

static int ve_tls_wire_put_varint_u64(ve_tls_wire_buf * b, uint64_t v) {
    while (v >= 0x80) {
        unsigned char c = (unsigned char)((v & 0x7F) | 0x80);
        if (ve_tls_wire_put_u8(b, c) != 0) {
            return -1;
        }
        v >>= 7;
    }
    return ve_tls_wire_put_u8(b, (unsigned char)v);
}

static int ve_tls_wire_put_key(ve_tls_wire_buf * b, uint32_t field_number, uint32_t wire_type) {
    uint64_t key = ((uint64_t)field_number << 3) | (uint64_t)wire_type;
    return ve_tls_wire_put_varint_u64(b, key);
}

static int ve_tls_wire_put_len_delimited(ve_tls_wire_buf * b, const void * p, size_t n) {
    if (ve_tls_wire_put_varint_u64(b, (uint64_t)n) != 0) {
        return -1;
    }
    return ve_tls_wire_put_bytes(b, p, n);
}

static int ve_tls_wire_put_fixed32(ve_tls_wire_buf * b, uint32_t v) {
    unsigned char le[4];
    le[0] = (unsigned char)(v & 0xFF);
    le[1] = (unsigned char)((v >> 8) & 0xFF);
    le[2] = (unsigned char)((v >> 16) & 0xFF);
    le[3] = (unsigned char)((v >> 24) & 0xFF);
    return ve_tls_wire_put_bytes(b, le, sizeof(le));
}

static size_t ve_tls_log_content_msg_size(size_t klen, size_t vlen) {
    return ve_tls_size_add_safe(ve_tls_bytes_field_size(1, klen), ve_tls_bytes_field_size(2, vlen));
}

static size_t ve_tls_log_content_field_size(size_t klen, size_t vlen) {
    size_t msg = ve_tls_log_content_msg_size(klen, vlen);
    if (msg == (size_t)-1) return (size_t)-1;
    return ve_tls_size_add_safe(
        ve_tls_size_add_safe(ve_tls_key_u32_size(2, 2), ve_tls_varint_u64_size((uint64_t)msg)),
        msg);
}

static size_t ve_tls_log_msg_size_lens(int64_t time_ms, uint32_t time_ns, int32_t has_time_ns, const size_t * key_lens, const size_t * val_lens, size_t kv_count) {
    if (time_ms <= 0) {
        time_ms = 0;
        has_time_ns = 0;
        time_ns = 0;
    }
    uint64_t t = (uint64_t)time_ms;
    size_t n = ve_tls_size_add_safe(ve_tls_key_u32_size(1, 0), ve_tls_varint_u64_size(t));
    for (size_t i = 0; i < kv_count; i++) {
        size_t klen = key_lens ? key_lens[i] : 0;
        size_t vlen = val_lens ? val_lens[i] : 0;
        size_t f = ve_tls_log_content_field_size(klen, vlen);
        n = ve_tls_size_add_safe(n, f);
        if (n == (size_t)-1) return (size_t)-1;
    }
    if (has_time_ns) {
        n = ve_tls_size_add_safe(n, ve_tls_size_add_safe(ve_tls_key_u32_size(3, 5), 4));
    }
    return n;
}

size_t ve_tls_log_builder_estimate_kv_lens_size(int64_t time_ms, uint32_t time_ns, int32_t has_time_ns, const size_t * key_lens, const size_t * val_lens, size_t kv_count) {
    size_t msg_size = ve_tls_log_msg_size_lens(time_ms, time_ns, has_time_ns, key_lens, val_lens, kv_count);
    if (msg_size == (size_t)-1) {
        return (size_t)-1;
    }
    size_t entry_size = 1;
    if (msg_size <= UINT32_MAX) {
        entry_size += ve_tls_varint_u32_size((uint32_t)msg_size);
    } else {
        entry_size += ve_tls_varint_u64_size((uint64_t)msg_size);
    }
    entry_size = ve_tls_size_add_safe(entry_size, msg_size);
    return entry_size;
}

ve_tls_log_group_builder * ve_tls_log_builder_create(const char * norm_key) {
    ve_tls_log_group_builder * b = (ve_tls_log_group_builder *)ve_tls_calloc(1, sizeof(*b));
    if (!b) {
        return NULL;
    }
    if (norm_key && norm_key[0] != 0) {
        b->norm_key = ve_tls_strdup(norm_key);
        if (!b->norm_key) {
            ve_tls_free(b);
            return NULL;
        }
    }
    return b;
}

void ve_tls_log_builder_free(ve_tls_log_group_builder * b) {
    if (!b) {
        return;
    }
    ve_tls_free(b->norm_key);
    ve_tls_free(b->logs);
    ve_tls_free(b);
}

void ve_tls_log_builder_shrink_if_needed(ve_tls_log_group_builder * b, size_t shrink_threshold, size_t shrink_to) {
    if (!b || !b->logs) {
        return;
    }
    if (b->logs_cap <= shrink_threshold) {
        return;
    }
    if (b->logs_len > shrink_to) {
        return;
    }
    if (shrink_to == 0) {
        ve_tls_free(b->logs);
        b->logs = NULL;
        b->logs_cap = 0;
        return;
    }
    unsigned char * p = (unsigned char *)ve_tls_realloc(b->logs, shrink_to);
    if (!p) {
        return;
    }
    b->logs = p;
    b->logs_cap = shrink_to;
}

int ve_tls_log_builder_append(ve_tls_log_group_builder * b, const unsigned char * logs, size_t logs_len, int32_t log_count, int64_t earliest, int64_t latest, int64_t start_id, int64_t end_id, int64_t last_time_ms, uint32_t last_time_ns, int32_t last_has_time_ns) {
    if (!b || !logs || logs_len == 0 || log_count <= 0) {
        return -1;
    }
    size_t need = b->logs_len + logs_len;
    unsigned char * p = b->logs;
    size_t cap = b->logs_cap;
    if (ve_tls_bytes_reserve(&p, &cap, need) != 0) {
        return -1;
    }
    memcpy(p + b->logs_len, logs, logs_len);
    b->logs = p;
    b->logs_cap = cap;
    b->logs_len += logs_len;
    b->log_count += log_count;
    if (earliest > 0) {
        if (b->earliest == 0 || earliest < b->earliest) {
            b->earliest = earliest;
        }
    }
    if (latest > 0) {
        if (latest > b->latest) {
            b->latest = latest;
        }
    }
    if (b->start_id == 0 || start_id < b->start_id) {
        b->start_id = start_id;
    }
    if (end_id > b->end_id) {
        b->end_id = end_id;
    }
    b->last_time_ms = last_time_ms;
    b->last_time_ns = last_time_ns;
    b->last_has_time_ns = last_has_time_ns ? 1 : 0;
    return 0;
}

int ve_tls_log_builder_add_kv_lens(ve_tls_log_group_builder * b, int64_t id, int64_t time_ms, uint32_t time_ns, int32_t has_time_ns, const ve_tls_kv * kvs, const size_t * key_lens, const size_t * val_lens, size_t kv_count) {
    if (!b) {
        return -1;
    }
    if (time_ms <= 0) {
        time_ms = 0;
        has_time_ns = 0;
        time_ns = 0;
    }

    size_t msg_size = ve_tls_log_msg_size_lens(time_ms, time_ns, has_time_ns, key_lens, val_lens, kv_count);
    if (msg_size == (size_t)-1) {
        /* 输入 kv 长度合计后会触发 size_t 回绕，立即拒绝；上层 enqueue 会据此返回 INVALID。 */
        return -1;
    }
    size_t entry_size = 1;
    if (msg_size <= UINT32_MAX) {
        entry_size += ve_tls_varint_u32_size((uint32_t)msg_size);
    } else {
        entry_size += ve_tls_varint_u64_size((uint64_t)msg_size);
    }
    /* entry_size += msg_size 必须经过饱和加法防止 wrap。 */
    entry_size = ve_tls_size_add_safe(entry_size, msg_size);
    if (entry_size == (size_t)-1) {
        return -1;
    }
    size_t need = ve_tls_size_add_safe(b->logs_len, entry_size);
    if (need == (size_t)-1) {
        return -1;
    }
    if (ve_tls_bytes_reserve(&b->logs, &b->logs_cap, need) != 0) {
        return -1;
    }

    unsigned char * buf = b->logs + b->logs_len;
    *buf++ = 0x0A;
    if (msg_size <= UINT32_MAX) {
        buf = ve_tls_varint_u32_pack((uint32_t)msg_size, buf);
    } else {
        buf = ve_tls_varint_u64_pack((uint64_t)msg_size, buf);
    }

    *buf++ = 0x08;
    if (time_ms >= 0 && (uint64_t)time_ms <= UINT32_MAX) {
        buf = ve_tls_varint_u32_pack((uint32_t)time_ms, buf);
    } else {
        buf = ve_tls_varint_u64_pack((uint64_t)time_ms, buf);
    }

    for (size_t i = 0; i < kv_count; i++) {
        const char * k = kvs[i].key ? kvs[i].key : "";
        const char * v = kvs[i].value ? kvs[i].value : "";
        size_t klen = key_lens ? key_lens[i] : 0;
        size_t vlen = val_lens ? val_lens[i] : 0;
        size_t cont_msg = ve_tls_log_content_msg_size(klen, vlen);

        *buf++ = 0x12;
        if (cont_msg <= UINT32_MAX) {
            buf = ve_tls_varint_u32_pack((uint32_t)cont_msg, buf);
        } else {
            buf = ve_tls_varint_u64_pack((uint64_t)cont_msg, buf);
        }
        *buf++ = 0x0A;
        if (klen <= UINT32_MAX) {
            buf = ve_tls_varint_u32_pack((uint32_t)klen, buf);
        } else {
            buf = ve_tls_varint_u64_pack((uint64_t)klen, buf);
        }
        if (klen > 0) {
            memcpy(buf, k, klen);
            buf += klen;
        }
        *buf++ = 0x12;
        if (vlen <= UINT32_MAX) {
            buf = ve_tls_varint_u32_pack((uint32_t)vlen, buf);
        } else {
            buf = ve_tls_varint_u64_pack((uint64_t)vlen, buf);
        }
        if (vlen > 0) {
            memcpy(buf, v, vlen);
            buf += vlen;
        }
    }

    if (has_time_ns) {
        *buf++ = 0x1D;
        buf[0] = (unsigned char)(time_ns & 0xFF);
        buf[1] = (unsigned char)((time_ns >> 8) & 0xFF);
        buf[2] = (unsigned char)((time_ns >> 16) & 0xFF);
        buf[3] = (unsigned char)((time_ns >> 24) & 0xFF);
        buf += 4;
    }

    b->logs_len = (size_t)(buf - b->logs);
    b->log_count += 1;
    if (time_ms > 0) {
        if (b->earliest == 0 || time_ms < b->earliest) {
            b->earliest = time_ms;
        }
        if (b->latest == 0 || time_ms > b->latest) {
            b->latest = time_ms;
        }
    }
    if (b->start_id == 0) {
        b->start_id = id;
    }
    b->end_id = id;
    b->last_time_ms = time_ms;
    b->last_time_ns = time_ns;
    b->last_has_time_ns = has_time_ns ? 1 : 0;
    return 0;
}

int ve_tls_producer_build_group_suffix(ve_tls_producer * producer) {
    if (!producer) {
        return -1;
    }
    ve_tls_free(producer->cfg_group_suffix);
    producer->cfg_group_suffix = NULL;
    producer->cfg_group_suffix_len = 0;
    ve_tls_wire_buf b = {0};
    const char * source = producer->config.source;
    const char * file_name = producer->config.file_name;
    const char * context_flow = producer->config.context_flow;
    if (source && source[0] != 0) {
        if (ve_tls_wire_put_key(&b, 2, 2) != 0) goto fail;
        if (ve_tls_wire_put_len_delimited(&b, source, strlen(source)) != 0) goto fail;
    }
    if (file_name && file_name[0] != 0) {
        if (ve_tls_wire_put_key(&b, 4, 2) != 0) goto fail;
        if (ve_tls_wire_put_len_delimited(&b, file_name, strlen(file_name)) != 0) goto fail;
    }
    if (producer->config.log_tags && producer->config.log_tag_count > 0) {
        for (size_t i = 0; i < producer->config.log_tag_count; i++) {
            const char * k = producer->config.log_tags[i].key ? producer->config.log_tags[i].key : "";
            const char * v = producer->config.log_tags[i].value ? producer->config.log_tags[i].value : "";
            size_t klen = strlen(k);
            size_t vlen = strlen(v);
            size_t msg = ve_tls_log_content_msg_size(klen, vlen);
            if (ve_tls_wire_put_key(&b, 3, 2) != 0) goto fail;
            if (ve_tls_wire_put_varint_u64(&b, (uint64_t)msg) != 0) goto fail;
            if (ve_tls_wire_put_key(&b, 1, 2) != 0) goto fail;
            if (ve_tls_wire_put_len_delimited(&b, k, klen) != 0) goto fail;
            if (ve_tls_wire_put_key(&b, 2, 2) != 0) goto fail;
            if (ve_tls_wire_put_len_delimited(&b, v, vlen) != 0) goto fail;
        }
    }
    if (context_flow && context_flow[0] != 0) {
        if (ve_tls_wire_put_key(&b, 5, 2) != 0) goto fail;
        if (ve_tls_wire_put_len_delimited(&b, context_flow, strlen(context_flow)) != 0) goto fail;
    }
    producer->cfg_group_suffix = b.data;
    producer->cfg_group_suffix_len = b.len;
    return 0;
fail:
    ve_tls_free(b.data);
    return -1;
}

int ve_tls_builder_to_send_task(ve_tls_producer * producer, ve_tls_log_group_builder * b, ve_tls_send_task * out) {
    if (!producer || !b || !out) {
        return -1;
    }
    memset(out, 0, sizeof(*out));
    size_t group_len = b->logs_len + producer->cfg_group_suffix_len;
    ve_tls_wire_buf wb = {0};
    if (ve_tls_wire_put_key(&wb, 1, 2) != 0) goto fail;
    if (ve_tls_wire_put_varint_u64(&wb, (uint64_t)group_len) != 0) goto fail;
    if (ve_tls_wire_put_bytes(&wb, b->logs, b->logs_len) != 0) goto fail;
    if (producer->cfg_group_suffix_len > 0) {
        if (ve_tls_wire_put_bytes(&wb, producer->cfg_group_suffix, producer->cfg_group_suffix_len) != 0) goto fail;
    }
    out->body = wb.data;
    out->body_size = wb.len;
    out->raw_body_size = wb.len;
    out->log_count = b->log_count;
    out->earliest = b->earliest;
    out->latest = b->latest;
    out->batch_bytes = group_len;
    out->start_id = b->start_id;
    out->end_id = b->end_id;
    if (b->norm_key && b->norm_key[0] != 0) {
        out->hash_key = ve_tls_strdup(b->norm_key);
        if (!out->hash_key) goto fail;
    }
    return 0;
fail:
    ve_tls_free(wb.data);
    ve_tls_send_task_free(out);
    return -1;
}
