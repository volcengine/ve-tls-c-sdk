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
    /* Do not shrink a reusable large builder with realloc. Darwin allocators
     * may keep the original large region resident, while the next batch then
     * grows it again and raises the process RSS high-water mark on every
     * flush. Allocate the bounded reusable block first, copy the live prefix,
     * and only then release the large allocation. Allocation failure is a
     * best-effort no-op, preserving the original builder and its data. */
    unsigned char * p = (unsigned char *)ve_tls_malloc(shrink_to);
    if (!p) {
        return;
    }
    if (b->logs_len > 0) {
        memcpy(p, b->logs, b->logs_len);
    }
    ve_tls_free(b->logs);
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

static int ve_tls_wire_read_varint(
    const unsigned char * data,
    size_t size,
    size_t * offset,
    uint64_t * out
) {
    uint64_t value = 0;
    unsigned int shift = 0;
    if (!data || !offset || !out) {
        return -1;
    }
    for (unsigned int i = 0; i < 10 && *offset < size; i++) {
        unsigned char byte = data[(*offset)++];
        if (shift == 63 && (byte & 0xFEu) != 0) {
            return -1;
        }
        value |= (uint64_t)(byte & 0x7Fu) << shift;
        if ((byte & 0x80u) == 0) {
            *out = value;
            return 0;
        }
        shift += 7;
    }
    return -1;
}

int ve_tls_log_payload_rewrite_time(
    const unsigned char * payload,
    size_t payload_size,
    int64_t time_ms,
    unsigned char ** out_payload,
    size_t * out_size
) {
    size_t outer_key_end = 0;
    size_t outer_message_start;
    size_t outer_message_end;
    size_t cursor = 0;
    size_t time_value_start = 0;
    size_t time_value_end = 0;
    uint64_t key = 0;
    uint64_t outer_size_u64 = 0;
    size_t new_time_size;
    size_t new_message_size;
    size_t new_outer_size_size;
    size_t trailing_size;
    size_t total_size;
    unsigned char * result;
    unsigned char * dst;
    if (!payload || payload_size == 0 || time_ms <= 0 || !out_payload || !out_size) {
        return -2;
    }
    *out_payload = NULL;
    *out_size = 0;

    if (ve_tls_wire_read_varint(payload, payload_size, &cursor, &key) != 0 ||
        key != ((1u << 3) | 2u)) {
        return -2;
    }
    outer_key_end = cursor;
    if (ve_tls_wire_read_varint(payload, payload_size, &cursor, &outer_size_u64) != 0 ||
        outer_size_u64 > SIZE_MAX) {
        return -2;
    }
    outer_message_start = cursor;
    if ((size_t)outer_size_u64 > payload_size - outer_message_start) {
        return -2;
    }
    outer_message_end = outer_message_start + (size_t)outer_size_u64;

    while (cursor < outer_message_end) {
        uint64_t field_key = 0;
        uint32_t field_number;
        uint32_t wire_type;
        if (ve_tls_wire_read_varint(payload, outer_message_end, &cursor, &field_key) != 0) {
            return -2;
        }
        field_number = (uint32_t)(field_key >> 3);
        wire_type = (uint32_t)(field_key & 7u);
        if (field_number == 1 && wire_type == 0) {
            uint64_t ignored = 0;
            time_value_start = cursor;
            if (ve_tls_wire_read_varint(payload, outer_message_end, &cursor, &ignored) != 0) {
                return -2;
            }
            time_value_end = cursor;
            break;
        }
        if (wire_type == 0) {
            uint64_t ignored = 0;
            if (ve_tls_wire_read_varint(payload, outer_message_end, &cursor, &ignored) != 0) return -2;
        } else if (wire_type == 1) {
            if (outer_message_end - cursor < 8) return -2;
            cursor += 8;
        } else if (wire_type == 2) {
            uint64_t field_size = 0;
            if (ve_tls_wire_read_varint(payload, outer_message_end, &cursor, &field_size) != 0 ||
                field_size > SIZE_MAX || (size_t)field_size > outer_message_end - cursor) return -2;
            cursor += (size_t)field_size;
        } else if (wire_type == 5) {
            if (outer_message_end - cursor < 4) return -2;
            cursor += 4;
        } else {
            return -2;
        }
    }
    if (time_value_end <= time_value_start) {
        return -2;
    }

    new_time_size = ve_tls_varint_u64_size((uint64_t)time_ms);
    new_message_size = (size_t)outer_size_u64 - (time_value_end - time_value_start);
    new_message_size = ve_tls_size_add_safe(new_message_size, new_time_size);
    if (new_message_size == SIZE_MAX) {
        return -2;
    }
    new_outer_size_size = ve_tls_varint_u64_size((uint64_t)new_message_size);
    trailing_size = payload_size - outer_message_end;
    total_size = ve_tls_size_add_safe(outer_key_end, new_outer_size_size);
    total_size = ve_tls_size_add_safe(total_size, new_message_size);
    total_size = ve_tls_size_add_safe(total_size, trailing_size);
    if (total_size == SIZE_MAX) {
        return -2;
    }
    result = (unsigned char *)ve_tls_malloc(total_size);
    if (!result) {
        return -1;
    }
    dst = result;
    memcpy(dst, payload, outer_key_end);
    dst += outer_key_end;
    dst = ve_tls_varint_u64_pack((uint64_t)new_message_size, dst);
    memcpy(dst, payload + outer_message_start, time_value_start - outer_message_start);
    dst += time_value_start - outer_message_start;
    dst = ve_tls_varint_u64_pack((uint64_t)time_ms, dst);
    memcpy(dst, payload + time_value_end, outer_message_end - time_value_end);
    dst += outer_message_end - time_value_end;
    if (trailing_size > 0) {
        memcpy(dst, payload + outer_message_end, trailing_size);
        dst += trailing_size;
    }
    *out_payload = result;
    *out_size = (size_t)(dst - result);
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

static int ve_tls_builder_group_sizes(
    const ve_tls_producer * producer,
    const ve_tls_log_group_builder * b,
    size_t * group_len,
    size_t * prefix_len,
    size_t * total_len
) {
    size_t group;
    size_t prefix;
    if (!producer || !b || !group_len || !prefix_len || !total_len) {
        return -1;
    }
    if (b->logs_len > 0 && !b->logs) {
        return -1;
    }
    group = ve_tls_size_add_safe(b->logs_len, producer->cfg_group_suffix_len);
    if (group == (size_t)-1) {
        return -1;
    }
    prefix = ve_tls_size_add_safe(
        ve_tls_key_u32_size(1, 2),
        ve_tls_varint_u64_size((uint64_t)group));
    if (prefix == (size_t)-1) {
        return -1;
    }
    *total_len = ve_tls_size_add_safe(prefix, group);
    if (*total_len == (size_t)-1) {
        return -1;
    }
    *group_len = group;
    *prefix_len = prefix;
    return 0;
}

static int ve_tls_builder_fill_task_metadata(
    const ve_tls_log_group_builder * b,
    size_t group_len,
    ve_tls_send_task * out
) {
    out->log_count = b->log_count;
    out->earliest = b->earliest;
    out->latest = b->latest;
    out->batch_bytes = group_len;
    out->start_id = b->start_id;
    out->end_id = b->end_id;
    if (b->norm_key && b->norm_key[0] != 0) {
        out->hash_key = ve_tls_strdup(b->norm_key);
        if (!out->hash_key) {
            return -1;
        }
    }
    return 0;
}

int ve_tls_builder_to_send_task(ve_tls_producer * producer, ve_tls_log_group_builder * b, ve_tls_send_task * out) {
    size_t group_len;
    size_t prefix_len;
    size_t total_len;
    ve_tls_wire_buf wb = {0};
    if (!producer || !b || !out) {
        return -1;
    }
    memset(out, 0, sizeof(*out));
    if (ve_tls_builder_group_sizes(producer, b, &group_len, &prefix_len, &total_len) != 0) {
        return -1;
    }
    (void)prefix_len;
    (void)total_len;
    if (ve_tls_builder_fill_task_metadata(b, group_len, out) != 0) goto fail;
    if (ve_tls_wire_put_key(&wb, 1, 2) != 0) goto fail;
    if (ve_tls_wire_put_varint_u64(&wb, (uint64_t)group_len) != 0) goto fail;
    if (ve_tls_wire_put_bytes(&wb, b->logs, b->logs_len) != 0) goto fail;
    if (producer->cfg_group_suffix_len > 0) {
        if (ve_tls_wire_put_bytes(&wb, producer->cfg_group_suffix, producer->cfg_group_suffix_len) != 0) goto fail;
    }
    out->body = wb.data;
    out->body_size = wb.len;
    out->raw_body_size = wb.len;
    wb.data = NULL;
    wb.len = 0;
    wb.cap = 0;
    return 0;
fail:
    ve_tls_free(wb.data);
    ve_tls_send_task_free(out);
    return -1;
}

int ve_tls_builder_move_to_send_task(
    ve_tls_producer * producer,
    ve_tls_log_group_builder * b,
    ve_tls_send_task * out
) {
    size_t group_len;
    size_t prefix_len;
    size_t total_len;
    unsigned char * body;
    unsigned char * cursor;
    if (!producer || !b || !out) {
        return -1;
    }
    memset(out, 0, sizeof(*out));
    if (ve_tls_builder_group_sizes(producer, b, &group_len, &prefix_len, &total_len) != 0) {
        return -1;
    }
    /* Allocate all fallible metadata before mutating the builder. A failed
     * conversion therefore leaves the sealed batch available to the caller
     * for deterministic drop accounting and cleanup. */
    if (ve_tls_builder_fill_task_metadata(b, group_len, out) != 0) {
        ve_tls_send_task_free(out);
        return -1;
    }
    body = b->logs;
    if (b->logs_cap < total_len) {
        /* Grow only to the exact envelope size. The generic wire builder
         * doubles capacity and creates a second roughly 2 MiB allocation for
         * a 1 MiB batch, which raises Darwin allocator RSS high-water. */
        body = (unsigned char *)ve_tls_realloc(body, total_len);
        if (!body) {
            ve_tls_send_task_free(out);
            return -1;
        }
        b->logs = body;
        b->logs_cap = total_len;
    }
    if (b->logs_len > 0) {
        memmove(body + prefix_len, body, b->logs_len);
    }
    cursor = body;
    cursor = ve_tls_varint_u64_pack(((uint64_t)1 << 3) | 2u, cursor);
    cursor = ve_tls_varint_u64_pack((uint64_t)group_len, cursor);
    (void)cursor;
    if (producer->cfg_group_suffix_len > 0) {
        memcpy(
            body + prefix_len + b->logs_len,
            producer->cfg_group_suffix,
            producer->cfg_group_suffix_len);
    }

    out->body = body;
    out->body_size = total_len;
    out->raw_body_size = total_len;
    b->logs = NULL;
    b->logs_len = 0;
    b->logs_cap = 0;
    return 0;
}
