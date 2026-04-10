#include "ve_tls_persistent_format.h"

#include "ve_tls_alloc.h"

#include <string.h>

static void write_u16_le(unsigned char * p, uint16_t v) {
    p[0] = (unsigned char)(v & 0xffu);
    p[1] = (unsigned char)((v >> 8) & 0xffu);
}

static void write_u32_le(unsigned char * p, uint32_t v) {
    p[0] = (unsigned char)(v & 0xffu);
    p[1] = (unsigned char)((v >> 8) & 0xffu);
    p[2] = (unsigned char)((v >> 16) & 0xffu);
    p[3] = (unsigned char)((v >> 24) & 0xffu);
}

static void write_u64_le(unsigned char * p, uint64_t v) {
    for (int i = 0; i < 8; i++) {
        p[i] = (unsigned char)((v >> (8 * i)) & 0xffu);
    }
}

static uint16_t read_u16_le(const unsigned char * p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t read_u32_le(const unsigned char * p) {
    return (uint32_t)p[0] |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static uint64_t read_u64_le(const unsigned char * p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) {
        v |= ((uint64_t)p[i] << (8 * i));
    }
    return v;
}

static uint32_t crc32_update(uint32_t crc, unsigned char b) {
    crc ^= (uint32_t)b;
    for (int i = 0; i < 8; i++) {
        crc = (crc & 1u) ? ((crc >> 1) ^ 0xEDB88320u) : (crc >> 1);
    }
    return crc;
}

static uint32_t crc32_bytes(const unsigned char * buf, size_t size) {
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < size; i++) {
        crc = crc32_update(crc, buf[i]);
    }
    return crc ^ 0xFFFFFFFFu;
}

static size_t ext_hash_key_size(const ve_tls_persistent_record_view * view) {
    size_t hk_len;
    if (!view || !view->hash_key || view->hash_key[0] == 0) {
        return 0;
    }
    hk_len = strlen(view->hash_key);
    if (hk_len == 0 || hk_len > VE_TLS_PERSISTENT_RECORD_HASH_KEY_MAX) {
        return 0;
    }
    return (size_t)4 + hk_len;
}

size_t ve_tls_persistent_record_encoded_size(const ve_tls_persistent_record_view * view) {
    size_t ext_len;
    if (!view || !view->payload || view->payload_size == 0) {
        return 0;
    }
    ext_len = ext_hash_key_size(view);
    if (view->hash_key && view->hash_key[0] != 0 && ext_len == 0) {
        return 0;
    }
    if (ext_len > VE_TLS_PERSISTENT_RECORD_EXT_MAX) {
        return 0;
    }
    return VE_TLS_PERSISTENT_RECORD_HEADER_SIZE + ext_len + view->payload_size;
}

int ve_tls_persistent_record_encode(unsigned char * out, size_t out_cap, const ve_tls_persistent_record_view * view, size_t * out_size) {
    size_t total_len;
    size_t ext_len;
    uint32_t flags;
    size_t pos;
    if (!out || !view || !out_size) {
        return -1;
    }
    total_len = ve_tls_persistent_record_encoded_size(view);
    if (total_len == 0 || out_cap < total_len) {
        return -1;
    }
    ext_len = ext_hash_key_size(view);
    flags = view->flags;
    if (ext_len > 0) {
        flags |= VE_TLS_PERSISTENT_RECORD_FLAG_HAS_EXT;
    } else {
        flags &= ~VE_TLS_PERSISTENT_RECORD_FLAG_HAS_EXT;
    }
    write_u32_le(out, VE_TLS_PERSISTENT_RECORD_MAGIC);
    write_u32_le(out + 4, (uint32_t)total_len);
    write_u64_le(out + 8, (uint64_t)view->log_id);
    write_u32_le(out + 16, flags);
    write_u32_le(out + 20, crc32_bytes(view->payload, view->payload_size));
    write_u32_le(out + 24, (uint32_t)ext_len);
    pos = VE_TLS_PERSISTENT_RECORD_HEADER_SIZE;
    if (ext_len > 0) {
        size_t hk_len = strlen(view->hash_key);
        out[pos] = VE_TLS_PERSISTENT_EXT_TYPE_HASH_KEY;
        out[pos + 1] = 0;
        write_u16_le(out + pos + 2, (uint16_t)hk_len);
        memcpy(out + pos + 4, view->hash_key, hk_len);
        pos += ext_len;
    }
    memcpy(out + pos, view->payload, view->payload_size);
    *out_size = total_len;
    return 0;
}

int ve_tls_persistent_record_decode(const unsigned char * buf, size_t size, ve_tls_persistent_record * out) {
    uint32_t magic;
    uint32_t total_len;
    uint32_t flags;
    uint32_t payload_crc;
    uint32_t ext_len;
    size_t payload_size;
    size_t pos;
    if (!buf || !out || size < VE_TLS_PERSISTENT_RECORD_HEADER_SIZE) {
        return -1;
    }
    memset(out, 0, sizeof(*out));
    magic = read_u32_le(buf);
    total_len = read_u32_le(buf + 4);
    flags = read_u32_le(buf + 16);
    payload_crc = read_u32_le(buf + 20);
    ext_len = read_u32_le(buf + 24);
    if (magic != VE_TLS_PERSISTENT_RECORD_MAGIC || total_len != size || ext_len > VE_TLS_PERSISTENT_RECORD_EXT_MAX) {
        return -1;
    }
    if ((size_t)VE_TLS_PERSISTENT_RECORD_HEADER_SIZE + (size_t)ext_len > size) {
        return -1;
    }
    pos = VE_TLS_PERSISTENT_RECORD_HEADER_SIZE;
    if (ext_len > 0) {
        size_t ext_end = pos + ext_len;
        while (pos < ext_end) {
            uint8_t type;
            uint16_t len;
            if (ext_end - pos < 4) {
                ve_tls_persistent_record_free(out);
                return -1;
            }
            type = buf[pos];
            len = read_u16_le(buf + pos + 2);
            pos += 4;
            if ((size_t)len > ext_end - pos) {
                ve_tls_persistent_record_free(out);
                return -1;
            }
            if (type == VE_TLS_PERSISTENT_EXT_TYPE_HASH_KEY) {
                if (out->hash_key || len == 0 || len > VE_TLS_PERSISTENT_RECORD_HASH_KEY_MAX) {
                    ve_tls_persistent_record_free(out);
                    return -1;
                }
                out->hash_key = (char *)ve_tls_malloc((size_t)len + 1);
                if (!out->hash_key) {
                    ve_tls_persistent_record_free(out);
                    return -1;
                }
                memcpy(out->hash_key, buf + pos, len);
                out->hash_key[len] = 0;
            }
            pos += len;
        }
    }
    payload_size = size - pos;
    if (payload_size == 0) {
        ve_tls_persistent_record_free(out);
        return -1;
    }
    out->payload = (unsigned char *)ve_tls_malloc(payload_size);
    if (!out->payload) {
        ve_tls_persistent_record_free(out);
        return -1;
    }
    memcpy(out->payload, buf + pos, payload_size);
    if (crc32_bytes(out->payload, payload_size) != payload_crc) {
        ve_tls_persistent_record_free(out);
        return -1;
    }
    out->log_id = (int64_t)read_u64_le(buf + 8);
    out->flags = flags;
    out->payload_size = payload_size;
    return 0;
}

void ve_tls_persistent_record_free(ve_tls_persistent_record * record) {
    if (!record) {
        return;
    }
    ve_tls_free(record->hash_key);
    ve_tls_free(record->payload);
    memset(record, 0, sizeof(*record));
}
