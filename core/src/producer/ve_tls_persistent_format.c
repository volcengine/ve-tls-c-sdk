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

static const uint32_t crc32_table[256] = {
    0x00000000u, 0x77073096u, 0xEE0E612Cu, 0x990951BAu, 0x076DC419u, 0x706AF48Fu, 0xE963A535u, 0x9E6495A3u,
    0x0EDB8832u, 0x79DCB8A4u, 0xE0D5E91Eu, 0x97D2D988u, 0x09B64C2Bu, 0x7EB17CBDu, 0xE7B82D07u, 0x90BF1D91u,
    0x1DB71064u, 0x6AB020F2u, 0xF3B97148u, 0x84BE41DEu, 0x1ADAD47Du, 0x6DDDE4EBu, 0xF4D4B551u, 0x83D385C7u,
    0x136C9856u, 0x646BA8C0u, 0xFD62F97Au, 0x8A65C9ECu, 0x14015C4Fu, 0x63066CD9u, 0xFA0F3D63u, 0x8D080DF5u,
    0x3B6E20C8u, 0x4C69105Eu, 0xD56041E4u, 0xA2677172u, 0x3C03E4D1u, 0x4B04D447u, 0xD20D85FDu, 0xA50AB56Bu,
    0x35B5A8FAu, 0x42B2986Cu, 0xDBBBC9D6u, 0xACBCF940u, 0x32D86CE3u, 0x45DF5C75u, 0xDCD60DCFu, 0xABD13D59u,
    0x26D930ACu, 0x51DE003Au, 0xC8D75180u, 0xBFD06116u, 0x21B4F4B5u, 0x56B3C423u, 0xCFBA9599u, 0xB8BDA50Fu,
    0x2802B89Eu, 0x5F058808u, 0xC60CD9B2u, 0xB10BE924u, 0x2F6F7C87u, 0x58684C11u, 0xC1611DABu, 0xB6662D3Du,
    0x76DC4190u, 0x01DB7106u, 0x98D220BCu, 0xEFD5102Au, 0x71B18589u, 0x06B6B51Fu, 0x9FBFE4A5u, 0xE8B8D433u,
    0x7807C9A2u, 0x0F00F934u, 0x9609A88Eu, 0xE10E9818u, 0x7F6A0DBBu, 0x086D3D2Du, 0x91646C97u, 0xE6635C01u,
    0x6B6B51F4u, 0x1C6C6162u, 0x856530D8u, 0xF262004Eu, 0x6C0695EDu, 0x1B01A57Bu, 0x8208F4C1u, 0xF50FC457u,
    0x65B0D9C6u, 0x12B7E950u, 0x8BBEB8EAu, 0xFCB9887Cu, 0x62DD1DDFu, 0x15DA2D49u, 0x8CD37CF3u, 0xFBD44C65u,
    0x4DB26158u, 0x3AB551CEu, 0xA3BC0074u, 0xD4BB30E2u, 0x4ADFA541u, 0x3DD895D7u, 0xA4D1C46Du, 0xD3D6F4FBu,
    0x4369E96Au, 0x346ED9FCu, 0xAD678846u, 0xDA60B8D0u, 0x44042D73u, 0x33031DE5u, 0xAA0A4C5Fu, 0xDD0D7CC9u,
    0x5005713Cu, 0x270241AAu, 0xBE0B1010u, 0xC90C2086u, 0x5768B525u, 0x206F85B3u, 0xB966D409u, 0xCE61E49Fu,
    0x5EDEF90Eu, 0x29D9C998u, 0xB0D09822u, 0xC7D7A8B4u, 0x59B33D17u, 0x2EB40D81u, 0xB7BD5C3Bu, 0xC0BA6CADu,
    0xEDB88320u, 0x9ABFB3B6u, 0x03B6E20Cu, 0x74B1D29Au, 0xEAD54739u, 0x9DD277AFu, 0x04DB2615u, 0x73DC1683u,
    0xE3630B12u, 0x94643B84u, 0x0D6D6A3Eu, 0x7A6A5AA8u, 0xE40ECF0Bu, 0x9309FF9Du, 0x0A00AE27u, 0x7D079EB1u,
    0xF00F9344u, 0x8708A3D2u, 0x1E01F268u, 0x6906C2FEu, 0xF762575Du, 0x806567CBu, 0x196C3671u, 0x6E6B06E7u,
    0xFED41B76u, 0x89D32BE0u, 0x10DA7A5Au, 0x67DD4ACCu, 0xF9B9DF6Fu, 0x8EBEEFF9u, 0x17B7BE43u, 0x60B08ED5u,
    0xD6D6A3E8u, 0xA1D1937Eu, 0x38D8C2C4u, 0x4FDFF252u, 0xD1BB67F1u, 0xA6BC5767u, 0x3FB506DDu, 0x48B2364Bu,
    0xD80D2BDAu, 0xAF0A1B4Cu, 0x36034AF6u, 0x41047A60u, 0xDF60EFC3u, 0xA867DF55u, 0x316E8EEFu, 0x4669BE79u,
    0xCB61B38Cu, 0xBC66831Au, 0x256FD2A0u, 0x5268E236u, 0xCC0C7795u, 0xBB0B4703u, 0x220216B9u, 0x5505262Fu,
    0xC5BA3BBEu, 0xB2BD0B28u, 0x2BB45A92u, 0x5CB36A04u, 0xC2D7FFA7u, 0xB5D0CF31u, 0x2CD99E8Bu, 0x5BDEAE1Du,
    0x9B64C2B0u, 0xEC63F226u, 0x756AA39Cu, 0x026D930Au, 0x9C0906A9u, 0xEB0E363Fu, 0x72076785u, 0x05005713u,
    0x95BF4A82u, 0xE2B87A14u, 0x7BB12BAEu, 0x0CB61B38u, 0x92D28E9Bu, 0xE5D5BE0Du, 0x7CDCEFB7u, 0x0BDBDF21u,
    0x86D3D2D4u, 0xF1D4E242u, 0x68DDB3F8u, 0x1FDA836Eu, 0x81BE16CDu, 0xF6B9265Bu, 0x6FB077E1u, 0x18B74777u,
    0x88085AE6u, 0xFF0F6A70u, 0x66063BCAu, 0x11010B5Cu, 0x8F659EFFu, 0xF862AE69u, 0x616BFFD3u, 0x166CCF45u,
    0xA00AE278u, 0xD70DD2EEu, 0x4E048354u, 0x3903B3C2u, 0xA7672661u, 0xD06016F7u, 0x4969474Du, 0x3E6E77DBu,
    0xAED16A4Au, 0xD9D65ADCu, 0x40DF0B66u, 0x37D83BF0u, 0xA9BCAE53u, 0xDEBB9EC5u, 0x47B2CF7Fu, 0x30B5FFE9u,
    0xBDBDF21Cu, 0xCABAC28Au, 0x53B39330u, 0x24B4A3A6u, 0xBAD03605u, 0xCDD70693u, 0x54DE5729u, 0x23D967BFu,
    0xB3667A2Eu, 0xC4614AB8u, 0x5D681B02u, 0x2A6F2B94u, 0xB40BBE37u, 0xC30C8EA1u, 0x5A05DF1Bu, 0x2D02EF8Du
};

static uint32_t crc32_bytes(const unsigned char * buf, size_t size) {
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < size; i++) {
        crc = crc32_table[(crc ^ (uint32_t)buf[i]) & 0xFFu] ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFFu;
}

static size_t ext_metadata_size(const ve_tls_persistent_record_view * view) {
    if (!view || view->record_version != VE_TLS_PERSISTENT_RECORD_VERSION_CURRENT) {
        return 0;
    }
    return (size_t)4 + 16;
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
    if (view->record_version != 0 &&
        view->record_version != VE_TLS_PERSISTENT_RECORD_VERSION_LEGACY &&
        view->record_version != VE_TLS_PERSISTENT_RECORD_VERSION_CURRENT) {
        return 0;
    }
    ext_len = ext_hash_key_size(view);
    if (view->hash_key && view->hash_key[0] != 0 && ext_len == 0) {
        return 0;
    }
    ext_len += ext_metadata_size(view);
    if (ext_len > VE_TLS_PERSISTENT_RECORD_EXT_MAX) {
        return 0;
    }
    return VE_TLS_PERSISTENT_RECORD_HEADER_SIZE + ext_len + view->payload_size;
}

int ve_tls_persistent_record_encode(unsigned char * out, size_t out_cap, const ve_tls_persistent_record_view * view, size_t * out_size) {
    size_t total_len;
    size_t ext_len;
    size_t hash_key_ext_len;
    size_t metadata_ext_len;
    uint32_t flags;
    size_t pos;
    if (!out || !view || !out_size) {
        return -1;
    }
    total_len = ve_tls_persistent_record_encoded_size(view);
    if (total_len == 0 || out_cap < total_len) {
        return -1;
    }
    hash_key_ext_len = ext_hash_key_size(view);
    metadata_ext_len = ext_metadata_size(view);
    ext_len = hash_key_ext_len + metadata_ext_len;
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
    if (hash_key_ext_len > 0) {
        size_t hk_len = strlen(view->hash_key);
        out[pos] = VE_TLS_PERSISTENT_EXT_TYPE_HASH_KEY;
        out[pos + 1] = 0;
        write_u16_le(out + pos + 2, (uint16_t)hk_len);
        memcpy(out + pos + 4, view->hash_key, hk_len);
        pos += hash_key_ext_len;
    }
    if (metadata_ext_len > 0) {
        out[pos] = VE_TLS_PERSISTENT_EXT_TYPE_METADATA;
        out[pos + 1] = 0;
        write_u16_le(out + pos + 2, 16);
        write_u32_le(out + pos + 4, view->record_version);
        write_u64_le(out + pos + 8, (uint64_t)view->enqueue_time_ms);
        write_u32_le(out + pos + 16, crc32_bytes(out + pos + 4, 12));
        pos += metadata_ext_len;
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
    int has_metadata = 0;
    if (!buf || !out || size < VE_TLS_PERSISTENT_RECORD_HEADER_SIZE) {
        return -1;
    }
    memset(out, 0, sizeof(*out));
    out->record_version = VE_TLS_PERSISTENT_RECORD_VERSION_LEGACY;
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
            } else if (type == VE_TLS_PERSISTENT_EXT_TYPE_METADATA) {
                uint32_t metadata_version;
                uint32_t metadata_crc;
                if (has_metadata || len != 16) {
                    ve_tls_persistent_record_free(out);
                    return -1;
                }
                metadata_version = read_u32_le(buf + pos);
                metadata_crc = read_u32_le(buf + pos + 12);
                if (crc32_bytes(buf + pos, 12) != metadata_crc) {
                    ve_tls_persistent_record_free(out);
                    return -1;
                }
                if (metadata_version != VE_TLS_PERSISTENT_RECORD_VERSION_LEGACY &&
                    metadata_version != VE_TLS_PERSISTENT_RECORD_VERSION_CURRENT) {
                    ve_tls_persistent_record_free(out);
                    return VE_TLS_PERSISTENT_RECORD_UNSUPPORTED_VERSION;
                }
                has_metadata = 1;
                out->record_version = metadata_version;
                out->enqueue_time_ms = (int64_t)read_u64_le(buf + pos + 4);
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
