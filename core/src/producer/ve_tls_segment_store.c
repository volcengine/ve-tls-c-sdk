#include "ve_tls_segment_store.h"

#include "ve_tls_alloc.h"
#include "ve_tls_persistent_format.h"

#include <stdio.h>
#include <string.h>

static uint32_t read_u32_le_local(const unsigned char * p) {
    return (uint32_t)p[0] |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static uint16_t read_u16_le_local(const unsigned char * p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static int read_full(ve_tls_platform * platform, ve_tls_file * file, void * buf, size_t size);

static uint64_t read_u64_le_local(const unsigned char * p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) {
        v |= ((uint64_t)p[i] << (8 * i));
    }
    return v;
}

static uint32_t crc32_update_local(uint32_t crc, unsigned char b) {
    crc ^= (uint32_t)b;
    for (int i = 0; i < 8; i++) {
        crc = (crc & 1u) ? ((crc >> 1) ^ 0xEDB88320u) : (crc >> 1);
    }
    return crc;
}

static int read_payload_crc(ve_tls_platform * platform, ve_tls_file * file, uint64_t payload_size, uint32_t * out_crc) {
    unsigned char buf[4096];
    uint64_t remain = payload_size;
    uint32_t crc = 0xFFFFFFFFu;
    if (!platform || !file || !out_crc || payload_size == 0) {
        return -1;
    }
    while (remain > 0) {
        size_t want = remain > sizeof(buf) ? sizeof(buf) : (size_t)remain;
        if (read_full(platform, file, buf, want) != 0) {
            return -1;
        }
        for (size_t i = 0; i < want; i++) {
            crc = crc32_update_local(crc, buf[i]);
        }
        remain -= (uint64_t)want;
    }
    *out_crc = crc ^ 0xFFFFFFFFu;
    return 0;
}

static int validate_ext_stream(const unsigned char * ext, uint32_t ext_len) {
    uint32_t pos = 0;
    int has_hash_key = 0;
    while (pos < ext_len) {
        uint8_t type;
        uint16_t len;
        if (ext_len - pos < 4) {
            return -1;
        }
        type = ext[pos];
        len = read_u16_le_local(ext + pos + 2);
        pos += 4;
        if ((uint32_t)len > ext_len - pos) {
            return -1;
        }
        if (type == VE_TLS_PERSISTENT_EXT_TYPE_HASH_KEY) {
            if (has_hash_key || len == 0 || len > VE_TLS_PERSISTENT_RECORD_HASH_KEY_MAX) {
                return -1;
            }
            has_hash_key = 1;
        }
        pos += (uint32_t)len;
    }
    return pos == ext_len ? 0 : -1;
}

static int scan_segment_file(ve_tls_platform * platform, const char * path, uint64_t * valid_end, uint64_t * record_count, int64_t * max_log_id);

static int read_full(ve_tls_platform * platform, ve_tls_file * file, void * buf, size_t size) {
    size_t off = 0;
    while (off < size) {
        int64_t n = platform->file_read(file, (unsigned char *)buf + off, size - off);
        if (n <= 0) {
            return -1;
        }
        off += (size_t)n;
    }
    return 0;
}

static int write_full(ve_tls_platform * platform, ve_tls_file * file, const void * buf, size_t size) {
    size_t off = 0;
    while (off < size) {
        int64_t n = platform->file_write(file, (const unsigned char *)buf + off, size - off);
        if (n <= 0) {
            return -1;
        }
        off += (size_t)n;
    }
    return 0;
}

static int read_record_from_current_position(
    ve_tls_platform * platform,
    ve_tls_file * file,
    uint64_t offset,
    uint64_t limit,
    unsigned char ** out_record,
    size_t * out_size,
    uint64_t * next_offset
) {
    unsigned char header[VE_TLS_PERSISTENT_RECORD_HEADER_SIZE];
    uint32_t total_len;
    unsigned char * record;
    if (!platform || !file || !out_record || !out_size) {
        return -1;
    }
    *out_record = NULL;
    *out_size = 0;
    if (limit != UINT64_MAX) {
        if (offset > limit || limit - offset < VE_TLS_PERSISTENT_RECORD_HEADER_SIZE) {
            return -1;
        }
    }
    if (read_full(platform, file, header, sizeof(header)) != 0) {
        return -1;
    }
    total_len = read_u32_le_local(header + 4);
    if (total_len < VE_TLS_PERSISTENT_RECORD_HEADER_SIZE) {
        return -1;
    }
    if (limit != UINT64_MAX && (uint64_t)total_len > limit - offset) {
        return -1;
    }
    record = (unsigned char *)ve_tls_malloc(total_len);
    if (!record) {
        return -1;
    }
    memcpy(record, header, sizeof(header));
    if (total_len > sizeof(header) &&
        read_full(platform, file, record + sizeof(header), total_len - sizeof(header)) != 0) {
        ve_tls_free(record);
        return -1;
    }
    *out_record = record;
    *out_size = total_len;
    if (next_offset) {
        *next_offset = offset + total_len;
    }
    return 0;
}

static int find_last_existing_segment(ve_tls_segment_store * store, uint32_t start_segment_id, uint32_t * out_segment_id) {
    ve_tls_path_info info;
    uint32_t segment_id;
    uint32_t last_existing = 0;
    char path[640];
    if (!store || !store->platform || !out_segment_id || start_segment_id == 0) {
        return -1;
    }
    segment_id = start_segment_id;
    while (1) {
        if (ve_tls_segment_store_get_segment_path(store, segment_id, path, sizeof(path)) != 0) {
            return -1;
        }
        if (store->platform->path_stat(path, &info) != 0) {
            return -1;
        }
        if (!info.exists) {
            break;
        }
        last_existing = segment_id;
        if (segment_id == UINT32_MAX) {
            break;
        }
        segment_id++;
    }
    *out_segment_id = last_existing;
    return 0;
}

int ve_tls_segment_store_get_segment_path(const ve_tls_segment_store * store, uint32_t segment_id, char * out, size_t out_size) {
    if (!store || !out || out_size == 0 || store->dir_path[0] == 0 || segment_id == 0) {
        return -1;
    }
    if ((size_t)snprintf(out, out_size, "%s/seg-%06u.log", store->dir_path, segment_id) >= out_size) {
        return -1;
    }
    return 0;
}

int ve_tls_segment_store_scan_segment(ve_tls_segment_store * store, uint32_t segment_id, uint64_t * out_valid_end, uint64_t * out_record_count, int64_t * out_max_log_id) {
    char path[640];
    if (!store || !store->platform) {
        return -1;
    }
    if (ve_tls_segment_store_get_segment_path(store, segment_id, path, sizeof(path)) != 0) {
        return -1;
    }
    return scan_segment_file(store->platform, path, out_valid_end, out_record_count, out_max_log_id);
}

int ve_tls_segment_store_get_segment_stats(ve_tls_segment_store * store, uint32_t segment_id, uint64_t * out_valid_end, uint64_t * out_record_count) {
    return ve_tls_segment_store_scan_segment(store, segment_id, out_valid_end, out_record_count, NULL);
}

static int scan_segment_file(ve_tls_platform * platform, const char * path, uint64_t * valid_end, uint64_t * record_count, int64_t * max_log_id) {
    ve_tls_file * file;
    ve_tls_path_info info;
    uint64_t offset = 0;
    uint64_t count = 0;
    int64_t max_id = 0;
    unsigned char header[VE_TLS_PERSISTENT_RECORD_HEADER_SIZE];
    if (platform->path_stat(path, &info) != 0) {
        return -1;
    }
    if (!info.exists) {
        if (valid_end) {
            *valid_end = 0;
        }
        if (record_count) {
            *record_count = 0;
        }
        if (max_log_id) {
            *max_log_id = 0;
        }
        return 0;
    }
    file = platform->file_open(path, VE_TLS_FILE_OPEN_RDONLY, 0);
    if (!file) {
        return -1;
    }
    while (offset + VE_TLS_PERSISTENT_RECORD_HEADER_SIZE <= info.size) {
        uint32_t total_len;
        uint32_t payload_crc;
        uint32_t ext_len;
        uint64_t payload_size;
        uint32_t actual_crc;
        unsigned char ext_buf[VE_TLS_PERSISTENT_RECORD_EXT_MAX];
        if (platform->file_seek(file, (int64_t)offset, VE_TLS_FILE_SEEK_SET) < 0) {
            platform->file_close(file);
            return -1;
        }
        if (read_full(platform, file, header, sizeof(header)) != 0) {
            break;
        }
        total_len = read_u32_le_local(header + 4);
        payload_crc = read_u32_le_local(header + 20);
        ext_len = read_u32_le_local(header + 24);
        if (read_u32_le_local(header) != VE_TLS_PERSISTENT_RECORD_MAGIC ||
            total_len < VE_TLS_PERSISTENT_RECORD_HEADER_SIZE ||
            ext_len > VE_TLS_PERSISTENT_RECORD_EXT_MAX ||
            (uint64_t)VE_TLS_PERSISTENT_RECORD_HEADER_SIZE + (uint64_t)ext_len >= (uint64_t)total_len ||
            offset + total_len > info.size) {
            break;
        }
        payload_size = (uint64_t)total_len - (uint64_t)VE_TLS_PERSISTENT_RECORD_HEADER_SIZE - (uint64_t)ext_len;
        if (ext_len > 0) {
            if (read_full(platform, file, ext_buf, ext_len) != 0 || validate_ext_stream(ext_buf, ext_len) != 0) {
                break;
            }
        }
        if (read_payload_crc(platform, file, payload_size, &actual_crc) != 0 || actual_crc != payload_crc) {
            break;
        }
        {
            int64_t log_id = (int64_t)read_u64_le_local(header + 8);
            if (log_id > max_id) {
                max_id = log_id;
            }
        }
        offset += total_len;
        count++;
    }
    platform->file_close(file);
    if (valid_end) {
        *valid_end = offset;
    }
    if (record_count) {
        *record_count = count;
    }
    if (max_log_id) {
        *max_log_id = max_id;
    }
    return 0;
}

static int open_active_segment(ve_tls_segment_store * store, uint32_t segment_id) {
    char path[640];
    ve_tls_path_info info;
    uint64_t valid_end = 0;
    uint64_t record_count = 0;
    if (ve_tls_segment_store_get_segment_path(store, segment_id, path, sizeof(path)) != 0) {
        return -1;
    }
    if (scan_segment_file(store->platform, path, &valid_end, &record_count, NULL) != 0) {
        return -1;
    }
    if (store->platform->path_stat(path, &info) != 0) {
        return -1;
    }
    store->active_file = store->platform->file_open(path, VE_TLS_FILE_OPEN_RDWR | VE_TLS_FILE_OPEN_CREATE | VE_TLS_FILE_OPEN_APPEND, 0644);
    if (!store->active_file) {
        return -1;
    }
    if (info.exists && info.size != valid_end && store->platform->file_truncate(store->active_file, (int64_t)valid_end) != 0) {
        store->platform->file_close(store->active_file);
        store->active_file = NULL;
        return -1;
    }
    store->active_segment_id = segment_id;
    store->active_size = valid_end;
    store->active_records = record_count;
    store->active_dirty = 0;
    return 0;
}

int ve_tls_segment_store_flush(ve_tls_segment_store * store) {
    if (!store || !store->platform || !store->active_file) {
        return VE_TLS_SEGMENT_STORE_ERROR;
    }
    if (!store->active_dirty) {
        return VE_TLS_SEGMENT_STORE_OK;
    }
    if (store->platform->file_fsync(store->active_file) != 0) {
        return VE_TLS_SEGMENT_STORE_SYNC_FAILED;
    }
    store->active_dirty = 0;
    return VE_TLS_SEGMENT_STORE_OK;
}

static int rotate_segment(ve_tls_segment_store * store) {
    if (ve_tls_segment_store_flush(store) != VE_TLS_SEGMENT_STORE_OK) {
        return VE_TLS_SEGMENT_STORE_SYNC_FAILED;
    }
    if (store->active_file) {
        store->platform->file_close(store->active_file);
        store->active_file = NULL;
    }
    return open_active_segment(store, store->active_segment_id + 1);
}

int ve_tls_segment_store_open(ve_tls_segment_store * store, const ve_tls_segment_store_options * options) {
    uint32_t segment_id = 0;
    if (!store || !options || !options->platform || !options->dir_path || options->dir_path[0] == 0) {
        return -1;
    }
    memset(store, 0, sizeof(*store));
    store->platform = options->platform;
    store->segment_max_bytes = options->segment_max_bytes > 0 ? options->segment_max_bytes : (64 * 1024);
    store->segment_max_records = options->segment_max_records > 0 ? options->segment_max_records : 1024;
    store->sync_on_append = options->sync_on_append ? 1 : 0;
    if (strlen(options->dir_path) >= sizeof(store->dir_path)) {
        return -1;
    }
    memcpy(store->dir_path, options->dir_path, strlen(options->dir_path) + 1);
    if (store->platform->path_mkdirs(store->dir_path, 0700) != 0) {
        return -1;
    }
    if (options->resume_segment_id > 0) {
        if (find_last_existing_segment(store, options->resume_segment_id, &segment_id) != 0) {
            return -1;
        }
    }
    if (segment_id == 0) {
        if (find_last_existing_segment(store, 1, &segment_id) != 0) {
            return -1;
        }
    }
    if (segment_id == 0) {
        segment_id = 1;
    }
    return open_active_segment(store, segment_id);
}

void ve_tls_segment_store_close(ve_tls_segment_store * store) {
    if (!store) {
        return;
    }
    if (store->active_file) {
        (void)ve_tls_segment_store_flush(store);
        store->platform->file_close(store->active_file);
        store->active_file = NULL;
    }
    memset(store, 0, sizeof(*store));
}

int ve_tls_segment_store_append(ve_tls_segment_store * store, const unsigned char * record, size_t size, ve_tls_segment_record_ref * out_ref) {
    uint64_t offset;
    if (!store || !store->platform || !store->active_file || !record || size == 0 || size > UINT32_MAX) {
        return -1;
    }
    if ((store->active_size > 0 && store->active_size + size > store->segment_max_bytes) ||
        (store->active_records > 0 && store->active_records >= store->segment_max_records)) {
        int rotate_rc = rotate_segment(store);
        if (rotate_rc != VE_TLS_SEGMENT_STORE_OK) {
            return rotate_rc;
        }
    }
    offset = store->active_size;
    if (write_full(store->platform, store->active_file, record, size) != 0) {
        (void)store->platform->file_truncate(store->active_file, (int64_t)offset);
        return VE_TLS_SEGMENT_STORE_ERROR;
    }
    store->active_size += size;
    store->active_records++;
    store->active_dirty = 1;
    if (out_ref) {
        out_ref->segment_id = store->active_segment_id;
        out_ref->offset = offset;
        out_ref->size = (uint32_t)size;
    }
    if (store->sync_on_append) {
        return ve_tls_segment_store_flush(store);
    }
    return VE_TLS_SEGMENT_STORE_OK;
}

int ve_tls_segment_store_read(ve_tls_segment_store * store, uint32_t segment_id, uint64_t offset, unsigned char ** out_record, size_t * out_size, uint64_t * next_offset) {
    char path[640];
    ve_tls_file * file;
    ve_tls_path_info info;
    if (!store || !store->platform || !out_record || !out_size) {
        return -1;
    }
    *out_record = NULL;
    *out_size = 0;
    if (ve_tls_segment_store_get_segment_path(store, segment_id, path, sizeof(path)) != 0) {
        return -1;
    }
    /* 先 stat 文件大小作为 limit，防止读取损坏 header 时按伪造的 total_len 大额分配。 */
    if (store->platform->path_stat(path, &info) != 0 || !info.exists) {
        return -1;
    }
    file = store->platform->file_open(path, VE_TLS_FILE_OPEN_RDONLY, 0);
    if (!file) {
        return -1;
    }
    if (store->platform->file_seek(file, (int64_t)offset, VE_TLS_FILE_SEEK_SET) < 0 ||
        read_record_from_current_position(store->platform, file, offset, info.size, out_record, out_size, next_offset) != 0) {
        store->platform->file_close(file);
        return -1;
    }
    store->platform->file_close(file);
    return 0;
}

void ve_tls_segment_store_read_free(unsigned char * record) {
    ve_tls_free(record);
}

int ve_tls_segment_store_reader_open(ve_tls_segment_store * store, uint32_t segment_id, uint64_t segment_size, ve_tls_segment_reader * reader) {
    char path[640];
    if (!store || !store->platform || !reader) {
        return -1;
    }
    memset(reader, 0, sizeof(*reader));
    if (ve_tls_segment_store_get_segment_path(store, segment_id, path, sizeof(path)) != 0) {
        return -1;
    }
    reader->file = store->platform->file_open(path, VE_TLS_FILE_OPEN_RDONLY, 0);
    if (!reader->file) {
        return -1;
    }
    reader->size = segment_size;
    reader->offset = 0;
    return 0;
}

int ve_tls_segment_store_reader_next(ve_tls_segment_store * store, ve_tls_segment_reader * reader, unsigned char ** out_record, size_t * out_size) {
    uint64_t next_offset;
    if (!store || !store->platform || !reader || !reader->file || !out_record || !out_size) {
        return -1;
    }
    *out_record = NULL;
    *out_size = 0;
    if (reader->offset >= reader->size) {
        return 0;
    }
    next_offset = reader->offset;
    if (read_record_from_current_position(store->platform, reader->file, reader->offset, reader->size, out_record, out_size, &next_offset) != 0) {
        return -1;
    }
    reader->offset = next_offset;
    return 1;
}

void ve_tls_segment_store_reader_close(ve_tls_segment_store * store, ve_tls_segment_reader * reader) {
    if (!store || !store->platform || !reader) {
        return;
    }
    if (reader->file) {
        store->platform->file_close(reader->file);
    }
    memset(reader, 0, sizeof(*reader));
}

int ve_tls_segment_store_repair_tail(ve_tls_segment_store * store, uint32_t segment_id, uint64_t * valid_end_offset) {
    char path[640];
    ve_tls_file * file;
    uint64_t valid_end = 0;
    uint64_t record_count = 0;
    if (!store || !store->platform) {
        return -1;
    }
    if (ve_tls_segment_store_get_segment_path(store, segment_id, path, sizeof(path)) != 0) {
        return -1;
    }
    if (scan_segment_file(store->platform, path, &valid_end, &record_count, NULL) != 0) {
        return -1;
    }
    file = store->platform->file_open(path, VE_TLS_FILE_OPEN_RDWR, 0644);
    if (!file) {
        return -1;
    }
    if (store->platform->file_truncate(file, (int64_t)valid_end) != 0) {
        store->platform->file_close(file);
        return -1;
    }
    store->platform->file_close(file);
    if (valid_end_offset) {
        *valid_end_offset = valid_end;
    }
    if (segment_id == store->active_segment_id) {
        store->active_size = valid_end;
        store->active_records = record_count;
    }
    return 0;
}
