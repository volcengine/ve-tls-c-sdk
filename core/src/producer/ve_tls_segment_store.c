#include "ve_tls_segment_store.h"

#include "ve_tls_alloc.h"
#include "ve_tls_persistent_format.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
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

static int read_payload_crc(ve_tls_platform * platform, ve_tls_file * file, uint64_t payload_size, uint32_t * out_crc) {
    unsigned char buf[4096];
    uint64_t remain = payload_size;
    uint32_t crc = UINT32_MAX;
    if (!platform || !file || !out_crc || payload_size == 0) {
        return -1;
    }
    while (remain > 0) {
        size_t want = remain > sizeof(buf) ? sizeof(buf) : (size_t)remain;
        if (read_full(platform, file, buf, want) != 0) {
            return -1;
        }
        crc = ve_tls_wal_crc32_update(crc, buf, want);
        remain -= (uint64_t)want;
    }
    *out_crc = crc ^ UINT32_MAX;
    return 0;
}

static int validate_ext_stream(const unsigned char * ext, uint32_t ext_len) {
    uint32_t pos = 0;
    int has_hash_key = 0;
    int has_metadata = 0;
    int bad_crc = 0;
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
        } else if (type == VE_TLS_PERSISTENT_EXT_TYPE_METADATA) {
            uint32_t metadata_version;
            uint32_t metadata_crc;
            if (has_metadata || len != 16) {
                return -1;
            }
            metadata_version = read_u32_le_local(ext + pos);
            metadata_crc = read_u32_le_local(ext + pos + 12);
            if ((ve_tls_wal_crc32_update(UINT32_MAX, ext + pos, 12) ^ UINT32_MAX) != metadata_crc) {
                bad_crc = 1;
            } else if (metadata_version != VE_TLS_PERSISTENT_RECORD_VERSION_LEGACY &&
                metadata_version != VE_TLS_PERSISTENT_RECORD_VERSION_CURRENT) {
                return VE_TLS_SEGMENT_STORE_UNSUPPORTED_VERSION;
            }
            has_metadata = 1;
        }
        pos += (uint32_t)len;
    }
    return bad_crc ? VE_TLS_PERSISTENT_RECORD_BAD_CRC : 0;
}

static int scan_segment_file(ve_tls_platform * platform, const char * path, const ve_tls_path_info * info,
    ve_tls_segment_scan * scan);

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
    uint32_t ext_len;
    unsigned char * record;
    if (!platform || !file || !out_record || !out_size) {
        return -1;
    }
    *out_record = NULL;
    *out_size = 0;
    if (limit != UINT64_MAX) {
        if (offset > limit || limit - offset < VE_TLS_PERSISTENT_RECORD_HEADER_SIZE) {
            return VE_TLS_SEGMENT_STORE_INVALID_RECORD;
        }
    }
    if (read_full(platform, file, header, sizeof(header)) != 0) {
        return VE_TLS_SEGMENT_STORE_IO_ERROR;
    }
    total_len = read_u32_le_local(header + 4);
    ext_len = read_u32_le_local(header + 24);
    if (read_u32_le_local(header) != VE_TLS_PERSISTENT_RECORD_MAGIC ||
        total_len < VE_TLS_PERSISTENT_RECORD_HEADER_SIZE ||
        ext_len > VE_TLS_PERSISTENT_RECORD_EXT_MAX ||
        (uint64_t)VE_TLS_PERSISTENT_RECORD_HEADER_SIZE + (uint64_t)ext_len >= (uint64_t)total_len) {
        return VE_TLS_SEGMENT_STORE_INVALID_RECORD;
    }
    if (limit != UINT64_MAX && (uint64_t)total_len > limit - offset) {
        return VE_TLS_SEGMENT_STORE_INVALID_RECORD;
    }
    record = (unsigned char *)ve_tls_malloc(total_len);
    if (!record) {
        return -1;
    }
    memcpy(record, header, sizeof(header));
    if (total_len > sizeof(header) &&
        read_full(platform, file, record + sizeof(header), total_len - sizeof(header)) != 0) {
        ve_tls_free(record);
        return VE_TLS_SEGMENT_STORE_IO_ERROR;
    }
    *out_record = record;
    *out_size = total_len;
    if (next_offset) {
        *next_offset = offset + total_len;
    }
    return 0;
}

static int find_last_existing_segment(const char * path, uint32_t * out_segment_id) {
    DIR * dir = opendir(path);
    uint32_t last_existing = 0;
    if (!dir) return -1;

    while (1) {
        errno = 0;
        struct dirent * entry = readdir(dir);
        if (!entry) {
            int rc = errno == 0 ? 0 : -1;
            closedir(dir);
            *out_segment_id = last_existing;
            return rc;
        }
        if (strncmp(entry->d_name, "seg-", 4) != 0) continue;
        char * suffix;
        unsigned long id = strtoul(entry->d_name + 4, &suffix, 10);
        if (id <= last_existing || id > UINT32_MAX || strcmp(suffix, ".log") != 0) continue;
        char name[sizeof("seg-4294967295.log")];
        (void)snprintf(name, sizeof(name), "seg-%06u.log", (uint32_t)id);
        if (strcmp(entry->d_name, name) == 0) last_existing = (uint32_t)id;
    }
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

int ve_tls_segment_store_scan_segment(ve_tls_segment_store * store, uint32_t segment_id, ve_tls_segment_scan * scan) {
    char path[640];
    ve_tls_path_info info;
    if (!store || !store->platform) {
        return -1;
    }
    if (ve_tls_segment_store_get_segment_path(store, segment_id, path, sizeof(path)) != 0) {
        return -1;
    }
    if (store->platform->path_stat(path, &info) != 0) {
        return VE_TLS_SEGMENT_STORE_IO_ERROR;
    }
    return scan_segment_file(store->platform, path, &info, scan);
}

int ve_tls_segment_store_get_segment_stats(ve_tls_segment_store * store, uint32_t segment_id, uint64_t * out_valid_end, uint64_t * out_record_count) {
    ve_tls_segment_scan scan;
    int rc = ve_tls_segment_store_scan_segment(store, segment_id, &scan);
    if (rc == 0) {
        if (out_valid_end) *out_valid_end = scan.framed_size;
        if (out_record_count) *out_record_count = scan.record_count;
    }
    return rc;
}

static int scan_segment_file(ve_tls_platform * platform, const char * path, const ve_tls_path_info * info,
    ve_tls_segment_scan * scan) {
    ve_tls_file * file;
    int rc = VE_TLS_SEGMENT_STORE_IO_ERROR;
    uint64_t offset = 0;
    int64_t previous_id = 0;
    int consecutive = 1;
    int first_crc_ok = 0;
    int last_crc_ok = 0;
    unsigned char header[VE_TLS_PERSISTENT_RECORD_HEADER_SIZE];
    memset(scan, 0, sizeof(*scan));
    if (!info->exists) {
        return 0;
    }
    file = platform->file_open(path, VE_TLS_FILE_OPEN_RDONLY, 0);
    if (!file) {
        return rc;
    }
    while (info->size - offset >= VE_TLS_PERSISTENT_RECORD_HEADER_SIZE) {
        uint32_t total_len;
        uint32_t payload_crc;
        uint32_t ext_len;
        uint64_t payload_size;
        uint32_t actual_crc;
        unsigned char ext_buf[VE_TLS_PERSISTENT_RECORD_EXT_MAX];
        int ext_rc = 0;
        if (read_full(platform, file, header, sizeof(header)) != 0) {
            goto done;
        }
        total_len = read_u32_le_local(header + 4);
        payload_crc = read_u32_le_local(header + 20);
        ext_len = read_u32_le_local(header + 24);
        if (read_u32_le_local(header) != VE_TLS_PERSISTENT_RECORD_MAGIC ||
            total_len < VE_TLS_PERSISTENT_RECORD_HEADER_SIZE ||
            ext_len > VE_TLS_PERSISTENT_RECORD_EXT_MAX ||
            (uint64_t)VE_TLS_PERSISTENT_RECORD_HEADER_SIZE + (uint64_t)ext_len >= (uint64_t)total_len ||
            total_len > info->size - offset) {
            break;
        }
        payload_size = (uint64_t)total_len - (uint64_t)VE_TLS_PERSISTENT_RECORD_HEADER_SIZE - (uint64_t)ext_len;
        if (ext_len > 0) {
            if (read_full(platform, file, ext_buf, ext_len) != 0) {
                goto done;
            }
            ext_rc = validate_ext_stream(ext_buf, ext_len);
            if (ext_rc == VE_TLS_SEGMENT_STORE_UNSUPPORTED_VERSION) {
                rc = ext_rc;
                goto done;
            }
            if (ext_rc != 0 && ext_rc != VE_TLS_PERSISTENT_RECORD_BAD_CRC) {
                break;
            }
        }
        if (read_payload_crc(platform, file, payload_size, &actual_crc) != 0) {
            goto done;
        }
        last_crc_ok = actual_crc == payload_crc && ext_rc == 0;
        int64_t log_id = (int64_t)read_u64_le_local(header + 8);
        if (!last_crc_ok) scan->has_bad_crc = 1;
        if (scan->record_count == 0) {
            first_crc_ok = last_crc_ok;
        } else if (previous_id == INT64_MAX || log_id != previous_id + 1) {
            consecutive = 0;
        }
        if (log_id <= 0) consecutive = 0;
        if (log_id > 0 && (scan->min_log_id == 0 || log_id < scan->min_log_id)) {
            scan->min_log_id = log_id;
        }
        if (log_id > scan->max_log_id) {
            scan->max_log_id = log_id;
        }
        previous_id = log_id;
        offset += total_len;
        scan->record_count++;
    }
    scan->framed_size = offset;
    /* Preserve ambiguous bytes if another full header could fit after the
       known frames. Earlier intact frames can still be replayed. */
    scan->keep_unframed_tail = scan->has_bad_crc &&
        info->size - offset >= VE_TLS_PERSISTENT_RECORD_HEADER_SIZE;
    scan->can_retire_bad_crc = scan->has_bad_crc && !scan->keep_unframed_tail &&
        consecutive && first_crc_ok && last_crc_ok;
    rc = VE_TLS_SEGMENT_STORE_OK;
done:
    platform->file_close(file);
    return rc;
}

static int open_active_segment(ve_tls_segment_store * store, uint32_t segment_id) {
    char path[640];
    ve_tls_path_info info;
    ve_tls_file * file;
    ve_tls_segment_scan scan;
    int scan_rc;
    if (ve_tls_segment_store_get_segment_path(store, segment_id, path, sizeof(path)) != 0) {
        return -1;
    }
    if (store->platform->path_stat(path, &info) != 0) {
        return VE_TLS_SEGMENT_STORE_IO_ERROR;
    }
    scan_rc = scan_segment_file(store->platform, path, &info, &scan);
    if (scan_rc != 0) {
        return scan_rc;
    }
    file = store->platform->file_open(path, VE_TLS_FILE_OPEN_RDWR | VE_TLS_FILE_OPEN_CREATE | VE_TLS_FILE_OPEN_APPEND, 0644);
    if (!file) {
        return -1;
    }
    if (info.exists && info.size > scan.framed_size && !scan.keep_unframed_tail &&
        store->platform->file_truncate(file, (int64_t)scan.framed_size) != 0) {
        store->platform->file_close(file);
        return -1;
    }
    if (store->active_file) store->platform->file_close(store->active_file);
    store->active_file = file;
    store->active_segment_id = segment_id;
    store->active_size = scan.keep_unframed_tail ? info.size : scan.framed_size;
    store->active_records = scan.record_count;
    store->active_dirty = 0;
    store->active_needs_rotation = scan.keep_unframed_tail;
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

int ve_tls_segment_store_reset_active(ve_tls_segment_store * store) {
    if (store->platform->file_truncate(store->active_file, 0) != 0) {
        return VE_TLS_SEGMENT_STORE_ERROR;
    }
    store->active_size = 0;
    store->active_records = 0;
    store->active_dirty = 1;
    store->active_needs_rotation = 0;
    return VE_TLS_SEGMENT_STORE_OK;
}

static int rotate_segment(ve_tls_segment_store * store) {
    if (ve_tls_segment_store_flush(store) != VE_TLS_SEGMENT_STORE_OK) {
        return VE_TLS_SEGMENT_STORE_SYNC_FAILED;
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
    /* Reclamation can leave gaps. Discover the active segment from the WAL
       directory even when there is no usable checkpoint anchor. */
    if (find_last_existing_segment(store->dir_path, &segment_id) != 0 || segment_id == UINT32_MAX) {
        return -1;
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

int ve_tls_segment_store_would_rotate(const ve_tls_segment_store * store, size_t size) {
    return store->active_needs_rotation ||
        (store->active_size > 0 && (store->active_size > store->segment_max_bytes ||
            (uint64_t)size > store->segment_max_bytes - store->active_size)) ||
        (store->active_records > 0 && store->active_records >= store->segment_max_records);
}

int ve_tls_segment_store_append(ve_tls_segment_store * store, const unsigned char * record, size_t size, ve_tls_segment_record_ref * out_ref) {
    uint64_t offset;
    if (!store || !store->platform || !store->active_file || store->append_failed ||
        !record || size == 0 || size > UINT32_MAX) {
        return -1;
    }
    if (ve_tls_segment_store_would_rotate(store, size)) {
        int rotate_rc = rotate_segment(store);
        if (rotate_rc != VE_TLS_SEGMENT_STORE_OK) {
            return rotate_rc;
        }
    }
    offset = store->active_size;
    /* A nonzero segment ID means the record may still exist. Size is set
       only after all bytes have been written. */
    if (out_ref) {
        out_ref->segment_id = store->active_segment_id;
        out_ref->offset = offset;
        out_ref->size = 0;
    }
    if (write_full(store->platform, store->active_file, record, size) != 0) {
        /* Only release the ID once the tail is gone at the WAL's configured
           durability boundary. Until then, preserve the ID and fence writes. */
        if (store->platform->file_truncate(store->active_file, (int64_t)offset) != 0 ||
            (store->sync_on_append && store->platform->file_fsync(store->active_file) != 0)) {
            store->append_failed = 1;
        } else if (out_ref) {
            *out_ref = (ve_tls_segment_record_ref){0};
        }
        return VE_TLS_SEGMENT_STORE_ERROR;
    }
    store->active_size += size;
    store->active_records++;
    store->active_dirty = 1;
    if (out_ref) {
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
        return VE_TLS_SEGMENT_STORE_IO_ERROR;
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
    int rc = read_record_from_current_position(
        store->platform, reader->file, reader->offset, reader->size, out_record, out_size, &next_offset);
    if (rc != 0) {
        return rc;
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

int ve_tls_segment_store_repair_tail(ve_tls_segment_store * store, uint32_t segment_id, uint64_t record_offset) {
    char path[640];
    ve_tls_file * file;
    ve_tls_path_info info;
    ve_tls_segment_scan scan;
    int scan_rc;
    if (!store || !store->platform) {
        return -1;
    }
    if (ve_tls_segment_store_get_segment_path(store, segment_id, path, sizeof(path)) != 0) {
        return -1;
    }
    if (store->platform->path_stat(path, &info) != 0 || !info.exists) {
        return VE_TLS_SEGMENT_STORE_IO_ERROR;
    }
    scan_rc = scan_segment_file(store->platform, path, &info, &scan);
    if (scan_rc != 0) {
        return scan_rc;
    }
    if (scan.keep_unframed_tail || scan.framed_size != record_offset || scan.framed_size == info.size) {
        return VE_TLS_SEGMENT_STORE_INVALID_RECORD;
    }
    file = store->platform->file_open(path, VE_TLS_FILE_OPEN_RDWR, 0644);
    if (!file) {
        return VE_TLS_SEGMENT_STORE_IO_ERROR;
    }
    if (store->platform->file_truncate(file, (int64_t)scan.framed_size) != 0) {
        store->platform->file_close(file);
        return VE_TLS_SEGMENT_STORE_IO_ERROR;
    }
    store->platform->file_close(file);
    if (segment_id == store->active_segment_id) {
        store->active_size = scan.framed_size;
        store->active_records = scan.record_count;
    }
    return 0;
}
