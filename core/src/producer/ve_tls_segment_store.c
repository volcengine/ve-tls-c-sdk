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

static int scan_segment_file(ve_tls_platform * platform, const char * path, uint64_t * valid_end, uint64_t * record_count);

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

int ve_tls_segment_store_get_segment_path(const ve_tls_segment_store * store, uint32_t segment_id, char * out, size_t out_size) {
    if (!store || !out || out_size == 0 || store->dir_path[0] == 0 || segment_id == 0) {
        return -1;
    }
    if ((size_t)snprintf(out, out_size, "%s/seg-%06u.log", store->dir_path, segment_id) >= out_size) {
        return -1;
    }
    return 0;
}

int ve_tls_segment_store_get_segment_stats(ve_tls_segment_store * store, uint32_t segment_id, uint64_t * out_valid_end, uint64_t * out_record_count) {
    char path[640];
    if (!store || !store->platform) {
        return -1;
    }
    if (ve_tls_segment_store_get_segment_path(store, segment_id, path, sizeof(path)) != 0) {
        return -1;
    }
    return scan_segment_file(store->platform, path, out_valid_end, out_record_count);
}

static int scan_segment_file(ve_tls_platform * platform, const char * path, uint64_t * valid_end, uint64_t * record_count) {
    ve_tls_file * file;
    ve_tls_path_info info;
    uint64_t offset = 0;
    uint64_t count = 0;
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
        return 0;
    }
    file = platform->file_open(path, VE_TLS_FILE_OPEN_RDONLY, 0);
    if (!file) {
        return -1;
    }
    while (offset + VE_TLS_PERSISTENT_RECORD_HEADER_SIZE <= info.size) {
        uint32_t total_len;
        unsigned char * record;
        if (platform->file_seek(file, (int64_t)offset, VE_TLS_FILE_SEEK_SET) < 0) {
            platform->file_close(file);
            return -1;
        }
        if (read_full(platform, file, header, sizeof(header)) != 0) {
            break;
        }
        total_len = read_u32_le_local(header + 4);
        if (read_u32_le_local(header) != VE_TLS_PERSISTENT_RECORD_MAGIC ||
            total_len < VE_TLS_PERSISTENT_RECORD_HEADER_SIZE ||
            offset + total_len > info.size) {
            break;
        }
        record = (unsigned char *)ve_tls_malloc(total_len);
        if (!record) {
            platform->file_close(file);
            return -1;
        }
        memcpy(record, header, sizeof(header));
        if (total_len > sizeof(header) &&
            read_full(platform, file, record + sizeof(header), total_len - sizeof(header)) != 0) {
            ve_tls_free(record);
            break;
        }
        {
            ve_tls_persistent_record decoded;
            if (ve_tls_persistent_record_decode(record, total_len, &decoded) != 0) {
                ve_tls_free(record);
                break;
            }
            ve_tls_persistent_record_free(&decoded);
        }
        ve_tls_free(record);
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
    if (scan_segment_file(store->platform, path, &valid_end, &record_count) != 0) {
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
    return 0;
}

static int rotate_segment(ve_tls_segment_store * store) {
    if (store->active_file) {
        store->platform->file_close(store->active_file);
        store->active_file = NULL;
    }
    return open_active_segment(store, store->active_segment_id + 1);
}

int ve_tls_segment_store_open(ve_tls_segment_store * store, const ve_tls_segment_store_options * options) {
    ve_tls_path_info info;
    uint32_t segment_id = 1;
    char path[640];
    if (!store || !options || !options->platform || !options->dir_path || options->dir_path[0] == 0) {
        return -1;
    }
    memset(store, 0, sizeof(*store));
    store->platform = options->platform;
    store->segment_max_bytes = options->segment_max_bytes > 0 ? options->segment_max_bytes : (64 * 1024);
    store->segment_max_records = options->segment_max_records > 0 ? options->segment_max_records : 1024;
    if (strlen(options->dir_path) >= sizeof(store->dir_path)) {
        return -1;
    }
    memcpy(store->dir_path, options->dir_path, strlen(options->dir_path) + 1);
    if (store->platform->path_mkdirs(store->dir_path, 0700) != 0) {
        return -1;
    }
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
        segment_id++;
    }
    if (segment_id > 1) {
        segment_id--;
    }
    return open_active_segment(store, segment_id);
}

void ve_tls_segment_store_close(ve_tls_segment_store * store) {
    if (!store) {
        return;
    }
    if (store->active_file) {
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
        if (rotate_segment(store) != 0) {
            return -1;
        }
    }
    offset = store->active_size;
    if (write_full(store->platform, store->active_file, record, size) != 0) {
        return -1;
    }
    store->active_size += size;
    store->active_records++;
    if (out_ref) {
        out_ref->segment_id = store->active_segment_id;
        out_ref->offset = offset;
        out_ref->size = (uint32_t)size;
    }
    return 0;
}

int ve_tls_segment_store_read(ve_tls_segment_store * store, uint32_t segment_id, uint64_t offset, unsigned char ** out_record, size_t * out_size, uint64_t * next_offset) {
    char path[640];
    ve_tls_file * file;
    unsigned char header[VE_TLS_PERSISTENT_RECORD_HEADER_SIZE];
    uint32_t total_len;
    unsigned char * record;
    if (!store || !store->platform || !out_record || !out_size) {
        return -1;
    }
    *out_record = NULL;
    *out_size = 0;
    if (ve_tls_segment_store_get_segment_path(store, segment_id, path, sizeof(path)) != 0) {
        return -1;
    }
    file = store->platform->file_open(path, VE_TLS_FILE_OPEN_RDONLY, 0);
    if (!file) {
        return -1;
    }
    if (store->platform->file_seek(file, (int64_t)offset, VE_TLS_FILE_SEEK_SET) < 0 ||
        read_full(store->platform, file, header, sizeof(header)) != 0) {
        store->platform->file_close(file);
        return -1;
    }
    total_len = read_u32_le_local(header + 4);
    if (total_len < VE_TLS_PERSISTENT_RECORD_HEADER_SIZE) {
        store->platform->file_close(file);
        return -1;
    }
    record = (unsigned char *)ve_tls_malloc(total_len);
    if (!record) {
        store->platform->file_close(file);
        return -1;
    }
    memcpy(record, header, sizeof(header));
    if (total_len > sizeof(header) &&
        read_full(store->platform, file, record + sizeof(header), total_len - sizeof(header)) != 0) {
        store->platform->file_close(file);
        ve_tls_free(record);
        return -1;
    }
    store->platform->file_close(file);
    *out_record = record;
    *out_size = total_len;
    if (next_offset) {
        *next_offset = offset + total_len;
    }
    return 0;
}

void ve_tls_segment_store_read_free(unsigned char * record) {
    ve_tls_free(record);
}

int ve_tls_segment_store_repair_tail(ve_tls_segment_store * store, uint32_t segment_id, uint64_t * valid_end_offset) {
    char path[640];
    ve_tls_file * file;
    uint64_t valid_end = 0;
    if (!store || !store->platform) {
        return -1;
    }
    if (ve_tls_segment_store_get_segment_path(store, segment_id, path, sizeof(path)) != 0) {
        return -1;
    }
    if (scan_segment_file(store->platform, path, &valid_end, NULL) != 0) {
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
        if (scan_segment_file(store->platform, path, NULL, &store->active_records) != 0) {
            return -1;
        }
    }
    return 0;
}
