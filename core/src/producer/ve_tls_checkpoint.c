#include "ve_tls_checkpoint.h"

#include "ve_tls_alloc.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define VE_TLS_CHECKPOINT_MAGIC 0x54435031u
#define VE_TLS_CHECKPOINT_VERSION 1u
#define VE_TLS_CHECKPOINT_RANGE_MAGIC 0x324b4341u
#define VE_TLS_CHECKPOINT_RANGE_VERSION 1u
#define VE_TLS_CHECKPOINT_RANGE_HEADER_SIZE 20u
#define VE_TLS_CHECKPOINT_RANGE_RECORD_SIZE 16u
#define VE_TLS_CHECKPOINT_PATH_CAPACITY 1024u

typedef struct {
    uint32_t magic;
    uint32_t version;
    int64_t acked_log_id;
    int64_t replay_begin_log_id;
    uint32_t replay_begin_segment_id;
    uint32_t reserved;
    uint64_t replay_begin_offset;
    uint32_t last_segment_id;
    uint32_t checksum;
} ve_tls_checkpoint_file;

static uint32_t checksum_bytes(const unsigned char * buf, size_t size) {
    uint32_t sum = 2166136261u;
    for (size_t i = 0; i < size; i++) {
        sum ^= buf[i];
        sum *= 16777619u;
    }
    return sum;
}

/* CRC32 of the V1 prefix, the first 16 extension-header bytes, and records. */
static uint32_t crc32_update(uint32_t crc, const unsigned char * buf, size_t size) {
    for (size_t i = 0; i < size; i++) {
        crc ^= buf[i];
        for (int bit = 0; bit < 8; bit++) {
            crc = (crc >> 1) ^ (0xEDB88320u & (uint32_t)-(int32_t)(crc & 1u));
        }
    }
    return crc;
}

static void write_u32_le(unsigned char * out, uint32_t value) {
    for (unsigned i = 0; i < 4; i++) out[i] = (unsigned char)(value >> (i * 8u));
}

static void write_u64_le(unsigned char * out, uint64_t value) {
    for (unsigned i = 0; i < 8; i++) out[i] = (unsigned char)(value >> (i * 8u));
}

static uint32_t read_u32_le(const unsigned char * in) {
    uint32_t value = 0;
    for (unsigned i = 0; i < 4; i++) value |= (uint32_t)in[i] << (i * 8u);
    return value;
}

static uint64_t read_u64_le(const unsigned char * in) {
    uint64_t value = 0;
    for (unsigned i = 0; i < 8; i++) value |= (uint64_t)in[i] << (i * 8u);
    return value;
}

static int read_full(ve_tls_platform * platform, ve_tls_file * file, void * buf, size_t size) {
    size_t off = 0;
    while (off < size) {
        int64_t n = platform->file_read(file, (unsigned char *)buf + off, size - off);
        if (n <= 0) return -1;
        off += (size_t)n;
    }
    return 0;
}

static int write_full(ve_tls_platform * platform, ve_tls_file * file, const void * buf, size_t size) {
    size_t off = 0;
    while (off < size) {
        int64_t n = platform->file_write(file, (const unsigned char *)buf + off, size - off);
        if (n <= 0) return -1;
        off += (size_t)n;
    }
    return 0;
}

static int range_valid(const ve_tls_checkpoint_range * range, int64_t previous_end) {
    if (previous_end >= INT64_MAX - 1 || range->start_id <= 0 ||
        range->start_id <= previous_end + 1 || range->end_id < range->start_id) {
        return 0;
    }
    return 1;
}

static void encode_range(unsigned char out[VE_TLS_CHECKPOINT_RANGE_RECORD_SIZE],
    const ve_tls_checkpoint_range * range) {
    write_u64_le(out, (uint64_t)range->start_id);
    write_u64_le(out + 8, (uint64_t)range->end_id);
}

static int checkpoint_paths(const char * path, char * tmp_path, char * parent) {
    size_t len = strlen(path);
    const char * slash = strrchr(path, '/');
    size_t parent_len = slash ? (size_t)(slash - path) : 1;
    if (len == 0 || len + sizeof(".tmp") > VE_TLS_CHECKPOINT_PATH_CAPACITY ||
        (slash && slash[1] == '\0') || parent_len + 1 > VE_TLS_CHECKPOINT_PATH_CAPACITY) {
        return -1;
    }
    memcpy(tmp_path, path, len);
    memcpy(tmp_path + len, ".tmp", sizeof(".tmp"));
    if (!slash) {
        parent[0] = '.';
        parent[1] = '\0';
    } else if (parent_len == 0) {
        parent[0] = '/';
        parent[1] = '\0';
    } else {
        memcpy(parent, path, parent_len);
        parent[parent_len] = '\0';
    }
    return 0;
}

static int load_prefix(ve_tls_platform * platform, ve_tls_file * file,
    ve_tls_checkpoint_file * file_data, ve_tls_checkpoint_state * state) {
    if (read_full(platform, file, file_data, sizeof(*file_data)) != 0 ||
        file_data->magic != VE_TLS_CHECKPOINT_MAGIC || file_data->version != VE_TLS_CHECKPOINT_VERSION ||
        file_data->checksum != checksum_bytes((const unsigned char *)file_data, offsetof(ve_tls_checkpoint_file, checksum))) {
        return -1;
    }
    state->acked_log_id = file_data->acked_log_id;
    state->replay_begin_log_id = file_data->replay_begin_log_id;
    state->replay_begin_segment_id = file_data->replay_begin_segment_id;
    state->replay_begin_offset = file_data->replay_begin_offset;
    state->last_segment_id = file_data->last_segment_id;
    return 0;
}

int ve_tls_checkpoint_save_ranges(ve_tls_platform * platform, const char * path,
    const ve_tls_checkpoint_state * state, const ve_tls_checkpoint_range * ranges, size_t count) {
    ve_tls_checkpoint_file file_data;
    unsigned char header[VE_TLS_CHECKPOINT_RANGE_HEADER_SIZE] = {0};
    unsigned char record[VE_TLS_CHECKPOINT_RANGE_RECORD_SIZE];
    char tmp_path[VE_TLS_CHECKPOINT_PATH_CAPACITY];
    char parent[VE_TLS_CHECKPOINT_PATH_CAPACITY];
    ve_tls_file * file;
    ve_tls_file * parent_file = NULL;
    int rc = -1;
    int64_t previous_end;
    uint32_t crc;
    if (!platform || !path || !state || (count && !ranges) ||
        count > SIZE_MAX / sizeof(*ranges) ||
        count > (SIZE_MAX - sizeof(file_data) - sizeof(header)) / sizeof(record) ||
        checkpoint_paths(path, tmp_path, parent) != 0) {
        return -1;
    }
    previous_end = state->acked_log_id;
    for (size_t i = 0; i < count; i++) {
        if (!range_valid(&ranges[i], previous_end)) return -1;
        previous_end = ranges[i].end_id;
    }
    memset(&file_data, 0, sizeof(file_data));
    file_data.magic = VE_TLS_CHECKPOINT_MAGIC;
    file_data.version = VE_TLS_CHECKPOINT_VERSION;
    file_data.acked_log_id = state->acked_log_id;
    file_data.replay_begin_log_id = state->replay_begin_log_id;
    file_data.replay_begin_segment_id = state->replay_begin_segment_id;
    file_data.replay_begin_offset = state->replay_begin_offset;
    file_data.last_segment_id = state->last_segment_id;
    file_data.checksum = checksum_bytes((const unsigned char *)&file_data, offsetof(ve_tls_checkpoint_file, checksum));
    if (count) {
        write_u32_le(header, VE_TLS_CHECKPOINT_RANGE_MAGIC);
        write_u32_le(header + 4, VE_TLS_CHECKPOINT_RANGE_VERSION);
        write_u64_le(header + 8, (uint64_t)count);
        crc = crc32_update(0xFFFFFFFFu, (const unsigned char *)&file_data, sizeof(file_data));
        crc = crc32_update(crc, header, 16);
        for (size_t i = 0; i < count; i++) {
            encode_range(record, &ranges[i]);
            crc = crc32_update(crc, record, sizeof(record));
        }
        write_u32_le(header + 16, crc ^ 0xFFFFFFFFu);
    }
    file = platform->file_open(tmp_path, VE_TLS_FILE_OPEN_WRONLY | VE_TLS_FILE_OPEN_CREATE | VE_TLS_FILE_OPEN_TRUNC, 0644);
    if (!file) return -1;
    if (write_full(platform, file, &file_data, sizeof(file_data)) != 0 ||
        (count && write_full(platform, file, header, sizeof(header)) != 0)) goto done;
    for (size_t i = 0; i < count; i++) {
        encode_range(record, &ranges[i]);
        if (write_full(platform, file, record, sizeof(record)) != 0) goto done;
    }
    if (platform->file_fsync(file) != 0) goto done;
    platform->file_close(file);
    file = NULL;
    parent_file = platform->file_open(parent, VE_TLS_FILE_OPEN_RDONLY, 0);
    if (!parent_file || platform->path_rename(tmp_path, path) != 0 ||
        platform->file_fsync(parent_file) != 0) goto done;
    rc = 0;
done:
    if (file) platform->file_close(file);
    if (parent_file) platform->file_close(parent_file);
    if (rc != 0) (void)platform->path_remove(tmp_path);
    return rc;
}

int ve_tls_checkpoint_save(ve_tls_platform * platform, const char * path, const ve_tls_checkpoint_state * state) {
    return ve_tls_checkpoint_save_ranges(platform, path, state, NULL, 0);
}

int ve_tls_checkpoint_load(ve_tls_platform * platform, const char * path, ve_tls_checkpoint_state * state) {
    ve_tls_checkpoint_file file_data;
    ve_tls_file * file;
    int rc;
    if (!platform || !path || !state) return -1;
    memset(state, 0, sizeof(*state));
    file = platform->file_open(path, VE_TLS_FILE_OPEN_RDONLY, 0);
    if (!file) return -1;
    rc = load_prefix(platform, file, &file_data, state);
    platform->file_close(file);
    return rc;
}

int ve_tls_checkpoint_load_ranges(ve_tls_platform * platform, const char * path,
    ve_tls_checkpoint_state * state, ve_tls_checkpoint_range ** ranges, size_t * count) {
    ve_tls_checkpoint_file file_data;
    unsigned char header[VE_TLS_CHECKPOINT_RANGE_HEADER_SIZE];
    unsigned char record[VE_TLS_CHECKPOINT_RANGE_RECORD_SIZE];
    ve_tls_file * file;
    int64_t file_size;
    uint64_t stored_count;
    int64_t previous_end;
    uint32_t crc;
    int rc = VE_TLS_CHECKPOINT_LOAD_ERROR;
    if (!platform || !path || !state || !ranges || !count) return rc;
    memset(state, 0, sizeof(*state));
    *ranges = NULL;
    *count = 0;
    file = platform->file_open(path, VE_TLS_FILE_OPEN_RDONLY, 0);
    if (!file) return rc;
    if (load_prefix(platform, file, &file_data, state) != 0) goto done;
    file_size = platform->file_seek(file, 0, VE_TLS_FILE_SEEK_END);
    if (file_size < 0 || platform->file_seek(file, (int64_t)sizeof(file_data), VE_TLS_FILE_SEEK_SET) < 0) goto done;
    if ((uint64_t)file_size == sizeof(file_data)) {
        rc = VE_TLS_CHECKPOINT_LOAD_OK;
        goto done;
    }
    rc = VE_TLS_CHECKPOINT_LOAD_EXT_INVALID;
    if ((uint64_t)file_size < sizeof(file_data) + sizeof(header)) goto done;
    rc = VE_TLS_CHECKPOINT_LOAD_ERROR;
    if (read_full(platform, file, header, sizeof(header)) != 0) goto done;
    rc = VE_TLS_CHECKPOINT_LOAD_EXT_INVALID;
    stored_count = read_u64_le(header + 8);
    if (read_u32_le(header) != VE_TLS_CHECKPOINT_RANGE_MAGIC ||
        read_u32_le(header + 4) != VE_TLS_CHECKPOINT_RANGE_VERSION ||
        stored_count == 0 || stored_count > SIZE_MAX / sizeof(**ranges) ||
        stored_count > (UINT64_MAX - sizeof(file_data) - sizeof(header)) / sizeof(record) ||
        (uint64_t)file_size != sizeof(file_data) + sizeof(header) + stored_count * sizeof(record)) {
        goto done;
    }
    crc = crc32_update(0xFFFFFFFFu, (const unsigned char *)&file_data, sizeof(file_data));
    crc = crc32_update(crc, header, 16);
    previous_end = state->acked_log_id;
    rc = VE_TLS_CHECKPOINT_LOAD_OOM;
    *ranges = (ve_tls_checkpoint_range *)ve_tls_malloc((size_t)stored_count * sizeof(**ranges));
    if (!*ranges) goto done;
    for (uint64_t i = 0; i < stored_count; i++) {
        uint64_t start;
        uint64_t end;
        rc = VE_TLS_CHECKPOINT_LOAD_ERROR;
        if (read_full(platform, file, record, sizeof(record)) != 0) goto done;
        crc = crc32_update(crc, record, sizeof(record));
        start = read_u64_le(record);
        end = read_u64_le(record + 8);
        rc = VE_TLS_CHECKPOINT_LOAD_EXT_INVALID;
        if (start > INT64_MAX || end > INT64_MAX) goto done;
        (*ranges)[i].start_id = (int64_t)start;
        (*ranges)[i].end_id = (int64_t)end;
        if (!range_valid(&(*ranges)[i], previous_end)) goto done;
        previous_end = (*ranges)[i].end_id;
    }
    if ((crc ^ 0xFFFFFFFFu) != read_u32_le(header + 16)) goto done;
    *count = (size_t)stored_count;
    rc = VE_TLS_CHECKPOINT_LOAD_OK;
done:
    platform->file_close(file);
    if (rc != VE_TLS_CHECKPOINT_LOAD_OK) {
        ve_tls_free(*ranges);
        *ranges = NULL;
        *count = 0;
    }
    return rc;
}
