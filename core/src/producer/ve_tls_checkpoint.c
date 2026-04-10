#include "ve_tls_checkpoint.h"

#include <stddef.h>
#include <string.h>

#define VE_TLS_CHECKPOINT_MAGIC 0x54435031u
#define VE_TLS_CHECKPOINT_VERSION 1u

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

int ve_tls_checkpoint_save(ve_tls_platform * platform, const char * path, const ve_tls_checkpoint_state * state) {
    ve_tls_checkpoint_file file_data;
    ve_tls_file * file;
    if (!platform || !path || !state) {
        return -1;
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
    file = platform->file_open(path, VE_TLS_FILE_OPEN_WRONLY | VE_TLS_FILE_OPEN_CREATE | VE_TLS_FILE_OPEN_TRUNC, 0644);
    if (!file) {
        return -1;
    }
    if (write_full(platform, file, &file_data, sizeof(file_data)) != 0 || platform->file_fsync(file) != 0) {
        platform->file_close(file);
        return -1;
    }
    platform->file_close(file);
    return 0;
}

int ve_tls_checkpoint_load(ve_tls_platform * platform, const char * path, ve_tls_checkpoint_state * state) {
    ve_tls_checkpoint_file file_data;
    ve_tls_file * file;
    if (!platform || !path || !state) {
        return -1;
    }
    memset(state, 0, sizeof(*state));
    file = platform->file_open(path, VE_TLS_FILE_OPEN_RDONLY, 0);
    if (!file) {
        return -1;
    }
    if (read_full(platform, file, &file_data, sizeof(file_data)) != 0) {
        platform->file_close(file);
        return -1;
    }
    platform->file_close(file);
    if (file_data.magic != VE_TLS_CHECKPOINT_MAGIC || file_data.version != VE_TLS_CHECKPOINT_VERSION) {
        return -1;
    }
    if (file_data.checksum != checksum_bytes((const unsigned char *)&file_data, offsetof(ve_tls_checkpoint_file, checksum))) {
        return -1;
    }
    state->acked_log_id = file_data.acked_log_id;
    state->replay_begin_log_id = file_data.replay_begin_log_id;
    state->replay_begin_segment_id = file_data.replay_begin_segment_id;
    state->replay_begin_offset = file_data.replay_begin_offset;
    state->last_segment_id = file_data.last_segment_id;
    return 0;
}
