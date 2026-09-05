#include "ve_tls_lease.h"

#include <stddef.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

#define VE_TLS_LEASE_MAGIC 0x544C5331u
#define VE_TLS_LEASE_VERSION 1u
#define VE_TLS_LEASE_TEMP_ATTEMPTS 256u

static _Atomic(uint64_t) g_lease_temp_sequence = 1;

typedef struct {
    uint32_t magic;
    uint32_t version;
    ve_tls_lease_state state;
    uint32_t checksum;
} ve_tls_lease_file;

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

static void copy_cstr(char * dst, size_t dst_size, const char * src) {
    size_t n;
    if (!dst || dst_size == 0) {
        return;
    }
    if (!src) {
        dst[0] = 0;
        return;
    }
    n = strlen(src);
    if (n >= dst_size) {
        n = dst_size - 1;
    }
    memcpy(dst, src, n);
    dst[n] = 0;
}

int ve_tls_lease_load(ve_tls_platform * platform, const char * path, ve_tls_lease_state * state) {
    ve_tls_lease_file file_data;
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
    if (file_data.magic != VE_TLS_LEASE_MAGIC || file_data.version != VE_TLS_LEASE_VERSION) {
        return -1;
    }
    if (file_data.checksum != checksum_bytes((const unsigned char *)&file_data, offsetof(ve_tls_lease_file, checksum))) {
        return -1;
    }
    *state = file_data.state;
    return 0;
}

static int lease_file_save(
    ve_tls_platform * platform,
    const char * path,
    const ve_tls_lease_state * state,
    int sync_file
) {
    ve_tls_lease_file file_data;
    ve_tls_file * file = NULL;
    char temp_path[768];
    int rc = -1;
    if (!platform || !path || !state || !platform->path_rename || !platform->path_remove) {
        return -1;
    }
    memset(&file_data, 0, sizeof(file_data));
    file_data.magic = VE_TLS_LEASE_MAGIC;
    file_data.version = VE_TLS_LEASE_VERSION;
    file_data.state = *state;
    file_data.checksum = checksum_bytes((const unsigned char *)&file_data, offsetof(ve_tls_lease_file, checksum));
    for (uint32_t attempt = 0; attempt < VE_TLS_LEASE_TEMP_ATTEMPTS; attempt++) {
        uint64_t sequence = atomic_fetch_add_explicit(
            &g_lease_temp_sequence,
            1,
            memory_order_relaxed);
        int n = snprintf(
            temp_path,
            sizeof(temp_path),
            "%s.tmp.%016llx.%016llx",
            path,
            (unsigned long long)state->last_heartbeat_ms,
            (unsigned long long)sequence);
        if (n < 0 || (size_t)n >= sizeof(temp_path)) {
            return -1;
        }
        file = platform->file_open(
            temp_path,
            VE_TLS_FILE_OPEN_WRONLY | VE_TLS_FILE_OPEN_CREATE | VE_TLS_FILE_OPEN_EXCL,
            0600);
        if (file) {
            break;
        }
    }
    if (!file) {
        return -1;
    }
    if (write_full(platform, file, &file_data, sizeof(file_data)) != 0 ||
        (sync_file && platform->file_fsync(file) != 0)) {
        goto done;
    }
    rc = 0;

done:
    platform->file_close(file);
    if (rc != 0 || platform->path_rename(temp_path, path) != 0) {
        (void)platform->path_remove(temp_path);
        return -1;
    }
    return 0;
}

int ve_tls_lease_acquire(const ve_tls_lease_options * options, ve_tls_lease_state * state) {
    ve_tls_lease_state current;
    ve_tls_path_info info;
    if (!options || !options->platform || !options->lease_path || !state) {
        return -1;
    }
    memset(state, 0, sizeof(*state));
    memset(&info, 0, sizeof(info));
    if (!options->platform->path_stat ||
        options->platform->path_stat(options->lease_path, &info) != 0) {
        return -1;
    }
    if (info.exists) {
        if (ve_tls_lease_load(options->platform, options->lease_path, &current) != 0) {
            return -1;
        }
        if (options->now_ms - current.last_heartbeat_ms <= options->lease_timeout_ms) {
            return -1;
        }
        if (options->mode != VE_TLS_LEASE_OPEN_TAKEOVER_IF_STALE) {
            return -1;
        }
        *state = current;
        state->fencing_token++;
    } else {
        state->fencing_token = 1;
    }
    copy_cstr(state->owner_id, sizeof(state->owner_id), options->owner_id);
    copy_cstr(state->owner_process_name, sizeof(state->owner_process_name), options->owner_process_name);
    state->owner_pid = options->owner_pid;
    state->acquire_time_ms = options->now_ms;
    state->last_heartbeat_ms = options->now_ms;
    return lease_file_save(options->platform, options->lease_path, state, 1);
}

int ve_tls_lease_heartbeat(const ve_tls_lease_options * options, ve_tls_lease_state * state) {
    ve_tls_lease_state next;
    if (!options || !options->platform || !options->lease_path || !state) {
        return -1;
    }
    next = *state;
    next.last_heartbeat_ms = options->now_ms;
    if (lease_file_save(
            options->platform,
            options->lease_path,
            &next,
            options->sync_on_heartbeat ? 1 : 0) != 0) {
        return -1;
    }
    *state = next;
    return 0;
}

int ve_tls_lease_release(ve_tls_platform * platform, const char * lease_path) {
    if (!platform || !lease_path || !platform->path_remove) {
        return -1;
    }
    return platform->path_remove(lease_path);
}
