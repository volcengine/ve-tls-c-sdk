#include "ve_tls_lease.h"

#include <stddef.h>
#include <stdatomic.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#define VE_TLS_LEASE_MAGIC 0x544C5331u
#define VE_TLS_LEASE_VERSION 1u
#define VE_TLS_LEASE_TEMP_ATTEMPTS 256u
#define VE_TLS_LEASE_GUARD_PATH_SIZE 4096u

static _Atomic(uint64_t) g_lease_temp_sequence = 1;

int ve_tls_lease_create_owner(char * out, size_t out_capacity, int32_t * pid_out) {
    static const char prefix[] = "ve-tls-";
    static const char hex[] = "0123456789abcdef";
    unsigned char nonce[16];
    size_t offset = 0;
    size_t i;
    int fd = -1;
    pid_t process_id;

    if (out && out_capacity > 0) {
        out[0] = '\0';
    }
    if (pid_out) {
        *pid_out = 0;
    }
    if (!out || out_capacity < sizeof(prefix) - 1 + sizeof(nonce) * 2 + 1 || !pid_out) {
        return -1;
    }
#if !defined(O_CLOEXEC) || !defined(O_NOFOLLOW)
    return -1;
#else
    do {
        fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    } while (fd < 0 && errno == EINTR);
    if (fd < 0) {
        return -1;
    }
    while (offset < sizeof(nonce)) {
        ssize_t read_size = read(fd, nonce + offset, sizeof(nonce) - offset);
        if (read_size < 0 && errno == EINTR) {
            continue;
        }
        if (read_size <= 0) {
            (void)close(fd);
            return -1;
        }
        offset += (size_t)read_size;
    }
    if (close(fd) != 0) {
        return -1;
    }
    fd = -1;
    process_id = getpid();
    if (process_id <= 0 || (uint64_t)process_id > INT32_MAX) {
        return -1;
    }
    memcpy(out, prefix, sizeof(prefix) - 1);
    for (i = 0; i < sizeof(nonce); i++) {
        out[sizeof(prefix) - 1 + i * 2] = hex[nonce[i] >> 4];
        out[sizeof(prefix) - 1 + i * 2 + 1] = hex[nonce[i] & 0x0f];
    }
    out[sizeof(prefix) - 1 + sizeof(nonce) * 2] = '\0';
    *pid_out = (int32_t)process_id;
    return 0;
#endif
}

typedef struct {
    uint32_t magic;
    uint32_t version;
    ve_tls_lease_state state;
    uint32_t checksum;
} ve_tls_lease_file;

static int lease_guard_path(
    const char * lease_path,
    char * lock_path,
    size_t lock_path_size
) {
    static const char suffix[] = ".lock";
    const size_t suffix_size = sizeof(suffix) - 1;
    size_t path_size = 0;

    if (!lease_path || !lock_path || lock_path_size <= suffix_size + 1) {
        return -1;
    }
    while (path_size < lock_path_size - suffix_size - 1 && lease_path[path_size] != '\0') {
        path_size++;
    }
    if (path_size == 0 || lease_path[path_size] != '\0') {
        return -1;
    }
    memcpy(lock_path, lease_path, path_size);
    memcpy(lock_path + path_size, suffix, suffix_size + 1);
    return 0;
}

int ve_tls_lease_guard_lock(int fd, int wait) {
    int flock_flags;
    if (fd < 0 || (wait != 0 && wait != 1)) {
        return -1;
    }
    flock_flags = LOCK_EX | (wait ? 0 : LOCK_NB);
    do {
        if (flock(fd, flock_flags) == 0) {
            return 0;
        }
    } while (errno == EINTR);
    return -1;
}

int ve_tls_lease_guard_unlock(int fd) {
    int rc;
    if (fd < 0) {
        return -1;
    }
    do {
        rc = flock(fd, LOCK_UN);
    } while (rc != 0 && errno == EINTR);
    return rc == 0 ? 0 : -1;
}

void ve_tls_lease_guard_close(int fd) {
    if (fd >= 0) {
        (void)close(fd);
    }
}

int ve_tls_lease_guard_enter(const char * lease_path, int wait, int * fd_out) {
    char lock_path[VE_TLS_LEASE_GUARD_PATH_SIZE];
    struct stat st;
    int fd = -1;
    int stat_rc;

    if (fd_out) {
        *fd_out = -1;
    }
    if (!fd_out || (wait != 0 && wait != 1) ||
        lease_guard_path(lease_path, lock_path, sizeof(lock_path)) != 0) {
        return -1;
    }
#if !defined(O_CLOEXEC) || !defined(O_NOFOLLOW)
    return -1;
#else
    do {
        fd = open(lock_path, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    } while (fd < 0 && errno == EINTR);
    if (fd < 0) {
        return -1;
    }

    do {
        stat_rc = fstat(fd, &st);
    } while (stat_rc != 0 && errno == EINTR);
    if (stat_rc != 0 || !S_ISREG(st.st_mode)) {
        (void)close(fd);
        return -1;
    }

    if (ve_tls_lease_guard_lock(fd, wait) != 0) {
        ve_tls_lease_guard_close(fd);
        return -1;
    }
    *fd_out = fd;
    return 0;
#endif
}

void ve_tls_lease_guard_leave(int fd) {
    if (fd < 0) {
        return;
    }
    (void)ve_tls_lease_guard_unlock(fd);
    ve_tls_lease_guard_close(fd);
}

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

static int lease_is_stale(int64_t now_ms, int64_t heartbeat_ms, int64_t timeout_ms) {
    if (now_ms < heartbeat_ms) {
        return 0;
    }
    if (timeout_ms < 0) {
        return 1;
    }
    return (uint64_t)now_ms - (uint64_t)heartbeat_ms > (uint64_t)timeout_ms;
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

int ve_tls_lease_validate_locked(
    ve_tls_platform * platform,
    const char * path,
    const ve_tls_lease_state * state
) {
    ve_tls_lease_state current;
    if (!platform || !path || !state) {
        return -1;
    }
    if (ve_tls_lease_load(platform, path, &current) != 0) {
        return -1;
    }
    if (current.fencing_token != state->fencing_token ||
        current.owner_pid != state->owner_pid ||
        current.acquire_time_ms != state->acquire_time_ms ||
        memcmp(current.owner_id, state->owner_id, sizeof(current.owner_id)) != 0 ||
        memcmp(
            current.owner_process_name,
            state->owner_process_name,
            sizeof(current.owner_process_name)) != 0) {
        return -1;
    }
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

int ve_tls_lease_acquire_locked(
    const ve_tls_lease_options * options,
    ve_tls_lease_state * state
) {
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
        if (!lease_is_stale(
                options->now_ms,
                current.last_heartbeat_ms,
                options->lease_timeout_ms)) {
            return -1;
        }
        if (options->mode != VE_TLS_LEASE_OPEN_TAKEOVER_IF_STALE) {
            return -1;
        }
        if (current.fencing_token == UINT64_MAX) {
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

int ve_tls_lease_heartbeat_locked(
    const ve_tls_lease_options * options,
    ve_tls_lease_state * state
) {
    ve_tls_lease_state next;
    if (!options || !options->platform || !options->lease_path || !state) {
        return -1;
    }
    if (ve_tls_lease_validate_locked(options->platform, options->lease_path, state) != 0) {
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

int ve_tls_lease_acquire(const ve_tls_lease_options * options, ve_tls_lease_state * state) {
    int guard_fd = -1;
    int rc;
    if (!options || !options->platform || !options->lease_path || !state) {
        return -1;
    }
    memset(state, 0, sizeof(*state));
    if (ve_tls_lease_guard_enter(options->lease_path, 0, &guard_fd) != 0) {
        return -1;
    }
    rc = ve_tls_lease_acquire_locked(options, state);
    ve_tls_lease_guard_leave(guard_fd);
    return rc;
}

int ve_tls_lease_heartbeat(const ve_tls_lease_options * options, ve_tls_lease_state * state) {
    int guard_fd = -1;
    int rc;
    if (!options || !options->platform || !options->lease_path || !state) {
        return -1;
    }
    if (ve_tls_lease_guard_enter(options->lease_path, 1, &guard_fd) != 0) {
        return -1;
    }
    rc = ve_tls_lease_heartbeat_locked(options, state);
    ve_tls_lease_guard_leave(guard_fd);
    return rc;
}

int ve_tls_lease_release_owned_locked(
    ve_tls_platform * platform,
    const char * path,
    const ve_tls_lease_state * state
) {
    if (!platform || !path || !state || !platform->path_remove) {
        return -1;
    }
    if (ve_tls_lease_validate_locked(platform, path, state) != 0) {
        return -1;
    }
    return platform->path_remove(path);
}

int ve_tls_lease_release(ve_tls_platform * platform, const char * lease_path) {
    if (!platform || !lease_path || !platform->path_remove) {
        return -1;
    }
    return platform->path_remove(lease_path);
}
