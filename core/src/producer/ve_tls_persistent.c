#include "ve_tls_persistent.h"

#include "ve_tls_alloc.h"
#include "ve_tls_persistent_format.h"

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

#define VE_TLS_PERSISTENT_OVERFLOW_BLOCK 1
#define VE_TLS_PERSISTENT_OVERFLOW_DROP_OLDEST_UNACKED 2
#define VE_TLS_PERSISTENT_OVERFLOW_DROP_NEWEST_SAMPLE 3
#define VE_TLS_PERSISTENT_CHECKPOINT_SAVE_WINDOW_MS 100
#define VE_TLS_PERSISTENT_CHECKPOINT_ACK_DELTA_THRESHOLD 64
#define VE_TLS_PERSISTENT_DEFAULT_HIGH_WATERMARK_PCT 85
#define VE_TLS_PERSISTENT_DEFAULT_LOW_WATERMARK_PCT 70
#define VE_TLS_PERSISTENT_MANIFEST_VERSION_CURRENT 2
#define VE_TLS_PERSISTENT_MANIFEST_MAX_BYTES 4096

static uint64_t add_u64_saturating(uint64_t left, uint64_t right) {
    return right > UINT64_MAX - left ? UINT64_MAX : left + right;
}

static int path_join(char * out, size_t out_size, const char * dir, const char * name) {
    if (!out || out_size == 0 || !dir || !name) {
        return -1;
    }
    if ((size_t)snprintf(out, out_size, "%s/%s", dir, name) >= out_size) {
        return -1;
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

static int64_t persistent_now_ms(ve_tls_persistent * persistent) {
    if (!persistent || !persistent->platform || !persistent->platform->time_ms) {
        return 0;
    }
    return persistent->platform->time_ms();
}

static void persistent_heartbeat_lock(ve_tls_persistent * persistent) {
    if (persistent && persistent->heartbeat_mutex && persistent->platform && persistent->platform->mutex_lock) {
        persistent->platform->mutex_lock(persistent->heartbeat_mutex);
    }
}

static void persistent_heartbeat_unlock(ve_tls_persistent * persistent) {
    if (persistent && persistent->heartbeat_mutex && persistent->platform && persistent->platform->mutex_unlock) {
        persistent->platform->mutex_unlock(persistent->heartbeat_mutex);
    }
}

static int write_manifest_full(ve_tls_platform * platform, ve_tls_file * file, const void * data, size_t size) {
    size_t offset = 0;
    while (offset < size) {
        int64_t written = platform->file_write(file, (const unsigned char *)data + offset, size - offset);
        if (written <= 0) {
            return -1;
        }
        offset += (size_t)written;
    }
    return 0;
}

static int write_manifest(const ve_tls_persistent_options * options) {
    char path[640];
    char tmp_path[640];
    char body[512];
    ve_tls_file * file;
    size_t body_len;
    int rc = -1;
    if (!options || !options->platform ||
        path_join(path, sizeof(path), options->dir_path, "manifest") != 0 ||
        path_join(tmp_path, sizeof(tmp_path), options->dir_path, "manifest.tmp") != 0) {
        return -1;
    }
    body_len = (size_t)snprintf(
        body,
        sizeof(body),
        "format_version=%d\ninstance_id=%s\nsegment_max_bytes=%llu\nsegment_max_records=%llu\nmax_bytes=%llu\nmax_records=%llu\nmax_segments=%u\ntarget_policy=current_target\n",
        VE_TLS_PERSISTENT_MANIFEST_VERSION_CURRENT,
        options->instance_id ? options->instance_id : "",
        (unsigned long long)options->segment_max_bytes,
        (unsigned long long)options->segment_max_records,
        (unsigned long long)options->max_bytes,
        (unsigned long long)options->max_records,
        options->max_segments
    );
    if (body_len >= sizeof(body)) {
        return -1;
    }
    file = options->platform->file_open(tmp_path, VE_TLS_FILE_OPEN_WRONLY | VE_TLS_FILE_OPEN_CREATE | VE_TLS_FILE_OPEN_TRUNC, 0644);
    if (!file) {
        return -1;
    }
    if (write_manifest_full(options->platform, file, body, body_len) == 0 &&
        options->platform->file_fsync(file) == 0) {
        rc = 0;
    }
    options->platform->file_close(file);
    if (rc != 0 || options->platform->path_rename(tmp_path, path) != 0) {
        (void)options->platform->path_remove(tmp_path);
        return -1;
    }
    return 0;
}

static int consume_manifest_line(
    const char * body,
    size_t body_size,
    size_t * offset,
    const char * key,
    const char ** value,
    size_t * value_len
) {
    size_t key_len;
    size_t line_end;
    size_t value_start;
    if (!body || !offset || !key || !value || !value_len || *offset >= body_size) {
        return -1;
    }
    key_len = strlen(key);
    line_end = *offset;
    while (line_end < body_size && body[line_end] != '\n') {
        line_end++;
    }
    if (line_end >= body_size || line_end - *offset < key_len + 1 ||
        memcmp(body + *offset, key, key_len) != 0 || body[*offset + key_len] != '=') {
        return -1;
    }
    value_start = *offset + key_len + 1;
    *value = body + value_start;
    *value_len = line_end - value_start;
    *offset = line_end + 1;
    return 0;
}

static int manifest_value_is_u64(const char * value, size_t value_len) {
    uint64_t parsed = 0;
    if (!value || value_len == 0) {
        return 0;
    }
    for (size_t i = 0; i < value_len; i++) {
        if (value[i] < '0' || value[i] > '9') {
            return 0;
        }
        uint64_t digit = (uint64_t)(value[i] - '0');
        if (parsed > (UINT64_MAX - digit) / 10) {
            return 0;
        }
        parsed = parsed * 10 + digit;
    }
    return 1;
}

static int validate_manifest_body(const char * body, size_t body_size, int * out_version) {
    static const char * numeric_keys[] = {
        "segment_max_bytes",
        "segment_max_records",
        "max_bytes",
        "max_records",
        "max_segments"
    };
    const char * value;
    size_t value_len;
    size_t offset = 0;
    int version;
    if (!body || body_size == 0 || !out_version ||
        consume_manifest_line(body, body_size, &offset, "format_version", &value, &value_len) != 0) {
        return -1;
    }
    if (value_len == 1 && value[0] == '1') {
        version = 1;
    } else if (value_len == 1 && value[0] == '2') {
        version = 2;
    } else {
        return -1;
    }
    if (consume_manifest_line(body, body_size, &offset, "instance_id", &value, &value_len) != 0) {
        return -1;
    }
    if (memchr(value, 0, value_len) != NULL) {
        return -1;
    }
    for (size_t i = 0; i < sizeof(numeric_keys) / sizeof(numeric_keys[0]); i++) {
        if (consume_manifest_line(body, body_size, &offset, numeric_keys[i], &value, &value_len) != 0 ||
            !manifest_value_is_u64(value, value_len)) {
            return -1;
        }
    }
    if (version == VE_TLS_PERSISTENT_MANIFEST_VERSION_CURRENT) {
        if (consume_manifest_line(body, body_size, &offset, "target_policy", &value, &value_len) != 0 ||
            value_len != strlen("current_target") ||
            memcmp(value, "current_target", value_len) != 0) {
            return -1;
        }
    }
    if (offset != body_size) {
        return -1;
    }
    *out_version = version;
    return 0;
}

static int read_manifest_version(const ve_tls_persistent_options * options, int * out_version, int * out_exists) {
    char path[640];
    char body[VE_TLS_PERSISTENT_MANIFEST_MAX_BYTES];
    ve_tls_path_info info;
    ve_tls_file * file;
    size_t offset = 0;
    if (!options || !options->platform || !out_version || !out_exists ||
        path_join(path, sizeof(path), options->dir_path, "manifest") != 0 ||
        options->platform->path_stat(path, &info) != 0) {
        return -1;
    }
    *out_exists = info.exists ? 1 : 0;
    *out_version = 0;
    if (!info.exists) {
        return 0;
    }
    if (info.size == 0 || info.size >= sizeof(body)) {
        return -1;
    }
    file = options->platform->file_open(path, VE_TLS_FILE_OPEN_RDONLY, 0);
    if (!file) {
        return -1;
    }
    while (offset < (size_t)info.size) {
        int64_t n = options->platform->file_read(file, body + offset, (size_t)info.size - offset);
        if (n <= 0) {
            options->platform->file_close(file);
            return -1;
        }
        offset += (size_t)n;
    }
    options->platform->file_close(file);
    return validate_manifest_body(body, offset, out_version);
}

static int ensure_manifest(const ve_tls_persistent_options * options) {
    int version = 0;
    int exists = 0;
    if (read_manifest_version(options, &version, &exists) != 0) {
        return -1;
    }
    if (!exists || version == 1) {
        return write_manifest(options);
    }
    return version == VE_TLS_PERSISTENT_MANIFEST_VERSION_CURRENT ? 0 : -1;
}

static void clear_segment_meta(ve_tls_persistent_segment_meta * meta) {
    if (!meta) {
        return;
    }
    memset(meta, 0, sizeof(*meta));
}

static int ensure_segment_meta_capacity(ve_tls_persistent * persistent, uint32_t segment_id) {
    if (!persistent) {
        return -1;
    }
    if (segment_id < persistent->segment_meta_cap) {
        return 0;
    }
    uint32_t next_cap = persistent->segment_meta_cap ? persistent->segment_meta_cap : 4;
    while (next_cap <= segment_id) {
        if (next_cap > UINT32_MAX / 2) {
            next_cap = segment_id + 1;
            break;
        }
        next_cap *= 2;
    }
    ve_tls_persistent_segment_meta * next = (ve_tls_persistent_segment_meta *)ve_tls_calloc(next_cap, sizeof(*next));
    if (!next) {
        return -1;
    }
    if (persistent->segment_meta && persistent->segment_meta_cap > 0) {
        memcpy(next, persistent->segment_meta, persistent->segment_meta_cap * sizeof(*next));
    }
    ve_tls_free(persistent->segment_meta);
    persistent->segment_meta = next;
    persistent->segment_meta_cap = next_cap;
    return 0;
}

static ve_tls_persistent_segment_meta * get_segment_meta_slot(ve_tls_persistent * persistent, uint32_t segment_id) {
    if (!persistent || segment_id >= persistent->segment_meta_cap) {
        return NULL;
    }
    return &persistent->segment_meta[segment_id];
}

static int refresh_segment_meta(ve_tls_persistent * persistent, uint32_t segment_id) {
    char path[640];
    ve_tls_path_info info;
    ve_tls_persistent_segment_meta * meta;
    if (!persistent || !persistent->platform) {
        return -1;
    }
    if (ensure_segment_meta_capacity(persistent, segment_id) != 0) {
        return -1;
    }
    meta = get_segment_meta_slot(persistent, segment_id);
    if (!meta) {
        return -1;
    }
    clear_segment_meta(meta);
    if (ve_tls_segment_store_get_segment_path(&persistent->store, segment_id, path, sizeof(path)) != 0) {
        return -1;
    }
    if (persistent->platform->path_stat(path, &info) != 0) {
        return -1;
    }
    if (!info.exists) {
        return 0;
    }
    if (ve_tls_segment_store_scan_segment(&persistent->store, segment_id, &meta->size, &meta->records, &meta->max_log_id) != 0) {
        return -1;
    }
    meta->exists = 1;
    return 0;
}

static int refresh_usage(ve_tls_persistent * persistent) {
    uint64_t bytes = 0;
    uint64_t records = 0;
    uint32_t segments = 0;
    if (!persistent) {
        return -1;
    }
    for (uint32_t segment_id = 1; segment_id <= persistent->store.active_segment_id; segment_id++) {
        ve_tls_persistent_segment_meta * meta;
        if (refresh_segment_meta(persistent, segment_id) != 0) {
            return -1;
        }
        meta = get_segment_meta_slot(persistent, segment_id);
        if (!meta || !meta->exists) {
            continue;
        }
        bytes += meta->size;
        records += meta->records;
        segments++;
    }
    persistent->current_bytes = bytes;
    persistent->current_records = records;
    persistent->current_segments = segments;
    return 0;
}

static void advance_reclaim_cursor(ve_tls_persistent * persistent) {
    uint32_t cursor;
    if (!persistent) {
        return;
    }
    cursor = persistent->next_reclaim_segment_id > 0 ? persistent->next_reclaim_segment_id : 1;
    while (cursor < persistent->store.active_segment_id) {
        ve_tls_persistent_segment_meta * meta;
        if (persistent->checkpoint.replay_begin_segment_id != 0 &&
            cursor == persistent->checkpoint.replay_begin_segment_id) {
            break;
        }
        meta = get_segment_meta_slot(persistent, cursor);
        if (meta && meta->exists) {
            break;
        }
        cursor++;
    }
    persistent->next_reclaim_segment_id = cursor;
}

static uint64_t percentage_floor(uint64_t max, int32_t pct) {
    uint64_t quotient = max / 100;
    uint64_t remainder = max % 100;
    return quotient * (uint64_t)pct + (remainder * (uint64_t)pct) / 100;
}

static int is_soft_limit_exceeded(uint64_t current, uint64_t max, int32_t pct) {
    uint64_t floor;
    uint64_t remainder_product;
    if (max == 0 || pct <= 0 || pct > 100) {
        return 0;
    }
    floor = percentage_floor(max, pct);
    remainder_product = (max % 100) * (uint64_t)pct;
    return current >= floor + (remainder_product % 100 != 0 ? 1 : 0);
}

static int is_soft_limit_above(uint64_t current, uint64_t max, int32_t pct) {
    uint64_t floor;
    if (max == 0 || pct <= 0 || pct > 100) {
        return 0;
    }
    floor = percentage_floor(max, pct);
    return floor != UINT64_MAX && current > floor;
}

static int validate_current_lease_locked(ve_tls_persistent * persistent) {
    ve_tls_lease_state current;
    if (!persistent || !persistent->platform) {
        return -1;
    }
    if (ve_tls_lease_load(persistent->platform, persistent->lease_path, &current) != 0) {
        return -1;
    }
    if (current.fencing_token != persistent->lease.fencing_token ||
        current.owner_pid != persistent->owner_pid ||
        strcmp(current.owner_id, persistent->owner_id) != 0 ||
        strcmp(current.owner_process_name, persistent->owner_process_name) != 0) {
        return -1;
    }
    return 0;
}

static int validate_current_lease(ve_tls_persistent * persistent) {
    int rc;
    if (!persistent || !persistent->platform) {
        return -1;
    }
    persistent_heartbeat_lock(persistent);
    rc = validate_current_lease_locked(persistent);
    persistent_heartbeat_unlock(persistent);
    return rc;
}

static int validate_current_lease_if_needed_locked(ve_tls_persistent * persistent) {
    int64_t now_ms;
    if (!persistent) {
        return -1;
    }
    if (persistent->heartbeat_interval_ms <= 0 ||
        persistent->lease_timeout_ms <= 0 ||
        persistent->heartbeat_interval_ms >= persistent->lease_timeout_ms) {
        return validate_current_lease_locked(persistent);
    }
    now_ms = persistent_now_ms(persistent);
    if (now_ms <= 0 || atomic_load_explicit(&persistent->next_heartbeat_ms, memory_order_relaxed) <= 0 ||
        now_ms >= atomic_load_explicit(&persistent->next_heartbeat_ms, memory_order_relaxed)) {
        return validate_current_lease_locked(persistent);
    }
    return 0;
}

static int ve_tls_persistent_heartbeat_if_due_locked(ve_tls_persistent * persistent, int force) {
    ve_tls_lease_options options;
    int64_t now_ms;
    now_ms = persistent_now_ms(persistent);
    if (!force && persistent->heartbeat_interval_ms > 0 && now_ms > 0 &&
        now_ms < atomic_load_explicit(&persistent->next_heartbeat_ms, memory_order_relaxed)) {
        return 0;
    }
    if (validate_current_lease_locked(persistent) != 0) {
        return -1;
    }
    memset(&options, 0, sizeof(options));
    options.platform = persistent->platform;
    options.lease_path = persistent->lease_path;
    options.owner_id = persistent->owner_id;
    options.owner_pid = persistent->owner_pid;
    options.owner_process_name = persistent->owner_process_name;
    options.now_ms = now_ms;
    options.lease_timeout_ms = persistent->lease_timeout_ms;
    options.mode = persistent->open_mode;
    if (ve_tls_lease_heartbeat(&options, &persistent->lease) != 0) {
        return -1;
    }
    if (persistent->heartbeat_interval_ms > 0 && now_ms > 0) {
        atomic_store_explicit(
            &persistent->next_heartbeat_ms,
            now_ms + persistent->heartbeat_interval_ms,
            memory_order_relaxed);
    } else {
        atomic_store_explicit(&persistent->next_heartbeat_ms, now_ms, memory_order_relaxed);
    }
    return 0;
}

static int persistent_heartbeat_and_validate_if_needed(ve_tls_persistent * persistent, int force) {
    int rc;
    if (!persistent || !persistent->platform) {
        return -1;
    }
    persistent_heartbeat_lock(persistent);
    rc = ve_tls_persistent_heartbeat_if_due_locked(persistent, force);
    if (rc == 0) {
        rc = validate_current_lease_if_needed_locked(persistent);
    }
    persistent_heartbeat_unlock(persistent);
    return rc;
}

int ve_tls_persistent_heartbeat_if_due(ve_tls_persistent * persistent, int force) {
    int rc;
    if (!persistent || !persistent->platform) {
        return -1;
    }
    persistent_heartbeat_lock(persistent);
    rc = ve_tls_persistent_heartbeat_if_due_locked(persistent, force);
    persistent_heartbeat_unlock(persistent);
    return rc;
}

static int remove_segment(
    ve_tls_persistent * persistent,
    uint32_t segment_id,
    ve_tls_persistent_segment_meta * meta,
    uint64_t * removed_bytes,
    uint64_t * removed_records
) {
    char path[640];
    uint64_t segment_bytes;
    uint64_t segment_records;
    if (!persistent || !persistent->platform || !meta || !meta->exists) {
        return -1;
    }
    if (ve_tls_segment_store_get_segment_path(&persistent->store, segment_id, path, sizeof(path)) != 0 ||
        persistent->platform->path_remove(path) != 0) {
        return -1;
    }
    segment_bytes = meta->size;
    segment_records = meta->records;
    if (persistent->current_bytes >= segment_bytes) {
        persistent->current_bytes -= segment_bytes;
    } else {
        persistent->current_bytes = 0;
    }
    if (persistent->current_records >= segment_records) {
        persistent->current_records -= segment_records;
    } else {
        persistent->current_records = 0;
    }
    if (persistent->current_segments > 0) {
        persistent->current_segments--;
    }
    clear_segment_meta(meta);
    if (segment_id >= persistent->next_reclaim_segment_id) {
        persistent->next_reclaim_segment_id = segment_id < UINT32_MAX ? segment_id + 1 : UINT32_MAX;
    }
    if (removed_bytes) {
        *removed_bytes = segment_bytes;
    }
    if (removed_records) {
        *removed_records = segment_records;
    }
    return 0;
}

static int reclaim_acked_segments(ve_tls_persistent * persistent, int force) {
    int stopped_at_replay_barrier = 0;
    if (!persistent || !persistent->platform) {
        return -1;
    }
    if (!force && !persistent->reclaim_pending) {
        return 0;
    }
    if (persistent->durable_checkpoint_acked_log_id <= 0) {
        persistent->reclaim_pending = 0;
        persistent->last_reclaim_acked_log_id = persistent->durable_checkpoint_acked_log_id;
        return 0;
    }
    advance_reclaim_cursor(persistent);
    for (uint32_t segment_id = persistent->next_reclaim_segment_id;
         segment_id < persistent->store.active_segment_id;
         segment_id++) {
        ve_tls_persistent_segment_meta * meta;
        if (persistent->checkpoint.replay_begin_segment_id != 0 &&
            segment_id == persistent->checkpoint.replay_begin_segment_id) {
            stopped_at_replay_barrier = 1;
            break;
        }
        meta = get_segment_meta_slot(persistent, segment_id);
        if (!meta || !meta->exists) {
            persistent->next_reclaim_segment_id = segment_id < UINT32_MAX ? segment_id + 1 : UINT32_MAX;
            continue;
        }
        if (meta->max_log_id > 0 && meta->max_log_id <= persistent->durable_checkpoint_acked_log_id) {
            if (remove_segment(persistent, segment_id, meta, NULL, NULL) != 0) {
                return -1;
            }
            continue;
        }
        break;
    }
    advance_reclaim_cursor(persistent);
    if (stopped_at_replay_barrier) {
        /* The barrier may clear without another ACK; keep flush eligible to retry. */
        persistent->reclaim_pending = 1;
        return 0;
    }
    persistent->reclaim_pending = 0;
    persistent->last_reclaim_acked_log_id = persistent->durable_checkpoint_acked_log_id;
    return 0;
}

static int pressure_reclaim_needed(const ve_tls_persistent * persistent) {
    if (!persistent) {
        return 0;
    }
    return is_soft_limit_exceeded(persistent->current_bytes, persistent->max_bytes, persistent->high_watermark_pct) ||
           is_soft_limit_exceeded(persistent->current_records, persistent->max_records, persistent->high_watermark_pct) ||
           is_soft_limit_exceeded(persistent->current_segments, persistent->max_segments, persistent->high_watermark_pct);
}

static int pressure_above_low_watermark(const ve_tls_persistent * persistent) {
    if (!persistent) {
        return 0;
    }
    return is_soft_limit_above(persistent->current_bytes, persistent->max_bytes, persistent->low_watermark_pct) ||
           is_soft_limit_above(persistent->current_records, persistent->max_records, persistent->low_watermark_pct) ||
           is_soft_limit_above(persistent->current_segments, persistent->max_segments, persistent->low_watermark_pct);
}

static int reclaim_to_low_watermark(ve_tls_persistent * persistent) {
    if (!persistent || !persistent->platform || !pressure_reclaim_needed(persistent) ||
        persistent->durable_checkpoint_acked_log_id <= 0) {
        return 0;
    }
    advance_reclaim_cursor(persistent);
    while (pressure_above_low_watermark(persistent)) {
        uint32_t segment_id = persistent->next_reclaim_segment_id;
        ve_tls_persistent_segment_meta * meta;
        if (segment_id >= persistent->store.active_segment_id) {
            break;
        }
        if (persistent->checkpoint.replay_begin_segment_id != 0 &&
            segment_id == persistent->checkpoint.replay_begin_segment_id) {
            persistent->reclaim_pending = 1;
            break;
        }
        meta = get_segment_meta_slot(persistent, segment_id);
        if (!meta || !meta->exists) {
            persistent->next_reclaim_segment_id = segment_id < UINT32_MAX ? segment_id + 1 : UINT32_MAX;
            advance_reclaim_cursor(persistent);
            continue;
        }
        if (meta->max_log_id <= 0 || meta->max_log_id > persistent->durable_checkpoint_acked_log_id) {
            break;
        }
        if (remove_segment(persistent, segment_id, meta, NULL, NULL) != 0) {
            return -1;
        }
        advance_reclaim_cursor(persistent);
    }
    advance_reclaim_cursor(persistent);
    return 0;
}

static int save_checkpoint(ve_tls_persistent * persistent) {
    if (!persistent || !persistent->platform) {
        return -1;
    }
    return ve_tls_checkpoint_save(persistent->platform, persistent->checkpoint_path, &persistent->checkpoint);
}

static void mark_checkpoint_dirty(ve_tls_persistent * persistent) {
    int64_t now_ms;
    if (!persistent) {
        return;
    }
    now_ms = persistent_now_ms(persistent);
    if (!persistent->checkpoint_dirty) {
        persistent->checkpoint_dirty = 1;
        persistent->checkpoint_dirty_since_ms = now_ms;
    } else if (persistent->checkpoint_dirty_since_ms <= 0 && now_ms > 0) {
        persistent->checkpoint_dirty_since_ms = now_ms;
    }
}

static int checkpoint_save_now(ve_tls_persistent * persistent) {
    int64_t now_ms;
    if (!persistent) {
        return -1;
    }
    if (save_checkpoint(persistent) != 0) {
        return -1;
    }
    now_ms = persistent_now_ms(persistent);
    persistent->durable_checkpoint_acked_log_id = persistent->checkpoint.acked_log_id;
    persistent->last_checkpoint_save_ms = now_ms;
    persistent->checkpoint_dirty_since_ms = 0;
    persistent->checkpoint_dirty = 0;
    if (persistent->durable_checkpoint_acked_log_id > persistent->last_reclaim_acked_log_id) {
        persistent->reclaim_pending = 1;
    }
    return 0;
}

static int checkpoint_should_save(ve_tls_persistent * persistent, int force) {
    int64_t now_ms;
    int64_t ack_delta;
    if (!persistent || !persistent->checkpoint_dirty) {
        return 0;
    }
    if (force) {
        return 1;
    }
    ack_delta = persistent->checkpoint.acked_log_id - persistent->durable_checkpoint_acked_log_id;
    if (ack_delta >= VE_TLS_PERSISTENT_CHECKPOINT_ACK_DELTA_THRESHOLD) {
        return 1;
    }
    now_ms = persistent_now_ms(persistent);
    if (now_ms <= 0 || persistent->checkpoint_dirty_since_ms <= 0) {
        return 1;
    }
    return (now_ms - persistent->checkpoint_dirty_since_ms) >= VE_TLS_PERSISTENT_CHECKPOINT_SAVE_WINDOW_MS ? 1 : 0;
}

static int checkpoint_save_if_due(ve_tls_persistent * persistent, int force) {
    if (!checkpoint_should_save(persistent, force)) {
        return 0;
    }
    return checkpoint_save_now(persistent);
}

static int persist_drop_oldest_unacked(ve_tls_persistent * persistent) {
    if (!persistent || !persistent->platform) {
        return -1;
    }
    for (uint32_t segment_id = 1; segment_id < persistent->store.active_segment_id; segment_id++) {
        ve_tls_persistent_segment_meta * meta;
        uint64_t removed_bytes = 0;
        uint64_t removed_records = 0;
        if (persistent->checkpoint.replay_begin_segment_id != 0 &&
            segment_id == persistent->checkpoint.replay_begin_segment_id) {
            break;
        }
        meta = get_segment_meta_slot(persistent, segment_id);
        if (!meta || !meta->exists || meta->max_log_id <= 0) {
            continue;
        }
        if (meta->max_log_id > persistent->checkpoint.acked_log_id) {
            persistent->checkpoint.acked_log_id = meta->max_log_id;
            persistent->checkpoint.last_segment_id = persistent->store.active_segment_id;
            if (checkpoint_save_now(persistent) != 0) {
                return -1;
            }
        }
        if (remove_segment(persistent, segment_id, meta, &removed_bytes, &removed_records) != 0) {
            return -1;
        }
        persistent->append_dropped_records = add_u64_saturating(
            persistent->append_dropped_records, removed_records);
        persistent->append_dropped_bytes = add_u64_saturating(
            persistent->append_dropped_bytes, removed_bytes);
        advance_reclaim_cursor(persistent);
        return 1;
    }
    return 0;
}

static int would_need_new_segment(ve_tls_persistent * persistent, size_t append_size) {
    if (!persistent) {
        return 0;
    }
    return ((persistent->store.active_size > 0 &&
             (persistent->store.active_size > persistent->store.segment_max_bytes ||
              (uint64_t)append_size > persistent->store.segment_max_bytes - persistent->store.active_size)) ||
            (persistent->store.active_records > 0 && persistent->store.active_records >= persistent->store.segment_max_records)) ? 1 : 0;
}

static int is_hard_limit_exceeded(uint64_t current, uint64_t max) {
    return (max > 0 && current > max) ? 1 : 0;
}

static int should_treat_as_sampled(ve_tls_persistent * persistent, int64_t log_id) {
    int32_t n;
    if (!persistent) {
        return 0;
    }
    n = persistent->sample_every_n > 0 ? persistent->sample_every_n : 10;
    if (n <= 1) {
        return 1;
    }
    return (log_id % n) == 0 ? 1 : 0;
}

static unsigned char * persistent_get_append_buffer(ve_tls_persistent * persistent, size_t size) {
    unsigned char * next;
    if (!persistent || size == 0) {
        return NULL;
    }
    if (persistent->append_buf_cap >= size) {
        return persistent->append_buf;
    }
    next = (unsigned char *)ve_tls_realloc(persistent->append_buf, size);
    if (!next) {
        return NULL;
    }
    persistent->append_buf = next;
    persistent->append_buf_cap = size;
    return persistent->append_buf;
}

static int ensure_capacity_for_append(ve_tls_persistent * persistent, int64_t log_id, size_t record_size) {
    uint64_t next_bytes;
    uint64_t next_records;
    uint64_t next_segments;
    int need_new_segment;
    int saturated;
    if (!persistent) {
        return -1;
    }
    need_new_segment = would_need_new_segment(persistent, record_size);
    next_bytes = add_u64_saturating(persistent->current_bytes, (uint64_t)record_size);
    next_records = add_u64_saturating(persistent->current_records, 1);
    next_segments = add_u64_saturating(persistent->current_segments, need_new_segment ? 1 : 0);
    saturated = is_hard_limit_exceeded(next_bytes, persistent->max_bytes) ||
                is_hard_limit_exceeded(next_records, persistent->max_records) ||
                (persistent->max_segments > 0 && next_segments > persistent->max_segments);
    if (saturated) {
        if (reclaim_acked_segments(persistent, 1) != 0) {
            return -1;
        }
        need_new_segment = would_need_new_segment(persistent, record_size);
        next_bytes = add_u64_saturating(persistent->current_bytes, (uint64_t)record_size);
        next_records = add_u64_saturating(persistent->current_records, 1);
        next_segments = add_u64_saturating(persistent->current_segments, need_new_segment ? 1 : 0);
        saturated = is_hard_limit_exceeded(next_bytes, persistent->max_bytes) ||
                    is_hard_limit_exceeded(next_records, persistent->max_records) ||
                    (persistent->max_segments > 0 && next_segments > (uint64_t)persistent->max_segments);
    }
    if (!saturated) {
        return 0;
    }
    if (persistent->overflow_policy == VE_TLS_PERSISTENT_OVERFLOW_DROP_OLDEST_UNACKED) {
        while (saturated) {
            int drop_rc = persist_drop_oldest_unacked(persistent);
            if (drop_rc <= 0) {
                break;
            }
            need_new_segment = would_need_new_segment(persistent, record_size);
            next_bytes = add_u64_saturating(persistent->current_bytes, (uint64_t)record_size);
            next_records = add_u64_saturating(persistent->current_records, 1);
            next_segments = add_u64_saturating(persistent->current_segments, need_new_segment ? 1 : 0);
            saturated = is_hard_limit_exceeded(next_bytes, persistent->max_bytes) ||
                        is_hard_limit_exceeded(next_records, persistent->max_records) ||
                        (persistent->max_segments > 0 && next_segments > (uint64_t)persistent->max_segments);
        }
        if (!saturated) {
            return 0;
        }
    }
    if (persistent->overflow_policy == VE_TLS_PERSISTENT_OVERFLOW_DROP_NEWEST_SAMPLE) {
        return should_treat_as_sampled(persistent, log_id)
            ? VE_TLS_PERSISTENT_APPEND_BLOCKED
            : VE_TLS_PERSISTENT_APPEND_REJECT_NEW;
    }
    if (persistent->overflow_policy == VE_TLS_PERSISTENT_OVERFLOW_BLOCK) {
        return VE_TLS_PERSISTENT_APPEND_BLOCKED;
    }
    return VE_TLS_PERSISTENT_APPEND_REJECT_NEW;
}

int ve_tls_persistent_open(ve_tls_persistent * persistent, const ve_tls_persistent_options * options) {
    ve_tls_path_info info;
    ve_tls_lease_options lease_options;
    ve_tls_segment_store_options store_options;
    int32_t high_watermark_pct;
    int32_t low_watermark_pct;
    if (!persistent || !options || !options->platform || !options->dir_path || options->dir_path[0] == 0) {
        return -1;
    }
    high_watermark_pct = options->high_watermark_pct;
    low_watermark_pct = options->low_watermark_pct;
    if (high_watermark_pct == 0) {
        high_watermark_pct = VE_TLS_PERSISTENT_DEFAULT_HIGH_WATERMARK_PCT;
    }
    if (low_watermark_pct == 0) {
        low_watermark_pct = VE_TLS_PERSISTENT_DEFAULT_LOW_WATERMARK_PCT;
    }
    if (low_watermark_pct <= 0 || high_watermark_pct <= 0 ||
        high_watermark_pct > 100 || low_watermark_pct >= high_watermark_pct) {
        return -1;
    }
    VE_TLS_ALLOC_SITE("persistent_open");
    memset(persistent, 0, sizeof(*persistent));
    if (strlen(options->dir_path) >= sizeof(persistent->dir_path)) {
        return -1;
    }
    persistent->platform = options->platform;
    memcpy(persistent->dir_path, options->dir_path, strlen(options->dir_path) + 1);
    copy_cstr(persistent->owner_id, sizeof(persistent->owner_id), options->owner_id);
    copy_cstr(persistent->owner_process_name, sizeof(persistent->owner_process_name), options->owner_process_name);
    persistent->owner_pid = options->owner_pid;
    persistent->max_bytes = options->max_bytes;
    persistent->max_records = options->max_records;
    persistent->max_segments = options->max_segments;
    persistent->high_watermark_pct = high_watermark_pct;
    persistent->low_watermark_pct = low_watermark_pct;
    persistent->overflow_policy = options->overflow_policy;
    persistent->sample_every_n = options->sample_every_n > 0 ? options->sample_every_n : 10;
    persistent->block_timeout_ms = options->block_timeout_ms;
    persistent->lease_timeout_ms = options->lease_timeout_ms;
    persistent->heartbeat_interval_ms = options->heartbeat_interval_ms;
    persistent->open_mode = options->open_mode;
    persistent->durability = options->durability == VE_TLS_PDURABILITY_DEFAULT
        ? VE_TLS_PDURABILITY_BUFFERED_WAL
        : options->durability;
    if (persistent->durability != VE_TLS_PDURABILITY_BUFFERED_WAL &&
        persistent->durability != VE_TLS_PDURABILITY_SYNC_WAL) {
        return -1;
    }
    if (persistent->platform->path_mkdirs(persistent->dir_path, 0700) != 0) {
        return -1;
    }
    if (ensure_manifest(options) != 0) {
        ve_tls_persistent_close(persistent);
        return -1;
    }
    if (path_join(persistent->checkpoint_path, sizeof(persistent->checkpoint_path), persistent->dir_path, "checkpoint") != 0 ||
        path_join(persistent->lease_path, sizeof(persistent->lease_path), persistent->dir_path, "lease") != 0) {
        ve_tls_persistent_close(persistent);
        return -1;
    }
    if (persistent->platform->path_stat(persistent->checkpoint_path, &info) != 0) {
        ve_tls_persistent_close(persistent);
        return -1;
    }
    if (!info.exists) {
        if (ve_tls_checkpoint_save(persistent->platform, persistent->checkpoint_path, &persistent->checkpoint) != 0) {
            ve_tls_persistent_close(persistent);
            return -1;
        }
    } else if (ve_tls_checkpoint_load(persistent->platform, persistent->checkpoint_path, &persistent->checkpoint) != 0) {
        memset(&persistent->checkpoint, 0, sizeof(persistent->checkpoint));
        if (ve_tls_checkpoint_save(persistent->platform, persistent->checkpoint_path, &persistent->checkpoint) != 0) {
            ve_tls_persistent_close(persistent);
            return -1;
        }
    }
    memset(&lease_options, 0, sizeof(lease_options));
    lease_options.platform = persistent->platform;
    lease_options.lease_path = persistent->lease_path;
    lease_options.owner_id = options->owner_id;
    lease_options.owner_pid = options->owner_pid;
    lease_options.owner_process_name = options->owner_process_name;
    lease_options.now_ms = options->now_ms;
    lease_options.lease_timeout_ms = options->lease_timeout_ms;
    lease_options.mode = options->open_mode;
    if (ve_tls_lease_acquire(&lease_options, &persistent->lease) != 0) {
        ve_tls_persistent_close(persistent);
        return -1;
    }
    memset(&store_options, 0, sizeof(store_options));
    store_options.platform = persistent->platform;
    store_options.dir_path = persistent->dir_path;
    store_options.segment_max_bytes = options->segment_max_bytes;
    store_options.segment_max_records = options->segment_max_records;
    store_options.resume_segment_id = persistent->checkpoint.last_segment_id > 0
        ? persistent->checkpoint.last_segment_id
        : 0;
    store_options.sync_on_append = persistent->durability == VE_TLS_PDURABILITY_SYNC_WAL ? 1 : 0;
    if (ve_tls_segment_store_open(&persistent->store, &store_options) != 0) {
        ve_tls_persistent_close(persistent);
        return -1;
    }
    if (refresh_usage(persistent) != 0) {
        ve_tls_persistent_close(persistent);
        return -1;
    }
    persistent->durable_checkpoint_acked_log_id = persistent->checkpoint.acked_log_id;
    persistent->last_checkpoint_save_ms = options->now_ms > 0 ? options->now_ms : persistent_now_ms(persistent);
    persistent->checkpoint_dirty_since_ms = 0;
    persistent->checkpoint_dirty = 0;
    persistent->next_reclaim_segment_id = 1;
    persistent->last_reclaim_acked_log_id = 0;
    persistent->reclaim_pending = persistent->durable_checkpoint_acked_log_id > 0 ? 1 : 0;
    advance_reclaim_cursor(persistent);
    if (persistent->reclaim_pending && reclaim_acked_segments(persistent, 1) != 0) {
        ve_tls_persistent_close(persistent);
        return -1;
    }
    if (!persistent->platform->mutex_create || !persistent->platform->mutex_destroy ||
        !persistent->platform->mutex_lock || !persistent->platform->mutex_unlock) {
        ve_tls_persistent_close(persistent);
        return -1;
    }
    persistent->heartbeat_mutex = persistent->platform->mutex_create();
    if (!persistent->heartbeat_mutex) {
        ve_tls_persistent_close(persistent);
        return -1;
    }
    atomic_store_explicit(
        &persistent->next_heartbeat_ms,
        options->now_ms > 0 && persistent->heartbeat_interval_ms > 0
            ? options->now_ms + persistent->heartbeat_interval_ms
            : options->now_ms,
        memory_order_relaxed);
    return 0;
}

void ve_tls_persistent_close(ve_tls_persistent * persistent) {
    ve_tls_platform * platform;
    ve_tls_mutex * heartbeat_mutex;
    if (!persistent || !persistent->platform) {
        return;
    }
    platform = persistent->platform;
    heartbeat_mutex = persistent->heartbeat_mutex;
    (void)ve_tls_persistent_flush(persistent);
    ve_tls_segment_store_close(&persistent->store);
    ve_tls_free(persistent->segment_meta);
    persistent->segment_meta = NULL;
    persistent->segment_meta_cap = 0;
    ve_tls_free(persistent->append_buf);
    persistent->append_buf = NULL;
    persistent->append_buf_cap = 0;
    if (persistent->lease_path[0] != 0 && validate_current_lease(persistent) == 0) {
        (void)ve_tls_lease_release(persistent->platform, persistent->lease_path);
    }
    if (heartbeat_mutex && platform->mutex_destroy) {
        platform->mutex_destroy(heartbeat_mutex);
    }
    memset(persistent, 0, sizeof(*persistent));
}

int ve_tls_persistent_flush(ve_tls_persistent * persistent) {
    if (!persistent || !persistent->platform) {
        return -1;
    }
    if (ve_tls_segment_store_flush(&persistent->store) != VE_TLS_SEGMENT_STORE_OK) {
        return VE_TLS_PERSISTENT_APPEND_SYNC_FAILED;
    }
    if (persistent->checkpoint_dirty) {
        if (checkpoint_save_if_due(persistent, 1) != 0) {
            return VE_TLS_PERSISTENT_FLUSH_CHECKPOINT_FAILED;
        }
    }
    if (persistent->durable_checkpoint_acked_log_id > persistent->last_reclaim_acked_log_id) {
        if (reclaim_acked_segments(persistent, 0) != 0) {
            return -1;
        }
    }
    return 0;
}

int ve_tls_persistent_append(ve_tls_persistent * persistent, int64_t log_id, const char * hash_key, const unsigned char * payload, size_t payload_size) {
    ve_tls_persistent_record_view view;
    ve_tls_segment_record_ref ref;
    unsigned char stack_buf[512];
    unsigned char * record_buf = stack_buf;
    size_t record_size = 0;
    int rc;
    if (!persistent) {
        return -1;
    }
    persistent->append_dropped_records = 0;
    persistent->append_dropped_bytes = 0;
    if (!persistent->platform || !payload || payload_size == 0) {
        return -1;
    }
    if (persistent_heartbeat_and_validate_if_needed(persistent, 0) != 0) {
        return -1;
    }
    memset(&view, 0, sizeof(view));
    view.log_id = log_id;
    view.record_version = VE_TLS_PERSISTENT_RECORD_VERSION_CURRENT;
    view.enqueue_time_ms = persistent_now_ms(persistent);
    view.hash_key = hash_key;
    view.payload = payload;
    view.payload_size = payload_size;
    record_size = ve_tls_persistent_record_encoded_size(&view);
    if (record_size == 0) {
        return -1;
    }
    if (record_size > sizeof(stack_buf)) {
        record_buf = persistent_get_append_buffer(persistent, record_size);
        if (!record_buf) {
            return -1;
        }
    }
    rc = ensure_capacity_for_append(persistent, log_id, record_size);
    if (rc != 0) {
        return rc;
    }
    {
        uint32_t target_segment = would_need_new_segment(persistent, record_size)
            ? (persistent->store.active_segment_id + 1)
            : persistent->store.active_segment_id;
        if (ensure_segment_meta_capacity(persistent, target_segment) != 0) {
            return -1;
        }
    }
    rc = ve_tls_persistent_record_encode(record_buf, record_size, &view, &record_size);
    if (rc == 0) {
        uint32_t prev_segment = persistent->store.active_segment_id;
        memset(&ref, 0, sizeof(ref));
        rc = ve_tls_segment_store_append(&persistent->store, record_buf, record_size, &ref);
        if (ref.size == record_size && ref.segment_id != 0) {
            ve_tls_persistent_segment_meta * meta;
            meta = get_segment_meta_slot(persistent, ref.segment_id);
            if (!meta) {
                rc = -1;
            } else {
                if (!meta->exists) {
                    clear_segment_meta(meta);
                    meta->exists = 1;
                }
                meta->size = ref.offset + (uint64_t)record_size;
                meta->records += 1;
                if (log_id > meta->max_log_id) {
                    meta->max_log_id = log_id;
                }
            }
        }
        if (ref.size == record_size && ref.segment_id != 0) {
            persistent->current_bytes = add_u64_saturating(persistent->current_bytes, (uint64_t)record_size);
            persistent->current_records = add_u64_saturating(persistent->current_records, 1);
            if (persistent->current_segments == 0) {
                persistent->current_segments = 1;
            } else if (persistent->store.active_segment_id != prev_segment) {
                if (persistent->current_segments < UINT32_MAX) {
                    persistent->current_segments++;
                }
            }
            if (pressure_reclaim_needed(persistent)) {
                (void)reclaim_to_low_watermark(persistent);
            }
        }
        if (rc == VE_TLS_SEGMENT_STORE_UNSUPPORTED_VERSION) {
            rc = VE_TLS_PERSISTENT_APPEND_UNSUPPORTED_VERSION;
        } else if (rc == VE_TLS_SEGMENT_STORE_SYNC_FAILED) {
            rc = VE_TLS_PERSISTENT_APPEND_SYNC_FAILED;
        }
    }
    return rc;
}

int ve_tls_persistent_recover(
    ve_tls_persistent * persistent,
    int (*on_record)(
        int64_t log_id,
        int64_t enqueue_time_ms,
        const char * hash_key,
        const unsigned char * payload,
        size_t payload_size,
        void * user
    ),
    void * user
) {
    uint32_t last_segment;
    if (!persistent || !persistent->platform || !on_record) {
        return -1;
    }
    if (persistent_heartbeat_and_validate_if_needed(persistent, 1) != 0) {
        return -1;
    }
    last_segment = persistent->store.active_segment_id;
    for (uint32_t segment_id = 1; segment_id <= last_segment; segment_id++) {
        char path[640];
        ve_tls_path_info info;
        ve_tls_segment_reader reader;
        memset(&reader, 0, sizeof(reader));
        if (ve_tls_segment_store_get_segment_path(&persistent->store, segment_id, path, sizeof(path)) != 0) {
            return -1;
        }
        if (persistent->platform->path_stat(path, &info) != 0) {
            return -1;
        }
        if (!info.exists) {
            continue;
        }
        if (persistent_heartbeat_and_validate_if_needed(persistent, 0) != 0) {
            return -1;
        }
        if (ve_tls_segment_store_reader_open(&persistent->store, segment_id, info.size, &reader) != 0) {
            return -1;
        }
        while (1) {
            unsigned char * record_buf = NULL;
            size_t record_size = 0;
            ve_tls_persistent_record record;
            int read_rc;
            int decode_rc;
            memset(&record, 0, sizeof(record));
            read_rc = ve_tls_segment_store_reader_next(&persistent->store, &reader, &record_buf, &record_size);
            if (read_rc == 0) {
                break;
            }
            if (read_rc != 1) {
                ve_tls_segment_store_reader_close(&persistent->store, &reader);
                if (ve_tls_segment_store_repair_tail(&persistent->store, segment_id, NULL) != 0) {
                    return -1;
                }
                if (refresh_segment_meta(persistent, segment_id) != 0 || refresh_usage(persistent) != 0) {
                    return -1;
                }
                break;
            }
            decode_rc = ve_tls_persistent_record_decode(record_buf, record_size, &record);
            if (decode_rc != 0) {
                ve_tls_segment_store_read_free(record_buf);
                ve_tls_segment_store_reader_close(&persistent->store, &reader);
                if (decode_rc == VE_TLS_PERSISTENT_RECORD_UNSUPPORTED_VERSION) {
                    return -1;
                }
                if (ve_tls_segment_store_repair_tail(&persistent->store, segment_id, NULL) != 0) {
                    return -1;
                }
                if (refresh_segment_meta(persistent, segment_id) != 0 || refresh_usage(persistent) != 0) {
                    return -1;
                }
                break;
            }
            ve_tls_segment_store_read_free(record_buf);
            record_buf = NULL;
            if (record.log_id > persistent->checkpoint.acked_log_id) {
                if (on_record(
                        record.log_id,
                        record.enqueue_time_ms,
                        record.hash_key,
                        record.payload,
                        record.payload_size,
                        user) != 0) {
                    ve_tls_persistent_record_free(&record);
                    ve_tls_segment_store_reader_close(&persistent->store, &reader);
                    return -1;
                }
            }
            ve_tls_persistent_record_free(&record);
        }
        ve_tls_segment_store_reader_close(&persistent->store, &reader);
    }
    return 0;
}

int ve_tls_persistent_ack_range(ve_tls_persistent * persistent, int64_t start_id, int64_t end_id) {
    if (!persistent || !persistent->platform || start_id <= 0 || end_id <= 0 || end_id < start_id) {
        return -1;
    }
    if (persistent->checkpoint.acked_log_id < INT64_MAX &&
        start_id > persistent->checkpoint.acked_log_id + 1) {
        return -1;
    }
    if (persistent_heartbeat_and_validate_if_needed(persistent, 0) != 0) {
        return -1;
    }
    if (end_id > persistent->checkpoint.acked_log_id) {
        persistent->checkpoint.acked_log_id = end_id;
        mark_checkpoint_dirty(persistent);
    }
    persistent->checkpoint.last_segment_id = persistent->store.active_segment_id;
    if (checkpoint_save_if_due(persistent, 0) != 0) {
        return -1;
    }
    return 0;
}
