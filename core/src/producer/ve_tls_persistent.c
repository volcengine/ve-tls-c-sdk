#include "ve_tls_persistent.h"

#include "ve_tls_alloc.h"
#include "ve_tls_persistent_format.h"

#include <stdio.h>
#include <string.h>

#define VE_TLS_PERSISTENT_APPEND_REJECT_NEW (-2)
#define VE_TLS_PERSISTENT_APPEND_BLOCKED    (-3)
#define VE_TLS_PERSISTENT_OVERFLOW_BLOCK 1
#define VE_TLS_PERSISTENT_OVERFLOW_DROP_OLDEST_UNACKED 2
#define VE_TLS_PERSISTENT_OVERFLOW_DROP_NEWEST_SAMPLE 3

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

static int write_manifest(const ve_tls_persistent_options * options) {
    char path[640];
    char body[512];
    ve_tls_file * file;
    size_t body_len;
    if (!options || !options->platform || path_join(path, sizeof(path), options->dir_path, "manifest") != 0) {
        return -1;
    }
    body_len = (size_t)snprintf(
        body,
        sizeof(body),
        "format_version=1\ninstance_id=%s\nsegment_max_bytes=%llu\nsegment_max_records=%llu\nmax_bytes=%llu\nmax_records=%llu\nmax_segments=%u\n",
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
    file = options->platform->file_open(path, VE_TLS_FILE_OPEN_WRONLY | VE_TLS_FILE_OPEN_CREATE | VE_TLS_FILE_OPEN_TRUNC, 0644);
    if (!file) {
        return -1;
    }
    if (options->platform->file_write(file, body, body_len) != (int64_t)body_len || options->platform->file_fsync(file) != 0) {
        options->platform->file_close(file);
        return -1;
    }
    options->platform->file_close(file);
    return 0;
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

static int validate_current_lease(ve_tls_persistent * persistent) {
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

int ve_tls_persistent_heartbeat_if_due(ve_tls_persistent * persistent, int force) {
    ve_tls_lease_options options;
    int64_t now_ms;
    if (!persistent || !persistent->platform) {
        return -1;
    }
    now_ms = persistent_now_ms(persistent);
    if (!force && persistent->heartbeat_interval_ms > 0 && now_ms > 0 && now_ms < persistent->next_heartbeat_ms) {
        return 0;
    }
    if (validate_current_lease(persistent) != 0) {
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
        persistent->next_heartbeat_ms = now_ms + persistent->heartbeat_interval_ms;
    } else {
        persistent->next_heartbeat_ms = now_ms;
    }
    return 0;
}

static int reclaim_acked_segments(ve_tls_persistent * persistent) {
    if (!persistent || !persistent->platform) {
        return -1;
    }
    if (persistent->checkpoint.acked_log_id <= 0) {
        return 0;
    }
    for (uint32_t segment_id = 1; segment_id < persistent->store.active_segment_id; segment_id++) {
        char path[640];
        ve_tls_persistent_segment_meta * meta;
        if (persistent->checkpoint.replay_begin_segment_id != 0 &&
            segment_id == persistent->checkpoint.replay_begin_segment_id) {
            continue;
        }
        if (ve_tls_segment_store_get_segment_path(&persistent->store, segment_id, path, sizeof(path)) != 0) {
            return -1;
        }
        meta = get_segment_meta_slot(persistent, segment_id);
        if (!meta || !meta->exists) {
            continue;
        }
        if (meta->max_log_id > 0 && meta->max_log_id <= persistent->checkpoint.acked_log_id) {
            if (persistent->platform->path_remove(path) != 0) {
                return -1;
            }
            if (persistent->current_bytes >= meta->size) {
                persistent->current_bytes -= meta->size;
            } else {
                persistent->current_bytes = 0;
            }
            if (persistent->current_records >= meta->records) {
                persistent->current_records -= meta->records;
            } else {
                persistent->current_records = 0;
            }
            if (persistent->current_segments > 0) {
                persistent->current_segments--;
            }
            clear_segment_meta(meta);
        }
    }
    return 0;
}

static int save_checkpoint(ve_tls_persistent * persistent) {
    if (!persistent || !persistent->platform) {
        return -1;
    }
    return ve_tls_checkpoint_save(persistent->platform, persistent->checkpoint_path, &persistent->checkpoint);
}

static int persist_drop_oldest_unacked(ve_tls_persistent * persistent) {
    if (!persistent || !persistent->platform) {
        return -1;
    }
    for (uint32_t segment_id = 1; segment_id < persistent->store.active_segment_id; segment_id++) {
        char path[640];
        ve_tls_persistent_segment_meta * meta;
        if (persistent->checkpoint.replay_begin_segment_id != 0 &&
            segment_id == persistent->checkpoint.replay_begin_segment_id) {
            continue;
        }
        if (ve_tls_segment_store_get_segment_path(&persistent->store, segment_id, path, sizeof(path)) != 0) {
            return -1;
        }
        meta = get_segment_meta_slot(persistent, segment_id);
        if (!meta || !meta->exists || meta->max_log_id <= 0) {
            continue;
        }
        if (meta->max_log_id > persistent->checkpoint.acked_log_id) {
            persistent->checkpoint.acked_log_id = meta->max_log_id;
            persistent->checkpoint.last_segment_id = persistent->store.active_segment_id;
            if (save_checkpoint(persistent) != 0) {
                return -1;
            }
        }
        if (persistent->platform->path_remove(path) != 0) {
            return -1;
        }
        if (persistent->current_bytes >= meta->size) {
            persistent->current_bytes -= meta->size;
        } else {
            persistent->current_bytes = 0;
        }
        if (persistent->current_records >= meta->records) {
            persistent->current_records -= meta->records;
        } else {
            persistent->current_records = 0;
        }
        if (persistent->current_segments > 0) {
            persistent->current_segments--;
        }
        clear_segment_meta(meta);
        return 1;
    }
    return 0;
}

static int would_need_new_segment(ve_tls_persistent * persistent, size_t append_size) {
    if (!persistent) {
        return 0;
    }
    return ((persistent->store.active_size > 0 && persistent->store.active_size + append_size > persistent->store.segment_max_bytes) ||
            (persistent->store.active_records > 0 && persistent->store.active_records >= persistent->store.segment_max_records)) ? 1 : 0;
}

static int is_soft_limit_exceeded(uint64_t current, uint64_t max, int32_t pct) {
    if (max == 0 || pct <= 0) {
        return 0;
    }
    return current * 100 >= max * (uint64_t)pct;
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
    uint32_t next_segments;
    int need_new_segment;
    int saturated;
    if (!persistent) {
        return -1;
    }
    if (reclaim_acked_segments(persistent) != 0) {
        return -1;
    }
    need_new_segment = would_need_new_segment(persistent, record_size);
    next_bytes = persistent->current_bytes + (uint64_t)record_size;
    next_records = persistent->current_records + 1;
    next_segments = persistent->current_segments + (uint32_t)(need_new_segment ? 1 : 0);
    saturated = is_hard_limit_exceeded(next_bytes, persistent->max_bytes) ||
                is_hard_limit_exceeded(next_records, persistent->max_records) ||
                (persistent->max_segments > 0 && next_segments > persistent->max_segments);
    if (!saturated) {
        return 0;
    }
    if (persistent->overflow_policy == VE_TLS_PERSISTENT_OVERFLOW_DROP_OLDEST_UNACKED ||
        (persistent->overflow_policy == VE_TLS_PERSISTENT_OVERFLOW_DROP_NEWEST_SAMPLE && should_treat_as_sampled(persistent, log_id))) {
        while (saturated) {
            int drop_rc = persist_drop_oldest_unacked(persistent);
            if (drop_rc <= 0) {
                break;
            }
            need_new_segment = would_need_new_segment(persistent, record_size);
            next_bytes = persistent->current_bytes + (uint64_t)record_size;
            next_records = persistent->current_records + 1;
            next_segments = persistent->current_segments + (uint32_t)(need_new_segment ? 1 : 0);
            saturated = is_hard_limit_exceeded(next_bytes, persistent->max_bytes) ||
                        is_hard_limit_exceeded(next_records, persistent->max_records) ||
                        (persistent->max_segments > 0 && next_segments > persistent->max_segments);
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
    if (!persistent || !options || !options->platform || !options->dir_path || options->dir_path[0] == 0) {
        return -1;
    }
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
    persistent->high_watermark_pct = options->high_watermark_pct > 0 ? options->high_watermark_pct : 85;
    persistent->low_watermark_pct = options->low_watermark_pct > 0 ? options->low_watermark_pct : 70;
    persistent->overflow_policy = options->overflow_policy;
    persistent->sample_every_n = options->sample_every_n > 0 ? options->sample_every_n : 10;
    persistent->block_timeout_ms = options->block_timeout_ms;
    persistent->lease_timeout_ms = options->lease_timeout_ms;
    persistent->heartbeat_interval_ms = options->heartbeat_interval_ms;
    persistent->open_mode = options->open_mode;
    if (persistent->platform->path_mkdirs(persistent->dir_path, 0700) != 0) {
        return -1;
    }
    if (write_manifest(options) != 0) {
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
    if (ve_tls_segment_store_open(&persistent->store, &store_options) != 0) {
        ve_tls_persistent_close(persistent);
        return -1;
    }
    if (refresh_usage(persistent) != 0) {
        ve_tls_persistent_close(persistent);
        return -1;
    }
    persistent->next_heartbeat_ms = options->now_ms > 0 && persistent->heartbeat_interval_ms > 0
        ? options->now_ms + persistent->heartbeat_interval_ms
        : options->now_ms;
    return 0;
}

void ve_tls_persistent_close(ve_tls_persistent * persistent) {
    if (!persistent || !persistent->platform) {
        return;
    }
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
    memset(persistent, 0, sizeof(*persistent));
}

int ve_tls_persistent_append(ve_tls_persistent * persistent, int64_t log_id, const char * hash_key, const unsigned char * payload, size_t payload_size) {
    ve_tls_persistent_record_view view;
    ve_tls_segment_record_ref ref;
    unsigned char stack_buf[512];
    unsigned char * record_buf = stack_buf;
    size_t record_size = 0;
    int rc;
    if (!persistent || !persistent->platform || !payload || payload_size == 0) {
        return -1;
    }
    if (ve_tls_persistent_heartbeat_if_due(persistent, 0) != 0) {
        return -1;
    }
    if (validate_current_lease(persistent) != 0) {
        return -1;
    }
    memset(&view, 0, sizeof(view));
    view.log_id = log_id;
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
        if (rc == 0) {
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
        if (rc == 0) {
            persistent->current_bytes += (uint64_t)record_size;
            persistent->current_records += 1;
            if (persistent->current_segments == 0) {
                persistent->current_segments = 1;
            } else if (persistent->store.active_segment_id != prev_segment) {
                persistent->current_segments += 1;
            }
            if (is_soft_limit_exceeded(persistent->current_bytes, persistent->max_bytes, persistent->high_watermark_pct) ||
                is_soft_limit_exceeded(persistent->current_records, persistent->max_records, persistent->high_watermark_pct) ||
                is_soft_limit_exceeded(persistent->current_segments, persistent->max_segments, persistent->high_watermark_pct)) {
                (void)reclaim_acked_segments(persistent);
            }
        }
    }
    return rc;
}

int ve_tls_persistent_recover(ve_tls_persistent * persistent, int (*on_record)(int64_t log_id, const char * hash_key, const unsigned char * payload, size_t payload_size, void * user), void * user) {
    uint32_t last_segment;
    if (!persistent || !persistent->platform || !on_record) {
        return -1;
    }
    if (ve_tls_persistent_heartbeat_if_due(persistent, 1) != 0) {
        return -1;
    }
    if (validate_current_lease(persistent) != 0) {
        return -1;
    }
    last_segment = persistent->store.active_segment_id;
    for (uint32_t segment_id = 1; segment_id <= last_segment; segment_id++) {
        uint64_t offset = 0;
        char path[640];
        ve_tls_path_info info;
        if (ve_tls_segment_store_get_segment_path(&persistent->store, segment_id, path, sizeof(path)) != 0) {
            return -1;
        }
        if (persistent->platform->path_stat(path, &info) != 0) {
            return -1;
        }
        if (!info.exists) {
            continue;
        }
        if (ve_tls_persistent_heartbeat_if_due(persistent, 0) != 0) {
            return -1;
        }
        if (validate_current_lease(persistent) != 0) {
            return -1;
        }
        while (offset < info.size) {
            unsigned char * record_buf = NULL;
            size_t record_size = 0;
            uint64_t next_offset = offset;
            ve_tls_persistent_record record;
            memset(&record, 0, sizeof(record));
            if (ve_tls_segment_store_read(&persistent->store, segment_id, offset, &record_buf, &record_size, &next_offset) != 0) {
                if (ve_tls_segment_store_repair_tail(&persistent->store, segment_id, NULL) != 0) {
                    return -1;
                }
                if (refresh_segment_meta(persistent, segment_id) != 0 || refresh_usage(persistent) != 0) {
                    return -1;
                }
                break;
            }
            if (ve_tls_persistent_record_decode(record_buf, record_size, &record) != 0) {
                ve_tls_segment_store_read_free(record_buf);
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
                if (on_record(record.log_id, record.hash_key, record.payload, record.payload_size, user) != 0) {
                    ve_tls_persistent_record_free(&record);
                    return -1;
                }
            }
            ve_tls_persistent_record_free(&record);
            if (next_offset <= offset) {
                return -1;
            }
            offset = next_offset;
        }
    }
    return 0;
}

int ve_tls_persistent_ack_range(ve_tls_persistent * persistent, int64_t start_id, int64_t end_id) {
    if (!persistent || !persistent->platform || end_id <= 0 || end_id < start_id) {
        return -1;
    }
    if (ve_tls_persistent_heartbeat_if_due(persistent, 0) != 0) {
        return -1;
    }
    if (validate_current_lease(persistent) != 0) {
        return -1;
    }
    if (end_id > persistent->checkpoint.acked_log_id) {
        persistent->checkpoint.acked_log_id = end_id;
    }
    persistent->checkpoint.last_segment_id = persistent->store.active_segment_id;
    if (save_checkpoint(persistent) != 0) {
        return -1;
    }
    return reclaim_acked_segments(persistent);
}
