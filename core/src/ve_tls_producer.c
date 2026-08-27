#include "producer/ve_tls_producer_internal.h"
#include "producer/ve_tls_persistent.h"
#include "ve_tls_env.h"
#include "ve_tls_alloc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>

static int ve_tls_str_empty(const char * s) {
    return !s || s[0] == 0;
}

typedef struct {
    const char * p;
    size_t n;
} ve_tls_cstr_len_cache_entry;

static __thread ve_tls_cstr_len_cache_entry g_cstr_len_cache[64];

static size_t ve_tls_cstr_len_cached(const char * s) {
    if (!s || s[0] == 0) {
        return 0;
    }
    size_t idx = (((size_t)(uintptr_t)s) >> 3) & 63;
    if (g_cstr_len_cache[idx].p == s) {
        return g_cstr_len_cache[idx].n;
    }
    size_t n = strlen(s);
    if (n >= 32) {
        g_cstr_len_cache[idx].p = s;
        g_cstr_len_cache[idx].n = n;
    }
    return n;
}

static char * ve_tls_dup_cstr(const char * s) {
    return s ? ve_tls_strdup(s) : NULL;
}

static int ve_tls_count_fits_array(size_t count, size_t elem_size) {
    return elem_size == 0 || count <= ((size_t)-1 / elem_size);
}

static int ve_tls_wait_buffer_space_locked(ve_tls_producer * producer, size_t need_bytes, int reserve_for_send);

static int ve_tls_copy_log_tags(const ve_tls_kv * tags, size_t count, ve_tls_kv ** out_tags, size_t * out_count) {
    VE_TLS_ALLOC_SITE("copy_log_tags");
    *out_tags = NULL;
    *out_count = 0;
    if (!tags || count == 0) {
        return 0;
    }
    if (!ve_tls_count_fits_array(count, sizeof(ve_tls_kv))) {
        return -1;
    }
    ve_tls_kv * copy = (ve_tls_kv *)ve_tls_calloc(count, sizeof(ve_tls_kv));
    if (!copy) {
        return -1;
    }
    for (size_t i = 0; i < count; i++) {
        copy[i].key = ve_tls_dup_cstr(tags[i].key);
        copy[i].value = ve_tls_dup_cstr(tags[i].value);
        if ((tags[i].key && !copy[i].key) || (tags[i].value && !copy[i].value)) {
            for (size_t j = 0; j <= i; j++) {
                ve_tls_free((void *)copy[j].key);
                ve_tls_free((void *)copy[j].value);
            }
            ve_tls_free(copy);
            return -1;
        }
    }
    *out_tags = copy;
    *out_count = count;
    return 0;
}

static int ve_tls_is_http_url(const char * s) {
    if (ve_tls_str_empty(s)) return 0;
    return strncmp(s, "http://", 7) == 0 || strncmp(s, "https://", 8) == 0;
}

static int ve_tls_persistent_enabled(const ve_tls_producer * producer) {
    return producer && producer->config.use_persistent && producer->persistent;
}

static size_t ve_tls_effective_package_bytes(const ve_tls_config * cfg) {
    if (!cfg) {
        return 0;
    }
    size_t bytes = cfg->log_bytes_per_package > 0 ? (size_t)cfg->log_bytes_per_package : 0;
    if (cfg->agg_max_raw_bytes_per_request > 0) {
        size_t max_raw = (size_t)cfg->agg_max_raw_bytes_per_request;
        if (bytes == 0 || bytes > max_raw) {
            bytes = max_raw;
        }
    }
    if (bytes == 0) {
        bytes = 256 * 1024;
    }
    return bytes;
}

static size_t ve_tls_desired_send_reserved_bytes(const ve_tls_config * cfg) {
    if (!cfg) {
        return 0;
    }
    size_t pkg_bytes = ve_tls_effective_package_bytes(cfg);
    size_t sender_count = (size_t)(cfg->send_thread_count > 0 ? cfg->send_thread_count : 1);
    if (pkg_bytes == 0 || sender_count == 0) {
        return 0;
    }
    if (pkg_bytes > (SIZE_MAX / sender_count)) {
        return SIZE_MAX;
    }
    return pkg_bytes * sender_count;
}

static size_t ve_tls_effective_send_reserved_bytes(const ve_tls_config * cfg) {
    if (!cfg || cfg->max_buffer_bytes <= 0) {
        return 0;
    }
    size_t desired = ve_tls_desired_send_reserved_bytes(cfg);
    size_t max_buffer = (size_t)cfg->max_buffer_bytes;
    size_t cap = max_buffer / 2;
    if (desired > cap) {
        desired = cap;
    }
    return desired;
}

static void ve_tls_warn_risky_block_config(const ve_tls_config * cfg) {
    if (!cfg || cfg->buffer_full_policy != VE_TLS_BUFFER_FULL_BLOCK || cfg->max_buffer_bytes <= 0) {
        return;
    }
    size_t desired_reserved = ve_tls_desired_send_reserved_bytes(cfg);
    if (desired_reserved == 0 || desired_reserved == SIZE_MAX || desired_reserved > (SIZE_MAX / 2)) {
        return;
    }
    size_t max_buffer = (size_t)cfg->max_buffer_bytes;
    size_t suggested = desired_reserved * 2;
    if (max_buffer < suggested) {
        fprintf(stderr,
                "ve_tls warning: BLOCK mode config may over-throttle ingress before send threads are fully utilized "
                "(max_buffer_bytes=%d send_thread_count=%d effective_package_bytes=%zu suggested_buffer_bytes>=%zu)\n",
                (int)cfg->max_buffer_bytes,
                (int)(cfg->send_thread_count > 0 ? cfg->send_thread_count : 1),
                ve_tls_effective_package_bytes(cfg),
                suggested);
    }
}

static int ve_tls_resolve_persistent_durability(
    const ve_tls_config * cfg,
    ve_tls_persistent_durability * out
) {
    ve_tls_persistent_durability durability;
    if (!cfg || !out) {
        return -1;
    }
    durability = cfg->persistent_durability;
    if (durability == VE_TLS_PDURABILITY_DEFAULT) {
        *out = cfg->force_flush_disk
            ? VE_TLS_PDURABILITY_SYNC_WAL
            : VE_TLS_PDURABILITY_BUFFERED_WAL;
        return 0;
    }
    if (durability == VE_TLS_PDURABILITY_BUFFERED_WAL) {
        if (cfg->force_flush_disk) {
            return -1;
        }
        *out = durability;
        return 0;
    }
    if (durability == VE_TLS_PDURABILITY_SYNC_WAL) {
        *out = durability;
        return 0;
    }
    return -1;
}

static int ve_tls_config_is_valid_for_create(const ve_tls_config * cfg) {
    if (!cfg) return 0;
    if (!ve_tls_is_http_url(cfg->endpoint)) return 0;
    if (ve_tls_str_empty(cfg->region)) return 0;
    if (ve_tls_str_empty(cfg->topic_id)) return 0;
    if (!cfg->credentials_provider) {
        if (ve_tls_str_empty(cfg->access_key_id) || ve_tls_str_empty(cfg->access_key_secret)) return 0;
    }
    if (cfg->use_persistent) {
        ve_tls_persistent_durability durability;
        if (ve_tls_str_empty(cfg->persistent_file_path)) return 0;
        if (cfg->max_persistent_log_count <= 0 || cfg->max_persistent_file_size <= 0 || cfg->max_persistent_file_count <= 0) return 0;
        if (cfg->persistent_low_watermark_pct <= 0 || cfg->persistent_high_watermark_pct <= 0 ||
            cfg->persistent_high_watermark_pct > 100 ||
            cfg->persistent_low_watermark_pct >= cfg->persistent_high_watermark_pct) return 0;
        if (ve_tls_resolve_persistent_durability(cfg, &durability) != 0) return 0;
        if (cfg->persistent_max_log_delay_ms < 0) return 0;
        if (cfg->persistent_expired_log_policy != VE_TLS_PEXPIRED_REWRITE &&
            cfg->persistent_expired_log_policy != VE_TLS_PEXPIRED_DROP) return 0;
        if (cfg->persistent_auth_failure_policy != VE_TLS_PAUTH_RETAIN &&
            cfg->persistent_auth_failure_policy != VE_TLS_PAUTH_DROP) return 0;
    }
    if (cfg->buffer_full_policy == VE_TLS_BUFFER_FULL_BLOCK) {
        if (cfg->max_buffer_bytes <= 0) return 0;
        if (cfg->buffer_full_block_timeout_ms <= 0) return 0;
        if (ve_tls_effective_package_bytes(cfg) > ((size_t)cfg->max_buffer_bytes / 2)) return 0;
    }
    return 1;
}

static ve_tls_result ve_tls_map_wait_error_to_result(ve_tls_producer * producer, int wrc, size_t dropped_bytes) {
    if (wrc == -2) {
        return VE_TLS_CLOSED;
    }
    if (wrc == -3) {
        ve_tls_metric_inc_u64(&producer->m_logs_dropped_total, 1);
        ve_tls_metric_inc_u64(&producer->m_bytes_dropped_total, dropped_bytes);
        ve_tls_metrics_emit(producer, "log_dropped_buffer_full_timeout", 1, (int64_t)dropped_bytes);
        ve_tls_metrics_emit(producer, "log_dropped", 1, (int64_t)dropped_bytes);
        return VE_TLS_TIMEOUT;
    }
    ve_tls_metric_inc_u64(&producer->m_logs_dropped_total, 1);
    ve_tls_metric_inc_u64(&producer->m_bytes_dropped_total, dropped_bytes);
    ve_tls_metrics_emit(producer, "log_dropped_buffer_full", 1, (int64_t)dropped_bytes);
    ve_tls_metrics_emit(producer, "log_dropped", 1, (int64_t)dropped_bytes);
    return VE_TLS_DROP_ERROR;
}

static int64_t ve_tls_producer_next_log_id(ve_tls_producer * producer) {
    return __atomic_fetch_add(&producer->next_id, 1, __ATOMIC_RELAXED);
}

static void ve_tls_producer_advance_next_log_id(ve_tls_producer * producer, int64_t desired_next) {
    if (!producer || desired_next <= 0) {
        return;
    }
    int64_t current = __atomic_load_n(&producer->next_id, __ATOMIC_RELAXED);
    while (current < desired_next &&
           !__atomic_compare_exchange_n(&producer->next_id, &current, desired_next, 0, __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
    }
}

static void ve_tls_release_queue_reservation_locked(ve_tls_producer * producer, size_t bytes) {
    if (!producer || bytes == 0) {
        return;
    }
    if (producer->queue_bytes >= bytes) {
        producer->queue_bytes -= bytes;
    } else {
        producer->queue_bytes = 0;
    }
    producer->config.platform.cond_broadcast(producer->cond);
}

static ve_tls_result ve_tls_map_persistent_append_error(
    ve_tls_producer * producer,
    int prc,
    int64_t log_id,
    size_t dropped_bytes
) {
    if (prc == VE_TLS_PERSISTENT_APPEND_REJECT_NEW) {
        ve_tls_metric_inc_u64(&producer->m_logs_dropped_total, 1);
        ve_tls_metric_inc_u64(&producer->m_bytes_dropped_total, dropped_bytes);
        ve_tls_metrics_emit(producer, "log_dropped_persistent_overflow", 1, (int64_t)dropped_bytes);
        ve_tls_metrics_emit(producer, "log_dropped", 1, (int64_t)dropped_bytes);
        return VE_TLS_DROP_ERROR;
    }
    if (prc == VE_TLS_PERSISTENT_APPEND_BLOCKED) {
        ve_tls_metric_inc_u64(&producer->m_logs_dropped_total, 1);
        ve_tls_metric_inc_u64(&producer->m_bytes_dropped_total, dropped_bytes);
        ve_tls_metrics_emit(producer, "log_dropped_persistent_overflow_timeout", 1, (int64_t)dropped_bytes);
        ve_tls_metrics_emit(producer, "log_dropped", 1, (int64_t)dropped_bytes);
        return VE_TLS_TIMEOUT;
    }
    if (prc == VE_TLS_PERSISTENT_APPEND_SYNC_FAILED) {
        ve_tls_metrics_emit(producer, "persistent_sync_failed", log_id, (int64_t)dropped_bytes);
        return VE_TLS_PERSISTENT_ERROR;
    }
    if (prc == VE_TLS_PERSISTENT_APPEND_UNSUPPORTED_VERSION) {
        ve_tls_metrics_emit(producer, "persistent_unsupported_version", log_id, (int64_t)dropped_bytes);
        return VE_TLS_PERSISTENT_ERROR;
    }
    ve_tls_metrics_emit(producer, "persistent_append_failed", log_id, (int64_t)dropped_bytes);
    return VE_TLS_PERSISTENT_ERROR;
}

static ve_tls_result ve_tls_map_persistent_flush_error(ve_tls_producer * producer, int flush_rc) {
    if (flush_rc == 0) {
        return VE_TLS_OK;
    }
    if (flush_rc == VE_TLS_PERSISTENT_APPEND_SYNC_FAILED) {
        ve_tls_metrics_emit(producer, "persistent_sync_failed", 0, 0);
    } else if (flush_rc == VE_TLS_PERSISTENT_FLUSH_CHECKPOINT_FAILED) {
        ve_tls_metrics_emit(producer, "persistent_checkpoint_save_failed", 0, 0);
    } else {
        ve_tls_metrics_emit(producer, "persistent_flush_failed", 0, 0);
    }
    return VE_TLS_PERSISTENT_ERROR;
}

static void ve_tls_record_persistent_append_drops(
    ve_tls_producer * producer,
    uint64_t dropped_records,
    uint64_t dropped_bytes
) {
    if (!producer || (dropped_records == 0 && dropped_bytes == 0)) {
        return;
    }
    ve_tls_metric_inc_u64(&producer->m_logs_dropped_total, dropped_records);
    ve_tls_metric_inc_u64(&producer->m_bytes_dropped_total, dropped_bytes);
    ve_tls_metrics_emit(
        producer,
        "persistent_overflow_drop_oldest_unacked",
        dropped_records > (uint64_t)INT64_MAX ? INT64_MAX : (int64_t)dropped_records,
        dropped_bytes > (uint64_t)INT64_MAX ? INT64_MAX : (int64_t)dropped_bytes);
}

static ve_tls_result ve_tls_persistent_append_with_retry_locked(
    ve_tls_producer * producer,
    int64_t id,
    const char * hash_key,
    const unsigned char * data,
    size_t size
) {
    int64_t start_ms = 0;
    int64_t timeout_ms = 0;
    if (!producer || !producer->persistent || !data || size == 0) {
        return VE_TLS_INVALID;
    }
    timeout_ms = producer->persistent->block_timeout_ms;
    if (timeout_ms > 0 && producer->config.platform.time_ms) {
        start_ms = producer->config.platform.time_ms();
    }
    for (;;) {
        uint64_t dropped_records = 0;
        uint64_t dropped_bytes = 0;
        producer->active_persistent_appends++;
        producer->config.platform.mutex_unlock(producer->mutex);
        if (producer->persistent_mutex) {
            producer->config.platform.mutex_lock(producer->persistent_mutex);
        }
        int prc = ve_tls_persistent_append(producer->persistent, id, hash_key, data, size);
        dropped_records = producer->persistent->append_dropped_records;
        dropped_bytes = producer->persistent->append_dropped_bytes;
        if (producer->persistent_mutex) {
            producer->config.platform.mutex_unlock(producer->persistent_mutex);
        }
        ve_tls_record_persistent_append_drops(producer, dropped_records, dropped_bytes);
        if (prc == VE_TLS_PERSISTENT_APPEND_BLOCKED) {
            producer->config.platform.sleep_ms(5);
        }
        producer->config.platform.mutex_lock(producer->mutex);
        producer->active_persistent_appends--;
        producer->config.platform.cond_broadcast(producer->cond);
        if (producer->stop || !producer->accepting) {
            return VE_TLS_CLOSED;
        }
        if (prc == 0) {
            return VE_TLS_OK;
        }
        if (prc != VE_TLS_PERSISTENT_APPEND_BLOCKED) {
            return ve_tls_map_persistent_append_error(producer, prc, id, size);
        }
        if (timeout_ms > 0 && producer->config.platform.time_ms) {
            int64_t now_ms = producer->config.platform.time_ms();
            if (start_ms > 0 && now_ms - start_ms >= timeout_ms) {
                return ve_tls_map_persistent_append_error(
                    producer, VE_TLS_PERSISTENT_APPEND_BLOCKED, id, size);
            }
        }
    }
}

static ve_tls_result ve_tls_enqueue_raw_owned_locked(
    ve_tls_producer * producer,
    unsigned char * data,
    size_t size,
    int64_t time_ms,
    uint32_t time_ns,
    int32_t has_time_ns,
    const char * hash_key,
    int flush,
    int64_t * out_log_id,
    int reserved_bytes
) {
    VE_TLS_ALLOC_SITE("hk_owned");
    char * hk_owned = NULL;
    int64_t id;
    if (!producer || !data || size == 0) {
        return VE_TLS_INVALID;
    }
    if (producer->stop || !producer->accepting) {
        if (reserved_bytes) {
            ve_tls_release_queue_reservation_locked(producer, size);
        }
        ve_tls_free(data);
        return VE_TLS_CLOSED;
    }
    if (hash_key && hash_key[0] != 0) {
        hk_owned = ve_tls_strdup(hash_key);
        if (!hk_owned) {
            if (reserved_bytes) {
                ve_tls_release_queue_reservation_locked(producer, size);
            }
            ve_tls_free(data);
            ve_tls_metric_inc_u64(&producer->m_logs_dropped_total, 1);
            ve_tls_metric_inc_u64(&producer->m_bytes_dropped_total, size);
            ve_tls_metrics_emit(producer, "log_dropped_enqueue_alloc_failed", 1, (int64_t)size);
            ve_tls_metrics_emit(producer, "log_dropped", 1, (int64_t)size);
            return VE_TLS_DROP_ERROR;
        }
    }
    if (!reserved_bytes) {
        int wrc = ve_tls_wait_buffer_space_locked(producer, size, 0);
        if (wrc != 0) {
            ve_tls_free(hk_owned);
            ve_tls_free(data);
            return ve_tls_map_wait_error_to_result(producer, wrc, size);
        }
    }
    id = ve_tls_producer_next_log_id(producer);
    if (out_log_id) {
        *out_log_id = id;
    }
    if (ve_tls_persistent_enabled(producer)) {
        ve_tls_result prc = ve_tls_persistent_append_with_retry_locked(producer, id, hk_owned, data, size);
        if (prc != VE_TLS_OK) {
            if (reserved_bytes) {
                ve_tls_release_queue_reservation_locked(producer, size);
            }
            ve_tls_free(hk_owned);
            ve_tls_free(data);
            return prc;
        }
    }
    int qrc = reserved_bytes ?
        ve_tls_queue_push_reserved_owned(producer, data, size, id, time_ms, time_ns, has_time_ns ? 1 : 0, hk_owned) :
        ve_tls_queue_push_owned(producer, data, size, id, time_ms, time_ns, has_time_ns ? 1 : 0, hk_owned);
    if (qrc != 0) {
        if (reserved_bytes) {
            ve_tls_release_queue_reservation_locked(producer, size);
        }
        ve_tls_free(hk_owned);
        ve_tls_free(data);
        return ve_tls_persistent_enabled(producer) ? VE_TLS_PERSISTENT_ERROR : VE_TLS_DROP_ERROR;
    }
    ve_tls_metric_inc_u64(&producer->m_logs_enqueued_total, 1);
    ve_tls_metric_inc_u64(&producer->m_bytes_enqueued_total, size);
    if (!flush) {
        size_t byte_limit = producer->config.log_bytes_per_package > 0 ? (size_t)producer->config.log_bytes_per_package : 0;
        if (producer->config.agg_max_raw_bytes_per_request > 0) {
            size_t max_raw = (size_t)producer->config.agg_max_raw_bytes_per_request;
            if (byte_limit == 0 || byte_limit > max_raw) {
                byte_limit = max_raw;
            }
        }
        if (producer->config.log_count_per_package > 0 && producer->queue_count >= producer->config.log_count_per_package) {
            flush = 1;
        }
        if (!flush && byte_limit > 0 && producer->queue_bytes >= byte_limit) {
            flush = 1;
        }
    }
    if (flush) {
        producer->flush_requested = 1;
        producer->config.platform.cond_signal(producer->cond);
    }
    ve_tls_metrics_emit(producer, "log_enqueued", 1, (int64_t)size);
    return VE_TLS_OK;
}

static ve_tls_result ve_tls_enqueue_ingress_raw_owned_locked(
    ve_tls_producer * producer,
    const char * norm_key,
    unsigned char * data,
    size_t size,
    int64_t log_id,
    int64_t time_ms,
    uint32_t time_ns,
    int32_t has_time_ns,
    int flush,
    int count_metrics
) {
    ve_tls_log_group_builder * batch = NULL;
    int wait_ms = 0;
    int wrc;
    int qrc;
    if (!producer || !data || size == 0 || log_id <= 0) {
        ve_tls_free(data);
        return VE_TLS_INVALID;
    }
    VE_TLS_ALLOC_SITE("ingress_owned");
    if (producer->stop || !producer->accepting) {
        ve_tls_free(data);
        return VE_TLS_CLOSED;
    }
    wrc = ve_tls_wait_buffer_space_locked(producer, size, 0);
    if (wrc != 0) {
        ve_tls_free(data);
        return ve_tls_map_wait_error_to_result(producer, wrc, size);
    }
    batch = ve_tls_log_builder_create(norm_key);
    if (!batch) {
        ve_tls_free(data);
        ve_tls_metric_inc_u64(&producer->m_logs_dropped_total, 1);
        ve_tls_metric_inc_u64(&producer->m_bytes_dropped_total, size);
        ve_tls_metrics_emit(producer, "log_dropped_enqueue_alloc_failed", 1, (int64_t)size);
        ve_tls_metrics_emit(producer, "log_dropped", 1, (int64_t)size);
        return VE_TLS_DROP_ERROR;
    }
    batch->logs = data;
    batch->logs_len = size;
    batch->logs_cap = size;
    batch->log_count = 1;
    if (time_ms > 0) {
        batch->earliest = time_ms;
        batch->latest = time_ms;
    }
    batch->start_id = log_id;
    batch->end_id = log_id;
    batch->last_time_ms = time_ms > 0 ? time_ms : 0;
    batch->last_time_ns = has_time_ns ? time_ns : 0;
    batch->last_has_time_ns = has_time_ns ? 1 : 0;
    batch->first_append_ms = producer->config.platform.time_ms ? producer->config.platform.time_ms() : 0;
    if (producer->config.buffer_full_policy == VE_TLS_BUFFER_FULL_BLOCK) {
        wait_ms = producer->config.buffer_full_block_timeout_ms;
        if (wait_ms == 0) {
            wait_ms = -1;
        }
    }
    qrc = ve_tls_ingress_queue_push_locked(producer, batch->norm_key, batch, flush, wait_ms);
    if (qrc != 0) {
        ve_tls_log_builder_free(batch);
        if (qrc == -2) {
            return VE_TLS_CLOSED;
        }
        if (qrc == -3) {
            return VE_TLS_TIMEOUT;
        }
        ve_tls_metric_inc_u64(&producer->m_logs_dropped_total, 1);
        ve_tls_metric_inc_u64(&producer->m_bytes_dropped_total, size);
        ve_tls_metrics_emit(producer, "log_dropped", 1, (int64_t)size);
        return VE_TLS_DROP_ERROR;
    }
    if (count_metrics) {
        ve_tls_metric_inc_u64(&producer->m_logs_enqueued_total, 1);
        ve_tls_metric_inc_u64(&producer->m_bytes_enqueued_total, size);
        ve_tls_metrics_emit(producer, "log_enqueued", 1, (int64_t)size);
    }
    return VE_TLS_OK;
}

static ve_tls_result ve_tls_producer_add_log_kv_persistent_locked(
    ve_tls_producer * producer,
    int64_t time_ms,
    int32_t has_time_ns,
    uint32_t time_ns,
    const char * hash_key,
    const ve_tls_kv * kvs,
    const size_t * key_lens,
    const size_t * val_lens,
    size_t kv_count,
    int flush,
    int64_t * out_log_id
) {
    const char * norm_key;
    ve_tls_log_group_builder * builder;
    unsigned char * raw_log = NULL;
    size_t raw_log_size = 0;
    int64_t id;
    ve_tls_result rc = VE_TLS_DROP_ERROR;
    if (!producer || !kvs || !key_lens || !val_lens || kv_count == 0) {
        return VE_TLS_INVALID;
    }
    if (producer->stop || !producer->accepting) {
        return VE_TLS_CLOSED;
    }
    norm_key = ve_tls_normalize_hash_key(producer, hash_key);
    id = ve_tls_producer_next_log_id(producer);
    if (out_log_id) {
        *out_log_id = id;
    }
    builder = ve_tls_log_builder_create(norm_key);
    if (!builder) {
        return VE_TLS_DROP_ERROR;
    }
    if (ve_tls_log_builder_add_kv_lens(builder, id, time_ms, time_ns, has_time_ns ? 1 : 0, kvs, key_lens, val_lens, kv_count) != 0) {
        goto end;
    }
    raw_log = builder->logs;
    raw_log_size = builder->logs_len;
    builder->logs = NULL;
    builder->logs_len = 0;
    builder->logs_cap = 0;
    if (!raw_log || raw_log_size == 0) {
        goto end;
    }
    rc = ve_tls_persistent_append_with_retry_locked(producer, id, norm_key, raw_log, raw_log_size);
    if (rc != VE_TLS_OK) {
        goto end;
    }
    rc = ve_tls_enqueue_ingress_raw_owned_locked(
        producer,
        norm_key,
        raw_log,
        raw_log_size,
        id,
        time_ms,
        time_ns,
        has_time_ns ? 1 : 0,
        flush,
        1);
    raw_log = NULL;
end:
    ve_tls_free(raw_log);
    ve_tls_log_builder_free(builder);
    if (rc != VE_TLS_OK) {
        ve_tls_metric_inc_u64(&producer->m_logs_dropped_total, 1);
        ve_tls_metric_inc_u64(&producer->m_bytes_dropped_total, 0);
        ve_tls_metrics_emit(producer, "log_dropped", 1, 0);
    }
    return rc;
}

typedef struct {
    ve_tls_send_done_fn cb;
    void * cb_param;
    ve_tls_send_done_v2_fn cb2;
    void * cb2_param;
} ve_tls_send_callbacks;

typedef struct {
    ve_tls_producer * producer;
} ve_tls_recover_ctx;

static ve_tls_send_callbacks ve_tls_capture_callbacks(ve_tls_producer * producer) {
    ve_tls_send_callbacks cbs;
    memset(&cbs, 0, sizeof(cbs));
    if (!producer) {
        return cbs;
    }
    cbs.cb = __atomic_load_n(&producer->send_done, __ATOMIC_ACQUIRE);
    cbs.cb_param = __atomic_load_n(&producer->send_done_param, __ATOMIC_ACQUIRE);
    cbs.cb2 = __atomic_load_n(&producer->send_done_v2, __ATOMIC_ACQUIRE);
    cbs.cb2_param = __atomic_load_n(&producer->send_done_v2_param, __ATOMIC_ACQUIRE);
    return cbs;
}

static int ve_tls_recover_record_to_queue(
    int64_t log_id,
    int64_t enqueue_time_ms,
    const char * hash_key,
    const unsigned char * payload,
    size_t payload_size,
    void * user
) {
    ve_tls_recover_ctx * ctx = (ve_tls_recover_ctx *)user;
    unsigned char * copy = NULL;
    size_t copy_size = payload_size;
    int64_t queue_time_ms = 0;
    if (!ctx || !ctx->producer || !payload || payload_size == 0) {
        return -1;
    }
    ve_tls_producer * producer = ctx->producer;
    int64_t now_ms = producer->config.platform.time_ms
        ? producer->config.platform.time_ms()
        : 0;
    int expired = producer->config.persistent_max_log_delay_ms > 0 &&
        enqueue_time_ms > 0 && now_ms > enqueue_time_ms &&
        now_ms - enqueue_time_ms > producer->config.persistent_max_log_delay_ms;
    if (expired &&
        producer->config.persistent_expired_log_policy == VE_TLS_PEXPIRED_DROP) {
        ve_tls_producer_advance_next_log_id(producer, log_id + 1);
        ve_tls_metric_inc_u64(&producer->m_logs_dropped_total, 1);
        ve_tls_metric_inc_u64(&producer->m_bytes_dropped_total, payload_size);
        ve_tls_metrics_emit(producer, "persistent_expired_drop", log_id, enqueue_time_ms);
        ve_tls_persistent_on_final_result(producer, VE_TLS_OK, log_id, log_id);
        return 0;
    }
    if (expired) {
        int rewrite_rc = ve_tls_log_payload_rewrite_time(
            payload, payload_size, now_ms, &copy, &copy_size);
        if (rewrite_rc == -1) {
            return -1;
        }
        if (rewrite_rc == 0) {
            queue_time_ms = now_ms;
            ve_tls_metrics_emit(producer, "persistent_expired_rewrite", log_id, enqueue_time_ms);
        } else {
            ve_tls_metrics_emit(producer, "persistent_expired_rewrite_skipped", log_id, enqueue_time_ms);
        }
    }
    if (!copy) {
        copy = (unsigned char *)ve_tls_malloc(payload_size);
        if (!copy) {
            return -1;
        }
        memcpy(copy, payload, payload_size);
        copy_size = payload_size;
    }
    producer->config.platform.mutex_lock(producer->mutex);
    ve_tls_producer_advance_next_log_id(producer, log_id + 1);
    if (ve_tls_enqueue_ingress_raw_owned_locked(
            producer,
            ve_tls_normalize_hash_key(producer, hash_key),
            copy,
            copy_size,
            log_id,
            queue_time_ms,
            0,
            0,
            0,
            1) != VE_TLS_OK) {
        producer->config.platform.mutex_unlock(producer->mutex);
        return -1;
    }
    producer->config.platform.mutex_unlock(producer->mutex);
    return 0;
}

static void ve_tls_persistent_free_ack_ranges(ve_tls_producer * producer) {
    ve_tls_completed_ack_range * cur;
    if (!producer) {
        return;
    }
    cur = producer->persistent_ack_head;
    while (cur) {
        ve_tls_completed_ack_range * next = cur->next;
        ve_tls_free(cur);
        cur = next;
    }
    producer->persistent_ack_head = NULL;
}

static int64_t ve_tls_persistent_record_completed_range_locked(ve_tls_producer * producer, int64_t start_id, int64_t end_id) {
    int64_t acked;
    int64_t advance_to;
    ve_tls_completed_ack_range * prev;
    ve_tls_completed_ack_range * cur;
    if (!producer || !producer->persistent || start_id <= 0 || end_id < start_id) {
        return 0;
    }
    acked = producer->persistent->checkpoint.acked_log_id;
    if (end_id <= acked) {
        return 0;
    }
    if (start_id <= acked) {
        start_id = acked + 1;
    }
    if (start_id > acked + 1) {
        ve_tls_completed_ack_range * node;
        prev = NULL;
        cur = producer->persistent_ack_head;
        while (cur && cur->end_id < start_id - 1) {
            prev = cur;
            cur = cur->next;
        }
        while (cur && cur->start_id <= end_id + 1) {
            ve_tls_completed_ack_range * next = cur->next;
            if (cur->start_id < start_id) {
                start_id = cur->start_id;
            }
            if (cur->end_id > end_id) {
                end_id = cur->end_id;
            }
            if (prev) {
                prev->next = next;
            } else {
                producer->persistent_ack_head = next;
            }
            ve_tls_free(cur);
            cur = next;
        }
        node = (ve_tls_completed_ack_range *)ve_tls_calloc(1, sizeof(*node));
        if (!node) {
            return 0;
        }
        node->start_id = start_id;
        node->end_id = end_id;
        if (prev) {
            node->next = prev->next;
            prev->next = node;
        } else {
            node->next = producer->persistent_ack_head;
            producer->persistent_ack_head = node;
        }
        return 0;
    }

    advance_to = end_id;
    prev = NULL;
    cur = producer->persistent_ack_head;
    while (cur && cur->start_id <= advance_to + 1) {
        ve_tls_completed_ack_range * next = cur->next;
        if (cur->end_id > advance_to) {
            advance_to = cur->end_id;
        }
        if (prev) {
            prev->next = next;
        } else {
            producer->persistent_ack_head = next;
        }
        ve_tls_free(cur);
        cur = next;
    }
    return advance_to > acked ? advance_to : 0;
}

void ve_tls_persistent_on_final_result(ve_tls_producer * producer, ve_tls_result result, int64_t start_id, int64_t end_id) {
    int64_t ack_to = 0;
    int checkpoint_save_failed = 0;
    if (!ve_tls_persistent_enabled(producer)) {
        return;
    }
    /* Delivery failures describe the current attempt, not a durable drop policy. */
    if (result != VE_TLS_OK) {
        return;
    }
    if (start_id <= 0 || end_id <= 0 || end_id < start_id) {
        return;
    }
    if (producer->persistent_mutex) {
        producer->config.platform.mutex_lock(producer->persistent_mutex);
    }
    ack_to = ve_tls_persistent_record_completed_range_locked(producer, start_id, end_id);
    if (ack_to > 0) {
        if (ve_tls_persistent_ack_range(producer->persistent, 1, ack_to) != 0 &&
            producer->persistent->checkpoint.acked_log_id >= ack_to &&
            producer->persistent->durable_checkpoint_acked_log_id < ack_to) {
            checkpoint_save_failed = 1;
        }
    }
    if (producer->persistent_mutex) {
        producer->config.platform.mutex_unlock(producer->persistent_mutex);
    }
    if (checkpoint_save_failed) {
        ve_tls_metrics_emit(producer, "persistent_checkpoint_save_failed", start_id, end_id);
    }
}

static void ve_tls_drop_one_with_error(ve_tls_send_callbacks cbs, size_t bytes, int64_t id, const char * code, const char * message) {
    ve_tls_error err;
    memset(&err, 0, sizeof(err));
    err.http_code = -1;
    err.transport_kind = VE_TLS_TRANSPORT_GENERIC;
    err.transport_code = 0;
    err.retryable = 0;
    err.error_code = (code && code[0] != 0) ? ve_tls_strdup(code) : ve_tls_strdup("ClientError");
    err.error_message = (message && message[0] != 0) ? ve_tls_strdup(message) : ve_tls_strdup("drop");
    if (cbs.cb) {
        cbs.cb(VE_TLS_DROP_ERROR, bytes, 0, NULL, err.error_message, NULL, cbs.cb_param, id, id);
    }
    if (cbs.cb2) {
        cbs.cb2(VE_TLS_DROP_ERROR, bytes, 0, &err, NULL, cbs.cb2_param, id, id);
    }
    ve_tls_error_free_fields(&err);
}

typedef struct {
    ve_tls_producer * producer;
    const char * norm_key;
    ve_tls_log_group_builder * builder;
} ve_tls_tls_batch;

struct ve_tls_log_template {
    ve_tls_producer * producer;
    char ** keys;
    size_t * key_lens;
    size_t key_count;
    char * hash_key;
};

static __thread ve_tls_tls_batch g_tls_batch;
static int64_t g_send_cfg_version_seed = 1;
static int64_t g_static_cred_version_seed = 1;
static const size_t VE_TLS_TLS_BATCH_SHRINK_THRESHOLD = 1024 * 1024;
static const size_t VE_TLS_TLS_BATCH_SHRINK_TO = 64 * 1024;

static void ve_tls_tls_batch_reset(ve_tls_log_group_builder * b) {
    if (!b) {
        return;
    }
    b->logs_len = 0;
    b->log_count = 0;
    b->earliest = 0;
    b->latest = 0;
    b->start_id = 0;
    b->end_id = 0;
    b->last_time_ms = 0;
    b->last_time_ns = 0;
    b->last_has_time_ns = 0;
    b->first_append_ms = 0;
    ve_tls_log_builder_shrink_if_needed(b, VE_TLS_TLS_BATCH_SHRINK_THRESHOLD, VE_TLS_TLS_BATCH_SHRINK_TO);
}

static int ve_tls_wait_buffer_space_locked(ve_tls_producer * producer, size_t need_bytes, int reserve_for_send);
int ve_tls_ingress_task_merge_locked(ve_tls_producer * producer, const ve_tls_ingress_task * task) {
    if (!producer || !task || !task->batch || task->batch->log_count == 0 || task->batch->logs_len == 0) {
        return 0;
    }
    const char * norm_key = task->norm_key ? task->norm_key : ve_tls_normalize_hash_key(producer, NULL);
    ve_tls_log_group_builder * tb = task->batch;
    ve_tls_key_queue * q = NULL;
    ve_tls_log_group_builder * b = NULL;
    int is_default_builder = 0;
    if (producer->fast_builder && producer->default_norm_key == norm_key) {
        if (!producer->default_builder) {
            producer->default_builder = ve_tls_log_builder_create(norm_key);
            if (!producer->default_builder) {
                return -1;
            }
            producer->default_builder->first_append_ms = producer->config.platform.time_ms ? producer->config.platform.time_ms() : 0;
        }
        b = producer->default_builder;
        is_default_builder = 1;
    } else {
        q = ve_tls_key_queue_get_or_create(producer, norm_key);
        if (!q) {
            if (producer->config.key_queue_max_active > 0 &&
                producer->key_queue_count >= (size_t)producer->config.key_queue_max_active) {
                return VE_TLS_INGRESS_MERGE_KEY_QUEUE_LIMIT;
            }
            return -1;
        }
        if (!q->builder) {
            q->builder = ve_tls_log_builder_create(q->key);
            if (!q->builder) {
                return -1;
            }
            q->builder->first_append_ms = producer->config.platform.time_ms ? producer->config.platform.time_ms() : 0;
        }
        b = q->builder;
    }
    if (b->first_append_ms == 0) {
        b->first_append_ms = tb->first_append_ms > 0 ? tb->first_append_ms : (producer->config.platform.time_ms ? producer->config.platform.time_ms() : 0);
    }
    size_t prev = b->logs_len;
    if (ve_tls_log_builder_append(b, tb->logs, tb->logs_len, tb->log_count, tb->earliest, tb->latest, tb->start_id, tb->end_id, tb->last_time_ms, tb->last_time_ns, tb->last_has_time_ns) != 0) {
        return -1;
    }
    size_t delta = b->logs_len - prev;
    producer->queue_bytes += delta;

    int wake_worker = 0;
    if (task->force_flush) {
        ve_tls_log_group_builder * sealed = b;
        if (is_default_builder) {
            producer->default_builder = NULL;
        } else {
            q->builder = NULL;
        }
        sealed->next = NULL;
        if (producer->sealed_tail) {
            producer->sealed_tail->next = sealed;
        } else {
            producer->sealed_head = sealed;
        }
        producer->sealed_tail = sealed;
        producer->flush_requested = 1;
        wake_worker = 1;
    } else {
        size_t byte_limit = producer->config.log_bytes_per_package > 0 ? (size_t)producer->config.log_bytes_per_package : 0;
        if (producer->config.agg_max_raw_bytes_per_request > 0) {
            size_t max_raw = (size_t)producer->config.agg_max_raw_bytes_per_request;
            if (byte_limit == 0 || byte_limit > max_raw) {
                byte_limit = max_raw;
            }
        }
        int should_seal = 0;
        if (producer->config.log_count_per_package > 0 && b->log_count >= producer->config.log_count_per_package) {
            should_seal = 1;
        }
        if (!should_seal && byte_limit > 0 && b->logs_len >= byte_limit) {
            should_seal = 1;
        }
        if (should_seal) {
            ve_tls_log_group_builder * sealed = b;
            if (is_default_builder) {
                producer->default_builder = NULL;
            } else {
                q->builder = NULL;
            }
            sealed->next = NULL;
            if (producer->sealed_tail) {
                producer->sealed_tail->next = sealed;
            } else {
                producer->sealed_head = sealed;
            }
            producer->sealed_tail = sealed;
            producer->flush_requested = 1;
            wake_worker = 1;
        }
    }
    if (!wake_worker &&
        producer->config.flush_interval_ms > 0 &&
        b &&
        b->log_count == 1) {
        wake_worker = 1;
    }
    if (wake_worker) {
        producer->config.platform.cond_signal(producer->cond);
    }
    return 0;
}

/* 归还 tls_bytes 预算并唤醒可能在 ve_tls_wait_buffer_space_locked() 上等待的线程。
 * 调用方必须当前未持有 producer->mutex。 */
static void ve_tls_release_tls_bytes(ve_tls_producer * producer, size_t bytes) {
    if (!producer || bytes == 0) {
        return;
    }
    __atomic_fetch_sub(&producer->tls_bytes, bytes, __ATOMIC_RELAXED);
    if (!producer->mutex || !producer->cond) {
        return;
    }
    producer->config.platform.mutex_lock(producer->mutex);
    producer->config.platform.cond_broadcast(producer->cond);
    producer->config.platform.mutex_unlock(producer->mutex);
}

static int ve_tls_tls_batch_flush_locked(ve_tls_producer * producer, const char * norm_key, ve_tls_log_group_builder * tb, int force_flush) {
    VE_TLS_ALLOC_SITE("tls_batch_flush");
    if (!producer || !tb || tb->log_count == 0 || tb->logs_len == 0) {
        return 0;
    }
    int wrc = ve_tls_wait_buffer_space_locked(producer, tb->logs_len, 0);
    if (wrc != 0) {
        return wrc;
    }
    ve_tls_log_group_builder * ingress_batch = ve_tls_log_builder_create(norm_key);
    if (!ingress_batch) {
        return -1;
    }
    ingress_batch->logs = tb->logs;
    ingress_batch->logs_len = tb->logs_len;
    ingress_batch->logs_cap = tb->logs_cap;
    ingress_batch->log_count = tb->log_count;
    ingress_batch->earliest = tb->earliest;
    ingress_batch->latest = tb->latest;
    ingress_batch->start_id = tb->start_id;
    ingress_batch->end_id = tb->end_id;
    ingress_batch->last_time_ms = tb->last_time_ms;
    ingress_batch->last_time_ns = tb->last_time_ns;
    ingress_batch->last_has_time_ns = tb->last_has_time_ns;
    ingress_batch->first_append_ms = tb->first_append_ms;
    tb->logs = NULL;
    tb->logs_len = 0;
    tb->logs_cap = 0;
    tb->log_count = 0;
    tb->earliest = 0;
    tb->latest = 0;
    tb->start_id = 0;
    tb->end_id = 0;
    tb->last_time_ms = 0;
    tb->last_time_ns = 0;
    tb->last_has_time_ns = 0;
    tb->first_append_ms = 0;
    int wait_ms = 0;
    if (producer->config.buffer_full_policy == VE_TLS_BUFFER_FULL_BLOCK) {
        wait_ms = producer->config.buffer_full_block_timeout_ms;
        if (wait_ms == 0) {
            wait_ms = -1;
        }
    }
    int qrc = ve_tls_ingress_queue_push_locked(producer, ingress_batch->norm_key, ingress_batch, force_flush, wait_ms);
    if (qrc != 0) {
        tb->logs = ingress_batch->logs;
        tb->logs_len = ingress_batch->logs_len;
        tb->logs_cap = ingress_batch->logs_cap;
        tb->log_count = ingress_batch->log_count;
        tb->earliest = ingress_batch->earliest;
        tb->latest = ingress_batch->latest;
        tb->start_id = ingress_batch->start_id;
        tb->end_id = ingress_batch->end_id;
        tb->last_time_ms = ingress_batch->last_time_ms;
        tb->last_time_ns = ingress_batch->last_time_ns;
        tb->last_has_time_ns = ingress_batch->last_has_time_ns;
        tb->first_append_ms = ingress_batch->first_append_ms;
        ingress_batch->logs = NULL;
        ingress_batch->logs_len = 0;
        ingress_batch->logs_cap = 0;
        ingress_batch->log_count = 0;
        ve_tls_log_builder_free(ingress_batch);
        return qrc;
    }
    __atomic_fetch_sub(&producer->tls_bytes, ingress_batch->logs_len, __ATOMIC_RELAXED);
    ve_tls_tls_batch_reset(tb);
    return 0;
}

static int ve_tls_tls_batch_merge_locked(ve_tls_producer * producer, const char * norm_key, ve_tls_log_group_builder * tb) {
    if (!producer || !tb || tb->log_count == 0 || tb->logs_len == 0) {
        return 0;
    }
    int wrc = ve_tls_wait_buffer_space_locked(producer, tb->logs_len, 0);
    if (wrc != 0) {
        return wrc;
    }
    ve_tls_ingress_task task;
    memset(&task, 0, sizeof(task));
    task.norm_key = norm_key;
    task.batch = tb;
    task.force_flush = 0;
    if (ve_tls_ingress_task_merge_locked(producer, &task) != 0) {
        return -1;
    }
    __atomic_fetch_sub(&producer->tls_bytes, tb->logs_len, __ATOMIC_RELAXED);
    ve_tls_tls_batch_reset(tb);
    return 0;
}

static int ve_tls_try_add_log_tls_batching(
    ve_tls_producer * producer,
    const char * hash_key,
    const char * norm_key,
    int64_t time_ms,
    uint32_t time_ns,
    int32_t has_time_ns,
    const ve_tls_kv * kvs,
    const size_t * key_lens,
    const size_t * val_lens,
    size_t kv_count,
    int flush,
    int64_t * out_log_id,
    ve_tls_result * out_rc) {
    if (!producer || !out_rc) {
        return 0;
    }
    if (!(!hash_key || hash_key[0] == 0)) {
        return 0;
    }
    if (!(producer->config.ordered_send == 0)) {
        return 0;
    }

    size_t estimated = ve_tls_log_builder_estimate_kv_lens_size(time_ms, time_ns, has_time_ns, key_lens, val_lens, kv_count);
    if (estimated == (size_t)-1) {
        /* size 估算溢出：直接拒绝该日志，避免下游基于回绕值做预算/编码 */
        *out_rc = VE_TLS_INVALID;
        return 1;
    }
    producer->config.platform.mutex_lock(producer->mutex);
    if (producer->stop || !producer->accepting) {
        producer->config.platform.mutex_unlock(producer->mutex);
        *out_rc = VE_TLS_CLOSED;
        return 1;
    }
    int wrc = ve_tls_wait_buffer_space_locked(producer, estimated, 0);
    if (wrc != 0) {
        producer->config.platform.mutex_unlock(producer->mutex);
        *out_rc = ve_tls_map_wait_error_to_result(producer, wrc, estimated);
        return 1;
    }
    __atomic_fetch_add(&producer->tls_bytes, estimated, __ATOMIC_RELAXED);
    producer->config.platform.mutex_unlock(producer->mutex);

    if (g_tls_batch.producer != producer || g_tls_batch.norm_key != norm_key) {
        if (g_tls_batch.producer && g_tls_batch.builder) {
            if (g_tls_batch.builder->logs_len > 0) {
                ve_tls_release_tls_bytes(g_tls_batch.producer, g_tls_batch.builder->logs_len);
            }
            ve_tls_log_builder_free(g_tls_batch.builder);
        }
        memset(&g_tls_batch, 0, sizeof(g_tls_batch));
        g_tls_batch.producer = producer;
        g_tls_batch.norm_key = norm_key;
        g_tls_batch.builder = ve_tls_log_builder_create(norm_key);
        if (!g_tls_batch.builder) {
            ve_tls_release_tls_bytes(producer, estimated);
            *out_rc = VE_TLS_DROP_ERROR;
            return 1;
        }
        ve_tls_tls_batch_reset(g_tls_batch.builder);
    }

    if (!g_tls_batch.builder) {
        ve_tls_release_tls_bytes(producer, estimated);
        *out_rc = VE_TLS_DROP_ERROR;
        return 1;
    }

    if (g_tls_batch.builder->log_count == 0) {
        producer->config.platform.mutex_lock(producer->mutex);
        int closed = (producer->stop || !producer->accepting) ? 1 : 0;
        producer->config.platform.mutex_unlock(producer->mutex);
        if (closed) {
            ve_tls_release_tls_bytes(producer, estimated);
            *out_rc = VE_TLS_CLOSED;
            return 1;
        }
    }

    int64_t id = ve_tls_producer_next_log_id(producer);
    if (out_log_id) {
        *out_log_id = id;
    }
    size_t prev_len = g_tls_batch.builder->logs_len;
    if (ve_tls_log_builder_add_kv_lens(g_tls_batch.builder, id, time_ms, time_ns, has_time_ns, kvs, key_lens, val_lens, kv_count) != 0) {
        ve_tls_release_tls_bytes(producer, prev_len + estimated);
        ve_tls_tls_batch_reset(g_tls_batch.builder);
        ve_tls_metric_inc_u64(&producer->m_logs_dropped_total, 1);
        ve_tls_metric_inc_u64(&producer->m_bytes_dropped_total, 0);
        ve_tls_metrics_emit(producer, "log_dropped_enqueue_alloc_failed", 1, 0);
        ve_tls_metrics_emit(producer, "log_dropped", 1, 0);
        *out_rc = VE_TLS_DROP_ERROR;
        return 1;
    }
    size_t delta = g_tls_batch.builder->logs_len - prev_len;
    if (delta > estimated) {
        __atomic_fetch_add(&producer->tls_bytes, delta - estimated, __ATOMIC_RELAXED);
    } else if (estimated > delta) {
        ve_tls_release_tls_bytes(producer, estimated - delta);
    }
    ve_tls_metric_inc_u64(&producer->m_logs_enqueued_total, 1);
    ve_tls_metric_inc_u64(&producer->m_bytes_enqueued_total, delta);
    ve_tls_metrics_emit(producer, "log_enqueued", 1, (int64_t)delta);

    size_t merge_count = (producer->config.log_count_per_package > 0) ? (size_t)producer->config.log_count_per_package : 256;
    size_t merge_bytes = (producer->config.log_bytes_per_package > 0) ? (size_t)producer->config.log_bytes_per_package : 0;
    if (producer->config.agg_max_raw_bytes_per_request > 0) {
        size_t max_raw = (size_t)producer->config.agg_max_raw_bytes_per_request;
        if (merge_bytes == 0 || merge_bytes > max_raw) {
            merge_bytes = max_raw;
        }
    }
    if (merge_bytes == 0) {
        merge_bytes = 256 * 1024;
    }
    if (producer->config.max_buffer_bytes > 0) {
        size_t cap = (size_t)producer->config.max_buffer_bytes;
        size_t quarter = cap / 4;
        if (quarter >= 16 * 1024 && merge_bytes > quarter) {
            merge_bytes = quarter;
        }
    }

    int should_merge = flush;
    if (!should_merge && merge_count > 0 && (size_t)g_tls_batch.builder->log_count >= merge_count) {
        should_merge = 1;
    }
    if (!should_merge && merge_bytes > 0 && g_tls_batch.builder->logs_len >= merge_bytes) {
        should_merge = 1;
    }
    int expose_for_timeout = !should_merge && producer->config.flush_interval_ms > 0;
    if (should_merge || expose_for_timeout) {
        producer->config.platform.mutex_lock(producer->mutex);
        int frc = expose_for_timeout
            ? ve_tls_tls_batch_merge_locked(producer, norm_key, g_tls_batch.builder)
            : ve_tls_tls_batch_flush_locked(producer, norm_key, g_tls_batch.builder, flush);
        producer->config.platform.mutex_unlock(producer->mutex);
        if (frc != 0) {
            if (g_tls_batch.builder->logs_len > 0) {
                ve_tls_release_tls_bytes(producer, g_tls_batch.builder->logs_len);
            }
            ve_tls_tls_batch_reset(g_tls_batch.builder);
            if (frc == -2) {
                *out_rc = VE_TLS_CLOSED;
            } else if (frc == -3) {
                *out_rc = VE_TLS_TIMEOUT;
            } else {
                *out_rc = VE_TLS_DROP_ERROR;
            }
            return 1;
        }
    }
    *out_rc = VE_TLS_OK;
    return 1;
}

static int ve_tls_producer_send_queue_count_locked(ve_tls_producer * producer) {
    if (!producer || !producer->send_queue.mutex) {
        return 0;
    }
    producer->send_queue.platform->mutex_lock(producer->send_queue.mutex);
    size_t sc = producer->send_queue.count;
    producer->send_queue.platform->mutex_unlock(producer->send_queue.mutex);
    return sc != 0;
}

static int ve_tls_producer_is_flush_stage_drained_locked(ve_tls_producer * producer) {
    if (!producer) {
        return 1;
    }
    if (producer->queue_count != 0 || producer->ingress_queue_count != 0 || producer->worker_flushing_count > 0 || producer->active_persistent_appends > 0 || producer->sealed_head) {
        return 0;
    }
    if (ve_tls_producer_send_queue_count_locked(producer)) {
        return 0;
    }
    if (producer->default_builder && producer->default_builder->log_count > 0) {
        return 0;
    }
    for (size_t i = 0; i < producer->key_bucket_count; i++) {
        ve_tls_key_queue * q = producer->key_buckets[i];
        while (q) {
            if (q->count != 0 || (q->builder && q->builder->log_count > 0)) {
                return 0;
            }
            q = q->hnext;
        }
    }
    return 1;
}

int ve_tls_producer_is_drained_locked(ve_tls_producer * producer) {
    if (!producer) {
        return 1;
    }
    if (!ve_tls_producer_is_flush_stage_drained_locked(producer)) {
        return 0;
    }
    if (__atomic_load_n(&producer->fast_inflight, __ATOMIC_RELAXED) > 0) {
        return 0;
    }
    for (size_t i = 0; i < producer->key_bucket_count; i++) {
        ve_tls_key_queue * q = producer->key_buckets[i];
        while (q) {
            if (q->inflight != 0) {
                return 0;
            }
            q = q->hnext;
        }
    }
    return 1;
}

static ve_tls_result ve_tls_producer_wait_for_close_stage_locked(
    ve_tls_producer * producer,
    int32_t timeout_ms,
    int (*predicate)(ve_tls_producer *),
    const char * ok_metric,
    const char * timeout_metric
) {
    int64_t start_ms = producer->config.platform.time_ms ? producer->config.platform.time_ms() : 0;
    ve_tls_cond * wait_cond = producer->send_cond ? producer->send_cond : producer->cond;
    for (;;) {
        if (predicate(producer)) {
            if (ok_metric) {
                ve_tls_metrics_emit(producer, ok_metric, 1, 0);
            }
            return VE_TLS_OK;
        }
        if (timeout_ms == 0) {
            if (timeout_metric) {
                ve_tls_metrics_emit(producer, timeout_metric, 1, 0);
            }
            return VE_TLS_TIMEOUT;
        }
        int wait_ms = 50;
        if (timeout_ms > 0) {
            int64_t now = producer->config.platform.time_ms ? producer->config.platform.time_ms() : start_ms;
            int64_t elapsed = now - start_ms;
            int64_t remain = (int64_t)timeout_ms - elapsed;
            if (remain <= 0) {
                if (timeout_metric) {
                    ve_tls_metrics_emit(producer, timeout_metric, 1, 0);
                }
                return VE_TLS_TIMEOUT;
            }
            if (remain < wait_ms) {
                wait_ms = (int)remain;
            }
        }
        (void)producer->config.platform.cond_timedwait_ms(wait_cond, producer->mutex, wait_ms);
    }
}

static ve_tls_result ve_tls_producer_begin_close_locked(ve_tls_producer * producer) {
    if (g_tls_batch.producer == producer && g_tls_batch.builder && g_tls_batch.builder->log_count > 0) {
        int frc = ve_tls_tls_batch_flush_locked(producer, g_tls_batch.norm_key, g_tls_batch.builder, 1);
        if (frc != 0) {
            if (frc == -2) {
                return VE_TLS_CLOSED;
            }
            if (frc == -3) {
                return VE_TLS_TIMEOUT;
            }
            return VE_TLS_DROP_ERROR;
        }
    }
    producer->accepting = 0;
    producer->closing = 1;
    producer->flush_requested = 1;
    producer->config.platform.cond_broadcast(producer->cond);
    if (producer->send_cond) {
        producer->config.platform.cond_broadcast(producer->send_cond);
    }
    return VE_TLS_OK;
}

static void ve_tls_producer_finish_close_locked(ve_tls_producer * producer) {
    producer->closing = 0;
    producer->stop = 1;
    producer->config.platform.cond_broadcast(producer->cond);
    if (producer->send_cond) {
        producer->config.platform.cond_broadcast(producer->send_cond);
    }
}

void ve_tls_config_init(ve_tls_config * config) {
    ve_tls_config defaults;
    if (!config) {
        return;
    }
    ve_tls_producer_config_init(&defaults);
    memcpy(config, &defaults, VE_TLS_CONFIG_LEGACY_SIZE);
}

ve_tls_result ve_tls_config_init_versioned(
    ve_tls_config * config,
    size_t config_size,
    uint32_t config_version
) {
    size_t expected_size;
    ve_tls_config defaults;
    if (!config) {
        return VE_TLS_INVALID;
    }
    expected_size = config_version == VE_TLS_CONFIG_VERSION_1
        ? VE_TLS_CONFIG_VERSION_1_SIZE
        : (config_version == VE_TLS_CONFIG_VERSION_2 ? sizeof(ve_tls_config) : 0);
    if (expected_size == 0 || config_size != expected_size) {
        return VE_TLS_INVALID;
    }
    ve_tls_producer_config_init(&defaults);
    memcpy(config, &defaults, expected_size);
    return VE_TLS_OK;
}

static ve_tls_producer * ve_tls_producer_create_current(const ve_tls_config * config) {
    if (!config) {
        return NULL;
    }
    VE_TLS_ALLOC_SITE("producer_create");
    ve_tls_config effective = *config;
    ve_tls_producer_config_apply_runtime_defaults(&effective);
    if (!ve_tls_config_is_valid_for_create(&effective)) {
        return NULL;
    }
    ve_tls_warn_risky_block_config(&effective);
    ve_tls_producer * producer = (ve_tls_producer *)ve_tls_calloc(1, sizeof(ve_tls_producer));
    if (!producer) {
        return NULL;
    }
    producer->config = *config;
    producer->cfg_endpoint = ve_tls_strdup(config->endpoint);
    producer->cfg_region = ve_tls_strdup(config->region);
    producer->cfg_project_id = ve_tls_dup_cstr(config->project_id);
    producer->cfg_topic_id = ve_tls_strdup(config->topic_id);
    producer->cfg_source = ve_tls_dup_cstr(config->source);
    producer->cfg_file_name = ve_tls_dup_cstr(config->file_name);
    producer->cfg_context_flow = ve_tls_dup_cstr(config->context_flow);
    producer->cfg_hash_key = ve_tls_dup_cstr(config->hash_key);
    producer->cfg_access_key_id = config->access_key_id ? ve_tls_strdup(config->access_key_id) : NULL;
    producer->cfg_access_key_secret = config->access_key_secret ? ve_tls_strdup(config->access_key_secret) : NULL;
    producer->cfg_security_token = (config->security_token && config->security_token[0] != 0) ? ve_tls_strdup(config->security_token) : NULL;
    producer->cfg_api_version = ve_tls_dup_cstr(config->api_version);
    producer->cfg_compress_type = ve_tls_dup_cstr(config->compress_type);
    producer->cfg_ca_cert_path = ve_tls_dup_cstr(config->ca_cert_path);
    producer->cfg_proxy = ve_tls_dup_cstr(config->proxy);
    producer->cfg_user_agent = ve_tls_dup_cstr(config->user_agent);
    producer->cfg_persistent_file_path = ve_tls_dup_cstr(config->persistent_file_path);
    if (config->log_tag_count > 0 && !config->log_tags) {
        ve_tls_producer_destroy(producer);
        return NULL;
    }
    if (ve_tls_copy_log_tags(config->log_tags, config->log_tag_count, &producer->cfg_log_tags, &producer->cfg_log_tag_count) != 0) {
        ve_tls_producer_destroy(producer);
        return NULL;
    }
    if (!producer->cfg_endpoint || !producer->cfg_region || !producer->cfg_topic_id) {
        ve_tls_producer_destroy(producer);
        return NULL;
    }
    producer->config.endpoint = producer->cfg_endpoint;
    producer->config.region = producer->cfg_region;
    producer->config.project_id = producer->cfg_project_id;
    producer->config.topic_id = producer->cfg_topic_id;
    producer->config.source = producer->cfg_source;
    producer->config.file_name = producer->cfg_file_name;
    producer->config.context_flow = producer->cfg_context_flow;
    producer->config.log_tags = producer->cfg_log_tags;
    producer->config.log_tag_count = producer->cfg_log_tag_count;
    producer->config.hash_key = producer->cfg_hash_key;
    producer->config.access_key_id = producer->cfg_access_key_id;
    producer->config.access_key_secret = producer->cfg_access_key_secret;
    producer->config.security_token = producer->cfg_security_token;
    producer->config.api_version = producer->cfg_api_version;
    producer->config.compress_type = producer->cfg_compress_type;
    producer->config.ca_cert_path = producer->cfg_ca_cert_path;
    producer->config.proxy = producer->cfg_proxy;
    producer->config.user_agent = producer->cfg_user_agent;
    producer->config.persistent_file_path = producer->cfg_persistent_file_path;
    ve_tls_producer_config_apply_runtime_defaults(&producer->config);
    producer->send_reserved_bytes = ve_tls_effective_send_reserved_bytes(&producer->config);
    producer->send_cfg_version = __atomic_add_fetch(&g_send_cfg_version_seed, 1, __ATOMIC_RELAXED);
    producer->static_cred_version = __atomic_add_fetch(&g_static_cred_version_seed, 1, __ATOMIC_RELAXED);
    if (ve_tls_producer_build_group_suffix(producer) != 0) {
        ve_tls_producer_destroy(producer);
        return NULL;
    }
    producer->mutex = producer->config.platform.mutex_create();
    producer->cond = producer->config.platform.cond_create();
    producer->send_cond = producer->config.platform.cond_create();
    if (!producer->mutex || !producer->cond || !producer->send_cond) {
        ve_tls_producer_destroy(producer);
        return NULL;
    }
    if (ve_tls_runtime_snapshot_refresh(producer) != 0) {
        ve_tls_producer_destroy(producer);
        return NULL;
    }
    if (ve_tls_obj_pool_init(&producer->send_task_pool, sizeof(ve_tls_send_task), 2048) != 0 ||
        ve_tls_obj_pool_init(&producer->header_buf_pool, 1024, 1024) != 0 ||
        ve_tls_obj_pool_init(&producer->compress_buf_pool, 64 * 1024, 256) != 0) {
        ve_tls_producer_destroy(producer);
        return NULL;
    }
    producer->next_id = 1;
    producer->accepting = 1;
    if (producer->config.use_persistent) {
        ve_tls_persistent_options popt;
        ve_tls_persistent_durability durability;
        producer->persistent_mutex = producer->config.platform.mutex_create();
        if (!producer->persistent_mutex) {
            ve_tls_producer_destroy(producer);
            return NULL;
        }
        producer->persistent = (ve_tls_persistent *)ve_tls_calloc(1, sizeof(ve_tls_persistent));
        if (!producer->persistent) {
            ve_tls_producer_destroy(producer);
            return NULL;
        }
        memset(&popt, 0, sizeof(popt));
        popt.platform = &producer->config.platform;
        popt.dir_path = producer->cfg_persistent_file_path;
        popt.instance_id = producer->cfg_topic_id;
        popt.owner_id = "ve-tls-producer";
        popt.owner_process_name = "ve-tls";
        popt.owner_pid = 0;
        popt.segment_max_bytes = (uint64_t)producer->config.max_persistent_file_size;
        popt.segment_max_records = (uint64_t)producer->config.max_persistent_log_count;
        popt.max_bytes = producer->config.persistent_max_bytes > 0
            ? (uint64_t)producer->config.persistent_max_bytes
            : (uint64_t)producer->config.max_persistent_file_size * (uint64_t)producer->config.max_persistent_file_count;
        popt.max_records = producer->config.persistent_max_records > 0
            ? (uint64_t)producer->config.persistent_max_records
            : (uint64_t)producer->config.max_persistent_log_count;
        popt.max_segments = producer->config.persistent_max_segments > 0
            ? (uint32_t)producer->config.persistent_max_segments
            : (uint32_t)producer->config.max_persistent_file_count;
        popt.high_watermark_pct = producer->config.persistent_high_watermark_pct;
        popt.low_watermark_pct = producer->config.persistent_low_watermark_pct;
        popt.overflow_policy = producer->config.persistent_overflow_policy;
        popt.sample_every_n = producer->config.persistent_sample_every_n;
        popt.block_timeout_ms = producer->config.persistent_block_timeout_ms;
        popt.now_ms = producer->config.platform.time_ms ? producer->config.platform.time_ms() : 0;
        popt.lease_timeout_ms = producer->config.persistent_lease_timeout_ms > 0 ? producer->config.persistent_lease_timeout_ms : 60000;
        popt.heartbeat_interval_ms = producer->config.persistent_heartbeat_interval_ms > 0 ? producer->config.persistent_heartbeat_interval_ms : 10000;
        popt.open_mode = producer->config.persistent_open_mode == VE_TLS_POPEN_FAIL_IF_OWNED
            ? VE_TLS_LEASE_OPEN_FAIL_IF_OWNED
            : VE_TLS_LEASE_OPEN_TAKEOVER_IF_STALE;
        if (ve_tls_resolve_persistent_durability(&producer->config, &durability) != 0) {
            ve_tls_producer_destroy(producer);
            return NULL;
        }
        popt.durability = durability;
        if (ve_tls_persistent_open(producer->persistent, &popt) != 0) {
            ve_tls_producer_destroy(producer);
            return NULL;
        }
    }
    producer->use_global_env = producer->config.use_global_env ? 1 : 0;
    producer->fast_send = 0;
    if (!producer->use_global_env &&
        producer->config.ordered_send == 0 &&
        producer->config.rate_limit_rps <= 0 &&
        producer->config.rate_limit_bps <= 0 &&
        producer->config.breaker_fail_threshold <= 0 &&
        producer->config.key_rate_limit_rps <= 0 &&
        producer->config.key_rate_limit_bps <= 0 &&
        producer->config.key_breaker_fail_threshold <= 0) {
        producer->fast_send = 1;
    }
    producer->fast_builder = 0;
    producer->default_norm_key = NULL;
    producer->default_builder = NULL;
    if (!producer->use_global_env &&
        producer->config.ordered_send == 0 &&
        producer->config.key_queue_max_active <= 0 &&
        producer->config.key_queue_idle_ttl_ms <= 0 &&
        producer->config.key_rate_limit_rps <= 0 &&
        producer->config.key_rate_limit_bps <= 0 &&
        producer->config.key_breaker_fail_threshold <= 0) {
        producer->fast_builder = 1;
        producer->default_norm_key = ve_tls_normalize_hash_key(producer, NULL);
    }
    if (!producer->use_global_env) {
        producer->sender_count = producer->config.send_thread_count > 0 ? producer->config.send_thread_count : 1;
        producer->senders = (ve_tls_thread **)ve_tls_calloc((size_t)producer->sender_count, sizeof(ve_tls_thread *));
        if (!producer->senders) {
            ve_tls_producer_destroy(producer);
            return NULL;
        }
    } else {
        producer->sender_count = 0;
        producer->senders = NULL;
    }
    producer->key_bucket_count = (size_t)(producer->config.key_queue_bucket_count > 0 ? producer->config.key_queue_bucket_count : 1024);
    producer->key_buckets = (ve_tls_key_queue **)ve_tls_calloc(producer->key_bucket_count, sizeof(ve_tls_key_queue *));
    if (!producer->key_buckets) {
        ve_tls_producer_destroy(producer);
        return NULL;
    }
    size_t sq_cap = (size_t)(producer->config.send_queue_size > 0 ? producer->config.send_queue_size : 1024);
    if (ve_tls_send_queue_init(&producer->send_queue, &producer->config.platform, sq_cap, &producer->send_task_pool) != 0) {
        ve_tls_producer_destroy(producer);
        return NULL;
    }
    size_t iq_cap = sq_cap > 0 ? sq_cap : 1024;
    if (ve_tls_ingress_queue_init(producer, iq_cap) != 0) {
        ve_tls_producer_destroy(producer);
        return NULL;
    }
    producer->worker_count = producer->config.pack_thread_count > 0 ? producer->config.pack_thread_count : 1;
    producer->workers = (ve_tls_thread **)ve_tls_calloc((size_t)producer->worker_count, sizeof(ve_tls_thread *));
    if (!producer->workers) {
        ve_tls_producer_destroy(producer);
        return NULL;
    }
    for (int32_t i = 0; i < producer->worker_count; i++) {
        producer->workers[i] = producer->config.platform.thread_create(ve_tls_worker_main, producer);
        if (!producer->workers[i]) {
            ve_tls_producer_destroy(producer);
            return NULL;
        }
    }
    for (int32_t i = 0; i < producer->sender_count; i++) {
        producer->senders[i] = producer->config.platform.thread_create(ve_tls_sender_main, producer);
        if (!producer->senders[i]) {
            ve_tls_producer_destroy(producer);
            return NULL;
        }
    }
    if (producer->use_global_env) {
        /* Publish only after every producer data structure and worker exists. */
        if (ve_tls_env_register_producer(producer) != 0) {
            ve_tls_producer_destroy(producer);
            return NULL;
        }
        ve_tls_env_notify(producer);
    }
    return producer;
}

ve_tls_producer * ve_tls_producer_create(const ve_tls_config * config) {
    ve_tls_config current;
    if (!config) {
        return NULL;
    }
    ve_tls_producer_config_init(&current);
    memcpy(&current, config, VE_TLS_CONFIG_LEGACY_SIZE);
    return ve_tls_producer_create_current(&current);
}

ve_tls_producer * ve_tls_producer_create_versioned(
    const ve_tls_config * config,
    size_t config_size,
    uint32_t config_version
) {
    ve_tls_config current;
    size_t expected_size = config_version == VE_TLS_CONFIG_VERSION_1
        ? VE_TLS_CONFIG_VERSION_1_SIZE
        : (config_version == VE_TLS_CONFIG_VERSION_2 ? sizeof(ve_tls_config) : 0);
    if (!config || expected_size == 0 || config_size != expected_size) {
        return NULL;
    }
    if (config_version == VE_TLS_CONFIG_VERSION_2) {
        return ve_tls_producer_create_current(config);
    }
    ve_tls_producer_config_init(&current);
    memcpy(&current, config, expected_size);
    return ve_tls_producer_create_current(&current);
}

static void ve_tls_runtime_update_finish(ve_tls_producer * producer) {
    producer->config.platform.mutex_lock(producer->mutex);
    if (producer->runtime_updates_inflight > 0) {
        producer->runtime_updates_inflight--;
    }
    producer->config.platform.cond_broadcast(producer->cond);
    producer->config.platform.mutex_unlock(producer->mutex);
}

ve_tls_result ve_tls_producer_update_endpoint(ve_tls_producer * producer, const char * endpoint, const char * region, const char * topic_id) {
    uint64_t backlog_records = 0;
    uint64_t backlog_bytes = 0;
    char * old_endpoint = NULL;
    char * old_region = NULL;
    char * old_topic_id = NULL;
    int64_t old_version = 0;
    int64_t next_version = 0;
    ve_tls_runtime_snapshot * next_snapshot = NULL;
    ve_tls_runtime_snapshot_patch patch;
    if (!producer) {
        return VE_TLS_INVALID;
    }
    VE_TLS_ALLOC_SITE("update_endpoint");
    if ((endpoint && !ve_tls_is_http_url(endpoint)) || (region && ve_tls_str_empty(region)) || (topic_id && ve_tls_str_empty(topic_id))) {
        return VE_TLS_INVALID;
    }
    char * new_endpoint = endpoint ? ve_tls_strdup(endpoint) : NULL;
    char * new_region = region ? ve_tls_strdup(region) : NULL;
    char * new_topic_id = topic_id ? ve_tls_strdup(topic_id) : NULL;
    if ((endpoint && !new_endpoint) || (region && !new_region) || (topic_id && !new_topic_id)) {
        ve_tls_free(new_endpoint);
        ve_tls_free(new_region);
        ve_tls_free(new_topic_id);
        return VE_TLS_DROP_ERROR;
    }
    producer->config.platform.mutex_lock(producer->mutex);
    if (producer->stop || producer->closing || !producer->accepting) {
        producer->config.platform.mutex_unlock(producer->mutex);
        ve_tls_free(new_endpoint);
        ve_tls_free(new_region);
        ve_tls_free(new_topic_id);
        return VE_TLS_CLOSED;
    }
    producer->runtime_updates_inflight++;
    int changed = 0;
    old_version = __atomic_load_n(&producer->send_cfg_version, __ATOMIC_ACQUIRE);
    if (new_endpoint) {
        changed++;
    }
    if (new_region) {
        changed++;
    }
    if (new_topic_id) {
        changed++;
    }
    if (changed) {
        const ve_tls_runtime_snapshot * base = atomic_load_explicit(
            &producer->runtime_snapshot, memory_order_acquire);
        memset(&patch, 0, sizeof(patch));
        next_version = old_version + changed;
        patch.send_cfg_version = next_version;
        patch.static_cred_version = base ? base->static_cred_version : 0;
        if (new_endpoint) {
            patch.field_mask |= VE_TLS_SNAPSHOT_PATCH_ENDPOINT;
            patch.endpoint = new_endpoint;
        }
        if (new_region) {
            patch.field_mask |= VE_TLS_SNAPSHOT_PATCH_REGION;
            patch.region = new_region;
        }
        if (new_topic_id) {
            patch.field_mask |= VE_TLS_SNAPSHOT_PATCH_TOPIC_ID;
            patch.topic_id = new_topic_id;
        }
        if (!base || ve_tls_runtime_snapshot_build_patched(base, &patch, &next_snapshot) != 0) {
            producer->config.platform.mutex_unlock(producer->mutex);
            ve_tls_free(new_endpoint);
            ve_tls_free(new_region);
            ve_tls_free(new_topic_id);
            ve_tls_metrics_emit(producer, "snapshot_refresh_failed", 1, 0);
            ve_tls_runtime_update_finish(producer);
            return VE_TLS_DROP_ERROR;
        }
        old_endpoint = producer->cfg_endpoint;
        old_region = producer->cfg_region;
        old_topic_id = producer->cfg_topic_id;
        if (new_endpoint) {
            producer->cfg_endpoint = new_endpoint;
            producer->config.endpoint = new_endpoint;
        }
        if (new_region) {
            producer->cfg_region = new_region;
            producer->config.region = new_region;
        }
        if (new_topic_id) {
            producer->cfg_topic_id = new_topic_id;
            producer->config.topic_id = new_topic_id;
        }
        ve_tls_runtime_snapshot_publish_locked(producer, next_snapshot);
        __atomic_store_n(&producer->send_cfg_version, next_version, __ATOMIC_RELEASE);
    }
    producer->config.platform.mutex_unlock(producer->mutex);
    if (new_endpoint) {
        ve_tls_free(old_endpoint);
    }
    if (new_region) {
        ve_tls_free(old_region);
    }
    if (new_topic_id) {
        ve_tls_free(old_topic_id);
    }
    if (changed && producer->persistent) {
        if (producer->persistent_mutex) {
            producer->config.platform.mutex_lock(producer->persistent_mutex);
        }
        backlog_records = producer->persistent->current_records;
        backlog_bytes = producer->persistent->current_bytes;
        if (producer->persistent_mutex) {
            producer->config.platform.mutex_unlock(producer->persistent_mutex);
        }
    }
    if (backlog_records > 0) {
        ve_tls_metrics_emit(
            producer,
            "persistent_backlog_retarget",
            backlog_records > (uint64_t)INT64_MAX ? INT64_MAX : (int64_t)backlog_records,
            backlog_bytes > (uint64_t)INT64_MAX ? INT64_MAX : (int64_t)backlog_bytes);
    }
    ve_tls_metrics_emit(producer, "config_update_endpoint", 1, 0);
    ve_tls_runtime_update_finish(producer);
    return VE_TLS_OK;
}

ve_tls_result ve_tls_producer_update_static_credentials(ve_tls_producer * producer, const char * access_key_id, const char * access_key_secret, const char * security_token) {
    char * old_ak = NULL;
    char * old_sk = NULL;
    char * old_tok = NULL;
    int64_t old_version = 0;
    int64_t next_version = 0;
    ve_tls_runtime_snapshot * next_snapshot = NULL;
    ve_tls_runtime_snapshot_patch patch;
    if (!producer) {
        return VE_TLS_INVALID;
    }
    VE_TLS_ALLOC_SITE("update_credentials");
    if ((access_key_id && ve_tls_str_empty(access_key_id)) || (access_key_secret && ve_tls_str_empty(access_key_secret))) {
        return VE_TLS_INVALID;
    }
    if ((access_key_id && !access_key_secret) || (!access_key_id && access_key_secret)) {
        return VE_TLS_INVALID;
    }
    char * new_ak = access_key_id ? ve_tls_strdup(access_key_id) : NULL;
    char * new_sk = access_key_secret ? ve_tls_strdup(access_key_secret) : NULL;
    char * new_tok = (security_token && security_token[0] != 0) ? ve_tls_strdup(security_token) : NULL;
    if ((access_key_id && (!new_ak || !new_sk)) || (security_token && security_token[0] != 0 && !new_tok)) {
        ve_tls_secure_free_str(&new_ak);
        ve_tls_secure_free_str(&new_sk);
        ve_tls_secure_free_str(&new_tok);
        return VE_TLS_DROP_ERROR;
    }
    producer->config.platform.mutex_lock(producer->mutex);
    if (producer->stop || producer->closing || !producer->accepting) {
        producer->config.platform.mutex_unlock(producer->mutex);
        ve_tls_secure_free_str(&new_ak);
        ve_tls_secure_free_str(&new_sk);
        ve_tls_secure_free_str(&new_tok);
        return VE_TLS_CLOSED;
    }
    producer->runtime_updates_inflight++;
    int changed = 0;
    old_version = __atomic_load_n(&producer->static_cred_version, __ATOMIC_ACQUIRE);
    if (access_key_id) {
        changed++;
    }
    if (security_token) {
        changed++;
    }
    if (changed) {
        const ve_tls_runtime_snapshot * base = atomic_load_explicit(
            &producer->runtime_snapshot, memory_order_acquire);
        memset(&patch, 0, sizeof(patch));
        next_version = old_version + changed;
        patch.send_cfg_version = base ? base->send_cfg_version : 0;
        patch.static_cred_version = next_version;
        if (access_key_id) {
            patch.field_mask |= VE_TLS_SNAPSHOT_PATCH_ACCESS_KEY_ID |
                VE_TLS_SNAPSHOT_PATCH_ACCESS_KEY_SECRET;
            patch.access_key_id = new_ak;
            patch.access_key_secret = new_sk;
        }
        if (security_token) {
            patch.field_mask |= VE_TLS_SNAPSHOT_PATCH_SECURITY_TOKEN;
            patch.security_token = new_tok;
        }
        if (!base || ve_tls_runtime_snapshot_build_patched(base, &patch, &next_snapshot) != 0) {
            producer->config.platform.mutex_unlock(producer->mutex);
            ve_tls_secure_free_str(&new_ak);
            ve_tls_secure_free_str(&new_sk);
            ve_tls_secure_free_str(&new_tok);
            ve_tls_metrics_emit(producer, "snapshot_refresh_failed", 1, 0);
            ve_tls_runtime_update_finish(producer);
            return VE_TLS_DROP_ERROR;
        }
        old_ak = producer->cfg_access_key_id;
        old_sk = producer->cfg_access_key_secret;
        old_tok = producer->cfg_security_token;
        if (access_key_id) {
            producer->cfg_access_key_id = new_ak;
            producer->cfg_access_key_secret = new_sk;
            producer->config.access_key_id = new_ak;
            producer->config.access_key_secret = new_sk;
        }
        if (security_token) {
            producer->cfg_security_token = new_tok;
            producer->config.security_token = new_tok;
        }
        ve_tls_runtime_snapshot_publish_locked(producer, next_snapshot);
        __atomic_store_n(&producer->static_cred_version, next_version, __ATOMIC_RELEASE);
        ve_tls_key_queue_resume_auth_waiters_locked(producer, next_version);
    }
    producer->config.platform.mutex_unlock(producer->mutex);
    if (access_key_id) {
        ve_tls_secure_free_str(&old_ak);
        ve_tls_secure_free_str(&old_sk);
    }
    if (security_token) {
        ve_tls_secure_free_str(&old_tok);
    }
    ve_tls_metrics_emit(producer, "config_update_credentials", 1, 0);
    if (changed && producer->use_global_env) {
        ve_tls_env_notify(producer);
    }
    ve_tls_runtime_update_finish(producer);
    return VE_TLS_OK;
}

ve_tls_result ve_tls_producer_close(ve_tls_producer * producer, int32_t timeout_ms) {
    if (!producer) {
        return VE_TLS_INVALID;
    }
    ve_tls_metrics_emit(producer, "close_start", 1, timeout_ms);
    producer->config.platform.mutex_lock(producer->mutex);
    ve_tls_result rc = ve_tls_producer_begin_close_locked(producer);
    int join_threads = 0;
    if (rc == VE_TLS_OK && producer->use_global_env) {
        producer->config.platform.mutex_unlock(producer->mutex);
        ve_tls_env_notify(producer);
        producer->config.platform.mutex_lock(producer->mutex);
    }
    if (rc == VE_TLS_OK) {
        rc = ve_tls_producer_wait_for_close_stage_locked(producer, timeout_ms, ve_tls_producer_is_drained_locked, "close_drain_ok", "close_timeout");
        if (rc == VE_TLS_OK) {
            ve_tls_producer_finish_close_locked(producer);
            join_threads = 1;
        }
    }
    producer->config.platform.mutex_unlock(producer->mutex);
    if (join_threads) {
        ve_tls_send_queue_stop(&producer->send_queue);
        if (producer->workers) {
            for (int32_t i = 0; i < producer->worker_count; i++) {
                if (producer->workers[i]) {
                    producer->config.platform.thread_join(producer->workers[i]);
                    producer->workers[i] = NULL;
                }
            }
        }
        if (producer->senders) {
            for (int32_t i = 0; i < producer->sender_count; i++) {
                if (producer->senders[i]) {
                    producer->config.platform.thread_join(producer->senders[i]);
                    producer->senders[i] = NULL;
                }
            }
        }
    }
    if (rc == VE_TLS_OK && producer->persistent) {
        int flush_rc;
        if (producer->persistent_mutex) {
            producer->config.platform.mutex_lock(producer->persistent_mutex);
        }
        flush_rc = ve_tls_persistent_flush(producer->persistent);
        if (producer->persistent_mutex) {
            producer->config.platform.mutex_unlock(producer->persistent_mutex);
        }
        if (flush_rc != 0) {
            rc = ve_tls_map_persistent_flush_error(producer, flush_rc);
        }
    }
    return rc;
}

ve_tls_result ve_tls_producer_close_split(ve_tls_producer * producer, int32_t flusher_timeout_ms, int32_t sender_timeout_ms) {
    if (!producer) {
        return VE_TLS_INVALID;
    }
    ve_tls_metrics_emit(producer, "close_split_start", flusher_timeout_ms, sender_timeout_ms);
    producer->config.platform.mutex_lock(producer->mutex);
    ve_tls_result rc = ve_tls_producer_begin_close_locked(producer);
    int join_threads = 0;
    if (rc == VE_TLS_OK && producer->use_global_env) {
        producer->config.platform.mutex_unlock(producer->mutex);
        ve_tls_env_notify(producer);
        producer->config.platform.mutex_lock(producer->mutex);
    }
    if (rc == VE_TLS_OK) {
        rc = ve_tls_producer_wait_for_close_stage_locked(producer, flusher_timeout_ms, ve_tls_producer_is_flush_stage_drained_locked, "close_flusher_ok", "close_flusher_timeout");
        if (rc == VE_TLS_OK) {
            rc = ve_tls_producer_wait_for_close_stage_locked(producer, sender_timeout_ms, ve_tls_producer_is_drained_locked, "close_sender_ok", "close_sender_timeout");
        }
        if (rc == VE_TLS_OK) {
            ve_tls_producer_finish_close_locked(producer);
            join_threads = 1;
        }
    }
    producer->config.platform.mutex_unlock(producer->mutex);
    if (join_threads) {
        ve_tls_send_queue_stop(&producer->send_queue);
        if (producer->workers) {
            for (int32_t i = 0; i < producer->worker_count; i++) {
                if (producer->workers[i]) {
                    producer->config.platform.thread_join(producer->workers[i]);
                    producer->workers[i] = NULL;
                }
            }
        }
        if (producer->senders) {
            for (int32_t i = 0; i < producer->sender_count; i++) {
                if (producer->senders[i]) {
                    producer->config.platform.thread_join(producer->senders[i]);
                    producer->senders[i] = NULL;
                }
            }
        }
    }
    if (rc == VE_TLS_OK && producer->persistent) {
        int flush_rc;
        if (producer->persistent_mutex) {
            producer->config.platform.mutex_lock(producer->persistent_mutex);
        }
        flush_rc = ve_tls_persistent_flush(producer->persistent);
        if (producer->persistent_mutex) {
            producer->config.platform.mutex_unlock(producer->persistent_mutex);
        }
        if (flush_rc != 0) {
            rc = ve_tls_map_persistent_flush_error(producer, flush_rc);
        }
    }
    return rc;
}

void ve_tls_producer_destroy(ve_tls_producer * producer) {
    if (!producer) {
        return;
    }
    if (producer->use_global_env) {
        (void)ve_tls_producer_close(producer, 60000);
        /* use_global_env is immutable after create; env_registered is the teardown gate. */
        ve_tls_env_unregister_producer(producer);
        while (__atomic_load_n(&producer->env_inflight, __ATOMIC_RELAXED) > 0) {
            producer->config.platform.sleep_ms(1);
        }
    }
    if (producer->mutex) {
        producer->config.platform.mutex_lock(producer->mutex);
        producer->accepting = 0;
        producer->closing = 0;
        producer->stop = 1;
        producer->config.platform.cond_broadcast(producer->cond);
        if (producer->send_cond) {
            producer->config.platform.cond_broadcast(producer->send_cond);
        }
        while (producer->runtime_updates_inflight > 0) {
            producer->config.platform.cond_wait(producer->cond, producer->mutex);
        }
        producer->config.platform.mutex_unlock(producer->mutex);
    }
    if (g_tls_batch.producer == producer) {
        if (g_tls_batch.builder && g_tls_batch.builder->logs_len > 0) {
            ve_tls_release_tls_bytes(producer, g_tls_batch.builder->logs_len);
        }
        ve_tls_log_builder_free(g_tls_batch.builder);
        memset(&g_tls_batch, 0, sizeof(g_tls_batch));
    }
    ve_tls_send_queue_stop(&producer->send_queue);
    if (producer->workers) {
        for (int32_t i = 0; i < producer->worker_count; i++) {
            if (producer->workers[i]) {
                producer->config.platform.thread_join(producer->workers[i]);
                producer->workers[i] = NULL;
            }
        }
        ve_tls_free(producer->workers);
        producer->workers = NULL;
        producer->worker_count = 0;
    }
    if (producer->senders) {
        for (int32_t i = 0; i < producer->sender_count; i++) {
            if (producer->senders[i]) {
                producer->config.platform.thread_join(producer->senders[i]);
                producer->senders[i] = NULL;
            }
        }
        ve_tls_free(producer->senders);
        producer->senders = NULL;
        producer->sender_count = 0;
    }
    if (producer->default_builder) {
        ve_tls_log_builder_free(producer->default_builder);
        producer->default_builder = NULL;
    }
    ve_tls_queue_free_all(producer);
    ve_tls_ingress_queue_destroy(producer);
    while (producer->sealed_head) {
        ve_tls_log_group_builder * n = producer->sealed_head->next;
        ve_tls_log_builder_free(producer->sealed_head);
        producer->sealed_head = n;
    }
    producer->sealed_tail = NULL;
    ve_tls_key_map_free_all(producer);
    ve_tls_send_queue_destroy(&producer->send_queue);
    ve_tls_runtime_snapshot_clear(producer);
    ve_tls_obj_pool_destroy(&producer->send_task_pool);
    ve_tls_obj_pool_destroy(&producer->header_buf_pool);
    ve_tls_obj_pool_destroy(&producer->compress_buf_pool);
    ve_tls_free(producer->cfg_group_suffix);
    ve_tls_free(producer->cfg_endpoint);
    ve_tls_free(producer->cfg_region);
    ve_tls_free(producer->cfg_project_id);
    ve_tls_free(producer->cfg_topic_id);
    ve_tls_free(producer->cfg_source);
    ve_tls_free(producer->cfg_file_name);
    ve_tls_free(producer->cfg_context_flow);
    if (producer->cfg_log_tags) {
        for (size_t i = 0; i < producer->cfg_log_tag_count; i++) {
            ve_tls_free((void *)producer->cfg_log_tags[i].key);
            ve_tls_free((void *)producer->cfg_log_tags[i].value);
        }
        ve_tls_free(producer->cfg_log_tags);
    }
    ve_tls_free(producer->cfg_hash_key);
    ve_tls_secure_free_str(&producer->cfg_access_key_id);
    ve_tls_secure_free_str(&producer->cfg_access_key_secret);
    ve_tls_secure_free_str(&producer->cfg_security_token);
    ve_tls_free(producer->cfg_api_version);
    ve_tls_free(producer->cfg_compress_type);
    ve_tls_free(producer->cfg_ca_cert_path);
    ve_tls_free(producer->cfg_proxy);
    ve_tls_free(producer->cfg_user_agent);
    ve_tls_free(producer->cfg_persistent_file_path);
    producer->cfg_group_suffix = NULL;
    producer->cfg_group_suffix_len = 0;
    producer->cfg_endpoint = NULL;
    producer->cfg_region = NULL;
    producer->cfg_project_id = NULL;
    producer->cfg_topic_id = NULL;
    producer->cfg_source = NULL;
    producer->cfg_file_name = NULL;
    producer->cfg_context_flow = NULL;
    producer->cfg_log_tags = NULL;
    producer->cfg_log_tag_count = 0;
    producer->cfg_hash_key = NULL;
    producer->cfg_access_key_id = NULL;
    producer->cfg_access_key_secret = NULL;
    producer->cfg_security_token = NULL;
    producer->cfg_api_version = NULL;
    producer->cfg_compress_type = NULL;
    producer->cfg_ca_cert_path = NULL;
    producer->cfg_proxy = NULL;
    producer->cfg_user_agent = NULL;
    producer->cfg_persistent_file_path = NULL;
    ve_tls_secure_free_str(&producer->cred_access_key_id);
    ve_tls_secure_free_str(&producer->cred_access_key_secret);
    ve_tls_secure_free_str(&producer->cred_security_token);
    producer->cred_access_key_id = NULL;
    producer->cred_access_key_secret = NULL;
    producer->cred_security_token = NULL;
    if (producer->persistent) {
        ve_tls_persistent_close(producer->persistent);
        ve_tls_free(producer->persistent);
        producer->persistent = NULL;
    }
    ve_tls_persistent_free_ack_ranges(producer);
    if (producer->persistent_mutex) {
        producer->config.platform.mutex_destroy(producer->persistent_mutex);
        producer->persistent_mutex = NULL;
    }
    if (producer->cond) {
        producer->config.platform.cond_destroy(producer->cond);
        producer->cond = NULL;
    }
    if (producer->send_cond) {
        producer->config.platform.cond_destroy(producer->send_cond);
        producer->send_cond = NULL;
    }
    if (producer->mutex) {
        producer->config.platform.mutex_destroy(producer->mutex);
        producer->mutex = NULL;
    }
    ve_tls_free(producer);
}

void ve_tls_producer_set_send_done(ve_tls_producer * producer, ve_tls_send_done_fn callback, void * user_param) {
    if (!producer) {
        return;
    }
    __atomic_store_n(&producer->send_done, callback, __ATOMIC_RELEASE);
    __atomic_store_n(&producer->send_done_param, user_param, __ATOMIC_RELEASE);
}

void ve_tls_producer_set_send_done_v2(ve_tls_producer * producer, ve_tls_send_done_v2_fn callback, void * user_param) {
    if (!producer) {
        return;
    }
    __atomic_store_n(&producer->send_done_v2, callback, __ATOMIC_RELEASE);
    __atomic_store_n(&producer->send_done_v2_param, user_param, __ATOMIC_RELEASE);
}

void ve_tls_producer_get_metrics(ve_tls_producer * producer, ve_tls_metrics * out) {
    if (!producer || !out) {
        return;
    }
    memset(out, 0, sizeof(*out));
    out->logs_enqueued_total = ve_tls_metric_load_u64(&producer->m_logs_enqueued_total);
    out->logs_dropped_total = ve_tls_metric_load_u64(&producer->m_logs_dropped_total);
    out->bytes_enqueued_total = ve_tls_metric_load_u64(&producer->m_bytes_enqueued_total);
    out->bytes_dropped_total = ve_tls_metric_load_u64(&producer->m_bytes_dropped_total);
    out->batches_built_total = ve_tls_metric_load_u64(&producer->m_batches_built_total);
    out->requests_total = ve_tls_metric_load_u64(&producer->m_requests_total);
    out->requests_failed_total = ve_tls_metric_load_u64(&producer->m_requests_failed_total);
    out->retries_total = ve_tls_metric_load_u64(&producer->m_retries_total);
    out->bytes_sent_total = ve_tls_metric_load_u64(&producer->m_bytes_sent_total);
    for (int i = 0; i < 8; i++) {
        out->request_latency_buckets[i] = ve_tls_metric_load_u64(&producer->m_latency_buckets[i]);
    }
}

size_t ve_tls_producer_get_buffered_bytes(ve_tls_producer * producer) {
    if (!producer || !producer->mutex) {
        return 0;
    }
    producer->config.platform.mutex_lock(producer->mutex);
    size_t total = producer->queue_bytes +
                   producer->ingress_queue_bytes +
                   producer->send_queue_bytes +
                   producer->inflight_bytes +
                   producer->scratch_bytes +
                   (size_t)__atomic_load_n(&producer->tls_bytes, __ATOMIC_RELAXED);
    producer->config.platform.mutex_unlock(producer->mutex);
    return total;
}

static int ve_tls_size_fits_limit(size_t used, size_t need, size_t limit) {
    if (used > limit) {
        return 0;
    }
    return need <= limit - used;
}

static size_t ve_tls_producer_buffered_bytes_locked(ve_tls_producer * producer) {
    if (!producer) {
        return 0;
    }
    return producer->queue_bytes +
           producer->ingress_queue_bytes +
           producer->send_queue_bytes +
           producer->inflight_bytes +
           producer->scratch_bytes +
           (size_t)__atomic_load_n(&producer->tls_bytes, __ATOMIC_RELAXED);
}

static size_t ve_tls_producer_ingress_bytes_locked(ve_tls_producer * producer) {
    if (!producer) {
        return 0;
    }
    return producer->queue_bytes +
           producer->ingress_queue_bytes +
           (size_t)__atomic_load_n(&producer->tls_bytes, __ATOMIC_RELAXED);
}

static int ve_tls_has_buffer_space_locked(ve_tls_producer * producer, size_t need_bytes, int reserve_for_send) {
    if (!producer) {
        return 0;
    }
    if (producer->config.max_buffer_bytes <= 0) {
        return 1;
    }
    size_t max_buffer = (size_t)producer->config.max_buffer_bytes;
    if (reserve_for_send) {
        return ve_tls_size_fits_limit(ve_tls_producer_buffered_bytes_locked(producer), need_bytes, max_buffer);
    }
    size_t reserved = producer->send_reserved_bytes;
    if (reserved > max_buffer) {
        reserved = max_buffer;
    }
    size_t ingress_limit = max_buffer - reserved;
    return ve_tls_size_fits_limit(ve_tls_producer_ingress_bytes_locked(producer), need_bytes, ingress_limit);
}

static int ve_tls_wait_buffer_space_locked(ve_tls_producer * producer, size_t need_bytes, int reserve_for_send) {
    if (!producer) {
        return -1;
    }
    if (producer->config.max_buffer_bytes <= 0) {
        return 0;
    }
    if (ve_tls_has_buffer_space_locked(producer, need_bytes, reserve_for_send)) {
        return 0;
    }
    if (producer->config.buffer_full_policy != VE_TLS_BUFFER_FULL_BLOCK) {
        return -1;
    }
    int64_t now = producer->config.platform.time_ms ? producer->config.platform.time_ms() : 0;
    int64_t deadline = 0;
    if (producer->config.buffer_full_block_timeout_ms > 0 && now > 0) {
        deadline = now + producer->config.buffer_full_block_timeout_ms;
    }
    for (;;) {
        if (producer->stop || !producer->accepting) {
            return -2;
        }
        if (ve_tls_has_buffer_space_locked(producer, need_bytes, reserve_for_send)) {
            return 0;
        }
        producer->flush_requested = 1;
        producer->config.platform.cond_signal(producer->cond);
        ve_tls_metrics_emit(producer, "log_blocked_buffer_full", 1, (int64_t)need_bytes);
        if (deadline > 0) {
            int64_t now2 = producer->config.platform.time_ms ? producer->config.platform.time_ms() : 0;
            int64_t remain = deadline - now2;
            if (remain <= 0) {
                return -3;
            }
            if (producer->config.platform.cond_timedwait_ms) {
                (void)producer->config.platform.cond_timedwait_ms(producer->cond, producer->mutex, remain);
            } else {
                producer->config.platform.cond_wait(producer->cond, producer->mutex);
            }
        } else {
            producer->config.platform.cond_wait(producer->cond, producer->mutex);
        }
    }
}

size_t ve_tls_send_task_memory_bytes(const ve_tls_send_task * task) {
    size_t total = 0;
    if (!task) {
        return 0;
    }
    if (task->body) {
        total += task->body_size;
    }
    if (task->precompressed) {
        total += task->precompressed_size;
    }
    return total;
}

int ve_tls_producer_reserve_send_task_bytes(ve_tls_producer * producer, const ve_tls_send_task * task) {
    if (!producer || !producer->mutex) {
        return -1;
    }
    size_t bytes = ve_tls_send_task_memory_bytes(task);
    if (bytes == 0) {
        return 0;
    }
    producer->config.platform.mutex_lock(producer->mutex);
    int rc = ve_tls_wait_buffer_space_locked(producer, bytes, 1);
    if (rc == 0) {
        producer->send_queue_bytes += bytes;
    }
    producer->config.platform.mutex_unlock(producer->mutex);
    return rc;
}

void ve_tls_producer_release_send_queue_task_bytes(ve_tls_producer * producer, const ve_tls_send_task * task) {
    if (!producer || !producer->mutex) {
        return;
    }
    size_t bytes = ve_tls_send_task_memory_bytes(task);
    if (bytes == 0) {
        return;
    }
    producer->config.platform.mutex_lock(producer->mutex);
    if (producer->send_queue_bytes >= bytes) {
        producer->send_queue_bytes -= bytes;
    } else {
        producer->send_queue_bytes = 0;
    }
    producer->config.platform.cond_broadcast(producer->cond);
    producer->config.platform.mutex_unlock(producer->mutex);
}

void ve_tls_producer_move_send_task_to_inflight(ve_tls_producer * producer, const ve_tls_send_task * task) {
    if (!producer || !producer->mutex) {
        return;
    }
    size_t bytes = ve_tls_send_task_memory_bytes(task);
    if (bytes == 0) {
        return;
    }
    producer->config.platform.mutex_lock(producer->mutex);
    if (producer->send_queue_bytes >= bytes) {
        producer->send_queue_bytes -= bytes;
    } else {
        producer->send_queue_bytes = 0;
    }
    producer->inflight_bytes += bytes;
    producer->config.platform.mutex_unlock(producer->mutex);
}

void ve_tls_producer_release_inflight_task_bytes(ve_tls_producer * producer, const ve_tls_send_task * task) {
    if (!producer || !producer->mutex) {
        return;
    }
    size_t bytes = ve_tls_send_task_memory_bytes(task);
    if (bytes == 0) {
        return;
    }
    producer->config.platform.mutex_lock(producer->mutex);
    if (producer->inflight_bytes >= bytes) {
        producer->inflight_bytes -= bytes;
    } else {
        producer->inflight_bytes = 0;
    }
    producer->config.platform.cond_broadcast(producer->cond);
    producer->config.platform.mutex_unlock(producer->mutex);
}

int ve_tls_producer_reserve_scratch_bytes(ve_tls_producer * producer, size_t bytes) {
    if (!producer || !producer->mutex) {
        return -1;
    }
    if (bytes == 0) {
        return 0;
    }
    if (bytes == (size_t)-1) {
        return -1;
    }
    producer->config.platform.mutex_lock(producer->mutex);
    if (bytes > (size_t)-1 - producer->scratch_bytes) {
        producer->config.platform.mutex_unlock(producer->mutex);
        return -1;
    }
    int rc = ve_tls_wait_buffer_space_locked(producer, bytes, 1);
    if (rc == 0) {
        producer->scratch_bytes += bytes;
    }
    producer->config.platform.mutex_unlock(producer->mutex);
    return rc;
}

void ve_tls_producer_release_scratch_bytes(ve_tls_producer * producer, size_t bytes) {
    if (!producer || !producer->mutex || bytes == 0) {
        return;
    }
    producer->config.platform.mutex_lock(producer->mutex);
    if (producer->scratch_bytes >= bytes) {
        producer->scratch_bytes -= bytes;
    } else {
        producer->scratch_bytes = 0;
    }
    producer->config.platform.cond_broadcast(producer->cond);
    producer->config.platform.mutex_unlock(producer->mutex);
}

/* 把 task->scratch_held 中已计入 scratch_bytes 的预算原子迁移到 send_queue_bytes。
 * - 若 send 比 held 更大，需要为差额申请额外预算（可能 wait/超时/拒绝）。
 * - 若 send 比 held 更小或相等，差额回退到 scratch（实际只是从一个池转到另一个池，
 *   总占用不增加），始终不会让 buffered_bytes 在窗口期内出现"少计"。
 * - 成功后清零 task->scratch_held / scratch_owner，由 send_task_free 兜底逻辑跳过。 */
int ve_tls_producer_swap_scratch_to_send_task_bytes(ve_tls_producer * producer, ve_tls_send_task * task) {
    if (!producer || !producer->mutex || !task) {
        return -1;
    }
    size_t send_bytes = ve_tls_send_task_memory_bytes(task);
    size_t held = task->scratch_held;
    /* 硬契约：scratch 预算必须由本 producer 持有，禁止跨 producer 迁移；
     * 任一不一致都直接拒绝，避免对错误对象扣账造成预算泄漏或错算。 */
    if (held > 0 && task->scratch_owner != producer) {
        return -1;
    }
    if (send_bytes == 0 && held == 0) {
        task->scratch_held = 0;
        task->scratch_owner = NULL;
        return 0;
    }
    producer->config.platform.mutex_lock(producer->mutex);
    int rc = 0;
    if (send_bytes > held) {
        size_t need = send_bytes - held;
        rc = ve_tls_wait_buffer_space_locked(producer, need, 1);
        if (rc != 0) {
            producer->config.platform.mutex_unlock(producer->mutex);
            return rc;
        }
    }
    /* 释放 held 的 scratch 占用 */
    if (held > 0) {
        if (producer->scratch_bytes >= held) {
            producer->scratch_bytes -= held;
        } else {
            producer->scratch_bytes = 0;
        }
    }
    /* 累加到 send_queue_bytes */
    producer->send_queue_bytes += send_bytes;
    producer->config.platform.cond_broadcast(producer->cond);
    producer->config.platform.mutex_unlock(producer->mutex);
    task->scratch_held = 0;
    task->scratch_owner = NULL;
    return 0;
}

ve_tls_result ve_tls_producer_add_log_raw(ve_tls_producer * producer, const char * log_buf, size_t log_size, int flush) {
    return ve_tls_producer_add_log_raw_time_parts(producer, 0, 0, 0, log_buf, log_size, flush);
}

ve_tls_result ve_tls_producer_add_log_raw_time_parts(ve_tls_producer * producer, int64_t time_ms, int32_t has_time_ns, uint32_t time_ns, const char * log_buf, size_t log_size, int flush) {
    return ve_tls_producer_add_log_raw_time_parts_with_id(producer, time_ms, has_time_ns, time_ns, log_buf, log_size, flush, NULL);
}

ve_tls_result ve_tls_producer_add_log_raw_with_id(ve_tls_producer * producer, const char * log_buf, size_t log_size, int flush, int64_t * out_log_id) {
    return ve_tls_producer_add_log_raw_time_parts_with_id(producer, 0, 0, 0, log_buf, log_size, flush, out_log_id);
}

ve_tls_result ve_tls_producer_add_log_raw_time_parts_with_id(ve_tls_producer * producer, int64_t time_ms, int32_t has_time_ns, uint32_t time_ns, const char * log_buf, size_t log_size, int flush, int64_t * out_log_id) {
    if (!producer || !log_buf || log_size == 0) {
        return VE_TLS_INVALID;
    }
    producer->config.platform.mutex_lock(producer->mutex);
    if (producer->stop || !producer->accepting) {
        producer->config.platform.mutex_unlock(producer->mutex);
        return VE_TLS_CLOSED;
    }
    int wrc = ve_tls_wait_buffer_space_locked(producer, log_size, 0);
    if (wrc != 0) {
        producer->config.platform.mutex_unlock(producer->mutex);
        return ve_tls_map_wait_error_to_result(producer, wrc, log_size);
    }
    producer->queue_bytes += log_size;
    producer->config.platform.mutex_unlock(producer->mutex);

    unsigned char * copy = (unsigned char *)ve_tls_malloc(log_size);
    if (!copy) {
        producer->config.platform.mutex_lock(producer->mutex);
        ve_tls_release_queue_reservation_locked(producer, log_size);
        producer->config.platform.mutex_unlock(producer->mutex);
        ve_tls_metric_inc_u64(&producer->m_logs_dropped_total, 1);
        ve_tls_metric_inc_u64(&producer->m_bytes_dropped_total, log_size);
        ve_tls_metrics_emit(producer, "log_dropped_enqueue_alloc_failed", 1, (int64_t)log_size);
        ve_tls_metrics_emit(producer, "log_dropped", 1, (int64_t)log_size);
        return VE_TLS_DROP_ERROR;
    }
    memcpy(copy, log_buf, log_size);
    producer->config.platform.mutex_lock(producer->mutex);
    const char * hk = ve_tls_normalize_hash_key(producer, NULL);
    ve_tls_result rc = ve_tls_enqueue_raw_owned_locked(producer, copy, log_size, time_ms, time_ns, has_time_ns ? 1 : 0, hk, flush, out_log_id, 1);
    producer->config.platform.mutex_unlock(producer->mutex);
    return rc;
}

static ve_tls_result ve_tls_producer_add_log_kv_lens_time_parts_hashkey(
    ve_tls_producer * producer,
    int64_t time_ms,
    int32_t has_time_ns,
    uint32_t time_ns,
    const char * hash_key,
    const ve_tls_kv * kvs,
    const size_t * key_lens,
    const size_t * val_lens,
    size_t kv_count,
    int flush,
    int64_t * out_log_id) {
    if (!producer || !kvs || kv_count == 0) {
        return VE_TLS_INVALID;
    }
    if (producer->config.use_persistent) {
        producer->config.platform.mutex_lock(producer->mutex);
        ve_tls_result prc = ve_tls_producer_add_log_kv_persistent_locked(
            producer, time_ms, has_time_ns, time_ns, hash_key, kvs, key_lens, val_lens, kv_count, flush, out_log_id);
        producer->config.platform.mutex_unlock(producer->mutex);
        return prc;
    }
    const char * norm_key = ve_tls_normalize_hash_key(producer, hash_key);

    ve_tls_result tls_rc = VE_TLS_OK;
    if (ve_tls_try_add_log_tls_batching(producer, hash_key, norm_key, time_ms, time_ns, has_time_ns ? 1 : 0, kvs, key_lens, val_lens, kv_count, flush, out_log_id, &tls_rc)) {
        return tls_rc;
    }

    size_t estimated = ve_tls_log_builder_estimate_kv_lens_size(time_ms, time_ns, has_time_ns ? 1 : 0, key_lens, val_lens, kv_count);
    if (estimated == (size_t)-1) {
        /* size 估算溢出：直接拒绝该日志，避免下游基于回绕值做预算/编码 */
        return VE_TLS_INVALID;
    }
    producer->config.platform.mutex_lock(producer->mutex);
    if (producer->stop || !producer->accepting) {
        producer->config.platform.mutex_unlock(producer->mutex);
        return VE_TLS_CLOSED;
    }
    int wrc = ve_tls_wait_buffer_space_locked(producer, estimated, 0);
    if (wrc != 0) {
        producer->config.platform.mutex_unlock(producer->mutex);
        return ve_tls_map_wait_error_to_result(producer, wrc, estimated);
    }
    producer->queue_bytes += estimated;
    int64_t id = ve_tls_producer_next_log_id(producer);
    if (out_log_id) {
        *out_log_id = id;
    }
    ve_tls_key_queue * q = NULL;
    ve_tls_log_group_builder * b = NULL;
    int is_default_builder = 0;
    if (producer->fast_builder && (!hash_key || hash_key[0] == 0) && producer->default_norm_key == norm_key) {
        if (!producer->default_builder) {
            producer->default_builder = ve_tls_log_builder_create(norm_key);
            if (!producer->default_builder) {
                ve_tls_release_queue_reservation_locked(producer, estimated);
                producer->config.platform.mutex_unlock(producer->mutex);
                ve_tls_metric_inc_u64(&producer->m_logs_dropped_total, 1);
                ve_tls_metric_inc_u64(&producer->m_bytes_dropped_total, estimated);
                ve_tls_metrics_emit(producer, "log_dropped_enqueue_alloc_failed", 1, (int64_t)estimated);
                ve_tls_metrics_emit(producer, "log_dropped", 1, (int64_t)estimated);
                return VE_TLS_DROP_ERROR;
            }
            producer->default_builder->first_append_ms = producer->config.platform.time_ms ? producer->config.platform.time_ms() : 0;
        }
        b = producer->default_builder;
        is_default_builder = 1;
    } else {
        q = ve_tls_key_queue_get_or_create(producer, norm_key);
        if (!q) {
            ve_tls_send_callbacks cbs = ve_tls_capture_callbacks(producer);
            int is_limit = 0;
            if (producer->config.key_queue_max_active > 0 && producer->key_queue_count >= (size_t)producer->config.key_queue_max_active) {
                is_limit = 1;
            }
            ve_tls_release_queue_reservation_locked(producer, estimated);
            producer->config.platform.mutex_unlock(producer->mutex);
            ve_tls_metric_inc_u64(&producer->m_logs_dropped_total, 1);
            ve_tls_metric_inc_u64(&producer->m_bytes_dropped_total, estimated);
            if (is_limit) {
                ve_tls_metrics_emit(producer, "key_queue_drop", 1, (int64_t)estimated);
                ve_tls_drop_one_with_error(cbs, estimated, id, "KeyQueueLimitExceeded", "key queue limit exceeded");
            } else {
                ve_tls_metrics_emit(producer, "log_dropped_enqueue_alloc_failed", 1, (int64_t)estimated);
            }
            ve_tls_metrics_emit(producer, "log_dropped", 1, (int64_t)estimated);
            return is_limit ? VE_TLS_OK : VE_TLS_DROP_ERROR;
        }
        if (!q->builder) {
            q->builder = ve_tls_log_builder_create(q->key);
            if (!q->builder) {
                ve_tls_release_queue_reservation_locked(producer, estimated);
                producer->config.platform.mutex_unlock(producer->mutex);
                ve_tls_metric_inc_u64(&producer->m_logs_dropped_total, 1);
                ve_tls_metric_inc_u64(&producer->m_bytes_dropped_total, estimated);
                ve_tls_metrics_emit(producer, "log_dropped_enqueue_alloc_failed", 1, (int64_t)estimated);
                ve_tls_metrics_emit(producer, "log_dropped", 1, (int64_t)estimated);
                return VE_TLS_DROP_ERROR;
            }
            q->builder->first_append_ms = producer->config.platform.time_ms ? producer->config.platform.time_ms() : 0;
        }
        b = q->builder;
    }

    size_t prev = b->logs_len;
    if (ve_tls_log_builder_add_kv_lens(b, id, time_ms, time_ns, has_time_ns ? 1 : 0, kvs, key_lens, val_lens, kv_count) != 0) {
        ve_tls_release_queue_reservation_locked(producer, estimated);
        producer->config.platform.mutex_unlock(producer->mutex);
        ve_tls_metric_inc_u64(&producer->m_logs_dropped_total, 1);
        ve_tls_metric_inc_u64(&producer->m_bytes_dropped_total, estimated);
        ve_tls_metrics_emit(producer, "log_dropped_enqueue_alloc_failed", 1, (int64_t)estimated);
        ve_tls_metrics_emit(producer, "log_dropped", 1, (int64_t)estimated);
        return VE_TLS_DROP_ERROR;
    }
    size_t delta = b->logs_len - prev;
    if (delta > estimated) {
        producer->queue_bytes += delta - estimated;
    } else if (estimated > delta) {
        ve_tls_release_queue_reservation_locked(producer, estimated - delta);
    }
    ve_tls_metric_inc_u64(&producer->m_logs_enqueued_total, 1);
    ve_tls_metric_inc_u64(&producer->m_bytes_enqueued_total, delta);
    int64_t emit_size = (int64_t)delta;
    int wake_worker = 0;
    if (flush) {
        ve_tls_log_group_builder * sealed = b;
        if (is_default_builder) {
            producer->default_builder = NULL;
        } else {
            q->builder = NULL;
        }
        sealed->next = NULL;
        if (producer->sealed_tail) {
            producer->sealed_tail->next = sealed;
        } else {
            producer->sealed_head = sealed;
        }
        producer->sealed_tail = sealed;
        producer->flush_requested = 1;
        wake_worker = 1;
    } else {
        size_t byte_limit = producer->config.log_bytes_per_package > 0 ? (size_t)producer->config.log_bytes_per_package : 0;
        if (producer->config.agg_max_raw_bytes_per_request > 0) {
            size_t max_raw = (size_t)producer->config.agg_max_raw_bytes_per_request;
            if (byte_limit == 0 || byte_limit > max_raw) {
                byte_limit = max_raw;
            }
        }
        int should_seal = 0;
        if (producer->config.log_count_per_package > 0 && b->log_count >= producer->config.log_count_per_package) {
            should_seal = 1;
        }
        if (!should_seal && byte_limit > 0 && b->logs_len >= byte_limit) {
            should_seal = 1;
        }
        if (should_seal) {
            ve_tls_log_group_builder * sealed = b;
            if (is_default_builder) {
                producer->default_builder = NULL;
            } else {
                q->builder = NULL;
            }
            sealed->next = NULL;
            if (producer->sealed_tail) {
                producer->sealed_tail->next = sealed;
            } else {
                producer->sealed_head = sealed;
            }
            producer->sealed_tail = sealed;
            producer->flush_requested = 1;
            wake_worker = 1;
        }
    }
    if (wake_worker) {
        producer->config.platform.cond_signal(producer->cond);
    }
    producer->config.platform.mutex_unlock(producer->mutex);
    ve_tls_metrics_emit(producer, "log_enqueued", 1, emit_size);
    return VE_TLS_OK;
}

ve_tls_result ve_tls_producer_add_log_kv(ve_tls_producer * producer, int64_t time_ms, const ve_tls_kv * kvs, size_t kv_count, int flush) {
    return ve_tls_producer_add_log_kv_hashkey(producer, time_ms, NULL, kvs, kv_count, flush);
}

ve_tls_result ve_tls_producer_add_log_kv_hashkey(ve_tls_producer * producer, int64_t time_ms, const char * hash_key, const ve_tls_kv * kvs, size_t kv_count, int flush) {
    return ve_tls_producer_add_log_kv_hashkey_with_id(producer, time_ms, hash_key, kvs, kv_count, flush, NULL);
}

ve_tls_result ve_tls_producer_add_log_kv_with_id(ve_tls_producer * producer, int64_t time_ms, const ve_tls_kv * kvs, size_t kv_count, int flush, int64_t * out_log_id) {
    return ve_tls_producer_add_log_kv_hashkey_with_id(producer, time_ms, NULL, kvs, kv_count, flush, out_log_id);
}

ve_tls_result ve_tls_producer_add_log_kv_hashkey_with_id(ve_tls_producer * producer, int64_t time_ms, const char * hash_key, const ve_tls_kv * kvs, size_t kv_count, int flush, int64_t * out_log_id) {
    if (!producer || !kvs || kv_count == 0) {
        return VE_TLS_INVALID;
    }
    uint32_t time_ns = 0;
    int32_t has_time_ns = 0;
    if (time_ms <= 0) {
        time_ms = producer->config.platform.time_ms ? producer->config.platform.time_ms() : 0;
        if (producer->config.enable_time_ns && producer->config.platform.time_unix_ns) {
            int64_t now_ns = producer->config.platform.time_unix_ns();
            if (now_ns > 0) {
                int64_t ms = now_ns / 1000000LL;
                int64_t rem = now_ns - ms * 1000000LL;
                if (ms > 0 && rem >= 0) {
                    time_ms = ms;
                    has_time_ns = 1;
                    time_ns = (uint32_t)rem;
                }
            }
        }
    }
    size_t key_lens_stack[16];
    size_t val_lens_stack[16];
    size_t * key_lens = key_lens_stack;
    size_t * val_lens = val_lens_stack;
    if (kv_count > 16) {
        if (!ve_tls_count_fits_array(kv_count, sizeof(size_t))) {
            return VE_TLS_DROP_ERROR;
        }
        key_lens = (size_t *)ve_tls_malloc(kv_count * sizeof(size_t));
        val_lens = (size_t *)ve_tls_malloc(kv_count * sizeof(size_t));
        if (!key_lens || !val_lens) {
            ve_tls_free(key_lens);
            ve_tls_free(val_lens);
            return VE_TLS_DROP_ERROR;
        }
    }
    for (size_t i = 0; i < kv_count; i++) {
        const char * k = kvs[i].key ? kvs[i].key : "";
        const char * v = kvs[i].value ? kvs[i].value : "";
        key_lens[i] = ve_tls_cstr_len_cached(k);
        val_lens[i] = ve_tls_cstr_len_cached(v);
    }

    ve_tls_result rc = ve_tls_producer_add_log_kv_lens_time_parts_hashkey(producer, time_ms, has_time_ns, time_ns, hash_key, kvs, key_lens, val_lens, kv_count, flush, out_log_id);
    if (kv_count > 16) {
        ve_tls_free(key_lens);
        ve_tls_free(val_lens);
    }
    return rc;
}

ve_tls_result ve_tls_producer_add_log_kv_time_parts(ve_tls_producer * producer, int64_t time_ms, int32_t has_time_ns, uint32_t time_ns, const ve_tls_kv * kvs, size_t kv_count, int flush) {
    return ve_tls_producer_add_log_kv_time_parts_hashkey(producer, time_ms, has_time_ns, time_ns, NULL, kvs, kv_count, flush);
}

ve_tls_result ve_tls_producer_add_log_kv_time_parts_hashkey(ve_tls_producer * producer, int64_t time_ms, int32_t has_time_ns, uint32_t time_ns, const char * hash_key, const ve_tls_kv * kvs, size_t kv_count, int flush) {
    return ve_tls_producer_add_log_kv_time_parts_hashkey_with_id(producer, time_ms, has_time_ns, time_ns, hash_key, kvs, kv_count, flush, NULL);
}

ve_tls_result ve_tls_producer_add_log_kv_time_parts_with_id(ve_tls_producer * producer, int64_t time_ms, int32_t has_time_ns, uint32_t time_ns, const ve_tls_kv * kvs, size_t kv_count, int flush, int64_t * out_log_id) {
    return ve_tls_producer_add_log_kv_time_parts_hashkey_with_id(producer, time_ms, has_time_ns, time_ns, NULL, kvs, kv_count, flush, out_log_id);
}

ve_tls_result ve_tls_producer_add_log_kv_time_parts_hashkey_with_id(ve_tls_producer * producer, int64_t time_ms, int32_t has_time_ns, uint32_t time_ns, const char * hash_key, const ve_tls_kv * kvs, size_t kv_count, int flush, int64_t * out_log_id) {
    if (!producer || !kvs || kv_count == 0) {
        return VE_TLS_INVALID;
    }
    if (time_ms <= 0) {
        time_ms = producer->config.platform.time_ms ? producer->config.platform.time_ms() : 0;
        has_time_ns = 0;
        time_ns = 0;
        if (producer->config.enable_time_ns && producer->config.platform.time_unix_ns) {
            int64_t now_ns = producer->config.platform.time_unix_ns();
            if (now_ns > 0) {
                int64_t ms = now_ns / 1000000LL;
                int64_t rem = now_ns - ms * 1000000LL;
                if (ms > 0 && rem >= 0) {
                    time_ms = ms;
                    has_time_ns = 1;
                    time_ns = (uint32_t)rem;
                }
            }
        }
    } else if (!has_time_ns) {
        time_ns = 0;
    }
    size_t key_lens_stack[16];
    size_t val_lens_stack[16];
    size_t * key_lens = key_lens_stack;
    size_t * val_lens = val_lens_stack;
    if (kv_count > 16) {
        if (!ve_tls_count_fits_array(kv_count, sizeof(size_t))) {
            return VE_TLS_DROP_ERROR;
        }
        key_lens = (size_t *)ve_tls_malloc(kv_count * sizeof(size_t));
        val_lens = (size_t *)ve_tls_malloc(kv_count * sizeof(size_t));
        if (!key_lens || !val_lens) {
            ve_tls_free(key_lens);
            ve_tls_free(val_lens);
            return VE_TLS_DROP_ERROR;
        }
    }
    for (size_t i = 0; i < kv_count; i++) {
        const char * k = kvs[i].key ? kvs[i].key : "";
        const char * v = kvs[i].value ? kvs[i].value : "";
        key_lens[i] = ve_tls_cstr_len_cached(k);
        val_lens[i] = ve_tls_cstr_len_cached(v);
    }
    ve_tls_result rc = ve_tls_producer_add_log_kv_lens_time_parts_hashkey(producer, time_ms, has_time_ns, time_ns, hash_key, kvs, key_lens, val_lens, kv_count, flush, out_log_id);
    if (kv_count > 16) {
        ve_tls_free(key_lens);
        ve_tls_free(val_lens);
    }
    return rc;
}

static char * ve_tls_memdup0(const char * s, size_t n) {
    if (n == (size_t)-1) {
        return NULL;
    }
    char * p = (char *)ve_tls_calloc(1, n + 1);
    if (!p) {
        return NULL;
    }
    if (s && n > 0) {
        memcpy(p, s, n);
    }
    p[n] = 0;
    return p;
}

ve_tls_log_template * ve_tls_template_create(ve_tls_producer * producer, const char * const * keys, const size_t * key_lens, size_t key_count, const char * hash_key) {
    if (!producer || !keys || !key_lens || key_count == 0) {
        return NULL;
    }
    if (!ve_tls_count_fits_array(key_count, sizeof(char *)) || !ve_tls_count_fits_array(key_count, sizeof(size_t))) {
        return NULL;
    }
    VE_TLS_ALLOC_SITE("template_create");
    ve_tls_log_template * tpl = (ve_tls_log_template *)ve_tls_calloc(1, sizeof(*tpl));
    if (!tpl) {
        return NULL;
    }
    tpl->producer = producer;
    tpl->key_count = key_count;
    tpl->keys = (char **)ve_tls_calloc(key_count, sizeof(char *));
    tpl->key_lens = (size_t *)ve_tls_calloc(key_count, sizeof(size_t));
    if (!tpl->keys || !tpl->key_lens) {
        ve_tls_free(tpl->keys);
        ve_tls_free(tpl->key_lens);
        ve_tls_free(tpl);
        return NULL;
    }
    for (size_t i = 0; i < key_count; i++) {
        if (!keys[i] && key_lens[i] != 0) {
            for (size_t j = 0; j < i; j++) {
                ve_tls_free(tpl->keys[j]);
            }
            ve_tls_free(tpl->keys);
            ve_tls_free(tpl->key_lens);
            ve_tls_free(tpl);
            return NULL;
        }
        tpl->keys[i] = ve_tls_memdup0(keys[i], key_lens[i]);
        if (!tpl->keys[i]) {
            for (size_t j = 0; j < i; j++) {
                ve_tls_free(tpl->keys[j]);
            }
            ve_tls_free(tpl->keys);
            ve_tls_free(tpl->key_lens);
            ve_tls_free(tpl);
            return NULL;
        }
        tpl->key_lens[i] = key_lens[i];
    }
    if (hash_key && hash_key[0] != 0) {
        tpl->hash_key = ve_tls_strdup(hash_key);
        if (!tpl->hash_key) {
            for (size_t i = 0; i < key_count; i++) {
                ve_tls_free(tpl->keys[i]);
            }
            ve_tls_free(tpl->keys);
            ve_tls_free(tpl->key_lens);
            ve_tls_free(tpl);
            return NULL;
        }
    }
    return tpl;
}

ve_tls_result ve_tls_template_add_values(ve_tls_log_template * tpl, int64_t time_ms, int32_t has_time_ns, uint32_t time_ns, const char * const * values, const size_t * value_lens, size_t value_count, int flush) {
    if (!tpl || !tpl->producer || !values || !value_lens) {
        return VE_TLS_INVALID;
    }
    if (value_count != tpl->key_count) {
        return VE_TLS_INVALID;
    }
    if (time_ms <= 0) {
        time_ms = tpl->producer->config.platform.time_ms ? tpl->producer->config.platform.time_ms() : 0;
        has_time_ns = 0;
        time_ns = 0;
        if (tpl->producer->config.enable_time_ns && tpl->producer->config.platform.time_unix_ns) {
            int64_t now_ns = tpl->producer->config.platform.time_unix_ns();
            if (now_ns > 0) {
                int64_t ms = now_ns / 1000000LL;
                int64_t rem = now_ns - ms * 1000000LL;
                if (ms > 0 && rem >= 0) {
                    time_ms = ms;
                    has_time_ns = 1;
                    time_ns = (uint32_t)rem;
                }
            }
        }
    } else if (!has_time_ns) {
        time_ns = 0;
    }

    ve_tls_kv kvs_stack[16];
    ve_tls_kv * kvs = kvs_stack;
    if (tpl->key_count > 16) {
        if (!ve_tls_count_fits_array(tpl->key_count, sizeof(ve_tls_kv))) {
            return VE_TLS_DROP_ERROR;
        }
        kvs = (ve_tls_kv *)ve_tls_calloc(tpl->key_count, sizeof(ve_tls_kv));
        if (!kvs) {
            return VE_TLS_DROP_ERROR;
        }
    }
    for (size_t i = 0; i < tpl->key_count; i++) {
        if (!values[i] && value_lens[i] != 0) {
            if (tpl->key_count > 16) {
                ve_tls_free(kvs);
            }
            return VE_TLS_INVALID;
        }
        kvs[i].key = tpl->keys[i] ? tpl->keys[i] : "";
        kvs[i].value = values[i] ? values[i] : "";
    }
    ve_tls_result rc = ve_tls_producer_add_log_kv_lens_time_parts_hashkey(
        tpl->producer,
        time_ms,
        has_time_ns ? 1 : 0,
        time_ns,
        tpl->hash_key,
        kvs,
        tpl->key_lens,
        value_lens,
        tpl->key_count,
        flush,
        NULL);
    if (tpl->key_count > 16) {
        ve_tls_free(kvs);
    }
    return rc;
}

void ve_tls_template_destroy(ve_tls_log_template * tpl) {
    if (!tpl) {
        return;
    }
    if (tpl->keys) {
        for (size_t i = 0; i < tpl->key_count; i++) {
            ve_tls_free(tpl->keys[i]);
            tpl->keys[i] = NULL;
        }
        ve_tls_free(tpl->keys);
        tpl->keys = NULL;
    }
    ve_tls_free(tpl->key_lens);
    tpl->key_lens = NULL;
    ve_tls_free(tpl->hash_key);
    tpl->hash_key = NULL;
    tpl->key_count = 0;
    tpl->producer = NULL;
    ve_tls_free(tpl);
}

ve_tls_result ve_tls_producer_add_log_with_len(ve_tls_producer * producer, int64_t time_ms, const char * const * keys, const size_t * key_lens, const char * const * values, const size_t * value_lens, size_t pair_count, int flush) {
    return ve_tls_producer_add_log_with_len_hashkey(producer, time_ms, NULL, keys, key_lens, values, value_lens, pair_count, flush);
}

ve_tls_result ve_tls_producer_add_log_with_len_hashkey(ve_tls_producer * producer, int64_t time_ms, const char * hash_key, const char * const * keys, const size_t * key_lens, const char * const * values, const size_t * value_lens, size_t pair_count, int flush) {
    uint32_t time_ns = 0;
    int32_t has_time_ns = 0;
    if (time_ms <= 0) {
        time_ms = producer && producer->config.platform.time_ms ? producer->config.platform.time_ms() : 0;
        if (producer && producer->config.enable_time_ns && producer->config.platform.time_unix_ns) {
            int64_t now_ns = producer->config.platform.time_unix_ns();
            if (now_ns > 0) {
                int64_t ms = now_ns / 1000000LL;
                int64_t rem = now_ns - ms * 1000000LL;
                if (ms > 0 && rem >= 0) {
                    time_ms = ms;
                    has_time_ns = 1;
                    time_ns = (uint32_t)rem;
                }
            }
        }
    }
    return ve_tls_producer_add_log_with_len_time_parts_hashkey(producer, time_ms, has_time_ns, time_ns, hash_key, keys, key_lens, values, value_lens, pair_count, flush);
}

ve_tls_result ve_tls_producer_add_log_with_len_time_parts(ve_tls_producer * producer, int64_t time_ms, int32_t has_time_ns, uint32_t time_ns, const char * const * keys, const size_t * key_lens, const char * const * values, const size_t * value_lens, size_t pair_count, int flush) {
    return ve_tls_producer_add_log_with_len_time_parts_hashkey(producer, time_ms, has_time_ns, time_ns, NULL, keys, key_lens, values, value_lens, pair_count, flush);
}

ve_tls_result ve_tls_producer_add_log_with_len_time_parts_hashkey(ve_tls_producer * producer, int64_t time_ms, int32_t has_time_ns, uint32_t time_ns, const char * hash_key, const char * const * keys, const size_t * key_lens, const char * const * values, const size_t * value_lens, size_t pair_count, int flush) {
    if (!producer || !keys || !values || !key_lens || !value_lens || pair_count == 0) {
        return VE_TLS_INVALID;
    }
    if (time_ms <= 0) {
        time_ms = producer->config.platform.time_ms ? producer->config.platform.time_ms() : 0;
        has_time_ns = 0;
        time_ns = 0;
        if (producer->config.enable_time_ns && producer->config.platform.time_unix_ns) {
            int64_t now_ns = producer->config.platform.time_unix_ns();
            if (now_ns > 0) {
                int64_t ms = now_ns / 1000000LL;
                int64_t rem = now_ns - ms * 1000000LL;
                if (ms > 0 && rem >= 0) {
                    time_ms = ms;
                    has_time_ns = 1;
                    time_ns = (uint32_t)rem;
                }
            }
        }
    } else if (!has_time_ns) {
        time_ns = 0;
    }

    ve_tls_kv kvs_stack[16];
    ve_tls_kv * kvs = kvs_stack;
    if (pair_count > 16) {
        if (!ve_tls_count_fits_array(pair_count, sizeof(ve_tls_kv))) {
            return VE_TLS_DROP_ERROR;
        }
        kvs = (ve_tls_kv *)ve_tls_calloc(pair_count, sizeof(ve_tls_kv));
        if (!kvs) {
            return VE_TLS_DROP_ERROR;
        }
    }
    for (size_t i = 0; i < pair_count; i++) {
        const char * k = keys[i];
        const char * v = values[i];
        if (!k && key_lens[i] != 0) {
            if (pair_count > 16) ve_tls_free(kvs);
            return VE_TLS_INVALID;
        }
        if (!v && value_lens[i] != 0) {
            if (pair_count > 16) ve_tls_free(kvs);
            return VE_TLS_INVALID;
        }
        kvs[i].key = k ? k : "";
        kvs[i].value = v ? v : "";
    }

    ve_tls_result rc = ve_tls_producer_add_log_kv_lens_time_parts_hashkey(producer, time_ms, has_time_ns, time_ns, hash_key, kvs, key_lens, value_lens, pair_count, flush, NULL);
    if (pair_count > 16) {
        ve_tls_free(kvs);
    }
    return rc;
}

ve_tls_result ve_tls_producer_flush(ve_tls_producer * producer) {
    int flush_rc = 0;
    if (!producer) {
        return VE_TLS_INVALID;
    }
    producer->config.platform.mutex_lock(producer->mutex);
    producer->flush_requested = 1;
    producer->config.platform.cond_broadcast(producer->cond);
    producer->config.platform.mutex_unlock(producer->mutex);
    if (producer->persistent) {
        if (producer->persistent_mutex) {
            producer->config.platform.mutex_lock(producer->persistent_mutex);
        }
        flush_rc = ve_tls_persistent_flush(producer->persistent);
        if (producer->persistent_mutex) {
            producer->config.platform.mutex_unlock(producer->persistent_mutex);
        }
    }
    return ve_tls_map_persistent_flush_error(producer, flush_rc);
}

ve_tls_result ve_tls_producer_recover(ve_tls_producer * producer) {
    if (!producer) {
        return VE_TLS_INVALID;
    }
    if (!ve_tls_persistent_enabled(producer)) {
        return VE_TLS_OK;
    }
    ve_tls_recover_ctx ctx;
    ctx.producer = producer;
    if (ve_tls_persistent_recover(producer->persistent, ve_tls_recover_record_to_queue, &ctx) != 0) {
        return VE_TLS_PERSISTENT_ERROR;
    }
    return VE_TLS_OK;
}

static void ve_tls_write_u32_le(unsigned char * p, uint32_t v) {
    p[0] = (unsigned char)(v & 0xFF);
    p[1] = (unsigned char)((v >> 8) & 0xFF);
    p[2] = (unsigned char)((v >> 16) & 0xFF);
    p[3] = (unsigned char)((v >> 24) & 0xFF);
}

static void ve_tls_write_u64_le(unsigned char * p, uint64_t v) {
    for (int i = 0; i < 8; i++) {
        p[i] = (unsigned char)((v >> (8 * i)) & 0xFF);
    }
}

static int ve_tls_read_u32_le(const unsigned char * p, size_t size, size_t * off, uint32_t * out) {
    if (!p || !off || !out || *off + 4 > size) {
        return -1;
    }
    *out = (uint32_t)p[*off] |
           ((uint32_t)p[*off + 1] << 8) |
           ((uint32_t)p[*off + 2] << 16) |
           ((uint32_t)p[*off + 3] << 24);
    *off += 4;
    return 0;
}

static int ve_tls_read_u64_le(const unsigned char * p, size_t size, size_t * off, uint64_t * out) {
    if (!p || !off || !out || *off + 8 > size) {
        return -1;
    }
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) {
        v |= ((uint64_t)p[*off + (size_t)i]) << (8 * i);
    }
    *out = v;
    *off += 8;
    return 0;
}

static int ve_tls_read_u8(const unsigned char * p, size_t size, size_t * off, unsigned char * out) {
    if (!p || !off || !out || *off + 1 > size) {
        return -1;
    }
    *out = p[*off];
    *off += 1;
    return 0;
}

ve_tls_result ve_tls_producer_export_raw_buffer(ve_tls_producer * producer, unsigned char ** out_buf, size_t * out_size) {
    VE_TLS_ALLOC_SITE("export_raw_buffer");
    if (!producer || !out_buf || !out_size) {
        return VE_TLS_INVALID;
    }
    *out_buf = NULL;
    *out_size = 0;

    producer->config.platform.mutex_lock(producer->mutex);
    if (g_tls_batch.producer == producer && g_tls_batch.builder && g_tls_batch.builder->log_count > 0) {
        int frc = ve_tls_tls_batch_merge_locked(producer, g_tls_batch.norm_key, g_tls_batch.builder);
        if (frc != 0) {
            producer->config.platform.mutex_unlock(producer->mutex);
            if (frc == -2) {
                return VE_TLS_CLOSED;
            }
            if (frc == -3) {
                return VE_TLS_TIMEOUT;
            }
            return VE_TLS_DROP_ERROR;
        }
    }
    for (;;) {
        ve_tls_ingress_task it;
        memset(&it, 0, sizeof(it));
        if (ve_tls_ingress_queue_pop_locked(producer, &it) != 0) {
            break;
        }
        if (ve_tls_ingress_task_merge_locked(producer, &it) != 0) {
            if (it.batch) {
                ve_tls_log_builder_free(it.batch);
            }
            producer->config.platform.mutex_unlock(producer->mutex);
            return VE_TLS_DROP_ERROR;
        }
        if (it.batch) {
            ve_tls_log_builder_free(it.batch);
        }
    }
    typedef struct {
        int64_t id;
        int64_t time_ms;
        unsigned char has_ns;
        uint32_t time_ns;
        char * hk;
        uint32_t hk_len;
        unsigned char * data;
        uint32_t data_size;
        int owned;
    } ve_tls_export_rec;

    size_t builder_count = 0;
    if (producer->default_builder && producer->default_builder->log_count > 0) {
        builder_count++;
    }
    for (size_t bi = 0; bi < producer->key_bucket_count; bi++) {
        for (ve_tls_key_queue * q = producer->key_buckets[bi]; q; q = q->hnext) {
            if (q->builder && q->builder->log_count > 0) {
                builder_count++;
            }
        }
    }
    if (producer->queue_count + builder_count > 0xFFFFFFFFu) {
        producer->config.platform.mutex_unlock(producer->mutex);
        return VE_TLS_DROP_ERROR;
    }
    uint32_t count = (uint32_t)(producer->queue_count + builder_count);
    ve_tls_export_rec * recs = NULL;
    if (count > 0) {
        recs = (ve_tls_export_rec *)ve_tls_calloc((size_t)count, sizeof(*recs));
        if (!recs) {
            producer->config.platform.mutex_unlock(producer->mutex);
            return VE_TLS_DROP_ERROR;
        }
    }

    size_t rlen = 0;
    for (size_t i = 0; i < producer->queue_count; i++) {
        size_t idx = (producer->queue_head + i) % producer->queue_cap;
        ve_tls_log_item * it = &producer->queue[idx];
        ve_tls_export_rec * r = &recs[rlen++];
        r->id = it->id;
        r->time_ms = it->time_ms;
        r->has_ns = (unsigned char)(it->has_time_ns ? 1 : 0);
        r->time_ns = it->time_ns;
        r->hk = it->hash_key;
        r->hk_len = it->hash_key ? (uint32_t)strlen(it->hash_key) : 0;
        r->data = it->data;
        r->data_size = (uint32_t)it->size;
        r->owned = 0;
    }
    if (producer->default_builder && producer->default_builder->log_count > 0) {
        ve_tls_send_task t;
        if (ve_tls_builder_to_send_task(producer, producer->default_builder, &t) != 0 || !t.body || t.body_size == 0) {
            for (size_t k = producer->queue_count; k < rlen; k++) {
                if (recs[k].owned) {
                    ve_tls_free(recs[k].hk);
                    ve_tls_free(recs[k].data);
                }
            }
            ve_tls_free(recs);
            producer->config.platform.mutex_unlock(producer->mutex);
            return VE_TLS_DROP_ERROR;
        }
        ve_tls_export_rec * r = &recs[rlen++];
        r->id = producer->default_builder->end_id;
        r->time_ms = producer->default_builder->last_time_ms;
        r->has_ns = (unsigned char)(producer->default_builder->last_has_time_ns ? 1 : 0);
        r->time_ns = producer->default_builder->last_time_ns;
        r->hk = t.hash_key;
        r->hk_len = t.hash_key ? (uint32_t)strlen(t.hash_key) : 0;
        r->data = t.body;
        r->data_size = (uint32_t)t.body_size;
        r->owned = 1;
        t.hash_key = NULL;
        t.body = NULL;
        ve_tls_send_task_free(&t);
    }
    for (size_t bi = 0; bi < producer->key_bucket_count; bi++) {
        for (ve_tls_key_queue * q = producer->key_buckets[bi]; q; q = q->hnext) {
            if (!q->builder || q->builder->log_count == 0) {
                continue;
            }
            ve_tls_send_task t;
            if (ve_tls_builder_to_send_task(producer, q->builder, &t) != 0 || !t.body || t.body_size == 0) {
                for (size_t k = producer->queue_count; k < rlen; k++) {
                    if (recs[k].owned) {
                        ve_tls_free(recs[k].hk);
                        ve_tls_free(recs[k].data);
                    }
                }
                ve_tls_free(recs);
                producer->config.platform.mutex_unlock(producer->mutex);
                return VE_TLS_DROP_ERROR;
            }
            ve_tls_export_rec * r = &recs[rlen++];
            r->id = q->builder->end_id;
            r->time_ms = q->builder->last_time_ms;
            r->has_ns = (unsigned char)(q->builder->last_has_time_ns ? 1 : 0);
            r->time_ns = q->builder->last_time_ns;
            r->hk = t.hash_key;
            r->hk_len = t.hash_key ? (uint32_t)strlen(t.hash_key) : 0;
            r->data = t.body;
            r->data_size = (uint32_t)t.body_size;
            r->owned = 1;
            t.hash_key = NULL;
            t.body = NULL;
            ve_tls_send_task_free(&t);
        }
    }

    size_t total = 4 + 4 + 4 + 8;
    for (size_t i = 0; i < rlen; i++) {
        ve_tls_export_rec * r = &recs[i];
        if (r->hk_len > 0xFFFFFFFFu || r->data_size > 0xFFFFFFFFu) {
            for (size_t k = producer->queue_count; k < rlen; k++) {
                if (recs[k].owned) {
                    ve_tls_free(recs[k].hk);
                    ve_tls_free(recs[k].data);
                }
            }
            ve_tls_free(recs);
            producer->config.platform.mutex_unlock(producer->mutex);
            return VE_TLS_DROP_ERROR;
        }
        size_t add = 8 + 8 + 1 + 4 + 4 + 4;
        if (add > (size_t)-1 - (size_t)r->hk_len) {
            for (size_t k = producer->queue_count; k < rlen; k++) {
                if (recs[k].owned) {
                    ve_tls_free(recs[k].hk);
                    ve_tls_free(recs[k].data);
                }
            }
            ve_tls_free(recs);
            producer->config.platform.mutex_unlock(producer->mutex);
            return VE_TLS_DROP_ERROR;
        }
        add += (size_t)r->hk_len;
        if (add > (size_t)-1 - (size_t)r->data_size) {
            for (size_t k = producer->queue_count; k < rlen; k++) {
                if (recs[k].owned) {
                    ve_tls_free(recs[k].hk);
                    ve_tls_free(recs[k].data);
                }
            }
            ve_tls_free(recs);
            producer->config.platform.mutex_unlock(producer->mutex);
            return VE_TLS_DROP_ERROR;
        }
        add += (size_t)r->data_size;
        if (total > (size_t)-1 - add) {
            for (size_t k = producer->queue_count; k < rlen; k++) {
                if (recs[k].owned) {
                    ve_tls_free(recs[k].hk);
                    ve_tls_free(recs[k].data);
                }
            }
            ve_tls_free(recs);
            producer->config.platform.mutex_unlock(producer->mutex);
            return VE_TLS_DROP_ERROR;
        }
        total += add;
    }
    unsigned char * buf = (unsigned char *)ve_tls_malloc(total);
    if (!buf) {
        for (size_t k = producer->queue_count; k < rlen; k++) {
            if (recs[k].owned) {
                ve_tls_free(recs[k].hk);
                ve_tls_free(recs[k].data);
            }
        }
        ve_tls_free(recs);
        producer->config.platform.mutex_unlock(producer->mutex);
        return VE_TLS_DROP_ERROR;
    }
    size_t off = 0;
    buf[off++] = 'V';
    buf[off++] = 'T';
    buf[off++] = 'L';
    buf[off++] = 'S';
    ve_tls_write_u32_le(buf + off, 3);
    off += 4;
    ve_tls_write_u32_le(buf + off, count);
    off += 4;
    ve_tls_write_u64_le(buf + off, (uint64_t)__atomic_load_n(&producer->next_id, __ATOMIC_RELAXED));
    off += 8;

    for (size_t i = 0; i < rlen; i++) {
        ve_tls_export_rec * r = &recs[i];
        ve_tls_write_u64_le(buf + off, (uint64_t)r->id);
        off += 8;
        ve_tls_write_u64_le(buf + off, (uint64_t)r->time_ms);
        off += 8;
        buf[off++] = (unsigned char)(r->has_ns ? 1 : 0);
        ve_tls_write_u32_le(buf + off, r->time_ns);
        off += 4;
        ve_tls_write_u32_le(buf + off, r->hk_len);
        off += 4;
        ve_tls_write_u32_le(buf + off, r->data_size);
        off += 4;
        if (r->hk_len > 0) {
            memcpy(buf + off, r->hk, (size_t)r->hk_len);
            off += (size_t)r->hk_len;
        }
        memcpy(buf + off, r->data, (size_t)r->data_size);
        off += (size_t)r->data_size;
    }
    for (size_t k = producer->queue_count; k < rlen; k++) {
        if (recs[k].owned) {
            ve_tls_free(recs[k].hk);
            ve_tls_free(recs[k].data);
        }
    }
    ve_tls_free(recs);
    producer->config.platform.mutex_unlock(producer->mutex);

    *out_buf = buf;
    *out_size = off;
    return VE_TLS_OK;
}

ve_tls_result ve_tls_producer_import_raw_buffer(ve_tls_producer * producer, const unsigned char * buf, size_t size) {
    VE_TLS_ALLOC_SITE("import_raw_buffer");
    if (!producer || !buf || size < 4 + 4 + 4 + 8) {
        return VE_TLS_INVALID;
    }
    if (!(buf[0] == 'V' && buf[1] == 'T' && buf[2] == 'L' && buf[3] == 'S')) {
        return VE_TLS_INVALID;
    }
    size_t off = 4;
    uint32_t version = 0;
    uint32_t count = 0;
    uint64_t next_id = 0;
    if (ve_tls_read_u32_le(buf, size, &off, &version) != 0 || (version != 1 && version != 2 && version != 3)) {
        return VE_TLS_INVALID;
    }
    if (ve_tls_read_u32_le(buf, size, &off, &count) != 0) {
        return VE_TLS_INVALID;
    }
    if (ve_tls_read_u64_le(buf, size, &off, &next_id) != 0) {
        return VE_TLS_INVALID;
    }

    producer->config.platform.mutex_lock(producer->mutex);
    int64_t current_next_id = __atomic_load_n(&producer->next_id, __ATOMIC_RELAXED);
    uint64_t max_id = current_next_id > 0 ? (uint64_t)(current_next_id - 1) : 0;
    for (uint32_t i = 0; i < count; i++) {
        uint64_t id = 0;
        uint64_t time_ms = 0;
        unsigned char has_ns = 0;
        uint32_t time_ns = 0;
        uint32_t hk_len = 0;
        uint32_t data_size = 0;
        if (ve_tls_read_u64_le(buf, size, &off, &id) != 0 ||
            ve_tls_read_u64_le(buf, size, &off, &time_ms) != 0 ||
            ve_tls_read_u8(buf, size, &off, &has_ns) != 0 ||
            ve_tls_read_u32_le(buf, size, &off, &time_ns) != 0 ||
            (version >= 2 && ve_tls_read_u32_le(buf, size, &off, &hk_len) != 0) ||
            ve_tls_read_u32_le(buf, size, &off, &data_size) != 0) {
            producer->config.platform.mutex_unlock(producer->mutex);
            return VE_TLS_INVALID;
        }
        if (off > size) {
            producer->config.platform.mutex_unlock(producer->mutex);
            return VE_TLS_INVALID;
        }
        size_t remain = size - off;
        if (remain < (size_t)hk_len) {
            producer->config.platform.mutex_unlock(producer->mutex);
            return VE_TLS_INVALID;
        }
        if (!ve_tls_has_buffer_space_locked(producer, (size_t)data_size, 0)) {
            producer->config.platform.mutex_unlock(producer->mutex);
            return VE_TLS_DROP_ERROR;
        }
        char * hk = NULL;
        if (version >= 2 && hk_len > 0) {
            hk = (char *)ve_tls_malloc((size_t)hk_len + 1);
            if (!hk) {
                producer->config.platform.mutex_unlock(producer->mutex);
                return VE_TLS_DROP_ERROR;
            }
            memcpy(hk, buf + off, (size_t)hk_len);
            hk[hk_len] = 0;
        }
        off += (size_t)hk_len;
        if (off > size || (size - off) < (size_t)data_size) {
            ve_tls_free(hk);
            producer->config.platform.mutex_unlock(producer->mutex);
            return VE_TLS_INVALID;
        }
        if (ve_tls_queue_push(producer, buf + off, data_size, (int64_t)id, (int64_t)time_ms, time_ns, has_ns ? 1 : 0, hk) != 0) {
            ve_tls_free(hk);
            producer->config.platform.mutex_unlock(producer->mutex);
            return VE_TLS_DROP_ERROR;
        }
        ve_tls_free(hk);
        if (id > max_id) {
            max_id = id;
        }
        off += data_size;
    }
    uint64_t desired_next = max_id + 1;
    if (next_id > desired_next) {
        desired_next = next_id;
    }
    if (desired_next <= (uint64_t)INT64_MAX) {
        ve_tls_producer_advance_next_log_id(producer, (int64_t)desired_next);
    }
    producer->config.platform.cond_signal(producer->cond);
    producer->config.platform.mutex_unlock(producer->mutex);
    return VE_TLS_OK;
}

void ve_tls_producer_free_raw_buffer(unsigned char * buf) {
    ve_tls_free(buf);
}
