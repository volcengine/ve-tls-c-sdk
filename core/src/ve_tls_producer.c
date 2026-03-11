#include "producer/ve_tls_producer_internal.h"

#include <stdlib.h>
#include <string.h>

static int ve_tls_producer_is_drained_locked(ve_tls_producer * producer) {
    if (!producer) {
        return 1;
    }
    if (producer->queue_count != 0 || producer->worker_flushing) {
        return 0;
    }
    if (producer->send_queue.mutex) {
        producer->send_queue.platform->mutex_lock(producer->send_queue.mutex);
        size_t sc = producer->send_queue.count;
        producer->send_queue.platform->mutex_unlock(producer->send_queue.mutex);
        if (sc != 0) {
            return 0;
        }
    }
    for (size_t i = 0; i < producer->key_bucket_count; i++) {
        ve_tls_key_queue * q = producer->key_buckets[i];
        while (q) {
            if (q->count != 0 || q->inflight != 0) {
                return 0;
            }
            q = q->hnext;
        }
    }
    return 1;
}

void ve_tls_config_init(ve_tls_config * config) {
    ve_tls_producer_config_init(config);
}

ve_tls_producer * ve_tls_producer_create(const ve_tls_config * config) {
    if (!config) {
        return NULL;
    }
    ve_tls_producer * producer = (ve_tls_producer *)calloc(1, sizeof(ve_tls_producer));
    if (!producer) {
        return NULL;
    }
    producer->config = *config;
    producer->mutex = producer->config.platform.mutex_create();
    producer->cond = producer->config.platform.cond_create();
    producer->send_cond = producer->config.platform.cond_create();
    if (!producer->mutex || !producer->cond || !producer->send_cond) {
        ve_tls_producer_destroy(producer);
        return NULL;
    }
    producer->next_id = 1;
    producer->accepting = 1;
    producer->sender_count = producer->config.send_thread_count > 0 ? producer->config.send_thread_count : 1;
    producer->senders = (ve_tls_thread **)calloc((size_t)producer->sender_count, sizeof(ve_tls_thread *));
    if (!producer->senders) {
        ve_tls_producer_destroy(producer);
        return NULL;
    }
    producer->key_bucket_count = (size_t)(producer->config.key_queue_bucket_count > 0 ? producer->config.key_queue_bucket_count : 1024);
    producer->key_buckets = (ve_tls_key_queue **)calloc(producer->key_bucket_count, sizeof(ve_tls_key_queue *));
    if (!producer->key_buckets) {
        ve_tls_producer_destroy(producer);
        return NULL;
    }
    size_t sq_cap = (size_t)(producer->config.send_queue_size > 0 ? producer->config.send_queue_size : 1024);
    if (ve_tls_send_queue_init(&producer->send_queue, &producer->config.platform, sq_cap) != 0) {
        ve_tls_producer_destroy(producer);
        return NULL;
    }
    producer->worker = producer->config.platform.thread_create(ve_tls_worker_main, producer);
    if (!producer->worker) {
        ve_tls_producer_destroy(producer);
        return NULL;
    }
    for (int32_t i = 0; i < producer->sender_count; i++) {
        producer->senders[i] = producer->config.platform.thread_create(ve_tls_sender_main, producer);
        if (!producer->senders[i]) {
            ve_tls_producer_destroy(producer);
            return NULL;
        }
    }
    return producer;
}

ve_tls_result ve_tls_producer_close(ve_tls_producer * producer, int32_t timeout_ms) {
    if (!producer) {
        return VE_TLS_INVALID;
    }
    producer->config.platform.mutex_lock(producer->mutex);
    ve_tls_metrics_emit(producer, "close_start", 1, timeout_ms);
    producer->accepting = 0;
    producer->closing = 1;
    producer->flush_requested = 1;
    producer->config.platform.cond_broadcast(producer->cond);
    if (producer->send_cond) {
        producer->config.platform.cond_broadcast(producer->send_cond);
    }
    int64_t start_ms = producer->config.platform.time_ms ? producer->config.platform.time_ms() : 0;
    ve_tls_cond * wait_cond = producer->send_cond ? producer->send_cond : producer->cond;
    ve_tls_result rc = VE_TLS_OK;
    int join_threads = 0;
    for (;;) {
        if (ve_tls_producer_is_drained_locked(producer)) {
            ve_tls_metrics_emit(producer, "close_drain_ok", 1, 0);
            producer->closing = 0;
            producer->stop = 1;
            producer->config.platform.cond_broadcast(producer->cond);
            if (producer->send_cond) {
                producer->config.platform.cond_broadcast(producer->send_cond);
            }
            join_threads = 1;
            break;
        }
        if (timeout_ms == 0) {
            ve_tls_metrics_emit(producer, "close_timeout", 1, 0);
            rc = VE_TLS_TIMEOUT;
            break;
        }
        int wait_ms = 50;
        if (timeout_ms > 0) {
            int64_t now = producer->config.platform.time_ms ? producer->config.platform.time_ms() : start_ms;
            int64_t elapsed = now - start_ms;
            int64_t remain = (int64_t)timeout_ms - elapsed;
            if (remain <= 0) {
                ve_tls_metrics_emit(producer, "close_timeout", 1, 0);
                rc = VE_TLS_TIMEOUT;
                break;
            }
            if (remain < wait_ms) {
                wait_ms = (int)remain;
            }
        }
        (void)producer->config.platform.cond_timedwait_ms(wait_cond, producer->mutex, wait_ms);
    }
    producer->config.platform.mutex_unlock(producer->mutex);
    if (join_threads) {
        if (producer->worker) {
            producer->config.platform.thread_join(producer->worker);
            producer->worker = NULL;
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
    return rc;
}

void ve_tls_producer_destroy(ve_tls_producer * producer) {
    if (!producer) {
        return;
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
        producer->config.platform.mutex_unlock(producer->mutex);
    }
    ve_tls_send_queue_stop(&producer->send_queue);
    if (producer->worker) {
        producer->config.platform.thread_join(producer->worker);
        producer->worker = NULL;
    }
    if (producer->senders) {
        for (int32_t i = 0; i < producer->sender_count; i++) {
            if (producer->senders[i]) {
                producer->config.platform.thread_join(producer->senders[i]);
                producer->senders[i] = NULL;
            }
        }
        free(producer->senders);
        producer->senders = NULL;
        producer->sender_count = 0;
    }
    ve_tls_queue_free_all(producer);
    ve_tls_key_map_free_all(producer);
    ve_tls_send_queue_destroy(&producer->send_queue);
    free(producer->cred_access_key_id);
    free(producer->cred_access_key_secret);
    free(producer->cred_security_token);
    producer->cred_access_key_id = NULL;
    producer->cred_access_key_secret = NULL;
    producer->cred_security_token = NULL;
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
    free(producer);
}

void ve_tls_producer_set_send_done(ve_tls_producer * producer, ve_tls_send_done_fn callback, void * user_param) {
    if (!producer) {
        return;
    }
    producer->send_done = callback;
    producer->send_done_param = user_param;
}

void ve_tls_producer_set_send_done_v2(ve_tls_producer * producer, ve_tls_send_done_v2_fn callback, void * user_param) {
    if (!producer) {
        return;
    }
    producer->send_done_v2 = callback;
    producer->send_done_v2_param = user_param;
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

ve_tls_result ve_tls_producer_add_log_raw(ve_tls_producer * producer, const char * log_buf, size_t log_size, int flush) {
    if (!producer || !log_buf || log_size == 0) {
        return VE_TLS_INVALID;
    }
    producer->config.platform.mutex_lock(producer->mutex);
    if (producer->stop || !producer->accepting) {
        producer->config.platform.mutex_unlock(producer->mutex);
        return VE_TLS_CLOSED;
    }
    if (producer->config.max_buffer_bytes > 0 && (int64_t)(producer->queue_bytes + log_size) > producer->config.max_buffer_bytes) {
        producer->config.platform.mutex_unlock(producer->mutex);
        ve_tls_metric_inc_u64(&producer->m_logs_dropped_total, 1);
        ve_tls_metric_inc_u64(&producer->m_bytes_dropped_total, log_size);
        ve_tls_metrics_emit(producer, "log_dropped", 1, (int64_t)log_size);
        return VE_TLS_DROP_ERROR;
    }
    int64_t id = producer->next_id++;
    if (ve_tls_queue_push(producer, (const unsigned char *)log_buf, log_size, id, 0, 0, 0, NULL) != 0) {
        producer->config.platform.mutex_unlock(producer->mutex);
        ve_tls_metric_inc_u64(&producer->m_logs_dropped_total, 1);
        ve_tls_metric_inc_u64(&producer->m_bytes_dropped_total, log_size);
        ve_tls_metrics_emit(producer, "log_dropped", 1, (int64_t)log_size);
        return VE_TLS_DROP_ERROR;
    }
    ve_tls_metric_inc_u64(&producer->m_logs_enqueued_total, 1);
    ve_tls_metric_inc_u64(&producer->m_bytes_enqueued_total, log_size);
    ve_tls_metrics_emit(producer, "log_enqueued", 1, (int64_t)log_size);
    if (flush) {
        producer->flush_requested = 1;
    }
    producer->config.platform.cond_signal(producer->cond);
    producer->config.platform.mutex_unlock(producer->mutex);
    return VE_TLS_OK;
}

ve_tls_result ve_tls_producer_add_log_kv(ve_tls_producer * producer, int64_t time_ms, const ve_tls_kv * kvs, size_t kv_count, int flush) {
    return ve_tls_producer_add_log_kv_hashkey(producer, time_ms, NULL, kvs, kv_count, flush);
}

ve_tls_result ve_tls_producer_add_log_kv_ns(ve_tls_producer * producer, int64_t time_unix_ns, const ve_tls_kv * kvs, size_t kv_count, int flush) {
    return ve_tls_producer_add_log_kv_ns_hashkey(producer, time_unix_ns, NULL, kvs, kv_count, flush);
}

ve_tls_result ve_tls_producer_add_log_kv_hashkey(ve_tls_producer * producer, int64_t time_ms, const char * hash_key, const ve_tls_kv * kvs, size_t kv_count, int flush) {
    if (!producer || !kvs || kv_count == 0) {
        return VE_TLS_INVALID;
    }
    if (time_ms <= 0) {
        time_ms = producer->config.platform.time_ms();
    }
    ve_tls_bytes b;
    if (ve_tls_proto_encode_log_ex(time_ms, 0, 0, kvs, kv_count, &b) != 0) {
        return VE_TLS_DROP_ERROR;
    }
    producer->config.platform.mutex_lock(producer->mutex);
    if (producer->stop || !producer->accepting) {
        producer->config.platform.mutex_unlock(producer->mutex);
        ve_tls_bytes_free(&b);
        return VE_TLS_CLOSED;
    }
    if (producer->config.max_buffer_bytes > 0 && (int64_t)(producer->queue_bytes + b.size) > producer->config.max_buffer_bytes) {
        producer->config.platform.mutex_unlock(producer->mutex);
        ve_tls_bytes_free(&b);
        ve_tls_metric_inc_u64(&producer->m_logs_dropped_total, 1);
        ve_tls_metric_inc_u64(&producer->m_bytes_dropped_total, b.size);
        ve_tls_metrics_emit(producer, "log_dropped", 1, (int64_t)b.size);
        return VE_TLS_DROP_ERROR;
    }
    int64_t id = producer->next_id++;
    if (ve_tls_queue_push(producer, b.data, b.size, id, time_ms, 0, 0, hash_key) != 0) {
        producer->config.platform.mutex_unlock(producer->mutex);
        ve_tls_bytes_free(&b);
        ve_tls_metric_inc_u64(&producer->m_logs_dropped_total, 1);
        ve_tls_metric_inc_u64(&producer->m_bytes_dropped_total, b.size);
        ve_tls_metrics_emit(producer, "log_dropped", 1, (int64_t)b.size);
        return VE_TLS_DROP_ERROR;
    }
    ve_tls_metric_inc_u64(&producer->m_logs_enqueued_total, 1);
    ve_tls_metric_inc_u64(&producer->m_bytes_enqueued_total, b.size);
    ve_tls_metrics_emit(producer, "log_enqueued", 1, (int64_t)b.size);
    if (flush) {
        producer->flush_requested = 1;
    }
    producer->config.platform.cond_signal(producer->cond);
    producer->config.platform.mutex_unlock(producer->mutex);
    ve_tls_bytes_free(&b);
    return VE_TLS_OK;
}

ve_tls_result ve_tls_producer_add_log_kv_ns_hashkey(ve_tls_producer * producer, int64_t time_unix_ns, const char * hash_key, const ve_tls_kv * kvs, size_t kv_count, int flush) {
    if (!producer || !kvs || kv_count == 0) {
        return VE_TLS_INVALID;
    }
    if (time_unix_ns <= 0) {
        return ve_tls_producer_add_log_kv_hashkey(producer, 0, hash_key, kvs, kv_count, flush);
    }
    int64_t time_ms = time_unix_ns / 1000000LL;
    int64_t rem = time_unix_ns - time_ms * 1000000LL;
    if (rem < 0) {
        rem = 0;
    }
    if (rem > 999999) {
        rem = 999999;
    }
    uint32_t time_ns = (uint32_t)rem;

    ve_tls_bytes b;
    if (ve_tls_proto_encode_log_ex(time_ms, time_ns, 1, kvs, kv_count, &b) != 0) {
        return VE_TLS_DROP_ERROR;
    }
    producer->config.platform.mutex_lock(producer->mutex);
    if (producer->stop || !producer->accepting) {
        producer->config.platform.mutex_unlock(producer->mutex);
        ve_tls_bytes_free(&b);
        return VE_TLS_CLOSED;
    }
    if (producer->config.max_buffer_bytes > 0 && (int64_t)(producer->queue_bytes + b.size) > producer->config.max_buffer_bytes) {
        producer->config.platform.mutex_unlock(producer->mutex);
        ve_tls_bytes_free(&b);
        ve_tls_metric_inc_u64(&producer->m_logs_dropped_total, 1);
        ve_tls_metric_inc_u64(&producer->m_bytes_dropped_total, b.size);
        ve_tls_metrics_emit(producer, "log_dropped", 1, (int64_t)b.size);
        return VE_TLS_DROP_ERROR;
    }
    int64_t id = producer->next_id++;
    if (ve_tls_queue_push(producer, b.data, b.size, id, time_ms, time_ns, 1, hash_key) != 0) {
        producer->config.platform.mutex_unlock(producer->mutex);
        ve_tls_bytes_free(&b);
        ve_tls_metric_inc_u64(&producer->m_logs_dropped_total, 1);
        ve_tls_metric_inc_u64(&producer->m_bytes_dropped_total, b.size);
        ve_tls_metrics_emit(producer, "log_dropped", 1, (int64_t)b.size);
        return VE_TLS_DROP_ERROR;
    }
    ve_tls_metric_inc_u64(&producer->m_logs_enqueued_total, 1);
    ve_tls_metric_inc_u64(&producer->m_bytes_enqueued_total, b.size);
    ve_tls_metrics_emit(producer, "log_enqueued", 1, (int64_t)b.size);
    if (flush) {
        producer->flush_requested = 1;
    }
    producer->config.platform.cond_signal(producer->cond);
    producer->config.platform.mutex_unlock(producer->mutex);
    ve_tls_bytes_free(&b);
    return VE_TLS_OK;
}

ve_tls_result ve_tls_producer_flush(ve_tls_producer * producer) {
    if (!producer) {
        return VE_TLS_INVALID;
    }
    producer->config.platform.mutex_lock(producer->mutex);
    producer->flush_requested = 1;
    producer->config.platform.cond_broadcast(producer->cond);
    producer->config.platform.mutex_unlock(producer->mutex);
    return VE_TLS_OK;
}

ve_tls_result ve_tls_producer_recover(ve_tls_producer * producer) {
    if (!producer) {
        return VE_TLS_INVALID;
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
    if (!producer || !out_buf || !out_size) {
        return VE_TLS_INVALID;
    }
    *out_buf = NULL;
    *out_size = 0;

    producer->config.platform.mutex_lock(producer->mutex);
    uint32_t count = (uint32_t)producer->queue_count;
    size_t total = 4 + 4 + 4 + 8;
    for (size_t i = 0; i < producer->queue_count; i++) {
        size_t idx = (producer->queue_head + i) % producer->queue_cap;
        ve_tls_log_item * it = &producer->queue[idx];
        uint32_t hk_len = it->hash_key ? (uint32_t)strlen(it->hash_key) : 0;
        total += 8 + 8 + 1 + 4 + 4 + 4 + (size_t)hk_len + it->size;
    }
    unsigned char * buf = (unsigned char *)malloc(total);
    if (!buf) {
        producer->config.platform.mutex_unlock(producer->mutex);
        return VE_TLS_DROP_ERROR;
    }
    size_t off = 0;
    buf[off++] = 'V';
    buf[off++] = 'T';
    buf[off++] = 'L';
    buf[off++] = 'S';
    ve_tls_write_u32_le(buf + off, 2);
    off += 4;
    ve_tls_write_u32_le(buf + off, count);
    off += 4;
    ve_tls_write_u64_le(buf + off, (uint64_t)producer->next_id);
    off += 8;

    for (size_t i = 0; i < producer->queue_count; i++) {
        size_t idx = (producer->queue_head + i) % producer->queue_cap;
        ve_tls_log_item * it = &producer->queue[idx];
        ve_tls_write_u64_le(buf + off, (uint64_t)it->id);
        off += 8;
        ve_tls_write_u64_le(buf + off, (uint64_t)it->time_ms);
        off += 8;
        buf[off++] = (unsigned char)(it->has_time_ns ? 1 : 0);
        ve_tls_write_u32_le(buf + off, it->time_ns);
        off += 4;
        uint32_t hk_len = it->hash_key ? (uint32_t)strlen(it->hash_key) : 0;
        ve_tls_write_u32_le(buf + off, hk_len);
        off += 4;
        ve_tls_write_u32_le(buf + off, (uint32_t)it->size);
        off += 4;
        if (hk_len > 0) {
            memcpy(buf + off, it->hash_key, (size_t)hk_len);
            off += (size_t)hk_len;
        }
        memcpy(buf + off, it->data, it->size);
        off += it->size;
    }
    producer->config.platform.mutex_unlock(producer->mutex);

    *out_buf = buf;
    *out_size = off;
    return VE_TLS_OK;
}

ve_tls_result ve_tls_producer_import_raw_buffer(ve_tls_producer * producer, const unsigned char * buf, size_t size) {
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
    if (ve_tls_read_u32_le(buf, size, &off, &version) != 0 || (version != 1 && version != 2)) {
        return VE_TLS_INVALID;
    }
    if (ve_tls_read_u32_le(buf, size, &off, &count) != 0) {
        return VE_TLS_INVALID;
    }
    if (ve_tls_read_u64_le(buf, size, &off, &next_id) != 0) {
        return VE_TLS_INVALID;
    }

    producer->config.platform.mutex_lock(producer->mutex);
    uint64_t max_id = producer->next_id > 0 ? (uint64_t)(producer->next_id - 1) : 0;
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
            (version == 2 && ve_tls_read_u32_le(buf, size, &off, &hk_len) != 0) ||
            ve_tls_read_u32_le(buf, size, &off, &data_size) != 0 ||
            off + (size_t)hk_len + data_size > size) {
            producer->config.platform.mutex_unlock(producer->mutex);
            return VE_TLS_INVALID;
        }
        if (producer->config.max_buffer_bytes > 0 && (int64_t)(producer->queue_bytes + data_size) > producer->config.max_buffer_bytes) {
            producer->config.platform.mutex_unlock(producer->mutex);
            return VE_TLS_DROP_ERROR;
        }
        char * hk = NULL;
        if (version == 2 && hk_len > 0) {
            hk = (char *)malloc((size_t)hk_len + 1);
            if (!hk) {
                producer->config.platform.mutex_unlock(producer->mutex);
                return VE_TLS_DROP_ERROR;
            }
            memcpy(hk, buf + off, (size_t)hk_len);
            hk[hk_len] = 0;
        }
        off += (size_t)hk_len;
        if (ve_tls_queue_push(producer, buf + off, data_size, (int64_t)id, (int64_t)time_ms, time_ns, has_ns ? 1 : 0, hk) != 0) {
            free(hk);
            producer->config.platform.mutex_unlock(producer->mutex);
            return VE_TLS_DROP_ERROR;
        }
        free(hk);
        if (id > max_id) {
            max_id = id;
        }
        off += data_size;
    }
    uint64_t desired_next = max_id + 1;
    if (next_id > desired_next) {
        desired_next = next_id;
    }
    if (desired_next > (uint64_t)producer->next_id) {
        producer->next_id = (int64_t)desired_next;
    }
    producer->config.platform.cond_signal(producer->cond);
    producer->config.platform.mutex_unlock(producer->mutex);
    return VE_TLS_OK;
}

void ve_tls_producer_free_raw_buffer(unsigned char * buf) {
    free(buf);
}
