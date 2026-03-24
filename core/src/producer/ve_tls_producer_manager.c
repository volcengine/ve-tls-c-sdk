#include "ve_tls_producer_internal.h"
#include "ve_tls_alloc.h"

#include <stdlib.h>
#include <string.h>

typedef struct {
    ve_tls_send_done_fn cb;
    void * cb_param;
    ve_tls_send_done_v2_fn cb2;
    void * cb2_param;
} ve_tls_send_callbacks;

static ve_tls_send_callbacks ve_tls_capture_callbacks(ve_tls_producer * producer) {
    ve_tls_send_callbacks out;
    memset(&out, 0, sizeof(out));
    if (!producer) {
        return out;
    }
    producer->config.platform.mutex_lock(producer->mutex);
    out.cb = producer->send_done;
    out.cb_param = producer->send_done_param;
    out.cb2 = producer->send_done_v2;
    out.cb2_param = producer->send_done_v2_param;
    producer->config.platform.mutex_unlock(producer->mutex);
    return out;
}

static void ve_tls_manager_drop_item(ve_tls_producer * producer, size_t bytes, int64_t id, const char * code, const char * message) {
    ve_tls_send_callbacks cbs = ve_tls_capture_callbacks(producer);
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

static int ve_tls_manager_requeue_item(ve_tls_producer * producer, const ve_tls_log_item * item) {
    if (!producer || !item || !item->data || item->size == 0) {
        return -1;
    }
    producer->config.platform.mutex_lock(producer->mutex);
    int rc = ve_tls_queue_push(producer, item->data, item->size, item->id, item->time_ms, item->time_ns, item->has_time_ns, item->hash_key);
    if (rc == 0) {
        producer->flush_requested = 1;
        producer->config.platform.cond_signal(producer->cond);
    }
    producer->config.platform.mutex_unlock(producer->mutex);
    return rc;
}

void * ve_tls_worker_main(void * arg) {
    ve_tls_producer * producer = (ve_tls_producer *)arg;
    int64_t last_flush = producer->config.platform.time_ms ? producer->config.platform.time_ms() : 0;
    for (;;) {
        producer->config.platform.mutex_lock(producer->mutex);
        while (!producer->stop && producer->queue_count == 0 && !producer->flush_requested) {
            producer->config.platform.cond_wait(producer->cond, producer->mutex);
        }
        if (producer->stop && producer->queue_count == 0) {
            producer->config.platform.mutex_unlock(producer->mutex);
            break;
        }

        int should_flush = producer->flush_requested;
        int64_t now = producer->config.platform.time_ms ? producer->config.platform.time_ms() : 0;
        if (!should_flush && producer->stop && producer->queue_count > 0) {
            should_flush = 1;
        }
        if (!should_flush && producer->queue_count > 0 && producer->config.flush_interval_ms > 0) {
            if (now - last_flush >= producer->config.flush_interval_ms) {
                should_flush = 1;
            }
        }

        if (!should_flush) {
            producer->flush_requested = 0;
            producer->worker_flushing = 0;
            producer->config.platform.mutex_unlock(producer->mutex);
            continue;
        }
        producer->flush_requested = 0;
        producer->worker_flushing = 1;
        producer->config.platform.mutex_unlock(producer->mutex);

        ve_tls_log_item * items = NULL;
        size_t items_cap = 0;
        size_t items_len = 0;
        size_t batch_bytes = 0;
        int64_t start_id = 0;
        int64_t end_id = 0;
        int64_t earliest = 0;
        int64_t latest = 0;

        size_t byte_limit = producer->config.log_bytes_per_package > 0 ? (size_t)producer->config.log_bytes_per_package : 0;
        if (producer->config.agg_max_raw_bytes_per_request > 0) {
            size_t max_raw = (size_t)producer->config.agg_max_raw_bytes_per_request;
            if (byte_limit == 0 || byte_limit > max_raw) {
                byte_limit = max_raw;
            }
        }

        for (;;) {
            ve_tls_log_item item;
            producer->config.platform.mutex_lock(producer->mutex);
            int ok = ve_tls_queue_pop(producer, &item);
            producer->config.platform.mutex_unlock(producer->mutex);
            if (ok != 0) {
                break;
            }
            if (items_len == 0) {
                start_id = item.id;
            }
            end_id = item.id;
            batch_bytes += item.size;
            if (item.time_ms > 0) {
                if (earliest == 0 || item.time_ms < earliest) {
                    earliest = item.time_ms;
                }
                if (latest == 0 || item.time_ms > latest) {
                    latest = item.time_ms;
                }
            }
            if (items_len + 1 > items_cap) {
                size_t next = items_cap ? items_cap * 2 : 256;
                ve_tls_log_item * p = (ve_tls_log_item *)ve_tls_realloc(items, next * sizeof(ve_tls_log_item));
                if (!p) {
                    ve_tls_item_free(&item);
                    break;
                }
                items = p;
                items_cap = next;
            }
            items[items_len++] = item;
            if (producer->config.log_count_per_package > 0 && (int32_t)items_len >= producer->config.log_count_per_package) {
                break;
            }
            if (byte_limit > 0 && batch_bytes >= byte_limit) {
                break;
            }
        }

        if (items_len > 0) {
            typedef struct {
                char * key;
                ve_tls_bytes * logs;
                int64_t * times;
                int64_t * ids;
                size_t count;
                size_t cap;
                size_t bytes;
                int64_t earliest;
                int64_t latest;
                int64_t start_id;
                int64_t end_id;
            } ve_tls_group;

            ve_tls_group * groups = NULL;
            size_t groups_len = 0;
            size_t groups_cap = 0;

            for (size_t i = 0; i < items_len; i++) {
                const char * key = (items[i].hash_key && items[i].hash_key[0] != 0) ? items[i].hash_key : producer->config.hash_key;
                if (key && key[0] == 0) {
                    key = NULL;
                }
                size_t gi = (size_t)-1;
                for (size_t j = 0; j < groups_len; j++) {
                    if (!groups[j].key && !key) {
                        gi = j;
                        break;
                    }
                    if (groups[j].key && key && strcmp(groups[j].key, key) == 0) {
                        gi = j;
                        break;
                    }
                }
                if (gi == (size_t)-1) {
                    if (groups_len + 1 > groups_cap) {
                        size_t next = groups_cap ? groups_cap * 2 : 8;
                        ve_tls_group * p = (ve_tls_group *)ve_tls_realloc(groups, next * sizeof(ve_tls_group));
                        if (!p) {
                            ve_tls_metrics_emit(producer, "agg_groups_alloc_failed", 1, 0);
                            if (ve_tls_manager_requeue_item(producer, &items[i]) != 0) {
                                ve_tls_metric_inc_u64(&producer->m_logs_dropped_total, 1);
                                ve_tls_metric_inc_u64(&producer->m_bytes_dropped_total, items[i].size);
                                ve_tls_metrics_emit(producer, "log_dropped", 1, (int64_t)items[i].size);
                                ve_tls_manager_drop_item(producer, items[i].size, items[i].id, "MemoryAllocFailed", "groups realloc failed");
                            }
                            ve_tls_item_free(&items[i]);
                            continue;
                        }
                        groups = p;
                        groups_cap = next;
                    }
                    memset(&groups[groups_len], 0, sizeof(ve_tls_group));
                    if (key) {
                        groups[groups_len].key = ve_tls_strdup(key);
                        if (!groups[groups_len].key) {
                            ve_tls_metrics_emit(producer, "agg_groups_alloc_failed", 1, 0);
                            if (ve_tls_manager_requeue_item(producer, &items[i]) != 0) {
                                ve_tls_metric_inc_u64(&producer->m_logs_dropped_total, 1);
                                ve_tls_metric_inc_u64(&producer->m_bytes_dropped_total, items[i].size);
                                ve_tls_metrics_emit(producer, "log_dropped", 1, (int64_t)items[i].size);
                                ve_tls_manager_drop_item(producer, items[i].size, items[i].id, "MemoryAllocFailed", "group key strdup failed");
                            }
                            ve_tls_item_free(&items[i]);
                            continue;
                        }
                    }
                    groups[groups_len].earliest = items[i].time_ms;
                    groups[groups_len].latest = items[i].time_ms;
                    groups[groups_len].start_id = items[i].id;
                    groups[groups_len].end_id = items[i].id;
                    gi = groups_len++;
                }
                ve_tls_group * g = &groups[gi];
                if (g->count + 1 > g->cap) {
                    size_t next = g->cap ? g->cap * 2 : 256;
                    ve_tls_bytes * logs = (ve_tls_bytes *)ve_tls_malloc(next * sizeof(ve_tls_bytes));
                    int64_t * times = (int64_t *)ve_tls_malloc(next * sizeof(int64_t));
                    int64_t * ids = (int64_t *)ve_tls_malloc(next * sizeof(int64_t));
                    if (!logs || !times || !ids) {
                        ve_tls_free(logs);
                        ve_tls_free(times);
                        ve_tls_free(ids);
                        ve_tls_metrics_emit(producer, "agg_group_alloc_failed", 1, 0);
                        if (ve_tls_manager_requeue_item(producer, &items[i]) != 0) {
                            ve_tls_metric_inc_u64(&producer->m_logs_dropped_total, 1);
                            ve_tls_metric_inc_u64(&producer->m_bytes_dropped_total, items[i].size);
                            ve_tls_metrics_emit(producer, "log_dropped", 1, (int64_t)items[i].size);
                            ve_tls_manager_drop_item(producer, items[i].size, items[i].id, "MemoryAllocFailed", "group alloc failed");
                        }
                        ve_tls_item_free(&items[i]);
                        continue;
                    }
                    if (g->count > 0) {
                        memcpy(logs, g->logs, g->count * sizeof(ve_tls_bytes));
                        memcpy(times, g->times, g->count * sizeof(int64_t));
                        memcpy(ids, g->ids, g->count * sizeof(int64_t));
                    }
                    ve_tls_free(g->logs);
                    ve_tls_free(g->times);
                    ve_tls_free(g->ids);
                    g->logs = logs;
                    g->times = times;
                    g->ids = ids;
                    g->cap = next;
                }
                g->logs[g->count].data = items[i].data;
                g->logs[g->count].size = items[i].size;
                g->times[g->count] = items[i].time_ms;
                g->ids[g->count] = items[i].id;
                g->count++;
                g->bytes += items[i].size;
                if (items[i].time_ms > 0) {
                    if (g->earliest == 0 || items[i].time_ms < g->earliest) {
                        g->earliest = items[i].time_ms;
                    }
                    if (items[i].time_ms > g->latest) {
                        g->latest = items[i].time_ms;
                    }
                }
                if (items[i].id < g->start_id) {
                    g->start_id = items[i].id;
                }
                if (items[i].id > g->end_id) {
                    g->end_id = items[i].id;
                }
            }

            for (size_t gi = 0; gi < groups_len; gi++) {
                ve_tls_group * g = &groups[gi];
                if (!g->logs || g->count == 0) {
                    ve_tls_free(g->logs);
                    ve_tls_free(g->times);
                    ve_tls_free(g->ids);
                    ve_tls_free(g->key);
                    continue;
                }
                size_t max_group_logs = producer->config.agg_max_log_group_logs > 0 ? (size_t)producer->config.agg_max_log_group_logs : 10000;
                if (max_group_logs > 10000) {
                    max_group_logs = 10000;
                }
                size_t max_comp = (producer->config.agg_strategy == 1 && producer->config.agg_max_compressed_bytes_per_request > 0) ? (size_t)producer->config.agg_max_compressed_bytes_per_request : 0;

                typedef struct {
                    size_t start;
                    size_t count;
                } ve_tls_range;
                ve_tls_range * stack = (ve_tls_range *)ve_tls_calloc(1, sizeof(ve_tls_range));
                size_t stack_len = 0;
                size_t stack_cap = stack ? 1 : 0;
                if (stack) {
                    stack[stack_len++] = (ve_tls_range){0, g->count};
                }

                while (stack && stack_len > 0) {
                    ve_tls_range r = stack[--stack_len];
                    if (r.count == 0) {
                        continue;
                    }
                    ve_tls_bytes body;
                    if (ve_tls_proto_encode_log_group_list_ex2(g->logs + r.start, r.count, producer->config.source, producer->config.file_name, producer->config.log_tags, producer->config.log_tag_count, producer->config.context_flow, max_group_logs, &body) != 0 || !body.data || body.size == 0) {
                        ve_tls_bytes_free(&body);
                        continue;
                    }

                    size_t send_size = body.size;
                    ve_tls_bytes c = {0};
                    int c_rc = -2;
                    if (max_comp > 0) {
                        c_rc = ve_tls_compress_apply(producer->config.compress_type, body.data, body.size, &c);
                        if (c_rc == 0 && c.data && c.size > 0) {
                            send_size = c.size;
                        } else if (c_rc == -2) {
                            send_size = body.size;
                        } else {
                            ve_tls_error err;
                            memset(&err, 0, sizeof(err));
                            err.http_code = -1;
                            err.transport_kind = VE_TLS_TRANSPORT_GENERIC;
                            err.transport_code = 0;
                            err.retryable = 0;
                            err.error_code = ve_tls_strdup("ClientError");
                            err.error_message = ve_tls_strdup(c_rc == -1 ? "compress failed" : "unsupported compress_type");
                            ve_tls_send_callbacks cbs = ve_tls_capture_callbacks(producer);
                            if (cbs.cb) {
                                cbs.cb(VE_TLS_DROP_ERROR, g->bytes, 0, NULL, err.error_message, NULL, cbs.cb_param, g->start_id, g->end_id);
                            }
                            if (cbs.cb2) {
                                cbs.cb2(VE_TLS_DROP_ERROR, g->bytes, 0, &err, NULL, cbs.cb2_param, g->start_id, g->end_id);
                            }
                            ve_tls_error_free_fields(&err);
                            ve_tls_bytes_free(&c);
                            ve_tls_bytes_free(&body);
                            stack_len = 0;
                            break;
                        }
                    }

                    if (max_comp > 0 && send_size > max_comp) {
                        ve_tls_bytes_free(&c);
                        ve_tls_bytes_free(&body);
                        if (r.count <= 1) {
                            ve_tls_error err;
                            memset(&err, 0, sizeof(err));
                            err.http_code = -1;
                            err.transport_kind = VE_TLS_TRANSPORT_GENERIC;
                            err.transport_code = 0;
                            err.retryable = 0;
                            err.error_code = ve_tls_strdup("PayloadTooLarge");
                            err.error_message = ve_tls_strdup("payload too large after compression");
                            ve_tls_send_callbacks cbs = ve_tls_capture_callbacks(producer);
                            if (cbs.cb) {
                                cbs.cb(VE_TLS_DROP_ERROR, g->logs[r.start].size, 0, NULL, err.error_message, NULL, cbs.cb_param, g->ids[r.start], g->ids[r.start]);
                            }
                            if (cbs.cb2) {
                                cbs.cb2(VE_TLS_DROP_ERROR, g->logs[r.start].size, 0, &err, NULL, cbs.cb2_param, g->ids[r.start], g->ids[r.start]);
                            }
                            ve_tls_error_free_fields(&err);
                            continue;
                        }
                        size_t left = r.count / 2;
                        size_t right = r.count - left;
                        if (stack_len + 2 > stack_cap) {
                            size_t next = stack_cap ? stack_cap * 2 : 8;
                            if (next < stack_len + 2) {
                                next = stack_len + 2;
                            }
                            if (next > (size_t)-1 / sizeof(ve_tls_range)) {
                                stack_len = 0;
                                break;
                            }
                            ve_tls_range * ns = (ve_tls_range *)ve_tls_realloc(stack, next * sizeof(ve_tls_range));
                            if (!ns) {
                                stack_len = 0;
                                break;
                            }
                            stack = ns;
                            stack_cap = next;
                        }
                        stack[stack_len++] = (ve_tls_range){r.start + left, right};
                        stack[stack_len++] = (ve_tls_range){r.start, left};
                        continue;
                    }

                    ve_tls_send_task t;
                    memset(&t, 0, sizeof(t));
                    t.body = body.data;
                    t.body_size = body.size;
                    t.raw_body_size = body.size;
                    t.log_count = (int32_t)r.count;
                    t.hash_key = g->key ? ve_tls_strdup(g->key) : NULL;
                    t.partition_id = 0;
                    int64_t s_id = g->ids[r.start];
                    int64_t e_id = g->ids[r.start];
                    int64_t earl = g->times[r.start];
                    int64_t late = g->times[r.start];
                    size_t bsum = 0;
                    for (size_t k = 0; k < r.count; k++) {
                        int64_t id = g->ids[r.start + k];
                        if (id < s_id) s_id = id;
                        if (id > e_id) e_id = id;
                        int64_t tm = g->times[r.start + k];
                        if (tm > 0) {
                            if (earl == 0 || tm < earl) earl = tm;
                            if (tm > late) late = tm;
                        }
                        bsum += g->logs[r.start + k].size;
                    }
                    t.start_id = s_id;
                    t.end_id = e_id;
                    t.earliest = earl;
                    t.latest = late;
                    t.batch_bytes = bsum;
                    if (c_rc == 0 && c.data && c.size > 0) {
                        t.precompressed = c.data;
                        t.precompressed_size = c.size;
                        c.data = NULL;
                        c.size = 0;
                    }
                    body.data = NULL;
                    body.size = 0;
                    ve_tls_metric_inc_u64(&producer->m_batches_built_total, 1);
                    producer->config.platform.mutex_lock(producer->mutex);
                    const char * nk = ve_tls_normalize_hash_key(producer, t.hash_key);
                    int reserve_ok = (ve_tls_key_queue_reserve(producer, nk) == 0);
                    producer->config.platform.mutex_unlock(producer->mutex);
                    if (!reserve_ok) {
                        ve_tls_metrics_emit(producer, "key_queue_drop", 1, 0);
                        ve_tls_error err;
                        memset(&err, 0, sizeof(err));
                        err.http_code = -1;
                        err.transport_kind = VE_TLS_TRANSPORT_GENERIC;
                        err.transport_code = 0;
                        err.retryable = 0;
                        err.error_code = ve_tls_strdup("KeyQueueLimitExceeded");
                        err.error_message = ve_tls_strdup("key queue limit exceeded");
                        ve_tls_send_callbacks cbs = ve_tls_capture_callbacks(producer);
                        if (cbs.cb) {
                            cbs.cb(VE_TLS_DROP_ERROR, t.batch_bytes, 0, NULL, err.error_message, NULL, cbs.cb_param, t.start_id, t.end_id);
                        }
                        if (cbs.cb2) {
                            cbs.cb2(VE_TLS_DROP_ERROR, t.batch_bytes, 0, &err, NULL, cbs.cb2_param, t.start_id, t.end_id);
                        }
                        ve_tls_error_free_fields(&err);
                        ve_tls_send_task_free(&t);
                        ve_tls_bytes_free(&c);
                        ve_tls_bytes_free(&body);
                        continue;
                    }
                    int wait_ms = 0;
                    if (producer->config.send_queue_full_policy == VE_TLS_SEND_QUEUE_FULL_BLOCK) {
                        wait_ms = producer->config.send_queue_block_timeout_ms;
                        if (wait_ms == 0) {
                            wait_ms = -1;
                        }
                    } else if (producer->config.send_queue_full_policy == VE_TLS_SEND_QUEUE_FULL_DROP_SAMPLED) {
                        int32_t n = producer->config.send_queue_sample_every_n;
                        if (n < 1) {
                            n = 1;
                        }
                        if (n == 1 || (t.end_id % n) == 0) {
                            wait_ms = producer->config.send_queue_block_timeout_ms;
                            if (wait_ms == 0) {
                                wait_ms = -1;
                            }
                        } else {
                            wait_ms = 0;
                        }
                    }
                    int push_rc = ve_tls_send_queue_push(&producer->send_queue, &t, wait_ms);
                    if (push_rc != 0) {
                        if (push_rc == -2) {
                            ve_tls_metrics_emit(producer, "send_queue_timeout_drop", 1, 0);
                        } else {
                            int stopped = 0;
                            if (producer->send_queue.platform && producer->send_queue.mutex) {
                                producer->send_queue.platform->mutex_lock(producer->send_queue.mutex);
                                stopped = producer->send_queue.stop ? 1 : 0;
                                producer->send_queue.platform->mutex_unlock(producer->send_queue.mutex);
                            }
                            if (stopped) {
                                ve_tls_metrics_emit(producer, "send_queue_stop_drop", 1, 0);
                            } else {
                                ve_tls_metrics_emit(producer, "send_queue_drop", 1, 0);
                            }
                        }
                        ve_tls_error err;
                        memset(&err, 0, sizeof(err));
                        err.http_code = -1;
                        err.transport_kind = VE_TLS_TRANSPORT_GENERIC;
                        err.transport_code = 0;
                        err.retryable = 0;
                        if (push_rc == -2) {
                            err.error_code = ve_tls_strdup("SendQueueTimeout");
                            err.error_message = ve_tls_strdup("send queue push timeout");
                        } else {
                            int stopped = 0;
                            if (producer->send_queue.platform && producer->send_queue.mutex) {
                                producer->send_queue.platform->mutex_lock(producer->send_queue.mutex);
                                stopped = producer->send_queue.stop ? 1 : 0;
                                producer->send_queue.platform->mutex_unlock(producer->send_queue.mutex);
                            }
                            if (stopped) {
                                err.error_code = ve_tls_strdup("SendQueueStopped");
                                err.error_message = ve_tls_strdup("send queue stopped");
                            } else {
                                err.error_code = ve_tls_strdup("SendQueueFull");
                                err.error_message = ve_tls_strdup("send queue full");
                            }
                        }
                        ve_tls_send_callbacks cbs = ve_tls_capture_callbacks(producer);
                        if (cbs.cb) {
                            cbs.cb(VE_TLS_DROP_ERROR, t.batch_bytes, 0, NULL, err.error_message, NULL, cbs.cb_param, t.start_id, t.end_id);
                        }
                        if (cbs.cb2) {
                            cbs.cb2(VE_TLS_DROP_ERROR, t.batch_bytes, 0, &err, NULL, cbs.cb2_param, t.start_id, t.end_id);
                        }
                        ve_tls_error_free_fields(&err);
                        ve_tls_send_task_free(&t);
                    } else {
                        producer->config.platform.mutex_lock(producer->mutex);
                        producer->config.platform.cond_signal(producer->send_cond);
                        producer->config.platform.mutex_unlock(producer->mutex);
                        if (producer->use_global_env) {
                            ve_tls_env_notify(producer);
                        }
                    }
                    ve_tls_bytes_free(&c);
                    ve_tls_bytes_free(&body);
                }

                ve_tls_free(stack);
                ve_tls_free(g->logs);
                ve_tls_free(g->times);
                ve_tls_free(g->ids);
                ve_tls_free(g->key);
            }
            ve_tls_free(groups);

            for (size_t i = 0; i < items_len; i++) {
                ve_tls_item_free(&items[i]);
            }
        }
        ve_tls_free(items);
        producer->config.platform.mutex_lock(producer->mutex);
        if (producer->stop) {
            if (producer->queue_count > 0) {
                producer->flush_requested = 1;
            }
        } else {
            if (producer->config.log_count_per_package > 0 && producer->queue_count >= (size_t)producer->config.log_count_per_package) {
                producer->flush_requested = 1;
            } else if (byte_limit > 0 && producer->queue_bytes >= byte_limit) {
                producer->flush_requested = 1;
            }
        }
        producer->worker_flushing = 0;
        producer->config.platform.cond_broadcast(producer->send_cond);
        producer->config.platform.mutex_unlock(producer->mutex);
        last_flush = producer->config.platform.time_ms ? producer->config.platform.time_ms() : last_flush;
    }
    return NULL;
}
