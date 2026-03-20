#include "ve_tls_producer_internal.h"
#include "ve_tls_alloc.h"

#include <stdlib.h>
#include <string.h>

void ve_tls_queue_free_all(ve_tls_producer * producer) {
    if (!producer || !producer->queue) {
        return;
    }
    for (size_t i = 0; i < producer->queue_cap; i++) {
        ve_tls_free(producer->queue[i].hash_key);
        ve_tls_free(producer->queue[i].data);
        producer->queue[i].hash_key = NULL;
        producer->queue[i].data = NULL;
        producer->queue[i].size = 0;
        producer->queue[i].id = 0;
    }
    ve_tls_free(producer->queue);
    producer->queue = NULL;
    producer->queue_cap = 0;
    producer->queue_head = 0;
    producer->queue_tail = 0;
    producer->queue_count = 0;
    producer->queue_bytes = 0;
}

static int ve_tls_queue_ensure(ve_tls_producer * producer) {
    if (producer->queue_cap == 0) {
        producer->queue_cap = 1024;
        producer->queue = (ve_tls_log_item *)ve_tls_calloc(producer->queue_cap, sizeof(ve_tls_log_item));
        return producer->queue ? 0 : -1;
    }
    if (producer->queue_count < producer->queue_cap) {
        return 0;
    }
    size_t next_cap = producer->queue_cap * 2;
    ve_tls_log_item * next = (ve_tls_log_item *)ve_tls_calloc(next_cap, sizeof(ve_tls_log_item));
    if (!next) {
        return -1;
    }
    for (size_t i = 0; i < producer->queue_count; i++) {
        size_t idx = (producer->queue_head + i) % producer->queue_cap;
        next[i] = producer->queue[idx];
        producer->queue[idx].hash_key = NULL;
        producer->queue[idx].data = NULL;
        producer->queue[idx].size = 0;
    }
    ve_tls_free(producer->queue);
    producer->queue = next;
    producer->queue_cap = next_cap;
    producer->queue_head = 0;
    producer->queue_tail = producer->queue_count;
    return 0;
}

int ve_tls_queue_push_owned(ve_tls_producer * producer, unsigned char * data, size_t size, int64_t id, int64_t time_ms, uint32_t time_ns, int32_t has_time_ns, char * hash_key) {
    if (!producer || !data || size == 0) {
        return -1;
    }
    if (ve_tls_queue_ensure(producer) != 0) {
        return -1;
    }
    ve_tls_log_item item;
    item.id = id;
    item.time_ms = time_ms;
    item.time_ns = time_ns;
    item.has_time_ns = has_time_ns;
    item.hash_key = hash_key;
    item.data = data;
    item.size = size;
    producer->queue[producer->queue_tail] = item;
    producer->queue_tail = (producer->queue_tail + 1) % producer->queue_cap;
    producer->queue_count++;
    producer->queue_bytes += size;
    return 0;
}

int ve_tls_queue_push(ve_tls_producer * producer, const unsigned char * data, size_t size, int64_t id, int64_t time_ms, uint32_t time_ns, int32_t has_time_ns, const char * hash_key) {
    unsigned char * copy = (unsigned char *)ve_tls_malloc(size);
    if (!copy) {
        return -1;
    }
    memcpy(copy, data, size);
    char * hk = NULL;
    if (hash_key && hash_key[0] != 0) {
        hk = ve_tls_strdup(hash_key);
        if (!hk) {
            ve_tls_free(copy);
            return -1;
        }
    }
    if (ve_tls_queue_push_owned(producer, copy, size, id, time_ms, time_ns, has_time_ns, hk) != 0) {
        ve_tls_free(copy);
        ve_tls_free(hk);
        return -1;
    }
    return 0;
}

int ve_tls_queue_pop(ve_tls_producer * producer, ve_tls_log_item * out) {
    if (producer->queue_count == 0) {
        return -1;
    }
    *out = producer->queue[producer->queue_head];
    producer->queue[producer->queue_head].hash_key = NULL;
    producer->queue[producer->queue_head].data = NULL;
    producer->queue[producer->queue_head].size = 0;
    producer->queue[producer->queue_head].id = 0;
    producer->queue_head = (producer->queue_head + 1) % producer->queue_cap;
    producer->queue_count--;
    producer->queue_bytes -= out->size;
    return 0;
}

void ve_tls_item_free(ve_tls_log_item * item) {
    if (!item) {
        return;
    }
    ve_tls_free(item->hash_key);
    ve_tls_free(item->data);
    item->hash_key = NULL;
    item->data = NULL;
    item->size = 0;
    item->id = 0;
    item->time_ms = 0;
    item->time_ns = 0;
    item->has_time_ns = 0;
}

void ve_tls_send_task_free(ve_tls_send_task * t) {
    if (!t) {
        return;
    }
    ve_tls_free(t->hash_key);
    ve_tls_free(t->precompressed);
    ve_tls_free(t->body);
    memset(t, 0, sizeof(*t));
}

int ve_tls_send_queue_init(ve_tls_send_queue * q, ve_tls_platform * platform, size_t cap) {
    if (!q || !platform || cap == 0) {
        return -1;
    }
    memset(q, 0, sizeof(*q));
    q->platform = platform;
    q->cap = cap;
    q->buf = (ve_tls_send_task *)ve_tls_calloc(q->cap, sizeof(ve_tls_send_task));
    q->mutex = platform->mutex_create();
    q->not_empty = platform->cond_create();
    q->not_full = platform->cond_create();
    if (!q->buf || !q->mutex || !q->not_empty || !q->not_full) {
        ve_tls_send_queue_destroy(q);
        return -1;
    }
    return 0;
}

void ve_tls_send_queue_stop(ve_tls_send_queue * q) {
    if (!q || !q->platform || !q->mutex) {
        return;
    }
    q->platform->mutex_lock(q->mutex);
    q->stop = 1;
    q->platform->cond_broadcast(q->not_empty);
    q->platform->cond_broadcast(q->not_full);
    q->platform->mutex_unlock(q->mutex);
}

int ve_tls_send_queue_push(ve_tls_send_queue * q, const ve_tls_send_task * t, int wait_ms) {
    if (!q || !q->platform || !q->mutex || !q->not_full || !q->not_empty || !t) {
        return -1;
    }
    int64_t start = q->platform->time_ms ? q->platform->time_ms() : 0;
    q->platform->mutex_lock(q->mutex);
    while (!q->stop && q->count >= q->cap) {
        if (wait_ms == 0) {
            q->platform->mutex_unlock(q->mutex);
            return -1;
        }
        if (wait_ms < 0) {
            q->platform->cond_wait(q->not_full, q->mutex);
            continue;
        }
        int64_t now = q->platform->time_ms ? q->platform->time_ms() : start;
        int64_t elapsed = now - start;
        int64_t remain = (int64_t)wait_ms - elapsed;
        if (remain <= 0) {
            q->platform->mutex_unlock(q->mutex);
            return -2;
        }
        (void)q->platform->cond_timedwait_ms(q->not_full, q->mutex, remain);
    }
    if (q->stop) {
        q->platform->mutex_unlock(q->mutex);
        return -1;
    }
    q->buf[q->tail] = *t;
    q->tail = (q->tail + 1) % q->cap;
    q->count++;
    q->platform->cond_signal(q->not_empty);
    q->platform->mutex_unlock(q->mutex);
    return 0;
}

int ve_tls_send_queue_pop(ve_tls_send_queue * q, ve_tls_send_task * out, int wait_ms) {
    if (!q || !q->platform || !q->mutex || !q->not_full || !q->not_empty || !out) {
        return -1;
    }
    int64_t start = q->platform->time_ms ? q->platform->time_ms() : 0;
    q->platform->mutex_lock(q->mutex);
    while (!q->stop && q->count == 0) {
        if (wait_ms == 0) {
            q->platform->mutex_unlock(q->mutex);
            return -1;
        }
        if (wait_ms < 0) {
            q->platform->cond_wait(q->not_empty, q->mutex);
            continue;
        }
        int64_t now = q->platform->time_ms ? q->platform->time_ms() : start;
        int64_t elapsed = now - start;
        int64_t remain = (int64_t)wait_ms - elapsed;
        if (remain <= 0) {
            q->platform->mutex_unlock(q->mutex);
            return -2;
        }
        (void)q->platform->cond_timedwait_ms(q->not_empty, q->mutex, remain);
    }
    if (q->count == 0) {
        q->platform->mutex_unlock(q->mutex);
        return -1;
    }
    *out = q->buf[q->head];
    memset(&q->buf[q->head], 0, sizeof(ve_tls_send_task));
    q->head = (q->head + 1) % q->cap;
    q->count--;
    q->platform->cond_signal(q->not_full);
    q->platform->mutex_unlock(q->mutex);
    return 0;
}

void ve_tls_send_queue_destroy(ve_tls_send_queue * q) {
    if (!q) {
        return;
    }
    if (q->buf) {
        for (size_t i = 0; i < q->cap; i++) {
            ve_tls_send_task_free(&q->buf[i]);
        }
        ve_tls_free(q->buf);
        q->buf = NULL;
    }
    if (q->platform) {
        if (q->not_empty) {
            q->platform->cond_destroy(q->not_empty);
            q->not_empty = NULL;
        }
        if (q->not_full) {
            q->platform->cond_destroy(q->not_full);
            q->not_full = NULL;
        }
        if (q->mutex) {
            q->platform->mutex_destroy(q->mutex);
            q->mutex = NULL;
        }
    }
    q->platform = NULL;
    q->cap = 0;
    q->head = 0;
    q->tail = 0;
    q->count = 0;
    q->stop = 0;
}

static uint32_t ve_tls_hash32_fnv1a(const char * s) {
    uint32_t h = 2166136261u;
    if (!s) {
        return h;
    }
    while (*s) {
        h ^= (uint8_t)*s;
        h *= 16777619u;
        s++;
    }
    return h;
}

const char * ve_tls_normalize_hash_key(ve_tls_producer * producer, const char * hash_key) {
    const char * k = hash_key;
    if (!k || k[0] == 0) {
        k = producer ? producer->config.hash_key : NULL;
    }
    return (k && k[0] != 0) ? k : "";
}

static int ve_tls_key_queue_ensure(ve_tls_key_queue * q) {
    if (q->cap == 0) {
        q->cap = 64;
        q->q = (ve_tls_send_task *)ve_tls_calloc(q->cap, sizeof(ve_tls_send_task));
        return q->q ? 0 : -1;
    }
    if (q->count < q->cap) {
        return 0;
    }
    size_t next_cap = q->cap * 2;
    ve_tls_send_task * next = (ve_tls_send_task *)ve_tls_calloc(next_cap, sizeof(ve_tls_send_task));
    if (!next) {
        return -1;
    }
    for (size_t i = 0; i < q->count; i++) {
        size_t idx = (q->head + i) % q->cap;
        next[i] = q->q[idx];
        q->q[idx].hash_key = NULL;
        q->q[idx].precompressed = NULL;
        q->q[idx].body = NULL;
        q->q[idx].body_size = 0;
    }
    ve_tls_free(q->q);
    q->q = next;
    q->cap = next_cap;
    q->head = 0;
    q->tail = q->count;
    return 0;
}

static void ve_tls_key_queue_remove_and_free(ve_tls_producer * producer, ve_tls_key_queue * q);

static void ve_tls_ready_add(ve_tls_producer * producer, ve_tls_key_queue * q) {
    if (!producer || !q || q->ready || q->delayed || q->inflight || q->count == 0) {
        return;
    }
    q->ready = 1;
    q->rprev = producer->ready_tail;
    q->rnext = NULL;
    if (producer->ready_tail) {
        producer->ready_tail->rnext = q;
    } else {
        producer->ready_head = q;
    }
    producer->ready_tail = q;
}

static void ve_tls_ready_remove(ve_tls_producer * producer, ve_tls_key_queue * q) {
    if (!producer || !q || !q->ready) {
        return;
    }
    if (q->rprev) {
        q->rprev->rnext = q->rnext;
    } else {
        producer->ready_head = q->rnext;
    }
    if (q->rnext) {
        q->rnext->rprev = q->rprev;
    } else {
        producer->ready_tail = q->rprev;
    }
    q->rprev = NULL;
    q->rnext = NULL;
    q->ready = 0;
}

static void ve_tls_idle_remove(ve_tls_producer * producer, ve_tls_key_queue * q) {
    if (!producer || !q || !q->idle) {
        return;
    }
    if (q->iprev) {
        q->iprev->inext = q->inext;
    } else {
        producer->idle_head = q->inext;
    }
    if (q->inext) {
        q->inext->iprev = q->iprev;
    } else {
        producer->idle_tail = q->iprev;
    }
    q->iprev = NULL;
    q->inext = NULL;
    q->idle = 0;
    q->empty_since_ms = 0;
}

static void ve_tls_delayed_remove(ve_tls_producer * producer, ve_tls_key_queue * q) {
    if (!producer || !q || !q->delayed) {
        return;
    }
    if (q->dprev) {
        q->dprev->dnext = q->dnext;
    } else {
        producer->delayed_head = q->dnext;
    }
    if (q->dnext) {
        q->dnext->dprev = q->dprev;
    } else {
        producer->delayed_tail = q->dprev;
    }
    q->dprev = NULL;
    q->dnext = NULL;
    q->delayed = 0;
    q->next_ready_ms = 0;
}

void ve_tls_delayed_add_sorted(ve_tls_producer * producer, ve_tls_key_queue * q, int64_t next_ready_ms) {
    if (!producer || !q) {
        return;
    }
    ve_tls_ready_remove(producer, q);
    ve_tls_idle_remove(producer, q);
    ve_tls_delayed_remove(producer, q);
    q->delayed = 1;
    q->next_ready_ms = next_ready_ms;
    ve_tls_key_queue * cur = producer->delayed_head;
    if (!cur) {
        producer->delayed_head = q;
        producer->delayed_tail = q;
        q->dprev = NULL;
        q->dnext = NULL;
        return;
    }
    while (cur && cur->next_ready_ms <= next_ready_ms) {
        cur = cur->dnext;
    }
    if (!cur) {
        q->dprev = producer->delayed_tail;
        q->dnext = NULL;
        producer->delayed_tail->dnext = q;
        producer->delayed_tail = q;
        return;
    }
    q->dnext = cur;
    q->dprev = cur->dprev;
    if (cur->dprev) {
        cur->dprev->dnext = q;
    } else {
        producer->delayed_head = q;
    }
    cur->dprev = q;
}

void ve_tls_delayed_promote_due(ve_tls_producer * producer, int64_t now_ms) {
    if (!producer) {
        return;
    }
    ve_tls_key_queue * q = producer->delayed_head;
    while (q) {
        if (q->next_ready_ms > now_ms) {
            break;
        }
        ve_tls_key_queue * next = q->dnext;
        ve_tls_delayed_remove(producer, q);
        if (!q->inflight && q->count > 0) {
            ve_tls_ready_add(producer, q);
        }
        q = next;
    }
}

static void ve_tls_idle_add(ve_tls_producer * producer, ve_tls_key_queue * q, int64_t now_ms) {
    if (!producer || !q || q->idle || q->count != 0 || q->inflight) {
        return;
    }
    q->idle = 1;
    q->empty_since_ms = now_ms;
    q->iprev = producer->idle_tail;
    q->inext = NULL;
    if (producer->idle_tail) {
        producer->idle_tail->inext = q;
    } else {
        producer->idle_head = q;
    }
    producer->idle_tail = q;
}

void ve_tls_idle_cleanup(ve_tls_producer * producer) {
    if (!producer) {
        return;
    }
    int32_t ttl = producer->config.key_queue_idle_ttl_ms;
    if (ttl <= 0) {
        return;
    }
    int64_t now = producer->config.platform.time_ms ? producer->config.platform.time_ms() : 0;
    ve_tls_key_queue * q = producer->idle_head;
    while (q) {
        ve_tls_key_queue * next = q->inext;
        if (q->idle && q->count == 0 && !q->inflight && now - q->empty_since_ms >= ttl) {
            ve_tls_idle_remove(producer, q);
            ve_tls_key_queue_remove_and_free(producer, q);
        }
        q = next;
    }
}

ve_tls_key_queue * ve_tls_ready_pop(ve_tls_producer * producer) {
    ve_tls_key_queue * q = producer ? producer->ready_head : NULL;
    if (!q) {
        return NULL;
    }
    producer->ready_head = q->rnext;
    if (producer->ready_head) {
        producer->ready_head->rprev = NULL;
    } else {
        producer->ready_tail = NULL;
    }
    q->rprev = NULL;
    q->rnext = NULL;
    q->ready = 0;
    q->inflight = 1;
    return q;
}

static ve_tls_key_queue * ve_tls_key_queue_get_or_create(ve_tls_producer * producer, const char * norm_key) {
    if (!producer || !producer->key_buckets || producer->key_bucket_count == 0) {
        return NULL;
    }
    uint32_t h = ve_tls_hash32_fnv1a(norm_key);
    size_t idx = (size_t)(h % (uint32_t)producer->key_bucket_count);
    for (ve_tls_key_queue * p = producer->key_buckets[idx]; p; p = p->hnext) {
        if (p->hash == h && strcmp(p->key, norm_key) == 0) {
            ve_tls_idle_remove(producer, p);
            return p;
        }
    }
    if (producer->config.key_queue_max_active > 0 && producer->key_queue_count >= (size_t)producer->config.key_queue_max_active) {
        return NULL;
    }
    ve_tls_key_queue * q = (ve_tls_key_queue *)ve_tls_calloc(1, sizeof(ve_tls_key_queue));
    if (!q) {
        return NULL;
    }
    q->key = ve_tls_strdup(norm_key);
    if (!q->key) {
        ve_tls_free(q);
        return NULL;
    }
    q->hash = h;
    q->hnext = producer->key_buckets[idx];
    producer->key_buckets[idx] = q;
    producer->key_queue_count++;
    return q;
}

static void ve_tls_key_queue_remove_and_free(ve_tls_producer * producer, ve_tls_key_queue * q) {
    if (!producer || !q || !producer->key_buckets || producer->key_bucket_count == 0) {
        return;
    }
    ve_tls_ready_remove(producer, q);
    ve_tls_idle_remove(producer, q);
    ve_tls_delayed_remove(producer, q);
    size_t idx = (size_t)(q->hash % (uint32_t)producer->key_bucket_count);
    ve_tls_key_queue * prev = NULL;
    for (ve_tls_key_queue * p = producer->key_buckets[idx]; p; p = p->hnext) {
        if (p == q) {
            if (prev) {
                prev->hnext = p->hnext;
            } else {
                producer->key_buckets[idx] = p->hnext;
            }
            break;
        }
        prev = p;
    }
    if (q->q) {
        for (size_t i = 0; i < q->cap; i++) {
            ve_tls_free(q->q[i].hash_key);
            ve_tls_free(q->q[i].precompressed);
            ve_tls_free(q->q[i].body);
        }
        ve_tls_free(q->q);
    }
    ve_tls_free(q->key);
    ve_tls_free(q);
    if (producer->key_queue_count > 0) {
        producer->key_queue_count--;
    }
}

int ve_tls_key_queue_push_task(ve_tls_producer * producer, const char * norm_key, const ve_tls_send_task * t) {
    ve_tls_key_queue * q = ve_tls_key_queue_get_or_create(producer, norm_key);
    if (!q) {
        return -1;
    }
    if (ve_tls_key_queue_ensure(q) != 0) {
        return -1;
    }
    int was_empty = (q->count == 0);
    q->q[q->tail] = *t;
    q->tail = (q->tail + 1) % q->cap;
    q->count++;
    if (was_empty && !q->inflight) {
        ve_tls_ready_add(producer, q);
    }
    return 0;
}

int ve_tls_key_queue_reserve(ve_tls_producer * producer, const char * norm_key) {
    ve_tls_key_queue * q = ve_tls_key_queue_get_or_create(producer, norm_key);
    return q ? 0 : -1;
}

int ve_tls_key_queue_push_front_task(ve_tls_key_queue * q, const ve_tls_send_task * t) {
    if (!q || !t) {
        return -1;
    }
    if (ve_tls_key_queue_ensure(q) != 0) {
        return -1;
    }
    q->head = (q->head + q->cap - 1) % q->cap;
    q->q[q->head] = *t;
    q->count++;
    return 0;
}

int ve_tls_key_queue_pop_task(ve_tls_key_queue * q, ve_tls_send_task * out) {
    if (!q || q->count == 0) {
        return -1;
    }
    *out = q->q[q->head];
    memset(&q->q[q->head], 0, sizeof(ve_tls_send_task));
    q->head = (q->head + 1) % q->cap;
    q->count--;
    return 0;
}

void ve_tls_key_queue_finish(ve_tls_producer * producer, ve_tls_key_queue * q) {
    if (!producer || !q) {
        return;
    }
    q->inflight = 0;
    if (q->count > 0) {
        int64_t now = producer->config.platform.time_ms ? producer->config.platform.time_ms() : 0;
        if (producer->config.key_breaker_fail_threshold > 0 && q->breaker_open_until_ms > now) {
            ve_tls_delayed_add_sorted(producer, q, q->breaker_open_until_ms);
        } else {
            ve_tls_ready_add(producer, q);
        }
        producer->config.platform.cond_broadcast(producer->send_cond);
        return;
    }
    int32_t ttl = producer->config.key_queue_idle_ttl_ms;
    if (ttl > 0) {
        ve_tls_idle_add(producer, q, producer->config.platform.time_ms ? producer->config.platform.time_ms() : 0);
    } else {
        ve_tls_key_queue_remove_and_free(producer, q);
    }
    producer->config.platform.cond_broadcast(producer->send_cond);
}

void ve_tls_key_map_free_all(ve_tls_producer * producer) {
    if (!producer || !producer->key_buckets || producer->key_bucket_count == 0) {
        return;
    }
    for (size_t i = 0; i < producer->key_bucket_count; i++) {
        ve_tls_key_queue * p = producer->key_buckets[i];
        while (p) {
            ve_tls_key_queue * n = p->hnext;
            if (p->q) {
                for (size_t j = 0; j < p->cap; j++) {
                    ve_tls_free(p->q[j].hash_key);
                    ve_tls_free(p->q[j].precompressed);
                    ve_tls_free(p->q[j].body);
                }
                ve_tls_free(p->q);
            }
            ve_tls_free(p->key);
            ve_tls_free(p);
            p = n;
        }
        producer->key_buckets[i] = NULL;
    }
    ve_tls_free(producer->key_buckets);
    producer->key_buckets = NULL;
    producer->key_bucket_count = 0;
    producer->key_queue_count = 0;
    producer->ready_head = NULL;
    producer->ready_tail = NULL;
    producer->idle_head = NULL;
    producer->idle_tail = NULL;
    producer->delayed_head = NULL;
    producer->delayed_tail = NULL;
}
