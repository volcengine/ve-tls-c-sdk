#include "ve_tls_env.h"
#include "ve_tls_producer_internal.h"
#include "ve_tls_alloc.h"

#include <stdlib.h>
#include <string.h>

#if defined(VE_TLS_ENABLE_PTHREAD)
#include <pthread.h>
/* g_env_init_mu 保护全局 env 的生命周期；队列热路径仍由 g_env.mutex 保护。 */
static pthread_mutex_t g_env_init_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_env_lifecycle_cv = PTHREAD_COND_INITIALIZER;
#else
#include <stdatomic.h>
#endif

typedef struct {
    int inited;
    int stop;
    int destroying;
    int tearing_down;
    int active_ops;
    ve_tls_platform platform;
    ve_tls_mutex * mutex;
    ve_tls_cond * cond;
    ve_tls_thread ** senders;
    int32_t sender_count;
    ve_tls_producer * producers;
    ve_tls_producer ** q;
    size_t q_cap;
    size_t q_head;
    size_t q_tail;
    size_t q_count;
} ve_tls_env_state;

static ve_tls_env_state g_env;

static int ve_tls_env_has_resources(void) {
    return g_env.mutex || g_env.cond || g_env.q || g_env.senders;
}

static int ve_tls_env_resources_ready(void) {
    return g_env.inited && g_env.mutex && g_env.cond && g_env.q;
}

#if defined(VE_TLS_ENABLE_PTHREAD)
static int ve_tls_env_mark_destroying_locked(void) {
    if (!g_env.inited && !ve_tls_env_has_resources()) {
        return 0;
    }
    g_env.destroying = 1;
    while (g_env.active_ops > 0) {
        pthread_cond_wait(&g_env_lifecycle_cv, &g_env_init_mu);
    }
    g_env.tearing_down = 1;
    return 1;
}

static int ve_tls_env_prepare_destroy(void) {
    int ok;
    pthread_mutex_lock(&g_env_init_mu);
    while (g_env.destroying || g_env.tearing_down) {
        pthread_cond_wait(&g_env_lifecycle_cv, &g_env_init_mu);
    }
    ok = ve_tls_env_mark_destroying_locked();
    pthread_mutex_unlock(&g_env_init_mu);
    return ok;
}

static int ve_tls_env_lifecycle_begin(int allow_destroying) {
    int ok = 0;
    pthread_mutex_lock(&g_env_init_mu);
    if (ve_tls_env_resources_ready() && !g_env.tearing_down && (allow_destroying || !g_env.destroying)) {
        g_env.active_ops++;
        ok = 1;
    }
    pthread_mutex_unlock(&g_env_init_mu);
    return ok;
}

static int ve_tls_env_lifecycle_begin_unregister(void) {
    int ok = 0;
    pthread_mutex_lock(&g_env_init_mu);
    while (g_env.tearing_down) {
        pthread_cond_wait(&g_env_lifecycle_cv, &g_env_init_mu);
    }
    if (ve_tls_env_resources_ready()) {
        g_env.active_ops++;
        ok = 1;
    }
    pthread_mutex_unlock(&g_env_init_mu);
    return ok;
}

static void ve_tls_env_lifecycle_end(void) {
    pthread_mutex_lock(&g_env_init_mu);
    if (g_env.active_ops > 0) {
        g_env.active_ops--;
    }
    if (g_env.active_ops == 0) {
        pthread_cond_broadcast(&g_env_lifecycle_cv);
    }
    pthread_mutex_unlock(&g_env_init_mu);
}

static void ve_tls_env_destroy_abort_lifecycle(void) {
    pthread_mutex_lock(&g_env_init_mu);
    g_env.destroying = 0;
    g_env.tearing_down = 0;
    pthread_cond_broadcast(&g_env_lifecycle_cv);
    pthread_mutex_unlock(&g_env_init_mu);
}

static void ve_tls_env_mark_unavailable(void) {
    pthread_mutex_lock(&g_env_init_mu);
    g_env.inited = 0;
    pthread_mutex_unlock(&g_env_init_mu);
}

static void ve_tls_env_destroy_finish_lifecycle(void) {
    pthread_mutex_lock(&g_env_init_mu);
    g_env.destroying = 0;
    g_env.tearing_down = 0;
    g_env.active_ops = 0;
    pthread_cond_broadcast(&g_env_lifecycle_cv);
    pthread_mutex_unlock(&g_env_init_mu);
}
#else
static atomic_flag g_env_lifecycle_spin = ATOMIC_FLAG_INIT;

static void ve_tls_env_lifecycle_lock(void) {
    while (atomic_flag_test_and_set_explicit(&g_env_lifecycle_spin, memory_order_acquire)) {
    }
}

static void ve_tls_env_lifecycle_unlock(void) {
    atomic_flag_clear_explicit(&g_env_lifecycle_spin, memory_order_release);
}

static void ve_tls_env_lifecycle_pause(void) {
    for (volatile int i = 0; i < 1000; i++) {
    }
}

static int ve_tls_env_mark_destroying_locked(void) {
    if (!g_env.inited && !ve_tls_env_has_resources()) {
        return 0;
    }
    g_env.destroying = 1;
    while (g_env.active_ops > 0) {
        ve_tls_env_lifecycle_unlock();
        ve_tls_env_lifecycle_pause();
        ve_tls_env_lifecycle_lock();
    }
    g_env.tearing_down = 1;
    return 1;
}

static int ve_tls_env_prepare_destroy(void) {
    int ok;
    ve_tls_env_lifecycle_lock();
    while (g_env.destroying || g_env.tearing_down) {
        ve_tls_env_lifecycle_unlock();
        ve_tls_env_lifecycle_pause();
        ve_tls_env_lifecycle_lock();
    }
    ok = ve_tls_env_mark_destroying_locked();
    ve_tls_env_lifecycle_unlock();
    return ok;
}

static int ve_tls_env_lifecycle_begin(int allow_destroying) {
    int ok = 0;
    ve_tls_env_lifecycle_lock();
    if (ve_tls_env_resources_ready() && !g_env.tearing_down && (allow_destroying || !g_env.destroying)) {
        g_env.active_ops++;
        ok = 1;
    }
    ve_tls_env_lifecycle_unlock();
    return ok;
}

static int ve_tls_env_lifecycle_begin_unregister(void) {
    int ok = 0;
    ve_tls_env_lifecycle_lock();
    while (g_env.tearing_down) {
        ve_tls_env_lifecycle_unlock();
        ve_tls_env_lifecycle_pause();
        ve_tls_env_lifecycle_lock();
    }
    if (ve_tls_env_resources_ready()) {
        g_env.active_ops++;
        ok = 1;
    }
    ve_tls_env_lifecycle_unlock();
    return ok;
}

static void ve_tls_env_lifecycle_end(void) {
    ve_tls_env_lifecycle_lock();
    if (g_env.active_ops > 0) {
        g_env.active_ops--;
    }
    ve_tls_env_lifecycle_unlock();
}

static void ve_tls_env_destroy_abort_lifecycle(void) {
    ve_tls_env_lifecycle_lock();
    g_env.destroying = 0;
    g_env.tearing_down = 0;
    ve_tls_env_lifecycle_unlock();
}

static void ve_tls_env_mark_unavailable(void) {
    ve_tls_env_lifecycle_lock();
    g_env.inited = 0;
    ve_tls_env_lifecycle_unlock();
}

static void ve_tls_env_destroy_finish_lifecycle(void) {
    ve_tls_env_lifecycle_lock();
    g_env.destroying = 0;
    g_env.tearing_down = 0;
    g_env.active_ops = 0;
    ve_tls_env_lifecycle_unlock();
}
#endif

static void ve_tls_env_queue_push_locked(ve_tls_producer * producer) {
    if (!producer ||
        __atomic_load_n(&producer->env_registered, __ATOMIC_ACQUIRE) == 0 ||
        g_env.q_count >= g_env.q_cap) {
        return;
    }
    g_env.q[g_env.q_tail] = producer;
    g_env.q_tail = (g_env.q_tail + 1) % g_env.q_cap;
    g_env.q_count++;
    g_env.platform.cond_signal(g_env.cond);
}

static ve_tls_producer * ve_tls_env_queue_pop_locked(void) {
    if (g_env.q_count == 0) {
        return NULL;
    }
    ve_tls_producer * p = g_env.q[g_env.q_head];
    g_env.q[g_env.q_head] = NULL;
    g_env.q_head = (g_env.q_head + 1) % g_env.q_cap;
    g_env.q_count--;
    return p;
}

static int ve_tls_producer_has_pending(ve_tls_producer * producer, int64_t now_ms) {
    if (!producer) {
        return 0;
    }
    int pending = 0;
    producer->config.platform.mutex_lock(producer->mutex);
    if (!producer->stop) {
        if (producer->ready_head) {
            pending = 1;
        } else if (producer->delayed_head && producer->delayed_head->next_ready_ms <= now_ms) {
            pending = 1;
        }
    }
    producer->config.platform.mutex_unlock(producer->mutex);
    if (pending) {
        return 1;
    }
    if (producer->send_queue.mutex) {
        producer->send_queue.platform->mutex_lock(producer->send_queue.mutex);
        size_t c = producer->send_queue.count;
        producer->send_queue.platform->mutex_unlock(producer->send_queue.mutex);
        if (c > 0) {
            return 1;
        }
    }
    return 0;
}

static void ve_tls_env_tick_locked(void) {
    int64_t now = g_env.platform.time_ms ? g_env.platform.time_ms() : 0;
    for (ve_tls_producer * p = g_env.producers; p; p = p->env_next) {
        if (__atomic_load_n(&p->env_registered, __ATOMIC_ACQUIRE) == 0) {
            continue;
        }
        if (__atomic_load_n(&p->env_in_queue, __ATOMIC_RELAXED) != 0) {
            continue;
        }
        if (ve_tls_producer_has_pending(p, now)) {
            if (__atomic_exchange_n(&p->env_in_queue, 1, __ATOMIC_RELAXED) == 0) {
                ve_tls_env_queue_push_locked(p);
            }
        }
    }
}

static void * ve_tls_env_sender_main(void * arg) {
    (void)arg;
    for (;;) {
        g_env.platform.mutex_lock(g_env.mutex);
        while (!g_env.stop && g_env.q_count == 0) {
            ve_tls_env_tick_locked();
            (void)g_env.platform.cond_timedwait_ms(g_env.cond, g_env.mutex, 50);
        }
        if (g_env.stop) {
            g_env.platform.mutex_unlock(g_env.mutex);
            return NULL;
        }
        ve_tls_producer * p = ve_tls_env_queue_pop_locked();
        if (p) {
            (void)__atomic_fetch_add(&p->env_inflight, 1, __ATOMIC_RELAXED);
        }
        g_env.platform.mutex_unlock(g_env.mutex);
        if (!p) {
            continue;
        }
        __atomic_store_n(&p->env_in_queue, 0, __ATOMIC_RELAXED);
        if (p->stop) {
            (void)__atomic_fetch_sub(&p->env_inflight, 1, __ATOMIC_RELAXED);
            continue;
        }
        for (int i = 0; i < 64; i++) {
            if (ve_tls_sender_step(p) == 0) {
                break;
            }
        }
        int64_t now = g_env.platform.time_ms ? g_env.platform.time_ms() : 0;
        if (ve_tls_producer_has_pending(p, now)) {
            ve_tls_env_notify(p);
        }
        (void)__atomic_fetch_sub(&p->env_inflight, 1, __ATOMIC_RELAXED);
    }
}

static ve_tls_result ve_tls_env_destroy_prepared(int32_t timeout_ms);

ve_tls_result ve_tls_env_init(int32_t global_send_thread_count) {
    if (global_send_thread_count <= 0) {
        global_send_thread_count = 1;
    }
#if defined(VE_TLS_ENABLE_PTHREAD)
    pthread_mutex_lock(&g_env_init_mu);
    while (g_env.destroying || g_env.tearing_down) {
        pthread_cond_wait(&g_env_lifecycle_cv, &g_env_init_mu);
    }
#else
    ve_tls_env_lifecycle_lock();
    while (g_env.destroying || g_env.tearing_down) {
        ve_tls_env_lifecycle_unlock();
        ve_tls_env_lifecycle_pause();
        ve_tls_env_lifecycle_lock();
    }
#endif
    if (g_env.inited) {
#if defined(VE_TLS_ENABLE_PTHREAD)
        pthread_mutex_unlock(&g_env_init_mu);
#else
        ve_tls_env_lifecycle_unlock();
#endif
        return VE_TLS_OK;
    }
    memset(&g_env, 0, sizeof(g_env));
    ve_tls_platform_init_default(&g_env.platform);
    g_env.mutex = g_env.platform.mutex_create();
    g_env.cond = g_env.platform.cond_create();
    g_env.q_cap = 4096;
    g_env.q = (ve_tls_producer **)ve_tls_calloc(g_env.q_cap, sizeof(ve_tls_producer *));
    g_env.sender_count = global_send_thread_count;
    g_env.senders = (ve_tls_thread **)ve_tls_calloc((size_t)g_env.sender_count, sizeof(ve_tls_thread *));
    if (!g_env.mutex || !g_env.cond || !g_env.q || !g_env.senders) {
        /* 失败路径需要在释放生命周期锁后清理，避免 public destroy 重入自锁。 */
        g_env.inited = 0;
#if defined(VE_TLS_ENABLE_PTHREAD)
        (void)ve_tls_env_mark_destroying_locked();
        pthread_mutex_unlock(&g_env_init_mu);
#else
        (void)ve_tls_env_mark_destroying_locked();
        ve_tls_env_lifecycle_unlock();
#endif
        (void)ve_tls_env_destroy_prepared(0);
        return VE_TLS_DROP_ERROR;
    }
    for (int32_t i = 0; i < g_env.sender_count; i++) {
        g_env.senders[i] = g_env.platform.thread_create(ve_tls_env_sender_main, NULL);
        if (!g_env.senders[i]) {
            g_env.inited = 0;
#if defined(VE_TLS_ENABLE_PTHREAD)
            (void)ve_tls_env_mark_destroying_locked();
            pthread_mutex_unlock(&g_env_init_mu);
#else
            (void)ve_tls_env_mark_destroying_locked();
            ve_tls_env_lifecycle_unlock();
#endif
            (void)ve_tls_env_destroy_prepared(0);
            return VE_TLS_DROP_ERROR;
        }
    }
    g_env.inited = 1;
#if defined(VE_TLS_ENABLE_PTHREAD)
    pthread_mutex_unlock(&g_env_init_mu);
#else
    ve_tls_env_lifecycle_unlock();
#endif
    return VE_TLS_OK;
}

static ve_tls_result ve_tls_env_destroy_prepared(int32_t timeout_ms) {
    if (!g_env.inited && !g_env.mutex && !g_env.cond && !g_env.q && !g_env.senders) {
        return VE_TLS_OK;
    }
    int64_t start = g_env.platform.time_ms ? g_env.platform.time_ms() : 0;
    if (g_env.mutex) {
        g_env.platform.mutex_lock(g_env.mutex);
    }
    for (;;) {
        int all_drained = 1;
        for (ve_tls_producer * p = g_env.producers; p; p = p->env_next) {
            p->config.platform.mutex_lock(p->mutex);
            int d = ve_tls_producer_is_drained_locked(p);
            p->config.platform.mutex_unlock(p->mutex);
            if (!d) {
                all_drained = 0;
                break;
            }
        }
        if (g_env.q_count == 0 && all_drained) {
            break;
        }
        if (timeout_ms == 0) {
            if (g_env.mutex) {
                g_env.platform.mutex_unlock(g_env.mutex);
            }
            ve_tls_env_destroy_abort_lifecycle();
            return VE_TLS_TIMEOUT;
        }
        int wait_ms = 50;
        if (timeout_ms > 0) {
            int64_t now = g_env.platform.time_ms ? g_env.platform.time_ms() : start;
            int64_t elapsed = now - start;
            int64_t remain = (int64_t)timeout_ms - elapsed;
            if (remain <= 0) {
                if (g_env.mutex) {
                    g_env.platform.mutex_unlock(g_env.mutex);
                }
                ve_tls_env_destroy_abort_lifecycle();
                return VE_TLS_TIMEOUT;
            }
            if (remain < wait_ms) {
                wait_ms = (int)remain;
            }
        }
        if (g_env.mutex) {
            ve_tls_env_tick_locked();
            (void)g_env.platform.cond_timedwait_ms(g_env.cond, g_env.mutex, wait_ms);
        } else {
            break;
        }
    }
    g_env.stop = 1;
    if (g_env.cond) {
        g_env.platform.cond_broadcast(g_env.cond);
    }
    if (g_env.mutex) {
        g_env.platform.mutex_unlock(g_env.mutex);
    }
    if (g_env.senders) {
        for (int32_t i = 0; i < g_env.sender_count; i++) {
            if (g_env.senders[i]) {
                g_env.platform.thread_join(g_env.senders[i]);
                g_env.senders[i] = NULL;
            }
        }
        ve_tls_free(g_env.senders);
        g_env.senders = NULL;
    }
    g_env.sender_count = 0;
    ve_tls_env_mark_unavailable();
    if (g_env.mutex) {
        g_env.platform.mutex_lock(g_env.mutex);
        g_env.stop = 0;
        g_env.platform.mutex_unlock(g_env.mutex);
    }
    if (g_env.q) {
        ve_tls_free(g_env.q);
        g_env.q = NULL;
    }
    g_env.q_cap = 0;
    g_env.q_head = 0;
    g_env.q_tail = 0;
    g_env.q_count = 0;
    for (ve_tls_producer * p = g_env.producers; p; p = p->env_next) {
        __atomic_store_n(&p->env_registered, 0, __ATOMIC_RELEASE);
        __atomic_store_n(&p->env_in_queue, 0, __ATOMIC_RELAXED);
    }
    g_env.producers = NULL;
    if (g_env.cond) {
        g_env.platform.cond_destroy(g_env.cond);
        g_env.cond = NULL;
    }
    if (g_env.mutex) {
        g_env.platform.mutex_destroy(g_env.mutex);
        g_env.mutex = NULL;
    }
    memset(&g_env.platform, 0, sizeof(g_env.platform));
    ve_tls_env_destroy_finish_lifecycle();
    return VE_TLS_OK;
}

ve_tls_result ve_tls_env_destroy(int32_t timeout_ms) {
    if (!ve_tls_env_prepare_destroy()) {
        return VE_TLS_OK;
    }
    return ve_tls_env_destroy_prepared(timeout_ms);
}

int ve_tls_env_register_producer(ve_tls_producer * producer) {
    if (!producer || !ve_tls_env_lifecycle_begin(0)) {
        return -1;
    }
    g_env.platform.mutex_lock(g_env.mutex);
    if (!g_env.stop) {
        __atomic_store_n(&producer->env_registered, 1, __ATOMIC_RELEASE);
        producer->env_next = g_env.producers;
        g_env.producers = producer;
    } else {
        g_env.platform.mutex_unlock(g_env.mutex);
        ve_tls_env_lifecycle_end();
        return -1;
    }
    g_env.platform.mutex_unlock(g_env.mutex);
    ve_tls_env_lifecycle_end();
    return 0;
}

void ve_tls_env_unregister_producer(ve_tls_producer * producer) {
    if (!producer) {
        return;
    }
    if (!ve_tls_env_lifecycle_begin_unregister()) {
        __atomic_store_n(&producer->env_registered, 0, __ATOMIC_RELEASE);
        __atomic_store_n(&producer->env_in_queue, 0, __ATOMIC_RELAXED);
        producer->env_next = NULL;
        return;
    }
    g_env.platform.mutex_lock(g_env.mutex);
    __atomic_store_n(&producer->env_registered, 0, __ATOMIC_RELEASE);
    ve_tls_producer * prev = NULL;
    for (ve_tls_producer * p = g_env.producers; p; p = p->env_next) {
        if (p == producer) {
            if (prev) {
                prev->env_next = p->env_next;
            } else {
                g_env.producers = p->env_next;
            }
            break;
        }
        prev = p;
    }
    producer->env_next = NULL;
    for (size_t i = 0, idx = g_env.q_head; i < g_env.q_count; i++) {
        if (g_env.q[idx] == producer) {
            g_env.q[idx] = NULL;
        }
        idx = (idx + 1) % g_env.q_cap;
    }
    __atomic_store_n(&producer->env_in_queue, 0, __ATOMIC_RELAXED);
    g_env.platform.mutex_unlock(g_env.mutex);
    ve_tls_env_lifecycle_end();
}

void ve_tls_env_notify(ve_tls_producer * producer) {
    /* 原子快路径前置：未注册 / 已在队列 / producer 为空，统统不进 g_env_init_mu。
     * 只有真的要把 producer 推入全局队列时，才付出一次 lifecycle 锁开销；
     * 若 lifecycle 失败（env 处于 destroying 等状态），需把 env_in_queue 复位以免漏 push。 */
    if (!producer) {
        return;
    }
    if (__atomic_load_n(&producer->env_registered, __ATOMIC_ACQUIRE) == 0) {
        return;
    }
    if (__atomic_exchange_n(&producer->env_in_queue, 1, __ATOMIC_RELAXED) != 0) {
        return;
    }
    if (!ve_tls_env_lifecycle_begin(0)) {
        __atomic_store_n(&producer->env_in_queue, 0, __ATOMIC_RELAXED);
        return;
    }
    g_env.platform.mutex_lock(g_env.mutex);
    if (!g_env.stop &&
        __atomic_load_n(&producer->env_registered, __ATOMIC_ACQUIRE) != 0) {
        ve_tls_env_queue_push_locked(producer);
    } else {
        __atomic_store_n(&producer->env_in_queue, 0, __ATOMIC_RELAXED);
    }
    g_env.platform.mutex_unlock(g_env.mutex);
    ve_tls_env_lifecycle_end();
}
