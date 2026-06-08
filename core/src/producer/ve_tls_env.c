#include "ve_tls_env.h"
#include "ve_tls_producer_internal.h"
#include "ve_tls_alloc.h"

#include <stdlib.h>
#include <string.h>

#if defined(VE_TLS_ENABLE_PTHREAD)
#include <pthread.h>
/* g_env_init_mu 仅用于串行化 ve_tls_env_init 的双检与状态切换，
 * 关闭并发 init 时 g_env 中间态字段（mutex/cond/q/senders）半初始化窗口。
 * 注意：destroy 路径不能持有此锁——init 失败会自调 destroy，否则自死锁。 */
static pthread_mutex_t g_env_init_mu = PTHREAD_MUTEX_INITIALIZER;
#define VE_TLS_ENV_INIT_LOCK()   pthread_mutex_lock(&g_env_init_mu)
#define VE_TLS_ENV_INIT_UNLOCK() pthread_mutex_unlock(&g_env_init_mu)
#else
#define VE_TLS_ENV_INIT_LOCK()   ((void)0)
#define VE_TLS_ENV_INIT_UNLOCK() ((void)0)
#endif

typedef struct {
    int inited;
    int stop;
    int destroying;
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

static void ve_tls_env_queue_push_locked(ve_tls_producer * producer) {
    if (!producer || g_env.q_count >= g_env.q_cap) {
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

ve_tls_result ve_tls_env_init(int32_t global_send_thread_count) {
    if (global_send_thread_count <= 0) {
        global_send_thread_count = 1;
    }
    VE_TLS_ENV_INIT_LOCK();
    if (g_env.inited) {
        VE_TLS_ENV_INIT_UNLOCK();
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
        /* 失败路径：destroy 不持 init 锁，先 unlock 再调 destroy 防止自死锁。
         * inited 显式置 0 兜底，避免 destroy 内部依赖默认零值时的歧义。 */
        g_env.inited = 0;
        VE_TLS_ENV_INIT_UNLOCK();
        ve_tls_env_destroy(0);
        return VE_TLS_DROP_ERROR;
    }
    for (int32_t i = 0; i < g_env.sender_count; i++) {
        g_env.senders[i] = g_env.platform.thread_create(ve_tls_env_sender_main, NULL);
        if (!g_env.senders[i]) {
            g_env.inited = 0;
            VE_TLS_ENV_INIT_UNLOCK();
            ve_tls_env_destroy(0);
            return VE_TLS_DROP_ERROR;
        }
    }
    g_env.inited = 1;
    VE_TLS_ENV_INIT_UNLOCK();
    return VE_TLS_OK;
}

ve_tls_result ve_tls_env_destroy(int32_t timeout_ms) {
    if (!g_env.inited && !g_env.mutex && !g_env.cond && !g_env.q && !g_env.senders) {
        return VE_TLS_OK;
    }
    int64_t start = g_env.platform.time_ms ? g_env.platform.time_ms() : 0;
    if (g_env.mutex) {
        g_env.platform.mutex_lock(g_env.mutex);
    }
    g_env.destroying = 1;
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
            g_env.destroying = 0;
            g_env.platform.mutex_unlock(g_env.mutex);
            return VE_TLS_TIMEOUT;
        }
        int wait_ms = 50;
        if (timeout_ms > 0) {
            int64_t now = g_env.platform.time_ms ? g_env.platform.time_ms() : start;
            int64_t elapsed = now - start;
            int64_t remain = (int64_t)timeout_ms - elapsed;
            if (remain <= 0) {
                g_env.destroying = 0;
                g_env.platform.mutex_unlock(g_env.mutex);
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
    if (g_env.q) {
        ve_tls_free(g_env.q);
        g_env.q = NULL;
    }
    g_env.q_cap = 0;
    g_env.q_head = 0;
    g_env.q_tail = 0;
    g_env.q_count = 0;
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
    g_env.inited = 0;
    g_env.stop = 0;
    g_env.destroying = 0;
    return VE_TLS_OK;
}

int ve_tls_env_register_producer(ve_tls_producer * producer) {
    if (!producer || !g_env.inited || g_env.destroying) {
        return -1;
    }
    g_env.platform.mutex_lock(g_env.mutex);
    producer->env_next = g_env.producers;
    g_env.producers = producer;
    g_env.platform.mutex_unlock(g_env.mutex);
    return 0;
}

void ve_tls_env_unregister_producer(ve_tls_producer * producer) {
    if (!producer || !g_env.inited) {
        return;
    }
    g_env.platform.mutex_lock(g_env.mutex);
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
    for (size_t i = 0, idx = g_env.q_head; i < g_env.q_count; i++) {
        if (g_env.q[idx] == producer) {
            g_env.q[idx] = NULL;
        }
        idx = (idx + 1) % g_env.q_cap;
    }
    __atomic_store_n(&producer->env_in_queue, 0, __ATOMIC_RELAXED);
    g_env.platform.mutex_unlock(g_env.mutex);
}

void ve_tls_env_notify(ve_tls_producer * producer) {
    if (!producer || !g_env.inited || g_env.stop || g_env.destroying) {
        return;
    }
    if (__atomic_exchange_n(&producer->env_in_queue, 1, __ATOMIC_RELAXED) != 0) {
        return;
    }
    g_env.platform.mutex_lock(g_env.mutex);
    if (!g_env.stop && !g_env.destroying) {
        ve_tls_env_queue_push_locked(producer);
    } else {
        __atomic_store_n(&producer->env_in_queue, 0, __ATOMIC_RELAXED);
    }
    g_env.platform.mutex_unlock(g_env.mutex);
}
