#include "ve_tls_pool.h"
#include "ve_tls_alloc.h"

#include <string.h>

int ve_tls_obj_pool_init(ve_tls_obj_pool * pool, size_t obj_size, uint32_t max_cached) {
    if (!pool || obj_size == 0) {
        return -1;
    }
    memset(pool, 0, sizeof(*pool));
    pool->obj_size = obj_size < sizeof(ve_tls_obj_pool_node) ? sizeof(ve_tls_obj_pool_node) : obj_size;
    pool->max_cached = max_cached;
    atomic_store_explicit(&pool->cached, 0u, memory_order_relaxed);
    atomic_store_explicit(&pool->head, NULL, memory_order_relaxed);
    return 0;
}

void * ve_tls_obj_pool_get(ve_tls_obj_pool * pool) {
    if (!pool || pool->obj_size == 0) {
        return NULL;
    }
    for (;;) {
        ve_tls_obj_pool_node * head = atomic_load_explicit(&pool->head, memory_order_acquire);
        if (!head) {
            return ve_tls_malloc(pool->obj_size);
        }
        ve_tls_obj_pool_node * next = head->next;
        if (atomic_compare_exchange_weak_explicit(&pool->head, &head, next, memory_order_acq_rel, memory_order_acquire)) {
            (void)atomic_fetch_sub_explicit(&pool->cached, 1u, memory_order_relaxed);
            return head;
        }
    }
}

void ve_tls_obj_pool_put(ve_tls_obj_pool * pool, void * obj) {
    if (!pool || !obj) {
        return;
    }
    if (pool->max_cached == 0) {
        ve_tls_free(obj);
        return;
    }

    uint32_t cur = atomic_load_explicit(&pool->cached, memory_order_relaxed);
    for (;;) {
        if (cur >= pool->max_cached) {
            ve_tls_free(obj);
            return;
        }
        uint32_t next = cur + 1u;
        if (atomic_compare_exchange_weak_explicit(&pool->cached, &cur, next, memory_order_acq_rel, memory_order_relaxed)) {
            break;
        }
    }

    ve_tls_obj_pool_node * node = (ve_tls_obj_pool_node *)obj;
    for (;;) {
        ve_tls_obj_pool_node * head = atomic_load_explicit(&pool->head, memory_order_acquire);
        node->next = head;
        if (atomic_compare_exchange_weak_explicit(&pool->head, &head, node, memory_order_acq_rel, memory_order_acquire)) {
            return;
        }
    }
}

size_t ve_tls_obj_pool_cached(const ve_tls_obj_pool * pool) {
    if (!pool) {
        return 0;
    }
    return (size_t)atomic_load_explicit(&pool->cached, memory_order_relaxed);
}

void ve_tls_obj_pool_destroy(ve_tls_obj_pool * pool) {
    if (!pool) {
        return;
    }
    ve_tls_obj_pool_node * head = atomic_exchange_explicit(&pool->head, NULL, memory_order_acq_rel);
    while (head) {
        ve_tls_obj_pool_node * next = head->next;
        ve_tls_free(head);
        head = next;
    }
    atomic_store_explicit(&pool->cached, 0u, memory_order_relaxed);
    pool->obj_size = 0;
    pool->max_cached = 0;
}
