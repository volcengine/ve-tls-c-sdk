#ifndef VE_TLS_POOL_H
#define VE_TLS_POOL_H

#include <stddef.h>
#include <stdint.h>
#include <stdatomic.h>

typedef struct ve_tls_obj_pool_node {
    struct ve_tls_obj_pool_node * next;
} ve_tls_obj_pool_node;

typedef struct {
    size_t obj_size;
    uint32_t max_cached;
    _Atomic(uint32_t) cached;
    _Atomic(ve_tls_obj_pool_node *) head;
} ve_tls_obj_pool;

int ve_tls_obj_pool_init(ve_tls_obj_pool * pool, size_t obj_size, uint32_t max_cached);
void * ve_tls_obj_pool_get(ve_tls_obj_pool * pool);
void ve_tls_obj_pool_put(ve_tls_obj_pool * pool, void * obj);
size_t ve_tls_obj_pool_cached(const ve_tls_obj_pool * pool);
void ve_tls_obj_pool_destroy(ve_tls_obj_pool * pool);

#endif
