#ifndef VE_TLS_TYPES_H
#define VE_TLS_TYPES_H

#include <stddef.h>

typedef struct {
    const char * key;
    const char * value;
} ve_tls_kv;

typedef struct {
    unsigned char * data;
    size_t size;
} ve_tls_bytes;

#endif
