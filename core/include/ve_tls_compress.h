#ifndef VE_TLS_COMPRESS_H
#define VE_TLS_COMPRESS_H

#include <stddef.h>

#include "ve_tls_proto.h"

int ve_tls_compress_apply(const char * compress_type, const unsigned char * in, size_t in_size, ve_tls_bytes * out);

#endif
