#ifndef VE_TLS_COMPRESS_H
#define VE_TLS_COMPRESS_H

#include <stddef.h>

#include "ve_tls_export.h"
#include "ve_tls_proto.h"

VE_TLS_BEGIN_DECLS

int ve_tls_compress_apply(const char * compress_type, const unsigned char * in, size_t in_size, ve_tls_bytes * out);
int ve_tls_compress_apply_to_buffer(const char * compress_type, const unsigned char * in, size_t in_size, unsigned char * out, size_t out_cap, size_t * out_size);

VE_TLS_END_DECLS

#endif
