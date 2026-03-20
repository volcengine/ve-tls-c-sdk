#include "ve_tls_compress.h"
#include "ve_tls_alloc.h"

#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <stdint.h>

#if defined(VE_TLS_HAVE_ZLIB)
#include <zlib.h>
#endif

#if defined(VE_TLS_HAVE_LZ4)
#include "lz4.h"
#endif

#if defined(VE_TLS_HAVE_ZLIB)
static voidpf ve_tls_zlib_alloc(voidpf opaque, uInt items, uInt size) {
    (void)opaque;
    if (items == 0 || size == 0) {
        return NULL;
    }
    size_t n = (size_t)items;
    size_t s = (size_t)size;
    if (n > (SIZE_MAX / s)) {
        return NULL;
    }
    return ve_tls_calloc(n, s);
}

static void ve_tls_zlib_free(voidpf opaque, voidpf address) {
    (void)opaque;
    ve_tls_free(address);
}
#endif

static int ve_tls_str_ieq(const char * a, const char * b) {
    while (*a && *b) {
        char ca = *a;
        char cb = *b;
        if (ca >= 'A' && ca <= 'Z') ca = (char)(ca - 'A' + 'a');
        if (cb >= 'A' && cb <= 'Z') cb = (char)(cb - 'A' + 'a');
        if (ca != cb) {
            return 0;
        }
        a++;
        b++;
    }
    return *a == 0 && *b == 0;
}

int ve_tls_compress_apply(const char * compress_type, const unsigned char * in, size_t in_size, ve_tls_bytes * out) {
    if (!out) {
        return -1;
    }
    out->data = NULL;
    out->size = 0;
    if (!compress_type || ve_tls_str_ieq(compress_type, "none")) {
        return -2;
    }
    if (!in || in_size == 0) {
        return -1;
    }

    if (ve_tls_str_ieq(compress_type, "zlib")) {
#if defined(VE_TLS_HAVE_ZLIB)
        if (in_size > (size_t)UINT_MAX) {
            return -1;
        }
        z_stream strm;
        memset(&strm, 0, sizeof(strm));
        strm.zalloc = ve_tls_zlib_alloc;
        strm.zfree = ve_tls_zlib_free;
        strm.opaque = NULL;
        int rc = deflateInit(&strm, Z_DEFAULT_COMPRESSION);
        if (rc != Z_OK) {
            deflateEnd(&strm);
            return -1;
        }
        uLong bound = deflateBound(&strm, (uLong)in_size);
        if (bound > (uLong)UINT_MAX) {
            deflateEnd(&strm);
            return -1;
        }
        unsigned char * buf = (unsigned char *)ve_tls_malloc((size_t)bound);
        if (!buf) {
            deflateEnd(&strm);
            return -1;
        }

        strm.next_in = (Bytef *)in;
        strm.avail_in = (uInt)in_size;
        strm.next_out = (Bytef *)buf;
        strm.avail_out = (uInt)bound;

        rc = deflate(&strm, Z_FINISH);
        if (rc != Z_STREAM_END) {
            ve_tls_free(buf);
            deflateEnd(&strm);
            return -1;
        }
        out->data = buf;
        out->size = (size_t)strm.total_out;
        deflateEnd(&strm);
        return 0;
#else
        return -3;
#endif
    }

    if (ve_tls_str_ieq(compress_type, "lz4")) {
#if defined(VE_TLS_HAVE_LZ4)
        if (in_size > (size_t)INT_MAX) {
            return -1;
        }
        int bound = LZ4_compressBound((int)in_size);
        if (bound <= 0) {
            return -1;
        }
        unsigned char * buf = (unsigned char *)ve_tls_malloc((size_t)bound);
        if (!buf) {
            return -1;
        }
        int n = LZ4_compress_default((const char *)in, (char *)buf, (int)in_size, bound);
        if (n <= 0) {
            ve_tls_free(buf);
            return -1;
        }
        out->data = buf;
        out->size = (size_t)n;
        return 0;
#else
        return -3;
#endif
    }

    return -3;
}
