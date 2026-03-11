#include "../include/ve_tls_compress.h"

#include <string.h>
#include <stdlib.h>

#if defined(VE_TLS_HAVE_ZLIB)
#include <zlib.h>
#endif

#if defined(VE_TLS_HAVE_LZ4)
#include "lz4.h"
#endif

static int ve_tls_str_ieq(const char * a, const char * b) {
    if (!a || !b) {
        return 0;
    }
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
        z_stream strm;
        memset(&strm, 0, sizeof(strm));
        int rc = deflateInit(&strm, Z_DEFAULT_COMPRESSION);
        if (rc != Z_OK) {
            deflateEnd(&strm);
            return -1;
        }
        uLong bound = deflateBound(&strm, (uLong)in_size);
        unsigned char * buf = (unsigned char *)malloc((size_t)bound);
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
            free(buf);
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
        int bound = LZ4_compressBound((int)in_size);
        if (bound <= 0) {
            return -1;
        }
        unsigned char * buf = (unsigned char *)malloc((size_t)bound);
        if (!buf) {
            return -1;
        }
        int n = LZ4_compress_default((const char *)in, (char *)buf, (int)in_size, bound);
        if (n <= 0) {
            free(buf);
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
