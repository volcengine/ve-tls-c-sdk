#include "ve_tls_compress.h"

#include <stddef.h>

static int g_host_compress_bound_calls;
static int g_host_compress_default_calls;

/* Deliberately unusable host symbols: the SDK must not resolve to these. */
int LZ4_compressBound(int input_size) {
    (void)input_size;
    g_host_compress_bound_calls++;
    return 0;
}

int LZ4_compress_default(
    const char * source,
    char * dest,
    int source_size,
    int max_dest_size
) {
    (void)source;
    (void)dest;
    (void)source_size;
    (void)max_dest_size;
    g_host_compress_default_calls++;
    return 0;
}

int main(void) {
    static const unsigned char input[] =
        "host LZ4 symbols must coexist with the bundled implementation";
    unsigned char compressed[256];
    size_t compressed_size = 0;
    ve_tls_bytes allocated = {0};

    if (LZ4_compressBound((int)sizeof(input)) != 0 ||
        LZ4_compress_default(
            (const char *)input,
            (char *)compressed,
            (int)sizeof(input),
            (int)sizeof(compressed)) != 0 ||
        g_host_compress_bound_calls != 1 ||
        g_host_compress_default_calls != 1) {
        return 1;
    }

    if (ve_tls_compress_apply_to_buffer(
            "lz4",
            input,
            sizeof(input),
            compressed,
            sizeof(compressed),
            &compressed_size) != 0 ||
        compressed_size == 0 ||
        g_host_compress_default_calls != 1) {
        return 2;
    }

    if (ve_tls_compress_apply("lz4", input, sizeof(input), &allocated) != 0 ||
        allocated.data == NULL ||
        allocated.size == 0 ||
        g_host_compress_bound_calls != 1 ||
        g_host_compress_default_calls != 1) {
        ve_tls_bytes_free(&allocated);
        return 3;
    }

    ve_tls_bytes_free(&allocated);
    return 0;
}
