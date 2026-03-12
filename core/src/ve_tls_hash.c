#include "ve_tls_hash.h"

#include <string.h>

typedef struct {
    uint32_t h[8];
    uint64_t len;
    unsigned char buf[64];
    size_t buf_len;
} ve_tls_sha256_ctx;

static uint32_t ve_tls_rotr32(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32 - n));
}

static uint32_t ve_tls_load_be32(const unsigned char * p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void ve_tls_store_be32(unsigned char * p, uint32_t v) {
    p[0] = (unsigned char)(v >> 24);
    p[1] = (unsigned char)(v >> 16);
    p[2] = (unsigned char)(v >> 8);
    p[3] = (unsigned char)(v);
}

static void ve_tls_store_be64(unsigned char * p, uint64_t v) {
    p[0] = (unsigned char)(v >> 56);
    p[1] = (unsigned char)(v >> 48);
    p[2] = (unsigned char)(v >> 40);
    p[3] = (unsigned char)(v >> 32);
    p[4] = (unsigned char)(v >> 24);
    p[5] = (unsigned char)(v >> 16);
    p[6] = (unsigned char)(v >> 8);
    p[7] = (unsigned char)(v);
}

static void ve_tls_sha256_init(ve_tls_sha256_ctx * ctx) {
    ctx->h[0] = 0x6a09e667;
    ctx->h[1] = 0xbb67ae85;
    ctx->h[2] = 0x3c6ef372;
    ctx->h[3] = 0xa54ff53a;
    ctx->h[4] = 0x510e527f;
    ctx->h[5] = 0x9b05688c;
    ctx->h[6] = 0x1f83d9ab;
    ctx->h[7] = 0x5be0cd19;
    ctx->len = 0;
    ctx->buf_len = 0;
}

static void ve_tls_sha256_transform(ve_tls_sha256_ctx * ctx, const unsigned char block[64]) {
    static const uint32_t k[64] = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    };
    uint32_t w[64];
    for (int i = 0; i < 16; i++) {
        w[i] = ve_tls_load_be32(block + i * 4);
    }
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ve_tls_rotr32(w[i - 15], 7) ^ ve_tls_rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = ve_tls_rotr32(w[i - 2], 17) ^ ve_tls_rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = ctx->h[0];
    uint32_t b = ctx->h[1];
    uint32_t c = ctx->h[2];
    uint32_t d = ctx->h[3];
    uint32_t e = ctx->h[4];
    uint32_t f = ctx->h[5];
    uint32_t g = ctx->h[6];
    uint32_t h = ctx->h[7];
    for (int i = 0; i < 64; i++) {
        uint32_t s1 = ve_tls_rotr32(e, 6) ^ ve_tls_rotr32(e, 11) ^ ve_tls_rotr32(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t t1 = h + s1 + ch + k[i] + w[i];
        uint32_t s0 = ve_tls_rotr32(a, 2) ^ ve_tls_rotr32(a, 13) ^ ve_tls_rotr32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = s0 + maj;
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    ctx->h[0] += a;
    ctx->h[1] += b;
    ctx->h[2] += c;
    ctx->h[3] += d;
    ctx->h[4] += e;
    ctx->h[5] += f;
    ctx->h[6] += g;
    ctx->h[7] += h;
}

static void ve_tls_sha256_update(ve_tls_sha256_ctx * ctx, const unsigned char * data, size_t len) {
    ctx->len += (uint64_t)len;
    if (ctx->buf_len > 0) {
        size_t n = 64 - ctx->buf_len;
        if (n > len) {
            n = len;
        }
        memcpy(ctx->buf + ctx->buf_len, data, n);
        ctx->buf_len += n;
        data += n;
        len -= n;
        if (ctx->buf_len == 64) {
            ve_tls_sha256_transform(ctx, ctx->buf);
            ctx->buf_len = 0;
        }
    }
    while (len >= 64) {
        ve_tls_sha256_transform(ctx, data);
        data += 64;
        len -= 64;
    }
    if (len > 0) {
        memcpy(ctx->buf, data, len);
        ctx->buf_len = len;
    }
}

static void ve_tls_sha256_final(ve_tls_sha256_ctx * ctx, unsigned char out32[32]) {
    unsigned char pad[64];
    memset(pad, 0, sizeof(pad));
    pad[0] = 0x80;
    uint64_t bit_len = ctx->len * 8;
    size_t pad_len = (ctx->buf_len < 56) ? (56 - ctx->buf_len) : (120 - ctx->buf_len);
    ve_tls_sha256_update(ctx, pad, pad_len);
    unsigned char lenbuf[8];
    ve_tls_store_be64(lenbuf, bit_len);
    ve_tls_sha256_update(ctx, lenbuf, 8);
    for (int i = 0; i < 8; i++) {
        ve_tls_store_be32(out32 + i * 4, ctx->h[i]);
    }
}

void ve_tls_sha256(const unsigned char * data, size_t len, unsigned char out32[32]) {
    ve_tls_sha256_ctx ctx;
    ve_tls_sha256_init(&ctx);
    ve_tls_sha256_update(&ctx, data, len);
    ve_tls_sha256_final(&ctx, out32);
}

void ve_tls_hmac_sha256(const unsigned char * key, size_t key_len, const unsigned char * data, size_t len, unsigned char out32[32]) {
    unsigned char k0[64];
    memset(k0, 0, sizeof(k0));
    if (key_len > 64) {
        unsigned char tmp[32];
        ve_tls_sha256(key, key_len, tmp);
        memcpy(k0, tmp, 32);
    } else {
        memcpy(k0, key, key_len);
    }
    unsigned char ipad[64];
    unsigned char opad[64];
    for (int i = 0; i < 64; i++) {
        ipad[i] = (unsigned char)(k0[i] ^ 0x36);
        opad[i] = (unsigned char)(k0[i] ^ 0x5c);
    }
    ve_tls_sha256_ctx inner;
    ve_tls_sha256_init(&inner);
    ve_tls_sha256_update(&inner, ipad, 64);
    ve_tls_sha256_update(&inner, data, len);
    unsigned char inner_hash[32];
    ve_tls_sha256_final(&inner, inner_hash);
    ve_tls_sha256_ctx outer;
    ve_tls_sha256_init(&outer);
    ve_tls_sha256_update(&outer, opad, 64);
    ve_tls_sha256_update(&outer, inner_hash, 32);
    ve_tls_sha256_final(&outer, out32);
}

void ve_tls_hex_lower(const unsigned char * data, size_t len, char * out_hex, size_t out_hex_cap) {
    static const char * digits = "0123456789abcdef";
    if (!out_hex || out_hex_cap == 0) {
        return;
    }
    size_t need = len * 2 + 1;
    if (out_hex_cap < need) {
        out_hex[0] = 0;
        return;
    }
    for (size_t i = 0; i < len; i++) {
        out_hex[i * 2] = digits[(data[i] >> 4) & 0xF];
        out_hex[i * 2 + 1] = digits[data[i] & 0xF];
    }
    out_hex[len * 2] = 0;
}
