#include "ve_tls_sign.h"

#include "ve_tls_hash.h"
#include "ve_tls_alloc.h"

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <stdio.h>
#include <stdint.h>

#if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 201112L)
#define VE_TLS_THREAD_LOCAL _Thread_local
#define VE_TLS_HAVE_THREAD_LOCAL 1
#elif defined(__GNUC__) || defined(__clang__)
#define VE_TLS_THREAD_LOCAL __thread
#define VE_TLS_HAVE_THREAD_LOCAL 1
#else
#define VE_TLS_THREAD_LOCAL
#define VE_TLS_HAVE_THREAD_LOCAL 0
#endif

static int ve_tls_gmtime_utc(const time_t * t, struct tm * out) {
#if defined(_WIN32)
    return gmtime_s(out, t) == 0 ? 0 : -1;
#else
    return gmtime_r(t, out) ? 0 : -1;
#endif
}

typedef struct {
    char * key;
    char * value;
    unsigned char own_key;
    unsigned char own_value;
} ve_tls_kv_pair;

static void ve_tls_pair_free(ve_tls_kv_pair * p) {
    if (!p) {
        return;
    }
    if (p->own_key) {
        ve_tls_free(p->key);
    }
    if (p->own_value) {
        ve_tls_free(p->value);
    }
    p->key = NULL;
    p->value = NULL;
    p->own_key = 0;
    p->own_value = 0;
}

static int ve_tls_buf_append(char ** buf, size_t * len, size_t * cap, const char * s) {
    if (!buf || !len || !cap || !s) {
        return -1;
    }
    size_t n = strlen(s);
    if (*len > (size_t)-1 - n - 1) {
        return -1;
    }
    size_t required = *len + n + 1;
    if (required > *cap) {
        size_t next = *cap ? *cap : 256;
        while (next < required) {
            if (next > (size_t)-1 / 2) {
                next = required;
                break;
            }
            next *= 2;
        }
        char * p = (char *)ve_tls_realloc(*buf, next);
        if (!p) {
            return -1;
        }
        *buf = p;
        *cap = next;
    }
    memcpy(*buf + *len, s, n);
    *len += n;
    (*buf)[*len] = 0;
    return 0;
}

static int ve_tls_buf_reserve(char ** buf, size_t * cap, size_t required) {
    if (!buf || !cap) {
        return -1;
    }
    if (required <= *cap) {
        return 0;
    }
    size_t next = *cap ? *cap : 256;
    while (next < required) {
        if (next > (size_t)-1 / 2) {
            next = required;
            break;
        }
        next *= 2;
    }
    char * p = (char *)ve_tls_realloc(*buf, next);
    if (!p) {
        return -1;
    }
    *buf = p;
    *cap = next;
    return 0;
}

static int ve_tls_should_escape(unsigned char c) {
    if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
        return 0;
    }
    if (c == '-' || c == '_' || c == '.' || c == '~') {
        return 0;
    }
    return 1;
}

static char * ve_tls_url_encode_span(const char * s, size_t slen) {
    size_t hex_count = 0;
    for (size_t i = 0; i < slen; i++) {
        if (ve_tls_should_escape((unsigned char)s[i])) {
            hex_count++;
        }
    }
    if (hex_count > ((size_t)-1 - slen - 1) / 2) {
        return NULL;
    }
    size_t n = slen + hex_count * 2 + 1;
    char * out = (char *)ve_tls_malloc(n);
    if (!out) {
        return NULL;
    }
    size_t j = 0;
    for (size_t i = 0; i < slen; i++) {
        unsigned char c = (unsigned char)s[i];
        if (ve_tls_should_escape(c)) {
            out[j++] = '%';
            out[j++] = "0123456789ABCDEF"[c >> 4];
            out[j++] = "0123456789ABCDEF"[c & 15];
        } else {
            out[j++] = (char)c;
        }
    }
    out[j] = 0;
    return out;
}

static char * ve_tls_norm_uri(const char * path) {
    if (!path || path[0] == 0) {
        return ve_tls_strdup("/");
    }
    size_t len = strlen(path);
    if (len > ((size_t)-1 - 2) / 3) {
        return NULL;
    }
    char * out = (char *)ve_tls_calloc(1, len * 3 + 2);
    if (!out) {
        return NULL;
    }
    size_t j = 0;
    if (path[0] != '/') {
        out[j++] = '/';
    }
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)path[i];
        if (c == '/') {
            out[j++] = '/';
            continue;
        }
        if (ve_tls_should_escape(c)) {
            out[j++] = '%';
            out[j++] = "0123456789ABCDEF"[c >> 4];
            out[j++] = "0123456789ABCDEF"[c & 15];
        } else {
            out[j++] = (char)c;
        }
    }
    out[j] = 0;
    return out;
}

static int ve_tls_pair_cmp(const void * a, const void * b) {
    const ve_tls_kv_pair * pa = (const ve_tls_kv_pair *)a;
    const ve_tls_kv_pair * pb = (const ve_tls_kv_pair *)b;
    int c = strcmp(pa->key, pb->key);
    if (c != 0) {
        return c;
    }
    return strcmp(pa->value, pb->value);
}

static void ve_tls_pair_sort(ve_tls_kv_pair * pairs, size_t len) {
    if (!pairs || len <= 1) {
        return;
    }
    if (len <= 16) {
        for (size_t i = 1; i < len; i++) {
            ve_tls_kv_pair cur = pairs[i];
            size_t j = i;
            while (j > 0) {
                int c = strcmp(pairs[j - 1].key, cur.key);
                if (c == 0) {
                    c = strcmp(pairs[j - 1].value, cur.value);
                }
                if (c <= 0) {
                    break;
                }
                pairs[j] = pairs[j - 1];
                j--;
            }
            pairs[j] = cur;
        }
        return;
    }
    qsort(pairs, len, sizeof(ve_tls_kv_pair), ve_tls_pair_cmp);
}

static char * ve_tls_norm_query(const char * query) {
    if (!query || query[0] == 0) {
        return ve_tls_strdup("");
    }
    const char * amp_first = strchr(query, '&');
    if (!amp_first) {
        size_t qlen = strlen(query);
        const char * eq = memchr(query, '=', qlen);
        size_t k_len = eq ? (size_t)(eq - query) : qlen;
        size_t v_len = eq ? (size_t)(qlen - k_len - 1) : 0;
        int needs_escape = 0;
        for (size_t i = 0; i < k_len; i++) {
            if (ve_tls_should_escape((unsigned char)query[i])) {
                needs_escape = 1;
                break;
            }
        }
        if (!needs_escape) {
            const char * v = eq ? (eq + 1) : (query + qlen);
            for (size_t i = 0; i < v_len; i++) {
                if (ve_tls_should_escape((unsigned char)v[i])) {
                    needs_escape = 1;
                    break;
                }
            }
        }
        if (!needs_escape) {
            if (eq) {
                return ve_tls_strdup(query);
            }
            char * out = (char *)ve_tls_malloc(qlen + 2);
            if (!out) {
                return NULL;
            }
            memcpy(out, query, qlen);
            out[qlen] = '=';
            out[qlen + 1] = 0;
            return out;
        }
    }
    ve_tls_kv_pair * pairs = NULL;
    size_t cap = 0;
    size_t len = 0;
    const char * qend = query + strlen(query);
    const char * p = query;
    while (p < qend) {
        const char * amp = memchr(p, '&', (size_t)(qend - p));
        const char * end = amp ? amp : qend;
        const char * eq = memchr(p, '=', (size_t)(end - p));
        const char * k_end = eq ? eq : end;
        const char * v_start = eq ? (eq + 1) : end;
        size_t k_len = (size_t)(k_end - p);
        size_t v_len = (size_t)(end - v_start);
        char * k = ve_tls_url_encode_span(p, k_len);
        char * v = ve_tls_url_encode_span(v_start, v_len);
        if (!k || !v) {
            ve_tls_free(k);
            ve_tls_free(v);
            for (size_t i = 0; i < len; i++) {
                ve_tls_pair_free(&pairs[i]);
            }
            ve_tls_free(pairs);
            return NULL;
        }
        if (len + 1 > cap) {
            size_t next = cap ? cap * 2 : 8;
            ve_tls_kv_pair * np = (ve_tls_kv_pair *)ve_tls_realloc(pairs, next * sizeof(ve_tls_kv_pair));
            if (!np) {
                ve_tls_free(k);
                ve_tls_free(v);
                for (size_t i = 0; i < len; i++) {
                    ve_tls_pair_free(&pairs[i]);
                }
                ve_tls_free(pairs);
                return NULL;
            }
            pairs = np;
            cap = next;
        }
        pairs[len].key = k;
        pairs[len].value = v;
        pairs[len].own_key = 1;
        pairs[len].own_value = 1;
        len++;
        p = amp ? (amp + 1) : end;
    }
    ve_tls_pair_sort(pairs, len);
    char * out = NULL;
    size_t out_len = 0;
    size_t out_cap = 0;
    for (size_t i = 0; i < len; i++) {
        if (i > 0) {
            if (ve_tls_buf_append(&out, &out_len, &out_cap, "&") != 0) {
                break;
            }
        }
        if (ve_tls_buf_append(&out, &out_len, &out_cap, pairs[i].key) != 0 ||
            ve_tls_buf_append(&out, &out_len, &out_cap, "=") != 0 ||
            ve_tls_buf_append(&out, &out_len, &out_cap, pairs[i].value) != 0) {
            break;
        }
    }
    for (size_t i = 0; i < len; i++) {
        ve_tls_pair_free(&pairs[i]);
    }
    ve_tls_free(pairs);
    if (!out) {
        out = ve_tls_strdup("");
    }
    return out;
}

static int ve_tls_norm_path_query_for_sign(const char * path, const char * query, const char ** out_uri, const char ** out_query, int * out_owned) {
    if (!out_uri || !out_query || !out_owned) {
        return -1;
    }
    *out_uri = NULL;
    *out_query = NULL;
    *out_owned = 0;

    const char * path_in = path ? path : "";
    const char * query_in = query ? query : "";
#if VE_TLS_HAVE_THREAD_LOCAL
    enum {
        VE_TLS_SIGN_PATH_CACHE_MAX = 128,
        VE_TLS_SIGN_QUERY_CACHE_MAX = 512,
        VE_TLS_SIGN_URI_CACHE_MAX = 256,
        VE_TLS_SIGN_NQUERY_CACHE_MAX = 1024
    };
    typedef struct {
        int valid;
        char path[VE_TLS_SIGN_PATH_CACHE_MAX];
        char query[VE_TLS_SIGN_QUERY_CACHE_MAX];
        char norm_uri[VE_TLS_SIGN_URI_CACHE_MAX];
        char norm_query[VE_TLS_SIGN_NQUERY_CACHE_MAX];
    } ve_tls_sign_norm_cache;
    static VE_TLS_THREAD_LOCAL ve_tls_sign_norm_cache cache;

    if (cache.valid &&
        strcmp(cache.path, path_in) == 0 &&
        strcmp(cache.query, query_in) == 0) {
        *out_uri = cache.norm_uri;
        *out_query = cache.norm_query;
        *out_owned = 0;
        return 0;
    }
#endif

    char * norm_uri = ve_tls_norm_uri(path);
    char * norm_query = ve_tls_norm_query(query);
    if (!norm_uri || !norm_query) {
        ve_tls_free(norm_uri);
        ve_tls_free(norm_query);
        return -1;
    }

#if VE_TLS_HAVE_THREAD_LOCAL
    size_t path_len = strlen(path_in);
    size_t query_len = strlen(query_in);
    size_t uri_len = strlen(norm_uri);
    size_t nquery_len = strlen(norm_query);
    if (path_len + 1 <= VE_TLS_SIGN_PATH_CACHE_MAX &&
        query_len + 1 <= VE_TLS_SIGN_QUERY_CACHE_MAX &&
        uri_len + 1 <= VE_TLS_SIGN_URI_CACHE_MAX &&
        nquery_len + 1 <= VE_TLS_SIGN_NQUERY_CACHE_MAX) {
        memcpy(cache.path, path_in, path_len + 1);
        memcpy(cache.query, query_in, query_len + 1);
        memcpy(cache.norm_uri, norm_uri, uri_len + 1);
        memcpy(cache.norm_query, norm_query, nquery_len + 1);
        cache.valid = 1;
        ve_tls_free(norm_uri);
        ve_tls_free(norm_query);
        *out_uri = cache.norm_uri;
        *out_query = cache.norm_query;
        *out_owned = 0;
        return 0;
    }
#endif

    *out_uri = norm_uri;
    *out_query = norm_query;
    *out_owned = 1;
    return 0;
}

static int ve_tls_parse_headers(const char * headers, ve_tls_kv_pair ** out_pairs, size_t * out_len, char ** out_arena, size_t reserve_pairs) {
    if (!out_pairs || !out_len || !out_arena) {
        return -1;
    }
    *out_pairs = NULL;
    *out_len = 0;
    *out_arena = NULL;
    if (!headers || headers[0] == 0) {
        return 0;
    }

    size_t pair_count = 0;
    size_t arena_need = 0;
    const char * p = headers;
    while (*p) {
        const char * nl = strchr(p, '\n');
        const char * end = nl ? nl : (p + strlen(p));
        const char * colon = memchr(p, ':', (size_t)(end - p));
        if (colon) {
            const char * kb = p;
            const char * ke = colon;
            const char * vb = colon + 1;
            const char * ve = end;
            while (kb < ke && isspace((unsigned char)(*kb))) kb++;
            while (ke > kb && isspace((unsigned char)(*(ke - 1)))) ke--;
            while (vb < ve && isspace((unsigned char)(*vb))) vb++;
            while (ve > vb && isspace((unsigned char)(*(ve - 1)))) ve--;
            size_t k_len = (size_t)(ke - kb);
            size_t v_len = (size_t)(ve - vb);
            if (arena_need > (size_t)-1 - (k_len + 1) || arena_need + k_len + 1 > (size_t)-1 - (v_len + 1)) {
                return -1;
            }
            arena_need += k_len + 1 + v_len + 1;
            pair_count++;
        }
        p = nl ? (nl + 1) : end;
    }
    if (pair_count == 0 && reserve_pairs == 0) {
        return 0;
    }

    if (pair_count > (size_t)-1 - reserve_pairs) {
        return -1;
    }
    size_t slot_count = pair_count + reserve_pairs;
    if (slot_count > (size_t)-1 / sizeof(ve_tls_kv_pair)) {
        return -1;
    }
    size_t pair_bytes = slot_count * sizeof(ve_tls_kv_pair);
    size_t arena_bytes = arena_need > 0 ? arena_need : 1;
    if (pair_bytes > (size_t)-1 - arena_bytes) {
        return -1;
    }
    unsigned char * block = (unsigned char *)ve_tls_malloc(pair_bytes + arena_bytes);
    if (!block) {
        return -1;
    }
    ve_tls_kv_pair * pairs = (ve_tls_kv_pair *)block;
    memset(pairs, 0, pair_bytes);
    char * arena = (char *)(block + pair_bytes);

    size_t idx = 0;
    char * dst = arena;
    p = headers;
    while (*p) {
        const char * nl = strchr(p, '\n');
        const char * end = nl ? nl : (p + strlen(p));
        const char * colon = memchr(p, ':', (size_t)(end - p));
        if (colon) {
            const char * kb = p;
            const char * ke = colon;
            const char * vb = colon + 1;
            const char * ve = end;
            while (kb < ke && isspace((unsigned char)(*kb))) kb++;
            while (ke > kb && isspace((unsigned char)(*(ke - 1)))) ke--;
            while (vb < ve && isspace((unsigned char)(*vb))) vb++;
            while (ve > vb && isspace((unsigned char)(*(ve - 1)))) ve--;
            size_t k_len = (size_t)(ke - kb);
            size_t v_len = (size_t)(ve - vb);

            pairs[idx].key = dst;
            for (size_t i = 0; i < k_len; i++) {
                dst[i] = (char)tolower((unsigned char)kb[i]);
            }
            dst[k_len] = 0;
            dst += k_len + 1;

            pairs[idx].value = dst;
            if (v_len > 0) {
                memcpy(dst, vb, v_len);
            }
            dst[v_len] = 0;
            dst += v_len + 1;

            pairs[idx].own_key = 0;
            pairs[idx].own_value = 0;
            idx++;
        }
        p = nl ? (nl + 1) : end;
    }

    *out_pairs = pairs;
    *out_len = idx;
    *out_arena = NULL;
    return 0;
}

static int ve_tls_header_signable(const char * key_lower) {
    if (strcmp(key_lower, "content-type") == 0) {
        return 1;
    }
    if (strcmp(key_lower, "content-md5") == 0) {
        return 1;
    }
    if (strcmp(key_lower, "host") == 0) {
        return 1;
    }
    if (strcmp(key_lower, "x-security-token") == 0) {
        return 1;
    }
    if (strncmp(key_lower, "x-", 2) == 0) {
        return 1;
    }
    return 0;
}

static void ve_tls_format_xdate(char out[17]) {
#if VE_TLS_HAVE_THREAD_LOCAL
    static VE_TLS_THREAD_LOCAL time_t cached_sec = (time_t)-1;
    static VE_TLS_THREAD_LOCAL char cached_xdate[17];
#endif
    time_t t = time(NULL);
#if VE_TLS_HAVE_THREAD_LOCAL
    if (cached_sec == t && cached_xdate[0] != 0) {
        memcpy(out, cached_xdate, 17);
        return;
    }
#endif
    struct tm tmv;
    if (ve_tls_gmtime_utc(&t, &tmv) != 0) {
        memset(out, 0, 17);
        return;
    }
    strftime(out, 17, "%Y%m%dT%H%M%SZ", &tmv);
#if VE_TLS_HAVE_THREAD_LOCAL
    cached_sec = t;
    memcpy(cached_xdate, out, 17);
#endif
}

static void ve_tls_format_date(char out[9], const char xdate[17]) {
    memcpy(out, xdate, 8);
    out[8] = 0;
}

static int ve_tls_build_canonical_headers(ve_tls_kv_pair * pairs, size_t pair_len, char ** out_canon, char ** out_signed_headers) {
    ve_tls_pair_sort(pairs, pair_len);
    char * canon = NULL;
    size_t canon_len = 0;
    size_t canon_cap = 0;
    char * signed_headers = NULL;
    size_t sh_len = 0;
    size_t sh_cap = 0;
    size_t sign_count = 0;
    size_t canon_need = 1;
    size_t sh_need = 1;
    for (size_t i = 0; i < pair_len; i++) {
        if (!ve_tls_header_signable(pairs[i].key)) {
            continue;
        }
        sign_count++;
        canon_need += strlen(pairs[i].key) + 1 + strlen(pairs[i].value) + 1;
        sh_need += strlen(pairs[i].key);
    }
    if (sign_count > 1) {
        sh_need += (sign_count - 1);
    }
    if (ve_tls_buf_reserve(&canon, &canon_cap, canon_need) != 0 ||
        ve_tls_buf_reserve(&signed_headers, &sh_cap, sh_need) != 0) {
        ve_tls_free(canon);
        ve_tls_free(signed_headers);
        return -1;
    }
    size_t seen = 0;
    for (size_t i = 0; i < pair_len; i++) {
        if (!ve_tls_header_signable(pairs[i].key)) {
            continue;
        }
        if (ve_tls_buf_append(&canon, &canon_len, &canon_cap, pairs[i].key) != 0 ||
            ve_tls_buf_append(&canon, &canon_len, &canon_cap, ":") != 0 ||
            ve_tls_buf_append(&canon, &canon_len, &canon_cap, pairs[i].value) != 0 ||
            ve_tls_buf_append(&canon, &canon_len, &canon_cap, "\n") != 0) {
            ve_tls_free(canon);
            ve_tls_free(signed_headers);
            return -1;
        }
        if (seen > 0) {
            if (ve_tls_buf_append(&signed_headers, &sh_len, &sh_cap, ";") != 0) {
                ve_tls_free(canon);
                ve_tls_free(signed_headers);
                return -1;
            }
        }
        if (ve_tls_buf_append(&signed_headers, &sh_len, &sh_cap, pairs[i].key) != 0) {
            ve_tls_free(canon);
            ve_tls_free(signed_headers);
            return -1;
        }
        seen++;
    }
    if (!canon) {
        canon = ve_tls_strdup("");
    }
    if (!signed_headers) {
        signed_headers = ve_tls_strdup("");
    }
    *out_canon = canon;
    *out_signed_headers = signed_headers;
    return 0;
}

static void ve_tls_sha256_hex_buf(const unsigned char * data, size_t len, char out_hex[65]) {
    unsigned char out[32];
    ve_tls_sha256(data, len, out);
    ve_tls_hex_lower(out, 32, out_hex, 65);
}

static void ve_tls_hmac_hex_buf(const unsigned char * key, size_t key_len, const unsigned char * data, size_t len, char out_hex[65]) {
    unsigned char out[32];
    ve_tls_hmac_sha256(key, key_len, data, len, out);
    ve_tls_hex_lower(out, 32, out_hex, 65);
}

static int ve_tls_signing_key(const char * sk, const char * date8, const char * region, const char * service, unsigned char out32[32]) {
    unsigned char k_date[32];
    unsigned char k_region[32];
    unsigned char k_service[32];
    ve_tls_hmac_sha256((const unsigned char *)sk, strlen(sk), (const unsigned char *)date8, strlen(date8), k_date);
    ve_tls_hmac_sha256(k_date, 32, (const unsigned char *)region, strlen(region), k_region);
    ve_tls_hmac_sha256(k_region, 32, (const unsigned char *)service, strlen(service), k_service);
    ve_tls_hmac_sha256(k_service, 32, (const unsigned char *)"request", 7, out32);
    return 0;
}

static uint64_t ve_tls_fnv1a64(const char * s) {
    uint64_t h = 1469598103934665603ULL;
    if (!s) {
        return h;
    }
    for (const unsigned char * p = (const unsigned char *)s; *p; p++) {
        h ^= (uint64_t)(*p);
        h *= 1099511628211ULL;
    }
    return h;
}

static void ve_tls_signing_key_cached(const char * sk, const char * date8, const char * region, const char * service, unsigned char out32[32]) {
#if VE_TLS_HAVE_THREAD_LOCAL
#define VE_TLS_SK_INLINE_CACHE_MAX 96
    typedef struct {
        int valid;
        char date8[9];
        uint64_t region_sig;
        uint64_t service_sig;
        size_t sk_len;
        int sk_use_digest;
        char sk_inline[VE_TLS_SK_INLINE_CACHE_MAX];
        unsigned char sk_digest[32];
        unsigned char key[32];
    } ve_tls_signing_key_cache;
    static VE_TLS_THREAD_LOCAL ve_tls_signing_key_cache cache;

    size_t sk_len = strlen(sk);
    unsigned char sk_digest[32];
    int sk_digest_ready = 0;
    uint64_t region_sig = ve_tls_fnv1a64(region);
    uint64_t service_sig = ve_tls_fnv1a64(service);
    if (cache.valid &&
        memcmp(cache.date8, date8, 9) == 0 &&
        cache.region_sig == region_sig &&
        cache.service_sig == service_sig &&
        cache.sk_len == sk_len) {
        int sk_match = 0;
        if (!cache.sk_use_digest) {
            if (sk_len <= VE_TLS_SK_INLINE_CACHE_MAX &&
                memcmp(cache.sk_inline, sk, sk_len) == 0) {
                sk_match = 1;
            }
        } else {
            ve_tls_sha256((const unsigned char *)sk, sk_len, sk_digest);
            sk_digest_ready = 1;
            if (memcmp(cache.sk_digest, sk_digest, 32) == 0) {
                sk_match = 1;
            }
        }
        if (sk_match) {
            memcpy(out32, cache.key, 32);
            return;
        }
    }
    ve_tls_signing_key(sk, date8, region, service, out32);
    cache.valid = 1;
    memcpy(cache.date8, date8, 9);
    cache.region_sig = region_sig;
    cache.service_sig = service_sig;
    cache.sk_len = sk_len;
    if (sk_len <= VE_TLS_SK_INLINE_CACHE_MAX) {
        cache.sk_use_digest = 0;
        if (sk_len > 0) {
            memcpy(cache.sk_inline, sk, sk_len);
        }
    } else {
        if (!sk_digest_ready) {
            ve_tls_sha256((const unsigned char *)sk, sk_len, sk_digest);
        }
        cache.sk_use_digest = 1;
        memcpy(cache.sk_digest, sk_digest, 32);
    }
    memcpy(cache.key, out32, 32);
#undef VE_TLS_SK_INLINE_CACHE_MAX
#else
    ve_tls_signing_key(sk, date8, region, service, out32);
#endif
}

int ve_tls_sign_v4_append(
    const char * access_key_id,
    const char * access_key_secret,
    const char * security_token,
    const char * region,
    const char * service,
    const char * method,
    const char * host,
    const char * path,
    const char * query,
    const unsigned char * body,
    size_t body_size,
    const char * headers_in,
    char ** headers_out
) {
    return ve_tls_sign_v4_append_at(
        access_key_id,
        access_key_secret,
        security_token,
        region,
        service,
        method,
        host,
        path,
        query,
        body,
        body_size,
        NULL,
        headers_in,
        headers_out
    );
}

int ve_tls_sign_v4_append_at(
    const char * access_key_id,
    const char * access_key_secret,
    const char * security_token,
    const char * region,
    const char * service,
    const char * method,
    const char * host,
    const char * path,
    const char * query,
    const unsigned char * body,
    size_t body_size,
    const char * xdate_override,
    const char * headers_in,
    char ** headers_out
) {
    if (!access_key_id || !access_key_secret || !region || !service || !method || !host || !path || !headers_out) {
        return -1;
    }
    *headers_out = NULL;
    char xdate[17];
    if (xdate_override && strlen(xdate_override) == 16) {
        memcpy(xdate, xdate_override, 16);
        xdate[16] = 0;
    } else {
        ve_tls_format_xdate(xdate);
    }
    char date8[9];
    ve_tls_format_date(date8, xdate);

    ve_tls_kv_pair * pairs = NULL;
    size_t pair_len = 0;
    char * parsed_headers_arena = NULL;
    if (ve_tls_parse_headers(headers_in, &pairs, &pair_len, &parsed_headers_arena, 4) != 0) {
        return -1;
    }

    pairs[pair_len].key = "host";
    pairs[pair_len].value = (char *)host;
    pairs[pair_len].own_key = 0;
    pairs[pair_len].own_value = 0;
    pair_len++;

    pairs[pair_len].key = "x-date";
    pairs[pair_len].value = xdate;
    pairs[pair_len].own_key = 0;
    pairs[pair_len].own_value = 0;
    pair_len++;

    char payload_hash_hex[65];
    ve_tls_sha256_hex_buf(body ? body : (const unsigned char *)"", body ? body_size : 0, payload_hash_hex);
    pairs[pair_len].key = "x-content-sha256";
    pairs[pair_len].value = payload_hash_hex;
    pairs[pair_len].own_key = 0;
    pairs[pair_len].own_value = 0;
    pair_len++;

    if (security_token && security_token[0] != 0) {
        pairs[pair_len].key = "x-security-token";
        pairs[pair_len].value = (char *)security_token;
        pairs[pair_len].own_key = 0;
        pairs[pair_len].own_value = 0;
        pair_len++;
    }

    char * canon_headers = NULL;
    char * signed_headers = NULL;
    if (ve_tls_build_canonical_headers(pairs, pair_len, &canon_headers, &signed_headers) != 0) {
        for (size_t i = 0; i < pair_len; i++) {
            ve_tls_pair_free(&pairs[i]);
        }
        ve_tls_free(pairs);
        ve_tls_free(parsed_headers_arena);
        return -1;
    }

    const char * norm_uri = NULL;
    const char * norm_query = NULL;
    int norm_owned = 0;
    if (ve_tls_norm_path_query_for_sign(path, query, &norm_uri, &norm_query, &norm_owned) != 0) {
        ve_tls_free(canon_headers);
        ve_tls_free(signed_headers);
        for (size_t i = 0; i < pair_len; i++) {
            ve_tls_pair_free(&pairs[i]);
        }
        ve_tls_free(pairs);
        ve_tls_free(parsed_headers_arena);
        return -1;
    }

    size_t method_n = strlen(method);
    size_t norm_uri_n = strlen(norm_uri);
    size_t norm_query_n = strlen(norm_query);
    size_t canon_headers_n = strlen(canon_headers);
    size_t signed_headers_n = strlen(signed_headers);
    size_t payload_hash_n = strlen(payload_hash_hex);
    size_t canon_req_need = method_n + norm_uri_n + norm_query_n + canon_headers_n + signed_headers_n + payload_hash_n + 5;

    char canon_req_stack[1024];
    char * canon_req = canon_req_stack;
    int canon_req_heap = 0;
    if (canon_req_need > (size_t)-1 - 1) {
        canon_req = NULL;
    } else if (canon_req_need + 1 > sizeof(canon_req_stack)) {
        canon_req = (char *)ve_tls_malloc(canon_req_need + 1);
        if (canon_req) {
            canon_req_heap = 1;
        }
    }
    if (canon_req) {
        char * wp = canon_req;
        memcpy(wp, method, method_n); wp += method_n;
        *wp++ = '\n';
        memcpy(wp, norm_uri, norm_uri_n); wp += norm_uri_n;
        *wp++ = '\n';
        memcpy(wp, norm_query, norm_query_n); wp += norm_query_n;
        *wp++ = '\n';
        memcpy(wp, canon_headers, canon_headers_n); wp += canon_headers_n;
        *wp++ = '\n';
        memcpy(wp, signed_headers, signed_headers_n); wp += signed_headers_n;
        *wp++ = '\n';
        memcpy(wp, payload_hash_hex, payload_hash_n); wp += payload_hash_n;
        *wp = 0;
    }

    if (norm_owned) {
        ve_tls_free((void *)norm_uri);
        ve_tls_free((void *)norm_query);
    }

    if (!canon_req) {
        ve_tls_free(canon_headers);
        ve_tls_free(signed_headers);
        for (size_t i = 0; i < pair_len; i++) {
            ve_tls_pair_free(&pairs[i]);
        }
        ve_tls_free(pairs);
        ve_tls_free(parsed_headers_arena);
        return -1;
    }

    char canon_req_hash_hex[65];
    ve_tls_sha256_hex_buf((const unsigned char *)canon_req, canon_req_need, canon_req_hash_hex);
    if (canon_req_heap) {
        ve_tls_free(canon_req);
    }

    char scope[256];
    int scope_n = snprintf(scope, sizeof(scope), "%s/%s/%s/request", date8, region, service);
    if (scope_n <= 0 || (size_t)scope_n >= sizeof(scope)) {
        ve_tls_free(canon_headers);
        ve_tls_free(signed_headers);
        for (size_t i = 0; i < pair_len; i++) {
            ve_tls_pair_free(&pairs[i]);
        }
        ve_tls_free(pairs);
        ve_tls_free(parsed_headers_arena);
        return -1;
    }

    char sts[640];
    int sts_n = snprintf(sts, sizeof(sts), "HMAC-SHA256\n%s\n%s\n%s", xdate, scope, canon_req_hash_hex);
    if (sts_n <= 0 || (size_t)sts_n >= sizeof(sts)) {
        ve_tls_free(canon_headers);
        ve_tls_free(signed_headers);
        for (size_t i = 0; i < pair_len; i++) {
            ve_tls_pair_free(&pairs[i]);
        }
        ve_tls_free(pairs);
        ve_tls_free(parsed_headers_arena);
        return -1;
    }

    unsigned char signing_key[32];
    ve_tls_signing_key_cached(access_key_secret, date8, region, service, signing_key);
    char signature_hex[65];
    ve_tls_hmac_hex_buf(signing_key, 32, (const unsigned char *)sts, (size_t)sts_n, signature_hex);
    int rc = -1;
    char * out = NULL;
    size_t out_len = 0;
    size_t out_cap = 0;
    size_t out_need = 1;
    if (headers_in && headers_in[0] != 0) {
        out_need += strlen(headers_in) + 1;
    }
    out_need += strlen("Host: ") + strlen(host) + 1;
    out_need += strlen("X-Date: ") + strlen(xdate) + 1;
    out_need += strlen("X-Content-Sha256: ") + strlen(payload_hash_hex) + 1;
    out_need += strlen("Authorization: HMAC-SHA256 Credential=") + strlen(access_key_id) + 1 +
                strlen(scope) + strlen(", SignedHeaders=") + strlen(signed_headers) +
                strlen(", Signature=") + strlen(signature_hex) + 1;
    if (security_token && security_token[0] != 0) {
        out_need += strlen("X-Security-Token: ") + strlen(security_token) + 1;
    }
    if (ve_tls_buf_reserve(&out, &out_cap, out_need) != 0) {
        goto cleanup;
    }
    if (headers_in && headers_in[0] != 0) {
        if (ve_tls_buf_append(&out, &out_len, &out_cap, headers_in) != 0) {
            goto cleanup;
        }
        if (out_len > 0 && out[out_len - 1] != '\n') {
            if (ve_tls_buf_append(&out, &out_len, &out_cap, "\n") != 0) {
                goto cleanup;
            }
        }
    }
    if (ve_tls_buf_append(&out, &out_len, &out_cap, "Host: ") != 0 ||
        ve_tls_buf_append(&out, &out_len, &out_cap, host) != 0 ||
        ve_tls_buf_append(&out, &out_len, &out_cap, "\n") != 0 ||
        ve_tls_buf_append(&out, &out_len, &out_cap, "X-Date: ") != 0 ||
        ve_tls_buf_append(&out, &out_len, &out_cap, xdate) != 0 ||
        ve_tls_buf_append(&out, &out_len, &out_cap, "\n") != 0 ||
        ve_tls_buf_append(&out, &out_len, &out_cap, "X-Content-Sha256: ") != 0 ||
        ve_tls_buf_append(&out, &out_len, &out_cap, payload_hash_hex) != 0 ||
        ve_tls_buf_append(&out, &out_len, &out_cap, "\n") != 0 ||
        ve_tls_buf_append(&out, &out_len, &out_cap, "Authorization: HMAC-SHA256 Credential=") != 0 ||
        ve_tls_buf_append(&out, &out_len, &out_cap, access_key_id) != 0 ||
        ve_tls_buf_append(&out, &out_len, &out_cap, "/") != 0 ||
        ve_tls_buf_append(&out, &out_len, &out_cap, scope) != 0 ||
        ve_tls_buf_append(&out, &out_len, &out_cap, ", SignedHeaders=") != 0 ||
        ve_tls_buf_append(&out, &out_len, &out_cap, signed_headers) != 0 ||
        ve_tls_buf_append(&out, &out_len, &out_cap, ", Signature=") != 0 ||
        ve_tls_buf_append(&out, &out_len, &out_cap, signature_hex) != 0 ||
        ve_tls_buf_append(&out, &out_len, &out_cap, "\n") != 0) {
        goto cleanup;
    }
    if (security_token && security_token[0] != 0) {
        if (ve_tls_buf_append(&out, &out_len, &out_cap, "X-Security-Token: ") != 0 ||
            ve_tls_buf_append(&out, &out_len, &out_cap, security_token) != 0 ||
            ve_tls_buf_append(&out, &out_len, &out_cap, "\n") != 0) {
            goto cleanup;
        }
    }
    *headers_out = out;
    out = NULL;
    rc = 0;
cleanup:
    ve_tls_free(out);
    ve_tls_free(canon_headers);
    ve_tls_free(signed_headers);
    for (size_t i = 0; i < pair_len; i++) {
        ve_tls_pair_free(&pairs[i]);
    }
    ve_tls_free(pairs);
    ve_tls_free(parsed_headers_arena);
    return rc;
}
