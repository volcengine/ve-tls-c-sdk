#include "ve_tls_sign.h"

#include "ve_tls_hash.h"
#include "ve_tls_alloc.h"

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <stdio.h>

typedef struct {
    char * key;
    char * value;
} ve_tls_kv_pair;

static void ve_tls_pair_free(ve_tls_kv_pair * p) {
    if (!p) {
        return;
    }
    ve_tls_free(p->key);
    ve_tls_free(p->value);
    p->key = NULL;
    p->value = NULL;
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

static char * ve_tls_trim(char * s) {
    while (*s && isspace((unsigned char)*s)) {
        s++;
    }
    char * end = s + strlen(s);
    while (end > s && isspace((unsigned char)end[-1])) {
        end--;
    }
    *end = 0;
    return s;
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

static char * ve_tls_url_encode(const char * s) {
    size_t hex_count = 0;
    for (size_t i = 0; s[i]; i++) {
        if (ve_tls_should_escape((unsigned char)s[i])) {
            hex_count++;
        }
    }
    size_t slen = strlen(s);
    if (hex_count > ((size_t)-1 - slen - 1) / 2) {
        return NULL;
    }
    size_t n = slen + hex_count * 2 + 1;
    char * out = (char *)ve_tls_calloc(1, n);
    if (!out) {
        return NULL;
    }
    size_t j = 0;
    for (size_t i = 0; s[i]; i++) {
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

static char * ve_tls_norm_query(const char * query) {
    if (!query || query[0] == 0) {
        return ve_tls_strdup("");
    }
    ve_tls_kv_pair * pairs = NULL;
    size_t cap = 0;
    size_t len = 0;
    const char * p = query;
    while (*p) {
        const char * amp = strchr(p, '&');
        const char * end = amp ? amp : (p + strlen(p));
        const char * eq = memchr(p, '=', (size_t)(end - p));
        const char * k_end = eq ? eq : end;
        const char * v_start = eq ? (eq + 1) : end;
        size_t k_len = (size_t)(k_end - p);
        size_t v_len = (size_t)(end - v_start);
        char * k_raw = (char *)ve_tls_calloc(1, k_len + 1);
        char * v_raw = (char *)ve_tls_calloc(1, v_len + 1);
        if (!k_raw || !v_raw) {
            ve_tls_free(k_raw);
            ve_tls_free(v_raw);
            for (size_t i = 0; i < len; i++) {
                ve_tls_pair_free(&pairs[i]);
            }
            ve_tls_free(pairs);
            return NULL;
        }
        memcpy(k_raw, p, k_len);
        memcpy(v_raw, v_start, v_len);
        char * k = ve_tls_url_encode(k_raw);
        char * v = ve_tls_url_encode(v_raw);
        ve_tls_free(k_raw);
        ve_tls_free(v_raw);
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
        len++;
        p = amp ? (amp + 1) : end;
    }
    qsort(pairs, len, sizeof(ve_tls_kv_pair), ve_tls_pair_cmp);
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

static char * ve_tls_lower_dup(const char * s) {
    size_t n = strlen(s);
    char * out = (char *)ve_tls_calloc(1, n + 1);
    if (!out) {
        return NULL;
    }
    for (size_t i = 0; i < n; i++) {
        out[i] = (char)tolower((unsigned char)s[i]);
    }
    out[n] = 0;
    return out;
}

static int ve_tls_parse_headers(const char * headers, ve_tls_kv_pair ** out_pairs, size_t * out_len) {
    *out_pairs = NULL;
    *out_len = 0;
    if (!headers || headers[0] == 0) {
        return 0;
    }
    ve_tls_kv_pair * pairs = NULL;
    size_t cap = 0;
    size_t len = 0;
    const char * p = headers;
    while (*p) {
        const char * nl = strchr(p, '\n');
        const char * end = nl ? nl : (p + strlen(p));
        const char * colon = memchr(p, ':', (size_t)(end - p));
        if (colon) {
            size_t k_len = (size_t)(colon - p);
            size_t v_len = (size_t)(end - (colon + 1));
            char * k_raw = (char *)ve_tls_calloc(1, k_len + 1);
            char * v_raw = (char *)ve_tls_calloc(1, v_len + 1);
            if (!k_raw || !v_raw) {
                ve_tls_free(k_raw);
                ve_tls_free(v_raw);
                for (size_t i = 0; i < len; i++) {
                    ve_tls_pair_free(&pairs[i]);
                }
                ve_tls_free(pairs);
                return -1;
            }
            memcpy(k_raw, p, k_len);
            memcpy(v_raw, colon + 1, v_len);
            char * k = ve_tls_lower_dup(ve_tls_trim(k_raw));
            char * v = ve_tls_strdup(ve_tls_trim(v_raw));
            ve_tls_free(k_raw);
            ve_tls_free(v_raw);
            if (!k || !v) {
                ve_tls_free(k);
                ve_tls_free(v);
                for (size_t i = 0; i < len; i++) {
                    ve_tls_pair_free(&pairs[i]);
                }
                ve_tls_free(pairs);
                return -1;
            }
            if (len + 1 > cap) {
                size_t next = cap ? cap * 2 : 16;
                ve_tls_kv_pair * np = (ve_tls_kv_pair *)ve_tls_realloc(pairs, next * sizeof(ve_tls_kv_pair));
                if (!np) {
                    ve_tls_free(k);
                    ve_tls_free(v);
                    for (size_t i = 0; i < len; i++) {
                        ve_tls_pair_free(&pairs[i]);
                    }
                    ve_tls_free(pairs);
                    return -1;
                }
                pairs = np;
                cap = next;
            }
            pairs[len].key = k;
            pairs[len].value = v;
            len++;
        }
        p = nl ? (nl + 1) : end;
    }
    *out_pairs = pairs;
    *out_len = len;
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
    time_t t = time(NULL);
    struct tm tmv;
    gmtime_r(&t, &tmv);
    strftime(out, 17, "%Y%m%dT%H%M%SZ", &tmv);
}

static void ve_tls_format_date(char out[9], const char xdate[17]) {
    memcpy(out, xdate, 8);
    out[8] = 0;
}

static int ve_tls_build_canonical_headers(ve_tls_kv_pair * pairs, size_t pair_len, char ** out_canon, char ** out_signed_headers) {
    ve_tls_kv_pair * sign_pairs = NULL;
    size_t sign_len = 0;
    for (size_t i = 0; i < pair_len; i++) {
        if (ve_tls_header_signable(pairs[i].key)) {
            sign_len++;
        }
    }
    sign_pairs = (ve_tls_kv_pair *)ve_tls_calloc(sign_len, sizeof(ve_tls_kv_pair));
    if (!sign_pairs && sign_len > 0) {
        return -1;
    }
    size_t j = 0;
    for (size_t i = 0; i < pair_len; i++) {
        if (ve_tls_header_signable(pairs[i].key)) {
            sign_pairs[j++] = pairs[i];
        }
    }
    qsort(sign_pairs, sign_len, sizeof(ve_tls_kv_pair), ve_tls_pair_cmp);
    char * canon = NULL;
    size_t canon_len = 0;
    size_t canon_cap = 0;
    char * signed_headers = NULL;
    size_t sh_len = 0;
    size_t sh_cap = 0;
    for (size_t i = 0; i < sign_len; i++) {
        if (ve_tls_buf_append(&canon, &canon_len, &canon_cap, sign_pairs[i].key) != 0 ||
            ve_tls_buf_append(&canon, &canon_len, &canon_cap, ":") != 0 ||
            ve_tls_buf_append(&canon, &canon_len, &canon_cap, sign_pairs[i].value) != 0 ||
            ve_tls_buf_append(&canon, &canon_len, &canon_cap, "\n") != 0) {
            ve_tls_free(canon);
            ve_tls_free(signed_headers);
            ve_tls_free(sign_pairs);
            return -1;
        }
        if (i > 0) {
            if (ve_tls_buf_append(&signed_headers, &sh_len, &sh_cap, ";") != 0) {
                ve_tls_free(canon);
                ve_tls_free(signed_headers);
                ve_tls_free(sign_pairs);
                return -1;
            }
        }
        if (ve_tls_buf_append(&signed_headers, &sh_len, &sh_cap, sign_pairs[i].key) != 0) {
            ve_tls_free(canon);
            ve_tls_free(signed_headers);
            ve_tls_free(sign_pairs);
            return -1;
        }
    }
    ve_tls_free(sign_pairs);
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

static char * ve_tls_sha256_hex(const unsigned char * data, size_t len) {
    unsigned char out[32];
    ve_tls_sha256(data, len, out);
    char * hex = (char *)ve_tls_calloc(1, 65);
    if (!hex) {
        return NULL;
    }
    ve_tls_hex_lower(out, 32, hex, 65);
    return hex;
}

static char * ve_tls_hmac_hex(const unsigned char * key, size_t key_len, const unsigned char * data, size_t len) {
    unsigned char out[32];
    ve_tls_hmac_sha256(key, key_len, data, len, out);
    char * hex = (char *)ve_tls_calloc(1, 65);
    if (!hex) {
        return NULL;
    }
    ve_tls_hex_lower(out, 32, hex, 65);
    return hex;
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
    if (!access_key_id || !access_key_secret || !region || !service || !method || !host || !path || !headers_out) {
        return -1;
    }
    *headers_out = NULL;
    char xdate[17];
    ve_tls_format_xdate(xdate);
    char date8[9];
    ve_tls_format_date(date8, xdate);

    ve_tls_kv_pair * pairs = NULL;
    size_t pair_len = 0;
    if (ve_tls_parse_headers(headers_in, &pairs, &pair_len) != 0) {
        return -1;
    }

    ve_tls_kv_pair * np = (ve_tls_kv_pair *)ve_tls_realloc(pairs, (pair_len + 4) * sizeof(ve_tls_kv_pair));
    if (!np) {
        for (size_t i = 0; i < pair_len; i++) {
            ve_tls_pair_free(&pairs[i]);
        }
        ve_tls_free(pairs);
        return -1;
    }
    pairs = np;
    pairs[pair_len].key = ve_tls_strdup("host");
    pairs[pair_len].value = ve_tls_strdup(host);
    if (!pairs[pair_len].key || !pairs[pair_len].value) {
        for (size_t i = 0; i <= pair_len; i++) {
            ve_tls_pair_free(&pairs[i]);
        }
        ve_tls_free(pairs);
        return -1;
    }
    pair_len++;

    pairs[pair_len].key = ve_tls_strdup("x-date");
    pairs[pair_len].value = ve_tls_strdup(xdate);
    if (!pairs[pair_len].key || !pairs[pair_len].value) {
        for (size_t i = 0; i <= pair_len; i++) {
            ve_tls_pair_free(&pairs[i]);
        }
        ve_tls_free(pairs);
        return -1;
    }
    pair_len++;

    char * payload_hash = ve_tls_sha256_hex(body ? body : (const unsigned char *)"", body ? body_size : 0);
    if (!payload_hash) {
        for (size_t i = 0; i < pair_len; i++) {
            ve_tls_pair_free(&pairs[i]);
        }
        ve_tls_free(pairs);
        return -1;
    }
    pairs[pair_len].key = ve_tls_strdup("x-content-sha256");
    pairs[pair_len].value = payload_hash;
    if (!pairs[pair_len].key) {
        for (size_t i = 0; i < pair_len; i++) {
            ve_tls_pair_free(&pairs[i]);
        }
        ve_tls_free(payload_hash);
        ve_tls_free(pairs);
        return -1;
    }
    pair_len++;

    if (security_token && security_token[0] != 0) {
        pairs[pair_len].key = ve_tls_strdup("x-security-token");
        pairs[pair_len].value = ve_tls_strdup(security_token);
        if (!pairs[pair_len].key || !pairs[pair_len].value) {
            for (size_t i = 0; i < pair_len; i++) {
                ve_tls_pair_free(&pairs[i]);
            }
            ve_tls_pair_free(&pairs[pair_len]);
            ve_tls_free(pairs);
            return -1;
        }
        pair_len++;
    }

    char * canon_headers = NULL;
    char * signed_headers = NULL;
    if (ve_tls_build_canonical_headers(pairs, pair_len, &canon_headers, &signed_headers) != 0) {
        for (size_t i = 0; i < pair_len; i++) {
            ve_tls_pair_free(&pairs[i]);
        }
        ve_tls_free(pairs);
        return -1;
    }

    char * norm_uri = ve_tls_norm_uri(path);
    char * norm_query = ve_tls_norm_query(query);
    if (!norm_uri || !norm_query) {
        ve_tls_free(norm_uri);
        ve_tls_free(norm_query);
        ve_tls_free(canon_headers);
        ve_tls_free(signed_headers);
        for (size_t i = 0; i < pair_len; i++) {
            ve_tls_pair_free(&pairs[i]);
        }
        ve_tls_free(pairs);
        return -1;
    }

    char * canon_req = NULL;
    size_t cr_len = 0;
    size_t cr_cap = 0;
    if (ve_tls_buf_append(&canon_req, &cr_len, &cr_cap, method) != 0 ||
        ve_tls_buf_append(&canon_req, &cr_len, &cr_cap, "\n") != 0 ||
        ve_tls_buf_append(&canon_req, &cr_len, &cr_cap, norm_uri) != 0 ||
        ve_tls_buf_append(&canon_req, &cr_len, &cr_cap, "\n") != 0 ||
        ve_tls_buf_append(&canon_req, &cr_len, &cr_cap, norm_query) != 0 ||
        ve_tls_buf_append(&canon_req, &cr_len, &cr_cap, "\n") != 0 ||
        ve_tls_buf_append(&canon_req, &cr_len, &cr_cap, canon_headers) != 0 ||
        ve_tls_buf_append(&canon_req, &cr_len, &cr_cap, "\n") != 0 ||
        ve_tls_buf_append(&canon_req, &cr_len, &cr_cap, signed_headers) != 0 ||
        ve_tls_buf_append(&canon_req, &cr_len, &cr_cap, "\n") != 0 ||
        ve_tls_buf_append(&canon_req, &cr_len, &cr_cap, payload_hash) != 0) {
        ve_tls_free(canon_req);
        canon_req = NULL;
    }

    ve_tls_free(norm_uri);
    ve_tls_free(norm_query);

    if (!canon_req) {
        ve_tls_free(canon_headers);
        ve_tls_free(signed_headers);
        for (size_t i = 0; i < pair_len; i++) {
            ve_tls_pair_free(&pairs[i]);
        }
        ve_tls_free(pairs);
        return -1;
    }

    char * canon_req_hash = ve_tls_sha256_hex((const unsigned char *)canon_req, strlen(canon_req));
    ve_tls_free(canon_req);
    if (!canon_req_hash) {
        ve_tls_free(canon_headers);
        ve_tls_free(signed_headers);
        for (size_t i = 0; i < pair_len; i++) {
            ve_tls_pair_free(&pairs[i]);
        }
        ve_tls_free(pairs);
        return -1;
    }

    char scope[256];
    snprintf(scope, sizeof(scope), "%s/%s/%s/request", date8, region, service);

    char * sts = NULL;
    size_t sts_len = 0;
    size_t sts_cap = 0;
    if (ve_tls_buf_append(&sts, &sts_len, &sts_cap, "HMAC-SHA256\n") != 0 ||
        ve_tls_buf_append(&sts, &sts_len, &sts_cap, xdate) != 0 ||
        ve_tls_buf_append(&sts, &sts_len, &sts_cap, "\n") != 0 ||
        ve_tls_buf_append(&sts, &sts_len, &sts_cap, scope) != 0 ||
        ve_tls_buf_append(&sts, &sts_len, &sts_cap, "\n") != 0 ||
        ve_tls_buf_append(&sts, &sts_len, &sts_cap, canon_req_hash) != 0) {
        ve_tls_free(sts);
        sts = NULL;
    }
    ve_tls_free(canon_req_hash);
    if (!sts) {
        ve_tls_free(canon_headers);
        ve_tls_free(signed_headers);
        for (size_t i = 0; i < pair_len; i++) {
            ve_tls_pair_free(&pairs[i]);
        }
        ve_tls_free(pairs);
        return -1;
    }

    unsigned char signing_key[32];
    ve_tls_signing_key(access_key_secret, date8, region, service, signing_key);
    char * signature = ve_tls_hmac_hex(signing_key, 32, (const unsigned char *)sts, strlen(sts));
    ve_tls_free(sts);
    if (!signature) {
        ve_tls_free(canon_headers);
        ve_tls_free(signed_headers);
        for (size_t i = 0; i < pair_len; i++) {
            ve_tls_pair_free(&pairs[i]);
        }
        ve_tls_free(pairs);
        return -1;
    }

    char * auth = NULL;
    size_t a_len = 0;
    size_t a_cap = 0;
    if (ve_tls_buf_append(&auth, &a_len, &a_cap, "HMAC-SHA256 Credential=") != 0 ||
        ve_tls_buf_append(&auth, &a_len, &a_cap, access_key_id) != 0 ||
        ve_tls_buf_append(&auth, &a_len, &a_cap, "/") != 0 ||
        ve_tls_buf_append(&auth, &a_len, &a_cap, scope) != 0 ||
        ve_tls_buf_append(&auth, &a_len, &a_cap, ", SignedHeaders=") != 0 ||
        ve_tls_buf_append(&auth, &a_len, &a_cap, signed_headers) != 0 ||
        ve_tls_buf_append(&auth, &a_len, &a_cap, ", Signature=") != 0 ||
        ve_tls_buf_append(&auth, &a_len, &a_cap, signature) != 0) {
        ve_tls_free(auth);
        auth = NULL;
    }
    ve_tls_free(signature);
    int rc = -1;
    char * out = NULL;
    size_t out_len = 0;
    size_t out_cap = 0;
    if (!auth) {
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
        ve_tls_buf_append(&out, &out_len, &out_cap, payload_hash) != 0 ||
        ve_tls_buf_append(&out, &out_len, &out_cap, "\n") != 0 ||
        ve_tls_buf_append(&out, &out_len, &out_cap, "Authorization: ") != 0 ||
        ve_tls_buf_append(&out, &out_len, &out_cap, auth) != 0 ||
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
    ve_tls_free(auth);
    ve_tls_free(canon_headers);
    ve_tls_free(signed_headers);
    for (size_t i = 0; i < pair_len; i++) {
        ve_tls_pair_free(&pairs[i]);
    }
    ve_tls_free(pairs);
    return rc;
}
