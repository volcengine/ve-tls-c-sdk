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

static char * ve_tls_dup_trim_span(const char * s, size_t n) {
    if (!s) {
        return NULL;
    }
    size_t begin = 0;
    size_t end = n;
    while (begin < end && isspace((unsigned char)s[begin])) {
        begin++;
    }
    while (end > begin && isspace((unsigned char)s[end - 1])) {
        end--;
    }
    size_t out_len = end - begin;
    char * out = (char *)ve_tls_malloc(out_len + 1);
    if (!out) {
        return NULL;
    }
    if (out_len > 0) {
        memcpy(out, s + begin, out_len);
    }
    out[out_len] = 0;
    return out;
}

static char * ve_tls_lower_dup_trim_span(const char * s, size_t n) {
    if (!s) {
        return NULL;
    }
    size_t begin = 0;
    size_t end = n;
    while (begin < end && isspace((unsigned char)s[begin])) {
        begin++;
    }
    while (end > begin && isspace((unsigned char)s[end - 1])) {
        end--;
    }
    size_t out_len = end - begin;
    char * out = (char *)ve_tls_malloc(out_len + 1);
    if (!out) {
        return NULL;
    }
    for (size_t i = 0; i < out_len; i++) {
        out[i] = (char)tolower((unsigned char)s[begin + i]);
    }
    out[out_len] = 0;
    return out;
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

static char * ve_tls_norm_query(const char * query) {
    if (!query || query[0] == 0) {
        return ve_tls_strdup("");
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
            char * k = ve_tls_lower_dup_trim_span(p, k_len);
            char * v = ve_tls_dup_trim_span(colon + 1, v_len);
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
            pairs[len].own_key = 1;
            pairs[len].own_value = 1;
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
    if (pair_len > 1) {
        qsort(pairs, pair_len, sizeof(ve_tls_kv_pair), ve_tls_pair_cmp);
    }
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
    size_t canon_req_need = strlen(method) + strlen(norm_uri) + strlen(norm_query) + strlen(canon_headers) + strlen(signed_headers) + strlen(payload_hash_hex) + 6;
    if (ve_tls_buf_reserve(&canon_req, &cr_cap, canon_req_need + 1) != 0 ||
        ve_tls_buf_append(&canon_req, &cr_len, &cr_cap, method) != 0 ||
        ve_tls_buf_append(&canon_req, &cr_len, &cr_cap, "\n") != 0 ||
        ve_tls_buf_append(&canon_req, &cr_len, &cr_cap, norm_uri) != 0 ||
        ve_tls_buf_append(&canon_req, &cr_len, &cr_cap, "\n") != 0 ||
        ve_tls_buf_append(&canon_req, &cr_len, &cr_cap, norm_query) != 0 ||
        ve_tls_buf_append(&canon_req, &cr_len, &cr_cap, "\n") != 0 ||
        ve_tls_buf_append(&canon_req, &cr_len, &cr_cap, canon_headers) != 0 ||
        ve_tls_buf_append(&canon_req, &cr_len, &cr_cap, "\n") != 0 ||
        ve_tls_buf_append(&canon_req, &cr_len, &cr_cap, signed_headers) != 0 ||
        ve_tls_buf_append(&canon_req, &cr_len, &cr_cap, "\n") != 0 ||
        ve_tls_buf_append(&canon_req, &cr_len, &cr_cap, payload_hash_hex) != 0) {
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

    char canon_req_hash_hex[65];
    ve_tls_sha256_hex_buf((const unsigned char *)canon_req, strlen(canon_req), canon_req_hash_hex);
    ve_tls_free(canon_req);

    char scope[256];
    int scope_n = snprintf(scope, sizeof(scope), "%s/%s/%s/request", date8, region, service);
    if (scope_n <= 0 || (size_t)scope_n >= sizeof(scope)) {
        ve_tls_free(canon_headers);
        ve_tls_free(signed_headers);
        for (size_t i = 0; i < pair_len; i++) {
            ve_tls_pair_free(&pairs[i]);
        }
        ve_tls_free(pairs);
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
        return -1;
    }

    unsigned char signing_key[32];
    ve_tls_signing_key(access_key_secret, date8, region, service, signing_key);
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
    return rc;
}
