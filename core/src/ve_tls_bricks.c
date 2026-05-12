#include "ve_tls_bricks.h"

#include "ve_tls_alloc.h"
#include "ve_tls_compress.h"
#include "ve_tls_hash.h"
#include "ve_tls_sign.h"
#include "ve_tls_version.h"

#include <stdio.h>
#include <string.h>

static int ve_tls_bricks_streq_ignore_case(const char * a, const char * b) {
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

static char * ve_tls_bricks_strdup_n(const char * s, size_t n) {
    char * out = (char *)ve_tls_malloc(n + 1);
    if (!out) {
        return NULL;
    }
    if (n > 0) {
        memcpy(out, s, n);
    }
    out[n] = 0;
    return out;
}

static char * ve_tls_bricks_build_url(const char * endpoint, const char * topic_id) {
    endpoint = endpoint ? endpoint : "";
    topic_id = topic_id ? topic_id : "";
    size_t epn = strlen(endpoint);
    size_t tpn = strlen(topic_id);
    size_t mid = strlen("/PutLogs?TopicId=");
    if (epn > (size_t)-1 - mid || epn + mid > (size_t)-1 - tpn || epn + mid + tpn > (size_t)-1 - 1) {
        return NULL;
    }
    size_t n = epn + mid + tpn + 1;
    char * url = (char *)ve_tls_calloc(1, n);
    if (!url) {
        return NULL;
    }
    snprintf(url, n, "%s/PutLogs?TopicId=%s", endpoint, topic_id);
    return url;
}

static char * ve_tls_bricks_extract_host(const char * endpoint) {
    if (!endpoint) {
        return ve_tls_bricks_strdup_n("", 0);
    }
    const char * p = strstr(endpoint, "://");
    p = p ? p + 3 : endpoint;
    const char * end = strchr(p, '/');
    if (!end) {
        end = p + strlen(p);
    }
    return ve_tls_bricks_strdup_n(p, (size_t)(end - p));
}

static int ve_tls_bricks_append_header(char ** headers, size_t * len, const char * key, const char * value) {
    if (!headers || !len || !key) {
        return -1;
    }
    value = value ? value : "";
    size_t kn = strlen(key);
    size_t vn = strlen(value);
    size_t need = *len;
    if (need > (size_t)-1 - kn || need + kn > (size_t)-1 - 2 ||
        need + kn + 2 > (size_t)-1 - vn || need + kn + 2 + vn > (size_t)-1 - 2) {
        return -1;
    }
    need += kn + 2 + vn + 1 + 1;
    char * next = (char *)ve_tls_realloc(*headers, need);
    if (!next) {
        return -1;
    }
    memcpy(next + *len, key, kn);
    *len += kn;
    memcpy(next + *len, ": ", 2);
    *len += 2;
    if (vn > 0) {
        memcpy(next + *len, value, vn);
        *len += vn;
    }
    next[(*len)++] = '\n';
    next[*len] = 0;
    *headers = next;
    return 0;
}

static int ve_tls_bricks_copy_body(const unsigned char * in, size_t in_size, unsigned char ** out) {
    if (!in || in_size == 0 || !out) {
        return -1;
    }
    unsigned char * p = (unsigned char *)ve_tls_malloc(in_size);
    if (!p) {
        return -1;
    }
    memcpy(p, in, in_size);
    *out = p;
    return 0;
}

void ve_tls_bricks_request_free(ve_tls_bricks_request * req) {
    if (!req) {
        return;
    }
    ve_tls_free(req->method);
    ve_tls_free(req->url);
    ve_tls_free(req->headers);
    if (req->body_owned) {
        ve_tls_free(req->body);
    }
    memset(req, 0, sizeof(*req));
}

int ve_tls_bricks_pack_request(
    const ve_tls_bricks_config * config,
    const unsigned char * raw_log_group_list,
    size_t raw_log_group_list_size,
    int32_t log_count,
    int64_t earliest_log_time_ms,
    int64_t latest_log_time_ms,
    ve_tls_bricks_request * out) {
    if (!config || !raw_log_group_list || raw_log_group_list_size == 0 || !out) {
        return -1;
    }
    memset(out, 0, sizeof(*out));

    ve_tls_bricks_request req;
    memset(&req, 0, sizeof(req));
    char * host = NULL;
    char * query = NULL;
    char * headers = NULL;
    char * signed_headers = NULL;
    int rc = -1;

    const char * compress_type = config->compress_type;
    if (!compress_type || compress_type[0] == 0 || ve_tls_bricks_streq_ignore_case(compress_type, "none")) {
        compress_type = "none";
        if (config->body_no_copy) {
            req.body = (unsigned char *)raw_log_group_list;
            req.body_owned = 0;
        } else {
            if (ve_tls_bricks_copy_body(raw_log_group_list, raw_log_group_list_size, &req.body) != 0) {
                goto fail;
            }
            req.body_owned = 1;
        }
        req.body_size = raw_log_group_list_size;
    } else {
        ve_tls_bytes compressed;
        memset(&compressed, 0, sizeof(compressed));
        rc = ve_tls_compress_apply(compress_type, raw_log_group_list, raw_log_group_list_size, &compressed);
        if (rc != 0) {
            goto fail;
        }
        rc = -1;
        req.body = compressed.data;
        req.body_size = compressed.size;
        req.body_owned = 1;
    }
    req.raw_body_size = raw_log_group_list_size;
    req.log_count = log_count;
    req.earliest_log_time_ms = earliest_log_time_ms;
    req.latest_log_time_ms = latest_log_time_ms;

    req.method = ve_tls_strdup("POST");
    req.url = ve_tls_bricks_build_url(config->endpoint, config->topic_id);
    host = ve_tls_bricks_extract_host(config->endpoint);
    if (!req.method || !req.url || !host) {
        goto fail;
    }

    const char * topic_id = config->topic_id ? config->topic_id : "";
    size_t query_prefix = strlen("TopicId=");
    size_t topic_len = strlen(topic_id);
    if (query_prefix > (size_t)-1 - topic_len || query_prefix + topic_len > (size_t)-1 - 1) {
        goto fail;
    }
    query = (char *)ve_tls_malloc(query_prefix + topic_len + 1);
    if (!query) {
        goto fail;
    }
    memcpy(query, "TopicId=", query_prefix);
    memcpy(query + query_prefix, topic_id, topic_len);
    query[query_prefix + topic_len] = 0;

    unsigned char md5_raw[16];
    char content_md5[33];
    ve_tls_md5(req.body, req.body_size, md5_raw);
    ve_tls_hex_upper(md5_raw, sizeof(md5_raw), content_md5, sizeof(content_md5));

    char raw_size[32];
    char count[32];
    char earliest[32];
    char latest[32];
    snprintf(raw_size, sizeof(raw_size), "%zu", req.raw_body_size);
    snprintf(count, sizeof(count), "%d", log_count);
    snprintf(earliest, sizeof(earliest), "%lld", (long long)earliest_log_time_ms);
    snprintf(latest, sizeof(latest), "%lld", (long long)latest_log_time_ms);

    size_t hlen = 0;
    if (ve_tls_bricks_append_header(&headers, &hlen, "Content-Type", "application/x-protobuf") != 0 ||
        ve_tls_bricks_append_header(&headers, &hlen, "Content-MD5", content_md5) != 0 ||
        ve_tls_bricks_append_header(&headers, &hlen, "x-tls-apiversion", config->api_version ? config->api_version : VE_TLS_C_SDK_API_VERSION) != 0 ||
        ve_tls_bricks_append_header(&headers, &hlen, "x-tls-bodyrawsize", raw_size) != 0 ||
        ve_tls_bricks_append_header(&headers, &hlen, "x-tls-compresstype", compress_type) != 0 ||
        ve_tls_bricks_append_header(&headers, &hlen, "x-tls-hashkey", config->hash_key ? config->hash_key : "") != 0) {
        goto fail;
    }

    if (ve_tls_sign_v4_append_at(
            config->access_key_id,
            config->access_key_secret,
            config->security_token,
            config->region ? config->region : "",
            "TLS",
            "POST",
            host,
            "/PutLogs",
            query,
            req.body,
            req.body_size,
            config->xdate,
            headers,
            &signed_headers) != 0) {
        goto fail;
    }
    ve_tls_free(headers);
    headers = signed_headers;
    signed_headers = NULL;
    hlen = strlen(headers);
    if (ve_tls_bricks_append_header(&headers, &hlen, "log-count", count) != 0 ||
        ve_tls_bricks_append_header(&headers, &hlen, "earliest-log-time", earliest) != 0 ||
        ve_tls_bricks_append_header(&headers, &hlen, "latest-log-time", latest) != 0) {
        goto fail;
    }
    req.headers = headers;
    headers = NULL;

    ve_tls_free(host);
    ve_tls_free(query);
    *out = req;
    return 0;

fail:
    ve_tls_free(host);
    ve_tls_free(query);
    ve_tls_free(headers);
    ve_tls_free(signed_headers);
    ve_tls_bricks_request_free(&req);
    return rc;
}
