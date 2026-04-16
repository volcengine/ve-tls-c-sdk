#include "ve_tls_producer.h"
#include "ve_tls_proto.h"
#include "ve_tls_hash.h"
#include "ve_tls_sign.h"
#include "ve_tls_version.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static const char * env_str(const char * key, const char * defv) {
    const char * v = getenv(key);
    return (v && v[0] != 0) ? v : defv;
}

static int32_t env_i32(const char * key, int32_t defv) {
    const char * s = getenv(key);
    if (!s || s[0] == 0) return defv;
    char * end = NULL;
    long v = strtol(s, &end, 10);
    if (!end || end == s) return defv;
    return (int32_t)v;
}

static void usage(const char * argv0) {
    fprintf(stderr, "usage: %s [--help]\n", argv0 ? argv0 : "ve_tls_demo_putlogsv2");
    fprintf(stderr, "required env: VE_TLS_ENDPOINT VE_TLS_REGION VE_TLS_TOPIC_ID VE_TLS_ACCESS_KEY_ID VE_TLS_ACCESS_KEY_SECRET\n");
    fprintf(stderr, "optional env: VE_TLS_SECURITY_TOKEN VE_TLS_HASH_KEY VE_TLS_DEMO_MESSAGE VE_TLS_SOURCE VE_TLS_FILE_NAME VE_TLS_CONTEXT_FLOW VE_TLS_API_VERSION VE_TLS_REQUEST_TIMEOUT_MS VE_TLS_CONNECT_TIMEOUT_MS VE_TLS_HTTP_DEBUG\n");
}

static char * dup_slice(const char * s, size_t n) {
    char * out = (char *)malloc(n + 1);
    if (!out) {
        return NULL;
    }
    memcpy(out, s, n);
    out[n] = 0;
    return out;
}

static char * extract_host(const char * endpoint) {
    const char * start = endpoint ? endpoint : "";
    const char * p = strstr(start, "://");
    if (p) {
        start = p + 3;
    }
    const char * end = strchr(start, '/');
    if (!end) {
        end = start + strlen(start);
    }
    return dup_slice(start, (size_t)(end - start));
}

static char * build_url(const char * endpoint, const char * topic_id) {
    const char * ep = endpoint ? endpoint : "";
    size_t ep_len = strlen(ep);
    while (ep_len > 0 && ep[ep_len - 1] == '/') {
        ep_len--;
    }
    size_t topic_len = strlen(topic_id ? topic_id : "");
    size_t total = ep_len + strlen("/PutLogs?TopicId=") + topic_len + 1;
    char * out = (char *)malloc(total);
    if (!out) {
        return NULL;
    }
    snprintf(out, total, "%.*s/PutLogs?TopicId=%s", (int)ep_len, ep, topic_id ? topic_id : "");
    return out;
}

static int append_headers(char ** headers, const char * extra) {
    size_t base_len = *headers ? strlen(*headers) : 0;
    size_t extra_len = extra ? strlen(extra) : 0;
    char * next = (char *)realloc(*headers, base_len + extra_len + 1);
    if (!next) {
        return -1;
    }
    memcpy(next + base_len, extra, extra_len);
    next[base_len + extra_len] = 0;
    *headers = next;
    return 0;
}

int main(int argc, char ** argv) {
    if (argc > 1 && strcmp(argv[1], "--help") == 0) {
        usage(argv[0]);
        return 0;
    }

#if !defined(VE_TLS_HAVE_CURL)
    fprintf(stderr, "ve_tls_demo_putlogsv2 requires VE_TLS_ENABLE_CURL=ON at build time\n");
    return 2;
#else
    ve_tls_config cfg;
    ve_tls_bytes log = {0};
    ve_tls_bytes body = {0};
    ve_tls_http_response resp;
    char * host = NULL;
    char * url = NULL;
    char * headers = NULL;
    char * signed_headers = NULL;
    const char * endpoint;
    const char * region;
    const char * topic_id;
    const char * access_key_id;
    const char * access_key_secret;
    const char * security_token;
    const char * hash_key;
    const char * message;
    const char * source;
    const char * file_name;
    const char * context_flow;
    const char * api_version;
    int32_t request_timeout_ms;
    int32_t connect_timeout_ms;
    int32_t http_debug;
    int64_t now_ms;
    uint32_t time_ns = 0;
    char content_md5[33];
    char raw_size[32];
    char earliest_s[32];
    char latest_s[32];
    char * query = NULL;
    int rc = 1;

    ve_tls_config_init(&cfg);
    endpoint = env_str("VE_TLS_ENDPOINT", NULL);
    region = env_str("VE_TLS_REGION", NULL);
    topic_id = env_str("VE_TLS_TOPIC_ID", NULL);
    access_key_id = env_str("VE_TLS_ACCESS_KEY_ID", NULL);
    access_key_secret = env_str("VE_TLS_ACCESS_KEY_SECRET", NULL);
    security_token = env_str("VE_TLS_SECURITY_TOKEN", "");
    hash_key = env_str("VE_TLS_HASH_KEY", "");
    message = env_str("VE_TLS_DEMO_MESSAGE", "hello from direct PutLogsV2 demo");
    source = env_str("VE_TLS_SOURCE", "ve-tls-c-sdk");
    file_name = env_str("VE_TLS_FILE_NAME", "tools/putlogsv2_demo.c");
    context_flow = env_str("VE_TLS_CONTEXT_FLOW", "putlogsv2-demo");
    api_version = env_str("VE_TLS_API_VERSION", VE_TLS_C_SDK_API_VERSION);
    request_timeout_ms = env_i32("VE_TLS_REQUEST_TIMEOUT_MS", 10000);
    connect_timeout_ms = env_i32("VE_TLS_CONNECT_TIMEOUT_MS", 10000);
    http_debug = env_i32("VE_TLS_HTTP_DEBUG", 0);

    if (!endpoint || !region || !topic_id || !access_key_id || !access_key_secret) {
        usage(argv[0]);
        return 2;
    }

    now_ms = cfg.platform.time_ms ? cfg.platform.time_ms() : 0;
    if (cfg.platform.time_unix_ns) {
        int64_t now_ns = cfg.platform.time_unix_ns();
        if (now_ns > 0) {
            time_ns = (uint32_t)(now_ns % 1000000000LL);
        }
    }
    ve_tls_kv kvs[4];
    ve_tls_kv tags[2];
    kvs[0].key = "message";
    kvs[0].value = message;
    kvs[1].key = "demo";
    kvs[1].value = "putlogsv2";
    kvs[2].key = "sdk";
    kvs[2].value = "ve-tls-c";
    kvs[3].key = "context_flow";
    kvs[3].value = context_flow;
    tags[0].key = "demo";
    tags[0].value = "putlogsv2";
    tags[1].key = "api_version";
    tags[1].value = api_version;
    if (ve_tls_proto_encode_log_ex(now_ms, time_ns, 1, kvs, 4, &log) != 0 ||
        ve_tls_proto_encode_log_group_list_ex2(&log, 1, source, file_name, tags, 2, context_flow, 1, &body) != 0) {
        fprintf(stderr, "encode PutLogsV2 body failed\n");
        goto cleanup;
    }

    host = extract_host(endpoint);
    url = build_url(endpoint, topic_id);
    if (!host || !url) {
        fprintf(stderr, "build host/url failed\n");
        goto cleanup;
    }

    {
        size_t qlen = strlen("TopicId=") + strlen(topic_id) + 1;
        query = (char *)malloc(qlen);
        if (!query) {
            goto cleanup;
        }
        snprintf(query, qlen, "TopicId=%s", topic_id);
    }

    {
        unsigned char md5_raw[16];
        size_t header_len;
        ve_tls_md5(body.data, body.size, md5_raw);
        ve_tls_hex_upper(md5_raw, sizeof(md5_raw), content_md5, sizeof(content_md5));
        snprintf(raw_size, sizeof(raw_size), "%zu", body.size);
        header_len = (size_t)snprintf(
            NULL,
            0,
            "Content-Type: application/x-protobuf\nContent-MD5: %s\nx-tls-apiversion: %s\nx-tls-bodyrawsize: %s\nx-tls-compresstype: none\nx-tls-hashkey: %s\n",
            content_md5,
            api_version,
            raw_size,
            hash_key
        );
        headers = (char *)malloc(header_len + 1);
        if (!headers) {
            goto cleanup;
        }
        snprintf(
            headers,
            header_len + 1,
            "Content-Type: application/x-protobuf\nContent-MD5: %s\nx-tls-apiversion: %s\nx-tls-bodyrawsize: %s\nx-tls-compresstype: none\nx-tls-hashkey: %s\n",
            content_md5,
            api_version,
            raw_size,
            hash_key
        );
    }

    if (ve_tls_sign_v4_append(
            access_key_id,
            access_key_secret,
            security_token,
            region,
            "TLS",
            "POST",
            host,
            "/PutLogs",
            query,
            body.data,
            body.size,
            headers,
            &signed_headers) != 0) {
        fprintf(stderr, "sign PutLogsV2 request failed\n");
        goto cleanup;
    }

    snprintf(earliest_s, sizeof(earliest_s), "%lld", (long long)now_ms);
    snprintf(latest_s, sizeof(latest_s), "%lld", (long long)now_ms);
    {
        char extra[128];
        snprintf(extra, sizeof(extra), "log-count: 1\nearliest-log-time: %s\nlatest-log-time: %s\n", earliest_s, latest_s);
        if (append_headers(&signed_headers, extra) != 0) {
            goto cleanup;
        }
    }

    memset(&resp, 0, sizeof(resp));
    ve_tls_http_response_init(&resp);
    ve_tls_http_request req;
    memset(&req, 0, sizeof(req));
    req.method = "POST";
    req.url = url;
    req.headers = signed_headers;
    req.body = body.data;
    req.body_size = body.size;
    req.timeout_ms = request_timeout_ms;
    req.connect_timeout_ms = connect_timeout_ms;
    req.tls_verify_peer = 1;
    req.tls_verify_host = 1;
    req.user_agent = "volc-tls-c/direct-putlogsv2-demo";
    req.debug_log = http_debug;

    if (cfg.http_client.do_request(&cfg.http_client, &req, &resp) != 0) {
        fprintf(stderr, "PutLogsV2 request failed transport_code=%d error_code=%s error_message=%s\n",
            (int)resp.transport_code,
            resp.error_code ? resp.error_code : "",
            resp.error_message ? resp.error_message : "");
        cfg.http_client.free_response(&cfg.http_client, &resp);
        goto cleanup;
    }

    printf("PUTLOGSV2_DEMO status=%d request_id=%s body_size=%zu api_version=%s context_flow=%s\n",
        (int)resp.status_code,
        resp.request_id ? resp.request_id : "",
        body.size,
        api_version,
        context_flow);
    cfg.http_client.free_response(&cfg.http_client, &resp);
    rc = resp.status_code == 200 ? 0 : 1;

cleanup:
    free(query);
    free(host);
    free(url);
    free(headers);
    free(signed_headers);
    ve_tls_bytes_free(&log);
    ve_tls_bytes_free(&body);
    return rc;
#endif
}
