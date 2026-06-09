#include "ve_tls_producer_internal.h"
#include "ve_tls_hash.h"
#include "ve_tls_sign.h"
#include "ve_tls_version.h"
#include "ve_tls_alloc.h"

#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>

static void ve_tls_secure_zero(void * p, size_t n) {
    if (!p || n == 0) {
        return;
    }
    volatile unsigned char * vp = (volatile unsigned char *)p;
    while (n--) {
        *vp++ = 0;
    }
}

static void ve_tls_secure_free_str(char ** ps) {
    if (!ps || !*ps) {
        return;
    }
    size_t n = strlen(*ps);
    ve_tls_secure_zero(*ps, n);
    ve_tls_free(*ps);
    *ps = NULL;
}

static int ve_tls_sender_pop_send_queue_task(ve_tls_producer * producer, ve_tls_send_task * task, int wait_ms) {
    if (!producer || !task) {
        return -1;
    }
    int rc = ve_tls_send_queue_pop(&producer->send_queue, task, wait_ms);
    if (rc == 0) {
        ve_tls_producer_move_send_task_to_inflight(producer, task);
    }
    return rc;
}

static void ve_tls_sender_release_task(ve_tls_producer * producer, ve_tls_send_task * task) {
    if (!task) {
        return;
    }
    ve_tls_producer_release_inflight_task_bytes(producer, task);
    ve_tls_send_task_free(task);
}

static int ve_tls_key_rate_limit_reserve(ve_tls_producer * producer, ve_tls_key_queue * q, size_t bytes, int64_t now_ms, int64_t * next_ready_ms) {
    if (!producer || !q) {
        return 1;
    }
    int32_t rps = producer->config.key_rate_limit_rps;
    int32_t bps = producer->config.key_rate_limit_bps;
    if (rps <= 0 && bps <= 0) {
        return 1;
    }
    double req_need = rps > 0 ? 1.0 : 0.0;
    double byte_need = bps > 0 ? (double)bytes : 0.0;
    producer->config.platform.mutex_lock(producer->mutex);
    if (q->rl_last_ms == 0) {
        q->rl_last_ms = now_ms;
        q->rl_req_tokens = rps > 0 ? (double)rps : 0.0;
        q->rl_byte_tokens = bps > 0 ? (double)bps : 0.0;
    } else if (now_ms > q->rl_last_ms) {
        double dt = (double)(now_ms - q->rl_last_ms) / 1000.0;
        q->rl_last_ms = now_ms;
        if (rps > 0) {
            q->rl_req_tokens += dt * (double)rps;
            if (q->rl_req_tokens > (double)rps) {
                q->rl_req_tokens = (double)rps;
            }
        }
        if (bps > 0) {
            q->rl_byte_tokens += dt * (double)bps;
            if (q->rl_byte_tokens > (double)bps) {
                q->rl_byte_tokens = (double)bps;
            }
        }
    }
    int ok = 1;
    if (rps > 0 && q->rl_req_tokens < req_need) {
        ok = 0;
    }
    if (bps > 0 && q->rl_byte_tokens < byte_need) {
        ok = 0;
    }
    if (ok) {
        if (rps > 0) {
            q->rl_req_tokens -= req_need;
        }
        if (bps > 0) {
            q->rl_byte_tokens -= byte_need;
        }
        producer->config.platform.mutex_unlock(producer->mutex);
        return 1;
    }
    int64_t wait_ms = 10;
    if (rps > 0 && q->rl_req_tokens < req_need) {
        double miss = req_need - q->rl_req_tokens;
        int64_t t = (int64_t)((miss * 1000.0) / (double)rps);
        if (t > wait_ms) wait_ms = t;
    }
    if (bps > 0 && q->rl_byte_tokens < byte_need) {
        double miss = byte_need - q->rl_byte_tokens;
        int64_t t = (int64_t)((miss * 1000.0) / (double)bps);
        if (t > wait_ms) wait_ms = t;
    }
    if (next_ready_ms) {
        *next_ready_ms = now_ms + wait_ms;
    }
    producer->config.platform.mutex_unlock(producer->mutex);
    return 0;
}

static int ve_tls_key_breaker_allow(ve_tls_producer * producer, ve_tls_key_queue * q, int64_t now_ms, int64_t * next_ready_ms) {
    if (!producer || !q || producer->config.key_breaker_fail_threshold <= 0) {
        return 1;
    }
    producer->config.platform.mutex_lock(producer->mutex);
    int64_t until = q->breaker_open_until_ms;
    if (until == 0 || now_ms >= until) {
        producer->config.platform.mutex_unlock(producer->mutex);
        return 1;
    }
    if (next_ready_ms) {
        *next_ready_ms = until;
    }
    producer->config.platform.mutex_unlock(producer->mutex);
    return 0;
}

static void ve_tls_key_breaker_on_final_result(ve_tls_producer * producer, ve_tls_key_queue * q, int ok) {
    if (!producer || !q || producer->config.key_breaker_fail_threshold <= 0) {
        return;
    }
    int64_t now = producer->config.platform.time_ms ? producer->config.platform.time_ms() : 0;
    producer->config.platform.mutex_lock(producer->mutex);
    if (ok) {
        q->breaker_consecutive_failures = 0;
        q->breaker_open_until_ms = 0;
        producer->config.platform.mutex_unlock(producer->mutex);
        return;
    }
    q->breaker_consecutive_failures += 1;
    if (q->breaker_consecutive_failures >= producer->config.key_breaker_fail_threshold) {
        int32_t open_ms = producer->config.key_breaker_open_ms > 0 ? producer->config.key_breaker_open_ms : 30000;
        q->breaker_open_until_ms = now + open_ms;
    }
    producer->config.platform.mutex_unlock(producer->mutex);
}

static int ve_tls_is_retryable_http(int32_t code) {
    return code == 429 || code == 500 || code == 502 || code == 503;
}

static char * ve_tls_strdup_n(const char * s, size_t n) {
    char * p = (char *)ve_tls_calloc(1, n + 1);
    if (!p) {
        return NULL;
    }
    memcpy(p, s, n);
    p[n] = 0;
    return p;
}

static char * ve_tls_json_get_string(const unsigned char * json, size_t len, const char * key) {
    if (!json || len == 0 || !key) {
        return NULL;
    }
    size_t klen = strlen(key);
    for (size_t i = 0; i + klen + 2 < len; i++) {
        if (json[i] != '\"' || memcmp(json + i + 1, key, klen) != 0 || json[i + 1 + klen] != '\"') {
            continue;
        }
        size_t j = i + 1 + klen + 1;
        while (j < len && (json[j] == ' ' || json[j] == '\t' || json[j] == '\r' || json[j] == '\n')) {
            j++;
        }
        if (j >= len || json[j] != ':') {
            continue;
        }
        j++;
        while (j < len && (json[j] == ' ' || json[j] == '\t' || json[j] == '\r' || json[j] == '\n')) {
            j++;
        }
        if (j >= len || json[j] != '\"') {
            continue;
        }
        j++;
        size_t start = j;
        while (j < len) {
            if (json[j] == '\\') {
                j += 2;
                continue;
            }
            if (json[j] == '\"') {
                break;
            }
            j++;
        }
        if (j >= len) {
            return NULL;
        }
        return ve_tls_strdup_n((const char *)(json + start), j - start);
    }
    return NULL;
}

static int ve_tls_query_value_should_escape(unsigned char c) {
    if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
        return 0;
    }
    return !(c == '-' || c == '_' || c == '.' || c == '~');
}

static char * ve_tls_query_encode_value(const char * value) {
    value = value ? value : "";
    size_t len = strlen(value);
    size_t escape_count = 0;
    for (size_t i = 0; i < len; i++) {
        if (ve_tls_query_value_should_escape((unsigned char)value[i])) {
            escape_count++;
        }
    }
    if (escape_count > (((size_t)-1 - len - 1) / 2)) {
        return NULL;
    }
    size_t n = len + escape_count * 2 + 1;
    char * out = (char *)ve_tls_malloc(n);
    if (!out) {
        return NULL;
    }
    size_t j = 0;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)value[i];
        if (ve_tls_query_value_should_escape(c)) {
            out[j++] = '%';
            out[j++] = "0123456789ABCDEF"[c >> 4];
            out[j++] = "0123456789ABCDEF"[c & 0x0F];
        } else {
            out[j++] = (char)c;
        }
    }
    out[j] = 0;
    return out;
}

static char * ve_tls_build_put_logs_url(const char * endpoint, const char * encoded_topic_id) {
    endpoint = endpoint ? endpoint : "";
    encoded_topic_id = encoded_topic_id ? encoded_topic_id : "";
    size_t epn = strlen(endpoint);
    size_t tpn = strlen(encoded_topic_id);
    size_t mid = strlen("/PutLogs?TopicId=");
    size_t n = epn;
    if (n > (size_t)-1 - mid) return NULL;
    n += mid;
    if (n > (size_t)-1 - tpn) return NULL;
    n += tpn;
    if (n > (size_t)-1 - 1) return NULL;
    n += 1;
    char * url = (char *)ve_tls_calloc(1, n);
    if (!url) {
        return NULL;
    }
    snprintf(url, n, "%s/PutLogs?TopicId=%s", endpoint, encoded_topic_id);
    return url;
}

static char * ve_tls_extract_host(const char * endpoint) {
    if (!endpoint) {
        return ve_tls_strdup("");
    }
    const char * p = strstr(endpoint, "://");
    p = p ? (p + 3) : endpoint;
    const char * end = strchr(p, '/');
    if (!end) {
        end = p + strlen(p);
    }
    size_t n = (size_t)(end - p);
    return ve_tls_strdup_n(p, n);
}

static void ve_tls_header_buf_release(ve_tls_producer * producer, char * buf, int pooled) {
    if (!buf) {
        return;
    }
    if (pooled && producer && producer->header_buf_pool.obj_size > 0) {
        ve_tls_obj_pool_put(&producer->header_buf_pool, buf);
        return;
    }
    ve_tls_free(buf);
}

static int ve_tls_headers_grow(ve_tls_producer * producer, char ** headers, size_t len, size_t * cap, size_t required, int * pooled) {
    if (!headers || !cap || !pooled) {
        return -1;
    }
    size_t next = *cap ? *cap : 256;
    while (next < required) {
        if (next > (size_t)-1 / 2) {
            next = required;
            break;
        }
        next *= 2;
    }
    if (*pooled) {
        char * p = (char *)ve_tls_malloc(next);
        if (!p) {
            return -1;
        }
        if (*headers && len > 0) {
            memcpy(p, *headers, len);
        }
        p[len] = 0;
        ve_tls_header_buf_release(producer, *headers, 1);
        *headers = p;
        *cap = next;
        *pooled = 0;
        return 0;
    }
    char * p = (char *)ve_tls_realloc(*headers, next);
    if (!p) {
        return -1;
    }
    *headers = p;
    *cap = next;
    return 0;
}

static void ve_tls_headers_try_use_pool(ve_tls_producer * producer, char ** headers, size_t len, size_t * cap, int * pooled) {
    if (!producer || !headers || !*headers || !cap || !pooled || *pooled) {
        return;
    }
    size_t pool_cap = producer->header_buf_pool.obj_size;
    if (pool_cap == 0 || len + 1 > pool_cap) {
        return;
    }
    char * pooled_buf = (char *)ve_tls_obj_pool_get(&producer->header_buf_pool);
    if (!pooled_buf) {
        return;
    }
    memcpy(pooled_buf, *headers, len);
    pooled_buf[len] = 0;
    ve_tls_free(*headers);
    *headers = pooled_buf;
    *cap = pool_cap;
    *pooled = 1;
}

static int ve_tls_headers_append(ve_tls_producer * producer, char ** headers, size_t * len, size_t * cap, int * pooled, const char * k, const char * v) {
    if (!headers || !len || !cap || !pooled || !k || !v) {
        return -1;
    }
    size_t kn = strlen(k);
    size_t vn = strlen(v);
    size_t need = kn;
    if (need > (size_t)-1 - 2) return -1;
    need += 2;
    if (need > (size_t)-1 - vn) return -1;
    need += vn;
    if (need > (size_t)-1 - 1) return -1;
    need += 1;
    size_t required = *len;
    if (required > (size_t)-1 - need) return -1;
    required += need;
    if (required > (size_t)-1 - 1) return -1;
    required += 1;
    if (required > *cap) {
        if (ve_tls_headers_grow(producer, headers, *len, cap, required, pooled) != 0) {
            return -1;
        }
    }
    int written = snprintf(*headers + *len, *cap - *len, "%s: %s\n", k, v);
    if (written <= 0) {
        return -1;
    }
    *len += (size_t)written;
    return 0;
}

static char * ve_tls_dup_body_limited(const unsigned char * data, size_t size) {
    if (!data || size == 0) {
        return NULL;
    }
    size_t n = size;
    if (n > 2048) {
        n = 2048;
    }
    return ve_tls_strdup_n((const char *)data, n);
}

static void ve_tls_error_set_client(ve_tls_error * out, const char * msg) {
    if (!out) {
        return;
    }
    out->http_code = -1;
    out->transport_kind = VE_TLS_TRANSPORT_GENERIC;
    out->transport_code = 0;
    out->retryable = 0;
    out->error_code = ve_tls_strdup("ClientError");
    out->error_message = msg ? ve_tls_strdup(msg) : NULL;
}

static void ve_tls_error_set_http(ve_tls_error * out, int32_t http_code) {
    if (!out) {
        return;
    }
    out->http_code = http_code;
    out->retryable = ve_tls_is_retryable_http(http_code) ? 1 : 0;
}

static void ve_tls_error_parse_body_fields(ve_tls_error * out, const unsigned char * body, size_t body_size) {
    if (!out || !body || body_size == 0) {
        return;
    }
    if (!out->error_code) {
        out->error_code = ve_tls_json_get_string(body, body_size, "errorCode");
    }
    if (!out->error_message) {
        out->error_message = ve_tls_json_get_string(body, body_size, "errorMessage");
    }
    if (!out->request_id) {
        out->request_id = ve_tls_json_get_string(body, body_size, "requestID");
        if (!out->request_id) {
            out->request_id = ve_tls_json_get_string(body, body_size, "requestId");
        }
        if (!out->request_id) {
            out->request_id = ve_tls_json_get_string(body, body_size, "RequestId");
        }
    }
}

static char * ve_tls_error_build_message(const ve_tls_error * e) {
    if (!e) {
        return NULL;
    }
    if (e->http_code == 200) {
        return NULL;
    }
    if (e->http_code > 0) {
        if (e->error_code && e->error_message) {
            char code_s[32];
            snprintf(code_s, sizeof(code_s), "%d", e->http_code);
            size_t n = strlen("HTTP ") + strlen(code_s) + 1 + strlen(e->error_code) + 2 + strlen(e->error_message) + 1;
            char * out = (char *)ve_tls_calloc(1, n);
            if (!out) {
                return NULL;
            }
            snprintf(out, n, "HTTP %s %s: %s", code_s, e->error_code, e->error_message);
            return out;
        }
        if (e->error_message) {
            return ve_tls_strdup(e->error_message);
        }
        return ve_tls_strdup("non-200 response");
    }
    if (e->error_message) {
        return ve_tls_strdup(e->error_message);
    }
    return ve_tls_strdup("client error");
}

typedef struct {
    char * access_key_id;
    char * access_key_secret;
    char * security_token;
} ve_tls_owned_credentials;

typedef struct {
    ve_tls_producer * producer;
    int64_t version;
    char * access_key_id;
    char * access_key_secret;
    char * security_token;
} ve_tls_static_cred_cache;

static __thread ve_tls_static_cred_cache g_static_cred_cache;

static void ve_tls_owned_credentials_free(ve_tls_owned_credentials * owned) {
    if (!owned) {
        return;
    }
    ve_tls_free(owned->access_key_id);
    ve_tls_secure_free_str(&owned->access_key_secret);
    ve_tls_secure_free_str(&owned->security_token);
    memset(owned, 0, sizeof(*owned));
}

static void ve_tls_static_cred_cache_free(ve_tls_static_cred_cache * cache) {
    if (!cache) {
        return;
    }
    ve_tls_free(cache->access_key_id);
    ve_tls_secure_free_str(&cache->access_key_secret);
    ve_tls_secure_free_str(&cache->security_token);
    memset(cache, 0, sizeof(*cache));
}

static const ve_tls_runtime_snapshot * ve_tls_snapshot_acquire_static_cred(ve_tls_producer * producer, int64_t * out_version) {
    if (!producer || !out_version) {
        return NULL;
    }
    for (int i = 0; i < 4; i++) {
        int64_t want_version = __atomic_load_n(&producer->static_cred_version, __ATOMIC_ACQUIRE);
        const ve_tls_runtime_snapshot * snapshot = ve_tls_runtime_snapshot_acquire(producer);
        if (!snapshot) {
            return NULL;
        }
        if (snapshot->static_cred_version == want_version) {
            *out_version = want_version;
            return snapshot;
        }
        ve_tls_runtime_snapshot_release(snapshot);
    }
    return NULL;
}

static int ve_tls_static_cred_cache_refresh(ve_tls_producer * producer, ve_tls_static_cred_cache * cache) {
    if (!producer || !cache) {
        return -1;
    }
    char * ak = NULL;
    char * sk = NULL;
    char * tok = NULL;
    int64_t version = 0;
    const ve_tls_runtime_snapshot * snapshot = ve_tls_snapshot_acquire_static_cred(producer, &version);
    if (!snapshot) {
        return -2;
    }
    ak = snapshot->access_key_id ? ve_tls_strdup(snapshot->access_key_id) : NULL;
    sk = snapshot->access_key_secret ? ve_tls_strdup(snapshot->access_key_secret) : NULL;
    tok = snapshot->security_token ? ve_tls_strdup(snapshot->security_token) : NULL;
    ve_tls_runtime_snapshot_release(snapshot);
    if (!ak || !sk) {
        ve_tls_free(ak);
        ve_tls_secure_free_str(&sk);
        ve_tls_secure_free_str(&tok);
        return -1;
    }
    ve_tls_static_cred_cache_free(cache);
    cache->producer = producer;
    cache->version = version;
    cache->access_key_id = ak;
    cache->access_key_secret = sk;
    cache->security_token = tok;
    return 0;
}

static int ve_tls_get_dynamic_credentials_owned(
    ve_tls_producer * producer,
    int64_t now_ms,
    const char ** out_ak,
    const char ** out_sk,
    const char ** out_token,
    ve_tls_owned_credentials * owned) {
    if (!producer || !out_ak || !out_sk || !out_token || !owned) {
        return -1;
    }
    int64_t advance = producer->config.credentials_expire_advance_ms;
    if (advance < 0) {
        advance = 0;
    }
    int64_t min_int = producer->config.credentials_refresh_min_interval_ms;
    if (min_int < 0) {
        min_int = 0;
    }

    for (;;) {
        producer->config.platform.mutex_lock(producer->mutex);
        while (producer->cred_refreshing) {
            producer->config.platform.cond_wait(producer->send_cond, producer->mutex);
        }

        int have = producer->cred_access_key_id && producer->cred_access_key_secret;
        int need = 0;
        if (!have) {
            need = 1;
        } else if (producer->cred_expire_ms > 0 && now_ms + advance >= producer->cred_expire_ms) {
            need = 1;
        }

        if (!need) {
            owned->access_key_id = producer->cred_access_key_id ? ve_tls_strdup(producer->cred_access_key_id) : NULL;
            owned->access_key_secret = producer->cred_access_key_secret ? ve_tls_strdup(producer->cred_access_key_secret) : NULL;
            owned->security_token = producer->cred_security_token ? ve_tls_strdup(producer->cred_security_token) : NULL;
            producer->config.platform.mutex_unlock(producer->mutex);
            if (!owned->access_key_id || !owned->access_key_secret) {
                ve_tls_owned_credentials_free(owned);
                return -1;
            }
            *out_ak = owned->access_key_id;
            *out_sk = owned->access_key_secret;
            *out_token = owned->security_token;
            return 0;
        }

        if (min_int > 0 && producer->cred_last_refresh_ms > 0 && now_ms - producer->cred_last_refresh_ms < min_int) {
            if (have) {
                owned->access_key_id = producer->cred_access_key_id ? ve_tls_strdup(producer->cred_access_key_id) : NULL;
                owned->access_key_secret = producer->cred_access_key_secret ? ve_tls_strdup(producer->cred_access_key_secret) : NULL;
                owned->security_token = producer->cred_security_token ? ve_tls_strdup(producer->cred_security_token) : NULL;
                producer->config.platform.mutex_unlock(producer->mutex);
                if (!owned->access_key_id || !owned->access_key_secret) {
                    ve_tls_owned_credentials_free(owned);
                    return -1;
                }
                *out_ak = owned->access_key_id;
                *out_sk = owned->access_key_secret;
                *out_token = owned->security_token;
                return 0;
            }
            producer->config.platform.mutex_unlock(producer->mutex);
            return -1;
        }

        producer->cred_refreshing = 1;
        producer->config.platform.mutex_unlock(producer->mutex);

        ve_tls_credentials creds;
        memset(&creds, 0, sizeof(creds));
        ve_tls_metrics_emit(producer, "credentials_refresh_attempt", 1, 0);
        int prc = producer->config.credentials_provider(&creds, producer->config.credentials_provider_param);

        producer->config.platform.mutex_lock(producer->mutex);
        producer->cred_last_refresh_ms = now_ms;
        if (prc == 0 && creds.access_key_id && creds.access_key_secret) {
            ve_tls_secure_free_str(&producer->cred_access_key_id);
            ve_tls_secure_free_str(&producer->cred_access_key_secret);
            ve_tls_secure_free_str(&producer->cred_security_token);
            producer->cred_access_key_id = ve_tls_strdup(creds.access_key_id);
            producer->cred_access_key_secret = ve_tls_strdup(creds.access_key_secret);
            producer->cred_security_token = (creds.security_token && creds.security_token[0] != 0) ? ve_tls_strdup(creds.security_token) : NULL;
            producer->cred_expire_ms = creds.expire_time_ms;
            if (!producer->cred_access_key_id || !producer->cred_access_key_secret) {
                ve_tls_secure_free_str(&producer->cred_access_key_id);
                ve_tls_secure_free_str(&producer->cred_access_key_secret);
                ve_tls_secure_free_str(&producer->cred_security_token);
                producer->cred_access_key_id = NULL;
                producer->cred_access_key_secret = NULL;
                producer->cred_security_token = NULL;
                producer->cred_expire_ms = 0;
                prc = -1;
            }
        } else {
            prc = -1;
        }
        producer->cred_refreshing = 0;
        producer->config.platform.cond_broadcast(producer->send_cond);
        producer->config.platform.mutex_unlock(producer->mutex);

        if (prc != 0) {
            ve_tls_metrics_emit(producer, "credentials_refresh_failed", 1, 0);
            return -1;
        }
        ve_tls_metrics_emit(producer, "credentials_refresh_ok", 1, 0);
    }
}

static int ve_tls_get_signing_credentials(
    ve_tls_producer * producer,
    int64_t now_ms,
    const char ** out_ak,
    const char ** out_sk,
    const char ** out_token,
    ve_tls_owned_credentials * owned) {
    if (!producer || !out_ak || !out_sk || !out_token || !owned) {
        return -1;
    }
    *out_ak = NULL;
    *out_sk = NULL;
    *out_token = NULL;
    memset(owned, 0, sizeof(*owned));

    if (!producer->config.credentials_provider) {
        int64_t version = __atomic_load_n(&producer->static_cred_version, __ATOMIC_ACQUIRE);
        if (g_static_cred_cache.producer != producer || g_static_cred_cache.version != version) {
            if (ve_tls_static_cred_cache_refresh(producer, &g_static_cred_cache) != 0) {
                return -1;
            }
        }
        if (!g_static_cred_cache.access_key_id || !g_static_cred_cache.access_key_secret) {
            return -1;
        }
        *out_ak = g_static_cred_cache.access_key_id;
        *out_sk = g_static_cred_cache.access_key_secret;
        *out_token = g_static_cred_cache.security_token;
        return 0;
    }

    return ve_tls_get_dynamic_credentials_owned(producer, now_ms, out_ak, out_sk, out_token, owned);
}

static int ve_tls_is_sensitive_header_key(const char * key, size_t n) {
    if (!key || n == 0) return 0;
    if (n == strlen("authorization") && strncasecmp(key, "authorization", n) == 0) return 1;
    if (n == strlen("x-security-token") && strncasecmp(key, "x-security-token", n) == 0) return 1;
    if (n == strlen("x-date") && strncasecmp(key, "x-date", n) == 0) return 1;
    if (n == strlen("x-content-sha256") && strncasecmp(key, "x-content-sha256", n) == 0) return 1;
    return 0;
}

static void ve_tls_http_debug_log_request(const ve_tls_http_request * req) {
    if (!req || req->debug_log == 0) return;
    fprintf(stderr,
        "http_debug request method=%s url=%s connect_timeout_ms=%lld timeout_ms=%lld tls_verify_peer=%d tls_verify_host=%d user_agent_set=%d proxy_set=%d\n",
        req->method ? req->method : "",
        req->url ? req->url : "",
        (long long)req->connect_timeout_ms,
        (long long)req->timeout_ms,
        (int)req->tls_verify_peer,
        (int)req->tls_verify_host,
        (req->user_agent && req->user_agent[0] != 0) ? 1 : 0,
        (req->proxy && req->proxy[0] != 0) ? 1 : 0
    );
    int has_rawsize = 0, has_comp = 0, has_count = 0, has_earliest = 0, has_latest = 0, has_apiver = 0;
    if (req->headers && req->headers[0] != 0) {
        const char * p = req->headers;
        const char * line = p;
        while (*p) {
            if (*p == '\n') {
                const char * end = p;
                const char * colon = memchr(line, ':', (size_t)(end - line));
                if (colon) {
                    const char * key = line;
                    size_t kn = (size_t)(colon - key);
                    while (kn > 0 && (key[kn - 1] == ' ' || key[kn - 1] == '\t')) kn--;
                    if (!ve_tls_is_sensitive_header_key(key, kn)) {
                        if (kn == strlen("x-tls-bodyrawsize") && strncasecmp(key, "x-tls-bodyrawsize", kn) == 0) has_rawsize = 1;
                        else if (kn == strlen("x-tls-compresstype") && strncasecmp(key, "x-tls-compresstype", kn) == 0) has_comp = 1;
                        else if (kn == strlen("log-count") && strncasecmp(key, "log-count", kn) == 0) has_count = 1;
                        else if (kn == strlen("earliest-log-time") && strncasecmp(key, "earliest-log-time", kn) == 0) has_earliest = 1;
                        else if (kn == strlen("latest-log-time") && strncasecmp(key, "latest-log-time", kn) == 0) has_latest = 1;
                        else if (kn == strlen("x-tls-apiversion") && strncasecmp(key, "x-tls-apiversion", kn) == 0) has_apiver = 1;
                    }
                }
                line = p + 1;
            }
            p++;
        }
    }
    fprintf(stderr,
        "http_debug io_headers apiversion=%d bodyrawsize=%d compresstype=%d log_count=%d earliest=%d latest=%d\n",
        has_apiver, has_rawsize, has_comp, has_count, has_earliest, has_latest
    );
}

static void ve_tls_http_debug_log_failure(const ve_tls_http_request * req, const ve_tls_http_response * resp) {
    if (!req || req->debug_log == 0 || !resp) return;
    fprintf(stderr,
        "http_debug failure http_code=%d transport_kind=%d transport_code=%d transport_retryable=%d req_id=%s error_code=%s\n",
        (int)resp->status_code,
        (int)resp->transport_kind,
        (int)resp->transport_code,
        (int)resp->transport_retryable,
        resp->request_id ? resp->request_id : "",
        resp->error_code ? resp->error_code : ""
    );
}

typedef struct {
    ve_tls_producer * producer;
    int64_t version;
    char * endpoint;
    char * topic_id;
    char * region;
    char * api_version;
    char * compress_type;
    char * default_hash_key;
    char * ca_cert_path;
    char * proxy;
    char * user_agent;
    char * url;
    char * host;
    char * query;
    int32_t connect_timeout_ms;
    int32_t request_timeout_ms;
    int32_t tls_verify_peer;
    int32_t tls_verify_host;
    int32_t http_debug;
    int32_t tcp_keepalive;
    int32_t tcp_keepidle;
    int32_t tcp_keepintvl;
} ve_tls_send_cfg_cache;

static __thread ve_tls_send_cfg_cache g_send_cfg_cache;

static void ve_tls_send_cfg_cache_free(ve_tls_send_cfg_cache * s) {
    if (!s) {
        return;
    }
    ve_tls_free(s->endpoint);
    ve_tls_free(s->topic_id);
    ve_tls_free(s->region);
    ve_tls_free(s->api_version);
    ve_tls_free(s->compress_type);
    ve_tls_free(s->default_hash_key);
    ve_tls_free(s->ca_cert_path);
    ve_tls_free(s->proxy);
    ve_tls_free(s->user_agent);
    ve_tls_free(s->url);
    ve_tls_free(s->host);
    ve_tls_free(s->query);
    memset(s, 0, sizeof(*s));
}

static void ve_tls_sender_thread_cache_clear(void) {
    ve_tls_send_cfg_cache_free(&g_send_cfg_cache);
    ve_tls_static_cred_cache_free(&g_static_cred_cache);
    ve_tls_sign_thread_cache_clear();
}

static char * ve_tls_build_topic_query(const char * encoded_topic_id) {
    if (!encoded_topic_id || encoded_topic_id[0] == 0) {
        return ve_tls_strdup("");
    }
    size_t qn = strlen("TopicId=");
    size_t tpn = strlen(encoded_topic_id);
    if (qn > (size_t)-1 - tpn) {
        return NULL;
    }
    qn += tpn;
    if (qn > (size_t)-1 - 1) {
        return NULL;
    }
    qn += 1;
    char * query = (char *)ve_tls_calloc(1, qn);
    if (!query) {
        return NULL;
    }
    snprintf(query, qn, "TopicId=%s", encoded_topic_id);
    return query;
}

static const ve_tls_runtime_snapshot * ve_tls_snapshot_acquire_send_cfg(ve_tls_producer * producer, int64_t * out_version) {
    if (!producer || !out_version) {
        return NULL;
    }
    for (int i = 0; i < 4; i++) {
        int64_t want_version = __atomic_load_n(&producer->send_cfg_version, __ATOMIC_ACQUIRE);
        const ve_tls_runtime_snapshot * snapshot = ve_tls_runtime_snapshot_acquire(producer);
        if (!snapshot) {
            return NULL;
        }
        if (snapshot->send_cfg_version == want_version) {
            *out_version = want_version;
            return snapshot;
        }
        ve_tls_runtime_snapshot_release(snapshot);
    }
    return NULL;
}

static int ve_tls_send_cfg_cache_refresh(ve_tls_producer * producer, ve_tls_send_cfg_cache * out) {
    if (!producer || !out) {
        return -1;
    }
    ve_tls_send_cfg_cache next;
    memset(&next, 0, sizeof(next));
    const ve_tls_runtime_snapshot * snapshot = ve_tls_snapshot_acquire_send_cfg(producer, &next.version);
    if (!snapshot) {
        return -3;
    }
    next.endpoint = snapshot->endpoint ? ve_tls_strdup(snapshot->endpoint) : ve_tls_strdup("");
    next.topic_id = snapshot->topic_id ? ve_tls_strdup(snapshot->topic_id) : ve_tls_strdup("");
    next.region = snapshot->region ? ve_tls_strdup(snapshot->region) : ve_tls_strdup("");
    next.api_version = snapshot->api_version ? ve_tls_strdup(snapshot->api_version) : ve_tls_strdup(VE_TLS_C_SDK_API_VERSION);
    next.compress_type = snapshot->compress_type ? ve_tls_strdup(snapshot->compress_type) : ve_tls_strdup("none");
    next.default_hash_key = snapshot->default_hash_key ? ve_tls_strdup(snapshot->default_hash_key) : NULL;
    next.ca_cert_path = snapshot->ca_cert_path ? ve_tls_strdup(snapshot->ca_cert_path) : NULL;
    next.proxy = snapshot->proxy ? ve_tls_strdup(snapshot->proxy) : NULL;
    next.user_agent = snapshot->user_agent ? ve_tls_strdup(snapshot->user_agent) : NULL;
    next.connect_timeout_ms = snapshot->connect_timeout_ms;
    next.request_timeout_ms = snapshot->request_timeout_ms;
    next.tls_verify_peer = snapshot->tls_verify_peer;
    next.tls_verify_host = snapshot->tls_verify_host;
    next.http_debug = snapshot->http_debug;
    next.tcp_keepalive = snapshot->tcp_keepalive;
    next.tcp_keepidle = snapshot->tcp_keepidle;
    next.tcp_keepintvl = snapshot->tcp_keepintvl;
    ve_tls_runtime_snapshot_release(snapshot);

    if (!next.endpoint || !next.topic_id || !next.region || !next.api_version || !next.compress_type) {
        ve_tls_send_cfg_cache_free(&next);
        return -1;
    }
    char * encoded_topic_id = ve_tls_query_encode_value(next.topic_id);
    if (!encoded_topic_id) {
        ve_tls_send_cfg_cache_free(&next);
        return -2;
    }
    next.url = ve_tls_build_put_logs_url(next.endpoint, encoded_topic_id);
    next.host = ve_tls_extract_host(next.endpoint);
    next.query = ve_tls_build_topic_query(encoded_topic_id);
    ve_tls_free(encoded_topic_id);
    if (!next.url || !next.host || !next.query) {
        ve_tls_send_cfg_cache_free(&next);
        return -2;
    }
    next.producer = producer;
    ve_tls_send_cfg_cache_free(out);
    *out = next;
    return 0;
}

typedef struct {
    ve_tls_send_done_fn cb;
    void * cb_param;
    ve_tls_send_done_v2_fn cb2;
    void * cb2_param;
} ve_tls_send_callbacks;

static ve_tls_send_callbacks ve_tls_capture_callbacks(ve_tls_producer * producer) {
    ve_tls_send_callbacks out;
    memset(&out, 0, sizeof(out));
    if (!producer) {
        return out;
    }
    out.cb = __atomic_load_n(&producer->send_done, __ATOMIC_ACQUIRE);
    out.cb_param = __atomic_load_n(&producer->send_done_param, __ATOMIC_ACQUIRE);
    out.cb2 = __atomic_load_n(&producer->send_done_v2, __ATOMIC_ACQUIRE);
    out.cb2_param = __atomic_load_n(&producer->send_done_v2_param, __ATOMIC_ACQUIRE);
    return out;
}

static int ve_tls_sender_resolve_payload(ve_tls_producer * producer, const ve_tls_send_task * task, const unsigned char ** out_body, size_t * out_body_size, size_t * out_raw_body_size, const char ** out_compress_type) {
    if (!producer || !task || !out_body || !out_body_size || !out_raw_body_size || !out_compress_type) {
        return -1;
    }
    const unsigned char * body = task->body;
    size_t body_size = task->body_size;
    size_t raw_body_size = task->raw_body_size > 0 ? task->raw_body_size : task->body_size;
    const char * compress_type = "none";

    if (task->precompressed && task->precompressed_size > 0) {
        body = task->precompressed;
        body_size = task->precompressed_size;
        compress_type = producer->config.compress_type ? producer->config.compress_type : "none";
    }
    if (!body || body_size == 0) {
        return -1;
    }
    if (raw_body_size == 0) {
        raw_body_size = body_size;
    }

    *out_body = body;
    *out_body_size = body_size;
    *out_raw_body_size = raw_body_size;
    *out_compress_type = compress_type;
    return 0;
}

static int ve_tls_send_put_logs(ve_tls_producer * producer, const char * access_key_id, const char * access_key_secret, const char * security_token, const char * actual_compress_type, const unsigned char * body, size_t body_size, size_t raw_body_size, int32_t log_count, int64_t earliest, int64_t latest, const char * hash_key, ve_tls_error * out_error) {
    if (out_error) {
        ve_tls_error_free_fields(out_error);
    }
    if (!producer || !body || body_size == 0 || raw_body_size == 0) {
        ve_tls_error_set_client(out_error, "invalid request");
        return -1;
    }
    int64_t cfg_version = __atomic_load_n(&producer->send_cfg_version, __ATOMIC_ACQUIRE);
    if (g_send_cfg_cache.producer != producer || g_send_cfg_cache.version != cfg_version) {
        int cfg_rc = ve_tls_send_cfg_cache_refresh(producer, &g_send_cfg_cache);
        if (cfg_rc != 0) {
            if (cfg_rc == -2) {
                ve_tls_error_set_client(out_error, "build url failed");
            } else {
                ve_tls_error_set_client(out_error, "snapshot config failed");
            }
            return -1;
        }
    }
    const ve_tls_send_cfg_cache * cfg = &g_send_cfg_cache;
    if (!cfg->url || !cfg->host || !cfg->query) {
        ve_tls_error_set_client(out_error, "build url failed");
        return -1;
    }
    char * headers = NULL;
    size_t hlen = 0;
    size_t hcap = 0;
    int headers_pooled = 0;

    char raw_size[32];
    snprintf(raw_size, sizeof(raw_size), "%zu", raw_body_size);
    char count[32];
    snprintf(count, sizeof(count), "%d", log_count);
    char earliest_s[32];
    snprintf(earliest_s, sizeof(earliest_s), "%lld", (long long)earliest);
    char latest_s[32];
    snprintf(latest_s, sizeof(latest_s), "%lld", (long long)latest);
    const char * compress_type = actual_compress_type ? actual_compress_type : (cfg->compress_type ? cfg->compress_type : "none");
    unsigned char md5_raw[16];
    char content_md5[33];
    ve_tls_md5(body, body_size, md5_raw);
    ve_tls_hex_upper(md5_raw, sizeof(md5_raw), content_md5, sizeof(content_md5));

    if (ve_tls_headers_append(producer, &headers, &hlen, &hcap, &headers_pooled, "Content-Type", "application/x-protobuf") != 0 ||
        ve_tls_headers_append(producer, &headers, &hlen, &hcap, &headers_pooled, "Content-MD5", content_md5) != 0 ||
        ve_tls_headers_append(producer, &headers, &hlen, &hcap, &headers_pooled, "x-tls-apiversion", cfg->api_version ? cfg->api_version : VE_TLS_C_SDK_API_VERSION) != 0 ||
        ve_tls_headers_append(producer, &headers, &hlen, &hcap, &headers_pooled, "x-tls-bodyrawsize", raw_size) != 0 ||
        ve_tls_headers_append(producer, &headers, &hlen, &hcap, &headers_pooled, "x-tls-compresstype", compress_type) != 0) {
        ve_tls_header_buf_release(producer, headers, headers_pooled);
        ve_tls_error_set_client(out_error, "build headers failed");
        return -1;
    }
    const char * hk = hash_key;
    if (!hk || hk[0] == 0) {
        hk = cfg->default_hash_key;
    }
    if (!hk) {
        hk = "";
    }
    if (ve_tls_headers_append(producer, &headers, &hlen, &hcap, &headers_pooled, "x-tls-hashkey", hk) != 0) {
        ve_tls_header_buf_release(producer, headers, headers_pooled);
        ve_tls_error_set_client(out_error, "build headers failed");
        return -1;
    }

    char * signed_headers = NULL;
    int signed_pooled = 0;
    int sign_ok = ve_tls_sign_v4_append(
        access_key_id,
        access_key_secret,
        security_token,
        cfg->region ? cfg->region : "",
        "TLS",
        "POST",
        cfg->host ? cfg->host : "",
        "/PutLogs",
        cfg->query ? cfg->query : "",
        body,
        body_size,
        headers,
        &signed_headers
    );
    if (sign_ok != 0) {
        ve_tls_header_buf_release(producer, headers, headers_pooled);
        ve_tls_error_set_client(out_error, "sign request failed");
        return -1;
    }
    size_t signed_len = signed_headers ? strlen(signed_headers) : 0;
    size_t signed_cap = signed_len + 1;
    ve_tls_headers_try_use_pool(producer, &signed_headers, signed_len, &signed_cap, &signed_pooled);
    if (ve_tls_headers_append(producer, &signed_headers, &signed_len, &signed_cap, &signed_pooled, "log-count", count) != 0 ||
        ve_tls_headers_append(producer, &signed_headers, &signed_len, &signed_cap, &signed_pooled, "earliest-log-time", earliest_s) != 0 ||
        ve_tls_headers_append(producer, &signed_headers, &signed_len, &signed_cap, &signed_pooled, "latest-log-time", latest_s) != 0) {
        ve_tls_header_buf_release(producer, headers, headers_pooled);
        ve_tls_header_buf_release(producer, signed_headers, signed_pooled);
        ve_tls_error_set_client(out_error, "build headers failed");
        return -1;
    }

    ve_tls_http_request req;
    memset(&req, 0, sizeof(req));
    req.method = "POST";
    req.url = cfg->url;
    req.headers = signed_headers;
    req.body = body;
    req.body_size = body_size;
    req.timeout_ms = cfg->request_timeout_ms > 0 ? cfg->request_timeout_ms : 50000;
    req.connect_timeout_ms = cfg->connect_timeout_ms > 0 ? cfg->connect_timeout_ms : 10000;
    req.tls_verify_peer = cfg->tls_verify_peer;
    req.tls_verify_host = cfg->tls_verify_host;
    req.ca_cert_path = cfg->ca_cert_path;
    req.proxy = cfg->proxy;
    req.user_agent = cfg->user_agent;
    req.tcp_keepalive = cfg->tcp_keepalive;
    req.tcp_keepidle = cfg->tcp_keepidle;
    req.tcp_keepintvl = cfg->tcp_keepintvl;
    req.debug_log = cfg->http_debug;
    ve_tls_http_response resp;
    ve_tls_http_response_init(&resp);
    resp.transport_kind = VE_TLS_TRANSPORT_GENERIC;
    resp.transport_code = 0;
    resp.transport_retryable = 1;

    ve_tls_http_debug_log_request(&req);
    int rc = producer->config.http_client.do_request(&producer->config.http_client, &req, &resp);
    ve_tls_header_buf_release(producer, headers, headers_pooled);
    ve_tls_header_buf_release(producer, signed_headers, signed_pooled);

    if (rc != 0) {
        ve_tls_http_debug_log_failure(&req, &resp);
        if (out_error) {
            out_error->http_code = -1;
            out_error->transport_kind = resp.transport_kind ? resp.transport_kind : VE_TLS_TRANSPORT_GENERIC;
            out_error->transport_code = resp.transport_code;
            if (out_error->transport_kind == VE_TLS_TRANSPORT_CURL) {
                out_error->retryable = resp.transport_retryable ? 1 : 0;
            } else {
                out_error->retryable = 1;
            }
            out_error->error_code = resp.error_code ? ve_tls_strdup(resp.error_code) : ve_tls_strdup("ClientError");
            out_error->error_message = resp.error_message ? ve_tls_strdup(resp.error_message) : ve_tls_strdup("http request failed");
            out_error->request_id = resp.request_id ? ve_tls_strdup(resp.request_id) : NULL;
        }
        producer->config.http_client.free_response(&producer->config.http_client, &resp);
        return -1;
    }

    if (out_error) {
        ve_tls_error_set_http(out_error, resp.status_code);
        out_error->transport_kind = resp.transport_kind;
        out_error->transport_code = resp.transport_code;
        out_error->request_id = resp.request_id ? ve_tls_strdup(resp.request_id) : NULL;
        ve_tls_error_parse_body_fields(out_error, resp.body, resp.body_size);
        if (resp.status_code != 200) {
            if (!out_error->error_code) {
                out_error->error_code = ve_tls_strdup("BadResponse");
            }
            if (!out_error->error_message) {
                out_error->error_message = resp.body ? ve_tls_dup_body_limited(resp.body, resp.body_size) : ve_tls_strdup("non-200 response");
            }
        }
    }
    if (resp.status_code != 200) {
        ve_tls_http_debug_log_failure(&req, &resp);
        producer->config.http_client.free_response(&producer->config.http_client, &resp);
        return -1;
    }

    producer->config.http_client.free_response(&producer->config.http_client, &resp);
    return 0;
}

int ve_tls_sender_step(ve_tls_producer * producer) {
    if (!producer) {
        return 0;
    }
    ve_tls_send_task task;
    ve_tls_key_queue * kq = NULL;
    memset(&task, 0, sizeof(task));

    producer->config.platform.mutex_lock(producer->mutex);
    int64_t now0 = producer->config.platform.time_ms ? producer->config.platform.time_ms() : 0;
    ve_tls_delayed_promote_due(producer, now0);
    kq = ve_tls_ready_pop(producer);
    if (kq) {
        (void)ve_tls_key_queue_pop_task(kq, &task);
        producer->config.platform.mutex_unlock(producer->mutex);
        goto have_task;
    }
    producer->config.platform.mutex_unlock(producer->mutex);

    ve_tls_send_task inbound;
    memset(&inbound, 0, sizeof(inbound));
    if (ve_tls_sender_pop_send_queue_task(producer, &inbound, 0) == 0) {
        producer->config.platform.mutex_lock(producer->mutex);
        const char * nk = ve_tls_normalize_hash_key(producer, inbound.hash_key);
        if (ve_tls_key_queue_push_task(producer, nk, &inbound) != 0) {
            producer->config.platform.mutex_unlock(producer->mutex);
            ve_tls_metrics_emit(producer, "key_queue_drop", 1, 0);
            ve_tls_error derr;
            memset(&derr, 0, sizeof(derr));
            derr.http_code = -1;
            derr.transport_kind = VE_TLS_TRANSPORT_GENERIC;
            derr.transport_code = 0;
            derr.retryable = 0;
            derr.error_code = ve_tls_strdup("KeyQueueLimitExceeded");
            derr.error_message = ve_tls_strdup("key queue limit exceeded");
            ve_tls_send_callbacks cbs = ve_tls_capture_callbacks(producer);
            if (cbs.cb) {
                cbs.cb(VE_TLS_DROP_ERROR, inbound.batch_bytes, 0, NULL, derr.error_message, NULL, cbs.cb_param, inbound.start_id, inbound.end_id);
            }
            if (cbs.cb2) {
                cbs.cb2(VE_TLS_DROP_ERROR, inbound.batch_bytes, 0, &derr, NULL, cbs.cb2_param, inbound.start_id, inbound.end_id);
            }
            ve_tls_error_free_fields(&derr);
            ve_tls_sender_release_task(producer, &inbound);
        } else {
            producer->config.platform.cond_signal(producer->send_cond);
            producer->config.platform.mutex_unlock(producer->mutex);
        }
        if (producer->use_global_env) {
            ve_tls_env_notify(producer);
        }
        return 1;
    }
    return 0;

have_task: {
    const unsigned char * send_body_data = NULL;
    size_t send_body_size = 0;
    size_t raw_body_size = 0;
    const char * send_compress_type = "none";
    if (ve_tls_sender_resolve_payload(producer, &task, &send_body_data, &send_body_size, &raw_body_size, &send_compress_type) != 0) {
        ve_tls_error err;
        memset(&err, 0, sizeof(err));
        err.http_code = -1;
        err.transport_kind = VE_TLS_TRANSPORT_GENERIC;
        err.transport_code = 0;
        err.retryable = 0;
        err.error_code = ve_tls_strdup("ClientError");
        err.error_message = ve_tls_strdup("invalid send payload");
        ve_tls_send_callbacks cbs = ve_tls_capture_callbacks(producer);
        if (cbs.cb) {
            cbs.cb(VE_TLS_DROP_ERROR, task.batch_bytes, 0, NULL, err.error_message, NULL, cbs.cb_param, task.start_id, task.end_id);
        }
        if (cbs.cb2) {
            cbs.cb2(VE_TLS_DROP_ERROR, task.batch_bytes, 0, &err, NULL, cbs.cb2_param, task.start_id, task.end_id);
        }
        ve_tls_error_free_fields(&err);
        ve_tls_sender_release_task(producer, &task);
        producer->config.platform.mutex_lock(producer->mutex);
        ve_tls_key_queue_finish(producer, kq);
        producer->config.platform.mutex_unlock(producer->mutex);
        if (producer->use_global_env) {
            ve_tls_env_notify(producer);
        }
        return 1;
    }

    int32_t attempt = 0;
    int64_t start_time = producer->config.platform.time_ms ? producer->config.platform.time_ms() : 0;
    ve_tls_error err;
    memset(&err, 0, sizeof(err));
    int sent_ok = 0;
    int entered_breaker = 0;
    int half_open_guard = 0;
    for (;;) {
        attempt++;
        ve_tls_error_free_fields(&err);

        int64_t gate_now = producer->config.platform.time_ms ? producer->config.platform.time_ms() : 0;
        int64_t next_bk = 0;
        int64_t next_rl = 0;
        int allow_bk = ve_tls_key_breaker_allow(producer, kq, gate_now, &next_bk);
        int allow_rl = ve_tls_key_rate_limit_reserve(producer, kq, send_body_size, gate_now, &next_rl);
        if (!allow_bk || !allow_rl) {
            int64_t next = next_bk > next_rl ? next_bk : next_rl;
            if (next <= 0) {
                next = gate_now + 10;
            }
            producer->config.platform.mutex_lock(producer->mutex);
            (void)ve_tls_key_queue_push_front_task(kq, &task);
            memset(&task, 0, sizeof(task));
            kq->inflight = 0;
            ve_tls_delayed_add_sorted(producer, kq, next);
            producer->config.platform.cond_signal(producer->send_cond);
            producer->config.platform.mutex_unlock(producer->mutex);
            ve_tls_error_free_fields(&err);
            if (producer->use_global_env) {
                ve_tls_env_notify(producer);
            }
            return 1;
        }

        if (!entered_breaker) {
            for (;;) {
                ve_tls_breaker_wait_open(producer);
                int bo = ve_tls_breaker_try_enter_half_open(producer);
                if (bo == 1) {
                    half_open_guard = 0;
                    entered_breaker = 1;
                    break;
                }
                if (bo == 2) {
                    half_open_guard = 1;
                    entered_breaker = 1;
                    break;
                }
                producer->config.platform.sleep_ms(10);
            }
        }

        ve_tls_rate_limit_wait(producer, send_body_size);
        ve_tls_metric_inc_u64(&producer->m_requests_total, 1);
        ve_tls_metrics_emit(producer, "request_attempt", 1, 0);
        int64_t attempt_start = producer->config.platform.time_ms ? producer->config.platform.time_ms() : 0;
        const char * ak = NULL;
        const char * sk = NULL;
        const char * token = NULL;
        ve_tls_owned_credentials owned_creds;
        if (ve_tls_get_signing_credentials(producer, attempt_start, &ak, &sk, &token, &owned_creds) != 0) {
            ve_tls_error_free_fields(&err);
            err.http_code = -1;
            err.transport_kind = VE_TLS_TRANSPORT_GENERIC;
            err.transport_code = 0;
            err.retryable = 0;
            err.error_code = ve_tls_strdup("CredentialsRefreshFailed");
            err.error_message = ve_tls_strdup("credentials refresh failed");
            break;
        }
        int rc = ve_tls_send_put_logs(producer, ak, sk, token, send_compress_type, send_body_data, send_body_size, raw_body_size, task.log_count, task.earliest, task.latest, task.hash_key, &err);
        ve_tls_owned_credentials_free(&owned_creds);
        int64_t attempt_end = producer->config.platform.time_ms ? producer->config.platform.time_ms() : 0;
        int64_t attempt_ms = attempt_end - attempt_start;
        if (attempt_ms < 0) {
            attempt_ms = 0;
        }
        int bi = ve_tls_latency_bucket_index(attempt_ms);
        ve_tls_metric_inc_u64(&producer->m_latency_buckets[bi], 1);
        ve_tls_metrics_emit(producer, "request_latency_ms", attempt_ms, err.http_code);
        if (rc == 0) {
            sent_ok = 1;
            break;
        }
        int64_t now2 = producer->config.platform.time_ms ? producer->config.platform.time_ms() : 0;
        int64_t elapsed = now2 - start_time;
        if (!err.retryable) {
            break;
        }
        if (producer->config.retry_policy.max_attempts > 0 && attempt >= producer->config.retry_policy.max_attempts) {
            break;
        }
        if (producer->config.retry_policy.total_timeout_ms > 0 && elapsed >= producer->config.retry_policy.total_timeout_ms) {
            break;
        }
        ve_tls_metric_inc_u64(&producer->m_retries_total, 1);
        ve_tls_metrics_emit(producer, "retry", attempt, err.http_code);
        int64_t delay = ve_tls_retry_next_interval_ms(&producer->config.retry_policy, attempt);
        if (producer->config.retry_policy.total_timeout_ms > 0 && elapsed + delay > producer->config.retry_policy.total_timeout_ms) {
            delay = producer->config.retry_policy.total_timeout_ms - elapsed;
        }
        producer->config.platform.sleep_ms(delay);
    }
    int64_t total_end = producer->config.platform.time_ms ? producer->config.platform.time_ms() : 0;
    int64_t total_ms = total_end - start_time;
    if (total_ms < 0) {
        total_ms = 0;
    }
    if (sent_ok) {
        ve_tls_metric_inc_u64(&producer->m_bytes_sent_total, send_body_size);
        ve_tls_metrics_emit(producer, "send_ok", total_ms, send_body_size);
        ve_tls_send_callbacks cbs = ve_tls_capture_callbacks(producer);
        if (cbs.cb) {
            cbs.cb(VE_TLS_OK, task.batch_bytes, send_body_size, err.request_id, NULL, NULL, cbs.cb_param, task.start_id, task.end_id);
        }
        if (cbs.cb2) {
            cbs.cb2(VE_TLS_OK, task.batch_bytes, send_body_size, &err, NULL, cbs.cb2_param, task.start_id, task.end_id);
        }
    } else {
        ve_tls_metric_inc_u64(&producer->m_requests_failed_total, 1);
        ve_tls_metrics_emit(producer, "send_failed", total_ms, err.http_code);
        char * msg = ve_tls_error_build_message(&err);
        ve_tls_send_callbacks cbs = ve_tls_capture_callbacks(producer);
        if (cbs.cb) {
            cbs.cb(VE_TLS_DROP_ERROR, task.batch_bytes, send_body_size, err.request_id, msg, NULL, cbs.cb_param, task.start_id, task.end_id);
        }
        if (cbs.cb2) {
            cbs.cb2(VE_TLS_DROP_ERROR, task.batch_bytes, send_body_size, &err, NULL, cbs.cb2_param, task.start_id, task.end_id);
        }
        ve_tls_free(msg);
    }
    if (entered_breaker) {
        if (half_open_guard) {
            ve_tls_breaker_leave_half_open(producer, sent_ok ? 1 : 0);
        } else {
            ve_tls_breaker_on_final_result(producer, sent_ok ? 1 : 0);
        }
    }
    ve_tls_key_breaker_on_final_result(producer, kq, sent_ok ? 1 : 0);
    ve_tls_error_free_fields(&err);
    ve_tls_sender_release_task(producer, &task);
    producer->config.platform.mutex_lock(producer->mutex);
    ve_tls_key_queue_finish(producer, kq);
    producer->config.platform.mutex_unlock(producer->mutex);
    if (producer->use_global_env) {
        ve_tls_env_notify(producer);
    }
    return 1;
}
}

static void * ve_tls_sender_main_fast(void * arg) {
    ve_tls_producer * producer = (ve_tls_producer *)arg;
    for (;;) {
        ve_tls_send_task task;
        memset(&task, 0, sizeof(task));
        if (ve_tls_sender_pop_send_queue_task(producer, &task, -1) != 0) {
            ve_tls_sender_thread_cache_clear();
            return NULL;
        }
        (void)__atomic_fetch_add(&producer->fast_inflight, 1, __ATOMIC_RELAXED);

        const unsigned char * send_body_data = NULL;
        size_t send_body_size = 0;
        size_t raw_body_size = 0;
        const char * send_compress_type = "none";
        if (ve_tls_sender_resolve_payload(producer, &task, &send_body_data, &send_body_size, &raw_body_size, &send_compress_type) != 0) {
            ve_tls_error err;
            memset(&err, 0, sizeof(err));
            err.http_code = -1;
            err.transport_kind = VE_TLS_TRANSPORT_GENERIC;
            err.transport_code = 0;
            err.retryable = 0;
            err.error_code = ve_tls_strdup("ClientError");
            err.error_message = ve_tls_strdup("invalid send payload");
            ve_tls_send_callbacks cbs = ve_tls_capture_callbacks(producer);
            if (cbs.cb) {
                cbs.cb(VE_TLS_DROP_ERROR, task.batch_bytes, 0, NULL, err.error_message, NULL, cbs.cb_param, task.start_id, task.end_id);
            }
            if (cbs.cb2) {
                cbs.cb2(VE_TLS_DROP_ERROR, task.batch_bytes, 0, &err, NULL, cbs.cb2_param, task.start_id, task.end_id);
            }
            ve_tls_error_free_fields(&err);
            ve_tls_sender_release_task(producer, &task);
            (void)__atomic_fetch_sub(&producer->fast_inflight, 1, __ATOMIC_RELAXED);
            continue;
        }

        int32_t attempt = 0;
        int64_t start_time = producer->config.platform.time_ms ? producer->config.platform.time_ms() : 0;
        ve_tls_error err;
        memset(&err, 0, sizeof(err));
        int sent_ok = 0;
        for (;;) {
            attempt++;
            ve_tls_error_free_fields(&err);
            ve_tls_metric_inc_u64(&producer->m_requests_total, 1);
            ve_tls_metrics_emit(producer, "request_attempt", 1, 0);
            int64_t attempt_start = producer->config.platform.time_ms ? producer->config.platform.time_ms() : 0;
            const char * ak = NULL;
            const char * sk = NULL;
            const char * token = NULL;
            ve_tls_owned_credentials owned_creds;
            if (ve_tls_get_signing_credentials(producer, attempt_start, &ak, &sk, &token, &owned_creds) != 0) {
                ve_tls_error_free_fields(&err);
                err.http_code = -1;
                err.transport_kind = VE_TLS_TRANSPORT_GENERIC;
                err.transport_code = 0;
                err.retryable = 0;
                err.error_code = ve_tls_strdup("CredentialsRefreshFailed");
                err.error_message = ve_tls_strdup("credentials refresh failed");
                break;
            }
            int rc = ve_tls_send_put_logs(producer, ak, sk, token, send_compress_type, send_body_data, send_body_size, raw_body_size, task.log_count, task.earliest, task.latest, task.hash_key, &err);
            ve_tls_owned_credentials_free(&owned_creds);
            int64_t attempt_end = producer->config.platform.time_ms ? producer->config.platform.time_ms() : 0;
            int64_t attempt_ms = attempt_end - attempt_start;
            if (attempt_ms < 0) {
                attempt_ms = 0;
            }
            int bi = ve_tls_latency_bucket_index(attempt_ms);
            ve_tls_metric_inc_u64(&producer->m_latency_buckets[bi], 1);
            ve_tls_metrics_emit(producer, "request_latency_ms", attempt_ms, err.http_code);
            if (rc == 0) {
                sent_ok = 1;
                break;
            }
            int64_t now2 = producer->config.platform.time_ms ? producer->config.platform.time_ms() : 0;
            int64_t elapsed = now2 - start_time;
            if (!err.retryable) {
                break;
            }
            if (producer->config.retry_policy.max_attempts > 0 && attempt >= producer->config.retry_policy.max_attempts) {
                break;
            }
            if (producer->config.retry_policy.total_timeout_ms > 0 && elapsed >= producer->config.retry_policy.total_timeout_ms) {
                break;
            }
            ve_tls_metric_inc_u64(&producer->m_retries_total, 1);
            ve_tls_metrics_emit(producer, "retry", attempt, err.http_code);
            int64_t delay = ve_tls_retry_next_interval_ms(&producer->config.retry_policy, attempt);
            if (producer->config.retry_policy.total_timeout_ms > 0 && elapsed + delay > producer->config.retry_policy.total_timeout_ms) {
                delay = producer->config.retry_policy.total_timeout_ms - elapsed;
            }
            producer->config.platform.sleep_ms(delay);
        }
        int64_t total_end = producer->config.platform.time_ms ? producer->config.platform.time_ms() : 0;
        int64_t total_ms = total_end - start_time;
        if (total_ms < 0) {
            total_ms = 0;
        }
        if (sent_ok) {
            ve_tls_metric_inc_u64(&producer->m_bytes_sent_total, send_body_size);
            ve_tls_metrics_emit(producer, "send_ok", total_ms, send_body_size);
            ve_tls_send_callbacks cbs = ve_tls_capture_callbacks(producer);
            if (cbs.cb) {
                cbs.cb(VE_TLS_OK, task.batch_bytes, send_body_size, err.request_id, NULL, NULL, cbs.cb_param, task.start_id, task.end_id);
            }
            if (cbs.cb2) {
                cbs.cb2(VE_TLS_OK, task.batch_bytes, send_body_size, &err, NULL, cbs.cb2_param, task.start_id, task.end_id);
            }
        } else {
            ve_tls_metric_inc_u64(&producer->m_requests_failed_total, 1);
            ve_tls_metrics_emit(producer, "send_failed", total_ms, err.http_code);
            char * msg = ve_tls_error_build_message(&err);
            ve_tls_send_callbacks cbs = ve_tls_capture_callbacks(producer);
            if (cbs.cb) {
                cbs.cb(VE_TLS_DROP_ERROR, task.batch_bytes, send_body_size, err.request_id, msg, NULL, cbs.cb_param, task.start_id, task.end_id);
            }
            if (cbs.cb2) {
                cbs.cb2(VE_TLS_DROP_ERROR, task.batch_bytes, send_body_size, &err, NULL, cbs.cb2_param, task.start_id, task.end_id);
            }
            ve_tls_free(msg);
        }
        ve_tls_error_free_fields(&err);
        ve_tls_sender_release_task(producer, &task);
        (void)__atomic_fetch_sub(&producer->fast_inflight, 1, __ATOMIC_RELAXED);
    }
}

void * ve_tls_sender_main(void * arg) {
    ve_tls_producer * producer = (ve_tls_producer *)arg;
    if (producer && producer->fast_send) {
        return ve_tls_sender_main_fast(arg);
    }
    for (;;) {
        ve_tls_send_task task;
        ve_tls_key_queue * kq = NULL;
next_task:
        memset(&task, 0, sizeof(task));
        kq = NULL;
        producer->config.platform.mutex_lock(producer->mutex);
        for (;;) {
            int64_t now0 = producer->config.platform.time_ms ? producer->config.platform.time_ms() : 0;
            int wait_sendq_ms = 0;
            ve_tls_delayed_promote_due(producer, now0);
            kq = ve_tls_ready_pop(producer);
            if (kq) {
                (void)ve_tls_key_queue_pop_task(kq, &task);
                break;
            }
            if (!producer->delayed_head && !producer->stop) {
                wait_sendq_ms = -1;
            }
            producer->config.platform.mutex_unlock(producer->mutex);
            ve_tls_send_task inbound;
            memset(&inbound, 0, sizeof(inbound));
            if (ve_tls_sender_pop_send_queue_task(producer, &inbound, wait_sendq_ms) == 0) {
                producer->config.platform.mutex_lock(producer->mutex);
                const char * nk = ve_tls_normalize_hash_key(producer, inbound.hash_key);
                if (ve_tls_key_queue_push_task(producer, nk, &inbound) != 0) {
                    producer->config.platform.mutex_unlock(producer->mutex);
                    ve_tls_metrics_emit(producer, "key_queue_drop", 1, 0);
                    ve_tls_error derr;
                    memset(&derr, 0, sizeof(derr));
                    derr.http_code = -1;
                    derr.transport_kind = VE_TLS_TRANSPORT_GENERIC;
                    derr.transport_code = 0;
                    derr.retryable = 0;
                    derr.error_code = ve_tls_strdup("KeyQueueLimitExceeded");
                    derr.error_message = ve_tls_strdup("key queue limit exceeded");
                    ve_tls_send_callbacks cbs = ve_tls_capture_callbacks(producer);
                    if (cbs.cb) {
                        cbs.cb(VE_TLS_DROP_ERROR, inbound.batch_bytes, 0, NULL, derr.error_message, NULL, cbs.cb_param, inbound.start_id, inbound.end_id);
                    }
                    if (cbs.cb2) {
                        cbs.cb2(VE_TLS_DROP_ERROR, inbound.batch_bytes, 0, &derr, NULL, cbs.cb2_param, inbound.start_id, inbound.end_id);
                    }
                    ve_tls_error_free_fields(&derr);
                    ve_tls_sender_release_task(producer, &inbound);
                } else {
                    producer->config.platform.cond_signal(producer->send_cond);
                    producer->config.platform.mutex_unlock(producer->mutex);
                }
                producer->config.platform.mutex_lock(producer->mutex);
                continue;
            }
            producer->config.platform.mutex_lock(producer->mutex);
            if (producer->stop && !producer->ready_head) {
                int pending = 0;
                if (producer->key_buckets) {
                    for (size_t bi = 0; bi < producer->key_bucket_count; bi++) {
                        for (ve_tls_key_queue * q = producer->key_buckets[bi]; q; q = q->hnext) {
                            if (q->count > 0 || q->inflight > 0) {
                                pending = 1;
                                break;
                            }
                        }
                        if (pending) {
                            break;
                        }
                    }
                }
                producer->config.platform.mutex_unlock(producer->mutex);
                ve_tls_send_task tail;
                memset(&tail, 0, sizeof(tail));
                int have_sendq = (ve_tls_sender_pop_send_queue_task(producer, &tail, 0) == 0);
                if (have_sendq) {
                    producer->config.platform.mutex_lock(producer->mutex);
                    const char * nk = ve_tls_normalize_hash_key(producer, tail.hash_key);
                    if (ve_tls_key_queue_push_task(producer, nk, &tail) != 0) {
                        producer->config.platform.mutex_unlock(producer->mutex);
                        ve_tls_metrics_emit(producer, "key_queue_drop", 1, 0);
                        ve_tls_error derr;
                        memset(&derr, 0, sizeof(derr));
                        derr.http_code = -1;
                        derr.transport_kind = VE_TLS_TRANSPORT_GENERIC;
                        derr.transport_code = 0;
                        derr.retryable = 0;
                        derr.error_code = ve_tls_strdup("KeyQueueLimitExceeded");
                        derr.error_message = ve_tls_strdup("key queue limit exceeded");
                        ve_tls_send_callbacks cbs = ve_tls_capture_callbacks(producer);
                        if (cbs.cb) {
                            cbs.cb(VE_TLS_DROP_ERROR, tail.batch_bytes, 0, NULL, derr.error_message, NULL, cbs.cb_param, tail.start_id, tail.end_id);
                        }
                        if (cbs.cb2) {
                            cbs.cb2(VE_TLS_DROP_ERROR, tail.batch_bytes, 0, &derr, NULL, cbs.cb2_param, tail.start_id, tail.end_id);
                        }
                        ve_tls_error_free_fields(&derr);
                        ve_tls_sender_release_task(producer, &tail);
                    } else {
                        producer->config.platform.cond_signal(producer->send_cond);
                        producer->config.platform.mutex_unlock(producer->mutex);
                    }
                    producer->config.platform.mutex_lock(producer->mutex);
                    continue;
                }
                producer->config.platform.mutex_lock(producer->mutex);
                if (!pending) {
                    producer->config.platform.mutex_unlock(producer->mutex);
                    ve_tls_sender_thread_cache_clear();
                    return NULL;
                }
            }
            int64_t now1 = producer->config.platform.time_ms ? producer->config.platform.time_ms() : 0;
            if (now1 > 0 && now1 >= producer->idle_cleanup_next_ms) {
                producer->idle_cleanup_next_ms = now1 + 1000;
                ve_tls_idle_cleanup(producer);
            }
            if (!producer->delayed_head) {
                if (producer->stop) {
                    (void)producer->config.platform.cond_timedwait_ms(producer->send_cond, producer->mutex, 100);
                }
                continue;
            }
            int64_t deadline = producer->delayed_head->next_ready_ms;
            int64_t wait_ms = deadline - now1;
            if (wait_ms < 1) {
                wait_ms = 1;
            }
            (void)producer->config.platform.cond_timedwait_ms(producer->send_cond, producer->mutex, wait_ms);
        }
        producer->config.platform.mutex_unlock(producer->mutex);

        const unsigned char * send_body_data = NULL;
        size_t send_body_size = 0;
        size_t raw_body_size = 0;
        const char * send_compress_type = "none";
        if (ve_tls_sender_resolve_payload(producer, &task, &send_body_data, &send_body_size, &raw_body_size, &send_compress_type) != 0) {
            ve_tls_error err;
            memset(&err, 0, sizeof(err));
            err.http_code = -1;
            err.transport_kind = VE_TLS_TRANSPORT_GENERIC;
            err.transport_code = 0;
            err.retryable = 0;
            err.error_code = ve_tls_strdup("ClientError");
            err.error_message = ve_tls_strdup("invalid send payload");
            ve_tls_send_callbacks cbs = ve_tls_capture_callbacks(producer);
            if (cbs.cb) {
                cbs.cb(VE_TLS_DROP_ERROR, task.batch_bytes, 0, NULL, err.error_message, NULL, cbs.cb_param, task.start_id, task.end_id);
            }
            if (cbs.cb2) {
                cbs.cb2(VE_TLS_DROP_ERROR, task.batch_bytes, 0, &err, NULL, cbs.cb2_param, task.start_id, task.end_id);
            }
            ve_tls_error_free_fields(&err);
            ve_tls_sender_release_task(producer, &task);
            producer->config.platform.mutex_lock(producer->mutex);
            ve_tls_key_queue_finish(producer, kq);
            producer->config.platform.mutex_unlock(producer->mutex);
            continue;
        }

        int32_t attempt = 0;
        int64_t start_time = producer->config.platform.time_ms ? producer->config.platform.time_ms() : 0;
        ve_tls_error err;
        memset(&err, 0, sizeof(err));
        int sent_ok = 0;
        int entered_breaker = 0;
        int half_open_guard = 0;
        for (;;) {
            attempt++;
            ve_tls_error_free_fields(&err);

            int64_t gate_now = producer->config.platform.time_ms ? producer->config.platform.time_ms() : 0;
            int64_t next_bk = 0;
            int64_t next_rl = 0;
            int allow_bk = ve_tls_key_breaker_allow(producer, kq, gate_now, &next_bk);
            int allow_rl = ve_tls_key_rate_limit_reserve(producer, kq, send_body_size, gate_now, &next_rl);
            if (!allow_bk || !allow_rl) {
                int64_t next = next_bk > next_rl ? next_bk : next_rl;
                if (next <= 0) {
                    next = gate_now + 10;
                }
                producer->config.platform.mutex_lock(producer->mutex);
                (void)ve_tls_key_queue_push_front_task(kq, &task);
                memset(&task, 0, sizeof(task));
                kq->inflight = 0;
                ve_tls_delayed_add_sorted(producer, kq, next);
                producer->config.platform.cond_signal(producer->send_cond);
                producer->config.platform.mutex_unlock(producer->mutex);
                ve_tls_error_free_fields(&err);
                goto next_task;
            }

            if (!entered_breaker) {
                for (;;) {
                    ve_tls_breaker_wait_open(producer);
                    int bo = ve_tls_breaker_try_enter_half_open(producer);
                    if (bo == 1) {
                        half_open_guard = 0;
                        entered_breaker = 1;
                        break;
                    }
                    if (bo == 2) {
                        half_open_guard = 1;
                        entered_breaker = 1;
                        break;
                    }
                    producer->config.platform.sleep_ms(10);
                }
            }

            ve_tls_rate_limit_wait(producer, send_body_size);
            ve_tls_metric_inc_u64(&producer->m_requests_total, 1);
            ve_tls_metrics_emit(producer, "request_attempt", 1, 0);
            int64_t attempt_start = producer->config.platform.time_ms ? producer->config.platform.time_ms() : 0;
            const char * ak = NULL;
            const char * sk = NULL;
            const char * token = NULL;
            ve_tls_owned_credentials owned_creds;
            if (ve_tls_get_signing_credentials(producer, attempt_start, &ak, &sk, &token, &owned_creds) != 0) {
                ve_tls_error_free_fields(&err);
                err.http_code = -1;
                err.transport_kind = VE_TLS_TRANSPORT_GENERIC;
                err.transport_code = 0;
                err.retryable = 0;
                err.error_code = ve_tls_strdup("CredentialsRefreshFailed");
                err.error_message = ve_tls_strdup("credentials refresh failed");
                break;
            }
            int rc = ve_tls_send_put_logs(producer, ak, sk, token, send_compress_type, send_body_data, send_body_size, raw_body_size, task.log_count, task.earliest, task.latest, task.hash_key, &err);
            ve_tls_owned_credentials_free(&owned_creds);
            int64_t attempt_end = producer->config.platform.time_ms ? producer->config.platform.time_ms() : 0;
            int64_t attempt_ms = attempt_end - attempt_start;
            if (attempt_ms < 0) {
                attempt_ms = 0;
            }
            int bi = ve_tls_latency_bucket_index(attempt_ms);
            ve_tls_metric_inc_u64(&producer->m_latency_buckets[bi], 1);
            ve_tls_metrics_emit(producer, "request_latency_ms", attempt_ms, err.http_code);
            if (rc == 0) {
                sent_ok = 1;
                break;
            }
            int64_t now2 = producer->config.platform.time_ms ? producer->config.platform.time_ms() : 0;
            int64_t elapsed = now2 - start_time;
            if (!err.retryable) {
                break;
            }
            if (producer->config.retry_policy.max_attempts > 0 && attempt >= producer->config.retry_policy.max_attempts) {
                break;
            }
            if (producer->config.retry_policy.total_timeout_ms > 0 && elapsed >= producer->config.retry_policy.total_timeout_ms) {
                break;
            }
            ve_tls_metric_inc_u64(&producer->m_retries_total, 1);
            ve_tls_metrics_emit(producer, "retry", attempt, err.http_code);
            int64_t delay = ve_tls_retry_next_interval_ms(&producer->config.retry_policy, attempt);
            if (producer->config.retry_policy.total_timeout_ms > 0 && elapsed + delay > producer->config.retry_policy.total_timeout_ms) {
                delay = producer->config.retry_policy.total_timeout_ms - elapsed;
            }
            producer->config.platform.sleep_ms(delay);
        }
        int64_t total_end = producer->config.platform.time_ms ? producer->config.platform.time_ms() : 0;
        int64_t total_ms = total_end - start_time;
        if (total_ms < 0) {
            total_ms = 0;
        }
        if (sent_ok) {
            ve_tls_metric_inc_u64(&producer->m_bytes_sent_total, send_body_size);
            ve_tls_metrics_emit(producer, "send_ok", total_ms, send_body_size);
            ve_tls_send_callbacks cbs = ve_tls_capture_callbacks(producer);
            if (cbs.cb) {
                cbs.cb(VE_TLS_OK, task.batch_bytes, send_body_size, err.request_id, NULL, NULL, cbs.cb_param, task.start_id, task.end_id);
            }
            if (cbs.cb2) {
                cbs.cb2(VE_TLS_OK, task.batch_bytes, send_body_size, &err, NULL, cbs.cb2_param, task.start_id, task.end_id);
            }
        } else {
            ve_tls_metric_inc_u64(&producer->m_requests_failed_total, 1);
            ve_tls_metrics_emit(producer, "send_failed", total_ms, err.http_code);
            char * msg = ve_tls_error_build_message(&err);
            ve_tls_send_callbacks cbs = ve_tls_capture_callbacks(producer);
            if (cbs.cb) {
                cbs.cb(VE_TLS_DROP_ERROR, task.batch_bytes, send_body_size, err.request_id, msg, NULL, cbs.cb_param, task.start_id, task.end_id);
            }
            if (cbs.cb2) {
                cbs.cb2(VE_TLS_DROP_ERROR, task.batch_bytes, send_body_size, &err, NULL, cbs.cb2_param, task.start_id, task.end_id);
            }
            ve_tls_free(msg);
        }
        if (entered_breaker) {
            if (half_open_guard) {
                ve_tls_breaker_leave_half_open(producer, sent_ok ? 1 : 0);
            } else {
                ve_tls_breaker_on_final_result(producer, sent_ok ? 1 : 0);
            }
        }
        ve_tls_key_breaker_on_final_result(producer, kq, sent_ok ? 1 : 0);
        ve_tls_error_free_fields(&err);
        ve_tls_sender_release_task(producer, &task);
        producer->config.platform.mutex_lock(producer->mutex);
        ve_tls_key_queue_finish(producer, kq);
        producer->config.platform.mutex_unlock(producer->mutex);
    }
    ve_tls_sender_thread_cache_clear();
    return NULL;
}
