#include "producer/ve_tls_producer_internal.h"
#include "ve_tls_env.h"
#include "ve_tls_alloc.h"

#include <stdlib.h>
#include <string.h>

static int ve_tls_str_empty(const char * s) {
    return !s || s[0] == 0;
}

static char * ve_tls_dup_cstr(const char * s) {
    return s ? ve_tls_strdup(s) : NULL;
}

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

static int ve_tls_copy_log_tags(const ve_tls_kv * tags, size_t count, ve_tls_kv ** out_tags, size_t * out_count) {
    *out_tags = NULL;
    *out_count = 0;
    if (!tags || count == 0) {
        return 0;
    }
    ve_tls_kv * copy = (ve_tls_kv *)ve_tls_calloc(count, sizeof(ve_tls_kv));
    if (!copy) {
        return -1;
    }
    for (size_t i = 0; i < count; i++) {
        copy[i].key = ve_tls_dup_cstr(tags[i].key);
        copy[i].value = ve_tls_dup_cstr(tags[i].value);
        if ((tags[i].key && !copy[i].key) || (tags[i].value && !copy[i].value)) {
            for (size_t j = 0; j <= i; j++) {
                ve_tls_free((void *)copy[j].key);
                ve_tls_free((void *)copy[j].value);
            }
            ve_tls_free(copy);
            return -1;
        }
    }
    *out_tags = copy;
    *out_count = count;
    return 0;
}

static int ve_tls_is_http_url(const char * s) {
    if (ve_tls_str_empty(s)) return 0;
    return strncmp(s, "http://", 7) == 0 || strncmp(s, "https://", 8) == 0;
}

static int ve_tls_config_is_valid_for_create(const ve_tls_config * cfg) {
    if (!cfg) return 0;
    if (!ve_tls_is_http_url(cfg->endpoint)) return 0;
    if (ve_tls_str_empty(cfg->region)) return 0;
    if (ve_tls_str_empty(cfg->topic_id)) return 0;
    if (!cfg->credentials_provider) {
        if (ve_tls_str_empty(cfg->access_key_id) || ve_tls_str_empty(cfg->access_key_secret)) return 0;
    }
    return 1;
}

typedef struct {
    ve_tls_send_done_fn cb;
    void * cb_param;
    ve_tls_send_done_v2_fn cb2;
    void * cb2_param;
} ve_tls_send_callbacks;

static ve_tls_send_callbacks ve_tls_capture_callbacks(ve_tls_producer * producer) {
    ve_tls_send_callbacks cbs;
    memset(&cbs, 0, sizeof(cbs));
    if (!producer) {
        return cbs;
    }
    cbs.cb = producer->send_done;
    cbs.cb_param = producer->send_done_param;
    cbs.cb2 = producer->send_done_v2;
    cbs.cb2_param = producer->send_done_v2_param;
    return cbs;
}

static void ve_tls_drop_one_with_error(ve_tls_send_callbacks cbs, size_t bytes, int64_t id, const char * code, const char * message) {
    ve_tls_error err;
    memset(&err, 0, sizeof(err));
    err.http_code = -1;
    err.transport_kind = VE_TLS_TRANSPORT_GENERIC;
    err.transport_code = 0;
    err.retryable = 0;
    err.error_code = (code && code[0] != 0) ? ve_tls_strdup(code) : ve_tls_strdup("ClientError");
    err.error_message = (message && message[0] != 0) ? ve_tls_strdup(message) : ve_tls_strdup("drop");
    if (cbs.cb) {
        cbs.cb(VE_TLS_DROP_ERROR, bytes, 0, NULL, err.error_message, NULL, cbs.cb_param, id, id);
    }
    if (cbs.cb2) {
        cbs.cb2(VE_TLS_DROP_ERROR, bytes, 0, &err, NULL, cbs.cb2_param, id, id);
    }
    ve_tls_error_free_fields(&err);
}

int ve_tls_producer_is_drained_locked(ve_tls_producer * producer) {
    if (!producer) {
        return 1;
    }
    if (producer->queue_count != 0 || producer->worker_flushing || producer->sealed_head) {
        return 0;
    }
    if (producer->send_queue.mutex) {
        producer->send_queue.platform->mutex_lock(producer->send_queue.mutex);
        size_t sc = producer->send_queue.count;
        producer->send_queue.platform->mutex_unlock(producer->send_queue.mutex);
        if (sc != 0) {
            return 0;
        }
    }
    for (size_t i = 0; i < producer->key_bucket_count; i++) {
        ve_tls_key_queue * q = producer->key_buckets[i];
        while (q) {
            if (q->count != 0 || q->inflight != 0 || (q->builder && q->builder->log_count > 0)) {
                return 0;
            }
            q = q->hnext;
        }
    }
    return 1;
}

void ve_tls_config_init(ve_tls_config * config) {
    ve_tls_producer_config_init(config);
}

ve_tls_producer * ve_tls_producer_create(const ve_tls_config * config) {
    if (!config) {
        return NULL;
    }
    if (!ve_tls_config_is_valid_for_create(config)) {
        return NULL;
    }
    ve_tls_producer * producer = (ve_tls_producer *)ve_tls_calloc(1, sizeof(ve_tls_producer));
    if (!producer) {
        return NULL;
    }
    producer->config = *config;
    producer->cfg_endpoint = ve_tls_strdup(config->endpoint);
    producer->cfg_region = ve_tls_strdup(config->region);
    producer->cfg_project_id = ve_tls_dup_cstr(config->project_id);
    producer->cfg_topic_id = ve_tls_strdup(config->topic_id);
    producer->cfg_source = ve_tls_dup_cstr(config->source);
    producer->cfg_file_name = ve_tls_dup_cstr(config->file_name);
    producer->cfg_context_flow = ve_tls_dup_cstr(config->context_flow);
    producer->cfg_hash_key = ve_tls_dup_cstr(config->hash_key);
    producer->cfg_access_key_id = config->access_key_id ? ve_tls_strdup(config->access_key_id) : NULL;
    producer->cfg_access_key_secret = config->access_key_secret ? ve_tls_strdup(config->access_key_secret) : NULL;
    producer->cfg_security_token = (config->security_token && config->security_token[0] != 0) ? ve_tls_strdup(config->security_token) : NULL;
    producer->cfg_api_version = ve_tls_dup_cstr(config->api_version);
    producer->cfg_compress_type = ve_tls_dup_cstr(config->compress_type);
    producer->cfg_ca_cert_path = ve_tls_dup_cstr(config->ca_cert_path);
    producer->cfg_proxy = ve_tls_dup_cstr(config->proxy);
    producer->cfg_user_agent = ve_tls_dup_cstr(config->user_agent);
    producer->cfg_persistent_file_path = ve_tls_dup_cstr(config->persistent_file_path);
    if (config->log_tag_count > 0 && !config->log_tags) {
        ve_tls_producer_destroy(producer);
        return NULL;
    }
    if (ve_tls_copy_log_tags(config->log_tags, config->log_tag_count, &producer->cfg_log_tags, &producer->cfg_log_tag_count) != 0) {
        ve_tls_producer_destroy(producer);
        return NULL;
    }
    if (!producer->cfg_endpoint || !producer->cfg_region || !producer->cfg_topic_id) {
        ve_tls_producer_destroy(producer);
        return NULL;
    }
    producer->config.endpoint = producer->cfg_endpoint;
    producer->config.region = producer->cfg_region;
    producer->config.project_id = producer->cfg_project_id;
    producer->config.topic_id = producer->cfg_topic_id;
    producer->config.source = producer->cfg_source;
    producer->config.file_name = producer->cfg_file_name;
    producer->config.context_flow = producer->cfg_context_flow;
    producer->config.log_tags = producer->cfg_log_tags;
    producer->config.log_tag_count = producer->cfg_log_tag_count;
    producer->config.hash_key = producer->cfg_hash_key;
    producer->config.access_key_id = producer->cfg_access_key_id;
    producer->config.access_key_secret = producer->cfg_access_key_secret;
    producer->config.security_token = producer->cfg_security_token;
    producer->config.api_version = producer->cfg_api_version;
    producer->config.compress_type = producer->cfg_compress_type;
    producer->config.ca_cert_path = producer->cfg_ca_cert_path;
    producer->config.proxy = producer->cfg_proxy;
    producer->config.user_agent = producer->cfg_user_agent;
    producer->config.persistent_file_path = producer->cfg_persistent_file_path;
    if (ve_tls_producer_build_group_suffix(producer) != 0) {
        ve_tls_producer_destroy(producer);
        return NULL;
    }
    producer->mutex = producer->config.platform.mutex_create();
    producer->cond = producer->config.platform.cond_create();
    producer->send_cond = producer->config.platform.cond_create();
    if (!producer->mutex || !producer->cond || !producer->send_cond) {
        ve_tls_producer_destroy(producer);
        return NULL;
    }
    producer->next_id = 1;
    producer->accepting = 1;
    producer->use_global_env = producer->config.use_global_env ? 1 : 0;
    if (!producer->use_global_env) {
        producer->sender_count = producer->config.send_thread_count > 0 ? producer->config.send_thread_count : 1;
        producer->senders = (ve_tls_thread **)ve_tls_calloc((size_t)producer->sender_count, sizeof(ve_tls_thread *));
        if (!producer->senders) {
            ve_tls_producer_destroy(producer);
            return NULL;
        }
    } else {
        if (ve_tls_env_register_producer(producer) != 0) {
            ve_tls_producer_destroy(producer);
            return NULL;
        }
        producer->sender_count = 0;
        producer->senders = NULL;
    }
    producer->key_bucket_count = (size_t)(producer->config.key_queue_bucket_count > 0 ? producer->config.key_queue_bucket_count : 1024);
    producer->key_buckets = (ve_tls_key_queue **)ve_tls_calloc(producer->key_bucket_count, sizeof(ve_tls_key_queue *));
    if (!producer->key_buckets) {
        ve_tls_producer_destroy(producer);
        return NULL;
    }
    size_t sq_cap = (size_t)(producer->config.send_queue_size > 0 ? producer->config.send_queue_size : 1024);
    if (ve_tls_send_queue_init(&producer->send_queue, &producer->config.platform, sq_cap) != 0) {
        ve_tls_producer_destroy(producer);
        return NULL;
    }
    producer->worker = producer->config.platform.thread_create(ve_tls_worker_main, producer);
    if (!producer->worker) {
        ve_tls_producer_destroy(producer);
        return NULL;
    }
    for (int32_t i = 0; i < producer->sender_count; i++) {
        producer->senders[i] = producer->config.platform.thread_create(ve_tls_sender_main, producer);
        if (!producer->senders[i]) {
            ve_tls_producer_destroy(producer);
            return NULL;
        }
    }
    if (producer->use_global_env) {
        ve_tls_env_notify(producer);
    }
    return producer;
}

ve_tls_result ve_tls_producer_update_endpoint(ve_tls_producer * producer, const char * endpoint, const char * region, const char * topic_id) {
    if (!producer) {
        return VE_TLS_INVALID;
    }
    if ((endpoint && !ve_tls_is_http_url(endpoint)) || (region && ve_tls_str_empty(region)) || (topic_id && ve_tls_str_empty(topic_id))) {
        return VE_TLS_INVALID;
    }
    char * new_endpoint = endpoint ? ve_tls_strdup(endpoint) : NULL;
    char * new_region = region ? ve_tls_strdup(region) : NULL;
    char * new_topic_id = topic_id ? ve_tls_strdup(topic_id) : NULL;
    if ((endpoint && !new_endpoint) || (region && !new_region) || (topic_id && !new_topic_id)) {
        ve_tls_free(new_endpoint);
        ve_tls_free(new_region);
        ve_tls_free(new_topic_id);
        return VE_TLS_DROP_ERROR;
    }
    producer->config.platform.mutex_lock(producer->mutex);
    if (producer->stop || producer->closing || !producer->accepting) {
        producer->config.platform.mutex_unlock(producer->mutex);
        ve_tls_free(new_endpoint);
        ve_tls_free(new_region);
        ve_tls_free(new_topic_id);
        return VE_TLS_CLOSED;
    }
    if (new_endpoint) {
        ve_tls_free(producer->cfg_endpoint);
        producer->cfg_endpoint = new_endpoint;
        producer->config.endpoint = producer->cfg_endpoint;
    }
    if (new_region) {
        ve_tls_free(producer->cfg_region);
        producer->cfg_region = new_region;
        producer->config.region = producer->cfg_region;
    }
    if (new_topic_id) {
        ve_tls_free(producer->cfg_topic_id);
        producer->cfg_topic_id = new_topic_id;
        producer->config.topic_id = producer->cfg_topic_id;
    }
    producer->config.platform.mutex_unlock(producer->mutex);
    ve_tls_metrics_emit(producer, "config_update_endpoint", 1, 0);
    return VE_TLS_OK;
}

ve_tls_result ve_tls_producer_update_static_credentials(ve_tls_producer * producer, const char * access_key_id, const char * access_key_secret, const char * security_token) {
    if (!producer) {
        return VE_TLS_INVALID;
    }
    if ((access_key_id && ve_tls_str_empty(access_key_id)) || (access_key_secret && ve_tls_str_empty(access_key_secret))) {
        return VE_TLS_INVALID;
    }
    if ((access_key_id && !access_key_secret) || (!access_key_id && access_key_secret)) {
        return VE_TLS_INVALID;
    }
    char * new_ak = access_key_id ? ve_tls_strdup(access_key_id) : NULL;
    char * new_sk = access_key_secret ? ve_tls_strdup(access_key_secret) : NULL;
    char * new_tok = (security_token && security_token[0] != 0) ? ve_tls_strdup(security_token) : NULL;
    if ((access_key_id && (!new_ak || !new_sk)) || (security_token && security_token[0] != 0 && !new_tok)) {
        ve_tls_free(new_ak);
        ve_tls_free(new_sk);
        ve_tls_free(new_tok);
        return VE_TLS_DROP_ERROR;
    }
    producer->config.platform.mutex_lock(producer->mutex);
    if (producer->stop || producer->closing || !producer->accepting) {
        producer->config.platform.mutex_unlock(producer->mutex);
        ve_tls_free(new_ak);
        ve_tls_free(new_sk);
        ve_tls_free(new_tok);
        return VE_TLS_CLOSED;
    }
    if (access_key_id) {
        ve_tls_secure_free_str(&producer->cfg_access_key_id);
        ve_tls_secure_free_str(&producer->cfg_access_key_secret);
        producer->cfg_access_key_id = new_ak;
        producer->cfg_access_key_secret = new_sk;
        producer->config.access_key_id = producer->cfg_access_key_id;
        producer->config.access_key_secret = producer->cfg_access_key_secret;
    } else {
        ve_tls_free(new_ak);
        ve_tls_free(new_sk);
    }
    if (security_token) {
        ve_tls_secure_free_str(&producer->cfg_security_token);
        producer->cfg_security_token = new_tok;
        producer->config.security_token = producer->cfg_security_token;
    } else {
        ve_tls_free(new_tok);
    }
    producer->config.platform.mutex_unlock(producer->mutex);
    ve_tls_metrics_emit(producer, "config_update_credentials", 1, 0);
    return VE_TLS_OK;
}

ve_tls_result ve_tls_producer_close(ve_tls_producer * producer, int32_t timeout_ms) {
    if (!producer) {
        return VE_TLS_INVALID;
    }
    ve_tls_metrics_emit(producer, "close_start", 1, timeout_ms);
    producer->config.platform.mutex_lock(producer->mutex);
    producer->accepting = 0;
    producer->closing = 1;
    producer->flush_requested = 1;
    producer->config.platform.cond_broadcast(producer->cond);
    if (producer->send_cond) {
        producer->config.platform.cond_broadcast(producer->send_cond);
    }
    int64_t start_ms = producer->config.platform.time_ms ? producer->config.platform.time_ms() : 0;
    ve_tls_cond * wait_cond = producer->send_cond ? producer->send_cond : producer->cond;
    ve_tls_result rc = VE_TLS_OK;
    int join_threads = 0;
    int emit_drain_ok = 0;
    int emit_timeout = 0;
    for (;;) {
        if (ve_tls_producer_is_drained_locked(producer)) {
            emit_drain_ok = 1;
            producer->closing = 0;
            producer->stop = 1;
            producer->config.platform.cond_broadcast(producer->cond);
            if (producer->send_cond) {
                producer->config.platform.cond_broadcast(producer->send_cond);
            }
            join_threads = 1;
            break;
        }
        if (timeout_ms == 0) {
            emit_timeout = 1;
            rc = VE_TLS_TIMEOUT;
            break;
        }
        int wait_ms = 50;
        if (timeout_ms > 0) {
            int64_t now = producer->config.platform.time_ms ? producer->config.platform.time_ms() : start_ms;
            int64_t elapsed = now - start_ms;
            int64_t remain = (int64_t)timeout_ms - elapsed;
            if (remain <= 0) {
                emit_timeout = 1;
                rc = VE_TLS_TIMEOUT;
                break;
            }
            if (remain < wait_ms) {
                wait_ms = (int)remain;
            }
        }
        (void)producer->config.platform.cond_timedwait_ms(wait_cond, producer->mutex, wait_ms);
    }
    producer->config.platform.mutex_unlock(producer->mutex);
    if (emit_drain_ok) {
        ve_tls_metrics_emit(producer, "close_drain_ok", 1, 0);
    } else if (emit_timeout) {
        ve_tls_metrics_emit(producer, "close_timeout", 1, 0);
    }
    if (join_threads) {
        if (producer->worker) {
            producer->config.platform.thread_join(producer->worker);
            producer->worker = NULL;
        }
        if (producer->senders) {
            for (int32_t i = 0; i < producer->sender_count; i++) {
                if (producer->senders[i]) {
                    producer->config.platform.thread_join(producer->senders[i]);
                    producer->senders[i] = NULL;
                }
            }
        }
    }
    return rc;
}

void ve_tls_producer_destroy(ve_tls_producer * producer) {
    if (!producer) {
        return;
    }
    if (producer->use_global_env) {
        (void)ve_tls_producer_close(producer, 60000);
        producer->use_global_env = 0;
        ve_tls_env_unregister_producer(producer);
        while (__atomic_load_n(&producer->env_inflight, __ATOMIC_RELAXED) > 0) {
            producer->config.platform.sleep_ms(1);
        }
    }
    if (producer->mutex) {
        producer->config.platform.mutex_lock(producer->mutex);
        producer->accepting = 0;
        producer->closing = 0;
        producer->stop = 1;
        producer->config.platform.cond_broadcast(producer->cond);
        if (producer->send_cond) {
            producer->config.platform.cond_broadcast(producer->send_cond);
        }
        producer->config.platform.mutex_unlock(producer->mutex);
    }
    ve_tls_send_queue_stop(&producer->send_queue);
    if (producer->worker) {
        producer->config.platform.thread_join(producer->worker);
        producer->worker = NULL;
    }
    if (producer->senders) {
        for (int32_t i = 0; i < producer->sender_count; i++) {
            if (producer->senders[i]) {
                producer->config.platform.thread_join(producer->senders[i]);
                producer->senders[i] = NULL;
            }
        }
        ve_tls_free(producer->senders);
        producer->senders = NULL;
        producer->sender_count = 0;
    }
    ve_tls_queue_free_all(producer);
    while (producer->sealed_head) {
        ve_tls_log_group_builder * n = producer->sealed_head->next;
        ve_tls_log_builder_free(producer->sealed_head);
        producer->sealed_head = n;
    }
    producer->sealed_tail = NULL;
    ve_tls_key_map_free_all(producer);
    ve_tls_send_queue_destroy(&producer->send_queue);
    ve_tls_free(producer->cfg_group_suffix);
    ve_tls_free(producer->cfg_endpoint);
    ve_tls_free(producer->cfg_region);
    ve_tls_free(producer->cfg_project_id);
    ve_tls_free(producer->cfg_topic_id);
    ve_tls_free(producer->cfg_source);
    ve_tls_free(producer->cfg_file_name);
    ve_tls_free(producer->cfg_context_flow);
    if (producer->cfg_log_tags) {
        for (size_t i = 0; i < producer->cfg_log_tag_count; i++) {
            ve_tls_free((void *)producer->cfg_log_tags[i].key);
            ve_tls_free((void *)producer->cfg_log_tags[i].value);
        }
        ve_tls_free(producer->cfg_log_tags);
    }
    ve_tls_free(producer->cfg_hash_key);
    ve_tls_secure_free_str(&producer->cfg_access_key_id);
    ve_tls_secure_free_str(&producer->cfg_access_key_secret);
    ve_tls_secure_free_str(&producer->cfg_security_token);
    ve_tls_free(producer->cfg_api_version);
    ve_tls_free(producer->cfg_compress_type);
    ve_tls_free(producer->cfg_ca_cert_path);
    ve_tls_free(producer->cfg_proxy);
    ve_tls_free(producer->cfg_user_agent);
    ve_tls_free(producer->cfg_persistent_file_path);
    producer->cfg_group_suffix = NULL;
    producer->cfg_group_suffix_len = 0;
    producer->cfg_endpoint = NULL;
    producer->cfg_region = NULL;
    producer->cfg_project_id = NULL;
    producer->cfg_topic_id = NULL;
    producer->cfg_source = NULL;
    producer->cfg_file_name = NULL;
    producer->cfg_context_flow = NULL;
    producer->cfg_log_tags = NULL;
    producer->cfg_log_tag_count = 0;
    producer->cfg_hash_key = NULL;
    producer->cfg_access_key_id = NULL;
    producer->cfg_access_key_secret = NULL;
    producer->cfg_security_token = NULL;
    producer->cfg_api_version = NULL;
    producer->cfg_compress_type = NULL;
    producer->cfg_ca_cert_path = NULL;
    producer->cfg_proxy = NULL;
    producer->cfg_user_agent = NULL;
    producer->cfg_persistent_file_path = NULL;
    ve_tls_secure_free_str(&producer->cred_access_key_id);
    ve_tls_secure_free_str(&producer->cred_access_key_secret);
    ve_tls_secure_free_str(&producer->cred_security_token);
    producer->cred_access_key_id = NULL;
    producer->cred_access_key_secret = NULL;
    producer->cred_security_token = NULL;
    if (producer->cond) {
        producer->config.platform.cond_destroy(producer->cond);
        producer->cond = NULL;
    }
    if (producer->send_cond) {
        producer->config.platform.cond_destroy(producer->send_cond);
        producer->send_cond = NULL;
    }
    if (producer->mutex) {
        producer->config.platform.mutex_destroy(producer->mutex);
        producer->mutex = NULL;
    }
    ve_tls_free(producer);
}

void ve_tls_producer_set_send_done(ve_tls_producer * producer, ve_tls_send_done_fn callback, void * user_param) {
    if (!producer) {
        return;
    }
    if (producer->mutex) {
        producer->config.platform.mutex_lock(producer->mutex);
    }
    producer->send_done = callback;
    producer->send_done_param = user_param;
    if (producer->mutex) {
        producer->config.platform.mutex_unlock(producer->mutex);
    }
}

void ve_tls_producer_set_send_done_v2(ve_tls_producer * producer, ve_tls_send_done_v2_fn callback, void * user_param) {
    if (!producer) {
        return;
    }
    if (producer->mutex) {
        producer->config.platform.mutex_lock(producer->mutex);
    }
    producer->send_done_v2 = callback;
    producer->send_done_v2_param = user_param;
    if (producer->mutex) {
        producer->config.platform.mutex_unlock(producer->mutex);
    }
}

void ve_tls_producer_get_metrics(ve_tls_producer * producer, ve_tls_metrics * out) {
    if (!producer || !out) {
        return;
    }
    memset(out, 0, sizeof(*out));
    out->logs_enqueued_total = ve_tls_metric_load_u64(&producer->m_logs_enqueued_total);
    out->logs_dropped_total = ve_tls_metric_load_u64(&producer->m_logs_dropped_total);
    out->bytes_enqueued_total = ve_tls_metric_load_u64(&producer->m_bytes_enqueued_total);
    out->bytes_dropped_total = ve_tls_metric_load_u64(&producer->m_bytes_dropped_total);
    out->batches_built_total = ve_tls_metric_load_u64(&producer->m_batches_built_total);
    out->requests_total = ve_tls_metric_load_u64(&producer->m_requests_total);
    out->requests_failed_total = ve_tls_metric_load_u64(&producer->m_requests_failed_total);
    out->retries_total = ve_tls_metric_load_u64(&producer->m_retries_total);
    out->bytes_sent_total = ve_tls_metric_load_u64(&producer->m_bytes_sent_total);
    for (int i = 0; i < 8; i++) {
        out->request_latency_buckets[i] = ve_tls_metric_load_u64(&producer->m_latency_buckets[i]);
    }
}

static int ve_tls_wait_buffer_space_locked(ve_tls_producer * producer, size_t need_bytes) {
    if (!producer) {
        return -1;
    }
    if (producer->config.max_buffer_bytes <= 0) {
        return 0;
    }
    if ((int64_t)(producer->queue_bytes + need_bytes) <= producer->config.max_buffer_bytes) {
        return 0;
    }
    if (producer->config.buffer_full_policy != VE_TLS_BUFFER_FULL_BLOCK) {
        return -1;
    }
    int64_t now = producer->config.platform.time_ms ? producer->config.platform.time_ms() : 0;
    int64_t deadline = 0;
    if (producer->config.buffer_full_block_timeout_ms > 0 && now > 0) {
        deadline = now + producer->config.buffer_full_block_timeout_ms;
    }
    for (;;) {
        if (producer->stop || !producer->accepting) {
            return -2;
        }
        if ((int64_t)(producer->queue_bytes + need_bytes) <= producer->config.max_buffer_bytes) {
            return 0;
        }
        producer->flush_requested = 1;
        producer->config.platform.cond_signal(producer->cond);
        ve_tls_metrics_emit(producer, "log_blocked_buffer_full", 1, (int64_t)need_bytes);
        if (deadline > 0) {
            int64_t now2 = producer->config.platform.time_ms ? producer->config.platform.time_ms() : 0;
            int64_t remain = deadline - now2;
            if (remain <= 0) {
                return -3;
            }
            if (producer->config.platform.cond_timedwait_ms) {
                (void)producer->config.platform.cond_timedwait_ms(producer->cond, producer->mutex, remain);
            } else {
                producer->config.platform.cond_wait(producer->cond, producer->mutex);
            }
        } else {
            producer->config.platform.cond_wait(producer->cond, producer->mutex);
        }
    }
}

ve_tls_result ve_tls_producer_add_log_raw(ve_tls_producer * producer, const char * log_buf, size_t log_size, int flush) {
    if (!producer || !log_buf || log_size == 0) {
        return VE_TLS_INVALID;
    }
    unsigned char * copy = (unsigned char *)ve_tls_malloc(log_size);
    if (!copy) {
        return VE_TLS_DROP_ERROR;
    }
    memcpy(copy, log_buf, log_size);
    producer->config.platform.mutex_lock(producer->mutex);
    if (producer->stop || !producer->accepting) {
        producer->config.platform.mutex_unlock(producer->mutex);
        ve_tls_free(copy);
        return VE_TLS_CLOSED;
    }
    int wrc = ve_tls_wait_buffer_space_locked(producer, log_size);
    if (wrc != 0) {
        producer->config.platform.mutex_unlock(producer->mutex);
        ve_tls_free(copy);
        if (wrc == -2) {
            return VE_TLS_CLOSED;
        }
        if (wrc == -3) {
            ve_tls_metric_inc_u64(&producer->m_logs_dropped_total, 1);
            ve_tls_metric_inc_u64(&producer->m_bytes_dropped_total, log_size);
            ve_tls_metrics_emit(producer, "log_dropped_buffer_full_timeout", 1, (int64_t)log_size);
            ve_tls_metrics_emit(producer, "log_dropped", 1, (int64_t)log_size);
            return VE_TLS_TIMEOUT;
        }
        ve_tls_metric_inc_u64(&producer->m_logs_dropped_total, 1);
        ve_tls_metric_inc_u64(&producer->m_bytes_dropped_total, log_size);
        ve_tls_metrics_emit(producer, "log_dropped_buffer_full", 1, (int64_t)log_size);
        ve_tls_metrics_emit(producer, "log_dropped", 1, (int64_t)log_size);
        return VE_TLS_DROP_ERROR;
    }
    int64_t id = producer->next_id++;
    if (ve_tls_queue_push_owned(producer, copy, log_size, id, 0, 0, 0, NULL) != 0) {
        producer->config.platform.mutex_unlock(producer->mutex);
        ve_tls_free(copy);
        ve_tls_metric_inc_u64(&producer->m_logs_dropped_total, 1);
        ve_tls_metric_inc_u64(&producer->m_bytes_dropped_total, log_size);
        ve_tls_metrics_emit(producer, "log_dropped_enqueue_alloc_failed", 1, (int64_t)log_size);
        ve_tls_metrics_emit(producer, "log_dropped", 1, (int64_t)log_size);
        return VE_TLS_DROP_ERROR;
    }
    ve_tls_metric_inc_u64(&producer->m_logs_enqueued_total, 1);
    ve_tls_metric_inc_u64(&producer->m_bytes_enqueued_total, log_size);
    int64_t emit_size = (int64_t)log_size;
    if (!flush) {
        size_t byte_limit = producer->config.log_bytes_per_package > 0 ? (size_t)producer->config.log_bytes_per_package : 0;
        if (producer->config.agg_max_raw_bytes_per_request > 0) {
            size_t max_raw = (size_t)producer->config.agg_max_raw_bytes_per_request;
            if (byte_limit == 0 || byte_limit > max_raw) {
                byte_limit = max_raw;
            }
        }
        if (producer->config.log_count_per_package > 0 && producer->queue_count >= producer->config.log_count_per_package) {
            flush = 1;
        }
        if (!flush && byte_limit > 0 && producer->queue_bytes >= byte_limit) {
            flush = 1;
        }
    }
    if (flush) {
        producer->flush_requested = 1;
    }
    producer->config.platform.cond_signal(producer->cond);
    producer->config.platform.mutex_unlock(producer->mutex);
    ve_tls_metrics_emit(producer, "log_enqueued", 1, emit_size);
    return VE_TLS_OK;
}

ve_tls_result ve_tls_producer_add_log_raw_time_parts(ve_tls_producer * producer, int64_t time_ms, int32_t has_time_ns, uint32_t time_ns, const char * log_buf, size_t log_size, int flush) {
    if (!producer || !log_buf || log_size == 0) {
        return VE_TLS_INVALID;
    }
    unsigned char * copy = (unsigned char *)ve_tls_malloc(log_size);
    if (!copy) {
        return VE_TLS_DROP_ERROR;
    }
    memcpy(copy, log_buf, log_size);
    producer->config.platform.mutex_lock(producer->mutex);
    if (producer->stop || !producer->accepting) {
        producer->config.platform.mutex_unlock(producer->mutex);
        ve_tls_free(copy);
        return VE_TLS_CLOSED;
    }
    int wrc = ve_tls_wait_buffer_space_locked(producer, log_size);
    if (wrc != 0) {
        producer->config.platform.mutex_unlock(producer->mutex);
        ve_tls_free(copy);
        if (wrc == -2) {
            return VE_TLS_CLOSED;
        }
        if (wrc == -3) {
            ve_tls_metric_inc_u64(&producer->m_logs_dropped_total, 1);
            ve_tls_metric_inc_u64(&producer->m_bytes_dropped_total, log_size);
            ve_tls_metrics_emit(producer, "log_dropped_buffer_full_timeout", 1, (int64_t)log_size);
            ve_tls_metrics_emit(producer, "log_dropped", 1, (int64_t)log_size);
            return VE_TLS_TIMEOUT;
        }
        ve_tls_metric_inc_u64(&producer->m_logs_dropped_total, 1);
        ve_tls_metric_inc_u64(&producer->m_bytes_dropped_total, log_size);
        ve_tls_metrics_emit(producer, "log_dropped_buffer_full", 1, (int64_t)log_size);
        ve_tls_metrics_emit(producer, "log_dropped", 1, (int64_t)log_size);
        return VE_TLS_DROP_ERROR;
    }
    int64_t id = producer->next_id++;
    if (ve_tls_queue_push_owned(producer, copy, log_size, id, time_ms, time_ns, has_time_ns ? 1 : 0, NULL) != 0) {
        producer->config.platform.mutex_unlock(producer->mutex);
        ve_tls_free(copy);
        ve_tls_metric_inc_u64(&producer->m_logs_dropped_total, 1);
        ve_tls_metric_inc_u64(&producer->m_bytes_dropped_total, log_size);
        ve_tls_metrics_emit(producer, "log_dropped_enqueue_alloc_failed", 1, (int64_t)log_size);
        ve_tls_metrics_emit(producer, "log_dropped", 1, (int64_t)log_size);
        return VE_TLS_DROP_ERROR;
    }
    ve_tls_metric_inc_u64(&producer->m_logs_enqueued_total, 1);
    ve_tls_metric_inc_u64(&producer->m_bytes_enqueued_total, log_size);
    int64_t emit_size = (int64_t)log_size;
    if (!flush) {
        size_t byte_limit = producer->config.log_bytes_per_package > 0 ? (size_t)producer->config.log_bytes_per_package : 0;
        if (producer->config.agg_max_raw_bytes_per_request > 0) {
            size_t max_raw = (size_t)producer->config.agg_max_raw_bytes_per_request;
            if (byte_limit == 0 || byte_limit > max_raw) {
                byte_limit = max_raw;
            }
        }
        if (producer->config.log_count_per_package > 0 && producer->queue_count >= producer->config.log_count_per_package) {
            flush = 1;
        }
        if (!flush && byte_limit > 0 && producer->queue_bytes >= byte_limit) {
            flush = 1;
        }
    }
    if (flush) {
        producer->flush_requested = 1;
    }
    producer->config.platform.cond_signal(producer->cond);
    producer->config.platform.mutex_unlock(producer->mutex);
    ve_tls_metrics_emit(producer, "log_enqueued", 1, emit_size);
    return VE_TLS_OK;
}

ve_tls_result ve_tls_producer_add_log_kv(ve_tls_producer * producer, int64_t time_ms, const ve_tls_kv * kvs, size_t kv_count, int flush) {
    return ve_tls_producer_add_log_kv_hashkey(producer, time_ms, NULL, kvs, kv_count, flush);
}

ve_tls_result ve_tls_producer_add_log_kv_hashkey(ve_tls_producer * producer, int64_t time_ms, const char * hash_key, const ve_tls_kv * kvs, size_t kv_count, int flush) {
    if (!producer || !kvs || kv_count == 0) {
        return VE_TLS_INVALID;
    }
    uint32_t time_ns = 0;
    int32_t has_time_ns = 0;
    if (time_ms <= 0) {
        time_ms = producer->config.platform.time_ms ? producer->config.platform.time_ms() : 0;
        if (producer->config.enable_time_ns && producer->config.platform.time_unix_ns) {
            int64_t now_ns = producer->config.platform.time_unix_ns();
            if (now_ns > 0) {
                int64_t ms = now_ns / 1000000LL;
                int64_t rem = now_ns - ms * 1000000LL;
                if (ms > 0 && rem >= 0) {
                    time_ms = ms;
                    has_time_ns = 1;
                    time_ns = (uint32_t)rem;
                }
            }
        }
    }
    const char * norm_key = ve_tls_normalize_hash_key(producer, hash_key);
    size_t need = ve_tls_log_builder_log_entry_size(time_ms, time_ns, has_time_ns, kvs, kv_count);
    producer->config.platform.mutex_lock(producer->mutex);
    if (producer->stop || !producer->accepting) {
        producer->config.platform.mutex_unlock(producer->mutex);
        return VE_TLS_CLOSED;
    }
    int wrc = ve_tls_wait_buffer_space_locked(producer, need);
    if (wrc != 0) {
        producer->config.platform.mutex_unlock(producer->mutex);
        if (wrc == -2) {
            return VE_TLS_CLOSED;
        }
        if (wrc == -3) {
            ve_tls_metric_inc_u64(&producer->m_logs_dropped_total, 1);
            ve_tls_metric_inc_u64(&producer->m_bytes_dropped_total, need);
            ve_tls_metrics_emit(producer, "log_dropped_buffer_full_timeout", 1, (int64_t)need);
            ve_tls_metrics_emit(producer, "log_dropped", 1, (int64_t)need);
            return VE_TLS_TIMEOUT;
        }
        ve_tls_metric_inc_u64(&producer->m_logs_dropped_total, 1);
        ve_tls_metric_inc_u64(&producer->m_bytes_dropped_total, need);
        ve_tls_metrics_emit(producer, "log_dropped_buffer_full", 1, (int64_t)need);
        ve_tls_metrics_emit(producer, "log_dropped", 1, (int64_t)need);
        return VE_TLS_DROP_ERROR;
    }
    int64_t id = producer->next_id++;
    ve_tls_key_queue * q = ve_tls_key_queue_get_or_create(producer, norm_key);
    if (!q) {
        ve_tls_send_callbacks cbs = ve_tls_capture_callbacks(producer);
        int is_limit = 0;
        if (producer->config.key_queue_max_active > 0 && producer->key_queue_count >= (size_t)producer->config.key_queue_max_active) {
            is_limit = 1;
        }
        producer->config.platform.mutex_unlock(producer->mutex);
        ve_tls_metric_inc_u64(&producer->m_logs_dropped_total, 1);
        ve_tls_metric_inc_u64(&producer->m_bytes_dropped_total, need);
        if (is_limit) {
            ve_tls_metrics_emit(producer, "key_queue_drop", 1, 0);
            ve_tls_drop_one_with_error(cbs, need, id, "KeyQueueLimitExceeded", "key queue limit exceeded");
        } else {
            ve_tls_metrics_emit(producer, "log_dropped_enqueue_alloc_failed", 1, (int64_t)need);
        }
        ve_tls_metrics_emit(producer, "log_dropped", 1, (int64_t)need);
        return is_limit ? VE_TLS_OK : VE_TLS_DROP_ERROR;
    }
    if (!q->builder) {
        q->builder = ve_tls_log_builder_create(q->key);
        if (!q->builder) {
            producer->config.platform.mutex_unlock(producer->mutex);
            ve_tls_metric_inc_u64(&producer->m_logs_dropped_total, 1);
            ve_tls_metric_inc_u64(&producer->m_bytes_dropped_total, need);
            ve_tls_metrics_emit(producer, "log_dropped_enqueue_alloc_failed", 1, (int64_t)need);
            ve_tls_metrics_emit(producer, "log_dropped", 1, (int64_t)need);
            return VE_TLS_DROP_ERROR;
        }
        q->builder->first_append_ms = producer->config.platform.time_ms ? producer->config.platform.time_ms() : 0;
    }
    size_t prev = q->builder->logs_len;
    if (ve_tls_log_builder_add_kv(q->builder, id, time_ms, time_ns, has_time_ns, kvs, kv_count) != 0) {
        producer->config.platform.mutex_unlock(producer->mutex);
        ve_tls_metric_inc_u64(&producer->m_logs_dropped_total, 1);
        ve_tls_metric_inc_u64(&producer->m_bytes_dropped_total, need);
        ve_tls_metrics_emit(producer, "log_dropped_enqueue_alloc_failed", 1, (int64_t)need);
        ve_tls_metrics_emit(producer, "log_dropped", 1, (int64_t)need);
        return VE_TLS_DROP_ERROR;
    }
    size_t delta = q->builder->logs_len - prev;
    producer->queue_bytes += delta;
    ve_tls_metric_inc_u64(&producer->m_logs_enqueued_total, 1);
    ve_tls_metric_inc_u64(&producer->m_bytes_enqueued_total, delta);
    int64_t emit_size = (int64_t)delta;
    if (flush) {
        ve_tls_log_group_builder * sealed = q->builder;
        q->builder = NULL;
        sealed->next = NULL;
        if (producer->sealed_tail) {
            producer->sealed_tail->next = sealed;
        } else {
            producer->sealed_head = sealed;
        }
        producer->sealed_tail = sealed;
        producer->flush_requested = 1;
    } else {
        size_t byte_limit = producer->config.log_bytes_per_package > 0 ? (size_t)producer->config.log_bytes_per_package : 0;
        if (producer->config.agg_max_raw_bytes_per_request > 0) {
            size_t max_raw = (size_t)producer->config.agg_max_raw_bytes_per_request;
            if (byte_limit == 0 || byte_limit > max_raw) {
                byte_limit = max_raw;
            }
        }
        int should_seal = 0;
        if (producer->config.log_count_per_package > 0 && q->builder->log_count >= producer->config.log_count_per_package) {
            should_seal = 1;
        }
        if (!should_seal && byte_limit > 0 && q->builder->logs_len >= byte_limit) {
            should_seal = 1;
        }
        if (should_seal) {
            ve_tls_log_group_builder * sealed = q->builder;
            q->builder = NULL;
            sealed->next = NULL;
            if (producer->sealed_tail) {
                producer->sealed_tail->next = sealed;
            } else {
                producer->sealed_head = sealed;
            }
            producer->sealed_tail = sealed;
            producer->flush_requested = 1;
        }
    }
    producer->config.platform.cond_signal(producer->cond);
    producer->config.platform.mutex_unlock(producer->mutex);
    ve_tls_metrics_emit(producer, "log_enqueued", 1, emit_size);
    return VE_TLS_OK;
}

ve_tls_result ve_tls_producer_add_log_kv_time_parts(ve_tls_producer * producer, int64_t time_ms, int32_t has_time_ns, uint32_t time_ns, const ve_tls_kv * kvs, size_t kv_count, int flush) {
    return ve_tls_producer_add_log_kv_time_parts_hashkey(producer, time_ms, has_time_ns, time_ns, NULL, kvs, kv_count, flush);
}

ve_tls_result ve_tls_producer_add_log_kv_time_parts_hashkey(ve_tls_producer * producer, int64_t time_ms, int32_t has_time_ns, uint32_t time_ns, const char * hash_key, const ve_tls_kv * kvs, size_t kv_count, int flush) {
    if (!producer || !kvs || kv_count == 0) {
        return VE_TLS_INVALID;
    }
    if (time_ms <= 0) {
        time_ms = producer->config.platform.time_ms ? producer->config.platform.time_ms() : 0;
        has_time_ns = 0;
        time_ns = 0;
        if (producer->config.enable_time_ns && producer->config.platform.time_unix_ns) {
            int64_t now_ns = producer->config.platform.time_unix_ns();
            if (now_ns > 0) {
                int64_t ms = now_ns / 1000000LL;
                int64_t rem = now_ns - ms * 1000000LL;
                if (ms > 0 && rem >= 0) {
                    time_ms = ms;
                    has_time_ns = 1;
                    time_ns = (uint32_t)rem;
                }
            }
        }
    } else if (!has_time_ns) {
        time_ns = 0;
    }
    const char * norm_key = ve_tls_normalize_hash_key(producer, hash_key);
    size_t need = ve_tls_log_builder_log_entry_size(time_ms, time_ns, has_time_ns ? 1 : 0, kvs, kv_count);
    producer->config.platform.mutex_lock(producer->mutex);
    if (producer->stop || !producer->accepting) {
        producer->config.platform.mutex_unlock(producer->mutex);
        return VE_TLS_CLOSED;
    }
    int wrc = ve_tls_wait_buffer_space_locked(producer, need);
    if (wrc != 0) {
        producer->config.platform.mutex_unlock(producer->mutex);
        if (wrc == -2) {
            return VE_TLS_CLOSED;
        }
        if (wrc == -3) {
            ve_tls_metric_inc_u64(&producer->m_logs_dropped_total, 1);
            ve_tls_metric_inc_u64(&producer->m_bytes_dropped_total, need);
            ve_tls_metrics_emit(producer, "log_dropped_buffer_full_timeout", 1, (int64_t)need);
            ve_tls_metrics_emit(producer, "log_dropped", 1, (int64_t)need);
            return VE_TLS_TIMEOUT;
        }
        ve_tls_metric_inc_u64(&producer->m_logs_dropped_total, 1);
        ve_tls_metric_inc_u64(&producer->m_bytes_dropped_total, need);
        ve_tls_metrics_emit(producer, "log_dropped_buffer_full", 1, (int64_t)need);
        ve_tls_metrics_emit(producer, "log_dropped", 1, (int64_t)need);
        return VE_TLS_DROP_ERROR;
    }
    int64_t id = producer->next_id++;
    ve_tls_key_queue * q = ve_tls_key_queue_get_or_create(producer, norm_key);
    if (!q) {
        ve_tls_send_callbacks cbs = ve_tls_capture_callbacks(producer);
        int is_limit = 0;
        if (producer->config.key_queue_max_active > 0 && producer->key_queue_count >= (size_t)producer->config.key_queue_max_active) {
            is_limit = 1;
        }
        producer->config.platform.mutex_unlock(producer->mutex);
        ve_tls_metric_inc_u64(&producer->m_logs_dropped_total, 1);
        ve_tls_metric_inc_u64(&producer->m_bytes_dropped_total, need);
        if (is_limit) {
            ve_tls_metrics_emit(producer, "key_queue_drop", 1, 0);
            ve_tls_drop_one_with_error(cbs, need, id, "KeyQueueLimitExceeded", "key queue limit exceeded");
        } else {
            ve_tls_metrics_emit(producer, "log_dropped_enqueue_alloc_failed", 1, (int64_t)need);
        }
        ve_tls_metrics_emit(producer, "log_dropped", 1, (int64_t)need);
        return is_limit ? VE_TLS_OK : VE_TLS_DROP_ERROR;
    }
    if (!q->builder) {
        q->builder = ve_tls_log_builder_create(q->key);
        if (!q->builder) {
            producer->config.platform.mutex_unlock(producer->mutex);
            ve_tls_metric_inc_u64(&producer->m_logs_dropped_total, 1);
            ve_tls_metric_inc_u64(&producer->m_bytes_dropped_total, need);
            ve_tls_metrics_emit(producer, "log_dropped_enqueue_alloc_failed", 1, (int64_t)need);
            ve_tls_metrics_emit(producer, "log_dropped", 1, (int64_t)need);
            return VE_TLS_DROP_ERROR;
        }
        q->builder->first_append_ms = producer->config.platform.time_ms ? producer->config.platform.time_ms() : 0;
    }
    size_t prev = q->builder->logs_len;
    if (ve_tls_log_builder_add_kv(q->builder, id, time_ms, time_ns, has_time_ns ? 1 : 0, kvs, kv_count) != 0) {
        producer->config.platform.mutex_unlock(producer->mutex);
        ve_tls_metric_inc_u64(&producer->m_logs_dropped_total, 1);
        ve_tls_metric_inc_u64(&producer->m_bytes_dropped_total, need);
        ve_tls_metrics_emit(producer, "log_dropped_enqueue_alloc_failed", 1, (int64_t)need);
        ve_tls_metrics_emit(producer, "log_dropped", 1, (int64_t)need);
        return VE_TLS_DROP_ERROR;
    }
    size_t delta = q->builder->logs_len - prev;
    producer->queue_bytes += delta;
    ve_tls_metric_inc_u64(&producer->m_logs_enqueued_total, 1);
    ve_tls_metric_inc_u64(&producer->m_bytes_enqueued_total, delta);
    int64_t emit_size = (int64_t)delta;
    if (flush) {
        ve_tls_log_group_builder * sealed = q->builder;
        q->builder = NULL;
        sealed->next = NULL;
        if (producer->sealed_tail) {
            producer->sealed_tail->next = sealed;
        } else {
            producer->sealed_head = sealed;
        }
        producer->sealed_tail = sealed;
        producer->flush_requested = 1;
    } else {
        size_t byte_limit = producer->config.log_bytes_per_package > 0 ? (size_t)producer->config.log_bytes_per_package : 0;
        if (producer->config.agg_max_raw_bytes_per_request > 0) {
            size_t max_raw = (size_t)producer->config.agg_max_raw_bytes_per_request;
            if (byte_limit == 0 || byte_limit > max_raw) {
                byte_limit = max_raw;
            }
        }
        int should_seal = 0;
        if (producer->config.log_count_per_package > 0 && q->builder->log_count >= producer->config.log_count_per_package) {
            should_seal = 1;
        }
        if (!should_seal && byte_limit > 0 && q->builder->logs_len >= byte_limit) {
            should_seal = 1;
        }
        if (should_seal) {
            ve_tls_log_group_builder * sealed = q->builder;
            q->builder = NULL;
            sealed->next = NULL;
            if (producer->sealed_tail) {
                producer->sealed_tail->next = sealed;
            } else {
                producer->sealed_head = sealed;
            }
            producer->sealed_tail = sealed;
            producer->flush_requested = 1;
        }
    }
    producer->config.platform.cond_signal(producer->cond);
    producer->config.platform.mutex_unlock(producer->mutex);
    ve_tls_metrics_emit(producer, "log_enqueued", 1, emit_size);
    return VE_TLS_OK;
}

ve_tls_result ve_tls_producer_flush(ve_tls_producer * producer) {
    if (!producer) {
        return VE_TLS_INVALID;
    }
    producer->config.platform.mutex_lock(producer->mutex);
    producer->flush_requested = 1;
    producer->config.platform.cond_broadcast(producer->cond);
    producer->config.platform.mutex_unlock(producer->mutex);
    return VE_TLS_OK;
}

ve_tls_result ve_tls_producer_recover(ve_tls_producer * producer) {
    if (!producer) {
        return VE_TLS_INVALID;
    }
    return VE_TLS_OK;
}

static void ve_tls_write_u32_le(unsigned char * p, uint32_t v) {
    p[0] = (unsigned char)(v & 0xFF);
    p[1] = (unsigned char)((v >> 8) & 0xFF);
    p[2] = (unsigned char)((v >> 16) & 0xFF);
    p[3] = (unsigned char)((v >> 24) & 0xFF);
}

static void ve_tls_write_u64_le(unsigned char * p, uint64_t v) {
    for (int i = 0; i < 8; i++) {
        p[i] = (unsigned char)((v >> (8 * i)) & 0xFF);
    }
}

static int ve_tls_read_u32_le(const unsigned char * p, size_t size, size_t * off, uint32_t * out) {
    if (!p || !off || !out || *off + 4 > size) {
        return -1;
    }
    *out = (uint32_t)p[*off] |
           ((uint32_t)p[*off + 1] << 8) |
           ((uint32_t)p[*off + 2] << 16) |
           ((uint32_t)p[*off + 3] << 24);
    *off += 4;
    return 0;
}

static int ve_tls_read_u64_le(const unsigned char * p, size_t size, size_t * off, uint64_t * out) {
    if (!p || !off || !out || *off + 8 > size) {
        return -1;
    }
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) {
        v |= ((uint64_t)p[*off + (size_t)i]) << (8 * i);
    }
    *out = v;
    *off += 8;
    return 0;
}

static int ve_tls_read_u8(const unsigned char * p, size_t size, size_t * off, unsigned char * out) {
    if (!p || !off || !out || *off + 1 > size) {
        return -1;
    }
    *out = p[*off];
    *off += 1;
    return 0;
}

ve_tls_result ve_tls_producer_export_raw_buffer(ve_tls_producer * producer, unsigned char ** out_buf, size_t * out_size) {
    if (!producer || !out_buf || !out_size) {
        return VE_TLS_INVALID;
    }
    *out_buf = NULL;
    *out_size = 0;

    producer->config.platform.mutex_lock(producer->mutex);
    typedef struct {
        int64_t id;
        int64_t time_ms;
        unsigned char has_ns;
        uint32_t time_ns;
        char * hk;
        uint32_t hk_len;
        unsigned char * data;
        uint32_t data_size;
        int owned;
    } ve_tls_export_rec;

    size_t builder_count = 0;
    for (size_t bi = 0; bi < producer->key_bucket_count; bi++) {
        for (ve_tls_key_queue * q = producer->key_buckets[bi]; q; q = q->hnext) {
            if (q->builder && q->builder->log_count > 0) {
                builder_count++;
            }
        }
    }
    if (producer->queue_count + builder_count > 0xFFFFFFFFu) {
        producer->config.platform.mutex_unlock(producer->mutex);
        return VE_TLS_DROP_ERROR;
    }
    uint32_t count = (uint32_t)(producer->queue_count + builder_count);
    ve_tls_export_rec * recs = NULL;
    if (count > 0) {
        recs = (ve_tls_export_rec *)ve_tls_calloc((size_t)count, sizeof(*recs));
        if (!recs) {
            producer->config.platform.mutex_unlock(producer->mutex);
            return VE_TLS_DROP_ERROR;
        }
    }

    size_t rlen = 0;
    for (size_t i = 0; i < producer->queue_count; i++) {
        size_t idx = (producer->queue_head + i) % producer->queue_cap;
        ve_tls_log_item * it = &producer->queue[idx];
        ve_tls_export_rec * r = &recs[rlen++];
        r->id = it->id;
        r->time_ms = it->time_ms;
        r->has_ns = (unsigned char)(it->has_time_ns ? 1 : 0);
        r->time_ns = it->time_ns;
        r->hk = it->hash_key;
        r->hk_len = it->hash_key ? (uint32_t)strlen(it->hash_key) : 0;
        r->data = it->data;
        r->data_size = (uint32_t)it->size;
        r->owned = 0;
    }
    for (size_t bi = 0; bi < producer->key_bucket_count; bi++) {
        for (ve_tls_key_queue * q = producer->key_buckets[bi]; q; q = q->hnext) {
            if (!q->builder || q->builder->log_count == 0) {
                continue;
            }
            ve_tls_send_task t;
            if (ve_tls_builder_to_send_task(producer, q->builder, &t) != 0 || !t.body || t.body_size == 0) {
                for (size_t k = producer->queue_count; k < rlen; k++) {
                    if (recs[k].owned) {
                        ve_tls_free(recs[k].hk);
                        ve_tls_free(recs[k].data);
                    }
                }
                ve_tls_free(recs);
                producer->config.platform.mutex_unlock(producer->mutex);
                return VE_TLS_DROP_ERROR;
            }
            ve_tls_export_rec * r = &recs[rlen++];
            r->id = q->builder->end_id;
            r->time_ms = q->builder->last_time_ms;
            r->has_ns = (unsigned char)(q->builder->last_has_time_ns ? 1 : 0);
            r->time_ns = q->builder->last_time_ns;
            r->hk = t.hash_key;
            r->hk_len = t.hash_key ? (uint32_t)strlen(t.hash_key) : 0;
            r->data = t.body;
            r->data_size = (uint32_t)t.body_size;
            r->owned = 1;
            t.hash_key = NULL;
            t.body = NULL;
            ve_tls_send_task_free(&t);
        }
    }

    size_t total = 4 + 4 + 4 + 8;
    for (size_t i = 0; i < rlen; i++) {
        ve_tls_export_rec * r = &recs[i];
        if (r->hk_len > 0xFFFFFFFFu || r->data_size > 0xFFFFFFFFu) {
            for (size_t k = producer->queue_count; k < rlen; k++) {
                if (recs[k].owned) {
                    ve_tls_free(recs[k].hk);
                    ve_tls_free(recs[k].data);
                }
            }
            ve_tls_free(recs);
            producer->config.platform.mutex_unlock(producer->mutex);
            return VE_TLS_DROP_ERROR;
        }
        size_t add = 8 + 8 + 1 + 4 + 4 + 4;
        if (add > (size_t)-1 - (size_t)r->hk_len) {
            for (size_t k = producer->queue_count; k < rlen; k++) {
                if (recs[k].owned) {
                    ve_tls_free(recs[k].hk);
                    ve_tls_free(recs[k].data);
                }
            }
            ve_tls_free(recs);
            producer->config.platform.mutex_unlock(producer->mutex);
            return VE_TLS_DROP_ERROR;
        }
        add += (size_t)r->hk_len;
        if (add > (size_t)-1 - (size_t)r->data_size) {
            for (size_t k = producer->queue_count; k < rlen; k++) {
                if (recs[k].owned) {
                    ve_tls_free(recs[k].hk);
                    ve_tls_free(recs[k].data);
                }
            }
            ve_tls_free(recs);
            producer->config.platform.mutex_unlock(producer->mutex);
            return VE_TLS_DROP_ERROR;
        }
        add += (size_t)r->data_size;
        if (total > (size_t)-1 - add) {
            for (size_t k = producer->queue_count; k < rlen; k++) {
                if (recs[k].owned) {
                    ve_tls_free(recs[k].hk);
                    ve_tls_free(recs[k].data);
                }
            }
            ve_tls_free(recs);
            producer->config.platform.mutex_unlock(producer->mutex);
            return VE_TLS_DROP_ERROR;
        }
        total += add;
    }
    unsigned char * buf = (unsigned char *)ve_tls_malloc(total);
    if (!buf) {
        for (size_t k = producer->queue_count; k < rlen; k++) {
            if (recs[k].owned) {
                ve_tls_free(recs[k].hk);
                ve_tls_free(recs[k].data);
            }
        }
        ve_tls_free(recs);
        producer->config.platform.mutex_unlock(producer->mutex);
        return VE_TLS_DROP_ERROR;
    }
    size_t off = 0;
    buf[off++] = 'V';
    buf[off++] = 'T';
    buf[off++] = 'L';
    buf[off++] = 'S';
    ve_tls_write_u32_le(buf + off, 3);
    off += 4;
    ve_tls_write_u32_le(buf + off, count);
    off += 4;
    ve_tls_write_u64_le(buf + off, (uint64_t)producer->next_id);
    off += 8;

    for (size_t i = 0; i < rlen; i++) {
        ve_tls_export_rec * r = &recs[i];
        ve_tls_write_u64_le(buf + off, (uint64_t)r->id);
        off += 8;
        ve_tls_write_u64_le(buf + off, (uint64_t)r->time_ms);
        off += 8;
        buf[off++] = (unsigned char)(r->has_ns ? 1 : 0);
        ve_tls_write_u32_le(buf + off, r->time_ns);
        off += 4;
        ve_tls_write_u32_le(buf + off, r->hk_len);
        off += 4;
        ve_tls_write_u32_le(buf + off, r->data_size);
        off += 4;
        if (r->hk_len > 0) {
            memcpy(buf + off, r->hk, (size_t)r->hk_len);
            off += (size_t)r->hk_len;
        }
        memcpy(buf + off, r->data, (size_t)r->data_size);
        off += (size_t)r->data_size;
    }
    for (size_t k = producer->queue_count; k < rlen; k++) {
        if (recs[k].owned) {
            ve_tls_free(recs[k].hk);
            ve_tls_free(recs[k].data);
        }
    }
    ve_tls_free(recs);
    producer->config.platform.mutex_unlock(producer->mutex);

    *out_buf = buf;
    *out_size = off;
    return VE_TLS_OK;
}

ve_tls_result ve_tls_producer_import_raw_buffer(ve_tls_producer * producer, const unsigned char * buf, size_t size) {
    if (!producer || !buf || size < 4 + 4 + 4 + 8) {
        return VE_TLS_INVALID;
    }
    if (!(buf[0] == 'V' && buf[1] == 'T' && buf[2] == 'L' && buf[3] == 'S')) {
        return VE_TLS_INVALID;
    }
    size_t off = 4;
    uint32_t version = 0;
    uint32_t count = 0;
    uint64_t next_id = 0;
    if (ve_tls_read_u32_le(buf, size, &off, &version) != 0 || (version != 1 && version != 2 && version != 3)) {
        return VE_TLS_INVALID;
    }
    if (ve_tls_read_u32_le(buf, size, &off, &count) != 0) {
        return VE_TLS_INVALID;
    }
    if (ve_tls_read_u64_le(buf, size, &off, &next_id) != 0) {
        return VE_TLS_INVALID;
    }

    producer->config.platform.mutex_lock(producer->mutex);
    uint64_t max_id = producer->next_id > 0 ? (uint64_t)(producer->next_id - 1) : 0;
    for (uint32_t i = 0; i < count; i++) {
        uint64_t id = 0;
        uint64_t time_ms = 0;
        unsigned char has_ns = 0;
        uint32_t time_ns = 0;
        uint32_t hk_len = 0;
        uint32_t data_size = 0;
        if (ve_tls_read_u64_le(buf, size, &off, &id) != 0 ||
            ve_tls_read_u64_le(buf, size, &off, &time_ms) != 0 ||
            ve_tls_read_u8(buf, size, &off, &has_ns) != 0 ||
            ve_tls_read_u32_le(buf, size, &off, &time_ns) != 0 ||
            (version >= 2 && ve_tls_read_u32_le(buf, size, &off, &hk_len) != 0) ||
            ve_tls_read_u32_le(buf, size, &off, &data_size) != 0) {
            producer->config.platform.mutex_unlock(producer->mutex);
            return VE_TLS_INVALID;
        }
        if (off > size) {
            producer->config.platform.mutex_unlock(producer->mutex);
            return VE_TLS_INVALID;
        }
        size_t remain = size - off;
        if (remain < (size_t)hk_len) {
            producer->config.platform.mutex_unlock(producer->mutex);
            return VE_TLS_INVALID;
        }
        if (producer->config.max_buffer_bytes > 0 && (int64_t)(producer->queue_bytes + data_size) > producer->config.max_buffer_bytes) {
            producer->config.platform.mutex_unlock(producer->mutex);
            return VE_TLS_DROP_ERROR;
        }
        char * hk = NULL;
        if (version >= 2 && hk_len > 0) {
            hk = (char *)ve_tls_malloc((size_t)hk_len + 1);
            if (!hk) {
                producer->config.platform.mutex_unlock(producer->mutex);
                return VE_TLS_DROP_ERROR;
            }
            memcpy(hk, buf + off, (size_t)hk_len);
            hk[hk_len] = 0;
        }
        off += (size_t)hk_len;
        if (off > size || (size - off) < (size_t)data_size) {
            ve_tls_free(hk);
            producer->config.platform.mutex_unlock(producer->mutex);
            return VE_TLS_INVALID;
        }
        if (ve_tls_queue_push(producer, buf + off, data_size, (int64_t)id, (int64_t)time_ms, time_ns, has_ns ? 1 : 0, hk) != 0) {
            ve_tls_free(hk);
            producer->config.platform.mutex_unlock(producer->mutex);
            return VE_TLS_DROP_ERROR;
        }
        ve_tls_free(hk);
        if (id > max_id) {
            max_id = id;
        }
        off += data_size;
    }
    uint64_t desired_next = max_id + 1;
    if (next_id > desired_next) {
        desired_next = next_id;
    }
    if (desired_next > (uint64_t)producer->next_id) {
        producer->next_id = (int64_t)desired_next;
    }
    producer->config.platform.cond_signal(producer->cond);
    producer->config.platform.mutex_unlock(producer->mutex);
    return VE_TLS_OK;
}

void ve_tls_producer_free_raw_buffer(unsigned char * buf) {
    ve_tls_free(buf);
}
