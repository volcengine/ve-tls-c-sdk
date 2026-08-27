#include "ve_tls_producer_internal.h"
#include "ve_tls_alloc.h"
#include "ve_tls_version.h"

#include <string.h>

static void ve_tls_runtime_snapshot_free(ve_tls_runtime_snapshot * snapshot) {
    if (!snapshot) {
        return;
    }
    ve_tls_free(snapshot->endpoint);
    ve_tls_free(snapshot->region);
    ve_tls_free(snapshot->topic_id);
    ve_tls_free(snapshot->api_version);
    ve_tls_free(snapshot->compress_type);
    ve_tls_free(snapshot->default_hash_key);
    ve_tls_free(snapshot->ca_cert_path);
    ve_tls_free(snapshot->proxy);
    ve_tls_free(snapshot->user_agent);
    ve_tls_secure_free_str(&snapshot->access_key_id);
    ve_tls_secure_free_str(&snapshot->access_key_secret);
    ve_tls_secure_free_str(&snapshot->security_token);
    memset(snapshot, 0, sizeof(*snapshot));
    ve_tls_free(snapshot);
}

const ve_tls_runtime_snapshot * ve_tls_runtime_snapshot_acquire(ve_tls_producer * producer) {
    ve_tls_runtime_snapshot * snapshot;
    if (!producer) {
        return NULL;
    }
    if (producer->mutex) {
        producer->config.platform.mutex_lock(producer->mutex);
    }
    snapshot = atomic_load_explicit(&producer->runtime_snapshot, memory_order_acquire);
    if (snapshot) {
        (void)atomic_fetch_add_explicit(&snapshot->refcnt, 1u, memory_order_relaxed);
    }
    if (producer->mutex) {
        producer->config.platform.mutex_unlock(producer->mutex);
    }
    return snapshot;
}

void ve_tls_runtime_snapshot_release(const ve_tls_runtime_snapshot * snapshot) {
    if (!snapshot) {
        return;
    }
    ve_tls_runtime_snapshot * mut = (ve_tls_runtime_snapshot *)snapshot;
    uint32_t prev = atomic_fetch_sub_explicit(&mut->refcnt, 1u, memory_order_acq_rel);
    if (prev == 1u) {
        ve_tls_runtime_snapshot_free(mut);
    }
}

int ve_tls_runtime_snapshot_build_patched(
    const ve_tls_runtime_snapshot * base,
    const ve_tls_runtime_snapshot_patch * patch,
    ve_tls_runtime_snapshot ** out
) {
    ve_tls_runtime_snapshot * next;
    const char * source;
    if (!base || !patch || !out) {
        return -1;
    }
    *out = NULL;
    next = (ve_tls_runtime_snapshot *)ve_tls_calloc(1, sizeof(*next));
    if (!next) {
        return -1;
    }
    atomic_store_explicit(&next->refcnt, 1u, memory_order_relaxed);
    next->send_cfg_version = patch->send_cfg_version;
    next->static_cred_version = patch->static_cred_version;

#define VE_TLS_SNAPSHOT_DUP_PATCHED(field, mask_bit) \
    do { \
        source = (patch->field_mask & (mask_bit)) ? patch->field : base->field; \
        next->field = source ? ve_tls_strdup(source) : NULL; \
        if (source && !next->field) { \
            goto fail; \
        } \
    } while (0)
#define VE_TLS_SNAPSHOT_DUP_BASE(field) \
    do { \
        source = base->field; \
        next->field = source ? ve_tls_strdup(source) : NULL; \
        if (source && !next->field) { \
            goto fail; \
        } \
    } while (0)

    VE_TLS_SNAPSHOT_DUP_PATCHED(endpoint, VE_TLS_SNAPSHOT_PATCH_ENDPOINT);
    VE_TLS_SNAPSHOT_DUP_PATCHED(region, VE_TLS_SNAPSHOT_PATCH_REGION);
    VE_TLS_SNAPSHOT_DUP_PATCHED(topic_id, VE_TLS_SNAPSHOT_PATCH_TOPIC_ID);
    VE_TLS_SNAPSHOT_DUP_BASE(api_version);
    VE_TLS_SNAPSHOT_DUP_BASE(compress_type);
    VE_TLS_SNAPSHOT_DUP_BASE(default_hash_key);
    VE_TLS_SNAPSHOT_DUP_BASE(ca_cert_path);
    VE_TLS_SNAPSHOT_DUP_BASE(proxy);
    VE_TLS_SNAPSHOT_DUP_BASE(user_agent);
    VE_TLS_SNAPSHOT_DUP_PATCHED(access_key_id, VE_TLS_SNAPSHOT_PATCH_ACCESS_KEY_ID);
    VE_TLS_SNAPSHOT_DUP_PATCHED(access_key_secret, VE_TLS_SNAPSHOT_PATCH_ACCESS_KEY_SECRET);
    VE_TLS_SNAPSHOT_DUP_PATCHED(security_token, VE_TLS_SNAPSHOT_PATCH_SECURITY_TOKEN);
#undef VE_TLS_SNAPSHOT_DUP_PATCHED
#undef VE_TLS_SNAPSHOT_DUP_BASE

    next->connect_timeout_ms = base->connect_timeout_ms;
    next->request_timeout_ms = base->request_timeout_ms;
    next->tls_verify_peer = base->tls_verify_peer;
    next->tls_verify_host = base->tls_verify_host;
    next->http_debug = base->http_debug;
    next->tcp_keepalive = base->tcp_keepalive;
    next->tcp_keepidle = base->tcp_keepidle;
    next->tcp_keepintvl = base->tcp_keepintvl;
    *out = next;
    return 0;

fail:
    ve_tls_runtime_snapshot_release(next);
    return -1;
}

void ve_tls_runtime_snapshot_publish_locked(
    ve_tls_producer * producer,
    ve_tls_runtime_snapshot * next
) {
    if (!producer || !next) {
        return;
    }
    ve_tls_runtime_snapshot * old = atomic_exchange_explicit(
        &producer->runtime_snapshot, next, memory_order_acq_rel);
    if (old) {
        ve_tls_runtime_snapshot_release(old);
    }
}

int ve_tls_runtime_snapshot_refresh_locked(ve_tls_producer * producer) {
    if (!producer) {
        return -1;
    }
    ve_tls_runtime_snapshot * next = (ve_tls_runtime_snapshot *)ve_tls_calloc(1, sizeof(*next));
    if (!next) {
        return -1;
    }
    atomic_store_explicit(&next->refcnt, 1u, memory_order_relaxed);

    next->send_cfg_version = producer->send_cfg_version;
    next->static_cred_version = producer->static_cred_version;

    next->endpoint = producer->cfg_endpoint ? ve_tls_strdup(producer->cfg_endpoint) :
        (producer->config.endpoint ? ve_tls_strdup(producer->config.endpoint) : ve_tls_strdup(""));
    next->region = producer->cfg_region ? ve_tls_strdup(producer->cfg_region) :
        (producer->config.region ? ve_tls_strdup(producer->config.region) : ve_tls_strdup(""));
    next->topic_id = producer->cfg_topic_id ? ve_tls_strdup(producer->cfg_topic_id) :
        (producer->config.topic_id ? ve_tls_strdup(producer->config.topic_id) : ve_tls_strdup(""));
    next->api_version = producer->cfg_api_version ? ve_tls_strdup(producer->cfg_api_version) :
        (producer->config.api_version ? ve_tls_strdup(producer->config.api_version) : ve_tls_strdup(VE_TLS_C_SDK_API_VERSION));
    next->compress_type = producer->cfg_compress_type ? ve_tls_strdup(producer->cfg_compress_type) :
        (producer->config.compress_type ? ve_tls_strdup(producer->config.compress_type) : ve_tls_strdup("none"));
    next->default_hash_key = producer->cfg_hash_key ? ve_tls_strdup(producer->cfg_hash_key) :
        (producer->config.hash_key ? ve_tls_strdup(producer->config.hash_key) : NULL);
    next->ca_cert_path = producer->cfg_ca_cert_path ? ve_tls_strdup(producer->cfg_ca_cert_path) :
        (producer->config.ca_cert_path ? ve_tls_strdup(producer->config.ca_cert_path) : NULL);
    next->proxy = producer->cfg_proxy ? ve_tls_strdup(producer->cfg_proxy) :
        (producer->config.proxy ? ve_tls_strdup(producer->config.proxy) : NULL);
    next->user_agent = producer->cfg_user_agent ? ve_tls_strdup(producer->cfg_user_agent) :
        (producer->config.user_agent ? ve_tls_strdup(producer->config.user_agent) : NULL);
    next->access_key_id = producer->cfg_access_key_id ? ve_tls_strdup(producer->cfg_access_key_id) :
        (producer->config.access_key_id ? ve_tls_strdup(producer->config.access_key_id) : NULL);
    next->access_key_secret = producer->cfg_access_key_secret ? ve_tls_strdup(producer->cfg_access_key_secret) :
        (producer->config.access_key_secret ? ve_tls_strdup(producer->config.access_key_secret) : NULL);
    next->security_token = producer->cfg_security_token ? ve_tls_strdup(producer->cfg_security_token) :
        (producer->config.security_token ? ve_tls_strdup(producer->config.security_token) : NULL);

    next->connect_timeout_ms = producer->config.connect_timeout_ms;
    next->request_timeout_ms = producer->config.request_timeout_ms;
    next->tls_verify_peer = producer->config.tls_verify_peer;
    next->tls_verify_host = producer->config.tls_verify_host;
    next->http_debug = producer->config.http_debug;
    next->tcp_keepalive = producer->config.tcp_keepalive;
    next->tcp_keepidle = producer->config.tcp_keepidle;
    next->tcp_keepintvl = producer->config.tcp_keepintvl;

    if (!next->endpoint || !next->region || !next->topic_id || !next->api_version || !next->compress_type ||
        ((producer->cfg_hash_key || producer->config.hash_key) && !next->default_hash_key) ||
        ((producer->cfg_ca_cert_path || producer->config.ca_cert_path) && !next->ca_cert_path) ||
        ((producer->cfg_proxy || producer->config.proxy) && !next->proxy) ||
        ((producer->cfg_user_agent || producer->config.user_agent) && !next->user_agent) ||
        ((producer->cfg_access_key_id || producer->config.access_key_id) && !next->access_key_id) ||
        ((producer->cfg_access_key_secret || producer->config.access_key_secret) && !next->access_key_secret) ||
        ((producer->cfg_security_token || producer->config.security_token) && !next->security_token)) {
        ve_tls_runtime_snapshot_free(next);
        return -1;
    }

    ve_tls_runtime_snapshot_publish_locked(producer, next);
    return 0;
}

int ve_tls_runtime_snapshot_refresh(ve_tls_producer * producer) {
    if (!producer) {
        return -1;
    }
    if (!producer->mutex) {
        return ve_tls_runtime_snapshot_refresh_locked(producer);
    }
    producer->config.platform.mutex_lock(producer->mutex);
    int rc = ve_tls_runtime_snapshot_refresh_locked(producer);
    producer->config.platform.mutex_unlock(producer->mutex);
    return rc;
}

void ve_tls_runtime_snapshot_clear(ve_tls_producer * producer) {
    if (!producer) {
        return;
    }
    ve_tls_runtime_snapshot * old = atomic_exchange_explicit(&producer->runtime_snapshot, NULL, memory_order_acq_rel);
    if (old) {
        ve_tls_runtime_snapshot_release(old);
    }
}
