#include "ve_tls_producer_internal.h"
#include "ve_tls_version.h"

#include <string.h>

enum {
    VE_TLS_DEFAULT_PERSISTENT_LEASE_TIMEOUT_MS = 60000,
    VE_TLS_DEFAULT_PERSISTENT_HEARTBEAT_INTERVAL_MS = 10000
};

#if defined(VE_TLS_HAVE_CURL)
#include "ve_tls_http_curl.h"
#endif

#if !defined(VE_TLS_HAVE_CURL)
static int ve_tls_http_noop_do(ve_tls_http_client * client, const ve_tls_http_request * req, ve_tls_http_response * resp) {
    (void)client;
    (void)req;
    (void)resp;
    return -1;
}

static void ve_tls_http_noop_free(ve_tls_http_client * client, ve_tls_http_response * resp) {
    (void)client;
    (void)resp;
}

static void ve_tls_http_client_init_noop(ve_tls_http_client * client) {
    if (!client) {
        return;
    }
    client->do_request = ve_tls_http_noop_do;
    client->free_response = ve_tls_http_noop_free;
    client->user_data = NULL;
}
#endif

enum {
    /* Zero is the auto-tune sentinel. Positive values are exact caller
     * overrides, including one; do not conflate an explicit single-thread
     * configuration with the runtime-derived default. */
    VE_TLS_DEFAULT_SEND_THREAD_COUNT = 0,
    VE_TLS_DEFAULT_PACK_THREAD_COUNT = 0,
    VE_TLS_DEFAULT_MAX_BUFFER_BYTES = 64 * 1024 * 1024,
    VE_TLS_DEFAULT_LOG_BYTES_PER_PACKAGE = 10 * 1024 * 1024,
    VE_TLS_DEFAULT_LOG_COUNT_PER_PACKAGE = 2048,
    /* Zero is the auto-tune sentinel. Keep positive values available as exact
     * caller overrides; 1024 is also a useful real capacity for high-cardinality
     * ordered/hash routing and must not be mistaken for "use defaults". */
    VE_TLS_AUTO_SEND_QUEUE_SIZE = 0
};

static int32_t ve_tls_runtime_default_package_bytes(int32_t max_buffer_bytes) {
    if (max_buffer_bytes > 0 && max_buffer_bytes <= 64 * 1024 * 1024) {
        return 2 * 1024 * 1024;
    }
    return 4 * 1024 * 1024;
}

static int32_t ve_tls_runtime_default_thread_count(int32_t max_buffer_bytes) {
    if (max_buffer_bytes > 0 && max_buffer_bytes <= 64 * 1024 * 1024) {
        return 2;
    }
    if (max_buffer_bytes > 0 && max_buffer_bytes <= 256 * 1024 * 1024) {
        return 4;
    }
    return 8;
}

static int32_t ve_tls_runtime_default_send_queue_size(int32_t max_buffer_bytes, int32_t log_bytes_per_package) {
    int32_t base = 8;
    if (max_buffer_bytes > 0 && log_bytes_per_package > 0) {
        base += max_buffer_bytes / log_bytes_per_package;
    }
    if (base < 8) {
        base = 8;
    } else if (base > 128) {
        base = 128;
    }
    return base;
}

void ve_tls_producer_config_init(ve_tls_config * config) {
    if (!config) {
        return;
    }
    memset(config, 0, sizeof(ve_tls_config));
    config->api_version = VE_TLS_C_SDK_API_VERSION;
    config->user_agent = VE_TLS_C_SDK_DEFAULT_USER_AGENT;
#if defined(VE_TLS_HAVE_LZ4)
    config->compress_type = "lz4";
#elif defined(VE_TLS_HAVE_ZLIB)
    config->compress_type = "zlib";
#else
    config->compress_type = "none";
#endif
    config->send_thread_count = VE_TLS_DEFAULT_SEND_THREAD_COUNT;
    config->pack_thread_count = VE_TLS_DEFAULT_PACK_THREAD_COUNT;
    config->use_global_env = 0;
    config->ordered_send = 0;
    config->rate_limit_rps = 0;
    config->rate_limit_bps = 0;
    config->breaker_fail_threshold = 0;
    config->breaker_open_ms = 30000;
    config->breaker_half_open_max_inflight = 1;
    config->max_buffer_bytes = VE_TLS_DEFAULT_MAX_BUFFER_BYTES;
    config->buffer_full_policy = VE_TLS_BUFFER_FULL_DROP;
    config->buffer_full_block_timeout_ms = 0;
    config->log_bytes_per_package = VE_TLS_DEFAULT_LOG_BYTES_PER_PACKAGE;
    config->log_count_per_package = VE_TLS_DEFAULT_LOG_COUNT_PER_PACKAGE;
    config->flush_interval_ms = 1000;
    config->send_queue_size = VE_TLS_AUTO_SEND_QUEUE_SIZE;
    config->send_queue_full_policy = VE_TLS_SEND_QUEUE_FULL_DROP;
    config->send_queue_block_timeout_ms = 100;
    config->send_queue_sample_every_n = 10;
    config->agg_strategy = 1;
    config->agg_max_log_group_logs = 10000;
    config->agg_max_raw_bytes_per_request = 10 * 1024 * 1024;
    config->agg_max_compressed_bytes_per_request = 5 * 1024 * 1024;
    config->enable_time_ns = 0;
    config->key_queue_max_active = 0;
    config->key_queue_bucket_count = 1024;
    config->key_queue_idle_ttl_ms = 0;
    config->key_rate_limit_rps = 0;
    config->key_rate_limit_bps = 0;
    config->key_breaker_fail_threshold = 0;
    config->key_breaker_open_ms = 30000;
    config->connect_timeout_ms = 10000;
    config->request_timeout_ms = 50000;
    config->tls_verify_peer = 1;
    config->tls_verify_host = 1;
    config->http_debug = 0;
    config->tcp_keepalive = 0;
    config->tcp_keepidle = 60;
    config->tcp_keepintvl = 30;
    config->metrics_sink.emit = NULL;
    config->metrics_sink.user_param = NULL;
    config->credentials_provider = NULL;
    config->credentials_provider_param = NULL;
    config->credentials_expire_advance_ms = 300000;
    config->credentials_refresh_min_interval_ms = 60000;
    config->persistent_high_watermark_pct = 85;
    config->persistent_low_watermark_pct = 70;
    config->persistent_overflow_policy = VE_TLS_POVERFLOW_REJECT_NEW;
    config->persistent_sample_every_n = 10;
    config->persistent_block_timeout_ms = 1000;
    config->persistent_lease_timeout_ms = VE_TLS_DEFAULT_PERSISTENT_LEASE_TIMEOUT_MS;
    config->persistent_heartbeat_interval_ms = VE_TLS_DEFAULT_PERSISTENT_HEARTBEAT_INTERVAL_MS;
    config->persistent_open_mode = VE_TLS_POPEN_TAKEOVER_IF_STALE;
    config->persistent_durability = VE_TLS_PDURABILITY_DEFAULT;
    config->persistent_max_log_delay_ms = 0;
    config->persistent_expired_log_policy = VE_TLS_PEXPIRED_REWRITE;
    config->persistent_auth_failure_policy = VE_TLS_PAUTH_RETAIN;
    ve_tls_retry_policy_init(&config->retry_policy);
    ve_tls_platform_init_default(&config->platform);
#if defined(VE_TLS_HAVE_CURL)
    ve_tls_http_client_init_curl(&config->http_client);
#else
    ve_tls_http_client_init_noop(&config->http_client);
#endif
}

void ve_tls_producer_config_apply_runtime_defaults(ve_tls_config * config) {
    int32_t derived_log_bytes;
    int32_t derived_threads;

    if (!config) {
        return;
    }

    if (config->persistent_lease_timeout_ms == 0) {
        config->persistent_lease_timeout_ms = VE_TLS_DEFAULT_PERSISTENT_LEASE_TIMEOUT_MS;
    }
    if (config->persistent_heartbeat_interval_ms == 0) {
        config->persistent_heartbeat_interval_ms = VE_TLS_DEFAULT_PERSISTENT_HEARTBEAT_INTERVAL_MS;
    }

    derived_log_bytes = ve_tls_runtime_default_package_bytes(config->max_buffer_bytes);
    if (config->log_bytes_per_package == VE_TLS_DEFAULT_LOG_BYTES_PER_PACKAGE) {
        config->log_bytes_per_package = derived_log_bytes;
    }
    if (config->log_count_per_package == VE_TLS_DEFAULT_LOG_COUNT_PER_PACKAGE) {
        config->log_count_per_package = 4096;
    }

    derived_threads = ve_tls_runtime_default_thread_count(config->max_buffer_bytes);
    if (config->send_thread_count == VE_TLS_DEFAULT_SEND_THREAD_COUNT) {
        config->send_thread_count = derived_threads;
    }
    if (config->pack_thread_count == VE_TLS_DEFAULT_PACK_THREAD_COUNT) {
        config->pack_thread_count = config->send_thread_count;
    }
    if (config->send_queue_size == VE_TLS_AUTO_SEND_QUEUE_SIZE) {
        config->send_queue_size = ve_tls_runtime_default_send_queue_size(
            config->max_buffer_bytes,
            config->log_bytes_per_package > 0 ? config->log_bytes_per_package : derived_log_bytes);
    }
}
