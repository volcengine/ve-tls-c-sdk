#include "ve_tls_producer_internal.h"

#include <string.h>

#include "ve_tls_version.h"

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
    config->send_thread_count = 1;
    config->pack_thread_count = 1;
    config->use_global_env = 0;
    config->ordered_send = 0;
    config->rate_limit_rps = 0;
    config->rate_limit_bps = 0;
    config->breaker_fail_threshold = 0;
    config->breaker_open_ms = 30000;
    config->breaker_half_open_max_inflight = 1;
    config->max_buffer_bytes = 64 * 1024 * 1024;
    config->buffer_full_policy = VE_TLS_BUFFER_FULL_DROP;
    config->buffer_full_block_timeout_ms = 0;
    config->log_bytes_per_package = 10 * 1024 * 1024;
    config->log_count_per_package = 2048;
    config->flush_interval_ms = 1000;
    config->send_queue_size = 1024;
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
    config->request_timeout_ms = 10000;
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
    ve_tls_retry_policy_init(&config->retry_policy);
    ve_tls_platform_init_default(&config->platform);
#if defined(VE_TLS_HAVE_CURL)
    ve_tls_http_client_init_curl(&config->http_client);
#else
    ve_tls_http_client_init_noop(&config->http_client);
#endif
}
