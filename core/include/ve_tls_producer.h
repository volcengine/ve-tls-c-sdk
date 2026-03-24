#ifndef VE_TLS_PRODUCER_H
#define VE_TLS_PRODUCER_H

#include <stdint.h>
#include <stddef.h>

#include "ve_tls_retry.h"
#include "ve_tls_http.h"
#include "ve_tls_error.h"
#include "ve_tls_platform.h"

typedef struct ve_tls_producer ve_tls_producer;

typedef enum {
    VE_TLS_OK = 0,
    VE_TLS_INVALID = 1,
    VE_TLS_DROP_ERROR = 2,
    VE_TLS_PERSISTENT_ERROR = 3,
    VE_TLS_CLOSED = 4,
    VE_TLS_TIMEOUT = 5
} ve_tls_result;

typedef enum {
    VE_TLS_SEND_QUEUE_FULL_BLOCK = 0,
    VE_TLS_SEND_QUEUE_FULL_DROP = 1,
    VE_TLS_SEND_QUEUE_FULL_DROP_SAMPLED = 2
} ve_tls_send_queue_full_policy;

typedef enum {
    VE_TLS_BUFFER_FULL_DROP = 0,
    VE_TLS_BUFFER_FULL_BLOCK = 1
} ve_tls_buffer_full_policy;

typedef struct {
    const char * key;
    const char * value;
} ve_tls_kv;

typedef struct {
    void (*emit)(const char * name, int64_t v1, int64_t v2, void * user_param);
    void * user_param;
} ve_tls_metrics_sink;

typedef struct {
    const char * access_key_id;
    const char * access_key_secret;
    const char * security_token;
    int64_t expire_time_ms;
} ve_tls_credentials;

typedef int (*ve_tls_credentials_provider_fn)(ve_tls_credentials * out, void * user_param);

typedef struct {
    const char * endpoint;
    const char * region;
    const char * project_id;
    const char * topic_id;
    const char * source;
    const char * file_name;
    const char * context_flow;
    const ve_tls_kv * log_tags;
    size_t log_tag_count;
    const char * hash_key;
    int32_t enable_time_ns;
    const char * access_key_id;
    const char * access_key_secret;
    const char * security_token;
    ve_tls_credentials_provider_fn credentials_provider;
    void * credentials_provider_param;
    int64_t credentials_expire_advance_ms;
    int64_t credentials_refresh_min_interval_ms;
    const char * api_version;
    const char * compress_type;
    int32_t send_thread_count;
    int32_t use_global_env;
    int32_t ordered_send;
    int32_t rate_limit_rps;
    int32_t rate_limit_bps;
    int32_t breaker_fail_threshold;
    int32_t breaker_open_ms;
    int32_t breaker_half_open_max_inflight;
    int32_t max_buffer_bytes;
    ve_tls_buffer_full_policy buffer_full_policy;
    int32_t buffer_full_block_timeout_ms;
    int32_t log_bytes_per_package;
    int32_t log_count_per_package;
    int32_t flush_interval_ms;
    int32_t send_queue_size;
    ve_tls_send_queue_full_policy send_queue_full_policy;
    int32_t send_queue_block_timeout_ms;
    int32_t send_queue_sample_every_n;
    int32_t agg_strategy;
    int32_t agg_max_log_group_logs;
    int32_t agg_max_raw_bytes_per_request;
    int32_t agg_max_compressed_bytes_per_request;
    int32_t key_queue_max_active;
    int32_t key_queue_bucket_count;
    int32_t key_queue_idle_ttl_ms;
    int32_t key_rate_limit_rps;
    int32_t key_rate_limit_bps;
    int32_t key_breaker_fail_threshold;
    int32_t key_breaker_open_ms;
    int32_t connect_timeout_ms;
    int32_t request_timeout_ms;
    int32_t tls_verify_peer;
    int32_t tls_verify_host;
    const char * ca_cert_path;
    const char * proxy;
    const char * user_agent;
    int32_t http_debug;
    int32_t tcp_keepalive;
    int32_t tcp_keepidle;
    int32_t tcp_keepintvl;
    ve_tls_metrics_sink metrics_sink;
    int32_t retry_max_attempts;
    ve_tls_retry_policy retry_policy;
    int32_t use_persistent;
    const char * persistent_file_path;
    int32_t max_persistent_log_count;
    int32_t max_persistent_file_size;
    int32_t max_persistent_file_count;
    int32_t force_flush_disk;
    ve_tls_platform platform;
    ve_tls_http_client http_client;
} ve_tls_config;

typedef void (*ve_tls_send_done_fn)(
    ve_tls_result result,
    size_t log_bytes,
    size_t compressed_bytes,
    const char * req_id,
    const char * error_message,
    const unsigned char * raw_buffer,
    void * user_param,
    int64_t start_id,
    int64_t end_id
);

typedef void (*ve_tls_send_done_v2_fn)(
    ve_tls_result result,
    size_t log_bytes,
    size_t compressed_bytes,
    const ve_tls_error * error,
    const unsigned char * raw_buffer,
    void * user_param,
    int64_t start_id,
    int64_t end_id
);

typedef struct {
    uint64_t logs_enqueued_total;
    uint64_t logs_dropped_total;
    uint64_t bytes_enqueued_total;
    uint64_t bytes_dropped_total;
    uint64_t batches_built_total;
    uint64_t requests_total;
    uint64_t requests_failed_total;
    uint64_t retries_total;
    uint64_t bytes_sent_total;
    uint64_t request_latency_buckets[8];
} ve_tls_metrics;

void ve_tls_config_init(ve_tls_config * config);

ve_tls_producer * ve_tls_producer_create(const ve_tls_config * config);
ve_tls_result ve_tls_producer_update_endpoint(ve_tls_producer * producer, const char * endpoint, const char * region, const char * topic_id);
ve_tls_result ve_tls_producer_update_static_credentials(ve_tls_producer * producer, const char * access_key_id, const char * access_key_secret, const char * security_token);
ve_tls_result ve_tls_producer_close(ve_tls_producer * producer, int32_t timeout_ms);
void ve_tls_producer_destroy(ve_tls_producer * producer);

void ve_tls_producer_set_send_done(ve_tls_producer * producer, ve_tls_send_done_fn callback, void * user_param);
void ve_tls_producer_set_send_done_v2(ve_tls_producer * producer, ve_tls_send_done_v2_fn callback, void * user_param);
void ve_tls_producer_get_metrics(ve_tls_producer * producer, ve_tls_metrics * out);

ve_tls_result ve_tls_producer_add_log_raw(ve_tls_producer * producer, const char * log_buf, size_t log_size, int flush);
ve_tls_result ve_tls_producer_add_log_raw_time_parts(ve_tls_producer * producer, int64_t time_ms, int32_t has_time_ns, uint32_t time_ns, const char * log_buf, size_t log_size, int flush);
ve_tls_result ve_tls_producer_add_log_kv(ve_tls_producer * producer, int64_t time_ms, const ve_tls_kv * kvs, size_t kv_count, int flush);
ve_tls_result ve_tls_producer_add_log_kv_hashkey(ve_tls_producer * producer, int64_t time_ms, const char * hash_key, const ve_tls_kv * kvs, size_t kv_count, int flush);
ve_tls_result ve_tls_producer_add_log_kv_time_parts(ve_tls_producer * producer, int64_t time_ms, int32_t has_time_ns, uint32_t time_ns, const ve_tls_kv * kvs, size_t kv_count, int flush);
ve_tls_result ve_tls_producer_add_log_kv_time_parts_hashkey(ve_tls_producer * producer, int64_t time_ms, int32_t has_time_ns, uint32_t time_ns, const char * hash_key, const ve_tls_kv * kvs, size_t kv_count, int flush);
ve_tls_result ve_tls_producer_flush(ve_tls_producer * producer);
ve_tls_result ve_tls_producer_recover(ve_tls_producer * producer);
ve_tls_result ve_tls_producer_export_raw_buffer(ve_tls_producer * producer, unsigned char ** out_buf, size_t * out_size);
ve_tls_result ve_tls_producer_import_raw_buffer(ve_tls_producer * producer, const unsigned char * buf, size_t size);
void ve_tls_producer_free_raw_buffer(unsigned char * buf);

#endif
