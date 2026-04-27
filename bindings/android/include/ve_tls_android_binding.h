#ifndef VE_TLS_ANDROID_BINDING_H
#define VE_TLS_ANDROID_BINDING_H

#include <stdint.h>
#include <stddef.h>

#include "ve_tls_producer.h"

typedef ve_tls_result (*ve_tls_android_recover_fn)(ve_tls_producer * producer);
typedef ve_tls_result (*ve_tls_android_close_fn)(ve_tls_producer * producer, int32_t timeout_ms);
typedef ve_tls_result (*ve_tls_android_close_split_fn)(ve_tls_producer * producer, int32_t flusher_timeout_ms, int32_t sender_timeout_ms);
typedef void (*ve_tls_android_destroy_fn)(ve_tls_producer * producer);

typedef enum {
    VE_TLS_ANDROID_COMPRESS_UNSPECIFIED = 0,
    VE_TLS_ANDROID_COMPRESS_NONE = 1,
    VE_TLS_ANDROID_COMPRESS_LZ4 = 2,
    VE_TLS_ANDROID_COMPRESS_ZLIB = 3
} ve_tls_android_compress_type;

typedef struct {
    ve_tls_http_do_fn do_request;
    ve_tls_http_free_response_fn free_response;
    void * user_data;
} ve_tls_android_http_client_bridge;

typedef struct {
    const char * endpoint;
    const char * region;
    const char * project_id;
    const char * topic_id;
    const char * access_key_id;
    const char * access_key_secret;
    const char * security_token;
    const char * source;
    const char * hash_key;
    const ve_tls_kv * log_tags;
    size_t log_tag_count;
    ve_tls_android_compress_type compress_type;
    int32_t send_thread_count;
    int32_t log_bytes_per_package;
    int32_t log_count_per_package;
    int32_t flush_interval_ms;
    int32_t max_buffer_bytes;
    int32_t retry_max_attempts;
    int32_t retry_total_timeout_ms;
    int32_t retry_initial_interval_ms;
    int32_t retry_max_interval_ms;
    int32_t connect_timeout_ms;
    int32_t request_timeout_ms;
    int32_t enable_time_ns;
    int32_t use_persistent;
    const char * persistent_file_path;
    int32_t max_persistent_log_count;
    int32_t max_persistent_file_size;
    int32_t max_persistent_file_count;
    int32_t force_flush_disk;
    int32_t destroy_wait_ms;
    int32_t destroy_flusher_wait_ms;
    int32_t destroy_sender_wait_ms;
    int32_t destroy_wait_split_enabled;
    const ve_tls_android_http_client_bridge * http_client;
} ve_tls_android_config_view;

typedef struct {
    int32_t destroy_wait_ms;
    int32_t destroy_flusher_wait_ms;
    int32_t destroy_sender_wait_ms;
    int32_t destroy_wait_split_enabled;
    int32_t persistent_enabled;
    ve_tls_android_recover_fn recover;
    ve_tls_android_close_fn close;
    ve_tls_android_close_split_fn close_split;
    ve_tls_android_destroy_fn destroy;
} ve_tls_android_runtime_options;

ve_tls_result ve_tls_android_binding_build_config(
    const ve_tls_android_config_view * in,
    ve_tls_config * out,
    ve_tls_android_runtime_options * runtime
);

ve_tls_result ve_tls_android_binding_build_persistent_path(
    const char * base_path,
    const char * process_name,
    char * rewritten_path,
    size_t rewritten_cap
);

ve_tls_result ve_tls_android_binding_after_create(
    ve_tls_producer * producer,
    const ve_tls_android_runtime_options * runtime
);

void ve_tls_android_binding_before_destroy(
    ve_tls_producer * producer,
    const ve_tls_android_runtime_options * runtime
);

#endif
