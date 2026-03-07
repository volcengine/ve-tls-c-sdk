#ifndef VE_TLS_PRODUCER_H
#define VE_TLS_PRODUCER_H

#include <stdint.h>
#include <stddef.h>

typedef struct ve_tls_producer ve_tls_producer;

typedef enum {
    VE_TLS_OK = 0,
    VE_TLS_INVALID = 1,
    VE_TLS_DROP_ERROR = 2,
    VE_TLS_PERSISTENT_ERROR = 3
} ve_tls_result;

typedef struct {
    int32_t send_thread_count;
    int32_t max_buffer_bytes;
    int32_t log_bytes_per_package;
    int32_t log_count_per_package;
    int32_t flush_interval_ms;
    int32_t use_persistent;
    const char * persistent_file_path;
    int32_t max_persistent_log_count;
    int32_t max_persistent_file_size;
    int32_t max_persistent_file_count;
    int32_t force_flush_disk;
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

void ve_tls_config_init(ve_tls_config * config);

ve_tls_producer * ve_tls_producer_create(const ve_tls_config * config);
void ve_tls_producer_destroy(ve_tls_producer * producer);

void ve_tls_producer_set_send_done(ve_tls_producer * producer, ve_tls_send_done_fn callback, void * user_param);

ve_tls_result ve_tls_producer_add_log_raw(ve_tls_producer * producer, const char * log_buf, size_t log_size, int flush);
ve_tls_result ve_tls_producer_recover(ve_tls_producer * producer);

#endif
