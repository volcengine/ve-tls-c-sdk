#include "../include/ve_tls_producer.h"

#include <stdlib.h>
#include <string.h>

struct ve_tls_producer {
    ve_tls_config config;
    ve_tls_send_done_fn send_done;
    void * send_done_param;
};

void ve_tls_config_init(ve_tls_config * config) {
    if (!config) {
        return;
    }
    memset(config, 0, sizeof(ve_tls_config));
    config->send_thread_count = 1;
    config->max_buffer_bytes = 64 * 1024 * 1024;
    config->log_bytes_per_package = 3 * 1024 * 1024;
    config->log_count_per_package = 2048;
    config->flush_interval_ms = 1000;
}

ve_tls_producer * ve_tls_producer_create(const ve_tls_config * config) {
    if (!config) {
        return NULL;
    }
    ve_tls_producer * producer = (ve_tls_producer *)calloc(1, sizeof(ve_tls_producer));
    if (!producer) {
        return NULL;
    }
    producer->config = *config;
    return producer;
}

void ve_tls_producer_destroy(ve_tls_producer * producer) {
    if (!producer) {
        return;
    }
    free(producer);
}

void ve_tls_producer_set_send_done(ve_tls_producer * producer, ve_tls_send_done_fn callback, void * user_param) {
    if (!producer) {
        return;
    }
    producer->send_done = callback;
    producer->send_done_param = user_param;
}

ve_tls_result ve_tls_producer_add_log_raw(ve_tls_producer * producer, const char * log_buf, size_t log_size, int flush) {
    if (!producer || !log_buf || log_size == 0) {
        return VE_TLS_INVALID;
    }
    (void)flush;
    return VE_TLS_OK;
}

ve_tls_result ve_tls_producer_recover(ve_tls_producer * producer) {
    if (!producer) {
        return VE_TLS_INVALID;
    }
    return VE_TLS_OK;
}
