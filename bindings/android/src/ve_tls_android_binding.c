#include "ve_tls_android_binding.h"

#include <stdio.h>

static void ve_tls_android_config_view_copy_strings(const ve_tls_android_config_view * in, ve_tls_config * out) {
    if (!in || !out) return;
    out->endpoint = in->endpoint;
    out->region = in->region;
    out->project_id = in->project_id;
    out->topic_id = in->topic_id;
    out->source = in->source;
    out->access_key_id = in->access_key_id;
    out->access_key_secret = in->access_key_secret;
    out->security_token = in->security_token;
    out->user_agent = in->user_agent;
    out->hash_key = in->hash_key;
    out->persistent_file_path = in->persistent_file_path;
}

static void ve_tls_android_config_view_copy_http_client(const ve_tls_android_config_view * in, ve_tls_config * out) {
    if (!in || !out || !in->http_client) {
        return;
    }
    out->http_client.do_request = in->http_client->do_request;
    out->http_client.free_response = in->http_client->free_response;
    out->http_client.user_data = in->http_client->user_data;
}

static void ve_tls_android_config_view_copy_runtime_fields(const ve_tls_android_config_view * in, ve_tls_config * out) {
    if (!in || !out) {
        return;
    }
    out->log_tags = in->log_tags;
    out->log_tag_count = in->log_tag_count;
    out->log_bytes_per_package = in->log_bytes_per_package;
    out->log_count_per_package = in->log_count_per_package;
    out->flush_interval_ms = in->flush_interval_ms;
    out->max_buffer_bytes = in->max_buffer_bytes;
    out->retry_policy.max_attempts = in->retry_max_attempts;
    out->retry_policy.total_timeout_ms = in->retry_total_timeout_ms;
    out->retry_policy.initial_interval_ms = in->retry_initial_interval_ms;
    out->retry_policy.max_interval_ms = in->retry_max_interval_ms;
    out->connect_timeout_ms = in->connect_timeout_ms;
    out->request_timeout_ms = in->request_timeout_ms;
    out->enable_time_ns = in->enable_time_ns;
    out->max_persistent_log_count = in->max_persistent_log_count;
    out->max_persistent_file_size = in->max_persistent_file_size;
    out->max_persistent_file_count = in->max_persistent_file_count;
    out->force_flush_disk = in->force_flush_disk;
    out->persistent_durability = (ve_tls_persistent_durability)in->persistent_durability;
}

static int ve_tls_android_binding_sanitize_process_name(const char * in, char * out, size_t out_cap) {
    if (!out || out_cap == 0) {
        return -1;
    }
    if (!in) {
        out[0] = '\0';
        return 0;
    }
    size_t out_len = 0;
    for (const unsigned char * p = (const unsigned char *)in; *p; p++) {
        char c = (char)*p;
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.')) {
            c = '_';
        }
        if (out_len + 1 >= out_cap) {
            return -1;
        }
        out[out_len++] = c;
    }
    out[out_len] = '\0';
    return 0;
}

static int ve_tls_android_binding_is_non_main_process(const char * process_name) {
    if (!process_name) {
        return 0;
    }
    for (const char * p = process_name; *p; p++) {
        if (*p == ':') return 1;
    }
    return 0;
}

ve_tls_result ve_tls_android_binding_build_persistent_path(
    const char * base_path,
    const char * process_name,
    char * rewritten_path,
    size_t rewritten_cap
) {
    if (!base_path || !rewritten_path || rewritten_cap == 0) {
        return VE_TLS_INVALID;
    }
    if (process_name && process_name[0] != '\0' && ve_tls_android_binding_is_non_main_process(process_name)) {
        char sanitized[128];
        if (ve_tls_android_binding_sanitize_process_name(process_name, sanitized, sizeof(sanitized)) != 0) {
            return VE_TLS_INVALID;
        }
        if (sanitized[0] == '\0') {
            if (snprintf(rewritten_path, rewritten_cap, "%s", base_path) >= (int)rewritten_cap) {
                return VE_TLS_INVALID;
            }
            return VE_TLS_OK;
        }
        if (snprintf(rewritten_path, rewritten_cap, "%s-%s", base_path, sanitized) >= (int)rewritten_cap) {
            return VE_TLS_INVALID;
        }
        return VE_TLS_OK;
    }
    if (snprintf(rewritten_path, rewritten_cap, "%s", base_path) >= (int)rewritten_cap) {
        return VE_TLS_INVALID;
    }
    return VE_TLS_OK;
}

ve_tls_result ve_tls_android_binding_after_create(
    ve_tls_producer * producer,
    const ve_tls_android_runtime_options * runtime
) {
    if (!producer || !runtime) {
        return VE_TLS_INVALID;
    }
    if (!runtime->persistent_enabled || !runtime->recover) {
        return VE_TLS_OK;
    }
    return runtime->recover(producer);
}

void ve_tls_android_binding_before_destroy(
    ve_tls_producer * producer,
    const ve_tls_android_runtime_options * runtime
) {
    if (!producer || !runtime) {
        return;
    }
    ve_tls_android_destroy_fn destroy_fn = runtime->destroy ? runtime->destroy : ve_tls_producer_destroy;
    if (runtime->destroy_wait_split_enabled) {
        ve_tls_android_close_split_fn close_split_fn = runtime->close_split ? runtime->close_split : ve_tls_producer_close_split;
        (void)close_split_fn(producer, runtime->destroy_flusher_wait_ms, runtime->destroy_sender_wait_ms);
    } else {
        ve_tls_android_close_fn close_fn = runtime->close ? runtime->close : ve_tls_producer_close;
        (void)close_fn(producer, runtime->destroy_wait_ms);
    }
    destroy_fn(producer);
}

ve_tls_result ve_tls_android_binding_build_config(
    const ve_tls_android_config_view * in,
    ve_tls_config * out,
    ve_tls_android_runtime_options * runtime
) {
    if (!out || !in) {
        return VE_TLS_INVALID;
    }
    ve_tls_config_init(out);
    out->use_persistent = in->use_persistent;
    out->send_thread_count = in->send_thread_count;
    if (in->use_persistent) {
        out->send_thread_count = 1;
    }
    switch (in->compress_type) {
        case VE_TLS_ANDROID_COMPRESS_NONE:
            out->compress_type = "none";
            break;
        case VE_TLS_ANDROID_COMPRESS_LZ4:
            out->compress_type = "lz4";
            break;
        case VE_TLS_ANDROID_COMPRESS_ZLIB:
            out->compress_type = "zlib";
            break;
        case VE_TLS_ANDROID_COMPRESS_UNSPECIFIED:
        default:
            out->compress_type = "lz4";
            break;
    }
    if (runtime) {
        runtime->destroy_wait_ms = in->destroy_wait_ms;
        runtime->destroy_flusher_wait_ms = in->destroy_flusher_wait_ms;
        runtime->destroy_sender_wait_ms = in->destroy_sender_wait_ms;
        runtime->destroy_wait_split_enabled = in->destroy_wait_split_enabled;
        runtime->persistent_enabled = in->use_persistent;
        runtime->recover = in->use_persistent ? ve_tls_producer_recover : NULL;
        runtime->close = ve_tls_producer_close;
        runtime->close_split = ve_tls_producer_close_split;
        runtime->destroy = ve_tls_producer_destroy;
    }
    ve_tls_android_config_view_copy_strings(in, out);
    ve_tls_android_config_view_copy_runtime_fields(in, out);
    ve_tls_android_config_view_copy_http_client(in, out);
    return VE_TLS_OK;
}
