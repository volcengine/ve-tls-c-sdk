#ifndef VE_TLS_BRICKS_H
#define VE_TLS_BRICKS_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    const char * endpoint;
    const char * region;
    const char * topic_id;
    const char * api_version;
    const char * access_key_id;
    const char * access_key_secret;
    const char * security_token;
    const char * compress_type;
    const char * hash_key;
    const char * xdate;
    int body_no_copy;
} ve_tls_bricks_config;

typedef struct {
    char * method;
    char * url;
    char * headers;
    unsigned char * body;
    size_t body_size;
    size_t raw_body_size;
    int body_owned;
    int32_t log_count;
    int64_t earliest_log_time_ms;
    int64_t latest_log_time_ms;
} ve_tls_bricks_request;

int ve_tls_bricks_pack_request(
    const ve_tls_bricks_config * config,
    const unsigned char * raw_log_group_list,
    size_t raw_log_group_list_size,
    int32_t log_count,
    int64_t earliest_log_time_ms,
    int64_t latest_log_time_ms,
    ve_tls_bricks_request * out);

void ve_tls_bricks_request_free(ve_tls_bricks_request * req);

#endif
