#ifndef VE_TLS_HTTP_H
#define VE_TLS_HTTP_H

#include <stdint.h>
#include <stddef.h>

#include "ve_tls_export.h"

VE_TLS_BEGIN_DECLS

typedef enum {
    VE_TLS_TRANSPORT_NONE = 0,
    VE_TLS_TRANSPORT_CURL = 1,
    VE_TLS_TRANSPORT_GENERIC = 2
} ve_tls_transport_kind;

typedef struct {
    const char * method;
    const char * url;
    const char * headers;
    const unsigned char * body;
    size_t body_size;
    int64_t connect_timeout_ms;
    int64_t timeout_ms;
    int32_t tls_verify_peer;
    int32_t tls_verify_host;
    const char * ca_cert_path;
    const char * proxy;
    const char * user_agent;
    int32_t tcp_keepalive;
    int32_t tcp_keepidle;
    int32_t tcp_keepintvl;
    int32_t debug_log;
} ve_tls_http_request;

typedef struct {
    int32_t status_code;
    unsigned char * body;
    size_t body_size;
    char * request_id;
    char * error_code;
    char * error_message;
    ve_tls_transport_kind transport_kind;
    int32_t transport_code;
    /* Adapter-owned retry decision for transport failures returned by
     * do_request. Set to non-zero only when replaying this request is safe and
     * likely to succeed; zero is terminal. The producer honors this field for
     * every transport_kind, including VE_TLS_TRANSPORT_GENERIC. */
    int32_t transport_retryable;
} ve_tls_http_response;

typedef struct ve_tls_http_client ve_tls_http_client;

typedef int (*ve_tls_http_do_fn)(
    ve_tls_http_client * client,
    const ve_tls_http_request * req,
    ve_tls_http_response * resp
);

typedef void (*ve_tls_http_free_response_fn)(
    ve_tls_http_client * client,
    ve_tls_http_response * resp
);

struct ve_tls_http_client {
    ve_tls_http_do_fn do_request;
    ve_tls_http_free_response_fn free_response;
    void * user_data;
};

VE_TLS_API void ve_tls_http_response_init(ve_tls_http_response * resp);

VE_TLS_END_DECLS

#endif
