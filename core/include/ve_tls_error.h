#ifndef VE_TLS_ERROR_H
#define VE_TLS_ERROR_H

#include <stdint.h>

#include "ve_tls_http.h"

typedef struct {
    int32_t http_code;
    char * error_code;
    char * error_message;
    char * request_id;
    ve_tls_transport_kind transport_kind;
    int32_t transport_code;
    int32_t retryable;
} ve_tls_error;

void ve_tls_error_free_fields(ve_tls_error * err);

#endif
