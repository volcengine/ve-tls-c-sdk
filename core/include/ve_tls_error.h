#ifndef VE_TLS_ERROR_H
#define VE_TLS_ERROR_H

#include <stdint.h>

#include "ve_tls_export.h"
#include "ve_tls_http.h"

VE_TLS_BEGIN_DECLS

typedef struct {
    int32_t http_code;
    char * error_code;
    char * error_message;
    char * request_id;
    ve_tls_transport_kind transport_kind;
    int32_t transport_code;
    int32_t retryable;
} ve_tls_error;

VE_TLS_API void ve_tls_error_free_fields(ve_tls_error * err);

VE_TLS_END_DECLS

#endif
