#include "ve_tls_error.h"
#include "ve_tls_alloc.h"

#include <stdlib.h>

void ve_tls_error_free_fields(ve_tls_error * err) {
    if (!err) {
        return;
    }
    ve_tls_free(err->error_code);
    ve_tls_free(err->error_message);
    ve_tls_free(err->request_id);
    err->error_code = NULL;
    err->error_message = NULL;
    err->request_id = NULL;
    err->http_code = 0;
    err->transport_kind = VE_TLS_TRANSPORT_NONE;
    err->transport_code = 0;
    err->retryable = 0;
}
