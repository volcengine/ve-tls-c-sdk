#include "../include/ve_tls_http.h"

#include <string.h>

void ve_tls_http_response_init(ve_tls_http_response * resp) {
    if (!resp) {
        return;
    }
    memset(resp, 0, sizeof(ve_tls_http_response));
}
