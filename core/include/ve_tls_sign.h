#ifndef VE_TLS_SIGN_H
#define VE_TLS_SIGN_H

#include <stddef.h>

int ve_tls_sign_v4_append(
    const char * access_key_id,
    const char * access_key_secret,
    const char * security_token,
    const char * region,
    const char * service,
    const char * method,
    const char * host,
    const char * path,
    const char * query,
    const unsigned char * body,
    size_t body_size,
    const char * headers_in,
    char ** headers_out
);

int ve_tls_sign_v4_append_at(
    const char * access_key_id,
    const char * access_key_secret,
    const char * security_token,
    const char * region,
    const char * service,
    const char * method,
    const char * host,
    const char * path,
    const char * query,
    const unsigned char * body,
    size_t body_size,
    const char * xdate_override,
    const char * headers_in,
    char ** headers_out
);

#endif
