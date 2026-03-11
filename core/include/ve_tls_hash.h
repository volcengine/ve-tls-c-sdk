#ifndef VE_TLS_HASH_H
#define VE_TLS_HASH_H

#include <stddef.h>
#include <stdint.h>

void ve_tls_sha256(const unsigned char * data, size_t len, unsigned char out32[32]);
void ve_tls_hmac_sha256(const unsigned char * key, size_t key_len, const unsigned char * data, size_t len, unsigned char out32[32]);
void ve_tls_hex_lower(const unsigned char * data, size_t len, char * out_hex, size_t out_hex_cap);

#endif
