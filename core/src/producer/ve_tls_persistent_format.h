#ifndef VE_TLS_PERSISTENT_FORMAT_H
#define VE_TLS_PERSISTENT_FORMAT_H

#include <stdint.h>
#include <stddef.h>

#define VE_TLS_PERSISTENT_RECORD_MAGIC 0x54504C31u
#define VE_TLS_PERSISTENT_RECORD_HEADER_SIZE 28u
#define VE_TLS_PERSISTENT_RECORD_EXT_MAX 1024u
#define VE_TLS_PERSISTENT_RECORD_HASH_KEY_MAX 256u

#define VE_TLS_PERSISTENT_RECORD_FLAG_HAS_EXT 0x00000001u

#define VE_TLS_PERSISTENT_EXT_TYPE_HASH_KEY 0x01u

typedef struct {
    int64_t log_id;
    uint32_t flags;
    const char * hash_key;
    const unsigned char * payload;
    size_t payload_size;
} ve_tls_persistent_record_view;

typedef struct {
    int64_t log_id;
    uint32_t flags;
    char * hash_key;
    unsigned char * payload;
    size_t payload_size;
} ve_tls_persistent_record;

size_t ve_tls_persistent_record_encoded_size(const ve_tls_persistent_record_view * view);
int ve_tls_persistent_record_encode(unsigned char * out, size_t out_cap, const ve_tls_persistent_record_view * view, size_t * out_size);
int ve_tls_persistent_record_decode(const unsigned char * buf, size_t size, ve_tls_persistent_record * out);
void ve_tls_persistent_record_free(ve_tls_persistent_record * record);

#endif
