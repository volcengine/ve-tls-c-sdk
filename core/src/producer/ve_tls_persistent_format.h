#ifndef VE_TLS_PERSISTENT_FORMAT_H
#define VE_TLS_PERSISTENT_FORMAT_H

#include <stdint.h>
#include <stddef.h>

#define VE_TLS_PERSISTENT_RECORD_MAGIC 0x54504C31u
#define VE_TLS_PERSISTENT_RECORD_HEADER_SIZE 28u
#define VE_TLS_PERSISTENT_RECORD_EXT_MAX 1024u
#define VE_TLS_PERSISTENT_RECORD_HASH_KEY_MAX 256u
#define VE_TLS_PERSISTENT_RECORD_VERSION_LEGACY 1u
#define VE_TLS_PERSISTENT_RECORD_VERSION_CURRENT 2u
#define VE_TLS_PERSISTENT_RECORD_UNSUPPORTED_VERSION (-2)
#define VE_TLS_PERSISTENT_RECORD_BAD_CRC (-4)

#define VE_TLS_PERSISTENT_RECORD_FLAG_HAS_EXT 0x00000001u
#define VE_TLS_PERSISTENT_RECORD_FLAG_RAW 0x00000002u
#define VE_TLS_PERSISTENT_RECORD_FLAG_FLUSH 0x00000004u

#define VE_TLS_PERSISTENT_EXT_TYPE_HASH_KEY 0x01u
#define VE_TLS_PERSISTENT_EXT_TYPE_METADATA 0x02u
#define VE_TLS_PERSISTENT_EXT_TYPE_RAW_TIME 0x03u

typedef enum {
    VE_TLS_RECOVERY_CRC_OK = 0,
    VE_TLS_RECOVERY_CRC_RETAINED,
    VE_TLS_RECOVERY_CRC_RETIRED
} ve_tls_recovery_crc;

typedef struct {
    int64_t log_id;
    uint32_t flags;
    const char * hash_key;
    const unsigned char * payload;
    size_t payload_size;
    uint32_t record_version;
    int64_t enqueue_time_ms;
    int64_t raw_time_ms;
} ve_tls_persistent_record_view;

typedef struct {
    int64_t log_id;
    uint32_t flags;
    char * hash_key;
    unsigned char * payload;
    size_t payload_size;
    uint32_t record_version;
    int64_t enqueue_time_ms;
    int64_t raw_time_ms;
    ve_tls_recovery_crc recovery_crc;
} ve_tls_persistent_record;

/* Streaming CRC32 state. Initialize with UINT32_MAX and xor the result with
 * UINT32_MAX after the last chunk. */
uint32_t ve_tls_wal_crc32_update(uint32_t crc, const unsigned char * data, size_t size);
size_t ve_tls_persistent_record_encoded_size(const ve_tls_persistent_record_view * view);
int ve_tls_persistent_record_encode(unsigned char * out, size_t out_cap, const ve_tls_persistent_record_view * view, size_t * out_size);
int ve_tls_persistent_record_decode(const unsigned char * buf, size_t size, ve_tls_persistent_record * out);
void ve_tls_persistent_record_free(ve_tls_persistent_record * record);

#endif
