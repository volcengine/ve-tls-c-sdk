#ifndef VE_TLS_SEGMENT_STORE_H
#define VE_TLS_SEGMENT_STORE_H

#include "ve_tls_platform.h"

#include <stdint.h>
#include <stddef.h>

typedef struct {
    ve_tls_platform * platform;
    const char * dir_path;
    uint64_t segment_max_bytes;
    uint64_t segment_max_records;
    int32_t sync_on_append;
} ve_tls_segment_store_options;

typedef enum {
    VE_TLS_SEGMENT_STORE_OK = 0,
    VE_TLS_SEGMENT_STORE_ERROR = -1,
    VE_TLS_SEGMENT_STORE_SYNC_FAILED = -2,
    VE_TLS_SEGMENT_STORE_UNSUPPORTED_VERSION = -3,
    VE_TLS_SEGMENT_STORE_IO_ERROR = -7,
    VE_TLS_SEGMENT_STORE_INVALID_RECORD = -8
} ve_tls_segment_store_result;

typedef struct {
    uint32_t segment_id;
    uint64_t offset;
    uint32_t size;
} ve_tls_segment_record_ref;

typedef struct {
    uint64_t framed_size;
    uint64_t record_count;
    int64_t min_log_id;
    int64_t max_log_id;
    uint8_t has_bad_crc;
    uint8_t can_retire_bad_crc;
    uint8_t keep_unframed_tail;
} ve_tls_segment_scan;

typedef struct {
    ve_tls_file * file;
    uint64_t size;
    uint64_t offset;
} ve_tls_segment_reader;

typedef struct {
    ve_tls_platform * platform;
    char dir_path[512];
    uint64_t segment_max_bytes;
    uint64_t segment_max_records;
    uint32_t active_segment_id;
    uint64_t active_size;
    uint64_t active_records;
    ve_tls_file * active_file;
    int32_t sync_on_append;
    uint8_t active_dirty;
    uint8_t active_needs_rotation;
    uint8_t append_failed;
} ve_tls_segment_store;

int ve_tls_segment_store_open(ve_tls_segment_store * store, const ve_tls_segment_store_options * options);
void ve_tls_segment_store_close(ve_tls_segment_store * store);
int ve_tls_segment_store_flush(ve_tls_segment_store * store);
int ve_tls_segment_store_reset_active(ve_tls_segment_store * store);
int ve_tls_segment_store_would_rotate(const ve_tls_segment_store * store, size_t size);
int ve_tls_segment_store_append(ve_tls_segment_store * store, const unsigned char * record, size_t size, ve_tls_segment_record_ref * out_ref);
int ve_tls_segment_store_read(ve_tls_segment_store * store, uint32_t segment_id, uint64_t offset, unsigned char ** out_record, size_t * out_size, uint64_t * next_offset);
void ve_tls_segment_store_read_free(unsigned char * record);
int ve_tls_segment_store_reader_open(ve_tls_segment_store * store, uint32_t segment_id, uint64_t segment_size, ve_tls_segment_reader * reader);
int ve_tls_segment_store_reader_next(ve_tls_segment_store * store, ve_tls_segment_reader * reader, unsigned char ** out_record, size_t * out_size);
void ve_tls_segment_store_reader_close(ve_tls_segment_store * store, ve_tls_segment_reader * reader);
int ve_tls_segment_store_repair_tail(ve_tls_segment_store * store, uint32_t segment_id, uint64_t record_offset);
int ve_tls_segment_store_get_segment_path(const ve_tls_segment_store * store, uint32_t segment_id, char * out, size_t out_size);
int ve_tls_segment_store_scan_segment(ve_tls_segment_store * store, uint32_t segment_id, ve_tls_segment_scan * scan);
int ve_tls_segment_store_get_segment_stats(ve_tls_segment_store * store, uint32_t segment_id, uint64_t * out_valid_end, uint64_t * out_record_count);

#endif
