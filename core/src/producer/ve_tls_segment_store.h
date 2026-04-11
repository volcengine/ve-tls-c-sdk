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
} ve_tls_segment_store_options;

typedef struct {
    uint32_t segment_id;
    uint64_t offset;
    uint32_t size;
} ve_tls_segment_record_ref;

typedef struct {
    ve_tls_platform * platform;
    char dir_path[512];
    uint64_t segment_max_bytes;
    uint64_t segment_max_records;
    uint32_t active_segment_id;
    uint64_t active_size;
    uint64_t active_records;
    ve_tls_file * active_file;
} ve_tls_segment_store;

int ve_tls_segment_store_open(ve_tls_segment_store * store, const ve_tls_segment_store_options * options);
void ve_tls_segment_store_close(ve_tls_segment_store * store);
int ve_tls_segment_store_append(ve_tls_segment_store * store, const unsigned char * record, size_t size, ve_tls_segment_record_ref * out_ref);
int ve_tls_segment_store_read(ve_tls_segment_store * store, uint32_t segment_id, uint64_t offset, unsigned char ** out_record, size_t * out_size, uint64_t * next_offset);
void ve_tls_segment_store_read_free(unsigned char * record);
int ve_tls_segment_store_repair_tail(ve_tls_segment_store * store, uint32_t segment_id, uint64_t * valid_end_offset);
int ve_tls_segment_store_get_segment_path(const ve_tls_segment_store * store, uint32_t segment_id, char * out, size_t out_size);
int ve_tls_segment_store_scan_segment(ve_tls_segment_store * store, uint32_t segment_id, uint64_t * out_valid_end, uint64_t * out_record_count, int64_t * out_max_log_id);
int ve_tls_segment_store_get_segment_stats(ve_tls_segment_store * store, uint32_t segment_id, uint64_t * out_valid_end, uint64_t * out_record_count);

#endif
