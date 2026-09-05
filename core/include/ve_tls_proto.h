#ifndef VE_TLS_PROTO_H
#define VE_TLS_PROTO_H

#include <stdint.h>
#include <stddef.h>

#include "ve_tls_export.h"
#include "ve_tls_producer.h"

VE_TLS_BEGIN_DECLS

typedef struct {
    unsigned char * data;
    size_t size;
} ve_tls_bytes;

int ve_tls_proto_encode_log(int64_t time_ms, const ve_tls_kv * kvs, size_t kv_count, ve_tls_bytes * out);
int ve_tls_proto_encode_log_ex(int64_t time_ms, uint32_t time_ns, int32_t has_time_ns, const ve_tls_kv * kvs, size_t kv_count, ve_tls_bytes * out);
int ve_tls_proto_encode_log_group_list(const ve_tls_bytes * logs, size_t log_count, const char * source, const char * file_name, ve_tls_bytes * out);
int ve_tls_proto_encode_log_group_list_ex(const ve_tls_bytes * logs, size_t log_count, const char * source, const char * file_name, const ve_tls_kv * log_tags, size_t log_tag_count, const char * context_flow, ve_tls_bytes * out);
int ve_tls_proto_encode_log_group_list_ex2(const ve_tls_bytes * logs, size_t log_count, const char * source, const char * file_name, const ve_tls_kv * log_tags, size_t log_tag_count, const char * context_flow, size_t max_log_group_logs, ve_tls_bytes * out);
void ve_tls_bytes_free(ve_tls_bytes * b);

#if defined(VE_TLS_ENABLE_ALLOC_FAULT_INJECT)
int ve_tls_proto_test_reserve(size_t len, size_t cap, size_t append_size);
#endif

VE_TLS_END_DECLS

#endif
