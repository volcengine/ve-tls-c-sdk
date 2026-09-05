#ifndef VE_TLS_PERSISTENT_H
#define VE_TLS_PERSISTENT_H

#include "ve_tls_producer.h"
#include "ve_tls_checkpoint.h"
#include "ve_tls_lease.h"
#include "ve_tls_segment_store.h"

#include <stdint.h>
#include <stdatomic.h>

enum {
    VE_TLS_PERSISTENT_APPEND_REJECT_NEW = -2,
    VE_TLS_PERSISTENT_APPEND_BLOCKED = -3,
    VE_TLS_PERSISTENT_APPEND_SYNC_FAILED = -4,
    VE_TLS_PERSISTENT_FLUSH_CHECKPOINT_FAILED = -5,
    VE_TLS_PERSISTENT_APPEND_UNSUPPORTED_VERSION = -6
};

typedef struct {
    ve_tls_platform * platform;
    const char * dir_path;
    const char * instance_id;
    const char * owner_id;
    const char * owner_process_name;
    int32_t owner_pid;
    uint64_t segment_max_bytes;
    uint64_t segment_max_records;
    uint64_t max_bytes;
    uint64_t max_records;
    uint32_t max_segments;
    int32_t high_watermark_pct;
    int32_t low_watermark_pct;
    int32_t overflow_policy;
    int32_t sample_every_n;
    int32_t block_timeout_ms;
    int64_t now_ms;
    int64_t lease_timeout_ms;
    int64_t heartbeat_interval_ms;
    int open_mode;
    ve_tls_persistent_durability durability;
} ve_tls_persistent_options;

typedef struct {
    uint64_t size;
    uint64_t records;
    int64_t max_log_id;
    uint8_t exists;
} ve_tls_persistent_segment_meta;

struct ve_tls_persistent {
    ve_tls_platform * platform;
    char dir_path[512];
    char checkpoint_path[640];
    char lease_path[640];
    char owner_id[64];
    char owner_process_name[64];
    int32_t owner_pid;
    ve_tls_segment_store store;
    ve_tls_checkpoint_state checkpoint;
    ve_tls_lease_state lease;
    uint64_t max_bytes;
    uint64_t max_records;
    uint32_t max_segments;
    int32_t high_watermark_pct;
    int32_t low_watermark_pct;
    int32_t overflow_policy;
    int32_t sample_every_n;
    int32_t block_timeout_ms;
    int64_t lease_timeout_ms;
    int64_t heartbeat_interval_ms;
    int32_t open_mode;
    ve_tls_persistent_durability durability;
    ve_tls_mutex * heartbeat_mutex;
    _Atomic(int64_t) next_heartbeat_ms;
    _Atomic(int64_t) lease_valid_until_ms;
    uint64_t current_bytes;
    uint64_t current_records;
    uint32_t current_segments;
    int64_t durable_checkpoint_acked_log_id;
    int64_t last_checkpoint_save_ms;
    int64_t checkpoint_dirty_since_ms;
    uint32_t next_reclaim_segment_id;
    int64_t last_reclaim_acked_log_id;
    uint64_t append_dropped_records;
    uint64_t append_dropped_bytes;
    uint8_t checkpoint_dirty;
    uint8_t reclaim_pending;
    ve_tls_persistent_segment_meta * segment_meta;
    uint32_t segment_meta_cap;
    unsigned char * append_buf;
    size_t append_buf_cap;
};

typedef struct ve_tls_persistent ve_tls_persistent;

int ve_tls_persistent_open(ve_tls_persistent * persistent, const ve_tls_persistent_options * options);
void ve_tls_persistent_close(ve_tls_persistent * persistent);
int ve_tls_persistent_append(ve_tls_persistent * persistent, int64_t log_id, const char * hash_key, const unsigned char * payload, size_t payload_size);
int ve_tls_persistent_recover(
    ve_tls_persistent * persistent,
    int (*on_record)(
        int64_t log_id,
        int64_t enqueue_time_ms,
        const char * hash_key,
        const unsigned char * payload,
        size_t payload_size,
        void * user
    ),
    void * user
);
int ve_tls_persistent_ack_range(ve_tls_persistent * persistent, int64_t start_id, int64_t end_id);
int ve_tls_persistent_heartbeat_if_due(ve_tls_persistent * persistent, int force);
int ve_tls_persistent_flush(ve_tls_persistent * persistent);

#endif
