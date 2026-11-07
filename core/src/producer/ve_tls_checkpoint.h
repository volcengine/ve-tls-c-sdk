#ifndef VE_TLS_CHECKPOINT_H
#define VE_TLS_CHECKPOINT_H

#include "ve_tls_platform.h"

#include <stddef.h>
#include <stdint.h>

typedef struct {
    int64_t acked_log_id;
    int64_t replay_begin_log_id;
    uint32_t replay_begin_segment_id;
    uint64_t replay_begin_offset;
    uint32_t last_segment_id;
} ve_tls_checkpoint_state;

typedef struct {
    int64_t start_id;
    int64_t end_id;
} ve_tls_checkpoint_range;

enum {
    VE_TLS_CHECKPOINT_LOAD_OK = 0,
    /* The V1 prefix is valid, but an extension is damaged or unsupported. */
    VE_TLS_CHECKPOINT_LOAD_EXT_INVALID = 1,
    VE_TLS_CHECKPOINT_LOAD_ERROR = -1,
    /* Allocation failed: the caller must not reset or overwrite the file. */
    VE_TLS_CHECKPOINT_LOAD_OOM = -2
};

/* Legacy APIs read/write only the V1 contiguous acknowledgement prefix.
 * All saves for a path must be serialized by the caller's persistence lock.
 * A save failure leaves either the prior file or a complete replacement; the
 * latter is possible if directory fsync fails after rename. */
int ve_tls_checkpoint_save(ve_tls_platform * platform, const char * path, const ve_tls_checkpoint_state * state);
int ve_tls_checkpoint_load(ve_tls_platform * platform, const char * path, ve_tls_checkpoint_state * state);

/* The returned range array belongs to the caller and must be freed with
 * ve_tls_free. On any nonzero result no ranges are returned. EXT_INVALID
 * preserves the valid V1 prefix; ERROR means the prefix or I/O failed. */
int ve_tls_checkpoint_save_ranges(ve_tls_platform * platform, const char * path,
    const ve_tls_checkpoint_state * state, const ve_tls_checkpoint_range * ranges, size_t count);
int ve_tls_checkpoint_load_ranges(ve_tls_platform * platform, const char * path,
    ve_tls_checkpoint_state * state, ve_tls_checkpoint_range ** ranges, size_t * count);

#endif
