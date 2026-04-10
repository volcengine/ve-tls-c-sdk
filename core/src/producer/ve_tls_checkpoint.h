#ifndef VE_TLS_CHECKPOINT_H
#define VE_TLS_CHECKPOINT_H

#include "ve_tls_platform.h"

#include <stdint.h>

typedef struct {
    int64_t acked_log_id;
    int64_t replay_begin_log_id;
    uint32_t replay_begin_segment_id;
    uint64_t replay_begin_offset;
    uint32_t last_segment_id;
} ve_tls_checkpoint_state;

int ve_tls_checkpoint_save(ve_tls_platform * platform, const char * path, const ve_tls_checkpoint_state * state);
int ve_tls_checkpoint_load(ve_tls_platform * platform, const char * path, ve_tls_checkpoint_state * state);

#endif
