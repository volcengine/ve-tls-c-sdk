#ifndef VE_TLS_LEASE_H
#define VE_TLS_LEASE_H

#include "ve_tls_platform.h"

#include <stdint.h>

enum {
    VE_TLS_LEASE_OPEN_FAIL_IF_OWNED = 0,
    VE_TLS_LEASE_OPEN_TAKEOVER_IF_STALE = 1
};

typedef struct {
    char owner_id[64];
    int32_t owner_pid;
    char owner_process_name[64];
    int64_t acquire_time_ms;
    int64_t last_heartbeat_ms;
    uint64_t fencing_token;
} ve_tls_lease_state;

typedef struct {
    ve_tls_platform * platform;
    const char * lease_path;
    const char * owner_id;
    int32_t owner_pid;
    const char * owner_process_name;
    int64_t now_ms;
    int64_t lease_timeout_ms;
    int mode;
} ve_tls_lease_options;

int ve_tls_lease_acquire(const ve_tls_lease_options * options, ve_tls_lease_state * state);
int ve_tls_lease_heartbeat(const ve_tls_lease_options * options, ve_tls_lease_state * state);
int ve_tls_lease_release(ve_tls_platform * platform, const char * lease_path);
int ve_tls_lease_load(ve_tls_platform * platform, const char * lease_path, ve_tls_lease_state * state);

#endif
