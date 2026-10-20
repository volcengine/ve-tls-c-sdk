#ifndef VE_TLS_LEASE_H
#define VE_TLS_LEASE_H

#include "ve_tls_platform.h"

#include <stddef.h>
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
    /* Unique per instance, including successive owners in the same process.
       Private callers must not reuse a fixed id: token/time alone permit ABA. */
    const char * owner_id;
    int32_t owner_pid;
    const char * owner_process_name;
    int64_t now_ms;
    int64_t lease_timeout_ms;
    int mode;
    int sync_on_heartbeat;
} ve_tls_lease_options;

/* Private producer identity helper.  Generates a fresh 128-bit owner nonce
   and returns the process id used with it; failures leave outputs empty.
   Requires local POSIX /dev/urandom; never falls back to time or a fixed id. */
int ve_tls_lease_create_owner(char * out, size_t out_capacity, int32_t * pid_out);

int ve_tls_lease_acquire(const ve_tls_lease_options * options, ve_tls_lease_state * state);
int ve_tls_lease_heartbeat(const ve_tls_lease_options * options, ve_tls_lease_state * state);
/* Raw removal primitive: persistent owners use release_owned_locked instead. */
int ve_tls_lease_release(ve_tls_platform * platform, const char * lease_path);
int ve_tls_lease_load(ve_tls_platform * platform, const char * lease_path, ve_tls_lease_state * state);

/* Private local-POSIX guard. Each enter opens a distinct lease.lock descriptor;
   wait=0 fails immediately on contention, wait=1 waits. Never unlink the sidecar
   while an instance may use it. All *_locked calls require this guard, held
   through the complete file mutation. Default persistent mode takes the
   retained descriptor per operation; exclusive persistent mode keeps its
   descriptor locked for the instance lifetime and uses the instance mutex as
   the operation guard. Stateless callers use enter/leave. Never invoke
   SDK/user callbacks while holding the operation guard; exclusive ownership
   remains held by the instance during callbacks. */
int ve_tls_lease_guard_enter(const char * lease_path, int wait, int * fd_out);
int ve_tls_lease_guard_lock(int fd, int wait);
int ve_tls_lease_guard_unlock(int fd);
void ve_tls_lease_guard_close(int fd);
void ve_tls_lease_guard_leave(int fd);
int ve_tls_lease_acquire_locked(const ve_tls_lease_options * options, ve_tls_lease_state * state);
int ve_tls_lease_heartbeat_locked(const ve_tls_lease_options * options, ve_tls_lease_state * state);
int ve_tls_lease_validate_locked(
    ve_tls_platform * platform,
    const char * lease_path,
    const ve_tls_lease_state * state
);
int ve_tls_lease_release_owned_locked(
    ve_tls_platform * platform,
    const char * lease_path,
    const ve_tls_lease_state * state
);

#endif
