#ifndef VE_TLS_SNAPSHOT_H
#define VE_TLS_SNAPSHOT_H

#include "ve_tls_producer.h"

#include <stdint.h>
#include <stdatomic.h>

typedef struct ve_tls_runtime_snapshot {
    _Atomic(uint32_t) refcnt;

    int64_t send_cfg_version;
    int64_t static_cred_version;

    char * endpoint;
    char * region;
    char * topic_id;
    char * api_version;
    char * compress_type;
    char * default_hash_key;
    char * ca_cert_path;
    char * proxy;
    char * user_agent;
    char * access_key_id;
    char * access_key_secret;
    char * security_token;

    int32_t connect_timeout_ms;
    int32_t request_timeout_ms;
    int32_t tls_verify_peer;
    int32_t tls_verify_host;
    int32_t http_debug;
    int32_t tcp_keepalive;
    int32_t tcp_keepidle;
    int32_t tcp_keepintvl;
} ve_tls_runtime_snapshot;

enum {
    VE_TLS_SNAPSHOT_PATCH_ENDPOINT = 1u << 0,
    VE_TLS_SNAPSHOT_PATCH_REGION = 1u << 1,
    VE_TLS_SNAPSHOT_PATCH_TOPIC_ID = 1u << 2,
    VE_TLS_SNAPSHOT_PATCH_ACCESS_KEY_ID = 1u << 3,
    VE_TLS_SNAPSHOT_PATCH_ACCESS_KEY_SECRET = 1u << 4,
    VE_TLS_SNAPSHOT_PATCH_SECURITY_TOKEN = 1u << 5
};

typedef struct {
    uint32_t field_mask;
    int64_t send_cfg_version;
    int64_t static_cred_version;
    const char * endpoint;
    const char * region;
    const char * topic_id;
    const char * access_key_id;
    const char * access_key_secret;
    const char * security_token;
} ve_tls_runtime_snapshot_patch;

const ve_tls_runtime_snapshot * ve_tls_runtime_snapshot_acquire(ve_tls_producer * producer);
void ve_tls_runtime_snapshot_release(const ve_tls_runtime_snapshot * snapshot);
int ve_tls_runtime_snapshot_refresh(ve_tls_producer * producer);
int ve_tls_runtime_snapshot_refresh_locked(ve_tls_producer * producer);
int ve_tls_runtime_snapshot_build_patched(
    const ve_tls_runtime_snapshot * base,
    const ve_tls_runtime_snapshot_patch * patch,
    ve_tls_runtime_snapshot ** out
);
void ve_tls_runtime_snapshot_publish_locked(
    ve_tls_producer * producer,
    ve_tls_runtime_snapshot * next
);
void ve_tls_runtime_snapshot_clear(ve_tls_producer * producer);

#endif
