#include "ve_tls_alloc.h"
#include "ve_tls_compress.h"
#include "ve_tls_env.h"
#include "ve_tls_error.h"
#include "ve_tls_hash.h"
#include "ve_tls_http.h"
#include "ve_tls_http_curl.h"
#include "ve_tls_platform.h"
#include "ve_tls_producer.h"
#include "ve_tls_proto.h"
#include "ve_tls_retry.h"
#include "ve_tls_sign.h"
#include "ve_tls_adapter.h"
#include "ve_tls_android_binding.h"
#include "ve_tls_version.h"

int main() {
    ve_tls_alloc_hooks hooks = {};
    ve_tls_config config = {};
    ve_tls_platform platform = {};
    ve_tls_retry_policy retry = {};
    ve_tls_http_response response = {};
    ve_tls_error error = {};
    ve_tls_android_config_view android_view = {};
    ve_tls_android_runtime_options runtime = {};
    char path[64] = {};
    ve_tls_producer *producer = nullptr;

    ve_tls_alloc_get_hooks(&hooks);
    ve_tls_config_init(&config);
    ve_tls_platform_init_default(&platform);
    ve_tls_retry_policy_init(&retry);
    ve_tls_http_response_init(&response);
    ve_tls_error_free_fields(&error);
    if (ve_tls_android_binding_build_config(&android_view, &config, &runtime) != VE_TLS_OK) {
        return 1;
    }
    if (ve_tls_android_binding_build_persistent_path("", "", path, sizeof(path)) != VE_TLS_OK) {
        return 1;
    }
    if (ve_tls_android_binding_after_create(nullptr, &runtime) != VE_TLS_INVALID) {
        return 1;
    }
    ve_tls_android_binding_before_destroy(nullptr, &runtime);

    config.endpoint = "https://example.com";
    config.region = "cn-beijing";
    config.topic_id = "topic";
    config.access_key_id = "ak";
    config.access_key_secret = "sk";
    producer = ve_tls_producer_create_versioned(
        &config, sizeof(config), VE_TLS_CONFIG_VERSION_CURRENT);
    if (producer == nullptr) {
        return 1;
    }
    ve_tls_producer_destroy(producer);
    if (ve_tls_producer_create_versioned(
            &config, sizeof(config), VE_TLS_CONFIG_VERSION_CURRENT + 1u) != nullptr) {
        return 1;
    }
    if (ve_tls_producer_create_versioned(
            &config, sizeof(config) - 1u, VE_TLS_CONFIG_VERSION_CURRENT) != nullptr) {
        return 1;
    }
    return 0;
}
