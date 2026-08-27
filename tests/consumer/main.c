#include "ve_tls_http.h"
#include "ve_tls_http_curl.h"
#include "ve_tls_platform.h"
#include "ve_tls_producer.h"
#include "ve_tls_retry.h"
#include "ve_tls_version.h"

int main(void) {
    ve_tls_config config;
    ve_tls_platform platform;
    ve_tls_retry_policy retry;
    ve_tls_http_response response;
    ve_tls_producer *producer;

    if (ve_tls_config_init_versioned(
            &config, sizeof(config), VE_TLS_CONFIG_VERSION_CURRENT) != VE_TLS_OK) {
        return 1;
    }
    ve_tls_platform_init_default(&platform);
    ve_tls_retry_policy_init(&retry);
    ve_tls_http_response_init(&response);

#if defined(VE_TLS_HAVE_CURL)
    {
        ve_tls_http_client client = {0};
        ve_tls_http_client_init_curl(&client);
        if (client.do_request == NULL || client.free_response == NULL) {
            return 1;
        }
    }
#endif

    config.endpoint = "https://example.com";
    config.region = "cn-beijing";
    config.topic_id = "topic";
    config.access_key_id = "ak";
    config.access_key_secret = "sk";
    producer = ve_tls_producer_create_versioned(
        &config, sizeof(config), VE_TLS_CONFIG_VERSION_CURRENT);
    if (producer == NULL) {
        return 1;
    }
    ve_tls_producer_destroy(producer);
    if (ve_tls_producer_create_versioned(
            &config, sizeof(config), VE_TLS_CONFIG_VERSION_CURRENT + 1u) != NULL) {
        return 1;
    }
    if (ve_tls_producer_create_versioned(
            &config, sizeof(config) - 1u, VE_TLS_CONFIG_VERSION_CURRENT) != NULL) {
        return 1;
    }

    return config.api_version != 0 && platform.time_ms != 0 && retry.max_attempts > 0
        && response.status_code == 0 && VE_TLS_C_SDK_VERSION[0] != '\0' ? 0 : 1;
}
