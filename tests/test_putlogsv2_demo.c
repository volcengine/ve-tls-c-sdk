#include "ve_tls_producer.h"

static void initialize_demo_config(ve_tls_config * config);

#define main putlogsv2_demo_main
#define ve_tls_config_init initialize_demo_config
#include "../tools/putlogsv2_demo.c"
#undef ve_tls_config_init
#undef main

static int64_t test_unix_ns;
static int request_count;

static int64_t test_time_ms(void) {
    return test_unix_ns / 1000000LL;
}

static int64_t test_time_unix_ns(void) {
    return test_unix_ns;
}

static int send_demo_request(
    ve_tls_http_client * client,
    const ve_tls_http_request * request,
    ve_tls_http_response * response
) {
    (void)client;
    if (!request->body || request->body_size == 0 ||
        !strstr(request->headers, "Authorization:")) {
        return -1;
    }
    request_count++;
    response->status_code = 200;
    return 0;
}

static void free_demo_response(
    ve_tls_http_client * client,
    ve_tls_http_response * response
) {
    (void)client;
    memset(response, 0, sizeof(*response));
}

static void initialize_demo_config(ve_tls_config * config) {
    ve_tls_config_init(config);
    config->platform.time_ms = test_time_ms;
    config->platform.time_unix_ns = test_time_unix_ns;
    config->http_client.do_request = send_demo_request;
    config->http_client.free_response = free_demo_response;
}

int main(void) {
    const int64_t timestamps[] = {
        1700000000123456789LL,
        1700000000000999999LL,
        1700000000001000000LL
    };
    char program[] = "ve_tls_demo_putlogsv2";
    char * arguments[] = {program, NULL};
    if (setenv("VE_TLS_ENDPOINT", "https://example.com", 1) != 0 ||
        setenv("VE_TLS_REGION", "cn-beijing", 1) != 0 ||
        setenv("VE_TLS_TOPIC_ID", "demo-test", 1) != 0 ||
        setenv("VE_TLS_ACCESS_KEY_ID", "demo-test-ak", 1) != 0 ||
        setenv("VE_TLS_ACCESS_KEY_SECRET", "demo-test-sk", 1) != 0 ||
        setenv("VE_TLS_SECURITY_TOKEN", "", 1) != 0 ||
        setenv("VE_TLS_HTTP_DEBUG", "0", 1) != 0) {
        return 1;
    }
    for (size_t i = 0; i < sizeof(timestamps) / sizeof(timestamps[0]); i++) {
        test_unix_ns = timestamps[i];
        if (putlogsv2_demo_main(1, arguments) != 0 || request_count != (int)i + 1) {
            return 1;
        }
    }
    return 0;
}
