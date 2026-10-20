#ifndef VE_TLS_CONFIG_VERSION_CONTRACT_INC
#define VE_TLS_CONFIG_VERSION_CONTRACT_INC

#include "ve_tls_producer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    ve_tls_config config;
    unsigned char guard[32];
} ve_tls_config_contract_canary;

typedef struct {
    ve_tls_platform platform;
    ve_tls_mutex * mutex;
    ve_tls_cond * cond;
    int requests;
    int callbacks;
    int successes;
    int diagnostics;
    int terminal_successes;
    int schema_valid;
    int bad_wire;
} ve_tls_config_contract_state;

static int ve_tls_config_contract_bytes_are(
    const unsigned char * bytes,
    size_t size,
    unsigned char value
) {
    for (size_t i = 0; i < size; i++) {
        if (bytes[i] != value) return 0;
    }
    return 1;
}

static int ve_tls_config_contract_http_do(
    ve_tls_http_client * client,
    const ve_tls_http_request * request,
    ve_tls_http_response * response
) {
    ve_tls_config_contract_state * state = client ? client->user_data : NULL;
    if (!state || !request || !response ||
        !request->method || strcmp(request->method, "POST") != 0 ||
        !request->url || request->body_size == 0) {
        if (state) {
            state->platform.mutex_lock(state->mutex);
            state->bad_wire = 1;
            state->platform.mutex_unlock(state->mutex);
        }
        return -1;
    }
    state->platform.mutex_lock(state->mutex);
    state->requests++;
    state->platform.cond_broadcast(state->cond);
    state->platform.mutex_unlock(state->mutex);
    response->status_code = 200;
    return 0;
}

static void ve_tls_config_contract_http_free(
    ve_tls_http_client * client,
    ve_tls_http_response * response
) {
    (void)client;
    (void)response;
}

static void ve_tls_config_contract_send_done(
    ve_tls_result result,
    size_t log_bytes,
    size_t compressed_bytes,
    const char * request_id,
    const char * error_message,
    const unsigned char * raw_buffer,
    void * user_param,
    int64_t start_id,
    int64_t end_id
) {
    (void)log_bytes;
    (void)compressed_bytes;
    (void)request_id;
    (void)error_message;
    (void)raw_buffer;
    (void)start_id;
    (void)end_id;
    ve_tls_config_contract_state * state = user_param;
    if (!state) return;
    state->platform.mutex_lock(state->mutex);
    state->callbacks++;
    state->successes += result == VE_TLS_OK;
    state->platform.cond_broadcast(state->cond);
    state->platform.mutex_unlock(state->mutex);
}

static void ve_tls_config_contract_diagnostic(
    const ve_tls_delivery_diagnostic * event,
    void * user_param
) {
    ve_tls_config_contract_state * state = user_param;
    if (!state || !event) return;
    state->platform.mutex_lock(state->mutex);
    state->diagnostics++;
    if (event->metadata_version == VE_TLS_DELIVERY_DIAGNOSTIC_METADATA_VERSION_1 &&
        event->metadata_size == sizeof(*event)) {
        state->schema_valid = 1;
    }
    if (event->event == VE_TLS_DELIVERY_DIAGNOSTIC_BATCH_TERMINAL &&
        event->reason == VE_TLS_DELIVERY_DIAGNOSTIC_REASON_SUCCESS) {
        state->terminal_successes++;
    }
    state->platform.cond_broadcast(state->cond);
    state->platform.mutex_unlock(state->mutex);
}

static int ve_tls_config_contract_state_init(
    ve_tls_config_contract_state * state,
    const ve_tls_platform * platform
) {
    memset(state, 0, sizeof(*state));
    state->platform = *platform;
    state->mutex = state->platform.mutex_create();
    state->cond = state->platform.cond_create();
    if (state->mutex && state->cond) return 0;
    if (state->cond) state->platform.cond_destroy(state->cond);
    if (state->mutex) state->platform.mutex_destroy(state->mutex);
    memset(state, 0, sizeof(*state));
    return -1;
}

static void ve_tls_config_contract_state_reset(
    ve_tls_config_contract_state * state
) {
    state->platform.mutex_lock(state->mutex);
    state->requests = 0;
    state->callbacks = 0;
    state->successes = 0;
    state->diagnostics = 0;
    state->terminal_successes = 0;
    state->schema_valid = 0;
    state->bad_wire = 0;
    state->platform.mutex_unlock(state->mutex);
}

static void ve_tls_config_contract_state_destroy(
    ve_tls_config_contract_state * state
) {
    if (!state || !state->mutex || !state->cond) return;
    state->platform.cond_destroy(state->cond);
    state->platform.mutex_destroy(state->mutex);
    state->mutex = NULL;
    state->cond = NULL;
}

static int ve_tls_config_contract_wait(
    ve_tls_config_contract_state * state,
    int requests,
    int callbacks,
    int diagnostics,
    int terminal_successes
) {
    int64_t deadline = state->platform.time_ms() + 5000;
    state->platform.mutex_lock(state->mutex);
    while (state->requests < requests ||
           state->callbacks < callbacks ||
           state->diagnostics < diagnostics ||
           state->terminal_successes < terminal_successes) {
        int64_t remaining = deadline - state->platform.time_ms();
        if (remaining <= 0) break;
        state->platform.cond_timedwait_ms(state->cond, state->mutex, remaining);
    }
    int ok = state->requests >= requests &&
        state->callbacks >= callbacks &&
        state->diagnostics >= diagnostics &&
        state->terminal_successes >= terminal_successes;
    state->platform.mutex_unlock(state->mutex);
    return ok ? 0 : -1;
}

#define VE_TLS_CONFIG_CONTRACT_CHECK(expression) do { \
    if (!(expression)) { \
        fprintf(stderr, "%s:%d: %s\n", __func__, __LINE__, #expression); \
        rc = -1; \
        goto done; \
    } \
} while (0)

static int test_config_version_initialization_contract(void) {
    int rc = 0;
    ve_tls_config cfg;
    ve_tls_config_contract_state state;
    ve_tls_producer * producer = NULL;
    int state_ready = 0;
    const uint32_t versions[] = {
        VE_TLS_CONFIG_VERSION_1,
        VE_TLS_CONFIG_VERSION_2,
        VE_TLS_CONFIG_VERSION_3
    };
    const size_t sizes[] = {
        VE_TLS_CONFIG_VERSION_1_SIZE,
        VE_TLS_CONFIG_VERSION_2_SIZE,
        VE_TLS_CONFIG_VERSION_3_SIZE
    };

    ve_tls_config_contract_canary legacy_storage;
    ve_tls_config legacy_expected;
    memset(&legacy_storage, 0xA5, sizeof(legacy_storage));
    memset(&legacy_expected, 0x3C, sizeof(legacy_expected));
    ve_tls_config_init(&legacy_expected);
    ve_tls_config_init(&legacy_storage.config);
    VE_TLS_CONFIG_CONTRACT_CHECK(memcmp(
        &legacy_storage.config,
        &legacy_expected,
        VE_TLS_CONFIG_LEGACY_SIZE) == 0);
    VE_TLS_CONFIG_CONTRACT_CHECK(ve_tls_config_contract_bytes_are(
        ((const unsigned char *)&legacy_storage.config) + VE_TLS_CONFIG_LEGACY_SIZE,
        sizeof(legacy_storage.config) - VE_TLS_CONFIG_LEGACY_SIZE,
        0xA5));
    VE_TLS_CONFIG_CONTRACT_CHECK(ve_tls_config_contract_bytes_are(
        legacy_storage.guard, sizeof(legacy_storage.guard), 0xA5));

    for (size_t i = 0; i < 2; i++) {
        ve_tls_config_contract_canary versioned_storage;
        ve_tls_config versioned_expected;
        memset(&versioned_storage, 0xA5, sizeof(versioned_storage));
        memset(&versioned_expected, 0x3C, sizeof(versioned_expected));
        VE_TLS_CONFIG_CONTRACT_CHECK(ve_tls_config_init_versioned(
            &versioned_expected, sizes[i], versions[i]) == VE_TLS_OK);
        VE_TLS_CONFIG_CONTRACT_CHECK(ve_tls_config_init_versioned(
            &versioned_storage.config, sizes[i], versions[i]) == VE_TLS_OK);
        VE_TLS_CONFIG_CONTRACT_CHECK(memcmp(
            &versioned_storage.config, &versioned_expected, sizes[i]) == 0);
        VE_TLS_CONFIG_CONTRACT_CHECK(ve_tls_config_contract_bytes_are(
            ((const unsigned char *)&versioned_storage.config) + sizes[i],
            sizeof(versioned_storage.config) - sizes[i],
            0xA5));
        VE_TLS_CONFIG_CONTRACT_CHECK(ve_tls_config_contract_bytes_are(
            versioned_storage.guard, sizeof(versioned_storage.guard), 0xA5));
    }

    ve_tls_config_contract_canary v3_storage;
    ve_tls_config v3_expected;
    memset(&v3_storage, 0xA5, sizeof(v3_storage));
    memset(&v3_expected, 0x3C, sizeof(v3_expected));
    VE_TLS_CONFIG_CONTRACT_CHECK(ve_tls_config_init_versioned(
        &v3_expected, VE_TLS_CONFIG_VERSION_3_SIZE, VE_TLS_CONFIG_VERSION_3) == VE_TLS_OK);
    VE_TLS_CONFIG_CONTRACT_CHECK(ve_tls_config_init_versioned(
        &v3_storage.config, VE_TLS_CONFIG_VERSION_3_SIZE, VE_TLS_CONFIG_VERSION_3) == VE_TLS_OK);
    VE_TLS_CONFIG_CONTRACT_CHECK(memcmp(
        &v3_storage.config, &v3_expected, sizeof(v3_storage.config)) == 0);
    VE_TLS_CONFIG_CONTRACT_CHECK(v3_storage.config.memory_retry_retention_ms == 0);
    VE_TLS_CONFIG_CONTRACT_CHECK(v3_storage.config.bound_request_timeout_to_retry_budget == 0);
    VE_TLS_CONFIG_CONTRACT_CHECK(v3_storage.config.delivery_diagnostic == NULL);
    VE_TLS_CONFIG_CONTRACT_CHECK(v3_storage.config.delivery_diagnostic_param == NULL);
    VE_TLS_CONFIG_CONTRACT_CHECK(v3_storage.config.retry_transient_http_errors == 0);
    VE_TLS_CONFIG_CONTRACT_CHECK(ve_tls_config_contract_bytes_are(
        v3_storage.guard, sizeof(v3_storage.guard), 0xA5));

    VE_TLS_CONFIG_CONTRACT_CHECK(ve_tls_config_init_versioned(
        &cfg, sizeof(cfg), VE_TLS_CONFIG_VERSION_3) == VE_TLS_OK);
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "topic";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.compress_type = "none";
    cfg.send_thread_count = 1;
    cfg.pack_thread_count = 1;
    cfg.flush_interval_ms = 1;
    cfg.log_count_per_package = 1;
    cfg.retry_policy.max_attempts = 1;
    cfg.http_client.do_request = ve_tls_config_contract_http_do;
    cfg.http_client.free_response = ve_tls_config_contract_http_free;
    cfg.delivery_diagnostic = ve_tls_config_contract_diagnostic;

    VE_TLS_CONFIG_CONTRACT_CHECK(ve_tls_config_contract_state_init(
        &state, &cfg.platform) == 0);
    state_ready = 1;
    cfg.http_client.user_data = &state;
    cfg.delivery_diagnostic_param = &state;

    producer = ve_tls_producer_create_versioned(
        &cfg, VE_TLS_CONFIG_VERSION_3_SIZE, VE_TLS_CONFIG_VERSION_3);
    VE_TLS_CONFIG_CONTRACT_CHECK(producer != NULL);
    ve_tls_producer_set_send_done(producer, ve_tls_config_contract_send_done, &state);
    ve_tls_kv kv = {"message", "config-version-contract"};
    VE_TLS_CONFIG_CONTRACT_CHECK(ve_tls_producer_add_log_kv(
        producer, state.platform.time_ms(), &kv, 1, 1) == VE_TLS_OK);
    VE_TLS_CONFIG_CONTRACT_CHECK(ve_tls_config_contract_wait(&state, 1, 1, 1, 1) == 0);
    VE_TLS_CONFIG_CONTRACT_CHECK(state.successes >= 1 && state.schema_valid == 1);
    VE_TLS_CONFIG_CONTRACT_CHECK(state.bad_wire == 0);
    VE_TLS_CONFIG_CONTRACT_CHECK(ve_tls_producer_close(producer, 5000) == VE_TLS_OK);
    ve_tls_producer_destroy(producer);
    producer = NULL;

    /* Reuse the V3-populated config: legacy create consumes only its prefix. */
    ve_tls_config_contract_state_reset(&state);
    producer = ve_tls_producer_create(&cfg);
    VE_TLS_CONFIG_CONTRACT_CHECK(producer != NULL);
    ve_tls_producer_set_send_done(producer, ve_tls_config_contract_send_done, &state);
    VE_TLS_CONFIG_CONTRACT_CHECK(ve_tls_producer_add_log_kv(
        producer, state.platform.time_ms(), &kv, 1, 1) == VE_TLS_OK);
    VE_TLS_CONFIG_CONTRACT_CHECK(ve_tls_config_contract_wait(&state, 1, 1, 0, 0) == 0);
    VE_TLS_CONFIG_CONTRACT_CHECK(state.diagnostics == 0);
    VE_TLS_CONFIG_CONTRACT_CHECK(state.successes >= 1 && state.bad_wire == 0);
    VE_TLS_CONFIG_CONTRACT_CHECK(ve_tls_producer_close(producer, 5000) == VE_TLS_OK);
    ve_tls_producer_destroy(producer);
    producer = NULL;

done:
    if (producer) {
        (void)ve_tls_producer_close(producer, 5000);
        ve_tls_producer_destroy(producer);
    }
    if (state_ready) ve_tls_config_contract_state_destroy(&state);
    return rc;
}

#undef VE_TLS_CONFIG_CONTRACT_CHECK

#endif
