/* Real sender-thread retention coverage.  This file is textually included by
 * test_basic.c after its internal test fixtures, so it may use the internal
 * producer/queue types only to build a deterministic allocator fixture. */

#include <pthread.h>
#include <time.h>

#define TLS_THREAD_MAX_SCHEDULED 64

typedef enum {
    TLS_THREAD_HTTP_RETRY = 0,
    TLS_THREAD_HTTP_REQUEUE_OOM = 1
} tls_thread_http_mode;

typedef struct tls_thread_state {
    ve_tls_platform platform;
    ve_tls_mutex * mutex;
    ve_tls_cond * cond;
    ve_tls_producer * producer;
    tls_thread_http_mode http_mode;
    int64_t http_sleep_ms;
    int http_success;
    int request_count;
    int callback_count;
    int callback_v1_count;
    int retained_count;
    int terminal_count;
    int scheduled_count;
    int provider_calls;
    int schema_error;
    int oom_fixture_error;
    int credential_test_clock;
    int oom_hit;
    pthread_t sender_thread;
    int sender_thread_valid;
    ve_tls_result result;
    ve_tls_result callback_v1_result;
    ve_tls_delivery_diagnostic_reason terminal_reason;
    ve_tls_delivery_diagnostic_disposition terminal_disposition;
    ve_tls_delivery_diagnostic_disposition retained_disposition;
    char terminal_error_code[64];
    char callback_error_code[64];
    char callback_v1_error_message[128];
    int64_t scheduled_elapsed[TLS_THREAD_MAX_SCHEDULED];
} tls_thread_state;

/* The producer under the credentials-deadline test sees this wrapper, while
 * tls_thread_wait continues to use state.platform.time_ms directly. */
static _Atomic int64_t tls_thread_clock_offset_ms;
static int64_t (*tls_thread_clock_base_ms)(void);

static int64_t tls_thread_clock_ms(void) {
    int64_t base = tls_thread_clock_base_ms ? tls_thread_clock_base_ms() : 0;
    int64_t offset = atomic_load_explicit(&tls_thread_clock_offset_ms, memory_order_relaxed);
    if (offset > 0 && base > INT64_MAX - offset) return INT64_MAX;
    if (offset < 0 && base < INT64_MIN - offset) return INT64_MIN;
    return base + offset;
}

static void tls_thread_clock_reset(void) {
    atomic_store_explicit(&tls_thread_clock_offset_ms, 0, memory_order_relaxed);
    tls_thread_clock_base_ms = NULL;
}

static int64_t tls_thread_provider_now(const tls_thread_state * state) {
    if (state && state->credential_test_clock) return tls_thread_clock_ms();
    return state && state->platform.time_ms ? state->platform.time_ms() : 0;
}

static int tls_thread_state_init(tls_thread_state * state) {
    if (!state) return -1;
    memset(state, 0, sizeof(*state));
    state->result = VE_TLS_INVALID;
    ve_tls_platform_init_default(&state->platform);
    state->mutex = state->platform.mutex_create();
    state->cond = state->platform.cond_create();
    if (!state->mutex || !state->cond) {
        if (state->cond) state->platform.cond_destroy(state->cond);
        if (state->mutex) state->platform.mutex_destroy(state->mutex);
        memset(state, 0, sizeof(*state));
        return -1;
    }
    return 0;
}

static void tls_thread_state_destroy(tls_thread_state * state) {
    if (!state) return;
    if (state->cond) state->platform.cond_destroy(state->cond);
    if (state->mutex) state->platform.mutex_destroy(state->mutex);
    memset(state, 0, sizeof(*state));
}

typedef int (*tls_thread_predicate)(const tls_thread_state * state);

static int tls_thread_wait(
    tls_thread_state * state,
    tls_thread_predicate predicate,
    int64_t timeout_ms
) {
    if (!state || !predicate || timeout_ms < 0) return -1;
    int64_t now = state->platform.time_ms ? state->platform.time_ms() : 0;
    int64_t deadline = now > INT64_MAX - timeout_ms ? INT64_MAX : now + timeout_ms;
    state->platform.mutex_lock(state->mutex);
    while (!predicate(state)) {
        now = state->platform.time_ms ? state->platform.time_ms() : deadline;
        int64_t remaining = deadline - now;
        if (remaining <= 0) break;
        if (!state->platform.cond_timedwait_ms ||
            state->platform.cond_timedwait_ms(state->cond, state->mutex, remaining) != 0) {
            break;
        }
    }
    int ok = predicate(state);
    state->platform.mutex_unlock(state->mutex);
    return ok ? 0 : -1;
}

static int tls_thread_pred_retained(const tls_thread_state * state) {
    return state && state->retained_count >= 1;
}

static int tls_thread_pred_terminal(const tls_thread_state * state) {
    return state && state->terminal_count >= 1 && state->callback_count >= 1;
}

static int tls_thread_wait_quiet(tls_thread_state * state, int64_t timeout_ms) {
    if (!state || timeout_ms < 0) return -1;
    state->platform.mutex_lock(state->mutex);
    if (state->platform.cond_timedwait_ms) {
        (void)state->platform.cond_timedwait_ms(state->cond, state->mutex, timeout_ms);
    } else if (state->platform.sleep_ms) {
        state->platform.mutex_unlock(state->mutex);
        state->platform.sleep_ms(timeout_ms);
        return 0;
    }
    state->platform.mutex_unlock(state->mutex);
    return 0;
}

static void tls_thread_reset_observations(tls_thread_state * state) {
    if (!state) return;
    state->platform.mutex_lock(state->mutex);
    state->producer = NULL;
    state->request_count = 0;
    state->callback_count = 0;
    state->callback_v1_count = 0;
    state->retained_count = 0;
    state->terminal_count = 0;
    state->scheduled_count = 0;
    state->provider_calls = 0;
    state->schema_error = 0;
    state->oom_fixture_error = 0;
    state->sender_thread_valid = 0;
    state->result = VE_TLS_INVALID;
    state->callback_v1_result = VE_TLS_INVALID;
    state->terminal_reason = VE_TLS_DELIVERY_DIAGNOSTIC_REASON_NONE;
    state->terminal_disposition = VE_TLS_DELIVERY_DIAGNOSTIC_DISPOSITION_UNKNOWN;
    state->retained_disposition = VE_TLS_DELIVERY_DIAGNOSTIC_DISPOSITION_UNKNOWN;
    memset(state->terminal_error_code, 0, sizeof(state->terminal_error_code));
    memset(state->callback_error_code, 0, sizeof(state->callback_error_code));
    memset(state->callback_v1_error_message, 0, sizeof(state->callback_v1_error_message));
    memset(state->scheduled_elapsed, 0, sizeof(state->scheduled_elapsed));
    state->platform.mutex_unlock(state->mutex);
}

static int tls_thread_pred_two_retained(const tls_thread_state * state) {
    return state && state->retained_count >= 2 && state->scheduled_count >= 3;
}

static int tls_thread_elapsed_is_cumulative(const tls_thread_state * state) {
    if (!state || state->scheduled_count <= 0 || state->scheduled_count > TLS_THREAD_MAX_SCHEDULED) {
        return 0;
    }
    int64_t previous = -1;
    for (int i = 0; i < state->scheduled_count; i++) {
        if (state->scheduled_elapsed[i] < 0 ||
            (previous >= 0 && state->scheduled_elapsed[i] < previous)) {
            return 0;
        }
        previous = state->scheduled_elapsed[i];
    }
    return 1;
}

static void tls_thread_diagnostic(
    const ve_tls_delivery_diagnostic * event,
    void * user_param
) {
    tls_thread_state * state = (tls_thread_state *)user_param;
    if (!state || !event) return;
    state->platform.mutex_lock(state->mutex);
    if (event->metadata_version != VE_TLS_DELIVERY_DIAGNOSTIC_METADATA_VERSION_1 ||
        event->metadata_size != sizeof(*event)) {
        state->schema_error = 1;
    }
    if (event->event == VE_TLS_DELIVERY_DIAGNOSTIC_RETRY_SCHEDULED) {
        if (state->scheduled_count < TLS_THREAD_MAX_SCHEDULED) {
            state->scheduled_elapsed[state->scheduled_count] = event->elapsed_ms;
        } else {
            state->schema_error = 1;
        }
        state->scheduled_count++;
    } else if (event->event == VE_TLS_DELIVERY_DIAGNOSTIC_BATCH_RETAINED) {
        state->retained_count++;
        state->retained_disposition = event->disposition;
        state->sender_thread = pthread_self();
        state->sender_thread_valid = 1;
    } else if (event->event == VE_TLS_DELIVERY_DIAGNOSTIC_BATCH_TERMINAL) {
        state->terminal_count++;
        state->terminal_reason = event->reason;
        state->terminal_disposition = event->disposition;
        snprintf(
            state->terminal_error_code,
            sizeof(state->terminal_error_code),
            "%s",
            event->error_code ? event->error_code : "");
    }
    state->platform.cond_broadcast(state->cond);
    state->platform.mutex_unlock(state->mutex);
}

static void tls_thread_done(
    ve_tls_result result,
    size_t log_bytes,
    size_t compressed_bytes,
    const ve_tls_error * error,
    const unsigned char * raw_buffer,
    void * user_param,
    int64_t start_id,
    int64_t end_id
) {
    (void)log_bytes;
    (void)compressed_bytes;
    (void)raw_buffer;
    (void)start_id;
    (void)end_id;
    tls_thread_state * state = (tls_thread_state *)user_param;
    if (!state) return;
    state->platform.mutex_lock(state->mutex);
    state->callback_count++;
    state->result = result;
    snprintf(
        state->callback_error_code,
        sizeof(state->callback_error_code),
        "%s",
        error && error->error_code ? error->error_code : "");
    state->platform.cond_broadcast(state->cond);
    state->platform.mutex_unlock(state->mutex);
}

static void tls_thread_done_v1(
    ve_tls_result result,
    size_t log_bytes,
    size_t compressed_bytes,
    const char * req_id,
    const char * error_message,
    const unsigned char * raw_buffer,
    void * user_param,
    int64_t start_id,
    int64_t end_id
) {
    (void)log_bytes;
    (void)compressed_bytes;
    (void)req_id;
    (void)raw_buffer;
    (void)start_id;
    (void)end_id;
    tls_thread_state * state = (tls_thread_state *)user_param;
    if (!state) return;
    state->platform.mutex_lock(state->mutex);
    state->callback_v1_count++;
    state->callback_v1_result = result;
    snprintf(
        state->callback_v1_error_message,
        sizeof(state->callback_v1_error_message),
        "%s",
        error_message ? error_message : "");
    state->platform.cond_broadcast(state->cond);
    state->platform.mutex_unlock(state->mutex);
}

static ve_tls_key_queue * tls_thread_find_inflight_queue(ve_tls_producer * producer) {
    if (!producer || !producer->key_buckets) return NULL;
    for (size_t i = 0; i < producer->key_bucket_count; i++) {
        for (ve_tls_key_queue * q = producer->key_buckets[i]; q; q = q->hnext) {
            if (q->inflight || (q->count == 0 && q->q)) return q;
        }
    }
    return NULL;
}

static _Thread_local int tls_thread_fail_requeue_alloc;

static int tls_thread_http_do(
    ve_tls_http_client * client,
    const ve_tls_http_request * req,
    ve_tls_http_response * resp
) {
    (void)req;
    if (!client || !resp) return -1;
    tls_thread_state * state = (tls_thread_state *)client->user_data;
    if (!state) return -1;
    state->platform.mutex_lock(state->mutex);
    state->request_count++;
    tls_thread_http_mode mode = state->http_mode;
    int64_t sleep_ms = state->http_sleep_ms;
    int http_success = state->http_success;
    ve_tls_producer * producer = state->producer;
    state->platform.cond_broadcast(state->cond);
    state->platform.mutex_unlock(state->mutex);

    if (sleep_ms > 0 && state->platform.sleep_ms) {
        state->platform.sleep_ms(sleep_ms);
    }
    if (http_success) {
        resp->status_code = 200;
        return 0;
    }
    if (mode == TLS_THREAD_HTTP_REQUEUE_OOM) {
        int fixture_ok = 0;
        if (producer && producer->mutex) {
            producer->config.platform.mutex_lock(producer->mutex);
            ve_tls_key_queue * q = tls_thread_find_inflight_queue(producer);
            if (q && q->q && q->count == 0) {
                /* The popped task owns no ring slot.  Drop only the ring so
                 * the real memory-retention push_front must allocate it. */
                ve_tls_free(q->q);
                q->q = NULL;
                q->cap = 0;
                q->head = 0;
                q->tail = 0;
                q->count = 0;
                fixture_ok = 1;
            }
            producer->config.platform.mutex_unlock(producer->mutex);
        }
        if (!fixture_ok) {
            state->platform.mutex_lock(state->mutex);
            state->oom_fixture_error = 1;
            state->platform.mutex_unlock(state->mutex);
        } else {
            tls_thread_fail_requeue_alloc = 1;
        }
    }
    resp->transport_kind = VE_TLS_TRANSPORT_GENERIC;
    resp->transport_code = 7;
    resp->transport_retryable = 1;
    return -1;
}

static void tls_thread_http_free(
    ve_tls_http_client * client,
    ve_tls_http_response * response
) {
    (void)client;
    (void)response;
}

static int tls_thread_credentials(
    ve_tls_credentials * out,
    void * user_param
) {
    tls_thread_state * state = (tls_thread_state *)user_param;
    if (!state || !out) return -1;
    state->platform.mutex_lock(state->mutex);
    state->provider_calls++;
    int call = state->provider_calls;
    state->platform.cond_broadcast(state->cond);
    state->platform.mutex_unlock(state->mutex);

    int64_t now = tls_thread_provider_now(state);
    if (call >= 2) {
        /* Cross the producer's 60000 ms retention deadline in one atomic
         * clock adjustment, then return credentials valid at that new time. */
        atomic_fetch_add_explicit(
            &tls_thread_clock_offset_ms, 60001, memory_order_relaxed);
        now = tls_thread_provider_now(state);
    }
    out->access_key_id = "retention-test-ak";
    out->access_key_secret = "retention-test-sk";
    out->security_token = NULL;
    out->expire_time_ms = call == 1 ? now + 5 : now + 60000;
    return 0;
}

static int tls_thread_config(
    ve_tls_config * config,
    tls_thread_state * state,
    int64_t retention_ms,
    int32_t max_attempts,
    int64_t retry_interval_ms
) {
    if (!config || !state ||
        ve_tls_config_init_versioned(
            config, sizeof(*config), VE_TLS_CONFIG_VERSION_3) != VE_TLS_OK) {
        return -1;
    }
    config->endpoint = "https://retention.example.com";
    config->region = "cn-beijing";
    config->topic_id = "retention-test-topic";
    config->access_key_id = "retention-test-ak";
    config->access_key_secret = "retention-test-sk";
    config->compress_type = "none";
    config->send_thread_count = 1;
    config->pack_thread_count = 1;
    config->use_global_env = 0;
    config->flush_interval_ms = 1;
    config->log_count_per_package = 1;
    config->request_timeout_ms = 1000;
    config->retry_policy.max_attempts = max_attempts;
    config->retry_policy.initial_interval_ms = retry_interval_ms;
    config->retry_policy.max_interval_ms = retry_interval_ms;
    config->retry_policy.randomization_factor = 0;
    config->memory_retry_retention_ms = retention_ms;
    config->http_client.do_request = tls_thread_http_do;
    config->http_client.free_response = tls_thread_http_free;
    config->http_client.user_data = state;
    config->delivery_diagnostic = tls_thread_diagnostic;
    config->delivery_diagnostic_param = state;
    return 0;
}

static ve_tls_producer * tls_thread_open(
    ve_tls_config * config,
    tls_thread_state * state
) {
    ve_tls_producer * producer = ve_tls_producer_create_versioned(
        config, sizeof(*config), VE_TLS_CONFIG_VERSION_3);
    if (!producer) return NULL;
    state->platform.mutex_lock(state->mutex);
    state->producer = producer;
    state->platform.mutex_unlock(state->mutex);
    ve_tls_producer_set_send_done_v2(producer, tls_thread_done, state);
    return producer;
}

static int tls_thread_add_one(ve_tls_producer * producer) {
    static const char body[] = "retention-thread-payload";
    return producer && ve_tls_producer_add_log_raw(
        producer, body, sizeof(body) - 1, 1) == VE_TLS_OK ? 0 : -1;
}

static int tls_thread_expect_terminal(
    const tls_thread_state * state,
    ve_tls_result result,
    ve_tls_delivery_diagnostic_reason reason,
    const char * error_code
) {
    return state && state->schema_error == 0 && state->request_count >= 1 &&
        state->callback_count == 1 && state->terminal_count == 1 &&
        state->result == result && state->terminal_reason == reason &&
        state->terminal_disposition == VE_TLS_DELIVERY_DIAGNOSTIC_DISPOSITION_DISCARD &&
        (!error_code || strcmp(state->terminal_error_code, error_code) == 0) &&
        (!error_code || strcmp(state->callback_error_code, error_code) == 0);
}

static int tls_thread_expect_success(const tls_thread_state * state) {
    return state && state->schema_error == 0 && state->request_count == 1 &&
        state->callback_count == 1 && state->terminal_count == 1 &&
        state->result == VE_TLS_OK &&
        state->terminal_reason == VE_TLS_DELIVERY_DIAGNOSTIC_REASON_SUCCESS &&
        state->terminal_disposition == VE_TLS_DELIVERY_DIAGNOSTIC_DISPOSITION_SUCCESS;
}

static int test_sender_thread_memory_retry_expiry(void) {
    tls_thread_state state;
    ve_tls_config config;
    ve_tls_producer * producer = NULL;
    int observed = 0;
    int rc = -1;
    if (tls_thread_state_init(&state) != 0 ||
        tls_thread_config(&config, &state, 80, 1, 1000) != 0) {
        tls_thread_state_destroy(&state);
        return -1;
    }
    state.http_mode = TLS_THREAD_HTTP_RETRY;
    state.http_sleep_ms = 2;
    producer = tls_thread_open(&config, &state);
    if (!producer || tls_thread_add_one(producer) != 0 ||
        tls_thread_wait(&state, tls_thread_pred_retained, 1500) != 0 ||
        tls_thread_wait(&state, tls_thread_pred_terminal, 2500) != 0) {
        goto done;
    }
    observed = 1;
done:
    if (producer) {
        (void)ve_tls_producer_close(producer, 3000);
        ve_tls_producer_destroy(producer);
    }
    if (observed) {
        rc = tls_thread_expect_terminal(
            &state,
            VE_TLS_DROP_ERROR,
            VE_TLS_DELIVERY_DIAGNOSTIC_REASON_RETENTION_EXPIRED,
            "RetryRetentionExpired") && state.request_count == 1 &&
            state.retained_count == 1 ? 0 : -2;
    }
    tls_thread_state_destroy(&state);
    return rc;
}

static int test_sender_thread_memory_retry_close_discards(void) {
    tls_thread_state state;
    ve_tls_config config;
    ve_tls_producer * producer = NULL;
    int close_rc = VE_TLS_INVALID;
    int observed = 0;
    int rc = -1;
    if (tls_thread_state_init(&state) != 0 ||
        tls_thread_config(&config, &state, 60000, 1, 1000) != 0) {
        tls_thread_state_destroy(&state);
        return -1;
    }
    state.http_mode = TLS_THREAD_HTTP_RETRY;
    state.http_sleep_ms = 2;
    producer = tls_thread_open(&config, &state);
    if (producer) {
        ve_tls_producer_set_send_done(producer, tls_thread_done_v1, &state);
    }
    if (!producer || tls_thread_add_one(producer) != 0 ||
        tls_thread_wait(&state, tls_thread_pred_retained, 1500) != 0) {
        goto done;
    }
    close_rc = ve_tls_producer_close(producer, 3000);
    observed = 1;
done:
    if (producer) ve_tls_producer_destroy(producer);
    if (observed) {
        rc = close_rc == VE_TLS_OK &&
            tls_thread_expect_terminal(
                &state,
                VE_TLS_CLOSED,
                VE_TLS_DELIVERY_DIAGNOSTIC_REASON_CLOSED,
                "ProducerClosed") &&
            state.callback_v1_count == 1 &&
            state.callback_v1_result == VE_TLS_CLOSED &&
            strcmp(state.callback_v1_error_message, "producer closed") == 0 &&
            state.request_count == 1 && state.retained_count == 1 ? 0 : -2;
    }
    tls_thread_state_destroy(&state);
    return rc;
}

static int test_sender_thread_credentials_expire_before_http(void) {
    tls_thread_state state;
    ve_tls_config config;
    ve_tls_producer * producer = NULL;
    int observed = 0;
    int rc = -1;
    if (tls_thread_state_init(&state) != 0 ||
        tls_thread_config(&config, &state, 60000, 1, 30) != 0) {
        tls_thread_state_destroy(&state);
        return -1;
    }
    config.access_key_id = NULL;
    config.access_key_secret = NULL;
    config.credentials_provider = tls_thread_credentials;
    config.credentials_provider_param = &state;
    config.credentials_expire_advance_ms = 0;
    config.credentials_refresh_min_interval_ms = 0;
    state.credential_test_clock = 1;
    tls_thread_clock_base_ms = state.platform.time_ms;
    atomic_store_explicit(&tls_thread_clock_offset_ms, 0, memory_order_relaxed);
    config.platform.time_ms = tls_thread_clock_ms;
    state.http_mode = TLS_THREAD_HTTP_RETRY;
    state.http_sleep_ms = 2;
    producer = tls_thread_open(&config, &state);
    if (!producer || tls_thread_add_one(producer) != 0 ||
        tls_thread_wait(&state, tls_thread_pred_terminal, 3000) != 0) {
        goto done;
    }
    observed = 1;
done:
    if (producer) {
        (void)ve_tls_producer_close(producer, 3000);
        ve_tls_producer_destroy(producer);
    }
    tls_thread_clock_reset();
    if (observed) {
        rc = tls_thread_expect_terminal(
            &state,
            VE_TLS_DROP_ERROR,
            VE_TLS_DELIVERY_DIAGNOSTIC_REASON_RETENTION_EXPIRED,
            "RetryRetentionExpired") && state.request_count == 1 &&
            state.provider_calls >= 2 ? 0 : -2;
    }
    tls_thread_state_destroy(&state);
    return rc;
}

typedef struct tls_thread_alloc_state {
    _Atomic int64_t live;
    _Atomic int hit;
} tls_thread_alloc_state;

static void * tls_thread_alloc_malloc(size_t size, void * user_data) {
    tls_thread_alloc_state * state = (tls_thread_alloc_state *)user_data;
    void * p = malloc(size);
    if (p && state) atomic_fetch_add_explicit(&state->live, 1, memory_order_relaxed);
    return p;
}

static void * tls_thread_alloc_calloc(size_t n, size_t size, void * user_data) {
    tls_thread_alloc_state * state = (tls_thread_alloc_state *)user_data;
    if (tls_thread_fail_requeue_alloc && n == 64 && size == sizeof(ve_tls_send_task)) {
        tls_thread_fail_requeue_alloc = 0;
        if (state) atomic_store_explicit(&state->hit, 1, memory_order_relaxed);
        return NULL;
    }
    void * p = calloc(n, size);
    if (p && state) atomic_fetch_add_explicit(&state->live, 1, memory_order_relaxed);
    return p;
}

static void * tls_thread_alloc_realloc(void * ptr, size_t size, void * user_data) {
    tls_thread_alloc_state * state = (tls_thread_alloc_state *)user_data;
    void * p = realloc(ptr, size);
    if (!ptr && p && state) atomic_fetch_add_explicit(&state->live, 1, memory_order_relaxed);
    return p;
}

static void tls_thread_alloc_free(void * ptr, void * user_data) {
    tls_thread_alloc_state * state = (tls_thread_alloc_state *)user_data;
    if (ptr && state) atomic_fetch_sub_explicit(&state->live, 1, memory_order_relaxed);
    free(ptr);
}

static char * tls_thread_alloc_strdup(const char * string, void * user_data) {
    if (!string) return NULL;
    size_t size = strlen(string) + 1;
    char * result = (char *)tls_thread_alloc_malloc(size, user_data);
    if (result) memcpy(result, string, size);
    return result;
}

static int test_sender_thread_memory_retry_requeue_oom(void) {
    tls_thread_state state;
    tls_thread_alloc_state alloc_state;
    ve_tls_alloc_hooks saved_hooks;
    ve_tls_alloc_hooks hooks;
    ve_tls_config config;
    ve_tls_producer * producer = NULL;
    int hooks_installed = 0;
    int observed = 0;
    int rc = -1;
    memset(&alloc_state, 0, sizeof(alloc_state));
    atomic_init(&alloc_state.live, 0);
    atomic_init(&alloc_state.hit, 0);
    if (tls_thread_state_init(&state) != 0 ||
        tls_thread_config(&config, &state, 60000, 1, 1000) != 0) {
        tls_thread_state_destroy(&state);
        return -1;
    }
    memset(&hooks, 0, sizeof(hooks));
    hooks.malloc_fn = tls_thread_alloc_malloc;
    hooks.calloc_fn = tls_thread_alloc_calloc;
    hooks.realloc_fn = tls_thread_alloc_realloc;
    hooks.free_fn = tls_thread_alloc_free;
    hooks.strdup_fn = tls_thread_alloc_strdup;
    hooks.user_data = &alloc_state;
    ve_tls_alloc_get_hooks(&saved_hooks);
    ve_tls_alloc_set_hooks(&hooks);
    hooks_installed = 1;
    state.http_mode = TLS_THREAD_HTTP_REQUEUE_OOM;
    state.http_sleep_ms = 2;
    producer = tls_thread_open(&config, &state);
    if (!producer || tls_thread_add_one(producer) != 0 ||
        tls_thread_wait(&state, tls_thread_pred_terminal, 2500) != 0) {
        goto done;
    }
    observed = 1;
done:
    if (producer) {
        (void)ve_tls_producer_close(producer, 3000);
        ve_tls_producer_destroy(producer);
    }
    if (hooks_installed) ve_tls_alloc_set_hooks(&saved_hooks);
    if (observed) {
        rc = !state.oom_fixture_error &&
            atomic_load_explicit(&alloc_state.hit, memory_order_relaxed) &&
            tls_thread_expect_terminal(
                &state,
                VE_TLS_DROP_ERROR,
                VE_TLS_DELIVERY_DIAGNOSTIC_REASON_NON_RETRYABLE,
                "OutOfMemory") && state.request_count == 1 ? 0 : -2;
    }
    if (rc == 0 && atomic_load_explicit(&alloc_state.live, memory_order_relaxed) != 0) {
        rc = -3;
    }
    tls_thread_state_destroy(&state);
    return rc;
}

static int tls_thread_step_elapsed_http_do(
    ve_tls_http_client * client,
    const ve_tls_http_request * req,
    ve_tls_http_response * resp
) {
    (void)req;
    if (!client || !resp) return -1;
    tls_thread_state * state = (tls_thread_state *)client->user_data;
    if (!state) return -1;
    state->request_count++;
    g_fake_time += 5;
    resp->transport_kind = VE_TLS_TRANSPORT_GENERIC;
    resp->transport_code = 9;
    resp->transport_retryable = 1;
    return -1;
}

static int test_sender_step_retention_elapsed_is_cumulative(void) {
    tls_thread_state state;
    ve_tls_config config;
    ve_tls_producer producer;
    int rc = -1;
    if (tls_thread_state_init(&state) != 0) {
        return -1;
    }
    ve_tls_config_init(&config);
    g_real_platform = config.platform;
    g_fake_time = 10000;
    config.platform.time_ms = test_fake_time_ms;
    config.platform.sleep_ms = test_fake_sleep_ms;
    config.platform.cond_timedwait_ms = test_fake_cond_timedwait_ms;
    config.endpoint = "https://retention.example.com";
    config.region = "cn-beijing";
    config.topic_id = "retention-test-topic";
    config.access_key_id = "retention-test-ak";
    config.access_key_secret = "retention-test-sk";
    config.compress_type = "none";
    config.retry_policy.max_attempts = 2;
    config.retry_policy.initial_interval_ms = 1;
    config.retry_policy.max_interval_ms = 1;
    config.retry_policy.randomization_factor = 0;
    config.http_client.do_request = tls_thread_step_elapsed_http_do;
    config.http_client.free_response = tls_thread_http_free;
    config.http_client.user_data = &state;
    config.delivery_diagnostic = tls_thread_diagnostic;
    config.delivery_diagnostic_param = &state;
    if (init_fake_sender_producer(&producer, &config) != 0) goto done;
    producer.config.memory_retry_retention_ms = 100;
    producer.send_done_v2 = tls_thread_done;
    producer.send_done_v2_param = &state;
    producer.delivery_diagnostic = tls_thread_diagnostic;
    producer.delivery_diagnostic_param = &state;
    int first_step_rc = enqueue_delivery_test_task(&producer, "k1", 1) == 0
        ? ve_tls_sender_step(&producer) : -1;
    if (first_step_rc != 1 || state.scheduled_count < 2 || !producer.delayed_head) {
        destroy_fake_sender_producer(&producer);
        goto done;
    }
    g_fake_time += 1;
    int second_step_rc = ve_tls_sender_step(&producer);
    if (second_step_rc != 1 || state.scheduled_count < 3) {
        destroy_fake_sender_producer(&producer);
        goto done;
    }
    rc = state.schema_error == 0 &&
        tls_thread_elapsed_is_cumulative(&state) &&
        state.scheduled_elapsed[2] > state.scheduled_elapsed[0] ? 0 : -2;
    destroy_fake_sender_producer(&producer);
done:
    tls_thread_state_destroy(&state);
    return rc;
}

static int test_sender_thread_keyed_retention_elapsed_is_cumulative(void) {
    tls_thread_state state;
    ve_tls_config config;
    ve_tls_producer * producer = NULL;
    int rc = -1;
    int observed = 0;
    if (tls_thread_state_init(&state) != 0 ||
        tls_thread_config(&config, &state, 60000, 2, 1) != 0) {
        tls_thread_state_destroy(&state);
        return -1;
    }
    state.http_mode = TLS_THREAD_HTTP_RETRY;
    state.http_sleep_ms = 2;
    producer = tls_thread_open(&config, &state);
    if (!producer || tls_thread_add_one(producer) != 0 ||
        tls_thread_wait(&state, tls_thread_pred_two_retained, 1500) != 0) {
        goto done;
    }
    observed = 1;
done:
    if (producer) {
        (void)ve_tls_producer_close(producer, 3000);
        ve_tls_producer_destroy(producer);
    }
    if (observed) {
        rc = state.schema_error == 0 &&
            tls_thread_elapsed_is_cumulative(&state) &&
            state.scheduled_elapsed[2] > state.scheduled_elapsed[0] ? 0 : -2;
    }
    tls_thread_state_destroy(&state);
    return rc;
}

typedef struct tls_thread_close_gate {
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    ve_tls_platform * real_platform;
    _Atomic(ve_tls_producer *) producer;
    pthread_t sender_thread;
    int sender_thread_valid;
    int armed;
    int entered;
    int closing_seen;
    int released;
    int sender_waiting;
    int pause_sender_wait;
    int release_sender_wait;
} tls_thread_close_gate;

typedef struct tls_thread_close_arg {
    ve_tls_producer * producer;
    ve_tls_result result;
} tls_thread_close_arg;

static tls_thread_close_gate * g_tls_thread_close_gate;

static int tls_thread_close_path_is_lease(const char * path) {
    static const char suffix[] = "/lease";
    size_t path_size;
    if (!path) return 0;
    path_size = strlen(path);
    return path_size >= sizeof(suffix) - 1 &&
        strcmp(path + path_size - (sizeof(suffix) - 1), suffix) == 0;
}

static void tls_thread_close_gate_deadline(int64_t timeout_ms, struct timespec * deadline) {
    struct timespec now;
    if (clock_gettime(CLOCK_REALTIME, &now) != 0) {
        memset(deadline, 0, sizeof(*deadline));
        return;
    }
    deadline->tv_sec = now.tv_sec + (time_t)(timeout_ms / 1000);
    deadline->tv_nsec = now.tv_nsec + (long)((timeout_ms % 1000) * 1000000);
    if (deadline->tv_nsec >= 1000000000L) {
        deadline->tv_sec++;
        deadline->tv_nsec -= 1000000000L;
    }
}

static int tls_thread_close_gate_wait(
    tls_thread_close_gate * gate,
    int wait_for_closing,
    int64_t timeout_ms
) {
    struct timespec deadline;
    int rc = 0;
    int observed = 0;
    if (!gate || timeout_ms < 0) return -1;
    tls_thread_close_gate_deadline(timeout_ms, &deadline);
    pthread_mutex_lock(&gate->mutex);
    while (!(observed = wait_for_closing ? gate->closing_seen : gate->entered)) {
        rc = pthread_cond_timedwait(&gate->cond, &gate->mutex, &deadline);
        if (rc != 0) break;
    }
    observed = wait_for_closing ? gate->closing_seen : gate->entered;
    pthread_mutex_unlock(&gate->mutex);
    return observed ? 0 : -1;
}

static void tls_thread_close_gate_release(tls_thread_close_gate * gate) {
    if (!gate) return;
    pthread_mutex_lock(&gate->mutex);
    gate->released = 1;
    gate->pause_sender_wait = 0;
    gate->release_sender_wait = 1;
    pthread_cond_broadcast(&gate->cond);
    pthread_mutex_unlock(&gate->mutex);
}

static int tls_thread_close_gate_wait_sender_wait(
    tls_thread_close_gate * gate,
    int64_t timeout_ms
) {
    struct timespec deadline;
    int observed = 0;
    if (!gate || timeout_ms < 0) return -1;
    tls_thread_close_gate_deadline(timeout_ms, &deadline);
    pthread_mutex_lock(&gate->mutex);
    while (!gate->sender_waiting) {
        if (pthread_cond_timedwait(&gate->cond, &gate->mutex, &deadline) != 0) {
            break;
        }
    }
    observed = gate->sender_waiting;
    pthread_mutex_unlock(&gate->mutex);
    return observed ? 0 : -1;
}

static ve_tls_file * tls_thread_close_gate_file_open(
    const char * path,
    int flags,
    int mode
) {
    tls_thread_close_gate * gate = g_tls_thread_close_gate;
    if (gate && tls_thread_close_path_is_lease(path) &&
        (flags & VE_TLS_FILE_OPEN_RDONLY) != 0 &&
        (flags & (VE_TLS_FILE_OPEN_CREATE | VE_TLS_FILE_OPEN_WRONLY | VE_TLS_FILE_OPEN_RDWR)) == 0) {
        pthread_mutex_lock(&gate->mutex);
        if (gate->armed && gate->sender_thread_valid &&
            pthread_equal(pthread_self(), gate->sender_thread) && !gate->entered) {
            gate->entered = 1;
            pthread_cond_broadcast(&gate->cond);
            while (!gate->released) {
                pthread_cond_wait(&gate->cond, &gate->mutex);
            }
        }
        pthread_mutex_unlock(&gate->mutex);
    }
    return gate && gate->real_platform && gate->real_platform->file_open
        ? gate->real_platform->file_open(path, flags, mode)
        : NULL;
}

static int tls_thread_close_gate_cond_timedwait_ms(
    ve_tls_cond * cond,
    ve_tls_mutex * mutex,
    int64_t timeout_ms
) {
    tls_thread_close_gate * gate = g_tls_thread_close_gate;
    ve_tls_producer * producer = gate
        ? atomic_load_explicit(&gate->producer, memory_order_acquire)
        : NULL;
    if (gate && producer && cond == producer->send_cond) {
        pthread_mutex_lock(&gate->mutex);
        int sender_wait = gate->pause_sender_wait && gate->sender_thread_valid &&
            pthread_equal(pthread_self(), gate->sender_thread);
        if (sender_wait) {
            if (!gate->sender_waiting) {
                gate->sender_waiting = 1;
                pthread_cond_broadcast(&gate->cond);
            }
            while (gate->pause_sender_wait && !gate->release_sender_wait) {
                pthread_cond_wait(&gate->cond, &gate->mutex);
            }
            pthread_mutex_unlock(&gate->mutex);
            /* The test gate is the wakeup; preserve the caller's locked mutex
               and make the sender revisit its heartbeat before the real timed
               wait. */
            return 0;
        }
        pthread_mutex_unlock(&gate->mutex);
    }
    return gate && gate->real_platform && gate->real_platform->cond_timedwait_ms
        ? gate->real_platform->cond_timedwait_ms(cond, mutex, timeout_ms)
        : -1;
}

static void tls_thread_close_gate_cond_broadcast(ve_tls_cond * cond) {
    tls_thread_close_gate * gate = g_tls_thread_close_gate;
    ve_tls_producer * producer = gate
        ? atomic_load_explicit(&gate->producer, memory_order_acquire)
        : NULL;
    int closing_seen = gate && producer && cond == producer->cond &&
        producer->closing;
    if (gate && gate->real_platform && gate->real_platform->cond_broadcast) {
        gate->real_platform->cond_broadcast(cond);
    }
    if (closing_seen) {
        pthread_mutex_lock(&gate->mutex);
        gate->closing_seen = 1;
        pthread_cond_broadcast(&gate->cond);
        pthread_mutex_unlock(&gate->mutex);
    }
}

static void * tls_thread_close_main(void * arg) {
    tls_thread_close_arg * close_arg = (tls_thread_close_arg *)arg;
    if (!close_arg || !close_arg->producer) return NULL;
    close_arg->result = ve_tls_producer_close(close_arg->producer, 1000);
    return NULL;
}

static int test_sender_thread_persistent_close_heartbeat_wakeup(void) {
    tls_thread_state state;
    ve_tls_config config;
    ve_tls_producer * producer = NULL;
    char dir[PATH_MAX] = {0};
    tls_thread_close_gate gate;
    tls_thread_close_arg close_arg;
    ve_tls_thread * close_thread = NULL;
    int gate_initialized = 0;
    int gate_mutex_initialized = 0;
    int gate_cond_initialized = 0;
    int close_started = 0;
    int observed = 0;
    int stage = 0;
    int rc = -1;

    memset(&gate, 0, sizeof(gate));
    atomic_init(&gate.producer, NULL);
    memset(&close_arg, 0, sizeof(close_arg));
    if (tls_thread_state_init(&state) != 0 ||
        tls_thread_config(&config, &state, 0, 1, 60000) != 0 ||
        make_temp_dir(dir, sizeof(dir)) != 0) {
        tls_thread_state_destroy(&state);
        cleanup_persistent_dir(dir);
        return -1;
    }
    config.use_global_env = 0;
    config.use_persistent = 1;
    config.persistent_file_path = dir;
    config.persistent_durability = VE_TLS_PDURABILITY_SYNC_WAL;
    config.persistent_lease_timeout_ms = 60000;
    config.persistent_heartbeat_interval_ms = 1;
    config.max_persistent_log_count = 64;
    config.max_persistent_file_size = 1024;
    config.max_persistent_file_count = 4;
    config.platform.file_open = tls_thread_close_gate_file_open;
    config.platform.cond_timedwait_ms = tls_thread_close_gate_cond_timedwait_ms;
    config.platform.cond_broadcast = tls_thread_close_gate_cond_broadcast;
    state.http_mode = TLS_THREAD_HTTP_RETRY;
    state.http_sleep_ms = 0;
    state.http_success = 0;
    stage = 1;

    if (pthread_mutex_init(&gate.mutex, NULL) != 0) {
        goto done;
    }
    gate_mutex_initialized = 1;
    if (pthread_cond_init(&gate.cond, NULL) != 0) {
        goto done;
    }
    gate_cond_initialized = 1;
    gate_initialized = 1;
    stage = 2;
    gate.real_platform = &state.platform;
    g_tls_thread_close_gate = &gate;
    producer = tls_thread_open(&config, &state);
    if (!producer || tls_thread_add_one(producer) != 0 ||
        tls_thread_wait(&state, tls_thread_pred_retained, 1500) != 0) {
        goto done;
    }
    stage = 3;
    state.platform.mutex_lock(state.mutex);
    gate.sender_thread = state.sender_thread;
    gate.sender_thread_valid = state.sender_thread_valid;
    state.platform.mutex_unlock(state.mutex);
    atomic_store_explicit(&gate.producer, producer, memory_order_release);
    state.platform.mutex_lock(producer->mutex);
    pthread_mutex_lock(&gate.mutex);
    gate.pause_sender_wait = 1;
    pthread_mutex_unlock(&gate.mutex);
    /* Pair the wakeup with the producer mutex so it cannot race the sender's
       transition into its real timed wait. */
    state.platform.cond_broadcast(producer->send_cond);
    state.platform.mutex_unlock(producer->mutex);
    if (tls_thread_close_gate_wait_sender_wait(&gate, 2000) != 0) {
        goto done;
    }
    pthread_mutex_lock(&gate.mutex);
    /* The sender is paused before returning from its retry wait. Make the next
       heartbeat due only now, after any earlier heartbeat has completed. */
    atomic_store_explicit(
        &producer->persistent->next_heartbeat_ms,
        0,
        memory_order_relaxed);
    gate.armed = 1;
    gate.pause_sender_wait = 0;
    gate.release_sender_wait = 1;
    pthread_cond_broadcast(&gate.cond);
    pthread_mutex_unlock(&gate.mutex);
    if (tls_thread_close_gate_wait(&gate, 0, 2000) != 0) {
        goto done;
    }
    stage = 4;

    close_arg.producer = producer;
    close_arg.result = VE_TLS_INVALID;
    close_thread = state.platform.thread_create(tls_thread_close_main, &close_arg);
    if (!close_thread) goto done;
    close_started = 1;
    stage = 5;
    if (tls_thread_close_gate_wait(&gate, 1, 1000) != 0) {
        goto done;
    }
    stage = 6;
    tls_thread_close_gate_release(&gate);
    state.platform.thread_join(close_thread);
    close_thread = NULL;
    observed = 1;
    rc = close_arg.result == VE_TLS_OK && state.request_count == 1 &&
        state.callback_count == 0 && state.terminal_count == 0 &&
        state.retained_disposition == VE_TLS_DELIVERY_DIAGNOSTIC_DISPOSITION_RETAINED_WAL
        ? 0 : -2;

done:
    if (gate_initialized) {
        tls_thread_close_gate_release(&gate);
    }
    if (close_thread) {
        state.platform.thread_join(close_thread);
        close_thread = NULL;
    }
    if (producer) {
        if (!close_started) {
            (void)ve_tls_producer_close(producer, 1000);
        }
        ve_tls_producer_destroy(producer);
        producer = NULL;
    }
    atomic_store_explicit(&gate.producer, NULL, memory_order_release);
    g_tls_thread_close_gate = NULL;
    if (gate_cond_initialized) {
        pthread_cond_destroy(&gate.cond);
    }
    if (gate_mutex_initialized) {
        pthread_mutex_destroy(&gate.mutex);
    }
    if (rc != 0) {
        fprintf(stderr,
            "close heartbeat wakeup: stage=%d gate=%d/%d/%d released=%d close_started=%d close_rc=%d requests=%d retained=%d callbacks=%d terminal=%d\n",
            stage, gate.entered, gate.closing_seen, gate.armed, gate.released,
            close_started, close_arg.result, state.request_count,
            state.retained_count, state.callback_count, state.terminal_count);
    }
    if (!observed && rc == 0) rc = -1;
    tls_thread_state_destroy(&state);
    cleanup_persistent_dir(dir);
    return rc;
}

static int test_sender_thread_persistent_close_preserves_wal(void) {
    tls_thread_state state;
    ve_tls_config config;
    ve_tls_producer * producer = NULL;
    char dir[PATH_MAX] = {0};
    int p1_close_rc = VE_TLS_INVALID;
    int p2_close_rc = VE_TLS_INVALID;
    int p3_close_rc = VE_TLS_INVALID;
    int p1_checkpoint = -1;
    int p2_checkpoint = -1;
    int p2_success = 0;
    int observed_p1 = 0;
    int observed_p2 = 0;
    int observed_p3 = 0;
    int rc = -1;

    if (tls_thread_state_init(&state) != 0 ||
        tls_thread_config(&config, &state, 0, 1, 60000) != 0 ||
        make_temp_dir(dir, sizeof(dir)) != 0) {
        tls_thread_state_destroy(&state);
        cleanup_persistent_dir(dir);
        return -1;
    }
    config.use_global_env = 0;
    config.use_persistent = 1;
    config.persistent_file_path = dir;
    config.persistent_durability = VE_TLS_PDURABILITY_SYNC_WAL;
    config.max_persistent_log_count = 64;
    config.max_persistent_file_size = 1024;
    config.max_persistent_file_count = 4;
    state.http_mode = TLS_THREAD_HTTP_RETRY;
    state.http_sleep_ms = 2;
    state.http_success = 0;

    producer = tls_thread_open(&config, &state);
    if (!producer || tls_thread_add_one(producer) != 0 ||
        tls_thread_wait(&state, tls_thread_pred_retained, 1500) != 0) {
        goto done;
    }
    p1_close_rc = (int)ve_tls_producer_close(producer, 3000);
    if (p1_close_rc != VE_TLS_OK) {
        producer->config.platform.mutex_lock(producer->mutex);
        fprintf(stderr, "close pending: queue=%zu ingress=%zu worker=%d append=%d fast=%lld sendq=%zu\n",
            producer->queue_count, producer->ingress_queue_count, producer->worker_flushing_count,
            producer->active_persistent_appends, (long long)producer->fast_inflight, producer->send_queue.count);
        for (size_t i = 0; i < producer->key_bucket_count; i++) {
            for (ve_tls_key_queue * q = producer->key_buckets[i]; q; q = q->hnext) {
                fprintf(stderr, "close key: count=%zu inflight=%d delayed=%d ready=%lld cycle=%u\n",
                    q->count, q->inflight, q->delayed, (long long)q->next_ready_ms,
                    q->count ? q->q[q->head].persistent_retry_cycle : 0);
            }
        }
        producer->config.platform.mutex_unlock(producer->mutex);
    }
    p1_checkpoint = test_producer_checkpoint_acked_log_id(producer);
    observed_p1 = 1;
    if (producer) ve_tls_producer_destroy(producer);
    producer = NULL;
    if (p1_close_rc != VE_TLS_OK || p1_checkpoint != 0 ||
        state.request_count != 1 || state.callback_count != 0 ||
        state.terminal_count != 0 ||
        state.retained_disposition != VE_TLS_DELIVERY_DIAGNOSTIC_DISPOSITION_RETAINED_WAL) {
        goto done;
    }

    tls_thread_reset_observations(&state);
    state.http_success = 1;
    producer = tls_thread_open(&config, &state);
    if (!producer || ve_tls_producer_recover(producer) != VE_TLS_OK ||
        tls_thread_wait(&state, tls_thread_pred_terminal, 3000) != 0) {
        goto done;
    }
    p2_close_rc = (int)ve_tls_producer_close(producer, 3000);
    p2_checkpoint = test_producer_checkpoint_acked_log_id(producer);
    observed_p2 = 1;
    if (producer) ve_tls_producer_destroy(producer);
    producer = NULL;
    p2_success = tls_thread_expect_success(&state);
    if (!p2_success || p2_close_rc != VE_TLS_OK ||
        p2_checkpoint < 1) {
        goto done;
    }

    tls_thread_reset_observations(&state);
    producer = tls_thread_open(&config, &state);
    if (!producer || ve_tls_producer_recover(producer) != VE_TLS_OK ||
        tls_thread_wait_quiet(&state, 250) != 0) {
        goto done;
    }
    p3_close_rc = (int)ve_tls_producer_close(producer, 3000);
    observed_p3 = 1;
    if (producer) ve_tls_producer_destroy(producer);
    producer = NULL;
    rc = p3_close_rc == VE_TLS_OK && state.request_count == 0 &&
        state.callback_count == 0 && state.terminal_count == 0 ? 0 : -2;

done:
    if (producer) {
        (void)ve_tls_producer_close(producer, 3000);
        ve_tls_producer_destroy(producer);
    }
    if (!observed_p1 || !observed_p2 || !observed_p3) rc = -1;
    tls_thread_state_destroy(&state);
    cleanup_persistent_dir(dir);
    return rc;
}

#undef TLS_THREAD_MAX_SCHEDULED
