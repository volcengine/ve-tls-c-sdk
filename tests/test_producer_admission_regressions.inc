/* Allocation, mutable-input, and persistent admission regressions. */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#define REGRESSION_PRODUCER_TEST_TIME 1710000000000LL

typedef struct {
    int fail_calloc_call;
    int fail_realloc_call;
    int calloc_calls;
    int realloc_calls;
} regression_prod_alloc_state;

static void * regression_prod_malloc(size_t n, void * user_data) {
    (void)user_data;
    return malloc(n);
}

static void * regression_prod_calloc(size_t n, size_t size, void * user_data) {
    regression_prod_alloc_state * state = (regression_prod_alloc_state *)user_data;
    if (state) {
        state->calloc_calls++;
        if (state->fail_calloc_call > 0 &&
            state->calloc_calls == state->fail_calloc_call) {
            return NULL;
        }
    }
    return calloc(n, size);
}

static void * regression_prod_realloc(void * ptr, size_t n, void * user_data) {
    regression_prod_alloc_state * state = (regression_prod_alloc_state *)user_data;
    if (state) {
        state->realloc_calls++;
        if (state->fail_realloc_call > 0 &&
            state->realloc_calls == state->fail_realloc_call) {
            return NULL;
        }
    }
    return realloc(ptr, n);
}

static void regression_prod_free(void * ptr, void * user_data) {
    (void)user_data;
    free(ptr);
}

static char * regression_prod_strdup(const char * value, void * user_data) {
    (void)user_data;
    if (!value) {
        return NULL;
    }
    size_t n = strlen(value);
    char * copy = (char *)malloc(n + 1);
    if (!copy) {
        return NULL;
    }
    memcpy(copy, value, n + 1);
    return copy;
}

static void regression_prod_install_alloc_failure(
    regression_prod_alloc_state * state,
    int fail_calloc_call,
    int fail_realloc_call
) {
    ve_tls_alloc_hooks hooks;
    memset(state, 0, sizeof(*state));
    state->fail_calloc_call = fail_calloc_call;
    state->fail_realloc_call = fail_realloc_call;
    memset(&hooks, 0, sizeof(hooks));
    hooks.malloc_fn = regression_prod_malloc;
    hooks.calloc_fn = regression_prod_calloc;
    hooks.realloc_fn = regression_prod_realloc;
    hooks.free_fn = regression_prod_free;
    hooks.strdup_fn = regression_prod_strdup;
    hooks.user_data = state;
    ve_tls_alloc_set_hooks(&hooks);
}

typedef struct {
    int enqueued_events;
    int dropped_events;
    int alloc_drop_events;
    int64_t enqueued_bytes;
    int64_t dropped_bytes;
} regression_prod_metric_state;

static void regression_prod_metrics_emit(
    const char * name,
    int64_t v1,
    int64_t v2,
    void * user_data
) {
    (void)v1;
    regression_prod_metric_state * state = (regression_prod_metric_state *)user_data;
    if (!state || !name) {
        return;
    }
    if (strcmp(name, "log_enqueued") == 0) {
        state->enqueued_events++;
        state->enqueued_bytes += v2;
    } else if (strcmp(name, "log_dropped") == 0) {
        state->dropped_events++;
        state->dropped_bytes += v2;
    } else if (strcmp(name, "log_dropped_enqueue_alloc_failed") == 0) {
        state->alloc_drop_events++;
    }
}

static void regression_prod_init_config(ve_tls_config * config) {
    ve_tls_config_init(config);
    config->endpoint = "https://example.com";
    config->region = "cn-beijing";
    config->topic_id = "t";
    config->access_key_id = "ak";
    config->access_key_secret = "sk";
    config->compress_type = "none";
    config->retry_policy.max_attempts = 1;
    config->flush_interval_ms = 0;
    config->log_count_per_package = 1000000;
    config->log_bytes_per_package = 100000000;
    config->agg_max_raw_bytes_per_request = 100000000;
}

static uint32_t regression_prod_read_u32_le(const unsigned char * p) {
    return (uint32_t)p[0] |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

/* Export contains one record per builder/queue item. Compare the exact
 * protobuf body, rather than looking for substrings, so stale pointer-length
 * reuse cannot pass the regression accidentally. */
static int regression_prod_export_equals(
    ve_tls_producer * producer,
    uint32_t expected_record_count,
    const ve_tls_log_group_builder * expected
) {
    unsigned char * raw = NULL;
    size_t raw_size = 0;
    int ok = 0;
    if (!producer || !expected ||
        ve_tls_producer_export_raw_buffer(producer, &raw, &raw_size) != VE_TLS_OK ||
        !raw || raw_size < 20 ||
        memcmp(raw, "VTLS", 4) != 0 ||
        regression_prod_read_u32_le(raw + 8) != expected_record_count) {
        goto done;
    }

    size_t off = 20;
    for (uint32_t i = 0; i < expected_record_count; i++) {
        if (raw_size - off < 29) {
            goto done;
        }
        uint32_t hash_key_len = regression_prod_read_u32_le(raw + off + 21);
        uint32_t body_len = regression_prod_read_u32_le(raw + off + 25);
        off += 29;
        if ((size_t)hash_key_len > raw_size - off) {
            goto done;
        }
        off += (size_t)hash_key_len;
        if ((size_t)body_len > raw_size - off) {
            goto done;
        }
        if (i == 0) {
            /* A send task wraps the builder log entries in LogGroup field 1.
             * The test config has no group suffix, so compare that exact
             * wrapper and the complete entry payload. */
            size_t body_start = off;
            if (body_len < 2 || raw[off++] != 0x0A) {
                goto done;
            }
            uint64_t group_len = 0;
            unsigned int shift = 0;
            int terminated = 0;
            while (off < body_start + (size_t)body_len && shift < 64) {
                unsigned char byte = raw[off++];
                group_len |= ((uint64_t)(byte & 0x7F)) << shift;
                if ((byte & 0x80) == 0) {
                    terminated = 1;
                    break;
                }
                shift += 7;
            }
            if (!terminated || group_len != expected->logs_len ||
                (size_t)body_len - (off - body_start) != expected->logs_len ||
                (expected->logs_len > 0 &&
                 memcmp(raw + off, expected->logs, expected->logs_len) != 0)) {
                goto done;
            }
            off = body_start + (size_t)body_len;
        }
        if (i != 0) {
            off += (size_t)body_len;
        }
    }
    ok = (off == raw_size) ? 1 : 0;

done:
    ve_tls_producer_free_raw_buffer(raw);
    return ok ? 0 : -1;
}

static ve_tls_log_group_builder * regression_prod_build_expected(
    const char * const * values,
    const size_t * value_lens,
    const int64_t * times,
    const int64_t * ids,
    size_t count
) {
    ve_tls_log_group_builder * builder = ve_tls_log_builder_create("");
    if (!builder) {
        return NULL;
    }
    const ve_tls_kv kv = {"key", NULL};
    const size_t key_len = 3;
    for (size_t i = 0; i < count; i++) {
        ve_tls_kv item = kv;
        item.value = values[i];
        if (ve_tls_log_builder_add_kv_lens(
                builder,
                ids[i],
                times[i],
                0,
                0,
                &item,
                &key_len,
                &value_lens[i],
                1) != 0) {
            ve_tls_log_builder_free(builder);
            return NULL;
        }
    }
    return builder;
}

static size_t regression_prod_estimate(size_t value_len, int64_t time_ms) {
    const size_t key_len = 3;
    return ve_tls_log_builder_estimate_kv_lens_size(
        time_ms, 0, 0, &key_len, &value_len, 1);
}

static void regression_prod_fill(char * value, size_t len, char byte) {
    memset(value, (unsigned char)byte, len);
    value[len] = 0;
}

static int regression_prod_test_mutable_value_lengths(int first_long) {
    const size_t first_len = first_long ? 96 : 40;
    const size_t second_len = first_long ? 40 : 96;
    char mutable_value[128];
    char first_copy[128];
    char second_copy[128];
    ve_tls_config config;
    ve_tls_kv kv;
    ve_tls_producer * producer = NULL;
    ve_tls_log_group_builder * expected = NULL;
    int64_t ids[2] = {0, 0};
    int64_t times[2] = {REGRESSION_PRODUCER_TEST_TIME, REGRESSION_PRODUCER_TEST_TIME + 1};
    const char * values[2] = {first_copy, second_copy};
    size_t value_lens[2] = {first_len, second_len};
    int rc = -1;

    regression_prod_init_config(&config);
    producer = ve_tls_producer_create(&config);
    if (!producer) {
        return -1;
    }
    kv.key = "key";
    kv.value = mutable_value;
    regression_prod_fill(mutable_value, first_len, 'L');
    memcpy(first_copy, mutable_value, first_len + 1);
    if (ve_tls_producer_add_log_kv_with_id(
            producer, times[0], &kv, 1, 0, &ids[0]) != VE_TLS_OK) {
        goto done;
    }
    regression_prod_fill(mutable_value, second_len, 'S');
    memcpy(second_copy, mutable_value, second_len + 1);
    if (ve_tls_producer_add_log_kv_with_id(
            producer, times[1], &kv, 1, 0, &ids[1]) != VE_TLS_OK ||
        ids[0] <= 0 || ids[1] != ids[0] + 1) {
        goto done;
    }
    expected = regression_prod_build_expected(values, value_lens, times, ids, 2);
    if (!expected || regression_prod_export_equals(producer, 1, expected) != 0) {
        goto done;
    }
    rc = 0;

done:
    ve_tls_log_builder_free(expected);
    ve_tls_producer_destroy(producer);
    return rc;
}

static int regression_prod_test_append_oom_preserves_old(void) {
#define REGRESSION_PROD_APPEND_OLD_LEN 220
#define REGRESSION_PROD_APPEND_REJECTED_LEN 40
    const size_t old_len = REGRESSION_PROD_APPEND_OLD_LEN;
    const size_t rejected_len = REGRESSION_PROD_APPEND_REJECTED_LEN;
    char old_value[REGRESSION_PROD_APPEND_OLD_LEN + 1];
    char rejected_value[REGRESSION_PROD_APPEND_REJECTED_LEN + 1];
    const char * old_values[1] = {old_value};
    const char * both_values[2] = {old_value, rejected_value};
    const size_t old_lens[1] = {old_len};
    const size_t both_lens[2] = {old_len, rejected_len};
    const int64_t times[2] = {REGRESSION_PRODUCER_TEST_TIME, REGRESSION_PRODUCER_TEST_TIME + 1};
    ve_tls_config config;
    regression_prod_metric_state metric_state;
    regression_prod_alloc_state alloc_state;
    ve_tls_alloc_hooks saved_hooks;
    ve_tls_kv kv;
    ve_tls_producer * producer = NULL;
    ve_tls_log_group_builder * expected = NULL;
    ve_tls_metrics metrics;
    int64_t ids[2] = {0, 0};
    size_t old_estimate = regression_prod_estimate(old_len, times[0]);
    size_t rejected_estimate = regression_prod_estimate(rejected_len, times[1]);
    int rc = -1;

    regression_prod_fill(old_value, old_len, 'O');
    regression_prod_fill(rejected_value, rejected_len, 'R');
    memset(&metric_state, 0, sizeof(metric_state));
    regression_prod_init_config(&config);
    config.metrics_sink.emit = regression_prod_metrics_emit;
    config.metrics_sink.user_param = &metric_state;
    producer = ve_tls_producer_create(&config);
    if (!producer || old_estimate == (size_t)-1 || rejected_estimate == (size_t)-1 ||
        old_estimate >= 256 || old_estimate + rejected_estimate <= 256) {
        goto done;
    }
    kv.key = "key";
    kv.value = old_value;
    if (ve_tls_producer_add_log_kv_with_id(
            producer, times[0], &kv, 1, 0, &ids[0]) != VE_TLS_OK ||
        ve_tls_producer_get_buffered_bytes(producer) != old_estimate) {
        goto done;
    }

    ve_tls_alloc_get_hooks(&saved_hooks);
    regression_prod_install_alloc_failure(&alloc_state, 0, 1);
    kv.value = rejected_value;
    ids[1] = -1;
    ve_tls_result failed = ve_tls_producer_add_log_kv_with_id(
        producer, times[1], &kv, 1, 0, &ids[1]);
    ve_tls_alloc_set_hooks(&saved_hooks);
    if (failed != VE_TLS_DROP_ERROR || ids[1] != 0 ||
        alloc_state.realloc_calls != 1 ||
        ve_tls_producer_get_buffered_bytes(producer) != old_estimate) {
        goto done;
    }
    ve_tls_producer_get_metrics(producer, &metrics);
    if (metrics.logs_enqueued_total != 1 || metrics.logs_dropped_total != 1 ||
        metrics.bytes_enqueued_total != old_estimate ||
        metrics.bytes_dropped_total != rejected_estimate ||
        metric_state.enqueued_events != 1 || metric_state.enqueued_bytes != (int64_t)old_estimate ||
        metric_state.dropped_events != 1 || metric_state.dropped_bytes != (int64_t)rejected_estimate ||
        metric_state.alloc_drop_events != 1) {
        goto done;
    }

    expected = regression_prod_build_expected(old_values, old_lens, times, ids, 1);
    if (!expected || regression_prod_export_equals(producer, 1, expected) != 0) {
        goto done;
    }
    ve_tls_log_builder_free(expected);
    expected = NULL;

    kv.value = rejected_value;
    if (ve_tls_producer_add_log_kv_with_id(
            producer, times[1], &kv, 1, 0, &ids[1]) != VE_TLS_OK ||
        ids[1] != ids[0] + 1) {
        goto done;
    }
    expected = regression_prod_build_expected(both_values, both_lens, times, ids, 2);
    if (!expected || regression_prod_export_equals(producer, 1, expected) != 0) {
        goto done;
    }
    ve_tls_producer_get_metrics(producer, &metrics);
    if (metrics.logs_enqueued_total != 2 || metrics.logs_dropped_total != 1 ||
        metrics.bytes_enqueued_total != old_estimate + rejected_estimate ||
        metrics.bytes_dropped_total != rejected_estimate ||
        metric_state.enqueued_events != 2 || metric_state.enqueued_bytes != (int64_t)(old_estimate + rejected_estimate)) {
        goto done;
    }
    rc = 0;

done:
    ve_tls_alloc_set_hooks(NULL);
    ve_tls_log_builder_free(expected);
    ve_tls_producer_destroy(producer);
    return rc;
}

static int regression_prod_test_flush_oom_rolls_back_current(void) {
#define REGRESSION_PROD_FLUSH_OLD_LEN 40
#define REGRESSION_PROD_FLUSH_CURRENT_LEN 40
    const size_t old_len = REGRESSION_PROD_FLUSH_OLD_LEN;
    const size_t current_len = REGRESSION_PROD_FLUSH_CURRENT_LEN;
    char old_value[REGRESSION_PROD_FLUSH_OLD_LEN + 1];
    char current_value[REGRESSION_PROD_FLUSH_CURRENT_LEN + 1];
    const char * old_values[1] = {old_value};
    const char * both_values[2] = {old_value, current_value};
    const size_t old_lens[1] = {old_len};
    const size_t both_lens[2] = {old_len, current_len};
    const int64_t times[2] = {REGRESSION_PRODUCER_TEST_TIME, REGRESSION_PRODUCER_TEST_TIME + 1};
    ve_tls_config config;
    regression_prod_metric_state metric_state;
    regression_prod_alloc_state alloc_state;
    ve_tls_alloc_hooks saved_hooks;
    ve_tls_kv kv;
    ve_tls_producer * producer = NULL;
    ve_tls_log_group_builder * expected = NULL;
    ve_tls_metrics metrics;
    int64_t ids[2] = {0, 0};
    size_t old_estimate = regression_prod_estimate(old_len, times[0]);
    size_t current_estimate = regression_prod_estimate(current_len, times[1]);
    int rc = -1;

    regression_prod_fill(old_value, old_len, 'O');
    regression_prod_fill(current_value, current_len, 'C');
    memset(&metric_state, 0, sizeof(metric_state));
    regression_prod_init_config(&config);
    config.metrics_sink.emit = regression_prod_metrics_emit;
    config.metrics_sink.user_param = &metric_state;
    producer = ve_tls_producer_create(&config);
    if (!producer) {
        goto done;
    }
    kv.key = "key";
    kv.value = old_value;
    if (ve_tls_producer_add_log_kv_with_id(
            producer, times[0], &kv, 1, 0, &ids[0]) != VE_TLS_OK ||
        ve_tls_producer_get_buffered_bytes(producer) != old_estimate) {
        goto done;
    }

    ve_tls_alloc_get_hooks(&saved_hooks);
    regression_prod_install_alloc_failure(&alloc_state, 1, 0);
    kv.value = current_value;
    ve_tls_result failed = ve_tls_producer_add_log_kv_with_id(
        producer, times[1], &kv, 1, 1, &ids[1]);
    ve_tls_alloc_set_hooks(&saved_hooks);
    if (failed != VE_TLS_DROP_ERROR || ids[1] != 0 ||
        alloc_state.calloc_calls != 1 ||
        ve_tls_producer_get_buffered_bytes(producer) != old_estimate) {
        goto done;
    }
    ve_tls_producer_get_metrics(producer, &metrics);
    if (metrics.logs_enqueued_total != 1 || metrics.logs_dropped_total != 1 ||
        metrics.bytes_enqueued_total != old_estimate ||
        metrics.bytes_dropped_total != current_estimate ||
        metric_state.enqueued_events != 1 || metric_state.dropped_events != 1 ||
        metric_state.enqueued_bytes != (int64_t)old_estimate ||
        metric_state.dropped_bytes != (int64_t)current_estimate ||
        metric_state.alloc_drop_events != 1) {
        goto done;
    }

    expected = regression_prod_build_expected(old_values, old_lens, times, ids, 1);
    if (!expected || regression_prod_export_equals(producer, 1, expected) != 0) {
        goto done;
    }
    ve_tls_log_builder_free(expected);
    expected = NULL;

    kv.value = current_value;
    if (ve_tls_producer_add_log_kv_with_id(
            producer, times[1], &kv, 1, 0, &ids[1]) != VE_TLS_OK ||
        ids[1] != ids[0] + 1) {
        goto done;
    }
    expected = regression_prod_build_expected(both_values, both_lens, times, ids, 2);
    if (!expected || regression_prod_export_equals(producer, 1, expected) != 0) {
        goto done;
    }
    rc = 0;

done:
    ve_tls_alloc_set_hooks(NULL);
    ve_tls_log_builder_free(expected);
    ve_tls_producer_destroy(producer);
    return rc;
}

static int regression_prod_test_merge_oom_rolls_back_current(void) {
#define REGRESSION_PROD_MERGE_OLD_LEN 40
#define REGRESSION_PROD_MERGE_CURRENT_LEN 40
    const size_t old_len = REGRESSION_PROD_MERGE_OLD_LEN;
    const size_t current_len = REGRESSION_PROD_MERGE_CURRENT_LEN;
    char old_value[REGRESSION_PROD_MERGE_OLD_LEN + 1];
    char current_value[REGRESSION_PROD_MERGE_CURRENT_LEN + 1];
    const char * old_values[1] = {old_value};
    const char * both_values[2] = {old_value, current_value};
    const size_t old_lens[1] = {old_len};
    const size_t both_lens[2] = {old_len, current_len};
    const int64_t times[2] = {REGRESSION_PRODUCER_TEST_TIME, REGRESSION_PRODUCER_TEST_TIME + 1};
    ve_tls_config config;
    regression_prod_metric_state metric_state;
    regression_prod_alloc_state alloc_state;
    ve_tls_alloc_hooks saved_hooks;
    ve_tls_kv kv;
    ve_tls_producer * producer = NULL;
    ve_tls_log_group_builder * expected = NULL;
    int64_t ids[2] = {0, 0};
    size_t old_estimate = regression_prod_estimate(old_len, times[0]);
    size_t current_estimate = regression_prod_estimate(current_len, times[1]);
    int rc = -1;

    regression_prod_fill(old_value, old_len, 'O');
    regression_prod_fill(current_value, current_len, 'C');
    memset(&metric_state, 0, sizeof(metric_state));
    regression_prod_init_config(&config);
    config.metrics_sink.emit = regression_prod_metrics_emit;
    config.metrics_sink.user_param = &metric_state;
    producer = ve_tls_producer_create(&config);
    if (!producer) {
        goto done;
    }
    kv.key = "key";
    kv.value = old_value;
    if (ve_tls_producer_add_log_kv_with_id(
            producer, times[0], &kv, 1, 0, &ids[0]) != VE_TLS_OK) {
        goto done;
    }

    /* The first append stays in the thread-local batch. Turn on the timeout
     * exposure only for the second append so its merge creates the ingress
     * builder and can be failed deterministically. */
    producer->config.platform.mutex_lock(producer->mutex);
    producer->config.flush_interval_ms = 1;
    producer->config.platform.mutex_unlock(producer->mutex);
    ve_tls_alloc_get_hooks(&saved_hooks);
    regression_prod_install_alloc_failure(&alloc_state, 1, 0);
    kv.value = current_value;
    ve_tls_result failed = ve_tls_producer_add_log_kv_with_id(
        producer, times[1], &kv, 1, 0, &ids[1]);
    ve_tls_alloc_set_hooks(&saved_hooks);
    producer->config.platform.mutex_lock(producer->mutex);
    producer->config.flush_interval_ms = 0;
    producer->config.platform.mutex_unlock(producer->mutex);
    if (failed != VE_TLS_DROP_ERROR || ids[1] != 0 ||
        alloc_state.calloc_calls != 1 ||
        ve_tls_producer_get_buffered_bytes(producer) != old_estimate) {
        goto done;
    }
    ve_tls_metrics metrics;
    ve_tls_producer_get_metrics(producer, &metrics);
    if (metrics.logs_enqueued_total != 1 || metrics.logs_dropped_total != 1 ||
        metrics.bytes_enqueued_total != old_estimate ||
        metrics.bytes_dropped_total != current_estimate ||
        metric_state.enqueued_events != 1 || metric_state.dropped_events != 1 ||
        metric_state.alloc_drop_events != 1) {
        goto done;
    }

    expected = regression_prod_build_expected(old_values, old_lens, times, ids, 1);
    if (!expected || regression_prod_export_equals(producer, 1, expected) != 0) {
        goto done;
    }
    ve_tls_log_builder_free(expected);
    expected = NULL;
    kv.value = current_value;
    if (ve_tls_producer_add_log_kv_with_id(
            producer, times[1], &kv, 1, 0, &ids[1]) != VE_TLS_OK ||
        ids[1] != ids[0] + 1) {
        goto done;
    }
    expected = regression_prod_build_expected(both_values, both_lens, times, ids, 2);
    if (!expected || regression_prod_export_equals(producer, 1, expected) != 0) {
        goto done;
    }
    rc = 0;

done:
    ve_tls_alloc_set_hooks(NULL);
    ve_tls_log_builder_free(expected);
    ve_tls_producer_destroy(producer);
    return rc;
}

static int regression_prod_test_initial_builder_oom_retries(void) {
#define REGRESSION_PROD_INITIAL_VALUE_LEN 40
    const size_t value_len = REGRESSION_PROD_INITIAL_VALUE_LEN;
    char value[REGRESSION_PROD_INITIAL_VALUE_LEN + 1];
    const char * values[1] = {value};
    const size_t value_lens[1] = {value_len};
    const int64_t times[1] = {REGRESSION_PRODUCER_TEST_TIME};
    const int64_t ids[1] = {1};
    ve_tls_config config;
    regression_prod_metric_state metric_state;
    regression_prod_alloc_state alloc_state;
    ve_tls_alloc_hooks saved_hooks;
    ve_tls_kv kv;
    ve_tls_producer * producer = NULL;
    ve_tls_log_group_builder * expected = NULL;
    int64_t failed_id = -1;
    int64_t success_id = 0;
    int rc = -1;

    regression_prod_fill(value, value_len, 'V');
    memset(&metric_state, 0, sizeof(metric_state));
    regression_prod_init_config(&config);
    config.metrics_sink.emit = regression_prod_metrics_emit;
    config.metrics_sink.user_param = &metric_state;
    producer = ve_tls_producer_create(&config);
    if (!producer) {
        goto done;
    }
    kv.key = "key";
    kv.value = value;
    ve_tls_alloc_get_hooks(&saved_hooks);
    regression_prod_install_alloc_failure(&alloc_state, 1, 0);
    ve_tls_result failed = ve_tls_producer_add_log_kv_with_id(
        producer, times[0], &kv, 1, 0, &failed_id);
    ve_tls_alloc_set_hooks(&saved_hooks);
    if (failed != VE_TLS_DROP_ERROR || alloc_state.calloc_calls != 1 ||
        ve_tls_producer_get_buffered_bytes(producer) != 0) {
        goto done;
    }
    if (ve_tls_producer_add_log_kv_with_id(
            producer, times[0], &kv, 1, 0, &success_id) != VE_TLS_OK ||
        success_id != 1 || metric_state.enqueued_events != 1 ||
        metric_state.dropped_events != 0) {
        goto done;
    }
    expected = regression_prod_build_expected(values, value_lens, times, ids, 1);
    if (!expected || regression_prod_export_equals(producer, 1, expected) != 0) {
        goto done;
    }
    rc = 0;

done:
    ve_tls_alloc_set_hooks(NULL);
    ve_tls_log_builder_free(expected);
    ve_tls_producer_destroy(producer);
    return rc;
}

/* Persistent admission regressions use a platform with inert worker/sender
 * threads.  The WAL and admission code still runs normally, while the test
 * can inspect the exact durable records without a background consumer racing
 * the assertions. */
#define REGRESSION_PROD_DUMMY_THREAD ((ve_tls_thread *)(uintptr_t)1)

static ve_tls_thread * regression_prod_persistent_no_thread_create(
    ve_tls_thread_fn fn,
    void * arg
) {
    (void)fn;
    (void)arg;
    return REGRESSION_PROD_DUMMY_THREAD;
}

static void regression_prod_persistent_no_thread_join(ve_tls_thread * thread) {
    (void)thread;
}

static int regression_prod_persistent_init_config(
    ve_tls_config * config,
    const char * dir
) {
    if (!config || !dir ||
        ve_tls_config_init_versioned(
            config, sizeof(*config), VE_TLS_CONFIG_VERSION_CURRENT) != VE_TLS_OK) {
        return -1;
    }
    config->endpoint = "https://example.com";
    config->region = "cn-beijing";
    config->topic_id = "producer-admission";
    config->access_key_id = "ak";
    config->access_key_secret = "sk";
    config->compress_type = "none";
    config->retry_policy.max_attempts = 1;
    config->flush_interval_ms = 100000;
    config->send_thread_count = 1;
    config->pack_thread_count = 1;
    config->send_queue_size = 4;
    config->log_count_per_package = 4096;
    config->log_bytes_per_package = 1024 * 1024;
    config->agg_max_raw_bytes_per_request = 1024 * 1024;
    config->use_persistent = 1;
    config->persistent_file_path = dir;
    config->max_persistent_log_count = 64;
    config->max_persistent_file_size = 4096;
    config->max_persistent_file_count = 4;
    config->persistent_max_bytes = 16384;
    config->persistent_max_records = 64;
    config->persistent_max_segments = 4;
    config->persistent_overflow_policy = VE_TLS_POVERFLOW_REJECT_NEW;
    config->persistent_durability = VE_TLS_PDURABILITY_BUFFERED_WAL;

    /* The existing fake clock makes BLOCK and close waits deterministic. */
    g_real_platform = config->platform;
    config->platform.time_ms = test_fake_time_ms;
    config->platform.sleep_ms = test_fake_sleep_ms;
    config->platform.cond_timedwait_ms = test_fake_cond_timedwait_ms;
    config->platform.thread_create = regression_prod_persistent_no_thread_create;
    config->platform.thread_join = regression_prod_persistent_no_thread_join;
    return 0;
}

typedef struct {
    int expected_count;
    int seen;
    const int64_t * ids;
    const unsigned char * const * payloads;
    const size_t * payload_sizes;
} regression_prod_persistent_recover_state;

static int regression_prod_persistent_recover_record(
    int64_t log_id,
    int64_t enqueue_time_ms,
    const char * hash_key,
    const unsigned char * payload,
    size_t payload_size,
    void * user
) {
    regression_prod_persistent_recover_state * state =
        (regression_prod_persistent_recover_state *)user;
    int index;
    (void)enqueue_time_ms;
    if (!state || !payload || state->seen < 0 || state->seen >= state->expected_count) {
        return -1;
    }
    index = state->seen;
    if (log_id != state->ids[index] ||
        payload_size != state->payload_sizes[index] ||
        memcmp(payload, state->payloads[index], payload_size) != 0 ||
        (hash_key && hash_key[0] != 0)) {
        return -1;
    }
    state->seen++;
    return 0;
}

static int regression_prod_persistent_recover_exact(
    const ve_tls_config * config,
    int expected_count,
    const int64_t * ids,
    const unsigned char * const * payloads,
    const size_t * payload_sizes
) {
    ve_tls_producer * producer = NULL;
    regression_prod_persistent_recover_state state;
    int rc;
    int ok;
    if (!config || expected_count <= 0 || !ids || !payloads || !payload_sizes) {
        return -1;
    }
    producer = ve_tls_producer_create_versioned(
        config, sizeof(*config), VE_TLS_CONFIG_VERSION_CURRENT);
    if (!producer || !producer->persistent ||
        producer->persistent->checkpoint.acked_log_id != 0) {
        ve_tls_producer_destroy(producer);
        return -1;
    }
    memset(&state, 0, sizeof(state));
    state.expected_count = expected_count;
    state.ids = ids;
    state.payloads = payloads;
    state.payload_sizes = payload_sizes;
    rc = ve_tls_persistent_recover(
        producer->persistent,
        regression_prod_persistent_recover_record,
        &state);
    ok = rc == 0 && state.seen == expected_count &&
        producer->persistent->checkpoint.acked_log_id == 0;
    ve_tls_producer_destroy(producer);
    return ok ? 0 : -1;
}

typedef struct {
    ve_tls_alloc_hooks saved_hooks;
    int fail_next_calloc;
    int failed_calloc;
} regression_prod_persistent_alloc_state;

static void * regression_prod_persistent_malloc(size_t size, void * user_data) {
    regression_prod_persistent_alloc_state * state =
        (regression_prod_persistent_alloc_state *)user_data;
    return state->saved_hooks.malloc_fn(size, state->saved_hooks.user_data);
}

static void * regression_prod_persistent_calloc(size_t count, size_t size, void * user_data) {
    regression_prod_persistent_alloc_state * state =
        (regression_prod_persistent_alloc_state *)user_data;
    if (state && state->fail_next_calloc) {
        state->fail_next_calloc = 0;
        state->failed_calloc++;
        return NULL;
    }
    return state->saved_hooks.calloc_fn(count, size, state->saved_hooks.user_data);
}

static void * regression_prod_persistent_realloc(void * ptr, size_t size, void * user_data) {
    regression_prod_persistent_alloc_state * state =
        (regression_prod_persistent_alloc_state *)user_data;
    return state->saved_hooks.realloc_fn(ptr, size, state->saved_hooks.user_data);
}

static void regression_prod_persistent_free(void * ptr, void * user_data) {
    regression_prod_persistent_alloc_state * state =
        (regression_prod_persistent_alloc_state *)user_data;
    state->saved_hooks.free_fn(ptr, state->saved_hooks.user_data);
}

static char * regression_prod_persistent_strdup(const char * value, void * user_data) {
    regression_prod_persistent_alloc_state * state =
        (regression_prod_persistent_alloc_state *)user_data;
    return state->saved_hooks.strdup_fn(value, state->saved_hooks.user_data);
}

static void regression_prod_persistent_alloc_begin(
    regression_prod_persistent_alloc_state * state
) {
    ve_tls_alloc_hooks hooks;
    memset(state, 0, sizeof(*state));
    ve_tls_alloc_get_hooks(&state->saved_hooks);
    hooks = state->saved_hooks;
    hooks.malloc_fn = regression_prod_persistent_malloc;
    hooks.calloc_fn = regression_prod_persistent_calloc;
    hooks.realloc_fn = regression_prod_persistent_realloc;
    hooks.free_fn = regression_prod_persistent_free;
    hooks.strdup_fn = regression_prod_persistent_strdup;
    hooks.user_data = state;
    ve_tls_alloc_set_hooks(&hooks);
}

static void regression_prod_persistent_alloc_end(
    regression_prod_persistent_alloc_state * state
) {
    if (!state) {
        return;
    }
    ve_tls_alloc_set_hooks(&state->saved_hooks);
}

typedef struct {
    regression_prod_persistent_alloc_state * alloc;
    int arm_fail_next_calloc;
    int record_writes;
} regression_prod_persistent_wal_write_state;

static regression_prod_persistent_wal_write_state * g_regression_prod_persistent_wal_write;

static int regression_prod_persistent_is_record(const void * buffer, size_t size) {
    const unsigned char * bytes = (const unsigned char *)buffer;
    return bytes && size >= 4 && bytes[0] == 0x31 && bytes[1] == 0x4c &&
        bytes[2] == 0x50 && bytes[3] == 0x54;
}

static int64_t regression_prod_persistent_wal_file_write(
    ve_tls_file * file,
    const void * buffer,
    size_t size
) {
    int64_t written = g_real_platform.file_write(file, buffer, size);
    regression_prod_persistent_wal_write_state * state =
        g_regression_prod_persistent_wal_write;
    if (written > 0 && state && regression_prod_persistent_is_record(buffer, size)) {
        state->record_writes++;
        if (state->arm_fail_next_calloc && state->alloc) {
            state->arm_fail_next_calloc = 0;
            state->alloc->fail_next_calloc = 1;
        }
    }
    return written;
}

static int regression_prod_test_persistent_raw_queue_oom(void) {
    static const unsigned char payload[] = "persistent-raw-queue-oom";
    const unsigned char * payloads[1] = {payload};
    const size_t payload_sizes[1] = {sizeof(payload) - 1};
    const int64_t ids[1] = {1};
    char dir[PATH_MAX] = {0};
    ve_tls_config config;
    ve_tls_producer * producer = NULL;
    regression_prod_persistent_alloc_state alloc_state = {0};
    regression_prod_persistent_wal_write_state write_state;
    int64_t id = -1;
    ve_tls_result result;
    int alloc_active = 0;
    int ok = 0;

    if (make_temp_dir(dir, sizeof(dir)) != 0 ||
        regression_prod_persistent_init_config(&config, dir) != 0) {
        cleanup_persistent_dir(dir);
        return -1;
    }
    g_fake_time = REGRESSION_PRODUCER_TEST_TIME;
    memset(&write_state, 0, sizeof(write_state));
    write_state.arm_fail_next_calloc = 1;
    g_regression_prod_persistent_wal_write = &write_state;
    config.platform.file_write = regression_prod_persistent_wal_file_write;
    producer = ve_tls_producer_create_versioned(
        &config, sizeof(config), VE_TLS_CONFIG_VERSION_CURRENT);
    if (!producer || !producer->persistent) {
        goto done;
    }
    regression_prod_persistent_alloc_begin(&alloc_state);
    alloc_active = 1;
    write_state.alloc = &alloc_state;
    result = ve_tls_producer_add_log_raw_with_id(
        producer, (const char *)payload, sizeof(payload) - 1, 0, &id);
    regression_prod_persistent_alloc_end(&alloc_state);
    alloc_active = 0;
    g_regression_prod_persistent_wal_write = NULL;
    if (result != VE_TLS_PERSISTENT_ERROR || id != 1 ||
        alloc_state.failed_calloc != 1 || write_state.record_writes < 1 ||
        producer->persistent->current_records != 1 ||
        producer->persistent->checkpoint.acked_log_id != 0 ||
        producer->queue_count != 0 || producer->ingress_queue_count != 0) {
        goto done;
    }
    ve_tls_producer_destroy(producer);
    producer = NULL;
    config.platform.file_write = g_real_platform.file_write;
    ok = regression_prod_persistent_recover_exact(
        &config, 1, ids, payloads, payload_sizes) == 0;

done:
    if (g_regression_prod_persistent_wal_write == &write_state) {
        g_regression_prod_persistent_wal_write = NULL;
    }
    if (alloc_active) {
        regression_prod_persistent_alloc_end(&alloc_state);
    }
    ve_tls_producer_destroy(producer);
    cleanup_persistent_dir(dir);
    return ok ? 0 : -1;
}

static int regression_prod_test_persistent_merge_and_ingress_oom(void) {
#define REGRESSION_PROD_PERSISTENT_MERGE_VALUE_LEN 40
    char old_value[REGRESSION_PROD_PERSISTENT_MERGE_VALUE_LEN + 1];
    char rejected_value[REGRESSION_PROD_PERSISTENT_MERGE_VALUE_LEN + 1];
    const char * old_values[1] = {old_value};
    const char * rejected_values[1] = {rejected_value};
    const size_t value_lens[1] = {REGRESSION_PROD_PERSISTENT_MERGE_VALUE_LEN};
    const int64_t times[2] = {REGRESSION_PRODUCER_TEST_TIME, REGRESSION_PRODUCER_TEST_TIME + 1};
    const int64_t ids[2] = {1, 2};
    const unsigned char * payloads[2] = {NULL, NULL};
    size_t payload_sizes[2] = {0, 0};
    char dir[PATH_MAX] = {0};
    ve_tls_config config;
    ve_tls_producer * producer = NULL;
    ve_tls_log_group_builder * expected_old = NULL;
    ve_tls_log_group_builder * expected_rejected = NULL;
    regression_prod_persistent_alloc_state alloc_state = {0};
    regression_prod_persistent_wal_write_state write_state;
    ve_tls_kv kv;
    int64_t old_id = -1;
    int64_t rejected_id = -1;
    ve_tls_result result;
    int alloc_active = 0;
    int ok = 0;

    regression_prod_fill(old_value, REGRESSION_PROD_PERSISTENT_MERGE_VALUE_LEN, 'O');
    regression_prod_fill(rejected_value, REGRESSION_PROD_PERSISTENT_MERGE_VALUE_LEN, 'R');
    if (make_temp_dir(dir, sizeof(dir)) != 0 ||
        regression_prod_persistent_init_config(&config, dir) != 0) {
        cleanup_persistent_dir(dir);
        return -1;
    }
    g_fake_time = REGRESSION_PRODUCER_TEST_TIME;
    config.flush_interval_ms = 100000;
    config.metrics_sink.emit = regression_prod_metrics_emit;
    memset(&write_state, 0, sizeof(write_state));
    g_regression_prod_persistent_wal_write = &write_state;
    config.platform.file_write = regression_prod_persistent_wal_file_write;
    kv.key = "key";
    kv.value = old_value;
    producer = ve_tls_producer_create_versioned(
        &config, sizeof(config), VE_TLS_CONFIG_VERSION_CURRENT);
    if (!producer || !producer->persistent ||
        ve_tls_producer_add_log_kv_with_id(
            producer, times[0], &kv, 1, 1, &old_id) != VE_TLS_OK ||
        old_id != 1 || !producer->persistent_builder_cache ||
        producer->default_builder != NULL || !producer->sealed_head) {
        goto done;
    }
    producer->ingress_queue_count = producer->ingress_queue_cap;
    regression_prod_persistent_alloc_begin(&alloc_state);
    alloc_active = 1;
    write_state.alloc = &alloc_state;
    write_state.arm_fail_next_calloc = 1;
    kv.value = rejected_value;
    result = ve_tls_producer_add_log_kv_with_id(
        producer, times[1], &kv, 1, 0, &rejected_id);
    regression_prod_persistent_alloc_end(&alloc_state);
    alloc_active = 0;
    g_regression_prod_persistent_wal_write = NULL;
    if (result != VE_TLS_DROP_ERROR || rejected_id != 2 ||
        alloc_state.failed_calloc != 1 || write_state.record_writes < 2 ||
        producer->persistent->current_records != 2 ||
        producer->persistent->checkpoint.acked_log_id != 0 ||
        producer->ingress_queue_count != producer->ingress_queue_cap) {
        goto done;
    }
    expected_old = regression_prod_build_expected(
        old_values, value_lens, &times[0], &ids[0], 1);
    expected_rejected = regression_prod_build_expected(
        rejected_values, value_lens, &times[1], &ids[1], 1);
    if (!expected_old || !expected_rejected) {
        goto done;
    }
    payloads[0] = expected_old->logs;
    payload_sizes[0] = expected_old->logs_len;
    payloads[1] = expected_rejected->logs;
    payload_sizes[1] = expected_rejected->logs_len;
    ve_tls_producer_destroy(producer);
    producer = NULL;
    config.platform.file_write = g_real_platform.file_write;
    ok = regression_prod_persistent_recover_exact(
        &config, 2, ids, payloads, payload_sizes) == 0;

done:
    if (g_regression_prod_persistent_wal_write == &write_state) {
        g_regression_prod_persistent_wal_write = NULL;
    }
    if (alloc_active) {
        regression_prod_persistent_alloc_end(&alloc_state);
    }
    ve_tls_producer_destroy(producer);
    ve_tls_log_builder_free(expected_old);
    ve_tls_log_builder_free(expected_rejected);
    cleanup_persistent_dir(dir);
    return ok ? 0 : -1;
#undef REGRESSION_PROD_PERSISTENT_MERGE_VALUE_LEN
}

typedef struct {
    ve_tls_producer * producer;
    ve_tls_mutex * sync_mutex;
    ve_tls_cond * sync_cond;
    ve_tls_thread * thread;
    ve_tls_result close_result;
    int armed;
    int launched;
    int close_begun;
    int close_done;
    int launch_failed;
    int wait_failed;
} regression_prod_persistent_close_state;

enum {
    REGRESSION_PROD_PERSISTENT_CLOSE_WAIT_MS = 5000
};

static regression_prod_persistent_close_state * g_regression_prod_persistent_close;
static _Thread_local regression_prod_persistent_close_state *
    g_regression_prod_persistent_close_tls;

static void * regression_prod_persistent_close_thread_main(void * arg) {
    regression_prod_persistent_close_state * state =
        (regression_prod_persistent_close_state *)arg;
    if (!state) {
        return NULL;
    }
    g_regression_prod_persistent_close_tls = state;
    state->close_result = ve_tls_producer_close(state->producer, 10000);
    g_real_platform.mutex_lock(state->sync_mutex);
    state->close_done = 1;
    g_real_platform.cond_signal(state->sync_cond);
    g_real_platform.mutex_unlock(state->sync_mutex);
    g_regression_prod_persistent_close_tls = NULL;
    return NULL;
}

static ve_tls_thread * regression_prod_persistent_mixed_thread_create(
    ve_tls_thread_fn fn,
    void * arg
) {
    if (fn == ve_tls_worker_main || fn == ve_tls_sender_main) {
        return REGRESSION_PROD_DUMMY_THREAD;
    }
    return g_real_platform.thread_create(fn, arg);
}

static void regression_prod_persistent_mixed_thread_join(ve_tls_thread * thread) {
    if (thread == REGRESSION_PROD_DUMMY_THREAD) {
        return;
    }
    g_real_platform.thread_join(thread);
}

static int regression_prod_persistent_close_cond_timedwait(
    ve_tls_cond * cond,
    ve_tls_mutex * mutex,
    int64_t timeout_ms
) {
    regression_prod_persistent_close_state * state =
        g_regression_prod_persistent_close_tls;
    if (state) {
        g_real_platform.mutex_lock(state->sync_mutex);
        state->close_begun = 1;
        g_real_platform.cond_signal(state->sync_cond);
        g_real_platform.mutex_unlock(state->sync_mutex);
    }
    return g_real_platform.cond_timedwait_ms(cond, mutex, timeout_ms);
}

static int64_t regression_prod_persistent_close_file_write(
    ve_tls_file * file,
    const void * buffer,
    size_t size
) {
    regression_prod_persistent_close_state * state =
        g_regression_prod_persistent_close;
    if (state && state->armed && regression_prod_persistent_is_record(buffer, size)) {
        int launch = 0;
        g_real_platform.mutex_lock(state->sync_mutex);
        if (!state->launched) {
            state->launched = 1;
            launch = 1;
        }
        g_real_platform.mutex_unlock(state->sync_mutex);
        if (launch) {
            state->thread = g_real_platform.thread_create(
                regression_prod_persistent_close_thread_main, state);
            if (!state->thread) {
                g_real_platform.mutex_lock(state->sync_mutex);
                state->launch_failed = 1;
                g_real_platform.cond_signal(state->sync_cond);
                g_real_platform.mutex_unlock(state->sync_mutex);
            } else {
                g_real_platform.mutex_lock(state->sync_mutex);
                while (!state->close_begun && !state->close_done &&
                       !state->launch_failed) {
                    int wait_rc = g_real_platform.cond_timedwait_ms(
                        state->sync_cond,
                        state->sync_mutex,
                        REGRESSION_PROD_PERSISTENT_CLOSE_WAIT_MS);
                    if (wait_rc != 0 && !state->close_begun &&
                        !state->close_done) {
                        state->wait_failed = 1;
                        break;
                    }
                }
                g_real_platform.mutex_unlock(state->sync_mutex);
            }
        }
    }
    return g_real_platform.file_write(file, buffer, size);
}

static int regression_prod_test_persistent_append_close_interleave(void) {
    static const unsigned char payload[] = "persistent-close-interleave";
    const unsigned char * payloads[1] = {payload};
    const size_t payload_sizes[1] = {sizeof(payload) - 1};
    const int64_t ids[1] = {1};
    char dir[PATH_MAX] = {0};
    ve_tls_config config;
    ve_tls_producer * producer = NULL;
    regression_prod_persistent_close_state close_state;
    int64_t id = -1;
    ve_tls_result result;
    int ok = 0;

    if (make_temp_dir(dir, sizeof(dir)) != 0 ||
        regression_prod_persistent_init_config(&config, dir) != 0) {
        cleanup_persistent_dir(dir);
        return -1;
    }
    g_fake_time = REGRESSION_PRODUCER_TEST_TIME;
    memset(&close_state, 0, sizeof(close_state));
    close_state.close_result = VE_TLS_INVALID;
    close_state.sync_mutex = g_real_platform.mutex_create();
    close_state.sync_cond = g_real_platform.cond_create();
    if (!close_state.sync_mutex || !close_state.sync_cond) {
        goto done;
    }
    config.platform.thread_create = regression_prod_persistent_mixed_thread_create;
    config.platform.thread_join = regression_prod_persistent_mixed_thread_join;
    /* This case uses real condition waits, so close's deadline must also
     * advance if the expected rendezvous fails. */
    config.platform.time_ms = g_real_platform.time_ms;
    config.platform.cond_timedwait_ms = regression_prod_persistent_close_cond_timedwait;
    config.platform.file_write = regression_prod_persistent_close_file_write;
    producer = ve_tls_producer_create_versioned(
        &config, sizeof(config), VE_TLS_CONFIG_VERSION_CURRENT);
    if (!producer || !producer->persistent) {
        goto done;
    }
    close_state.producer = producer;
    close_state.armed = 1;
    g_regression_prod_persistent_close = &close_state;
    result = ve_tls_producer_add_log_raw_with_id(
        producer, (const char *)payload, sizeof(payload) - 1, 0, &id);
    close_state.armed = 0;
    if (close_state.thread) {
        g_real_platform.thread_join(close_state.thread);
        close_state.thread = NULL;
    }
    g_regression_prod_persistent_close = NULL;
    if (result != VE_TLS_CLOSED || id != 1 || close_state.launch_failed ||
        close_state.wait_failed ||
        !close_state.launched || !close_state.close_begun ||
        !close_state.close_done || close_state.close_result != VE_TLS_OK ||
        producer->persistent->current_records != 1 ||
        producer->persistent->checkpoint.acked_log_id != 0 ||
        producer->queue_count != 0 || producer->ingress_queue_count != 0) {
        goto done;
    }
    ve_tls_producer_destroy(producer);
    producer = NULL;
    config.platform.file_write = g_real_platform.file_write;
    config.platform.cond_timedwait_ms = test_fake_cond_timedwait_ms;
    config.platform.thread_create = regression_prod_persistent_no_thread_create;
    config.platform.thread_join = regression_prod_persistent_no_thread_join;
    ok = regression_prod_persistent_recover_exact(
        &config, 1, ids, payloads, payload_sizes) == 0;

done:
    g_regression_prod_persistent_close = NULL;
    if (close_state.thread) {
        g_real_platform.thread_join(close_state.thread);
        close_state.thread = NULL;
    }
    ve_tls_producer_destroy(producer);
    if (close_state.sync_cond) {
        g_real_platform.cond_destroy(close_state.sync_cond);
    }
    if (close_state.sync_mutex) {
        g_real_platform.mutex_destroy(close_state.sync_mutex);
    }
    cleanup_persistent_dir(dir);
    return ok ? 0 : -1;
}

static int test_producer_admission_regressions(void) {
    if (regression_prod_test_mutable_value_lengths(1) != 0) return -1;
    if (regression_prod_test_mutable_value_lengths(0) != 0) return -2;
    if (regression_prod_test_append_oom_preserves_old() != 0) return -3;
    if (regression_prod_test_flush_oom_rolls_back_current() != 0) return -4;
    if (regression_prod_test_merge_oom_rolls_back_current() != 0) return -5;
    if (regression_prod_test_initial_builder_oom_retries() != 0) return -6;
    if (regression_prod_test_persistent_raw_queue_oom() != 0) return -7;
    if (regression_prod_test_persistent_merge_and_ingress_oom() != 0) return -8;
    if (regression_prod_test_persistent_append_close_interleave() != 0) return -9;
    return 0;
}
