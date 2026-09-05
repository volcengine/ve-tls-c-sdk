/* Builder bounds and signing-input regressions. */
#include <stdint.h>

static int regression_builder_state_equal(
    const ve_tls_log_group_builder * a,
    const ve_tls_log_group_builder * b
) {
    return a && b &&
           a->norm_key == b->norm_key &&
           a->logs == b->logs &&
           a->logs_len == b->logs_len &&
           a->logs_cap == b->logs_cap &&
           a->log_count == b->log_count &&
           a->earliest == b->earliest &&
           a->latest == b->latest &&
           a->last_time_ms == b->last_time_ms &&
           a->last_time_ns == b->last_time_ns &&
           a->last_has_time_ns == b->last_has_time_ns &&
           a->start_id == b->start_id &&
           a->end_id == b->end_id &&
           a->first_append_ms == b->first_append_ms &&
           a->next == b->next;
}

static int regression_test_sign_empty_headers_matrix(void) {
    const unsigned char body[] = {1, 2, 3, 4};
    const char * tokens[] = {NULL, "", "regression-sts-token"};
    char * outputs[3][2] = {{NULL, NULL}, {NULL, NULL}, {NULL, NULL}};
    int failed = 0;

    for (size_t token_index = 0; token_index < 3 && !failed; token_index++) {
        for (size_t headers_index = 0; headers_index < 2; headers_index++) {
            const char * headers = headers_index == 0 ? NULL : "";
            if (ve_tls_sign_v4_append_at(
                    "regression-ak",
                    "regression-sk",
                    tokens[token_index],
                    "cn-beijing",
                    "TLS",
                    "POST",
                    "example.com",
                    "/PutLogs",
                    "TopicId=regression",
                    body,
                    sizeof(body),
                    "20260410T032329Z",
                    headers,
                    &outputs[token_index][headers_index]) != 0 ||
                !outputs[token_index][headers_index]) {
                failed = 1;
                break;
            }
        }
        if (!failed && strcmp(outputs[token_index][0], outputs[token_index][1]) != 0) {
            failed = 1;
        }
        if (!failed && strstr(outputs[token_index][0], "X-Date: 20260410T032329Z\n") == NULL) {
            failed = 1;
        }
        if (!failed && token_index == 2 &&
            strstr(outputs[token_index][0], "X-Security-Token: regression-sts-token\n") == NULL) {
            failed = 1;
        }
        if (!failed && token_index != 2 &&
            strstr(outputs[token_index][0], "X-Security-Token: ") != NULL) {
            failed = 1;
        }
    }

    if (!failed && strcmp(outputs[0][0], outputs[1][0]) != 0) {
        failed = 1;
    }
    for (size_t token_index = 0; token_index < 3; token_index++) {
        for (size_t headers_index = 0; headers_index < 2; headers_index++) {
            ve_tls_free(outputs[token_index][headers_index]);
        }
    }
    return failed ? -1 : 0;
}

static int regression_test_sign_empty_headers_oom(void) {
    ve_tls_alloc_hooks saved;
    alloc_fail_state state;
    char * out = NULL;
    int rc;

    memset(&saved, 0, sizeof(saved));
    memset(&state, 0, sizeof(state));
    ve_tls_alloc_get_hooks(&saved);
    set_alloc_fail_after(&state, 1);
    rc = ve_tls_sign_v4_append_at(
        "regression-ak",
        "regression-sk",
        NULL,
        "cn-beijing",
        "TLS",
        "POST",
        "example.com",
        "/PutLogs",
        "TopicId=regression",
        (const unsigned char *)"body",
        4,
        "20260410T032329Z",
        NULL,
        &out);
    ve_tls_alloc_set_hooks(&saved);
    ve_tls_free(out);
    return (rc != 0 && out == NULL) ? 0 : -1;
}

static int regression_test_builder_append_rejections(void) {
    unsigned char storage[8] = {0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5};
    const unsigned char extra[2] = {0x11, 0x22};
    ve_tls_log_group_builder b;
    ve_tls_log_group_builder before;

    memset(&b, 0, sizeof(b));
    b.logs = storage;
    b.logs_len = 2;
    b.logs_cap = 1;
    b.log_count = 3;
    before = b;
    if (ve_tls_log_builder_append(&b, extra, 1, 1, 1, 2, 3, 4, 5, 6, 1) == 0 ||
        !regression_builder_state_equal(&b, &before)) {
        return -1;
    }

    memset(&b, 0, sizeof(b));
    b.logs_cap = sizeof(storage);
    b.log_count = 3;
    before = b;
    if (ve_tls_log_builder_append(&b, extra, 1, 1, 1, 2, 3, 4, 5, 6, 1) == 0 ||
        !regression_builder_state_equal(&b, &before)) {
        return -1;
    }

    memset(&b, 0, sizeof(b));
    b.logs = storage;
    b.log_count = 3;
    before = b;
    if (ve_tls_log_builder_append(&b, extra, 1, 1, 1, 2, 3, 4, 5, 6, 1) == 0 ||
        !regression_builder_state_equal(&b, &before)) {
        return -1;
    }

    memset(&b, 0, sizeof(b));
    b.logs = storage;
    b.logs_len = 1;
    b.logs_cap = sizeof(storage);
    b.log_count = -1;
    before = b;
    if (ve_tls_log_builder_append(&b, extra, 1, 1, 1, 2, 3, 4, 5, 6, 1) == 0 ||
        !regression_builder_state_equal(&b, &before)) {
        return -1;
    }

    memset(&b, 0, sizeof(b));
    b.logs = storage;
    b.logs_len = (size_t)-1 - 1;
    b.logs_cap = (size_t)-1;
    b.log_count = 3;
    before = b;
    if (ve_tls_log_builder_append(&b, extra, 2, 1, 1, 2, 3, 4, 5, 6, 1) == 0 ||
        !regression_builder_state_equal(&b, &before)) {
        return -1;
    }

    memset(&b, 0, sizeof(b));
    b.logs = storage;
    b.logs_cap = sizeof(storage);
    b.log_count = INT32_MAX;
    before = b;
    if (ve_tls_log_builder_append(&b, extra, 1, 1, 1, 2, 3, 4, 5, 6, 1) == 0 ||
        !regression_builder_state_equal(&b, &before) || storage[0] != 0xA5) {
        return -1;
    }
    return 0;
}

static int regression_test_builder_append_oom_is_atomic(void) {
    ve_tls_alloc_hooks saved;
    alloc_fail_state state;
    ve_tls_log_group_builder b;
    ve_tls_log_group_builder before;
    const unsigned char extra[2] = {0x11, 0x22};

    memset(&saved, 0, sizeof(saved));
    memset(&state, 0, sizeof(state));
    memset(&b, 0, sizeof(b));
    before = b;
    ve_tls_alloc_get_hooks(&saved);
    set_alloc_fail_after(&state, 1);
    int rc = ve_tls_log_builder_append(&b, extra, sizeof(extra), 1, 1, 2, 3, 4, 5, 6, 1);
    ve_tls_alloc_set_hooks(&saved);
    if (rc == 0 || !regression_builder_state_equal(&b, &before)) {
        return -1;
    }
    return 0;
}

static int regression_test_wire_build_reachable_paths(void) {
    /* ve_tls_wire_reserve is static; exercise it through the existing group
     * suffix builder so no public test-only ABI is added. */
    ve_tls_producer producer;
    char long_source[300];
    ve_tls_alloc_hooks saved;
    alloc_fail_state state;

    memset(&producer, 0, sizeof(producer));
    producer.config.source = "s";
    producer.config.file_name = "f";
    producer.config.context_flow = "c";
    if (ve_tls_producer_build_group_suffix(&producer) != 0 ||
        !producer.cfg_group_suffix || producer.cfg_group_suffix_len == 0) {
        ve_tls_free(producer.cfg_group_suffix);
        return -1;
    }
    ve_tls_free(producer.cfg_group_suffix);
    producer.cfg_group_suffix = NULL;
    producer.cfg_group_suffix_len = 0;

    for (size_t i = 0; i + 1 < sizeof(long_source); i++) {
        long_source[i] = 's';
    }
    long_source[sizeof(long_source) - 1] = 0;
    producer.config.source = long_source;
    producer.config.file_name = NULL;
    producer.config.context_flow = NULL;
    if (ve_tls_producer_build_group_suffix(&producer) != 0 ||
        !producer.cfg_group_suffix || producer.cfg_group_suffix_len <= 128) {
        ve_tls_free(producer.cfg_group_suffix);
        return -1;
    }
    ve_tls_free(producer.cfg_group_suffix);
    producer.cfg_group_suffix = NULL;
    producer.cfg_group_suffix_len = 0;

    memset(&saved, 0, sizeof(saved));
    memset(&state, 0, sizeof(state));
    ve_tls_alloc_get_hooks(&saved);
    set_alloc_fail_after(&state, 1);
    int rc = ve_tls_producer_build_group_suffix(&producer);
    ve_tls_alloc_set_hooks(&saved);
    if (rc == 0 || producer.cfg_group_suffix != NULL || producer.cfg_group_suffix_len != 0) {
        ve_tls_free(producer.cfg_group_suffix);
        return -1;
    }
    return 0;
}

static int test_builder_sign_regressions(void) {
    if (regression_test_sign_empty_headers_matrix() != 0) return -1;
    if (regression_test_sign_empty_headers_oom() != 0) return -1;
    if (regression_test_builder_append_rejections() != 0) return -1;
    if (regression_test_builder_append_oom_is_atomic() != 0) return -1;
    if (regression_test_wire_build_reachable_paths() != 0) return -1;
    return 0;
}
