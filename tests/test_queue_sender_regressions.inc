/* Queue and sender allocation-failure regressions use test_basic.c fixtures. */
static int test_regression_queue_arguments_and_accounting(void) {
    ve_tls_config cfg;
    ve_tls_producer p;
    ve_tls_log_item out;
    alloc_select_fail_state fault = {0};
    ve_tls_config_init(&cfg);
    if (init_fake_sender_producer(&p, &cfg) != 0) return -1;
    int rc = -1;
    /* Invalid input must not even attempt allocation. */
    set_alloc_select_fail(&fault, 1, 0, 0, 0);
    int null_producer = ve_tls_queue_push(NULL, (const unsigned char *)"a", 1, 1, 1, 0, 0, NULL);
    int allocations = fault.malloc_calls;
    ve_tls_alloc_set_hooks(NULL);
    if (null_producer == 0 || allocations != 0) goto end;
    if (ve_tls_queue_push(&p, NULL, 1, 1, 1, 0, 0, NULL) == 0 ||
        ve_tls_queue_push(&p, (const unsigned char *)"a", 0, 1, 1, 0, 0, NULL) == 0) goto end;

    set_alloc_select_fail(&fault, 0, 1, 0, 0);
    int failed = ve_tls_queue_push(&p, (const unsigned char *)"abc", 3, 1, 1, 0, 0, NULL);
    ve_tls_alloc_set_hooks(NULL);
    if (failed == 0 || p.queue || p.queue_cap || p.queue_count || p.queue_bytes) goto end;
    if (ve_tls_queue_push(&p, (const unsigned char *)"abc", 3, 1, 1, 0, 0, NULL) != 0 ||
        ve_tls_queue_push(&p, (const unsigned char *)"de", 2, 2, 1, 0, 0, NULL) != 0) goto end;
    /* Reject inconsistent accounting atomically: preserve both queued items. */
    p.queue_bytes = 2;
    memset(&out, 0, sizeof(out));
    if (ve_tls_queue_pop(&p, &out) == 0 || p.queue_count != 2 ||
        p.queue_bytes != 2 || p.queue_head != 0 || out.data) goto end;
    p.queue_bytes = 5;
    if (ve_tls_queue_pop(&p, &out) != 0) goto end;
    if (out.size != 3 || memcmp(out.data, "abc", 3) || p.queue_bytes != 2) {
        ve_tls_item_free(&out);
        goto end;
    }
    ve_tls_item_free(&out);
    if (ve_tls_queue_pop(&p, &out) != 0) goto end;
    ve_tls_item_free(&out);
    if (p.queue_bytes || p.queue_count) goto end;

    ve_tls_key_queue q = {0};
    ve_tls_send_task t = {0};
    set_alloc_select_fail(&fault, 0, 1, 0, 0);
    failed = ve_tls_key_queue_push_front_task(&q, &t);
    ve_tls_alloc_set_hooks(NULL);
    if (failed == 0 || q.q || q.cap || q.count) { ve_tls_free(q.q); goto end; }
    if (ve_tls_key_queue_push_front_task(&q, &t) != 0) goto end;
    ve_tls_free(q.q);
    rc = 0;
end:
    ve_tls_alloc_set_hooks(NULL);
    ve_tls_queue_free_all(&p);
    destroy_fake_sender_producer(&p);
    return rc;
}

typedef struct {
    ve_tls_producer * producer;
    ve_tls_key_queue * queue;
    ve_tls_send_task filler;
    void * tracked[3];
    int frees[3];
    int injected;
    int fail_growth;
    int drop_v1;
    int drop_v2;
    int metric;
    int bad_callback;
} regression_reschedule_state;
static regression_reschedule_state * g_regression_reschedule;

static void * regression_reschedule_calloc(size_t n, size_t size, void * user) {
    regression_reschedule_state * s = (regression_reschedule_state *)user;
    if (s->fail_growth && n == 2 && size == sizeof(ve_tls_send_task)) {
        s->fail_growth = 0;
        return NULL;
    }
    return calloc(n, size);
}
static void regression_reschedule_free(void * ptr, void * user) {
    regression_reschedule_state * s = (regression_reschedule_state *)user;
    for (int i = 0; i < 3; ++i) if (ptr && ptr == s->tracked[i]) {
        s->frees[i]++;
        /* Later unrelated allocations may reuse the address; ASan separately
         * checks double frees of the original allocation. */
        s->tracked[i] = NULL;
    }
    free(ptr);
}
static int64_t regression_reschedule_time_ms(void) {
    regression_reschedule_state * s = g_regression_reschedule;
    if (s && !s->injected && s->queue->inflight && !s->queue->count) {
        /* Model a concurrent enqueue using the slot vacated by the sender. */
        s->injected = 1;
        if (ve_tls_key_queue_push_task(s->producer, "k1", &s->filler) != 0) abort();
        memset(&s->filler, 0, sizeof(s->filler));
        s->fail_growth = 1;
    }
    return 1000;
}
static void regression_reschedule_metric(const char * event, int64_t a, int64_t b, void * user) {
    (void)a; (void)b;
    regression_reschedule_state * s = (regression_reschedule_state *)user;
    if (!strcmp(event, "persistent_reschedule_failed") || !strcmp(event, "send_reschedule_failed")) {
        s->metric++;
        s->producer->config.key_rate_limit_rps = 0;
        s->producer->stop = 1;
    }
}
static void regression_reschedule_done_v1(ve_tls_result result, size_t bytes, size_t compressed,
    const char * request_id, const char * message, const unsigned char * raw,
    void * user, int64_t start, int64_t end) {
    (void)compressed; (void)request_id; (void)raw;
    regression_reschedule_state * s = (regression_reschedule_state *)user;
    if (start == 1) {
        s->drop_v1++;
        if (result != VE_TLS_DROP_ERROR || bytes != 16 || end != 1 || !message) s->bad_callback = 1;
    }
}
static void regression_reschedule_done_v2(ve_tls_result result, size_t bytes, size_t compressed,
    const ve_tls_error * error, const unsigned char * raw, void * user, int64_t start, int64_t end) {
    (void)compressed; (void)raw;
    regression_reschedule_state * s = (regression_reschedule_state *)user;
    if (start == 1) {
        s->drop_v2++;
        if (result != VE_TLS_DROP_ERROR || bytes != 16 || end != 1 || !error ||
            !error->error_code || strcmp(error->error_code, "OutOfMemory")) s->bad_callback = 1;
    }
}
static int regression_reschedule_recover(int64_t id, int64_t time_ms, const char * key,
    const unsigned char * payload, size_t size, void * user) {
    if (id != 1 || time_ms != 1000 || !key || strcmp(key, "k1") ||
        size != 16 || memcmp(payload, "0123456789abcdef", 16)) return -1;
    (*(int *)user)++;
    return 0;
}

static int regression_reschedule_case(int main_loop, int persistent_mode) {
    ve_tls_config cfg;
    ve_tls_config wal_cfg;
    ve_tls_persistent_options opt;
    ve_tls_persistent wal = {0};
    char dir[PATH_MAX] = {0};
    int rc = -1, opened = 0;
    regression_reschedule_state state = {0};
    ve_tls_producer p;
    ve_tls_config_init(&cfg);
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "t";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.compress_type = "none";
    cfg.key_rate_limit_rps = 1;
    cfg.platform.time_ms = regression_reschedule_time_ms;
    cfg.http_client.do_request = test_http_step_ok_do;
    cfg.http_client.free_response = test_http_free;
    cfg.metrics_sink.emit = regression_reschedule_metric;
    cfg.metrics_sink.user_param = &state;
    if (init_fake_sender_producer(&p, &cfg) != 0) return -1;
    state.producer = &p;
    p.send_done = regression_reschedule_done_v1;
    p.send_done_param = &state;
    p.send_done_v2 = regression_reschedule_done_v2;
    p.send_done_v2_param = &state;
    if (persistent_mode) {
        if (make_temp_dir(dir, sizeof(dir)) != 0) goto end;
        test_init_persistent_options(&opt, &wal_cfg, dir);
        g_fake_time = 1000;
        wal_cfg.platform.time_ms = test_fake_time_ms;
        if (ve_tls_persistent_open(&wal, &opt) != 0) goto end;
        opened = 1;
        if (ve_tls_persistent_append(&wal, 1, "k1", (const unsigned char *)"0123456789abcdef", 16) != 0) goto end;
        p.persistent = &wal;
    }
    for (int id = 1; id <= 2; ++id) {
        ve_tls_send_task task = {0};
        task.body = (unsigned char *)ve_tls_malloc(16);
        task.hash_key = ve_tls_strdup("k1");
        if (!task.body || !task.hash_key) { ve_tls_send_task_free(&task); goto end; }
        memcpy(task.body, "0123456789abcdef", 16);
        task.body_size = task.raw_body_size = task.batch_bytes = 16;
        task.start_id = task.end_id = id;
        task.log_count = 1;
        if (id == 1) {
            task.precompressed = (unsigned char *)ve_tls_malloc(8);
            if (!task.precompressed) { ve_tls_send_task_free(&task); goto end; }
            memset(task.precompressed, 'x', 8);
            task.precompressed_size = 8;
            state.tracked[0] = task.body;
            state.tracked[1] = task.precompressed;
            state.tracked[2] = task.hash_key;
            if (ve_tls_key_queue_push_task(&p, "k1", &task) != 0) { ve_tls_send_task_free(&task); goto end; }
        } else state.filler = task;
        p.inflight_bytes += ve_tls_send_task_memory_bytes(&task);
    }
    state.queue = find_key_queue(&p, "k1");
    /* A one-slot ring is enough to exercise the exact full-ring interleaving. */
    state.queue->cap = 1;
    state.queue->tail = 0;
    state.queue->rl_last_ms = 1000;
    state.queue->rl_req_tokens = 0;
    ve_tls_alloc_hooks hooks = {0};
    hooks.calloc_fn = regression_reschedule_calloc;
    hooks.free_fn = regression_reschedule_free;
    hooks.user_data = &state;
    g_regression_reschedule = &state;
    ve_tls_alloc_set_hooks(&hooks);
    g_step_http_calls = 0;
    if (main_loop) ve_tls_sender_main(&p);
    else {
        if (ve_tls_sender_step(&p) != 1) goto end;
        if (state.metric != 1 || state.frees[0] != 1 || state.frees[1] != 1 || state.frees[2] != 1) goto end;
        if (ve_tls_sender_step(&p) != 1) goto end;
    }
    ve_tls_alloc_set_hooks(NULL);
    g_regression_reschedule = NULL;
    if (!state.injected || state.fail_growth || state.metric != 1 || state.bad_callback ||
        state.drop_v1 != !persistent_mode || state.drop_v2 != !persistent_mode ||
        state.frees[0] != 1 || state.frees[1] != 1 || state.frees[2] != 1 ||
        g_step_http_calls != 1 || p.inflight_bytes != 0 || p.m_logs_dropped_total != (uint64_t)!persistent_mode) goto end;
    if (persistent_mode) {
        p.persistent = NULL;
        ve_tls_persistent_close(&wal);
        opened = 0;
        if (ve_tls_persistent_open(&wal, &opt) != 0) goto end;
        opened = 1;
        int recovered = 0;
        if (ve_tls_persistent_recover(&wal, regression_reschedule_recover, &recovered) != 0 || recovered != 1) goto end;
    }
    rc = 0;
end:
    ve_tls_alloc_set_hooks(NULL);
    g_regression_reschedule = NULL;
    p.persistent = NULL;
    if (opened) ve_tls_persistent_close(&wal);
    if (dir[0]) cleanup_persistent_dir(dir);
    ve_tls_send_task_free(&state.filler);
    destroy_fake_sender_producer(&p);
    if (rc) fprintf(stderr, "reschedule main=%d persistent=%d injected=%d metric=%d frees=%d/%d/%d callbacks=%d/%d http=%d\n",
        main_loop, persistent_mode, state.injected, state.metric, state.frees[0], state.frees[1], state.frees[2], state.drop_v1, state.drop_v2, g_step_http_calls);
    return rc;
}

static ve_tls_producer * g_regression_waking_manager;
static ve_tls_log_group_builder * g_regression_waking_batch;
static int g_regression_manager_waits;
static void regression_manager_wake_with_builder(ve_tls_cond * cond, ve_tls_mutex * mutex) {
    (void)cond; (void)mutex;
    if (++g_regression_manager_waits != 1) abort();
    /* Simulate the state observable after cond_wait reacquires the mutex:
     * another caller has published a builder and then requested shutdown. */
    g_regression_waking_manager->default_builder = g_regression_waking_batch;
    g_regression_waking_manager->queue_bytes = g_regression_waking_batch->logs_len;
    g_regression_waking_batch = NULL;
    g_regression_waking_manager->stop = 1;
}
static int test_regression_manager_wake_rechecks_builder(void) {
    ve_tls_config cfg;
    ve_tls_producer p;
    ve_tls_send_task task = {0};
    ve_tls_kv kv = {"k", "v"};
    size_t len = 1;
    ve_tls_config_init(&cfg);
    cfg.compress_type = "none";
    cfg.platform.cond_wait = regression_manager_wake_with_builder;
    if (init_fake_sender_producer(&p, &cfg) != 0) return -1;
    int rc = -1;
    g_regression_waking_batch = ve_tls_log_builder_create("");
    if (!g_regression_waking_batch || ve_tls_log_builder_add_kv_lens(
        g_regression_waking_batch, 1, 1000, 0, 0, &kv, &len, &len, 1) != 0) goto end;
    g_regression_manager_waits = 0;
    g_regression_waking_manager = &p;
    ve_tls_worker_main(&p);
    if (g_regression_manager_waits != 1 || p.default_builder || p.queue_bytes ||
        ve_tls_send_queue_pop(&p.send_queue, &task, 0) != 0 || task.log_count != 1 ||
        task.start_id != 1 || task.end_id != 1) goto end;
    rc = 0;
end:
    ve_tls_send_task_free(&task);
    ve_tls_log_builder_free(g_regression_waking_batch);
    g_regression_waking_batch = NULL;
    g_regression_waking_manager = NULL;
    ve_tls_log_builder_free(p.default_builder);
    p.default_builder = NULL;
    destroy_fake_sender_producer(&p);
    return rc;
}

static int test_queue_sender_regressions(void) {
    if (test_regression_queue_arguments_and_accounting() != 0) return -1;
    for (int main_loop = 0; main_loop <= 1; ++main_loop)
        for (int persistent_mode = 0; persistent_mode <= 1; ++persistent_mode)
            if (regression_reschedule_case(main_loop, persistent_mode) != 0) return -2;
    if (test_regression_manager_wake_rechecks_builder() != 0) return -3;
    return 0;
}
