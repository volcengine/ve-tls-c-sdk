#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "ve_tls_android_binding.h"

static int g_events[16];
static int g_event_count;
static int g_recover_calls;
static int g_close_calls;
static int g_close_split_calls;
static int g_destroy_calls;
static int g_last_close_timeout_ms;
static int g_last_close_flusher_wait_ms;
static int g_last_close_sender_wait_ms;

static void reset_runtime_events(void) {
    g_event_count = 0;
    g_recover_calls = 0;
    g_close_calls = 0;
    g_close_split_calls = 0;
    g_destroy_calls = 0;
    g_last_close_timeout_ms = 0;
    g_last_close_flusher_wait_ms = 0;
    g_last_close_sender_wait_ms = 0;
}

static void mark_event(int event) {
    if (g_event_count < (int)(sizeof(g_events) / sizeof(g_events[0]))) {
        g_events[g_event_count++] = event;
    }
}

static ve_tls_result test_record_recover(ve_tls_producer * producer) {
    (void)producer;
    g_recover_calls++;
    mark_event(1);
    return VE_TLS_OK;
}

static ve_tls_result test_record_close(ve_tls_producer * producer, int32_t timeout_ms) {
    (void)producer;
    g_close_calls++;
    g_last_close_timeout_ms = timeout_ms;
    mark_event(2);
    return VE_TLS_OK;
}

static ve_tls_result test_record_close_split(ve_tls_producer * producer, int32_t flusher_timeout_ms, int32_t sender_timeout_ms) {
    (void)producer;
    g_close_split_calls++;
    g_last_close_flusher_wait_ms = flusher_timeout_ms;
    g_last_close_sender_wait_ms = sender_timeout_ms;
    mark_event(4);
    return VE_TLS_OK;
}

static void test_record_destroy(ve_tls_producer * producer) {
    (void)producer;
    g_destroy_calls++;
    mark_event(3);
}

static int test_http_bridge_do(ve_tls_http_client * client, const ve_tls_http_request * req, ve_tls_http_response * resp) {
    (void)client;
    (void)req;
    (void)resp;
    return 0;
}

static void test_http_bridge_free(ve_tls_http_client * client, ve_tls_http_response * resp) {
    (void)client;
    (void)resp;
}

static int test_android_binding_build_config_preserves_http_client_bridge(void) {
    ve_tls_android_config_view in;
    ve_tls_android_http_client_bridge bridge;
    ve_tls_android_runtime_options runtime;
    ve_tls_config out;
    int bridge_user_data = 1234;
    ve_tls_result rc;

    memset(&in, 0, sizeof(in));
    memset(&bridge, 0, sizeof(bridge));
    memset(&runtime, 0, sizeof(runtime));

    bridge.do_request = test_http_bridge_do;
    bridge.free_response = test_http_bridge_free;
    bridge.user_data = &bridge_user_data;
    in.http_client = &bridge;

    rc = ve_tls_android_binding_build_config(&in, &out, &runtime);
    if (rc != VE_TLS_OK) {
        fprintf(stderr, "build_config failed for http client bridge: %d\n", rc);
        return 1;
    }
    if (out.http_client.do_request != bridge.do_request) {
        fprintf(stderr, "http_client.do_request was not preserved\n");
        return 1;
    }
    if (out.http_client.free_response != bridge.free_response) {
        fprintf(stderr, "http_client.free_response was not preserved\n");
        return 1;
    }
    if (out.http_client.user_data != bridge.user_data) {
        fprintf(stderr, "http_client.user_data was not preserved\n");
        return 1;
    }

    return 0;
}

static int test_android_binding_build_persistent_path_and_clamps_sender(void) {
    ve_tls_android_config_view in;
    ve_tls_android_runtime_options runtime;
    ve_tls_config out;
    char rewritten[128] = {0};
    ve_tls_result rc;

    memset(&in, 0, sizeof(in));
    memset(&runtime, 0, sizeof(runtime));

    in.compress_type = VE_TLS_ANDROID_COMPRESS_LZ4;
    in.send_thread_count = 8;
    in.use_persistent = 1;
    in.destroy_wait_ms = 15000;

    rc = ve_tls_android_binding_build_config(&in, &out, &runtime);
    if (rc != VE_TLS_OK) {
        fprintf(stderr, "build_config failed: %d\n", rc);
        return 1;
    }
    if (out.send_thread_count != 1) {
        fprintf(stderr, "unexpected send_thread_count=%d, want 1\n", out.send_thread_count);
        return 1;
    }
    if (!runtime.persistent_enabled) {
        fprintf(stderr, "persistent enabled flag should be true in runtime\n");
        return 1;
    }

    rc = ve_tls_android_binding_build_persistent_path(
        "/tmp/ve-tls-base",
        "com.example.app:worker",
        rewritten,
        sizeof(rewritten)
    );
    if (rc != VE_TLS_OK || strcmp(rewritten, "/tmp/ve-tls-base-com.example.app_worker") != 0) {
        fprintf(stderr, "rewrite worker path failed: rc=%d rewritten=%s\n", rc, rewritten);
        return 1;
    }

    rc = ve_tls_android_binding_build_persistent_path(
        "/tmp/ve-tls-base",
        "com.example.app:we!rd#proc/name",
        rewritten,
        sizeof(rewritten)
    );
    if (rc != VE_TLS_OK || strcmp(rewritten, "/tmp/ve-tls-base-com.example.app_we_rd_proc_name") != 0) {
        fprintf(stderr, "sanitize rewrite failed: rc=%d rewritten=%s\n", rc, rewritten);
        return 1;
    }

    rc = ve_tls_android_binding_build_persistent_path("/tmp/ve-tls-base", "com.example.app", rewritten, sizeof(rewritten));
    if (rc != VE_TLS_OK || strcmp(rewritten, "/tmp/ve-tls-base") != 0) {
        fprintf(stderr, "main process rewrite changed path: rc=%d rewritten=%s\n", rc, rewritten);
        return 1;
    }

    rc = ve_tls_android_binding_build_persistent_path("/tmp/ve-tls-base", NULL, rewritten, sizeof(rewritten));
    if (rc != VE_TLS_OK || strcmp(rewritten, "/tmp/ve-tls-base") != 0) {
        fprintf(stderr, "null process name should keep base: rc=%d rewritten=%s\n", rc, rewritten);
        return 1;
    }

    rc = ve_tls_android_binding_build_persistent_path("/tmp/ve-tls-base", "", rewritten, sizeof(rewritten));
    if (rc != VE_TLS_OK || strcmp(rewritten, "/tmp/ve-tls-base") != 0) {
        fprintf(stderr, "empty process name should keep base: rc=%d rewritten=%s\n", rc, rewritten);
        return 1;
    }

    rc = ve_tls_android_binding_build_persistent_path("/tmp/ve-tls-base", "com.example.app:worker", rewritten, 6);
    if (rc != VE_TLS_INVALID) {
        fprintf(stderr, "small rewrite buffer should fail\n");
        return 1;
    }

    if (runtime.destroy_wait_ms != in.destroy_wait_ms) {
        fprintf(stderr, "unexpected destroy_wait_ms=%d want %d\n", runtime.destroy_wait_ms, in.destroy_wait_ms);
        return 1;
    }
    if (runtime.destroy_flusher_wait_ms != 0 || runtime.destroy_sender_wait_ms != 0 || runtime.destroy_wait_split_enabled != 0) {
        fprintf(stderr, "legacy destroy wait should not enable split mode\n");
        return 1;
    }

    return 0;
}

static int test_android_binding_build_config_runtime_defaults_without_memset(void) {
    ve_tls_android_config_view in;
    ve_tls_android_runtime_options runtime;
    ve_tls_config out;
    ve_tls_result rc;

    memset(&in, 0, sizeof(in));

    in.compress_type = VE_TLS_ANDROID_COMPRESS_LZ4;
    in.send_thread_count = 3;
    in.use_persistent = 1;
    in.destroy_wait_ms = 15000;

    rc = ve_tls_android_binding_build_config(&in, &out, &runtime);
    if (rc != VE_TLS_OK) {
        fprintf(stderr, "build_config failed when runtime is not pre-cleared: %d\n", rc);
        return 1;
    }
    if (!runtime.persistent_enabled) {
        fprintf(stderr, "runtime.persistent_enabled should mirror in.use_persistent when runtime is not zeroed\n");
        return 1;
    }
    if (runtime.recover != ve_tls_producer_recover) {
        fprintf(stderr, "runtime.recover should default to ve_tls_producer_recover for persistent mode\n");
        return 1;
    }
    if (runtime.close != ve_tls_producer_close) {
        fprintf(stderr, "runtime.close should default to ve_tls_producer_close\n");
        return 1;
    }
    if (runtime.close_split != ve_tls_producer_close_split) {
        fprintf(stderr, "runtime.close_split should default to ve_tls_producer_close_split\n");
        return 1;
    }
    if (runtime.destroy != ve_tls_producer_destroy) {
        fprintf(stderr, "runtime.destroy should default to ve_tls_producer_destroy\n");
        return 1;
    }

    in.use_persistent = 0;
    rc = ve_tls_android_binding_build_config(&in, &out, &runtime);
    if (rc != VE_TLS_OK) {
        fprintf(stderr, "build_config failed for non-persistent mode: %d\n", rc);
        return 1;
    }
    if (runtime.persistent_enabled != 0) {
        fprintf(stderr, "runtime.persistent_enabled should be false in non-persistent mode\n");
        return 1;
    }
    if (runtime.recover != NULL) {
        fprintf(stderr, "runtime.recover should be null when persistence disabled\n");
        return 1;
    }

    return 0;
}

static int run_android_binding_recover_and_destroy_sequence_probe(void) {
    char dir_template[] = "/tmp/ve_tls_android_binding_XXXXXX";
    if (!mkdtemp(dir_template)) {
        fprintf(stderr, "mkdtemp failed\n");
        return 1;
    }

    ve_tls_android_config_view in;
    ve_tls_android_runtime_options runtime;
    ve_tls_config out_cfg;
    ve_tls_config cfg;
    ve_tls_producer * producer;

    memset(&in, 0, sizeof(in));
    in.compress_type = VE_TLS_ANDROID_COMPRESS_NONE;
    in.send_thread_count = 1;
    in.use_persistent = 1;
    in.destroy_wait_ms = 1000;
    in.endpoint = "https://example.com";
    in.region = "cn-hangzhou";
    in.project_id = "test_project";
    in.topic_id = "test_topic";
    in.access_key_id = "ak";
    in.access_key_secret = "sk";

    if (ve_tls_android_binding_build_config(&in, &out_cfg, &runtime) != VE_TLS_OK) {
        fprintf(stderr, "build_config persistent failed\n");
        return 1;
    }
    runtime.recover = test_record_recover;
    runtime.close = test_record_close;
    runtime.destroy = test_record_destroy;

    ve_tls_config_init(&cfg);
    cfg.endpoint = in.endpoint;
    cfg.region = in.region;
    cfg.project_id = in.project_id;
    cfg.topic_id = in.topic_id;
    cfg.access_key_id = in.access_key_id;
    cfg.access_key_secret = in.access_key_secret;
    cfg.use_persistent = in.use_persistent;
    cfg.persistent_file_path = dir_template;
    cfg.max_persistent_log_count = 16;
    cfg.max_persistent_file_size = 1024;
    cfg.max_persistent_file_count = 4;
    cfg.send_thread_count = 1;
    cfg.compress_type = out_cfg.compress_type;

    producer = ve_tls_producer_create(&cfg);
    if (!producer) {
        fprintf(stderr, "producer_create persistent failed\n");
        return 1;
    }
    reset_runtime_events();
    if (ve_tls_android_binding_after_create(producer, &runtime) != VE_TLS_OK) {
        fprintf(stderr, "after_create persistent did not return OK\n");
        ve_tls_android_binding_before_destroy(producer, &runtime);
        return 1;
    }
    if (g_recover_calls != 1 || g_events[0] != 1) {
        fprintf(stderr, "persistent after_create should call recover\n");
        ve_tls_android_binding_before_destroy(producer, &runtime);
        return 1;
    }

    reset_runtime_events();
    ve_tls_android_binding_before_destroy(producer, &runtime);
    if (g_event_count != 2 || g_events[0] != 2 || g_events[1] != 3) {
        fprintf(stderr, "close should be called before destroy when persistent\n");
        return 1;
    }

    memset(&in, 0, sizeof(in));
    in.compress_type = VE_TLS_ANDROID_COMPRESS_NONE;
    in.send_thread_count = 1;
    in.use_persistent = 0;
    in.destroy_wait_ms = 1000;
    in.endpoint = "https://example.com";
    in.region = "cn-hangzhou";
    in.project_id = "test_project";
    in.topic_id = "test_topic";
    in.access_key_id = "ak";
    in.access_key_secret = "sk";

    if (ve_tls_android_binding_build_config(&in, &out_cfg, &runtime) != VE_TLS_OK) {
        fprintf(stderr, "build_config nonpersistent failed\n");
        return 1;
    }
    runtime.recover = test_record_recover;
    runtime.close = test_record_close;
    runtime.destroy = test_record_destroy;

    memset(&cfg, 0, sizeof(cfg));
    ve_tls_config_init(&cfg);
    cfg.endpoint = in.endpoint;
    cfg.region = in.region;
    cfg.project_id = in.project_id;
    cfg.topic_id = in.topic_id;
    cfg.access_key_id = in.access_key_id;
    cfg.access_key_secret = in.access_key_secret;
    cfg.send_thread_count = 1;
    cfg.use_persistent = in.use_persistent;
    cfg.compress_type = "none";
    producer = ve_tls_producer_create(&cfg);
    if (!producer) {
        fprintf(stderr, "producer_create nonpersistent failed\n");
        return 1;
    }
    reset_runtime_events();
    if (ve_tls_android_binding_after_create(producer, &runtime) != VE_TLS_OK) {
        fprintf(stderr, "after_create nonpersistent did not return OK\n");
        ve_tls_android_binding_before_destroy(producer, &runtime);
        return 1;
    }
    if (g_recover_calls != 0) {
        fprintf(stderr, "nonpersistent after_create should not call recover\n");
        ve_tls_android_binding_before_destroy(producer, &runtime);
        return 1;
    }

    reset_runtime_events();
    ve_tls_android_binding_before_destroy(producer, &runtime);
    if (g_event_count != 2 || g_events[0] != 2 || g_events[1] != 3) {
        fprintf(stderr, "close should be called before destroy when nonpersistent\n");
        return 1;
    }

    return 0;
}

static int test_android_binding_before_destroy_prefers_split_close(void) {
    ve_tls_android_runtime_options runtime;

    memset(&runtime, 0, sizeof(runtime));
    runtime.destroy_wait_ms = 7;
    runtime.destroy_flusher_wait_ms = 11;
    runtime.destroy_sender_wait_ms = 13;
    runtime.destroy_wait_split_enabled = 1;
    runtime.close = test_record_close;
    runtime.close_split = test_record_close_split;
    runtime.destroy = test_record_destroy;

    reset_runtime_events();
    ve_tls_android_binding_before_destroy((ve_tls_producer *)0x1, &runtime);

    if (g_close_calls != 0 || g_close_split_calls != 1 || g_destroy_calls != 1) {
        fprintf(stderr, "split destroy should call close_split once and destroy once\n");
        return 1;
    }
    if (g_last_close_flusher_wait_ms != 11 || g_last_close_sender_wait_ms != 13) {
        fprintf(stderr, "split destroy used wrong waits: flusher=%d sender=%d\n", g_last_close_flusher_wait_ms, g_last_close_sender_wait_ms);
        return 1;
    }
    if (g_event_count != 2 || g_events[0] != 4 || g_events[1] != 3) {
        fprintf(stderr, "split destroy should close_split before destroy\n");
        return 1;
    }
    return 0;
}

static int test_android_binding_recover_and_destroy_sequence(void) {
    pid_t child = fork();
    if (child < 0) {
        fprintf(stderr, "fork failed\n");
        return 1;
    }
    if (child == 0) {
        _exit(run_android_binding_recover_and_destroy_sequence_probe());
    }

    int status = 0;
    if (waitpid(child, &status, 0) != child) {
        fprintf(stderr, "waitpid failed\n");
        return 1;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "recover/destroy sequence probe failed or crashed\n");
        return 1;
    }
    return 0;
}

int main(void) {
    if (test_android_binding_build_persistent_path_and_clamps_sender() != 0) {
        return 1;
    }
    if (test_android_binding_build_config_preserves_http_client_bridge() != 0) {
        return 1;
    }
    if (test_android_binding_build_config_runtime_defaults_without_memset() != 0) {
        return 1;
    }
    if (test_android_binding_before_destroy_prefers_split_close() != 0) {
        return 1;
    }
    if (test_android_binding_recover_and_destroy_sequence() != 0) {
        return 1;
    }
    return 0;
}
