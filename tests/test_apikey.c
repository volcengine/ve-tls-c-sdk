#include "ve_tls_producer.h"
#include "ve_tls_env.h"
#include "ve_tls_alloc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>

/* These tests run the real batching/sending threads against an in-process HTTP
 * adapter. No service credentials or network access are required. */
typedef struct {
    ve_tls_platform platform;
    ve_tls_mutex * mutex;
    ve_tls_cond * cond;
    ve_tls_producer * producer;
    int requests;
    int callbacks;
    int successes;
    int bad_wire;
    int provider_calls;
    int block_first;
    int release_first;
    int fail_first;
    int rotate_in_request;
    int saw_first_key;
    int saw_second_key;
    int saw_signed;
    int saw_token;
    int auth_failure_events;
    int api_key_update_events;
    int diagnostic_events;
    int diagnostic_terminal_successes;
    int diagnostic_metadata_valid;
} capture;

static int header_value(const char * headers, const char * key, char * out, size_t cap) {
    size_t key_len = strlen(key);
    int found = 0;
    if (cap) out[0] = 0;
    for (const char * line = headers; line && *line;) {
        const char * end = strchr(line, '\n');
        if (!end) end = line + strlen(line);
        if ((size_t)(end - line) > key_len &&
            memcmp(line, key, key_len) == 0 && line[key_len] == ':') {
            const char * value = line + key_len + 1;
            while (value < end && (*value == ' ' || *value == '\t')) value++;
            size_t len = (size_t)(end - value);
            if (len && value[len - 1] == '\r') len--;
            if (len >= cap) return -1;
            memcpy(out, value, len);
            out[len] = 0;
            found++;
        }
        line = *end ? end + 1 : end;
    }
    return found;
}

static int http_capture(ve_tls_http_client * client, const ve_tls_http_request * req,
                        ve_tls_http_response * resp) {
    capture * c = client->user_data;
    char key[128], auth[1024], token[128], value[128];
    int anonymous = header_value(req->headers, "x-tls-anonymous-identity", key, sizeof(key));
    int signed_request = header_value(req->headers, "Authorization", auth, sizeof(auth));
    int has_token = header_value(req->headers, "X-Security-Token", token, sizeof(token));
    int bad = !req->method || strcmp(req->method, "POST") || !req->url ||
        strcmp(req->url, "https://example.com/PutLogs?TopicId=topic") ||
        !req->body || req->body_size == 0;
    bad |= header_value(req->headers, "Content-Type", value, sizeof(value)) != 1 ||
           strcmp(value, "application/x-protobuf") != 0;
    bad |= header_value(req->headers, "Content-MD5", value, sizeof(value)) != 1 || strlen(value) != 32;
    bad |= header_value(req->headers, "x-tls-bodyrawsize", value, sizeof(value)) != 1;
    bad |= header_value(req->headers, "x-tls-compresstype", value, sizeof(value)) != 1 ||
           strcmp(value, "none") != 0;
    bad |= header_value(req->headers, "x-tls-apiversion", value, sizeof(value)) != 1;
    bad |= header_value(req->headers, "log-count", value, sizeof(value)) != 1;
    if (anonymous) {
        bad |= anonymous != 1 || signed_request != 0 || has_token != 0 || req->debug_log != 0;
        bad |= header_value(req->headers, "X-Date", value, sizeof(value)) != 0;
        bad |= header_value(req->headers, "X-Content-Sha256", value, sizeof(value)) != 0;
        bad |= strcmp(key, "test-key-one") != 0 && strcmp(key, "test-key-two") != 0;
    } else {
        bad |= signed_request != 1 || strstr(auth, "HMAC-SHA256 Credential=ak/") == NULL;
    }

    c->platform.mutex_lock(c->mutex);
    int index = ++c->requests;
    c->bad_wire += !!bad;
    c->saw_first_key += anonymous == 1 && strcmp(key, "test-key-one") == 0;
    c->saw_second_key += anonymous == 1 && strcmp(key, "test-key-two") == 0;
    c->saw_signed += signed_request == 1;
    c->saw_token += has_token == 1 && strcmp(token, "test-sts") == 0;
    c->platform.cond_broadcast(c->cond);
    while (index == 1 && c->block_first && !c->release_first) {
        c->platform.cond_wait(c->cond, c->mutex);
    }
    int rotate = index == 1 && c->rotate_in_request;
    int status = index == 1 && c->fail_first ? c->fail_first : 200;
    c->platform.mutex_unlock(c->mutex);

    if (rotate && ve_tls_producer_update_api_key(c->producer, "test-key-two") != VE_TLS_OK) {
        c->platform.mutex_lock(c->mutex);
        c->bad_wire++;
        c->platform.mutex_unlock(c->mutex);
    }
    /* Re-read the borrowed request after concurrent mutation: its key must
     * remain intact until the adapter returns. */
    char after[128];
    if (header_value(req->headers, "x-tls-anonymous-identity", after, sizeof(after)) != anonymous ||
        (anonymous == 1 && strcmp(key, after) != 0)) {
        c->platform.mutex_lock(c->mutex);
        c->bad_wire++;
        c->platform.mutex_unlock(c->mutex);
    }
    resp->status_code = status;
    return 0;
}

static void http_free(ve_tls_http_client * client, ve_tls_http_response * resp) {
    (void)client;
    (void)resp;
}

static void send_done(ve_tls_result result, size_t bytes, size_t compressed,
                      const char * req_id, const char * error, const unsigned char * raw,
                      void * user, int64_t start, int64_t end) {
    (void)bytes; (void)compressed; (void)req_id; (void)error; (void)raw; (void)start; (void)end;
    capture * c = user;
    c->platform.mutex_lock(c->mutex);
    c->callbacks++;
    c->successes += result == VE_TLS_OK;
    c->platform.cond_broadcast(c->cond);
    c->platform.mutex_unlock(c->mutex);
}

static void delivery_diagnostic(const ve_tls_delivery_diagnostic * event, void * user) {
    capture * c = user;
    if (!c || !event) return;
    c->platform.mutex_lock(c->mutex);
    c->diagnostic_events++;
    if (event->event == VE_TLS_DELIVERY_DIAGNOSTIC_BATCH_TERMINAL &&
        event->reason == VE_TLS_DELIVERY_DIAGNOSTIC_REASON_SUCCESS) {
        c->diagnostic_terminal_successes++;
    }
    if (event->metadata_version == VE_TLS_DELIVERY_DIAGNOSTIC_METADATA_VERSION_1 &&
        event->metadata_size == sizeof(*event)) {
        c->diagnostic_metadata_valid = 1;
    }
    c->platform.cond_broadcast(c->cond);
    c->platform.mutex_unlock(c->mutex);
}

static void metrics_emit(const char * name, int64_t v1, int64_t v2, void * user) {
    (void)v1;
    capture * c = user;
    if (!c || !name) return;
    c->platform.mutex_lock(c->mutex);
    if (strcmp(name, "send_failed") == 0 && v2 == 401) {
        c->auth_failure_events++;
    } else if (strcmp(name, "config_update_api_key") == 0) {
        c->api_key_update_events++;
    }
    c->platform.cond_broadcast(c->cond);
    c->platform.mutex_unlock(c->mutex);
}

static int provider(ve_tls_credentials * credentials, void * user) {
    capture * c = user;
    c->platform.mutex_lock(c->mutex);
    c->provider_calls++;
    c->platform.mutex_unlock(c->mutex);
    credentials->access_key_id = "ak";
    credentials->access_key_secret = "sk";
    credentials->security_token = "test-sts";
    return 0;
}

static int setup(capture * c, ve_tls_config * cfg, int global, int ordered) {
    memset(c, 0, sizeof(*c));
    memset(cfg, 0, sizeof(*cfg));
    if (ve_tls_config_init_versioned(cfg, sizeof(*cfg), VE_TLS_CONFIG_VERSION_CURRENT) != VE_TLS_OK) return -1;
    cfg->endpoint = "https://example.com";
    cfg->region = "cn-beijing";
    cfg->topic_id = "topic";
    cfg->compress_type = "none";
    cfg->send_thread_count = 1;
    cfg->pack_thread_count = 1;
    cfg->flush_interval_ms = 1;
    cfg->log_count_per_package = 1;
    cfg->use_global_env = global;
    cfg->ordered_send = ordered;
    cfg->retry_policy.max_attempts = 2;
    cfg->retry_policy.initial_interval_ms = 1;
    cfg->retry_policy.max_interval_ms = 2;
    cfg->retry_policy.randomization_factor = 0;
    cfg->http_client.do_request = http_capture;
    cfg->http_client.free_response = http_free;
    cfg->http_client.user_data = c;
    c->platform = cfg->platform;
    c->mutex = c->platform.mutex_create();
    c->cond = c->platform.cond_create();
    if (global && ve_tls_env_init(1) != VE_TLS_OK) return -1;
    cfg->metrics_sink.emit = metrics_emit;
    cfg->metrics_sink.user_param = c;
    return c->mutex && c->cond ? 0 : -1;
}

static int wait_count(capture * c, int requests, int callbacks) {
    int64_t deadline = c->platform.time_ms() + 5000;
    c->platform.mutex_lock(c->mutex);
    while (c->requests < requests || c->callbacks < callbacks) {
        int64_t remaining = deadline - c->platform.time_ms();
        if (remaining <= 0) break;
        c->platform.cond_timedwait_ms(c->cond, c->mutex, remaining);
    }
    int ok = c->requests >= requests && c->callbacks >= callbacks;
    c->platform.mutex_unlock(c->mutex);
    return ok ? 0 : -1;
}

static int wait_diagnostics(capture * c, int diagnostics) {
    int64_t deadline = c->platform.time_ms() + 5000;
    c->platform.mutex_lock(c->mutex);
    while (c->diagnostic_events < diagnostics) {
        int64_t remaining = deadline - c->platform.time_ms();
        if (remaining <= 0) break;
        c->platform.cond_timedwait_ms(c->cond, c->mutex, remaining);
    }
    int ok = c->diagnostic_events >= diagnostics;
    c->platform.mutex_unlock(c->mutex);
    return ok ? 0 : -1;
}

static void release_request(capture * c) {
    c->platform.mutex_lock(c->mutex);
    c->release_first = 1;
    c->platform.cond_broadcast(c->cond);
    c->platform.mutex_unlock(c->mutex);
}

static int wait_auth_failure(capture * c, ve_tls_producer * producer) {
    int64_t deadline = c->platform.time_ms() + 5000;
    int64_t stable_since = 0;
    for (;;) {
        ve_tls_metrics metrics;
        memset(&metrics, 0, sizeof(metrics));
        ve_tls_producer_get_metrics(producer, &metrics);
        c->platform.mutex_lock(c->mutex);
        int observed = c->auth_failure_events > 0 && c->callbacks == 0 &&
            c->requests == 1 && metrics.requests_total == 1 &&
            metrics.requests_failed_total >= 1;
        c->platform.mutex_unlock(c->mutex);
        if (observed) {
            int64_t now = c->platform.time_ms();
            if (stable_since == 0) stable_since = now;
            /* Public API has no retained-waiter count/event. Keep the public
             * 401 failure observation stable for one scheduler tick before
             * rotating; this bounds, but cannot prove, the internal handoff. */
            if (now - stable_since >= 10) return 0;
        } else {
            stable_since = 0;
        }
        if (c->platform.time_ms() >= deadline) return -1;
        c->platform.sleep_ms(1);
    }
}

static void reset_capture(capture * c, ve_tls_producer * producer) {
    c->platform.mutex_lock(c->mutex);
    c->producer = producer;
    c->requests = 0;
    c->callbacks = 0;
    c->successes = 0;
    c->bad_wire = 0;
    c->provider_calls = 0;
    c->block_first = 0;
    c->release_first = 0;
    c->fail_first = 0;
    c->rotate_in_request = 0;
    c->saw_first_key = 0;
    c->saw_second_key = 0;
    c->saw_signed = 0;
    c->saw_token = 0;
    c->auth_failure_events = 0;
    c->api_key_update_events = 0;
    c->diagnostic_events = 0;
    c->diagnostic_terminal_successes = 0;
    c->diagnostic_metadata_valid = 0;
    c->platform.mutex_unlock(c->mutex);
}

static void cleanup(capture * c) {
    release_request(c);
    if (c->producer) {
        ve_tls_producer_close(c->producer, 5000);
        ve_tls_producer_destroy(c->producer);
    }
    c->platform.cond_destroy(c->cond);
    c->platform.mutex_destroy(c->mutex);
}

static int add(capture * c) {
    ve_tls_kv kv = {"message", "api-key contract"};
    return ve_tls_producer_add_log_kv(c->producer, c->platform.time_ms(), &kv, 1, 1) == VE_TLS_OK ? 0 : -1;
}

#define CHECK(expression) do { if (!(expression)) { \
    fprintf(stderr, "%s:%d: %s\n", __func__, __LINE__, #expression); rc = -1; goto done; \
} } while (0)

static int test_auth_modes(int global, int ordered, int credentials) {
    capture c;
    ve_tls_config cfg;
    if (setup(&c, &cfg, global, ordered) != 0) return -1;
    int rc = 0;
    if (credentials == 1) {
        cfg.access_key_id = "ak";
        cfg.access_key_secret = "sk";
        cfg.security_token = "test-sts";
    } else if (credentials == 2) {
        cfg.credentials_provider = provider;
        cfg.credentials_provider_param = &c;
    }
    cfg.http_debug = 1;
    char initial[] = "test-key-one";
    c.producer = ve_tls_producer_create_with_api_key(&cfg, initial);
    memset(initial, 'x', sizeof(initial) - 1);
    CHECK(c.producer != NULL);
    ve_tls_producer_set_send_done(c.producer, send_done, &c);
    CHECK(add(&c) == 0 && wait_count(&c, 1, 1) == 0);
    CHECK(c.saw_first_key == 1 && c.saw_signed == 0 && c.provider_calls == 0 && c.bad_wire == 0);
    char next[] = "test-key-two";
    CHECK(ve_tls_producer_update_api_key(c.producer, next) == VE_TLS_OK);
    memset(next, 'x', sizeof(next) - 1);
    CHECK(add(&c) == 0 && wait_count(&c, 2, 2) == 0);
    CHECK(c.saw_second_key == 1 && c.provider_calls == 0 && c.bad_wire == 0);
    CHECK(ve_tls_producer_update_api_key(c.producer, credentials == 1 ? NULL : "") == VE_TLS_OK);
    CHECK(add(&c) == 0 && wait_count(&c, 2, 3) == 0);
    if (credentials) {
        CHECK(c.requests == 3 && c.saw_signed == 1 && c.saw_token == 1 && c.successes == 3);
        CHECK(c.provider_calls == (credentials == 2 ? 1 : 0));
    } else {
        CHECK(c.requests == 2 && c.successes == 2);
    }
    CHECK(ve_tls_producer_update_api_key(c.producer, "test-key-two") == VE_TLS_OK);
    CHECK(add(&c) == 0 && wait_count(&c, credentials ? 4 : 3, 4) == 0);
    CHECK(c.bad_wire == 0);
    CHECK(ve_tls_producer_close(c.producer, 5000) == VE_TLS_OK);
    CHECK(ve_tls_producer_update_api_key(c.producer, "test-key-one") == VE_TLS_CLOSED);
done:
    cleanup(&c);
    if (global && ve_tls_env_destroy(5000) != VE_TLS_OK) rc = -1;
    return rc;
}

static int test_rotation_during_request(int global, int ordered, int retry) {
    capture c;
    ve_tls_config cfg;
    if (setup(&c, &cfg, global, ordered) != 0) return -1;
    int rc = 0;
    c.block_first = 1;
    c.fail_first = retry ? 500 : 0;
    c.producer = ve_tls_producer_create_with_api_key(&cfg, "test-key-one");
    CHECK(c.producer != NULL);
    ve_tls_producer_set_send_done(c.producer, send_done, &c);
    CHECK(add(&c) == 0 && wait_count(&c, 1, 0) == 0);
    for (int i = 0; i < 32; ++i) {
        CHECK(ve_tls_producer_update_api_key(c.producer, (i & 1) ? "test-key-two" : "test-key-one") == VE_TLS_OK);
    }
    release_request(&c);
    CHECK(wait_count(&c, retry ? 2 : 1, 1) == 0);
    if (!retry) CHECK(add(&c) == 0 && wait_count(&c, 2, 2) == 0);
    CHECK(c.saw_first_key == 1 && c.saw_second_key == 1 && c.bad_wire == 0);
done:
    cleanup(&c);
    if (global && ve_tls_env_destroy(5000) != VE_TLS_OK) rc = -1;
    return rc;
}

static int test_validation_and_legacy(void) {
    capture c;
    ve_tls_config cfg;
    if (setup(&c, &cfg, 0, 0) != 0) return -1;
    int rc = 0;
    CHECK(ve_tls_producer_create_with_api_key(NULL, "test-key-one") == NULL);
    CHECK(ve_tls_producer_update_api_key(NULL, "test-key-one") == VE_TLS_INVALID);
    CHECK(ve_tls_producer_create(&cfg) == NULL);
    CHECK(ve_tls_producer_create_with_api_key(&cfg, NULL) == NULL);
    CHECK(ve_tls_producer_create_with_api_key(&cfg, "") == NULL);
    const char * invalid[] = {"bad\rkey", "bad\nInjected: header", "bad\tkey", "bad\177key"};
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++)
        CHECK(ve_tls_producer_create_with_api_key(&cfg, invalid[i]) == NULL);
    void * legacy_config = malloc(VE_TLS_CONFIG_LEGACY_SIZE);
    CHECK(legacy_config != NULL);
    memcpy(legacy_config, &cfg, VE_TLS_CONFIG_LEGACY_SIZE);
    c.producer = ve_tls_producer_create_with_api_key(legacy_config, "test-key-one");
    free(legacy_config);
    CHECK(c.producer != NULL);
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++)
        CHECK(ve_tls_producer_update_api_key(c.producer, invalid[i]) == VE_TLS_INVALID);
    ve_tls_producer_set_send_done(c.producer, send_done, &c);
    CHECK(add(&c) == 0 && wait_count(&c, 1, 1) == 0);
    CHECK(c.saw_first_key == 1 && c.bad_wire == 0);
    CHECK(ve_tls_producer_close(c.producer, 5000) == VE_TLS_OK);
    ve_tls_producer_destroy(c.producer);
    c.producer = NULL;
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.security_token = "test-sts";
    c.producer = ve_tls_producer_create(&cfg);
    CHECK(c.producer != NULL);
    ve_tls_producer_set_send_done(c.producer, send_done, &c);
    CHECK(add(&c) == 0 && wait_count(&c, 2, 2) == 0);
    CHECK(c.saw_signed == 1 && c.saw_token == 1 && c.bad_wire == 0);
done:
    cleanup(&c);
    return rc;
}

static int wal_contains(const char * directory, const char * needle) {
    DIR * dir = opendir(directory);
    if (!dir) return -1;
    if (!needle || needle[0] == '\0' || strlen(needle) >= 64) {
        closedir(dir);
        return -1;
    }
    int found = 0;
    struct dirent * entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
        char file[1024];
        if (snprintf(file, sizeof(file), "%s/%s", directory, entry->d_name) >= (int)sizeof(file)) {
            closedir(dir);
            return -1;
        }
        FILE * stream = fopen(file, "rb");
        if (stream) {
            char window[64];
            size_t needle_len = strlen(needle);
            size_t used = 0;
            int ch;
            while ((ch = fgetc(stream)) != EOF) {
                if (used < needle_len) {
                    window[used++] = (char)ch;
                } else {
                    memmove(window, window + 1, needle_len - 1);
                    window[needle_len - 1] = (char)ch;
                }
                if (used == needle_len && memcmp(window, needle, needle_len) == 0) {
                    found = 1;
                    break;
                }
            }
            fclose(stream);
        } else {
            closedir(dir);
            return -1;
        }
        if (found) break;
    }
    closedir(dir);
    return found;
}

static int wal_has_segment(const char * directory) {
    DIR * dir = opendir(directory);
    if (!dir) return -1;
    int found = 0;
    struct dirent * entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strncmp(entry->d_name, "seg-", 4) == 0) {
            found = 1;
            break;
        }
    }
    closedir(dir);
    return found;
}

static int inspect_and_remove_wal(const char * directory) {
    DIR * dir = opendir(directory);
    if (!dir) return -1;
    int rc = wal_contains(directory, "test-key-") != 0 ? -1 : 0;
    struct dirent * entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
        char file[1024];
        if (snprintf(file, sizeof(file), "%s/%s", directory, entry->d_name) >= (int)sizeof(file)) {
            rc = -1;
            continue;
        }
        if (unlink(file) != 0) rc = -1;
    }
    closedir(dir);
    if (rmdir(directory) != 0) rc = -1;
    return rc;
}

static int test_persistent_rotation(int global, int ordered, int dynamic, int rotate_before_response) {
    capture c;
    ve_tls_config cfg;
    char directory[] = "/tmp/ve-tls-apikey-wal-XXXXXX";
    if (!mkdtemp(directory)) return -1;
    if (setup(&c, &cfg, global, ordered) != 0) return -1;
    int rc = 0;
    cfg.use_persistent = 1;
    cfg.persistent_file_path = directory;
    cfg.max_persistent_log_count = 64;
    cfg.max_persistent_file_size = 1024 * 1024;
    cfg.max_persistent_file_count = 4;
    if (dynamic) {
        cfg.credentials_provider = provider;
        cfg.credentials_provider_param = &c;
    }
    c.fail_first = 401;
    c.rotate_in_request = rotate_before_response;
    c.producer = ve_tls_producer_create_with_api_key_versioned(
        &cfg, VE_TLS_CONFIG_VERSION_3_SIZE, VE_TLS_CONFIG_VERSION_CURRENT, "test-key-one");
    CHECK(c.producer != NULL);
    ve_tls_producer_set_send_done(c.producer, send_done, &c);
    CHECK(add(&c) == 0 && wait_count(&c, 1, 0) == 0);
    if (!rotate_before_response) {
        /* There is no public retained-waiter count. Use the public 401 metric
         * and stable producer stats as the smallest observable handoff point
         * before rotating, instead of updating immediately after request #1. */
        CHECK(wait_auth_failure(&c, c.producer) == 0);
        CHECK(c.api_key_update_events == 0);
        CHECK(ve_tls_producer_update_api_key(c.producer, "test-key-two") == VE_TLS_OK);
    }
    CHECK(wait_count(&c, 2, 1) == 0);
    CHECK(c.saw_first_key == 1 && c.saw_second_key == 1 && c.successes == 1);
    CHECK(c.provider_calls == 0 && c.bad_wire == 0 && c.api_key_update_events >= 1);
done:
    cleanup(&c);
    if (global && ve_tls_env_destroy(5000) != VE_TLS_OK) rc = -1;
    if (inspect_and_remove_wal(directory) != 0) rc = -1;
    return rc;
}

static int test_persistent_reopen(int global, int ordered, int dynamic) {
    capture c;
    ve_tls_config cfg;
    char directory[] = "/tmp/ve-tls-apikey-reopen-XXXXXX";
    if (!mkdtemp(directory)) return -1;
    if (setup(&c, &cfg, global, ordered) != 0) {
        (void)inspect_and_remove_wal(directory);
        return -1;
    }
    int rc = 0;
    cfg.use_persistent = 1;
    cfg.persistent_file_path = directory;
    cfg.max_persistent_log_count = 64;
    cfg.max_persistent_file_size = 1024 * 1024;
    cfg.max_persistent_file_count = 4;
    if (dynamic) {
        cfg.credentials_provider = provider;
        cfg.credentials_provider_param = &c;
    }

    c.fail_first = 401;
    c.producer = ve_tls_producer_create_with_api_key_versioned(
        &cfg, VE_TLS_CONFIG_VERSION_3_SIZE, VE_TLS_CONFIG_VERSION_CURRENT, "test-key-one");
    CHECK(c.producer != NULL);
    ve_tls_producer_set_send_done(c.producer, send_done, &c);
    CHECK(add(&c) == 0 && wait_count(&c, 1, 0) == 0);
    CHECK(wait_auth_failure(&c, c.producer) == 0);
    CHECK(c.callbacks == 0 && c.successes == 0 && c.provider_calls == 0);

    CHECK(ve_tls_producer_close(c.producer, 5000) == VE_TLS_OK);
    ve_tls_producer_destroy(c.producer);
    c.producer = NULL;
    /* This is the restart boundary: the unacked segment must still exist,
     * while the API key is request metadata and must not be WAL plaintext. */
    CHECK(wal_has_segment(directory) == 1);
    CHECK(wal_contains(directory, "test-key-one") == 0);

    reset_capture(&c, NULL);
    c.producer = ve_tls_producer_create_with_api_key_versioned(
        &cfg, VE_TLS_CONFIG_VERSION_3_SIZE, VE_TLS_CONFIG_VERSION_CURRENT, "test-key-two");
    CHECK(c.producer != NULL);
    ve_tls_producer_set_send_done(c.producer, send_done, &c);
    CHECK(ve_tls_producer_recover(c.producer) == VE_TLS_OK);
    /* Do not require the callback as the recovery proof: a future create path
     * may start replay before a callback is installed. The public request
     * stats and captured request headers are the recovery evidence. */
    CHECK(wait_count(&c, 1, 0) == 0);
    CHECK(ve_tls_producer_close(c.producer, 5000) == VE_TLS_OK);
    ve_tls_metrics metrics;
    memset(&metrics, 0, sizeof(metrics));
    ve_tls_producer_get_metrics(c.producer, &metrics);
    CHECK(metrics.requests_total == 1 && metrics.requests_failed_total == 0);
    CHECK(c.saw_first_key == 0 && c.saw_second_key == 1 && c.bad_wire == 0);
    CHECK(c.provider_calls == 0);
    ve_tls_producer_destroy(c.producer);
    c.producer = NULL;
    CHECK(wal_contains(directory, "test-key-one") == 0);
done:
    cleanup(&c);
    if (global && ve_tls_env_destroy(5000) != VE_TLS_OK) rc = -1;
    if (inspect_and_remove_wal(directory) != 0) rc = -1;
    return rc;
}

static int test_versioned_creation(void) {
    capture c;
    ve_tls_config cfg;
    if (setup(&c, &cfg, 0, 0) != 0) return -1;
    int rc = 0;
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
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.security_token = "test-sts";
    cfg.memory_retry_retention_ms = 100;
    cfg.bound_request_timeout_to_retry_budget = 1;
    cfg.delivery_diagnostic = delivery_diagnostic;
    cfg.delivery_diagnostic_param = &c;
    cfg.retry_transient_http_errors = 1;
    CHECK(ve_tls_producer_create_versioned(NULL, sizes[2], versions[2]) == NULL);
    CHECK(ve_tls_producer_create_with_api_key_versioned(NULL, sizes[2], versions[2], "test-key-one") == NULL);
    for (size_t i = 0; i < sizeof(versions) / sizeof(versions[0]); i++) {
        CHECK(ve_tls_producer_create_versioned(&cfg, sizes[i] - 1, versions[i]) == NULL);
        CHECK(ve_tls_producer_create_with_api_key_versioned(
            &cfg, sizes[i] - 1, versions[i], "test-key-one") == NULL);
        CHECK(ve_tls_producer_create_versioned(&cfg, sizes[i], versions[i] + 10) == NULL);
        CHECK(ve_tls_producer_create_with_api_key_versioned(
            &cfg, sizes[i], versions[i] + 10, "test-key-one") == NULL);
    }
    CHECK(ve_tls_producer_create_versioned(&cfg, sizes[0], versions[1]) == NULL);
    CHECK(ve_tls_producer_create_with_api_key_versioned(
        &cfg, sizes[0], versions[1], "test-key-one") == NULL);
    CHECK(ve_tls_producer_create_versioned(&cfg, sizes[1], versions[2]) == NULL);
    CHECK(ve_tls_producer_create_with_api_key_versioned(
        &cfg, sizes[1], versions[2], "test-key-one") == NULL);
    for (int with_api_key = 0; with_api_key <= 1; with_api_key++) {
        for (size_t i = 0; i < sizeof(versions) / sizeof(versions[0]); i++) {
            uint32_t version = versions[i];
            size_t size = sizes[i];
            /* Exact-sized old config buffer: ASan will catch an over-read. */
            void * old_config = malloc(size);
            CHECK(old_config != NULL);
            memcpy(old_config, &cfg, size);
            int before_requests = c.requests;
            int before_callbacks = c.callbacks;
            int before_diagnostics = c.diagnostic_events;
            if (with_api_key) {
                c.producer = ve_tls_producer_create_with_api_key_versioned(
                    old_config, size, version, "test-key-one");
            } else {
                c.producer = ve_tls_producer_create_versioned(old_config, size, version);
            }
            free(old_config);
            CHECK(c.producer != NULL);
            ve_tls_producer_set_send_done(c.producer, send_done, &c);
            CHECK(add(&c) == 0 &&
                  wait_count(&c, before_requests + 1, before_callbacks + 1) == 0);
            if (version == VE_TLS_CONFIG_VERSION_3) {
                CHECK(wait_diagnostics(&c, before_diagnostics + 1) == 0);
            } else {
                CHECK(c.diagnostic_events == before_diagnostics);
            }
            CHECK(ve_tls_producer_close(c.producer, 5000) == VE_TLS_OK);
            ve_tls_producer_destroy(c.producer);
            c.producer = NULL;
        }
    }
    CHECK(c.saw_first_key == 3 && c.saw_signed == 3 && c.saw_token == 3);
    CHECK(c.diagnostic_terminal_successes >= 2 && c.diagnostic_metadata_valid == 1);
    CHECK(c.bad_wire == 0);
done:
    cleanup(&c);
    return rc;
}

static ve_tls_alloc_hooks saved_alloc;
static _Thread_local int fail_allocation_after = -1;
static _Thread_local int fail_key_copy;

static int fail_allocation(void) {
    if (fail_allocation_after < 0) return 0;
    if (fail_allocation_after-- == 0) return 1;
    return 0;
}

static void * fault_malloc(size_t size, void * user) {
    (void)user;
    return fail_allocation() ? NULL : saved_alloc.malloc_fn(size, saved_alloc.user_data);
}

static void * fault_calloc(size_t count, size_t size, void * user) {
    (void)user;
    return fail_allocation() ? NULL : saved_alloc.calloc_fn(count, size, saved_alloc.user_data);
}

static void * fault_realloc(void * ptr, size_t size, void * user) {
    (void)user;
    return fail_allocation() ? NULL : saved_alloc.realloc_fn(ptr, size, saved_alloc.user_data);
}

static char * fault_strdup(const char * value, void * user) {
    (void)user;
    if ((fail_key_copy && value && strcmp(value, "test-key-one") == 0) || fail_allocation())
        return NULL;
    return saved_alloc.strdup_fn(value, saved_alloc.user_data);
}

static int test_allocation_rollback(void) {
    capture c;
    ve_tls_config cfg;
    if (setup(&c, &cfg, 0, 0) != 0) return -1;
    int rc = 0, failures = 0, successes = 0;
    ve_tls_alloc_get_hooks(&saved_alloc);
    ve_tls_alloc_hooks faults = saved_alloc;
    faults.malloc_fn = fault_malloc;
    faults.calloc_fn = fault_calloc;
    faults.realloc_fn = fault_realloc;
    faults.strdup_fn = fault_strdup;
    ve_tls_alloc_set_hooks(&faults);
    fail_key_copy = 1;
    c.producer = ve_tls_producer_create_with_api_key(&cfg, "test-key-one");
    fail_key_copy = 0;
    CHECK(c.producer == NULL);
    c.producer = ve_tls_producer_create_with_api_key(&cfg, "test-key-one");
    CHECK(c.producer != NULL);
    ve_tls_producer_set_send_done(c.producer, send_done, &c);
    for (int after = 0; after < 48; after++) {
        CHECK(ve_tls_producer_update_api_key(c.producer, "test-key-one") == VE_TLS_OK);
        int old_count = c.saw_first_key;
        int new_count = c.saw_second_key;
        fail_allocation_after = after;
        ve_tls_result result = ve_tls_producer_update_api_key(c.producer, "test-key-two");
        fail_allocation_after = -1;
        CHECK(result == VE_TLS_OK || result == VE_TLS_DROP_ERROR);
        CHECK(add(&c) == 0 && wait_count(&c, after + 1, after + 1) == 0);
        if (result == VE_TLS_OK) {
            successes++;
            CHECK(c.saw_second_key == new_count + 1 && c.saw_first_key == old_count);
        } else {
            failures++;
            CHECK(c.saw_first_key == old_count + 1 && c.saw_second_key == new_count);
        }
        CHECK(c.bad_wire == 0);
    }
    CHECK(failures > 0 && successes > 0);
done:
    fail_key_copy = 0;
    fail_allocation_after = -1;
    cleanup(&c);
    ve_tls_alloc_set_hooks(&saved_alloc);
    return rc;
}

int main(void) {
    if (test_allocation_rollback() != 0) return 6;
    if (test_validation_and_legacy() != 0) return 1;
    for (int global = 0; global <= 1; global++) {
        for (int ordered = 0; ordered <= 1; ordered++) {
            for (int credentials = 0; credentials <= 2; credentials++) {
                if (test_auth_modes(global, ordered, credentials) != 0) return 2;
            }
            for (int retry = 0; retry <= 1; retry++) {
                if (test_rotation_during_request(global, ordered, retry) != 0) return 3;
            }
        }
    }
    if (test_versioned_creation() != 0) return 4;
    for (int global = 0; global <= 1; global++) {
        for (int ordered = 0; ordered <= 1; ordered++) {
            for (int dynamic = 0; dynamic <= 1; dynamic++) {
                for (int early = 0; early <= 1; early++) {
                    if (test_persistent_rotation(global, ordered, dynamic, early) != 0) return 5;
                }
            }
        }
    }
    for (int global = 0; global <= 1; global++) {
        for (int ordered = 0; ordered <= 1; ordered++) {
            for (int dynamic = 0; dynamic <= 1; dynamic++) {
                if (test_persistent_reopen(global, ordered, dynamic) != 0) return 7;
            }
        }
    }
    puts("apiKey/versioned contract: 47 scenarios passed");
    return 0;
}
