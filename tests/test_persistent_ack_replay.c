#include "ve_tls_producer.h"
#include "ve_tls_http.h"
#include "producer/ve_tls_checkpoint.h"
#include "producer/ve_tls_persistent.h"
#include "ve_tls_alloc.h"

#include <dirent.h>
#include <limits.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* Run the real Producer/WAL/sender; mock HTTP counts actual payload markers. */
static const char * const markers[] = {
    "tls-replay-regression-A-record", "tls-replay-regression-B-record",
    "tls-replay-regression-C-record", "tls-replay-regression-D-record"
};
static const char * const hash_keys[] = {
    "00000000000000000000000000000001", "00000000000000000000000000000002",
    "00000000000000000000000000000003", "00000000000000000000000000000004"
};
enum { A = 0, B = 1, C = 2, D = 3, NMARKERS = 4, MAX_TEST_ID = 32 };

typedef struct {
    _Atomic int hits[NMARKERS];
    _Atomic int ok[MAX_TEST_ID];
    _Atomic int failed[MAX_TEST_ID];
    _Atomic int calls;
    _Atomic int bad_payload;
    _Atomic int block_entered;
    _Atomic int release_block;
    _Atomic int block_timeout;
    unsigned fail_mask;
    int block_a;
} mock_state;

#define REQUIRE(expr) do { \
    if (!(expr)) { \
        fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #expr); \
        failed = 1; goto cleanup; \
    } \
} while (0)

static int64_t monotonic_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void sleep_ms(int ms) {
    struct timespec delay = {ms / 1000, (long)(ms % 1000) * 1000000L};
    nanosleep(&delay, NULL);
}

static int wait_value(_Atomic int * value, int expected, int timeout_ms) {
    int64_t deadline = monotonic_ms() + timeout_ms;
    while (monotonic_ms() < deadline) {
        if (atomic_load_explicit(value, memory_order_acquire) >= expected) return 0;
        sleep_ms(5);
    }
    return -1;
}

static int count_marker(const unsigned char * data, size_t size, const char * marker) {
    size_t len = strlen(marker);
    int count = 0;
    if (len > size) return 0;
    for (size_t i = 0; i <= size - len; i++) {
        if (memcmp(data + i, marker, len) == 0) {
            count++;
            i += len - 1;
        }
    }
    return count;
}

static int mock_http(ve_tls_http_client * client, const ve_tls_http_request * req,
    ve_tls_http_response * resp) {
    mock_state * state = (mock_state *)client->user_data;
    unsigned present = 0;
    atomic_fetch_add_explicit(&state->calls, 1, memory_order_relaxed);
    for (int i = 0; i < NMARKERS; i++) {
        int count = count_marker(req->body, req->body_size, markers[i]);
        if (count) {
            present |= 1u << i;
            atomic_fetch_add_explicit(&state->hits[i], count, memory_order_release);
        }
    }
    if (!present) atomic_store_explicit(&state->bad_payload, 1, memory_order_release);
    if (state->block_a && (present & (1u << A))) {
        atomic_store_explicit(&state->block_entered, 1, memory_order_release);
        if (wait_value(&state->release_block, 1, 5000) != 0) {
            atomic_store_explicit(&state->block_timeout, 1, memory_order_release);
            return -1;
        }
    }
    resp->status_code = (present & state->fail_mask) ? 400 : 200;
    resp->request_id = strdup(resp->status_code == 200 ? "mock-200" : "mock-400");
    if (resp->status_code == 400) {
        resp->error_code = strdup("BadRequest");
        resp->error_message = strdup("ordinary non-retryable HTTP 400");
    }
    return resp->request_id ? 0 : -1;
}

static void free_http(ve_tls_http_client * client, ve_tls_http_response * resp) {
    (void)client;
    free(resp->body);
    free(resp->request_id);
    free(resp->error_code);
    free(resp->error_message);
}

static void send_done(ve_tls_result result, size_t log_bytes, size_t compressed_bytes,
    const ve_tls_error * error, const unsigned char * raw, void * user, int64_t first, int64_t last) {
    (void)log_bytes; (void)compressed_bytes; (void)error; (void)raw;
    mock_state * state = (mock_state *)user;
    for (int64_t id = first; id <= last && id < MAX_TEST_ID; id++) {
        if (id > 0) {
            _Atomic int * value = result == VE_TLS_OK ? &state->ok[id] : &state->failed[id];
            atomic_fetch_add_explicit(value, 1, memory_order_release);
        }
    }
}

static void init_mock(mock_state * state, unsigned fail_mask, int block_a) {
    memset(state, 0, sizeof(*state));
    state->fail_mask = fail_mask;
    state->block_a = block_a;
}

static ve_tls_producer * open_producer(const char * dir, mock_state * state, int threads) {
    ve_tls_config cfg;
    if (ve_tls_config_init_versioned(&cfg, sizeof(cfg), VE_TLS_CONFIG_VERSION_CURRENT) != VE_TLS_OK) return NULL;
    cfg.endpoint = "https://example.invalid";
    cfg.region = "cn-test";
    cfg.topic_id = "test-topic";
    cfg.access_key_id = "test-ak";
    cfg.access_key_secret = "test-sk";
    cfg.retry_policy.max_attempts = 1;
    cfg.retry_policy.initial_interval_ms = 5;
    cfg.retry_policy.max_interval_ms = 5;
    cfg.retry_policy.randomization_factor = 0;
    cfg.retry_transient_http_errors = 0;
    cfg.flush_interval_ms = 0;
    cfg.log_count_per_package = 1;
    cfg.agg_strategy = 0;
    cfg.compress_type = "none";
    cfg.send_thread_count = threads;
    cfg.pack_thread_count = 1;
    cfg.use_global_env = 0;
    cfg.use_persistent = 1;
    cfg.persistent_file_path = dir;
    cfg.max_persistent_log_count = 64;
    cfg.max_persistent_file_size = 16384;
    cfg.max_persistent_file_count = 4;
    cfg.persistent_max_log_delay_ms = 0;
    cfg.persistent_durability = VE_TLS_PDURABILITY_SYNC_WAL;
    cfg.persistent_open_mode = VE_TLS_POPEN_TAKEOVER_IF_STALE;
    cfg.persistent_lease_timeout_ms = 150;
    cfg.persistent_heartbeat_interval_ms = 50;
    cfg.http_client.do_request = mock_http;
    cfg.http_client.free_response = free_http;
    cfg.http_client.user_data = state;
    ve_tls_producer * producer = ve_tls_producer_create_versioned(&cfg, sizeof(cfg), VE_TLS_CONFIG_VERSION_CURRENT);
    if (producer) ve_tls_producer_set_send_done_v2(producer, send_done, state);
    return producer;
}

static int add(ve_tls_producer * producer, int marker, int64_t * assigned_id) {
    ve_tls_kv kv[] = {{"event_id", markers[marker]}, {"trace_id", "same-trace"}};
    return ve_tls_producer_add_log_kv_hashkey_with_id(producer, 1700000000000LL,
        hash_keys[marker], kv, 2, 1, assigned_id) == VE_TLS_OK ? 0 : -1;
}

static int wait_result(mock_state * state, int64_t id, int success) {
    if (id <= 0 || id >= MAX_TEST_ID) return -1;
    return wait_value(success ? &state->ok[id] : &state->failed[id], 1, 5000);
}

static int close_producer(ve_tls_producer ** producer) {
    int rc = ve_tls_producer_close(*producer, 10000);
    ve_tls_producer_destroy(*producer);
    *producer = NULL;
    return rc == VE_TLS_OK ? 0 : -1;
}

static int make_dir(char * dir, size_t size) {
    char temp[] = "/tmp/ve-tls-ack-replay-XXXXXX";
    if (!mkdtemp(temp)) return -1;
    if (snprintf(dir, size, "%s", temp) < 0) return -1;
    return 0;
}

static void remove_dir(const char * dir) {
    DIR * d = opendir(dir);
    if (!d) return;
    struct dirent * entry;
    while ((entry = readdir(d)) != NULL) {
        char path[PATH_MAX];
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
        if (snprintf(path, sizeof(path), "%s/%s", dir, entry->d_name) > 0) (void)unlink(path);
    }
    closedir(d);
    (void)rmdir(dir);
}

static int hit_count(mock_state * state, int marker) {
    return atomic_load_explicit(&state->hits[marker], memory_order_acquire);
}

static int checkpoint_ack(const char * dir, int64_t * acked) {
    ve_tls_platform platform;
    ve_tls_checkpoint_state checkpoint;
    char path[PATH_MAX];
    ve_tls_platform_init_default(&platform);
    if (snprintf(path, sizeof(path), "%s/checkpoint", dir) < 0 ||
        ve_tls_checkpoint_load(&platform, path, &checkpoint) != 0) return -1;
    *acked = checkpoint.acked_log_id;
    return 0;
}

static ve_tls_platform drop_real_platform;
static _Atomic int drop_fail_checkpoint_rename;
static _Atomic int drop_failed_checkpoint_renames;
static _Atomic int drop_fail_directory_fsync;
static _Atomic int drop_failed_directory_fsyncs;
static _Atomic int64_t drop_now_ms;
static char drop_directory[PATH_MAX];
static ve_tls_file * drop_directory_file;

static int64_t drop_fake_time_ms(void) {
    return atomic_load_explicit(&drop_now_ms, memory_order_acquire);
}

static int drop_fault_rename(const char * from, const char * to) {
    const char * name = strrchr(to, '/');
    if (atomic_load_explicit(&drop_fail_checkpoint_rename, memory_order_acquire) &&
        name && strcmp(name, "/checkpoint") == 0) {
        atomic_fetch_add_explicit(&drop_failed_checkpoint_renames, 1, memory_order_relaxed);
        return -1;
    }
    return drop_real_platform.path_rename(from, to);
}

static ve_tls_file * drop_fault_open(const char * path, int flags, int mode) {
    ve_tls_file * file = drop_real_platform.file_open(path, flags, mode);
    if (file && flags == VE_TLS_FILE_OPEN_RDONLY && strcmp(path, drop_directory) == 0) {
        drop_directory_file = file;
    }
    return file;
}

static void drop_fault_close(ve_tls_file * file) {
    if (file == drop_directory_file) drop_directory_file = NULL;
    drop_real_platform.file_close(file);
}

static int drop_fault_fsync(ve_tls_file * file) {
    if (file == drop_directory_file && atomic_load_explicit(&drop_fail_directory_fsync, memory_order_acquire)) {
        atomic_fetch_add_explicit(&drop_failed_directory_fsyncs, 1, memory_order_relaxed);
        return -1;
    }
    return drop_real_platform.file_fsync(file);
}

static int drop_recovered_record(int64_t id, int64_t enqueue_time_ms, const char * hash_key,
    const unsigned char * payload, size_t size, void * user) {
    (void)enqueue_time_ms; (void)hash_key;
    unsigned * mask = (unsigned *)user;
    static const unsigned char expected[] = "real-persistent-wal-record";
    if (id < 1 || id > 3 || size != sizeof(expected) - 1 || memcmp(payload, expected, size) != 0) return -1;
    *mask |= 1u << (unsigned)id;
    return 0;
}

/* A failed DROP_OLDEST checkpoint write must not commit the candidate prefix
 * or remove a segment; no overdue timer may remain armed for clean state. */
static int run_drop_oldest_checkpoint_failure_is_atomic(int fail_after_rename) {
    int failed = 0, opened = 0, append_rc = 0, timer_rc = 0;
    char dir[PATH_MAX] = {0}, seg1[PATH_MAX], checkpoint_path[PATH_MAX];
    ve_tls_platform platform;
    ve_tls_persistent persistent;
    ve_tls_persistent_options options;
    ve_tls_checkpoint_state disk;
    ve_tls_checkpoint_range * disk_ranges = NULL;
    size_t disk_count = 0;
    unsigned recovered = 0;
    struct stat segment_info;
    int64_t due = 0;
    static const unsigned char payload[] = "real-persistent-wal-record";
    memset(&persistent, 0, sizeof(persistent));
    memset(&options, 0, sizeof(options));
    REQUIRE(make_dir(dir, sizeof(dir)) == 0);
    REQUIRE(snprintf(seg1, sizeof(seg1), "%s/seg-000001.log", dir) > 0);
    REQUIRE(snprintf(checkpoint_path, sizeof(checkpoint_path), "%s/checkpoint", dir) > 0);
    ve_tls_platform_init_default(&drop_real_platform);
    platform = drop_real_platform;
    platform.path_rename = drop_fault_rename;
    platform.file_open = drop_fault_open;
    platform.file_close = drop_fault_close;
    platform.file_fsync = drop_fault_fsync;
    platform.time_ms = drop_fake_time_ms;
    snprintf(drop_directory, sizeof(drop_directory), "%s", dir);
    drop_directory_file = NULL;
    atomic_store(&drop_now_ms, 1000);
    atomic_store(&drop_fail_checkpoint_rename, 0);
    atomic_store(&drop_failed_checkpoint_renames, 0);
    atomic_store(&drop_fail_directory_fsync, 0);
    atomic_store(&drop_failed_directory_fsyncs, 0);
    options.platform = &platform;
    options.dir_path = dir;
    options.instance_id = "drop-test";
    options.owner_id = "drop-owner";
    options.owner_process_name = "drop-test";
    options.segment_max_bytes = 4096;
    options.segment_max_records = 1;
    options.max_bytes = 16384;
    options.max_records = 2;
    options.max_segments = 2;
    options.overflow_policy = VE_TLS_POVERFLOW_DROP_OLDEST_UNACKED;
    options.now_ms = 1000;
    options.lease_timeout_ms = 60000;
    options.heartbeat_interval_ms = 10000;
    options.open_mode = VE_TLS_POPEN_TAKEOVER_IF_STALE;
    options.durability = VE_TLS_PDURABILITY_SYNC_WAL;
    REQUIRE(ve_tls_persistent_open(&persistent, &options) == 0);
    opened = 1;
    REQUIRE(ve_tls_persistent_append(&persistent, 1, NULL, payload, sizeof(payload) - 1) == 0);
    REQUIRE(ve_tls_persistent_append(&persistent, 2, NULL, payload, sizeof(payload) - 1) == 0);
    REQUIRE(ve_tls_persistent_ack_completed_range(&persistent, 2, 2) == 0);
    REQUIRE(ve_tls_persistent_flush(&persistent) == 0);
    REQUIRE(persistent.checkpoint.acked_log_id == 0 && persistent.completed_range_count == 1 &&
        persistent.completed_ranges[0].start_id == 2 && persistent.completed_ranges[0].end_id == 2 &&
        !persistent.checkpoint_dirty && atomic_load(&persistent.next_checkpoint_ms) == 0);
    if (fail_after_rename) atomic_store(&drop_fail_directory_fsync, 1);
    else atomic_store(&drop_fail_checkpoint_rename, 1);
    append_rc = ve_tls_persistent_append(&persistent, 3, NULL, payload, sizeof(payload) - 1);
    atomic_store(&drop_now_ms, 1200);
    timer_rc = ve_tls_persistent_checkpoint_if_due(&persistent);
    due = atomic_load(&persistent.next_checkpoint_ms);
    REQUIRE(ve_tls_persistent_recover(&persistent, drop_recovered_record, &recovered) == 0);
    fprintf(stderr, "drop stage=%s rc=%d renames=%d dirfsync=%d prefix=%lld ranges=%zu segment1=%d timer_rc=%d due=%lld recovered_mask=%u\n",
        fail_after_rename ? "after_rename" : "before_rename", append_rc,
        atomic_load(&drop_failed_checkpoint_renames), atomic_load(&drop_failed_directory_fsyncs),
        (long long)persistent.checkpoint.acked_log_id,
        persistent.completed_range_count, stat(seg1, &segment_info) == 0, timer_rc, (long long)due, recovered);
    REQUIRE(append_rc != 0 &&
        (fail_after_rename ? atomic_load(&drop_failed_directory_fsyncs) == 1 :
         atomic_load(&drop_failed_checkpoint_renames) == 1));
    REQUIRE(persistent.checkpoint.acked_log_id == 0 && persistent.completed_range_count == 1 &&
        persistent.completed_ranges[0].start_id == 2 && persistent.completed_ranges[0].end_id == 2);
    REQUIRE(stat(seg1, &segment_info) == 0 && persistent.current_segments == 2 && recovered == (1u << 1));
    REQUIRE(timer_rc == 0 && (due == 0 || due > atomic_load(&drop_now_ms)));
    REQUIRE(ve_tls_checkpoint_load_ranges(&drop_real_platform, checkpoint_path, &disk, &disk_ranges, &disk_count) ==
        VE_TLS_CHECKPOINT_LOAD_OK);
    REQUIRE((disk.acked_log_id == 0 && disk_count == 1 && disk_ranges[0].start_id == 2 && disk_ranges[0].end_id == 2) ||
        (fail_after_rename && disk.acked_log_id == 2 && disk_count == 0));
cleanup:
    atomic_store(&drop_fail_checkpoint_rename, 0);
    atomic_store(&drop_fail_directory_fsync, 0);
    ve_tls_free(disk_ranges);
    if (opened) ve_tls_persistent_close(&persistent);
    if (dir[0]) remove_dir(dir);
    return failed ? -1 : 0;
}

static int test_drop_oldest_rename_failure_is_atomic(void) {
    return run_drop_oldest_checkpoint_failure_is_atomic(0);
}

static int test_drop_oldest_directory_fsync_failure_is_atomic(void) {
    return run_drop_oldest_checkpoint_failure_is_atomic(1);
}

/* Under the default reject policy, an uncertain post-rename result must not
 * turn the unsent ID 1 into an ACK. A failed timer retry must re-arm. */
static int test_reject_new_directory_fsync_failure_keeps_gap(void) {
    int failed = 0, opened = 0, flush_rc = 0, timer_rc = 0;
    char dir[PATH_MAX] = {0}, checkpoint_path[PATH_MAX];
    ve_tls_platform platform;
    ve_tls_persistent persistent;
    ve_tls_persistent_options options;
    ve_tls_checkpoint_state disk;
    ve_tls_checkpoint_range * disk_ranges = NULL;
    size_t disk_count = 0;
    unsigned recovered = 0;
    int64_t due = 0;
    static const unsigned char payload[] = "real-persistent-wal-record";
    memset(&persistent, 0, sizeof(persistent));
    memset(&options, 0, sizeof(options));
    REQUIRE(make_dir(dir, sizeof(dir)) == 0);
    REQUIRE(snprintf(checkpoint_path, sizeof(checkpoint_path), "%s/checkpoint", dir) > 0);
    ve_tls_platform_init_default(&drop_real_platform);
    platform = drop_real_platform;
    platform.path_rename = drop_fault_rename;
    platform.file_open = drop_fault_open;
    platform.file_close = drop_fault_close;
    platform.file_fsync = drop_fault_fsync;
    platform.time_ms = drop_fake_time_ms;
    snprintf(drop_directory, sizeof(drop_directory), "%s", dir);
    drop_directory_file = NULL;
    atomic_store(&drop_now_ms, 1000);
    atomic_store(&drop_fail_checkpoint_rename, 0);
    atomic_store(&drop_failed_checkpoint_renames, 0);
    atomic_store(&drop_fail_directory_fsync, 0);
    atomic_store(&drop_failed_directory_fsyncs, 0);
    options.platform = &platform;
    options.dir_path = dir;
    options.instance_id = "reject-test";
    options.owner_id = "reject-owner";
    options.owner_process_name = "reject-test";
    options.segment_max_bytes = 4096;
    options.segment_max_records = 1;
    options.max_bytes = 16384;
    options.max_records = 4;
    options.max_segments = 4;
    options.overflow_policy = VE_TLS_POVERFLOW_REJECT_NEW;
    options.now_ms = 1000;
    options.lease_timeout_ms = 60000;
    options.heartbeat_interval_ms = 10000;
    options.open_mode = VE_TLS_POPEN_TAKEOVER_IF_STALE;
    options.durability = VE_TLS_PDURABILITY_SYNC_WAL;
    REQUIRE(ve_tls_persistent_open(&persistent, &options) == 0);
    opened = 1;
    for (int64_t id = 1; id <= 3; id++) {
        REQUIRE(ve_tls_persistent_append(&persistent, id, NULL, payload, sizeof(payload) - 1) == 0);
    }
    REQUIRE(ve_tls_persistent_ack_completed_range(&persistent, 2, 2) == 0);
    REQUIRE(ve_tls_persistent_flush(&persistent) == 0);
    REQUIRE(ve_tls_persistent_ack_completed_range(&persistent, 3, 3) == 0);
    atomic_store(&drop_fail_directory_fsync, 1);
    flush_rc = ve_tls_persistent_flush(&persistent);
    atomic_store(&drop_now_ms, 1200);
    timer_rc = ve_tls_persistent_checkpoint_if_due(&persistent);
    due = atomic_load(&persistent.next_checkpoint_ms);
    REQUIRE(ve_tls_persistent_recover(&persistent, drop_recovered_record, &recovered) == 0);
    REQUIRE(ve_tls_checkpoint_load_ranges(&drop_real_platform, checkpoint_path, &disk, &disk_ranges, &disk_count) ==
        VE_TLS_CHECKPOINT_LOAD_OK);
    fprintf(stderr, "reject fsync flush=%d timer=%d due=%lld prefix=%lld disk_prefix=%lld ranges=%zu recovered_mask=%u\n",
        flush_rc, timer_rc, (long long)due, (long long)persistent.checkpoint.acked_log_id,
        (long long)disk.acked_log_id, disk_count, recovered);
    REQUIRE(flush_rc != 0 && timer_rc != 0 && atomic_load(&drop_failed_directory_fsyncs) >= 2);
    REQUIRE(due > atomic_load(&drop_now_ms) && persistent.checkpoint.acked_log_id == 0 && recovered == (1u << 1));
    REQUIRE(disk.acked_log_id == 0 && disk_count == 1 && disk_ranges[0].start_id == 2 &&
        (disk_ranges[0].end_id == 2 || disk_ranges[0].end_id == 3));
    ve_tls_free(disk_ranges); disk_ranges = NULL;
    atomic_store(&drop_fail_directory_fsync, 0);
    ve_tls_persistent_close(&persistent); opened = 0;
    options.now_ms = atomic_load(&drop_now_ms);
    REQUIRE(ve_tls_persistent_open(&persistent, &options) == 0);
    opened = 1; recovered = 0;
    REQUIRE(ve_tls_persistent_recover(&persistent, drop_recovered_record, &recovered) == 0 && recovered == (1u << 1));
cleanup:
    atomic_store(&drop_fail_directory_fsync, 0);
    ve_tls_free(disk_ranges);
    if (opened) ve_tls_persistent_close(&persistent);
    if (dir[0]) remove_dir(dir);
    return failed ? -1 : 0;
}

static int run_checkpoint_failure_backoff(int64_t first_save_id, int force_flush) {
    int failed = 0, opened = 0;
    char dir[PATH_MAX] = {0};
    ve_tls_platform platform;
    ve_tls_persistent persistent;
    ve_tls_persistent_options options = {0};
    int64_t disk_ack = -1;
    int64_t failure_ms = first_save_id == 64 ? 1000 : 1100;
    static const unsigned char payload[] = "checkpoint-backoff-record";

    REQUIRE(make_dir(dir, sizeof(dir)) == 0);
    ve_tls_platform_init_default(&drop_real_platform);
    platform = drop_real_platform;
    platform.path_rename = drop_fault_rename;
    platform.time_ms = drop_fake_time_ms;
    atomic_store(&drop_now_ms, 1000);
    atomic_store(&drop_fail_checkpoint_rename, 0);
    atomic_store(&drop_failed_checkpoint_renames, 0);
    options.platform = &platform;
    options.dir_path = dir;
    options.instance_id = "backoff-test";
    options.owner_id = "backoff-owner";
    options.owner_process_name = "backoff-test";
    options.segment_max_bytes = 16384;
    options.segment_max_records = 128;
    options.now_ms = 1000;
    options.lease_timeout_ms = 60000;
    options.heartbeat_interval_ms = 10000;
    options.open_mode = VE_TLS_POPEN_TAKEOVER_IF_STALE;
    options.durability = VE_TLS_PDURABILITY_SYNC_WAL;
    REQUIRE(ve_tls_persistent_open(&persistent, &options) == 0);
    opened = 1;
    for (int64_t id = 1; id <= first_save_id + 3; id++) {
        REQUIRE(ve_tls_persistent_append(&persistent, id, NULL, payload, sizeof(payload) - 1) == 0);
    }
    REQUIRE(ve_tls_persistent_ack_range(&persistent, 1, first_save_id - 1) == 0);
    REQUIRE(checkpoint_ack(dir, &disk_ack) == 0 && disk_ack == 0);

    atomic_store(&drop_now_ms, failure_ms);
    atomic_store(&drop_fail_checkpoint_rename, 1);
    REQUIRE(ve_tls_persistent_ack_range(&persistent, first_save_id, first_save_id) ==
        VE_TLS_PERSISTENT_FLUSH_CHECKPOINT_FAILED);
    REQUIRE(atomic_load(&drop_failed_checkpoint_renames) == 1);
    atomic_store(&drop_now_ms, failure_ms + 99);
    REQUIRE(ve_tls_persistent_ack_range(&persistent, first_save_id + 1, first_save_id + 1) == 0);
    REQUIRE(ve_tls_persistent_checkpoint_if_due(&persistent) == 0);
    REQUIRE(atomic_load(&drop_failed_checkpoint_renames) == 1);

    atomic_store(&drop_now_ms, failure_ms + 100);
    REQUIRE(ve_tls_persistent_checkpoint_if_due(&persistent) != 0);
    REQUIRE(atomic_load(&drop_failed_checkpoint_renames) == 2);
    REQUIRE(ve_tls_persistent_ack_range(&persistent, first_save_id + 2, first_save_id + 2) == 0);
    REQUIRE(atomic_load(&drop_failed_checkpoint_renames) == 2);
    REQUIRE(checkpoint_ack(dir, &disk_ack) == 0 && disk_ack == 0);
    REQUIRE(persistent.durable_checkpoint_acked_log_id == 0 && persistent.checkpoint_dirty);

    atomic_store(&drop_fail_checkpoint_rename, 0);
    if (force_flush) {
        REQUIRE(ve_tls_persistent_flush(&persistent) == 0);
        REQUIRE(checkpoint_ack(dir, &disk_ack) == 0 && disk_ack == first_save_id + 2);
    } else {
        atomic_store(&drop_now_ms, failure_ms + 200);
        REQUIRE(ve_tls_persistent_ack_range(&persistent, first_save_id + 3, first_save_id + 3) == 0);
        REQUIRE(checkpoint_ack(dir, &disk_ack) == 0 && disk_ack == first_save_id + 3);
    }
    REQUIRE(persistent.durable_checkpoint_acked_log_id == disk_ack && !persistent.checkpoint_dirty);
    REQUIRE(atomic_load(&persistent.next_checkpoint_ms) == 0);
cleanup:
    atomic_store(&drop_fail_checkpoint_rename, 0);
    if (opened) ve_tls_persistent_close(&persistent);
    if (dir[0]) remove_dir(dir);
    return failed ? -1 : 0;
}

static int test_checkpoint_failure_backoff_after_save_window(void) {
    return run_checkpoint_failure_backoff(2, 0);
}

static int test_checkpoint_failure_backoff_after_ack_threshold(void) {
    return run_checkpoint_failure_backoff(64, 1);
}

static void * failing_range_realloc(void * ptr, size_t size, void * user) {
    (void)ptr; (void)size; (void)user;
    return NULL;
}

static int record_recovered_mask(int64_t id, int64_t enqueue_time_ms, const char * hash_key,
    const unsigned char * payload, size_t size, void * user) {
    (void)enqueue_time_ms; (void)hash_key;
    uint64_t * mask = (uint64_t *)user;
    static const unsigned char expected[] = "sparse-range-wal-record";
    if (id < 1 || id > 20 || size != sizeof(expected) - 1 || memcmp(payload, expected, size) != 0) return -1;
    *mask |= UINT64_C(1) << (unsigned)id;
    return 0;
}

/* Exercise range growth, OOM, restart filtering, bridging two ranges, and
 * incremental prefix coalescing using records in a real WAL. */
static int test_many_sparse_ranges_merge_and_oom(void) {
    int failed = 0, opened = 0, ack_rc = 0;
    char dir[PATH_MAX] = {0};
    ve_tls_platform platform;
    ve_tls_persistent persistent;
    ve_tls_persistent_options options;
    ve_tls_alloc_hooks saved_hooks, failing_hooks;
    uint64_t expected_mask = 0, recovered = 0;
    static const int fill_order[] = {3, 7, 11, 15, 19, 1, 5, 9, 13, 17};
    static const unsigned char payload[] = "sparse-range-wal-record";
    memset(&persistent, 0, sizeof(persistent));
    memset(&options, 0, sizeof(options));
    REQUIRE(make_dir(dir, sizeof(dir)) == 0);
    ve_tls_platform_init_default(&platform);
    platform.time_ms = drop_fake_time_ms;
    atomic_store(&drop_now_ms, 1000);
    options.platform = &platform;
    options.dir_path = dir;
    options.instance_id = "sparse-test";
    options.owner_id = "sparse-owner";
    options.owner_process_name = "sparse-test";
    options.segment_max_bytes = 8192;
    options.segment_max_records = 64;
    options.max_bytes = 32768;
    options.max_records = 64;
    options.max_segments = 4;
    options.overflow_policy = VE_TLS_POVERFLOW_REJECT_NEW;
    options.now_ms = 1000;
    options.lease_timeout_ms = 60000;
    options.heartbeat_interval_ms = 10000;
    options.open_mode = VE_TLS_POPEN_TAKEOVER_IF_STALE;
    options.durability = VE_TLS_PDURABILITY_SYNC_WAL;
    REQUIRE(ve_tls_persistent_open(&persistent, &options) == 0);
    opened = 1;
    for (int64_t id = 1; id <= 20; id++) {
        REQUIRE(ve_tls_persistent_append(&persistent, id, NULL, payload, sizeof(payload) - 1) == 0);
    }
    for (int64_t id = 2; id <= 16; id += 2) {
        REQUIRE(ve_tls_persistent_ack_completed_range(&persistent, id, id) == 0);
    }
    REQUIRE(ve_tls_persistent_flush(&persistent) == 0);
    REQUIRE(persistent.checkpoint.acked_log_id == 0 && persistent.completed_range_count == 8 &&
        persistent.completed_range_capacity == 8);
    ve_tls_alloc_get_hooks(&saved_hooks);
    failing_hooks = saved_hooks;
    failing_hooks.realloc_fn = failing_range_realloc;
    ve_tls_alloc_set_hooks(&failing_hooks);
    ack_rc = ve_tls_persistent_ack_completed_range(&persistent, 18, 18);
    ve_tls_alloc_set_hooks(&saved_hooks);
    REQUIRE(ack_rc != 0 && persistent.checkpoint.acked_log_id == 0 && persistent.completed_range_count == 8);
    for (size_t i = 0; i < persistent.completed_range_count; i++) {
        REQUIRE(persistent.completed_ranges[i].start_id == (int64_t)(2 * (i + 1)) &&
            persistent.completed_ranges[i].end_id == (int64_t)(2 * (i + 1)));
    }
    for (int id = 1; id <= 20; id++) {
        if ((id & 1) || id >= 18) expected_mask |= UINT64_C(1) << (unsigned)id;
    }
    REQUIRE(ve_tls_persistent_recover(&persistent, record_recovered_mask, &recovered) == 0 && recovered == expected_mask);
    REQUIRE(ve_tls_persistent_ack_completed_range(&persistent, 18, 18) == 0);
    REQUIRE(ve_tls_persistent_ack_completed_range(&persistent, 20, 20) == 0);
    REQUIRE(persistent.completed_range_count == 10 && ve_tls_persistent_flush(&persistent) == 0);
    ve_tls_persistent_close(&persistent); opened = 0;
    REQUIRE(ve_tls_persistent_open(&persistent, &options) == 0);
    opened = 1;
    expected_mask = 0; recovered = 0;
    for (int id = 1; id <= 20; id += 2) expected_mask |= UINT64_C(1) << (unsigned)id;
    REQUIRE(persistent.checkpoint.acked_log_id == 0 && persistent.completed_range_count == 10);
    REQUIRE(ve_tls_persistent_recover(&persistent, record_recovered_mask, &recovered) == 0 && recovered == expected_mask);
    for (size_t i = 0; i < sizeof(fill_order) / sizeof(fill_order[0]); i++) {
        int id = fill_order[i];
        REQUIRE(ve_tls_persistent_ack_completed_range(&persistent, id, id) == 0);
        expected_mask &= ~(UINT64_C(1) << (unsigned)id);
        recovered = 0;
        REQUIRE(ve_tls_persistent_recover(&persistent, record_recovered_mask, &recovered) == 0 && recovered == expected_mask);
    }
    REQUIRE(persistent.checkpoint.acked_log_id == 20 && persistent.completed_range_count == 0);
    REQUIRE(ve_tls_persistent_flush(&persistent) == 0);
    ve_tls_persistent_close(&persistent); opened = 0;
    REQUIRE(ve_tls_persistent_open(&persistent, &options) == 0);
    opened = 1; recovered = 0;
    REQUIRE(ve_tls_persistent_recover(&persistent, record_recovered_mask, &recovered) == 0 && recovered == 0);
    fprintf(stderr, "sparse OOM preserved 8 ranges; 10 ranges restored; incremental merges acked=20\n");
cleanup:
    if (opened) ve_tls_persistent_close(&persistent);
    if (dir[0]) remove_dir(dir);
    return failed ? -1 : 0;
}

/* No explicit flush/close/destroy before the child exits. */
static int test_idle_ack_survives_process_exit(void) {
    int failed = 0; char dir[PATH_MAX] = {0}; ve_tls_producer * producer = NULL;
    mock_state state; int child_status = 0;
    REQUIRE(make_dir(dir, sizeof(dir)) == 0);
    fflush(NULL);
    pid_t child = fork();
    REQUIRE(child >= 0);
    if (child == 0) {
        init_mock(&state, 0, 0);
        producer = open_producer(dir, &state, 1);
        int64_t id = 0, acked = 0;
        if (!producer || add(producer, A, &id) || id != 1 || wait_result(&state, id, 1)) _exit(11);
        int64_t started = monotonic_ms();
        while (monotonic_ms() - started < 1500) {
            if (checkpoint_ack(dir, &acked) == 0 && acked == 1) break;
            sleep_ms(5);
        }
        fprintf(stderr, "idle checkpoint ack=%lld after_ms=%lld requests_A=%d\n",
            (long long)acked, (long long)(monotonic_ms() - started), hit_count(&state, A));
        if (acked != 1 || hit_count(&state, A) != 1) _exit(12);
        _exit(0);
    }
    REQUIRE(waitpid(child, &child_status, 0) == child);
    REQUIRE(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
    sleep_ms(250);
    init_mock(&state, 0, 0);
    producer = open_producer(dir, &state, 1);
    REQUIRE(producer != NULL);
    REQUIRE(ve_tls_producer_recover(producer) == VE_TLS_OK);
    REQUIRE(close_producer(&producer) == 0);
    REQUIRE(atomic_load(&state.calls) == 0 && !atomic_load(&state.bad_payload));
cleanup:
    if (producer) ve_tls_producer_destroy(producer);
    if (dir[0]) remove_dir(dir);
    return failed ? -1 : 0;
}

/* The idle timer must also save a success beyond an unacknowledged gap. */
static int test_idle_sparse_ack_survives_process_exit(void) {
    int failed = 0; char dir[PATH_MAX] = {0}; ve_tls_producer * producer = NULL;
    mock_state state; int child_status = 0;
    REQUIRE(make_dir(dir, sizeof(dir)) == 0);
    fflush(NULL);
    pid_t child = fork();
    REQUIRE(child >= 0);
    if (child == 0) {
        char path[PATH_MAX]; struct stat initial_stat, current_stat;
        int64_t a = 0, b = 0, c = 0, acked = 0;
        init_mock(&state, 1u << B, 0);
        producer = open_producer(dir, &state, 1);
        if (!producer || snprintf(path, sizeof(path), "%s/checkpoint", dir) < 0 ||
            stat(path, &initial_stat) != 0 ||
            add(producer, A, &a) || a != 1 || wait_result(&state, a, 1) ||
            add(producer, B, &b) || b != 2 || wait_result(&state, b, 0) ||
            add(producer, C, &c) || c != 3 || wait_result(&state, c, 1)) _exit(21);
        int64_t started = monotonic_ms();
        memset(&current_stat, 0, sizeof(current_stat));
        while (monotonic_ms() - started < 1500) {
            if (stat(path, &current_stat) == 0 && current_stat.st_size > initial_stat.st_size &&
                checkpoint_ack(dir, &acked) == 0 && acked == 1) break;
            sleep_ms(5);
        }
        fprintf(stderr, "idle sparse ack=%lld checkpoint_bytes=%lld initial_bytes=%lld after_ms=%lld\n",
            (long long)acked, (long long)current_stat.st_size, (long long)initial_stat.st_size,
            (long long)(monotonic_ms() - started));
        if (acked != 1 || current_stat.st_size <= initial_stat.st_size ||
            hit_count(&state, A) != 1 || hit_count(&state, B) != 1 || hit_count(&state, C) != 1) _exit(22);
        _exit(0);
    }
    REQUIRE(waitpid(child, &child_status, 0) == child);
    REQUIRE(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
    sleep_ms(250);
    init_mock(&state, 0, 0);
    producer = open_producer(dir, &state, 1);
    REQUIRE(producer != NULL && ve_tls_producer_recover(producer) == VE_TLS_OK);
    REQUIRE(close_producer(&producer) == 0);
    fprintf(stderr, "idle sparse reopen A=%d B=%d C=%d\n", hit_count(&state, A), hit_count(&state, B), hit_count(&state, C));
    REQUIRE(hit_count(&state, A) == 0 && hit_count(&state, B) == 1 && hit_count(&state, C) == 0 &&
        !atomic_load(&state.bad_payload));
cleanup:
    if (producer) ve_tls_producer_destroy(producer);
    if (dir[0]) remove_dir(dir);
    return failed ? -1 : 0;
}

/* Across two restarts, successful C must never replay and failed B/D must not
 * be lost. D must not reuse any ID present in the original WAL. */
static int test_sparse_ack_and_high_id(void) {
    int failed = 0; char dir[PATH_MAX] = {0}; ve_tls_producer * producer = NULL;
    mock_state initial, replay, final; int64_t a = 0, b = 0, c = 0, d = 0;
    REQUIRE(make_dir(dir, sizeof(dir)) == 0);
    init_mock(&initial, 1u << B, 0);
    producer = open_producer(dir, &initial, 1);
    REQUIRE(producer != NULL);
    REQUIRE(add(producer, A, &a) == 0 && a == 1 && wait_result(&initial, a, 1) == 0);
    REQUIRE(add(producer, B, &b) == 0 && b == 2 && wait_result(&initial, b, 0) == 0);
    REQUIRE(add(producer, C, &c) == 0 && c == 3 && wait_result(&initial, c, 1) == 0);
    REQUIRE(close_producer(&producer) == 0);
    REQUIRE(hit_count(&initial, A) == 1 && hit_count(&initial, B) == 1 && hit_count(&initial, C) == 1);

    init_mock(&replay, (1u << B) | (1u << D), 0);
    producer = open_producer(dir, &replay, 1);
    REQUIRE(producer != NULL);
    REQUIRE(ve_tls_producer_recover(producer) == VE_TLS_OK);
    REQUIRE(ve_tls_producer_flush(producer) == VE_TLS_OK);
    REQUIRE(wait_result(&replay, b, 0) == 0);
    REQUIRE(add(producer, D, &d) == 0 && wait_result(&replay, d, 0) == 0);
    REQUIRE(close_producer(&producer) == 0);
    fprintf(stderr, "sparse reopen A=%d B=%d C=%d D=%d assigned_D=%lld\n",
        hit_count(&replay, A), hit_count(&replay, B), hit_count(&replay, C), hit_count(&replay, D), (long long)d);

    init_mock(&final, 0, 0);
    producer = open_producer(dir, &final, 1);
    REQUIRE(producer != NULL);
    REQUIRE(ve_tls_producer_recover(producer) == VE_TLS_OK);
    REQUIRE(close_producer(&producer) == 0);
    fprintf(stderr, "sparse final A=%d B=%d C=%d D=%d\n",
        hit_count(&final, A), hit_count(&final, B), hit_count(&final, C), hit_count(&final, D));
    REQUIRE(d > c && hit_count(&replay, A) == 0 && hit_count(&replay, B) == 1 &&
        hit_count(&replay, C) == 0 && hit_count(&replay, D) == 1);
    REQUIRE(hit_count(&final, A) == 0 && hit_count(&final, B) == 1 &&
        hit_count(&final, C) == 0 && hit_count(&final, D) == 1);
    REQUIRE(!atomic_load(&initial.bad_payload) && !atomic_load(&replay.bad_payload) && !atomic_load(&final.bad_payload));
cleanup:
    if (producer) ve_tls_producer_destroy(producer);
    if (dir[0]) remove_dir(dir);
    return failed ? -1 : 0;
}

/* No replay callback fires when every original record was already ACKed. The
 * newly allocated ID must nevertheless exceed the original maximum. */
static int test_high_id_after_fully_acked_restart(void) {
    int failed = 0; char dir[PATH_MAX] = {0}; ve_tls_producer * producer = NULL;
    mock_state initial, append, replay; int64_t a = 0, d = 0;
    REQUIRE(make_dir(dir, sizeof(dir)) == 0);
    init_mock(&initial, 0, 0);
    producer = open_producer(dir, &initial, 1);
    REQUIRE(producer != NULL);
    REQUIRE(add(producer, A, &a) == 0 && a == 1 && wait_result(&initial, a, 1) == 0);
    REQUIRE(close_producer(&producer) == 0);
    init_mock(&append, 1u << D, 0);
    producer = open_producer(dir, &append, 1);
    REQUIRE(producer != NULL && ve_tls_producer_recover(producer) == VE_TLS_OK);
    REQUIRE(add(producer, D, &d) == 0 && wait_result(&append, d, 0) == 0);
    REQUIRE(close_producer(&producer) == 0);
    init_mock(&replay, 0, 0);
    producer = open_producer(dir, &replay, 1);
    REQUIRE(producer != NULL && ve_tls_producer_recover(producer) == VE_TLS_OK);
    REQUIRE(close_producer(&producer) == 0);
    fprintf(stderr, "fully-acked reopen D_id=%lld replay_A=%d replay_D=%d\n",
        (long long)d, hit_count(&replay, A), hit_count(&replay, D));
    REQUIRE(d > a && hit_count(&append, D) == 1 && hit_count(&replay, A) == 0 && hit_count(&replay, D) == 1);
    REQUIRE(!atomic_load(&initial.bad_payload) && !atomic_load(&append.bad_payload) && !atomic_load(&replay.bad_payload));
cleanup:
    if (producer) ve_tls_producer_destroy(producer);
    if (dir[0]) remove_dir(dir);
    return failed ? -1 : 0;
}

/* Distinct hash keys permit parallel sends. A is held in mock HTTP until B has
 * failed and C has succeeded, forcing success callbacks to complete out of order. */
static int test_concurrent_out_of_order_ack(void) {
    int failed = 0; char dir[PATH_MAX] = {0}; ve_tls_producer * producer = NULL;
    mock_state initial, replay; int64_t a = 0, b = 0, c = 0;
    init_mock(&initial, 1u << B, 1);
    REQUIRE(make_dir(dir, sizeof(dir)) == 0);
    producer = open_producer(dir, &initial, 3);
    REQUIRE(producer != NULL);
    REQUIRE(add(producer, A, &a) == 0 && a == 1);
    REQUIRE(wait_value(&initial.block_entered, 1, 5000) == 0);
    REQUIRE(add(producer, B, &b) == 0 && b == 2);
    REQUIRE(add(producer, C, &c) == 0 && c == 3);
    REQUIRE(wait_result(&initial, b, 0) == 0 && wait_result(&initial, c, 1) == 0);
    REQUIRE(atomic_load(&initial.ok[a]) == 0);
    atomic_store_explicit(&initial.release_block, 1, memory_order_release);
    REQUIRE(wait_result(&initial, a, 1) == 0);
    REQUIRE(close_producer(&producer) == 0);
    REQUIRE(!atomic_load(&initial.block_timeout));
    init_mock(&replay, 0, 0);
    producer = open_producer(dir, &replay, 3);
    REQUIRE(producer != NULL && ve_tls_producer_recover(producer) == VE_TLS_OK);
    REQUIRE(close_producer(&producer) == 0);
    fprintf(stderr, "concurrent reopen A=%d B=%d C=%d\n", hit_count(&replay, A), hit_count(&replay, B), hit_count(&replay, C));
    REQUIRE(hit_count(&initial, A) == 1 && hit_count(&initial, B) == 1 && hit_count(&initial, C) == 1);
    REQUIRE(hit_count(&replay, A) == 0 && hit_count(&replay, B) == 1 && hit_count(&replay, C) == 0);
    REQUIRE(!atomic_load(&initial.bad_payload) && !atomic_load(&replay.bad_payload));
cleanup:
    atomic_store_explicit(&initial.release_block, 1, memory_order_release);
    if (producer) ve_tls_producer_destroy(producer);
    if (dir[0]) remove_dir(dir);
    return failed ? -1 : 0;
}

int main(void) {
    struct { const char * name; int (*run)(void); } tests[] = {
        {"idle_ack_survives_process_exit", test_idle_ack_survives_process_exit},
        {"idle_sparse_ack_survives_process_exit", test_idle_sparse_ack_survives_process_exit},
        {"sparse_ack_and_high_id", test_sparse_ack_and_high_id},
        {"high_id_after_fully_acked_restart", test_high_id_after_fully_acked_restart},
        {"concurrent_out_of_order_ack", test_concurrent_out_of_order_ack},
        {"drop_oldest_rename_failure_is_atomic", test_drop_oldest_rename_failure_is_atomic},
        {"drop_oldest_directory_fsync_failure_is_atomic", test_drop_oldest_directory_fsync_failure_is_atomic},
        {"reject_new_directory_fsync_failure_keeps_gap", test_reject_new_directory_fsync_failure_keeps_gap},
        {"checkpoint_failure_backoff_after_save_window", test_checkpoint_failure_backoff_after_save_window},
        {"checkpoint_failure_backoff_after_ack_threshold", test_checkpoint_failure_backoff_after_ack_threshold},
        {"many_sparse_ranges_merge_and_oom", test_many_sparse_ranges_merge_and_oom},
    };
    int failures = 0;
    for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
        int rc = tests[i].run();
        printf("%s %s\n", rc == 0 ? "PASS" : "FAIL", tests[i].name);
        fflush(stdout);
        if (rc != 0) failures++;
    }
    return failures ? 1 : 0;
}
