#include "ve_tls_producer.h"
#include "ve_tls_http.h"
#include "ve_tls_proto.h"
#include "producer/ve_tls_checkpoint.h"
#include "producer/ve_tls_persistent.h"
#include "producer/ve_tls_producer_internal.h"
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
    _Atomic int send_before_sync;
    _Atomic int * required_sync;
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
    if (state->required_sync && !atomic_load(state->required_sync)) atomic_store(&state->send_before_sync, 1);
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

static int wait_checkpoint_ack(const char * dir, int64_t expected) {
    int64_t deadline = monotonic_ms() + 5000;
    while (monotonic_ms() < deadline) {
        int64_t ack;
        if (checkpoint_ack(dir, &ack) == 0 && ack == expected) return 0;
        sleep_ms(5);
    }
    return -1;
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

enum {
    REPLAY_MIB = 1024 * 1024,
    REPLAY_RECORDS = 128,
    REPLAY_MAX_RECORDS = 1152,
    REPLAY_PREFIX = 4,
    REPLAY_RECORD_BYTES = 8 * 1024
};

typedef struct {
    _Atomic int requests;
    _Atomic int wire_records;
    _Atomic int failed;
    _Atomic int delivered[REPLAY_MAX_RECORDS + 2];
    _Atomic int delivered_count;
    _Atomic int release_http;
    _Atomic int budget_wait;
    _Atomic int closing;
    int hold_first_request;
} backlog_replay_state;

static ve_tls_platform replay_platform;
static _Atomic int replay_builder_waiting;
static _Atomic int replay_release_builder;
static _Atomic int replay_finished;
static ve_tls_result replay_result;
static ve_tls_result close_result;

typedef enum {
    WAL_FAULT_NONE,
    WAL_FAULT_STAT,
    WAL_FAULT_OPEN,
    WAL_FAULT_READ,
    WAL_FAULT_EOF
} wal_fault;

static _Atomic int wal_fault_pending;
static const char * wal_fault_basename;
static int64_t wal_fault_read_offset;
static _Thread_local ve_tls_file * wal_fault_reader;

static int wal_fault_matches(const char * path) {
    return strcmp(strrchr(path, '/') + 1, wal_fault_basename) == 0;
}

static int wal_fault_once(wal_fault operation) {
    int expected = operation;
    return atomic_compare_exchange_strong(&wal_fault_pending, &expected, WAL_FAULT_NONE);
}

static int wal_fault_stat(const char * path, ve_tls_path_info * info) {
    if (wal_fault_matches(path) && wal_fault_once(WAL_FAULT_STAT)) return -1;
    return replay_platform.path_stat(path, info);
}

static ve_tls_file * wal_fault_open(const char * path, int flags, int mode) {
    int target = wal_fault_matches(path);
    if (target && wal_fault_once(WAL_FAULT_OPEN)) return NULL;
    ve_tls_file * file = replay_platform.file_open(path, flags, mode);
    if (target && flags == VE_TLS_FILE_OPEN_RDONLY) wal_fault_reader = file;
    return file;
}

static void wal_fault_close(ve_tls_file * file) {
    if (file == wal_fault_reader) wal_fault_reader = NULL;
    replay_platform.file_close(file);
}

static int64_t wal_fault_read(ve_tls_file * file, void * buf, size_t size) {
    if (file == wal_fault_reader &&
        replay_platform.file_seek(file, 0, VE_TLS_FILE_SEEK_CUR) == wal_fault_read_offset) {
        if (wal_fault_once(WAL_FAULT_READ)) return -1;
        if (wal_fault_once(WAL_FAULT_EOF)) return 0;
    }
    return replay_platform.file_read(file, buf, size);
}

static void install_wal_fault(ve_tls_config * cfg, const char * basename, int64_t read_offset) {
    replay_platform = cfg->platform;
    wal_fault_basename = basename;
    wal_fault_read_offset = read_offset;
    atomic_store(&wal_fault_pending, WAL_FAULT_NONE);
    cfg->platform.path_stat = wal_fault_stat;
    cfg->platform.file_open = wal_fault_open;
    cfg->platform.file_close = wal_fault_close;
    cfg->platform.file_read = wal_fault_read;
}

static void * wait_then_build(void * producer) {
    atomic_store(&replay_builder_waiting, 1);
    while (!atomic_load(&replay_release_builder)) sleep_ms(1);
    return ve_tls_worker_main(producer);
}

static ve_tls_thread * gate_replay_builder(ve_tls_thread_fn fn, void * arg) {
    return replay_platform.thread_create(fn == ve_tls_worker_main ? wait_then_build : fn, arg);
}

static int backlog_http(ve_tls_http_client * client, const ve_tls_http_request * request,
    ve_tls_http_response * response) {
    backlog_replay_state * state = client->user_data;
    const char * count = strstr(request->headers, "\nlog-count:");
    if (!count) return -1;
    atomic_fetch_add(&state->wire_records, atoi(count + strlen("\nlog-count:")));
    if (atomic_fetch_add(&state->requests, 1) == 0 && state->hold_first_request &&
        wait_value(&state->release_http, 1, 10000) != 0) {
        atomic_store(&state->failed, 1);
        return -1;
    }
    response->status_code = 200;
    return 0;
}

static int wait_send_queue_full(ve_tls_producer * producer) {
    ve_tls_send_queue * queue = &producer->send_queue;
    int64_t deadline = monotonic_ms() + 5000;
    while (monotonic_ms() < deadline) {
        queue->platform->mutex_lock(queue->mutex);
        int full = queue->count == queue->cap;
        queue->platform->mutex_unlock(queue->mutex);
        if (full) return 0;
        sleep_ms(5);
    }
    return -1;
}

static void backlog_send_done(ve_tls_result result, size_t bytes, size_t compressed_bytes,
    const ve_tls_error * error, const unsigned char * raw, void * user, int64_t first, int64_t last) {
    (void)bytes;
    (void)compressed_bytes;
    (void)error;
    (void)raw;
    backlog_replay_state * state = user;
    if (result != VE_TLS_OK || first <= 0 || last < first || last > REPLAY_MAX_RECORDS + 1) {
        atomic_store(&state->failed, 1);
        return;
    }
    for (int64_t id = first; id <= last; ++id) atomic_fetch_add(&state->delivered[id], 1);
    atomic_fetch_add(&state->delivered_count, (int)(last - first + 1));
}

static int write_legacy_backlog(ve_tls_producer * producer, int records) {
    ve_tls_log_group_builder * record = ve_tls_log_builder_create(NULL);
    if (!record) return -1;
    char body[REPLAY_RECORD_BYTES];
    memset(body, 'x', sizeof(body));
    body[sizeof(body) - 1] = 0;
    ve_tls_kv kv = {"message", body};
    const size_t key_len = sizeof("message") - 1;
    const size_t value_len = sizeof(body) - 1;
    int rc = 0;
    for (int64_t id = 1; id <= records && rc == 0; ++id) {
        record->logs_len = 0;
        record->log_count = 0;
        rc = ve_tls_log_builder_add_kv_lens(record, id, 1700000000000LL, 0, 0, &kv, &key_len, &value_len, 1);
        if (rc == 0) {
            rc = ve_tls_persistent_append(producer->persistent, id, NULL, record->logs, record->logs_len);
        }
    }
    ve_tls_log_builder_free(record);
    return rc;
}

/* Android 2.1.4 writes V2 records and the V1 checkpoint prefix. Keep that
 * format and the customer's 8 MiB/10 MiB limits. Holding the worker at startup
 * makes the old per-record queue failure independent of thread scheduling. */
static void backlog_metrics(const char * name, int64_t first, int64_t second, void * user) {
    (void)first;
    (void)second;
    backlog_replay_state * state = user;
    if (strcmp(name, "persistent_recovery_wait_buffer") == 0) atomic_store(&state->budget_wait, 1);
    if (strcmp(name, "close_start") == 0) atomic_store(&state->closing, 1);
}

static void * recover_backlog(void * producer) {
    replay_result = ve_tls_producer_recover(producer);
    atomic_store(&replay_finished, 1);
    return NULL;
}

static void * close_during_recovery(void * arg) {
    ve_tls_producer * producer = arg;
    close_result = ve_tls_producer_close(producer, 10000);
    return NULL;
}

static int customer_wal_config(ve_tls_config * cfg, const char * dir) {
    if (ve_tls_config_init_versioned(cfg, sizeof(*cfg), VE_TLS_CONFIG_VERSION_CURRENT) != VE_TLS_OK) return -1;
    cfg->endpoint = "https://example.invalid";
    cfg->region = "ap-southeast-1";
    cfg->topic_id = "replay-test";
    cfg->access_key_id = "test-ak";
    cfg->access_key_secret = "test-sk";
    cfg->send_thread_count = 1;
    cfg->log_bytes_per_package = REPLAY_MIB;
    cfg->log_count_per_package = 1024;
    cfg->flush_interval_ms = 3000;
    cfg->max_buffer_bytes = 8 * REPLAY_MIB;
#if defined(VE_TLS_HAVE_LZ4)
    cfg->compress_type = "lz4";
#else
    cfg->compress_type = "none";
#endif
    cfg->use_persistent = 1;
    cfg->persistent_file_path = dir;
    cfg->persistent_durability = VE_TLS_PDURABILITY_SYNC_WAL;
    cfg->force_flush_disk = 1;
    cfg->max_persistent_file_count = 10;
    cfg->max_persistent_file_size = REPLAY_MIB;
    cfg->max_persistent_log_count = 65536;
    cfg->persistent_max_bytes = 10 * REPLAY_MIB;
    cfg->persistent_max_records = 65536;
    cfg->persistent_max_segments = 10;
    cfg->persistent_overflow_policy = VE_TLS_POVERFLOW_REJECT_NEW;
    return 0;
}

static ve_tls_producer * open_customer_wal(ve_tls_config * cfg, mock_state * state) {
    cfg->http_client.do_request = mock_http;
    cfg->http_client.free_response = free_http;
    cfg->http_client.user_data = state;
    cfg->retry_policy.max_attempts = 1;
    ve_tls_producer * producer = ve_tls_producer_create_exclusive_persistence(cfg, sizeof(*cfg));
    if (producer) ve_tls_producer_set_send_done_v2(producer, send_done, state);
    return producer;
}

static int test_legacy_backlog(int records, int hold_http, int close_early, wal_fault fault) {
    int failed = 0;
    char dir[PATH_MAX] = {0};
    char checkpoint_path[PATH_MAX];
    ve_tls_producer * producer = NULL;
    ve_tls_thread * recovery = NULL;
    ve_tls_thread * close_thread = NULL;
    ve_tls_config cfg;
    ve_tls_metrics metrics;
    ve_tls_checkpoint_state checkpoint = {.acked_log_id = REPLAY_PREFIX, .last_segment_id = 1};
    backlog_replay_state state = {.hold_first_request = hold_http};
    REQUIRE(make_dir(dir, sizeof(dir)) == 0);
    REQUIRE(snprintf(checkpoint_path, sizeof(checkpoint_path), "%s/checkpoint", dir) > 0);
    REQUIRE(customer_wal_config(&cfg, dir) == 0);
    replay_platform = cfg.platform;
    cfg.http_client.do_request = backlog_http;
    cfg.http_client.free_response = free_http;
    cfg.http_client.user_data = &state;
    cfg.metrics_sink.emit = backlog_metrics;
    cfg.metrics_sink.user_param = &state;

    producer = ve_tls_producer_create_versioned(&cfg, sizeof(cfg), VE_TLS_CONFIG_VERSION_CURRENT);
    REQUIRE(producer != NULL && write_legacy_backlog(producer, records) == 0);
    REQUIRE(close_producer(&producer) == 0 && atomic_load(&state.requests) == 0);
    REQUIRE(ve_tls_checkpoint_save(&cfg.platform, checkpoint_path, &checkpoint) == 0);
    if (fault != WAL_FAULT_NONE) {
        /* The transport gate forces the first recovery pass to pause before
           this segment. Arm the failure only after the store has opened. */
        install_wal_fault(&cfg, "seg-000009.log", 0);
    }

    atomic_store(&replay_builder_waiting, 0);
    atomic_store(&replay_release_builder, hold_http);
    cfg.platform.thread_create = gate_replay_builder;
    producer = ve_tls_producer_create_exclusive_persistence(&cfg, sizeof(cfg));
    REQUIRE(producer != NULL && wait_value(&replay_builder_waiting, 1, 5000) == 0);
    REQUIRE(producer->ingress_queue_cap == 16);
    ve_tls_producer_set_send_done_v2(producer, backlog_send_done, &state);
    int expected = records;
    if (hold_http) {
        atomic_store(&replay_finished, 0);
        recovery = replay_platform.thread_create(recover_backlog, producer);
        REQUIRE(recovery != NULL);
        REQUIRE(wait_value(&state.requests, 1, 5000) == 0);
        REQUIRE(wait_value(&state.budget_wait, 1, 5000) == 0);
        REQUIRE(wait_value(&replay_finished, 1, 2000) == 0);
        REQUIRE(ve_tls_producer_get_buffered_bytes(producer) <= 8 * REPLAY_MIB);
        atomic_store(&wal_fault_pending, fault);
        replay_platform.thread_join(recovery);
        recovery = NULL;
        REQUIRE(replay_result == VE_TLS_OK);

        int64_t live_id = 0;
        ve_tls_kv live = {"message", "event created during recovery"};
        REQUIRE(ve_tls_producer_add_log_kv_with_id(producer, 1700000000000LL,
            &live, 1, 0, &live_id) == VE_TLS_OK && live_id == records + 1);
        expected++;
        REQUIRE(atomic_load(&state.requests) == 1 && atomic_load(&state.delivered_count) == 0);
        if (close_early) {
            atomic_store(&state.closing, 0);
            close_thread = replay_platform.thread_create(close_during_recovery, producer);
            REQUIRE(close_thread != NULL && wait_value(&state.closing, 1, 5000) == 0);
            cfg.platform.mutex_lock(producer->mutex);
            while (producer->accepting) cfg.platform.cond_wait(producer->cond, producer->mutex);
            cfg.platform.mutex_unlock(producer->mutex);
        }
        atomic_store(&state.release_http, 1);
        if (close_early) {
            replay_platform.thread_join(close_thread);
            close_thread = NULL;
            REQUIRE(close_result == VE_TLS_OK);
            ve_tls_producer_destroy(producer);
            producer = NULL;
            REQUIRE(atomic_load(&state.delivered_count) > 0 &&
                atomic_load(&state.delivered_count) < expected - REPLAY_PREFIX);

            producer = ve_tls_producer_create_exclusive_persistence(&cfg, sizeof(cfg));
            REQUIRE(producer != NULL);
            ve_tls_producer_set_send_done_v2(producer, backlog_send_done, &state);
            REQUIRE(ve_tls_producer_recover(producer) == VE_TLS_OK);
        }
        REQUIRE(wait_value(&state.delivered_count, expected - REPLAY_PREFIX, 8000) == 0);
        REQUIRE(atomic_load(&wal_fault_pending) == WAL_FAULT_NONE);
    } else {
        REQUIRE(ve_tls_producer_recover(producer) == VE_TLS_OK);
        REQUIRE(atomic_load(&state.requests) == 0);
    }
    ve_tls_producer_get_metrics(producer, &metrics);
    REQUIRE(metrics.logs_dropped_total == 0);
    if (!close_early) REQUIRE(metrics.logs_enqueued_total == (uint64_t)(expected - REPLAY_PREFIX));
    atomic_store(&replay_release_builder, 1);
    REQUIRE(close_producer(&producer) == 0);
    REQUIRE(atomic_load(&state.wire_records) == expected - REPLAY_PREFIX && !atomic_load(&state.failed));
    for (int id = 1; id <= expected; ++id) {
        REQUIRE(atomic_load(&state.delivered[id]) == (id > REPLAY_PREFIX));
    }
    REQUIRE(ve_tls_checkpoint_load(&cfg.platform, checkpoint_path, &checkpoint) == 0);
    REQUIRE(checkpoint.acked_log_id == expected);

    int requests = atomic_load(&state.requests);
    producer = ve_tls_producer_create_exclusive_persistence(&cfg, sizeof(cfg));
    REQUIRE(producer != NULL && ve_tls_producer_recover(producer) == VE_TLS_OK);
    REQUIRE(close_producer(&producer) == 0 && atomic_load(&state.requests) == requests);
cleanup:
    atomic_store(&wal_fault_pending, WAL_FAULT_NONE);
    atomic_store(&replay_release_builder, 1);
    atomic_store(&state.release_http, 1);
    if (recovery) replay_platform.thread_join(recovery);
    if (close_thread) replay_platform.thread_join(close_thread);
    if (producer) ve_tls_producer_destroy(producer);
    if (dir[0]) remove_dir(dir);
    return failed ? -1 : 0;
}

static int test_legacy_backlog_with_builder_paused(void) {
    return test_legacy_backlog(REPLAY_RECORDS, 0, 0, WAL_FAULT_NONE);
}

static int test_legacy_backlog_with_transport_paused(void) {
    return test_legacy_backlog(REPLAY_MAX_RECORDS, 1, 0, WAL_FAULT_NONE);
}

static int test_legacy_backlog_close_then_reopen(void) {
    return test_legacy_backlog(REPLAY_MAX_RECORDS, 1, 1, WAL_FAULT_NONE);
}

static int test_background_recovery_retries_segment_stat(void) {
    return test_legacy_backlog(REPLAY_MAX_RECORDS, 1, 0, WAL_FAULT_STAT);
}

static int test_background_recovery_retries_segment_open(void) {
    return test_legacy_backlog(REPLAY_MAX_RECORDS, 1, 0, WAL_FAULT_OPEN);
}

static int test_background_recovery_retries_segment_read(void) {
    return test_legacy_backlog(REPLAY_MAX_RECORDS, 1, 0, WAL_FAULT_READ);
}

static size_t read_wal_fixture(const char * path, unsigned char * bytes, size_t capacity) {
    FILE * file = fopen(path, "rb");
    if (!file) return 0;
    size_t size = fread(bytes, 1, capacity, file);
    int complete = feof(file) && !ferror(file);
    return fclose(file) == 0 && complete ? size : 0;
}

/* Fail the first synchronous pass after the exclusive native handle is open.
 * No new add or second recover may be needed to start the retry. */
static int test_initial_recovery_retries_io(wal_fault fault) {
    enum { RECORDS = 32 };
    int failed = 0;
    char dir[PATH_MAX] = {0}, segment[PATH_MAX], checkpoint_path[PATH_MAX];
    ve_tls_config cfg;
    ve_tls_producer * producer = NULL;
    backlog_replay_state state = {0};
    ve_tls_checkpoint_state checkpoint = {.acked_log_id = REPLAY_PREFIX, .last_segment_id = 1};
    unsigned char * before = NULL, * after = NULL;
    int64_t ack = 0;
    REQUIRE(make_dir(dir, sizeof(dir)) == 0 && customer_wal_config(&cfg, dir) == 0);
    REQUIRE(snprintf(segment, sizeof(segment), "%s/seg-000001.log", dir) > 0);
    REQUIRE(snprintf(checkpoint_path, sizeof(checkpoint_path), "%s/checkpoint", dir) > 0);
    cfg.http_client.do_request = backlog_http;
    cfg.http_client.free_response = free_http;
    cfg.http_client.user_data = &state;
    producer = ve_tls_producer_create_exclusive_persistence(&cfg, sizeof(cfg));
    REQUIRE(producer != NULL && write_legacy_backlog(producer, RECORDS) == 0);
    REQUIRE(close_producer(&producer) == 0 && atomic_load(&state.requests) == 0);
    REQUIRE(ve_tls_checkpoint_save(&cfg.platform, checkpoint_path, &checkpoint) == 0);
    before = malloc(REPLAY_MIB + 1);
    after = malloc(REPLAY_MIB + 1);
    REQUIRE(before != NULL && after != NULL);
    size_t size = read_wal_fixture(segment, before, REPLAY_MIB + 1);
    REQUIRE(size > 0 && size < REPLAY_MIB);

    install_wal_fault(&cfg, "seg-000001.log", 0);
    atomic_store(&replay_builder_waiting, 0);
    atomic_store(&replay_release_builder, 0);
    cfg.platform.thread_create = gate_replay_builder;
    producer = ve_tls_producer_create_exclusive_persistence(&cfg, sizeof(cfg));
    REQUIRE(producer != NULL && wait_value(&replay_builder_waiting, 1, 5000) == 0);
    ve_tls_producer_set_send_done_v2(producer, backlog_send_done, &state);
    atomic_store(&wal_fault_pending, fault);
    REQUIRE(ve_tls_producer_recover(producer) == VE_TLS_OK);
    REQUIRE(atomic_load(&wal_fault_pending) == WAL_FAULT_NONE);
    REQUIRE(read_wal_fixture(segment, after, REPLAY_MIB + 1) == size && memcmp(before, after, size) == 0);
    REQUIRE(atomic_load(&state.requests) == 0 && atomic_load(&state.delivered_count) == 0);
    REQUIRE(checkpoint_ack(dir, &ack) == 0 && ack == REPLAY_PREFIX);

    atomic_store(&replay_release_builder, 1);
    REQUIRE(wait_value(&state.delivered_count, RECORDS - REPLAY_PREFIX, 10000) == 0);
    REQUIRE(wait_checkpoint_ack(dir, RECORDS) == 0);
    REQUIRE(atomic_load(&state.wire_records) == RECORDS - REPLAY_PREFIX && !atomic_load(&state.failed));
    for (int id = 1; id <= RECORDS; id++) {
        REQUIRE(atomic_load(&state.delivered[id]) == (id > REPLAY_PREFIX));
    }
    REQUIRE(close_producer(&producer) == 0);
    int requests = atomic_load(&state.requests);
    producer = ve_tls_producer_create_exclusive_persistence(&cfg, sizeof(cfg));
    REQUIRE(producer != NULL && ve_tls_producer_recover(producer) == VE_TLS_OK);
    REQUIRE(close_producer(&producer) == 0 && atomic_load(&state.requests) == requests);
    REQUIRE(checkpoint_ack(dir, &ack) == 0 && ack == RECORDS);
cleanup:
    atomic_store(&wal_fault_pending, WAL_FAULT_NONE);
    atomic_store(&replay_release_builder, 1);
    if (producer) ve_tls_producer_destroy(producer);
    free(before);
    free(after);
    if (dir[0]) remove_dir(dir);
    return failed ? -1 : 0;
}

static int test_initial_recovery_retries_segment_stat(void) {
    return test_initial_recovery_retries_io(WAL_FAULT_STAT);
}

static int test_initial_recovery_retries_segment_open(void) {
    return test_initial_recovery_retries_io(WAL_FAULT_OPEN);
}

static int test_initial_recovery_retries_segment_read(void) {
    return test_initial_recovery_retries_io(WAL_FAULT_READ);
}

static int test_wal_scan_preserves_records(int closed_segment, wal_fault fault) {
    static const unsigned char payload[] = "real-persistent-wal-record";
    int failed = 0;
    char dir[PATH_MAX] = {0}, first_segment[PATH_MAX], checkpoint_path[PATH_MAX];
    unsigned char before[512], after[512];
    ve_tls_config cfg;
    ve_tls_producer * producer = NULL;
    mock_state state;
    unsigned ids = 0;
    ve_tls_create_status status = VE_TLS_CREATE_OK;
    init_mock(&state, 0, 0);
    REQUIRE(make_dir(dir, sizeof(dir)) == 0 && customer_wal_config(&cfg, dir) == 0);
    REQUIRE(snprintf(first_segment, sizeof(first_segment), "%s/seg-000001.log", dir) > 0);
    REQUIRE(snprintf(checkpoint_path, sizeof(checkpoint_path), "%s/checkpoint", dir) > 0);
    cfg.max_persistent_log_count = closed_segment ? 2 : 3;
    producer = open_customer_wal(&cfg, &state);
    REQUIRE(producer != NULL);
    REQUIRE(ve_tls_persistent_append(producer->persistent, 1, NULL, payload, sizeof(payload) - 1) == 0);
    int64_t second_record_offset = (int64_t)producer->persistent->store.active_size;
    for (int id = 2; id <= 3; id++) {
        REQUIRE(ve_tls_persistent_append(producer->persistent, id, NULL, payload, sizeof(payload) - 1) == 0);
    }
    REQUIRE(close_producer(&producer) == 0);
    ve_tls_checkpoint_state checkpoint = {.acked_log_id = 1, .last_segment_id = 1};
    REQUIRE(ve_tls_checkpoint_save(&cfg.platform, checkpoint_path, &checkpoint) == 0);
    size_t size = read_wal_fixture(first_segment, before, sizeof(before));
    REQUIRE(size > (size_t)second_record_offset);
    install_wal_fault(&cfg, "seg-000001.log", second_record_offset);
    atomic_store(&wal_fault_pending, fault);
    producer = ve_tls_producer_create_exclusive_persistence_with_status(&cfg, sizeof(cfg), &status);
    REQUIRE(atomic_load(&wal_fault_pending) == WAL_FAULT_NONE);
    REQUIRE(read_wal_fixture(first_segment, after, sizeof(after)) == size && memcmp(before, after, size) == 0);
    REQUIRE(producer == NULL && (int)status == 7); /* WAL_OPEN_IO_ERROR */
    producer = open_customer_wal(&cfg, &state);
    REQUIRE(producer != NULL && ve_tls_persistent_recover(producer->persistent, drop_recovered_record, &ids) == 0);
    REQUIRE(ids == ((1u << 2) | (1u << 3)));
cleanup:
    atomic_store(&wal_fault_pending, WAL_FAULT_NONE);
    if (producer) ve_tls_producer_destroy(producer);
    if (dir[0]) remove_dir(dir);
    return failed ? -1 : 0;
}

static int test_active_wal_scan_preserves_records_on_read_error(void) {
    return test_wal_scan_preserves_records(0, WAL_FAULT_READ);
}

static int test_closed_wal_scan_preserves_unacked_records_on_unexpected_eof(void) {
    return test_wal_scan_preserves_records(1, WAL_FAULT_EOF);
}

static int test_wal_rotation_open_failure_allows_next_append(void) {
    int failed = 0;
    char dir[PATH_MAX] = {0};
    ve_tls_config cfg;
    ve_tls_producer * producer = NULL;
    mock_state state;
    int64_t id = 0;
    init_mock(&state, 0, 1);
    REQUIRE(make_dir(dir, sizeof(dir)) == 0 && customer_wal_config(&cfg, dir) == 0);
    cfg.max_persistent_log_count = 1;
    cfg.compress_type = "none";
    install_wal_fault(&cfg, "seg-000002.log", 0);
    producer = open_customer_wal(&cfg, &state);
    REQUIRE(producer != NULL && add(producer, A, &id) == 0 && id == 1);
    REQUIRE(wait_value(&state.block_entered, 1, 5000) == 0);
    atomic_store(&wal_fault_pending, WAL_FAULT_OPEN);
    ve_tls_kv kv = {"event_id", markers[B]};
    REQUIRE(ve_tls_producer_add_log_kv_with_id(producer, 1700000000000LL, &kv, 1, 1, &id) == VE_TLS_PERSISTENT_ERROR);
    REQUIRE(id == 0 && atomic_load(&wal_fault_pending) == WAL_FAULT_NONE);
    REQUIRE(add(producer, C, &id) == 0 && id == 2);
    atomic_store(&state.release_block, 1);
    REQUIRE(close_producer(&producer) == 0);
    REQUIRE(hit_count(&state, A) == 1 && hit_count(&state, B) == 0 && hit_count(&state, C) == 1);
    REQUIRE(checkpoint_ack(dir, &id) == 0 && id == 2);
cleanup:
    atomic_store(&wal_fault_pending, WAL_FAULT_NONE);
    atomic_store(&state.release_block, 1);
    if (producer) ve_tls_producer_destroy(producer);
    if (dir[0]) remove_dir(dir);
    return failed ? -1 : 0;
}

typedef enum {
    CHECKPOINT_READ_PREFIX,
    CHECKPOINT_READ_RANGES,
    CHECKPOINT_MISSING,
    CHECKPOINT_BAD_PREFIX
} checkpoint_fault;

static int test_checkpoint_after_reclaim(checkpoint_fault fault) {
    static const unsigned char payload[] = "real-persistent-wal-record";
    int failed = 0;
    char dir[PATH_MAX] = {0}, checkpoint_path[PATH_MAX], first_segment[PATH_MAX];
    unsigned char before[512], after[512];
    ve_tls_config cfg;
    ve_tls_producer * producer = NULL;
    mock_state state;
    unsigned ids = 0, expected = 1u << 2;
    ve_tls_create_status status = VE_TLS_CREATE_OK;
    init_mock(&state, 0, 0);
    REQUIRE(make_dir(dir, sizeof(dir)) == 0 && customer_wal_config(&cfg, dir) == 0);
    REQUIRE(snprintf(first_segment, sizeof(first_segment), "%s/seg-000001.log", dir) > 0);
    REQUIRE(snprintf(checkpoint_path, sizeof(checkpoint_path), "%s/checkpoint", dir) > 0);
    cfg.max_persistent_log_count = 1;
    producer = open_customer_wal(&cfg, &state);
    REQUIRE(producer != NULL);
    for (int id = 1; id <= 3; id++) {
        REQUIRE(ve_tls_persistent_append(producer->persistent, id, NULL, payload, sizeof(payload) - 1) == 0);
    }
    REQUIRE(ve_tls_persistent_ack_range(producer->persistent, 1, 1) == 0);
    REQUIRE(ve_tls_persistent_flush(producer->persistent) == 0 && close_producer(&producer) == 0);
    REQUIRE(access(first_segment, F_OK) != 0);
    ve_tls_checkpoint_state checkpoint;
    REQUIRE(ve_tls_checkpoint_load(&cfg.platform, checkpoint_path, &checkpoint) == 0);
    size_t prefix_size = read_wal_fixture(checkpoint_path, before, sizeof(before));
    REQUIRE(prefix_size > 0 && checkpoint.acked_log_id == 1 && checkpoint.last_segment_id == 3);
    const ve_tls_checkpoint_range range = {3, 3};
    REQUIRE(ve_tls_checkpoint_save_ranges(&cfg.platform, checkpoint_path, &checkpoint, &range, 1) == 0);
    size_t size = read_wal_fixture(checkpoint_path, before, sizeof(before));
    REQUIRE(size > prefix_size);
    if (fault == CHECKPOINT_READ_PREFIX || fault == CHECKPOINT_READ_RANGES) {
        install_wal_fault(&cfg, "checkpoint", fault == CHECKPOINT_READ_PREFIX ? 0 : (int64_t)prefix_size);
        atomic_store(&wal_fault_pending, WAL_FAULT_READ);
        producer = ve_tls_producer_create_exclusive_persistence_with_status(&cfg, sizeof(cfg), &status);
        REQUIRE(atomic_load(&wal_fault_pending) == WAL_FAULT_NONE);
        REQUIRE(read_wal_fixture(checkpoint_path, after, sizeof(after)) == size && memcmp(before, after, size) == 0);
        REQUIRE(producer == NULL && (int)status == 7); /* WAL_OPEN_IO_ERROR */
    } else {
        if (fault == CHECKPOINT_MISSING) {
            REQUIRE(unlink(checkpoint_path) == 0);
        } else {
            FILE * file = fopen(checkpoint_path, "r+b");
            REQUIRE(file != NULL);
            int wrote = fputc(before[0] ^ 1, file);
            REQUIRE(fclose(file) == 0 && wrote != EOF);
        }
        /* With no trustworthy checkpoint, all surviving records are pending. */
        expected |= 1u << 3;
    }
    producer = open_customer_wal(&cfg, &state);
    REQUIRE(producer != NULL && producer->persistent->store.active_segment_id == 3);
    REQUIRE(producer->persistent->recovered_max_log_id == 3);
    REQUIRE(ve_tls_persistent_recover(producer->persistent, drop_recovered_record, &ids) == 0 && ids == expected);
    REQUIRE(ve_tls_checkpoint_load(&cfg.platform, checkpoint_path, &checkpoint) == 0 &&
        checkpoint.last_segment_id == 3);
cleanup:
    atomic_store(&wal_fault_pending, WAL_FAULT_NONE);
    if (producer) ve_tls_producer_destroy(producer);
    if (dir[0]) remove_dir(dir);
    return failed ? -1 : 0;
}

static int test_checkpoint_prefix_read_error_preserves_checkpoint(void) {
    return test_checkpoint_after_reclaim(CHECKPOINT_READ_PREFIX);
}

static int test_checkpoint_ranges_read_error_preserves_checkpoint(void) {
    return test_checkpoint_after_reclaim(CHECKPOINT_READ_RANGES);
}

static int test_missing_checkpoint_recovers_remaining_segments(void) {
    return test_checkpoint_after_reclaim(CHECKPOINT_MISSING);
}

static int test_corrupt_checkpoint_recovers_remaining_segments(void) {
    return test_checkpoint_after_reclaim(CHECKPOINT_BAD_PREFIX);
}

typedef enum {
    LIMIT_WAL_RECORDS,
    LIMIT_WAL_BYTES,
    LIMIT_WAL_SEGMENTS
} wal_limit;

static int test_fully_acked_active_segment(wal_limit limit) {
    int failed = 0;
    char dir[PATH_MAX] = {0};
    ve_tls_config cfg;
    mock_state initial, reopened;
    ve_tls_producer * producer = NULL;
    int64_t id = 0, ack = 0;
    init_mock(&initial, 0, 0);
    init_mock(&reopened, 0, 0);
    REQUIRE(make_dir(dir, sizeof(dir)) == 0 && customer_wal_config(&cfg, dir) == 0);
    atomic_store(&drop_now_ms, 1000);
    cfg.platform.time_ms = drop_fake_time_ms;
    if (limit == LIMIT_WAL_BYTES) {
        /* Three small records fit; four exceed the total byte cap. */
        cfg.persistent_max_bytes = 550;
    } else {
        cfg.max_persistent_log_count = 3;
        if (limit == LIMIT_WAL_RECORDS) cfg.persistent_max_records = 3;
        if (limit == LIMIT_WAL_SEGMENTS) cfg.persistent_max_segments = 1;
    }
    producer = open_customer_wal(&cfg, &initial);
    REQUIRE(producer != NULL);
    for (int i = A; i <= C; i++) {
        REQUIRE(add(producer, i, &id) == 0 && id == i + 1);
        REQUIRE(wait_result(&initial, id, 1) == 0);
    }
    REQUIRE(checkpoint_ack(dir, &ack) == 0 && ack == 0);
    REQUIRE(add(producer, D, &id) == 0 && id == 4);
    REQUIRE(checkpoint_ack(dir, &ack) == 0 && ack == 3);
    REQUIRE(wait_result(&initial, id, 1) == 0);
    REQUIRE(producer->persistent->current_records == 1 &&
        producer->persistent->current_segments == 1 &&
        producer->persistent->current_bytes <= (uint64_t)cfg.persistent_max_bytes);
    REQUIRE(close_producer(&producer) == 0);
    for (int i = A; i <= D; i++) REQUIRE(hit_count(&initial, i) == 1);
    producer = open_customer_wal(&cfg, &reopened);
    REQUIRE(producer != NULL && ve_tls_producer_recover(producer) == VE_TLS_OK);
    REQUIRE(add(producer, D, &id) == 0 && id == 5);
    REQUIRE(close_producer(&producer) == 0);
    REQUIRE(atomic_load(&reopened.calls) == 1 && hit_count(&reopened, D) == 1);
    REQUIRE(checkpoint_ack(dir, &ack) == 0 && ack == 5);
cleanup:
    if (producer) ve_tls_producer_destroy(producer);
    if (dir[0]) remove_dir(dir);
    return failed ? -1 : 0;
}

static int test_full_acked_record_limit(void) {
    return test_fully_acked_active_segment(LIMIT_WAL_RECORDS);
}

static int test_full_acked_byte_limit(void) {
    return test_fully_acked_active_segment(LIMIT_WAL_BYTES);
}

static int test_full_acked_segment_limit(void) {
    return test_fully_acked_active_segment(LIMIT_WAL_SEGMENTS);
}

typedef struct {
    ve_tls_persistent * persistent;
    int64_t seen[2];
    size_t count;
} reuse_during_replay;

static int ack_and_reuse_record(ve_tls_persistent_record * record, void * user) {
    reuse_during_replay * replay = user;
    if (replay->count == 2) return -1;
    replay->seen[replay->count++] = record->log_id;
    if (record->log_id != 1) return 0;
    if (ve_tls_persistent_ack_completed_range(replay->persistent, 1, 1) != 0) return -1;
    return ve_tls_persistent_append(replay->persistent, 2, NULL, record->payload, record->payload_size);
}

static int test_active_reuse_preserves_reader_position(void) {
    int failed = 0;
    char dir[PATH_MAX] = {0};
    ve_tls_config cfg;
    mock_state state;
    ve_tls_producer * producer = NULL;
    static const unsigned char payload[] = "record adjacent to active reuse";
    ve_tls_persistent_recovery_position position = {0}, end = {0};
    init_mock(&state, 0, 0);
    REQUIRE(make_dir(dir, sizeof(dir)) == 0 && customer_wal_config(&cfg, dir) == 0);
    cfg.persistent_max_records = 1;
    cfg.persistent_max_segments = 1;
    producer = open_customer_wal(&cfg, &state);
    REQUIRE(producer != NULL);
    reuse_during_replay replay = {.persistent = producer->persistent};
    REQUIRE(ve_tls_persistent_append(replay.persistent, 1, NULL, payload, sizeof(payload) - 1) == 0);
    REQUIRE(ve_tls_persistent_recover_from(replay.persistent, &position, &end, 0,
        ack_and_reuse_record, &replay) == 0);
    REQUIRE(replay.count == 1 && replay.seen[0] == 1);
    end = (ve_tls_persistent_recovery_position){0};
    REQUIRE(ve_tls_persistent_recover_from(replay.persistent, &position, &end, 0,
        ack_and_reuse_record, &replay) == 0);
    REQUIRE(replay.count == 2 && replay.seen[1] == 2);
cleanup:
    if (producer) ve_tls_producer_destroy(producer);
    if (dir[0]) remove_dir(dir);
    return failed ? -1 : 0;
}

static int test_active_reuse_waits_for_checkpoint(void) {
    int failed = 0;
    char dir[PATH_MAX] = {0};
    ve_tls_config cfg;
    mock_state state;
    ve_tls_producer * producer = NULL;
    int64_t id = 0, ack = 0;
    init_mock(&state, 0, 0);
    REQUIRE(make_dir(dir, sizeof(dir)) == 0 && customer_wal_config(&cfg, dir) == 0);
    cfg.persistent_max_records = 1;
    drop_real_platform = cfg.platform;
    cfg.platform.path_rename = drop_fault_rename;
    cfg.platform.time_ms = drop_fake_time_ms;
    atomic_store(&drop_now_ms, 1000);
    atomic_store(&drop_failed_checkpoint_renames, 0);
    producer = open_customer_wal(&cfg, &state);
    REQUIRE(producer != NULL && add(producer, A, &id) == 0 && id == 1);
    REQUIRE(wait_result(&state, id, 1) == 0);
    uint64_t original_size = producer->persistent->store.active_size;
    atomic_store(&drop_fail_checkpoint_rename, 1);
    ve_tls_kv kv = {"event_id", markers[B]};
    REQUIRE(ve_tls_producer_add_log_kv_with_id(producer, 1700000000000LL, &kv, 1, 1, &id) == VE_TLS_PERSISTENT_ERROR);
    REQUIRE(id == 0 && atomic_load(&drop_failed_checkpoint_renames) == 1);
    REQUIRE(producer->persistent->store.active_size == original_size &&
            producer->persistent->current_records == 1);
    REQUIRE(checkpoint_ack(dir, &ack) == 0 && ack == 0);
    atomic_store(&drop_fail_checkpoint_rename, 0);
    REQUIRE(add(producer, C, &id) == 0 && id == 2);
    REQUIRE(close_producer(&producer) == 0 && checkpoint_ack(dir, &ack) == 0 && ack == 2);
    REQUIRE(hit_count(&state, A) == 1 && hit_count(&state, B) == 0 && hit_count(&state, C) == 1);
cleanup:
    atomic_store(&drop_fail_checkpoint_rename, 0);
    if (producer) ve_tls_producer_destroy(producer);
    if (dir[0]) remove_dir(dir);
    return failed ? -1 : 0;
}

static int test_reclaim_keeps_unacked_segment_discoverable(void) {
    int failed = 0;
    char dir[PATH_MAX] = {0};
    ve_tls_config cfg;
    mock_state initial, reopened;
    ve_tls_producer * producer = NULL;
    int64_t id = 0, ack = 0;
    init_mock(&initial, 0, 0);
    init_mock(&reopened, 0, 0);
    REQUIRE(make_dir(dir, sizeof(dir)) == 0 && customer_wal_config(&cfg, dir) == 0);
    cfg.max_persistent_log_count = 1;
    cfg.persistent_max_segments = 2;
    producer = open_customer_wal(&cfg, &initial);
    REQUIRE(producer != NULL && add(producer, A, &id) == 0 && id == 1);
    REQUIRE(wait_result(&initial, id, 1) == 0);
    REQUIRE(ve_tls_producer_flush(producer) == VE_TLS_OK);
    REQUIRE(checkpoint_ack(dir, &ack) == 0 && ack == 1);

    /* Append without scheduling delivery. Crossing the soft segment
       watermark can delete the file named by the previous checkpoint. */
    const unsigned char raw[] = "unacked after segment rotation";
    REQUIRE(ve_tls_persistent_append(producer->persistent, 2, NULL, raw, sizeof(raw) - 1) == 0);
    REQUIRE(producer->persistent->store.active_segment_id == 2 && producer->persistent->current_segments == 1);
    REQUIRE(close_producer(&producer) == 0 && checkpoint_ack(dir, &ack) == 0 && ack == 1);
    producer = open_customer_wal(&cfg, &reopened);
    REQUIRE(producer != NULL && producer->persistent->recovered_max_log_id == 2);
    REQUIRE(producer->persistent->current_records == 1);
cleanup:
    if (producer) ve_tls_producer_destroy(producer);
    if (dir[0]) remove_dir(dir);
    return failed ? -1 : 0;
}

static int test_rejected_append_keeps_ids_contiguous(void) {
    int failed = 0;
    char dir[PATH_MAX] = {0};
    ve_tls_config cfg;
    mock_state initial, reopened;
    ve_tls_producer * producer = NULL;
    int64_t id = 0, ack = 0;
    init_mock(&initial, 0, 1);
    init_mock(&reopened, 0, 0);
    REQUIRE(make_dir(dir, sizeof(dir)) == 0 && customer_wal_config(&cfg, dir) == 0);
    cfg.max_persistent_log_count = 2;
    cfg.persistent_max_records = 4;
    producer = open_customer_wal(&cfg, &initial);
    REQUIRE(producer != NULL && add(producer, A, &id) == 0);
    REQUIRE(wait_value(&initial.block_entered, 1, 5000) == 0);
    for (int i = B; i <= D; i++) REQUIRE(add(producer, i, &id) == 0 && id == i + 1);
    ve_tls_kv rejected = {"message", "rejected before WAL write"};
    REQUIRE(ve_tls_producer_add_log_kv_with_id(producer, 1700000000000LL, &rejected, 1, 1, &id) == VE_TLS_DROP_ERROR);
    REQUIRE(id == 0 && producer->persistent->current_records == 4);
    atomic_store(&initial.release_block, 1);
    for (int i = 1; i <= 4; i++) REQUIRE(wait_result(&initial, i, 1) == 0);
    REQUIRE(ve_tls_producer_flush(producer) == VE_TLS_OK);
    for (int i = A; i <= D; i++) REQUIRE(add(producer, i, &id) == 0 && id == i + 5);
    REQUIRE(close_producer(&producer) == 0);
    REQUIRE(checkpoint_ack(dir, &ack) == 0 && ack == 8);
    producer = open_customer_wal(&cfg, &reopened);
    REQUIRE(producer != NULL && ve_tls_producer_recover(producer) == VE_TLS_OK);
    REQUIRE(add(producer, D, &id) == 0 && id == 9);
    REQUIRE(close_producer(&producer) == 0);
    for (int i = A; i <= D; i++) REQUIRE(hit_count(&initial, i) == 2);
    REQUIRE(atomic_load(&reopened.calls) == 1 && hit_count(&reopened, D) == 1);
cleanup:
    atomic_store(&initial.release_block, 1);
    if (producer) ve_tls_producer_destroy(producer);
    if (dir[0]) remove_dir(dir);
    return failed ? -1 : 0;
}

static _Atomic(ve_tls_file *) fail_sync_file;
static _Atomic int sync_failed_once;
static _Atomic int sync_retry_waiting;
static _Atomic int sync_retry_release;
static _Atomic int sync_retry_timeout;
static _Atomic int sync_succeeded;
static int sync_segment_once(ve_tls_file * file) {
    int watched = atomic_load(&fail_sync_file) == file;
    if (watched) {
        int expected = 0;
        if (atomic_compare_exchange_strong(&sync_failed_once, &expected, 1)) return -1;
        atomic_store(&sync_retry_waiting, 1);
        if (wait_value(&sync_retry_release, 1, 10000) != 0) {
            atomic_store(&sync_retry_timeout, 1);
            return -1;
        }
    }
    int rc = replay_platform.file_fsync(file);
    if (watched && rc == 0) atomic_store(&sync_succeeded, 1);
    return rc;
}

typedef struct {
    ve_tls_producer * producer;
    int64_t id;
    ve_tls_result result;
    _Atomic int finished;
} sync_append_state;

static void * add_with_sync_failure(void * arg) {
    sync_append_state * state = arg;
    ve_tls_kv kv = {"event_id", markers[A]};
    state->result = ve_tls_producer_add_log_kv_hashkey_with_id(state->producer, 1700000000000LL,
        hash_keys[A], &kv, 1, 1, &state->id);
    atomic_store(&state->finished, 1);
    return NULL;
}

static int test_uncertain_sync_preserves_unacked_id(void) {
    int failed = 0;
    char dir[PATH_MAX] = {0}, segment[PATH_MAX];
    unsigned char before[512], after[512];
    ve_tls_config cfg;
    mock_state initial, reopened;
    ve_tls_producer * producer = NULL;
    ve_tls_thread * append = NULL;
    sync_append_state pending = {0};
    ve_tls_persistent_record disk_record = {0};
    int64_t id = 0, ack = 0;
    init_mock(&initial, 0, 0);
    init_mock(&reopened, 0, 0);
    REQUIRE(make_dir(dir, sizeof(dir)) == 0 && customer_wal_config(&cfg, dir) == 0);
    REQUIRE(snprintf(segment, sizeof(segment), "%s/seg-000001.log", dir) > 0);
    cfg.compress_type = "none";
    cfg.log_count_per_package = 1;
    cfg.flush_interval_ms = 0;
    replay_platform = cfg.platform;
    cfg.platform.file_fsync = sync_segment_once;
    producer = open_customer_wal(&cfg, &initial);
    REQUIRE(producer != NULL);
    atomic_store(&sync_failed_once, 0);
    atomic_store(&sync_retry_waiting, 0);
    atomic_store(&sync_retry_release, 0);
    atomic_store(&sync_retry_timeout, 0);
    atomic_store(&sync_succeeded, 0);
    initial.required_sync = &sync_succeeded;
    atomic_store(&fail_sync_file, producer->persistent->store.active_file);
    pending.producer = producer;
    append = replay_platform.thread_create(add_with_sync_failure, &pending);
    REQUIRE(append != NULL && wait_value(&pending.finished, 1, 5000) == 0);
    replay_platform.thread_join(append);
    append = NULL;
    REQUIRE(pending.result == VE_TLS_PERSISTENT_ERROR && pending.id == 1);
    REQUIRE(atomic_load(&sync_failed_once) == 1);
    size_t size = read_wal_fixture(segment, before, sizeof(before));
    REQUIRE(size > 0 && count_marker(before, size, markers[A]) == 1);
    REQUIRE(ve_tls_persistent_record_decode(before, size, &disk_record) == 0 && disk_record.log_id == 1 &&
        count_marker(disk_record.payload, disk_record.payload_size, markers[A]) == 1);
    REQUIRE(wait_value(&sync_retry_waiting, 1, 5000) == 0);
    REQUIRE(read_wal_fixture(segment, after, sizeof(after)) == size && memcmp(before, after, size) == 0);
    REQUIRE(atomic_load(&initial.calls) == 0 && atomic_load(&initial.ok[1]) == 0);
    REQUIRE(checkpoint_ack(dir, &ack) == 0 && ack == 0);

    atomic_store(&sync_retry_release, 1);
    REQUIRE(wait_result(&initial, 1, 1) == 0 && wait_checkpoint_ack(dir, 1) == 0);
    REQUIRE(atomic_load(&sync_succeeded) && !atomic_load(&initial.send_before_sync) &&
        hit_count(&initial, A) == 1 && atomic_load(&initial.ok[1]) == 1);
    REQUIRE(add(producer, B, &id) == 0 && id == 2);
    REQUIRE(wait_result(&initial, 2, 1) == 0 && wait_checkpoint_ack(dir, 2) == 0);
    REQUIRE(close_producer(&producer) == 0);
    producer = open_customer_wal(&cfg, &reopened);
    REQUIRE(producer != NULL && ve_tls_producer_recover(producer) == VE_TLS_OK);
    REQUIRE(close_producer(&producer) == 0);
    REQUIRE(hit_count(&initial, A) == 1 && hit_count(&initial, B) == 1);
    REQUIRE(atomic_load(&reopened.calls) == 0 && !atomic_load(&initial.bad_payload));
    REQUIRE(!atomic_load(&sync_retry_timeout));
    REQUIRE(checkpoint_ack(dir, &ack) == 0 && ack == 2);
cleanup:
    atomic_store(&sync_retry_release, 1);
    atomic_store(&fail_sync_file, NULL);
    if (append) replay_platform.thread_join(append);
    if (producer) ve_tls_producer_destroy(producer);
    ve_tls_persistent_record_free(&disk_record);
    if (dir[0]) remove_dir(dir);
    return failed ? -1 : 0;
}

typedef enum {
    WRITE_FAIL_IMMEDIATE,
    WRITE_FAIL_SHORT,
    WRITE_FAIL_TRUNCATE,
    WRITE_FAIL_ROLLBACK_SYNC
} write_failure;

static _Thread_local struct {
    ve_tls_file * file;
    write_failure kind;
    int writes;
    int truncates;
    int syncs;
} rollback_fault;

static int64_t rollback_test_write(ve_tls_file * file, const void * data, size_t size) {
    if (file != rollback_fault.file) return replay_platform.file_write(file, data, size);
    rollback_fault.writes++;
    if (rollback_fault.kind != WRITE_FAIL_IMMEDIATE && rollback_fault.writes == 1) {
        return replay_platform.file_write(file, data, size / 2);
    }
    return -1;
}

static int rollback_test_truncate(ve_tls_file * file, int64_t offset) {
    if (file == rollback_fault.file) {
        rollback_fault.truncates++;
        if (rollback_fault.kind == WRITE_FAIL_TRUNCATE) return -1;
    }
    return replay_platform.file_truncate(file, offset);
}

static int rollback_test_fsync(ve_tls_file * file) {
    if (file == rollback_fault.file) {
        rollback_fault.syncs++;
        if (rollback_fault.kind == WRITE_FAIL_ROLLBACK_SYNC) return -1;
    }
    return replay_platform.file_fsync(file);
}

static int test_wal_append_rollback(write_failure fault) {
    enum { RECORDS = 19, PAYLOAD_BYTES = 600 * 1024 };
    int failed = 0;
    char dir[PATH_MAX] = {0};
    ve_tls_config cfg;
    mock_state initial, reopened;
    ve_tls_producer * producer = NULL;
    char * payload = NULL;
    int64_t id = 0, last_ack = 1;
    int rolled_back = fault == WRITE_FAIL_IMMEDIATE || fault == WRITE_FAIL_SHORT;
    init_mock(&initial, 0, 0);
    init_mock(&reopened, 0, 0);
    REQUIRE(make_dir(dir, sizeof(dir)) == 0 && customer_wal_config(&cfg, dir) == 0);
    /* Keep request payloads inspectable while retaining all customer WAL limits. */
    cfg.compress_type = "none";
    replay_platform = cfg.platform;
    cfg.platform.file_write = rollback_test_write;
    cfg.platform.file_truncate = rollback_test_truncate;
    cfg.platform.file_fsync = rollback_test_fsync;
    producer = open_customer_wal(&cfg, &initial);
    REQUIRE(producer != NULL && add(producer, A, &id) == 0 && id == 1);
    REQUIRE(wait_result(&initial, id, 1) == 0 && wait_checkpoint_ack(dir, 1) == 0);

    ve_tls_file * segment = producer->persistent->store.active_file;
    int64_t original_size = replay_platform.file_seek(segment, 0, VE_TLS_FILE_SEEK_END);
    REQUIRE(original_size > 0);
    memset(&rollback_fault, 0, sizeof(rollback_fault));
    rollback_fault.kind = fault;
    rollback_fault.file = segment;
    ve_tls_kv rejected = {"event_id", markers[B]};
    REQUIRE(ve_tls_producer_add_log_kv_hashkey_with_id(producer, 1700000000000LL,
        hash_keys[B], &rejected, 1, 1, &id) == VE_TLS_PERSISTENT_ERROR);
    rollback_fault.file = NULL;
    REQUIRE(rollback_fault.writes == (fault == WRITE_FAIL_IMMEDIATE ? 1 : 2));
    REQUIRE(rollback_fault.truncates == 1);
    REQUIRE(id == (rolled_back ? 0 : 2));
    REQUIRE(rollback_fault.syncs == (fault == WRITE_FAIL_TRUNCATE ? 0 : 1));
    int64_t size_after = replay_platform.file_seek(segment, 0, VE_TLS_FILE_SEEK_END);
    REQUIRE(fault == WRITE_FAIL_TRUNCATE ? size_after > original_size : size_after == original_size);

    if (rolled_back) {
        payload = malloc(PAYLOAD_BYTES);
        REQUIRE(payload != NULL);
        memset(payload, 'x', PAYLOAD_BYTES - 1);
        payload[PAYLOAD_BYTES - 1] = 0;
        ve_tls_kv large[] = {{"event_id", markers[C]}, {"message", payload}};
        /* Each 600 KiB record after the first needs a new 1 MiB segment.
         * The cumulative input exceeds the 10 MiB WAL limit. */
        for (int i = 0; i < RECORDS; i++) {
            REQUIRE(ve_tls_producer_add_log_kv_with_id(producer, 1700000000000LL,
                large, 2, 1, &id) == VE_TLS_OK && id == i + 2);
            REQUIRE(wait_result(&initial, id, 1) == 0);
            REQUIRE(hit_count(&initial, C) == i + 1 && atomic_load(&initial.ok[id]) == 1);
        }
        REQUIRE(producer->persistent->store.active_segment_id > 10);
        REQUIRE(wait_checkpoint_ack(dir, id) == 0);
        char first_segment[PATH_MAX];
        ve_tls_path_info info;
        REQUIRE(ve_tls_segment_store_get_segment_path(&producer->persistent->store, 1,
            first_segment, sizeof(first_segment)) == 0);
        REQUIRE(replay_platform.path_stat(first_segment, &info) == 0 && !info.exists);
        last_ack = id;
    } else {
        REQUIRE(ve_tls_producer_add_log_kv_with_id(producer, 1700000000000LL,
            &rejected, 1, 1, &id) == VE_TLS_PERSISTENT_ERROR && id == 0);
        REQUIRE(replay_platform.file_seek(segment, 0, VE_TLS_FILE_SEEK_END) == size_after);
    }
    REQUIRE(close_producer(&producer) == 0);
    REQUIRE(hit_count(&initial, A) == 1 && hit_count(&initial, B) == 0 && !atomic_load(&initial.bad_payload));
    producer = open_customer_wal(&cfg, &reopened);
    REQUIRE(producer != NULL && ve_tls_producer_recover(producer) == VE_TLS_OK);
    REQUIRE(add(producer, D, &id) == 0 && id == last_ack + 1);
    REQUIRE(close_producer(&producer) == 0);
    REQUIRE(atomic_load(&reopened.calls) == 1 && hit_count(&reopened, D) == 1 &&
        atomic_load(&reopened.ok[id]) == 1);
cleanup:
    rollback_fault.file = NULL;
    if (producer) ve_tls_producer_destroy(producer);
    free(payload);
    if (dir[0]) remove_dir(dir);
    return failed ? -1 : 0;
}

static int test_zero_byte_write_rollback_reuses_id(void) {
    return test_wal_append_rollback(WRITE_FAIL_IMMEDIATE);
}

static int test_short_write_rollback_reuses_id(void) {
    return test_wal_append_rollback(WRITE_FAIL_SHORT);
}

static int test_failed_truncate_preserves_uncertain_id(void) {
    return test_wal_append_rollback(WRITE_FAIL_TRUNCATE);
}

static int test_failed_rollback_sync_preserves_uncertain_id(void) {
    return test_wal_append_rollback(WRITE_FAIL_ROLLBACK_SYNC);
}

static int test_live_wal_survives_memory_backpressure(void) {
    enum { RECORDS = 18, PAYLOAD_BYTES = 480 * 1024 };
    int failed = 0;
    char dir[PATH_MAX] = {0};
    ve_tls_config cfg;
    ve_tls_producer * producer = NULL;
    backlog_replay_state state = {0};
    char * body = NULL;
    int64_t ack = 0;
    REQUIRE(make_dir(dir, sizeof(dir)) == 0 && customer_wal_config(&cfg, dir) == 0);
    replay_platform = cfg.platform;
    cfg.platform.thread_create = gate_replay_builder;
    cfg.http_client.do_request = backlog_http;
    cfg.http_client.free_response = free_http;
    cfg.http_client.user_data = &state;
    atomic_store(&replay_builder_waiting, 0);
    atomic_store(&replay_release_builder, 0);
    producer = ve_tls_producer_create_exclusive_persistence(&cfg, sizeof(cfg));
    REQUIRE(producer != NULL && wait_value(&replay_builder_waiting, 1, 5000) == 0);
    ve_tls_producer_set_send_done_v2(producer, backlog_send_done, &state);
    REQUIRE(ve_tls_producer_recover(producer) == VE_TLS_OK);
    body = malloc(PAYLOAD_BYTES);
    REQUIRE(body != NULL);
    memset(body, 'x', PAYLOAD_BYTES);
    body[PAYLOAD_BYTES - 1] = 0;
    ve_tls_kv kv = {"message", body};
    for (int i = 1; i <= RECORDS; i++) {
        int64_t id = 0;
        REQUIRE(ve_tls_producer_add_log_kv_with_id(producer, 1700000000000LL,
            &kv, 1, 1, &id) == VE_TLS_OK && id == i);
        REQUIRE(ve_tls_producer_get_buffered_bytes(producer) <= 8 * REPLAY_MIB);
    }
    REQUIRE(producer->persistent->current_records == RECORDS && atomic_load(&state.requests) == 0);
    atomic_store(&replay_release_builder, 1);
    REQUIRE(wait_value(&state.delivered_count, RECORDS, 8000) == 0);
    REQUIRE(close_producer(&producer) == 0);
    REQUIRE(!atomic_load(&state.failed) && atomic_load(&state.wire_records) == RECORDS);
    for (int i = 1; i <= RECORDS; i++) REQUIRE(atomic_load(&state.delivered[i]) == 1);
    REQUIRE(checkpoint_ack(dir, &ack) == 0 && ack == RECORDS);
    int requests = atomic_load(&state.requests);
    producer = ve_tls_producer_create_exclusive_persistence(&cfg, sizeof(cfg));
    REQUIRE(producer != NULL && ve_tls_producer_recover(producer) == VE_TLS_OK);
    REQUIRE(close_producer(&producer) == 0 && atomic_load(&state.requests) == requests);
cleanup:
    atomic_store(&replay_release_builder, 1);
    if (producer) ve_tls_producer_destroy(producer);
    free(body);
    if (dir[0]) remove_dir(dir);
    return failed ? -1 : 0;
}

static int test_live_wal_survives_send_queue_backpressure(void) {
    enum { RECORDS = 6 };
    int failed = 0;
    char dir[PATH_MAX] = {0};
    ve_tls_config cfg;
    ve_tls_producer * producer = NULL;
    backlog_replay_state state = {.hold_first_request = 1};
    int64_t ack = 0;
    REQUIRE(make_dir(dir, sizeof(dir)) == 0 && customer_wal_config(&cfg, dir) == 0);
    cfg.send_queue_size = 1;
    cfg.send_queue_full_policy = VE_TLS_SEND_QUEUE_FULL_DROP;
    cfg.http_client.do_request = backlog_http;
    cfg.http_client.free_response = free_http;
    cfg.http_client.user_data = &state;
    producer = ve_tls_producer_create_exclusive_persistence(&cfg, sizeof(cfg));
    REQUIRE(producer != NULL);
    ve_tls_producer_set_send_done_v2(producer, backlog_send_done, &state);
    ve_tls_kv kv = {"message", "send queue pressure"};
    for (int i = 1; i <= RECORDS; i++) {
        int64_t id = 0;
        REQUIRE(ve_tls_producer_add_log_kv_with_id(producer, 1700000000000LL,
            &kv, 1, 1, &id) == VE_TLS_OK && id == i);
        if (i == 1) REQUIRE(wait_value(&state.requests, 1, 5000) == 0);
        if (i == 2) REQUIRE(wait_send_queue_full(producer) == 0);
    }
    /* At least one more batch reached the full queue before releasing HTTP. */
    int64_t deadline = monotonic_ms() + 5000;
    ve_tls_metrics metrics;
    do {
        ve_tls_producer_get_metrics(producer, &metrics);
        if (metrics.batches_built_total >= 3) break;
        sleep_ms(5);
    } while (monotonic_ms() < deadline);
    REQUIRE(metrics.batches_built_total >= 3 && atomic_load(&state.requests) == 1);
    atomic_store(&state.release_http, 1);
    REQUIRE(wait_value(&state.delivered_count, RECORDS, 5000) == 0);
    REQUIRE(close_producer(&producer) == 0);
    REQUIRE(!atomic_load(&state.failed) && atomic_load(&state.wire_records) == RECORDS);
    for (int i = 1; i <= RECORDS; i++) REQUIRE(atomic_load(&state.delivered[i]) == 1);
    REQUIRE(checkpoint_ack(dir, &ack) == 0 && ack == RECORDS);
cleanup:
    atomic_store(&state.release_http, 1);
    if (producer) ve_tls_producer_destroy(producer);
    if (dir[0]) remove_dir(dir);
    return failed ? -1 : 0;
}

static ve_tls_alloc_hooks batch_original_alloc;
static _Thread_local int batch_fault_worker;
static _Atomic int batch_fail_remaining;
static void * batch_fault_body;

static char * fail_batch_key_copy(const char * value, void * user) {
    if (batch_fault_worker && atomic_load(&batch_fail_remaining) > 0 &&
        strcmp(value, hash_keys[A]) == 0) {
        atomic_fetch_sub(&batch_fail_remaining, 1);
        return NULL;
    }
    return batch_original_alloc.strdup_fn(value, user);
}

static void * fail_batch_body_growth(void * ptr, size_t size, void * user) {
    if (batch_fault_worker && atomic_load(&batch_fail_remaining) > 0 && ptr == batch_fault_body) {
        atomic_fetch_sub(&batch_fail_remaining, 1);
        return NULL;
    }
    return batch_original_alloc.realloc_fn(ptr, size, user);
}

static void * build_with_alloc_fault(void * producer) {
    batch_fault_worker = 1;
    return wait_then_build(producer);
}

static ve_tls_thread * gate_batch_alloc_fault(ve_tls_thread_fn fn, void * arg) {
    return replay_platform.thread_create(fn == ve_tls_worker_main ? build_with_alloc_fault : fn, arg);
}

static int test_wal_batch_alloc_failure(int fail_body, int failures) {
    int failed = 0, hooks_set = 0;
    char dir[PATH_MAX] = {0};
    char source[512];
    ve_tls_config cfg;
    mock_state initial, reopened;
    ve_tls_producer * producer = NULL;
    int64_t id = 0;
    init_mock(&initial, 0, 0);
    init_mock(&reopened, 0, 0);
    REQUIRE(make_dir(dir, sizeof(dir)) == 0 && customer_wal_config(&cfg, dir) == 0);
    memset(source, 's', sizeof(source) - 1);
    source[sizeof(source) - 1] = 0;
    if (fail_body) cfg.source = source;
    cfg.compress_type = "none";
    cfg.pack_thread_count = 1;
    replay_platform = cfg.platform;
    cfg.platform.thread_create = gate_batch_alloc_fault;
    atomic_store(&replay_builder_waiting, 0);
    atomic_store(&replay_release_builder, 0);
    atomic_store(&batch_fail_remaining, failures);
    batch_fault_body = NULL;
    ve_tls_alloc_get_hooks(&batch_original_alloc);
    ve_tls_alloc_hooks fault_hooks = batch_original_alloc;
    if (fail_body) {
        fault_hooks.realloc_fn = fail_batch_body_growth;
    } else {
        fault_hooks.strdup_fn = fail_batch_key_copy;
    }
    ve_tls_alloc_set_hooks(&fault_hooks);
    hooks_set = 1;

    producer = open_customer_wal(&cfg, &initial);
    REQUIRE(producer != NULL && wait_value(&replay_builder_waiting, 1, 5000) == 0);
    REQUIRE(add(producer, A, &id) == 0 && id == 1);
    cfg.platform.mutex_lock(producer->mutex);
    ve_tls_log_group_builder * sealed = producer->sealed_head;
    int needs_growth = sealed && sealed->logs_cap < sealed->logs_len + producer->cfg_group_suffix_len;
    if (sealed) batch_fault_body = sealed->logs;
    cfg.platform.mutex_unlock(producer->mutex);
    REQUIRE(batch_fault_body != NULL && (!fail_body || needs_growth));
    REQUIRE(producer->persistent->current_records == 1 && atomic_load(&initial.calls) == 0);
    atomic_store(&replay_release_builder, 1);

    /* The first completion must happen while the original instance is live. */
    int delivered = failures == 1;
    REQUIRE(wait_result(&initial, id, delivered) == 0);
    REQUIRE(atomic_load(&batch_fail_remaining) == 0);
    if (delivered) REQUIRE(wait_checkpoint_ack(dir, id) == 0);
    REQUIRE(close_producer(&producer) == 0);
    int64_t ack = 0;
    REQUIRE(checkpoint_ack(dir, &ack) == 0 && ack == delivered);
    REQUIRE(atomic_load(&initial.ok[id]) == delivered && atomic_load(&initial.failed[id]) == !delivered);
    REQUIRE(hit_count(&initial, A) == delivered && atomic_load(&initial.calls) == delivered);
    ve_tls_alloc_set_hooks(&batch_original_alloc);
    hooks_set = 0;

    cfg.platform.thread_create = replay_platform.thread_create;
    producer = open_customer_wal(&cfg, &reopened);
    REQUIRE(producer != NULL && ve_tls_producer_recover(producer) == VE_TLS_OK);
    REQUIRE(add(producer, B, &id) == 0 && id == 2);
    REQUIRE(close_producer(&producer) == 0);
    REQUIRE(hit_count(&reopened, A) == !delivered && hit_count(&reopened, B) == 1);
    REQUIRE(atomic_load(&reopened.calls) == (delivered ? 1 : 2));
    REQUIRE(checkpoint_ack(dir, &ack) == 0 && ack == 2);
cleanup:
    atomic_store(&replay_release_builder, 1);
    if (producer) ve_tls_producer_destroy(producer);
    if (hooks_set) ve_tls_alloc_set_hooks(&batch_original_alloc);
    if (dir[0]) remove_dir(dir);
    return failed ? -1 : 0;
}

static int test_wal_retries_batch_key_allocation(void) {
    return test_wal_batch_alloc_failure(0, 1);
}

static int test_wal_retries_batch_body_allocation(void) {
    return test_wal_batch_alloc_failure(1, 1);
}

static int test_wal_retains_batch_after_allocation_retry_fails(void) {
    return test_wal_batch_alloc_failure(0, 2);
}

typedef struct {
    const unsigned char * body;
    size_t size;
    _Atomic int calls;
    _Atomic int mismatch;
} raw_replay_state;

static int raw_replay_http(ve_tls_http_client * client, const ve_tls_http_request * req, ve_tls_http_response * resp) {
    raw_replay_state * state = client->user_data;
    if (req->body_size != state->size || memcmp(req->body, state->body, state->size) != 0) {
        atomic_store(&state->mismatch, 1);
    }
    atomic_fetch_add(&state->calls, 1);
    resp->status_code = 200;
    return 0;
}

static int test_live_raw_wal_preserves_payload(void) {
    enum { RECORDS = 16, PAYLOAD_BYTES = 480 * 1024 };
    int failed = 0;
    char dir[PATH_MAX] = {0};
    ve_tls_config cfg;
    mock_state state;
    raw_replay_state wire = {0};
    ve_tls_producer * producer = NULL;
    unsigned char * body = NULL;
    int64_t ack = 0;
    init_mock(&state, 0, 0);
    REQUIRE(make_dir(dir, sizeof(dir)) == 0 && customer_wal_config(&cfg, dir) == 0);
    cfg.compress_type = "none";
    body = malloc(PAYLOAD_BYTES);
    REQUIRE(body != NULL);
    memset(body, 'x', PAYLOAD_BYTES);
    memcpy(body, markers[A], strlen(markers[A]));
    wire.body = body;
    wire.size = PAYLOAD_BYTES;
    cfg.http_client.do_request = raw_replay_http;
    cfg.http_client.free_response = free_http;
    cfg.http_client.user_data = &wire;
    replay_platform = cfg.platform;
    cfg.platform.thread_create = gate_replay_builder;
    atomic_store(&replay_builder_waiting, 0);
    atomic_store(&replay_release_builder, 0);
    producer = ve_tls_producer_create_exclusive_persistence(&cfg, sizeof(cfg));
    REQUIRE(producer && wait_value(&replay_builder_waiting, 1, 5000) == 0);
    ve_tls_producer_set_send_done_v2(producer, send_done, &state);
    for (int i = 1; i <= RECORDS; i++) {
        int64_t id = 0;
        REQUIRE(ve_tls_producer_add_log_raw_time_parts_with_id(producer, 1700000000000LL, 1, 123,
            (const char *)body, PAYLOAD_BYTES, 1, &id) == VE_TLS_OK && id == i);
    }
    REQUIRE(producer->persistent->current_records == RECORDS);
    atomic_store(&replay_release_builder, 1);
    for (int i = 1; i <= RECORDS; i++) REQUIRE(wait_result(&state, i, 1) == 0);
    REQUIRE(close_producer(&producer) == 0);
    REQUIRE(atomic_load(&wire.calls) == RECORDS && !atomic_load(&wire.mismatch));
    for (int i = 1; i <= RECORDS; i++) REQUIRE(atomic_load(&state.ok[i]) == 1);
    REQUIRE(checkpoint_ack(dir, &ack) == 0 && ack == RECORDS);
cleanup:
    atomic_store(&replay_release_builder, 1);
    if (producer) ve_tls_producer_destroy(producer);
    free(body);
    if (dir[0]) remove_dir(dir);
    return failed ? -1 : 0;
}

enum { LEGACY_REPLAY_MAX = 3 };

typedef struct {
    ve_tls_bytes bodies[LEGACY_REPLAY_MAX];
    size_t count;
    _Atomic int hits[LEGACY_REPLAY_MAX];
    _Atomic int unexpected;
    int block_enabled;
    size_t block_index;
    int fail_enabled;
    size_t fail_index;
    _Atomic int block_entered;
    _Atomic int block_release;
    _Atomic int block_timeout;
} legacy_replay_wire;

static int legacy_replay_http(ve_tls_http_client * client, const ve_tls_http_request * req,
    ve_tls_http_response * resp) {
    legacy_replay_wire * wire = client->user_data;
    for (size_t i = 0; i < wire->count; i++) {
        if (req->body_size == wire->bodies[i].size &&
            memcmp(req->body, wire->bodies[i].data, req->body_size) == 0) {
            atomic_fetch_add(&wire->hits[i], 1);
            if (wire->block_enabled && i == wire->block_index) {
                atomic_store(&wire->block_entered, 1);
                if (wait_value(&wire->block_release, 1, 10000) != 0) {
                    atomic_store(&wire->block_timeout, 1);
                    return -1;
                }
            }
            resp->status_code = wire->fail_enabled && i == wire->fail_index ? 400 : 200;
            return 0;
        }
    }
    atomic_fetch_add(&wire->unexpected, 1);
    resp->status_code = 400;
    return 0;
}

static int append_legacy_kv(ve_tls_persistent * wal, int64_t id, int64_t time_ms, int has_time_ns,
    const char * marker, const ve_tls_config * cfg, ve_tls_bytes * wire) {
    const ve_tls_kv kv = {"event_id", marker};
    const size_t key_len = sizeof("event_id") - 1;
    const size_t val_len = strlen(marker);
    ve_tls_log_group_builder * builder = ve_tls_log_builder_create(NULL);
    if (!builder) return -1;
    int rc = ve_tls_log_builder_add_kv_lens(builder, id, time_ms, 123, has_time_ns,
        &kv, &key_len, &val_len, 1);
    if (rc == 0) rc = ve_tls_persistent_append(wal, id, NULL, builder->logs, builder->logs_len);
    ve_tls_log_builder_free(builder);

    ve_tls_bytes log = {0};
    if (rc == 0) rc = ve_tls_proto_encode_log_ex(time_ms, 123, has_time_ns, &kv, 1, &log);
    if (rc == 0) rc = ve_tls_proto_encode_log_group_list(&log, 1, cfg->source, cfg->file_name, wire);
    ve_tls_bytes_free(&log);
    return rc;
}

/* A was actually sent and ACKed; only B's payload or metadata CRC is changed.
 * C and the optional next-segment D retain their exact encoded request bodies. */
static int test_mid_segment_crc_keeps_suffix(int closed_segment, int overlap, int metadata_crc, int unframed_tail) {
    static const unsigned char tail[32] = {0};
    int failed = 0;
    char dir[PATH_MAX] = {0}, segment[PATH_MAX], next_segment[PATH_MAX], checkpoint_path[PATH_MAX];
    unsigned char original[4096], damaged[4096], gated[4096];
    ve_tls_config cfg;
    ve_tls_producer * producer = NULL;
    mock_state initial, callbacks;
    ve_tls_bytes live_log = {0};
    ve_tls_checkpoint_state checkpoint;
    ve_tls_checkpoint_range * ranges = NULL;
    size_t range_count = 0;
    legacy_replay_wire wire = {.block_enabled = 1, .block_index = overlap ? 2 : 1,
        .fail_enabled = overlap, .fail_index = 2};
    int64_t id = 0, ack = 0;
    init_mock(&initial, 0, 0);
    init_mock(&callbacks, 0, 0);
    REQUIRE(make_dir(dir, sizeof(dir)) == 0 && customer_wal_config(&cfg, dir) == 0);
    REQUIRE(snprintf(segment, sizeof(segment), "%s/seg-000001.log", dir) > 0);
    REQUIRE(snprintf(next_segment, sizeof(next_segment), "%s/seg-000002.log", dir) > 0);
    REQUIRE(snprintf(checkpoint_path, sizeof(checkpoint_path), "%s/checkpoint", dir) > 0);
    cfg.compress_type = "none";
    cfg.log_count_per_package = 1;
    cfg.flush_interval_ms = 0;
    cfg.max_persistent_log_count = unframed_tail ? 65536 : 3;
    producer = open_customer_wal(&cfg, &initial);
    REQUIRE(producer != NULL && add(producer, A, &id) == 0 && id == 1);
    REQUIRE(wait_result(&initial, 1, 1) == 0 && wait_checkpoint_ack(dir, 1) == 0);
    REQUIRE(hit_count(&initial, A) == 1);

    uint64_t b_offset = producer->persistent->store.active_size;
    REQUIRE(append_legacy_kv(producer->persistent, 2, 1700000000000LL, 0,
        markers[B], &cfg, &wire.bodies[0]) == 0);
    uint64_t c_offset = producer->persistent->store.active_size;
    REQUIRE(append_legacy_kv(producer->persistent, 3, 1700000000000LL, 0,
        markers[C], &cfg, &wire.bodies[1]) == 0);
    wire.count = 2;
    if (closed_segment) {
        REQUIRE(append_legacy_kv(producer->persistent, overlap ? 2 : 4, 1700000000000LL, 0,
            markers[D], &cfg, &wire.bodies[2]) == 0);
        wire.count = 3;
        REQUIRE(producer->persistent->store.active_segment_id == 2);
    } else {
        REQUIRE(producer->persistent->store.active_segment_id == 1);
    }
    if (unframed_tail) {
        const ve_tls_kv kvs[] = {{"event_id", markers[D]}, {"trace_id", "same-trace"}};
        REQUIRE(ve_tls_proto_encode_log(1700000000000LL, kvs, 2, &live_log) == 0);
        REQUIRE(ve_tls_proto_encode_log_group_list(&live_log, 1, cfg.source, cfg.file_name, &wire.bodies[2]) == 0);
        wire.count = 3;
    }
    REQUIRE(close_producer(&producer) == 0 && checkpoint_ack(dir, &ack) == 0 && ack == 1);

    size_t size = read_wal_fixture(segment, original, sizeof(original));
    REQUIRE(size > c_offset && c_offset > b_offset);
    memcpy(damaged, original, size);
    size_t corrupt = size;
    if (metadata_crc) {
        size_t ext = (size_t)b_offset + VE_TLS_PERSISTENT_RECORD_HEADER_SIZE;
        REQUIRE(ext + 20 < c_offset && damaged[ext] == VE_TLS_PERSISTENT_EXT_TYPE_METADATA &&
            damaged[ext + 2] == 16 && damaged[ext + 3] == 0);
        corrupt = ext + 4 + 12;
    } else {
        size_t marker_size = strlen(markers[B]);
        for (size_t i = (size_t)b_offset; i + marker_size <= (size_t)c_offset; i++) {
            if (memcmp(damaged + i, markers[B], marker_size) == 0) { corrupt = i; break; }
        }
    }
    REQUIRE(corrupt < c_offset && count_marker(original + c_offset, size - c_offset, markers[C]) == 1);
    damaged[corrupt] ^= 1;
    REQUIRE(!unframed_tail || size + sizeof(tail) < sizeof(damaged));
    FILE * file = fopen(segment, "r+b");
    REQUIRE(file != NULL);
    int wrote = fseek(file, (long)corrupt, SEEK_SET) == 0 && fputc(damaged[corrupt], file) != EOF;
    if (unframed_tail) {
        wrote = wrote && fseek(file, 0, SEEK_END) == 0 && fwrite(tail, 1, sizeof(tail), file) == sizeof(tail);
        memcpy(damaged + size, tail, sizeof(tail));
        size += sizeof(tail);
    }
    int file_closed = fclose(file) == 0;
    REQUIRE(wrote && file_closed);
    REQUIRE(read_wal_fixture(segment, gated, sizeof(gated)) == size && memcmp(damaged, gated, size) == 0);

    cfg.http_client.do_request = legacy_replay_http;
    cfg.http_client.free_response = free_http;
    cfg.http_client.user_data = &wire;
    producer = ve_tls_producer_create_exclusive_persistence(&cfg, sizeof(cfg));
    REQUIRE(producer != NULL);
    ve_tls_producer_set_send_done_v2(producer, send_done, &callbacks);
    REQUIRE(read_wal_fixture(segment, gated, sizeof(gated)) == size && memcmp(damaged, gated, size) == 0);
    REQUIRE(ve_tls_producer_recover(producer) == VE_TLS_OK);
    REQUIRE(wait_value(&wire.block_entered, 1, 5000) == 0);
    if (overlap) REQUIRE(wait_result(&callbacks, 3, 1) == 0);
    REQUIRE(read_wal_fixture(segment, gated, sizeof(gated)) == size && memcmp(damaged, gated, size) == 0);
    REQUIRE(checkpoint_ack(dir, &ack) == 0 && ack == 1);
    REQUIRE(atomic_load(&wire.hits[0]) == 0 && atomic_load(&wire.hits[1]) == 1 &&
        atomic_load(&wire.hits[2]) == overlap && atomic_load(&wire.unexpected) == 0 &&
        atomic_load(&callbacks.ok[3]) == overlap);

    atomic_store(&wire.block_release, 1);
    REQUIRE(wait_result(&callbacks, 3, 1) == 0);
    if (unframed_tail) {
        REQUIRE(ve_tls_producer_flush(producer) == VE_TLS_OK);
        REQUIRE(ve_tls_checkpoint_load_ranges(&cfg.platform, checkpoint_path, &checkpoint, &ranges, &range_count) == 0);
        REQUIRE(checkpoint.acked_log_id == 1 && range_count == 1 &&
            ranges[0].start_id == 3 && ranges[0].end_id == 3);
        ve_tls_free(ranges);
        ranges = NULL;
        REQUIRE(add(producer, D, &id) == 0 && id == 4 && wait_result(&callbacks, 4, 1) == 0);
        REQUIRE(access(next_segment, F_OK) == 0 && ve_tls_producer_flush(producer) == VE_TLS_OK);
        REQUIRE(ve_tls_checkpoint_load_ranges(&cfg.platform, checkpoint_path, &checkpoint, &ranges, &range_count) == 0);
        REQUIRE(checkpoint.acked_log_id == 1 && range_count == 1 &&
            ranges[0].start_id == 3 && ranges[0].end_id == 4);
        REQUIRE(read_wal_fixture(segment, gated, sizeof(gated)) == size && memcmp(damaged, gated, size) == 0);
        REQUIRE(close_producer(&producer) == 0);
        REQUIRE(atomic_load(&wire.hits[0]) == 0 && atomic_load(&wire.hits[1]) == 1 &&
            atomic_load(&wire.hits[2]) == 1 && atomic_load(&wire.unexpected) == 0);
        producer = ve_tls_producer_create_exclusive_persistence(&cfg, sizeof(cfg));
        REQUIRE(producer != NULL && ve_tls_producer_recover(producer) == VE_TLS_OK);
        REQUIRE(close_producer(&producer) == 0);
        REQUIRE(atomic_load(&wire.hits[1]) == 1 && atomic_load(&wire.hits[2]) == 1 &&
            atomic_load(&wire.unexpected) == 0 && !atomic_load(&wire.block_timeout));
        REQUIRE(read_wal_fixture(segment, gated, sizeof(gated)) == size && memcmp(damaged, gated, size) == 0);
        goto cleanup;
    }
    if (overlap) {
        /* The other segment's valid ID 2 is still retryable. Its failed send
           must not be masked by retiring the damaged frame's untrusted ID. */
        REQUIRE(wait_result(&callbacks, 2, 0) == 0 && close_producer(&producer) == 0);
        REQUIRE(checkpoint_ack(dir, &ack) == 0 && ack == 1);
        REQUIRE(read_wal_fixture(segment, gated, sizeof(gated)) == size && memcmp(damaged, gated, size) == 0);
        wire.fail_enabled = 0;
        wire.block_enabled = 0;
        producer = ve_tls_producer_create_exclusive_persistence(&cfg, sizeof(cfg));
        REQUIRE(producer != NULL);
        ve_tls_producer_set_send_done_v2(producer, send_done, &callbacks);
        REQUIRE(ve_tls_producer_recover(producer) == VE_TLS_OK && wait_result(&callbacks, 2, 1) == 0);
        REQUIRE(wait_checkpoint_ack(dir, 3) == 0 && close_producer(&producer) == 0);
        REQUIRE(read_wal_fixture(segment, gated, sizeof(gated)) == size && memcmp(damaged, gated, size) == 0);
        REQUIRE(atomic_load(&wire.hits[0]) == 0 && atomic_load(&wire.hits[1]) == 1 &&
            atomic_load(&wire.hits[2]) == 2 && atomic_load(&wire.unexpected) == 0);
        producer = ve_tls_producer_create_exclusive_persistence(&cfg, sizeof(cfg));
        REQUIRE(producer != NULL && ve_tls_producer_recover(producer) == VE_TLS_OK);
        REQUIRE(close_producer(&producer) == 0);
        REQUIRE(atomic_load(&wire.hits[1]) == 1 && atomic_load(&wire.hits[2]) == 2 &&
            atomic_load(&wire.unexpected) == 0 && !atomic_load(&wire.block_timeout));
        goto cleanup;
    }
    if (closed_segment) REQUIRE(wait_result(&callbacks, 4, 1) == 0);
    REQUIRE(wait_checkpoint_ack(dir, closed_segment ? 4 : 3) == 0);
    REQUIRE(close_producer(&producer) == 0);
    REQUIRE(atomic_load(&wire.hits[0]) == 0 && atomic_load(&wire.hits[1]) == 1 &&
        atomic_load(&wire.hits[2]) == closed_segment && atomic_load(&wire.unexpected) == 0);
    REQUIRE(atomic_load(&callbacks.ok[2]) == 0 && atomic_load(&callbacks.ok[3]) == 1 &&
        atomic_load(&callbacks.ok[4]) == closed_segment && !atomic_load(&wire.block_timeout));
    producer = ve_tls_producer_create_exclusive_persistence(&cfg, sizeof(cfg));
    REQUIRE(producer != NULL && ve_tls_producer_recover(producer) == VE_TLS_OK);
    REQUIRE(close_producer(&producer) == 0);
    REQUIRE(atomic_load(&wire.hits[0]) == 0 && atomic_load(&wire.hits[1]) == 1 &&
        atomic_load(&wire.hits[2]) == closed_segment && atomic_load(&wire.unexpected) == 0);
cleanup:
    atomic_store(&wire.block_release, 1);
    if (producer) ve_tls_producer_destroy(producer);
    ve_tls_free(ranges);
    ve_tls_bytes_free(&live_log);
    for (size_t i = 0; i < LEGACY_REPLAY_MAX; i++) ve_tls_bytes_free(&wire.bodies[i]);
    if (dir[0]) remove_dir(dir);
    return failed ? -1 : 0;
}

static int test_active_mid_segment_crc_keeps_suffix(void) {
    return test_mid_segment_crc_keeps_suffix(0, 0, 0, 0);
}

static int test_closed_mid_segment_crc_keeps_suffix(void) {
    return test_mid_segment_crc_keeps_suffix(1, 0, 0, 0);
}

static int test_overlapping_segment_crc_keeps_gap(void) {
    return test_mid_segment_crc_keeps_suffix(1, 1, 0, 0);
}

static int test_active_mid_segment_metadata_crc_keeps_suffix(void) {
    return test_mid_segment_crc_keeps_suffix(0, 0, 1, 0);
}

static int test_closed_mid_segment_metadata_crc_keeps_suffix(void) {
    return test_mid_segment_crc_keeps_suffix(1, 0, 1, 0);
}

static int test_active_crc_with_unframed_tail_keeps_suffix(void) {
    return test_mid_segment_crc_keeps_suffix(0, 0, 0, 1);
}

static int test_legacy_wal_replay(int raw, int kv) {
    int failed = 0;
    char dir[PATH_MAX] = {0};
    ve_tls_config cfg;
    ve_tls_producer * producer = NULL;
    mock_state callbacks;
    legacy_replay_wire wire = {0};
    ve_tls_bytes raw_logs[2] = {{0}};
    int64_t ack = 0;
    init_mock(&callbacks, 0, 0);
    REQUIRE(make_dir(dir, sizeof(dir)) == 0 && customer_wal_config(&cfg, dir) == 0);
    cfg.source = "kv-source";
    cfg.file_name = "kv-file";
    cfg.compress_type = "none";
    cfg.retry_policy.max_attempts = 1;
    cfg.http_client.do_request = legacy_replay_http;
    cfg.http_client.free_response = free_http;
    cfg.http_client.user_data = &wire;

    producer = ve_tls_producer_create_exclusive_persistence(&cfg, sizeof(cfg));
    REQUIRE(producer != NULL);
    if (kv) {
        /* The old KV writer always put Time on the wire, including zero. */
        REQUIRE(append_legacy_kv(producer->persistent, 1, 0, 0, markers[A], &cfg, &wire.bodies[wire.count]) == 0);
        wire.count++;
    }
    if (raw) {
        const ve_tls_kv events[] = {{"event_id", markers[B]}, {"event_id", markers[C]}};
        const ve_tls_kv tag = {"tag", "from-raw"};
        REQUIRE(ve_tls_proto_encode_log(1700000000123LL, &events[0], 1, &raw_logs[0]) == 0);
        REQUIRE(ve_tls_proto_encode_log_ex(1700000000124LL, 456, 1, &events[1], 1, &raw_logs[1]) == 0);
        REQUIRE(ve_tls_proto_encode_log_group_list_ex2(raw_logs, 2, "raw-source", "raw-file", &tag, 1,
            "raw-context", kv ? 1 : 10000, &wire.bodies[wire.count]) == 0);
        /* Match the pre-marker Raw writer: store the request body as an
           unmarked V2 record, via the same append path as KV. */
        REQUIRE(ve_tls_persistent_append(producer->persistent, (int64_t)wire.count + 1, NULL,
            wire.bodies[wire.count].data, wire.bodies[wire.count].size) == 0);
        wire.count++;
    }
    if (raw && kv) {
        REQUIRE(append_legacy_kv(producer->persistent, 3, 1700000000125LL, 1,
            markers[D], &cfg, &wire.bodies[wire.count]) == 0);
        wire.count++;
    }
    REQUIRE(close_producer(&producer) == 0 && checkpoint_ack(dir, &ack) == 0 && ack == 0);
    REQUIRE(atomic_load(&wire.unexpected) == 0);
    for (size_t i = 0; i < wire.count; i++) REQUIRE(atomic_load(&wire.hits[i]) == 0);

    producer = ve_tls_producer_create_exclusive_persistence(&cfg, sizeof(cfg));
    REQUIRE(producer != NULL);
    ve_tls_producer_set_send_done_v2(producer, send_done, &callbacks);
    REQUIRE(ve_tls_producer_recover(producer) == VE_TLS_OK && close_producer(&producer) == 0);
    REQUIRE(atomic_load(&wire.unexpected) == 0);
    REQUIRE(checkpoint_ack(dir, &ack) == 0 && ack == (int64_t)wire.count);
    for (size_t i = 0; i < wire.count; i++) {
        REQUIRE(atomic_load(&wire.hits[i]) == 1 && atomic_load(&callbacks.ok[i + 1]) == 1);
    }

    producer = ve_tls_producer_create_exclusive_persistence(&cfg, sizeof(cfg));
    REQUIRE(producer != NULL && ve_tls_producer_recover(producer) == VE_TLS_OK && close_producer(&producer) == 0);
    REQUIRE(atomic_load(&wire.unexpected) == 0);
    for (size_t i = 0; i < wire.count; i++) REQUIRE(atomic_load(&wire.hits[i]) == 1);
cleanup:
    if (producer) ve_tls_producer_destroy(producer);
    for (size_t i = 0; i < LEGACY_REPLAY_MAX; i++) ve_tls_bytes_free(&wire.bodies[i]);
    for (size_t i = 0; i < 2; i++) ve_tls_bytes_free(&raw_logs[i]);
    if (dir[0]) remove_dir(dir);
    return failed ? -1 : 0;
}

static int test_legacy_raw_wal_preserves_body(void) {
    return test_legacy_wal_replay(1, 0);
}

static int test_legacy_kv_wal_builds_group_list(void) {
    return test_legacy_wal_replay(0, 1);
}

static int test_mixed_legacy_wal_sends_raw_and_kv(void) {
    return test_legacy_wal_replay(1, 1);
}

typedef struct {
    ve_tls_producer * producer;
    const char * marker;
    ve_tls_result result;
    int64_t id;
    int fail_write;
    _Atomic int waiting_for_wal;
} concurrent_append;

static _Thread_local concurrent_append * current_append;
static _Atomic int first_write_entered;
static _Atomic int release_first_write;
static ve_tls_mutex * concurrent_wal_mutex;

static void concurrent_await_wal(ve_tls_mutex * mutex) {
    if (current_append && mutex == concurrent_wal_mutex) atomic_store(&current_append->waiting_for_wal, 1);
    replay_platform.mutex_lock(mutex);
}

static int64_t concurrent_write(ve_tls_file * file, const void * data, size_t size) {
    if (current_append && !atomic_exchange(&first_write_entered, 1)) {
        if (wait_value(&release_first_write, 1, 5000) != 0) return -1;
        if (current_append->fail_write) return -1;
    }
    return replay_platform.file_write(file, data, size);
}

static void * append_concurrently(void * arg) {
    concurrent_append * append = arg;
    ve_tls_kv kv = {"event_id", append->marker};
    current_append = append;
    append->result = ve_tls_producer_add_log_kv_with_id(append->producer,
        1700000000000LL, &kv, 1, 1, &append->id);
    return NULL;
}

static int test_concurrent_append_ids(int fail_write) {
    int failed = 0;
    char dir[PATH_MAX] = {0};
    ve_tls_config cfg;
    mock_state state;
    ve_tls_producer * producer = NULL;
    ve_tls_thread * first = NULL;
    ve_tls_thread * second = NULL;
    int64_t id = 0, ack = 0;
    init_mock(&state, 0, !fail_write);
    REQUIRE(make_dir(dir, sizeof(dir)) == 0 && customer_wal_config(&cfg, dir) == 0);
    replay_platform = cfg.platform;
    cfg.platform.mutex_lock = concurrent_await_wal;
    cfg.platform.file_write = concurrent_write;
    if (!fail_write) cfg.persistent_max_records = 1;
    producer = open_customer_wal(&cfg, &state);
    REQUIRE(producer != NULL);
    concurrent_wal_mutex = producer->persistent_mutex;
    atomic_store(&first_write_entered, 0);
    atomic_store(&release_first_write, 0);
    concurrent_append a = {.producer = producer, .marker = markers[A], .fail_write = fail_write};
    concurrent_append b = {.producer = producer, .marker = markers[B]};
    first = replay_platform.thread_create(append_concurrently, &a);
    REQUIRE(first && wait_value(&first_write_entered, 1, 5000) == 0);
    second = replay_platform.thread_create(append_concurrently, &b);
    REQUIRE(second && wait_value(&b.waiting_for_wal, 1, 5000) == 0);
    atomic_store(&release_first_write, 1);
    replay_platform.thread_join(first);
    first = NULL;
    replay_platform.thread_join(second);
    second = NULL;
    if (fail_write) {
        REQUIRE(a.result == VE_TLS_PERSISTENT_ERROR && a.id == 0 && b.result == VE_TLS_OK && b.id == 1);
    } else {
        REQUIRE(a.result == VE_TLS_OK && a.id == 1 && b.result == VE_TLS_DROP_ERROR && b.id == 0);
        REQUIRE(wait_value(&state.block_entered, 1, 5000) == 0);
        atomic_store(&state.release_block, 1);
    }
    REQUIRE(wait_result(&state, 1, 1) == 0);
    REQUIRE(add(producer, C, &id) == 0 && id == 2);
    REQUIRE(close_producer(&producer) == 0 && checkpoint_ack(dir, &ack) == 0 && ack == 2);
    REQUIRE(hit_count(&state, A) == !fail_write && hit_count(&state, B) == fail_write && hit_count(&state, C) == 1);
cleanup:
    atomic_store(&release_first_write, 1);
    atomic_store(&state.release_block, 1);
    if (first) replay_platform.thread_join(first);
    if (second) replay_platform.thread_join(second);
    if (producer) ve_tls_producer_destroy(producer);
    if (dir[0]) remove_dir(dir);
    return failed ? -1 : 0;
}

static int test_concurrent_capacity_reject_does_not_consume_id(void) {
    return test_concurrent_append_ids(0);
}

static int test_concurrent_rollback_reuses_id(void) {
    return test_concurrent_append_ids(1);
}

int main(int argc, char ** argv) {
    struct { const char * name; int (*run)(void); } tests[] = {
        {"idle_ack_survives_process_exit", test_idle_ack_survives_process_exit},
        {"idle_sparse_ack_survives_process_exit", test_idle_sparse_ack_survives_process_exit},
        {"sparse_ack_and_high_id", test_sparse_ack_and_high_id},
        {"high_id_after_fully_acked_restart", test_high_id_after_fully_acked_restart},
        {"concurrent_out_of_order_ack", test_concurrent_out_of_order_ack},
        {"legacy_backlog_with_builder_paused", test_legacy_backlog_with_builder_paused},
        {"legacy_backlog_with_transport_paused", test_legacy_backlog_with_transport_paused},
        {"legacy_backlog_close_then_reopen", test_legacy_backlog_close_then_reopen},
        {"background_recovery_retries_segment_stat", test_background_recovery_retries_segment_stat},
        {"background_recovery_retries_segment_open", test_background_recovery_retries_segment_open},
        {"background_recovery_retries_segment_read", test_background_recovery_retries_segment_read},
        {"initial_recovery_retries_segment_stat", test_initial_recovery_retries_segment_stat},
        {"initial_recovery_retries_segment_open", test_initial_recovery_retries_segment_open},
        {"initial_recovery_retries_segment_read", test_initial_recovery_retries_segment_read},
        {"active_wal_scan_preserves_records_on_read_error", test_active_wal_scan_preserves_records_on_read_error},
        {"closed_wal_scan_preserves_unacked_records_on_unexpected_eof", test_closed_wal_scan_preserves_unacked_records_on_unexpected_eof},
        {"wal_rotation_open_failure_allows_next_append", test_wal_rotation_open_failure_allows_next_append},
        {"checkpoint_prefix_read_error_preserves_checkpoint", test_checkpoint_prefix_read_error_preserves_checkpoint},
        {"checkpoint_ranges_read_error_preserves_checkpoint", test_checkpoint_ranges_read_error_preserves_checkpoint},
        {"missing_checkpoint_recovers_remaining_segments", test_missing_checkpoint_recovers_remaining_segments},
        {"corrupt_checkpoint_recovers_remaining_segments", test_corrupt_checkpoint_recovers_remaining_segments},
        {"full_acked_record_limit", test_full_acked_record_limit},
        {"full_acked_byte_limit", test_full_acked_byte_limit},
        {"full_acked_segment_limit", test_full_acked_segment_limit},
        {"active_reuse_preserves_reader_position", test_active_reuse_preserves_reader_position},
        {"active_reuse_waits_for_checkpoint", test_active_reuse_waits_for_checkpoint},
        {"reclaim_keeps_unacked_segment_discoverable", test_reclaim_keeps_unacked_segment_discoverable},
        {"rejected_append_keeps_ids_contiguous", test_rejected_append_keeps_ids_contiguous},
        {"concurrent_capacity_reject_does_not_consume_id", test_concurrent_capacity_reject_does_not_consume_id},
        {"concurrent_rollback_reuses_id", test_concurrent_rollback_reuses_id},
        {"zero_byte_write_rollback_reuses_id", test_zero_byte_write_rollback_reuses_id},
        {"short_write_rollback_reuses_id", test_short_write_rollback_reuses_id},
        {"failed_truncate_preserves_uncertain_id", test_failed_truncate_preserves_uncertain_id},
        {"failed_rollback_sync_preserves_uncertain_id", test_failed_rollback_sync_preserves_uncertain_id},
        {"uncertain_sync_preserves_unacked_id", test_uncertain_sync_preserves_unacked_id},
        {"live_wal_survives_memory_backpressure", test_live_wal_survives_memory_backpressure},
        {"live_wal_survives_send_queue_backpressure", test_live_wal_survives_send_queue_backpressure},
        {"wal_retries_batch_key_allocation", test_wal_retries_batch_key_allocation},
        {"wal_retries_batch_body_allocation", test_wal_retries_batch_body_allocation},
        {"wal_retains_batch_after_allocation_retry_fails", test_wal_retains_batch_after_allocation_retry_fails},
        {"live_raw_wal_preserves_payload", test_live_raw_wal_preserves_payload},
        {"legacy_raw_wal_preserves_body", test_legacy_raw_wal_preserves_body},
        {"legacy_kv_wal_builds_group_list", test_legacy_kv_wal_builds_group_list},
        {"mixed_legacy_wal_sends_raw_and_kv", test_mixed_legacy_wal_sends_raw_and_kv},
        {"active_mid_segment_crc_keeps_suffix", test_active_mid_segment_crc_keeps_suffix},
        {"closed_mid_segment_crc_keeps_suffix", test_closed_mid_segment_crc_keeps_suffix},
        {"overlapping_segment_crc_keeps_gap", test_overlapping_segment_crc_keeps_gap},
        {"active_mid_segment_metadata_crc_keeps_suffix", test_active_mid_segment_metadata_crc_keeps_suffix},
        {"closed_mid_segment_metadata_crc_keeps_suffix", test_closed_mid_segment_metadata_crc_keeps_suffix},
        {"active_crc_with_unframed_tail_keeps_suffix", test_active_crc_with_unframed_tail_keeps_suffix},
        {"drop_oldest_rename_failure_is_atomic", test_drop_oldest_rename_failure_is_atomic},
        {"drop_oldest_directory_fsync_failure_is_atomic", test_drop_oldest_directory_fsync_failure_is_atomic},
        {"reject_new_directory_fsync_failure_keeps_gap", test_reject_new_directory_fsync_failure_keeps_gap},
        {"checkpoint_failure_backoff_after_save_window", test_checkpoint_failure_backoff_after_save_window},
        {"checkpoint_failure_backoff_after_ack_threshold", test_checkpoint_failure_backoff_after_ack_threshold},
        {"many_sparse_ranges_merge_and_oom", test_many_sparse_ranges_merge_and_oom},
    };
    int failures = 0;
    int selected = 0;
    for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
        if (argc > 1 && strcmp(argv[1], tests[i].name) != 0) continue;
        selected++;
        int rc = tests[i].run();
        printf("%s %s\n", rc == 0 ? "PASS" : "FAIL", tests[i].name);
        fflush(stdout);
        if (rc != 0) failures++;
    }
    return failures || !selected ? 1 : 0;
}
