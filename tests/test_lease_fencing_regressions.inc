/* Deterministic lease-fencing regressions.  This file is included by
 * test_basic.c after its common fixtures and before main(). */

#include <pthread.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <errno.h>
#include <time.h>

typedef struct {
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    int armed;
    int entered;
    int released;
    int first_taken;
} lf_gate;

static lf_gate * g_lf_rename_gate = NULL;
static lf_gate * g_lf_remove_gate = NULL;
static lf_gate * g_lf_write_gate = NULL;
static ve_tls_file * g_lf_segment_file = NULL;
static int g_lf_capture_segment_file = 0;
static int g_lf_write_count = 0;
static int g_lf_fork_enter_fd = -1;
static int g_lf_fork_release_fd = -1;
static int g_lf_fork_entered = 0;

typedef struct {
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    int go;
} lf_start_gate;

typedef struct {
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    int armed;
    int count;
    int released;
} lf_stat_gate;

static lf_stat_gate * g_lf_stat_gate = NULL;
static int g_lf_lease_path_stat_count = 0;
static int g_lf_lease_file_read_count = 0;

static void lf_gate_init(lf_gate * gate) {
    memset(gate, 0, sizeof(*gate));
    pthread_mutex_init(&gate->mutex, NULL);
    pthread_cond_init(&gate->cond, NULL);
}

static void lf_gate_destroy(lf_gate * gate) {
    pthread_cond_destroy(&gate->cond);
    pthread_mutex_destroy(&gate->mutex);
}

static void lf_gate_arm(lf_gate * gate) {
    pthread_mutex_lock(&gate->mutex);
    gate->armed = 1;
    gate->entered = 0;
    gate->released = 0;
    gate->first_taken = 0;
    pthread_mutex_unlock(&gate->mutex);
}

static int lf_gate_wait_entered(lf_gate * gate) {
    int rc = 0;
    pthread_mutex_lock(&gate->mutex);
    while (!gate->entered) {
        struct timespec deadline;
        if (clock_gettime(CLOCK_REALTIME, &deadline) != 0) {
            rc = -1;
            break;
        }
        deadline.tv_sec += 3;
        if (pthread_cond_timedwait(&gate->cond, &gate->mutex, &deadline) == ETIMEDOUT) {
            rc = -1;
            break;
        }
    }
    pthread_mutex_unlock(&gate->mutex);
    return rc;
}

static void lf_gate_release(lf_gate * gate) {
    pthread_mutex_lock(&gate->mutex);
    gate->released = 1;
    pthread_cond_broadcast(&gate->cond);
    pthread_mutex_unlock(&gate->mutex);
}

static void lf_start_gate_init(lf_start_gate * gate) {
    memset(gate, 0, sizeof(*gate));
    pthread_mutex_init(&gate->mutex, NULL);
    pthread_cond_init(&gate->cond, NULL);
}

static void lf_start_gate_destroy(lf_start_gate * gate) {
    pthread_cond_destroy(&gate->cond);
    pthread_mutex_destroy(&gate->mutex);
}

static void lf_start_gate_start(lf_start_gate * gate) {
    pthread_mutex_lock(&gate->mutex);
    gate->go = 1;
    pthread_cond_broadcast(&gate->cond);
    pthread_mutex_unlock(&gate->mutex);
}

static void lf_start_gate_wait(lf_start_gate * gate) {
    pthread_mutex_lock(&gate->mutex);
    while (!gate->go) {
        pthread_cond_wait(&gate->cond, &gate->mutex);
    }
    pthread_mutex_unlock(&gate->mutex);
}

static void lf_stat_gate_init(lf_stat_gate * gate) {
    memset(gate, 0, sizeof(*gate));
    pthread_mutex_init(&gate->mutex, NULL);
    pthread_cond_init(&gate->cond, NULL);
}

static void lf_stat_gate_destroy(lf_stat_gate * gate) {
    pthread_cond_destroy(&gate->cond);
    pthread_mutex_destroy(&gate->mutex);
}

static int lf_stat_gate_wait_count(lf_stat_gate * gate, int wanted) {
    int rc = 0;
    pthread_mutex_lock(&gate->mutex);
    while (gate->count < wanted) {
        struct timespec deadline;
        if (clock_gettime(CLOCK_REALTIME, &deadline) != 0) {
            rc = -1;
            break;
        }
        deadline.tv_sec += 1;
        if (pthread_cond_timedwait(&gate->cond, &gate->mutex, &deadline) == ETIMEDOUT) {
            rc = -1;
            break;
        }
    }
    pthread_mutex_unlock(&gate->mutex);
    return rc;
}

static void lf_stat_gate_release(lf_stat_gate * gate) {
    pthread_mutex_lock(&gate->mutex);
    gate->released = 1;
    pthread_cond_broadcast(&gate->cond);
    pthread_mutex_unlock(&gate->mutex);
}

static int lf_is_lease_path(const char * path) {
    size_t n;
    static const char suffix[] = "/lease";
    if (!path) {
        return 0;
    }
    n = strlen(path);
    return n >= sizeof(suffix) - 1 &&
        strcmp(path + n - (sizeof(suffix) - 1), suffix) == 0;
}

static int lf_gated_path_stat(const char * path, ve_tls_path_info * info) {
    int rc = g_real_platform.path_stat(path, info);
    if (rc == 0 && lf_is_lease_path(path) && g_lf_stat_gate) {
        pthread_mutex_lock(&g_lf_stat_gate->mutex);
        if (g_lf_stat_gate->armed && g_lf_stat_gate->count < 2) {
            g_lf_stat_gate->count++;
            pthread_cond_broadcast(&g_lf_stat_gate->cond);
            while (!g_lf_stat_gate->released) {
                pthread_cond_wait(&g_lf_stat_gate->cond, &g_lf_stat_gate->mutex);
            }
        }
        pthread_mutex_unlock(&g_lf_stat_gate->mutex);
    }
    return rc;
}

static int lf_count_lease_path_stat(const char * path, ve_tls_path_info * info) {
    int rc = g_real_platform.path_stat(path, info);
    if (rc == 0 && lf_is_lease_path(path)) {
        __atomic_add_fetch(&g_lf_lease_path_stat_count, 1, __ATOMIC_ACQ_REL);
    }
    return rc;
}

static ve_tls_file * lf_count_lease_file_open(const char * path, int flags, int mode) {
    if (path && lf_is_lease_path(path) && (flags & VE_TLS_FILE_OPEN_RDONLY) != 0) {
        __atomic_add_fetch(&g_lf_lease_file_read_count, 1, __ATOMIC_ACQ_REL);
    }
    return g_real_platform.file_open(path, flags, mode);
}

static void lf_gate_before_lease_mutation(lf_gate * gate) {
    if (!gate) {
        return;
    }
    pthread_mutex_lock(&gate->mutex);
    if (gate->armed && !gate->first_taken) {
        gate->first_taken = 1;
        gate->entered = 1;
        pthread_cond_broadcast(&gate->cond);
        while (!gate->released) {
            pthread_cond_wait(&gate->cond, &gate->mutex);
        }
    }
    pthread_mutex_unlock(&gate->mutex);
}

static int lf_gated_path_rename(const char * from, const char * to) {
    if (lf_is_lease_path(to)) {
        lf_gate_before_lease_mutation(g_lf_rename_gate);
    }
    return g_real_platform.path_rename(from, to);
}

static int lf_gated_path_remove(const char * path) {
    if (lf_is_lease_path(path)) {
        lf_gate_before_lease_mutation(g_lf_remove_gate);
    }
    return g_real_platform.path_remove(path);
}

static ve_tls_file * lf_capture_file_open(const char * path, int flags, int mode) {
    ve_tls_file * file = g_real_platform.file_open(path, flags, mode);
    if (file && g_lf_capture_segment_file && path && strstr(path, "/seg-") != NULL &&
        (flags & VE_TLS_FILE_OPEN_APPEND) != 0 && g_lf_segment_file == NULL) {
        g_lf_segment_file = file;
    }
    return file;
}

static int64_t lf_gated_file_write(ve_tls_file * file, const void * buf, size_t size) {
    if (file && file == g_lf_segment_file) {
        lf_gate_before_lease_mutation(g_lf_write_gate);
    }
    __atomic_add_fetch(&g_lf_write_count, 1, __ATOMIC_ACQ_REL);
    return g_real_platform.file_write(file, buf, size);
}

static int lf_read_file_snapshot(
    ve_tls_platform * platform,
    const char * path,
    unsigned char ** out_data,
    size_t * out_size
) {
    ve_tls_path_info info;
    ve_tls_file * file;
    unsigned char * data;
    size_t offset = 0;
    if (!platform || !path || !out_data || !out_size ||
        platform->path_stat(path, &info) != 0 || !info.exists || info.size > SIZE_MAX) {
        return -1;
    }
    data = (unsigned char *)malloc(info.size > 0 ? (size_t)info.size : 1);
    if (!data) {
        return -1;
    }
    file = platform->file_open(path, VE_TLS_FILE_OPEN_RDONLY, 0);
    if (!file) {
        free(data);
        return -1;
    }
    while (offset < (size_t)info.size) {
        int64_t n = platform->file_read(file, data + offset, (size_t)info.size - offset);
        if (n <= 0) {
            platform->file_close(file);
            free(data);
            return -1;
        }
        offset += (size_t)n;
    }
    platform->file_close(file);
    *out_data = data;
    *out_size = (size_t)info.size;
    return 0;
}

static int lf_fork_blocking_path_rename(const char * from, const char * to) {
    if (lf_is_lease_path(to) && !g_lf_fork_entered) {
        char marker = 'L';
        g_lf_fork_entered = 1;
        if (write(g_lf_fork_enter_fd, &marker, 1) != 1) {
            _exit(2);
        }
        while (read(g_lf_fork_release_fd, &marker, 1) > 0) {
        }
    }
    return g_real_platform.path_rename(from, to);
}

static void lf_cleanup_dir(const char * dir) {
    char lock_path[PATH_MAX];
    if (dir) {
        join_path(lock_path, sizeof(lock_path), dir, "lease.lock");
        unlink(lock_path);
    }
    cleanup_persistent_dir(dir);
}

static void lf_make_options(
    ve_tls_persistent_options * options,
    ve_tls_platform * platform,
    const char * dir,
    const char * owner_id,
    int64_t now_ms
) {
    memset(options, 0, sizeof(*options));
    options->platform = platform;
    options->dir_path = dir;
    options->instance_id = "lease-fencing-regression";
    options->owner_id = owner_id;
    options->owner_process_name = "lease-fencing-test";
    options->owner_pid = (int32_t)getpid();
    options->segment_max_bytes = 4096;
    options->segment_max_records = 128;
    options->max_bytes = 1024 * 1024;
    options->max_records = 512;
    options->max_segments = 8;
    options->now_ms = now_ms;
    options->lease_timeout_ms = 1000;
    options->heartbeat_interval_ms = 100;
    options->open_mode = VE_TLS_LEASE_OPEN_TAKEOVER_IF_STALE;
    options->durability = VE_TLS_PDURABILITY_BUFFERED_WAL;
}

static int lf_lease_matches(const ve_tls_lease_state * left, const ve_tls_lease_state * right) {
    return left && right &&
        strcmp(left->owner_id, right->owner_id) == 0 &&
        left->owner_pid == right->owner_pid &&
        strcmp(left->owner_process_name, right->owner_process_name) == 0 &&
        left->acquire_time_ms == right->acquire_time_ms &&
        left->last_heartbeat_ms == right->last_heartbeat_ms &&
        left->fencing_token == right->fencing_token;
}

typedef struct {
    ve_tls_persistent * persistent;
    int rc;
} lf_persistent_thread_arg;

typedef struct {
    lf_start_gate * start;
    ve_tls_lease_state * state;
    const ve_tls_lease_options * options;
    int rc;
} lf_open_thread_arg;

static void * lf_heartbeat_thread(void * arg) {
    lf_persistent_thread_arg * state = (lf_persistent_thread_arg *)arg;
    state->rc = ve_tls_persistent_heartbeat_if_due(state->persistent, 1);
    return NULL;
}

static void * lf_append_thread(void * arg) {
    lf_persistent_thread_arg * state = (lf_persistent_thread_arg *)arg;
    static const unsigned char payload[] = "lease-fencing-append";
    state->rc = ve_tls_persistent_append(
        state->persistent, 1, NULL, payload, sizeof(payload) - 1);
    return NULL;
}

static void * lf_close_thread(void * arg) {
    lf_persistent_thread_arg * state = (lf_persistent_thread_arg *)arg;
    ve_tls_persistent_close(state->persistent);
    state->rc = 0;
    return NULL;
}

static void * lf_open_thread(void * arg) {
    lf_open_thread_arg * state = (lf_open_thread_arg *)arg;
    lf_start_gate_wait(state->start);
    state->rc = ve_tls_lease_acquire(state->options, state->state);
    return NULL;
}

typedef struct {
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    int started;
    int done;
    int rc;
} lf_done;

typedef struct {
    ve_tls_persistent * persistent;
    int64_t log_id;
    lf_done * done;
} lf_append_done_arg;

static void lf_done_init(lf_done * done) {
    memset(done, 0, sizeof(*done));
    pthread_mutex_init(&done->mutex, NULL);
    pthread_cond_init(&done->cond, NULL);
}

static void lf_done_destroy(lf_done * done) {
    pthread_cond_destroy(&done->cond);
    pthread_mutex_destroy(&done->mutex);
}

static int lf_done_wait(lf_done * done, int timeout_ms) {
    struct timespec deadline;
    int rc = 0;
    if (!done || timeout_ms < 0 || clock_gettime(CLOCK_REALTIME, &deadline) != 0) {
        return -1;
    }
    deadline.tv_sec += timeout_ms / 1000;
    deadline.tv_nsec += (long)(timeout_ms % 1000) * 1000000L;
    if (deadline.tv_nsec >= 1000000000L) {
        deadline.tv_sec++;
        deadline.tv_nsec -= 1000000000L;
    }
    pthread_mutex_lock(&done->mutex);
    while (!done->done) {
        rc = pthread_cond_timedwait(&done->cond, &done->mutex, &deadline);
        if (rc == ETIMEDOUT) {
            break;
        }
        if (rc != 0) {
            pthread_mutex_unlock(&done->mutex);
            return -1;
        }
    }
    if (!done->done && rc == 0) {
        rc = ETIMEDOUT;
    }
    pthread_mutex_unlock(&done->mutex);
    return rc == 0 ? 0 : -1;
}

static int lf_done_wait_started(lf_done * done, int timeout_ms) {
    struct timespec deadline;
    int rc = 0;
    if (!done || timeout_ms < 0 || clock_gettime(CLOCK_REALTIME, &deadline) != 0) {
        return -1;
    }
    deadline.tv_sec += timeout_ms / 1000;
    deadline.tv_nsec += (long)(timeout_ms % 1000) * 1000000L;
    if (deadline.tv_nsec >= 1000000000L) {
        deadline.tv_sec++;
        deadline.tv_nsec -= 1000000000L;
    }
    pthread_mutex_lock(&done->mutex);
    while (!done->started) {
        rc = pthread_cond_timedwait(&done->cond, &done->mutex, &deadline);
        if (rc == ETIMEDOUT) {
            break;
        }
        if (rc != 0) {
            pthread_mutex_unlock(&done->mutex);
            return -1;
        }
    }
    if (!done->started && rc == 0) {
        rc = ETIMEDOUT;
    }
    pthread_mutex_unlock(&done->mutex);
    return rc == 0 ? 0 : -1;
}

static void * lf_append_done_thread(void * arg) {
    static const unsigned char payload[] = "lease-fencing-shared-fd";
    lf_append_done_arg * state = (lf_append_done_arg *)arg;
    if (!state || !state->persistent || !state->done) {
        return NULL;
    }
    pthread_mutex_lock(&state->done->mutex);
    state->done->started = 1;
    pthread_cond_broadcast(&state->done->cond);
    pthread_mutex_unlock(&state->done->mutex);
    state->done->rc = ve_tls_persistent_append(
        state->persistent, state->log_id, NULL, payload, sizeof(payload) - 1);
    pthread_mutex_lock(&state->done->mutex);
    state->done->done = 1;
    pthread_cond_broadcast(&state->done->cond);
    pthread_mutex_unlock(&state->done->mutex);
    return NULL;
}

static int lf_read_byte_timeout(int fd, char * value) {
    fd_set read_set;
    struct timeval timeout;
    if (fd < 0 || !value) {
        return -1;
    }
    FD_ZERO(&read_set);
    FD_SET(fd, &read_set);
    timeout.tv_sec = 3;
    timeout.tv_usec = 0;
    if (select(fd + 1, &read_set, NULL, NULL, &timeout) != 1 ||
        read(fd, value, 1) != 1) {
        return -1;
    }
    return 0;
}

static int test_lease_fencing_persistent_shared_fd(void) {
    char dir[PATH_MAX];
    ve_tls_config cfg;
    ve_tls_persistent persistent;
    ve_tls_persistent_options options;
    lf_gate write_gate;
    lf_done first_done;
    lf_done second_done;
    lf_append_done_arg first_arg;
    lf_append_done_arg second_arg;
    ve_tls_thread * first_thread = NULL;
    ve_tls_thread * second_thread = NULL;
    int writes_while_blocked;
    int failed = 0;

    if (make_temp_dir(dir, sizeof(dir)) != 0) {
        return -1;
    }
    ve_tls_config_init(&cfg);
    g_real_platform = cfg.platform;
    cfg.platform.time_ms = test_fake_time_ms;
    cfg.platform.file_open = lf_capture_file_open;
    cfg.platform.file_write = lf_gated_file_write;
    g_fake_time = 1000;
    g_lf_capture_segment_file = 1;
    g_lf_segment_file = NULL;
    __atomic_store_n(&g_lf_write_count, 0, __ATOMIC_RELEASE);
    lf_make_options(&options, &cfg.platform, dir, "shared-fd-owner", 1000);
    memset(&persistent, 0, sizeof(persistent));
    lf_gate_init(&write_gate);
    lf_done_init(&first_done);
    lf_done_init(&second_done);
    g_lf_write_gate = &write_gate;
    if (ve_tls_persistent_open(&persistent, &options) != 0 ||
        persistent.lease_fd < 0 || fcntl(persistent.lease_fd, F_GETFD) < 0 ||
        !g_lf_segment_file) {
        failed = 1;
        goto done;
    }
    lf_gate_arm(&write_gate);
    memset(&first_arg, 0, sizeof(first_arg));
    first_arg.persistent = &persistent;
    first_arg.log_id = 1;
    first_arg.done = &first_done;
    first_thread = cfg.platform.thread_create(lf_append_done_thread, &first_arg);
    if (!first_thread || lf_gate_wait_entered(&write_gate) != 0) {
        failed = 1;
        goto done;
    }
    writes_while_blocked = __atomic_load_n(&g_lf_write_count, __ATOMIC_ACQUIRE);
    memset(&second_arg, 0, sizeof(second_arg));
    second_arg.persistent = &persistent;
    second_arg.log_id = 2;
    second_arg.done = &second_done;
    second_thread = cfg.platform.thread_create(lf_append_done_thread, &second_arg);
    if (!second_thread || lf_done_wait_started(&second_done, 1000) != 0 ||
        lf_done_wait(&second_done, 1000) == 0 ||
        __atomic_load_n(&g_lf_write_count, __ATOMIC_ACQUIRE) != writes_while_blocked) {
        failed = 1;
        goto done;
    }
    lf_gate_release(&write_gate);
    cfg.platform.thread_join(first_thread);
    first_thread = NULL;
    cfg.platform.thread_join(second_thread);
    second_thread = NULL;
    if (first_done.rc != 0 || second_done.rc != 0 || persistent.current_records != 2) {
        failed = 1;
    }

done:
    if (first_thread || second_thread) {
        lf_gate_release(&write_gate);
    }
    if (first_thread) {
        cfg.platform.thread_join(first_thread);
    }
    if (second_thread) {
        cfg.platform.thread_join(second_thread);
    }
    if (persistent.platform) {
        ve_tls_persistent_close(&persistent);
    }
    g_lf_write_gate = NULL;
    g_lf_capture_segment_file = 0;
    g_lf_segment_file = NULL;
    lf_done_destroy(&first_done);
    lf_done_destroy(&second_done);
    lf_gate_destroy(&write_gate);
    lf_cleanup_dir(dir);
    return failed ? -1 : 0;
}

static int test_lease_fencing_persistent_fork_fd(void) {
    char dir[PATH_MAX];
    char lease_path[PATH_MAX];
    ve_tls_config cfg;
    ve_tls_persistent persistent;
    ve_tls_persistent_options options;
    int report_pipe[2] = {-1, -1};
    pid_t child = -1;
    int parent_mutex_locked = 0;
    int parent_fd_locked = 0;
    int probe_fd = -1;
    int status = 0;
    char marker = 0;
    int failed = 0;

    dir[0] = 0;
    if (make_temp_dir(dir, sizeof(dir)) != 0 || pipe(report_pipe) != 0) {
        if (report_pipe[0] >= 0) close(report_pipe[0]);
        if (report_pipe[1] >= 0) close(report_pipe[1]);
        if (dir[0] != 0) lf_cleanup_dir(dir);
        return -1;
    }
    ve_tls_config_init(&cfg);
    g_real_platform = cfg.platform;
    cfg.platform.time_ms = test_fake_time_ms;
    g_fake_time = 1000;
    lf_make_options(&options, &cfg.platform, dir, "fork-fd-owner", 1000);
    memset(&persistent, 0, sizeof(persistent));
    join_path(lease_path, sizeof(lease_path), dir, "lease");
    if (ve_tls_persistent_open(&persistent, &options) != 0 || persistent.lease_fd < 0 ||
        fcntl(persistent.lease_fd, F_GETFD) < 0 ||
        ve_tls_lease_guard_lock(persistent.lease_fd, 1) != 0) {
        failed = 1;
        goto done;
    }
    parent_fd_locked = 1;
    if (!persistent.heartbeat_mutex || !cfg.platform.mutex_lock || !cfg.platform.mutex_unlock) {
        failed = 1;
        goto done;
    }
    cfg.platform.mutex_lock(persistent.heartbeat_mutex);
    parent_mutex_locked = 1;
    child = fork();
    if (child < 0) {
        failed = 1;
        goto done;
    }
    if (child == 0) {
        static const unsigned char payload[] = "fork-child-must-fail";
        close(report_pipe[0]);
        int child_rc = ve_tls_persistent_append(&persistent, 1, NULL, payload, sizeof(payload) - 1);
        char child_marker = child_rc != 0 ? 'R' : 'F';
        if (write(report_pipe[1], &child_marker, 1) != 1) {
            _exit(2);
        }
        ve_tls_persistent_close(&persistent);
        child_marker = 'C';
        if (write(report_pipe[1], &child_marker, 1) != 1) {
            _exit(3);
        }
        _exit(child_rc != 0 ? 0 : 1);
    }
    close(report_pipe[1]);
    report_pipe[1] = -1;
    cfg.platform.mutex_unlock(persistent.heartbeat_mutex);
    parent_mutex_locked = 0;
    if (lf_read_byte_timeout(report_pipe[0], &marker) != 0 || marker != 'R' ||
        lf_read_byte_timeout(report_pipe[0], &marker) != 0 || marker != 'C') {
        /* A child operation must fail before touching the inherited mutex;
         * close must only close the inherited descriptor. */
        failed = 1;
        goto done;
    }
    if (ve_tls_lease_guard_enter(lease_path, 0, &probe_fd) == 0 || probe_fd != -1) {
        /* The parent still owns the lock after child close. */
        failed = 1;
        goto done;
    }
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        failed = 1;
        child = -1;
        goto done;
    }
    child = -1;
    if (ve_tls_lease_guard_unlock(persistent.lease_fd) != 0) {
        failed = 1;
        parent_fd_locked = 0;
        goto done;
    }
    parent_fd_locked = 0;
    if (ve_tls_lease_guard_enter(lease_path, 0, &probe_fd) != 0 || probe_fd < 0) {
        failed = 1;
        goto done;
    }
    ve_tls_lease_guard_leave(probe_fd);
    probe_fd = -1;

done:
    if (parent_mutex_locked && persistent.heartbeat_mutex) {
        cfg.platform.mutex_unlock(persistent.heartbeat_mutex);
        parent_mutex_locked = 0;
    }
    if (child > 0) {
        (void)kill(child, SIGKILL);
        (void)waitpid(child, &status, 0);
    }
    if (parent_fd_locked && persistent.lease_fd >= 0) {
        (void)ve_tls_lease_guard_unlock(persistent.lease_fd);
        parent_fd_locked = 0;
    }
    if (probe_fd >= 0) {
        ve_tls_lease_guard_leave(probe_fd);
    }
    if (report_pipe[0] >= 0) close(report_pipe[0]);
    if (report_pipe[1] >= 0) close(report_pipe[1]);
    if (persistent.platform) {
        ve_tls_persistent_close(&persistent);
        ve_tls_persistent_close(&persistent);
    }
    lf_cleanup_dir(dir);
    return failed ? -1 : 0;
}

static int test_lease_fencing_persistent_fd_lifecycle(void) {
    char dir[PATH_MAX];
    char lease_path[PATH_MAX];
    char manifest_path[PATH_MAX];
    ve_tls_config cfg;
    ve_tls_persistent persistent;
    ve_tls_persistent failed_persistent;
    ve_tls_persistent_options options;
    FILE * manifest = NULL;
    int lease_fd = -1;
    int probe_fd = -1;
    int failed = 0;

    if (make_temp_dir(dir, sizeof(dir)) != 0) {
        return -1;
    }
    ve_tls_config_init(&cfg);
    g_real_platform = cfg.platform;
    cfg.platform.time_ms = test_fake_time_ms;
    g_fake_time = 1000;
    lf_make_options(&options, &cfg.platform, dir, "lifecycle-owner", 1000);
    memset(&persistent, 0, sizeof(persistent));
    memset(&failed_persistent, 0, sizeof(failed_persistent));
    join_path(lease_path, sizeof(lease_path), dir, "lease");
    join_path(manifest_path, sizeof(manifest_path), dir, "manifest");
    manifest = fopen(manifest_path, "wb");
    if (!manifest || fputs("invalid-manifest\n", manifest) == EOF) {
        if (manifest) {
            fclose(manifest);
        }
        manifest = NULL;
        failed = 1;
        goto done;
    }
    if (fclose(manifest) != 0) {
        manifest = NULL;
        failed = 1;
        goto done;
    }
    manifest = NULL;
    if (ve_tls_persistent_open(&failed_persistent, &options) == 0 ||
        failed_persistent.lease_fd != -1 ||
        ve_tls_lease_guard_enter(lease_path, 0, &probe_fd) != 0 || probe_fd < 0) {
        failed = 1;
        goto done;
    }
    ve_tls_lease_guard_leave(probe_fd);
    probe_fd = -1;
    unlink(manifest_path);
    if (ve_tls_persistent_open(&persistent, &options) != 0 ||
        persistent.lease_fd < 0 || fcntl(persistent.lease_fd, F_GETFD) < 0 ||
        (fcntl(persistent.lease_fd, F_GETFD) & FD_CLOEXEC) == 0) {
        failed = 1;
        goto done;
    }
    lease_fd = persistent.lease_fd;
    for (int i = 0; i < 3; i++) {
        unsigned char payload = (unsigned char)('a' + i);
        if (ve_tls_persistent_append(&persistent, i + 1, NULL, &payload, 1) != 0 ||
            ve_tls_persistent_heartbeat_if_due(&persistent, 1) != 0 ||
            ve_tls_persistent_flush(&persistent) != 0 ||
            fcntl(lease_fd, F_GETFD) < 0) {
            failed = 1;
            goto done;
        }
    }
    ve_tls_persistent_close(&persistent);
    if (persistent.lease_fd != -1 || fcntl(lease_fd, F_GETFD) >= 0) {
        failed = 1;
    }
    ve_tls_persistent_close(&persistent);
    if (ve_tls_lease_guard_enter(lease_path, 0, &probe_fd) != 0 || probe_fd < 0) {
        failed = 1;
        goto done;
    }
    ve_tls_lease_guard_leave(probe_fd);
    probe_fd = -1;

done:
    if (manifest) {
        fclose(manifest);
    }
    if (probe_fd >= 0) {
        ve_tls_lease_guard_leave(probe_fd);
    }
    if (failed_persistent.platform) {
        ve_tls_persistent_close(&failed_persistent);
    }
    if (persistent.platform) {
        ve_tls_persistent_close(&persistent);
    }
    lf_cleanup_dir(dir);
    return failed ? -1 : 0;
}

static int test_lease_fencing_heartbeat_gate(void) {
    char dir[PATH_MAX];
    char lease_path[PATH_MAX];
    ve_tls_config cfg;
    ve_tls_persistent p1;
    ve_tls_persistent p2;
    ve_tls_persistent_options o1;
    ve_tls_persistent_options o2;
    ve_tls_thread * thread = NULL;
    lf_persistent_thread_arg hb;
    lf_gate gate;
    ve_tls_lease_state current;
    ve_tls_lease_state takeover_before;
    ve_tls_lease_state takeover_after;
    int p2_rc = -1;
    int late_p2_rc = -1;
    int failed = 0;

    if (make_temp_dir(dir, sizeof(dir)) != 0) {
        return -1;
    }
    ve_tls_config_init(&cfg);
    g_real_platform = cfg.platform;
    cfg.platform.time_ms = test_fake_time_ms;
    cfg.platform.path_rename = lf_gated_path_rename;
    g_fake_time = 1000;
    lf_make_options(&o1, &cfg.platform, dir, "heartbeat-owner", 1000);
    lf_make_options(&o2, &cfg.platform, dir, "takeover-owner", 4000);
    memset(&p1, 0, sizeof(p1));
    memset(&p2, 0, sizeof(p2));
    lf_gate_init(&gate);
    g_lf_rename_gate = &gate;
    if (ve_tls_persistent_open(&p1, &o1) != 0) {
        failed = 1;
        goto done;
    }

    g_fake_time = 2000;
    lf_gate_arm(&gate);
    memset(&hb, 0, sizeof(hb));
    hb.persistent = &p1;
    thread = cfg.platform.thread_create(lf_heartbeat_thread, &hb);
    if (!thread) {
        failed = 1;
        lf_gate_release(&gate);
        goto done;
    }
    if (lf_gate_wait_entered(&gate) != 0) {
        failed = 1;
        lf_gate_release(&gate);
        goto done;
    }

    /* The old heartbeat owns the stable sidecar while its lease rename is
       paused.  A stale takeover must fail closed at this point. */
    g_fake_time = 4000;
    p2_rc = ve_tls_persistent_open(&p2, &o2);
    if (p2_rc == 0) {
        fprintf(stderr, "lease_fencing heartbeat gate: takeover succeeded while old heartbeat was paused\n");
        failed = 1;
    }
    lf_gate_release(&gate);
    cfg.platform.thread_join(thread);
    thread = NULL;
    if (hb.rc != 0) {
        failed = 1;
    }
    if (p2_rc == 0) {
        ve_tls_persistent_close(&p2);
        memset(&p2, 0, sizeof(p2));
    }

    /* Once the old heartbeat has completed, only an actually stale lease may
       be taken over. */
    g_fake_time = 5000;
    o2.now_ms = g_fake_time;
    late_p2_rc = ve_tls_persistent_open(&p2, &o2);
    if (late_p2_rc != 0 || ve_tls_lease_load(&cfg.platform, p2.lease_path, &current) != 0 ||
        strcmp(current.owner_id, "takeover-owner") != 0) {
        failed = 1;
    }
    if (ve_tls_lease_load(&cfg.platform, p2.lease_path, &takeover_before) != 0) {
        failed = 1;
    }
    g_fake_time = 6000;
    if (ve_tls_persistent_heartbeat_if_due(&p1, 1) == 0 ||
        ve_tls_lease_load(&cfg.platform, p2.lease_path, &takeover_after) != 0 ||
        !lf_lease_matches(&takeover_before, &takeover_after)) {
        fprintf(stderr, "lease_fencing heartbeat gate: old heartbeat changed the new lease after takeover\n");
        failed = 1;
    }

done:
    if (thread) {
        lf_gate_release(&gate);
        cfg.platform.thread_join(thread);
    }
    if (p2_rc == 0 || late_p2_rc == 0) {
        ve_tls_persistent_close(&p2);
    }
    if (p1.platform) {
        ve_tls_persistent_close(&p1);
    }
    g_lf_rename_gate = NULL;
    lf_gate_destroy(&gate);
    lf_cleanup_dir(dir);
    return failed ? -1 : 0;
}

static int test_lease_fencing_append_gate(void) {
    char dir[PATH_MAX];
    ve_tls_config cfg;
    ve_tls_persistent p1;
    ve_tls_persistent p2;
    ve_tls_persistent_options o1;
    ve_tls_persistent_options o2;
    lf_persistent_thread_arg append;
    lf_gate gate;
    ve_tls_thread * thread = NULL;
    ve_tls_lease_state lease_before;
    ve_tls_lease_state lease_after;
    ve_tls_checkpoint_state checkpoint_before;
    ve_tls_checkpoint_state checkpoint_after;
    char segment_path[PATH_MAX];
    unsigned char * segment_before = NULL;
    unsigned char * segment_after = NULL;
    size_t segment_before_size = 0;
    size_t segment_after_size = 0;
    unsigned char * checkpoint_file_before = NULL;
    unsigned char * checkpoint_file_after = NULL;
    size_t checkpoint_file_before_size = 0;
    size_t checkpoint_file_after_size = 0;
    uint64_t records_before = 0;
    uint64_t bytes_before = 0;
    int first_p2_rc = -1;
    int second_p2_rc = -1;
    int old_append_rc = 0;
    int old_ack_rc = 0;
    int old_flush_rc = 0;
    int failed = 0;

    if (make_temp_dir(dir, sizeof(dir)) != 0) {
        return -1;
    }
    ve_tls_config_init(&cfg);
    g_real_platform = cfg.platform;
    cfg.platform.time_ms = test_fake_time_ms;
    cfg.platform.file_open = lf_capture_file_open;
    cfg.platform.file_write = lf_gated_file_write;
    g_fake_time = 1000;
    g_lf_capture_segment_file = 1;
    g_lf_segment_file = NULL;
    lf_make_options(&o1, &cfg.platform, dir, "append-owner", 1000);
    lf_make_options(&o2, &cfg.platform, dir, "takeover-owner", 4000);
    memset(&p1, 0, sizeof(p1));
    memset(&p2, 0, sizeof(p2));
    lf_gate_init(&gate);
    g_lf_write_gate = &gate;
    if (ve_tls_persistent_open(&p1, &o1) != 0 || !g_lf_segment_file) {
        failed = 1;
        goto done;
    }

    lf_gate_arm(&gate);
    memset(&append, 0, sizeof(append));
    append.persistent = &p1;
    thread = cfg.platform.thread_create(lf_append_thread, &append);
    if (!thread) {
        failed = 1;
        lf_gate_release(&gate);
        goto done;
    }
    if (lf_gate_wait_entered(&gate) != 0) {
        failed = 1;
        lf_gate_release(&gate);
        goto done;
    }

    g_fake_time = 4000;
    first_p2_rc = ve_tls_persistent_open(&p2, &o2);
    if (first_p2_rc == 0) {
        fprintf(stderr, "lease_fencing append gate: takeover succeeded while old WAL write was paused\n");
        failed = 1;
    }
    lf_gate_release(&gate);
    cfg.platform.thread_join(thread);
    thread = NULL;
    if (append.rc != 0) {
        failed = 1;
    }
    if (first_p2_rc == 0) {
        ve_tls_persistent_close(&p2);
        memset(&p2, 0, sizeof(p2));
    }

    g_fake_time = 5000;
    o2.now_ms = g_fake_time;
    second_p2_rc = ve_tls_persistent_open(&p2, &o2);
    if (second_p2_rc != 0 ||
        ve_tls_lease_load(&cfg.platform, p2.lease_path, &lease_before) != 0 ||
        ve_tls_checkpoint_load(&cfg.platform, p2.checkpoint_path, &checkpoint_before) != 0) {
        failed = 1;
        goto done;
    }
    records_before = p2.current_records;
    bytes_before = p2.current_bytes;
    memset(segment_path, 0, sizeof(segment_path));
    if (ve_tls_segment_store_get_segment_path(
            &p2.store, p2.store.active_segment_id, segment_path, sizeof(segment_path)) != 0 ||
        lf_read_file_snapshot(&cfg.platform, segment_path, &segment_before, &segment_before_size) != 0 ||
        lf_read_file_snapshot(&cfg.platform, p2.checkpoint_path,
            &checkpoint_file_before, &checkpoint_file_before_size) != 0) {
        failed = 1;
        goto done;
    }
    __atomic_store_n(&g_lf_write_count, 0, __ATOMIC_RELEASE);

    old_append_rc = ve_tls_persistent_append(
        &p1, 2, NULL, (const unsigned char *)"old-writer", strlen("old-writer"));
    old_ack_rc = ve_tls_persistent_ack_range(&p1, 1, 1);
    old_flush_rc = ve_tls_persistent_flush(&p1);
    if (old_append_rc == 0 || old_ack_rc == 0 || old_flush_rc == 0) {
        fprintf(stderr,
            "lease_fencing append gate: old mutation rc append=%d ack=%d flush=%d\n",
            old_append_rc, old_ack_rc, old_flush_rc);
        failed = 1;
    }
    ve_tls_persistent_close(&p1);
    memset(&p1, 0, sizeof(p1));
    if (ve_tls_lease_load(&cfg.platform, p2.lease_path, &lease_after) != 0 ||
        !lf_lease_matches(&lease_before, &lease_after) ||
        p2.current_records != records_before || p2.current_bytes != bytes_before ||
        ve_tls_checkpoint_load(&cfg.platform, p2.checkpoint_path, &checkpoint_after) != 0 ||
        checkpoint_after.acked_log_id != checkpoint_before.acked_log_id ||
        checkpoint_after.replay_begin_log_id != checkpoint_before.replay_begin_log_id ||
        checkpoint_after.replay_begin_segment_id != checkpoint_before.replay_begin_segment_id ||
        checkpoint_after.replay_begin_offset != checkpoint_before.replay_begin_offset ||
        checkpoint_after.last_segment_id != checkpoint_before.last_segment_id ||
        lf_read_file_snapshot(&cfg.platform, segment_path, &segment_after, &segment_after_size) != 0 ||
        lf_read_file_snapshot(&cfg.platform, p2.checkpoint_path,
            &checkpoint_file_after, &checkpoint_file_after_size) != 0 ||
        segment_before_size != segment_after_size ||
        memcmp(segment_before, segment_after, segment_before_size) != 0 ||
        checkpoint_file_before_size != checkpoint_file_after_size ||
        memcmp(checkpoint_file_before, checkpoint_file_after, checkpoint_file_before_size) != 0 ||
        __atomic_load_n(&g_lf_write_count, __ATOMIC_ACQUIRE) != 0) {
        failed = 1;
    }

done:
    if (thread) {
        lf_gate_release(&gate);
        cfg.platform.thread_join(thread);
    }
    if (first_p2_rc == 0 || second_p2_rc == 0) {
        ve_tls_persistent_close(&p2);
    }
    if (p1.platform) {
        ve_tls_persistent_close(&p1);
    }
    g_lf_write_gate = NULL;
    g_lf_capture_segment_file = 0;
    g_lf_segment_file = NULL;
    free(segment_before);
    free(segment_after);
    free(checkpoint_file_before);
    free(checkpoint_file_after);
    lf_gate_destroy(&gate);
    lf_cleanup_dir(dir);
    return failed ? -1 : 0;
}

static int test_lease_fencing_close_gate(void) {
    char dir[PATH_MAX];
    ve_tls_config cfg;
    ve_tls_persistent p1;
    ve_tls_persistent p2;
    ve_tls_persistent_options o1;
    ve_tls_persistent_options o2;
    lf_persistent_thread_arg close_arg;
    lf_gate gate;
    ve_tls_thread * thread = NULL;
    ve_tls_lease_state lease;
    int first_p2_rc = -1;
    int second_p2_rc = -1;
    int failed = 0;

    if (make_temp_dir(dir, sizeof(dir)) != 0) {
        return -1;
    }
    ve_tls_config_init(&cfg);
    g_real_platform = cfg.platform;
    cfg.platform.time_ms = test_fake_time_ms;
    cfg.platform.path_remove = lf_gated_path_remove;
    g_fake_time = 1000;
    lf_make_options(&o1, &cfg.platform, dir, "close-owner", 1000);
    lf_make_options(&o2, &cfg.platform, dir, "takeover-owner", 4000);
    memset(&p1, 0, sizeof(p1));
    memset(&p2, 0, sizeof(p2));
    lf_gate_init(&gate);
    g_lf_remove_gate = &gate;
    if (ve_tls_persistent_open(&p1, &o1) != 0) {
        failed = 1;
        goto done;
    }

    lf_gate_arm(&gate);
    memset(&close_arg, 0, sizeof(close_arg));
    close_arg.persistent = &p1;
    thread = cfg.platform.thread_create(lf_close_thread, &close_arg);
    if (!thread) {
        failed = 1;
        lf_gate_release(&gate);
        goto done;
    }
    if (lf_gate_wait_entered(&gate) != 0) {
        failed = 1;
        lf_gate_release(&gate);
        goto done;
    }
    g_fake_time = 4000;
    first_p2_rc = ve_tls_persistent_open(&p2, &o2);
    if (first_p2_rc == 0) {
        fprintf(stderr, "lease_fencing close gate: takeover succeeded while old close was deleting lease\n");
        failed = 1;
    }
    lf_gate_release(&gate);
    cfg.platform.thread_join(thread);
    thread = NULL;
    if (close_arg.rc != 0) {
        failed = 1;
    }
    if (first_p2_rc == 0) {
        if (ve_tls_lease_load(&cfg.platform, p2.lease_path, &lease) != 0 ||
            strcmp(lease.owner_id, "takeover-owner") != 0) {
            failed = 1;
        }
        ve_tls_persistent_close(&p2);
        memset(&p2, 0, sizeof(p2));
    }

    g_fake_time = 5000;
    o2.now_ms = g_fake_time;
    second_p2_rc = ve_tls_persistent_open(&p2, &o2);
    if (second_p2_rc != 0) {
        failed = 1;
    }

done:
    if (thread) {
        lf_gate_release(&gate);
        cfg.platform.thread_join(thread);
    }
    if (first_p2_rc == 0 || second_p2_rc == 0) {
        ve_tls_persistent_close(&p2);
    }
    if (p1.platform) {
        /* The close thread zeroes p1; this is only for early-failure cleanup. */
        ve_tls_persistent_close(&p1);
    }
    g_lf_remove_gate = NULL;
    lf_gate_destroy(&gate);
    lf_cleanup_dir(dir);
    return failed ? -1 : 0;
}

static int test_lease_fencing_same_process_one_winner(void) {
    char dir[PATH_MAX];
    ve_tls_config cfg;
    char lease_path[PATH_MAX];
    ve_tls_lease_state p1;
    ve_tls_lease_state p2;
    ve_tls_lease_options o1;
    ve_tls_lease_options o2;
    lf_start_gate start;
    lf_stat_gate stat_gate;
    lf_open_thread_arg a1;
    lf_open_thread_arg a2;
    pthread_t t1;
    pthread_t t2;
    int have_t1 = 0;
    int have_t2 = 0;
    int rc1 = -1;
    int rc2 = -1;
    int failed = 0;
    if (make_temp_dir(dir, sizeof(dir)) != 0) {
        return -1;
    }
    ve_tls_config_init(&cfg);
    g_real_platform = cfg.platform;
    cfg.platform.time_ms = test_fake_time_ms;
    g_fake_time = 1000;
    join_path(lease_path, sizeof(lease_path), dir, "lease");
    memset(&o1, 0, sizeof(o1));
    o1.platform = &cfg.platform;
    o1.lease_path = lease_path;
    o1.owner_id = "winner-a";
    o1.owner_pid = (int32_t)getpid();
    o1.owner_process_name = "same-process-race";
    o1.now_ms = 1000;
    o1.lease_timeout_ms = 1000;
    o1.mode = VE_TLS_LEASE_OPEN_TAKEOVER_IF_STALE;
    o2 = o1;
    o2.owner_id = "winner-b";
    memset(&p1, 0, sizeof(p1));
    memset(&p2, 0, sizeof(p2));
    lf_start_gate_init(&start);
    lf_stat_gate_init(&stat_gate);
    stat_gate.armed = 1;
    cfg.platform.path_stat = lf_gated_path_stat;
    g_lf_stat_gate = &stat_gate;
    memset(&a1, 0, sizeof(a1));
    memset(&a2, 0, sizeof(a2));
    a1.start = &start;
    a1.state = &p1;
    a1.options = &o1;
    a2.start = &start;
    a2.state = &p2;
    a2.options = &o2;
    if (pthread_create(&t1, NULL, lf_open_thread, &a1) != 0) {
        failed = 1;
        goto done;
    }
    have_t1 = 1;
    if (pthread_create(&t2, NULL, lf_open_thread, &a2) != 0) {
        failed = 1;
        lf_start_gate_start(&start);
        lf_stat_gate_release(&stat_gate);
        goto done;
    }
    have_t2 = 1;
    lf_start_gate_start(&start);
    if (lf_stat_gate_wait_count(&stat_gate, 2) != 0) {
        /* With the fixed guard, the second opener fails before lease stat;
           the one-second bound keeps this diagnostic deterministic. */
        pthread_mutex_lock(&stat_gate.mutex);
        if (stat_gate.count == 0) {
            failed = 1;
        }
        pthread_mutex_unlock(&stat_gate.mutex);
    }
    lf_stat_gate_release(&stat_gate);
done:
    if (have_t1) {
        pthread_join(t1, NULL);
        rc1 = a1.rc;
    }
    if (have_t2) {
        pthread_join(t2, NULL);
        rc2 = a2.rc;
    }
    g_lf_stat_gate = NULL;
    if ((rc1 == 0) == (rc2 == 0)) {
        failed = 1;
    }
    if (rc1 == 0) {
        (void)ve_tls_lease_release(&cfg.platform, lease_path);
    }
    if (rc2 == 0) {
        (void)ve_tls_lease_release(&cfg.platform, lease_path);
    }
    lf_stat_gate_destroy(&stat_gate);
    lf_start_gate_destroy(&start);
    lf_cleanup_dir(dir);
    return failed ? -1 : 0;
}

static int test_lease_fencing_fork_kill_releases_guard(void) {
    char dir[PATH_MAX];
    ve_tls_config cfg;
    ve_tls_config child_cfg;
    ve_tls_persistent_options child_options;
    ve_tls_persistent_options parent_options;
    ve_tls_persistent parent_persistent;
    int entered_pipe[2] = {-1, -1};
    int release_pipe[2] = {-1, -1};
    pid_t child = -1;
    int first_parent_rc = -1;
    int second_parent_rc = -1;
    int status = 0;
    int failed = 0;

    dir[0] = 0;
    if (make_temp_dir(dir, sizeof(dir)) != 0 || pipe(entered_pipe) != 0 ||
        pipe(release_pipe) != 0) {
        if (entered_pipe[0] >= 0) close(entered_pipe[0]);
        if (entered_pipe[1] >= 0) close(entered_pipe[1]);
        if (release_pipe[0] >= 0) close(release_pipe[0]);
        if (release_pipe[1] >= 0) close(release_pipe[1]);
        if (dir[0] != 0) lf_cleanup_dir(dir);
        return -1;
    }
    ve_tls_config_init(&cfg);
    g_real_platform = cfg.platform;
    cfg.platform.time_ms = test_fake_time_ms;
    g_fake_time = 1000;
    lf_make_options(&child_options, &cfg.platform, dir, "fork-child", 1000);
    child_cfg = cfg;
    child_cfg.platform.path_rename = lf_fork_blocking_path_rename;
    child_options.platform = &child_cfg.platform;
    lf_make_options(&parent_options, &cfg.platform, dir, "fork-parent", 4000);
    memset(&parent_persistent, 0, sizeof(parent_persistent));

    child = fork();
    if (child < 0) {
        failed = 1;
        goto done;
    }
    if (child == 0) {
        ve_tls_persistent child_persistent;
        int child_rc;
        close(entered_pipe[0]);
        close(release_pipe[1]);
        g_lf_fork_enter_fd = entered_pipe[1];
        g_lf_fork_release_fd = release_pipe[0];
        g_lf_fork_entered = 0;
        memset(&child_persistent, 0, sizeof(child_persistent));
        child_rc = ve_tls_persistent_open(&child_persistent, &child_options);
        _exit(child_rc == 0 ? 0 : 1);
    }
    close(entered_pipe[1]);
    entered_pipe[1] = -1;
    close(release_pipe[0]);
    release_pipe[0] = -1;

    {
        fd_set read_set;
        struct timeval timeout;
        char marker;
        int select_rc;
        FD_ZERO(&read_set);
        FD_SET(entered_pipe[0], &read_set);
        timeout.tv_sec = 3;
        timeout.tv_usec = 0;
        select_rc = select(entered_pipe[0] + 1, &read_set, NULL, NULL, &timeout);
        if (select_rc != 1 || read(entered_pipe[0], &marker, 1) != 1) {
            failed = 1;
            goto done;
        }
    }

    /* The child is paused in its first lease rename.  The parent must fail
       closed while the child still owns the stable sidecar. */
    first_parent_rc = ve_tls_persistent_open(&parent_persistent, &parent_options);
    if (first_parent_rc == 0) {
        fprintf(stderr, "lease_fencing fork gate: parent takeover succeeded before child SIGKILL\n");
        failed = 1;
        ve_tls_persistent_close(&parent_persistent);
        memset(&parent_persistent, 0, sizeof(parent_persistent));
    }

done:
    if (child > 0) {
        (void)kill(child, SIGKILL);
        (void)waitpid(child, &status, 0);
    }
    if (entered_pipe[0] >= 0) close(entered_pipe[0]);
    if (entered_pipe[1] >= 0) close(entered_pipe[1]);
    if (release_pipe[0] >= 0) close(release_pipe[0]);
    if (release_pipe[1] >= 0) close(release_pipe[1]);
    if (!failed) {
        g_fake_time = 5000;
        parent_options.now_ms = g_fake_time;
        second_parent_rc = ve_tls_persistent_open(&parent_persistent, &parent_options);
        if (second_parent_rc != 0 || strcmp(parent_persistent.lease.owner_id, "fork-parent") != 0) {
            failed = 1;
        }
    }
    if (first_parent_rc == 0 || second_parent_rc == 0) {
        ve_tls_persistent_close(&parent_persistent);
    }
    lf_cleanup_dir(dir);
    return failed ? -1 : 0;
}

typedef struct {
    ve_tls_persistent * persistent;
    int calls;
    int ack_rc;
    int flush_rc;
} lf_recover_reentry_state;

static int lf_recover_ack_flush_callback(
    int64_t log_id,
    int64_t enqueue_time_ms,
    const char * hash_key,
    const unsigned char * payload,
    size_t payload_size,
    void * user
) {
    lf_recover_reentry_state * state = (lf_recover_reentry_state *)user;
    (void)enqueue_time_ms;
    (void)hash_key;
    (void)payload;
    (void)payload_size;
    if (!state || !state->persistent) {
        return -1;
    }
    state->calls++;
    state->ack_rc = ve_tls_persistent_ack_range(state->persistent, log_id, log_id);
    state->flush_rc = ve_tls_persistent_flush(state->persistent);
    return state->ack_rc == 0 && state->flush_rc == 0 ? 0 : -1;
}

static int test_lease_fencing_recover_callback_reentry(void) {
    char dir[PATH_MAX];
    ve_tls_config cfg;
    ve_tls_config child_cfg;
    ve_tls_persistent p1;
    ve_tls_persistent_options o1;
    ve_tls_persistent_options o2;
    int result_pipe[2] = {-1, -1};
    pid_t child = -1;
    int status = 0;
    int failed = 0;
    char marker = 0;
    char payload[] = "recover-reentry";
    dir[0] = 0;
    if (make_temp_dir(dir, sizeof(dir)) != 0 || pipe(result_pipe) != 0) {
        if (result_pipe[0] >= 0) close(result_pipe[0]);
        if (result_pipe[1] >= 0) close(result_pipe[1]);
        if (dir[0] != 0) lf_cleanup_dir(dir);
        return -1;
    }
    ve_tls_config_init(&cfg);
    g_real_platform = cfg.platform;
    cfg.platform.time_ms = test_fake_time_ms;
    g_fake_time = 1000;
    lf_make_options(&o1, &cfg.platform, dir, "recover-owner", 1000);
    memset(&p1, 0, sizeof(p1));
    if (ve_tls_persistent_open(&p1, &o1) != 0 ||
        ve_tls_persistent_append(&p1, 1, NULL,
            (const unsigned char *)payload, strlen(payload)) != 0) {
        failed = 1;
        goto done;
    }
    ve_tls_persistent_close(&p1);
    memset(&p1, 0, sizeof(p1));
    child_cfg = cfg;
    lf_make_options(&o2, &child_cfg.platform, dir, "recover-child", 2000);
    child = fork();
    if (child < 0) {
        failed = 1;
        goto done;
    }
    if (child == 0) {
        ve_tls_persistent p2;
        lf_recover_reentry_state state;
        int rc;
        close(result_pipe[0]);
        memset(&p2, 0, sizeof(p2));
        memset(&state, 0, sizeof(state));
        state.persistent = &p2;
        rc = ve_tls_persistent_open(&p2, &o2);
        if (rc == 0) {
            rc = ve_tls_persistent_recover(&p2, lf_recover_ack_flush_callback, &state);
            if (rc == 0 && state.calls == 1 && state.ack_rc == 0 && state.flush_rc == 0) {
                marker = '0';
            } else {
                marker = '1';
            }
            ve_tls_persistent_close(&p2);
        } else {
            marker = '1';
        }
        (void)write(result_pipe[1], &marker, 1);
        close(result_pipe[1]);
        _exit(marker == '0' ? 0 : 1);
    }
    close(result_pipe[1]);
    result_pipe[1] = -1;
    {
        fd_set read_set;
        struct timeval timeout;
        int select_rc;
        FD_ZERO(&read_set);
        FD_SET(result_pipe[0], &read_set);
        timeout.tv_sec = 3;
        timeout.tv_usec = 0;
        select_rc = select(result_pipe[0] + 1, &read_set, NULL, NULL, &timeout);
        if (select_rc != 1 || read(result_pipe[0], &marker, 1) != 1 || marker != '0') {
            failed = 1;
            goto done;
        }
    }
    if (child > 0) {
        if (waitpid(child, &status, 0) < 0 || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            failed = 1;
        }
        child = -1;
    }
    {
        ve_tls_checkpoint_state checkpoint;
        char checkpoint_path[PATH_MAX];
        join_path(checkpoint_path, sizeof(checkpoint_path), dir, "checkpoint");
        if (ve_tls_checkpoint_load(&cfg.platform, checkpoint_path, &checkpoint) != 0 ||
            checkpoint.acked_log_id != 1) {
            failed = 1;
        }
    }

done:
    if (child > 0) {
        (void)kill(child, SIGKILL);
        (void)waitpid(child, &status, 0);
    }
    if (result_pipe[0] >= 0) close(result_pipe[0]);
    if (result_pipe[1] >= 0) close(result_pipe[1]);
    if (p1.platform) {
        ve_tls_persistent_close(&p1);
    }
    lf_cleanup_dir(dir);
    return failed ? -1 : 0;
}

static int test_lease_fencing_guard_error_paths(void) {
    char dir[PATH_MAX];
    char lease_path[PATH_MAX];
    char lock_path[PATH_MAX];
    char target_path[PATH_MAX];
    ve_tls_config cfg;
    ve_tls_lease_state state;
    ve_tls_lease_options options;
    struct stat before_stat;
    struct stat after_stat;
    struct {
        uint32_t magic;
        uint32_t version;
        ve_tls_lease_state state;
        uint32_t checksum;
    } overflow_file;
    unsigned char * overflow_before = NULL;
    unsigned char * overflow_after = NULL;
    size_t overflow_before_size = 0;
    size_t overflow_after_size = 0;
    static const char target_data[] = "guard-target";
    char target_check[sizeof(target_data)];
    FILE * file = NULL;
    int fd = -1;
    int failed = 0;
    if (make_temp_dir(dir, sizeof(dir)) != 0) {
        return -1;
    }
    ve_tls_config_init(&cfg);
    g_real_platform = cfg.platform;
    join_path(lease_path, sizeof(lease_path), dir, "lease");
    join_path(lock_path, sizeof(lock_path), dir, "lease.lock");
    join_path(target_path, sizeof(target_path), dir, "target");
    if (ve_tls_lease_guard_enter(lease_path, 1, &fd) != 0 || fd < 0) {
        failed = 1;
        goto done;
    }
    if (fstat(fd, &before_stat) != 0) {
        failed = 1;
    }
    ve_tls_lease_guard_leave(fd);
    fd = -1;
    if (stat(lock_path, &after_stat) != 0 || before_stat.st_ino != after_stat.st_ino) {
        failed = 1;
    }
    unlink(target_path);
    file = fopen(target_path, "wb");
    if (!file || fwrite(target_data, 1, sizeof(target_data), file) != sizeof(target_data)) {
        if (file) fclose(file);
        file = NULL;
        failed = 1;
        goto done;
    }
    fclose(file);
    file = NULL;
    unlink(lock_path);
    if (symlink(target_path, lock_path) != 0 ||
        ve_tls_lease_guard_enter(lease_path, 0, &fd) == 0 || fd != -1 ||
        lstat(lock_path, &after_stat) != 0 || !S_ISLNK(after_stat.st_mode)) {
        failed = 1;
    }
    file = fopen(target_path, "rb");
    if (!file || fread(target_check, 1, sizeof(target_check), file) != sizeof(target_check) ||
        memcmp(target_check, target_data, sizeof(target_data)) != 0) {
        failed = 1;
    }
    if (file) fclose(file);
    file = NULL;
    unlink(lock_path);
    if (mkdir(lock_path, 0700) != 0 ||
        ve_tls_lease_guard_enter(lease_path, 0, &fd) == 0 || fd != -1) {
        failed = 1;
    }
    rmdir(lock_path);
    memset(&overflow_file, 0, sizeof(overflow_file));
    overflow_file.magic = 0x544C5331u;
    overflow_file.version = 1u;
    strncpy(overflow_file.state.owner_id, "overflow-owner", sizeof(overflow_file.state.owner_id) - 1);
    strncpy(overflow_file.state.owner_process_name, "overflow-test",
        sizeof(overflow_file.state.owner_process_name) - 1);
    overflow_file.state.owner_pid = (int32_t)getpid();
    overflow_file.state.acquire_time_ms = 1000;
    overflow_file.state.last_heartbeat_ms = 1000;
    overflow_file.state.fencing_token = UINT64_MAX;
    overflow_file.checksum = 2166136261u;
    for (size_t i = 0; i < (size_t)((unsigned char *)&overflow_file.checksum -
            (unsigned char *)&overflow_file); i++) {
        overflow_file.checksum ^= ((const unsigned char *)&overflow_file)[i];
        overflow_file.checksum *= 16777619u;
    }
    file = fopen(lease_path, "wb");
    if (!file || fwrite(&overflow_file, 1, sizeof(overflow_file), file) != sizeof(overflow_file)) {
        if (file) fclose(file);
        file = NULL;
        failed = 1;
        goto done;
    }
    fclose(file);
    file = NULL;
    if (lf_read_file_snapshot(&cfg.platform, lease_path,
            &overflow_before, &overflow_before_size) != 0) {
        failed = 1;
        goto done;
    }
    memset(&options, 0, sizeof(options));
    options.platform = &cfg.platform;
    options.lease_path = lease_path;
    options.owner_id = "token-owner";
    options.owner_process_name = "token-test";
    options.owner_pid = (int32_t)getpid();
    options.now_ms = 2000;
    options.lease_timeout_ms = 1;
    options.mode = VE_TLS_LEASE_OPEN_TAKEOVER_IF_STALE;
    memset(&state, 0, sizeof(state));
    if (ve_tls_lease_acquire(&options, &state) == 0 ||
        ve_tls_lease_load(&cfg.platform, lease_path, &state) != 0 ||
        state.fencing_token != UINT64_MAX ||
        lf_read_file_snapshot(&cfg.platform, lease_path,
            &overflow_after, &overflow_after_size) != 0 ||
        overflow_before_size != overflow_after_size ||
        memcmp(overflow_before, overflow_after, overflow_before_size) != 0) {
        /* The on-disk token was not modified by the rejected overflow case. */
        failed = 1;
    }
done:
    if (file) {
        fclose(file);
    }
    if (fd >= 0) {
        ve_tls_lease_guard_leave(fd);
    }
    free(overflow_before);
    free(overflow_after);
    lf_cleanup_dir(dir);
    return failed ? -1 : 0;
}

/* The ABA identity contract uses the public producer constructor, but does not
 * need its worker/sender loops.  Keep those loops out of the handoff window so
 * the lease transition is controlled by this test rather than scheduler luck. */
static int g_aba_stub_thread_create_count;

static ve_tls_thread * lf_aba_stub_thread_create(ve_tls_thread_fn fn, void * arg) {
    (void)fn;
    (void)arg;
    g_aba_stub_thread_create_count++;
    return (ve_tls_thread *)(uintptr_t)g_aba_stub_thread_create_count;
}

static void lf_aba_stub_thread_join(ve_tls_thread * thread) {
    (void)thread;
}

static int test_producer_aba_owner_identity(void) {
    char dir[PATH_MAX];
    ve_tls_config cfg;
    ve_tls_producer * p1 = NULL;
    ve_tls_producer * p2 = NULL;
    ve_tls_producer * p3 = NULL;
    ve_tls_lease_state lease_before;
    ve_tls_lease_state lease_after;
    char owner1[64];
    char owner2[64];
    char owner3[64];
    int failed = 0;
    int stage = 0;
    int seed_append_rc = -999;
    int old_add_rc = -999;
    int old_heartbeat_rc = -999;
    int old_ack_rc = -999;
    int old_flush_rc = -999;
    int lease_before_rc = -999;
    int lease_after_rc = -999;
    int threads_per_producer = 0;
    dir[0] = 0;
    memset(owner1, 0, sizeof(owner1));
    memset(owner2, 0, sizeof(owner2));
    memset(owner3, 0, sizeof(owner3));
    g_aba_stub_thread_create_count = 0;
    if (make_temp_dir(dir, sizeof(dir)) != 0 ||
        ve_tls_config_init_versioned(&cfg, sizeof(cfg), VE_TLS_CONFIG_VERSION_CURRENT) != VE_TLS_OK) {
        if (dir[0] != 0) lf_cleanup_dir(dir);
        return -1;
    }
    cfg.platform.thread_create = lf_aba_stub_thread_create;
    cfg.platform.thread_join = lf_aba_stub_thread_join;
    g_takeover_main_thread = pthread_self();
    g_takeover_time_frozen = 1;
    g_fake_time = 1000;
    cfg.platform.time_ms = test_takeover_time_ms;
    cfg.endpoint = "https://example.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "aba-owner";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.retry_policy.max_attempts = 1;
    cfg.flush_interval_ms = 100000;
    cfg.pack_thread_count = 1;
    cfg.send_thread_count = 1;
    cfg.agg_strategy = 0;
    cfg.compress_type = "none";
    cfg.use_persistent = 1;
    cfg.persistent_file_path = dir;
    cfg.max_persistent_log_count = 64;
    cfg.max_persistent_file_size = 4096;
    cfg.max_persistent_file_count = 4;
    cfg.persistent_lease_timeout_ms = 1000;
    cfg.persistent_heartbeat_interval_ms = 100;
    cfg.persistent_open_mode = VE_TLS_POPEN_TAKEOVER_IF_STALE;
    threads_per_producer = (cfg.pack_thread_count > 0 ? cfg.pack_thread_count : 1) +
        (cfg.send_thread_count > 0 ? cfg.send_thread_count : 1);

    stage = 1;
    p1 = ve_tls_producer_create_versioned(&cfg, sizeof(cfg), VE_TLS_CONFIG_VERSION_CURRENT);
    if (!p1 || !p1->persistent ||
        g_aba_stub_thread_create_count != threads_per_producer) {
        failed = 1;
        goto done;
    }
    stage = 2;
    memcpy(owner1, p1->persistent->lease.owner_id, sizeof(owner1));
    seed_append_rc = ve_tls_persistent_append(p1->persistent, 1, NULL,
        (const unsigned char *)"seed", 4);
    if (owner1[0] == '\0' || seed_append_rc != 0) {
        failed = 1;
        goto done;
    }

    stage = 3;
    g_fake_time = 4000;
    p2 = ve_tls_producer_create_versioned(&cfg, sizeof(cfg), VE_TLS_CONFIG_VERSION_CURRENT);
    if (!p2 || !p2->persistent ||
        g_aba_stub_thread_create_count != threads_per_producer * 2) {
        failed = 1;
        goto done;
    }
    memcpy(owner2, p2->persistent->lease.owner_id, sizeof(owner2));
    stage = 4;
    if (owner2[0] == '\0' || strcmp(owner1, owner2) == 0) {
        failed = 1;
    }
    ve_tls_producer_destroy(p2);
    p2 = NULL;

    /* A clock rollback must not recreate the first instance's identity. */
    stage = 5;
    g_fake_time = 1000;
    p3 = ve_tls_producer_create_versioned(&cfg, sizeof(cfg), VE_TLS_CONFIG_VERSION_CURRENT);
    if (!p3 || !p3->persistent ||
        g_aba_stub_thread_create_count != threads_per_producer * 3) {
        failed = 1;
        goto done;
    }
    memcpy(owner3, p3->persistent->lease.owner_id, sizeof(owner3));
    stage = 6;
    lease_before_rc = ve_tls_lease_load(&cfg.platform, p3->persistent->lease_path,
        &lease_before);
    if (owner3[0] == '\0' || strcmp(owner1, owner3) == 0 || strcmp(owner2, owner3) == 0) {
        failed = 1;
    }
    if (lease_before_rc != 0) {
        failed = 1;
        goto done;
    }

    stage = 7;
    old_add_rc = ve_tls_producer_add_log_raw(p1, "stale", 5, 0);
    old_heartbeat_rc = ve_tls_persistent_heartbeat_if_due(p1->persistent, 1);
    old_ack_rc = ve_tls_persistent_ack_range(p1->persistent, 1, 1);
    old_flush_rc = ve_tls_persistent_flush(p1->persistent);
    if (old_add_rc == VE_TLS_OK || old_heartbeat_rc == 0 || old_ack_rc == 0 ||
        old_flush_rc == 0) {
        failed = 1;
    }
    stage = 8;
    ve_tls_producer_destroy(p1);
    p1 = NULL;
    stage = 9;
    lease_after_rc = ve_tls_lease_load(&cfg.platform, p3->persistent->lease_path, &lease_after);
    if (lease_after_rc != 0 ||
        !lf_lease_matches(&lease_before, &lease_after)) {
        failed = 1;
    }

done:
    if (failed) {
        fprintf(stderr,
            "aba owner stage=%d fake=%lld p1=%p p1persistent=%p threads=%d expected=%d p2=%p p3=%p owners='%s'/'%s'/'%s' "
            "seed=%d lease_before=%d old_add=%d old_hb=%d old_ack=%d old_flush=%d "
            "lease_after=%d\n",
            stage, (long long)g_fake_time, (void *)p1,
            p1 ? (void *)p1->persistent : NULL, g_aba_stub_thread_create_count,
            threads_per_producer,
            (void *)p2, (void *)p3,
            owner1, owner2, owner3, seed_append_rc, lease_before_rc, old_add_rc,
            old_heartbeat_rc, old_ack_rc, old_flush_rc, lease_after_rc);
    }
    if (p2) ve_tls_producer_destroy(p2);
    if (p1) ve_tls_producer_destroy(p1);
    if (p3) ve_tls_producer_destroy(p3);
    g_takeover_time_frozen = 0;
    lf_cleanup_dir(dir);
    return failed ? -1 : 0;
}

static int test_lease_owner_identity_helper(void) {
    char owner1[64];
    char owner2[64];
    char tiny[8];
    int32_t pid1 = 0;
    int32_t pid2 = 0;
    size_t i;
    memset(owner1, 0xA5, sizeof(owner1));
    memset(owner2, 0xA5, sizeof(owner2));
    memset(tiny, 0xA5, sizeof(tiny));
    if (ve_tls_lease_create_owner(owner1, sizeof(owner1), &pid1) != 0 ||
        ve_tls_lease_create_owner(owner2, sizeof(owner2), &pid2) != 0 ||
        strncmp(owner1, "ve-tls-", 7) != 0 || strncmp(owner2, "ve-tls-", 7) != 0 ||
        strlen(owner1) != 39 || strlen(owner2) != 39 || strcmp(owner1, owner2) == 0 ||
        pid1 != (int32_t)getpid() || pid1 != pid2 ||
        ve_tls_lease_create_owner(tiny, sizeof(tiny), &pid1) == 0 || tiny[0] != '\0' || pid1 != 0) {
        return -1;
    }
    for (i = 7; i < 39; i++) {
        if (!strchr("0123456789abcdef", owner1[i]) ||
            !strchr("0123456789abcdef", owner2[i])) return -1;
    }
    if (ve_tls_lease_create_owner(NULL, sizeof(owner1), &pid2) == 0 || pid2 != 0 ||
        ve_tls_lease_create_owner(owner1, sizeof(owner1), NULL) == 0 || owner1[0] != '\0') {
        return -1;
    }
    return 0;
}

static int ep_prepare_config(ve_tls_config * cfg, const char * dir) {
    if (!cfg || !dir ||
        ve_tls_config_init_versioned(cfg, sizeof(*cfg), VE_TLS_CONFIG_VERSION_CURRENT) != VE_TLS_OK) {
        return -1;
    }
    cfg->endpoint = "https://example.com";
    cfg->region = "cn-beijing";
    cfg->topic_id = "exclusive-persistence";
    cfg->access_key_id = "ak";
    cfg->access_key_secret = "sk";
    cfg->retry_policy.max_attempts = 1;
    cfg->flush_interval_ms = 100000;
    cfg->pack_thread_count = 1;
    cfg->send_thread_count = 1;
    cfg->agg_strategy = 0;
    cfg->compress_type = "none";
    cfg->use_persistent = 1;
    cfg->persistent_file_path = dir;
    cfg->max_persistent_log_count = 64;
    cfg->max_persistent_file_size = 4096;
    cfg->max_persistent_file_count = 4;
    cfg->persistent_lease_timeout_ms = 1000;
    cfg->persistent_heartbeat_interval_ms = 100;
    cfg->persistent_open_mode = VE_TLS_POPEN_TAKEOVER_IF_STALE;
    cfg->platform.thread_create = lf_aba_stub_thread_create;
    cfg->platform.thread_join = lf_aba_stub_thread_join;
    return 0;
}

static void ep_make_exclusive_options(
    ve_tls_persistent_options * options,
    ve_tls_platform * platform,
    const char * dir,
    const char * owner_id,
    int64_t now_ms
) {
    lf_make_options(options, platform, dir, owner_id, now_ms);
    options->exclusive_lifetime_lock = 1;
}

typedef struct {
    int calls;
    int64_t ids[8];
    size_t sizes[8];
    unsigned char payloads[8][64];
} ep_recover_records;

static int ep_collect_recovered_record(
    int64_t log_id,
    int64_t enqueue_time_ms,
    const char * hash_key,
    const unsigned char * payload,
    size_t payload_size,
    void * user
) {
    ep_recover_records * records = (ep_recover_records *)user;
    (void)enqueue_time_ms;
    (void)hash_key;
    if (!records || !payload || records->calls < 0 || records->calls >= 8 ||
        payload_size > sizeof(records->payloads[0])) {
        return -1;
    }
    records->ids[records->calls] = log_id;
    records->sizes[records->calls] = payload_size;
    memcpy(records->payloads[records->calls], payload, payload_size);
    records->calls++;
    return 0;
}

static int test_exclusive_persistence_factory_contract(void) {
    char dir[PATH_MAX];
    ve_tls_config cfg;
    ve_tls_producer * producer = NULL;
    int failed = 0;

    dir[0] = 0;
    if (make_temp_dir(dir, sizeof(dir)) != 0 || ep_prepare_config(&cfg, dir) != 0) {
        if (dir[0] != 0) {
            lf_cleanup_dir(dir);
        }
        return -1;
    }
    g_aba_stub_thread_create_count = 0;
    g_fake_time = 1000;
    g_real_platform = cfg.platform;

    producer = ve_tls_producer_create_versioned(
        &cfg, sizeof(cfg), VE_TLS_CONFIG_VERSION_CURRENT);
    if (!producer || !producer->persistent ||
        producer->persistent->exclusive_lifetime_lock != 0) {
        failed = 1;
    }
    if (producer) {
        ve_tls_producer_destroy(producer);
        producer = NULL;
    }

    if (ve_tls_producer_create_exclusive_persistence(
            &cfg, sizeof(cfg) - 1) != NULL) {
        failed = 1;
    }
    cfg.use_persistent = 0;
    if (ve_tls_producer_create_exclusive_persistence(
            &cfg, sizeof(cfg)) != NULL) {
        failed = 1;
    }
    cfg.use_persistent = 1;
    producer = ve_tls_producer_create_exclusive_persistence(&cfg, sizeof(cfg));
    if (!producer || !producer->persistent ||
        producer->persistent->exclusive_lifetime_lock != 1) {
        failed = 1;
    }

    if (producer) {
        ve_tls_producer_destroy(producer);
    }
    lf_cleanup_dir(dir);
    return failed ? -1 : 0;
}

static int test_exclusive_persistence_lifetime_takeover(void) {
    char dir[PATH_MAX];
    char lease_path[PATH_MAX];
    char manifest_path[PATH_MAX];
    ve_tls_config cfg;
    ve_tls_persistent first;
    ve_tls_persistent second;
    ve_tls_persistent failed_open;
    ve_tls_persistent_options first_options;
    ve_tls_persistent_options second_options;
    ve_tls_persistent_options ordinary_options;
    FILE * manifest = NULL;
    int probe_fd = -1;
    int failed = 0;

    dir[0] = 0;
    memset(&first, 0, sizeof(first));
    memset(&second, 0, sizeof(second));
    memset(&failed_open, 0, sizeof(failed_open));
    if (make_temp_dir(dir, sizeof(dir)) != 0) {
        return -1;
    }
    ve_tls_config_init(&cfg);
    g_real_platform = cfg.platform;
    cfg.platform.time_ms = test_fake_time_ms;
    g_fake_time = 1000;
    ep_make_exclusive_options(&first_options, &cfg.platform, dir, "exclusive-owner", 1000);
    ep_make_exclusive_options(&second_options, &cfg.platform, dir, "takeover-owner", 5000);
    ep_make_exclusive_options(&ordinary_options, &cfg.platform, dir, "ordinary-takeover", 5000);
    ordinary_options.exclusive_lifetime_lock = 0;
    join_path(lease_path, sizeof(lease_path), dir, "lease");
    join_path(manifest_path, sizeof(manifest_path), dir, "manifest");

    if (ve_tls_persistent_open(&first, &first_options) != 0) {
        failed = 1;
        goto done;
    }
    g_fake_time = 5000;
    if (ve_tls_persistent_open(&second, &second_options) == 0) {
        failed = 1;
        ve_tls_persistent_close(&second);
        memset(&second, 0, sizeof(second));
    }
    if (ve_tls_persistent_open(&second, &ordinary_options) == 0) {
        failed = 1;
        ve_tls_persistent_close(&second);
        memset(&second, 0, sizeof(second));
    }
    ve_tls_persistent_close(&first);
    memset(&first, 0, sizeof(first));
    if (ve_tls_persistent_open(&second, &second_options) != 0) {
        failed = 1;
        goto done;
    }
    ve_tls_persistent_close(&second);
    memset(&second, 0, sizeof(second));

    manifest = fopen(manifest_path, "wb");
    if (!manifest || fputs("invalid-manifest\n", manifest) == EOF) {
        failed = 1;
        goto done;
    }
    fclose(manifest);
    manifest = NULL;
    failed_open.lease_fd = -1;
    first_options.now_ms = 5000;
    if (ve_tls_persistent_open(&failed_open, &first_options) == 0 ||
        failed_open.lease_fd != -1 ||
        ve_tls_lease_guard_enter(lease_path, 0, &probe_fd) != 0 || probe_fd < 0) {
        failed = 1;
    }
    if (probe_fd >= 0) {
        ve_tls_lease_guard_leave(probe_fd);
        probe_fd = -1;
    }

done:
    if (manifest) {
        fclose(manifest);
    }
    if (probe_fd >= 0) {
        ve_tls_lease_guard_leave(probe_fd);
    }
    if (failed_open.platform) {
        ve_tls_persistent_close(&failed_open);
    }
    if (first.platform) {
        ve_tls_persistent_close(&first);
    }
    if (second.platform) {
        ve_tls_persistent_close(&second);
    }
    lf_cleanup_dir(dir);
    return failed ? -1 : 0;
}

static int test_exclusive_persistence_hot_path_recovery(void) {
    char dir[PATH_MAX];
    char checkpoint_path[PATH_MAX];
    ve_tls_config cfg;
    ve_tls_persistent first;
    ve_tls_persistent second;
    ve_tls_persistent_options first_options;
    ve_tls_persistent_options second_options;
    ve_tls_checkpoint_state checkpoint;
    ep_recover_records recovered;
    static const char * payloads[] = {"hot-1", "hot-2", "hot-3"};
    int failed = 0;

    dir[0] = 0;
    memset(&first, 0, sizeof(first));
    memset(&second, 0, sizeof(second));
    memset(&recovered, 0, sizeof(recovered));
    if (make_temp_dir(dir, sizeof(dir)) != 0) {
        return -1;
    }
    ve_tls_config_init(&cfg);
    g_real_platform = cfg.platform;
    cfg.platform.time_ms = test_fake_time_ms;
    cfg.platform.file_open = lf_count_lease_file_open;
    cfg.platform.path_stat = lf_count_lease_path_stat;
    g_fake_time = 1000;
    ep_make_exclusive_options(&first_options, &cfg.platform, dir, "hot-owner", 1000);
    ep_make_exclusive_options(&second_options, &cfg.platform, dir, "hot-recovery", 1300);
    if (ve_tls_persistent_open(&first, &first_options) != 0) {
        failed = 1;
        goto done;
    }
    __atomic_store_n(&g_lf_lease_path_stat_count, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&g_lf_lease_file_read_count, 0, __ATOMIC_RELEASE);
    for (int i = 0; i < 3; i++) {
        if (ve_tls_persistent_append(
                &first, i + 1, NULL,
                (const unsigned char *)payloads[i], strlen(payloads[i])) != 0) {
            failed = 1;
        }
    }
    if (ve_tls_persistent_ack_range(&first, 1, 2) != 0 ||
        ve_tls_persistent_flush(&first) != 0 ||
        __atomic_load_n(&g_lf_lease_path_stat_count, __ATOMIC_ACQUIRE) != 0 ||
        __atomic_load_n(&g_lf_lease_file_read_count, __ATOMIC_ACQUIRE) != 0) {
        failed = 1;
    }
    g_fake_time = 1200;
    first_options.now_ms = g_fake_time;
    if (ve_tls_persistent_heartbeat_if_due(&first, 0) != 0 ||
        (__atomic_load_n(&g_lf_lease_path_stat_count, __ATOMIC_ACQUIRE) +
         __atomic_load_n(&g_lf_lease_file_read_count, __ATOMIC_ACQUIRE)) <= 0) {
        failed = 1;
    }
    ve_tls_persistent_close(&first);
    memset(&first, 0, sizeof(first));

    if (ve_tls_persistent_open(&second, &second_options) != 0 ||
        ve_tls_persistent_recover(&second, ep_collect_recovered_record, &recovered) != 0 ||
        recovered.calls != 1 || recovered.ids[0] != 3 ||
        recovered.sizes[0] != strlen(payloads[2]) ||
        memcmp(recovered.payloads[0], payloads[2], recovered.sizes[0]) != 0) {
        failed = 1;
    }
    join_path(checkpoint_path, sizeof(checkpoint_path), dir, "checkpoint");
    if (ve_tls_checkpoint_load(&cfg.platform, checkpoint_path, &checkpoint) != 0 ||
        checkpoint.acked_log_id != 2) {
        failed = 1;
    }

done:
    if (first.platform) {
        ve_tls_persistent_close(&first);
    }
    if (second.platform) {
        ve_tls_persistent_close(&second);
    }
    lf_cleanup_dir(dir);
    return failed ? -1 : 0;
}

static int test_exclusive_persistence_concurrent_append_recovery(void) {
    char dir[PATH_MAX];
    ve_tls_config cfg;
    ve_tls_persistent first;
    ve_tls_persistent second;
    ve_tls_persistent_options first_options;
    ve_tls_persistent_options second_options;
    lf_gate write_gate;
    lf_done first_done;
    lf_done second_done;
    lf_append_done_arg first_arg;
    lf_append_done_arg second_arg;
    ep_recover_records recovered;
    ve_tls_thread * first_thread = NULL;
    ve_tls_thread * second_thread = NULL;
    int failed = 0;

    dir[0] = 0;
    memset(&first, 0, sizeof(first));
    memset(&second, 0, sizeof(second));
    memset(&recovered, 0, sizeof(recovered));
    if (make_temp_dir(dir, sizeof(dir)) != 0) {
        return -1;
    }
    ve_tls_config_init(&cfg);
    g_real_platform = cfg.platform;
    cfg.platform.time_ms = test_fake_time_ms;
    cfg.platform.file_open = lf_capture_file_open;
    cfg.platform.file_write = lf_gated_file_write;
    g_fake_time = 1000;
    ep_make_exclusive_options(&first_options, &cfg.platform, dir, "concurrent-owner", 1000);
    ep_make_exclusive_options(&second_options, &cfg.platform, dir, "concurrent-recovery", 1000);
    lf_gate_init(&write_gate);
    lf_done_init(&first_done);
    lf_done_init(&second_done);
    g_lf_capture_segment_file = 1;
    g_lf_segment_file = NULL;
    g_lf_write_gate = &write_gate;
    if (ve_tls_persistent_open(&first, &first_options) != 0 || !g_lf_segment_file) {
        failed = 1;
        goto done;
    }
    lf_gate_arm(&write_gate);
    memset(&first_arg, 0, sizeof(first_arg));
    first_arg.persistent = &first;
    first_arg.log_id = 1;
    first_arg.done = &first_done;
    first_thread = cfg.platform.thread_create(lf_append_done_thread, &first_arg);
    if (!first_thread || lf_gate_wait_entered(&write_gate) != 0) {
        failed = 1;
        goto done;
    }
    memset(&second_arg, 0, sizeof(second_arg));
    second_arg.persistent = &first;
    second_arg.log_id = 2;
    second_arg.done = &second_done;
    second_thread = cfg.platform.thread_create(lf_append_done_thread, &second_arg);
    if (!second_thread || lf_done_wait_started(&second_done, 1000) != 0) {
        failed = 1;
        goto done;
    }
    pthread_mutex_lock(&second_done.mutex);
    if (second_done.done) {
        failed = 1;
    }
    pthread_mutex_unlock(&second_done.mutex);
    lf_gate_release(&write_gate);
    cfg.platform.thread_join(first_thread);
    first_thread = NULL;
    cfg.platform.thread_join(second_thread);
    second_thread = NULL;
    if (first_done.rc != 0 || second_done.rc != 0 || first.current_records != 2) {
        failed = 1;
    }
    ve_tls_persistent_close(&first);
    memset(&first, 0, sizeof(first));
    g_lf_write_gate = NULL;
    g_lf_capture_segment_file = 0;
    g_lf_segment_file = NULL;
    if (ve_tls_persistent_open(&second, &second_options) != 0 ||
        ve_tls_persistent_recover(&second, ep_collect_recovered_record, &recovered) != 0 ||
        recovered.calls != 2 || recovered.ids[0] != 1 || recovered.ids[1] != 2) {
        failed = 1;
    }

done:
    if (first_thread || second_thread) {
        lf_gate_release(&write_gate);
    }
    if (first_thread) {
        cfg.platform.thread_join(first_thread);
    }
    if (second_thread) {
        cfg.platform.thread_join(second_thread);
    }
    if (first.platform) {
        ve_tls_persistent_close(&first);
    }
    if (second.platform) {
        ve_tls_persistent_close(&second);
    }
    g_lf_write_gate = NULL;
    g_lf_capture_segment_file = 0;
    g_lf_segment_file = NULL;
    lf_done_destroy(&first_done);
    lf_done_destroy(&second_done);
    lf_gate_destroy(&write_gate);
    lf_cleanup_dir(dir);
    return failed ? -1 : 0;
}

static int test_exclusive_persistence_recovery_reentry(void) {
    char dir[PATH_MAX];
    ve_tls_config cfg;
    ve_tls_config child_cfg;
    ve_tls_persistent first;
    ve_tls_persistent_options first_options;
    int result_pipe[2] = {-1, -1};
    pid_t child = -1;
    int status = 0;
    int failed = 0;
    char marker = 0;

    dir[0] = 0;
    memset(&first, 0, sizeof(first));
    if (make_temp_dir(dir, sizeof(dir)) != 0 || pipe(result_pipe) != 0) {
        if (result_pipe[0] >= 0) close(result_pipe[0]);
        if (result_pipe[1] >= 0) close(result_pipe[1]);
        if (dir[0] != 0) lf_cleanup_dir(dir);
        return -1;
    }
    ve_tls_config_init(&cfg);
    g_real_platform = cfg.platform;
    cfg.platform.time_ms = test_fake_time_ms;
    g_fake_time = 1000;
    ep_make_exclusive_options(&first_options, &cfg.platform, dir, "reentry-owner", 1000);
    if (ve_tls_persistent_open(&first, &first_options) != 0 ||
        ve_tls_persistent_append(&first, 1, NULL,
            (const unsigned char *)"reentry", strlen("reentry")) != 0) {
        failed = 1;
        goto done;
    }
    ve_tls_persistent_close(&first);
    memset(&first, 0, sizeof(first));
    child_cfg = cfg;
    child = fork();
    if (child < 0) {
        failed = 1;
        goto done;
    }
    if (child == 0) {
        ve_tls_persistent second;
        ve_tls_persistent_options second_options;
        lf_recover_reentry_state state;
        int rc;
        close(result_pipe[0]);
        memset(&second, 0, sizeof(second));
        memset(&state, 0, sizeof(state));
        ep_make_exclusive_options(&second_options, &child_cfg.platform, dir, "reentry-child", 2000);
        second_options.owner_pid = (int32_t)getpid();
        state.persistent = &second;
        rc = ve_tls_persistent_open(&second, &second_options);
        if (rc == 0) {
            rc = ve_tls_persistent_recover(&second, lf_recover_ack_flush_callback, &state);
            marker = (rc == 0 && state.calls == 1 &&
                state.ack_rc == 0 && state.flush_rc == 0) ? '0' : '1';
            if (second.platform) {
                ve_tls_persistent_close(&second);
            }
        } else {
            marker = '1';
        }
        (void)write(result_pipe[1], &marker, 1);
        close(result_pipe[1]);
        _exit(marker == '0' ? 0 : 1);
    }
    close(result_pipe[1]);
    result_pipe[1] = -1;
    if (lf_read_byte_timeout(result_pipe[0], &marker) != 0 || marker != '0') {
        failed = 1;
    } else if (waitpid(child, &status, 0) != child) {
        failed = 1;
    } else {
        child = -1;
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            failed = 1;
        }
    }
    {
        ve_tls_checkpoint_state checkpoint;
        char checkpoint_path[PATH_MAX];
        join_path(checkpoint_path, sizeof(checkpoint_path), dir, "checkpoint");
        if (ve_tls_checkpoint_load(&cfg.platform, checkpoint_path, &checkpoint) != 0 ||
            checkpoint.acked_log_id != 1) {
            failed = 1;
        }
    }

done:
    if (child > 0) {
        (void)kill(child, SIGKILL);
        (void)waitpid(child, &status, 0);
    }
    if (result_pipe[0] >= 0) close(result_pipe[0]);
    if (result_pipe[1] >= 0) close(result_pipe[1]);
    if (first.platform) {
        ve_tls_persistent_close(&first);
    }
    lf_cleanup_dir(dir);
    return failed ? -1 : 0;
}

static int test_exclusive_persistence_fork_close_preserves_lock(void) {
    char dir[PATH_MAX];
    ve_tls_config cfg;
    ve_tls_persistent first;
    ve_tls_persistent second;
    ve_tls_persistent_options first_options;
    ve_tls_persistent_options second_options;
    int result_pipe[2] = {-1, -1};
    pid_t child = -1;
    int status = 0;
    int failed = 0;
    char marker = 0;

    dir[0] = 0;
    memset(&first, 0, sizeof(first));
    memset(&second, 0, sizeof(second));
    if (make_temp_dir(dir, sizeof(dir)) != 0 || pipe(result_pipe) != 0) {
        if (result_pipe[0] >= 0) close(result_pipe[0]);
        if (result_pipe[1] >= 0) close(result_pipe[1]);
        if (dir[0] != 0) lf_cleanup_dir(dir);
        return -1;
    }
    ve_tls_config_init(&cfg);
    g_real_platform = cfg.platform;
    cfg.platform.time_ms = test_fake_time_ms;
    g_fake_time = 1000;
    ep_make_exclusive_options(&first_options, &cfg.platform, dir, "fork-parent", 1000);
    ep_make_exclusive_options(&second_options, &cfg.platform, dir, "fork-second", 5000);
    if (ve_tls_persistent_open(&first, &first_options) != 0) {
        failed = 1;
        goto done;
    }
    child = fork();
    if (child < 0) {
        failed = 1;
        goto done;
    }
    if (child == 0) {
        static const unsigned char payload[] = "fork-child-rejected";
        int append_rc;
        close(result_pipe[0]);
        append_rc = ve_tls_persistent_append(&first, 1, NULL, payload, sizeof(payload) - 1);
        ve_tls_persistent_close(&first);
        marker = append_rc != 0 ? '0' : '1';
        (void)write(result_pipe[1], &marker, 1);
        close(result_pipe[1]);
        _exit(marker == '0' ? 0 : 1);
    }
    close(result_pipe[1]);
    result_pipe[1] = -1;
    if (lf_read_byte_timeout(result_pipe[0], &marker) != 0 || marker != '0') {
        failed = 1;
    } else if (waitpid(child, &status, 0) != child) {
        failed = 1;
    } else {
        child = -1;
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            failed = 1;
        }
    }

    g_fake_time = 5000;
    if (ve_tls_persistent_open(&second, &second_options) == 0) {
        failed = 1;
        ve_tls_persistent_close(&second);
        memset(&second, 0, sizeof(second));
    }
    ve_tls_persistent_close(&first);
    memset(&first, 0, sizeof(first));
    if (ve_tls_persistent_open(&second, &second_options) != 0) {
        failed = 1;
    }

done:
    if (child > 0) {
        (void)kill(child, SIGKILL);
        (void)waitpid(child, &status, 0);
    }
    if (result_pipe[0] >= 0) close(result_pipe[0]);
    if (result_pipe[1] >= 0) close(result_pipe[1]);
    if (first.platform) {
        ve_tls_persistent_close(&first);
    }
    if (second.platform) {
        ve_tls_persistent_close(&second);
    }
    lf_cleanup_dir(dir);
    return failed ? -1 : 0;
}
