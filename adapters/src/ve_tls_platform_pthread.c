#include "ve_tls_platform.h"

#include <pthread.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <stdio.h>

struct ve_tls_mutex {
    pthread_mutex_t mutex;
};

struct ve_tls_cond {
    pthread_cond_t cond;
};

struct ve_tls_thread {
    pthread_t thread;
};

struct ve_tls_file {
    int fd;
};

static int64_t ve_tls_posix_time_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (int64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

static int64_t ve_tls_posix_time_unix_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

static void ve_tls_posix_sleep_ms(int64_t ms) {
    if (ms <= 0) {
        return;
    }
    struct timespec ts;
    ts.tv_sec = (time_t)(ms / 1000);
    ts.tv_nsec = (long)((ms % 1000) * 1000000);
    nanosleep(&ts, NULL);
}

static ve_tls_mutex * ve_tls_pthread_mutex_create(void) {
    ve_tls_mutex * m = (ve_tls_mutex *)calloc(1, sizeof(ve_tls_mutex));
    if (!m) {
        return NULL;
    }
    pthread_mutex_init(&m->mutex, NULL);
    return m;
}

static void ve_tls_pthread_mutex_destroy(ve_tls_mutex * m) {
    if (!m) {
        return;
    }
    pthread_mutex_destroy(&m->mutex);
    free(m);
}

static void ve_tls_pthread_mutex_lock(ve_tls_mutex * m) {
    pthread_mutex_lock(&m->mutex);
}

static void ve_tls_pthread_mutex_unlock(ve_tls_mutex * m) {
    pthread_mutex_unlock(&m->mutex);
}

static ve_tls_cond * ve_tls_pthread_cond_create(void) {
    ve_tls_cond * c = (ve_tls_cond *)calloc(1, sizeof(ve_tls_cond));
    if (!c) {
        return NULL;
    }
    pthread_condattr_t attr;
    pthread_condattr_init(&attr);
#if defined(CLOCK_MONOTONIC) && defined(_POSIX_CLOCK_SELECTION) && (_POSIX_CLOCK_SELECTION > 0)
    pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
#endif
    pthread_cond_init(&c->cond, &attr);
    pthread_condattr_destroy(&attr);
    return c;
}

static void ve_tls_pthread_cond_destroy(ve_tls_cond * c) {
    if (!c) {
        return;
    }
    pthread_cond_destroy(&c->cond);
    free(c);
}

static void ve_tls_pthread_cond_wait(ve_tls_cond * c, ve_tls_mutex * m) {
    pthread_cond_wait(&c->cond, &m->mutex);
}

static int ve_tls_pthread_cond_timedwait_ms(ve_tls_cond * c, ve_tls_mutex * m, int64_t timeout_ms) {
    struct timespec ts;
    struct timespec now;
#if defined(CLOCK_MONOTONIC)
    clock_gettime(CLOCK_MONOTONIC, &now);
#else
    clock_gettime(CLOCK_REALTIME, &now);
#endif
    int64_t nanos = (int64_t)now.tv_nsec + (timeout_ms % 1000) * 1000000;
    ts.tv_sec = now.tv_sec + (timeout_ms / 1000) + nanos / 1000000000;
    ts.tv_nsec = nanos % 1000000000;
    return pthread_cond_timedwait(&c->cond, &m->mutex, &ts);
}

static void ve_tls_pthread_cond_signal(ve_tls_cond * c) {
    pthread_cond_signal(&c->cond);
}

static void ve_tls_pthread_cond_broadcast(ve_tls_cond * c) {
    pthread_cond_broadcast(&c->cond);
}

static ve_tls_thread * ve_tls_pthread_thread_create(ve_tls_thread_fn fn, void * arg) {
    ve_tls_thread * t = (ve_tls_thread *)calloc(1, sizeof(ve_tls_thread));
    if (!t) {
        return NULL;
    }
    if (pthread_create(&t->thread, NULL, fn, arg) != 0) {
        free(t);
        return NULL;
    }
    return t;
}

static void ve_tls_pthread_thread_join(ve_tls_thread * t) {
    if (!t) {
        return;
    }
    pthread_join(t->thread, NULL);
    free(t);
}

static int ve_tls_posix_open_flags(int flags) {
    int oflags = 0;
    if (flags & VE_TLS_FILE_OPEN_RDWR) {
        oflags |= O_RDWR;
    } else if (flags & VE_TLS_FILE_OPEN_WRONLY) {
        oflags |= O_WRONLY;
    } else {
        oflags |= O_RDONLY;
    }
    if (flags & VE_TLS_FILE_OPEN_CREATE) {
        oflags |= O_CREAT;
    }
    if (flags & VE_TLS_FILE_OPEN_TRUNC) {
        oflags |= O_TRUNC;
    }
    if (flags & VE_TLS_FILE_OPEN_APPEND) {
        oflags |= O_APPEND;
    }
    if (flags & VE_TLS_FILE_OPEN_EXCL) {
        oflags |= O_EXCL;
    }
    return oflags;
}

static ve_tls_file * ve_tls_posix_file_open(const char * path, int flags, int mode) {
    int fd;
    ve_tls_file * file;
    if (!path) {
        return NULL;
    }
    fd = open(path, ve_tls_posix_open_flags(flags), mode);
    if (fd < 0) {
        return NULL;
    }
    file = (ve_tls_file *)calloc(1, sizeof(ve_tls_file));
    if (!file) {
        close(fd);
        return NULL;
    }
    file->fd = fd;
    return file;
}

static void ve_tls_posix_file_close(ve_tls_file * f) {
    if (!f) {
        return;
    }
    close(f->fd);
    free(f);
}

static int64_t ve_tls_posix_file_read(ve_tls_file * f, void * buf, size_t size) {
    ssize_t n;
    if (!f || (!buf && size > 0)) {
        return -1;
    }
    n = read(f->fd, buf, size);
    return n < 0 ? -1 : (int64_t)n;
}

static int64_t ve_tls_posix_file_write(ve_tls_file * f, const void * buf, size_t size) {
    ssize_t n;
    if (!f || (!buf && size > 0)) {
        return -1;
    }
    n = write(f->fd, buf, size);
    return n < 0 ? -1 : (int64_t)n;
}

static int64_t ve_tls_posix_file_seek(ve_tls_file * f, int64_t offset, int whence) {
    int native_whence = SEEK_SET;
    off_t out;
    if (!f) {
        return -1;
    }
    if (whence == VE_TLS_FILE_SEEK_CUR) {
        native_whence = SEEK_CUR;
    } else if (whence == VE_TLS_FILE_SEEK_END) {
        native_whence = SEEK_END;
    }
    out = lseek(f->fd, (off_t)offset, native_whence);
    return out < 0 ? -1 : (int64_t)out;
}

static int ve_tls_posix_file_fsync(ve_tls_file * f) {
    if (!f) {
        return -1;
    }
    return fsync(f->fd);
}

static int ve_tls_posix_file_truncate(ve_tls_file * f, int64_t size) {
    if (!f || size < 0) {
        return -1;
    }
    return ftruncate(f->fd, (off_t)size);
}

static int ve_tls_posix_path_mkdirs(const char * path, int mode) {
    char buf[PATH_MAX];
    size_t len;
    size_t i;
    if (!path || path[0] == 0) {
        return -1;
    }
    len = strlen(path);
    if (len >= sizeof(buf)) {
        return -1;
    }
    memcpy(buf, path, len + 1);
    for (i = 1; i < len; i++) {
        if (buf[i] != '/') {
            continue;
        }
        buf[i] = 0;
        if (mkdir(buf, (mode_t)mode) != 0 && errno != EEXIST) {
            return -1;
        }
        buf[i] = '/';
    }
    if (mkdir(buf, (mode_t)mode) != 0 && errno != EEXIST) {
        return -1;
    }
    return 0;
}

static int ve_tls_posix_path_stat(const char * path, ve_tls_path_info * out) {
    struct stat st;
    if (!path) {
        return -1;
    }
    if (out) {
        memset(out, 0, sizeof(*out));
    }
    if (stat(path, &st) != 0) {
        return errno == ENOENT ? 0 : -1;
    }
    if (out) {
        out->exists = 1;
        out->is_dir = S_ISDIR(st.st_mode) ? 1 : 0;
        out->size = (uint64_t)st.st_size;
#if defined(__APPLE__)
        out->mtime_ms = (int64_t)st.st_mtimespec.tv_sec * 1000 + st.st_mtimespec.tv_nsec / 1000000;
#else
        out->mtime_ms = (int64_t)st.st_mtim.tv_sec * 1000 + st.st_mtim.tv_nsec / 1000000;
#endif
    }
    return 0;
}

static int ve_tls_posix_path_remove(const char * path) {
    if (!path) {
        return -1;
    }
    if (unlink(path) == 0 || errno == ENOENT) {
        return 0;
    }
    if (errno == EISDIR || errno == EPERM) {
        if (rmdir(path) == 0 || errno == ENOENT) {
            return 0;
        }
    }
    return -1;
}

static int ve_tls_posix_path_rename(const char * from, const char * to) {
    if (!from || !to) {
        return -1;
    }
    return rename(from, to);
}

void ve_tls_platform_init_default(ve_tls_platform * platform) {
    if (!platform) {
        return;
    }
    platform->time_ms = ve_tls_posix_time_ms;
    platform->time_unix_ns = ve_tls_posix_time_unix_ns;
    platform->sleep_ms = ve_tls_posix_sleep_ms;
    platform->mutex_create = ve_tls_pthread_mutex_create;
    platform->mutex_destroy = ve_tls_pthread_mutex_destroy;
    platform->mutex_lock = ve_tls_pthread_mutex_lock;
    platform->mutex_unlock = ve_tls_pthread_mutex_unlock;
    platform->cond_create = ve_tls_pthread_cond_create;
    platform->cond_destroy = ve_tls_pthread_cond_destroy;
    platform->cond_wait = ve_tls_pthread_cond_wait;
    platform->cond_timedwait_ms = ve_tls_pthread_cond_timedwait_ms;
    platform->cond_signal = ve_tls_pthread_cond_signal;
    platform->cond_broadcast = ve_tls_pthread_cond_broadcast;
    platform->thread_create = ve_tls_pthread_thread_create;
    platform->thread_join = ve_tls_pthread_thread_join;
    platform->file_open = ve_tls_posix_file_open;
    platform->file_close = ve_tls_posix_file_close;
    platform->file_read = ve_tls_posix_file_read;
    platform->file_write = ve_tls_posix_file_write;
    platform->file_seek = ve_tls_posix_file_seek;
    platform->file_fsync = ve_tls_posix_file_fsync;
    platform->file_truncate = ve_tls_posix_file_truncate;
    platform->path_mkdirs = ve_tls_posix_path_mkdirs;
    platform->path_stat = ve_tls_posix_path_stat;
    platform->path_remove = ve_tls_posix_path_remove;
    platform->path_rename = ve_tls_posix_path_rename;
}
