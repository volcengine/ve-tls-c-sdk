#include "ve_tls_platform.h"

#include <pthread.h>
#include <sys/time.h>
#include <stdlib.h>
#include <time.h>

struct ve_tls_mutex {
    pthread_mutex_t mutex;
};

struct ve_tls_cond {
    pthread_cond_t cond;
};

struct ve_tls_thread {
    pthread_t thread;
};

static int64_t ve_tls_posix_time_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (int64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
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
    pthread_cond_init(&c->cond, NULL);
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
    struct timeval tv;
    gettimeofday(&tv, NULL);
    int64_t nanos = (int64_t)tv.tv_usec * 1000 + (timeout_ms % 1000) * 1000000;
    ts.tv_sec = tv.tv_sec + (timeout_ms / 1000) + nanos / 1000000000;
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

void ve_tls_platform_init_default(ve_tls_platform * platform) {
    if (!platform) {
        return;
    }
    platform->time_ms = ve_tls_posix_time_ms;
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
}
