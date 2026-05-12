#include "ve_tls_platform.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <process.h>
#include <stdlib.h>

#define VE_TLS_WIN32_UNIX_EPOCH_100NS 116444736000000000ULL

struct ve_tls_mutex {
    CRITICAL_SECTION cs;
};

struct ve_tls_cond {
    CONDITION_VARIABLE cond;
};

struct ve_tls_thread {
    HANDLE handle;
};

typedef struct {
    ve_tls_thread_fn fn;
    void * arg;
} ve_tls_win32_thread_start;

static uint64_t ve_tls_win32_time_100ns(void) {
    FILETIME ft;
    ULARGE_INTEGER u;
    GetSystemTimeAsFileTime(&ft);
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    return u.QuadPart;
}

static int64_t ve_tls_win32_time_ms(void) {
    uint64_t ticks = ve_tls_win32_time_100ns();
    if (ticks < VE_TLS_WIN32_UNIX_EPOCH_100NS) {
        return 0;
    }
    return (int64_t)((ticks - VE_TLS_WIN32_UNIX_EPOCH_100NS) / 10000ULL);
}

static int64_t ve_tls_win32_time_unix_ns(void) {
    uint64_t ticks = ve_tls_win32_time_100ns();
    if (ticks < VE_TLS_WIN32_UNIX_EPOCH_100NS) {
        return 0;
    }
    return (int64_t)((ticks - VE_TLS_WIN32_UNIX_EPOCH_100NS) * 100ULL);
}

static void ve_tls_win32_sleep_ms(int64_t ms) {
    while (ms > 0) {
        DWORD chunk = ms > 0x7fffffffLL ? 0x7fffffffUL : (DWORD)ms;
        Sleep(chunk);
        ms -= chunk;
    }
}

static ve_tls_mutex * ve_tls_win32_mutex_create(void) {
    ve_tls_mutex * m = (ve_tls_mutex *)calloc(1, sizeof(ve_tls_mutex));
    if (!m) {
        return NULL;
    }
    if (!InitializeCriticalSectionAndSpinCount(&m->cs, 4000)) {
        free(m);
        return NULL;
    }
    return m;
}

static void ve_tls_win32_mutex_destroy(ve_tls_mutex * m) {
    if (!m) {
        return;
    }
    DeleteCriticalSection(&m->cs);
    free(m);
}

static void ve_tls_win32_mutex_lock(ve_tls_mutex * m) {
    EnterCriticalSection(&m->cs);
}

static void ve_tls_win32_mutex_unlock(ve_tls_mutex * m) {
    LeaveCriticalSection(&m->cs);
}

static ve_tls_cond * ve_tls_win32_cond_create(void) {
    ve_tls_cond * c = (ve_tls_cond *)calloc(1, sizeof(ve_tls_cond));
    if (!c) {
        return NULL;
    }
    InitializeConditionVariable(&c->cond);
    return c;
}

static void ve_tls_win32_cond_destroy(ve_tls_cond * c) {
    free(c);
}

static void ve_tls_win32_cond_wait(ve_tls_cond * c, ve_tls_mutex * m) {
    (void)SleepConditionVariableCS(&c->cond, &m->cs, INFINITE);
}

static int ve_tls_win32_cond_timedwait_ms(ve_tls_cond * c, ve_tls_mutex * m, int64_t timeout_ms) {
    DWORD timeout = timeout_ms <= 0 ? 0 : (timeout_ms > 0x7fffffffLL ? 0x7fffffffUL : (DWORD)timeout_ms);
    if (SleepConditionVariableCS(&c->cond, &m->cs, timeout)) {
        return 0;
    }
    return GetLastError() == ERROR_TIMEOUT ? 1 : -1;
}

static void ve_tls_win32_cond_signal(ve_tls_cond * c) {
    WakeConditionVariable(&c->cond);
}

static void ve_tls_win32_cond_broadcast(ve_tls_cond * c) {
    WakeAllConditionVariable(&c->cond);
}

static unsigned __stdcall ve_tls_win32_thread_main(void * arg) {
    ve_tls_win32_thread_start * start = (ve_tls_win32_thread_start *)arg;
    ve_tls_thread_fn fn = start->fn;
    void * user_arg = start->arg;
    free(start);
    (void)fn(user_arg);
    return 0;
}

static ve_tls_thread * ve_tls_win32_thread_create(ve_tls_thread_fn fn, void * arg) {
    ve_tls_thread * t = (ve_tls_thread *)calloc(1, sizeof(ve_tls_thread));
    ve_tls_win32_thread_start * start = (ve_tls_win32_thread_start *)calloc(1, sizeof(ve_tls_win32_thread_start));
    uintptr_t handle;
    if (!t || !start) {
        free(start);
        free(t);
        return NULL;
    }
    start->fn = fn;
    start->arg = arg;
    handle = _beginthreadex(NULL, 0, ve_tls_win32_thread_main, start, 0, NULL);
    if (!handle) {
        free(start);
        free(t);
        return NULL;
    }
    t->handle = (HANDLE)handle;
    return t;
}

static void ve_tls_win32_thread_join(ve_tls_thread * t) {
    if (!t) {
        return;
    }
    WaitForSingleObject(t->handle, INFINITE);
    CloseHandle(t->handle);
    free(t);
}

void ve_tls_platform_init_default(ve_tls_platform * platform) {
    if (!platform) {
        return;
    }
    platform->time_ms = ve_tls_win32_time_ms;
    platform->time_unix_ns = ve_tls_win32_time_unix_ns;
    platform->sleep_ms = ve_tls_win32_sleep_ms;
    platform->mutex_create = ve_tls_win32_mutex_create;
    platform->mutex_destroy = ve_tls_win32_mutex_destroy;
    platform->mutex_lock = ve_tls_win32_mutex_lock;
    platform->mutex_unlock = ve_tls_win32_mutex_unlock;
    platform->cond_create = ve_tls_win32_cond_create;
    platform->cond_destroy = ve_tls_win32_cond_destroy;
    platform->cond_wait = ve_tls_win32_cond_wait;
    platform->cond_timedwait_ms = ve_tls_win32_cond_timedwait_ms;
    platform->cond_signal = ve_tls_win32_cond_signal;
    platform->cond_broadcast = ve_tls_win32_cond_broadcast;
    platform->thread_create = ve_tls_win32_thread_create;
    platform->thread_join = ve_tls_win32_thread_join;
}
