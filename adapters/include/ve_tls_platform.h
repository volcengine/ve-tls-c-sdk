#ifndef VE_TLS_PLATFORM_H
#define VE_TLS_PLATFORM_H

#include <stdint.h>
#include <stddef.h>

#include "ve_tls_export.h"

VE_TLS_BEGIN_DECLS

typedef struct ve_tls_mutex ve_tls_mutex;
typedef struct ve_tls_cond ve_tls_cond;
typedef struct ve_tls_thread ve_tls_thread;
typedef struct ve_tls_file ve_tls_file;

typedef void * (*ve_tls_thread_fn)(void * arg);

typedef struct {
    int exists;
    int is_dir;
    uint64_t size;
    int64_t mtime_ms;
} ve_tls_path_info;

enum {
    VE_TLS_FILE_OPEN_RDONLY = 0x01,
    VE_TLS_FILE_OPEN_WRONLY = 0x02,
    VE_TLS_FILE_OPEN_RDWR = 0x04,
    VE_TLS_FILE_OPEN_CREATE = 0x08,
    VE_TLS_FILE_OPEN_TRUNC = 0x10,
    VE_TLS_FILE_OPEN_APPEND = 0x20,
    VE_TLS_FILE_OPEN_EXCL = 0x40
};

enum {
    VE_TLS_FILE_SEEK_SET = 0,
    VE_TLS_FILE_SEEK_CUR = 1,
    VE_TLS_FILE_SEEK_END = 2
};

typedef struct {
    int64_t (*time_ms)(void);
    int64_t (*time_unix_ns)(void);
    void (*sleep_ms)(int64_t ms);
    ve_tls_mutex * (*mutex_create)(void);
    void (*mutex_destroy)(ve_tls_mutex * m);
    void (*mutex_lock)(ve_tls_mutex * m);
    void (*mutex_unlock)(ve_tls_mutex * m);
    ve_tls_cond * (*cond_create)(void);
    void (*cond_destroy)(ve_tls_cond * c);
    void (*cond_wait)(ve_tls_cond * c, ve_tls_mutex * m);
    int (*cond_timedwait_ms)(ve_tls_cond * c, ve_tls_mutex * m, int64_t timeout_ms);
    void (*cond_signal)(ve_tls_cond * c);
    void (*cond_broadcast)(ve_tls_cond * c);
    ve_tls_thread * (*thread_create)(ve_tls_thread_fn fn, void * arg);
    void (*thread_join)(ve_tls_thread * t);
    ve_tls_file * (*file_open)(const char * path, int flags, int mode);
    void (*file_close)(ve_tls_file * f);
    int64_t (*file_read)(ve_tls_file * f, void * buf, size_t size);
    int64_t (*file_write)(ve_tls_file * f, const void * buf, size_t size);
    int64_t (*file_seek)(ve_tls_file * f, int64_t offset, int whence);
    int (*file_fsync)(ve_tls_file * f);
    int (*file_truncate)(ve_tls_file * f, int64_t size);
    int (*path_mkdirs)(const char * path, int mode);
    int (*path_stat)(const char * path, ve_tls_path_info * out);
    int (*path_remove)(const char * path);
    int (*path_rename)(const char * from, const char * to);
} ve_tls_platform;

VE_TLS_API void ve_tls_platform_init_default(ve_tls_platform * platform);

VE_TLS_END_DECLS

#endif
