#ifndef VE_TLS_ADAPTER_H
#define VE_TLS_ADAPTER_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    int (*file_open)(const char * path, int flags, int mode);
    int (*file_close)(int fd);
    int (*file_read)(int fd, void * buf, size_t size);
    int (*file_write)(int fd, const void * buf, size_t size);
    int (*file_seek)(int fd, int64_t offset, int whence);
    int (*file_sync)(int fd);
    int (*file_remove)(const char * path);
    int (*file_rename)(const char * from, const char * to);
    int64_t (*time_ms)(void);
} ve_tls_adapter;

void ve_tls_adapter_init_default(ve_tls_adapter * adapter);

#endif
