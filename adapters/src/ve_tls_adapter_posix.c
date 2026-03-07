#include "../include/ve_tls_adapter.h"

#include <sys/time.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>

static int ve_tls_posix_open(const char * path, int flags, int mode) {
    return open(path, flags, mode);
}

static int ve_tls_posix_close(int fd) {
    return close(fd);
}

static int ve_tls_posix_read(int fd, void * buf, size_t size) {
    return (int)read(fd, buf, size);
}

static int ve_tls_posix_write(int fd, const void * buf, size_t size) {
    return (int)write(fd, buf, size);
}

static int ve_tls_posix_seek(int fd, int64_t offset, int whence) {
    return (int)lseek(fd, offset, whence);
}

static int ve_tls_posix_sync(int fd) {
    return fsync(fd);
}

static int ve_tls_posix_remove(const char * path) {
    return remove(path);
}

static int ve_tls_posix_rename(const char * from, const char * to) {
    return rename(from, to);
}

static int64_t ve_tls_posix_time_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (int64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

void ve_tls_adapter_init_default(ve_tls_adapter * adapter) {
    if (!adapter) {
        return;
    }
    adapter->file_open = ve_tls_posix_open;
    adapter->file_close = ve_tls_posix_close;
    adapter->file_read = ve_tls_posix_read;
    adapter->file_write = ve_tls_posix_write;
    adapter->file_seek = ve_tls_posix_seek;
    adapter->file_sync = ve_tls_posix_sync;
    adapter->file_remove = ve_tls_posix_remove;
    adapter->file_rename = ve_tls_posix_rename;
    adapter->time_ms = ve_tls_posix_time_ms;
}
