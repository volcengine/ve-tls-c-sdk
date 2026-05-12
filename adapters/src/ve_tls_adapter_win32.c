#include "ve_tls_adapter.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <fcntl.h>
#include <io.h>
#include <stdio.h>

#define VE_TLS_WIN32_UNIX_EPOCH_100NS 116444736000000000ULL

static int ve_tls_win32_open(const char * path, int flags, int mode) {
    return _open(path, flags | _O_BINARY, mode);
}

static int ve_tls_win32_close(int fd) {
    return _close(fd);
}

static int ve_tls_win32_read(int fd, void * buf, size_t size) {
    return (int)_read(fd, buf, (unsigned int)size);
}

static int ve_tls_win32_write(int fd, const void * buf, size_t size) {
    return (int)_write(fd, buf, (unsigned int)size);
}

static int ve_tls_win32_seek(int fd, int64_t offset, int whence) {
    return (int)_lseeki64(fd, offset, whence);
}

static int ve_tls_win32_sync(int fd) {
    return _commit(fd);
}

static int ve_tls_win32_remove(const char * path) {
    return remove(path);
}

static int ve_tls_win32_rename(const char * from, const char * to) {
    return rename(from, to);
}

static int64_t ve_tls_win32_time_ms(void) {
    FILETIME ft;
    ULARGE_INTEGER u;
    GetSystemTimeAsFileTime(&ft);
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    if (u.QuadPart < VE_TLS_WIN32_UNIX_EPOCH_100NS) {
        return 0;
    }
    return (int64_t)((u.QuadPart - VE_TLS_WIN32_UNIX_EPOCH_100NS) / 10000ULL);
}

void ve_tls_adapter_init_default(ve_tls_adapter * adapter) {
    if (!adapter) {
        return;
    }
    adapter->file_open = ve_tls_win32_open;
    adapter->file_close = ve_tls_win32_close;
    adapter->file_read = ve_tls_win32_read;
    adapter->file_write = ve_tls_win32_write;
    adapter->file_seek = ve_tls_win32_seek;
    adapter->file_sync = ve_tls_win32_sync;
    adapter->file_remove = ve_tls_win32_remove;
    adapter->file_rename = ve_tls_win32_rename;
    adapter->time_ms = ve_tls_win32_time_ms;
}
