#ifndef VE_TLS_COMPAT_MSVC_UNISTD_H
#define VE_TLS_COMPAT_MSVC_UNISTD_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

typedef unsigned int useconds_t;

static inline int usleep(useconds_t usec) {
    Sleep((DWORD)((usec + 999u) / 1000u));
    return 0;
}

#endif
