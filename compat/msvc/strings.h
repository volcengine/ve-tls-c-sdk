#ifndef VE_TLS_COMPAT_MSVC_STRINGS_H
#define VE_TLS_COMPAT_MSVC_STRINGS_H

#include <string.h>

#define strcasecmp _stricmp
#define strncasecmp _strnicmp

#endif
