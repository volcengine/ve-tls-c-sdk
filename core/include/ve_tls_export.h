#ifndef VE_TLS_EXPORT_H
#define VE_TLS_EXPORT_H

#if defined(_WIN32) || defined(__CYGWIN__)
#  if defined(VE_TLS_SHARED)
#    if defined(VE_TLS_BUILDING_LIBRARY) || defined(VE_TLS_BUILDING) || defined(VE_TLS_EXPORTS)
#      define VE_TLS_API __declspec(dllexport)
#    else
#      define VE_TLS_API __declspec(dllimport)
#    endif
#  else
#    define VE_TLS_API
#  endif
#elif defined(__GNUC__) || defined(__clang__)
#  define VE_TLS_API __attribute__((visibility("default")))
#else
#  define VE_TLS_API
#endif

#ifdef __cplusplus
#  define VE_TLS_BEGIN_DECLS extern "C" {
#  define VE_TLS_END_DECLS }
#else
#  define VE_TLS_BEGIN_DECLS
#  define VE_TLS_END_DECLS
#endif

#endif
