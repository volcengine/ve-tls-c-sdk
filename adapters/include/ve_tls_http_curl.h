#ifndef VE_TLS_HTTP_CURL_H
#define VE_TLS_HTTP_CURL_H

#include "ve_tls_export.h"
#include "ve_tls_http.h"

VE_TLS_BEGIN_DECLS

#if defined(VE_TLS_HAVE_CURL)
VE_TLS_API void ve_tls_http_client_init_curl(ve_tls_http_client * client);
#endif

VE_TLS_END_DECLS

#endif
