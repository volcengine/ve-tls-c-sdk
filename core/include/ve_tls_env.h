#ifndef VE_TLS_ENV_H
#define VE_TLS_ENV_H

#include "ve_tls_export.h"
#include "ve_tls_producer.h"

VE_TLS_BEGIN_DECLS

VE_TLS_API ve_tls_result ve_tls_env_init(int32_t global_send_thread_count);
VE_TLS_API ve_tls_result ve_tls_env_destroy(int32_t timeout_ms);

VE_TLS_END_DECLS

#endif
