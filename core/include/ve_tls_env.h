#ifndef VE_TLS_ENV_H
#define VE_TLS_ENV_H

#include "ve_tls_producer.h"

#ifdef __cplusplus
extern "C" {
#endif

ve_tls_result ve_tls_env_init(int32_t global_send_thread_count);
ve_tls_result ve_tls_env_destroy(int32_t timeout_ms);

#ifdef __cplusplus
}
#endif

#endif
