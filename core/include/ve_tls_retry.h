#ifndef VE_TLS_RETRY_H
#define VE_TLS_RETRY_H

#include <stdint.h>

#include "ve_tls_export.h"

VE_TLS_BEGIN_DECLS

typedef struct {
    int64_t total_timeout_ms;
    int64_t initial_interval_ms;
    int64_t max_interval_ms;
    double multiplier;
    double randomization_factor;
    int32_t max_attempts;
    double (*rand01)(void * user_param);
    void * rand01_param;
} ve_tls_retry_policy;

VE_TLS_API void ve_tls_retry_policy_init(ve_tls_retry_policy * policy);
VE_TLS_API int64_t ve_tls_retry_next_interval_ms(ve_tls_retry_policy * policy, int32_t attempt);

VE_TLS_END_DECLS

#endif
