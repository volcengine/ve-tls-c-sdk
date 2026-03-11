#include "../include/ve_tls_retry.h"

#include <stdlib.h>
#include <math.h>

void ve_tls_retry_policy_init(ve_tls_retry_policy * policy) {
    if (!policy) {
        return;
    }
    policy->total_timeout_ms = 90 * 1000;
    policy->initial_interval_ms = 500;
    policy->max_interval_ms = 10 * 1000;
    policy->multiplier = 1.6;
    policy->randomization_factor = 0.2;
    policy->max_attempts = 5;
}

static double ve_tls_rand01(void) {
    return (double)rand() / (double)RAND_MAX;
}

int64_t ve_tls_retry_next_interval_ms(ve_tls_retry_policy * policy, int32_t attempt) {
    if (!policy || attempt <= 0) {
        return 0;
    }
    double base = (double)policy->initial_interval_ms;
    double interval = base * pow(policy->multiplier, (double)(attempt - 1));
    if (interval > (double)policy->max_interval_ms) {
        interval = (double)policy->max_interval_ms;
    }
    double delta = policy->randomization_factor * interval;
    double min = interval - delta;
    double max = interval + delta;
    double v = min + (max - min) * ve_tls_rand01();
    if (v < 0) {
        v = 0;
    }
    return (int64_t)(v);
}
