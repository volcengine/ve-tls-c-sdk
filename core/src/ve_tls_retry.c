#include "ve_tls_retry.h"

#include <stdlib.h>
#include <math.h>
#include <stdint.h>
#include <string.h>

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
    policy->rand01 = NULL;
    policy->rand01_param = NULL;
}

static uint64_t ve_tls_mix64(uint64_t x) {
    x ^= x >> 33;
    x *= 0xff51afd7ed558ccdULL;
    x ^= x >> 33;
    x *= 0xc4ceb9fe1a85ec53ULL;
    x ^= x >> 33;
    return x;
}

static double ve_tls_rand01_fallback(void) {
    static uint64_t s = 0;
    if (s == 0) {
        uintptr_t a = (uintptr_t)&s;
        uintptr_t b = (uintptr_t)&ve_tls_rand01_fallback;
        s = ve_tls_mix64(((uint64_t)a << 32) ^ (uint64_t)b ^ 0x9e3779b97f4a7c15ULL);
    }
    s = ve_tls_mix64(s + 0x9e3779b97f4a7c15ULL);
    uint64_t u = (s >> 11) | 0x3ff0000000000000ULL;
    double d;
    memcpy(&d, &u, sizeof(d));
    return d - 1.0;
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
    double r = 0;
    if (policy->rand01) {
        r = policy->rand01(policy->rand01_param);
    } else {
        r = ve_tls_rand01_fallback();
    }
    if (r < 0) r = 0;
    if (r > 1) r = 1;
    double v = min + (max - min) * r;
    if (v < 0) {
        v = 0;
    }
    return (int64_t)(v);
}
