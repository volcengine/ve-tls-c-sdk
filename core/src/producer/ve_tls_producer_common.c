#include "ve_tls_producer_internal.h"

#include <string.h>

void ve_tls_metrics_emit(ve_tls_producer * producer, const char * name, int64_t v1, int64_t v2) {
    if (!producer || !producer->config.metrics_sink.emit) {
        return;
    }
    producer->config.metrics_sink.emit(name, v1, v2, producer->config.metrics_sink.user_param);
}

int ve_tls_latency_bucket_index(int64_t ms) {
    if (ms <= 5) return 0;
    if (ms <= 10) return 1;
    if (ms <= 50) return 2;
    if (ms <= 100) return 3;
    if (ms <= 300) return 4;
    if (ms <= 1000) return 5;
    if (ms <= 3000) return 6;
    return 7;
}

void ve_tls_rate_limit_wait(ve_tls_producer * producer, size_t bytes) {
    if (!producer) {
        return;
    }
    int32_t rps = producer->config.rate_limit_rps;
    int32_t bps = producer->config.rate_limit_bps;
    if (rps <= 0 && bps <= 0) {
        return;
    }
    if (!producer->config.platform.time_ms) {
        return;
    }
    double req_need = rps > 0 ? 1.0 : 0.0;
    double byte_need = bps > 0 ? (double)bytes : 0.0;
    for (;;) {
        int64_t now = producer->config.platform.time_ms();
        producer->config.platform.mutex_lock(producer->mutex);
        if (producer->stop) {
            producer->config.platform.mutex_unlock(producer->mutex);
            return;
        }
        if (producer->rl_last_ms == 0) {
            producer->rl_last_ms = now;
            producer->rl_req_tokens = rps > 0 ? (double)rps : 0.0;
            producer->rl_byte_tokens = bps > 0 ? (double)bps : 0.0;
        } else if (now > producer->rl_last_ms) {
            double dt = (double)(now - producer->rl_last_ms) / 1000.0;
            producer->rl_last_ms = now;
            if (rps > 0) {
                producer->rl_req_tokens += dt * (double)rps;
                if (producer->rl_req_tokens > (double)rps) {
                    producer->rl_req_tokens = (double)rps;
                }
            }
            if (bps > 0) {
                producer->rl_byte_tokens += dt * (double)bps;
                if (producer->rl_byte_tokens > (double)bps) {
                    producer->rl_byte_tokens = (double)bps;
                }
            }
        }
        int ok = 1;
        if (rps > 0 && producer->rl_req_tokens < req_need) {
            ok = 0;
        }
        if (bps > 0 && producer->rl_byte_tokens < byte_need) {
            ok = 0;
        }
        if (ok) {
            if (rps > 0) {
                producer->rl_req_tokens -= req_need;
            }
            if (bps > 0) {
                producer->rl_byte_tokens -= byte_need;
            }
            producer->config.platform.mutex_unlock(producer->mutex);
            return;
        }
        producer->config.platform.mutex_unlock(producer->mutex);
        producer->config.platform.sleep_ms(10);
    }
}

void ve_tls_breaker_wait_open(ve_tls_producer * producer) {
    if (!producer || producer->config.breaker_fail_threshold <= 0) {
        return;
    }
    if (!producer->config.platform.time_ms) {
        return;
    }
    for (;;) {
        int64_t now = producer->config.platform.time_ms();
        producer->config.platform.mutex_lock(producer->mutex);
        if (producer->stop) {
            producer->config.platform.mutex_unlock(producer->mutex);
            return;
        }
        int64_t until = producer->breaker_open_until_ms;
        if (until == 0 || now >= until) {
            producer->config.platform.mutex_unlock(producer->mutex);
            return;
        }
        producer->config.platform.mutex_unlock(producer->mutex);
        int64_t d = until - now;
        if (d > 50) {
            d = 50;
        }
        if (d < 1) {
            d = 1;
        }
        producer->config.platform.sleep_ms(d);
    }
}

int ve_tls_breaker_try_enter_half_open(ve_tls_producer * producer) {
    if (!producer || producer->config.breaker_fail_threshold <= 0) {
        return 1;
    }
    if (!producer->config.platform.time_ms) {
        return 1;
    }
    int64_t now = producer->config.platform.time_ms();
    producer->config.platform.mutex_lock(producer->mutex);
    if (producer->breaker_open_until_ms == 0 || now >= producer->breaker_open_until_ms) {
        if (producer->breaker_half_open_inflight < producer->config.breaker_half_open_max_inflight) {
            producer->breaker_half_open_inflight++;
            producer->config.platform.mutex_unlock(producer->mutex);
            return 2;
        }
        producer->config.platform.mutex_unlock(producer->mutex);
        return 0;
    }
    producer->config.platform.mutex_unlock(producer->mutex);
    return 0;
}

void ve_tls_breaker_leave_half_open(ve_tls_producer * producer, int ok) {
    if (!producer || producer->config.breaker_fail_threshold <= 0) {
        return;
    }
    if (!producer->config.platform.time_ms) {
        return;
    }
    int64_t now = producer->config.platform.time_ms();
    producer->config.platform.mutex_lock(producer->mutex);
    if (producer->breaker_half_open_inflight > 0) {
        producer->breaker_half_open_inflight--;
    }
    if (ok) {
        producer->breaker_consecutive_failures = 0;
        producer->breaker_open_until_ms = 0;
        producer->config.platform.mutex_unlock(producer->mutex);
        return;
    }
    producer->breaker_consecutive_failures += 1;
    if (producer->breaker_consecutive_failures >= producer->config.breaker_fail_threshold) {
        int32_t open_ms = producer->config.breaker_open_ms > 0 ? producer->config.breaker_open_ms : 30000;
        producer->breaker_open_until_ms = now + open_ms;
    }
    producer->config.platform.mutex_unlock(producer->mutex);
}

void ve_tls_breaker_on_final_result(ve_tls_producer * producer, int ok) {
    if (!producer || producer->config.breaker_fail_threshold <= 0) {
        return;
    }
    if (!producer->config.platform.time_ms) {
        return;
    }
    int64_t now = producer->config.platform.time_ms();
    producer->config.platform.mutex_lock(producer->mutex);
    if (ok) {
        producer->breaker_consecutive_failures = 0;
        producer->breaker_open_until_ms = 0;
        producer->config.platform.mutex_unlock(producer->mutex);
        return;
    }
    producer->breaker_consecutive_failures += 1;
    if (producer->breaker_consecutive_failures >= producer->config.breaker_fail_threshold) {
        int32_t open_ms = producer->config.breaker_open_ms > 0 ? producer->config.breaker_open_ms : 30000;
        producer->breaker_open_until_ms = now + open_ms;
    }
    producer->config.platform.mutex_unlock(producer->mutex);
}

void ve_tls_metric_inc_u64(_Atomic(uint64_t) * p, uint64_t v) {
    (void)atomic_fetch_add_explicit(p, v, memory_order_relaxed);
}

uint64_t ve_tls_metric_load_u64(_Atomic(uint64_t) * p) {
    return atomic_load_explicit(p, memory_order_relaxed);
}
