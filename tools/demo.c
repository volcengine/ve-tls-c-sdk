#include "../core/include/ve_tls_producer.h"

#include <stdio.h>

static void on_send_done(
    ve_tls_result result,
    size_t log_bytes,
    size_t compressed_bytes,
    const char * req_id,
    const char * error_message,
    const unsigned char * raw_buffer,
    void * user_param,
    int64_t start_id,
    int64_t end_id
) {
    (void)compressed_bytes;
    (void)raw_buffer;
    (void)user_param;
    printf("result=%d bytes=%zu req_id=%s err=%s start=%lld end=%lld\n",
           (int)result,
           log_bytes,
           req_id ? req_id : "",
           error_message ? error_message : "",
           (long long)start_id,
           (long long)end_id);
}

int main(void) {
    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    cfg.endpoint = "https://tls-cn-beijing.volces.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "your-topic-id";
    cfg.access_key_id = "ak";
    cfg.access_key_secret = "sk";
    cfg.compress_type = "none";

    ve_tls_producer * p = ve_tls_producer_create(&cfg);
    if (!p) {
        return 1;
    }
    ve_tls_producer_set_send_done(p, on_send_done, NULL);

    ve_tls_kv kvs[2];
    kvs[0].key = "k1";
    kvs[0].value = "v1";
    kvs[1].key = "k2";
    kvs[1].value = "v2";
    ve_tls_producer_add_log_kv(p, 1710000000000, kvs, 2, 1);
    ve_tls_producer_flush(p);

    cfg.platform.sleep_ms(1000);

    ve_tls_producer_destroy(p);
    return 0;
}
