#ifndef VE_TLS_PRODUCER_INTERNAL_H
#define VE_TLS_PRODUCER_INTERNAL_H

#include "ve_tls_producer.h"
#include "ve_tls_proto.h"
#include "ve_tls_compress.h"
#include "ve_tls_retry.h"
#include "ve_tls_error.h"

#include <stdint.h>
#include <stddef.h>

typedef struct {
    int64_t id;
    int64_t time_ms;
    uint32_t time_ns;
    int32_t has_time_ns;
    char * hash_key;
    unsigned char * data;
    size_t size;
} ve_tls_log_item;

typedef struct ve_tls_log_group_builder ve_tls_log_group_builder;

struct ve_tls_log_group_builder {
    char * norm_key;
    unsigned char * logs;
    size_t logs_len;
    size_t logs_cap;
    int32_t log_count;
    int64_t earliest;
    int64_t latest;
    int64_t last_time_ms;
    uint32_t last_time_ns;
    int32_t last_has_time_ns;
    int64_t start_id;
    int64_t end_id;
    int64_t first_append_ms;
    ve_tls_log_group_builder * next;
};

typedef struct {
    unsigned char * body;
    size_t body_size;
    size_t raw_body_size;
    int32_t log_count;
    int64_t earliest;
    int64_t latest;
    size_t batch_bytes;
    int64_t start_id;
    int64_t end_id;
    char * hash_key;
    int32_t partition_id;
    unsigned char * precompressed;
    size_t precompressed_size;
} ve_tls_send_task;

typedef struct {
    ve_tls_platform * platform;
    ve_tls_mutex * mutex;
    ve_tls_cond * not_empty;
    ve_tls_cond * not_full;
    ve_tls_send_task * buf;
    size_t cap;
    size_t head;
    size_t tail;
    size_t count;
    int stop;
} ve_tls_send_queue;

typedef struct ve_tls_key_queue ve_tls_key_queue;

struct ve_tls_key_queue {
    char * key;
    uint32_t hash;
    ve_tls_send_task * q;
    size_t cap;
    size_t head;
    size_t tail;
    size_t count;
    int32_t inflight;
    int32_t ready;
    int64_t rl_last_ms;
    double rl_req_tokens;
    double rl_byte_tokens;
    int64_t breaker_open_until_ms;
    int32_t breaker_consecutive_failures;
    int32_t idle;
    int64_t empty_since_ms;
    int32_t delayed;
    int64_t next_ready_ms;
    ve_tls_key_queue * hnext;
    ve_tls_key_queue * rprev;
    ve_tls_key_queue * rnext;
    ve_tls_key_queue * iprev;
    ve_tls_key_queue * inext;
    ve_tls_key_queue * dprev;
    ve_tls_key_queue * dnext;
    ve_tls_log_group_builder * builder;
};

struct ve_tls_producer {
    ve_tls_config config;
    ve_tls_send_done_fn send_done;
    void * send_done_param;
    ve_tls_send_done_v2_fn send_done_v2;
    void * send_done_v2_param;
    int32_t fast_send;
    int32_t fast_inflight;
    int32_t fast_builder;
    const char * default_norm_key;
    ve_tls_log_group_builder * default_builder;
    ve_tls_mutex * mutex;
    ve_tls_cond * cond;
    ve_tls_cond * send_cond;
    ve_tls_thread * worker;
    ve_tls_thread ** senders;
    int32_t sender_count;
    ve_tls_key_queue ** key_buckets;
    size_t key_bucket_count;
    size_t key_queue_count;
    ve_tls_key_queue * ready_head;
    ve_tls_key_queue * ready_tail;
    ve_tls_key_queue * idle_head;
    ve_tls_key_queue * idle_tail;
    int64_t idle_cleanup_next_ms;
    ve_tls_key_queue * delayed_head;
    ve_tls_key_queue * delayed_tail;
    ve_tls_send_queue send_queue;
    int stop;
    int flush_requested;
    int accepting;
    int closing;
    int worker_flushing;
    int64_t next_id;
    ve_tls_log_item * queue;
    size_t queue_cap;
    size_t queue_head;
    size_t queue_tail;
    size_t queue_count;
    size_t queue_bytes;
    size_t tls_bytes;
    ve_tls_log_group_builder * sealed_head;
    ve_tls_log_group_builder * sealed_tail;
    unsigned char * cfg_group_suffix;
    size_t cfg_group_suffix_len;
    int64_t rl_last_ms;
    double rl_req_tokens;
    double rl_byte_tokens;
    int64_t breaker_open_until_ms;
    int32_t breaker_consecutive_failures;
    int32_t breaker_half_open_inflight;
    int32_t cred_refreshing;
    int64_t cred_expire_ms;
    int64_t cred_last_refresh_ms;
    char * cred_access_key_id;
    char * cred_access_key_secret;
    char * cred_security_token;
    char * cfg_endpoint;
    char * cfg_region;
    char * cfg_project_id;
    char * cfg_topic_id;
    char * cfg_source;
    char * cfg_file_name;
    char * cfg_context_flow;
    ve_tls_kv * cfg_log_tags;
    size_t cfg_log_tag_count;
    char * cfg_hash_key;
    char * cfg_access_key_id;
    char * cfg_access_key_secret;
    char * cfg_security_token;
    char * cfg_api_version;
    char * cfg_compress_type;
    char * cfg_ca_cert_path;
    char * cfg_proxy;
    char * cfg_user_agent;
    char * cfg_persistent_file_path;
    int64_t send_cfg_version;
    int64_t static_cred_version;
    uint64_t m_logs_enqueued_total;
    uint64_t m_logs_dropped_total;
    uint64_t m_bytes_enqueued_total;
    uint64_t m_bytes_dropped_total;
    uint64_t m_batches_built_total;
    uint64_t m_requests_total;
    uint64_t m_requests_failed_total;
    uint64_t m_retries_total;
    uint64_t m_bytes_sent_total;
    uint64_t m_latency_buckets[8];
    int32_t use_global_env;
    int32_t env_in_queue;
    int32_t env_inflight;
    ve_tls_producer * env_next;
};

void ve_tls_producer_config_init(ve_tls_config * config);
void ve_tls_metrics_emit(ve_tls_producer * producer, const char * name, int64_t v1, int64_t v2);
int ve_tls_latency_bucket_index(int64_t ms);
void ve_tls_rate_limit_wait(ve_tls_producer * producer, size_t bytes);
void ve_tls_breaker_wait_open(ve_tls_producer * producer);
int ve_tls_breaker_try_enter_half_open(ve_tls_producer * producer);
void ve_tls_breaker_leave_half_open(ve_tls_producer * producer, int ok);
void ve_tls_breaker_on_final_result(ve_tls_producer * producer, int ok);
void ve_tls_metric_inc_u64(uint64_t * p, uint64_t v);
uint64_t ve_tls_metric_load_u64(uint64_t * p);

void ve_tls_queue_free_all(ve_tls_producer * producer);
int ve_tls_queue_push(ve_tls_producer * producer, const unsigned char * data, size_t size, int64_t id, int64_t time_ms, uint32_t time_ns, int32_t has_time_ns, const char * hash_key);
int ve_tls_queue_push_owned(ve_tls_producer * producer, unsigned char * data, size_t size, int64_t id, int64_t time_ms, uint32_t time_ns, int32_t has_time_ns, char * hash_key);
int ve_tls_queue_pop(ve_tls_producer * producer, ve_tls_log_item * out);
void ve_tls_item_free(ve_tls_log_item * item);
void ve_tls_send_task_free(ve_tls_send_task * t);

ve_tls_log_group_builder * ve_tls_log_builder_create(const char * norm_key);
void ve_tls_log_builder_free(ve_tls_log_group_builder * b);
int ve_tls_log_builder_add_kv_lens(ve_tls_log_group_builder * b, int64_t id, int64_t time_ms, uint32_t time_ns, int32_t has_time_ns, const ve_tls_kv * kvs, const size_t * key_lens, const size_t * val_lens, size_t kv_count);
int ve_tls_log_builder_append(ve_tls_log_group_builder * b, const unsigned char * logs, size_t logs_len, int32_t log_count, int64_t earliest, int64_t latest, int64_t start_id, int64_t end_id, int64_t last_time_ms, uint32_t last_time_ns, int32_t last_has_time_ns);
int ve_tls_producer_build_group_suffix(ve_tls_producer * producer);
int ve_tls_builder_to_send_task(ve_tls_producer * producer, ve_tls_log_group_builder * b, ve_tls_send_task * out);

int ve_tls_send_queue_init(ve_tls_send_queue * q, ve_tls_platform * platform, size_t cap);
int ve_tls_send_queue_push(ve_tls_send_queue * q, const ve_tls_send_task * t, int wait_ms);
int ve_tls_send_queue_pop(ve_tls_send_queue * q, ve_tls_send_task * out, int wait_ms);
void ve_tls_send_queue_stop(ve_tls_send_queue * q);
void ve_tls_send_queue_destroy(ve_tls_send_queue * q);

void ve_tls_key_map_free_all(ve_tls_producer * producer);
ve_tls_key_queue * ve_tls_key_queue_get_or_create(ve_tls_producer * producer, const char * norm_key);
int ve_tls_key_queue_push_task(ve_tls_producer * producer, const char * norm_key, const ve_tls_send_task * t);
int ve_tls_key_queue_reserve(ve_tls_producer * producer, const char * norm_key);
int ve_tls_key_queue_pop_task(ve_tls_key_queue * q, ve_tls_send_task * out);
int ve_tls_key_queue_push_front_task(ve_tls_key_queue * q, const ve_tls_send_task * t);
void ve_tls_key_queue_finish(ve_tls_producer * producer, ve_tls_key_queue * q);
void ve_tls_delayed_promote_due(ve_tls_producer * producer, int64_t now_ms);
void ve_tls_idle_cleanup(ve_tls_producer * producer);
const char * ve_tls_normalize_hash_key(ve_tls_producer * producer, const char * hash_key);
ve_tls_key_queue * ve_tls_ready_pop(ve_tls_producer * producer);
void ve_tls_delayed_add_sorted(ve_tls_producer * producer, ve_tls_key_queue * q, int64_t next_ready_ms);

int ve_tls_producer_is_drained_locked(ve_tls_producer * producer);
int ve_tls_sender_step(ve_tls_producer * producer);
int ve_tls_env_register_producer(ve_tls_producer * producer);
void ve_tls_env_unregister_producer(ve_tls_producer * producer);
void ve_tls_env_notify(ve_tls_producer * producer);

void * ve_tls_worker_main(void * arg);
void * ve_tls_sender_main(void * arg);

#endif
