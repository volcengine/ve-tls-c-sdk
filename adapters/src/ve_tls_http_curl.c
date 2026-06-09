#include "ve_tls_http.h"

#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <pthread.h>
#endif

typedef struct {
    unsigned char * data;
    size_t size;
} ve_tls_buf;

static int ve_tls_ascii_tolower(int c) {
    return (c >= 'A' && c <= 'Z') ? (c + ('a' - 'A')) : c;
}

static int ve_tls_ascii_strncasecmp(const char * a, const char * b, size_t n) {
    for (size_t i = 0; i < n; i++) {
        unsigned char ca = (unsigned char)a[i];
        unsigned char cb = (unsigned char)b[i];
        int da = ve_tls_ascii_tolower((int)ca);
        int db = ve_tls_ascii_tolower((int)cb);
        if (da != db) {
            return da - db;
        }
        if (ca == 0) {
            return 0;
        }
    }
    return 0;
}

static size_t ve_tls_write_cb(char * ptr, size_t size, size_t nmemb, void * userdata) {
    if (nmemb != 0 && size > (size_t)-1 / nmemb) {
        return 0;
    }
    size_t total = size * nmemb;
    ve_tls_buf * buf = (ve_tls_buf *)userdata;
    if (buf->size > (size_t)-1 - total - 1) {
        return 0;
    }
    unsigned char * next = (unsigned char *)realloc(buf->data, buf->size + total + 1);
    if (!next) {
        return 0;
    }
    buf->data = next;
    memcpy(buf->data + buf->size, ptr, total);
    buf->size += total;
    buf->data[buf->size] = 0;
    return total;
}

static size_t ve_tls_header_cb(char * ptr, size_t size, size_t nmemb, void * userdata) {
    if (nmemb != 0 && size > (size_t)-1 / nmemb) {
        return 0;
    }
    size_t total = size * nmemb;
    ve_tls_http_response * resp = (ve_tls_http_response *)userdata;
    const char * key = "x-tls-requestid:";
    if (total > strlen(key) && ve_tls_ascii_strncasecmp(ptr, key, strlen(key)) == 0) {
        char * start = ptr + strlen(key);
        while (*start == ' ' || *start == '\t') {
            start++;
        }
        char * end = ptr + total;
        while (end > start && (end[-1] == '\r' || end[-1] == '\n')) {
            end--;
        }
        size_t len = (size_t)(end - start);
        char * id = (char *)calloc(1, len + 1);
        if (id) {
            memcpy(id, start, len);
            free(resp->request_id);
            resp->request_id = id;
        }
    }
    return total;
}

static int ve_tls_curl_retryable(CURLcode code) {
    switch (code) {
        case CURLE_COULDNT_RESOLVE_PROXY:
        case CURLE_COULDNT_RESOLVE_HOST:
        case CURLE_COULDNT_CONNECT:
        case CURLE_OPERATION_TIMEDOUT:
        case CURLE_SEND_ERROR:
        case CURLE_RECV_ERROR:
        case CURLE_GOT_NOTHING:
        case CURLE_PARTIAL_FILE:
        case CURLE_SSL_CONNECT_ERROR:
            return 1;
        default:
            return 0;
    }
}

static const char * ve_tls_curl_error_code(CURLcode code) {
    switch (code) {
        case CURLE_OPERATION_TIMEDOUT:
            return "TimeoutError";
        case CURLE_COULDNT_RESOLVE_HOST:
        case CURLE_COULDNT_RESOLVE_PROXY:
            return "DNSError";
        case CURLE_COULDNT_CONNECT:
            return "ConnectError";
        case CURLE_SSL_CONNECT_ERROR:
            return "SSLError";
        case CURLE_SEND_ERROR:
            return "SendError";
        case CURLE_RECV_ERROR:
        case CURLE_GOT_NOTHING:
        case CURLE_PARTIAL_FILE:
            return "RecvError";
        default:
            return "TransportError";
    }
}

#if !defined(_WIN32)
static pthread_once_t g_easy_key_once = PTHREAD_ONCE_INIT;
static pthread_key_t g_easy_key;

static void ve_tls_easy_key_cleanup(void * p) {
    if (p) {
        curl_easy_cleanup((CURL *)p);
    }
}

static void ve_tls_easy_key_init(void) {
    (void)pthread_key_create(&g_easy_key, ve_tls_easy_key_cleanup);
}

static CURL * ve_tls_easy_get(void) {
    (void)pthread_once(&g_easy_key_once, ve_tls_easy_key_init);
    CURL * curl = (CURL *)pthread_getspecific(g_easy_key);
    if (!curl) {
        curl = curl_easy_init();
        if (curl) {
            (void)pthread_setspecific(g_easy_key, curl);
        }
    }
    return curl;
}
#else
static _Thread_local CURL * g_tls_easy = NULL;
static CURL * ve_tls_easy_get(void) {
    if (!g_tls_easy) {
        g_tls_easy = curl_easy_init();
    }
    return g_tls_easy;
}
#endif

static int ve_tls_http_curl_do(ve_tls_http_client * client, const ve_tls_http_request * req, ve_tls_http_response * resp) {
    (void)client;
    CURL * curl = ve_tls_easy_get();
    if (!curl) {
        return -1;
    }
    /* 入口统一清理上一次复用 resp 时残留的动态字段，避免成功/失败路径覆盖指针时泄漏旧的 strdup 内存。
     * 调用方仍可在终止使用时显式调用 free_response 释放本次结果；free(NULL) 安全。 */
    if (resp) {
        free(resp->body);
        free(resp->request_id);
        free(resp->error_code);
        free(resp->error_message);
        resp->body = NULL;
        resp->body_size = 0;
        resp->request_id = NULL;
        resp->error_code = NULL;
        resp->error_message = NULL;
        resp->status_code = 0;
        resp->transport_kind = VE_TLS_TRANSPORT_NONE;
        resp->transport_code = 0;
        resp->transport_retryable = 0;
    }
    curl_easy_reset(curl);
    ve_tls_buf body = {0};
    struct curl_slist * headers = NULL;
    if (req->headers && req->headers[0] != 0) {
        char * tmp = strdup(req->headers);
        if (!tmp) {
            curl_slist_free_all(headers);
            free(body.data);
            return -1;
        }
        char * line = tmp;
        for (char * p = tmp;; p++) {
            if (*p == '\n' || *p == 0) {
                char end = *p;
                *p = 0;
                if (line[0] != 0) {
                    const char * header_line = line;
                    char * empty_header = NULL;
                    char * colon = strchr(line, ':');
                    if (colon) {
                        const char * value = colon + 1;
                        while (*value == ' ' || *value == '\t') {
                            value++;
                        }
                        if (*value == 0) {
                            size_t key_len = (size_t)(colon - line);
                            empty_header = (char *)malloc(key_len + 2);
                            if (!empty_header) {
                                free(tmp);
                                curl_slist_free_all(headers);
                                free(body.data);
                                return -1;
                            }
                            memcpy(empty_header, line, key_len);
                            empty_header[key_len] = ';';
                            empty_header[key_len + 1] = 0;
                            header_line = empty_header;
                        }
                    }
                    struct curl_slist * nh = curl_slist_append(headers, header_line);
                    free(empty_header);
                    if (!nh) {
                        free(tmp);
                        curl_slist_free_all(headers);
                        free(body.data);
                        return -1;
                    }
                    headers = nh;
                }
                if (end == 0) {
                    break;
                }
                line = p + 1;
            }
        }
        free(tmp);
    }

    curl_easy_setopt(curl, CURLOPT_URL, req->url);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, req->method);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, ve_tls_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &body);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, ve_tls_header_cb);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, resp);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    if (req->debug_log > 0) {
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    }
    if (req->tls_verify_peer == 0) {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    } else {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    }
    if (req->tls_verify_host == 0) {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    } else {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    }
    if (req->ca_cert_path && req->ca_cert_path[0] != 0) {
        curl_easy_setopt(curl, CURLOPT_CAINFO, req->ca_cert_path);
    }
    if (req->proxy && req->proxy[0] != 0) {
        curl_easy_setopt(curl, CURLOPT_PROXY, req->proxy);
    }
    if (req->user_agent && req->user_agent[0] != 0) {
        curl_easy_setopt(curl, CURLOPT_USERAGENT, req->user_agent);
    }
    if (req->tcp_keepalive > 0) {
        curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);
        if (req->tcp_keepidle > 0) {
            curl_easy_setopt(curl, CURLOPT_TCP_KEEPIDLE, (long)req->tcp_keepidle);
        }
        if (req->tcp_keepintvl > 0) {
            curl_easy_setopt(curl, CURLOPT_TCP_KEEPINTVL, (long)req->tcp_keepintvl);
        }
    }
    if (req->connect_timeout_ms > 0) {
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, (long)req->connect_timeout_ms);
    }
    if (req->timeout_ms > 0) {
        curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, (long)req->timeout_ms);
    }
    if (req->body && req->body_size > 0) {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, req->body);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)req->body_size);
    }

    CURLcode code = curl_easy_perform(curl);
    if (code != CURLE_OK) {
        resp->transport_kind = VE_TLS_TRANSPORT_CURL;
        resp->transport_code = (int32_t)code;
        resp->transport_retryable = ve_tls_curl_retryable(code) ? 1 : 0;
        resp->error_code = strdup(ve_tls_curl_error_code(code));
        const char * err = curl_easy_strerror(code);
        if (err) {
            resp->error_message = strdup(err);
        }
        curl_slist_free_all(headers);
        free(body.data);
        return -1;
    }
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    resp->status_code = (int32_t)http_code;
    resp->body = body.data;
    resp->body_size = body.size;
    /* transport_kind / transport_code / transport_retryable / error_code / error_message
     * 已在 do 入口统一清零；本路径仅写状态码与 body，避免重复赋值。 */
    curl_slist_free_all(headers);
    return 0;
}

static void ve_tls_http_curl_free(ve_tls_http_client * client, ve_tls_http_response * resp) {
    (void)client;
    if (!resp) {
        return;
    }
    free(resp->body);
    free(resp->request_id);
    free(resp->error_code);
    free(resp->error_message);
    resp->body = NULL;
    resp->request_id = NULL;
    resp->error_message = NULL;
    resp->body_size = 0;
    resp->error_code = NULL;
    resp->status_code = 0;
    resp->transport_kind = VE_TLS_TRANSPORT_NONE;
    resp->transport_code = 0;
    resp->transport_retryable = 0;
}


void ve_tls_http_client_init_curl(ve_tls_http_client * client) {
    if (!client) {
        return;
    }
    static int g_curl_global_inited = 0;
    int expected = 0;
    if (__atomic_compare_exchange_n(&g_curl_global_inited, &expected, 1, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) {
        CURLcode rc = curl_global_init(CURL_GLOBAL_DEFAULT);
        if (rc != CURLE_OK) {
            __atomic_store_n(&g_curl_global_inited, 0, __ATOMIC_SEQ_CST);
        } else {
            atexit(curl_global_cleanup);
        }
    }
    client->do_request = ve_tls_http_curl_do;
    client->free_response = ve_tls_http_curl_free;
    client->user_data = NULL;
}
