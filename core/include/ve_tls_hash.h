#ifndef VE_TLS_HASH_H
#define VE_TLS_HASH_H

#include <stddef.h>
#include <stdint.h>

#include "ve_tls_export.h"

VE_TLS_BEGIN_DECLS

void ve_tls_sha256(const unsigned char * data, size_t len, unsigned char out32[32]);
void ve_tls_hmac_sha256(const unsigned char * key, size_t key_len, const unsigned char * data, size_t len, unsigned char out32[32]);
void ve_tls_md5(const unsigned char * data, size_t len, unsigned char out16[16]);

/**
 * 将 data[0..len) 编码为 hex 字符串写入 out_hex。
 *
 * 容量约束:
 *   调用方必须保证 out_hex_cap >= 2*len + 1（含末尾 '\0'）。
 *   若容量不足，函数会安全截断输出并以 '\0' 收尾，不会越界写入；
 *   截断后的输出不可用于密码学比较或签名拼接。
 *
 * 线程安全: 函数无内部状态，多线程并发调用安全；out_hex 不得被多线程同时写入。
 */
void ve_tls_hex_lower(const unsigned char * data, size_t len, char * out_hex, size_t out_hex_cap);

/**
 * 与 ve_tls_hex_lower 一致，但输出大写 HEX。
 * 容量与线程安全约束相同。
 */
void ve_tls_hex_upper(const unsigned char * data, size_t len, char * out_hex, size_t out_hex_cap);

VE_TLS_END_DECLS

#endif
