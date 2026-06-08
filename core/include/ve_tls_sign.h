#ifndef VE_TLS_SIGN_H
#define VE_TLS_SIGN_H

#include <stddef.h>

/**
 * 计算 Volcengine V4 签名并把签名结果与 SDK 管理头（Host/X-Date/X-Content-Sha256/
 * X-Security-Token/Authorization）追加到 headers_in 之后。
 *
 * 入参:
 *   access_key_id / access_key_secret  必填
 *   security_token                     可空（""或NULL均视为不携带 STS）
 *   region / service                   必填，e.g. "cn-beijing" / "TLS"
 *   method / host / path / query       HTTP 规范化输入，host 不含 scheme
 *   body / body_size                   用于计算 X-Content-Sha256；body 可为 NULL 当 body_size=0
 *   headers_in                         调用方头部，按 "Key: Value\n" 行格式；
 *                                      若包含上述 SDK 管理头会被 canonical 计算与输出统一过滤，避免重复签名
 *
 * 出参:
 *   headers_out                        新分配的字符串，所有权交给调用方，
 *                                      使用完毕必须 ve_tls_free() 释放（与 SDK 内部 alloc 配对）
 *
 * 返回:   0 成功；非 0 失败（参数缺失/分配失败/签名内部错误）
 *
 * 线程安全:  无内部全局状态，多线程并发调用安全；调用方需保证入参缓冲不被并发修改。
 */
int ve_tls_sign_v4_append(
    const char * access_key_id,
    const char * access_key_secret,
    const char * security_token,
    const char * region,
    const char * service,
    const char * method,
    const char * host,
    const char * path,
    const char * query,
    const unsigned char * body,
    size_t body_size,
    const char * headers_in,
    char ** headers_out
);

/**
 * 与 ve_tls_sign_v4_append 行为一致，额外通过 xdate_override 注入固定的 X-Date 时间戳，
 * 便于离线测试或时钟对齐场景；xdate_override 为 NULL/空串时退化为读取系统时间。
 *
 * 所有权 / 线程安全约束与 ve_tls_sign_v4_append 相同。
 */
int ve_tls_sign_v4_append_at(
    const char * access_key_id,
    const char * access_key_secret,
    const char * security_token,
    const char * region,
    const char * service,
    const char * method,
    const char * host,
    const char * path,
    const char * query,
    const unsigned char * body,
    size_t body_size,
    const char * xdate_override,
    const char * headers_in,
    char ** headers_out
);

#endif
