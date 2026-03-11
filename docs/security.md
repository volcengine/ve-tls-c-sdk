# 安全规范

## 机密信息
- 禁止在日志与回调中输出 AK/SK/security_token
- 禁止输出完整请求体（允许采样与脱敏）

## 签名与时间
- 必须支持 X-Date 生成与请求过期处理
- 本地时间漂移导致的 RequestExpired 必须明确错误码返回

## 传输安全
- 默认使用 HTTPS
- 证书校验由 Adapter/Net 层实现且默认开启
