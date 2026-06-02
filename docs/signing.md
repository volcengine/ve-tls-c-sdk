# 签名与鉴权规范

## 目标
说明 SDK 发送 TLS 请求时使用的签名与鉴权规则。

## 签名算法
- V4 签名（scope 包含 region 与 service=TLS）
- 必须写入请求头：
  - X-Date
  - X-Content-Sha256
  - Authorization
  - X-Security-Token（可选）

## Canonicalization
- URI 归一化与编码规则必须稳定
- Query 归一化需要正确处理空格与 `+`
- Header 参与签名的规则与白名单必须稳定（包含 X- 前缀策略）

## 内容摘要
- body 存在时支持 Content-MD5（与 TLS 服务侧兼容）
- X-Content-Sha256 参与签名
