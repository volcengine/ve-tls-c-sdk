# 签名与鉴权规范

## 目标
对齐 volc-sdk-golang 的 TLS 鉴权行为，确保跨语言 SDK 签名一致。

## 签名算法
- V4 签名（scope 包含 region 与 service=TLS）
- 必须写入请求头：
  - X-Date
  - X-Content-Sha256
  - Authorization
  - X-Security-Token（可选）

## Canonicalization
- URI 归一化与编码规则一致
- Query 归一化规则一致（包含空格与 + 的处理）
- Header 参与签名的规则与白名单一致（包含 X- 前缀策略）

## 内容摘要
- body 存在时支持 Content-MD5（与 TLS 服务侧兼容）
- X-Content-Sha256 参与签名

## 预签名 URL（可选）
- 支持生成带签名的 URL（用于特殊场景）
