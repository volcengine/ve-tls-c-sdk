# 错误模型规范

## 错误结构
错误对象 MUST 包含：
- request_id
- http_code
- error_code
- error_message

## 错误分类
- ClientError：参数非法、配置缺失、序列化失败
- NetworkError：DNS/连接/超时/EOF 等
- ServerError：HTTP 5xx
- Throttled：HTTP 429
- AuthError：签名错误、过期、权限不足

## 可重试判定
- Throttled/ServerError/部分 NetworkError 可重试
- AuthError 默认不可重试（可配置白名单例外）

## 回调语义
- send_done 回调返回：
  - result（成功/失败/可重试/不可重试）
  - req_id（若已生成）
  - error_message（失败原因）
