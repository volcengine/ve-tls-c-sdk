# 文档索引

这些文档面向接入方，说明 ve-tls-c-sdk 在当前分支的公开能力。内部计划、历史比较材料和不适合发布的验证记录不要放在这里。

## 接入

- [配置字段](config-fields.md)：`ve_tls_config` 中建议公开使用的字段、默认值和调优边界。
- [签名与鉴权](signing.md)：请求签名、临时凭证和日志脱敏要求。
- [错误模型](error-model.md)：`send_done_v2`、`ve_tls_error` 和常见失败分类。
- [重试策略](retry-policy.md)：请求级重试、批次重试和 Persistent 模式下的处理边界。

## 运行与排障

- [Persistent 模式](persistent.md)：本地持久化、恢复、checkpoint、lease 和重复语义。
- [指标与观测](metrics.md)：metrics、回调和资源压力排查。
- [调优与性能测试](tuning.md)：内存、磁盘、队列、线程和 benchmark 用法。
- [安全规范](security.md)：凭证、日志、TLS 和漏洞报告入口。

## 架构图

- [Mermaid 源文件](diagrams/architecture.mmd)：Producer 到 Persistent Store、Sender 和 HTTP adapter 的主要链路。
