# Producer 模块拆分与 SLS 对齐差异表

本文以 SLS C SDK producer 的常见模块边界为参照（config/client/common/manager/sender/queue），对当前 ve-tls C SDK 的 producer 实现做对齐点与差异点梳理。

## 模块映射

| 模块 | 责任边界 | 我方实现 |
| --- | --- | --- |
| config | 默认配置、参数归一化、adapter 选择 | [ve_tls_producer_config.c](file:///Users/bytedance/workspace/src/sdk/volcengine-sdk/ve-tls-android-sdk/ve-tls-c-sdk/core/src/producer/ve_tls_producer_config.c) |
| client | 对外 API、生命周期、入队与 flush | [ve_tls_producer.c](file:///Users/bytedance/workspace/src/sdk/volcengine-sdk/ve-tls-android-sdk/ve-tls-c-sdk/core/src/ve_tls_producer.c) |
| common | metrics、全局限流/熔断、原子计数、工具函数 | [ve_tls_producer_common.c](file:///Users/bytedance/workspace/src/sdk/volcengine-sdk/ve-tls-android-sdk/ve-tls-c-sdk/core/src/producer/ve_tls_producer_common.c) |
| queue | log queue、有界 send_queue、key->queue 调度（ready/delayed/idle） | [ve_tls_producer_queue.c](file:///Users/bytedance/workspace/src/sdk/volcengine-sdk/ve-tls-android-sdk/ve-tls-c-sdk/core/src/producer/ve_tls_producer_queue.c) |
| manager | 从 log queue 聚合/拆包、生成 send_task 并入 send_queue | [ve_tls_producer_manager.c](file:///Users/bytedance/workspace/src/sdk/volcengine-sdk/ve-tls-android-sdk/ve-tls-c-sdk/core/src/producer/ve_tls_producer_manager.c) |
| sender | 从 send_queue/key_queue 调度发送、HTTP PutLogs、重试与回调 | [ve_tls_producer_sender.c](file:///Users/bytedance/workspace/src/sdk/volcengine-sdk/ve-tls-android-sdk/ve-tls-c-sdk/core/src/producer/ve_tls_producer_sender.c) |

## 已对齐点（关键行为）

| 维度 | 行为 | 我方状态 |
| --- | --- | --- |
| 并发与有序 | 同 hash_key 严格有序，不同 hash_key 无冲突并发 | 已实现（key->queue 映射调度） |
| manager→sender 解耦 | manager 只产出任务，sender 只消费任务 | 已实现（有界 send_queue + key_queue 调度） |
| IO 聚合 | 尽可能合并请求减少 IO | 已实现（worker 聚合编码后批量入 send_queue） |
| Payload 上限兜底 | LogGroupList 原始大小超限时拆包避免发送失败 | 已实现（预编码测大小 + 二分拆分） |
| 退避重试 | 可配置重试次数/总超时/间隔 | 已实现（retry policy） |
| 限流/熔断 | producer 全局 + per-key 限流/熔断，避免热点阻塞 | 已实现（非阻塞 delayed 调度） |
| key 资源保护 | 活跃 key 数上限、空闲 TTL 清理 | 已实现（max_active + idle_ttl） |

## 差异与待补齐项（以 SLS 生产实践为参照）

| 类别 | 差异/缺口 | 影响 | 建议 |
| --- | --- | --- | --- |
| 持久化语义 | 目前以 memory queue 为主，持久化/恢复语义未成体系（exactly-once/at-least-once 边界、落盘时机、重放顺序） | 崩溃后可能丢数据或重复投递 | 引入独立 persistent 模块与明确语义文档，manager 入队前决定落盘策略，sender ack 后清理 |
| 背压策略 | send_queue 满时当前策略为丢弃并回调 Drop（SendQueueFull） | 高峰期丢数据风险 | 提供可配置策略：阻塞/丢弃/采样丢弃，并暴露可观测指标 |
| 失败分类 | HTTP/传输层错误分类较粗（主要依赖 http_code + transport_kind） | 诊断与自动化治理能力不足 | 统一错误码体系（可重试/不可重试/可降级）与 metrics 维度；对 4xx 做更细分 |
| Endpoint/Topic 变更 | sender 侧对 endpoint/topic 变更的动态刷新策略未对齐 | 配置热更新能力不足 | 提供运行期更新 API 与线程安全的可见性模型 |
| 批量策略维度 | TLS 的 LogGroupList 可聚合多个 LogGroup、单 LogGroup≤1w、LogGroupList 原始大小≤10MB，与 SLS 的限制不同 | 不能直接复用 SLS 参数默认值 | 在 config 层显式区分 TLS/SLS 限制，默认值与文档分别标注 |

## 本次拆分落地检查点

- manager/sender 已从 producer.c 抽离，线程入口分别为 [ve_tls_worker_main](file:///Users/bytedance/workspace/src/sdk/volcengine-sdk/ve-tls-android-sdk/ve-tls-c-sdk/core/src/producer/ve_tls_producer_manager.c#L1) 与 [ve_tls_sender_main](file:///Users/bytedance/workspace/src/sdk/volcengine-sdk/ve-tls-android-sdk/ve-tls-c-sdk/core/src/producer/ve_tls_producer_sender.c#L1)。
- producer.c 已收敛为对外 API 与生命周期入口，旧内联实现已禁用以避免边界混乱。
- 现有验证：`build_modular_full` 与 `build_modular_min` 的 `ctest` 通过。
